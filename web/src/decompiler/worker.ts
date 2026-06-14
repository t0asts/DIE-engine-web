/// <reference lib="webworker" />

import type {
  DecompWorkerRequest,
  DecompWorkerReply,
  DecompCallTarget,
  DecompInitRequest,
  DecompOpenRequest,
  DecompileRequest,
  DecompCallTargetsRequest,
  DecompCloseRequest,
} from "./protocol";

interface EmFS {
  mkdir(path: string): void;
  createLazyFile(parent: string, name: string, url: string, canRead: boolean, canWrite: boolean): unknown;
}
interface EmModule {
  FS: EmFS;
  HEAPU8: Uint8Array;
  ccall: (name: string, ret: string | null, argTypes: string[], args: unknown[]) => unknown;
  cwrap: (name: string, ret: string | null, argTypes: string[]) => (...args: unknown[]) => unknown;
  UTF8ToString(ptr: number): string;
  _malloc(size: number): number;
  _free(ptr: number): void;
}

interface DecompApi {
  addSpecDir(dir: string): number;
  create(languageId: string): number;
  addRegion(handle: number, addr: bigint, ptr: number, size: number): number;
  addSymbol(handle: number, addr: bigint, name: string): number;
  addImport(handle: number, addr: bigint, name: string): number;
  addReadonly(handle: number, addr: bigint, size: bigint): number;
  addString(handle: number, addr: bigint, len: bigint): number;
  decompile(handle: number, addr: bigint, name: string): number;
  callTargets(handle: number, addr: bigint): number;
  freeString(ptr: number): void;
  destroy(handle: number): void;
}

interface SpecManifest {
  files: { path: string; size: number }[];
}

let mod: EmModule | null = null;
let api: DecompApi | null = null;
const sessions = new Map<number, number>();
let nextSession = 1;
let manifest: SpecManifest | null = null;
let initialized = false;

function bindApi(m: EmModule): DecompApi {
  return {
    addSpecDir: m.cwrap("decomp_add_spec_dir", "number", ["string"]) as DecompApi["addSpecDir"],
    create: m.cwrap("decomp_create", "number", ["string"]) as DecompApi["create"],
    addRegion: m.cwrap("decomp_add_region", "number", ["number", "bigint", "number", "number"]) as DecompApi["addRegion"],
    addSymbol: m.cwrap("decomp_add_symbol", "number", ["number", "bigint", "string"]) as DecompApi["addSymbol"],
    addImport: m.cwrap("decomp_add_import", "number", ["number", "bigint", "string"]) as DecompApi["addImport"],
    addReadonly: m.cwrap("decomp_add_readonly", "number", ["number", "bigint", "bigint"]) as DecompApi["addReadonly"],
    addString: m.cwrap("decomp_add_string", "number", ["number", "bigint", "bigint"]) as DecompApi["addString"],
    decompile: m.cwrap("decomp_decompile", "number", ["number", "bigint", "string"]) as DecompApi["decompile"],
    callTargets: m.cwrap("decomp_call_targets", "number", ["number", "bigint"]) as DecompApi["callTargets"],
    freeString: m.cwrap("decomp_free_string", null, ["number"]) as DecompApi["freeString"],
    destroy: m.cwrap("decomp_destroy", null, ["number"]) as DecompApi["destroy"],
  };
}

function mountLazyFile(FS: EmFS, relPath: string, url: string): void {
  const parts = relPath.split("/");
  let cur = "/spec";
  for (let i = 0; i < parts.length - 1; i++) {
    cur += "/" + parts[i];
    try { FS.mkdir(cur); } catch {}
  }
  FS.createLazyFile(cur, parts[parts.length - 1]!, url, true, false);
}

async function doInit(req: DecompInitRequest): Promise<void> {
  if (!mod) {
    const factoryUrl = "/decompile-engine/decompile_engine.js";
    const { default: factory } = (await import(/* @vite-ignore */ factoryUrl)) as {
      default: (overrides?: Record<string, unknown>) => Promise<EmModule>;
    };
    mod = await factory();
    api = bindApi(mod);
    try { mod.FS.mkdir("/spec"); } catch {}
  }

  if (initialized) return;
  initialized = true;

  if (!manifest) {
    const res = await fetch(req.manifestUrl);
    if (!res.ok) throw new Error(`fetch manifest ${req.manifestUrl}: ${res.status}`);
    manifest = (await res.json()) as SpecManifest;
  }

  const base = req.specBaseUrl.replace(/\/+$/, "") + "/";
  const langDirs = new Set<string>();
  for (const entry of manifest.files) {
    mountLazyFile(mod.FS, entry.path, base + entry.path);
    const parts = entry.path.split("/");
    if (parts[parts.length - 2] === "languages") {
      langDirs.add("/spec/" + parts.slice(0, -1).join("/"));
    }
  }
  for (const dir of langDirs) {
    if (api!.addSpecDir(dir) !== 0) throw new Error(`add_spec_dir(${dir}) failed`);
  }
}

function doOpen(req: DecompOpenRequest): number {
  if (!mod || !api) throw new Error("decompiler worker not initialized");
  if (req.regions.length === 0) throw new Error("open requires at least one region");

  const handle = api.create(req.languageId);
  if (!handle) throw new Error(`decompiler create failed for ${req.languageId}`);

  for (const region of req.regions) {
    const u8 = new Uint8Array(region.bytes);
    if (u8.length === 0) continue;
    const ptr = mod._malloc(u8.length);
    mod.HEAPU8.set(u8, ptr);
    api.addRegion(handle, BigInt(region.vaddr), ptr, u8.length);
    mod._free(ptr);
  }
  for (const [addr, name] of req.symbols) api.addSymbol(handle, BigInt(addr), name);
  for (const [addr, name] of req.imports) api.addImport(handle, BigInt(addr), name);
  for (const [addr, size] of req.readonly) api.addReadonly(handle, BigInt(addr), BigInt(size));
  for (const [addr, len] of req.strings) api.addString(handle, BigInt(addr), BigInt(len));

  const id = nextSession++;
  sessions.set(id, handle);
  return id;
}

function readCallTargets(handle: number, address: number): DecompCallTarget[] {
  if (!mod || !api) return [];
  const ptr = api.callTargets(handle, BigInt(address));
  if (!ptr) return [];
  const json = mod.UTF8ToString(ptr);
  api.freeString(ptr);
  try {
    return JSON.parse(json) as DecompCallTarget[];
  } catch {
    return [];
  }
}

function doDecompile(req: DecompileRequest): { code: string; calls: DecompCallTarget[] } {
  if (!mod || !api) throw new Error("decompiler worker not initialized");
  const handle = sessions.get(req.sessionId);
  if (handle == null) throw new Error(`unknown session ${req.sessionId}`);
  const ptr = api.decompile(handle, BigInt(req.address), req.name ?? "");
  if (!ptr) throw new Error("decompile returned null");
  const code = mod.UTF8ToString(ptr);
  api.freeString(ptr);
  const calls = readCallTargets(handle, req.address);
  return { code, calls };
}

function doCallTargets(req: DecompCallTargetsRequest): DecompCallTarget[] {
  if (!mod || !api) throw new Error("decompiler worker not initialized");
  const handle = sessions.get(req.sessionId);
  if (handle == null) throw new Error(`unknown session ${req.sessionId}`);
  return readCallTargets(handle, req.address);
}

function doClose(req: DecompCloseRequest): void {
  if (!api) return;
  const handle = sessions.get(req.sessionId);
  if (handle != null) {
    api.destroy(handle);
    sessions.delete(req.sessionId);
  }
}

self.addEventListener("message", async (ev: MessageEvent<DecompWorkerRequest>) => {
  const req = ev.data;
  const reply = (msg: DecompWorkerReply) => (self as unknown as Worker).postMessage(msg);
  try {
    switch (req.cmd) {
      case "init":
        await doInit(req);
        reply({ id: req.id, ok: true });
        break;
      case "open":
        reply({ id: req.id, ok: true, sessionId: doOpen(req) });
        break;
      case "decompile": {
        const { code, calls } = doDecompile(req);
        reply({ id: req.id, ok: true, code, calls });
        break;
      }
      case "callTargets":
        reply({ id: req.id, ok: true, calls: doCallTargets(req) });
        break;
      case "close":
        doClose(req);
        reply({ id: req.id, ok: true });
        break;
    }
  } catch (err) {
    reply({ id: req.id, ok: false, error: err instanceof Error ? err.message : String(err) });
  }
});
