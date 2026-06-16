import type {
  WorkerRequest,
  WorkerReply,
  InitRequest,
  ScanRequest,
  OpenSessionRequest,
  InvokeBindingRequest,
  InvokeHotRequest,
  CloseSessionRequest,
  DemangleRequest,
  DisasmRequest,
  YaraScanRequest,
  YaraScanResult,
  ScanResult,
  OpenSessionReply,
  EntropyPoint,
  Hashes,
  FileInfo,
  MemoryMap,
  ArchiveListing,
  StructNode,
  DisasmResult,
  DisasmMode,
  SymbolEntry,
  ExtractEntry,
  CertificateInfo,
  DebugInfo,
  ExtractArchiveEntryRequest,
} from "./protocol";

import { runScan } from "../signature-runtime/runner";
import { scanStrings } from "./strings";
import { listZipEntries, looksLikeZip, extractZipEntry } from "./archive";
import { listOle2, looksLikeOle2, extractOle2Stream } from "./ole2";
import { listCab, looksLikeCab, extractCabFile } from "./cab";
import { parseDebugInfo } from "./debug-info";

const ZIP_FAMILY = new Set(["ZIP", "JAR", "APK", "IPA", "NPM"]);
const ARCHIVE_LIST_MAX_BYTES = 512 * 1024 * 1024;

interface EmFS {
  mkdir(path: string): void;
  createLazyFile(parent: string, name: string, url: string, canRead: boolean, canWrite: boolean): unknown;
  writeFile(path: string, data: Uint8Array): void;
}
interface EmModule {
  FS: EmFS;
  HEAPU8: Uint8Array;
  ccall: (name: string, ret: string | null, argTypes: string[], args: unknown[]) => unknown;
  _malloc(size: number): number;
  _free(ptr: number): void;
  UTF8ToString(ptr: number): string;

  [key: string]: unknown;
}

let mod: EmModule | null = null;
let dieHandle: number | null = null;
let sessions = new Map<number, number>();
let nextSessionId = 1;

let manifest: SignaturePackManifest | null = null;
let signaturesBaseUrl = "";

interface SignaturePackManifest {
  version: number;
  dbs: Record<string, Record<string, { path: string; size: number; kind: string }[]>>;
}

async function doInit(req: InitRequest): Promise<void> {
  const factoryUrl: string = "/scan-engine/scan_engine.js";
  const { default: factory } = (await import(/* @vite-ignore */ factoryUrl)) as {
    default: (overrides?: Record<string, unknown>) => Promise<EmModule>;
  };
  mod = await factory();

  try { mod.FS.mkdir("/signatures"); } catch {}

  const manifestRes = await fetch(req.manifestUrl);
  manifest = (await manifestRes.json()) as SignaturePackManifest;
  signaturesBaseUrl = req.signaturesUrl.replace(/\/+$/, "") + "/";

  dieHandle = mod.ccall("die_create", "number", [], []) as number;
  if (!dieHandle) throw new Error("die_create returned null");

  const pathPtr = writeCString(mod, "/signatures");
  mod.ccall("die_set_signatures_root", "number", ["number", "number"],
            [dieHandle, pathPtr]);
  mod._free(pathPtr);
}

const sigCache = new Map<string, Promise<string>>();
function fetchSignatureFile(relPath: string): Promise<string> {
  const url = signaturesBaseUrl + relPath;
  let p = sigCache.get(url);
  if (!p) {
    p = (async () => {
      const res = await fetch(url);
      if (!res.ok) throw new Error(`fetch ${relPath}: ${res.status}`);
      return await res.text();
    })();
    p.catch(() => sigCache.delete(url));
    sigCache.set(url, p);
  }
  return p;
}

function getFileInfo(bytes: Uint8Array): FileInfo {
  if (!mod) throw new Error("not initialized");
  const ptr = mod._malloc(bytes.byteLength);
  mod.HEAPU8.set(bytes, ptr);
  const resPtr = mod.ccall("die_get_file_info", "number",
    ["number", "number"], [ptr, bytes.byteLength]) as number;
  const json = mod.UTF8ToString(resPtr);
  mod.ccall("die_free_string", null, ["number"], [resPtr]);
  mod._free(ptr);
  return JSON.parse(json) as FileInfo;
}

function getHashes(bytes: Uint8Array): Hashes {
  if (!mod) throw new Error("not initialized");
  const ptr = mod._malloc(bytes.byteLength);
  mod.HEAPU8.set(bytes, ptr);
  const resPtr = mod.ccall("die_compute_hashes", "number",
    ["number", "number"], [ptr, bytes.byteLength]) as number;
  const json = mod.UTF8ToString(resPtr);
  mod.ccall("die_free_string", null, ["number"], [resPtr]);
  mod._free(ptr);
  return JSON.parse(json) as Hashes;
}

function getImportHash(sessionPtr: number): Partial<Hashes> {
  if (!mod) throw new Error("not initialized");
  const resPtr = mod.ccall("die_get_import_hash", "number", ["number"], [sessionPtr]) as number;
  if (!resPtr) return {};
  const json = mod.UTF8ToString(resPtr);
  mod.ccall("die_free_string", null, ["number"], [resPtr]);
  return JSON.parse(json) as Partial<Hashes>;
}

function getCertificates(sessionPtr: number): CertificateInfo | null {
  if (!mod) throw new Error("not initialized");
  const resPtr = mod.ccall("die_get_certificates", "number", ["number"], [sessionPtr]) as number;
  if (!resPtr) return null;
  const json = mod.UTF8ToString(resPtr);
  mod.ccall("die_free_string", null, ["number"], [resPtr]);
  return JSON.parse(json) as CertificateInfo;
}

function getMemoryMap(sessionPtr: number): MemoryMap | null {
  if (!mod) throw new Error("not initialized");
  const resPtr = mod.ccall("die_get_memory_map", "number",
    ["number"], [sessionPtr]) as number;
  if (!resPtr) return null;
  const json = mod.UTF8ToString(resPtr);
  mod.ccall("die_free_string", null, ["number"], [resPtr]);
  return JSON.parse(json) as MemoryMap;
}

function getFormatStruct(sessionPtr: number): StructNode[] {
  if (!mod) throw new Error("not initialized");
  const resPtr = mod.ccall("die_get_format_struct", "number",
    ["number"], [sessionPtr]) as number;
  if (!resPtr) return [];
  const json = mod.UTF8ToString(resPtr);
  mod.ccall("die_free_string", null, ["number"], [resPtr]);
  return JSON.parse(json) as StructNode[];
}

const DISASM_MODE_INT: Record<DisasmMode, number> = { auto: 0, arm: 1, thumb: 2, cortexm: 3 };

function disasmRange(sessionPtr: number, address: number, count: number, mode: DisasmMode): DisasmResult {
  if (!mod) throw new Error("not initialized");
  const resPtr = mod.ccall("die_disasm_range", "number",
    ["number", "number", "number", "number"],
    [sessionPtr, address, count, DISASM_MODE_INT[mode]]) as number;
  if (!resPtr) return { mode: "unknown", insns: [] };
  const json = mod.UTF8ToString(resPtr);
  mod.ccall("die_free_string", null, ["number"], [resPtr]);
  return JSON.parse(json) as DisasmResult;
}

function getSymbols(sessionPtr: number): { symbols: SymbolEntry[]; truncated: boolean } {
  if (!mod) throw new Error("not initialized");
  const resPtr = mod.ccall("die_get_symbols", "number", ["number"], [sessionPtr]) as number;
  if (!resPtr) return { symbols: [], truncated: false };
  const json = mod.UTF8ToString(resPtr);
  mod.ccall("die_free_string", null, ["number"], [resPtr]);
  return JSON.parse(json) as { symbols: SymbolEntry[]; truncated: boolean };
}

function getMime(bytes: Uint8Array): string[] {
  if (!mod) throw new Error("not initialized");
  const ptr = mod._malloc(bytes.byteLength || 1);
  if (bytes.byteLength) mod.HEAPU8.set(bytes, ptr);
  const resPtr = mod.ccall("die_get_mime", "number", ["number", "number"], [ptr, bytes.byteLength]) as number;
  mod._free(ptr);
  if (!resPtr) return [];
  const json = mod.UTF8ToString(resPtr);
  mod.ccall("die_free_string", null, ["number"], [resPtr]);
  return JSON.parse(json) as string[];
}

function getExtract(sessionPtr: number): ExtractEntry[] {
  if (!mod) throw new Error("not initialized");
  const resPtr = mod.ccall("die_extract", "number", ["number"], [sessionPtr]) as number;
  if (!resPtr) return [];
  const json = mod.UTF8ToString(resPtr);
  mod.ccall("die_free_string", null, ["number"], [resPtr]);
  return JSON.parse(json) as ExtractEntry[];
}

const DISASM_SUPPORTED_ARCH_RE =
  /^(?:8086|286|386|80[3-5]86|486|i386|x86|x86_?64|x64|amd64|aarch64|thumb|arm(?:nt|_v[67]s?|_a500|64(?:_32|e)?)?|mips|r3000|r4000|r10000|wcemipsv2|ppc|ppc64|powerpc|powerpc_be|risc_v|riscv32|riscv64)$/i;

function safe<T>(fn: () => T): T | null {
  try {
    return fn();
  } catch {
    return null;
  }
}

function demangleSymbol(name: string): string | null {
  if (!mod) throw new Error("not initialized");
  const namePtr = writeCString(mod, name);
  const resPtr = mod.ccall("die_demangle", "number",
    ["number"], [namePtr]) as number;
  mod._free(namePtr);
  if (!resPtr) return null;
  const out = mod.UTF8ToString(resPtr);
  mod.ccall("die_free_string", null, ["number"], [resPtr]);
  return out;
}

function getEntropy(bytes: Uint8Array, windowSize: number): EntropyPoint[] {
  if (!mod) throw new Error("not initialized");
  const ptr = mod._malloc(bytes.byteLength);
  mod.HEAPU8.set(bytes, ptr);
  const resPtr = mod.ccall("die_compute_entropy", "number",
    ["number", "number", "number"], [ptr, bytes.byteLength, windowSize]) as number;
  const json = mod.UTF8ToString(resPtr);
  mod.ccall("die_free_string", null, ["number"], [resPtr]);
  mod._free(ptr);
  return JSON.parse(json) as EntropyPoint[];
}

function openSession(req: OpenSessionRequest): OpenSessionReply {
  if (!mod || !dieHandle) throw new Error("not initialized");
  const bytes = new Uint8Array(req.bytes);
  const ptr = mod._malloc(bytes.byteLength);
  mod.HEAPU8.set(bytes, ptr);
  const optsPtr = req.optionsJson ? writeCString(mod, req.optionsJson) : 0;

  const sessionPtr = mod.ccall("die_open_session", "number",
    ["number", "number", "number", "number"],
    [dieHandle, ptr, bytes.byteLength, optsPtr]) as number;

  mod._free(ptr);
  if (optsPtr) mod._free(optsPtr);
  if (!sessionPtr) throw new Error("die_open_session returned null");

  const jsClassPtr = mod.ccall("die_session_jsclass", "number",
    ["number"], [sessionPtr]) as number;
  const jsClass = mod.UTF8ToString(jsClassPtr);
  mod.ccall("die_free_string", null, ["number"], [jsClassPtr]);

  const sessionId = nextSessionId++;
  sessions.set(sessionId, sessionPtr);

  const fileInfo = getFileInfo(bytes);

  return { sessionId, jsClass, fileInfo };
}

function closeSession(req: CloseSessionRequest): void {
  if (!mod) return;
  const ptr = sessions.get(req.sessionId);
  if (ptr == null) return;
  mod.ccall("die_close_session", null, ["number"], [ptr]);
  sessions.delete(req.sessionId);
}

function invokeBinding(req: InvokeBindingRequest): unknown {
  if (!mod) throw new Error("not initialized");
  const ptr = sessions.get(req.sessionId);
  if (ptr == null) throw new Error(`unknown session ${req.sessionId}`);

  const safeArgs = req.args.map((a) => (typeof a === "bigint" ? Number(a) : a));
  const argsJson = JSON.stringify(safeArgs);
  const argsPtr = writeCString(mod, argsJson);
  const resPtr = mod.ccall("die_invoke", "number",
    ["number", "number", "number"],
    [ptr, req.methodId, argsPtr]) as number;
  mod._free(argsPtr);

  if (!resPtr) return null;
  const json = mod.UTF8ToString(resPtr);
  mod.ccall("die_free_string", null, ["number"], [resPtr]);
  const env = JSON.parse(json) as { result: unknown };
  return env.result;
}

function invokeHot(req: InvokeHotRequest): unknown {
  if (!mod) throw new Error("not initialized");
  const ptr = sessions.get(req.sessionId);
  if (ptr == null) throw new Error(`unknown session ${req.sessionId}`);

  const argTypes: string[] = ["number"];
  const ccallArgs: unknown[] = [ptr];
  const allocated: number[] = [];

  for (const a of req.args) {
    if (typeof a === "string") {
      const p = writeCString(mod, a);
      argTypes.push("number");
      ccallArgs.push(p);
      allocated.push(p);
    } else if (typeof a === "boolean") {
      argTypes.push("number");
      ccallArgs.push(a ? 1 : 0);
    } else if (typeof a === "number") {
      argTypes.push("number");
      ccallArgs.push(a);
    } else if (typeof a === "bigint") {
      argTypes.push("number");
      ccallArgs.push(Number(a));
    } else if (a == null) {
      argTypes.push("number");
      ccallArgs.push(0);
    } else {
      throw new Error(`unsupported hot-path arg type: ${typeof a}`);
    }
  }

  const result = mod.ccall(req.exportName.replace(/^_/, ""),
    "number", argTypes, ccallArgs);
  const numeric = typeof result === "bigint" ? Number(result) : result;

  for (const p of allocated) mod._free(p);
  return numeric;
}

async function doScan(req: ScanRequest): Promise<ScanResult> {
  if (!mod || !dieHandle || !manifest) throw new Error("not initialized");
  const t0 = performance.now();
  const bytes = new Uint8Array(req.bytes);
  const opts = req.options ?? {};
  const stringsMinLen = opts.stringsMinLen && opts.stringsMinLen >= 1 ? opts.stringsMinLen : 4;

  const optionsJson = JSON.stringify({
    deepScan: opts.deepScan, heuristicScan: opts.heuristicScan, aggressiveScan: opts.aggressiveScan,
    recursiveScan: opts.recursiveScan, overlayScan: opts.overlayScan, resourcesScan: opts.resourcesScan,
    archivesScan: opts.archivesScan, verbose: opts.verbose,
  });

  const fileInfo = safe(() => getFileInfo(bytes)) ??
    { size: bytes.byteLength, primaryFormat: "Unknown", allFormats: [] };
  const hashes = safe(() => getHashes(bytes)) ?? { md5: "", sha1: "", sha256: "" };
  const entropy = safe(() => getEntropy(bytes, 4096)) ?? [];

  const sessionReply = openSession({ id: -1, cmd: "openSession", bytes: req.bytes, optionsJson });
  const sessionPtr = sessions.get(sessionReply.sessionId)!;

  for (const e of [...(manifest.dbs.db?.[sessionReply.jsClass] ?? []),
                   ...(manifest.dbs.db_extra?.[sessionReply.jsClass] ?? [])])
    if (e.kind === "sg") void fetchSignatureFile(e.path).catch(() => {});

  const memoryMap = safe(() => getMemoryMap(sessionPtr));
  const structure = safe(() => getFormatStruct(sessionPtr)) ?? [];
  const symbols = safe(() => getSymbols(sessionPtr))?.symbols ?? [];
  const mime = safe(() => getMime(bytes)) ?? [];
  const extracted = safe(() => getExtract(sessionPtr)) ?? [];

  const importHash = safe(() => getImportHash(sessionPtr)) ?? {};
  const hashesFull: Hashes = { ...hashes, ...importHash };

  const certificates = safe(() => getCertificates(sessionPtr)) ?? null;

  const debugInfo: DebugInfo[] = safe(() => parseDebugInfo(bytes)) ?? [];

  const disasmAvailable = !!memoryMap && DISASM_SUPPORTED_ARCH_RE.test(memoryMap.arch);

  const strings = safe(() => scanStrings(bytes, { minLen: stringsMinLen, maxResults: 50_000 })) ?? [];

  let archive: ArchiveListing | null = null;
  if (bytes.byteLength <= ARCHIVE_LIST_MAX_BYTES) {
    if (looksLikeZip(bytes)) {
      archive = safe(() =>
        listZipEntries(bytes, ZIP_FAMILY.has(sessionReply.jsClass) ? sessionReply.jsClass : "ZIP-family"));
    } else if (looksLikeCab(bytes)) {
      archive = safe(() => listCab(bytes, "Microsoft Cabinet (CAB)"));
    } else if (looksLikeOle2(bytes)) {
      archive = safe(() => listOle2(bytes, "OLE2 Compound File"));
    }
  }

  let sigResult;
  try {
    sigResult = await runScan({
      jsClass: sessionReply.jsClass,
      sessionId: sessionReply.sessionId,
      verbose: opts.verbose,
      invokeHot: (exportName, args) =>
        invokeHot({ id: -1, cmd: "invokeHot", sessionId: sessionReply.sessionId, exportName, args }),
      invokeBinding: (methodId, args) =>
        invokeBinding({ id: -1, cmd: "invokeBinding", sessionId: sessionReply.sessionId, methodId, args }),
      fetchSignatureFile,
      manifest,
    });
  } catch (e) {
    closeSession({ id: -1, cmd: "closeSession", sessionId: sessionReply.sessionId });
    throw e;
  }

  closeSession({ id: -1, cmd: "closeSession", sessionId: sessionReply.sessionId });

  return {
    fileInfo,
    hashes: hashesFull,
    entropy,
    records: sigResult.records,
    errors: sigResult.errors,
    formatClass: sessionReply.jsClass,
    memoryMap,
    strings,
    archive,
    structure,
    symbols,
    extracted,
    mime,
    certificates,
    debugInfo,
    disasmAvailable,
    durationMs: Math.round(performance.now() - t0),
  };
}

async function doExtractArchiveEntry(req: ExtractArchiveEntryRequest): Promise<ArrayBuffer> {
  const bytes = new Uint8Array(req.bytes);
  const r = looksLikeOle2(bytes)
    ? extractOle2Stream(bytes, req.entryName)
    : looksLikeCab(bytes)
      ? extractCabFile(bytes, req.entryName)
      : await extractZipEntry(bytes, req.entryName, req.password);
  if ("error" in r) throw new Error(r.error);

  return r.data.buffer;
}

function doYaraScan(req: YaraScanRequest): YaraScanResult {
  if (!mod) throw new Error("not initialized");
  const bytes = new Uint8Array(req.bytes);
  const bp = mod._malloc(bytes.byteLength || 1);
  if (bytes.byteLength) mod.HEAPU8.set(bytes, bp);
  const rp = writeCString(mod, JSON.stringify(req.units ?? []));
  const resPtr = mod.ccall("die_yara_scan", "number",
    ["number", "number", "number"], [bp, bytes.byteLength, rp]) as number;
  mod._free(bp);
  mod._free(rp);
  if (!resPtr) throw new Error("die_yara_scan returned null");
  const json = mod.UTF8ToString(resPtr);
  mod.ccall("die_free_string", null, ["number"], [resPtr]);
  return JSON.parse(json) as YaraScanResult;
}

function doDisasm(req: DisasmRequest): DisasmResult {
  if (!mod || !dieHandle) throw new Error("not initialized");
  const bytes = new Uint8Array(req.bytes);
  const ptr = mod._malloc(bytes.byteLength);
  mod.HEAPU8.set(bytes, ptr);
  const sessionPtr = mod.ccall("die_open_session", "number",
    ["number", "number", "number", "number"], [dieHandle, ptr, bytes.byteLength, 0]) as number;
  mod._free(ptr);
  if (!sessionPtr) throw new Error("die_open_session returned null");
  try {
    return disasmRange(sessionPtr, req.address, req.count, req.mode ?? "auto");
  } finally {
    mod.ccall("die_close_session", null, ["number"], [sessionPtr]);
  }
}

function writeCString(m: EmModule, s: string): number {
  const bytes = new TextEncoder().encode(s + "\0");
  const ptr = m._malloc(bytes.byteLength);
  m.HEAPU8.set(bytes, ptr);
  return ptr;
}

self.addEventListener("message", async (ev: MessageEvent<WorkerRequest>) => {
  const req = ev.data;
  const reply = (msg: WorkerReply, transfer: Transferable[] = []) =>
    (self as unknown as Worker).postMessage(msg, transfer);

  try {
    switch (req.cmd) {
      case "init":
        await doInit(req);
        reply({ id: req.id, ok: true, result: null });
        break;
      case "scan":
        reply({ id: req.id, ok: true, result: await doScan(req) });
        break;
      case "openSession":
        reply({ id: req.id, ok: true, result: openSession(req) });
        break;
      case "invokeBinding":
        reply({ id: req.id, ok: true, result: invokeBinding(req) });
        break;
      case "invokeHot":
        reply({ id: req.id, ok: true, result: invokeHot(req) });
        break;
      case "closeSession":
        closeSession(req);
        reply({ id: req.id, ok: true, result: null });
        break;
      case "demangle":
        reply({ id: req.id, ok: true, result: demangleSymbol((req as DemangleRequest).name) });
        break;
      case "disasm":
        reply({ id: req.id, ok: true, result: doDisasm(req) });
        break;
      case "yaraScan":
        reply({ id: req.id, ok: true, result: doYaraScan(req) });
        break;
      case "extractArchiveEntry": {
        const buf = await doExtractArchiveEntry(req);
        reply({ id: req.id, ok: true, result: buf }, [buf]);
        break;
      }
    }
  } catch (err) {
    reply({
      id: req.id,
      ok: false,
      error: err instanceof Error ? err.message : String(err),
    });
  }
});
