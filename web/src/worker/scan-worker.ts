
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
  ModuleLog,
  ExtractEntry,
  ExtractArchiveEntryRequest,
} from "./protocol";

import { runScan } from "../signature-runtime/runner";
import { scanStrings } from "./strings";
import { listZipEntries, looksLikeZip, extractZipEntry } from "./archive";

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

  try { mod.FS.mkdir("/signatures"); } catch {  }

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

async function fetchSignatureFile(relPath: string): Promise<string> {
  const res = await fetch(signaturesBaseUrl + relPath);
  if (!res.ok) throw new Error(`fetch ${relPath}: ${res.status}`);
  return await res.text();
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
  /^(?:8086|286|386|80[3-5]86|486|i386|x86|x86_?64|x64|amd64|aarch64|thumb|arm(?:nt|_v[67]s?|_a500|64(?:_32|e)?)?)$/i;

function timed<T>(
  log: ModuleLog[], module: string, fn: () => T, note?: (v: T) => string | undefined,
): T | null {
  const t = performance.now();
  try {
    const v = fn();
    log.push({ module, ok: true, durationMs: Math.round(performance.now() - t), note: note?.(v) });
    return v;
  } catch (e) {
    log.push({ module, ok: false, durationMs: Math.round(performance.now() - t), error: (e as Error).message });
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
  const moduleLogs: ModuleLog[] = [];
  const opts = req.options ?? {};
  const stringsMinLen = opts.stringsMinLen && opts.stringsMinLen >= 1 ? opts.stringsMinLen : 4;
  
  const optionsJson = JSON.stringify({
    deepScan: opts.deepScan, heuristicScan: opts.heuristicScan, aggressiveScan: opts.aggressiveScan,
    recursiveScan: opts.recursiveScan, overlayScan: opts.overlayScan, resourcesScan: opts.resourcesScan,
    archivesScan: opts.archivesScan, verbose: opts.verbose,
  });

  const fileInfo =
    timed(moduleLogs, "Format detection", () => getFileInfo(bytes),
      (fi) => `${fi.primaryFormat}${fi.allFormats.length > 1 ? ` (+${fi.allFormats.length - 1} more)` : ""}`) ??
    { size: bytes.byteLength, primaryFormat: "Unknown", allFormats: [] };
  const hashes =
    timed(moduleLogs, "Hashes", () => getHashes(bytes)) ?? { md5: "", sha1: "", sha256: "" };
  const entropy =
    timed(moduleLogs, "Entropy", () => getEntropy(bytes, 4096), (e) => `${e.length} windows @4 KiB`) ?? [];

  const sessionReply = openSession({ id: -1, cmd: "openSession", bytes: req.bytes, optionsJson });
  moduleLogs.push({ module: "Format parse", ok: true, durationMs: 0, note: `binding class: ${sessionReply.jsClass}` });
  const sessionPtr = sessions.get(sessionReply.sessionId)!;

  const memoryMap = timed(moduleLogs, "Memory map", () => getMemoryMap(sessionPtr),
    (m) => m ? `${m.records.length} regions · ${m.arch} ${m.mode} · EP 0x${m.entryPoint.toString(16)}`
             : "(not available for this format)");
  const structure = timed(moduleLogs, "Structure", () => getFormatStruct(sessionPtr),
    (st) => `${st.length} group(s)`) ?? [];
  const symRes = timed(moduleLogs, "Symbols", () => getSymbols(sessionPtr),
    (r) => `${r.symbols.length} symbol(s)${r.truncated ? " - truncated" : ""}`);
  const symbols = symRes?.symbols ?? [];
  const mime = timed(moduleLogs, "MIME", () => getMime(bytes), (m) => m.join(", ") || "(none)") ?? [];
  const extracted = timed(moduleLogs, "Extractor", () => getExtract(sessionPtr),
    (x) => `${x.length} embedded/overlay sub-file(s)`) ?? [];

  const disasmAvailable = !!memoryMap && DISASM_SUPPORTED_ARCH_RE.test(memoryMap.arch);
  
  if (disasmAvailable && memoryMap) {
    timed(moduleLogs, "Disassembly", () => disasmRange(sessionPtr, memoryMap.entryPoint, 8, "auto"),
      (d) => {
        const first = d.insns[0];
        const at = first ? ` @ 0x${first.address.toString(16)}` : "";
        return first
          ? `probe${at} (${d.mode}): ${d.insns.length} insn(s) - ${first.mnemonic}${first.operands ? " " + first.operands : ""} …`
          : `probe returned 0 instructions (${d.mode})`;
      });
  } else {
    moduleLogs.push({ module: "Disassembly", ok: true, durationMs: 0,
      note: memoryMap ? `arch ${memoryMap.arch || "?"}: not one of the linked Capstone backends (x86/x86-64, ARM, AArch64)`
                      : "no memory map" });
  }

  const strings = timed(moduleLogs, "Strings", () => scanStrings(bytes, { minLen: stringsMinLen, maxResults: 50_000 }),
    (s) => `${s.length} string(s) ≥${stringsMinLen} chars`) ?? [];

  let archive: ArchiveListing | null = null;
  if (!looksLikeZip(bytes)) {
    moduleLogs.push({ module: "Archive", ok: true, durationMs: 0, note: "not a ZIP-family file" });
  } else if (bytes.byteLength > ARCHIVE_LIST_MAX_BYTES) {
    moduleLogs.push({ module: "Archive", ok: true, durationMs: 0, note: "ZIP-family but too large - listing skipped" });
  } else {
    archive = timed(moduleLogs, "Archive",
      () => listZipEntries(bytes, ZIP_FAMILY.has(sessionReply.jsClass) ? sessionReply.jsClass : "ZIP-family"),
      (a) => a ? `${a.totalEntries} entr${a.totalEntries === 1 ? "y" : "ies"} (${a.kind})` : "(central directory not found)");
  }

  const sigT = performance.now();
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
    moduleLogs.push({ module: "Signatures", ok: false, durationMs: Math.round(performance.now() - sigT), error: (e as Error).message });
    closeSession({ id: -1, cmd: "closeSession", sessionId: sessionReply.sessionId });
    throw e;
  }
  moduleLogs.push({
    module: "Signatures",
    ok: sigResult.scriptsFailed === 0,
    durationMs: Math.round(performance.now() - sigT),
    note: `${sigResult.scriptsSucceeded}/${sigResult.scriptsAttempted} scripts ok · ${sigResult.records.length} detection(s)` +
          (sigResult.scriptsFailed ? ` · ${sigResult.scriptsFailed} failed` : ""),
    detail: sigResult.scriptsFailed
      ? sigResult.scriptOutcomes.filter((o) => !o.ok).slice(0, 50).map((o) => `${o.path}: ${o.error ?? "?"}`).join("\n")
      : undefined,
  });

  closeSession({ id: -1, cmd: "closeSession", sessionId: sessionReply.sessionId });

  return {
    fileInfo,
    hashes,
    entropy,
    records: sigResult.records,
    errors: sigResult.errors,
    debugLog: {
      fileSize: bytes.byteLength,
      jsClass: sessionReply.jsClass,
      scriptsAttempted: sigResult.scriptsAttempted,
      scriptsSucceeded: sigResult.scriptsSucceeded,
      scriptsFailed: sigResult.scriptsFailed,
      scriptOutcomes: sigResult.scriptOutcomes,
    },
    moduleLogs,
    memoryMap,
    strings,
    archive,
    structure,
    symbols,
    extracted,
    mime,
    disasmAvailable,
    durationMs: Math.round(performance.now() - t0),
  };
}

async function doExtractArchiveEntry(req: ExtractArchiveEntryRequest): Promise<ArrayBuffer> {
  const r = await extractZipEntry(new Uint8Array(req.bytes), req.entryName);
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
