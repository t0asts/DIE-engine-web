
import { makeBindings, METHOD_IDS, bindingChain } from "../wasm-bindings/_generated";
import type { SessionHandle } from "../wasm-bindings/session";
import type { ScanRecord } from "../worker/protocol";

export interface RunScanOpts {
  jsClass: string;                        
  sessionId: number;
  verbose?: boolean;                      
  invokeHot(exportName: string, args: unknown[]): unknown;
  invokeBinding(methodId: number, args: unknown[]): unknown;
  fetchSignatureFile(relPath: string): Promise<string>;
  manifest: {
    version: number;
    dbs: Record<string, Record<string, { path: string; size: number; kind: string }[]>>;
  };
}

export interface ScriptOutcome {
  path: string;
  ok: boolean;
  durationMs: number;
  records: number;            
  error?: string;
  logs?: string[];            
}

export interface RunScanResult {
  records: ScanRecord[];
  errors: string[];
  scriptOutcomes: ScriptOutcome[];   
  scriptsAttempted: number;
  scriptsSucceeded: number;
  scriptsFailed: number;
}

interface SigEntry { path: string; size: number; kind: string }

export async function runScan(opts: RunScanOpts): Promise<RunScanResult> {
  patchPrototypesOnce();

  const session: SessionHandle = {
    hot:    (name, args) => opts.invokeHot(name, args),
    invoke: (id, args)   => opts.invokeBinding(id, args),
  };
  const allBindings = makeBindings(session) as unknown as Record<string, Record<string, unknown>>;

  const rawBinding: Record<string, unknown> = {};
  for (const cls of bindingChain(opts.jsClass)) {
    const layer = allBindings[cls];
    if (layer) Object.assign(rawBinding, layer);
  }

  const verbose = opts.verbose ?? true;
  rawBinding.isVerbose = () => verbose;

  const wrapCache = new Map<string, (...a: unknown[]) => unknown>();
  const bindingObj: Record<string, unknown> = new Proxy(rawBinding, {
    get(target, prop, receiver) {
      const val = Reflect.get(target, prop, receiver);
      if (typeof val !== "function") return val;
      const name = String(prop);
      const cached = wrapCache.get(name);
      if (cached && (cached as { __orig?: unknown }).__orig === val) return cached;
      const fn = val as (...a: unknown[]) => unknown;
      const wrapped = function (this: unknown, ...args: unknown[]) {
        try {
          return fn.apply(this === receiver ? target : this, args);
        } catch (e) {
          const fmtArgs = args
            .map((a) =>
              typeof a === "string"
                ? JSON.stringify(a.length > 40 ? a.slice(0, 40) + "…" : a)
                : typeof a === "bigint" ? `${a}n`
                : a === undefined ? "undefined"
                : a === null ? "null"
                : String(a),
            )
            .join(", ");
          const inner = e instanceof Error ? e.message : String(e);
          const wrappedErr = new Error(`${opts.jsClass}.${name}(${fmtArgs}) → ${inner}`);
          if (e instanceof Error && e.stack) wrappedErr.stack = e.stack;
          throw wrappedErr;
        }
      };
      (wrapped as { __orig?: unknown }).__orig = val;
      wrapCache.set(name, wrapped);
      return wrapped;
    },
  });

  const rootEntries: SigEntry[] = opts.manifest.dbs.db?.["_root"] ?? [];
  const rootInitEntry = rootEntries.find((e) => e.kind === "init" && basename(e.path) === "_init");

  const dbFmtEntries: SigEntry[]    = opts.manifest.dbs.db?.[opts.jsClass]       ?? [];
  const extraFmtEntries: SigEntry[] = opts.manifest.dbs.db_extra?.[opts.jsClass] ?? [];
  const formatInitEntry = dbFmtEntries.find((e) => e.kind === "init")
                       ?? extraFmtEntries.find((e) => e.kind === "init");

  const sgEntries: SigEntry[] = [
    ...dbFmtEntries.filter((e) => e.kind === "sg"),
    ...extraFmtEntries.filter((e) => e.kind === "sg"),
  ].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));

  const fileCache = new Map<string, string>();
  async function loadFile(rel: string): Promise<string> {
    let v = fileCache.get(rel);
    if (v === undefined) { v = await opts.fetchSignatureFile(rel); fileCache.set(rel, v); }
    return v;
  }
  async function resolveInclude(name: string): Promise<string | null> {
    const want = name.toLowerCase();
    const hit = rootEntries.find((e) => basename(e.path).toLowerCase() === want);
    return hit ? await loadFile(hit.path) : null;
  }

  const rootInitSource   = rootInitEntry   ? await loadFile(rootInitEntry.path)   : "";
  const formatInitSource = formatInitEntry ? await loadFile(formatInitEntry.path) : "";

  const allRecords: ScanRecord[] = [];
  const errors: string[] = [];
  const scriptOutcomes: ScriptOutcome[] = [];

  if (!rootInitEntry) {
    errors.push("db/_init (framework prelude) missing from signature pack - detections will fail");
  }

  for (const sg of sgEntries) {
    const logs: string[] = [];
    const t0 = performance.now();
    const recordsBefore = allRecords.length;
    let ok = true;
    let outcomeError: string | undefined;
    try {
      const sgSource = await loadFile(sg.path);
      await evalScript(
        { rootInitSource, formatInitSource, sgSource, resolveInclude },
        { binding: bindingObj, fmt: opts.jsClass, records: allRecords, logs },
      );
    } catch (e) {
      ok = false;
      const err = e as Error | string;
      const msg = typeof err === "string" ? err : err.message;
      const stackHead = typeof err !== "string" && err.stack
        ? "\n  " + err.stack.split("\n").slice(0, 4).join("\n  ")
        : "";
      outcomeError = msg + stackHead;
      errors.push(`${sg.path}: ${msg}`);
    }
    const outcome: ScriptOutcome = {
      path: sg.path,
      ok,
      durationMs: Math.round((performance.now() - t0) * 100) / 100,
      records: allRecords.length - recordsBefore,
    };
    if (outcomeError) outcome.error = outcomeError;
    if (logs.length) outcome.logs = logs;
    scriptOutcomes.push(outcome);
  }

  const scriptsAttempted = scriptOutcomes.length;
  const scriptsFailed = scriptOutcomes.filter((o) => !o.ok).length;
  return {
    records: allRecords,
    errors,
    scriptOutcomes,
    scriptsAttempted,
    scriptsSucceeded: scriptsAttempted - scriptsFailed,
    scriptsFailed,
  };
}

interface EvalSource {
  rootInitSource: string;
  formatInitSource: string;
  sgSource: string;
  resolveInclude(name: string): Promise<string | null>;
}
interface EvalCtx {
  binding: unknown;
  fmt: string;
  records: ScanRecord[];   
  logs: string[];          
}

const INCLUDE_RE = /includeScript\(\s*["']([^"']+)["']\s*\)\s*;?/g;

async function evalScript(src: EvalSource, ctx: EvalCtx): Promise<void> {
  const seen = new Set<string>();

  async function inline(source: string): Promise<string> {
    INCLUDE_RE.lastIndex = 0;
    const hits: { idx: number; len: number; name: string }[] = [];
    let m: RegExpExecArray | null;
    while ((m = INCLUDE_RE.exec(source)) !== null) {
      hits.push({ idx: m.index, len: m[0].length, name: m[1]! });
    }
    if (hits.length === 0) return source;

    let out = "";
    let last = 0;
    for (const h of hits) {
      out += source.slice(last, h.idx);
      last = h.idx + h.len;
      const key = h.name.toLowerCase();
      if (seen.has(key)) continue;       
      seen.add(key);
      const inc = await src.resolveInclude(h.name);
      if (inc != null) {
        out += `\n/* >>> includeScript(${JSON.stringify(h.name)}) */\n`
             + (await inline(inc))
             + `\n/* <<< end ${h.name} */\n`;
      } else {
        out += `\n/* includeScript(${JSON.stringify(h.name)}): NOT FOUND */\n`;
      }
    }
    out += source.slice(last);
    return out;
  }

  const rootBody   = src.rootInitSource   ? await inline(src.rootInitSource)   : "";
  const formatBody = src.formatInitSource ? await inline(src.formatInitSource) : "";
  const sgBody     = await inline(src.sgSource);

  const fullSource =
    rootBody + "\n" +
    formatBody + "\n" +
    sgBody + "\n" +
    ";if (typeof detect === 'function') { detect(true, true, true); }\n";

  const pushRecord = (t: unknown, n: unknown, v?: unknown, o?: unknown) => {
    const rec: ScanRecord = { type: String(t ?? ""), name: String(n ?? "") };
    const vs = v == null ? "" : String(v);
    const os = o == null ? "" : String(o);
    if (vs) rec.version = vs;
    if (os) rec.options = os;
    ctx.records.push(rec);
  };

  const injected: Record<string, unknown> = {
    [ctx.fmt]: ctx.binding,
    Binary: ctx.binding,
    File:   ctx.binding,
    X:      ctx.binding,
    Util:   UTIL,

    includeScript: (_name?: unknown) => undefined,

    _log: (s?: unknown) => { ctx.logs.push(String(s ?? "")); },
    _setResult: pushRecord,
    _isResultPresent: (t?: unknown, n?: unknown) =>
      ctx.records.some((r) => r.type === String(t ?? "") && r.name === String(n ?? "")),
    _getNumberOfResults: (t?: unknown) =>
      ctx.records.reduce((c, r) => (r.type === String(t ?? "") ? c + 1 : c), 0),
    _removeResult: (t?: unknown, n?: unknown) => {
      const ts = String(t ?? ""), ns = String(n ?? "");
      for (let i = ctx.records.length - 1; i >= 0; i--) {
        const r = ctx.records[i]!;
        if (r.type === ts && r.name === ns) ctx.records.splice(i, 1);
      }
    },
    _isStop: () => false,
    _breakScan: () => undefined,
    _encodingList: () => ["System", "UTF-8", "UTF-16", "UTF-32", "Latin1", "ASCII"],
    _isConsoleMode: () => false,
    _isLiteMode: () => false,
    _isGuiMode: () => false,
    _isLibraryMode: () => true,
    _getEngineVersion: () => "die-web/0.1",
    _getOS: () => "browser",
    _getQtVersion: () => "",
  };

  const keys = Object.keys(injected);
  const vals = keys.map((k) => injected[k]);
  // eslint-disable-next-line @typescript-eslint/no-implied-eval, no-new-func
  const fn = new Function(...keys, fullSource);
  try {
    fn(...vals);
  } catch (e) {
    const err = e as Error | string;
    const msg = typeof err === "string" ? err : err.message;
    const wrapped = new Error(`script error: ${msg}`);
    if (typeof err !== "string" && err.stack) wrapped.stack = err.stack;
    throw wrapped;
  }
}

const UTIL = {
  shlu64: (v: number, s: number) =>
    Number(BigInt.asUintN(64, BigInt.asUintN(64, BigInt(Math.trunc(v))) << BigInt(Math.trunc(s)))),
  shru64: (v: number, s: number) =>
    Number(BigInt.asUintN(64, BigInt(Math.trunc(v))) >> BigInt(Math.trunc(s))),
  shl64: (v: number, s: number) =>
    Number(BigInt.asIntN(64, BigInt(Math.trunc(v)) << BigInt(Math.trunc(s)))),
  shr64: (v: number, s: number) =>
    Number(BigInt.asIntN(64, BigInt(Math.trunc(v)) >> BigInt(Math.trunc(s)))),
  divu64: (a: number, b: number) =>
    (Math.trunc(b) === 0 ? 0 : Math.floor(Math.abs(Math.trunc(a)) / Math.abs(Math.trunc(b)))),
  div64: (a: number, b: number) =>
    (Math.trunc(b) === 0 ? 0 : Math.trunc(Math.trunc(a) / Math.trunc(b))),
  secondsToTimeStr: (n: number) => {
    const s = Math.max(0, Math.trunc(n));
    const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
    return `${h}:${String(m).padStart(2, "0")}:${String(sec).padStart(2, "0")}`;
  },
};

let patched = false;
function patchPrototypesOnce(): void {
  if (patched) return;
  patched = true;
  const proto = String.prototype as unknown as { append?: unknown };
  if (typeof proto.append !== "function") {
    Object.defineProperty(String.prototype, "append", {
      value: function (this: string, ...parts: string[]): string {
        let str = String(this);
        if (parts.length) {
          if (str.length) str += ", ";
          str += parts.join(", ");
        }
        return str;
      },
      writable: true,
      configurable: true,
    });
  }
}

function basename(p: string): string {
  const i = p.lastIndexOf("/");
  return i < 0 ? p : p.slice(i + 1);
}

void METHOD_IDS;
