import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import Editor, { type OnMount } from "@monaco-editor/react";

import type { ScanResult } from "../worker/protocol";
import type { DecompArch } from "../decompiler/arch-map";
import type { DecompFunction } from "../decompiler/protocol";
import { buildDecompInput } from "../decompiler/regions";
import { getDecompilerClient, type DecompilerSession } from "../decompiler/client";
import { setupMonaco } from "../decompiler/monaco-setup";

setupMonaco();

interface Props {
  result: ScanResult;
  bytes: ArrayBuffer;
  arch: DecompArch;
  target: { addr: number; nonce: number } | null;
}

const hex = (n: number) => "0x" + Math.max(0, Math.trunc(n)).toString(16);

function tokenToAddress(token: string, nameToAddr: Map<string, number>): number | null {
  let m = /^FUN_([0-9a-fA-F]+)$/.exec(token);
  if (m) return parseInt(m[1]!, 16);
  m = /^0x([0-9a-fA-F]+)$/.exec(token);
  if (m) return parseInt(m[1]!, 16);
  const known = nameToAddr.get(token);
  return known ?? null;
}

const FUN_TOKEN_RE = /FUN_([0-9a-f]+)/g;
function harvestFunAddrs(code: string): number[] {
  const out: number[] = [];
  FUN_TOKEN_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = FUN_TOKEN_RE.exec(code)) !== null) {
    const a = parseInt(m[1]!, 16);
    if (a > 0) out.push(a);
  }
  return out;
}

export function DecompilerPanel({ result, bytes, arch, target }: Props) {
  const input = useMemo(() => buildDecompInput(result, bytes), [result, bytes]);

  const [discovered, setDiscovered] = useState<Map<number, DecompFunction>>(new Map());
  const [discovering, setDiscovering] = useState(false);

  const allFunctions = useMemo(() => {
    const m = new Map<number, DecompFunction>();
    for (const f of input.functions) m.set(f.addr, f);
    for (const [a, f] of discovered) if (!m.has(a)) m.set(a, f);
    return [...m.values()].sort((x, y) => x.addr - y.addr);
  }, [input.functions, discovered]);

  const addrToName = useMemo(() => {
    const m = new Map<number, string>();
    for (const f of allFunctions) if (!m.has(f.addr)) m.set(f.addr, f.name);
    return m;
  }, [allFunctions]);
  const nameToAddr = useMemo(() => {
    const m = new Map<string, number>();
    for (const f of allFunctions) m.set(f.name, f.addr);
    for (const [a, n] of input.symbols) if (!m.has(n)) m.set(n, a);
    return m;
  }, [allFunctions, input.symbols]);

  const [session, setSession] = useState<DecompilerSession | null>(null);
  const [opening, setOpening] = useState(true);
  const [openErr, setOpenErr] = useState<string | null>(null);
  const [addr, setAddr] = useState<number | null>(null);
  const [code, setCode] = useState("");
  const [status, setStatus] = useState<"idle" | "loading" | "done" | "error">("idle");
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState("");

  const cache = useRef(new Map<number, string>());

  const seedAddrs = useMemo(() => new Set(input.functions.map((f) => f.addr)), [input.functions]);

  const mergeCallTargets = useCallback(
    (calls: { addr: number; name?: string }[]): number[] => {
      const fresh: number[] = [];
      setDiscovered((prev) => {
        let changed = false;
        const next = new Map(prev);
        for (const c of calls) {
          if (c.addr <= 0 || seedAddrs.has(c.addr) || next.has(c.addr)) continue;
          next.set(c.addr, { addr: c.addr, name: c.name || `FUN_${c.addr.toString(16)}`, kind: "discovered" });
          fresh.push(c.addr);
          changed = true;
        }
        return changed ? next : prev;
      });
      return fresh;
    },
    [seedAddrs],
  );

  useEffect(() => {
    let cancelled = false;
    let opened: DecompilerSession | null = null;
    setOpening(true);
    setOpenErr(null);
    setSession(null);
    cache.current.clear();
    setDiscovered(new Map());

    getDecompilerClient()
      .open({
        arch: arch.arch,
        languageId: arch.languageId,
        regions: input.regions,
        symbols: input.symbols,
        imports: input.imports,
        readonly: input.readonly,
        strings: input.strings,
        functions: input.functions,
      })
      .then((s) => {
        if (cancelled) { void s.close(); return; }
        opened = s;
        setSession(s);
        setOpening(false);
      })
      .catch((e) => {
        if (!cancelled) {
          setOpenErr((e as Error).message); setOpening(false);
        }
      });

    return () => {
      cancelled = true;
      if (opened) void opened.close();
    };
  }, [input, arch.arch, arch.languageId]);

  const decompile = useCallback(
    async (a: number) => {
      if (!session || a <= 0) return;
      setAddr(a);
      const hit = cache.current.get(a);
      if (hit !== undefined) { setCode(hit); setStatus("done"); setError(null); return; }
      setStatus("loading");
      setError(null);
      try {
        const { code: c, calls } = await session.decompile(a, addrToName.get(a));
        cache.current.set(a, c);
        setCode(c);
        setStatus("done");
        const ptrs = harvestFunAddrs(c).map((addr) => ({ addr }));
        mergeCallTargets([...calls, ...ptrs]);
      } catch (e) {
        setError((e as Error).message);
        setStatus("error");
      }
    },
    [session, addrToName, mergeCallTargets],
  );

  const MAX_DISCOVER = 4000;
  const runDiscovery = useCallback(
    async (seeds: number[]) => {
      if (!session || discovering) return;
      setDiscovering(true);

      const known = new Set<number>(seedAddrs);
      for (const a of discovered.keys()) known.add(a);

      const visited = new Set<number>();
      const queue: number[] = [];
      const enqueue = (a: number) => { if (a > 0 && !visited.has(a)) { visited.add(a); queue.push(a); } };
      for (const a of seeds) enqueue(a);

      let pending = new Map<number, DecompFunction>();
      const flush = () => {
        if (pending.size === 0) return;
        const batch = pending;
        pending = new Map();
        setDiscovered((prev) => {
          const next = new Map(prev);
          for (const [a, f] of batch) if (!next.has(a)) next.set(a, f);
          return next;
        });
      };

      try {
        while (queue.length > 0 && visited.size <= MAX_DISCOVER) {
          const a = queue.shift()!;
          let calls: { addr: number; name?: string }[];
          let codeText = cache.current.get(a);
          if (codeText !== undefined) {
            calls = await session.callTargets(a);
          } else {
            const out = await session.decompile(a, addrToName.get(a));
            cache.current.set(a, out.code);
            codeText = out.code;
            calls = out.calls;
          }

          const nameOf = new Map<number, string>();
          const neighbours = new Set<number>();
          for (const c of calls) {
            if (c.addr <= 0) continue;
            neighbours.add(c.addr);
            if (c.name) nameOf.set(c.addr, c.name);
          }
          for (const fa of harvestFunAddrs(codeText)) neighbours.add(fa);

          for (const n of neighbours) {
            if (!known.has(n)) {
              known.add(n);
              pending.set(n, {
                addr: n,
                name: nameOf.get(n) || addrToName.get(n) || `FUN_${n.toString(16)}`,
                kind: "discovered",
              });
            }
            enqueue(n);
          }
          if (pending.size >= 128) flush();
        }
        flush();
      } catch {
        flush();
      } finally {
        setDiscovering(false);
      }
    },
    [session, discovering, seedAddrs, discovered, addrToName],
  );

  const discoverAll = useCallback(() => {
    const seeds: number[] = [];
    if (input.entryPoint > 0) seeds.push(input.entryPoint);
    for (const f of input.functions) seeds.push(f.addr);
    for (const a of discovered.keys()) seeds.push(a);
    return runDiscovery(seeds);
  }, [runDiscovery, input.entryPoint, input.functions, discovered]);

  const discoverFromCurrent = useCallback(() => {
    if (addr == null || addr <= 0) return Promise.resolve();
    return runDiscovery([addr]);
  }, [runDiscovery, addr]);

  const decompileRef = useRef(decompile);
  decompileRef.current = decompile;
  const nameToAddrRef = useRef(nameToAddr);
  nameToAddrRef.current = nameToAddr;

  useEffect(() => {
    if (!session) return;
    const a = target?.addr ?? input.entryPoint ?? input.functions[0]?.addr ?? 0;
    if (a > 0) void decompile(a);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session, target?.addr, target?.nonce]);

  const handleMount: OnMount = (editor) => {
    editor.onMouseDown((e) => {
      if (!(e.event.ctrlKey || e.event.metaKey)) return;
      const pos = e.target.position;
      const model = editor.getModel();
      if (!pos || !model) return;
      const word = model.getWordAtPosition(pos);
      if (!word) return;
      const a = tokenToAddress(word.word, nameToAddrRef.current);
      if (a != null && a > 0) void decompileRef.current(a);
    });
  };

  const functions = useMemo(() => {
    const f = filter.trim().toLowerCase();
    if (!f) return allFunctions;
    return allFunctions.filter(
      (fn) => fn.name.toLowerCase().includes(f) || hex(fn.addr).includes(f),
    );
  }, [allFunctions, filter]);

  const discoveredCount = discovered.size;

  return (
    <div className="flex h-full min-h-0">
      <div className="w-72 shrink-0 border-r border-zinc-800 flex flex-col min-h-0">
        <div className="p-2 border-b border-zinc-800">
          <input
            type="text"
            placeholder="Filter functions..."
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            className="w-full px-2 py-1 text-xs bg-zinc-900 border border-zinc-800 rounded"
          />
          <div className="mt-1 text-[11px] text-zinc-500">
            {allFunctions.length.toLocaleString()} function(s)
            {discoveredCount ? <span className="text-emerald-500"> : +{discoveredCount} found</span> : null}
            {" : "}{arch.label}
          </div>
          <div className="mt-1.5 flex items-center gap-1.5">
            <button
              type="button"
              onClick={() => void discoverAll()}
              disabled={!session || discovering}
              title="Recursively decompile from the entry point and all known symbols, following calls to recover every reachable function a stripped binary's symbol table doesn't list"
              className="flex-1 px-2 py-0.5 text-[11px] rounded bg-zinc-800 hover:bg-zinc-700 disabled:text-zinc-600 whitespace-nowrap"
            >
              {discovering ? "Discovering..." : "Discover all"}
            </button>
            <button
              type="button"
              onClick={() => void discoverFromCurrent()}
              disabled={!session || discovering || addr == null}
              title="Recursively follow calls from the function shown on the right, chaining through its entire call subtree"
              className="flex-1 px-2 py-0.5 text-[11px] rounded bg-zinc-800 hover:bg-zinc-700 disabled:text-zinc-600 whitespace-nowrap"
            >
              Discover from current
            </button>
          </div>
        </div>
        <div className="flex-1 overflow-auto font-mono text-xs">
          {functions.length === 0 ? (
            <div className="px-3 py-6 text-center text-zinc-500">No functions match.</div>
          ) : (
            functions.map((fn) => (
              <button
                key={`${fn.addr}:${fn.name}`}
                type="button"
                onClick={() => void decompile(fn.addr)}
                className={
                  "block w-full text-left px-3 py-1 border-b border-zinc-900 hover:bg-zinc-900/60 truncate " +
                  (addr === fn.addr ? "bg-zinc-800 text-zinc-100" : "text-zinc-300")
                }
                title={`${fn.name} @ ${hex(fn.addr)}`}
              >
                <span className="text-zinc-600 mr-2">{hex(fn.addr)}</span>
                {fn.name}
                {fn.kind === "entry" ? <span className="ml-1 text-amber-400">←</span> : null}
                {fn.kind === "discovered" ? <span className="ml-1 text-emerald-500" title="found via call-graph discovery">·</span> : null}
              </button>
            ))
          )}
        </div>
      </div>

      <div className="flex-1 flex flex-col min-h-0">
        <div className="flex items-center gap-3 px-3 py-1.5 border-b border-zinc-800 text-xs text-zinc-500">
          <span className="font-mono text-zinc-300">{addr != null ? hex(addr) : "-"}</span>
          <span>
            {opening
              ? "loading decompiler..."
              : status === "loading"
                ? "decompiling..."
                : status === "error"
                  ? "error"
                  : status === "done"
                    ? "ready"
                    : ""}
          </span>
        </div>

        {openErr ? (
          <div className="p-4 text-red-400 text-xs font-mono">
            Could not start the decompiler: {openErr}
          </div>
        ) : error ? (
          <div className="px-3 py-1.5 text-red-400 text-xs font-mono border-b border-zinc-900">
            decompile failed: {error}
          </div>
        ) : null}

        <div className="flex-1 min-h-0">
          <Editor
            height="100%"
            language="cpp"
            theme="vs-dark"
            value={code}
            onMount={handleMount}
            options={{
              readOnly: true,
              fontSize: 12,
              minimap: { enabled: false },
              scrollBeyondLastLine: false,
              wordWrap: "off",
              renderLineHighlight: "none",
              smoothScrolling: true,
            }}
          />
        </div>
      </div>
    </div>
  );
}
