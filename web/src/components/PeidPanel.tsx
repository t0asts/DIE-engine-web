import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import type { MemoryMap } from "../worker/protocol";

interface Props {
  bytes: ArrayBuffer;
  memoryMap: MemoryMap | null;
}

interface PeidSig { name: string; pattern: (number | null)[]; epOnly: boolean; }

const BUNDLED_URL = "/signatures-pack/peid/userdb.txt";
const NONEP_SEARCH_CAP = 8 * 1024 * 1024;

function parseUserDb(text: string): PeidSig[] {
  const out: PeidSig[] = [];
  let name = "";
  let pattern: (number | null)[] | null = null;
  let epOnly = false;
  const flush = () => { if (name && pattern && pattern.length) out.push({ name, pattern, epOnly }); };
  for (const lineRaw of text.split(/\r?\n/)) {
    const line = lineRaw.trim();
    if (!line || line.startsWith(";")) continue;
    if (line.startsWith("[") && line.endsWith("]")) {
      flush();
      name = line.slice(1, -1).trim();
      pattern = null; epOnly = false;
      continue;
    }
    const eq = line.indexOf("=");
    if (eq < 0) continue;
    const key = line.slice(0, eq).trim().toLowerCase();
    const val = line.slice(eq + 1).trim();
    if (key === "signature") {
      pattern = val.split(/\s+/).filter(Boolean).map((tok) =>
        /^\?\?$|^\?$/.test(tok) ? null : (parseInt(tok, 16) & 0xff));
    } else if (key === "ep_only") {
      epOnly = /^true$/i.test(val);
    }
  }
  flush();
  return out;
}

function matchAt(view: Uint8Array, off: number, pat: (number | null)[]): boolean {
  if (off < 0 || off + pat.length > view.length) return false;
  for (let i = 0; i < pat.length; i++) {
    const p = pat[i];
    if (p !== null && view[off + i] !== p) return false;
  }
  return true;
}

function findFirst(view: Uint8Array, limit: number, pat: (number | null)[]): number {
  const end = Math.min(view.length, limit) - pat.length;
  const p0 = pat[0];
  for (let off = 0; off <= end; off++) {
    if (p0 !== null && view[off] !== p0) continue;
    if (matchAt(view, off, pat)) return off;
  }
  return -1;
}

function epFileOffset(mm: MemoryMap | null): number | null {
  if (!mm || !(mm.entryPoint > 0)) return null;
  const ep = mm.entryPoint;
  for (const r of mm.records) {
    if (r.isVirtual || r.offset < 0 || r.size <= 0) continue;
    if (ep >= r.address && ep < r.address + r.size) return r.offset + (ep - r.address);
  }
  return null;
}

interface Hit { name: string; epOnly: boolean; offset: number; }

function scan(view: Uint8Array, mm: MemoryMap | null, sigs: PeidSig[]): { hits: Hit[]; epOff: number | null; partialNonEp: boolean } {
  const epOff = epFileOffset(mm);
  const seen = new Set<string>();
  const hits: Hit[] = [];
  for (const s of sigs) {
    if (s.epOnly) {
      if (epOff === null) continue;
      if (matchAt(view, epOff, s.pattern) && !seen.has(s.name)) { seen.add(s.name); hits.push({ name: s.name, epOnly: true, offset: epOff }); }
    } else {
      const at = findFirst(view, NONEP_SEARCH_CAP, s.pattern);
      if (at >= 0 && !seen.has(s.name)) { seen.add(s.name); hits.push({ name: s.name, epOnly: false, offset: at }); }
    }
  }
  hits.sort((a, b) => (a.epOnly === b.epOnly ? a.name.localeCompare(b.name) : a.epOnly ? -1 : 1));
  return { hits, epOff, partialNonEp: view.length > NONEP_SEARCH_CAP };
}

export function PeidPanel({ bytes, memoryMap }: Props) {
  const view = useMemo(() => new Uint8Array(bytes), [bytes]);
  const [status, setStatus] = useState<"loading" | "scanning" | "done" | "error">("loading");
  const [error, setError] = useState<string | null>(null);
  const [sigs, setSigs] = useState<PeidSig[]>([]);
  const [source, setSource] = useState<"bundled" | "custom">("bundled");
  const [result, setResult] = useState<ReturnType<typeof scan> | null>(null);
  const [filter, setFilter] = useState("");
  const fileRef = useRef<HTMLInputElement>(null);

  const runScan = useCallback((parsed: PeidSig[]) => {
    setStatus("scanning");

    setTimeout(() => {
      try { setResult(scan(view, memoryMap, parsed)); setStatus("done"); }
      catch (e) { setError((e as Error).message); setStatus("error"); }
    }, 0);
  }, [view, memoryMap]);

  useEffect(() => {
    let cancelled = false;
    fetch(BUNDLED_URL)
      .then((r) => { if (!r.ok) throw new Error(`fetch userdb.txt: ${r.status}`); return r.text(); })
      .then((text) => {
        if (cancelled) return;
        const parsed = parseUserDb(text);
        setSigs(parsed); setSource("bundled");
        runScan(parsed);
      })
      .catch((e) => { if (!cancelled) { setError((e as Error).message); setStatus("error"); } });
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const loadCustom = (text: string) => {
    const parsed = parseUserDb(text);
    if (parsed.length === 0) { setError("no signatures parsed from that file"); setStatus("error"); return; }
    setSigs(parsed); setSource("custom"); setError(null);
    runScan(parsed);
  };

  const onFile = (e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0];
    if (!f) return;
    f.text().then(loadCustom);
    e.target.value = "";
  };

  const hits = result?.hits ?? [];
  const shown = useMemo(() => {
    const f = filter.trim().toLowerCase();
    return f ? hits.filter((h) => h.name.toLowerCase().includes(f)) : hits;
  }, [hits, filter]);

  return (
    <div className="p-4 flex flex-col h-full min-h-0">
      <div className="flex flex-wrap items-center gap-2 mb-2 text-xs">
        <span className="text-zinc-500">
          rules: {source} ({sigs.length.toLocaleString()})
          {result ? <> · EP @ <span className="font-mono">{result.epOff !== null ? "0x" + result.epOff.toString(16) : "n/a"}</span> · {hits.length} match{hits.length === 1 ? "" : "es"}</> : null}
        </span>
        <button type="button" onClick={() => fileRef.current?.click()} className="px-2 py-0.5 rounded bg-zinc-800 hover:bg-zinc-700">Load userdb.txt…</button>
        <input ref={fileRef} type="file" accept=".txt" className="hidden" onChange={onFile} />
        {source === "custom" ? (
          <button type="button" onClick={() => { setStatus("loading"); setError(null); fetch(BUNDLED_URL).then((r) => r.text()).then((t) => { const p = parseUserDb(t); setSigs(p); setSource("bundled"); runScan(p); }).catch((e) => { setError((e as Error).message); setStatus("error"); }); }}
            className="px-2 py-0.5 rounded bg-zinc-800 hover:bg-zinc-700">Back to bundled</button>
        ) : null}
        <input type="text" placeholder="Filter matches…" value={filter} onChange={(e) => setFilter(e.target.value)}
          className="px-2 py-0.5 bg-zinc-900 border border-zinc-800 rounded ml-auto min-w-[180px]" />
      </div>

      {status === "loading" ? <div className="text-zinc-500 text-sm">Loading PEiD database…</div> : null}
      {status === "scanning" ? <div className="text-zinc-500 text-sm">Scanning {sigs.length.toLocaleString()} PEiD signatures…</div> : null}
      {status === "error" ? <div className="text-red-400 text-sm font-mono">{error}</div> : null}

      {status === "done" ? (
        hits.length === 0 ? (
          <div className="text-zinc-500 text-sm">No PEiD signatures matched.</div>
        ) : (
          <div className="flex-1 overflow-auto border border-zinc-800 rounded">
            <table className="w-full font-mono text-xs">
              <thead className="bg-zinc-900 sticky top-0 text-left text-zinc-500">
                <tr>
                  <th className="px-3 py-1.5 w-16">Where</th>
                  <th className="px-3 py-1.5 w-28">Offset</th>
                  <th className="px-3 py-1.5">Signature</th>
                </tr>
              </thead>
              <tbody>
                {shown.map((h, i) => (
                  <tr key={i} className="border-t border-zinc-900 hover:bg-zinc-900/50">
                    <td className={"px-3 py-1 " + (h.epOnly ? "text-amber-400" : "text-zinc-500")}>{h.epOnly ? "EP" : "file"}</td>
                    <td className="px-3 py-1 text-zinc-500">0x{h.offset.toString(16)}</td>
                    <td className="px-3 py-1 text-zinc-200 break-all">{h.name}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )
      ) : null}

      {status === "done" && result?.partialNonEp ? (
        <div className="mt-2 text-[11px] text-zinc-600">non-EP signatures were searched only in the first {NONEP_SEARCH_CAP / 1024 / 1024} MB of the file</div>
      ) : null}
    </div>
  );
}
