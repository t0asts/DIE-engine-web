
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { useWorkspace } from "../store/workspace";
import type { YaraScanResult, YaraMatch, YaraCompileError, YaraRuleUnit } from "../worker/protocol";

interface Props {
  bytes: ArrayBuffer;
}

interface BundledRule { name: string; path: string; size: number; }

const INDEX_URL = "/signatures-pack/yara/index.json";
const PACK_BASE = "/signatures-pack/";
const CUSTOM_NS = "(custom)";

const hex = (n: number) => "0x" + Math.max(0, Math.trunc(n)).toString(16);
const fmtSize = (n: number) => (n < 1024 ? `${n} B` : `${(n / 1024).toFixed(1)} KB`);
const where = (e: YaraCompileError) => (e.unit ? `${e.unit}:${e.line}` : `line ${e.line}`);

function MetaTags({ m }: { m: YaraMatch }) {
  return (
    <>
      {m.tags && m.tags.length ? (
        <span className="ml-2">{m.tags.map((t) => <span key={t} className="text-sky-400 mr-1">#{t}</span>)}</span>
      ) : null}
      {m.meta && Object.keys(m.meta).length ? (
        <span className="ml-2 text-zinc-500">{Object.entries(m.meta).map(([k, v]) => `${k}=${typeof v === "string" ? JSON.stringify(v) : String(v)}`).join(" ")}</span>
      ) : null}
    </>
  );
}

function MatchRow({ m }: { m: YaraMatch }) {
  const [open, setOpen] = useState(false);
  const strs = m.strings ?? [];
  const ns = m.namespace && m.namespace !== "default" ? m.namespace : "";
  return (
    <div className="border-t border-zinc-900 py-1">
      <div
        className={"px-3 flex items-baseline gap-2 " + (strs.length ? "cursor-pointer hover:bg-zinc-900/40" : "")}
        onClick={strs.length ? () => setOpen((v) => !v) : undefined}
      >
        {strs.length ? <span className="text-zinc-600 text-xs w-3">{open ? "▾" : "▸"}</span> : <span className="w-3" />}
        <span className="text-emerald-400 font-medium">{m.rule}</span>
        {ns ? <span className="text-zinc-600 text-xs">[{ns}]</span> : null}
        <MetaTags m={m} />
        {strs.length ? <span className="text-zinc-600 text-xs ml-auto">{strs.length} string match{strs.length === 1 ? "" : "es"}</span> : null}
      </div>
      {open && strs.length ? (
        <ul className="ml-9 mt-1 space-y-0.5 text-[11px] text-zinc-400">
          {strs.map((s, i) => (
            <li key={i}>
              <span className="text-zinc-300">{s.id}</span>
              <span className="text-zinc-600"> @ {hex(s.offset)}</span>
              <span className="text-zinc-500"> · {s.dataHex}{s.truncated ? "…" : ""}</span>
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}

export function YaraPanel({ bytes }: Props) {
  const client = useWorkspace((s) => s.client);
  const [bundled, setBundled] = useState<BundledRule[]>([]);
  const [checked, setChecked] = useState<Set<string>>(new Set());
  const [custom, setCustom] = useState("");
  const [status, setStatus] = useState<"loadingIndex" | "idle" | "running" | "done" | "error">("loadingIndex");
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<YaraScanResult | null>(null);
  const [filter, setFilter] = useState("");
  const sourceCache = useRef<Map<string, string>>(new Map());

  useEffect(() => {
    let cancelled = false;
    fetch(INDEX_URL)
      .then((r) => { if (!r.ok) throw new Error(`fetch yara index: ${r.status}`); return r.json() as Promise<{ rules: BundledRule[] }>; })
      .then((j) => {
        if (cancelled) return;
        setBundled(j.rules ?? []);
        setChecked(new Set((j.rules ?? []).map((r) => r.name)));
        setStatus("idle");
      })
      .catch((e) => { if (!cancelled) { setError((e as Error).message); setStatus("error"); } });
    return () => { cancelled = true; };
  }, []);

  const toggle = (name: string) => setChecked((prev) => {
    const next = new Set(prev);
    if (next.has(name)) next.delete(name); else next.add(name);
    return next;
  });

  const fetchSource = useCallback(async (rule: BundledRule): Promise<string> => {
    const cached = sourceCache.current.get(rule.path);
    if (cached !== undefined) return cached;
    const r = await fetch(PACK_BASE + rule.path);
    if (!r.ok) throw new Error(`fetch ${rule.path}: ${r.status}`);
    const text = await r.text();
    sourceCache.current.set(rule.path, text);
    return text;
  }, []);

  const run = async () => {
    const selected = bundled.filter((r) => checked.has(r.name));
    const customTrim = custom.trim();
    if (selected.length === 0 && !customTrim) { setError("Select at least one bundled rule set or enter a custom rule."); setStatus("error"); return; }
    setStatus("running"); setError(null); setResult(null);
    try {
      const sources = await Promise.all(selected.map(fetchSource));
      const units: YaraRuleUnit[] = selected.map((r, i) => ({ ns: r.name, src: sources[i]! }));
      if (customTrim) units.push({ ns: CUSTOM_NS, src: customTrim });
      const res = await client.yaraScan(bytes, units);
      setResult(res);
      setStatus("done");
    } catch (e) {
      setError((e as Error).message);
      setStatus("error");
    }
  };

  const matches = result?.matches ?? [];
  const shown = useMemo(() => {
    const f = filter.trim().toLowerCase();
    return f ? matches.filter((m) => m.rule.toLowerCase().includes(f) || m.namespace.toLowerCase().includes(f) || (m.tags ?? []).some((t) => t.toLowerCase().includes(f))) : matches;
  }, [matches, filter]);
  const warnings = (result?.errors ?? []).filter((e) => e.level === "warning");
  const compileErrors = (result?.errors ?? []).filter((e) => e.level === "error");

  if (status === "loadingIndex") return <div className="p-8 text-zinc-500 text-sm">Loading bundled YARA rules…</div>;

  return (
    <div className="p-4 flex flex-col h-full min-h-0 gap-3">
      <section className="border border-zinc-800 rounded p-3">
        <div className="flex items-center justify-between mb-2">
          <h3 className="text-xs uppercase tracking-wide text-zinc-500">Rules</h3>
          <button
            type="button"
            onClick={run}
            disabled={status === "running"}
            className="px-3 py-1 text-sm rounded bg-amber-600/80 hover:bg-amber-600 text-zinc-950 font-medium disabled:opacity-50"
          >
            {status === "running" ? "Scanning…" : "Run scan"}
          </button>
        </div>
        <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs mb-2">
          {bundled.length === 0 ? <span className="text-zinc-500">(no bundled rules)</span> : null}
          {bundled.map((r) => (
            <label key={r.name} className="flex items-center gap-1.5 text-zinc-300">
              <input type="checkbox" checked={checked.has(r.name)} onChange={() => toggle(r.name)} />
              {r.name} <span className="text-zinc-600">({fmtSize(r.size)})</span>
            </label>
          ))}
        </div>
        <textarea
          value={custom}
          onChange={(e) => setCustom(e.target.value)}
          placeholder={'// your own rules, e.g.\nrule example { strings: $a = "MZ" condition: $a at 0 }'}
          className="w-full h-24 resize-y px-2 py-1 text-xs font-mono bg-zinc-900 border border-zinc-800 rounded"
        />
      </section>

      {status === "error" ? <div className="text-red-400 text-sm font-mono">{error}</div> : null}
      {status === "running" ? <div className="text-zinc-500 text-sm">Compiling rules &amp; scanning…</div> : null}

      {status === "done" && result ? (
        !result.ok ? (
          <div className="border border-red-900/50 rounded p-3">
            <div className="text-red-400 text-sm font-medium mb-2">Rules failed to compile ({compileErrors.length} error{compileErrors.length === 1 ? "" : "s"})</div>
            <ul className="space-y-1 text-xs font-mono">
              {compileErrors.map((e, i) => (
                <li key={i}><span className="text-red-400">{where(e)}</span><span className="text-zinc-400"> - {e.message}</span></li>
              ))}
            </ul>
            {warnings.length ? (
              <details className="mt-2 text-[11px] text-zinc-500"><summary className="cursor-pointer">{warnings.length} warning{warnings.length === 1 ? "" : "s"}</summary>
                <ul className="mt-1 font-mono">{warnings.map((w, i) => <li key={i}>{where(w)} - {w.message}</li>)}</ul>
              </details>
            ) : null}
          </div>
        ) : (
          <div className="flex-1 flex flex-col min-h-0">
            <div className="flex flex-wrap items-center gap-2 mb-2 text-xs">
              <span className="text-zinc-500">{matches.length} rule{matches.length === 1 ? "" : "s"} matched</span>
              {result.timeout ? <span className="text-amber-500">· scan timed out</span> : null}
              {result.truncated ? <span className="text-amber-500">· too many matches, list truncated</span> : null}
              {warnings.length ? (
                <details className="text-zinc-500"><summary className="cursor-pointer">{warnings.length} compile warning{warnings.length === 1 ? "" : "s"}</summary>
                  <ul className="mt-1 font-mono ml-3">{warnings.map((w, i) => <li key={i}>{where(w)} - {w.message}</li>)}</ul>
                </details>
              ) : null}
              <input type="text" placeholder="Filter matches…" value={filter} onChange={(e) => setFilter(e.target.value)}
                className="px-2 py-0.5 bg-zinc-900 border border-zinc-800 rounded ml-auto min-w-[180px]" />
            </div>
            {matches.length === 0 ? (
              <div className="text-zinc-500 text-sm">No rules matched.</div>
            ) : (
              <div className="flex-1 overflow-auto border border-zinc-800 rounded text-sm">
                {shown.map((m, i) => <MatchRow key={i} m={m} />)}
                {shown.length === 0 ? <div className="px-3 py-6 text-center text-xs text-zinc-500">No matches for that filter.</div> : null}
              </div>
            )}
          </div>
        )
      ) : null}
    </div>
  );
}
