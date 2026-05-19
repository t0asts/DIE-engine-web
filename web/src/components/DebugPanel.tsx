
import { useMemo, useState } from "react";

import type { ModuleLog, ScanResult, ScriptOutcome } from "../worker/protocol";

interface Props {
  fileName: string;
  result: ScanResult;
}

async function copyText(text: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const ta = document.createElement("textarea");
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    document.body.removeChild(ta);
  }
}

function ModuleRow({ m }: { m: ModuleLog }) {
  const [open, setOpen] = useState(false);
  const hasDetail = !!m.detail || !!m.error;
  return (
    <>
      <tr
        className={"border-t border-zinc-900 " + (hasDetail ? "cursor-pointer hover:bg-zinc-900/50" : "")}
        onClick={hasDetail ? () => setOpen((v) => !v) : undefined}
      >
        <td className="px-3 py-1 w-6 text-center">{m.ok ? "✓" : <span className="text-red-400">✗</span>}</td>
        <td className="px-3 py-1 text-zinc-200 whitespace-nowrap">{m.module}</td>
        <td className="px-3 py-1 text-zinc-500 w-16 text-right">{m.durationMs} ms</td>
        <td className={"px-3 py-1 " + (m.ok ? "text-zinc-400" : "text-red-400")}>
          {hasDetail ? <span className="text-zinc-600 mr-1">{open ? "▾" : "▸"}</span> : null}
          {m.error ?? m.note ?? ""}
        </td>
      </tr>
      {open && hasDetail ? (
        <tr className="bg-zinc-950">
          <td />
          <td colSpan={3} className="px-3 py-2">
            <pre className="text-[11px] leading-snug whitespace-pre-wrap text-zinc-400">{m.detail ?? m.error}</pre>
          </td>
        </tr>
      ) : null}
    </>
  );
}

function ScriptList({ title, items, color }: { title: string; items: ScriptOutcome[]; color: string }) {
  const [open, setOpen] = useState(false);
  if (items.length === 0) return null;
  return (
    <div className="mt-3">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="text-xs text-zinc-400 hover:text-zinc-200"
      >
        <span className="text-zinc-600 mr-1">{open ? "▾" : "▸"}</span>
        {title} ({items.length})
      </button>
      {open ? (
        <ul className="mt-1.5 ml-3 space-y-0.5 text-[11px] font-mono">
          {items.map((o, i) => (
            <li key={i}>
              <span className={color}>{o.path}</span>
              <span className="text-zinc-600"> · {o.durationMs} ms{o.records ? ` · ${o.records} rec` : ""}</span>
              {o.error ? <span className="text-red-400"> - {o.error}</span> : null}
              {o.logs && o.logs.length
                ? o.logs.map((l, j) => <div key={j} className="text-zinc-500 pl-4">log: {l}</div>)
                : null}
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}

export function DebugPanel({ fileName, result }: Props) {
  const [copied, setCopied] = useState(false);
  const reportText = useMemo(() => formatReport(fileName, result), [fileName, result]);

  const dl = result.debugLog;
  const failed = dl.scriptOutcomes.filter((o) => !o.ok);
  const withRecords = dl.scriptOutcomes.filter((o) => o.ok && o.records > 0);

  const onCopy = async () => {
    await copyText(reportText);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div className="p-4 flex flex-col gap-4 min-h-0">
      <section>
        <div className="flex items-center justify-between mb-2">
          <h2 className="text-xs uppercase tracking-wide text-zinc-500">Module run log</h2>
          <button type="button" onClick={onCopy} className="px-2 py-0.5 text-xs rounded bg-zinc-800 hover:bg-zinc-700">
            {copied ? "Copied!" : "Copy debug report"}
          </button>
        </div>
        <div className="border border-zinc-800 rounded overflow-hidden">
          <table className="w-full text-xs">
            <tbody>
              {result.moduleLogs.length === 0 ? (
                <tr><td className="px-3 py-3 text-zinc-500">No module logs (older scan).</td></tr>
              ) : (
                result.moduleLogs.map((m, i) => <ModuleRow key={i} m={m} />)
              )}
            </tbody>
          </table>
        </div>
        <div className="mt-1 text-[11px] text-zinc-600">Total scan time: {result.durationMs} ms</div>
      </section>

      <section>
        <h2 className="text-xs uppercase tracking-wide text-zinc-500 mb-2">Signature scripts</h2>
        <div className="text-xs text-zinc-400">
          {dl.scriptsSucceeded}/{dl.scriptsAttempted} ran clean
          {failed.length ? <span className="text-red-400"> · {failed.length} failed</span> : null}
          {" · "}{result.records.length} detection{result.records.length === 1 ? "" : "s"}
          {" · format binding "}<span className="font-mono">{dl.jsClass}</span>
        </div>
        <ScriptList title="Failed scripts" items={failed} color="text-red-400" />
        <ScriptList title="Scripts that produced detections" items={withRecords} color="text-zinc-300" />
        {result.errors.length ? (
          <details className="mt-3 text-[11px] text-zinc-500">
            <summary className="cursor-pointer text-zinc-400">Raw engine errors ({result.errors.length})</summary>
            <ul className="mt-1.5 ml-3 space-y-0.5 font-mono">
              {result.errors.map((e, i) => <li key={i}>{e}</li>)}
            </ul>
          </details>
        ) : null}
      </section>
    </div>
  );
}

function formatReport(fileName: string, r: ScanResult): string {
  const dl = r.debugLog;
  const failed = dl.scriptOutcomes.filter((o) => !o.ok);
  const withRecords = dl.scriptOutcomes.filter((o) => o.ok && o.records > 0);
  const L: string[] = [];
  L.push(`# DIE-Web debug report`, `generated: ${new Date().toISOString()}`, ``);
  L.push(`## file`);
  L.push(`name:   ${fileName}`, `size:   ${dl.fileSize} bytes`, `format: ${dl.jsClass} (primary: ${r.fileInfo.primaryFormat})`);
  if (r.fileInfo.allFormats.length > 1) L.push(`also matches: ${r.fileInfo.allFormats.join(", ")}`);
  L.push(`md5:    ${r.hashes.md5}`, `sha256: ${r.hashes.sha256}`, `scan duration: ${r.durationMs} ms`, ``);

  L.push(`## modules`);
  for (const m of r.moduleLogs) {
    L.push(`- [${m.ok ? "ok" : "FAIL"}] ${m.module}  (${m.durationMs} ms)${m.note ? `  - ${m.note}` : ""}${m.error ? `  - error: ${m.error}` : ""}`);
    if (m.detail) for (const line of m.detail.split("\n")) L.push(`    ${line}`);
  }
  L.push(``);

  L.push(`## records (${r.records.length})`);
  if (r.records.length === 0) L.push(`<no detections>`);
  for (const rec of r.records) {
    const parts = [rec.type, rec.name];
    if (rec.version) parts.push(`v${rec.version}`);
    if (rec.options) parts.push(`[${rec.options}]`);
    if (rec.language) parts.push(`(${rec.language})`);
    L.push(`- ${parts.join(" ")}`);
  }
  L.push(``);

  L.push(`## scripts: attempted ${dl.scriptsAttempted}, succeeded ${dl.scriptsSucceeded}, failed ${dl.scriptsFailed}`, ``);
  if (failed.length) {
    L.push(`## failed scripts (${failed.length})`);
    for (const o of failed) {
      L.push(`- ${o.path}  (${o.durationMs} ms)`);
      if (o.error) L.push(`    error: ${o.error}`);
      if (o.logs) for (const l of o.logs) L.push(`    log: ${l}`);
    }
    L.push(``);
  }
  if (withRecords.length) {
    L.push(`## successful scripts that produced records (${withRecords.length})`);
    for (const o of withRecords) {
      L.push(`- ${o.path}  (${o.durationMs} ms, ${o.records} record${o.records === 1 ? "" : "s"})`);
      if (o.logs) for (const l of o.logs) L.push(`    log: ${l}`);
    }
    L.push(``);
  }
  if (r.errors.length) {
    L.push(`## raw error list`);
    for (const e of r.errors) L.push(`- ${e}`);
  }
  return L.join("\n");
}
