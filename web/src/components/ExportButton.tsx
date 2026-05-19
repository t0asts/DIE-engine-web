
import { useState } from "react";

import type { ScanResult } from "../worker/protocol";

function recordLine(r: ScanResult["records"][number]): string {
  const parts: string[] = [r.name];
  if (r.version) parts.push(r.version);
  if (r.options) parts.push(`[${r.options}]`);
  if (r.language) parts.push(`(${r.language})`);
  return `${r.type}: ${parts.join(" ")}`;
}

function toPlainText(fileName: string, r: ScanResult): string {
  const lines = [`${fileName}: ${r.fileInfo.primaryFormat}${r.fileInfo.allFormats.length > 1 ? ` (also: ${r.fileInfo.allFormats.filter((f) => f !== r.fileInfo.primaryFormat).join(", ")})` : ""}`];
  if (r.records.length === 0) lines.push("    (no detections)");
  for (const rec of r.records) lines.push(`    ${recordLine(rec)}`);
  return lines.join("\n") + "\n";
}

function toJson(fileName: string, r: ScanResult): string {
  return JSON.stringify({
    file: { name: fileName, size: r.fileInfo.size, format: r.fileInfo.primaryFormat, allFormats: r.fileInfo.allFormats },
    hashes: r.hashes,
    records: r.records,
    scanDurationMs: r.durationMs,
    exportedAt: new Date().toISOString(),
  }, null, 2) + "\n";
}

function csvEscape(s: string): string {
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}
function toDelimited(r: ScanResult, sep: string): string {
  const head = ["type", "name", "version", "options", "language"].join(sep);
  const rows = r.records.map((rec) =>
    [rec.type, rec.name, rec.version ?? "", rec.options ?? "", rec.language ?? ""]
      .map((c) => (sep === "," ? csvEscape(c) : c.replace(/\t/g, " ")))
      .join(sep));
  return [head, ...rows].join("\n") + "\n";
}

function download(name: string, mime: string, text: string): void {
  const blob = new Blob([text], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
async function copyText(text: string): Promise<void> {
  try { await navigator.clipboard.writeText(text); }
  catch {
    const ta = document.createElement("textarea");
    ta.value = text; document.body.appendChild(ta); ta.select(); document.execCommand("copy"); document.body.removeChild(ta);
  }
}

const baseName = (n: string) => (n.replace(/\.[^.]+$/, "") || n);

export function ExportButton({ fileName, result }: { fileName: string; result: ScanResult }) {
  const [open, setOpen] = useState(false);
  const [copied, setCopied] = useState(false);
  const base = baseName(fileName);

  const item = (label: string, fn: () => void | Promise<void>) => (
    <button
      type="button"
      onClick={async () => { setOpen(false); await fn(); }}
      className="block w-full text-left px-3 py-1.5 hover:bg-zinc-800 text-zinc-300"
    >
      {label}
    </button>
  );

  return (
    <div className="relative inline-block">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="px-2 py-0.5 text-xs rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-300"
      >
        {copied ? "Copied!" : "Export ▾"}
      </button>
      {open ? (
        <div className="absolute right-0 mt-1 w-56 bg-zinc-950 border border-zinc-800 rounded shadow-2xl z-50 text-xs py-1"
             onMouseLeave={() => setOpen(false)}>
          {item("Copy as text (DIE format)", async () => { await copyText(toPlainText(fileName, result)); setCopied(true); setTimeout(() => setCopied(false), 1500); })}
          {item("Download .txt", () => download(`${base}.die.txt`, "text/plain", toPlainText(fileName, result)))}
          {item("Download .json", () => download(`${base}.die.json`, "application/json", toJson(fileName, result)))}
          {item("Download .csv", () => download(`${base}.die.csv`, "text/csv", toDelimited(result, ",")))}
          {item("Download .tsv", () => download(`${base}.die.tsv`, "text/tab-separated-values", toDelimited(result, "\t")))}
        </div>
      ) : null}
    </div>
  );
}
