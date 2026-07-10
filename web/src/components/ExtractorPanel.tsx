import { useState } from "react";

import { useWorkspace } from "../store/workspace";
import type { ExtractEntry, ExtractorMode } from "../worker/protocol";

interface Props {
  records: ExtractEntry[];
  bytes: ArrayBuffer;
  parentName: string;
}

function fmtSize(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(2)} MB`;
}
const hex = (n: number) => "0x" + Math.max(0, Math.trunc(n)).toString(16);
let uniq = 0;
const newId = () => (typeof crypto !== "undefined" && crypto.randomUUID ? crypto.randomUUID() : `f${Date.now()}_${++uniq}`);

const MODE_LABEL: Record<ExtractorMode, string> = {
  heuristic: "Heuristic",
  format: "Format",
  raw: "Raw carve",
};

function carve(bytes: ArrayBuffer, e: ExtractEntry): Uint8Array<ArrayBuffer> | null {
  if (e.offset < 0 || e.size <= 0 || e.offset + e.size > bytes.byteLength) return null;
  return new Uint8Array(bytes.slice(e.offset, e.offset + e.size));
}
function suggestName(parentName: string, e: ExtractEntry, idx: number): string {
  const base = (parentName.split("/").pop() || parentName).replace(/\.[^.]+$/, "");
  const ext = e.ext ? (e.ext.startsWith(".") ? e.ext : "." + e.ext) : "";
  return `${base}_${e.name || e.type || "sub"}_${idx}_${hex(e.offset)}${ext}`;
}
function download(name: string, data: Uint8Array<ArrayBuffer>): void {
  const blob = new Blob([data], { type: "application/octet-stream" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = name;
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

export function ExtractorPanel({ records, bytes, parentName }: Props) {
  const client = useWorkspace((s) => s.client);
  const addFile = useWorkspace((s) => s.addFile);

  const [mode, setMode] = useState<ExtractorMode>("heuristic");
  const [deepScan, setDeepScan] = useState(true);
  const [allTypes, setAllTypes] = useState(false);
  const [rows, setRows] = useState<ExtractEntry[]>(records);
  const [ranMode, setRanMode] = useState<ExtractorMode | null>(records.length ? "format" : null);
  const [running, setRunning] = useState(false);
  const [busy, setBusy] = useState<number | null>(null);
  const [dumpingAll, setDumpingAll] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const carvable = (e: ExtractEntry) => e.offset >= 0 && e.size > 0 && e.offset + e.size <= bytes.byteLength;

  const runExtract = async () => {
    setRunning(true);
    setErr(null);
    try {
      const res = await client.extract(bytes.slice(0), mode, deepScan, allTypes);
      setRows(res.records);
      setRanMode(res.mode);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setRunning(false);
    }
  };

  const scanRec = async (e: ExtractEntry, i: number) => {
    const data = carve(bytes, e);
    if (!data) return;
    setBusy(i);
    try {
      const base = parentName.split("/").pop() || parentName;
      await addFile({ id: newId(), name: `${base}#${e.type}@${hex(e.offset)}`, size: data.byteLength, bytes: data.buffer });
    } finally {
      setBusy(null);
    }
  };

  const dumpAll = async () => {
    setDumpingAll(true);
    try {
      for (let i = 0; i < rows.length; i++) {
        const e = rows[i]!;
        const data = carve(bytes, e);
        if (!data) continue;
        download(suggestName(parentName, e, i), data);
        await sleep(150);
      }
    } finally {
      setDumpingAll(false);
    }
  };

  const ctl = "text-xs bg-zinc-900 border border-zinc-700 rounded px-2 py-1";
  const btn = "px-3 py-1 text-xs bg-zinc-800 hover:bg-zinc-700 rounded disabled:opacity-40";

  return (
    <div className="p-4 flex flex-col h-full min-h-0">
      <div className="flex flex-wrap items-center gap-2 mb-2">
        <label className="text-xs text-zinc-500">Mode</label>
        <select className={ctl} value={mode} onChange={(e) => setMode(e.target.value as ExtractorMode)} disabled={running}>
          <option value="heuristic">Heuristic (auto)</option>
          <option value="format">Format (container)</option>
          <option value="raw">Raw (carve whole file)</option>
        </select>
        <label className="text-xs text-zinc-400 flex items-center gap-1">
          <input type="checkbox" checked={deepScan} onChange={(e) => setDeepScan(e.target.checked)} disabled={running} />
          Deep scan
        </label>
        <label className="text-xs text-zinc-400 flex items-center gap-1">
          <input type="checkbox" checked={allTypes} onChange={(e) => setAllTypes(e.target.checked)} disabled={running} />
          All types
        </label>
        <button type="button" className={btn} onClick={runExtract} disabled={running}>
          {running ? "Extracting…" : "Extract"}
        </button>
        <button type="button" className={btn} onClick={dumpAll} disabled={running || dumpingAll || rows.length === 0}>
          {dumpingAll ? "Downloading…" : "Download all"}
        </button>
        <div className="ml-auto text-[11px] text-zinc-500">
          {ranMode ? `${MODE_LABEL[ranMode]} · ` : ""}{rows.length} sub-file{rows.length === 1 ? "" : "s"}
        </div>
      </div>

      {err ? <div className="mb-2 text-xs text-red-400 font-mono">Extraction failed: {err}</div> : null}

      {rows.length === 0 ? (
        <div className="flex-1 grid place-items-center text-sm text-zinc-500 text-center px-6">
          {running
            ? "Scanning for embedded files…"
            : `No embedded or overlay sub-files found${ranMode ? " in " + MODE_LABEL[ranMode] + " mode" : " yet"}. Try Raw mode to carve the whole file by magic signatures.`}
        </div>
      ) : (
        <div className="flex-1 overflow-auto border border-zinc-800 rounded">
          <table className="w-full font-mono text-xs">
            <thead className="bg-zinc-900 sticky top-0 text-left text-zinc-500">
              <tr>
                <th className="px-3 py-1.5 w-24">Type</th>
                <th className="px-3 py-1.5 w-28">Offset</th>
                <th className="px-3 py-1.5 w-24">Size</th>
                <th className="px-3 py-1.5 w-24">Method</th>
                <th className="px-3 py-1.5">Detail</th>
                <th className="px-3 py-1.5 w-32" />
              </tr>
            </thead>
            <tbody>
              {rows.map((e, i) => {
                const ok = carvable(e);
                const detail = [e.name, e.string, e.crc ? `crc ${e.crc}` : ""].filter(Boolean).join(" · ") || "-";
                return (
                  <tr key={i} className="border-t border-zinc-900 hover:bg-zinc-900/50">
                    <td className="px-3 py-1 text-emerald-400">{e.type}</td>
                    <td className="px-3 py-1 text-zinc-500">{hex(e.offset)}</td>
                    <td className="px-3 py-1 text-zinc-400">{fmtSize(e.size)}</td>
                    <td className="px-3 py-1 text-zinc-500">{e.method || "-"}</td>
                    <td className="px-3 py-1 text-zinc-400 truncate max-w-[360px]" title={[e.name, e.ext, e.string, e.crc].filter(Boolean).join(" · ")}>
                      {detail}
                    </td>
                    <td className="px-3 py-1 text-right whitespace-nowrap">
                      {ok ? (
                        <>
                          <button type="button" onClick={() => { const d = carve(bytes, e); if (d) download(suggestName(parentName, e, i), d); }}
                            className="px-1.5 py-0.5 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-300 mr-1">download</button>
                          <button type="button" onClick={() => scanRec(e, i)} disabled={busy !== null}
                            className="px-1.5 py-0.5 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-300 disabled:opacity-40">
                            {busy === i ? "…" : "scan"}</button>
                        </>
                      ) : <span className="text-zinc-600">out of range</span>}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      <div className="mt-1.5 text-[11px] text-zinc-600">
        "download" / "scan" carve the byte range straight out of the file. For compressed
        sub-files (a DEFLATE/ZLIB/GZIP entry, shown under Method) the carved bytes are still compressed; use the
        Archive tab to decompress container members.
      </div>
    </div>
  );
}
