
import { useState } from "react";

import { useWorkspace } from "../store/workspace";
import type { ExtractEntry } from "../worker/protocol";

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

export function ExtractorPanel({ records, bytes, parentName }: Props) {
  const addFile = useWorkspace((s) => s.addFile);
  const [busy, setBusy] = useState<number | null>(null);

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

  if (records.length === 0) {
    return <div className="p-8 text-sm text-zinc-500">No embedded or overlay sub-files were found in this file.</div>;
  }

  return (
    <div className="p-4 flex flex-col h-full min-h-0">
      <div className="text-xs text-zinc-500 mb-2">{records.length} embedded / overlay sub-file{records.length === 1 ? "" : "s"} found by the extractor.</div>
      <div className="flex-1 overflow-auto border border-zinc-800 rounded">
        <table className="w-full font-mono text-xs">
          <thead className="bg-zinc-900 sticky top-0 text-left text-zinc-500">
            <tr>
              <th className="px-3 py-1.5 w-24">Type</th>
              <th className="px-3 py-1.5 w-28">Offset</th>
              <th className="px-3 py-1.5 w-24">Size</th>
              <th className="px-3 py-1.5">Detail</th>
              <th className="px-3 py-1.5 w-32" />
            </tr>
          </thead>
          <tbody>
            {records.map((e, i) => {
              const carvable = e.offset >= 0 && e.size > 0 && e.offset + e.size <= bytes.byteLength;
              return (
                <tr key={i} className="border-t border-zinc-900 hover:bg-zinc-900/50">
                  <td className="px-3 py-1 text-emerald-400">{e.type}</td>
                  <td className="px-3 py-1 text-zinc-500">{hex(e.offset)}</td>
                  <td className="px-3 py-1 text-zinc-400">{fmtSize(e.size)}</td>
                  <td className="px-3 py-1 text-zinc-400 truncate max-w-[360px]" title={[e.name, e.ext, e.string].filter(Boolean).join(" · ")}>
                    {[e.name, e.string].filter(Boolean).join(" · ") || "-"}
                  </td>
                  <td className="px-3 py-1 text-right whitespace-nowrap">
                    {carvable ? (
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
      <div className="mt-1.5 text-[11px] text-zinc-600">"download" / "scan" carve the byte range straight out of the file. For compressed sub-files (ZLIB/GZIP) the carved bytes are still compressed.</div>
    </div>
  );
}
