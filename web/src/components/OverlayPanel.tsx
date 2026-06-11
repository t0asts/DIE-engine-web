import { useMemo } from "react";

import type { MemoryRecord } from "../worker/protocol";

interface Props {
  overlay: MemoryRecord;
  bytes: ArrayBuffer;
  fileName: string;
  totalSize: number;
  onViewHex: (offset: number) => void;
}

function hex(n: number, pad = 8): string {
  if (!Number.isFinite(n) || n < 0) return "-";
  return "0x" + n.toString(16).padStart(pad, "0");
}

function fmtSize(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(2)} MB`;
}

function entropyOf(b: Uint8Array): number {
  if (b.length === 0) return 0;
  const counts = new Uint32Array(256);
  const step = Math.max(1, Math.floor(b.length / 4_000_000));
  let total = 0;
  for (let i = 0; i < b.length; i += step) {
    const v = b[i]!;
    counts[v] = counts[v]! + 1;
    total++;
  }
  let h = 0;
  for (let i = 0; i < 256; i++) {
    const c = counts[i]!;
    if (c) {
      const p = c / total;
      h -= p * Math.log2(p);
    }
  }
  return h;
}

const PREVIEW_BYTES = 256;
const ROW = 16;

export function OverlayPanel({ overlay, bytes, fileName, totalSize, onViewHex }: Props) {
  const slice = useMemo(() => {
    const all = new Uint8Array(bytes);
    const start = Math.max(0, overlay.offset);
    const end = Math.min(all.length, overlay.offset + overlay.size);
    return all.subarray(start, end);
  }, [bytes, overlay.offset, overlay.size]);

  const entropy = useMemo(() => entropyOf(slice), [slice]);
  const pct = totalSize > 0 ? (overlay.size / totalSize) * 100 : 0;
  const preview = useMemo(() => slice.subarray(0, PREVIEW_BYTES), [slice]);

  const onSave = () => {
    const blob = new Blob([slice], { type: "application/octet-stream" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${fileName}.overlay.bin`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  const rows: { offset: number; bytes: Uint8Array }[] = [];
  for (let off = 0; off < preview.length; off += ROW) {
    rows.push({ offset: off, bytes: preview.subarray(off, off + ROW) });
  }

  return (
    <div className="p-4 flex flex-col h-full min-h-0">
      <div className="flex items-center gap-2 mb-4">
        <h2 className="text-sm font-semibold">Overlay</h2>
        <span className="text-xs text-zinc-500">data appended after the structured image</span>
        <div className="ml-auto flex gap-2">
          <button
            type="button"
            onClick={() => onViewHex(overlay.offset)}
            className="px-3 py-1 text-xs bg-zinc-800 hover:bg-zinc-700 rounded"
          >
            View in hex
          </button>
          <button
            type="button"
            onClick={onSave}
            disabled={slice.length === 0}
            className="px-3 py-1 text-xs bg-zinc-800 hover:bg-zinc-700 rounded disabled:opacity-40"
          >
            Save overlay
          </button>
        </div>
      </div>

      <section className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-sm mb-4">
        <span className="text-zinc-500">File offset</span>
        <span className="font-mono">{hex(overlay.offset)}</span>
        <span className="text-zinc-500">Size</span>
        <span className="font-mono">{fmtSize(overlay.size)} <span className="text-zinc-500">({overlay.size.toLocaleString()} B)</span></span>
        <span className="text-zinc-500">Portion of file</span>
        <span className="font-mono">{pct.toFixed(1)}%</span>
        <span className="text-zinc-500">Entropy</span>
        <span className="font-mono">
          {entropy.toFixed(3)} <span className="text-zinc-500">bits/byte</span>
          {entropy > 7.0 ? <span className="text-amber-400"> · high (likely compressed/encrypted)</span> : null}
        </span>
        <span className="text-zinc-500">End offset</span>
        <span className="font-mono">{hex(overlay.offset + overlay.size)}</span>
      </section>

      <h3 className="text-xs uppercase tracking-wide text-zinc-500 mb-2">
        Preview (first {Math.min(PREVIEW_BYTES, slice.length)} bytes)
      </h3>
      <div className="flex-1 overflow-auto border border-zinc-800 rounded bg-zinc-950 font-mono text-xs leading-[18px] p-2">
        {rows.length === 0 ? (
          <div className="text-zinc-500 p-2">Overlay is empty.</div>
        ) : (
          rows.map((r) => <PreviewRow key={r.offset} base={overlay.offset} offset={r.offset} bytes={r.bytes} />)
        )}
      </div>
    </div>
  );
}

function PreviewRow({ base, offset, bytes }: { base: number; offset: number; bytes: Uint8Array }) {
  const hexCells: string[] = [];
  const asciiCells: string[] = [];
  for (let i = 0; i < ROW; i++) {
    if (i < bytes.length) {
      const b = bytes[i]!;
      hexCells.push(b.toString(16).padStart(2, "0"));
      asciiCells.push(b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".");
    } else {
      hexCells.push("  ");
      asciiCells.push(" ");
    }
  }
  return (
    <div className="flex gap-4 px-1 whitespace-pre" style={{ height: 18 }}>
      <span className="text-zinc-500 select-none">{(base + offset).toString(16).padStart(8, "0")}</span>
      <span className="text-zinc-200">
        {hexCells.slice(0, 8).join(" ")}  {hexCells.slice(8).join(" ")}
      </span>
      <span className="text-zinc-400">{asciiCells.join("")}</span>
    </div>
  );
}
