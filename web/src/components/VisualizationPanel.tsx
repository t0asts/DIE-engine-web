
import { useEffect, useMemo, useRef, useState } from "react";

import type { MemoryMap } from "../worker/protocol";

interface Props {
  bytes: ArrayBuffer;
  memoryMap: MemoryMap | null;
}

type Mode = "value" | "class" | "entropy";

const GW = 512;
const GH = 384;

const fmtSize = (n: number) => (n < 1024 ? `${n} B` : n < 1024 * 1024 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1024 / 1024).toFixed(2)} MB`);
const hex = (n: number) => "0x" + Math.max(0, n).toString(16);

function byteClass(b: number): 0 | 1 | 2 | 3 {
  if (b === 0) return 0;
  if (b === 9 || b === 10 || b === 13 || (b >= 32 && b <= 126)) return 2;
  if (b >= 128) return 3;
  return 1;
}
const CLASS_COLORS: [number, number, number][] = [
  [10, 10, 12],     
  [96, 165, 250],   
  [52, 211, 153],   
  [248, 113, 113],  
];

function entropyColor(h: number): [number, number, number] {
  const t = Math.max(0, Math.min(1, h / 8));
  
  if (t < 0.5) {
    const u = t / 0.5;
    return [Math.round(30 + u * (250 - 30)), Math.round(58 + u * (204 - 58)), Math.round(138 + u * (21 - 138))];
  }
  const u = (t - 0.5) / 0.5;
  return [Math.round(250 + u * (185 - 250)), Math.round(204 + u * (28 - 204)), Math.round(21 + u * (28 - 21))];
}

function shannon(view: Uint8Array, start: number, end: number): number {
  const n = end - start;
  if (n <= 1) return 0;
  const counts = new Uint32Array(256);
  for (let i = start; i < end; i++) { const k = view[i] ?? 0; counts[k] = (counts[k] ?? 0) + 1; }
  let h = 0;
  for (let b = 0; b < 256; b++) {
    const c = counts[b] ?? 0;
    if (!c) continue;
    const p = c / n;
    h -= p * Math.log2(p);
  }
  return h;
}

export function VisualizationPanel({ bytes, memoryMap }: Props) {
  const view = useMemo(() => new Uint8Array(bytes), [bytes]);
  const [mode, setMode] = useState<Mode>("class");
  const [overlay, setOverlay] = useState(true);
  const [hover, setHover] = useState<{ off: number; v: number; ent?: number } | null>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);

  const size = view.length;
  const bpp = Math.max(1, Math.ceil(size / (GW * GH)));   

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    canvas.width = GW;
    canvas.height = GH;

    const img = ctx.createImageData(GW, GH);
    const d = img.data;
    const cells = GW * GH;
    for (let c = 0; c < cells; c++) {
      const start = c * bpp;
      if (start >= size) { 
        const o = c * 4; d[o] = 18; d[o + 1] = 18; d[o + 2] = 22; d[o + 3] = 255;
        continue;
      }
      const end = Math.min(start + bpp, size);
      let r = 0, g = 0, b = 0;
      if (mode === "value") {
        let sum = 0;
        for (let i = start; i < end; i++) sum += view[i] ?? 0;
        const v = Math.round(sum / (end - start));
        r = g = b = v;
      } else if (mode === "class") {
        
        const cnt = new Uint32Array(4);
        for (let i = start; i < end; i++) { const ci = byteClass(view[i] ?? 0); cnt[ci] = (cnt[ci] ?? 0) + 1; }
        let best = 0;
        for (let k = 1; k < 4; k++) if ((cnt[k] ?? 0) > (cnt[best] ?? 0)) best = k;
        [r, g, b] = CLASS_COLORS[best] ?? CLASS_COLORS[0]!;
      } else {
        [r, g, b] = entropyColor(shannon(view, start, end));
      }
      const o = c * 4;
      d[o] = r; d[o + 1] = g; d[o + 2] = b; d[o + 3] = 255;
    }
    ctx.putImageData(img, 0, 0);

    if (overlay && memoryMap) {
      ctx.save();
      ctx.strokeStyle = "rgba(255,255,255,0.45)";
      ctx.lineWidth = 1;
      for (const rec of memoryMap.records) {
        if (rec.isVirtual || rec.offset < 0 || rec.offset >= size) continue;
        const cell = Math.floor(rec.offset / bpp);
        const row = Math.floor(cell / GW);
        if (row <= 0 || row >= GH) continue;
        ctx.beginPath();
        ctx.moveTo(0, row + 0.5);
        ctx.lineTo(GW, row + 0.5);
        ctx.stroke();
      }
      ctx.restore();
    }
  }, [view, mode, overlay, memoryMap, bpp, size]);

  const onMove = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const cx = Math.floor(((e.clientX - rect.left) / rect.width) * GW);
    const cy = Math.floor(((e.clientY - rect.top) / rect.height) * GH);
    if (cx < 0 || cy < 0 || cx >= GW || cy >= GH) { setHover(null); return; }
    const cell = cy * GW + cx;
    const start = cell * bpp;
    if (start >= size) { setHover(null); return; }
    const end = Math.min(start + bpp, size);
    setHover({ off: start, v: view[start]!, ent: mode === "entropy" ? shannon(view, start, end) : undefined });
  };

  const modeBtn = (m: Mode, label: string) => (
    <button type="button" onClick={() => setMode(m)}
      className={"px-2 py-0.5 text-xs rounded " + (mode === m ? "bg-zinc-700 text-zinc-100" : "bg-zinc-900 text-zinc-400 hover:text-zinc-200")}>
      {label}
    </button>
  );

  return (
    <div className="p-4 flex flex-col h-full min-h-0">
      <div className="flex flex-wrap items-center gap-2 mb-3">
        {modeBtn("class", "Byte class")}
        {modeBtn("value", "Byte value")}
        {modeBtn("entropy", "Entropy")}
        {memoryMap ? (
          <label className="text-xs text-zinc-400 flex items-center gap-1.5 ml-2">
            <input type="checkbox" checked={overlay} onChange={(e) => setOverlay(e.target.checked)} /> section lines
          </label>
        ) : null}
        <span className="text-xs text-zinc-500 ml-auto">
          {fmtSize(size)} · {bpp === 1 ? "1 byte/cell" : `${bpp} bytes/cell`}
          {hover ? <> · <span className="font-mono text-zinc-400">{hex(hover.off)}{bpp > 1 ? `-${hex(Math.min(hover.off + bpp, size))}` : ""}: {mode === "entropy" ? `H=${hover.ent!.toFixed(2)}` : `0x${hover.v.toString(16).padStart(2, "0")}`}</span></> : null}
        </span>
      </div>

      <div className="flex-1 min-h-0 overflow-auto border border-zinc-800 rounded bg-zinc-950 flex items-start justify-center p-2">
        <canvas
          ref={canvasRef}
          onMouseMove={onMove}
          onMouseLeave={() => setHover(null)}
          className="w-full max-w-3xl"
          style={{ imageRendering: "pixelated", aspectRatio: `${GW} / ${GH}` }}
        />
      </div>

      <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-zinc-500">
        {mode === "class" ? (
          <>
            <Legend c="rgb(10,10,12)" t="zero (0x00)" />
            <Legend c="rgb(96,165,250)" t="control" />
            <Legend c="rgb(52,211,153)" t="printable ASCII" />
            <Legend c="rgb(248,113,113)" t="high (0x80-0xff)" />
          </>
        ) : mode === "value" ? (
          <span>grayscale: black = 0x00 … white = 0xff</span>
        ) : (
          <>
            <Legend c="rgb(30,58,138)" t="low entropy" />
            <Legend c="rgb(250,204,21)" t="~4 bits" />
            <Legend c="rgb(185,28,28)" t="~8 bits (encrypted/compressed)" />
          </>
        )}
        <span className="ml-auto">file laid out left→right, top→bottom</span>
      </div>
    </div>
  );
}

function Legend({ c, t }: { c: string; t: string }) {
  return (
    <span className="flex items-center gap-1">
      <span className="inline-block w-3 h-3 rounded-sm border border-zinc-700" style={{ backgroundColor: c }} />
      {t}
    </span>
  );
}
