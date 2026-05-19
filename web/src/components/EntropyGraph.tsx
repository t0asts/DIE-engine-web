import { useEffect, useRef } from "react";

import type { EntropyPoint } from "../worker/protocol";

export function EntropyGraph({ points }: { points: EntropyPoint[] }) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const dpr = window.devicePixelRatio || 1;
    const W = canvas.clientWidth * dpr;
    const H = canvas.clientHeight * dpr;
    canvas.width = W;
    canvas.height = H;

    ctx.fillStyle = "#0b0b0e";
    ctx.fillRect(0, 0, W, H);

    if (points.length === 0) return;

    const yScale = (v: number) => H - (v / 8) * H;

    ctx.strokeStyle = "#fbbf24";
    ctx.lineWidth = 1.5 * dpr;
    ctx.beginPath();
    points.forEach((p, i) => {
      const x = (i / (points.length - 1 || 1)) * W;
      const y = yScale(p.value);
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.stroke();

    ctx.strokeStyle = "#27272a";
    ctx.lineWidth = 1 * dpr;
    for (const v of [4, 7]) {
      const y = yScale(v);
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(W, y);
      ctx.stroke();
    }
  }, [points]);

  return (
    <section className="p-4 border-t border-zinc-800">
      <h2 className="text-xs uppercase tracking-wide text-zinc-500 mb-2">
        Entropy
      </h2>
      <div className="h-32 w-full bg-zinc-950 rounded">
        <canvas ref={canvasRef} className="w-full h-full" />
      </div>
      <div className="text-xs text-zinc-500 mt-1 flex justify-between">
        <span>0</span>
        <span>{points.length} samples · 4 KB window</span>
        <span>EOF</span>
      </div>
    </section>
  );
}
