import { useMemo, useState } from "react";

import type { MemoryRecord } from "../worker/protocol";

interface Props {
  records: MemoryRecord[];
  binarySize: number;
}

const PALETTE = [
  "#60a5fa", "#34d399", "#f472b6", "#fbbf24", "#a78bfa",
  "#22d3ee", "#fb923c", "#4ade80", "#e879f9", "#facc15",
];

function fmtSize(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(2)} MB`;
}
const hex = (n: number) => "0x" + Math.max(0, n).toString(16);

export function RegionMap({ records, binarySize }: Props) {
  const segs = useMemo(() => {
    const fileBacked = records.filter((r) => !r.isVirtual && r.offset >= 0 && r.size > 0);
    const total = binarySize > 0
      ? binarySize
      : fileBacked.reduce((m, r) => Math.max(m, r.offset + r.size), 1);
    return fileBacked
      .map((r, i) => {
        const left = Math.min(100, (r.offset / total) * 100);
        const width = Math.max(0.15, Math.min(100 - left, (r.size / total) * 100));
        return { r, left, width, color: PALETTE[i % PALETTE.length]! };
      })
      .sort((a, b) => a.r.offset - b.r.offset);
  }, [records, binarySize]);

  const [hover, setHover] = useState<number | null>(null);

  if (segs.length === 0) return null;

  return (
    <div className="mb-4">
      <div className="flex items-baseline justify-between mb-1">
        <h2 className="text-xs uppercase tracking-wide text-zinc-500">File layout</h2>
        <span className="text-[10px] text-zinc-600 font-mono">
          {hover !== null && segs[hover]
            ? `${segs[hover]!.r.name || "(unnamed)"} · ${hex(segs[hover]!.r.offset)} … ${hex(segs[hover]!.r.offset + segs[hover]!.r.size)} · ${fmtSize(segs[hover]!.r.size)}`
            : `0 … ${fmtSize(binarySize)}`}
        </span>
      </div>
      <div className="relative h-7 w-full rounded bg-zinc-900 border border-zinc-800 overflow-hidden">
        {segs.map((s, i) => (
          <div
            key={i}
            className="absolute top-0 bottom-0 cursor-default transition-[filter]"
            style={{
              left: `${s.left}%`,
              width: `${s.width}%`,
              backgroundColor: s.color,
              opacity: hover === null || hover === i ? 0.85 : 0.35,
            }}
            onMouseEnter={() => setHover(i)}
            onMouseLeave={() => setHover(null)}
            title={`${s.r.name || "(unnamed)"}  ${hex(s.r.offset)}-${hex(s.r.offset + s.r.size)}  (${fmtSize(s.r.size)})`}
          />
        ))}
      </div>
      <div className="mt-1.5 flex flex-wrap gap-x-3 gap-y-0.5">
        {segs.map((s, i) => (
          <span
            key={i}
            className="text-[10px] font-mono flex items-center gap-1 cursor-default"
            style={{ opacity: hover === null || hover === i ? 1 : 0.4 }}
            onMouseEnter={() => setHover(i)}
            onMouseLeave={() => setHover(null)}
          >
            <span className="inline-block w-2.5 h-2.5 rounded-sm" style={{ backgroundColor: s.color }} />
            <span className="text-zinc-400">{s.r.name || `#${s.r.index}`}</span>
          </span>
        ))}
      </div>
    </div>
  );
}
