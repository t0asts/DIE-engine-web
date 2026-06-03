import { useEffect, useMemo, useRef, useState } from "react";

interface Props {
  bytes: Uint8Array;
}

const ROW_BYTES = 16;
const ROW_HEIGHT = 18;
const OVERSCAN = 4;

export function HexView({ bytes }: Props) {
  const totalRows = Math.ceil(bytes.length / ROW_BYTES);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [viewportH, setViewportH] = useState(0);
  const [jumpInput, setJumpInput] = useState("");

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const onScroll = () => setScrollTop(el.scrollTop);
    const onResize = () => setViewportH(el.clientHeight);
    onResize();
    el.addEventListener("scroll", onScroll);
    const ro = new ResizeObserver(onResize);
    ro.observe(el);
    return () => {
      el.removeEventListener("scroll", onScroll);
      ro.disconnect();
    };
  }, []);

  const firstRow = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - OVERSCAN);
  const lastRow = Math.min(
    totalRows,
    Math.ceil((scrollTop + viewportH) / ROW_HEIGHT) + OVERSCAN,
  );

  const rows = useMemo(() => {
    const out: { offset: number; bytes: Uint8Array }[] = [];
    for (let r = firstRow; r < lastRow; r++) {
      const off = r * ROW_BYTES;
      out.push({ offset: off, bytes: bytes.subarray(off, off + ROW_BYTES) });
    }
    return out;
  }, [bytes, firstRow, lastRow]);

  const onJump = () => {
    const el = containerRef.current;
    if (!el) return;
    const trimmed = jumpInput.trim();
    if (!trimmed) return;
    const off = trimmed.startsWith("0x") || trimmed.startsWith("0X")
      ? parseInt(trimmed.slice(2), 16)
      : parseInt(trimmed, 10);
    if (!Number.isFinite(off) || off < 0 || off >= bytes.length) return;
    el.scrollTop = Math.floor(off / ROW_BYTES) * ROW_HEIGHT;
  };

  return (
    <div className="p-4 flex flex-col h-full min-h-0">
      <div className="flex items-center gap-2 mb-3">
        <span className="text-xs text-zinc-500">{bytes.length.toLocaleString()} bytes</span>
        <input
          type="text"
          placeholder="Jump to offset (e.g. 0x1000)"
          value={jumpInput}
          onChange={(e) => setJumpInput(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && onJump()}
          className="ml-auto px-2 py-1 text-xs bg-zinc-900 border border-zinc-800 rounded font-mono w-64"
        />
        <button
          type="button"
          onClick={onJump}
          className="px-3 py-1 text-xs bg-zinc-800 hover:bg-zinc-700 rounded"
        >
          Jump
        </button>
      </div>

      <div
        ref={containerRef}
        className="flex-1 overflow-auto border border-zinc-800 rounded bg-zinc-950 font-mono text-xs leading-[18px]"
      >
        <div style={{ height: totalRows * ROW_HEIGHT, position: "relative" }}>
          <div
            style={{
              position: "absolute",
              top: firstRow * ROW_HEIGHT,
              left: 0,
              right: 0,
            }}
          >
            {rows.map((row) => (
              <HexRow key={row.offset} offset={row.offset} bytes={row.bytes} />
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

function HexRow({ offset, bytes }: { offset: number; bytes: Uint8Array }) {
  const hexCells: string[] = [];
  const asciiCells: string[] = [];
  for (let i = 0; i < ROW_BYTES; i++) {
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
    <div
      className="flex gap-4 px-3 hover:bg-zinc-900/50 whitespace-pre"
      style={{ height: ROW_HEIGHT }}
    >
      <span className="text-zinc-500 select-none">
        {offset.toString(16).padStart(8, "0")}
      </span>
      <span className="text-zinc-200">
        {hexCells.slice(0, 8).join(" ")}  {hexCells.slice(8).join(" ")}
      </span>
      <span className="text-zinc-400">{asciiCells.join("")}</span>
    </div>
  );
}
