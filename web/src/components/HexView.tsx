import { Fragment, useCallback, useEffect, useMemo, useRef, useState } from "react";

interface Props {
  bytes: Uint8Array;
  target?: { offset: number; nonce: number } | null;
}

const ROW_BYTES = 16;
const ROW_HEIGHT = 18;
const OVERSCAN = 4;
const MATCH_CAP = 100_000;

type BytePattern = (number | null)[];

function parseBytePattern(input: string): { pattern: BytePattern; error: string | null } {
  const raw = input.trim();
  if (!raw) return { pattern: [], error: null };

  let tokens: string[];
  if (/\s|,/.test(raw)) {
    tokens = raw.split(/[\s,]+/).filter(Boolean);
  } else {
    const s = raw.replace(/^0x/i, "");
    if (s.length % 2 !== 0) return { pattern: [], error: "Odd number of hex digits" };
    tokens = s.match(/.{2}/g) ?? [];
  }

  const pattern: BytePattern = [];
  for (const t of tokens) {
    if (t === "??" || t === "?") {
      pattern.push(null);
      continue;
    }
    const tok = t.replace(/^0x/i, "");
    if (!/^[0-9a-fA-F]{2}$/.test(tok)) return { pattern: [], error: `Invalid byte: "${t}"` };
    pattern.push(parseInt(tok, 16));
  }
  return { pattern, error: null };
}

function findMatches(bytes: Uint8Array, pattern: BytePattern): { starts: number[]; capped: boolean } {
  const starts: number[] = [];
  const m = pattern.length;
  if (m === 0) return { starts, capped: false };
  const n = bytes.length;
  const first = pattern[0]!;
  for (let i = 0; i + m <= n; i++) {
    if (first !== null && bytes[i] !== first) continue;
    let ok = true;
    for (let j = 1; j < m; j++) {
      const p = pattern[j]!;
      if (p !== null && bytes[i + j] !== p) {
        ok = false;
        break;
      }
    }
    if (ok) {
      starts.push(i);
      if (starts.length >= MATCH_CAP) return { starts, capped: true };
    }
  }
  return { starts, capped: false };
}

function lowerBound(arr: number[], x: number): number {
  let lo = 0;
  let hi = arr.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (arr[mid]! < x) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}

function rowHighlights(
  rowOff: number,
  starts: number[],
  patternLen: number,
  currentStart: number | null,
): Uint8Array {
  const hl = new Uint8Array(ROW_BYTES);
  if (!starts.length || patternLen <= 0) return hl;
  let idx = lowerBound(starts, rowOff - patternLen + 1);
  const hi = rowOff + ROW_BYTES;
  for (; idx < starts.length && starts[idx]! < hi; idx++) {
    const s = starts[idx]!;
    const isCur = currentStart !== null && s === currentStart;
    for (let k = 0; k < patternLen; k++) {
      const pos = s + k - rowOff;
      if (pos >= 0 && pos < ROW_BYTES) hl[pos] = isCur ? 2 : Math.max(hl[pos]!, 1);
    }
  }
  return hl;
}

export function HexView({ bytes, target }: Props) {
  const totalRows = Math.ceil(bytes.length / ROW_BYTES);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [viewportH, setViewportH] = useState(0);
  const [jumpInput, setJumpInput] = useState("");

  const [searchInput, setSearchInput] = useState("");
  const [query, setQuery] = useState<BytePattern | null>(null);
  const [lastQueryStr, setLastQueryStr] = useState("");
  const [searchError, setSearchError] = useState<string | null>(null);
  const [currentMatch, setCurrentMatch] = useState(-1);

  const { starts: matches, capped } = useMemo(
    () => (query ? findMatches(bytes, query) : { starts: [], capped: false }),
    [bytes, query],
  );
  const patternLen = query?.length ?? 0;
  const currentStart =
    currentMatch >= 0 && currentMatch < matches.length ? matches[currentMatch]! : null;

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

  const scrollToOffset = useCallback((off: number) => {
    const el = containerRef.current;
    if (!el) return;
    const top = Math.floor(off / ROW_BYTES) * ROW_HEIGHT - ROW_HEIGHT * 3;
    el.scrollTop = Math.max(0, top);
  }, []);

  useEffect(() => {
    if (!target) return;
    const off = target.offset;
    if (!Number.isFinite(off) || off < 0 || off >= bytes.length) return;
    scrollToOffset(off);
  }, [target?.offset, target?.nonce, bytes.length, scrollToOffset]);

  useEffect(() => {
    if (query && matches.length) {
      setCurrentMatch(0);
      scrollToOffset(matches[0]!);
    } else {
      setCurrentMatch(-1);
    }
  }, [matches, query, scrollToOffset]);

  const goToMatch = useCallback(
    (i: number) => {
      if (!matches.length) return;
      const idx = ((i % matches.length) + matches.length) % matches.length;
      setCurrentMatch(idx);
      scrollToOffset(matches[idx]!);
    },
    [matches, scrollToOffset],
  );

  const submitSearch = (backwards = false) => {
    const trimmed = searchInput.trim();
    const { pattern, error } = parseBytePattern(trimmed);
    if (error) {
      setSearchError(error);
      return;
    }
    setSearchError(null);
    if (trimmed === lastQueryStr && query && matches.length) {
      goToMatch(currentMatch + (backwards ? -1 : 1));
      return;
    }
    setLastQueryStr(trimmed);
    setQuery(pattern.length ? pattern : null);
  };

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
    const trimmed = jumpInput.trim();
    if (!trimmed) return;
    const off =
      trimmed.startsWith("0x") || trimmed.startsWith("0X")
        ? parseInt(trimmed.slice(2), 16)
        : parseInt(trimmed, 10);
    if (!Number.isFinite(off) || off < 0 || off >= bytes.length) return;
    scrollToOffset(off);
  };

  return (
    <div className="p-4 flex flex-col h-full min-h-0">
      <div className="flex items-center gap-2 mb-2">
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

      <div className="flex items-center gap-2 mb-3">
        <input
          type="text"
          placeholder="Find bytes (e.g. 77 6E 81 82, ?? = wildcard)"
          value={searchInput}
          onChange={(e) => setSearchInput(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") submitSearch(e.shiftKey);
          }}
          className={
            "px-2 py-1 text-xs bg-zinc-900 border rounded font-mono flex-1 " +
            (searchError ? "border-red-800" : "border-zinc-800")
          }
        />
        <button
          type="button"
          onClick={() => submitSearch(false)}
          className="px-3 py-1 text-xs bg-zinc-800 hover:bg-zinc-700 rounded"
        >
          Find
        </button>
        <button
          type="button"
          onClick={() => goToMatch(currentMatch - 1)}
          disabled={!matches.length}
          className="px-2 py-1 text-xs bg-zinc-800 hover:bg-zinc-700 rounded disabled:opacity-40"
          title="Previous match (Shift+Enter)"
        >
          ↑
        </button>
        <button
          type="button"
          onClick={() => goToMatch(currentMatch + 1)}
          disabled={!matches.length}
          className="px-2 py-1 text-xs bg-zinc-800 hover:bg-zinc-700 rounded disabled:opacity-40"
          title="Next match (Enter)"
        >
          ↓
        </button>
        <span className="text-xs font-mono w-32 text-right shrink-0">
          {searchError ? (
            <span className="text-red-400">{searchError}</span>
          ) : query && !matches.length ? (
            <span className="text-zinc-500">no matches</span>
          ) : matches.length ? (
            <span className="text-zinc-400">
              {currentMatch + 1} / {matches.length.toLocaleString()}
              {capped ? "+" : ""}
            </span>
          ) : null}
        </span>
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
              <HexRow
                key={row.offset}
                offset={row.offset}
                bytes={row.bytes}
                hl={rowHighlights(row.offset, matches, patternLen, currentStart)}
              />
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

function hexCellCls(h: number): string {
  if (h === 2) return "bg-amber-400 text-black rounded-sm";
  if (h === 1) return "bg-amber-500/30 text-amber-200 rounded-sm";
  return "";
}

function HexRow({ offset, bytes, hl }: { offset: number; bytes: Uint8Array; hl: Uint8Array }) {
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
      <span className="text-zinc-500 select-none">{offset.toString(16).padStart(8, "0")}</span>
      <span className="text-zinc-200">
        {hexCells.map((cell, i) => {
          const within = i < bytes.length;
          return (
            <Fragment key={i}>
              {i === 8 ? "  " : i > 0 ? " " : ""}
              <span className={within ? hexCellCls(hl[i]!) : ""}>{cell}</span>
            </Fragment>
          );
        })}
      </span>
      <span className="text-zinc-400">
        {asciiCells.map((ch, i) => (
          <span key={i} className={i < bytes.length ? hexCellCls(hl[i]!) : ""}>
            {ch}
          </span>
        ))}
      </span>
    </div>
  );
}
