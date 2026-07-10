import {
  Fragment,
  useCallback,
  useEffect,
  useMemo,
  useReducer,
  useRef,
  useState,
  type ClipboardEvent as ReactClipboardEvent,
  type KeyboardEvent as ReactKeyboardEvent,
} from "react";

import { useWorkspace } from "../store/workspace";
import {
  getHexEditState,
  writeByte,
  writeBytes,
  undoEdit,
  redoEdit,
  revertAll,
  type HexPane,
} from "../store/hex-edits";

interface Props {
  fileId: string;
  fileName: string;
  bytes: Uint8Array;
  target?: { offset: number; nonce: number } | null;
}

const ROW_BYTES = 16;
const ROW_HEIGHT = 18;
const OVERSCAN = 4;
const MATCH_CAP = 100_000;
const MAX_PASTE = 1 << 20;

let uniq = 0;
const newId = () =>
  typeof crypto !== "undefined" && crypto.randomUUID ? crypto.randomUUID() : `f${Date.now()}_${++uniq}`;

function patchedName(name: string): string {
  const i = name.lastIndexOf(".");
  return i > 0 ? `${name.slice(0, i)}.patched${name.slice(i)}` : `${name}.patched`;
}

function download(name: string, data: Uint8Array<ArrayBuffer>): void {
  const blob = new Blob([data], { type: "application/octet-stream" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

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

function rowDirtyMask(rowOff: number, dirty: Set<number>): number {
  if (!dirty.size) return 0;
  let mask = 0;
  for (let i = 0; i < ROW_BYTES; i++) if (dirty.has(rowOff + i)) mask |= 1 << i;
  return mask;
}

export function HexView({ fileId, fileName, bytes, target }: Props) {
  const addFile = useWorkspace((s) => s.addFile);
  const st = getHexEditState(fileId);
  const stRef = useRef(st);
  stRef.current = st;
  const [, force] = useReducer((x: number) => x + 1, 0);

  const data = st.edited ?? bytes;
  const len = bytes.length;
  const totalRows = Math.ceil(len / ROW_BYTES);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [viewportH, setViewportH] = useState(0);
  const [jumpInput, setJumpInput] = useState("");
  const [editMsg, setEditMsg] = useState<string | null>(null);
  const [opening, setOpening] = useState(false);

  const [searchInput, setSearchInput] = useState("");
  const [query, setQuery] = useState<BytePattern | null>(null);
  const [lastQueryStr, setLastQueryStr] = useState("");
  const [searchError, setSearchError] = useState<string | null>(null);
  const [currentMatch, setCurrentMatch] = useState(-1);

  const { starts: matches, capped } = useMemo(
    () => (query ? findMatches(data, query) : { starts: [], capped: false }),
    [data, query, st.editSeq],
  );
  const patternLen = query?.length ?? 0;
  const currentStart =
    currentMatch >= 0 && currentMatch < matches.length ? matches[currentMatch]! : null;

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const onScroll = () => {
      setScrollTop(el.scrollTop);
      stRef.current.scrollTop = el.scrollTop;
    };
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

  useEffect(() => {
    const el = containerRef.current;
    if (el) el.scrollTop = stRef.current.scrollTop;
    setEditMsg(null);
  }, [fileId]);

  const scrollToOffset = useCallback((off: number) => {
    const el = containerRef.current;
    if (!el) return;
    const top = Math.floor(off / ROW_BYTES) * ROW_HEIGHT - ROW_HEIGHT * 3;
    el.scrollTop = Math.max(0, top);
  }, []);

  const ensureVisible = useCallback((off: number) => {
    const el = containerRef.current;
    if (!el) return;
    const rowTop = Math.floor(off / ROW_BYTES) * ROW_HEIGHT;
    if (rowTop < el.scrollTop) el.scrollTop = rowTop;
    else if (rowTop + ROW_HEIGHT > el.scrollTop + el.clientHeight)
      el.scrollTop = rowTop + ROW_HEIGHT - el.clientHeight;
  }, []);

  useEffect(() => {
    if (!target) return;
    const off = target.offset;
    if (!Number.isFinite(off) || off < 0 || off >= len) return;
    const s = stRef.current;
    s.cursor = off;
    s.pane = "hex";
    s.nibble = 0;
    force();
    scrollToOffset(off);
  }, [target?.offset, target?.nonce, len, scrollToOffset]);

  const jumpedQuery = useRef<BytePattern | null>(null);
  useEffect(() => {
    if (query && matches.length) {
      if (jumpedQuery.current !== query) {
        jumpedQuery.current = query;
        setCurrentMatch(0);
        scrollToOffset(matches[0]!);
      } else {
        setCurrentMatch((c) => Math.min(Math.max(c, 0), matches.length - 1));
      }
    } else {
      jumpedQuery.current = query;
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

  const clampOff = (o: number) => Math.max(0, Math.min(len - 1, o));

  const setCursor = (off: number | null, pane?: HexPane) => {
    st.cursor = off === null ? null : clampOff(off);
    if (pane) st.pane = pane;
    st.nibble = 0;
    if (st.cursor !== null) ensureVisible(st.cursor);
    force();
  };

  const pick = useCallback(
    (off: number, pane: HexPane) => {
      const s = stRef.current;
      s.cursor = off;
      s.pane = pane;
      s.nibble = 0;
      force();
      containerRef.current?.focus();
    },
    [force],
  );

  const doUndo = (redo: boolean) => {
    const off = redo ? redoEdit(st, bytes) : undoEdit(st, bytes);
    if (off !== null) {
      st.cursor = clampOff(off);
      st.nibble = 0;
      ensureVisible(st.cursor);
      setEditMsg(null);
    }
    force();
  };

  const onKeyDown = (e: ReactKeyboardEvent<HTMLDivElement>) => {
    if (!len) return;
    const mod = e.ctrlKey || e.metaKey;
    const key = e.key;
    if (mod && (key === "z" || key === "Z")) {
      e.preventDefault();
      doUndo(e.shiftKey);
      return;
    }
    if (mod && (key === "y" || key === "Y")) {
      e.preventDefault();
      doUndo(true);
      return;
    }
    const cur = st.cursor;
    if (cur === null) return;
    const rowsPerPage = Math.max(
      1,
      Math.floor((containerRef.current?.clientHeight ?? ROW_HEIGHT) / ROW_HEIGHT) - 1,
    );
    switch (key) {
      case "ArrowLeft":
        e.preventDefault();
        setCursor(cur - 1);
        return;
      case "ArrowRight":
        e.preventDefault();
        setCursor(cur + 1);
        return;
      case "ArrowUp":
        e.preventDefault();
        setCursor(cur - ROW_BYTES);
        return;
      case "ArrowDown":
        e.preventDefault();
        setCursor(cur + ROW_BYTES);
        return;
      case "PageUp":
        e.preventDefault();
        setCursor(cur - rowsPerPage * ROW_BYTES);
        return;
      case "PageDown":
        e.preventDefault();
        setCursor(cur + rowsPerPage * ROW_BYTES);
        return;
      case "Home":
        e.preventDefault();
        setCursor(mod ? 0 : cur - (cur % ROW_BYTES));
        return;
      case "End":
        e.preventDefault();
        setCursor(mod ? len - 1 : cur - (cur % ROW_BYTES) + ROW_BYTES - 1);
        return;
      case "Tab":
        e.preventDefault();
        st.pane = st.pane === "hex" ? "ascii" : "hex";
        st.nibble = 0;
        force();
        return;
      case "Escape":
        e.preventDefault();
        setCursor(null);
        return;
    }
    if (mod || e.altKey) return;
    if (st.pane === "hex" && /^[0-9a-fA-F]$/.test(key)) {
      e.preventDefault();
      const d = parseInt(key, 16);
      const curVal = (st.edited ?? bytes)[cur]!;
      if (st.nibble === 0) {
        writeByte(st, bytes, cur, ((d << 4) | (curVal & 0x0f)) & 0xff, { half: true });
        st.nibble = 1;
      } else {
        writeByte(st, bytes, cur, ((curVal & 0xf0) | d) & 0xff, { coalesce: true });
        st.nibble = 0;
        st.cursor = clampOff(cur + 1);
        ensureVisible(st.cursor);
      }
      setEditMsg(null);
      force();
      return;
    }
    if (st.pane === "ascii" && key.length === 1) {
      const code = key.charCodeAt(0);
      if (code > 0xff) return;
      e.preventDefault();
      writeByte(st, bytes, cur, code);
      st.cursor = clampOff(cur + 1);
      st.nibble = 0;
      ensureVisible(st.cursor);
      setEditMsg(null);
      force();
    }
  };

  const onPaste = (e: ReactClipboardEvent<HTMLDivElement>) => {
    const cur = st.cursor;
    if (cur === null || !len) return;
    const text = e.clipboardData.getData("text");
    if (!text) return;
    e.preventDefault();
    let values: number[];
    if (st.pane === "hex") {
      const { pattern, error } = parseBytePattern(text);
      if (error || !pattern.length) {
        setEditMsg(error ?? "Nothing to paste");
        return;
      }
      if (pattern.some((b) => b === null)) {
        setEditMsg("Wildcards (??) can't be pasted");
        return;
      }
      values = pattern as number[];
    } else {
      values = [];
      for (const ch of text) {
        const code = ch.codePointAt(0)!;
        if (code > 0xff) {
          setEditMsg("Paste contains non-Latin-1 characters");
          return;
        }
        values.push(code);
      }
    }
    let msg: string | null = null;
    if (values.length > MAX_PASTE) {
      values = values.slice(0, MAX_PASTE);
      msg = `Paste capped at ${MAX_PASTE.toLocaleString()} bytes`;
    }
    const n = writeBytes(st, bytes, cur, values);
    if (n < values.length) msg = `Paste hit end of file - ${n.toLocaleString()} bytes written`;
    setEditMsg(msg);
    st.cursor = clampOff(cur + n);
    st.nibble = 0;
    ensureVisible(st.cursor);
    force();
  };

  const modified = st.dirty.size;

  const saveCopy = () => {
    if (!st.edited || !modified) return;
    download(patchedName(fileName), st.edited);
  };

  const openAsNew = async () => {
    if (!st.edited || !modified || opening) return;
    setOpening(true);
    try {
      const copy = st.edited.slice();
      await addFile({ id: newId(), name: patchedName(fileName), size: copy.byteLength, bytes: copy.buffer });
    } finally {
      setOpening(false);
    }
  };

  const firstRow = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - OVERSCAN);
  const lastRow = Math.min(totalRows, Math.ceil((scrollTop + viewportH) / ROW_HEIGHT) + OVERSCAN);

  const rows = useMemo(() => {
    const out: { offset: number; bytes: Uint8Array }[] = [];
    for (let r = firstRow; r < lastRow; r++) {
      const off = r * ROW_BYTES;
      out.push({ offset: off, bytes: data.subarray(off, off + ROW_BYTES) });
    }
    return out;
  }, [data, firstRow, lastRow]);

  const onJump = () => {
    const trimmed = jumpInput.trim();
    if (!trimmed) return;
    const off =
      trimmed.startsWith("0x") || trimmed.startsWith("0X")
        ? parseInt(trimmed.slice(2), 16)
        : parseInt(trimmed, 10);
    if (!Number.isFinite(off) || off < 0 || off >= len) return;
    scrollToOffset(off);
  };

  const btn = "px-3 py-1 text-xs bg-zinc-800 hover:bg-zinc-700 rounded disabled:opacity-40";

  return (
    <div className="p-4 flex flex-col h-full min-h-0">
      <div className="flex items-center gap-2 mb-2">
        <span className="text-xs text-zinc-500">{len.toLocaleString()} bytes</span>
        <input
          type="text"
          placeholder="Jump to offset (e.g. 0x1000)"
          value={jumpInput}
          onChange={(e) => setJumpInput(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && onJump()}
          className="ml-auto px-2 py-1 text-xs bg-zinc-900 border border-zinc-800 rounded font-mono w-64"
        />
        <button type="button" onClick={onJump} className={btn}>
          Jump
        </button>
      </div>

      <div className="flex items-center gap-2 mb-2">
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
        <button type="button" onClick={() => submitSearch(false)} className={btn}>
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

      <div className="flex items-center gap-2 mb-3 text-xs">
        <span className="font-mono text-zinc-500 shrink-0">
          {st.cursor !== null ? (
            <>
              cursor{" "}
              <span className="text-zinc-300">
                0x{st.cursor.toString(16).padStart(8, "0")}
              </span>{" "}
              · {st.pane}
            </>
          ) : (
            "no cursor"
          )}
        </span>
        <span className={"shrink-0 " + (modified ? "text-orange-400" : "text-zinc-600")}>
          {modified.toLocaleString()} modified
        </span>
        <span className="truncate min-w-0 flex-1">
          {editMsg ? (
            <span className="text-red-400">{editMsg}</span>
          ) : (
            <span className="text-zinc-600">
              click a byte, then type hex or text to overwrite · Tab switches pane · paste supported
            </span>
          )}
        </span>
        <button type="button" onClick={() => doUndo(false)} disabled={!st.undo.length} className={btn} title="Undo (Ctrl+Z)">
          Undo
        </button>
        <button type="button" onClick={() => doUndo(true)} disabled={!st.redo.length} className={btn} title="Redo (Ctrl+Shift+Z / Ctrl+Y)">
          Redo
        </button>
        <button
          type="button"
          onClick={() => {
            revertAll(st);
            setEditMsg(null);
            force();
          }}
          disabled={!modified && !st.undo.length && !st.redo.length}
          className={btn}
          title="Discard all edits"
        >
          Revert all
        </button>
        <button type="button" onClick={saveCopy} disabled={!modified} className={btn} title="Download the modified file">
          Save copy
        </button>
        <button
          type="button"
          onClick={() => void openAsNew()}
          disabled={!modified || opening}
          className={btn}
          title="Scan the modified bytes as a new file in this session"
        >
          Open as new file
        </button>
      </div>

      <div
        ref={containerRef}
        tabIndex={0}
        onKeyDown={onKeyDown}
        onPaste={onPaste}
        className="flex-1 overflow-auto border border-zinc-800 rounded bg-zinc-950 font-mono text-xs leading-[18px] outline-none focus:border-zinc-600"
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
                dirtyMask={rowDirtyMask(row.offset, st.dirty)}
                selIdx={
                  st.cursor !== null && st.cursor >= row.offset && st.cursor < row.offset + ROW_BYTES
                    ? st.cursor - row.offset
                    : -1
                }
                selPane={st.pane}
                selNibble={st.nibble}
                onPick={pick}
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

interface HexRowProps {
  offset: number;
  bytes: Uint8Array;
  hl: Uint8Array;
  dirtyMask: number;
  /** Index of the cursor byte within this row, or -1. */
  selIdx: number;
  selPane: HexPane;
  selNibble: 0 | 1;
  onPick: (offset: number, pane: HexPane) => void;
}

function HexRow({ offset, bytes, hl, dirtyMask, selIdx, selPane, selNibble, onPick }: HexRowProps) {
  const cells: { hex: string; ch: string; within: boolean; dirty: boolean }[] = [];
  for (let i = 0; i < ROW_BYTES; i++) {
    if (i < bytes.length) {
      const b = bytes[i]!;
      cells.push({
        hex: b.toString(16).padStart(2, "0"),
        ch: b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".",
        within: true,
        dirty: ((dirtyMask >> i) & 1) === 1,
      });
    } else {
      cells.push({ hex: "  ", ch: " ", within: false, dirty: false });
    }
  }

  const plainCls = (i: number, c: { dirty: boolean }) =>
    hexCellCls(hl[i]!) || (c.dirty ? "text-orange-400" : "");

  return (
    <div
      className="flex gap-4 px-3 hover:bg-zinc-900/50 whitespace-pre"
      style={{ height: ROW_HEIGHT }}
    >
      <span className="text-zinc-500 select-none">{offset.toString(16).padStart(8, "0")}</span>
      <span className="text-zinc-200">
        {cells.map((c, i) => (
          <Fragment key={i}>
            {i === 8 ? "  " : i > 0 ? " " : ""}
            {c.within ? (
              i === selIdx ? (
                <span
                  className={"rounded-sm " + (selPane === "hex" ? "bg-amber-500/25" : "bg-zinc-700/70")}
                  onMouseDown={(e) => e.button === 0 && onPick(offset + i, "hex")}
                >
                  <span className={selPane === "hex" && selNibble === 0 ? "bg-amber-400 text-black rounded-sm" : c.dirty ? "text-orange-400" : ""}>
                    {c.hex[0]}
                  </span>
                  <span className={selPane === "hex" && selNibble === 1 ? "bg-amber-400 text-black rounded-sm" : c.dirty ? "text-orange-400" : ""}>
                    {c.hex[1]}
                  </span>
                </span>
              ) : (
                <span className={plainCls(i, c)} onMouseDown={(e) => e.button === 0 && onPick(offset + i, "hex")}>
                  {c.hex}
                </span>
              )
            ) : (
              <span>{c.hex}</span>
            )}
          </Fragment>
        ))}
      </span>
      <span className="text-zinc-400">
        {cells.map((c, i) =>
          c.within ? (
            <span
              key={i}
              className={
                i === selIdx
                  ? selPane === "ascii"
                    ? "bg-amber-400 text-black rounded-sm"
                    : "bg-zinc-700/70 rounded-sm"
                  : plainCls(i, c)
              }
              onMouseDown={(e) => e.button === 0 && onPick(offset + i, "ascii")}
            >
              {c.ch}
            </span>
          ) : (
            <span key={i}>{c.ch}</span>
          ),
        )}
      </span>
    </div>
  );
}
