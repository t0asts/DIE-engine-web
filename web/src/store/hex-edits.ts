export interface HexEditEntry {
  offset: number;
  prev: number[];
  next: number[];
  half: boolean;
}

export type HexPane = "hex" | "ascii";

export interface HexEditState {
  edited: Uint8Array<ArrayBuffer> | null;
  dirty: Set<number>;
  undo: HexEditEntry[];
  redo: HexEditEntry[];
  editSeq: number;
  cursor: number | null;
  pane: HexPane;
  nibble: 0 | 1;
  scrollTop: number;
}

const MAX_UNDO = 1024;

const registry = new Map<string, HexEditState>();

function makeState(): HexEditState {
  return {
    edited: null,
    dirty: new Set(),
    undo: [],
    redo: [],
    editSeq: 0,
    cursor: null,
    pane: "hex",
    nibble: 0,
    scrollTop: 0,
  };
}

export function getHexEditState(fileId: string): HexEditState {
  let st = registry.get(fileId);
  if (!st) {
    st = makeState();
    registry.set(fileId, st);
  }
  return st;
}

export function evictHexEditState(fileId: string): void {
  registry.delete(fileId);
}

export function evictAllHexEditState(): void {
  registry.clear();
}

function ensureEdited(st: HexEditState, original: Uint8Array): Uint8Array<ArrayBuffer> {
  if (!st.edited) st.edited = original.slice();
  return st.edited;
}

function syncDirty(st: HexEditState, original: Uint8Array, offset: number): void {
  if (st.edited![offset] === original[offset]) st.dirty.delete(offset);
  else st.dirty.add(offset);
}

function pushUndo(st: HexEditState, entry: HexEditEntry): void {
  st.undo.push(entry);
  if (st.undo.length > MAX_UNDO) st.undo.shift();
  st.redo.length = 0;
}

export function writeByte(
  st: HexEditState,
  original: Uint8Array,
  offset: number,
  value: number,
  opts: { half?: boolean; coalesce?: boolean } = {},
): boolean {
  if (offset < 0 || offset >= original.length) return false;
  const data = ensureEdited(st, original);
  const prev = data[offset]!;
  if (prev === value) return false;
  data[offset] = value;
  syncDirty(st, original, offset);
  st.editSeq++;
  const top = st.undo[st.undo.length - 1];
  if (opts.coalesce && top && top.half && top.offset === offset) {
    top.next = [value];
    top.half = false;
    st.redo.length = 0;
  } else {
    pushUndo(st, { offset, prev: [prev], next: [value], half: !!opts.half });
  }
  return true;
}

export function writeBytes(
  st: HexEditState,
  original: Uint8Array,
  offset: number,
  values: ArrayLike<number>,
): number {
  if (offset < 0 || offset >= original.length) return 0;
  const data = ensureEdited(st, original);
  const n = Math.min(values.length, data.length - offset);
  if (n <= 0) return 0;
  const prev: number[] = [];
  const next: number[] = [];
  let changed = false;
  for (let i = 0; i < n; i++) {
    const p = data[offset + i]!;
    const v = values[i]! & 0xff;
    prev.push(p);
    next.push(v);
    if (p !== v) changed = true;
  }
  if (!changed) return n;
  for (let i = 0; i < n; i++) {
    data[offset + i] = next[i]!;
    syncDirty(st, original, offset + i);
  }
  st.editSeq++;
  pushUndo(st, { offset, prev, next, half: false });
  return n;
}

export function undoEdit(st: HexEditState, original: Uint8Array): number | null {
  const e = st.undo.pop();
  if (!e || !st.edited) return null;
  for (let i = 0; i < e.prev.length; i++) {
    st.edited[e.offset + i] = e.prev[i]!;
    syncDirty(st, original, e.offset + i);
  }
  st.redo.push(e);
  st.editSeq++;
  return e.offset;
}

export function redoEdit(st: HexEditState, original: Uint8Array): number | null {
  const e = st.redo.pop();
  if (!e || !st.edited) return null;
  for (let i = 0; i < e.next.length; i++) {
    st.edited[e.offset + i] = e.next[i]!;
    syncDirty(st, original, e.offset + i);
  }
  st.undo.push(e);
  st.editSeq++;
  return e.offset;
}

export function revertAll(st: HexEditState): void {
  st.edited = null;
  st.dirty.clear();
  st.undo.length = 0;
  st.redo.length = 0;
  st.editSeq++;
}
