export type ModuleId = string;

export interface ModuleTargets {
  decompile?: { addr: number; nonce: number };
  hex?: { offset: number; nonce: number };
}

export type Placement =
  | { mode: "docked" }
  | {
      mode: "floating";
      x: number;
      y: number;
      w: number;
      h: number;
      z: number;
      restore?: { w: number; h: number };
    };

export interface ModuleWindow {
  open: boolean;
  placement: Placement;
}

export interface FileLayout {
  activeDockedTab: ModuleId;
  windows: Record<string, ModuleWindow>;
  zCounter: number;
  targets: ModuleTargets;
}

export interface Bounds {
  w: number;
  h: number;
}

export interface Rect {
  x: number;
  y: number;
  w: number;
  h: number;
}

export const DEFAULT_FLOAT = { w: 560, h: 420 };
export const MIN_W = 240;
export const MIN_H = 160;

export const SNAP_EDGE = 32;
export const SNAP_CORNER = 80;

export function defaultLayout(): FileLayout {
  return { activeDockedTab: "detection", windows: {}, zCounter: 0, targets: {} };
}

export function windowOf(layout: FileLayout, id: ModuleId): ModuleWindow {
  return layout.windows[id] ?? { open: false, placement: { mode: "docked" } };
}

export function isFloating(layout: FileLayout, id: ModuleId): boolean {
  return layout.windows[id]?.placement.mode === "floating";
}

export function isFloatingOpen(layout: FileLayout, id: ModuleId): boolean {
  const w = layout.windows[id];
  return !!w && w.open && w.placement.mode === "floating";
}

export function clamp(v: number, lo: number, hi: number): number {
  return Math.min(Math.max(v, lo), Math.max(lo, hi));
}

export function floatSize(bounds: Bounds): { w: number; h: number } {
  return {
    w: Math.min(DEFAULT_FLOAT.w, Math.max(MIN_W, bounds.w - 32)),
    h: Math.min(DEFAULT_FLOAT.h, Math.max(MIN_H, bounds.h - 32)),
  };
}

export function snapRectFor(px: number, py: number, bounds: Bounds): Rect | null {
  const { w: W, h: H } = bounds;
  if (W <= 0 || H <= 0) return null;
  const halfW = Math.round(W / 2);
  const halfH = Math.round(H / 2);
  const inL = px <= SNAP_CORNER;
  const inR = px >= W - SNAP_CORNER;
  const inT = py <= SNAP_CORNER;
  const inB = py >= H - SNAP_CORNER;

  if (inL && inT) return { x: 0, y: 0, w: halfW, h: halfH };
  if (inR && inT) return { x: halfW, y: 0, w: W - halfW, h: halfH };
  if (inL && inB) return { x: 0, y: halfH, w: halfW, h: H - halfH };
  if (inR && inB) return { x: halfW, y: halfH, w: W - halfW, h: H - halfH };

  if (px <= SNAP_EDGE) return { x: 0, y: 0, w: halfW, h: H };
  if (px >= W - SNAP_EDGE) return { x: halfW, y: 0, w: W - halfW, h: H };
  if (py <= SNAP_EDGE) return { x: 0, y: 0, w: W, h: H };
  return null;
}

export function cascadeRect(layout: FileLayout, bounds: Bounds): Rect {
  const n = Object.values(layout.windows).filter((win) => win.placement.mode === "floating").length;
  const step = 28;
  const { w, h } = floatSize(bounds);
  const x = clamp(24 + n * step, 0, bounds.w - w);
  const y = clamp(24 + n * step, 0, bounds.h - h);
  return { x, y, w, h };
}

function withWindow(layout: FileLayout, id: ModuleId, win: ModuleWindow): FileLayout {
  return { ...layout, windows: { ...layout.windows, [id]: win } };
}

export function applyFloat(layout: FileLayout, id: ModuleId, rect: Rect): FileLayout {
  const z = layout.zCounter + 1;
  return {
    ...withWindow(layout, id, { open: true, placement: { mode: "floating", ...rect, z } }),
    zCounter: z,
  };
}

export function applyDock(layout: FileLayout, id: ModuleId, makeActive = true): FileLayout {
  const next = withWindow(layout, id, { open: false, placement: { mode: "docked" } });
  return makeActive ? { ...next, activeDockedTab: id } : next;
}

export function applyClose(layout: FileLayout, id: ModuleId): FileLayout {
  const cur = layout.windows[id];
  if (!cur) return layout;
  return withWindow(layout, id, { ...cur, open: false });
}

export function applyRaise(layout: FileLayout, id: ModuleId): FileLayout {
  const cur = layout.windows[id];
  if (!cur || cur.placement.mode !== "floating") return layout;
  const z = layout.zCounter + 1;
  return {
    ...withWindow(layout, id, { ...cur, open: true, placement: { ...cur.placement, z } }),
    zCounter: z,
  };
}

export function applyMove(layout: FileLayout, id: ModuleId, rect: Rect): FileLayout {
  const cur = layout.windows[id];
  if (!cur || cur.placement.mode !== "floating") return layout;
  return withWindow(layout, id, { ...cur, placement: { mode: "floating", ...rect, z: cur.placement.z } });
}

export function applyResize(layout: FileLayout, id: ModuleId, w: number, h: number): FileLayout {
  const cur = layout.windows[id];
  if (!cur || cur.placement.mode !== "floating") return layout;
  const p = cur.placement;
  return withWindow(layout, id, { ...cur, placement: { mode: "floating", x: p.x, y: p.y, w, h, z: p.z } });
}

export function applySnap(layout: FileLayout, id: ModuleId, rect: Rect): FileLayout {
  const cur = layout.windows[id];
  if (!cur || cur.placement.mode !== "floating") return layout;
  const p = cur.placement;
  const restore = p.restore ?? { w: p.w, h: p.h };
  return withWindow(layout, id, { ...cur, placement: { mode: "floating", ...rect, z: p.z, restore } });
}

export function applyFocus(layout: FileLayout, id: ModuleId): FileLayout {
  return isFloating(layout, id) ? applyRaise(layout, id) : { ...layout, activeDockedTab: id };
}

export function applyClampAll(layout: FileLayout, bounds: Bounds): FileLayout {
  if (bounds.w <= 0 || bounds.h <= 0) return layout;
  let changed = false;
  const windows: Record<string, ModuleWindow> = {};
  for (const [id, win] of Object.entries(layout.windows)) {
    if (win.placement.mode !== "floating") {
      windows[id] = win;
      continue;
    }
    const p = win.placement;
    const w = clamp(p.w, MIN_W, Math.max(MIN_W, bounds.w));
    const h = clamp(p.h, MIN_H, Math.max(MIN_H, bounds.h));
    const x = clamp(p.x, 0, bounds.w - w);
    const y = clamp(p.y, 0, bounds.h - h);
    if (w !== p.w || h !== p.h || x !== p.x || y !== p.y) {
      changed = true;
      windows[id] = { ...win, placement: { ...p, x, y, w, h } };
    } else {
      windows[id] = win;
    }
  }
  return changed ? { ...layout, windows } : layout;
}
