import { useRef, type PointerEvent as ReactPointerEvent, type ReactNode } from "react";

import { MIN_W, MIN_H, clamp, snapRectFor, type Bounds, type Rect } from "../store/layout";

const REVERT_THRESHOLD = 8;

interface Props {
  title: string;
  x: number;
  y: number;
  w: number;
  h: number;
  z: number;
  bounds: Bounds;
  restore?: { w: number; h: number };
  onMove(rect: Rect): void;
  onResize(w: number, h: number): void;
  onSnap(rect: Rect): void;
  onSnapPreview(rect: Rect | null): void;
  onFocus(): void;
  onDock(): void;
  onClose(): void;
  children: ReactNode;
}

type DragState = {
  kind: "move" | "resize";
  sx: number;
  sy: number;
  ox: number;
  oy: number;
  la: number;
  lb: number;
  surfL: number;
  surfT: number;
  snap: Rect | null;
  w0: number;
  h0: number;
  wasSnapped: boolean;
  reverted: boolean;
  restoreW: number;
  restoreH: number;
  grabFracX: number;
  grabOffY: number;
};

export function FloatingWindow({
  title, x, y, w, h, z, bounds, restore,
  onMove, onResize, onSnap, onSnapPreview, onFocus, onDock, onClose, children,
}: Props) {
  const ref = useRef<HTMLDivElement | null>(null);
  const drag = useRef<DragState | null>(null);

  function beginMove(e: ReactPointerEvent) {
    if (e.button !== 0) return;
    const rect = ref.current?.getBoundingClientRect();
    ref.current?.setPointerCapture(e.pointerId);
    drag.current = {
      kind: "move", sx: e.clientX, sy: e.clientY, ox: x, oy: y, la: x, lb: y,
      surfL: rect ? rect.left - x : 0,
      surfT: rect ? rect.top - y : 0,
      snap: null,
      w0: w, h0: h,
      wasSnapped: !!restore,
      reverted: false,
      restoreW: restore?.w ?? w,
      restoreH: restore?.h ?? h,
      grabFracX: rect && rect.width ? (e.clientX - rect.left) / rect.width : 0.5,
      grabOffY: rect ? e.clientY - rect.top : 8,
    };
  }

  function beginResize(e: ReactPointerEvent) {
    if (e.button !== 0) return;
    e.stopPropagation();
    onFocus();
    ref.current?.setPointerCapture(e.pointerId);
    drag.current = {
      kind: "resize", sx: e.clientX, sy: e.clientY, ox: w, oy: h, la: w, lb: h,
      surfL: 0, surfT: 0, snap: null, w0: w, h0: h,
      wasSnapped: false, reverted: false, restoreW: w, restoreH: h, grabFracX: 0, grabOffY: 0,
    };
  }

  function onPointerMove(e: ReactPointerEvent) {
    const d = drag.current;
    const el = ref.current;
    if (!d || !el) return;
    if (d.kind === "move") {
      if (d.wasSnapped && !d.reverted) {
        if (Math.hypot(e.clientX - d.sx, e.clientY - d.sy) < REVERT_THRESHOLD) return;
        d.reverted = true;
        d.w0 = d.restoreW;
        d.h0 = d.restoreH;
        d.ox = e.clientX - d.grabFracX * d.w0 - d.surfL;
        d.oy = e.clientY - Math.min(d.grabOffY, d.h0 - 1) - d.surfT;
        d.sx = e.clientX;
        d.sy = e.clientY;
        el.style.width = `${d.w0}px`;
        el.style.height = `${d.h0}px`;
      }
      const nx = clamp(d.ox + (e.clientX - d.sx), 0, bounds.w - d.w0);
      const ny = clamp(d.oy + (e.clientY - d.sy), 0, bounds.h - d.h0);
      d.la = nx;
      d.lb = ny;
      el.style.left = `${nx}px`;
      el.style.top = `${ny}px`;
      const snap = snapRectFor(e.clientX - d.surfL, e.clientY - d.surfT, bounds);
      d.snap = snap;
      onSnapPreview(snap);
    } else {
      const nw = clamp(d.ox + (e.clientX - d.sx), MIN_W, bounds.w - x);
      const nh = clamp(d.oy + (e.clientY - d.sy), MIN_H, bounds.h - y);
      d.la = nw;
      d.lb = nh;
      el.style.width = `${nw}px`;
      el.style.height = `${nh}px`;
    }
  }

  function endDrag(e: ReactPointerEvent) {
    const d = drag.current;
    if (!d) return;
    drag.current = null;
    onSnapPreview(null);
    ref.current?.releasePointerCapture?.(e.pointerId);
    if (d.kind === "resize") {
      onResize(d.la, d.lb);
      return;
    }
    if (d.snap) {
      onSnap(d.snap);
      return;
    }
    if (d.wasSnapped && !d.reverted) return;
    if (!d.reverted && d.la === d.ox && d.lb === d.oy) return;
    onMove({ x: d.la, y: d.lb, w: d.w0, h: d.h0 });
  }

  return (
    <div
      ref={ref}
      onPointerDown={onFocus}
      onPointerMove={onPointerMove}
      onPointerUp={endDrag}
      onPointerCancel={endDrag}
      style={{ position: "absolute", left: x, top: y, width: w, height: h, zIndex: z }}
      className="pointer-events-auto flex flex-col rounded-lg border border-zinc-700 bg-zinc-950 shadow-2xl overflow-hidden"
    >
      <div
        onPointerDown={beginMove}
        className="flex items-center gap-1 px-2 h-8 shrink-0 cursor-move select-none touch-none border-b border-zinc-800 bg-zinc-900"
      >
        <span className="text-xs font-medium text-zinc-300 truncate flex-1">{title}</span>
        <button
          type="button"
          title="Dock"
          aria-label="Dock window"
          onPointerDown={(e) => e.stopPropagation()}
          onClick={onDock}
          className="px-1.5 text-zinc-500 hover:text-zinc-200 text-xs leading-none"
        >
          ⤓
        </button>
        <button
          type="button"
          title="Close"
          aria-label="Close window"
          onPointerDown={(e) => e.stopPropagation()}
          onClick={onClose}
          className="px-1.5 text-zinc-500 hover:text-zinc-200 text-sm leading-none"
        >
          ×
        </button>
      </div>

      <div className="flex-1 min-h-0 overflow-auto">{children}</div>

      <div
        onPointerDown={beginResize}
        title="Resize"
        className="absolute bottom-0 right-0 w-4 h-4 cursor-nwse-resize touch-none text-zinc-600"
      >
        <svg viewBox="0 0 10 10" className="w-full h-full" aria-hidden="true">
          <path d="M9 1 L9 9 L1 9" fill="none" stroke="currentColor" strokeWidth="1" />
        </svg>
      </div>
    </div>
  );
}
