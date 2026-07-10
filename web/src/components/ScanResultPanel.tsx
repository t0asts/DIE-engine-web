import { useCallback, useEffect, useRef, useState, type PointerEvent as ReactPointerEvent } from "react";

import { useWorkspace } from "../store/workspace";
import { archForDecompile } from "../decompiler/arch-map";
import {
  type Bounds,
  type Rect,
  defaultLayout,
  cascadeRect,
  floatSize,
  clamp,
  isFloating,
  isFloatingOpen,
} from "../store/layout";

import { Tabs, type TabDef } from "./Tabs";
import { ModuleView } from "./ModuleView";
import { FloatingWindow } from "./FloatingWindow";
import { ModuleLauncher, type LauncherItem } from "./ModuleLauncher";

const NARROW_W = 640;
const DRAG_THRESHOLD = 6;

export function ScanResultPanel({ fileId }: { fileId: string }) {
  const file = useWorkspace((s) => s.files.find((f) => f.id === fileId));
  const entry = useWorkspace((s) => s.scans.get(fileId));
  const layout = useWorkspace((s) => s.layouts.get(fileId));
  const floatModule = useWorkspace((s) => s.floatModule);
  const dockModule = useWorkspace((s) => s.dockModule);
  const closeModule = useWorkspace((s) => s.closeModule);
  const focusModule = useWorkspace((s) => s.focusModule);
  const moveWindow = useWorkspace((s) => s.moveWindow);
  const resizeWindow = useWorkspace((s) => s.resizeWindow);
  const snapWindow = useWorkspace((s) => s.snapWindow);
  const clampWindows = useWorkspace((s) => s.clampWindows);
  const navToDecompileAction = useWorkspace((s) => s.navToDecompile);
  const navToHexAction = useWorkspace((s) => s.navToHex);

  const [bounds, setBounds] = useState<Bounds>({ w: 0, h: 0 });
  const roRef = useRef<ResizeObserver | null>(null);
  const surfaceElRef = useRef<HTMLDivElement | null>(null);
  const surfaceRef = useCallback((el: HTMLDivElement | null) => {
    surfaceElRef.current = el;
    roRef.current?.disconnect();
    if (!el) return;
    const measure = () =>
      setBounds((prev) =>
        prev.w === el.clientWidth && prev.h === el.clientHeight
          ? prev
          : { w: el.clientWidth, h: el.clientHeight },
      );
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    roRef.current = ro;
  }, []);

  const ghostRef = useRef<HTMLDivElement | null>(null);
  const justDragged = useRef(false);
  const tabDrag = useRef<
    null | { id: string; sx: number; sy: number; dragging: boolean; lastX: number; lastY: number }
  >(null);

  const snapPreviewRef = useRef<HTMLDivElement | null>(null);
  const showSnapPreview = useCallback((rect: Rect | null) => {
    const el = snapPreviewRef.current;
    if (!el) return;
    if (!rect) {
      el.style.display = "none";
      return;
    }
    el.style.display = "block";
    el.style.left = `${rect.x}px`;
    el.style.top = `${rect.y}px`;
    el.style.width = `${rect.w}px`;
    el.style.height = `${rect.h}px`;
  }, []);

  useEffect(() => {
    if (bounds.w > 0 && bounds.h > 0) clampWindows(fileId, bounds);
  }, [bounds, fileId, clampWindows]);

  const navToDecompile = useCallback((addr: number) => navToDecompileAction(fileId, addr), [navToDecompileAction, fileId]);
  const navToHex = useCallback((offset: number) => navToHexAction(fileId, offset), [navToHexAction, fileId]);

  if (!file) return null;

  if (!entry || entry.status === "loading") {
    return (
      <div className="p-8 text-zinc-500">
        Scanning <span className="font-mono">{file.name}</span>…
      </div>
    );
  }

  if (entry.status === "error") {
    return (
      <div className="p-8 text-red-400">
        <div className="font-medium">Scan failed</div>
        <div className="font-mono text-xs mt-2">{entry.error}</div>
      </div>
    );
  }

  const r = entry.result!;
  const sectionCount = r.memoryMap?.records.length ?? 0;
  const stringCount = r.strings.length;
  const structCount = r.structure?.length ?? 0;
  const symbolCount = r.symbols?.length ?? 0;

  const canDisasm = r.disasmAvailable;
  const decompArch = archForDecompile(r);
  const isPE = r.formatClass === "PE";
  const extractedCount = r.extracted?.length ?? 0;
  const overlay = r.memoryMap?.records.find((rec) => rec.name === "Overlay" || rec.filePart === 32) ?? null;
  const hasOverlay = !!overlay && overlay.size > 0;
  const hasCert = !!r.certificates?.present;
  const hasDotnet = !!r.dotnet?.present;

  const tabs: TabDef[] = [
    { id: "detection", label: "Detection", badge: r.records.length || undefined },
    { id: "sections",  label: "Sections",  badge: sectionCount || undefined },
    ...(hasOverlay ? [{ id: "overlay", label: "Overlay" } as TabDef] : []),
    ...(structCount ? [{ id: "structure", label: "Structure" } as TabDef] : []),
    ...(symbolCount ? [{ id: "symbols", label: "Symbols", badge: symbolCount } as TabDef] : []),
    ...(canDisasm ? [{ id: "disasm", label: "Disasm" } as TabDef] : []),
    ...(decompArch ? [{ id: "decompile", label: "Decompile" } as TabDef] : []),
    ...(isPE ? [{ id: "peid", label: "PEiD" } as TabDef] : []),
    ...(hasCert ? [{ id: "certificate", label: "Certificate", badge: r.certificates?.certificates?.length || undefined } as TabDef] : []),
    ...(hasDotnet ? [{ id: "dotnet", label: ".NET" } as TabDef] : []),
    { id: "yara",      label: "YARA" },
    ...(r.archive
      ? [{ id: "archive", label: "Archive", badge: r.archive.totalEntries || undefined } as TabDef]
      : []),
    { id: "extractor", label: "Extractor", badge: extractedCount || undefined },
    { id: "strings",   label: "Strings",   badge: stringCount || undefined },
    { id: "hex",       label: "Hex" },
    { id: "visualize", label: "Visualize" },
    { id: "convert",   label: "Convert" },
    { id: "demangle",  label: "Demangler" },
  ];

  const lay = layout ?? defaultLayout();
  const narrow = bounds.w > 0 && bounds.w < NARROW_W;

  const tabDefs: TabDef[] = tabs.map((t) => ({ ...t, floating: isFloating(lay, t.id) }));

  const dockedTabs = tabs.filter((t) => !isFloating(lay, t.id));
  const dockedActive = dockedTabs.some((t) => t.id === lay.activeDockedTab)
    ? lay.activeDockedTab
    : (dockedTabs[0]?.id ?? null);

  const floatingOpen = tabs.filter((t) => isFloatingOpen(lay, t.id));

  const decompileTarget = lay.targets.decompile ?? null;
  const hexTarget = lay.targets.hex ?? null;

  const labelOf = (id: string) => tabs.find((t) => t.id === id)?.label ?? id;

  const onTabChange = (id: string) => {
    if (justDragged.current) {
      justDragged.current = false;
      return;
    }
    focusModule(fileId, id);
  };
  const onPopOut = (id: string) => floatModule(fileId, id, cascadeRect(lay, bounds));

  const onTabPointerDown = (id: string, e: ReactPointerEvent<HTMLElement>) => {
    justDragged.current = false;
    if (e.button !== 0 || narrow || isFloating(lay, id)) return;
    e.currentTarget.setPointerCapture(e.pointerId);
    tabDrag.current = { id, sx: e.clientX, sy: e.clientY, dragging: false, lastX: 0, lastY: 0 };
  };

  const onTabPointerMove = (id: string, e: ReactPointerEvent<HTMLElement>) => {
    const d = tabDrag.current;
    const surf = surfaceElRef.current;
    if (!d || d.id !== id || !surf) return;
    const sr = surf.getBoundingClientRect();
    if (!d.dragging) {
      if (Math.hypot(e.clientX - d.sx, e.clientY - d.sy) < DRAG_THRESHOLD) return;
      d.dragging = true;
      const g = ghostRef.current;
      if (g) {
        g.textContent = labelOf(id);
        g.style.display = "block";
      }
    }
    d.lastX = e.clientX - sr.left;
    d.lastY = e.clientY - sr.top;
    const g = ghostRef.current;
    if (g) {
      g.style.left = `${d.lastX + 12}px`;
      g.style.top = `${d.lastY + 12}px`;
    }
  };

  const onTabPointerUp = (id: string, e: ReactPointerEvent<HTMLElement>) => {
    const d = tabDrag.current;
    tabDrag.current = null;
    const g = ghostRef.current;
    if (g) g.style.display = "none";
    if (!d || d.id !== id) return;
    e.currentTarget.releasePointerCapture?.(e.pointerId);
    if (!d.dragging) return;
    justDragged.current = true;
    const size = floatSize(bounds);
    const x = clamp(d.lastX - 24, 0, bounds.w - size.w);
    const y = clamp(d.lastY - 12, 0, bounds.h - size.h);
    floatModule(fileId, id, { x, y, ...size });
  };

  const launcherItems: LauncherItem[] = tabs.map((t) => ({
    id: t.id,
    label: t.label,
    state: !isFloating(lay, t.id) ? "docked" : isFloatingOpen(lay, t.id) ? "floating" : "hidden",
  }));

  return (
    <div className="flex flex-col h-full min-h-0">
      <Tabs
        tabs={tabDefs}
        activeId={dockedActive ?? ""}
        onChange={onTabChange}
        onPopOut={narrow ? undefined : onPopOut}
        onTabPointerDown={narrow ? undefined : onTabPointerDown}
        onTabPointerMove={narrow ? undefined : onTabPointerMove}
        onTabPointerUp={narrow ? undefined : onTabPointerUp}
        launcher={
          narrow ? undefined : (
            <ModuleLauncher
              items={launcherItems}
              onFloat={(id) => floatModule(fileId, id, cascadeRect(lay, bounds))}
              onFocus={(id) => focusModule(fileId, id)}
              onDock={(id) => dockModule(fileId, id)}
              onClose={(id) => closeModule(fileId, id)}
            />
          )
        }
        trailing={
          <span className="font-mono">
            {file.name} <span className="text-zinc-600">·</span> {file.size.toLocaleString()} B
          </span>
        }
      />
      <div ref={surfaceRef} className="relative flex-1 min-h-0">
        <div className="absolute inset-0 overflow-auto">
          {dockedActive ? (
            <ModuleView
              moduleId={dockedActive}
              file={file}
              result={r}
              decompileTarget={decompileTarget}
              hexTarget={hexTarget}
              onDecompile={navToDecompile}
              onViewHex={navToHex}
            />
          ) : (
            <div className="p-8 text-sm text-zinc-500">
              All modules are open in floating windows. Dock one (⤓) or click a tab to bring it back.
            </div>
          )}
        </div>

        <div className="absolute inset-0 pointer-events-none">
          <div
            ref={snapPreviewRef}
            style={{ display: "none", position: "absolute", left: 0, top: 0 }}
            className="z-[990] rounded-lg border-2 border-amber-400/80 bg-amber-400/10"
          />
          <div
            ref={ghostRef}
            style={{ display: "none", position: "absolute", left: 0, top: 0 }}
            className="z-[999] rounded border border-amber-400/70 bg-zinc-900/90 px-3 py-1.5 text-xs font-medium text-amber-200 shadow-xl"
          />
          {floatingOpen.map((t) => {
            const win = lay.windows[t.id];
            if (!win || win.placement.mode !== "floating") return null;
            const p = win.placement;
            return (
              <FloatingWindow
                key={t.id}
                title={t.label}
                x={p.x}
                y={p.y}
                w={p.w}
                h={p.h}
                z={p.z}
                restore={p.restore}
                bounds={bounds}
                onFocus={() => focusModule(fileId, t.id)}
                onMove={(rect) => moveWindow(fileId, t.id, rect)}
                onResize={(w, h) => resizeWindow(fileId, t.id, w, h)}
                onSnap={(rect) => snapWindow(fileId, t.id, rect)}
                onSnapPreview={showSnapPreview}
                onDock={() => dockModule(fileId, t.id)}
                onClose={() => closeModule(fileId, t.id)}
              >
                <ModuleView
                  moduleId={t.id}
                  file={file}
                  result={r}
                  decompileTarget={decompileTarget}
                  hexTarget={hexTarget}
                  onDecompile={navToDecompile}
                  onViewHex={navToHex}
                />
              </FloatingWindow>
            );
          })}
        </div>
      </div>
    </div>
  );
}
