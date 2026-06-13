import { create } from "zustand";

import { ScanClient } from "../worker/client";
import type { ScanResult } from "../worker/protocol";
import { useSettings, scanOptionsFromSettings } from "./settings";
import { recordRecentFile } from "./recent";
import {
  type FileLayout,
  type Rect,
  type Bounds,
  defaultLayout,
  applyFloat,
  applyDock,
  applyClose,
  applyFocus,
  applyMove,
  applyResize,
  applySnap,
  applyClampAll,
} from "./layout";

function makeId(name: string): string {
  return `${name}::${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
}

export interface DroppedFile {
  id: string;
  name: string;
  size: number;
  bytes: ArrayBuffer;
}

type Status = "idle" | "loading" | "ready" | "error";

interface ScanEntry {
  status: Status;
  result?: ScanResult;
  error?: string;
}

interface WorkspaceState {
  client: ScanClient;
  files: DroppedFile[];
  activeId: string | null;
  scans: Map<string, ScanEntry>;
  layouts: Map<string, FileLayout>;

  addFile(file: DroppedFile): Promise<void>;
  ingestFiles(list: FileList | File[]): Promise<void>;
  rescan(id: string): Promise<void>;
  rescanAll(): Promise<void>;
  setActive(id: string): void;
  closeFile(id: string): void;
  closeAll(): void;
  clear(): void;

  setActiveTab(id: string, moduleId: string): void;
  floatModule(id: string, moduleId: string, rect: Rect): void;
  dockModule(id: string, moduleId: string): void;
  closeModule(id: string, moduleId: string): void;
  focusModule(id: string, moduleId: string): void;
  moveWindow(id: string, moduleId: string, rect: Rect): void;
  resizeWindow(id: string, moduleId: string, w: number, h: number): void;
  snapWindow(id: string, moduleId: string, rect: Rect): void;
  clampWindows(id: string, bounds: Bounds): void;
  navToDecompile(id: string, addr: number): void;
  navToHex(id: string, offset: number): void;
}

export const useWorkspace = create<WorkspaceState>((set, get) => {
  const client = new ScanClient();

  function setScan(id: string, entry: ScanEntry): void {
    set((s) => {
      if (!s.files.some((f) => f.id === id)) return s;
      const next = new Map(s.scans);
      next.set(id, entry);
      return { scans: next };
    });
  }

  async function runScanFor(file: DroppedFile): Promise<void> {
    setScan(file.id, { status: "loading" });
    try {
      const result = await client.scan(file.bytes.slice(0), scanOptionsFromSettings(useSettings.getState()));
      setScan(file.id, { status: "ready", result });
      recordRecentFile({ name: file.name, size: file.size, format: result.fileInfo.primaryFormat, when: Date.now() });
    } catch (e) {
      setScan(file.id, { status: "error", error: (e as Error).message });
    }
  }

  function updateLayout(id: string, fn: (cur: FileLayout) => FileLayout): void {
    set((s) => {
      const layouts = new Map(s.layouts);
      layouts.set(id, fn(layouts.get(id) ?? defaultLayout()));
      return { layouts };
    });
  }

  return {
    client,
    files: [],
    activeId: null,
    scans: new Map(),
    layouts: new Map(),

    async addFile(file) {
      set((s) => {
        const layouts = new Map(s.layouts);
        layouts.set(file.id, defaultLayout());
        return { files: [...s.files, file], activeId: file.id, layouts };
      });
      await runScanFor(file);
    },

    async ingestFiles(list) {
      for (const file of Array.from(list)) {
        const buf = await file.arrayBuffer();
        await get().addFile({ id: makeId(file.name), name: file.name, size: file.size, bytes: buf });
      }
    },

    async rescan(id) {
      const file = get().files.find((f) => f.id === id);
      if (file) await runScanFor(file);
    },

    async rescanAll() {
      await Promise.all(get().files.map((f) => runScanFor(f)));
    },

    setActive(id) {
      set({ activeId: id });
    },

    closeFile(id) {
      set((s) => {
        const idx = s.files.findIndex((f) => f.id === id);
        if (idx === -1) return s;
        const files = s.files.filter((f) => f.id !== id);
        const scans = new Map(s.scans);
        scans.delete(id);
        const layouts = new Map(s.layouts);
        layouts.delete(id);
        const activeId =
          s.activeId === id
            ? (s.files[idx + 1] ?? s.files[idx - 1] ?? null)?.id ?? null
            : s.activeId;
        return { files, scans, layouts, activeId };
      });
    },

    closeAll() {
      set({ files: [], activeId: null, scans: new Map(), layouts: new Map() });
    },

    clear() {
      get().client.dispose();
      set({ files: [], activeId: null, scans: new Map(), layouts: new Map() });
    },

    setActiveTab(id, moduleId) {
      updateLayout(id, (cur) => ({ ...cur, activeDockedTab: moduleId }));
    },

    floatModule(id, moduleId, rect) {
      updateLayout(id, (cur) => applyFloat(cur, moduleId, rect));
    },

    dockModule(id, moduleId) {
      updateLayout(id, (cur) => applyDock(cur, moduleId, true));
    },

    closeModule(id, moduleId) {
      updateLayout(id, (cur) => applyClose(cur, moduleId));
    },

    focusModule(id, moduleId) {
      updateLayout(id, (cur) => applyFocus(cur, moduleId));
    },

    moveWindow(id, moduleId, rect) {
      updateLayout(id, (cur) => applyMove(cur, moduleId, rect));
    },

    resizeWindow(id, moduleId, w, h) {
      updateLayout(id, (cur) => applyResize(cur, moduleId, w, h));
    },

    snapWindow(id, moduleId, rect) {
      updateLayout(id, (cur) => applySnap(cur, moduleId, rect));
    },

    clampWindows(id, bounds) {
      set((s) => {
        const cur = s.layouts.get(id);
        if (!cur) return s;
        const next = applyClampAll(cur, bounds);
        if (next === cur) return s;
        const layouts = new Map(s.layouts);
        layouts.set(id, next);
        return { layouts };
      });
    },

    navToDecompile(id, addr) {
      updateLayout(id, (cur) => {
        const l = applyFocus(cur, "decompile");
        return { ...l, targets: { ...l.targets, decompile: { addr, nonce: (cur.targets.decompile?.nonce ?? 0) + 1 } } };
      });
    },

    navToHex(id, offset) {
      updateLayout(id, (cur) => {
        const l = applyFocus(cur, "hex");
        return { ...l, targets: { ...l.targets, hex: { offset, nonce: (cur.targets.hex?.nonce ?? 0) + 1 } } };
      });
    },
  };
});
