import { create } from "zustand";

import { ScanClient } from "../worker/client";
import type { ScanResult } from "../worker/protocol";
import { useSettings, scanOptionsFromSettings } from "./settings";
import { recordRecentFile } from "./recent";

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

  addFile(file: DroppedFile): Promise<void>;
  ingestFiles(list: FileList | File[]): Promise<void>;
  rescan(id: string): Promise<void>;
  rescanAll(): Promise<void>;
  setActive(id: string): void;
  closeFile(id: string): void;
  clear(): void;
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

  return {
    client,
    files: [],
    activeId: null,
    scans: new Map(),

    async addFile(file) {
      set((s) => ({ files: [...s.files, file], activeId: file.id }));
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
        const activeId =
          s.activeId === id
            ? (s.files[idx + 1] ?? s.files[idx - 1] ?? null)?.id ?? null
            : s.activeId;
        return { files, scans, activeId };
      });
    },

    clear() {
      get().client.dispose();
      set({ files: [], activeId: null, scans: new Map() });
    },
  };
});
