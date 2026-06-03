import { create } from "zustand";

import { ScanClient } from "../worker/client";
import type { ScanResult } from "../worker/protocol";
import { useSettings, scanOptionsFromSettings } from "./settings";
import { recordRecentFile } from "./recent";

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
  rescan(id: string): Promise<void>;
  rescanAll(): Promise<void>;
  setActive(id: string): void;
  clear(): void;
}

export const useWorkspace = create<WorkspaceState>((set, get) => {
  const client = new ScanClient();

  async function runScanFor(file: DroppedFile): Promise<void> {
    set((s) => { const next = new Map(s.scans); next.set(file.id, { status: "loading" }); return { scans: next }; });
    try {
      const result = await client.scan(file.bytes.slice(0), scanOptionsFromSettings(useSettings.getState()));
      set((s) => { const next = new Map(s.scans); next.set(file.id, { status: "ready", result }); return { scans: next }; });
      recordRecentFile({ name: file.name, size: file.size, format: result.fileInfo.primaryFormat, when: Date.now() });
    } catch (e) {
      set((s) => { const next = new Map(s.scans); next.set(file.id, { status: "error", error: (e as Error).message }); return { scans: next }; });
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

    clear() {
      get().client.dispose();
      set({ files: [], activeId: null, scans: new Map() });
    },
  };
});
