import { create } from "zustand";

export interface RecentFile {
  name: string;
  size: number;
  format: string;
  when: number;
}

const LS_KEY = "die-web.recent.v1";
const MAX = 25;

function load(): RecentFile[] {
  try {
    const raw = localStorage.getItem(LS_KEY);
    if (!raw) return [];
    const a = JSON.parse(raw);
    return Array.isArray(a) ? (a as RecentFile[]).slice(0, MAX) : [];
  } catch { return []; }
}
function save(list: RecentFile[]): void {
  try { localStorage.setItem(LS_KEY, JSON.stringify(list)); } catch {}
}

interface RecentState {
  items: RecentFile[];
  clear(): void;
}

export const useRecent = create<RecentState>((set) => ({
  items: load(),
  clear() { save([]); set({ items: [] }); },
}));

export function recordRecentFile(f: RecentFile): void {
  const cur = useRecent.getState().items;
  const next = [f, ...cur.filter((x) => !(x.name === f.name && x.size === f.size))].slice(0, MAX);
  save(next);
  useRecent.setState({ items: next });
}
