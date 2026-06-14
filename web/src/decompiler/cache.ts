import type { ScanResult } from "../worker/protocol";
import type { DecompilerSession } from "./client";
import type { DecompFunction } from "./protocol";

export interface DecompFileState {
  languageId: string;
  result: ScanResult | null;
  session: DecompilerSession | null;
  opening: Promise<DecompilerSession> | null;
  code: Map<number, string>;
  discovered: Map<number, DecompFunction>;
  selected: number | null;
  filter: string;
  lastTargetNonce: number;
  discoverCancel: { cancelled: boolean } | null;
  lastUsed: number;
  viewState: Map<number, unknown>;
}

const MAX_LIVE_SESSIONS = 3;

const registry = new Map<string, DecompFileState>();
let useTick = 0;

function makeState(languageId: string): DecompFileState {
  return {
    languageId,
    result: null,
    session: null,
    opening: null,
    code: new Map(),
    discovered: new Map(),
    selected: null,
    filter: "",
    lastTargetNonce: -1,
    discoverCancel: null,
    lastUsed: 0,
    viewState: new Map(),
  };
}

function teardown(st: DecompFileState): void {
  if (st.discoverCancel) st.discoverCancel.cancelled = true;
  void st.session?.close();
  if (st.opening) void st.opening.then((s) => s.close()).catch(() => {});
}

export function getDecompState(fileId: string, languageId: string): DecompFileState {
  const existing = registry.get(fileId);
  if (existing) {
    if (existing.languageId === languageId) return existing;
    teardown(existing);
  }
  const fresh = makeState(languageId);
  registry.set(fileId, fresh);
  return fresh;
}

export function markSessionUsed(fileId: string): void {
  const st = registry.get(fileId);
  if (!st) return;
  st.lastUsed = ++useTick;

  const live: DecompFileState[] = [];
  for (const s of registry.values()) if (s.session && !s.opening) live.push(s);
  if (live.length <= MAX_LIVE_SESSIONS) return;

  live.sort((a, b) => a.lastUsed - b.lastUsed);
  for (let i = 0; i < live.length - MAX_LIVE_SESSIONS; i++) {
    const victim = live[i]!;
    if (victim.discoverCancel) victim.discoverCancel.cancelled = true;
    void victim.session?.close();
    victim.session = null;
  }
}

export function evictDecompState(fileId: string): void {
  const st = registry.get(fileId);
  if (!st) return;
  registry.delete(fileId);
  teardown(st);
}

export function evictAllDecompState(): void {
  for (const st of registry.values()) teardown(st);
  registry.clear();
}
