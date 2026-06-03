import { create } from "zustand";

import type { ScanOptions } from "../worker/protocol";

export interface Settings {
  deepScan: boolean;
  heuristicScan: boolean;
  aggressiveScan: boolean;
  recursiveScan: boolean;
  overlayScan: boolean;
  resourcesScan: boolean;
  archivesScan: boolean;
  verbose: boolean;

  stringsMinLen: number;
}

export const SETTINGS_DEFAULTS: Settings = {
  deepScan: true,
  heuristicScan: true,
  aggressiveScan: false,
  recursiveScan: false,
  overlayScan: true,
  resourcesScan: true,
  archivesScan: true,
  verbose: true,
  stringsMinLen: 4,
};

const LS_KEY = "die-web.settings.v1";

function loadSettings(): Settings {
  try {
    const raw = localStorage.getItem(LS_KEY);
    if (!raw) return { ...SETTINGS_DEFAULTS };
    const parsed = JSON.parse(raw) as Partial<Settings>;
    const out = { ...SETTINGS_DEFAULTS, ...parsed };
    if (!(out.stringsMinLen >= 1 && out.stringsMinLen <= 64)) out.stringsMinLen = SETTINGS_DEFAULTS.stringsMinLen;
    return out;
  } catch {
    return { ...SETTINGS_DEFAULTS };
  }
}

interface SettingsState extends Settings {
  set<K extends keyof Settings>(key: K, value: Settings[K]): void;
  reset(): void;
}

function persist(state: SettingsState): void {
  const { set, reset, ...data } = state;
  void set; void reset;
  try { localStorage.setItem(LS_KEY, JSON.stringify(data)); } catch {}
}

export const useSettings = create<SettingsState>((setState, getState) => ({
  ...loadSettings(),
  set(key, value) {
    setState({ [key]: value } as Partial<SettingsState>);
    persist(getState());
  },
  reset() {
    setState({ ...SETTINGS_DEFAULTS } as Partial<SettingsState>);
    persist(getState());
  },
}));

export function scanOptionsFromSettings(s: Settings): ScanOptions {
  return {
    deepScan: s.deepScan,
    heuristicScan: s.heuristicScan,
    aggressiveScan: s.aggressiveScan,
    recursiveScan: s.recursiveScan,
    overlayScan: s.overlayScan,
    resourcesScan: s.resourcesScan,
    archivesScan: s.archivesScan,
    verbose: s.verbose,
    stringsMinLen: s.stringsMinLen,
  };
}
