import { create } from "zustand";

export type Theme = "dark" | "light";

const LS_KEY = "die-web.theme.v1";

function systemTheme(): Theme {
  try {
    return window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
  } catch { return "dark"; }
}

function load(): Theme {
  try {
    const raw = localStorage.getItem(LS_KEY);
    if (raw === "dark" || raw === "light") return raw;
  } catch {}
  return systemTheme();
}

function save(theme: Theme): void {
  try { localStorage.setItem(LS_KEY, theme); } catch {}
}

function apply(theme: Theme): void {
  document.documentElement.dataset.theme = theme;
}

interface ThemeState {
  theme: Theme;
  setTheme(theme: Theme): void;
  toggle(): void;
}

export const useTheme = create<ThemeState>((set, get) => ({
  theme: load(),
  setTheme(theme) {
    apply(theme);
    save(theme);
    set({ theme });
  },
  toggle() {
    get().setTheme(get().theme === "dark" ? "light" : "dark");
  },
}));

apply(useTheme.getState().theme);
