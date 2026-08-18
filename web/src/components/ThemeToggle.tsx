import { useTheme } from "../store/theme";

function SunIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true" className="w-3 h-3" fill="none"
         stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
      <circle cx="12" cy="12" r="4.5" />
      <path d="M12 1.8v2.4M12 19.8v2.4M4.6 4.6l1.7 1.7M17.7 17.7l1.7 1.7M1.8 12h2.4M19.8 12h2.4M4.6 19.4l1.7-1.7M17.7 6.3l1.7-1.7" />
    </svg>
  );
}

function MoonIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true" className="w-3 h-3" fill="currentColor">
      <path d="M21 13.2A9 9 0 1 1 10.8 3a7.2 7.2 0 0 0 10.2 10.2Z" />
    </svg>
  );
}

export function ThemeToggle() {
  const theme = useTheme((s) => s.theme);
  const toggle = useTheme((s) => s.toggle);
  const isLight = theme === "light";

  return (
    <button
      type="button"
      role="switch"
      aria-checked={isLight}
      aria-label="Light mode"
      title={isLight ? "Switch to dark theme" : "Switch to light theme"}
      onClick={toggle}
      className="relative inline-flex items-center w-11 h-6 shrink-0 rounded-full border border-zinc-700 bg-zinc-800 transition-colors hover:border-zinc-600"
    >
      <span
        className={
          "inline-flex items-center justify-center w-[18px] h-[18px] ml-[3px] rounded-full bg-zinc-400 text-zinc-950 transition-transform duration-200 " +
          (isLight ? "translate-x-5" : "translate-x-0")
        }
      >
        {isLight ? <SunIcon /> : <MoonIcon />}
      </span>
    </button>
  );
}
