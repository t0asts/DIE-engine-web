import type { Config } from "tailwindcss";

const STEPS = [50, 100, 200, 300, 400, 500, 600, 700, 800, 900, 950] as const;

function themed(name: string): Record<string, string> {
  return Object.fromEntries(
    STEPS.map((step) => [step, `rgb(var(--c-${name}-${step}) / <alpha-value>)`]),
  );
}

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  darkMode: ["class", '[data-theme="dark"]'],
  theme: {
    extend: {
      colors: {
        zinc: themed("zinc"),
        amber: themed("amber"),
        red: themed("red"),
        emerald: themed("emerald"),
        sky: themed("sky"),
        orange: themed("orange"),
      },
      fontFamily: {
        mono: ["ui-monospace", "Menlo", "Consolas", "monospace"],
      },
    },
  },
  plugins: [],
} satisfies Config;
