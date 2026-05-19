
import type { ReactNode } from "react";

export interface TabDef {
  id: string;
  label: string;
  badge?: string | number;   
}

interface Props {
  tabs: TabDef[];
  activeId: string;
  onChange(id: string): void;
  trailing?: ReactNode;       
}

export function Tabs({ tabs, activeId, onChange, trailing }: Props) {
  return (
    <div className="flex items-stretch border-b border-zinc-800 bg-zinc-950/50 sticky top-0 z-10">
      <ul className="flex">
        {tabs.map((t) => {
          const active = t.id === activeId;
          return (
            <li key={t.id}>
              <button
                type="button"
                onClick={() => onChange(t.id)}
                className={
                  "px-4 py-2 text-sm border-b-2 -mb-px transition-colors " +
                  (active
                    ? "border-amber-400 text-zinc-100"
                    : "border-transparent text-zinc-400 hover:text-zinc-200")
                }
              >
                {t.label}
                {t.badge !== undefined ? (
                  <span className="ml-2 px-1.5 py-0.5 rounded bg-zinc-800 text-xs text-zinc-400">
                    {t.badge}
                  </span>
                ) : null}
              </button>
            </li>
          );
        })}
      </ul>
      {trailing ? (
        <div className="ml-auto px-4 flex items-center text-xs text-zinc-500 truncate">
          {trailing}
        </div>
      ) : null}
    </div>
  );
}
