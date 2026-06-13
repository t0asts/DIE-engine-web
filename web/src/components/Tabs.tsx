import type { PointerEvent as ReactPointerEvent, ReactNode } from "react";

export interface TabDef {
  id: string;
  label: string;
  badge?: string | number;
  floating?: boolean;
}

interface Props {
  tabs: TabDef[];
  activeId: string;
  onChange(id: string): void;
  onPopOut?(id: string): void;
  onTabPointerDown?(id: string, e: ReactPointerEvent<HTMLElement>): void;
  onTabPointerMove?(id: string, e: ReactPointerEvent<HTMLElement>): void;
  onTabPointerUp?(id: string, e: ReactPointerEvent<HTMLElement>): void;
  launcher?: ReactNode;
  trailing?: ReactNode;
}

export function Tabs({
  tabs, activeId, onChange, onPopOut,
  onTabPointerDown, onTabPointerMove, onTabPointerUp,
  launcher, trailing,
}: Props) {
  const dragEnabled = !!onTabPointerDown;
  return (
    <div className="flex items-stretch border-b border-zinc-800 bg-zinc-950/50 sticky top-0 z-10">
      <ul className="flex">
        {tabs.map((t) => {
          const active = t.id === activeId;
          return (
            <li key={t.id} className="group relative flex items-stretch">
              <button
                type="button"
                onClick={() => onChange(t.id)}
                onPointerDown={onTabPointerDown ? (e) => onTabPointerDown(t.id, e) : undefined}
                onPointerMove={onTabPointerMove ? (e) => onTabPointerMove(t.id, e) : undefined}
                onPointerUp={onTabPointerUp ? (e) => onTabPointerUp(t.id, e) : undefined}
                onPointerCancel={onTabPointerUp ? (e) => onTabPointerUp(t.id, e) : undefined}
                style={dragEnabled ? { touchAction: "none" } : undefined}
                title={t.floating ? `${t.label} (floating - click to focus)` : undefined}
                className={
                  "pl-4 py-2 text-sm border-b-2 -mb-px transition-colors " +
                  (onPopOut ? "pr-7 " : "pr-4 ") +
                  (active
                    ? "border-amber-400 text-zinc-100"
                    : t.floating
                      ? "border-transparent text-zinc-500 italic hover:text-zinc-300"
                      : "border-transparent text-zinc-400 hover:text-zinc-200")
                }
              >
                {t.label}
                {t.floating ? <span className="ml-1 text-amber-400/80">↗</span> : null}
                {t.badge !== undefined ? (
                  <span className="ml-2 px-1.5 py-0.5 rounded bg-zinc-800 text-xs text-zinc-400">
                    {t.badge}
                  </span>
                ) : null}
              </button>
              {onPopOut && !t.floating ? (
                <button
                  type="button"
                  title="Pop out to window"
                  aria-label={`Pop out ${t.label} to a window`}
                  onPointerDown={(e) => e.stopPropagation()}
                  onClick={(e) => {
                    e.stopPropagation();
                    onPopOut(t.id);
                  }}
                  className="absolute right-1 top-1/2 -translate-y-1/2 px-1 text-xs leading-none text-zinc-600 opacity-0 group-hover:opacity-100 hover:text-zinc-200"
                >
                  ⤢
                </button>
              ) : null}
            </li>
          );
        })}
      </ul>
      {launcher ? <div className="flex items-center pl-1">{launcher}</div> : null}
      {trailing ? (
        <div className="ml-auto px-4 flex items-center text-xs text-zinc-500 truncate">
          {trailing}
        </div>
      ) : null}
    </div>
  );
}
