import { useEffect, useRef, useState } from "react";

export interface LauncherItem {
  id: string;
  label: string;
  state: "docked" | "floating" | "hidden";
}

interface Props {
  items: LauncherItem[];
  onFloat(id: string): void;
  onFocus(id: string): void;
  onDock(id: string): void;
  onClose(id: string): void;
}

const STATE_LABEL: Record<LauncherItem["state"], string> = {
  docked: "docked",
  floating: "floating",
  hidden: "hidden",
};

export function ModuleLauncher({ items, onFloat, onFocus, onDock, onClose }: Props) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, [open]);

  const act = (fn: (id: string) => void, id: string) => {
    fn(id);
    setOpen(false);
  };

  const iconBtn = "px-1 text-zinc-500 hover:text-zinc-200 leading-none";

  return (
    <div ref={ref} className="relative flex items-center">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        title="Open a module"
        aria-label="Open a module"
        aria-expanded={open}
        className="px-2 py-1 text-sm rounded text-zinc-400 hover:bg-zinc-800 hover:text-zinc-200"
      >
        ＋
      </button>
      {open ? (
        <div className="absolute left-0 top-full mt-1 w-60 max-h-96 overflow-auto bg-zinc-950 border border-zinc-800 rounded shadow-2xl z-50 text-xs py-1">
          {items.map((it) => (
            <div key={it.id} className="flex items-center gap-2 px-2 py-1 hover:bg-zinc-900">
              <button
                type="button"
                onClick={() => act(onFocus, it.id)}
                className="flex-1 min-w-0 text-left truncate text-zinc-200"
                title={it.state === "hidden" ? "Reopen" : "Show"}
              >
                {it.label}
              </button>
              <span className="text-[10px] uppercase tracking-wide text-zinc-600">
                {STATE_LABEL[it.state]}
              </span>
              {it.state === "docked" ? (
                <button type="button" title="Float" aria-label={`Float ${it.label}`} className={iconBtn} onClick={() => act(onFloat, it.id)}>
                  ⤢
                </button>
              ) : (
                <>
                  <button type="button" title="Dock" aria-label={`Dock ${it.label}`} className={iconBtn} onClick={() => act(onDock, it.id)}>
                    ⤓
                  </button>
                  {it.state === "floating" ? (
                    <button type="button" title="Close" aria-label={`Close ${it.label}`} className={iconBtn} onClick={() => act(onClose, it.id)}>
                      ×
                    </button>
                  ) : null}
                </>
              )}
            </div>
          ))}
        </div>
      ) : null}
    </div>
  );
}
