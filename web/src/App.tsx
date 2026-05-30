import { useState } from "react";

import { useWorkspace } from "./store/workspace";
import { useRecent } from "./store/recent";
import { DropZone } from "./components/DropZone";
import { FileList } from "./components/FileList";
import { ScanResultPanel } from "./components/ScanResultPanel";
import { SettingsDialog } from "./components/SettingsDialog";

function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(2)} MB`;
}
function timeAgo(when: number): string {
  const s = Math.max(0, Math.floor((Date.now() - when) / 1000));
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

function RecentMenu() {
  const recent = useRecent((s) => s.items);
  const clearRecent = useRecent((s) => s.clear);
  const [open, setOpen] = useState(false);
  if (recent.length === 0) return null;
  return (
    <div className="relative">
      <button onClick={() => setOpen((v) => !v)} className="px-2 py-1 text-xs rounded hover:bg-zinc-800 text-zinc-400">
        Recent ▾
      </button>
      {open ? (
        <div
          className="absolute right-0 mt-1 w-80 max-h-80 overflow-auto bg-zinc-950 border border-zinc-800 rounded shadow-2xl z-50 text-xs"
          onMouseLeave={() => setOpen(false)}
        >
          <div className="px-3 py-1.5 flex items-center justify-between border-b border-zinc-800 text-zinc-500 sticky top-0 bg-zinc-950">
            <span>Recently scanned (this browser)</span>
            <button onClick={() => { clearRecent(); setOpen(false); }} className="hover:text-zinc-300">clear</button>
          </div>
          {recent.map((r, i) => (
            <div key={i} className="px-3 py-1.5 border-b border-zinc-900 last:border-0">
              <div className="font-mono text-zinc-300 truncate" title={r.name}>{r.name}</div>
              <div className="text-zinc-600">{r.format} · {fmtBytes(r.size)} · {timeAgo(r.when)}</div>
            </div>
          ))}
        </div>
      ) : null}
    </div>
  );
}

export function App() {
  const files = useWorkspace((s) => s.files);
  const activeId = useWorkspace((s) => s.activeId);
  const [showSettings, setShowSettings] = useState(false);
  const [showSidebar, setShowSidebar] = useState(true);

  return (
    <div className="h-full flex flex-col">
      <header className="px-4 py-2 border-b border-zinc-800 flex items-center gap-3">
        {files.length > 0 ? (
          <button
            onClick={() => setShowSidebar((v) => !v)}
            title={showSidebar ? "Hide file list" : "Show file list"}
            aria-label={showSidebar ? "Hide file list" : "Show file list"}
            aria-pressed={showSidebar}
            className="px-2 py-1 text-sm rounded hover:bg-zinc-800 text-zinc-400"
          >
            ☰
          </button>
        ) : null}
        <span className="font-semibold">DIE-Web</span>
        <span className="text-xs text-zinc-500">Detect It Easy in your browser</span>
        <div className="ml-auto flex items-center gap-1">
          <RecentMenu />
          <button
            onClick={() => setShowSettings(true)}
            title="Settings"
            className="px-2 py-1 text-sm rounded hover:bg-zinc-800 text-zinc-400"
          >
            ⚙
          </button>
        </div>
      </header>

      {files.length === 0 ? (
        <div className="flex-1 flex items-center justify-center p-8">
          <DropZone />
        </div>
      ) : (
        <div className={`flex-1 grid min-h-0 ${showSidebar ? "grid-cols-[260px_1fr]" : "grid-cols-1"}`}>
          {showSidebar ? (
            <aside className="border-r border-zinc-800 overflow-y-auto">
              <FileList />
              <div className="p-3 border-t border-zinc-800">
                <DropZone compact />
              </div>
            </aside>
          ) : null}
          <main className="overflow-y-auto">
            {activeId ? <ScanResultPanel fileId={activeId} /> : null}
          </main>
        </div>
      )}

      {showSettings ? <SettingsDialog onClose={() => setShowSettings(false)} /> : null}
    </div>
  );
}
