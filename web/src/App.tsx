import { useState } from "react";

import { useWorkspace } from "./store/workspace";
import { useRecent } from "./store/recent";
import { DropZone } from "./components/DropZone";
import { FileList } from "./components/FileList";
import { ScanResultPanel } from "./components/ScanResultPanel";
import { SettingsDialog } from "./components/SettingsDialog";
import { useDropUpload } from "./components/useDropUpload";

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
  const { isDragging, dropHandlers } = useDropUpload();

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
          <a
            href="https://github.com/t0asts/DIE-engine-web"
            target="_blank"
            rel="noreferrer noopener"
            title="Source on GitHub"
            aria-label="Source on GitHub"
            className="px-2 py-1 rounded inline-flex items-center hover:bg-zinc-800 text-zinc-400 hover:text-zinc-200"
          >
            <svg viewBox="0 0 16 16" aria-hidden="true" className="w-4 h-4" fill="currentColor">
              <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27s1.36.09 2 .27c1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8Z" />
            </svg>
          </a>
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
            <aside
              {...dropHandlers}
              className={
                "border-r border-zinc-800 overflow-y-auto relative " +
                (isDragging ? "ring-2 ring-inset ring-amber-400/70 bg-amber-400/5" : "")
              }
            >
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
