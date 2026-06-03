import { useState } from "react";

import { useSettings, type Settings } from "../store/settings";
import { useWorkspace } from "../store/workspace";

const SCAN_FLAGS: { key: Extract<keyof Settings, string>; label: string; hint: string }[] = [
  { key: "deepScan",       label: "Deep scan",       hint: "more thorough format analysis" },
  { key: "heuristicScan",  label: "Heuristic scan",  hint: "run heuristic detection rules" },
  { key: "aggressiveScan", label: "Aggressive scan", hint: "broader, noisier matching" },
  { key: "recursiveScan",  label: "Recursive scan",  hint: "descend into embedded objects" },
  { key: "overlayScan",    label: "Overlay scan",    hint: "scan appended overlay data" },
  { key: "resourcesScan",  label: "Resources scan",  hint: "scan PE resources" },
  { key: "archivesScan",   label: "Archives scan",   hint: "scan archive members" },
  { key: "verbose",        label: "Verbose",         hint: "per-language records & extra detail" },
];

export function SettingsDialog({ onClose }: { onClose(): void }) {
  const s = useSettings();
  const rescanAll = useWorkspace((w) => w.rescanAll);
  const filesCount = useWorkspace((w) => w.files.length);
  const [rescanning, setRescanning] = useState(false);

  const doRescan = async () => {
    setRescanning(true);
    try { await rescanAll(); } finally { setRescanning(false); }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60" onClick={onClose}>
      <div
        className="bg-zinc-950 border border-zinc-800 rounded-lg w-[28rem] max-w-[92vw] p-5 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-semibold">Settings</h2>
          <button onClick={onClose} className="text-zinc-500 hover:text-zinc-200 text-xl leading-none">×</button>
        </div>

        <h3 className="text-xs uppercase tracking-wide text-zinc-500 mb-2">Scan flags</h3>
        <div className="space-y-1.5 text-sm mb-4">
          {SCAN_FLAGS.map(({ key, label, hint }) => (
            <label key={key} className="flex items-start gap-2 cursor-pointer">
              <input
                type="checkbox"
                className="mt-1"
                checked={s[key] as boolean}
                onChange={(e) => s.set(key, e.target.checked)}
              />
              <span>
                <span className="text-zinc-200">{label}</span>{" "}
                <span className="text-zinc-600 text-xs">- {hint}</span>
              </span>
            </label>
          ))}
        </div>

        <h3 className="text-xs uppercase tracking-wide text-zinc-500 mb-2">Strings panel</h3>
        <label className="flex items-center gap-2 text-sm mb-1">
          <span className="text-zinc-300">Minimum string length</span>
          <input
            type="number" min={1} max={64} value={s.stringsMinLen}
            onChange={(e) => s.set("stringsMinLen", Math.max(1, Math.min(64, Math.trunc(Number(e.target.value)) || 4)))}
            className="w-16 px-2 py-1 bg-zinc-900 border border-zinc-800 rounded font-mono"
          />
        </label>

        <div className="flex items-center gap-2 pt-3 mt-3 border-t border-zinc-800">
          <button onClick={() => s.reset()} className="px-2 py-1 text-xs rounded bg-zinc-800 hover:bg-zinc-700">Restore defaults</button>
          <button
            onClick={doRescan}
            disabled={rescanning || filesCount === 0}
            className="px-2 py-1 text-xs rounded bg-zinc-800 hover:bg-zinc-700 disabled:opacity-50"
          >
            {rescanning ? "Re-scanning…" : `Re-scan open file${filesCount === 1 ? "" : "s"}`}
          </button>
          <button onClick={onClose} className="ml-auto px-3 py-1 text-xs rounded bg-zinc-700 hover:bg-zinc-600">Done</button>
        </div>
        <p className="text-[11px] text-zinc-600 mt-2">
          Changes apply to the next scan; use "Re-scan" to apply them to files already open.
        </p>
      </div>
    </div>
  );
}
