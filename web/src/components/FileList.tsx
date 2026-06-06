import { useWorkspace } from "../store/workspace";

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

export function FileList() {
  const files = useWorkspace((s) => s.files);
  const activeId = useWorkspace((s) => s.activeId);
  const scans = useWorkspace((s) => s.scans);
  const setActive = useWorkspace((s) => s.setActive);
  const closeFile = useWorkspace((s) => s.closeFile);

  return (
    <ul className="text-sm">
      {files.map((f) => {
        const entry = scans.get(f.id);
        const active = f.id === activeId;
        const status = entry?.status ?? "loading";
        return (
          <li key={f.id} className="group relative flex border-b border-zinc-900">
            <button
              type="button"
              onClick={() => setActive(f.id)}
              className={
                "flex-1 min-w-0 text-left px-3 py-2 " +
                (active ? "bg-zinc-800" : "hover:bg-zinc-900")
              }
            >
              <div className="truncate font-medium pr-5">{f.name}</div>
              <div className="flex items-center gap-2 text-xs text-zinc-500">
                <span>{formatSize(f.size)}</span>
                <StatusDot status={status} />
              </div>
            </button>
            <button
              type="button"
              aria-label={`Close ${f.name}`}
              title="Close"
              onClick={() => closeFile(f.id)}
              className={
                "absolute top-1 right-1 flex items-center justify-center w-5 h-5 rounded leading-none " +
                "text-zinc-500 hover:bg-zinc-700 hover:text-zinc-200 focus:opacity-100 " +
                (active ? "opacity-100" : "opacity-0 group-hover:opacity-100")
              }
            >
              ×
            </button>
          </li>
        );
      })}
    </ul>
  );
}

function StatusDot({ status }: { status: string }) {
  const cls =
    status === "ready" ? "bg-emerald-500"
    : status === "error" ? "bg-red-500"
    : "bg-amber-500 animate-pulse";
  return <span className={"inline-block w-2 h-2 rounded-full " + cls} />;
}
