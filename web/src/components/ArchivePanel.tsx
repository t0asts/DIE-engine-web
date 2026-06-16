import { useMemo, useState } from "react";

import { useWorkspace } from "../store/workspace";
import type { ArchiveListing, ArchiveEntry } from "../worker/protocol";

interface Props {
  archive: ArchiveListing;
  bytes: ArrayBuffer;
  parentName: string;
}

type SortKey = "name" | "size" | "compressedSize" | "ratio";

let uniq = 0;
const newId = () => (typeof crypto !== "undefined" && crypto.randomUUID ? crypto.randomUUID() : `f${Date.now()}_${++uniq}`);

const EXTRACTABLE_METHODS = new Set(["store", "deflate", "aes", "stream", "mszip"]);
const extractable = (e: ArchiveEntry) => !e.isDir && EXTRACTABLE_METHODS.has(e.method);

function fmtSize(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(2)} MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

function ratio(e: ArchiveEntry): number {
  if (e.isDir || e.size === 0) return 1;
  return e.compressedSize / e.size;
}

export function ArchivePanel({ archive, bytes, parentName }: Props) {
  const client = useWorkspace((s) => s.client);
  const addFile = useWorkspace((s) => s.addFile);
  const [filter, setFilter] = useState("");
  const [sortKey, setSortKey] = useState<SortKey>("name");
  const [asc, setAsc] = useState(true);
  const [hideDirs, setHideDirs] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [err, setErr] = useState<{ name: string; msg: string } | null>(null);
  const [password, setPassword] = useState("");

  const hasEncrypted = useMemo(() => archive.entries.some((e) => e.encrypted), [archive.entries]);

  const scanEntry = async (e: ArchiveEntry) => {
    setBusy(e.name); setErr(null);
    try {
      const data = await client.extractArchiveEntry(bytes, e.name, password || undefined);
      const base = parentName.split("/").pop() || parentName;
      const member = e.name.split("/").pop() || e.name;
      await addFile({ id: newId(), name: `${base}!${member}`, size: data.byteLength, bytes: data });
    } catch (ex) {
      setErr({ name: e.name, msg: (ex as Error).message });
    } finally {
      setBusy(null);
    }
  };

  const rows = useMemo(() => {
    const f = filter.toLowerCase();
    let list = archive.entries.filter((e) => {
      if (hideDirs && e.isDir) return false;
      if (f && !e.name.toLowerCase().includes(f)) return false;
      return true;
    });
    list = [...list].sort((a, b) => {
      let cmp = 0;
      switch (sortKey) {
        case "name": cmp = a.name < b.name ? -1 : a.name > b.name ? 1 : 0; break;
        case "size": cmp = a.size - b.size; break;
        case "compressedSize": cmp = a.compressedSize - b.compressedSize; break;
        case "ratio": cmp = ratio(a) - ratio(b); break;
      }
      return asc ? cmp : -cmp;
    });
    return list;
  }, [archive.entries, filter, sortKey, asc, hideDirs]);

  const overallRatio = archive.totalSize > 0
    ? (archive.totalCompressedSize / archive.totalSize * 100).toFixed(1) + "%"
    : "-";

  const th = (key: SortKey, label: string, extra = "") => (
    <th
      className={`px-3 py-1.5 cursor-pointer select-none hover:text-zinc-300 ${extra}`}
      onClick={() => { if (sortKey === key) setAsc(!asc); else { setSortKey(key); setAsc(true); } }}
      title="Sort"
    >
      {label}{sortKey === key ? (asc ? " ▲" : " ▼") : ""}
    </th>
  );

  return (
    <div className="p-4 flex flex-col h-full min-h-0">
      <section className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-sm mb-3">
        <span className="text-zinc-500">Type</span>
        <span className="font-mono">{archive.kind}{archive.note ? ` (${archive.note})` : ""}</span>
        <span className="text-zinc-500">Entries</span>
        <span className="font-mono">
          {archive.totalEntries.toLocaleString()}
          {archive.truncated ? <span className="text-amber-500"> · showing first {archive.entries.length.toLocaleString()}</span> : null}
        </span>
        <span className="text-zinc-500">Uncompressed</span>
        <span className="font-mono">{fmtSize(archive.totalSize)}</span>
        <span className="text-zinc-500">Compressed</span>
        <span className="font-mono">{fmtSize(archive.totalCompressedSize)} <span className="text-zinc-600">({overallRatio})</span></span>
        {archive.comment ? (<>
          <span className="text-zinc-500">Comment</span>
          <span className="font-mono break-all">{archive.comment}</span>
        </>) : null}
      </section>

      <div className="flex flex-wrap items-center gap-2 mb-3">
        <input
          type="text"
          placeholder="Filter path…"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          className="px-2 py-1 text-sm bg-zinc-900 border border-zinc-800 rounded flex-1 min-w-[200px]"
        />
        <label className="text-xs text-zinc-400 flex items-center gap-1.5">
          <input type="checkbox" checked={hideDirs} onChange={(e) => setHideDirs(e.target.checked)} />
          hide directories
        </label>
        {hasEncrypted ? (
          <input
            type="text"
            placeholder="Password (for encrypted entries)…"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="off"
            spellCheck={false}
            className="px-2 py-1 text-sm bg-zinc-900 border border-amber-900/60 rounded w-56 font-mono"
          />
        ) : null}
        <span className="text-xs text-zinc-500">{rows.length.toLocaleString()} shown</span>
      </div>

      {err ? (
        <div className="text-red-400 text-xs font-mono mb-2">
          extract "{err.name}": {err.msg}
          {/password/i.test(err.msg) && hasEncrypted
            ? " - enter the password above and try again."
            : ""}
        </div>
      ) : null}

      <div className="flex-1 overflow-auto border border-zinc-800 rounded">
        <table className="w-full font-mono text-xs">
          <thead className="bg-zinc-900 sticky top-0 text-left text-zinc-500">
            <tr>
              {th("name", "Name")}
              {th("size", "Size", "w-24")}
              {th("compressedSize", "Packed", "w-24")}
              {th("ratio", "Ratio", "w-20")}
              <th className="px-3 py-1.5 w-20">Method</th>
              <th className="px-3 py-1.5 w-36">Modified</th>
              <th className="px-3 py-1.5 w-16" />
            </tr>
          </thead>
          <tbody>
            {rows.map((e, i) => (
              <tr key={i} className="border-t border-zinc-900 hover:bg-zinc-900/50">
                <td className={`px-3 py-1 truncate max-w-[420px] ${e.isDir ? "text-sky-400" : "text-zinc-200"}`} title={e.name}>
                  {e.isDir ? "📁 " : ""}{e.name}{e.encrypted ? <span className="text-amber-500" title="Encrypted"> 🔒</span> : null}
                </td>
                <td className="px-3 py-1 text-zinc-400">{e.isDir ? "-" : fmtSize(e.size)}</td>
                <td className="px-3 py-1 text-zinc-500">{e.isDir ? "-" : fmtSize(e.compressedSize)}</td>
                <td className="px-3 py-1 text-zinc-500">{e.isDir || e.size === 0 ? "-" : `${(ratio(e) * 100).toFixed(0)}%`}</td>
                <td className="px-3 py-1 text-zinc-500">{e.isDir ? "-" : e.method}</td>
                <td className="px-3 py-1 text-zinc-500">{e.date ?? "-"}</td>
                <td className="px-3 py-1 text-right">
                  {extractable(e) ? (
                    <button
                      type="button"
                      onClick={() => scanEntry(e)}
                      disabled={busy !== null}
                      className="px-1.5 py-0.5 rounded bg-zinc-800 hover:bg-zinc-700 disabled:opacity-40 text-zinc-300"
                      title="Extract this entry and scan it as a new file"
                    >
                      {busy === e.name ? "…" : "scan"}
                    </button>
                  ) : null}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {rows.length === 0 ? (
          <div className="px-3 py-6 text-center text-xs text-zinc-500">No entries match the filter.</div>
        ) : null}
      </div>
      <div className="mt-1.5 text-[11px] text-zinc-600">"scan" extracts the entry (stored / deflated, incl. ZipCrypto &amp; WinZip-AES with a password, and OLE2 / MSI streams) and adds it to the workspace as <span className="font-mono">parent!member</span>.</div>
    </div>
  );
}
