import { useMemo, useState } from "react";

import type { SymbolEntry } from "../worker/protocol";

interface Props {
  symbols: SymbolEntry[];
  onDecompile?: (addr: number) => void;
}

type SortKey = "name" | "address" | "kind";
type KindFilter = "all" | "import" | "export" | "symbol";

const hex = (n: number) => "0x" + Math.max(0, Math.trunc(n)).toString(16);

const KIND_STYLE: Record<SymbolEntry["kind"], string> = {
  import: "text-amber-400",
  export: "text-emerald-400",
  symbol: "text-zinc-400",
};

export function SymbolsPanel({ symbols, onDecompile }: Props) {
  const [filter, setFilter] = useState("");
  const [kind, setKind] = useState<KindFilter>("all");
  const [sortKey, setSortKey] = useState<SortKey>("name");
  const [asc, setAsc] = useState(true);

  const counts = useMemo(() => {
    const c = { import: 0, export: 0, symbol: 0 };
    for (const s of symbols) c[s.kind]++;
    return c;
  }, [symbols]);

  const rows = useMemo(() => {
    const f = filter.trim().toLowerCase();
    let list = symbols.filter((s) => {
      if (kind !== "all" && s.kind !== kind) return false;
      if (!f) return true;
      return (
        s.name.toLowerCase().includes(f) ||
        (s.demangled?.toLowerCase().includes(f) ?? false) ||
        (s.library?.toLowerCase().includes(f) ?? false)
      );
    });
    list = [...list].sort((a, b) => {
      let cmp = 0;
      switch (sortKey) {
        case "name": cmp = (a.demangled ?? a.name) < (b.demangled ?? b.name) ? -1 : (a.demangled ?? a.name) > (b.demangled ?? b.name) ? 1 : 0; break;
        case "address": cmp = (a.address ?? -1) - (b.address ?? -1); break;
        case "kind": cmp = a.kind < b.kind ? -1 : a.kind > b.kind ? 1 : 0; break;
      }
      return asc ? cmp : -cmp;
    });
    return list;
  }, [symbols, filter, kind, sortKey, asc]);

  const th = (key: SortKey, label: string, extra = "") => (
    <th
      className={`px-3 py-1.5 cursor-pointer select-none hover:text-zinc-300 ${extra}`}
      onClick={() => { if (sortKey === key) setAsc(!asc); else { setSortKey(key); setAsc(true); } }}
      title="Sort"
    >
      {label}{sortKey === key ? (asc ? " ▲" : " ▼") : ""}
    </th>
  );

  if (symbols.length === 0) {
    return (
      <div className="p-8 text-sm text-zinc-500">
        No symbol/import/export information for this format.
      </div>
    );
  }

  const kindBtn = (k: KindFilter, label: string, count?: number) => (
    <button
      type="button"
      onClick={() => setKind(k)}
      className={"px-2 py-0.5 text-xs rounded " + (kind === k ? "bg-zinc-700 text-zinc-100" : "bg-zinc-900 text-zinc-400 hover:text-zinc-200")}
    >
      {label}{count !== undefined ? ` (${count})` : ""}
    </button>
  );

  return (
    <div className="p-4 flex flex-col h-full min-h-0">
      <div className="flex flex-wrap items-center gap-2 mb-3">
        <input
          type="text"
          placeholder="Filter name / demangled / library…"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          className="px-2 py-1 text-sm bg-zinc-900 border border-zinc-800 rounded flex-1 min-w-[220px]"
        />
        {kindBtn("all", "All", symbols.length)}
        {kindBtn("import", "Imports", counts.import)}
        {kindBtn("export", "Exports", counts.export)}
        {counts.symbol ? kindBtn("symbol", "Symbols", counts.symbol) : null}
        <span className="text-xs text-zinc-500">{rows.length.toLocaleString()} shown</span>
      </div>

      <div className="flex-1 overflow-auto border border-zinc-800 rounded">
        <table className="w-full font-mono text-xs">
          <thead className="bg-zinc-900 sticky top-0 text-left text-zinc-500">
            <tr>
              {th("kind", "Kind", "w-16")}
              {th("name", "Name")}
              <th className="px-3 py-1.5 w-44">Library</th>
              {th("address", "Address", "w-32")}
              <th className="px-3 py-1.5 w-28">Type / bind</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((s, i) => (
              <tr key={i} className="border-t border-zinc-900 hover:bg-zinc-900/50">
                <td className={"px-3 py-1 " + KIND_STYLE[s.kind]}>{s.kind}</td>
                <td className="px-3 py-1 text-zinc-200 break-all" title={s.demangled ? `${s.demangled}\n${s.name}` : s.name}>
                  {s.demangled ?? s.name}
                  {s.demangled ? <span className="text-zinc-600"> · {s.name}</span> : null}
                  {s.ordinal !== undefined ? <span className="text-zinc-600"> @#{s.ordinal}</span> : null}
                </td>
                <td className="px-3 py-1 text-zinc-500 truncate" title={s.library ?? ""}>{s.library ?? ""}</td>
                <td className="px-3 py-1 text-zinc-500">
                  {s.address !== undefined ? (
                    onDecompile && s.kind !== "import" ? (
                      <button
                        type="button"
                        onClick={() => onDecompile(s.address!)}
                        className="text-sky-400 hover:underline"
                        title="Decompile this function"
                      >
                        {hex(s.address)}
                      </button>
                    ) : (
                      hex(s.address)
                    )
                  ) : (
                    ""
                  )}
                  {s.section ? <span className="text-zinc-600"> [{s.section}]</span> : null}
                </td>
                <td className="px-3 py-1 text-zinc-500">
                  {[s.type, s.bind].filter(Boolean).join(" / ")}
                  {s.size ? <span className="text-zinc-600"> · {s.size}B</span> : null}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {rows.length === 0 ? (
          <div className="px-3 py-6 text-center text-xs text-zinc-500">No symbols match the filter.</div>
        ) : null}
      </div>
    </div>
  );
}
