import { useMemo, useState } from "react";

import type { StringEntry } from "../worker/protocol";

interface Props {
  strings: StringEntry[];
}

export function StringsPanel({ strings }: Props) {
  const [filter, setFilter] = useState("");
  const [encoding, setEncoding] = useState<"all" | "ascii" | "utf16le">("all");
  const [minLen, setMinLen] = useState(4);

  const filtered = useMemo(() => {
    const f = filter.toLowerCase();
    return strings.filter((s) => {
      if (encoding !== "all" && s.encoding !== encoding) return false;
      if (s.length < minLen) return false;
      if (f && !s.text.toLowerCase().includes(f)) return false;
      return true;
    });
  }, [strings, filter, encoding, minLen]);

  return (
    <div className="p-4 flex flex-col h-full min-h-0">
      <div className="flex flex-wrap items-center gap-2 mb-3">
        <input
          type="text"
          placeholder="Filter…"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          className="px-2 py-1 text-sm bg-zinc-900 border border-zinc-800 rounded flex-1 min-w-[200px]"
        />
        <select
          value={encoding}
          onChange={(e) => setEncoding(e.target.value as "all" | "ascii" | "utf16le")}
          className="px-2 py-1 text-sm bg-zinc-900 border border-zinc-800 rounded"
        >
          <option value="all">all encodings</option>
          <option value="ascii">ascii</option>
          <option value="utf16le">utf-16 le</option>
        </select>
        <label className="text-xs text-zinc-400">
          min len{" "}
          <input
            type="number"
            min={1}
            max={1024}
            value={minLen}
            onChange={(e) => setMinLen(Math.max(1, parseInt(e.target.value, 10) || 1))}
            className="w-16 px-2 py-1 text-sm bg-zinc-900 border border-zinc-800 rounded"
          />
        </label>
        <span className="text-xs text-zinc-500">
          {filtered.length.toLocaleString()} / {strings.length.toLocaleString()}
        </span>
      </div>

      <div className="flex-1 overflow-auto border border-zinc-800 rounded">
        <table className="w-full font-mono text-xs">
          <thead className="bg-zinc-900 sticky top-0">
            <tr className="text-left text-zinc-500">
              <th className="px-3 py-1.5 w-28">Offset</th>
              <th className="px-3 py-1.5 w-16">Len</th>
              <th className="px-3 py-1.5 w-24">Encoding</th>
              <th className="px-3 py-1.5">Value</th>
            </tr>
          </thead>
          <tbody>
            {filtered.slice(0, 5000).map((s, i) => (
              <tr key={i} className="border-t border-zinc-900 hover:bg-zinc-900/50">
                <td className="px-3 py-1 text-zinc-500">0x{s.offset.toString(16)}</td>
                <td className="px-3 py-1 text-zinc-500">{s.length}</td>
                <td className="px-3 py-1 text-zinc-500">{s.encoding}</td>
                <td className="px-3 py-1 text-zinc-200 whitespace-pre">{s.text}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {filtered.length > 5000 ? (
          <div className="px-3 py-2 text-xs text-zinc-500 text-center bg-zinc-900">
            Showing first 5,000 of {filtered.length.toLocaleString()}. Refine the filter to narrow down.
          </div>
        ) : null}
      </div>
    </div>
  );
}
