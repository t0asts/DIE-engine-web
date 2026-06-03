import type { MemoryMap } from "../worker/protocol";
import { RegionMap } from "./RegionMap";

interface Props {
  memoryMap: MemoryMap | null;
}

function hex(n: number, pad = 8): string {
  if (!Number.isFinite(n) || n < 0) return "-";
  return "0x" + n.toString(16).padStart(pad, "0");
}

function fmtSize(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(2)} MB`;
}

export function SectionsPanel({ memoryMap }: Props) {
  if (!memoryMap) {
    return (
      <div className="p-8 text-zinc-500 text-sm">
        Memory map not available for this format.
      </div>
    );
  }

  const records = memoryMap.records;

  return (
    <div className="p-4 flex flex-col h-full min-h-0">
      <section className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-sm mb-4">
        <span className="text-zinc-500">File type</span>
        <span className="font-mono">{memoryMap.fileType}</span>
        <span className="text-zinc-500">Architecture</span>
        <span className="font-mono">{memoryMap.arch}</span>
        <span className="text-zinc-500">Mode</span>
        <span className="font-mono">{memoryMap.mode}</span>
        <span className="text-zinc-500">Endian</span>
        <span className="font-mono">{memoryMap.endian}</span>
        <span className="text-zinc-500">Module address</span>
        <span className="font-mono">{hex(memoryMap.moduleAddress)}</span>
        <span className="text-zinc-500">Image size</span>
        <span className="font-mono">{fmtSize(memoryMap.imageSize)}</span>
        <span className="text-zinc-500">Entry point</span>
        <span className="font-mono">{hex(memoryMap.entryPoint)}</span>
      </section>

      <RegionMap records={records} binarySize={memoryMap.binarySize} />

      <h2 className="text-xs uppercase tracking-wide text-zinc-500 mb-2">
        Sections / regions ({records.length})
      </h2>
      <div className="flex-1 overflow-auto border border-zinc-800 rounded">
        <table className="w-full font-mono text-xs">
          <thead className="bg-zinc-900 sticky top-0">
            <tr className="text-left text-zinc-500">
              <th className="px-3 py-1.5">Name</th>
              <th className="px-3 py-1.5 w-28">File offset</th>
              <th className="px-3 py-1.5 w-32">Address</th>
              <th className="px-3 py-1.5 w-20">Size</th>
              <th className="px-3 py-1.5 w-20">Flags</th>
            </tr>
          </thead>
          <tbody>
            {records.map((r, i) => (
              <tr key={i} className="border-t border-zinc-900 hover:bg-zinc-900/50">
                <td className="px-3 py-1 text-zinc-200 truncate max-w-[260px]" title={r.name}>
                  {r.name || <span className="text-zinc-500 italic">(unnamed)</span>}
                </td>
                <td className="px-3 py-1 text-zinc-500">{hex(r.offset)}</td>
                <td className="px-3 py-1 text-zinc-500">{hex(r.address, 12)}</td>
                <td className="px-3 py-1 text-zinc-400">{fmtSize(r.size)}</td>
                <td className="px-3 py-1 text-zinc-500">
                  {r.isVirtual ? "V" : ""}
                  {r.isInvisible ? "I" : ""}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
