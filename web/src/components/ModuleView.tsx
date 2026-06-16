import { lazy, Suspense, useMemo } from "react";

import type { DebugInfo, ScanResult } from "../worker/protocol";
import type { DroppedFile } from "../store/workspace";
import { archForDecompile } from "../decompiler/arch-map";
import { symbolAddrBase } from "../decompiler/regions";

import { FileInfoPanel } from "./FileInfoPanel";
import { HashPanel } from "./HashPanel";
import { EntropyGraph } from "./EntropyGraph";
import { StringsPanel } from "./StringsPanel";
import { SectionsPanel } from "./SectionsPanel";
import { StructPanel } from "./StructPanel";
import { DisasmView } from "./DisasmView";
import { SymbolsPanel } from "./SymbolsPanel";
import { PeidPanel } from "./PeidPanel";
import { YaraPanel } from "./YaraPanel";
import { ArchivePanel } from "./ArchivePanel";
import { ExtractorPanel } from "./ExtractorPanel";
import { VisualizationPanel } from "./VisualizationPanel";
import { HexView } from "./HexView";
import { OverlayPanel } from "./OverlayPanel";
import { CertificatePanel } from "./CertificatePanel";
import { DataConverterPanel } from "./DataConverterPanel";
import { DemanglerPanel } from "./DemanglerPanel";
import { ExportButton } from "./ExportButton";

const DecompilerPanel = lazy(() =>
  import("./DecompilerPanel").then((m) => ({ default: m.DecompilerPanel })),
);

export interface ModuleViewProps {
  moduleId: string;
  file: DroppedFile;
  result: ScanResult;
  decompileTarget: { addr: number; nonce: number } | null;
  hexTarget: { offset: number; nonce: number } | null;
  onDecompile: (addr: number) => void;
  onViewHex: (offset: number) => void;
}

export function ModuleView({
  moduleId,
  file,
  result: r,
  decompileTarget,
  hexTarget,
  onDecompile,
  onViewHex,
}: ModuleViewProps) {
  const decompArch = archForDecompile(r);
  const symBase = symbolAddrBase(r);
  const entryPoint = r.memoryMap?.entryPoint ?? 0;
  const overlay =
    r.memoryMap?.records.find((rec) => rec.name === "Overlay" || rec.filePart === 32) ?? null;
  const hexBytes = useMemo(() => new Uint8Array(file.bytes), [file.bytes]);

  switch (moduleId) {
    case "detection":
      return <DetectionTab fileName={file.name} result={r} />;
    case "sections":
      return <SectionsPanel memoryMap={r.memoryMap} />;
    case "overlay":
      return overlay ? (
        <OverlayPanel
          overlay={overlay}
          bytes={file.bytes}
          fileName={file.name}
          totalSize={r.fileInfo.size}
          onViewHex={onViewHex}
        />
      ) : null;
    case "structure":
      return <StructPanel structure={r.structure ?? []} />;
    case "symbols":
      return (
        <SymbolsPanel
          symbols={r.symbols ?? []}
          onDecompile={decompArch ? (addr) => onDecompile(addr + symBase) : undefined}
        />
      );
    case "disasm":
      return (
        <DisasmView
          bytes={file.bytes}
          entryPoint={entryPoint}
          arch={r.memoryMap?.arch ?? ""}
          onDecompile={decompArch ? onDecompile : undefined}
        />
      );
    case "decompile":
      return decompArch ? (
        <Suspense fallback={<div className="p-8 text-zinc-500">Loading decompiler...</div>}>
          <DecompilerPanel
            key={file.id}
            fileId={file.id}
            result={r}
            bytes={file.bytes}
            arch={decompArch}
            target={decompileTarget}
          />
        </Suspense>
      ) : null;
    case "peid":
      return <PeidPanel bytes={file.bytes} memoryMap={r.memoryMap} />;
    case "certificate":
      return r.certificates ? <CertificatePanel info={r.certificates} bytes={file.bytes} /> : null;
    case "yara":
      return <YaraPanel bytes={file.bytes} />;
    case "archive":
      return r.archive ? (
        <ArchivePanel archive={r.archive} bytes={file.bytes} parentName={file.name} />
      ) : null;
    case "extractor":
      return <ExtractorPanel records={r.extracted ?? []} bytes={file.bytes} parentName={file.name} />;
    case "strings":
      return <StringsPanel strings={r.strings} />;
    case "hex":
      return <HexView bytes={hexBytes} target={hexTarget} />;
    case "visualize":
      return <VisualizationPanel bytes={file.bytes} memoryMap={r.memoryMap} />;
    case "convert":
      return <DataConverterPanel />;
    case "demangle":
      return <DemanglerPanel />;
    default:
      return null;
  }
}

function DetectionTab({ fileName, result }: { fileName: string; result: ScanResult }) {
  const r = result;
  return (
    <div>
      <section className="p-4">
        <div className="flex items-start justify-between gap-3">
          <h1 className="text-lg font-semibold truncate">{fileName}</h1>
          <ExportButton fileName={fileName} result={r} />
        </div>
        <RecordsList records={r.records} />
        <DebugSymbols info={r.debugInfo} />
        {r.errors.length ? (
          <details className="mt-4 text-xs text-zinc-500">
            <summary>Engine warnings ({r.errors.length})</summary>
            <ul className="mt-2 space-y-0.5 font-mono">
              {r.errors.map((e, i) => <li key={i}>{e}</li>)}
            </ul>
          </details>
        ) : null}
      </section>

      <FileInfoPanel result={r} />
      <HashPanel hashes={r.hashes} />
      <EntropyGraph points={r.entropy} />
    </div>
  );
}

function DebugSymbols({ info }: { info: DebugInfo[] }) {
  if (!info.length) return null;
  return (
    <div className="mt-4 space-y-3">
      {info.map((d, i) => <DebugEntry key={i} entry={d} />)}
    </div>
  );
}

const DEBUG_LABELS: Record<DebugInfo["format"], string> = {
  pdb: "Debug symbols (PDB)",
  gnu_debuglink: "Debug symbols (.gnu_debuglink)",
  gnu_debugaltlink: "Debug symbols (.gnu_debugaltlink)",
  "build-id": "Build ID (.note.gnu.build-id)",
};

function DebugEntry({ entry }: { entry: DebugInfo }) {
  const primary = entry.format === "build-id" ? entry.buildId : entry.path;
  return (
    <div>
      <div className="text-zinc-500 text-sm mb-1">
        {DEBUG_LABELS[entry.format]}
        {entry.format === "pdb" ? (
          <span className="ml-2 text-[11px] text-zinc-600">{entry.signature}</span>
        ) : null}
      </div>
      <div className="font-mono text-sm text-emerald-400 break-all select-text">{primary}</div>
      {entry.format === "pdb" && (entry.guid || entry.age != null) ? (
        <div className="mt-0.5 font-mono text-[11px] text-zinc-500 break-all">
          {entry.guid ? <span className="mr-3">GUID {entry.guid}</span> : null}
          {entry.age != null ? <span>Age {entry.age}</span> : null}
        </div>
      ) : null}
      {entry.format === "gnu_debuglink" ? (
        <div className="mt-0.5 font-mono text-[11px] text-zinc-500 break-all">CRC32 {entry.crc32}</div>
      ) : null}
      {entry.format === "gnu_debugaltlink" ? (
        <div className="mt-0.5 font-mono text-[11px] text-zinc-500 break-all">Build ID {entry.buildId}</div>
      ) : null}
    </div>
  );
}

function RecordsList({ records }: { records: { type: string; name: string; version?: string; options?: string; language?: string }[] }) {
  if (records.length === 0) {
    return (
      <div className="mt-3 text-sm text-zinc-500">
        No detections. The format was identified but no signatures matched.
      </div>
    );
  }
  const groups = new Map<string, typeof records>();
  for (const r of records) {
    if (!groups.has(r.type)) groups.set(r.type, []);
    groups.get(r.type)!.push(r);
  }
  return (
    <ul className="mt-3 space-y-1 text-sm">
      {[...groups.entries()].map(([type, rs]) => (
        <li key={type}>
          <span className="text-zinc-500 mr-2">{type}:</span>
          {rs.map((r, i) => (
            <span key={i} className="mr-3">
              <span className="font-medium">{r.name}</span>
              {r.version ? <span className="text-zinc-400"> {r.version}</span> : null}
              {r.options ? <span className="text-zinc-500"> [{r.options}]</span> : null}
              {r.language ? <span className="text-zinc-500"> ({r.language})</span> : null}
            </span>
          ))}
        </li>
      ))}
    </ul>
  );
}
