import { lazy, Suspense, useCallback, useState } from "react";

import { useWorkspace } from "../store/workspace";
import { archForDecompile } from "../decompiler/arch-map";
import { symbolAddrBase } from "../decompiler/regions";

import { FileInfoPanel } from "./FileInfoPanel";
import { HashPanel } from "./HashPanel";
import { EntropyGraph } from "./EntropyGraph";
import { Tabs, type TabDef } from "./Tabs";
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

export function ScanResultPanel({ fileId }: { fileId: string }) {
  const file = useWorkspace((s) => s.files.find((f) => f.id === fileId));
  const entry = useWorkspace((s) => s.scans.get(fileId));
  const [activeTab, setActiveTab] = useState("detection");
  const [decompileTarget, setDecompileTarget] = useState<{ addr: number; nonce: number } | null>(null);
  const [hexTarget, setHexTarget] = useState<{ offset: number; nonce: number } | null>(null);

  const navToDecompile = useCallback((addr: number) => {
    setDecompileTarget((prev) => ({ addr, nonce: (prev?.nonce ?? 0) + 1 }));
    setActiveTab("decompile");
  }, []);

  const navToHex = useCallback((offset: number) => {
    setHexTarget((prev) => ({ offset, nonce: (prev?.nonce ?? 0) + 1 }));
    setActiveTab("hex");
  }, []);

  if (!file) return null;

  if (!entry || entry.status === "loading") {
    return (
      <div className="p-8 text-zinc-500">
        Scanning <span className="font-mono">{file.name}</span>…
      </div>
    );
  }

  if (entry.status === "error") {
    return (
      <div className="p-8 text-red-400">
        <div className="font-medium">Scan failed</div>
        <div className="font-mono text-xs mt-2">{entry.error}</div>
      </div>
    );
  }

  const r = entry.result!;
  const sectionCount = r.memoryMap?.records.length ?? 0;
  const stringCount = r.strings.length;
  const structCount = r.structure?.length ?? 0;
  const symbolCount = r.symbols?.length ?? 0;
  const entryPoint = r.memoryMap?.entryPoint ?? 0;

  const canDisasm = r.disasmAvailable;
  const decompArch = archForDecompile(r);
  const symBase = symbolAddrBase(r);
  const isPE = r.formatClass === "PE";
  const extractedCount = r.extracted?.length ?? 0;
  const overlay = r.memoryMap?.records.find((rec) => rec.name === "Overlay" || rec.filePart === 32) ?? null;
  const hasOverlay = !!overlay && overlay.size > 0;
  const hasCert = !!r.certificates?.present;

  const tabs: TabDef[] = [
    { id: "detection", label: "Detection", badge: r.records.length || undefined },
    { id: "sections",  label: "Sections",  badge: sectionCount || undefined },
    ...(hasOverlay ? [{ id: "overlay", label: "Overlay" } as TabDef] : []),
    ...(structCount ? [{ id: "structure", label: "Structure" } as TabDef] : []),
    ...(symbolCount ? [{ id: "symbols", label: "Symbols", badge: symbolCount } as TabDef] : []),
    ...(canDisasm ? [{ id: "disasm", label: "Disasm" } as TabDef] : []),
    ...(decompArch ? [{ id: "decompile", label: "Decompile" } as TabDef] : []),
    ...(isPE ? [{ id: "peid", label: "PEiD" } as TabDef] : []),
    ...(hasCert ? [{ id: "certificate", label: "Certificate", badge: r.certificates?.certificates?.length || undefined } as TabDef] : []),
    { id: "yara",      label: "YARA" },
    ...(r.archive
      ? [{ id: "archive", label: "Archive", badge: r.archive.totalEntries || undefined } as TabDef]
      : []),
    ...(extractedCount ? [{ id: "extractor", label: "Extractor", badge: extractedCount } as TabDef] : []),
    { id: "strings",   label: "Strings",   badge: stringCount || undefined },
    { id: "hex",       label: "Hex" },
    { id: "visualize", label: "Visualize" },
    { id: "convert",   label: "Convert" },
    { id: "demangle",  label: "Demangler" },
  ];

  const tab = tabs.some((t) => t.id === activeTab) ? activeTab : "detection";

  return (
    <div className="flex flex-col h-full min-h-0">
      <Tabs
        tabs={tabs}
        activeId={tab}
        onChange={setActiveTab}
        trailing={
          <span className="font-mono">
            {file.name} <span className="text-zinc-600">·</span> {file.size.toLocaleString()} B
          </span>
        }
      />
      <div className="flex-1 overflow-auto min-h-0">
        {tab === "detection" ? <DetectionTab fileName={file.name} result={r} /> : null}
        {tab === "sections"  ? <SectionsPanel memoryMap={r.memoryMap} /> : null}
        {tab === "overlay" && overlay ? <OverlayPanel overlay={overlay} bytes={file.bytes} fileName={file.name} totalSize={r.fileInfo.size} onViewHex={navToHex} /> : null}
        {tab === "structure" ? <StructPanel structure={r.structure ?? []} /> : null}
        {tab === "symbols"   ? <SymbolsPanel symbols={r.symbols ?? []} onDecompile={decompArch ? (addr) => navToDecompile(addr + symBase) : undefined} /> : null}
        {tab === "disasm"    ? <DisasmView bytes={file.bytes} entryPoint={entryPoint} arch={r.memoryMap?.arch ?? ""} onDecompile={decompArch ? navToDecompile : undefined} /> : null}
        {tab === "decompile" && decompArch ? (
          <Suspense fallback={<div className="p-8 text-zinc-500">Loading decompiler...</div>}>
            <DecompilerPanel result={r} bytes={file.bytes} arch={decompArch} target={decompileTarget} />
          </Suspense>
        ) : null}
        {tab === "peid"      ? <PeidPanel bytes={file.bytes} memoryMap={r.memoryMap} /> : null}
        {tab === "certificate" && r.certificates ? <CertificatePanel info={r.certificates} bytes={file.bytes} /> : null}
        {tab === "yara"      ? <YaraPanel bytes={file.bytes} /> : null}
        {tab === "archive" && r.archive ? <ArchivePanel archive={r.archive} bytes={file.bytes} parentName={file.name} /> : null}
        {tab === "extractor" ? <ExtractorPanel records={r.extracted ?? []} bytes={file.bytes} parentName={file.name} /> : null}
        {tab === "strings"   ? <StringsPanel strings={r.strings} /> : null}
        {tab === "hex"       ? <HexView bytes={new Uint8Array(file.bytes)} target={hexTarget} /> : null}
        {tab === "visualize" ? <VisualizationPanel bytes={file.bytes} memoryMap={r.memoryMap} /> : null}
        {tab === "convert"   ? <DataConverterPanel /> : null}
        {tab === "demangle"  ? <DemanglerPanel /> : null}
      </div>
    </div>
  );
}

function DetectionTab({ fileName, result }: { fileName: string; result: import("../worker/protocol").ScanResult }) {
  const r = result;
  return (
    <div>
      <section className="p-4">
        <div className="flex items-start justify-between gap-3">
          <h1 className="text-lg font-semibold truncate">{fileName}</h1>
          <ExportButton fileName={fileName} result={r} />
        </div>
        <RecordsList records={r.records} />
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
