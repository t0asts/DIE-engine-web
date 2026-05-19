import type { ScanResult } from "../worker/protocol";

export function FileInfoPanel({ result }: { result: ScanResult }) {
  return (
    <section className="p-4">
      <h2 className="text-xs uppercase tracking-wide text-zinc-500 mb-2">
        File info
      </h2>
      <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-sm">
        <dt className="text-zinc-500">Format</dt>
        <dd className="font-mono">{result.fileInfo.primaryFormat}</dd>

        <dt className="text-zinc-500">Size</dt>
        <dd className="font-mono">{result.fileInfo.size.toLocaleString()} bytes</dd>

        {result.fileInfo.allFormats.length > 1 ? (
          <>
            <dt className="text-zinc-500">All matches</dt>
            <dd className="font-mono">{result.fileInfo.allFormats.join(", ")}</dd>
          </>
        ) : null}

        {result.mime && result.mime.length ? (
          <>
            <dt className="text-zinc-500">MIME type</dt>
            <dd className="font-mono">{result.mime.join(", ")}</dd>
          </>
        ) : null}

        {result.extracted && result.extracted.length ? (
          <>
            <dt className="text-zinc-500">Embedded files</dt>
            <dd className="font-mono">{result.extracted.length} (see the Extractor tab)</dd>
          </>
        ) : null}

        <dt className="text-zinc-500">Scan time</dt>
        <dd className="font-mono">{result.durationMs} ms</dd>
      </dl>
    </section>
  );
}
