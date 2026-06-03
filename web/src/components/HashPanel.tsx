import type { Hashes } from "../worker/protocol";

export function HashPanel({ hashes }: { hashes: Hashes }) {
  const sha = (hashes.sha256 || "").trim();
  const looksLikeSha256 = /^[0-9a-f]{64}$/i.test(sha);
  return (
    <section className="p-4 border-t border-zinc-800">
      <h2 className="text-xs uppercase tracking-wide text-zinc-500 mb-2">
        Hashes
      </h2>
      <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-sm">
        <Row label="MD5"    value={hashes.md5} />
        <Row label="SHA-1"  value={hashes.sha1} />
        <Row label="SHA-256" value={hashes.sha256} />
        {hashes.importHash32 ? <Row label="Import hash (32)" value={hashes.importHash32} /> : null}
        {hashes.importHash64 ? <Row label="Import hash (64)" value={hashes.importHash64} /> : null}
      </dl>
      {looksLikeSha256 ? (
        <div className="mt-2 text-xs text-zinc-500 flex flex-wrap items-center gap-x-3 gap-y-1">
          <span>Look up SHA-256:</span>
          <a className="text-sky-400 hover:underline" target="_blank" rel="noreferrer"
             href={`https://www.virustotal.com/gui/file/${sha}`}>VirusTotal</a>
          <a className="text-sky-400 hover:underline" target="_blank" rel="noreferrer"
             href={`https://bazaar.abuse.ch/sample/${sha}/`}>MalwareBazaar</a>
        </div>
      ) : null}
    </section>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <>
      <dt className="text-zinc-500">{label}</dt>
      <dd className="font-mono break-all">{value}</dd>
    </>
  );
}
