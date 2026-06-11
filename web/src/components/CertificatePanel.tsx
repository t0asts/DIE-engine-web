import { useEffect, useMemo, useState } from "react";

import type { CertAsn1Node, CertEntry, CertificateInfo } from "../worker/protocol";
import {
  computeThumbprints,
  decodeNodeDisplayValue,
  parseCertificates,
  type ParsedX509,
  type Thumbprints,
} from "./cert-x509";

interface Props {
  info: CertificateInfo;
  bytes: ArrayBuffer;
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

function groupHex(s: string): string {
  return s.replace(/(.{2})/g, "$1 ").trim();
}

export function CertificatePanel({ info, bytes }: Props) {
  const u8 = useMemo(() => new Uint8Array(bytes), [bytes]);
  const certs = useMemo(() => info.certificates ?? [], [info.certificates]);

  const perEntry = useMemo(
    () => certs.map((c) => parseCertificates(u8, c.structure)),
    [u8, certs],
  );

  const [thumbs, setThumbs] = useState<Map<number, Thumbprints>>(new Map());
  useEffect(() => {
    let cancelled = false;
    const all = perEntry.flat();
    (async () => {
      const out = new Map<number, Thumbprints>();
      for (const c of all) {
        const der = u8.subarray(c.derOffset, c.derOffset + c.derLength);
        try {
          out.set(c.derOffset, await computeThumbprints(der));
        } catch {
        }
      }
      if (!cancelled) setThumbs(out);
    })();
    return () => {
      cancelled = true;
    };
  }, [perEntry, u8]);

  if (!info.present) {
    return (
      <div className="p-8 text-zinc-500 text-sm">
        This PE file is not Authenticode-signed (no security directory).
      </div>
    );
  }

  return (
    <div className="p-4 flex flex-col h-full min-h-0">
      <section className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-sm mb-4">
        <span className="text-zinc-500">Security directory</span>
        <span className="font-mono">
          {hex(info.securityOffset ?? -1)} · {fmtSize(info.securitySize ?? 0)}
        </span>
        <span className="text-zinc-500">Entries</span>
        <span className="font-mono">{certs.length}</span>
      </section>

      <div className="flex-1 overflow-auto space-y-4">
        {certs.length ? (
          certs.map((cert, i) => (
            <CertCard
              key={i}
              cert={cert}
              index={i}
              parsed={perEntry[i] ?? []}
              thumbs={thumbs}
              bytes={u8}
            />
          ))
        ) : (
          <div className="text-zinc-500 text-sm">
            A security directory is present, but no certificate records could be parsed
            (the WIN_CERTIFICATE blob may be malformed or truncated).
          </div>
        )}
      </div>
    </div>
  );
}

function CertCard({
  cert,
  index,
  parsed,
  thumbs,
  bytes,
}: {
  cert: CertEntry;
  index: number;
  parsed: ParsedX509[];
  thumbs: Map<number, Thumbprints>;
  bytes: Uint8Array;
}) {
  return (
    <div className="border border-zinc-800 rounded">
      <div className="flex items-center gap-3 px-3 py-2 bg-zinc-900 text-sm">
        <span className="font-medium">#{index + 1}</span>
        <span className="font-mono text-zinc-300">{cert.typeName}</span>
        <span className="text-zinc-500 font-mono text-xs">rev {cert.revision}</span>
        <span className="text-zinc-500 font-mono text-xs">
          {hex(cert.offset)} · {fmtSize(cert.length)}
        </span>
        <span
          className={
            "ml-auto text-xs px-2 py-0.5 rounded " +
            (cert.valid ? "bg-emerald-900/50 text-emerald-300" : "bg-amber-900/50 text-amber-300")
          }
        >
          {cert.valid ? "parsed" : "unparsed"}
        </span>
      </div>

      {parsed.length ? (
        <div className="p-3 space-y-3 border-b border-zinc-800">
          {parsed.map((c) => (
            <X509Summary key={c.derOffset} cert={c} thumbs={thumbs.get(c.derOffset)} />
          ))}
        </div>
      ) : null}

      <details className="group">
        <summary className="cursor-pointer select-none px-3 py-2 text-xs text-zinc-500 hover:text-zinc-300">
          Raw ASN.1 structure
        </summary>
        <div className="p-2 overflow-x-auto font-mono text-xs">
          <Asn1Node node={cert.structure} depth={0} bytes={bytes} />
        </div>
      </details>
    </div>
  );
}

function Row({ label, value, mono = true }: { label: string; value: string; mono?: boolean }) {
  if (!value) return null;
  return (
    <>
      <span className="text-zinc-500">{label}</span>
      <span className={(mono ? "font-mono " : "") + "break-all"}>{value}</span>
    </>
  );
}

function X509Summary({ cert, thumbs }: { cert: ParsedX509; thumbs: Thumbprints | undefined }) {
  return (
    <div className="border border-zinc-800/70 rounded bg-zinc-950/40">
      <div className="flex items-center gap-2 px-3 py-1.5 text-xs border-b border-zinc-800/70">
        <span className="text-zinc-400">X.509 v{cert.version}</span>
        {cert.selfSigned ? (
          <span className="text-xs px-1.5 py-0.5 rounded bg-sky-900/50 text-sky-300">self-signed</span>
        ) : null}
      </div>
      <div className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-xs p-3">
        <Row label="Subject" value={cert.subjectText} mono={false} />
        <Row label="Issuer" value={cert.issuerText} mono={false} />
        <Row label="Serial" value={groupHex(cert.serial)} />
        <Row label="Valid from" value={cert.notBefore} />
        <Row label="Valid to" value={cert.notAfter} />
        <Row label="Signature" value={cert.signatureAlgorithm} />
        <Row label="Public key" value={cert.publicKeyAlgorithm} />
        <Row label="SHA-1" value={thumbs ? groupHex(thumbs.sha1) : ""} />
        <Row label="SHA-256" value={thumbs ? groupHex(thumbs.sha256) : ""} />
      </div>
    </div>
  );
}

function Asn1Node({ node, depth, bytes }: { node: CertAsn1Node; depth: number; bytes: Uint8Array }) {
  const hasKids = !!node.children?.length;
  const display = hasKids ? null : decodeNodeDisplayValue(bytes, node);
  return (
    <div>
      <div
        className="flex gap-2 py-0.5 hover:bg-zinc-900/50 whitespace-pre"
        style={{ paddingLeft: depth * 16 }}
      >
        <span className="text-zinc-500 select-none w-20 shrink-0">{hex(node.offset)}</span>
        <span className="text-sky-300 shrink-0">{node.tag || "-"}</span>
        {node.oidName ? (
          <span className="text-emerald-300">{node.oidName}</span>
        ) : display ? (
          <span className="text-zinc-300 truncate max-w-[60ch]" title={display}>
            {display}
          </span>
        ) : null}
        <span className="text-zinc-600 ml-auto shrink-0">{node.size} B</span>
      </div>
      {hasKids
        ? node.children!.map((c, i) => <Asn1Node key={i} node={c} depth={depth + 1} bytes={bytes} />)
        : null}
    </div>
  );
}
