import { useMemo, useState } from "react";

import type { DotNetInfo, DotNetRecord } from "../worker/protocol";

interface Props {
  info: DotNetInfo;
}

function Section({
  title,
  subtitle,
  children,
}: {
  title: string;
  subtitle?: string;
  children: React.ReactNode;
}) {
  return (
    <section className="mb-5">
      <div className="flex items-baseline justify-between gap-3 mb-1.5">
        <h2 className="text-zinc-200 font-semibold text-sm">{title}</h2>
        {subtitle ? <span className="text-zinc-500 text-xs font-mono">{subtitle}</span> : null}
      </div>
      {children}
    </section>
  );
}

function RecordTable({ records }: { records: DotNetRecord[] }) {
  const anyComment = records.some((r) => r.comment);
  return (
    <div className="border border-zinc-800 rounded overflow-hidden">
      <table className="w-full text-xs font-mono">
        <thead>
          <tr className="text-zinc-500 bg-zinc-900/60 text-left">
            <th className="px-2 py-1 font-medium">Name</th>
            <th className="px-2 py-1 font-medium w-16">Offset</th>
            <th className="px-2 py-1 font-medium w-16">Type</th>
            <th className="px-2 py-1 font-medium">Value</th>
            {anyComment ? <th className="px-2 py-1 font-medium">Comment</th> : null}
          </tr>
        </thead>
        <tbody>
          {records.map((r, i) => (
            <tr key={i} className="border-t border-zinc-800/70 hover:bg-zinc-900/40">
              <td className="px-2 py-0.5 text-zinc-300 whitespace-nowrap">{r.name}</td>
              <td className="px-2 py-0.5 text-zinc-500">{r.offset}</td>
              <td className="px-2 py-0.5 text-zinc-500">{r.type}</td>
              <td className="px-2 py-0.5 text-amber-300/90 break-all">{r.value}</td>
              {anyComment ? <td className="px-2 py-0.5 text-emerald-400/80">{r.comment ?? ""}</td> : null}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function KeyVal({ k, v }: { k: string; v: string }) {
  return (
    <div className="flex gap-2 py-0.5">
      <span className="text-zinc-500 w-32 shrink-0">{k}</span>
      <span className="text-zinc-200 font-mono break-all">{v}</span>
    </div>
  );
}

export function DotNetPanel({ info }: Props) {
  const [strFilter, setStrFilter] = useState("");

  const ep = info.entryPoint;
  const epText = useMemo(() => {
    if (!ep || ep.kind === "none") return "none";
    if (ep.kind === "native") return `native @ ${ep.token ?? "?"}`;
    const where = ep.table ? `${ep.table}[${ep.row ?? 0}]` : "";
    return [ep.token, where, ep.method].filter(Boolean).join("  ·  ");
  }, [ep]);

  const userStrings = info.userStrings ?? [];
  const sf = strFilter.trim().toLowerCase();
  const filteredStrings = useMemo(
    () => (sf ? userStrings.filter((s) => s.toLowerCase().includes(sf)) : userStrings),
    [userStrings, sf],
  );

  return (
    <div className="p-4 overflow-auto h-full text-sm">
      {info.header ? (
        <Section title=".NET Header" subtitle={`IMAGE_COR20_HEADER @ ${info.header.offset}`}>
          <RecordTable records={info.header.records} />
        </Section>
      ) : null}

      {info.metadata ? (
        <Section title=".NET Metadata" subtitle={`BSJB @ ${info.metadata.offset}`}>
          <RecordTable records={info.metadata.records} />
          {info.metadata.streams.length > 0 ? (
            <div className="mt-2 border border-zinc-800 rounded overflow-hidden">
              <table className="w-full text-xs font-mono">
                <thead>
                  <tr className="text-zinc-500 bg-zinc-900/60 text-left">
                    <th className="px-2 py-1 font-medium">Stream</th>
                    <th className="px-2 py-1 font-medium">Offset</th>
                    <th className="px-2 py-1 font-medium">Size</th>
                  </tr>
                </thead>
                <tbody>
                  {info.metadata.streams.map((s, i) => (
                    <tr key={i} className="border-t border-zinc-800/70 hover:bg-zinc-900/40">
                      <td className="px-2 py-0.5 text-zinc-300">{s.name}</td>
                      <td className="px-2 py-0.5 text-zinc-500">{s.offset}</td>
                      <td className="px-2 py-0.5 text-zinc-500">{s.size}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : null}
        </Section>
      ) : null}

      {info.assembly || info.module || ep ? (
        <Section title="Assembly">
          <div className="border border-zinc-800 rounded px-3 py-2">
            {info.module ? <KeyVal k="Module" v={info.module.name} /> : null}
            {info.assembly ? (
              <>
                <KeyVal k="Name" v={info.assembly.name || "(none)"} />
                <KeyVal k="Version" v={info.assembly.version} />
                <KeyVal k="Culture" v={info.assembly.culture} />
                <KeyVal k="Flags" v={info.assembly.flags} />
                <KeyVal k="Hash algorithm" v={info.assembly.hashAlgId} />
                <KeyVal k="Public key" v={info.assembly.hasPublicKey ? "present" : "none"} />
              </>
            ) : null}
            {ep ? <KeyVal k="Entry point" v={epText} /> : null}
          </div>
        </Section>
      ) : null}

      {info.tables && info.tables.length > 0 ? (
        <Section title="Metadata tables" subtitle={`${info.tables.length} present`}>
          <div className="border border-zinc-800 rounded overflow-hidden">
            <table className="w-full text-xs font-mono">
              <thead>
                <tr className="text-zinc-500 bg-zinc-900/60 text-left">
                  <th className="px-2 py-1 font-medium">Table</th>
                  <th className="px-2 py-1 font-medium w-20">Rows</th>
                  <th className="px-2 py-1 font-medium w-16">Sorted</th>
                  <th className="px-2 py-1 font-medium">Offset</th>
                </tr>
              </thead>
              <tbody>
                {info.tables.map((t) => (
                  <tr key={t.id} className="border-t border-zinc-800/70 hover:bg-zinc-900/40">
                    <td className="px-2 py-0.5 text-zinc-300">{t.name}</td>
                    <td className="px-2 py-0.5 text-zinc-200">{t.count.toLocaleString()}</td>
                    <td className="px-2 py-0.5 text-zinc-500">{t.sorted ? "yes" : ""}</td>
                    <td className="px-2 py-0.5 text-zinc-500">{t.offset}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Section>
      ) : null}

      {userStrings.length > 0 ? (
        <Section
          title="User strings (#US)"
          subtitle={
            info.userStringsTotal && info.userStringsTotal > userStrings.length
              ? `showing ${userStrings.length} of ${info.userStringsTotal}`
              : `${userStrings.length}`
          }
        >
          <input
            type="text"
            placeholder="Filter strings…"
            value={strFilter}
            onChange={(e) => setStrFilter(e.target.value)}
            className="px-2 py-1 text-sm bg-zinc-900 border border-zinc-800 rounded mb-2 w-full max-w-md"
          />
          <div className="border border-zinc-800 rounded max-h-80 overflow-auto divide-y divide-zinc-800/60">
            {filteredStrings.length === 0 ? (
              <div className="px-3 py-4 text-center text-zinc-500 text-xs">No strings match the filter.</div>
            ) : (
              filteredStrings.map((s, i) => (
                <div key={i} className="px-2 py-0.5 text-xs font-mono text-zinc-300 break-all">
                  {s}
                </div>
              ))
            )}
          </div>
        </Section>
      ) : null}
    </div>
  );
}
