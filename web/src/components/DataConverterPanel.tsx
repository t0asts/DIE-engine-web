
import { useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";

function parseIntFlexible(s: string): bigint | null {
  let t = s.trim().replace(/[_ ]/g, "");
  if (!t) return null;
  let neg = false;
  if (t.startsWith("+")) t = t.slice(1);
  else if (t.startsWith("-")) { neg = true; t = t.slice(1); }
  try {
    let v: bigint;
    if (/^0x[0-9a-f]+$/i.test(t)) v = BigInt(t);
    else if (/^0b[01]+$/i.test(t)) v = BigInt(t);
    else if (/^0o[0-7]+$/i.test(t)) v = BigInt(t);
    else if (/^[0-9]+$/.test(t)) v = BigInt(t);
    else if (/^[0-9a-f]+$/i.test(t)) v = BigInt("0x" + t);   
    else return null;
    return neg ? -v : v;
  } catch { return null; }
}

const WIDTHS = [8, 16, 32, 64] as const;
type Width = (typeof WIDTHS)[number];

function maskTo(v: bigint, w: Width): bigint {
  const mod = 1n << BigInt(w);
  return ((v % mod) + mod) % mod;
}
function toSigned(u: bigint, w: Width): bigint {
  const half = 1n << BigInt(w - 1);
  return u >= half ? u - (1n << BigInt(w)) : u;
}
function bytesLE(u: bigint, w: Width): number[] {
  const n = w / 8;
  const out: number[] = [];
  let x = u;
  for (let i = 0; i < n; i++) { out.push(Number(x & 0xffn)); x >>= 8n; }
  return out;
}
const hexB = (b: number) => (b & 0xff).toString(16).padStart(2, "0");
function groupBits(bin: string): string {
  const pad = bin.padStart(Math.ceil(bin.length / 4) * 4 || 4, "0");
  return (pad.match(/.{1,4}/g) ?? []).join(" ");
}

function bytesFromHex(s: string): Uint8Array | null {
  const t = s.replace(/[^0-9a-fA-F]/g, "");
  if (t.length % 2 !== 0) return null;
  const out = new Uint8Array(t.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(t.substr(i * 2, 2), 16);
  return out;
}
function toHexStr(b: Uint8Array): string { let s = ""; for (const x of b) s += hexB(x); return s; }
function b64(b: Uint8Array, urlSafe = false): string {
  let bin = ""; for (const x of b) bin += String.fromCharCode(x);
  let s = btoa(bin);
  if (urlSafe) s = s.replace(/\+/g, "-").replace(/\
  return s;
}
function crc32(b: Uint8Array): number {
  let c = 0xffffffff;
  for (let i = 0; i < b.length; i++) {
    c ^= b[i]!;
    for (let k = 0; k < 8; k++) c = (c >>> 1) ^ (0xedb88320 & -(c & 1));
  }
  return (c ^ 0xffffffff) >>> 0;
}
const jsEscape = (s: string) => JSON.stringify(s).slice(1, -1);

const FILETIME_EPOCH_MS = -11644473600000;
const fromFiletime = (v: bigint) => new Date(Number(v / 10000n) + FILETIME_EPOCH_MS);

function fromDosDateTime(v: number): Date {
  const date = (v >>> 16) & 0xffff, time = v & 0xffff;
  const y = ((date >> 9) & 0x7f) + 1980, mo = (date >> 5) & 0x0f, d = date & 0x1f;
  const h = (time >> 11) & 0x1f, mi = (time >> 5) & 0x3f, s = (time & 0x1f) * 2;
  return new Date(y, Math.max(0, mo - 1), Math.max(1, d), h, mi, s);
}
function fmtDate(d: Date): string {
  if (!Number.isFinite(d.getTime())) return "(out of range)";
  return d.toISOString().replace("T", " ").replace(/\.\d{3}Z$/, "Z") + "  ·  " + d.toUTCString();
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[10rem_1fr] gap-x-3 items-baseline py-0.5">
      <span className="text-zinc-500">{label}</span>
      <span className="font-mono break-all text-zinc-200">{children}</span>
    </div>
  );
}
function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="border border-zinc-800 rounded p-3">
      <h3 className="text-xs uppercase tracking-wide text-zinc-500 mb-2">{title}</h3>
      <div className="text-sm">{children}</div>
    </section>
  );
}
const inputCls = "px-2 py-1 text-sm bg-zinc-900 border border-zinc-800 rounded font-mono";

function NumberSection() {
  const [raw, setRaw] = useState("0xdeadbeef");
  const [width, setWidth] = useState<Width>(32);
  const v = parseIntFlexible(raw);

  return (
    <Section title="Number">
      <div className="flex flex-wrap items-center gap-2 mb-2">
        <input className={inputCls + " flex-1 min-w-[200px]"} value={raw} onChange={(e) => setRaw(e.target.value)}
               placeholder="0x… / 0b… / 0o… / decimal / bare hex" />
        <select className={inputCls} value={width} onChange={(e) => setWidth(Number(e.target.value) as Width)}>
          {WIDTHS.map((w) => <option key={w} value={w}>{w}-bit</option>)}
        </select>
      </div>
      {v === null ? (
        <div className="text-zinc-500 text-xs">- enter a number -</div>
      ) : (() => {
        const u = maskTo(v, width);
        const le = bytesLE(u, width);
        return (
          <>
            <Row label="Hex">0x{u.toString(16)}</Row>
            <Row label="Decimal (unsigned)">{u.toString(10)}</Row>
            <Row label="Decimal (signed)">{toSigned(u, width).toString(10)}</Row>
            <Row label="Octal">0o{u.toString(8)}</Row>
            <Row label="Binary">{groupBits(u.toString(2))}</Row>
            <Row label={`Bytes (LE, ${width / 8})`}>{le.map(hexB).join(" ")}</Row>
            <Row label="Bytes (BE)">{[...le].reverse().map(hexB).join(" ")}</Row>
            {v !== u ? <div className="text-amber-500 text-xs mt-1">truncated to {width} bits</div> : null}
          </>
        );
      })()}
    </Section>
  );
}

function TextSection({ onBytes }: { onBytes(b: Uint8Array | null): void }) {
  const [text, setText] = useState("Hello, DIE!");
  const [mode, setMode] = useState<"text" | "hex">("text");

  const bytes = useMemo<Uint8Array | null>(
    () => (mode === "text" ? new TextEncoder().encode(text) : bytesFromHex(text)),
    [text, mode],
  );
  useEffect(() => { onBytes(bytes); }, [bytes, onBytes]);

  return (
    <Section title="Text / bytes">
      <div className="flex items-center gap-2 mb-2">
        <button type="button" onClick={() => setMode("text")}
          className={"px-2 py-0.5 text-xs rounded " + (mode === "text" ? "bg-zinc-700" : "bg-zinc-900 text-zinc-400")}>as text</button>
        <button type="button" onClick={() => setMode("hex")}
          className={"px-2 py-0.5 text-xs rounded " + (mode === "hex" ? "bg-zinc-700" : "bg-zinc-900 text-zinc-400")}>as hex</button>
      </div>
      <textarea className={inputCls + " w-full h-20 resize-y mb-2"} value={text} onChange={(e) => setText(e.target.value)} />
      {bytes === null ? (
        <div className="text-amber-500 text-xs">- odd-length / invalid hex -</div>
      ) : (
        <>
          <Row label="Length">{bytes.length} byte{bytes.length === 1 ? "" : "s"}</Row>
          <Row label="Hex">{toHexStr(bytes) || "(empty)"}</Row>
          <Row label="Base64">{b64(bytes)}</Row>
          <Row label="Base64url">{b64(bytes, true)}</Row>
          {mode === "text" ? <Row label="URL-encoded">{encodeURIComponent(text)}</Row> : null}
          {mode === "text" ? <Row label="JS escaped">{jsEscape(text)}</Row> : null}
          {mode === "text" ? (
            <Row label="Code points">{[...text].slice(0, 64).map((c) => "U+" + c.codePointAt(0)!.toString(16).toUpperCase().padStart(4, "0")).join(" ") + ([...text].length > 64 ? " …" : "")}</Row>
          ) : (
            <Row label="As UTF-8 text">{(() => { try { return new TextDecoder("utf-8", { fatal: true }).decode(bytes) || "(empty)"; } catch { return "(not valid UTF-8)"; } })()}</Row>
          )}
        </>
      )}
    </Section>
  );
}

function TimestampSection() {
  const [raw, setRaw] = useState(String(Math.floor(Date.now() / 1000)));
  const v = parseIntFlexible(raw);
  return (
    <Section title="Timestamp">
      <input className={inputCls + " w-full mb-2"} value={raw} onChange={(e) => setRaw(e.target.value)}
             placeholder="number (decimal or 0x…)" />
      {v === null ? <div className="text-zinc-500 text-xs">- enter a number -</div> : (
        <>
          <Row label="Unix (seconds)">{fmtDate(new Date(Number(v) * 1000))}</Row>
          <Row label="Unix (milliseconds)">{fmtDate(new Date(Number(v)))}</Row>
          <Row label="Windows FILETIME">{fmtDate(fromFiletime(v < 0n ? 0n : v))}</Row>
          <Row label="DOS date/time">{fmtDate(fromDosDateTime(Number(maskTo(v, 32))))}</Row>
        </>
      )}
    </Section>
  );
}

function HashSection({ bytes }: { bytes: Uint8Array | null }) {
  const [sha, setSha] = useState<{ sha1: string; sha256: string } | null>(null);
  const crc = useMemo(() => (bytes ? crc32(bytes) : 0), [bytes]);
  useEffect(() => {
    let cancelled = false;
    if (!bytes || !crypto?.subtle) { setSha(null); return; }
    const buf = bytes.slice().buffer;
    Promise.all([crypto.subtle.digest("SHA-1", buf), crypto.subtle.digest("SHA-256", buf)])
      .then(([a, b]) => { if (!cancelled) setSha({ sha1: toHexStr(new Uint8Array(a)), sha256: toHexStr(new Uint8Array(b)) }); })
      .catch(() => { if (!cancelled) setSha({ sha1: "?", sha256: "?" }); });
    return () => { cancelled = true; };
  }, [bytes]);
  return (
    <Section title="Hashes (of the Text / bytes input)">
      {bytes === null ? <div className="text-zinc-500 text-xs">- provide a valid input above -</div> : (
        <>
          <Row label="CRC32">{(crc >>> 0).toString(16).padStart(8, "0")} <span className="text-zinc-600">({crc >>> 0})</span></Row>
          <Row label="SHA-1">{sha?.sha1 ?? "…"}</Row>
          <Row label="SHA-256">{sha?.sha256 ?? "…"}</Row>
          <div className="text-[11px] text-zinc-600 mt-1">MD5 isn't in the browser crypto API - the file scan's Hash panel computes it via the wasm engine.</div>
        </>
      )}
    </Section>
  );
}

export function DataConverterPanel() {
  const [textBytes, setTextBytes] = useState<Uint8Array | null>(null);
  return (
    <div className="p-4 grid gap-3 md:grid-cols-2 content-start">
      <NumberSection />
      <TimestampSection />
      <TextSection onBytes={setTextBytes} />
      <HashSection bytes={textBytes} />
    </div>
  );
}
