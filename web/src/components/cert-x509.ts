import type { CertAsn1Node } from "../worker/protocol";

const TAG_INTEGER = 0x02;
const TAG_BIT_STRING = 0x03;
const TAG_UTF8_STRING = 0x0c;
const TAG_PRINTABLE_STRING = 0x13;
const TAG_T61_STRING = 0x14;
const TAG_IA5_STRING = 0x16;
const TAG_UTC_TIME = 0x17;
const TAG_GENERALIZED_TIME = 0x18;
const TAG_VISIBLE_STRING = 0x1a;
const TAG_UNIVERSAL_STRING = 0x1c;
const TAG_BMP_STRING = 0x1e;
const TAG_NUMERIC_STRING = 0x12;
const TAG_SEQUENCE = 0x30;
const TAG_CONTEXT_0 = 0xa0;

const STRING_TAGS = new Set<number>([
  TAG_UTF8_STRING,
  TAG_PRINTABLE_STRING,
  TAG_T61_STRING,
  TAG_IA5_STRING,
  TAG_VISIBLE_STRING,
  TAG_UNIVERSAL_STRING,
  TAG_BMP_STRING,
  TAG_NUMERIC_STRING,
]);

const DN_OID_LABELS: Record<string, string> = {
  "2.5.4.3": "CN",
  "2.5.4.4": "SN",
  "2.5.4.5": "serialNumber",
  "2.5.4.6": "C",
  "2.5.4.7": "L",
  "2.5.4.8": "ST",
  "2.5.4.9": "STREET",
  "2.5.4.10": "O",
  "2.5.4.11": "OU",
  "2.5.4.12": "title",
  "2.5.4.13": "description",
  "2.5.4.15": "businessCategory",
  "2.5.4.17": "postalCode",
  "2.5.4.42": "GN",
  "2.5.4.43": "initials",
  "2.5.4.97": "organizationIdentifier",
  "1.2.840.113549.1.9.1": "E",
  "1.3.6.1.4.1.311.60.2.1.1": "jurisdictionL",
  "1.3.6.1.4.1.311.60.2.1.2": "jurisdictionST",
  "1.3.6.1.4.1.311.60.2.1.3": "jurisdictionC",
};

const ALG_OID_NAMES: Record<string, string> = {
  "1.2.840.113549.1.1.1": "RSA",
  "1.2.840.113549.1.1.5": "SHA1withRSA",
  "1.2.840.113549.1.1.10": "RSASSA-PSS",
  "1.2.840.113549.1.1.11": "SHA256withRSA",
  "1.2.840.113549.1.1.12": "SHA384withRSA",
  "1.2.840.113549.1.1.13": "SHA512withRSA",
  "1.2.840.113549.1.1.14": "SHA224withRSA",
  "1.2.840.10045.2.1": "EC Public Key",
  "1.2.840.10045.4.3.2": "ECDSA-SHA256",
  "1.2.840.10045.4.3.3": "ECDSA-SHA384",
  "1.2.840.10045.4.3.4": "ECDSA-SHA512",
  "1.2.840.10040.4.1": "DSA",
  "1.3.14.3.2.29": "SHA1withRSA",
  "2.16.840.1.101.3.4.2.1": "SHA-256",
};

export interface DnPair {
  label: string;
  oid: string;
  value: string;
}

export interface ParsedX509 {
  derOffset: number;
  derLength: number;
  version: number;
  serial: string;
  subject: DnPair[];
  issuer: DnPair[];
  subjectText: string;
  issuerText: string;
  notBefore: string;
  notAfter: string;
  signatureAlgorithm: string;
  publicKeyAlgorithm: string;
  selfSigned: boolean;
}

export interface Thumbprints {
  sha1: string;
  sha256: string;
}

function headerSize(bytes: Uint8Array, tagOffset: number): number {
  const lenByte = bytes[tagOffset + 1];
  if (lenByte === undefined) return 2;
  if (lenByte < 0x80) return 2;
  return 2 + (lenByte & 0x7f);
}

function contentRange(bytes: Uint8Array, node: CertAsn1Node): [number, number] {
  const start = node.offset + headerSize(bytes, node.offset);
  const end = Math.min(bytes.length, start + node.size);
  return [Math.min(start, bytes.length), end];
}

function fullRange(bytes: Uint8Array, node: CertAsn1Node): [number, number] {
  const hs = headerSize(bytes, node.offset);
  const end = Math.min(bytes.length, node.offset + hs + node.size);
  return [Math.min(node.offset, bytes.length), end];
}

const latin1 = new TextDecoder("latin1");
const utf8 = new TextDecoder("utf-8");

function decodeUtf16BE(b: Uint8Array): string {
  try {
    return new TextDecoder("utf-16be").decode(b);
  } catch {
    let out = "";
    for (let i = 0; i + 1 < b.length; i += 2) out += String.fromCharCode((b[i]! << 8) | b[i + 1]!);
    return out;
  }
}

function decodeUtf32BE(b: Uint8Array): string {
  let out = "";
  for (let i = 0; i + 3 < b.length; i += 4) {
    out += String.fromCodePoint((b[i]! << 24) | (b[i + 1]! << 16) | (b[i + 2]! << 8) | b[i + 3]!);
  }
  return out;
}

export function decodeAsn1String(bytes: Uint8Array, node: CertAsn1Node): string {
  const [s, e] = contentRange(bytes, node);
  const slice = bytes.subarray(s, e);
  let text: string;
  switch (node.tagId) {
    case TAG_BMP_STRING:
      text = decodeUtf16BE(slice);
      break;
    case TAG_UNIVERSAL_STRING:
      text = decodeUtf32BE(slice);
      break;
    case TAG_UTF8_STRING:
      text = utf8.decode(slice);
      break;
    default:
      text = latin1.decode(slice);
  }
  return text.replace(/\0+$/, "").trim();
}

export function decodeAsn1Time(bytes: Uint8Array, node: CertAsn1Node): string {
  const [s, e] = contentRange(bytes, node);
  const raw = latin1.decode(bytes.subarray(s, e)).trim();
  const m = raw.match(/^(\d{2,4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?/);
  if (!m) return raw;
  let year = parseInt(m[1]!, 10);
  if (node.tagId === TAG_UTC_TIME && m[1]!.length === 2) {
    year += year < 50 ? 2000 : 1900;
  }
  const mo = m[2]!, d = m[3]!, h = m[4]!, mi = m[5]!, se = m[6] ?? "00";
  return `${year}-${mo}-${d} ${h}:${mi}:${se} UTC`;
}

function contentHex(bytes: Uint8Array, node: CertAsn1Node): string {
  const [s, e] = contentRange(bytes, node);
  let out = "";
  for (let i = s; i < e; i++) out += bytes[i]!.toString(16).padStart(2, "0");
  return out.toUpperCase();
}

function intFromContent(bytes: Uint8Array, node: CertAsn1Node): number {
  const [s, e] = contentRange(bytes, node);
  let n = 0;
  for (let i = s; i < e; i++) n = (n << 8) | bytes[i]!;
  return n;
}

function algName(seq: CertAsn1Node | undefined): string {
  const oidNode = seq?.children?.[0];
  if (!oidNode?.value) return "";
  return ALG_OID_NAMES[oidNode.value] ?? oidNode.oidName ?? oidNode.value;
}

function isCertificate(node: CertAsn1Node): boolean {
  if (node.tagId !== TAG_SEQUENCE) return false;
  const k = node.children;
  if (!k || k.length !== 3) return false;
  if (k[0]!.tagId !== TAG_SEQUENCE) return false;
  if (k[1]!.tagId !== TAG_SEQUENCE) return false;
  if (k[2]!.tagId !== TAG_BIT_STRING) return false;
  const tbs = k[0]!.children;
  return !!tbs && tbs.length >= 6;
}

function parseDN(bytes: Uint8Array, name: CertAsn1Node | undefined): DnPair[] {
  const out: DnPair[] = [];
  for (const rdn of name?.children ?? []) {
    for (const atv of rdn.children ?? []) {
      const oidNode = atv.children?.[0];
      const valNode = atv.children?.[1];
      if (!oidNode?.value || !valNode) continue;
      const oid = oidNode.value;
      out.push({
        label: DN_OID_LABELS[oid] ?? oidNode.oidName ?? oid,
        oid,
        value: STRING_TAGS.has(valNode.tagId) ? decodeAsn1String(bytes, valNode) : "",
      });
    }
  }
  return out;
}

function dnText(pairs: DnPair[]): string {
  return pairs.map((p) => `${p.label}=${p.value}`).join(", ");
}

function tryParseCert(bytes: Uint8Array, certNode: CertAsn1Node): ParsedX509 | null {
  try {
    const k = certNode.children!;
    const tbs = k[0]!.children!;
    const sigAlgNode = k[1]!;

    let i = 0;
    let version = 1;
    if (tbs[i]?.tagId === TAG_CONTEXT_0) {
      const verInt = tbs[i]!.children?.[0];
      if (verInt) version = intFromContent(bytes, verInt) + 1;
      i++;
    }
    const serialNode = tbs[i++];
    i++;
    const issuerNode = tbs[i++];
    const validityNode = tbs[i++];
    const subjectNode = tbs[i++];
    const spkiNode = tbs[i++];

    const issuer = parseDN(bytes, issuerNode);
    const subject = parseDN(bytes, subjectNode);
    const valKids = validityNode?.children ?? [];
    const [df, de] = fullRange(bytes, certNode);
    const issuerText = dnText(issuer);
    const subjectText = dnText(subject);

    return {
      derOffset: df,
      derLength: de - df,
      version,
      serial: serialNode ? contentHex(bytes, serialNode) : "",
      subject,
      issuer,
      subjectText,
      issuerText,
      notBefore: valKids[0] ? decodeAsn1Time(bytes, valKids[0]) : "",
      notAfter: valKids[1] ? decodeAsn1Time(bytes, valKids[1]) : "",
      signatureAlgorithm: algName(sigAlgNode),
      publicKeyAlgorithm: algName(spkiNode),
      selfSigned: issuerText !== "" && issuerText === subjectText,
    };
  } catch {
    return null;
  }
}

export function parseCertificates(bytes: Uint8Array, root: CertAsn1Node): ParsedX509[] {
  const out: ParsedX509[] = [];
  const seen = new Set<number>();
  const visit = (node: CertAsn1Node): void => {
    if (isCertificate(node)) {
      const parsed = tryParseCert(bytes, node);
      if (parsed && !seen.has(parsed.derOffset)) {
        seen.add(parsed.derOffset);
        out.push(parsed);
      }
      return;
    }
    for (const c of node.children ?? []) visit(c);
  };
  visit(root);
  return out;
}

function toHex(buf: ArrayBuffer): string {
  const b = new Uint8Array(buf);
  let out = "";
  for (let i = 0; i < b.length; i++) out += b[i]!.toString(16).padStart(2, "0");
  return out.toUpperCase();
}

export async function computeThumbprints(der: Uint8Array): Promise<Thumbprints> {
  const buf = der.slice().buffer;
  const [sha1, sha256] = await Promise.all([
    crypto.subtle.digest("SHA-1", buf),
    crypto.subtle.digest("SHA-256", buf),
  ]);
  return { sha1: toHex(sha1), sha256: toHex(sha256) };
}

export function decodeNodeDisplayValue(bytes: Uint8Array, node: CertAsn1Node): string | null {
  if (node.children?.length) return null;
  if (STRING_TAGS.has(node.tagId)) return decodeAsn1String(bytes, node) || null;
  if (node.tagId === TAG_UTC_TIME || node.tagId === TAG_GENERALIZED_TIME) {
    return decodeAsn1Time(bytes, node);
  }
  if (node.tagId === TAG_INTEGER) {
    const hex = contentHex(bytes, node);
    return hex ? `0x${hex}` : null;
  }
  return node.value ?? null;
}
