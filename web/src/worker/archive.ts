
import type { ArchiveEntry, ArchiveListing } from "./protocol";

const SIG_EOCD   = 0x06054b50; 
const SIG_EOCD64 = 0x06064b50; 
const SIG_LOC64  = 0x07064b50; 
const SIG_CDH    = 0x02014b50; 
const SIG_LFH    = 0x04034b50; 

const MAX_ENTRIES = 20_000;    
const MAX_EXTRACT_BYTES = 256 * 1024 * 1024;  

export function looksLikeZip(bytes: Uint8Array): boolean {
  
  return bytes.length >= 4 && bytes[0] === 0x50 && bytes[1] === 0x4b &&
    ((bytes[2] === 0x03 && bytes[3] === 0x04) ||
     (bytes[2] === 0x05 && bytes[3] === 0x06) ||
     (bytes[2] === 0x07 && bytes[3] === 0x08));
}

export function listZipEntries(bytes: Uint8Array, kindHint?: string): ArchiveListing | null {
  if (bytes.length < 22 || !looksLikeZip(bytes)) return null;
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

  const eocdOff = findSig(bytes, SIG_EOCD, Math.max(0, bytes.length - 22 - 0xffff), bytes.length - 22);
  if (eocdOff < 0) return null;

  let entryCount  = dv.getUint16(eocdOff + 10, true);
  let cdSize      = dv.getUint32(eocdOff + 12, true);
  let cdOffset    = dv.getUint32(eocdOff + 16, true);
  const commentLen = dv.getUint16(eocdOff + 20, true);
  const comment = commentLen
    ? new TextDecoder().decode(bytes.subarray(eocdOff + 22, eocdOff + 22 + commentLen))
    : "";

  let note: string | undefined;
  
  if (entryCount === 0xffff || cdSize === 0xffffffff || cdOffset === 0xffffffff) {
    const locOff = findSig(bytes, SIG_LOC64, Math.max(0, eocdOff - 20 - 0x100), eocdOff);
    if (locOff >= 0) {
      const z64Off = Number(dv.getBigUint64(locOff + 8, true));
      if (z64Off >= 0 && z64Off + 56 <= bytes.length && dv.getUint32(z64Off, true) === SIG_EOCD64) {
        entryCount = Number(dv.getBigUint64(z64Off + 32, true));
        cdSize     = Number(dv.getBigUint64(z64Off + 40, true));
        cdOffset   = Number(dv.getBigUint64(z64Off + 48, true));
        note = "Zip64";
      }
    }
  }

  if (cdOffset >= bytes.length) return null;

  const entries: ArchiveEntry[] = [];
  let totalSize = 0, totalCompressedSize = 0, parsed = 0;
  let p = cdOffset;
  const cdEnd = Math.min(bytes.length, cdOffset + (cdSize || bytes.length));

  while (p + 46 <= cdEnd && dv.getUint32(p, true) === SIG_CDH) {
    const flags        = dv.getUint16(p + 8, true);
    const method       = dv.getUint16(p + 10, true);
    const dosTime      = dv.getUint16(p + 12, true);
    const dosDate      = dv.getUint16(p + 14, true);
    const crc32        = dv.getUint32(p + 16, true) >>> 0;
    let   compSize     = dv.getUint32(p + 20, true);
    let   uncompSize   = dv.getUint32(p + 24, true);
    const nameLen      = dv.getUint16(p + 28, true);
    const extraLen     = dv.getUint16(p + 30, true);
    const cmtLen       = dv.getUint16(p + 32, true);
    const name = decodeName(bytes.subarray(p + 46, p + 46 + nameLen), flags);

    if (compSize === 0xffffffff || uncompSize === 0xffffffff) {
      const ex = bytes.subarray(p + 46 + nameLen, p + 46 + nameLen + extraLen);
      const z = readZip64Extra(ex, uncompSize === 0xffffffff, compSize === 0xffffffff);
      if (z) { if (z.uncomp !== undefined) uncompSize = z.uncomp; if (z.comp !== undefined) compSize = z.comp; }
    }

    parsed++;
    const isDir = name.endsWith("/");
    if (!isDir) { totalSize += uncompSize; totalCompressedSize += compSize; }
    if (entries.length < MAX_ENTRIES) {
      const e: ArchiveEntry = {
        name,
        isDir,
        size: uncompSize,
        compressedSize: compSize,
        method: method === 0 ? "store" : method === 8 ? "deflate"
              : method === 12 ? "bzip2" : method === 14 ? "lzma"
              : method === 99 ? "aes" : `0x${method.toString(16)}`,
        crc32,
        encrypted: (flags & 1) !== 0,
      };
      const d = dosDateTime(dosDate, dosTime);
      if (d) e.date = d;
      entries.push(e);
    }
    p += 46 + nameLen + extraLen + cmtLen;
    if (entryCount && parsed >= entryCount && entries.length >= entryCount) break;
  }

  if (parsed === 0) return null;

  return {
    kind: kindHint ?? "ZIP-family",
    entries,
    totalEntries: entryCount && entryCount >= parsed ? entryCount : parsed,
    totalSize,
    totalCompressedSize,
    truncated: entries.length < parsed,
    ...(comment ? { comment } : {}),
    ...(note ? { note } : {}),
  };
}

function findSig(bytes: Uint8Array, sig: number, from: number, to: number): number {
  const b0 = sig & 0xff, b1 = (sig >>> 8) & 0xff, b2 = (sig >>> 16) & 0xff, b3 = (sig >>> 24) & 0xff;
  for (let i = Math.min(to, bytes.length - 4); i >= Math.max(0, from); i--) {
    if (bytes[i] === b0 && bytes[i + 1] === b1 && bytes[i + 2] === b2 && bytes[i + 3] === b3) return i;
  }
  return -1;
}

function decodeName(buf: Uint8Array, flags: number): string {
  
  try {
    return new TextDecoder(flags & 0x800 ? "utf-8" : "utf-8", { fatal: false }).decode(buf);
  } catch {
    return Array.from(buf, (b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : "?")).join("");
  }
}

function readZip64Extra(extra: Uint8Array, wantUncomp: boolean, wantComp: boolean):
    { uncomp?: number; comp?: number } | null {
  const dv = new DataView(extra.buffer, extra.byteOffset, extra.byteLength);
  let i = 0;
  while (i + 4 <= extra.length) {
    const id = dv.getUint16(i, true);
    const len = dv.getUint16(i + 2, true);
    if (id === 0x0001) {
      let off = i + 4;
      const out: { uncomp?: number; comp?: number } = {};
      if (wantUncomp && off + 8 <= i + 4 + len) { out.uncomp = Number(dv.getBigUint64(off, true)); off += 8; }
      if (wantComp   && off + 8 <= i + 4 + len) { out.comp   = Number(dv.getBigUint64(off, true)); off += 8; }
      return out;
    }
    i += 4 + len;
  }
  return null;
}

function dosDateTime(date: number, time: number): string | undefined {
  if (!date) return undefined;
  const y = ((date >> 9) & 0x7f) + 1980;
  const mo = (date >> 5) & 0x0f;
  const d = date & 0x1f;
  const h = (time >> 11) & 0x1f;
  const mi = (time >> 5) & 0x3f;
  const s = (time & 0x1f) * 2;
  if (mo < 1 || mo > 12 || d < 1 || d > 31) return undefined;
  const p2 = (n: number) => String(n).padStart(2, "0");
  return `${y}-${p2(mo)}-${p2(d)} ${p2(h)}:${p2(mi)}:${p2(s)}`;
}

function findCentralDir(bytes: Uint8Array, dv: DataView): { cdOffset: number; cdSize: number } | null {
  const eocdOff = findSig(bytes, SIG_EOCD, Math.max(0, bytes.length - 22 - 0xffff), bytes.length - 22);
  if (eocdOff < 0) return null;
  let cdSize   = dv.getUint32(eocdOff + 12, true);
  let cdOffset = dv.getUint32(eocdOff + 16, true);
  const entryCount = dv.getUint16(eocdOff + 10, true);
  if (entryCount === 0xffff || cdSize === 0xffffffff || cdOffset === 0xffffffff) {
    const locOff = findSig(bytes, SIG_LOC64, Math.max(0, eocdOff - 20 - 0x100), eocdOff);
    if (locOff >= 0) {
      const z64Off = Number(dv.getBigUint64(locOff + 8, true));
      if (z64Off >= 0 && z64Off + 56 <= bytes.length && dv.getUint32(z64Off, true) === SIG_EOCD64) {
        cdSize   = Number(dv.getBigUint64(z64Off + 40, true));
        cdOffset = Number(dv.getBigUint64(z64Off + 48, true));
      }
    }
  }
  if (cdOffset >= bytes.length) return null;
  return { cdOffset, cdSize };
}

export async function extractZipEntry(
  bytes: Uint8Array, entryName: string,
): Promise<{ data: Uint8Array<ArrayBuffer> } | { error: string }> {
  if (!looksLikeZip(bytes)) return { error: "not a ZIP-family archive" };
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const cd = findCentralDir(bytes, dv);
  if (!cd) return { error: "central directory not found" };

  let p = cd.cdOffset;
  const cdEnd = Math.min(bytes.length, cd.cdOffset + (cd.cdSize || bytes.length));
  while (p + 46 <= cdEnd && dv.getUint32(p, true) === SIG_CDH) {
    const flags    = dv.getUint16(p + 8, true);
    const method   = dv.getUint16(p + 10, true);
    let   compSize = dv.getUint32(p + 20, true);
    let   uncompSize = dv.getUint32(p + 24, true);
    const nameLen  = dv.getUint16(p + 28, true);
    const extraLen = dv.getUint16(p + 30, true);
    const cmtLen   = dv.getUint16(p + 32, true);
    let   lhOff    = dv.getUint32(p + 42, true);
    const name = decodeName(bytes.subarray(p + 46, p + 46 + nameLen), flags);

    if (name === entryName) {
      
      if (compSize === 0xffffffff || uncompSize === 0xffffffff || lhOff === 0xffffffff) {
        const ex = bytes.subarray(p + 46 + nameLen, p + 46 + nameLen + extraLen);
        const exdv = new DataView(ex.buffer, ex.byteOffset, ex.byteLength);
        let i = 0;
        while (i + 4 <= ex.length) {
          const id = exdv.getUint16(i, true), len = exdv.getUint16(i + 2, true);
          if (id === 0x0001) {
            let o = i + 4;
            if (uncompSize === 0xffffffff && o + 8 <= i + 4 + len) { uncompSize = Number(exdv.getBigUint64(o, true)); o += 8; }
            if (compSize   === 0xffffffff && o + 8 <= i + 4 + len) { compSize   = Number(exdv.getBigUint64(o, true)); o += 8; }
            if (lhOff      === 0xffffffff && o + 8 <= i + 4 + len) { lhOff      = Number(exdv.getBigUint64(o, true)); o += 8; }
            break;
          }
          i += 4 + len;
        }
      }
      if ((flags & 1) !== 0) return { error: "entry is encrypted" };
      if (method !== 0 && method !== 8) return { error: `compression method ${method} not supported (only stored / deflated)` };
      if (uncompSize > MAX_EXTRACT_BYTES) return { error: `entry too large to extract (${uncompSize} bytes)` };
      if (lhOff + 30 > bytes.length || dv.getUint32(lhOff, true) !== SIG_LFH) return { error: "bad local file header" };
      const lNameLen  = dv.getUint16(lhOff + 26, true);
      const lExtraLen = dv.getUint16(lhOff + 28, true);
      const dataStart = lhOff + 30 + lNameLen + lExtraLen;
      if (dataStart + compSize > bytes.length) return { error: "truncated archive" };
      const comp = bytes.subarray(dataStart, dataStart + compSize).slice();   
      if (method === 0) return { data: comp };
      try {
        const ds = new DecompressionStream("deflate-raw");
        const stream = new Blob([comp]).stream().pipeThrough(ds);
        const buf = await new Response(stream).arrayBuffer();
        return { data: new Uint8Array(buf) };
      } catch (e) {
        return { error: `inflate failed: ${(e as Error).message}` };
      }
    }
    p += 46 + nameLen + extraLen + cmtLen;
  }
  return { error: `entry "${entryName}" not found in archive` };
}
