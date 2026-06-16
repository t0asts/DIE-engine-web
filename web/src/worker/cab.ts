import type { ArchiveEntry, ArchiveListing } from "./protocol";
import { inflateRaw } from "./inflate";

const MAX_EXTRACT_BYTES = 256 * 1024 * 1024;
const MAX_FILES = 20_000;
const MSZIP_WINDOW = 32768;

const COMPRESS = ["store", "mszip", "quantum", "lzx"] as const;

const FOLDER_CONTINUED_FROM_PREV = 0xfffd;
const FOLDER_CONTINUED_TO_NEXT = 0xfffe;
const FOLDER_CONTINUED_PREV_AND_NEXT = 0xffff;

export function looksLikeCab(b: Uint8Array): boolean {
  return b.length >= 36 && b[0] === 0x4d && b[1] === 0x53 && b[2] === 0x43 && b[3] === 0x46;
}

interface Folder { coffData: number; cCFData: number; compType: number }
interface CabFile { name: string; size: number; folderIdx: number; iFolder: number; offset: number; date?: string }
interface Cab { bytes: Uint8Array; cbCFData: number; folders: Folder[]; files: CabFile[]; truncated: boolean }

function cabDate(date: number, time: number): string | undefined {
  if (!date) return undefined;
  const y = ((date >> 9) & 0x7f) + 1980;
  const mo = (date >> 5) & 0x0f;
  const d = date & 0x1f;
  if (mo < 1 || mo > 12 || d < 1 || d > 31) return undefined;
  const h = (time >> 11) & 0x1f, mi = (time >> 5) & 0x3f, s = (time & 0x1f) * 2;
  const p2 = (n: number) => String(n).padStart(2, "0");
  return `${y}-${p2(mo)}-${p2(d)} ${p2(h)}:${p2(mi)}:${p2(s)}`;
}

function skipCstr(b: Uint8Array, p: number): number {
  while (p < b.length && b[p] !== 0) p++;
  return p + 1;
}

function parseCab(bytes: Uint8Array): Cab | null {
  if (!looksLikeCab(bytes)) return null;
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.length);

  const coffFiles = dv.getUint32(16, true);
  const cFolders = dv.getUint16(26, true);
  const cFiles = dv.getUint16(28, true);
  const flags = dv.getUint16(30, true);

  let p = 36;
  let cbCFFolder = 0, cbCFData = 0;
  if (flags & 0x0004) {
    const cbCFHeader = dv.getUint16(p, true);
    cbCFFolder = bytes[p + 2]!;
    cbCFData = bytes[p + 3]!;
    p += 4 + cbCFHeader;
  }
  if (flags & 0x0001) { p = skipCstr(bytes, skipCstr(bytes, p)); }
  if (flags & 0x0002) { p = skipCstr(bytes, skipCstr(bytes, p)); }

  const folders: Folder[] = [];
  for (let i = 0; i < cFolders; i++) {
    if (p + 8 > bytes.length) break;
    folders.push({
      coffData: dv.getUint32(p, true),
      cCFData: dv.getUint16(p + 4, true),
      compType: dv.getUint16(p + 6, true),
    });
    p += 8 + cbCFFolder;
  }

  const files: CabFile[] = [];
  let fp = coffFiles;
  let truncated = false;
  for (let i = 0; i < cFiles; i++) {
    if (fp + 16 > bytes.length) break;
    if (files.length >= MAX_FILES) { truncated = true; break; }
    const size = dv.getUint32(fp, true);
    const offset = dv.getUint32(fp + 4, true);
    const iFolder = dv.getUint16(fp + 8, true);
    const date = dv.getUint16(fp + 10, true);
    const time = dv.getUint16(fp + 12, true);
    const attribs = dv.getUint16(fp + 14, true);
    const nameStart = fp + 16;
    let e = nameStart;
    while (e < bytes.length && bytes[e] !== 0) e++;
    const nameBytes = bytes.subarray(nameStart, e);
    const name = new TextDecoder(attribs & 0x80 ? "utf-8" : "latin1", { fatal: false }).decode(nameBytes);
    const folderIdx =
      iFolder === FOLDER_CONTINUED_FROM_PREV || iFolder === FOLDER_CONTINUED_PREV_AND_NEXT ? 0
      : iFolder === FOLDER_CONTINUED_TO_NEXT ? Math.max(0, folders.length - 1)
      : iFolder;
    const f: CabFile = { name: name.replace(/\\/g, "/"), size, folderIdx, iFolder, offset };
    const d = cabDate(date, time);
    if (d) f.date = d;
    files.push(f);
    fp = e + 1;
  }

  return { bytes, cbCFData, folders, files, truncated };
}

function decompressFolder(cab: Cab, idx: number): Uint8Array<ArrayBuffer> | { error: string } {
  const folder = cab.folders[idx];
  if (!folder) return { error: "bad folder index" };
  const method = folder.compType & 0x0f;
  if (method !== 0 && method !== 1) {
    return { error: `${COMPRESS[method] ?? `type ${method}`} compression is not supported` };
  }
  const { bytes } = cab;
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.length);

  const chunks: Uint8Array[] = [];
  let total = 0;
  let dict: Uint8Array = new Uint8Array(0);
  let p = folder.coffData;

  for (let b = 0; b < folder.cCFData; b++) {
    if (p + 8 > bytes.length) break;
    const cbData = dv.getUint16(p + 4, true);
    const cbUncomp = dv.getUint16(p + 6, true);
    const dataOff = p + 8 + cab.cbCFData;
    if (dataOff + cbData > bytes.length) break;
    const comp = bytes.subarray(dataOff, dataOff + cbData);

    let block: Uint8Array;
    if (method === 0) {
      block = comp.slice(0, cbUncomp);
    } else {
      if (comp[0] !== 0x43 || comp[1] !== 0x4b) return { error: "bad MSZIP block signature" };
      try {
        block = inflateRaw(comp.subarray(2), cbUncomp, dict);
      } catch (e) {
        return { error: `MSZIP inflate failed: ${(e as Error).message}` };
      }
    }
    chunks.push(block);
    total += block.length;
    if (block.length >= MSZIP_WINDOW) {
      dict = block.subarray(block.length - MSZIP_WINDOW);
    } else if (dict.length + block.length <= MSZIP_WINDOW) {
      const merged = new Uint8Array(dict.length + block.length);
      merged.set(dict, 0); merged.set(block, dict.length);
      dict = merged;
    } else {
      const merged = new Uint8Array(MSZIP_WINDOW);
      const keepPrev = MSZIP_WINDOW - block.length;
      merged.set(dict.subarray(dict.length - keepPrev), 0);
      merged.set(block, keepPrev);
      dict = merged;
    }
    p = dataOff + cbData;
  }

  const out = new Uint8Array(total);
  let o = 0;
  for (const c of chunks) { out.set(c, o); o += c.length; }
  return out;
}

export function listCab(bytes: Uint8Array, kindHint?: string): ArchiveListing | null {
  const cab = parseCab(bytes);
  if (!cab) return null;

  const entries: ArchiveEntry[] = [];
  let totalSize = 0;
  for (const f of cab.files) {
    const folder = cab.folders[f.folderIdx];
    const method = folder ? COMPRESS[folder.compType & 0x0f] ?? `type${folder.compType & 0x0f}` : "?";
    totalSize += f.size;
    const e: ArchiveEntry = {
      name: f.name,
      isDir: false,
      size: f.size,
      compressedSize: f.size,
      method,
      crc32: 0,
      encrypted: false,
    };
    if (f.date) e.date = f.date;
    entries.push(e);
  }

  return {
    kind: kindHint ?? "Microsoft Cabinet (CAB)",
    entries,
    totalEntries: cab.files.length,
    totalSize,
    totalCompressedSize: totalSize,
    truncated: cab.truncated,
  };
}

export function extractCabFile(bytes: Uint8Array, name: string): { data: Uint8Array<ArrayBuffer> } | { error: string } {
  const cab = parseCab(bytes);
  if (!cab) return { error: "not a CAB archive" };
  const file = cab.files.find((f) => f.name === name);
  if (!file) return { error: `file "${name}" not found` };
  if (file.iFolder === FOLDER_CONTINUED_FROM_PREV || file.iFolder === FOLDER_CONTINUED_TO_NEXT
      || file.iFolder === FOLDER_CONTINUED_PREV_AND_NEXT) {
    return { error: "file spans multiple cabinets (multi-part CAB not supported)" };
  }
  if (file.size > MAX_EXTRACT_BYTES) return { error: `file too large to extract (${file.size} bytes)` };

  const folderData = decompressFolder(cab, file.folderIdx);
  if ("error" in folderData) return folderData;
  const end = file.offset + file.size;
  if (end > folderData.length) return { error: "truncated or corrupt folder data" };
  return { data: folderData.slice(file.offset, end) };
}
