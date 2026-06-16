import type { ArchiveEntry, ArchiveListing } from "./protocol";

const OLE_SIG = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
const ENDOFCHAIN = 0xfffffffe;
const FREESECT = 0xffffffff;
const NOSTREAM = 0xffffffff;
const MAX_STREAMS = 20_000;
const MAX_EXTRACT_BYTES = 256 * 1024 * 1024;

export function looksLikeOle2(b: Uint8Array): boolean {
  if (b.length < 512) return false;
  for (let i = 0; i < 8; i++) if (b[i] !== OLE_SIG[i]) return false;
  return true;
}

interface DirEntry {
  name: string;
  type: number;
  start: number;
  size: number;
  left: number;
  right: number;
  child: number;
  clsid: Uint8Array;
}

interface Ole2 {
  bytes: Uint8Array;
  sectorSize: number;
  miniSectorSize: number;
  miniCutoff: number;
  fat: Uint32Array;
  miniFat: Uint32Array;
  miniStream: Uint8Array;
  dir: DirEntry[];
}

const MSI_B64 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._";

function decodeMsiName(chars: number[]): string {
  let out = "";
  for (const c of chars) {
    if (c >= 0x3800 && c < 0x4800) {
      const n = c - 0x3800;
      out += MSI_B64[n & 0x3f]! + MSI_B64[(n >> 6) & 0x3f]!;
    } else if (c >= 0x4800 && c < 0x4840) {
      out += MSI_B64[c - 0x4800]!;
    } else if (c < 0x20) {
      out += "\\x" + c.toString(16).padStart(2, "0");
    } else {
      out += String.fromCharCode(c);
    }
  }
  return out;
}

function readChain(fat: Uint32Array, start: number): number[] {
  const out: number[] = [];
  const seen = new Set<number>();
  let s = start;
  while (s !== ENDOFCHAIN && s !== FREESECT && s < fat.length) {
    if (seen.has(s)) break;
    seen.add(s);
    out.push(s);
    if (out.length > fat.length) break;
    s = fat[s]!;
  }
  return out;
}

function gatherSectors(bytes: Uint8Array, chain: number[], sectorSize: number, headerSize: number): Uint8Array {
  const buf = new Uint8Array(chain.length * sectorSize);
  for (let i = 0; i < chain.length; i++) {
    const off = headerSize + chain[i]! * sectorSize;
    if (off + sectorSize <= bytes.length) buf.set(bytes.subarray(off, off + sectorSize), i * sectorSize);
  }
  return buf;
}

function gatherMini(miniStream: Uint8Array, chain: number[], miniSectorSize: number): Uint8Array {
  const buf = new Uint8Array(chain.length * miniSectorSize);
  for (let i = 0; i < chain.length; i++) {
    const off = chain[i]! * miniSectorSize;
    if (off + miniSectorSize <= miniStream.length) buf.set(miniStream.subarray(off, off + miniSectorSize), i * miniSectorSize);
  }
  return buf;
}

function parse(bytes: Uint8Array): Ole2 | null {
  if (!looksLikeOle2(bytes)) return null;
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.length);

  const sectorSize = 1 << dv.getUint16(0x1e, true);
  const miniSectorSize = 1 << dv.getUint16(0x20, true);
  if ((sectorSize !== 512 && sectorSize !== 4096) || miniSectorSize !== 64) return null;
  const headerSize = sectorSize;

  const firstDirSector = dv.getUint32(0x30, true);
  const miniCutoff = dv.getUint32(0x38, true) || 4096;
  const firstMiniFat = dv.getUint32(0x3c, true);
  const firstDifat = dv.getUint32(0x44, true);

  const fatSectors: number[] = [];
  for (let i = 0; i < 109; i++) {
    const s = dv.getUint32(0x4c + i * 4, true);
    if (s !== FREESECT && s !== ENDOFCHAIN) fatSectors.push(s);
  }
  let difat = firstDifat;
  const perDifat = sectorSize / 4 - 1;
  let guard = 0;
  while (difat !== ENDOFCHAIN && difat !== FREESECT && guard++ < 100_000) {
    const off = headerSize + difat * sectorSize;
    if (off + sectorSize > bytes.length) break;
    for (let i = 0; i < perDifat; i++) {
      const s = dv.getUint32(off + i * 4, true);
      if (s !== FREESECT && s !== ENDOFCHAIN) fatSectors.push(s);
    }
    difat = dv.getUint32(off + perDifat * 4, true);
  }

  const perSector = sectorSize / 4;
  const fat = new Uint32Array(fatSectors.length * perSector);
  let fi = 0;
  for (const fs of fatSectors) {
    const off = headerSize + fs * sectorSize;
    for (let i = 0; i < perSector; i++) {
      fat[fi++] = off + i * 4 + 4 <= bytes.length ? dv.getUint32(off + i * 4, true) : ENDOFCHAIN;
    }
  }

  const dirData = gatherSectors(bytes, readChain(fat, firstDirSector), sectorSize, headerSize);
  const ddv = new DataView(dirData.buffer, dirData.byteOffset, dirData.byteLength);
  const count = Math.floor(dirData.length / 128);
  const dir: DirEntry[] = [];
  for (let i = 0; i < count; i++) {
    const b0 = i * 128;
    const type = dirData[b0 + 0x42]!;
    const nameLen = ddv.getUint16(b0 + 0x40, true);
    const nchars = nameLen >= 2 ? Math.min(nameLen / 2 - 1, 32) : 0;
    const chars: number[] = [];
    for (let c = 0; c < nchars; c++) chars.push(ddv.getUint16(b0 + c * 2, true));
    let size = ddv.getUint32(b0 + 0x78, true);
    if (sectorSize !== 512) size += ddv.getUint32(b0 + 0x7c, true) * 0x1_0000_0000;
    dir.push({
      name: decodeMsiName(chars),
      type,
      start: ddv.getUint32(b0 + 0x74, true),
      size,
      left: ddv.getUint32(b0 + 0x44, true),
      right: ddv.getUint32(b0 + 0x48, true),
      child: ddv.getUint32(b0 + 0x4c, true),
      clsid: dirData.slice(b0 + 0x50, b0 + 0x60),
    });
  }
  if (dir.length === 0) return null;

  const root = dir[0]!;
  let miniStream = gatherSectors(bytes, readChain(fat, root.start), sectorSize, headerSize);
  if (miniStream.length > root.size) miniStream = miniStream.subarray(0, root.size);
  const miniFatData = gatherSectors(bytes, readChain(fat, firstMiniFat), sectorSize, headerSize);
  const mdv = new DataView(miniFatData.buffer, miniFatData.byteOffset, miniFatData.byteLength);
  const miniFat = new Uint32Array(Math.floor(miniFatData.length / 4));
  for (let i = 0; i < miniFat.length; i++) miniFat[i] = mdv.getUint32(i * 4, true);

  return { bytes, sectorSize, miniSectorSize, miniCutoff, fat, miniFat, miniStream, dir };
}

interface WalkItem { path: string; entry: DirEntry }

function walk(o: Ole2): WalkItem[] {
  const out: WalkItem[] = [];
  const visited = new Set<number>();
  const rec = (id: number, prefix: string): void => {
    if (id === NOSTREAM || id >= o.dir.length || visited.has(id) || out.length > MAX_STREAMS) return;
    visited.add(id);
    const e = o.dir[id]!;
    rec(e.left, prefix);
    const path = prefix ? prefix + "/" + e.name : e.name;
    if (e.type === 1) {
      out.push({ path, entry: e });
      rec(e.child, path);
    } else if (e.type === 2) {
      out.push({ path, entry: e });
    }
    rec(e.right, prefix);
  };
  rec(o.dir[0]!.child, "");
  return out;
}

function readStream(o: Ole2, e: DirEntry): Uint8Array {
  if (e.size <= 0) return new Uint8Array(0);
  if (e.size < o.miniCutoff) {
    return gatherMini(o.miniStream, readChain(o.miniFat, e.start), o.miniSectorSize).subarray(0, e.size);
  }
  return gatherSectors(o.bytes, readChain(o.fat, e.start), o.sectorSize, o.sectorSize).subarray(0, e.size);
}

function kindFromClsid(clsid: Uint8Array): string | null {
  const hex = Array.from(clsid, (b) => b.toString(16).padStart(2, "0")).join("");
  if (hex.startsWith("84100c00")) return "MSI Installer (CFBF)";
  if (hex.startsWith("86100c00")) return "MSI Patch / MSP (CFBF)";
  if (hex.startsWith("85100c00")) return "MSI Merge Module / MSM (CFBF)";
  return null;
}

export function listOle2(bytes: Uint8Array, kindHint?: string): ArchiveListing | null {
  const o = parse(bytes);
  if (!o) return null;
  const items = walk(o);

  const entries: ArchiveEntry[] = [];
  let totalSize = 0;
  for (const it of items) {
    if (entries.length >= MAX_STREAMS) break;
    const isDir = it.entry.type === 1;
    if (!isDir) totalSize += it.entry.size;
    entries.push({
      name: it.path,
      isDir,
      size: it.entry.size,
      compressedSize: it.entry.size,
      method: isDir ? "storage" : "stream",
      crc32: 0,
      encrypted: false,
    });
  }

  return {
    kind: kindFromClsid(o.dir[0]!.clsid) ?? kindHint ?? "OLE2 Compound File",
    entries,
    totalEntries: items.length,
    totalSize,
    totalCompressedSize: totalSize,
    truncated: entries.length < items.length,
  };
}

export function extractOle2Stream(
  bytes: Uint8Array, path: string,
): { data: Uint8Array<ArrayBuffer> } | { error: string } {
  const o = parse(bytes);
  if (!o) return { error: "not an OLE2 compound file" };
  const hit = walk(o).find((it) => it.path === path && it.entry.type === 2);
  if (!hit) return { error: `stream "${path}" not found` };
  if (hit.entry.size > MAX_EXTRACT_BYTES) return { error: `stream too large to extract (${hit.entry.size} bytes)` };
  return { data: readStream(o, hit.entry).slice() };
}
