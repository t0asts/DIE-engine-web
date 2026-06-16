import type {
  BuildIdInfo,
  DebugInfo,
  GnuDebugAltLinkInfo,
  GnuDebugLinkInfo,
  PdbInfo,
} from "./protocol";

const MAX_PATH_LEN = 1024;

function readCString(b: Uint8Array, start: number, maxLen: number): string {
  const hardEnd = Math.min(b.length, start + maxLen);
  let end = start;
  while (end < hardEnd && b[end] !== 0) end++;
  return new TextDecoder("utf-8", { fatal: false }).decode(b.subarray(start, end));
}

const IMAGE_DEBUG_TYPE_CODEVIEW = 2;
const DEBUG_ENTRY_SIZE = 28;
const MAX_DEBUG_ENTRIES = 64;

interface Section {
  vaddr: number;
  vsize: number;
  praw: number;
  rawSize: number;
}

function formatGuid(b: Uint8Array, o: number): string {
  const hb = (i: number) => b[o + i]!.toString(16).padStart(2, "0");
  const d1 = `${hb(3)}${hb(2)}${hb(1)}${hb(0)}`;
  const d2 = `${hb(5)}${hb(4)}`;
  const d3 = `${hb(7)}${hb(6)}`;
  const d4 = `${hb(8)}${hb(9)}`;
  const d5 = `${hb(10)}${hb(11)}${hb(12)}${hb(13)}${hb(14)}${hb(15)}`;
  return `${d1}-${d2}-${d3}-${d4}-${d5}`.toUpperCase();
}

function rvaToOffset(rva: number, sections: Section[]): number | null {
  for (const s of sections) {
    const span = Math.max(s.vsize, s.rawSize);
    if (rva >= s.vaddr && rva < s.vaddr + span) {
      return s.praw + (rva - s.vaddr);
    }
  }
  if (sections.length && rva < sections[0]!.vaddr) return rva;
  return null;
}

function parseCodeView(b: Uint8Array, off: number): PdbInfo | null {
  if (off < 0 || off + 4 > b.length) return null;
  const dv = new DataView(b.buffer, b.byteOffset, b.length);
  const sig = readCString(b, off, 4);

  if (sig === "RSDS") {
    if (off + 24 > b.length) return null;
    const guid = formatGuid(b, off + 4);
    const age = dv.getUint32(off + 20, true);
    const path = readCString(b, off + 24, MAX_PATH_LEN);
    if (!path) return null;
    return { format: "pdb", path, signature: "RSDS", guid, age };
  }

  if (sig === "NB10") {
    if (off + 16 > b.length) return null;
    const age = dv.getUint32(off + 12, true);
    const path = readCString(b, off + 16, MAX_PATH_LEN);
    if (!path) return null;
    return { format: "pdb", path, signature: "NB10", age };
  }

  return null;
}

export function parsePdbInfo(bytes: Uint8Array): PdbInfo | null {
  try {
    const b = bytes;
    const len = b.length;
    if (len < 0x40) return null;
    const dv = new DataView(b.buffer, b.byteOffset, len);

    if (dv.getUint16(0, true) !== 0x5a4d) return null;
    const peOff = dv.getUint32(0x3c, true);
    if (peOff + 24 > len) return null;
    if (dv.getUint32(peOff, true) !== 0x00004550) return null;

    const numSections = dv.getUint16(peOff + 6, true);
    const optSize = dv.getUint16(peOff + 20, true);
    const optOff = peOff + 24;
    if (optOff + 2 > len) return null;

    const magic = dv.getUint16(optOff, true);
    let dirCountOff: number;
    let dirArrayOff: number;
    if (magic === 0x10b) {
      dirCountOff = optOff + 92;
      dirArrayOff = optOff + 96;
    } else if (magic === 0x20b) {
      dirCountOff = optOff + 108;
      dirArrayOff = optOff + 112;
    } else {
      return null;
    }
    if (dirCountOff + 4 > len) return null;
    const numDirs = dv.getUint32(dirCountOff, true);
    if (numDirs <= 6) return null;

    const debugDirEntryOff = dirArrayOff + 6 * 8;
    if (debugDirEntryOff + 8 > len) return null;
    const debugRva = dv.getUint32(debugDirEntryOff, true);
    const debugSize = dv.getUint32(debugDirEntryOff + 4, true);
    if (debugRva === 0 || debugSize === 0) return null;

    const secTableOff = optOff + optSize;
    const sections: Section[] = [];
    for (let i = 0; i < numSections; i++) {
      const so = secTableOff + i * 40;
      if (so + 40 > len) break;
      sections.push({
        vsize: dv.getUint32(so + 8, true),
        vaddr: dv.getUint32(so + 12, true),
        rawSize: dv.getUint32(so + 16, true),
        praw: dv.getUint32(so + 20, true),
      });
    }

    const debugDirOff = rvaToOffset(debugRva, sections);
    if (debugDirOff === null) return null;

    const count = Math.min(Math.floor(debugSize / DEBUG_ENTRY_SIZE), MAX_DEBUG_ENTRIES);
    for (let i = 0; i < count; i++) {
      const eo = debugDirOff + i * DEBUG_ENTRY_SIZE;
      if (eo + DEBUG_ENTRY_SIZE > len) break;
      const type = dv.getUint32(eo + 12, true);
      if (type !== IMAGE_DEBUG_TYPE_CODEVIEW) continue;

      const praw = dv.getUint32(eo + 24, true);
      const rva = dv.getUint32(eo + 20, true);
      const cvOff = praw !== 0 ? praw : rvaToOffset(rva, sections);
      if (cvOff === null) continue;

      const info = parseCodeView(b, cvOff);
      if (info) return info;
    }
    return null;
  } catch {
    return null;
  }
}

const MAX_ELF_SECTIONS = 4096;
const SHN_XINDEX = 0xffff;
const NT_GNU_BUILD_ID = 3;
const MAX_BUILD_ID_BYTES = 64;

interface ElfSection {
  name: number;
  offset: number;
  size: number;
  link: number;
}

const align4 = (n: number) => (n + 3) & ~3;

function parseDebugLinkSection(
  b: Uint8Array, dv: DataView, sh: ElfSection, le: boolean, len: number,
): GnuDebugLinkInfo | null {
  if (sh.size < 5 || sh.offset + sh.size > len) return null;
  const path = readCString(b, sh.offset, MAX_PATH_LEN);
  if (!path) return null;
  const crcOff = sh.offset + sh.size - 4;
  if (crcOff < sh.offset || crcOff + 4 > len) return null;
  const crc = dv.getUint32(crcOff, le);
  return { format: "gnu_debuglink", path, crc32: "0x" + crc.toString(16).padStart(8, "0") };
}

function parseDebugAltLinkSection(
  b: Uint8Array, sh: ElfSection, len: number,
): GnuDebugAltLinkInfo | null {
  const end = Math.min(sh.offset + sh.size, len);
  if (sh.offset < 0 || sh.offset + 2 > end) return null;
  let nul = sh.offset;
  while (nul < end && b[nul] !== 0) nul++;
  if (nul >= end) return null;
  const path = readCString(b, sh.offset, MAX_PATH_LEN);
  if (!path) return null;
  const idStart = nul + 1;
  const idLen = Math.min(end - idStart, MAX_BUILD_ID_BYTES);
  if (idLen <= 0) return null;
  let hex = "";
  for (let i = 0; i < idLen; i++) hex += b[idStart + i]!.toString(16).padStart(2, "0");
  return { format: "gnu_debugaltlink", path, buildId: hex };
}

function parseBuildIdSection(
  b: Uint8Array, dv: DataView, sh: ElfSection, le: boolean, len: number,
): BuildIdInfo | null {
  if (sh.size < 12 || sh.offset + 12 > len) return null;
  const namesz = dv.getUint32(sh.offset, le);
  const descsz = dv.getUint32(sh.offset + 4, le);
  const ntype = dv.getUint32(sh.offset + 8, le);
  if (ntype !== NT_GNU_BUILD_ID || descsz === 0 || descsz > MAX_BUILD_ID_BYTES) return null;
  const nameOff = sh.offset + 12;
  if (readCString(b, nameOff, Math.min(namesz, 16)) !== "GNU") return null;
  const descOff = nameOff + align4(namesz);
  if (descOff + descsz > len || descOff + descsz > sh.offset + sh.size) return null;
  let hex = "";
  for (let i = 0; i < descsz; i++) hex += b[descOff + i]!.toString(16).padStart(2, "0");
  if (!hex) return null;
  return { format: "build-id", buildId: hex };
}

export function parseElfDebugInfo(bytes: Uint8Array): DebugInfo[] {
  try {
    const b = bytes;
    const len = b.length;
    if (len < 0x40) return [];
    if (b[0] !== 0x7f || b[1] !== 0x45 || b[2] !== 0x4c || b[3] !== 0x46) return [];

    const cls = b[4];
    const dataEnc = b[5];
    if (cls !== 1 && cls !== 2) return [];
    const is64 = cls === 2;
    const le = dataEnc !== 2;
    const dv = new DataView(b.buffer, b.byteOffset, len);
    const u64 = (o: number) => Number(dv.getBigUint64(o, le));

    let shoff: number, shentsize: number, shnum: number, shstrndx: number;
    if (is64) {
      shoff = u64(0x28);
      shentsize = dv.getUint16(0x3a, le);
      shnum = dv.getUint16(0x3c, le);
      shstrndx = dv.getUint16(0x3e, le);
    } else {
      shoff = dv.getUint32(0x20, le);
      shentsize = dv.getUint16(0x2e, le);
      shnum = dv.getUint16(0x30, le);
      shstrndx = dv.getUint16(0x32, le);
    }
    if (shoff === 0 || shentsize === 0 || shoff >= len) return [];

    const OFF_NAME = 0;
    const OFF_OFFSET = is64 ? 24 : 16;
    const OFF_SIZE = is64 ? 32 : 20;
    const OFF_LINK = is64 ? 40 : 24;

    const readShdr = (idx: number): ElfSection | null => {
      const base = shoff + idx * shentsize;
      if (base < 0 || base + shentsize > len) return null;
      return {
        name: dv.getUint32(base + OFF_NAME, le),
        offset: is64 ? u64(base + OFF_OFFSET) : dv.getUint32(base + OFF_OFFSET, le),
        size: is64 ? u64(base + OFF_SIZE) : dv.getUint32(base + OFF_SIZE, le),
        link: dv.getUint32(base + OFF_LINK, le),
      };
    };

    const sh0 = readShdr(0);
    if (!sh0) return [];
    if (shnum === 0) shnum = sh0.size;
    if (shstrndx === SHN_XINDEX) shstrndx = sh0.link;
    if (shnum === 0 || shstrndx >= shnum) return [];

    const strSh = readShdr(shstrndx);
    if (!strSh) return [];
    const strBase = strSh.offset;
    const strLimit = Math.min(strSh.offset + strSh.size, len);
    if (strBase >= len) return [];

    const sectionName = (nameOff: number): string => {
      const at = strBase + nameOff;
      if (at < strBase || at >= strLimit) return "";
      return readCString(b, at, 256);
    };

    let buildId: BuildIdInfo | null = null;
    let debugLink: GnuDebugLinkInfo | null = null;
    let altLink: GnuDebugAltLinkInfo | null = null;
    const cap = Math.min(shnum, MAX_ELF_SECTIONS);
    for (let i = 0; i < cap && (!buildId || !debugLink || !altLink); i++) {
      const sh = readShdr(i);
      if (!sh) break;
      const nm = sectionName(sh.name);
      if (!buildId && nm === ".note.gnu.build-id") buildId = parseBuildIdSection(b, dv, sh, le, len);
      else if (!debugLink && nm === ".gnu_debuglink") debugLink = parseDebugLinkSection(b, dv, sh, le, len);
      else if (!altLink && nm === ".gnu_debugaltlink") altLink = parseDebugAltLinkSection(b, sh, len);
    }

    const out: DebugInfo[] = [];
    if (buildId) out.push(buildId);
    if (debugLink) out.push(debugLink);
    if (altLink) out.push(altLink);
    return out;
  } catch {
    return [];
  }
}

export function parseDebugInfo(bytes: Uint8Array): DebugInfo[] {
  const pdb = parsePdbInfo(bytes);
  if (pdb) return [pdb];
  return parseElfDebugInfo(bytes);
}
