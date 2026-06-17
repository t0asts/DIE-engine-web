import type { ScanResult } from "../worker/protocol";
import type { DecompRegion, DecompFunction } from "./protocol";
import { win32Prototypes } from "./prototypes";

export interface DecompInput {
  regions: DecompRegion[];
  symbols: [number, string][];
  imports: [number, string][];
  readonly: [number, number][];
  strings: [number, number][];
  widestrings: [number, number][];
  functions: DecompFunction[];
  prototypes: string;
  entryPoint: number;
}

const MAX_FUNCTIONS = 5000;

const WRITABLE_SECTION_RE = /^\.?(data|bss|sdata|sbss|tdata|tbss|got|toc)\b/i;

interface MappedRange {
  off: number;
  addr: number;
  size: number;
  name: string;
}

export function symbolAddrBase(result: ScanResult): number {
  return result.formatClass === "PE" ? (result.memoryMap?.moduleAddress ?? 0) : 0;
}

export function buildDecompInput(result: ScanResult, fileBytes: ArrayBuffer): DecompInput {
  const fileSize = fileBytes.byteLength;
  const mm = result.memoryMap;

  const regions: DecompRegion[] = [];
  const seenRegion = new Set<string>();
  const mapped: MappedRange[] = [];
  if (mm) {
    for (const r of mm.records) {
      if (r.isVirtual || r.offset < 0 || r.size <= 0) continue;
      if (r.offset >= fileSize) continue;
      const len = Math.min(r.size, fileSize - r.offset);
      if (len <= 0) continue;
      const key = `${r.address}:${r.offset}:${len}`;
      if (seenRegion.has(key)) continue;
      seenRegion.add(key);
      regions.push({ vaddr: r.address, bytes: fileBytes.slice(r.offset, r.offset + len) });
      mapped.push({ off: r.offset, addr: r.address, size: len, name: r.name });
    }
  }

  const symbols: [number, string][] = [];
  const seenSym = new Set<number>();
  const functions: DecompFunction[] = [];
  const seenFn = new Set<number>();

  const entryPoint = mm?.entryPoint ?? 0;
  if (entryPoint > 0) {
    functions.push({ addr: entryPoint, name: "entry", kind: "entry" });
    seenFn.add(entryPoint);
  }

  const isPE = result.formatClass === "PE";
  const imports: [number, string][] = [];
  const base = symbolAddrBase(result);
  for (const s of result.symbols ?? []) {
    if (typeof s.address !== "number" || s.address <= 0 || !s.name) continue;
    const a = s.address + base;
    if (isPE && s.kind === "import") {
      if (!seenSym.has(a)) {
        seenSym.add(a);
        imports.push([a, s.name]);
      }
      continue;
    }
    if (!seenSym.has(a)) {
      seenSym.add(a);
      symbols.push([a, s.name]);
    }
    if (s.kind !== "import" && !seenFn.has(a)) {
      if (functions.length >= MAX_FUNCTIONS) continue;
      seenFn.add(a);
      functions.push({ addr: a, name: s.demangled || s.name, kind: s.kind });
    }
  }

  functions.sort((a, b) => a.addr - b.addr);

  const strings: [number, number][] = [];
  const widestrings: [number, number][] = [];
  const readonly: [number, number][] = [];
  const seenStr = new Set<number>();
  const findRange = (off: number, len: number): MappedRange | undefined =>
    mapped.find((m) => off >= m.off && off + len <= m.off + m.size);
  for (const st of result.strings ?? []) {
    const wide = st.encoding === "utf16le";
    if ((!wide && st.encoding !== "ascii") || st.length <= 0) continue;
    const rec = findRange(st.offset, st.length);
    if (!rec) continue;
    const vaddr = rec.addr + (st.offset - rec.off);
    if (seenStr.has(vaddr)) continue;
    seenStr.add(vaddr);
    const charSize = wide ? 2 : 1;
    const elemCount = st.length / charSize + 1;
    (wide ? widestrings : strings).push([vaddr, elemCount]);
    if (!WRITABLE_SECTION_RE.test(rec.name)) readonly.push([vaddr, st.length + charSize]);
  }

  const prototypes = isPE ? win32Prototypes(is64Arch(mm?.arch ?? "", mm?.mode ?? "")) : "";

  return {
    regions, symbols, imports, readonly, strings, widestrings, functions, prototypes, entryPoint,
  };
}

const ARCH64_RE = /^(amd64|x86[-_]?64|aarch64|arm64|ia64|ppc64|riscv64|mips64)/i;

function is64Arch(arch: string, mode: string): boolean {
  if (mode.includes("64")) return true;
  return ARCH64_RE.test(arch.trim());
}
