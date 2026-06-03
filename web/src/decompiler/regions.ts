import type { ScanResult } from "../worker/protocol";
import type { DecompRegion, DecompFunction } from "./protocol";

export interface DecompInput {
  regions: DecompRegion[];
  symbols: [number, string][];
  readonly: [number, number][];
  strings: [number, number][];
  functions: DecompFunction[];
  entryPoint: number;
}

const MAX_FUNCTIONS = 5000;

export function symbolAddrBase(result: ScanResult): number {
  return result.formatClass === "PE" ? (result.memoryMap?.moduleAddress ?? 0) : 0;
}

export function buildDecompInput(result: ScanResult, fileBytes: ArrayBuffer): DecompInput {
  const fileSize = fileBytes.byteLength;
  const mm = result.memoryMap;

  const regions: DecompRegion[] = [];
  const seenRegion = new Set<string>();
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

  const base = symbolAddrBase(result);
  for (const s of result.symbols ?? []) {
    if (typeof s.address !== "number" || s.address <= 0 || !s.name) continue;
    const a = s.address + base;
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

  return { regions, symbols, readonly: [], strings: [], functions, entryPoint };
}
