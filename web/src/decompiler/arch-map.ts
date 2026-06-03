import type { ScanResult } from "../worker/protocol";

export interface DecompArch {
  languageId: string;
  arch: string;
  label: string;
}
const MANAGED_RE = /\.net\b|\bmono\b|\bmsil\b|common language runtime|(?:^|[^a-z0-9])(?:c#|f#|vb\.net)/i;

function isManagedAssembly(result: ScanResult): boolean {
  return result.records.some((r) =>
    MANAGED_RE.test(`${r.type} ${r.name} ${r.version ?? ""} ${r.language ?? ""}`));
}

export function archForDecompile(result: ScanResult): DecompArch | null {
  const mm = result.memoryMap;
  if (!mm) return null;

  if (isManagedAssembly(result)) return null;

  const a = (mm.arch ?? "").toUpperCase().trim();
  const endian = mm.endian === "big" ? "BE" : "LE";
  const isPE = result.formatClass === "PE";

  if (a === "386" || a === "I386" || a === "X86") {
    const compiler = isPE ? "windows" : "gcc";
    return { languageId: `x86:LE:32:default:${compiler}`, arch: "x86", label: "x86 (32-bit)" };
  }
  if (a === "AMD64" || a === "X86_64" || a === "X86-64") {
    const compiler = isPE ? "windows" : "gcc";
    return { languageId: `x86:LE:64:default:${compiler}`, arch: "x86", label: "x86-64" };
  }

  if (a.startsWith("AARCH64") || a.startsWith("ARM64")) {
    const compiler = isPE ? "windows" : "default";
    return {
      languageId: `AARCH64:${endian}:64:v8A:${compiler}`,
      arch: "AARCH64",
      label: "AArch64",
    };
  }

  if (a.startsWith("ARM") || a.startsWith("THUMB")) {
    const compiler = isPE ? "windows" : "default";
    return {
      languageId: `ARM:${endian}:32:v7:${compiler}`,
      arch: "ARM",
      label: "ARM (32-bit)",
    };
  }

  return null;
}
