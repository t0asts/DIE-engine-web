
import type { StringEntry } from "./protocol";

export interface StringsScanOptions {
  minLen?: number;       
  maxResults?: number;   
  scanUtf16?: boolean;   
}

export function scanStrings(bytes: Uint8Array, opts: StringsScanOptions = {}): StringEntry[] {
  const minLen = opts.minLen ?? 4;
  const maxResults = opts.maxResults ?? 50_000;
  const scanUtf16 = opts.scanUtf16 ?? true;

  const out: StringEntry[] = [];

  let start = -1;
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i]!;
    const printable =
      (b >= 0x20 && b < 0x7f) || b === 0x09  || b === 0x0a  || b === 0x0d ;
    if (printable) {
      if (start < 0) start = i;
    } else {
      if (start >= 0 && i - start >= minLen) {
        out.push({
          offset: start,
          length: i - start,
          encoding: "ascii",
          text: utf8DecodeRange(bytes, start, i),
        });
        if (out.length >= maxResults) return out;
      }
      start = -1;
    }
  }
  if (start >= 0 && bytes.length - start >= minLen) {
    out.push({
      offset: start,
      length: bytes.length - start,
      encoding: "ascii",
      text: utf8DecodeRange(bytes, start, bytes.length),
    });
  }
  if (out.length >= maxResults) return out;

  if (scanUtf16) {
    let s = -1;
    for (let i = 0; i + 1 < bytes.length; i += 2) {
      const b0 = bytes[i]!;
      const b1 = bytes[i + 1]!;
      const printable = b1 === 0 && ((b0 >= 0x20 && b0 < 0x7f) || b0 === 0x09 || b0 === 0x0a || b0 === 0x0d);
      if (printable) {
        if (s < 0) s = i;
      } else {
        if (s >= 0) {
          const charCount = (i - s) / 2;
          if (charCount >= minLen) {
            out.push({
              offset: s,
              length: i - s,
              encoding: "utf16le",
              text: utf16leDecodeRange(bytes, s, i),
            });
            if (out.length >= maxResults) return out;
          }
        }
        s = -1;
      }
    }
  }

  return out;
}

function utf8DecodeRange(bytes: Uint8Array, from: number, to: number): string {
  return new TextDecoder("utf-8", { fatal: false }).decode(bytes.subarray(from, to));
}

function utf16leDecodeRange(bytes: Uint8Array, from: number, to: number): string {
  const sliceCopy = bytes.slice(from, to);
  return new TextDecoder("utf-16le", { fatal: false }).decode(sliceCopy);
}
