const MAXBITS = 15;
const WINDOW = 32768;

const LBASE = [3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258];
const LEXT  = [0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0];
const DBASE = [1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577];
const DEXT  = [0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13];
const CLORDER = [16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15];

interface Huff { count: Int32Array; symbol: Int32Array }

function buildHuff(lengths: Uint8Array, n: number): Huff {
  const count = new Int32Array(MAXBITS + 1);
  for (let i = 0; i < n; i++) { const l = lengths[i]!; count[l] = count[l]! + 1; }
  count[0] = 0;
  const offs = new Int32Array(MAXBITS + 1);
  for (let len = 1; len <= MAXBITS; len++) offs[len] = offs[len - 1]! + count[len - 1]!;
  const symbol = new Int32Array(n);
  for (let i = 0; i < n; i++) {
    const l = lengths[i]!;
    if (l) { symbol[offs[l]!] = i; offs[l] = offs[l]! + 1; }
  }
  return { count, symbol };
}

class BitReader {
  pos = 0;
  private buf = 0;
  private cnt = 0;
  constructor(readonly data: Uint8Array) {}
  bits(need: number): number {
    let val = this.buf;
    while (this.cnt < need) { val |= (this.data[this.pos++] ?? 0) << this.cnt; this.cnt += 8; }
    this.buf = val >>> need;
    this.cnt -= need;
    return val & ((1 << need) - 1);
  }
  decode(h: Huff): number {
    let code = 0, first = 0, index = 0;
    for (let len = 1; len <= MAXBITS; len++) {
      code |= this.bits(1);
      const count = h.count[len]!;
      if (code - count < first) return h.symbol[index + (code - first)]!;
      index += count;
      first = (first + count) << 1;
      code <<= 1;
    }
    return -1;
  }
  alignByte(): void { this.buf = 0; this.cnt = 0; }
  u16(): number { const v = (this.data[this.pos] ?? 0) | ((this.data[this.pos + 1] ?? 0) << 8); this.pos += 2; return v; }
}

const FIXED_LIT = (() => {
  const l = new Uint8Array(288);
  let i = 0;
  for (; i < 144; i++) l[i] = 8;
  for (; i < 256; i++) l[i] = 9;
  for (; i < 280; i++) l[i] = 7;
  for (; i < 288; i++) l[i] = 8;
  return buildHuff(l, 288);
})();
const FIXED_DIST = buildHuff(new Uint8Array(30).fill(5), 30);

function readDynamic(br: BitReader): { lit: Huff; dist: Huff } {
  const hlit = br.bits(5) + 257;
  const hdist = br.bits(5) + 1;
  const hclen = br.bits(4) + 4;
  const clcl = new Uint8Array(19);
  for (let i = 0; i < hclen; i++) clcl[CLORDER[i]!] = br.bits(3);
  const clHuff = buildHuff(clcl, 19);
  const lengths = new Uint8Array(hlit + hdist);
  let i = 0;
  while (i < hlit + hdist) {
    const sym = br.decode(clHuff);
    if (sym < 0) throw new Error("bad code-length symbol");
    if (sym < 16) lengths[i++] = sym;
    else if (sym === 16) { const r = 3 + br.bits(2); const prev = lengths[i - 1]!; for (let j = 0; j < r && i < lengths.length; j++) lengths[i++] = prev; }
    else if (sym === 17) { const r = 3 + br.bits(3); for (let j = 0; j < r && i < lengths.length; j++) lengths[i++] = 0; }
    else { const r = 11 + br.bits(7); for (let j = 0; j < r && i < lengths.length; j++) lengths[i++] = 0; }
  }
  return { lit: buildHuff(lengths.subarray(0, hlit), hlit), dist: buildHuff(lengths.subarray(hlit), hdist) };
}

function inflateBlock(br: BitReader, out: Uint8Array, posIn: number, lit: Huff, dist: Huff): number {
  let pos = posIn;
  for (;;) {
    const sym = br.decode(lit);
    if (sym < 0) throw new Error("bad literal/length code");
    if (sym === 256) return pos;
    if (sym < 256) { if (pos < out.length) out[pos] = sym; pos++; continue; }
    const s = sym - 257;
    if (s >= LBASE.length) throw new Error("bad length symbol");
    const length = LBASE[s]! + br.bits(LEXT[s]!);
    const dsym = br.decode(dist);
    if (dsym < 0 || dsym >= DBASE.length) throw new Error("bad distance code");
    const distance = DBASE[dsym]! + br.bits(DEXT[dsym]!);
    let from = pos - distance;
    if (from < 0) throw new Error("distance back-reference before window start");
    for (let i = 0; i < length; i++) { if (pos < out.length) out[pos] = out[from]!; pos++; from++; }
  }
}

export function inflateRaw(data: Uint8Array, outSize: number, dict?: Uint8Array): Uint8Array<ArrayBuffer> {
  const dictLen = dict ? Math.min(dict.length, WINDOW) : 0;
  const out = new Uint8Array(dictLen + outSize);
  if (dict && dictLen) out.set(dict.subarray(dict.length - dictLen), 0);

  const br = new BitReader(data);
  let pos = dictLen;
  let last = 0;
  do {
    last = br.bits(1);
    const type = br.bits(2);
    if (type === 0) {
      br.alignByte();
      const len = br.u16();
      br.u16();
      for (let i = 0; i < len; i++) { if (pos < out.length) out[pos] = br.data[br.pos] ?? 0; pos++; br.pos++; }
    } else if (type === 1) {
      pos = inflateBlock(br, out, pos, FIXED_LIT, FIXED_DIST);
    } else if (type === 2) {
      const { lit, dist } = readDynamic(br);
      pos = inflateBlock(br, out, pos, lit, dist);
    } else {
      throw new Error("invalid deflate block type");
    }
  } while (!last && pos < out.length);

  return out.subarray(dictLen, dictLen + outSize) as Uint8Array<ArrayBuffer>;
}
