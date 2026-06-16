export type DecryptResult = { data: Uint8Array<ArrayBuffer> } | { error: string };

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) c = c & 1 ? (0xedb88320 ^ (c >>> 1)) >>> 0 : c >>> 1;
    t[i] = c >>> 0;
  }
  return t;
})();
const crc32upd = (crc: number, b: number) => (CRC_TABLE[(crc ^ b) & 0xff]! ^ (crc >>> 8)) >>> 0;

class ZipCryptoKeys {
  k0 = 0x12345678;
  k1 = 0x23456789;
  k2 = 0x34567890;
  update(b: number): void {
    this.k0 = crc32upd(this.k0, b);
    this.k1 = (this.k1 + (this.k0 & 0xff)) >>> 0;
    this.k1 = (Math.imul(this.k1, 134775813) + 1) >>> 0;
    this.k2 = crc32upd(this.k2, (this.k1 >>> 24) & 0xff);
  }
  decryptByte(): number {
    const t = (this.k2 | 2) & 0xffff;
    return ((t * (t ^ 1)) >>> 8) & 0xff;
  }
}

export function zipCryptoDecrypt(data: Uint8Array, password: string, checkByte: number): DecryptResult {
  if (data.length < 12) return { error: "encrypted data too short" };
  const keys = new ZipCryptoKeys();
  for (const b of new TextEncoder().encode(password)) keys.update(b);

  let last = 0;
  for (let i = 0; i < 12; i++) {
    last = (data[i]! ^ keys.decryptByte()) & 0xff;
    keys.update(last);
  }
  if (last !== (checkByte & 0xff)) return { error: "wrong password" };

  const out = new Uint8Array(data.length - 12);
  for (let i = 12; i < data.length; i++) {
    const c = (data[i]! ^ keys.decryptByte()) & 0xff;
    keys.update(c);
    out[i - 12] = c;
  }
  return { data: out };
}

const SBOX = (() => {
  const s = new Uint8Array(256);
  let p = 1, q = 1;
  const rotl8 = (x: number, n: number) => ((x << n) | (x >>> (8 - n))) & 0xff;
  do {
    p = (p ^ (p << 1) ^ (p & 0x80 ? 0x1b : 0)) & 0xff;
    q = (q ^ (q << 1)) & 0xff;
    q = (q ^ (q << 2)) & 0xff;
    q = (q ^ (q << 4)) & 0xff;
    q = (q ^ (q & 0x80 ? 0x09 : 0)) & 0xff;
    s[p] = (q ^ rotl8(q, 1) ^ rotl8(q, 2) ^ rotl8(q, 3) ^ rotl8(q, 4) ^ 0x63) & 0xff;
  } while (p !== 1);
  s[0] = 0x63;
  return s;
})();

const RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d];

const xtime = (a: number) => ((a << 1) ^ (a & 0x80 ? 0x1b : 0)) & 0xff;

function keyExpansion(key: Uint8Array): { rk: Uint8Array; Nr: number } {
  const Nk = key.length / 4;
  const Nr = Nk + 6;
  const words = 4 * (Nr + 1);
  const rk = new Uint8Array(words * 4);
  rk.set(key, 0);
  for (let i = Nk; i < words; i++) {
    let t0 = rk[(i - 1) * 4]!, t1 = rk[(i - 1) * 4 + 1]!, t2 = rk[(i - 1) * 4 + 2]!, t3 = rk[(i - 1) * 4 + 3]!;
    if (i % Nk === 0) {
      const u0 = t0;
      t0 = (SBOX[t1]! ^ RCON[i / Nk - 1]!) & 0xff;
      t1 = SBOX[t2]!;
      t2 = SBOX[t3]!;
      t3 = SBOX[u0]!;
    } else if (Nk > 6 && i % Nk === 4) {
      t0 = SBOX[t0]!; t1 = SBOX[t1]!; t2 = SBOX[t2]!; t3 = SBOX[t3]!;
    }
    rk[i * 4] = rk[(i - Nk) * 4]! ^ t0;
    rk[i * 4 + 1] = rk[(i - Nk) * 4 + 1]! ^ t1;
    rk[i * 4 + 2] = rk[(i - Nk) * 4 + 2]! ^ t2;
    rk[i * 4 + 3] = rk[(i - Nk) * 4 + 3]! ^ t3;
  }
  return { rk, Nr };
}

function encryptBlock(rk: Uint8Array, Nr: number, block: Uint8Array): void {
  const s = block;
  for (let i = 0; i < 16; i++) s[i] = s[i]! ^ rk[i]!;
  for (let round = 1; round < Nr; round++) {
    for (let i = 0; i < 16; i++) s[i] = SBOX[s[i]!]!;
    shiftRows(s);
    mixColumns(s);
    for (let i = 0; i < 16; i++) s[i] = s[i]! ^ rk[round * 16 + i]!;
  }
  for (let i = 0; i < 16; i++) s[i] = SBOX[s[i]!]!;
  shiftRows(s);
  for (let i = 0; i < 16; i++) s[i] = s[i]! ^ rk[Nr * 16 + i]!;
}

function shiftRows(s: Uint8Array): void {
  let t = s[1]!; s[1] = s[5]!; s[5] = s[9]!; s[9] = s[13]!; s[13] = t;
  t = s[2]!; s[2] = s[10]!; s[10] = t; t = s[6]!; s[6] = s[14]!; s[14] = t;
  t = s[15]!; s[15] = s[11]!; s[11] = s[7]!; s[7] = s[3]!; s[3] = t;
}

function mixColumns(s: Uint8Array): void {
  for (let c = 0; c < 4; c++) {
    const i = 4 * c;
    const a0 = s[i]!, a1 = s[i + 1]!, a2 = s[i + 2]!, a3 = s[i + 3]!;
    s[i] = xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3;
    s[i + 1] = a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3;
    s[i + 2] = a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3);
    s[i + 3] = (xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3);
  }
}

function aesCtrLeXor(key: Uint8Array, data: Uint8Array): Uint8Array<ArrayBuffer> {
  const { rk, Nr } = keyExpansion(key);
  const ctr = new Uint8Array(16);
  ctr[0] = 1;
  const ks = new Uint8Array(16);
  const out = new Uint8Array(data.length);
  let pos = 16;
  for (let i = 0; i < data.length; i++) {
    if (pos === 16) {
      ks.set(ctr);
      encryptBlock(rk, Nr, ks);
      for (let j = 0; j < 16; j++) { ctr[j] = (ctr[j]! + 1) & 0xff; if (ctr[j] !== 0) break; }
      pos = 0;
    }
    out[i] = data[i]! ^ ks[pos++]!;
  }
  return out;
}

export type AesStrength = 1 | 2 | 3;

const SALT_LEN: Record<AesStrength, number> = { 1: 8, 2: 12, 3: 16 };
const KEY_LEN: Record<AesStrength, number> = { 1: 16, 2: 24, 3: 32 };

export async function winZipAesDecrypt(
  data: Uint8Array, password: string, strength: AesStrength,
): Promise<DecryptResult> {
  const saltLen = SALT_LEN[strength];
  const keyLen = KEY_LEN[strength];
  if (data.length < saltLen + 2 + 10) return { error: "AES data too short" };

  const salt = data.slice(0, saltLen);
  const pwVerify = data.subarray(saltLen, saltLen + 2);
  const ct = data.slice(saltLen + 2, data.length - 10);
  const authCode = data.subarray(data.length - 10);

  const baseKey = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const total = keyLen * 2 + 2;
  const derived = new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: "PBKDF2", salt, iterations: 1000, hash: "SHA-1" }, baseKey, total * 8));

  const encKey = derived.slice(0, keyLen);
  const authKey = derived.slice(keyLen, keyLen * 2);
  if (derived[total - 2] !== pwVerify[0] || derived[total - 1] !== pwVerify[1]) {
    return { error: "wrong password" };
  }

  const hmacKey = await crypto.subtle.importKey(
    "raw", authKey, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", hmacKey, ct));
  for (let i = 0; i < 10; i++) {
    if (mac[i] !== authCode[i]) return { error: "authentication failed (wrong password or corrupt data)" };
  }

  return { data: aesCtrLeXor(encKey, ct) };
}

export const _internal = { keyExpansion, encryptBlock };
