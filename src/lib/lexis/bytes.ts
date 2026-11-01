export function concat(...parts: Uint8Array[]): Uint8Array {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

export function fromUtf8(b: Uint8Array): string {
  return new TextDecoder("utf-8", { fatal: false }).decode(b);
}

export function u16be(n: number): Uint8Array {
  return new Uint8Array([(n >> 8) & 0xff, n & 0xff]);
}

export function u32be(n: number): Uint8Array {
  return new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}

export function readU16(b: Uint8Array, o: number): number {
  return ((b[o] << 8) | b[o + 1]) >>> 0;
}

export function readU32(b: Uint8Array, o: number): number {
  return ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;
}

export function hex(b: Uint8Array, max?: number): string {
  const v = max === undefined ? b : b.subarray(0, max);
  let s = "";
  for (let i = 0; i < v.length; i++) s += v[i].toString(16).padStart(2, "0");
  return s;
}

export function b64(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
  return btoa(s);
}

export function unb64(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

export function isPrintableText(b: Uint8Array): boolean {
  for (let i = 0; i < b.length; i++) {
    const c = b[i];
    if (c !== 9 && c !== 10 && c !== 13 && (c < 32 || c > 126)) return false;
  }
  return true;
}

/** 12-bit big-endian groups. A short tail is padded with zero bits. */
export function bytesToChunks(data: Uint8Array): number[] {
  const out: number[] = [];
  let acc = 0;
  let bits = 0;
  for (let i = 0; i < data.length; i++) {
    acc = (acc << 8) | data[i];
    bits += 8;
    while (bits >= 12) {
      bits -= 12;
      out.push((acc >> bits) & 0xfff);
      acc &= (1 << bits) - 1;
    }
  }
  if (bits > 0) out.push((acc << (12 - bits)) & 0xfff);
  return out;
}

/** Inverse of bytesToChunks. Trailing partial-byte padding is left for the caller to trim. */
export function chunksToBytes(chunks: number[]): Uint8Array {
  const tmp: number[] = [];
  let acc = 0;
  let bits = 0;
  for (let i = 0; i < chunks.length; i++) {
    acc = (acc << 12) | (chunks[i] & 0xfff);
    bits += 12;
    while (bits >= 8) {
      bits -= 8;
      tmp.push((acc >> bits) & 0xff);
      acc &= (1 << bits) - 1;
    }
  }
  return new Uint8Array(tmp);
}
