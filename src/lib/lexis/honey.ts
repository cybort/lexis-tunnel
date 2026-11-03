/**
 * One evaluation for every key. Programmed keys fall out of the polynomial;
 * nothing here compares a key against a list.
 */
import { x25519PublicKey } from "./native";
import { argon2id } from "@noble/hashes/argon2.js";
import { concat, randomBytes, u32be, utf8, b64, unb64 } from "./bytes";
import { hkdf, hmac, identityFromJwks, type KeyMaterial } from "./crypto";
import { clampVaultKdf, type ArgonParams } from "./kdf";
import { sessionLexicon } from "./lexicon";
import { SPEC } from "./spec";
import type { StoredProgram, StoredVault } from "./types";

const POLY = (1n << 128n) | 0x87n;
const MASK = (1n << 128n) - 1n;

export type HoneyProgram = {
  salt: Uint8Array;
  coeffs: Uint8Array[];
};

export type IdentityVault = {
  salt: Uint8Array;
  kdf: ArgonParams;
  lo: HoneyProgram;
  hi: HoneyProgram;
};

function bitLength(n: bigint): number {
  return n === 0n ? 1 : n.toString(2).length;
}

function add(a: bigint, b: bigint): bigint {
  return a ^ b;
}

function mul(a: bigint, b: bigint): bigint {
  let res = 0n;
  let x = a;
  let y = b;
  while (y > 0n) {
    if (y & 1n) res ^= x;
    x <<= 1n;
    if (x & (1n << 128n)) x ^= POLY;
    y >>= 1n;
  }
  return res & MASK;
}

function inv(a: bigint): bigint {
  if (a === 0n) throw new Error("零没有逆元");
  let u = a;
  let v = POLY;
  let g1 = 1n;
  let g2 = 0n;
  while (u !== 1n) {
    let j = bitLength(u) - bitLength(v);
    if (j < 0) {
      const su = u;
      u = v;
      v = su;
      const sg = g1;
      g1 = g2;
      g2 = sg;
      j = -j;
    }
    u ^= v << BigInt(j);
    g1 ^= g2 << BigInt(j);
  }
  return g1 & MASK;
}

function fromBytes(bytes: Uint8Array): bigint {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  return n & MASK;
}

function toBytes(n: bigint): Uint8Array {
  const out = new Uint8Array(16);
  let x = n & MASK;
  for (let i = 15; i >= 0; i -= 1) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

function xor16(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i += 1) out[i] = a[i] ^ b[i];
  return out;
}

function polyMul(p1: bigint[], p2: bigint[]): bigint[] {
  const res = Array<bigint>(p1.length + p2.length - 1).fill(0n);
  for (let i = 0; i < p1.length; i += 1) {
    if (p1[i] === 0n) continue;
    for (let j = 0; j < p2.length; j += 1) res[i + j] ^= mul(p1[i], p2[j]);
  }
  return res;
}

function horner(coeffs: bigint[], x: bigint): bigint {
  let result = 0n;
  for (let i = coeffs.length - 1; i >= 0; i -= 1) result = add(mul(result, x), coeffs[i]);
  return result;
}

function lagrange(points: Array<[bigint, bigint]>): bigint[] {
  const n = points.length;
  const final = Array<bigint>(n).fill(0n);
  for (let i = 0; i < n; i += 1) {
    const xi = points[i][0];
    const yi = points[i][1];
    let numerator: bigint[] = [1n];
    let denominator = 1n;
    for (let m = 0; m < n; m += 1) {
      if (i === m) continue;
      const xm = points[m][0];
      numerator = polyMul(numerator, [xm, 1n]);
      denominator = mul(denominator, xi ^ xm);
    }
    const scale = mul(yi, inv(denominator));
    for (let deg = 0; deg < numerator.length; deg += 1) final[deg] ^= mul(numerator[deg], scale);
  }
  return final;
}

async function lane(key: Uint8Array, salt: Uint8Array, label: string): Promise<Uint8Array> {
  const mac = await hmac(key, concat(salt, utf8(label)));
  return mac.subarray(0, 16);
}

export function indicesFrom(block: Uint8Array): [number, number, number, number] {
  const out = [0, 0, 0, 0] as [number, number, number, number];
  for (let i = 0; i < 4; i += 1) {
    const v = ((block[i * 2] << 8) | block[i * 2 + 1]) & 0xffff;
    out[i] = v % SPEC.lexiconSize;
  }
  return out;
}

export function packIndices(indices: [number, number, number, number]): Uint8Array {
  const out = new Uint8Array(16);
  for (let i = 0; i < 4; i += 1) {
    const n = indices[i] & 0xffff;
    out[i * 2] = (n >> 8) & 0xff;
    out[i * 2 + 1] = n & 0xff;
  }
  return out;
}

/** Coefficients only. The same Horner step serves every key. */
export async function compileBlocks(
  entries: { key: Uint8Array; block: Uint8Array }[],
  slots = 4,
  salt = randomBytes(16),
): Promise<HoneyProgram> {
  if (entries.length < 1 || entries.length > slots) throw new Error("可编程槽位数量不对");
  const points: Array<[bigint, bigint]> = [];
  const seen = new Set<string>();
  for (const entry of entries) {
    if (entry.block.length !== 16) throw new Error("可编程明文要 16 字节");
    const x = await lane(entry.key, salt, "x");
    const r = await lane(entry.key, salt, "r");
    const id = fromBytes(x).toString(16);
    if (seen.has(id)) throw new Error("横坐标撞上了");
    seen.add(id);
    points.push([fromBytes(x), fromBytes(xor16(entry.block, r))]);
  }
  while (points.length < slots) {
    const x = fromBytes(randomBytes(16));
    const id = x.toString(16);
    if (x === 0n || seen.has(id)) continue;
    seen.add(id);
    points.push([x, fromBytes(randomBytes(16))]);
  }
  const coeffs = lagrange(points).map(toBytes);
  return { salt, coeffs };
}

export async function evalHoney(program: HoneyProgram, key: Uint8Array): Promise<Uint8Array> {
  const x = await lane(key, program.salt, "x");
  const r = await lane(key, program.salt, "r");
  const y = horner(program.coeffs.map(fromBytes), fromBytes(x));
  return xor16(toBytes(y), r);
}

export async function honeyPhrase(
  key: Uint8Array,
  window: number,
  seed: Uint8Array,
  program?: HoneyProgram | null,
): Promise<string> {
  const lex = await sessionLexicon(key, window);
  const block = program
    ? await evalHoney(program, key)
    : await hkdf(key, u32be(window), seed.length ? seed : utf8("honey"), 16);
  const idx = indicesFrom(block);
  return `the ${lex[idx[0]]} and our ${lex[idx[1]]} that its ${lex[idx[2]]} and the ${lex[idx[3]]}`;
}

function b64url(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/g, "");
}

async function stretch(passphrase: string, salt: Uint8Array, params: ArgonParams): Promise<Uint8Array> {
  const c = clampVaultKdf(params);
  return argon2id(utf8(passphrase), salt, { t: c.iterations, m: c.memoryKiB, p: c.parallelism, dkLen: 32 });
}

/** Real passphrase and any programmed spare all sit in the same coefficients. */
export async function sealIdentityVault(
  entries: { passphrase: string; scalar: Uint8Array }[],
  salt: Uint8Array,
  params: ArgonParams,
  slots = 4,
): Promise<IdentityVault> {
  const c = clampVaultKdf(params);
  const seenPass = new Set<string>();
  for (const entry of entries) {
    if (seenPass.has(entry.passphrase)) throw new Error("口令重复，封不进同一条求值");
    seenPass.add(entry.passphrase);
  }
  for (;;) {
    const pepper = randomBytes(16);
    try {
      const loEntries: { key: Uint8Array; block: Uint8Array }[] = [];
      const hiEntries: { key: Uint8Array; block: Uint8Array }[] = [];
      for (const entry of entries) {
        if (entry.scalar.length !== 32) throw new Error("私钥标量要 32 字节");
        const dk = await stretch(entry.passphrase, salt, c);
        loEntries.push({ key: dk, block: entry.scalar.subarray(0, 16) });
        hiEntries.push({ key: dk, block: entry.scalar.subarray(16, 32) });
      }
      const lo = await compileBlocks(loEntries, slots, pepper);
      const hi = await compileBlocks(hiEntries, slots, pepper);
      return { salt, kdf: c, lo, hi };
    } catch (err) {
      if (err instanceof Error && err.message === "横坐标撞上了") continue;
      throw err;
    }
  }
}

/** Same steps for every passphrase. A spare one is not a separate branch. */
export async function openIdentityVault(vault: IdentityVault, passphrase: string): Promise<KeyMaterial> {
  const dk = await stretch(passphrase, vault.salt, vault.kdf);
  const lo = await evalHoney(vault.lo, dk);
  const hi = await evalHoney(vault.hi, dk);
  const joined = new Uint8Array(32);
  joined.set(lo, 0);
  joined.set(hi, 16);
  const seed = joined;
  const pub = x25519PublicKey(seed);
  const x = b64url(pub);
  const d = b64url(seed);
  return identityFromJwks(
    { kty: "OKP", crv: "X25519", x, ext: true },
    { kty: "OKP", crv: "X25519", x, d, ext: true },
  );
}

function unb64url(text: string): Uint8Array {
  const pad = text.length % 4 === 0 ? "" : "=".repeat(4 - (text.length % 4));
  return unb64(text.replaceAll("-", "+").replaceAll("_", "/") + pad);
}

/** Scalar bytes of an unlocked key. Absent after a sealed key is reloaded. */
export function freshScalar(): Uint8Array {
  // 3.0: identities are X25519; any 32 random bytes are a valid seed (clamped at use).
  return crypto.getRandomValues(new Uint8Array(32));
}

export function privateScalar(jwk: JsonWebKey): Uint8Array {
  if (!jwk.d) throw new Error("私钥不在内存里");
  const raw = unb64url(jwk.d);
  if (raw.length !== 32) throw new Error("私钥标量长度不对");
  return raw;
}

export function programToStored(program: HoneyProgram): StoredProgram {
  return { saltB64: b64(program.salt), coeffsB64: program.coeffs.map((item) => b64(item)) };
}

/** One shape for every stored program. Bad input is null, not a special key. */
export function programFromStored(raw: unknown): HoneyProgram | null {
  if (!raw || typeof raw !== "object") return null;
  const rec = raw as { saltB64?: unknown; coeffsB64?: unknown };
  if (typeof rec.saltB64 !== "string" || !Array.isArray(rec.coeffsB64) || rec.coeffsB64.length < 1 || rec.coeffsB64.length > 8) {
    return null;
  }
  try {
    const salt = unb64(rec.saltB64);
    if (salt.length !== 16) return null;
    const coeffs = rec.coeffsB64.map((item) => {
      if (typeof item !== "string") throw new Error("系数不对");
      const bytes = unb64(item);
      if (bytes.length !== 16) throw new Error("系数不对");
      return bytes;
    });
    return { salt, coeffs };
  } catch {
    return null;
  }
}

export function vaultToStored(vault: IdentityVault): StoredVault {
  return {
    saltB64: b64(vault.salt),
    memoryKiB: vault.kdf.memoryKiB,
    iterations: vault.kdf.iterations,
    parallelism: vault.kdf.parallelism,
    lo: programToStored(vault.lo),
    hi: programToStored(vault.hi),
  };
}

export function vaultFromStored(raw: unknown): IdentityVault | null {
  if (!raw || typeof raw !== "object") return null;
  const rec = raw as Partial<StoredVault>;
  if (typeof rec.saltB64 !== "string") return null;
  const lo = programFromStored(rec.lo);
  const hi = programFromStored(rec.hi);
  if (!lo || !hi) return null;
  try {
    const salt = unb64(rec.saltB64);
    if (salt.length < 8) return null;
    return {
      salt,
      kdf: clampVaultKdf({ memoryKiB: rec.memoryKiB, iterations: rec.iterations, parallelism: rec.parallelism }),
      lo,
      hi,
    };
  } catch {
    return null;
  }
}

export function blendBytes(real: Uint8Array, cover: Uint8Array, takeReal: number): Uint8Array {
  const m = takeReal & 1;
  const inv = 1 - m;
  const n = m * real.length + inv * cover.length;
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i += 1) {
    const a = i < real.length ? real[i] : 0;
    const b = i < cover.length ? cover[i] : 0;
    out[i] = (a * m + b * inv) & 0xff;
  }
  return out;
}
