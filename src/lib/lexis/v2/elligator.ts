/**
 * T21: X25519 ephemeral keys whose public value is sent as an Elligator2
 * representative (32 bytes indistinguishable from uniform).
 *
 * - Keys are "dirty": pub = clamp(seed)*B + T with T a random point of order
 *   dividing 8, so the decoded point is not always in the prime-order subgroup
 *   (a clean X25519 key would be a distinguisher). The clamped scalar is a
 *   multiple of 8, so X25519 shared secrets are unchanged.
 * - Both inverse branches are used at random, so the forward map's square/non-
 *   square branch is balanced.
 * - The forward map is cross-checked against @noble/curves'
 *   RFC 9380 map_to_curve_elligator2_curve25519 in elligator.test.ts.
 */
import { ed25519, x25519 } from "@noble/curves/ed25519.js";

const Fp = ed25519.Point.Fp;
const p = Fp.ORDER;
const A = 486662n;
const N = ed25519.Point.Fn.ORDER;
const T8 = ed25519.Point.fromHex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a");
const HALF = (p - 1n) / 2n;

function leBytesToBig(b: Uint8Array): bigint {
  let x = 0n;
  for (let i = b.length - 1; i >= 0; i--) x = (x << 8n) | BigInt(b[i]);
  return x;
}

function bigToLe(x: bigint, len = 32): Uint8Array {
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

function isSquare(x: bigint): boolean {
  if (x === 0n) return true;
  return Fp.pow(x, HALF) === 1n;
}

function clampScalar(seed: Uint8Array): bigint {
  const s = seed.slice();
  s[0] &= 248;
  s[31] &= 127;
  s[31] |= 64;
  return leBytesToBig(s);
}

/** Representative (32 bytes, top two bits ignored) -> Montgomery u (32 bytes LE). */
export function elligatorMap(rep: Uint8Array): Uint8Array {
  const r = leBytesToBig(rep) & ((1n << 254n) - 1n);
  const den = Fp.add(1n, Fp.mul(2n, Fp.sqr(Fp.create(r))));
  const w = Fp.neg(Fp.mul(A, Fp.inv(den)));
  const fw = Fp.add(Fp.mul(Fp.sqr(w), Fp.add(w, A)), w);
  const u = isSquare(fw) ? w : Fp.sub(Fp.neg(w), A);
  return bigToLe(u);
}

export type EphemeralKey = { seed: Uint8Array; rep: Uint8Array; pub: Uint8Array };

function rand(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

/** Retry until the dirty public key is representable on a randomly chosen branch. */
export function elligatorKeyPair(): EphemeralKey {
  for (let tries = 0; tries < 256; tries++) {
    const seed = rand(32);
    const s = clampScalar(seed);
    const extra = rand(2);
    const k = BigInt(extra[0] & 7);
    let Pe = ed25519.Point.BASE.multiply(s % N);
    if (k > 0n) Pe = Pe.add(T8.multiplyUnsafe(k));
    const y = Pe.toAffine().y;
    if (y === 1n) continue;
    const u = Fp.mul(Fp.add(1n, y), Fp.inv(Fp.sub(1n, y)));
    if (u === 0n || u === Fp.neg(A)) continue;
    const branch = extra[1] & 1;
    const rad = branch
      ? Fp.neg(Fp.mul(u, Fp.inv(Fp.mul(2n, Fp.add(u, A)))))
      : Fp.neg(Fp.mul(Fp.add(u, A), Fp.inv(Fp.mul(2n, u))));
    if (!isSquare(rad)) continue;
    let r = Fp.sqrt(rad);
    if (r > HALF) r = p - r;
    const top = BigInt(extra[1] >> 6) << 254n;
    const rep = bigToLe(r | top);
    const pub = bigToLe(u);
    const check = elligatorMap(rep);
    if (!check.every((b, i) => b === pub[i])) continue;
    return { seed, rep, pub };
  }
  throw new Error("elligator key generation failed");
}

/** X25519 with our seed and the peer's representative. */
export function sharedFromRep(seed: Uint8Array, peerRep: Uint8Array): Uint8Array {
  return x25519.getSharedSecret(seed, elligatorMap(peerRep));
}

/** X25519 with our seed and a raw 32-byte peer public key (long-term or mapped). */
export function sharedFromPub(seed: Uint8Array, peerPub: Uint8Array): Uint8Array {
  return x25519.getSharedSecret(seed, peerPub);
}
