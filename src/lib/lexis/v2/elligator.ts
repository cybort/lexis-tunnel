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

/* V3-4: Legendre symbol via the binary Jacobi algorithm (~13 µs) instead of Euler's
 * criterion x^((p-1)/2) (~115 µs). Same answer for every x mod p (p prime). Variable-time,
 * as the pow path already was for these public values (rep / dirty pub). */
function isSquare(x: bigint): boolean {
  let a = Fp.create(x);
  if (a === 0n) return true;
  let n = p;
  let r = 1;
  while (a !== 0n) {
    while ((a & 1n) === 0n) {
      a >>= 1n;
      const m = n & 7n;
      if (m === 3n || m === 5n) r = -r;
    }
    const t = a;
    a = n;
    n = t;
    if ((a & 3n) === 3n && (n & 3n) === 3n) r = -r;
    a %= n;
  }
  return n === 1n && r === 1;
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

/* V3-4 gate perf: native (OpenSSL) X25519 when running on Node; pure-JS @noble fallback elsewhere.
 * RFC 7748 X25519 on both paths (scalar clamped, top bit of u masked), so outputs are identical;
 * an all-zero (low-order) result throws on both paths. */
type NodeCrypto = typeof import("node:crypto");
const PKCS8 = Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20]);
const SPKI = Uint8Array.from([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00]);
const privCache = new Map<string, unknown>();
/** cacheKey: only for long-term (static) keys; ephemeral secrets are never kept. */
function nativeShared(c: NodeCrypto, seed: Uint8Array, u: Uint8Array, cacheKey = false): Uint8Array {
  const sk = cacheKey ? Buffer.from(seed.buffer, seed.byteOffset, seed.byteLength).toString("hex") : "";
  let priv = cacheKey ? (privCache.get(sk) as import("node:crypto").KeyObject | undefined) : undefined;
  if (!priv) {
    priv = c.createPrivateKey({ key: Buffer.concat([PKCS8, seed]), format: "der", type: "pkcs8" });
    if (cacheKey) {
      if (privCache.size >= 8) privCache.clear();
      privCache.set(sk, priv);
    }
  }
  const pub = c.createPublicKey({ key: Buffer.concat([SPKI, u]), format: "der", type: "spki" });
  const out = new Uint8Array(c.diffieHellman({ privateKey: priv, publicKey: pub }));
  if (out.every((b) => b === 0)) throw new Error("x25519 low-order");
  return out;
}
function nativeEphemeral(c: NodeCrypto, seed: Uint8Array): Uint8Array {
  const priv = c.createPrivateKey({ key: Buffer.concat([PKCS8, seed]), format: "der", type: "pkcs8" });
  const jwk = c.createPublicKey(priv).export({ format: "jwk" }) as { x: string };
  return new Uint8Array(Buffer.from(jwk.x, "base64url"));
}
const nodeCrypto: NodeCrypto | null = (() => {
  try {
    const g = (globalThis as { process?: { getBuiltinModule?: (m: string) => unknown } }).process;
    const c = g?.getBuiltinModule?.("node:crypto") as NodeCrypto | undefined;
    if (!c?.diffieHellman) return null;
    // self-test against noble once
    const s = new Uint8Array(32).fill(7);
    const u = x25519.getPublicKey(new Uint8Array(32).fill(9));
    const a = nativeShared(c, s, u);
    const b = x25519.getSharedSecret(s, u);
    return a.every((v, i) => v === b[i]) ? c : null;
  } catch {
    return null;
  }
})();
export const x25519Backend = nodeCrypto ? "node-openssl" : "noble";
export function x25519Shared(seed: Uint8Array, u: Uint8Array, staticKey = false): Uint8Array {
  return nodeCrypto ? nativeShared(nodeCrypto, seed, u, staticKey) : x25519.getSharedSecret(seed, u);
}
const T8M = [ed25519.Point.ZERO, ...Array.from({ length: 7 }, (_, i) => T8.multiplyUnsafe(BigInt(i + 1)))];

/** Edwards point for the X25519 public key of `seed`: clean u natively, then lift to Edwards (either
 * sign of x; u(-P + kT) = u(P - kT) = u(P + (8-k)T), so the dirty-u distribution over random k is
 * unchanged and X25519 results with the clamped scalar are unaffected). */
function cleanEdwards(seed: Uint8Array) {
  if (!nodeCrypto) return ed25519.Point.BASE.multiply(clampScalar(seed) % N);
  const u = leBytesToBig(nativeEphemeral(nodeCrypto, seed));
  const y = Fp.mul(Fp.sub(u, 1n), Fp.inv(Fp.add(u, 1n)));
  return ed25519.Point.fromBytes(bigToLe(y));
}

/** Retry until the dirty public key is representable on a randomly chosen branch. */
export function elligatorKeyPair(): EphemeralKey {
  for (let tries = 0; tries < 256; tries++) {
    const seed = rand(32);
    const extra = rand(2);
    const k = extra[0] & 7;
    let Pe = cleanEdwards(seed);
    if (k > 0) Pe = Pe.add(T8M[k]);
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
export function sharedFromRep(seed: Uint8Array, peerRep: Uint8Array, staticKey = false): Uint8Array {
  return x25519Shared(seed, elligatorMap(peerRep), staticKey);
}

/** X25519 with our seed and a raw 32-byte peer public key (long-term or mapped). */
export function sharedFromPub(seed: Uint8Array, peerPub: Uint8Array, staticKey = false): Uint8Array {
  return x25519Shared(seed, peerPub, staticKey);
}
