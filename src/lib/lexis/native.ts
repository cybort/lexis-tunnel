/**
 * fix/gate-alloc: native (OpenSSL via node:crypto) X25519 public-key derivation and AES-256
 * (CTR keystream, raw block encrypt/decrypt), with the @noble pure-JS code as fallback where
 * node:crypto is unavailable (browser). Each native path is self-tested against noble once
 * at load; on any mismatch the noble path is used. Outputs are byte-identical (RFC 7748 X25519,
 * FIPS-197 AES, SP 800-38A CTR with a 128-bit big-endian counter); see native.test.ts.
 */
import { x25519 } from "@noble/curves/ed25519.js";
import { ctr, unsafe } from "@noble/ciphers/aes.js";

type NodeCrypto = typeof import("node:crypto");
const PKCS8 = Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20]);

function getNode(): NodeCrypto | null {
  try {
    const g = (globalThis as { process?: { getBuiltinModule?: (m: string) => unknown } }).process;
    const c = g?.getBuiltinModule?.("node:crypto") as NodeCrypto | undefined;
    if (!c || typeof c.createCipheriv !== "function" || typeof c.createPrivateKey !== "function") return null;
    return c;
  } catch {
    return null;
  }
}
const node = getNode();
const eq = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((v, i) => v === b[i]);

function nodeX25519Pub(c: NodeCrypto, seed: Uint8Array): Uint8Array {
  const priv = c.createPrivateKey({ key: Buffer.concat([PKCS8, seed]), format: "der", type: "pkcs8" });
  const spki = c.createPublicKey(priv).export({ format: "der", type: "spki" });
  return new Uint8Array(spki.subarray(spki.length - 32));
}
function nodeCtr(c: NodeCrypto, key: Uint8Array, nonce: Uint8Array, len: number): Uint8Array {
  const ci = c.createCipheriv("aes-256-ctr", key, nonce);
  const out = ci.update(new Uint8Array(len));
  ci.final();
  return new Uint8Array(out.buffer, out.byteOffset, out.byteLength);
}

const useNodeX = (() => {
  if (!node) return false;
  try {
    const s = new Uint8Array(32).map((_, i) => i * 7 + 1);
    return eq(nodeX25519Pub(node, s), x25519.getPublicKey(s));
  } catch {
    return false;
  }
})();
const useNodeAes = (() => {
  if (!node) return false;
  try {
    const k = new Uint8Array(32).map((_, i) => i * 13 + 5);
    const n = new Uint8Array(16).fill(0xff); // exercises the full 128-bit counter carry
    return eq(nodeCtr(node, k, n, 100), ctr(k, n).encrypt(new Uint8Array(100)));
  } catch {
    return false;
  }
})();
export const nativeBackend = { x25519: useNodeX ? "node-openssl" : "noble", aes: useNodeAes ? "node-openssl" : "noble" };

/** RFC 7748 X25519(seed, 9): public key for a 32-byte secret (clamped internally). */
export function x25519PublicKey(seed: Uint8Array): Uint8Array {
  if (seed.length !== 32) throw new Error("x25519 seed must be 32 bytes");
  return useNodeX ? nodeX25519Pub(node!, seed) : x25519.getPublicKey(seed);
}

/** AES-256-CTR keystream of `len` bytes starting at counter block `nonce` (16 bytes, big-endian increment). */
export function aesCtrKeystream(key: Uint8Array, nonce: Uint8Array, len: number): Uint8Array {
  return useNodeAes ? nodeCtr(node!, key, nonce, len) : ctr(key, nonce).encrypt(new Uint8Array(len));
}

export type AesBlock = { enc(b: Uint8Array): Uint8Array; dec(b: Uint8Array): Uint8Array };

/** Raw AES-256 block cipher (ECB on whole blocks, no padding). Input length must be a multiple of 16. */
export function aes256Block(key: Uint8Array): AesBlock {
  if (key.length !== 32) throw new Error("AES-256 needs a 32-byte key");
  if (useNodeAes) {
    const c = node!;
    const e = c.createCipheriv("aes-256-ecb", key, null).setAutoPadding(false);
    const d = c.createDecipheriv("aes-256-ecb", key, null).setAutoPadding(false);
    const run = (x: { update(data: Uint8Array): Uint8Array<ArrayBufferLike> }, b: Uint8Array) => {
      if (b.length % 16) throw new Error("AES block input must be whole blocks");
      const o = x.update(b);
      return new Uint8Array(o.buffer, o.byteOffset, o.byteLength);
    };
    return { enc: (b) => run(e, b), dec: (b) => run(d, b) };
  }
  const ek = unsafe.expandKeyLE(key);
  const dk = unsafe.expandKeyDecLE(key);
  const each = (b: Uint8Array, f: (k: Uint32Array, x: Uint8Array) => Uint8Array, k: Uint32Array) => {
    if (b.length % 16) throw new Error("AES block input must be whole blocks");
    const out = new Uint8Array(b.length);
    for (let o = 0; o < b.length; o += 16) out.set(f(k, b.slice(o, o + 16)), o);
    return out;
  };
  return { enc: (b) => each(b, unsafe.encryptBlock, ek), dec: (b) => each(b, unsafe.decryptBlock, dk) };
}
