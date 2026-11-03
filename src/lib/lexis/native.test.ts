/** fix/gate-alloc: native (node:crypto) vs @noble reference — RFC 7748 X25519, FIPS-197 AES-256,
 * SP 800-38A CTR-AES256 vectors, then randomized differential tests against noble. */
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { x25519 } from "@noble/curves/ed25519.js";
import { ctr, unsafe } from "@noble/ciphers/aes.js";
import { aes256Block, aesCtrKeystream, nativeBackend, x25519PublicKey } from "./native";
import { x25519Shared, x25519Backend } from "./v2/elligator";

const h = (s: string) => Uint8Array.from(Buffer.from(s.replace(/\s+/g, ""), "hex"));
const hx = (u: Uint8Array) => Buffer.from(u).toString("hex");
assert.equal(nativeBackend.x25519, "node-openssl");
assert.equal(nativeBackend.aes, "node-openssl");
assert.equal(x25519Backend, "node-openssl");

// RFC 7748 §5.2 X25519 function vectors (shared-secret path)
assert.equal(hx(x25519Shared(h("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"), h("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"))), "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
assert.equal(hx(x25519Shared(h("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"), h("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493"))), "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");
// RFC 7748 §5.2 iterated, 1 and 1000 iterations (public-key path for k with u=9, then shared)
{
  let k = h("09".padEnd(64, "0"));
  let u = k;
  for (let i = 1; i <= 1000; i++) {
    const nk = new Uint8Array(x25519Shared(k, u));
    u = k;
    k = nk;
    if (i === 1) assert.equal(hx(k), "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079");
  }
  assert.equal(hx(k), "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51");
}
// RFC 7748 §6.1 Diffie-Hellman
const aPriv = h("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
const bPriv = h("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
assert.equal(hx(x25519PublicKey(aPriv)), "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
assert.equal(hx(x25519PublicKey(bPriv)), "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
assert.equal(hx(x25519Shared(aPriv, x25519PublicKey(bPriv))), "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
assert.equal(hx(x25519Shared(bPriv, x25519PublicKey(aPriv), true)), "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

// FIPS-197 Appendix C.3 AES-256
const fk = h("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
assert.equal(hx(aes256Block(fk).enc(h("00112233445566778899aabbccddeeff"))), "8ea2b7ca516745bfeafc49904b496089");
assert.equal(hx(aes256Block(fk).dec(h("8ea2b7ca516745bfeafc49904b496089"))), "00112233445566778899aabbccddeeff");
// SP 800-38A F.5.5 CTR-AES256.Encrypt
{
  const key = h("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
  const pt = h("6bc1bee22e409f96e93d7e117393172a ae2d8a571e03ac9c9eb76fac45af8e51 30c81c46a35ce411e5fbc1191a0a52ef f69f2445df4f9b17ad2b417be66c3710");
  const ks = aesCtrKeystream(key, h("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"), pt.length);
  assert.equal(hx(pt.map((b, i) => b ^ ks[i])), "601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c52b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6");
}

// Randomized differential tests vs noble
const N = +(process.env.NATIVE_FUZZ || 3000);
for (let i = 0; i < N; i++) {
  const s = new Uint8Array(randomBytes(32));
  assert.equal(hx(x25519PublicKey(s)), hx(x25519.getPublicKey(s)), `pub ${hx(s)}`);
  const u = i % 3 === 0 ? new Uint8Array(randomBytes(32)) : x25519.getPublicKey(new Uint8Array(randomBytes(32)));
  let a = "", b = "";
  try { a = hx(x25519Shared(s, u, i % 5 === 0)); } catch (e) { a = "throw"; }
  try { const r = x25519.getSharedSecret(s, u); b = r.every((v) => v === 0) ? "throw" : hx(r); } catch { b = "throw"; }
  assert.equal(a, b, `shared ${hx(s)} ${hx(u)}`);
  const key = new Uint8Array(randomBytes(32));
  const nonce = new Uint8Array(randomBytes(16));
  if (i % 7 === 0) nonce.fill(0xff, 8); // counter carry across 64-bit boundary
  const len = 1 + (i * 131) % 5000;
  assert.equal(hx(aesCtrKeystream(key, nonce, len)), hx(ctr(key, nonce).encrypt(new Uint8Array(len))), `ctr ${i}`);
  const blocks = new Uint8Array(randomBytes(16 * (1 + (i % 9))));
  const blk = aes256Block(key);
  const ek = unsafe.expandKeyLE(key), dk = unsafe.expandKeyDecLE(key);
  const ref = new Uint8Array(blocks.length), refD = new Uint8Array(blocks.length);
  for (let o = 0; o < blocks.length; o += 16) {
    ref.set(unsafe.encryptBlock(ek, blocks.slice(o, o + 16)), o);
    refD.set(unsafe.decryptBlock(dk, blocks.slice(o, o + 16)), o);
  }
  assert.equal(hx(blk.enc(blocks)), hx(ref), `ecb enc ${i}`);
  assert.equal(hx(blk.dec(blocks)), hx(refD), `ecb dec ${i}`);
}
console.log(`native ok: RFC 7748 (5.2 x2, iter 1/1000, 6.1), FIPS-197 C.3, SP800-38A F.5.5, ${N} random x25519/CTR/ECB vs noble`);
