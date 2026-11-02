import assert from "node:assert/strict";
import { x25519, ed25519 } from "@noble/curves/ed25519.js";
import { elligatorKeyPair, elligatorMap, x25519Backend, x25519Shared } from "./elligator.ts";
assert.equal(x25519Backend, "node-openssl");
for (let i = 0; i < 300; i++) {
  const s = crypto.getRandomValues(new Uint8Array(32)), u = crypto.getRandomValues(new Uint8Array(32));
  let a: Uint8Array | string, b: Uint8Array | string;
  try { a = x25519Shared(s, u); } catch { a = "err"; }
  try { b = x25519.getSharedSecret(s, u); } catch { b = "err"; }
  assert.deepEqual(a, b);
}
// dirty ephemerals: map(rep)==pub, DH agrees with noble both ways, torsion spread over all 8 classes
const L = ed25519.Point.Fn.ORDER; const cls = new Set<string>();
for (let i = 0; i < 300; i++) {
  const e = elligatorKeyPair(); const peer = crypto.getRandomValues(new Uint8Array(32));
  assert.deepEqual(elligatorMap(e.rep), e.pub);
  assert.deepEqual(x25519Shared(peer, e.pub), x25519.getSharedSecret(peer, e.pub));
  assert.deepEqual(x25519Shared(e.seed, x25519.getPublicKey(peer)), x25519.getSharedSecret(peer, x25519.getPublicKey(e.seed)));
  const yb = (() => { const u = BigInt("0x" + Buffer.from(e.pub).reverse().toString("hex")); const p = ed25519.Point.Fp; return p.mul(p.sub(u, 1n), p.inv(p.add(u, 1n))); })();
  const y = new Uint8Array(32); let t = yb; for (let j = 0; j < 32; j++) { y[j] = Number(t & 255n); t >>= 8n; }
  { const P = ed25519.Point.fromBytes(y); const Q = P.multiplyUnsafe(L - 1n).add(P); cls.add(Q.is0() ? "0" : Q.toAffine().y.toString() + Q.negate().toAffine().y); }
}
assert.equal(cls.size, 5); assert.ok(cls.size >= 5, "torsion classes " + cls.size);
console.log("x25519-native ok: 300 random u match noble (incl. errors), 300 dirty ephemerals consistent, torsion classes (u-visible, k~8-k)", cls.size);
