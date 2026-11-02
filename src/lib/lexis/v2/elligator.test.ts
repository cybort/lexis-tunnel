import assert from "node:assert/strict";
import { _map_to_curve_elligator2_curve25519, ed25519, x25519 } from "@noble/curves/ed25519.js";
import { elligatorKeyPair, elligatorMap, sharedFromRep } from "./elligator";

const Fp = ed25519.Point.Fp;
const le = (b: Uint8Array) => { let x = 0n; for (let i = b.length - 1; i >= 0; i--) x = (x << 8n) | BigInt(b[i]); return x; };
// Forward map equals RFC 9380 map_to_curve_elligator2_curve25519 (noble) on random inputs.
for (let i = 0; i < 300; i++) {
  const rep = crypto.getRandomValues(new Uint8Array(32));
  const r = le(rep) & ((1n << 254n) - 1n);
  const { xMn, xMd } = _map_to_curve_elligator2_curve25519(Fp.create(r)) as { xMn: bigint; xMd: bigint };
  assert.equal(le(elligatorMap(rep)), Fp.div(xMn, xMd), "forward map matches RFC 9380");
}
let lowOrder = 0;
for (let i = 0; i < 200; i++) {
  const a = elligatorKeyPair();
  const b = elligatorKeyPair();
  assert.deepEqual(sharedFromRep(a.seed, b.rep), sharedFromRep(b.seed, a.rep), "DH agrees");
  assert.deepEqual(sharedFromRep(a.seed, b.rep), x25519.getSharedSecret(a.seed, x25519.getPublicKey(b.seed)), "dirty key gives the clean DH");
  if (!ed25519.Point.fromAffine({ x: 0n, y: 1n }).equals(ed25519.Point.ZERO)) throw new Error("noble API");
  lowOrder += le(a.pub) === le(x25519.getPublicKey(a.seed)) ? 0 : 1;
}
console.log(`elligator ok: forward map = RFC 9380 (300), DH agree (200), dirty keys ${lowOrder}/200 differ from clean pub`);
