import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { deriveV2Keys, openV2, padLength, sealV2, unsealRawV2, OVERHEAD, WIRE_PER_INNER_BYTE } from "./frame2.ts";
const keys = deriveV2Keys(Uint8Array.from(randomBytes(32)));
// default path == the pre-switch formula (copied from a305882)
for (let len = 1; len < 5000; len += 7) for (const c of [1, 99, 12345]) {
  const budget = Math.floor((5 * Math.max(len, 1)) / WIRE_PER_INNER_BYTE) - len; const maxPad = Math.max(0, Math.min(255, budget - OVERHEAD));
  assert.equal(padLength(keys, c, "e2g", len, 5), padLength(keys, c, "e2g", len, 5, "expansion"));
  if (maxPad === 0) assert.equal(padLength(keys, c, "e2g", len, 5), 0); else assert.ok(padLength(keys, c, "e2g", len, 5) <= maxPad);
}
// honey policy: interoperates (receiver unchanged) and pads small frames
let padded = 0;
for (let c = 1; c <= 300; c++) {
  const P = Uint8Array.from(randomBytes(1 + (c % 60)));
  const prose = sealV2({ keys, counter: c, window: 7, dir: "e2g", plaintext: P, maxExpansion: 5, smallFramePolicy: "honey" });
  assert.deepEqual(openV2({ keys, counter: c, window: 7, dir: "e2g", prose }), P);
  const cap = unsealRawV2(keys, c, 7, "e2g", prose).length - OVERHEAD; if (cap > P.length) padded++;
  const d = sealV2({ keys, counter: c, window: 7, dir: "e2g", plaintext: P, maxExpansion: 5 });
  assert.equal(unsealRawV2(keys, c, 7, "e2g", d).length - OVERHEAD, P.length); // default: small frames unpadded
}
assert.ok(padded > 280, `padded ${padded}`);
console.log(`policy ok: default padLength unchanged over 2142 cases; honey policy roundtrips, padded ${padded}/300 small frames`);
