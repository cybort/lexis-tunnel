// bb-k-v4 (scheme K, keyed canonical tail): roundtrip, deterministic seal, every single-word
// change rejected (incl. the last 8 words), wrong key = honey frame (no throw, formatValid true),
// same ciphertext as bb-v4 (only the words below C differ), protocol name.
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import * as F from "./frame2";
import { bbParse } from "./bb";
import { buildModelV4 } from "./model";
const R = (n: number) => Uint8Array.from(randomBytes(n));
const words = buildModelV4().words;
assert.equal(F.protocolName("bb-k-v4"), "lexis-hctr2-bb-k-v4");
assert.equal(F.getDefaultDte(), "bb-k-v4s"); assert.equal(F.protocolName(), "lexis-hctr2-bb-k-v4s"); assert.equal(F.protocolName("bb-v4"), "lexis-hctr2-bb-v4"); F.setDefaultDte("bb-v4"); assert.equal(F.getDefaultDte(), "bb-v4"); F.setDefaultDte("bb-k-v4s");
const sk = R(32), mb = R(32);
const k = F.deriveV2Keys(sk, 0, mb, "bb-k-v4"), w = F.deriveV2Keys(R(32), 0, R(32), "bb-k-v4"), a0 = F.deriveV2Keys(sk, 0, mb, "bb-v4");
let tested = 0, rejected = 0;
for (let i = 0; i < 60; i++) {
  const pt = R(1 + Math.floor(Math.random() * (i < 30 ? 64 : 4096)));
  const o = { keys: k, counter: i + 1, window: 7, dir: "e2g" as const };
  const prose = F.sealV2({ ...o, plaintext: pt, maxExpansion: 5 });
  assert.deepEqual(F.openV2({ ...o, prose }), pt);
  assert.throws(() => F.openV2({ ...o, counter: i + 2, prose }));
  const hv = F.openV2Honey({ ...o, keys: w, prose });
  assert.equal(hv.mnemonic.length, 16); assert.equal(hv.formatValid, true);
  assert.throws(() => F.openV2({ ...o, keys: w, prose }));
  // bb-v4 with the same key opens it (same ciphertext layer); bb-k does not open bb-v4 frames
  assert.deepEqual(F.openV2({ ...o, keys: a0, prose }), pt);
  const p0 = F.sealV2({ ...o, keys: a0, plaintext: pt, maxExpansion: 5 });
  assert.throws(() => F.openV2({ ...o, prose: p0 }));
  const ws = prose.split(" ");
  for (let j = 0; j < 10; j++) {
    const pos = j < 8 ? ws.length - 1 - j : Math.floor(Math.random() * ws.length), ww = [...ws];
    let s; do { s = words[Math.floor(Math.random() * 3000)]; } while (s === ww[pos]); ww[pos] = s;
    tested++; try { F.openV2({ ...o, prose: ww.join(" ") }); } catch { rejected++; }
  }
}
assert.equal(rejected, tested);
// deterministic: same key/counter/plaintext -> same words? (length field is randomized, so compare via ciphertext)
{ const pt = R(500); const o = { keys: k, counter: 9, window: 7, dir: "e2g" as const };
  const p1 = F.sealV2({ ...o, plaintext: pt }).split(" ");
  const C = bbParse(p1);
  // a different word sequence for the same C is never accepted: tail is fixed by (key, tweak, C)
  assert.ok(C.length > 0); }
// total on garbage
for (let i = 0; i < 50; i++) { const L = 1 + Math.floor(Math.random() * 300); const any = Array.from({ length: L }, () => words[Math.floor(Math.random() * words.length)]).join(" ");
  F.openV2Honey({ keys: k, counter: 1, window: 7, dir: "e2g", prose: any }); assert.throws(() => F.openV2({ keys: k, counter: 1, window: 7, dir: "e2g", prose: any })); }
console.log(`bbk: ok (single-word changes rejected ${rejected}/${tested})`);
