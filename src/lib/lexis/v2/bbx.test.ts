// A1-A4 DTEs (bbx.ts): frame roundtrip per dte, wrong key = valid honey frame (no throw),
// arbitrary word strings parse (total), sealing randomized (except canonical dfa-v4).
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import * as F from "./frame2";
import { BBX_DTES, c8Opts, parseX, randomWordsX, sealX, specOf, wordsForBytesX } from "./bbx";
import { buildModelV4 } from "./model";
const R = (n: number) => Uint8Array.from(randomBytes(n));
const words = buildModelV4().words;
for (const dte of BBX_DTES) {
  const k = F.deriveV2Keys(R(32), 0, R(32), dte), w = F.deriveV2Keys(R(32), 0, R(32), dte);
  for (let i = 0; i < 40; i++) {
    const pt = R(1 + Math.floor(Math.random() * (i < 20 ? 64 : 1500)));
    const prose = F.sealV2({ keys: k, counter: i + 1, window: 7, dir: "e2g", plaintext: pt, maxExpansion: 5 });
    assert.deepEqual(F.openV2({ keys: k, counter: i + 1, window: 7, dir: "e2g", prose }), pt, dte);
    const hv = F.openV2Honey({ keys: w, counter: i + 1, window: 7, dir: "e2g", prose });
    assert.equal(hv.mnemonic.length, 16);
    assert.throws(() => F.openV2({ keys: w, counter: i + 1, window: 7, dir: "e2g", prose }));
  }
  const sp = specOf(dte);
  for (let i = 0; i < 100; i++) {
    const L = 1 + Math.floor(Math.random() * 400);
    const any = i % 2 ? Array.from({ length: L }, () => words[Math.floor(Math.random() * words.length)]) : randomWordsX(sp, sp.canon ? 19 + i : L);
    parseX(sp, any);
    F.openV2Honey({ keys: k, counter: 1, window: 7, dir: "e2g", prose: any.join(" ") });
  }
  const pt = R(100);
  const a = F.sealV2({ keys: k, counter: 9, window: 7, dir: "e2g", plaintext: pt, maxExpansion: 5 });
  const b = F.sealV2({ keys: k, counter: 9, window: 7, dir: "e2g", plaintext: pt, maxExpansion: 5 });
  if (sp.canon) assert.equal((sealX(sp, parseX(sp, a.split(" "))) as string[]).join(" "), a, "dfa-v4 canonical re-encode");
  else { assert.notEqual(a, b); const C = parseX(sp, a.split(" ")); assert.notEqual((sealX(sp, C) as string[]).join(" "), a, dte + " randomized"); }
}
{ // A1ds: fast c8 closure check == reference re-parse (same CSPRNG stream -> same words)
  const sp = specOf("bb-c8-v4");
  const pr = (seed: number) => { let x = seed >>> 0 || 1; return () => { x ^= x << 13; x >>>= 0; x ^= x >>> 17; x ^= x << 5; x >>>= 0; return x & 255; }; };
  for (const n0 of [1, 19, 64, 300, 1024]) for (let i = 0; i < 6; i++) {
    let n = n0; while (!wordsForBytesX(sp, n).length) n++;
    const C = R(n);
    c8Opts.slow = false; const a = sealX(sp, C, pr(n * 31 + i + 1)) as string[];
    c8Opts.slow = true; const b = sealX(sp, C, pr(n * 31 + i + 1)) as string[];
    c8Opts.slow = false;
    assert.equal(a.join(" "), b.join(" "), "c8 fast == reference"); assert.deepEqual(parseX(sp, a), C);
  }
}
console.log(`bbx ok: ${BBX_DTES.join(",")} roundtrip 40, wrong-key honey 40, arbitrary strings parse 100, randomized seal (dfa canonical)`);
