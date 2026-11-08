import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { bbInSupport, bbParse, bbSeal, bytesForWords, representable } from "./bb";
import { CORPUS } from "./model";
// round trip over representable lengths
for (let i = 0; i < 300; i++) { let n = 19 + Math.floor(Math.random() * 4200); while (!representable(n)) n++; const C = Uint8Array.from(randomBytes(n)); assert.deepEqual(bbParse(bbSeal(C)), C); }
// surjectivity: arbitrary word sequences (iid Zipf and uniform-random words) are possible encodings of their parse
const cum: number[] = []; { let s = 0; for (const f of CORPUS.freqByRank) cum.push((s += f)); }
const zipf = () => { const u = Math.random() * cum[cum.length - 1]; let l = 0, h = cum.length - 1; while (l < h) { const m = (l + h) >> 1; if (cum[m] > u) h = m; else l = m + 1; } return CORPUS.words[l]; };
for (let i = 0; i < 300; i++) { const m = 20 + Math.floor(Math.random() * 400); const W = Array.from({ length: m }, i % 2 ? zipf : () => CORPUS.words[Math.floor(Math.random() * CORPUS.words.length)]); assert.equal(bbParse(W).length, bytesForWords(m)); assert.ok(bbInSupport(W), "not in support"); }
// randomized: the same ciphertext twice -> different wire
const C = Uint8Array.from(randomBytes(200 + (representable(200) ? 0 : 1)));
if (representable(C.length)) assert.notEqual(bbSeal(C).join(" "), bbSeal(C).join(" "));
console.log("bb ok: 300 roundtrips, 300 arbitrary sequences in support, randomized");
