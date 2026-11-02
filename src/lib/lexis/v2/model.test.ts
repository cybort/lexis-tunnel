import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { buildGfModel, buildModel, bytesToWords, gfBytesToWords, gfWordsToBytes, wordsToBytes } from "./model";

const t0 = Date.now();
const m = buildModel(randomBytes(32), randomBytes(32));
console.log(`model build ${Date.now() - t0} ms, maxLen ${m.maxLen}`);
for (let i = 0; i < 2000; i++) {
  const n = 4 + Math.floor(Math.random() * 600);
  const data = Uint8Array.from(randomBytes(n));
  const words = bytesToWords(m, data, i);
  const back = wordsToBytes(m, words);
  assert.deepEqual(Buffer.from(back).toString("hex"), Buffer.from(data).toString("hex"), `rANS roundtrip len ${n}`);
}
const g = buildGfModel(randomBytes(32));
for (let i = 0; i < 500; i++) {
  const n = 1 + Math.floor(Math.random() * 600);
  const data = Uint8Array.from(randomBytes(n));
  assert.deepEqual(gfWordsToBytes(g, gfBytesToWords(g, data), n), data);
}
// Any key parses any words without throwing.
const other = buildModel(randomBytes(32), randomBytes(32));
const w = bytesToWords(m, Uint8Array.from(randomBytes(200)), 1);
wordsToBytes(other, w);
console.log("model ok: 2000 rANS + 500 GF roundtrips");
