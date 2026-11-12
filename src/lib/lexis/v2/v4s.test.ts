// bb-k-v4s (D-pool): shared allowed set + session-keyed permutation within frequency groups.
// - allowed-set constants (pack, full set 46701, bits-back length constants recomputed exactly)
// - group-flat frequencies: equal inside every group, so every word's probability is key-independent
// - every keyed model contains every allowed word (no secret subset, no membership test)
// - the permutation stays inside the 1.5x / 256-wide groups; frequencies are key-independent
// - data model depends on sk only (not wordsIkm, not the mnemonic base), deterministic per sk
// - roundtrip, keyed canonical tail (every single-word change refused), honey wrong key
// - bits-back surjectivity over the allowed set (arbitrary strings parse and are in support)
// The exclusion list itself is a build input and is NOT part of this test (see build notes).
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import * as F from "./frame2";
import { bbInSupportM, bbParseM, bytesForWordsS, wordsForBytesS } from "./bb";
import { buildModelS, buildModelV4, corpusS } from "./model";
import { ALLOWED_GROUPS } from "./vocab-allowed";
const R = (n: number) => Uint8Array.from(randomBytes(n));
const enc = new TextEncoder();
const S = corpusS();
assert.equal(S.pack, "fw50k-all-d1-gf");
assert.equal(S.words.length, 46701);
assert.equal(S.groups.length, ALLOWED_GROUPS);
assert.equal(new Set(S.words).size, S.words.length);
assert.ok(S.words.every((w) => /^[a-z]+$/.test(w)));
for (let i = 1; i < S.counts.length; i++) assert.ok(S.counts[i] <= S.counts[i - 1]);
{ let sum = 0; for (const f of S.freqByRank) { assert.ok(f >= 1); sum += f; } assert.equal(sum, 2 ** 24); }
{ const M = 2 ** 24; let mu = 0, m2 = 0; for (const f of S.freqByRank) { const p = f / M, b = -Math.log2(p); mu += p * b; m2 += p * b * b; }
  assert.equal(mu, S.mu); assert.equal(Math.sqrt(m2 - mu * mu), S.sig); }
for (const [a, b] of S.groups) { assert.ok(b - a <= 256); assert.ok(S.counts[b - 1] * 1.5 >= S.counts[a]); }
for (const [a, b] of S.groups) for (let i = a + 1; i < b; i++) assert.equal(S.freqByRank[i], S.freqByRank[a], "group-flat frequency");
assert.equal(F.getDefaultDte(), "bb-k-v4s");
assert.equal(F.protocolName(), "lexis-hctr2-bb-k-v4s");

const sorted = [...S.words].sort().join(" ");
const groupOf = new Int32Array(S.words.length); S.groups.forEach(([a, b], g) => { for (let i = a; i < b; i++) groupOf[i] = g; });
const corpusRank = new Map(S.words.map((w, i) => [w, i] as [string, number]));
const sks = Array.from({ length: 8 }, () => R(32));
const models = sks.map((sk) => F.deriveV2Keys(sk, 0, R(32), "bb-k-v4s"));
for (const k of models) {
  assert.equal(k.wire, k.model, "finish and data frames share the sk model");
  assert.equal(k.wire.words.length, S.words.length);
  assert.equal([...k.wire.words].sort().join(" "), sorted, "every keyed model holds the full allowed set");
  assert.equal(k.wire.freq, S.freqByRank, "frequencies are the shared table");
  k.wire.words.forEach((w, r) => assert.equal(groupOf[corpusRank.get(w)!], groupOf[r], "permutation stays in its group"));
  // every word has the same probability under every key (no candidate-key likelihood statistic)
  k.wire.words.forEach((w, r) => assert.equal(k.wire.freq[r], S.freqByRank[corpusRank.get(w)!], "word frequency is key-independent"));
}
// depends on sk only, with the design labels (salt empty, info lexis-v4s-lex / lexis-v4s-pad)
{
  const sk = sks[0];
  const again = F.deriveV2Keys(sk, 0, R(32), "bb-k-v4s");
  assert.deepEqual(again.wire.words, models[0].wire.words);
  const ref = buildModelS(hkdf(sha256, sk, new Uint8Array(0), enc.encode("lexis-v4s-lex"), 32), hkdf(sha256, sk, new Uint8Array(0), enc.encode("lexis-v4s-pad"), 32));
  assert.deepEqual(ref.words, models[0].wire.words);
  let diff = 0; for (let i = 0; i < S.words.length; i++) if (models[0].wire.words[i] !== models[1].wire.words[i]) diff++;
  assert.ok(diff > S.words.length / 2, `different sk -> different order (${diff})`);
  // not the hello model of any wordsIkm built from sk material (hello uses the lexis-v3-hello labels)
  const hello = buildModelS(hkdf(sha256, sk, enc.encode("lexis-v3-hello"), enc.encode("lex"), 32), hkdf(sha256, sk, enc.encode("lexis-v3-hello"), enc.encode("pad"), 32));
  assert.notDeepEqual(hello.words, models[0].wire.words);
  // legacy fallback untouched
  assert.equal(F.deriveV2Keys(sk, 0, R(32), "bb-k-v4").wire, buildModelV4());
}
// roundtrip + keyed canonical tail + honey
const k = models[0], w = models[1];
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
  const ws = prose.split(" ");
  assert.ok(ws.every((x) => corpusRank.has(x)), "every wire word is an allowed word");
  for (let j = 0; j < 10; j++) {
    const pos = j < 8 ? ws.length - 1 - j : Math.floor(Math.random() * ws.length), ww = [...ws];
    let s; do { s = S.words[Math.floor(Math.random() * 3000)]; } while (s === ww[pos]); ww[pos] = s;
    tested++; try { F.openV2({ ...o, prose: ww.join(" ") }); } catch { rejected++; }
  }
}
assert.equal(rejected, tested);
// surjectivity over the allowed set under a keyed model: iid model draws and uniform words
const cum: number[] = []; { let s = 0; for (const f of S.freqByRank) cum.push((s += f)); }
const zipf = () => { const u = Math.random() * cum[cum.length - 1]; let l = 0, h = cum.length - 1; while (l < h) { const m = (l + h) >> 1; if (cum[m] > u) h = m; else l = m + 1; } return k.wire.words[l]; };
for (let i = 0; i < 300; i++) {
  const m = 20 + Math.floor(Math.random() * 400);
  const W = Array.from({ length: m }, i % 2 ? zipf : () => S.words[Math.floor(Math.random() * S.words.length)]);
  assert.equal(bbParseM(k.wire, W).length, bytesForWordsS(m)); assert.ok(bbInSupportM(k.wire, W), "not in support");
  assert.equal(bbParseM(w.wire, W).length, bytesForWordsS(m)); // any key parses any string
}
for (let n = 19; n < 4400; n += 13) assert.ok(wordsForBytesS(n).length > 0 || wordsForBytesS(n + 1).length > 0);
console.log(`v4s ok: pack ${S.pack} ${S.words.length} words, ${models.length} sk models hold the full set, group-local permutation, sk-only derivation, roundtrip 60, single-word changes rejected ${rejected}/${tested}, 300 arbitrary sequences in support`);
