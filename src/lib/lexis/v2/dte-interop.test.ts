// frame.dte interop matrix for bb-k-v4s (default), the 4.0 values bb-k-v4, bb-v4 (A0), bb-c8-v4 (A1ds):
// same dte on both ends opens; mixed configs fail (at least one direction always refuses, so a
// session never works); single-word tamper: bb-k-v4 refuses all; bb-c8-v4 refuses ~99.7% (measured
// 19/6000 accepted with unchanged plaintext, same on feat/v4-a1-c8ds fast and LEXIS_C8_SLOW paths).
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import * as F from "./frame2";
import { buildModelV4 } from "./model";
const R = (n: number) => Uint8Array.from(randomBytes(n));
const words = buildModelV4().words;
const D = ["bb-k-v4s", "bb-k-v4", "bb-v4", "bb-c8-v4"] as const;
assert.equal(F.getDefaultDte(), "bb-k-v4s");
const sk = R(32), mb = R(32);
const K = Object.fromEntries(D.map((d) => [d, F.deriveV2Keys(sk, 0, mb, d)])) as Record<(typeof D)[number], F.V2Keys>;
const opens = (s: (typeof D)[number], r: (typeof D)[number], n: number) => {
  let ok = 0;
  for (let i = 0; i < n; i++) {
    const pt = R(1 + Math.floor(Math.random() * (i < n / 2 ? 64 : 4096))), o = { counter: i + 1, window: 7, dir: "e2g" as const };
    const prose = F.sealV2({ ...o, keys: K[s], plaintext: pt, maxExpansion: 5 });
    try { assert.deepEqual(F.openV2({ ...o, keys: K[r], prose }), pt); ok++; } catch { /* refused */ }
  }
  return ok;
};
const N = 24;
for (const d of D) assert.equal(opens(d, d, N), N, `${d} same-dte roundtrip`);
// bb-k-v4 refuses bb-v4 / bb-c8-v4 frames (canonical-tail check); bb-k-v4 frames are refused by bb-c8-v4.
for (const s of ["bb-v4", "bb-c8-v4"] as const) assert.equal(opens(s, "bb-k-v4", N), 0, `${s} -> bb-k-v4`);
assert.ok(opens("bb-k-v4", "bb-c8-v4", N) <= 2);
// bb-v4 <-> bb-c8-v4: refused almost always (measured ~0.5% of frames happen to satisfy the c8 check /
// parse under the other model and open correctly) -- not interoperable, but not a hard 0 either.
assert.ok(opens("bb-v4", "bb-c8-v4", N) <= 3); assert.ok(opens("bb-c8-v4", "bb-v4", N) <= 3);
// bb-k-v4 frames open under bb-v4 (same ciphertext layer, bb-v4 ignores the tail) -- one-way only;
// bb-v4 -> bb-k-v4 is refused (above), so a mixed bb-k/bb-v4 session still fails.
assert.equal(opens("bb-k-v4", "bb-v4", N), N);
// bb-k-v4s (allowed set, sk-keyed permutation, keyed canonical tail) and every 4.0 value refuse each
// other's frames in both directions, even with the same session key.
for (const o of ["bb-k-v4", "bb-v4", "bb-c8-v4"] as const) { assert.equal(opens("bb-k-v4s", o, N), 0, `bb-k-v4s -> ${o}`); assert.equal(opens(o, "bb-k-v4s", N), 0, `${o} -> bb-k-v4s`); }
for (const d of ["bb-k-v4s", "bb-k-v4", "bb-c8-v4"] as const) {
  let t = 0, rej = 0;
  for (let i = 0; i < 16; i++) {
    const o = { keys: K[d], counter: i + 1, window: 7, dir: "e2g" as const };
    const ws = F.sealV2({ ...o, plaintext: R(1 + Math.floor(Math.random() * 2048)), maxExpansion: 5 }).split(" ");
    for (let j = 0; j < 12; j++) {
      const pos = j < 8 ? ws.length - 1 - j : Math.floor(Math.random() * ws.length), ww = [...ws];
      let x; do { x = words[Math.floor(Math.random() * 3000)]; } while (x === ww[pos]); ww[pos] = x;
      t++; try { F.openV2({ ...o, prose: ww.join(" ") }); } catch { rej++; }
    }
  }
  if (d === "bb-k-v4" || d === "bb-k-v4s") assert.equal(rej, t, `${d} tamper`); else assert.ok(t - rej <= Math.ceil(t * 0.02), `${d} tamper ${t - rej}/${t} accepted`);
}
console.log("dte-interop ok");
