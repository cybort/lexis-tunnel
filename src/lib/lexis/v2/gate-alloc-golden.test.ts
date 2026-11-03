/**
 * fix/gate-alloc: old-vs-new equivalence. vectors/gate-alloc-golden.json was produced by running this
 * file with GOLDEN_WRITE=1 against the unmodified sources (e429eaa). Every case recomputes the wire-
 * relevant output with the current sources and must match byte for byte.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { buildModel, bytesToWords, wordsToBytes, KeyStream, VOCAB_SIZE, CORPUS } from "./model";
import { hctr2Decrypt, hctr2Encrypt, hctr2Key } from "./hctr2";
import { elligatorMap, x25519Shared } from "./elligator";
import { sessionLexicon, staticLexicon } from "../lexicon";
import { identityFromJwks } from "../crypto";
import { x25519 } from "@noble/curves/ed25519.js";

const H = (d: Uint8Array | string) => createHash("sha256").update(d).digest("hex");
let ctr = 0;
const det = (n: number) => {
  const out = new Uint8Array(n);
  for (let o = 0; o < n; o += 32) out.set(createHash("sha256").update(`gate-alloc-${ctr++}`).digest().subarray(0, Math.min(32, n - o)), o);
  return out;
};
const b64u = (u: Uint8Array) => Buffer.from(u).toString("base64url");

async function compute(): Promise<Record<string, string>> {
  ctr = 0;
  const r: Record<string, string> = {};
  for (let k = 0; k < 6; k++) {
    const m = buildModel(det(32), det(32));
    r[`model${k}.words`] = H(m.words.join(" "));
    for (let i = 0; i < 25; i++) {
      const len = 4 + (det(2)[0] * 7 + i * 13) % 900;
      const data = det(len);
      const ws = bytesToWords(m, data, det(1)[0]);
      r[`model${k}.b2w${i}`] = H(ws.join(" "));
      const back = wordsToBytes(m, ws);
      r[`model${k}.w2b${i}`] = H(back);
      const rnd = Array.from(det(40), (b, j) => m.words[(b * 251 + j * 977) % VOCAB_SIZE]);
      r[`model${k}.w2bRand${i}`] = H(wordsToBytes(m, rnd));
    }
  }
  r["corpus.freq"] = H(new Uint8Array(CORPUS.freqByRank.buffer));
  for (let k = 0; k < 6; k++) {
    const ks = new KeyStream(det(32), k * 37);
    const out = new Uint8Array(20000);
    for (let i = 0; i < out.length; i++) out[i] = ks.byte();
    r[`keystream${k}`] = H(out);
  }
  for (let k = 0; k < 40; k++) {
    const key = hctr2Key(det(32));
    const tweak = det(k % 3 === 0 ? 0 : 1 + (k * 5) % 40);
    const pt = det(16 + (k * 29) % 600);
    const ct = hctr2Encrypt(key, tweak, pt);
    r[`hctr2.${k}.ct`] = H(ct);
    r[`hctr2.${k}.dec`] = H(hctr2Decrypt(key, tweak, det(ct.length)));
  }
  for (let k = 0; k < 64; k++) {
    const seed = det(32);
    const u = k % 2 ? elligatorMap(det(32)) : x25519.getPublicKey(det(32));
    r[`x25519.${k}`] = H(x25519Shared(seed, u, k % 4 === 1));
  }
  for (let k = 0; k < 6; k++) {
    const d = det(32);
    const x = b64u(x25519.getPublicKey(d));
    const id = await identityFromJwks({ kty: "OKP", crv: "X25519", x }, { kty: "OKP", crv: "X25519", x, d: b64u(d) });
    r[`identity.${k}`] = id.fingerprint;
    let bad = "ok";
    try {
      await identityFromJwks({ kty: "OKP", crv: "X25519", x: b64u(det(32)) }, { kty: "OKP", crv: "X25519", x, d: b64u(d) });
    } catch (e) {
      bad = String((e as Error).message);
    }
    r[`identity.${k}.mismatch`] = bad;
  }
  r["lexicon.static"] = H((await staticLexicon()).join(" "));
  for (let k = 0; k < 12; k++) r[`lexicon.${k}`] = H((await sessionLexicon(det(32), k * 1000003)).join(" "));
  return r;
}

const file = new URL("./vectors/gate-alloc-golden.json", import.meta.url);
const got = await compute();
if (process.env.GOLDEN_WRITE === "1") {
  writeFileSync(file, JSON.stringify(got, null, 1) + "\n");
  console.log(`wrote ${Object.keys(got).length} golden values`);
} else {
  const want = JSON.parse(readFileSync(file, "utf8")) as Record<string, string>;
  assert.deepEqual(Object.keys(got).sort(), Object.keys(want).sort());
  for (const k of Object.keys(want)) assert.equal(got[k], want[k], k);
  console.log(`gate-alloc golden: ${Object.keys(want).length}/${Object.keys(want).length} identical to e429eaa`);
}
