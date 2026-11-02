/* v3 acceptance: token+gatePub must NOT decrypt hello / match admit.
 * Usage: node --import jiti/register v3-oracle.ts [out.json] */
import { randomBytes } from "node:crypto";
import { writeFileSync } from "node:fs";
import { b64 } from "../../bytes.ts";
import { createIdentity } from "../../crypto.ts";
import { resetHandshakeGuards } from "../../handshake.ts";
import type { MeshNode } from "../../types.ts";
import { edgeStart3, gateRespond3 } from "../handshake3.ts";
import { elligatorMap, sharedFromPub } from "../elligator.ts";
import { hctr2Decrypt, hctr2Key } from "../hctr2.ts";
import { buildModel, wordsToBytes } from "../model.ts";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { concat, u32be } from "../../bytes.ts";
import { constantTimeEqual } from "../frame2.ts";
import { ent, nistMonobit, nistRuns } from "./stats.ts";

const enc = new TextEncoder();
const T = "v3-test-token-9f3a2c1b0e7d6a5c";
const FAST = { memoryKiB: 32, iterations: 1, parallelism: 1, honey: false };
const out: Record<string, unknown> = {};
const log = (k: string, v: unknown) => { out[k] = v; console.log(k, JSON.stringify(v)); };

async function mk(role: MeshNode["role"]): Promise<MeshNode> {
  const k = await createIdentity();
  return { id: role, name: role, role, publicJwk: k.publicJwk, privateJwk: k.privateJwk, publicRawB64: b64(k.publicRaw), fingerprint: k.fingerprint, pinnedPeerId: null, createdAt: Date.now(), kdf: null };
}

function gateIkm(token: string, gatePub: Uint8Array) {
  return concat(enc.encode(token), new Uint8Array([0]), gatePub);
}
function helloIkm(token: string, es: Uint8Array) {
  return concat(enc.encode(token), new Uint8Array([0]), es);
}
function k(ikm: Uint8Array, salt: Uint8Array, info: string, len = 32) {
  return hkdf(sha256, ikm, salt, enc.encode(info), len);
}

resetHandshakeGuards();
const gate = await mk("gate");
const edge = await mk("edge");
const ltS = Uint8Array.from(Buffer.from(gate.publicRawB64, "base64"));
const N = Number(process.env.N || 500);

// --- a) offline decrypt with token+gatePub only ---
const admitHits = { v2style: 0, randomIkm: 0, correct: 0 };
const plainBytes: number[] = [];
const hellos: string[] = [];
for (let i = 0; i < N; i++) {
  resetHandshakeGuards();
  const p = edgeStart3(edge, gate.publicRawB64, Date.now(), FAST, T);
  hellos.push(p.helloWire);
  // attacker: word-decode with token||gatePub (same as v2)
  const wordsIkm = gateIkm(T, ltS);
  const model = buildModel(k(wordsIkm, enc.encode("lexis-v3-hello"), "lex", 32), k(wordsIkm, enc.encode("lexis-v3-hello"), "pad", 32));
  // use handshake's helloModel path equivalently via fromWords pattern in handshake3 - rebuild:
  const { buildModel: bm, bytesToWords, wordsToBytes: w2b } = await import("../model.ts");
  // Actually handshake caches via helloModel(wordsIkm) which uses hkdf labels lexis-v3-hello
  const lex = hkdf(sha256, wordsIkm, enc.encode("lexis-v3-hello"), enc.encode("lex"), 32);
  const pad = hkdf(sha256, wordsIkm, enc.encode("lexis-v3-hello"), enc.encode("pad"), 32);
  const m = bm(lex, pad);
  const bytes = w2b(m, p.helloWire.trim().toLowerCase().split(/\s+/).filter(Boolean));
  const repC = bytes.slice(0, 32);
  const ct = bytes.subarray(32);
  // v2-style ikm = token||gatePub (NO es) — should NOT match admit
  const ikmV2 = wordsIkm;
  for (const w of [Math.floor(Date.now() / 300000)]) {
    const pt = hctr2Decrypt(hctr2Key(k(ikmV2, repC, `hello|${w}`)), concat(enc.encode("hello"), u32be(w >>> 0)), ct);
    if (constantTimeEqual(pt.subarray(0, 16), k(ikmV2, new Uint8Array(0), `admit-c|${w}`, 16))) admitHits.v2style++;
    for (const x of pt) plainBytes.push(x);
  }
  // random ikm
  const ikmR = Uint8Array.from(randomBytes(32 + T.length));
  for (const w of [Math.floor(Date.now() / 300000)]) {
    const pt = hctr2Decrypt(hctr2Key(k(ikmR, repC, `hello|${w}`)), concat(enc.encode("hello"), u32be(w >>> 0)), ct);
    if (constantTimeEqual(pt.subarray(0, 16), k(ikmR, new Uint8Array(0), `admit-c|${w}`, 16))) admitHits.randomIkm++;
  }
  // correct (with es) — sanity
  const es = sharedFromPub(p.eph.seed, ltS);
  const ikmOk = helloIkm(T, es);
  for (const w of [p.window]) {
    const pt = hctr2Decrypt(hctr2Key(k(ikmOk, repC, `hello|${w}`)), concat(enc.encode("hello"), u32be(w >>> 0)), ct);
    if (constantTimeEqual(pt.subarray(0, 16), k(ikmOk, new Uint8Array(0), `admit-c|${w}`, 16))) admitHits.correct++;
  }
}
const plain = Uint8Array.from(plainBytes);
log("A.offlineTokenPlusGatePub", {
  n: N,
  admitMatches_v2styleIkm: admitHits.v2style,
  admitMatches_randomIkm: admitHits.randomIkm,
  admitMatches_correctEs: admitHits.correct,
  decryptPlaintextEntropy: ent(plain),
  nistMonobit: nistMonobit(plain),
  nistRuns: nistRuns(plain),
});

// --- b) wrong tokens + correct token without gate priv ---
let wrongTokenSignals = 0;
let rightTokenNoPrivSignals = 0;
resetHandshakeGuards();
const sample = edgeStart3(edge, gate.publicRawB64, Date.now(), FAST, T);
for (let i = 0; i < 200; i++) {
  const wrong = Buffer.from(randomBytes(16)).toString("base64url");
  try {
    await gateRespond3(gate, [{ id: "e", publicRawB64: edge.publicRawB64 }], sample.helloWire, { token: wrong, kdf: FAST });
    wrongTokenSignals++;
  } catch { /* HandshakeDrop expected */ }
}
// "signal" for offline: try admit with token but without computing es (already in A)
rightTokenNoPrivSignals = admitHits.v2style;
log("B.bruteAndNoPriv", { wrongTokenAccepted: wrongTokenSignals, offlineAdmitWithTokenNoPriv: rightTokenNoPrivSignals });

// --- c) hello uniqueness ---
const uniq = new Set(hellos);
const wc = hellos.map((h) => h.split(" ").length);
log("C.hellos", { n: hellos.length, unique: uniq.size, words: { min: Math.min(...wc), max: Math.max(...wc), mean: +(wc.reduce((a, b) => a + b, 0) / wc.length).toFixed(1) } });

// --- d) microbench gate CPU ---
resetHandshakeGuards();
const hellos2 = Array.from({ length: 200 }, () => edgeStart3(edge, gate.publicRawB64, Date.now(), FAST, T).helloWire);
const peers = [{ id: "e", publicRawB64: edge.publicRawB64 }];
const t0 = performance.now();
let ok = 0;
for (const h of hellos2) {
  resetHandshakeGuards();
  try { await gateRespond3(gate, peers, h, { token: T, kdf: FAST }); ok++; } catch { /* replay of identity across windows etc */ }
}
const ms = performance.now() - t0;
log("D.gateCpu", { attempts: hellos2.length, accepted: ok, ms: +ms.toFixed(1), usPerHello: +((ms / hellos2.length) * 1000).toFixed(1), opsPerSec: +(hellos2.length / (ms / 1000)).toFixed(1) });

if (process.argv[2]) writeFileSync(process.argv[2], JSON.stringify(out, null, 2));
