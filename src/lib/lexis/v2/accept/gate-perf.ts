/* Gate hello CPU profile. Usage: node --import jiti/register gate-perf.ts [rounds] [out.json]
 * Replicates gateRespond3 step by step with hrtime, plus end-to-end ops/s for valid + garbage hellos. */
import { writeFileSync } from "node:fs";
import { b64, concat, hex, u32be } from "../../bytes.ts";
import { createIdentity, x25519SeedFromJwk } from "../../crypto.ts";
import { claimHello, resetHandshakeGuards } from "../../handshake.ts";
import { clampKdf, decodeKdf, deriveSessionKeyAsync, encodeKdf } from "../../kdf.ts";
import type { MeshNode } from "../../types.ts";
import { edgeStart3, gateRespond3, windowCandidates } from "../handshake3.ts";
import * as ELL from "../elligator.ts";
const { elligatorKeyPair, elligatorMap, sharedFromPub, sharedFromRep } = ELL;
const esDH = (s: Uint8Array, u: Uint8Array) => ("x25519Shared" in ELL ? (ELL as any).x25519Shared(s, u, true) : x25519.getSharedSecret(s, u));
import { hctr2Decrypt, hctr2Encrypt, hctr2Key } from "../hctr2.ts";
import { buildModel, bytesToWords, wordsToBytes } from "../model.ts";
import { constantTimeEqual } from "../frame2.ts";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { x25519 } from "@noble/curves/ed25519.js";

const enc = new TextEncoder();
const T = "v3-test-token-9f3a2c1b0e7d6a5c";
const FAST = { memoryKiB: 32, iterations: 1, parallelism: 1, honey: false };
const N = Number(process.argv[2] || 300);
const k = (ikm: Uint8Array, salt: Uint8Array, info: string, len = 32) => hkdf(sha256, ikm, salt, enc.encode(info), len);
async function mk(role: MeshNode["role"]): Promise<MeshNode> {
  const kk = await createIdentity();
  return { id: role, name: role, role, publicJwk: kk.publicJwk, privateJwk: kk.privateJwk, publicRawB64: b64(kk.publicRaw), fingerprint: kk.fingerprint, pinnedPeerId: null, createdAt: Date.now(), kdf: null };
}
const gate = await mk("gate"), edge = await mk("edge");
const peers = [{ id: "e", publicRawB64: edge.publicRawB64 }];
const ltS = Uint8Array.from(Buffer.from(gate.publicRawB64, "base64"));
const now = () => Number(process.hrtime.bigint()) / 1000;
const acc: Record<string, number> = {};
const add = (key: string, t0: number) => { const t = now(); acc[key] = (acc[key] || 0) + (t - t0); return t; };
const med = (a: number[]) => a.slice().sort((x, y) => x - y)[a.length >> 1];

const mkHellos = (n: number) => Array.from({ length: n }, () => edgeStart3(edge, gate.publicRawB64, Date.now(), FAST, T).helloWire);
// warm-up
resetHandshakeGuards();
for (const h of mkHellos(50)) { resetHandshakeGuards(); await gateRespond3(gate, peers, h, { token: T, kdf: FAST }); }

// --- step profile (valid hellos), mirrors gateRespond3 exactly ---
const hellos = mkHellos(N);
let wins = 0;
for (const h of hellos) {
  resetHandshakeGuards();
  let t = now();
  const gateSeed = x25519SeedFromJwk(gate.privateJwk);
  const wordsIkm = concat(enc.encode(T), new Uint8Array([0]), ltS);
  t = add("other(jwk/ikm)", t);
  const id = hex(sha256(wordsIkm));
  const lex = hkdf(sha256, wordsIkm, enc.encode("lexis-v3-hello"), enc.encode("lex"), 32);
  const pad = hkdf(sha256, wordsIkm, enc.encode("lexis-v3-hello"), enc.encode("pad"), 32);
  const model = buildModel(lex, pad); void id;
  t = add("helloModel(cache hit: sha+2hkdf+lookup)", t);
  const bytes = wordsToBytes(model, h.trim().toLowerCase().split(/\s+/).filter(Boolean));
  t = add("decode fromWords/rANS", t);
  const repC = bytes.slice(0, 32), ct = bytes.subarray(32);
  const u = elligatorMap(repC);
  t = add("elligatorMap(repC)", t);
  const es = esDH(gateSeed, u);
  t = add("X25519 es", t);
  const ikm = concat(enc.encode(T), new Uint8Array([0]), es);
  let body: Uint8Array | null = null, window = 0;
  for (const w of windowCandidates()) {
    wins++;
    const hk = hctr2Key(k(ikm, repC, `hello|${w}`));
    t = add("window: hkdf+hctr2Key", t);
    const pt = hctr2Decrypt(hk, concat(enc.encode("hello"), u32be(w >>> 0)), ct);
    t = add("window: HCTR2 decrypt", t);
    const ok = constantTimeEqual(pt.subarray(0, 16), k(ikm, new Uint8Array(0), `admit-c|${w}`, 16));
    if (ok && !body) { body = pt; window = w; }
    t = add("window: admit hkdf+cmp", t);
  }
  if (!body) throw new Error("admit");
  const ltC = body.slice(16, 48), nonceC = body.slice(48, 64);
  const kdfC = decodeKdf(body, 64); const features = body[68];
  claimHello(window, nonceC, { peer: "e", ip: "" });
  t = add("other(peer/replay)", t);
  const ssS = (sharedFromPub as any)(gateSeed, ltC, true);
  t = add("X25519 ssS (static)", t);
  const ephS = elligatorKeyPair();
  t = add("Elligator2 keygen ephS", t);
  const ssE = sharedFromRep(ephS.seed, repC);
  t = add("X25519 ssE (+map)", t);
  const nonceS = crypto.getRandomValues(new Uint8Array(16));
  const agreed = clampKdf(FAST);
  const d = await deriveSessionKeyAsync(ssE, ssS, nonceC, nonceS, window, features, agreed);
  t = add("Argon2 session KDF (FAST)", t);
  const ikmS = concat(ikm, ssE);
  const hkS = hctr2Key(k(ikmS, ephS.rep, `server|${window}`));
  const wire = concat(ephS.rep, hctr2Encrypt(hkS, concat(enc.encode("server"), u32be(window)), concat(k(ikmS, new Uint8Array(0), `admit-s|${window}`, 16), nonceS, encodeKdf(agreed), new Uint8Array([features]), d.key.slice(0, 32), new Uint8Array(10))));
  t = add("server HCTR2 + transcript/confirm (approx)", t);
  bytesToWords(model, wire, 7).join(" ");
  t = add("encode server toWords", t);
}
const total = Object.values(acc).reduce((a, b) => a + b, 0);
const prof = Object.fromEntries(Object.entries(acc).map(([kk, v]) => [kk, { us: +(v / N).toFixed(1), pct: +((v / total) * 100).toFixed(1) }]));
console.log("backend", (ELL as any).x25519Backend ?? "noble(HEAD)", "windowsPerHello", wins / N);
console.table(prof);

// --- end-to-end, 5 runs each, median ---
async function e2e(kind: "valid" | "garbageWords" | "wrongToken") {
  const runs: number[] = [];
  for (let r = 0; r < 5; r++) {
    const hs = kind === "wrongToken" ? Array.from({ length: N }, () => edgeStart3(edge, gate.publicRawB64, Date.now(), FAST, "wrong-token-" + r).helloWire)
      : kind === "garbageWords" ? mkHellos(N).map((h) => h.split(" ").reverse().join(" ")) : mkHellos(N);
    const t0 = now();
    for (const h of hs) { if (kind === "valid") resetHandshakeGuards(); try { await gateRespond3(gate, peers, h, { token: T, kdf: FAST }); } catch { /* drop */ } }
    runs.push(N / ((now() - t0) / 1e6));
  }
  return { opsPerSec: +med(runs).toFixed(1), usPerHello: +(1e6 / med(runs)).toFixed(1), runs: runs.map((x) => +x.toFixed(1)) };
}
const res = { N, profileUs: prof, profileTotalUs: +(total / N).toFixed(1), e2e: { valid: await e2e("valid"), wrongToken: await e2e("wrongToken"), garbageWords: await e2e("garbageWords") } };
console.log(JSON.stringify(res.e2e, null, 1));
if (process.argv[3]) writeFileSync(process.argv[3], JSON.stringify(res, null, 2));
