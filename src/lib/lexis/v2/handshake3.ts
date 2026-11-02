/**
 * v3: handshake with Noise-NK-style hello (es = X25519(eph, gate_static)).
 *
 * hello  = words_H( repC(32) || HCTR2(K_h, "hello"|w, admitC || ltC || nonceC || kdf || feat || pad) )
 * server = words_H( repS(32) || HCTR2(K_s, "server"|w, admitS || nonceS || kdf || feat || confirmS || pad) )
 * finish = words_session( HCTR2(K_f, "finish"|w, confirmC || pad) )
 *
 * - repC/repS: Elligator2 representatives of dirty X25519 ephemerals (uniform 256-bit strings).
 * - K_h / admit-c = HKDF(token || es, ... ) where es = X25519(client_eph, gate_static_pub).
 *   Only the gate private key holder can compute es, so token+gatePub alone cannot check admit
 *   or read ltRaw (fixes the v2 offline oracle). Word model stays keyed by token||ltS so the
 *   wire can still be parsed into bytes without es; those bytes are useless without es.
 * - K_s additionally mixes the ephemeral-ephemeral secret ssE.
 * - Session key: ssE = X25519 eph-eph, ssS = X25519 static-static, through deriveSessionKeyAsync.
 * - Key confirmation restored: confirmS / confirmC = HMAC(HKDF(sk), transcript).
 * - The gate treats every failure the same way (HandshakeDrop): the caller drops silently.
 */
import { hkdf } from "@noble/hashes/hkdf.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { b64, concat, hex, u32be, unb64 as bytesUnb64 } from "../bytes";
import { x25519PubFromJwk, x25519SeedFromJwk } from "../crypto";
import { claimHello, currentWindow } from "../handshake";
import { clampKdf, decodeKdf, deriveSessionKeyAsync, encodeKdf, featureByte, type ArgonParams, type SessionOffer } from "../kdf";
import { SPEC } from "../spec";
import type { MeshNode } from "../types";
import { elligatorKeyPair, sharedFromPub, sharedFromRep, type EphemeralKey } from "./elligator";
import { constantTimeEqual, deriveV2Keys, type V2Keys } from "./frame2";
import { x25519 } from "@noble/curves/ed25519.js";
import { hctr2Decrypt, hctr2Encrypt, hctr2Key } from "./hctr2";
import { buildModel, bytesToWords, wordsToBytes, type WordModel } from "./model";

const enc = new TextEncoder();
export class HandshakeDrop extends Error {}

const fail = (why: string): never => {
  throw new HandshakeDrop(why);
};

function rand(n: number) {
  return crypto.getRandomValues(new Uint8Array(n));
}

function unb64(s: string): Uint8Array {
  return bytesUnb64(s);
}

const modelCache = new Map<string, WordModel>();
function helloModel(ikm: Uint8Array): WordModel {
  const id = hex(sha256(ikm));
  let m = modelCache.get(id);
  if (!m) {
    const lex = hkdf(sha256, ikm, enc.encode("lexis-v3-hello"), enc.encode("lex"), 32);
    const pad = hkdf(sha256, ikm, enc.encode("lexis-v3-hello"), enc.encode("pad"), 32);
    m = buildModel(lex, pad);
    if (modelCache.size > 16) modelCache.clear();
    modelCache.set(id, m);
  }
  return m;
}

function gateIkm(token: string, gatePubRaw: Uint8Array) {
  return concat(enc.encode(token), new Uint8Array([0]), gatePubRaw);
}

/** Secret hello IKM: token concatenated with the Noise-NK `es` shared secret. */
function helloIkm(token: string, es: Uint8Array) {
  return concat(enc.encode(token), new Uint8Array([0]), es);
}

function tw(label: string, window: number) {
  return concat(enc.encode(label), u32be(window >>> 0));
}

function k(ikm: Uint8Array, salt: Uint8Array, info: string, len = 32) {
  return hkdf(sha256, ikm, salt, enc.encode(info), len);
}

function toWords(model: WordModel, data: Uint8Array) {
  return bytesToWords(model, data, rand(1)[0]).join(" ");
}

function fromWords(model: WordModel, prose: string) {
  return wordsToBytes(model, prose.trim().toLowerCase().split(/\s+/).filter(Boolean));
}

const LT = 32; // X25519 raw pub
const HELLO_MIN = 16 + LT + 16 + 4 + 1;
const SERVER_MIN = 16 + 16 + 4 + 1 + 16 + 16; // admitS nonceS kdf feat seedS confirmS

export function windowCandidates(now = Date.now()): number[] {
  const current = currentWindow(now);
  const into = Math.floor(now / 1000) % SPEC.windowSec;
  const out = [current];
  if (into < SPEC.skewSec) out.push(current - 1);
  if (into >= SPEC.windowSec - SPEC.skewSec) out.push(current + 1);
  return out;
}

function transcript(p: {
  repC: Uint8Array; repS: Uint8Array; ltC: Uint8Array; ltS: Uint8Array; window: number;
  nonceC: Uint8Array; nonceS: Uint8Array; kdf: Uint8Array; features: number;
}) {
  return sha256(concat(enc.encode("lexis-v3-transcript"), p.repC, p.repS, p.ltC, p.ltS, u32be(p.window >>> 0), p.nonceC, p.nonceS, p.kdf, new Uint8Array([p.features & 0xff])));
}

/* D2: every confirmation is keyed on a secret that needs an EPHEMERAL private scalar
 * (ssE). Nothing here can be checked against public information alone (token, gate
 * public key, the transcript), so none of it is a key-guessing oracle.
 *   confirmS = HMAC(HKDF(ssE || sk, "confirm-s"), transcript)   gate -> edge
 *   confirmC = HMAC(HKDF(mnemonicBase, "confirm-c"), transcript) edge -> gate
 * mnemonicBase = HKDF(ssE, salt = seedC || seedS): fresh per handshake, both ends
 * contribute, each seed travels encrypted under a key that contains ssE. */
function confirmS_(ssE: Uint8Array, sk: Uint8Array, tr: Uint8Array) {
  return hmac(sha256, k(concat(ssE, sk), new Uint8Array(0), "lexis-v3-confirm-s"), tr).slice(0, 16);
}
function confirmC_(mnemonicBase: Uint8Array, tr: Uint8Array) {
  return hmac(sha256, k(mnemonicBase, new Uint8Array(0), "lexis-v3-confirm-c"), tr).slice(0, 16);
}
export function mnemonicBaseOf(ssE: Uint8Array, seedC: Uint8Array, seedS: Uint8Array) {
  return hkdf(sha256, ssE, concat(seedC, seedS), enc.encode("lexis-v3-mnemonic-base"), 32);
}
function finishKey(ssE: Uint8Array, sk: Uint8Array) {
  return hctr2Key(k(concat(ssE, sk), new Uint8Array(0), "lexis-v3-finish"));
}

export type EdgePending3 = {
  eph: EphemeralKey; nonceC: Uint8Array; window: number; helloWire: string;
  ltRaw: Uint8Array; ikm: Uint8Array; features: number; wordsIkm: Uint8Array; es: Uint8Array;
};

export function edgeStart3(edge: MeshNode, gatePubB64: string, now = Date.now(), offer?: Partial<SessionOffer>, token = ""): EdgePending3 {
  const ltRaw = unb64(edge.publicRawB64);
  if (ltRaw.length !== LT) throw new Error("edge 长期公钥必须是 32 字节 X25519");
  const ltS = unb64(gatePubB64);
  if (ltS.length !== LT) throw new Error("gate 长期公钥必须是 32 字节 X25519");
  const wordsIkm = gateIkm(token, ltS); // parseable by token+gatePub; does NOT protect body
  const window = currentWindow(now);
  const eph = elligatorKeyPair();
  const es = sharedFromPub(eph.seed, ltS); // Noise NK: es
  const ikm = helloIkm(token, es); // secret; needs gate priv to recompute
  const nonceC = rand(16);
  const kdf = encodeKdf(clampKdf(offer));
  const features = featureByte(!!offer?.honey);
  const admit = k(ikm, new Uint8Array(0), `admit-c|${window}`, 16);
  const pad = rand(rand(1)[0] % 48);
  const body = concat(admit, ltRaw, nonceC, kdf, new Uint8Array([features]), pad);
  const hk = hctr2Key(k(ikm, eph.rep, `hello|${window}`));
  const wire = concat(eph.rep, hctr2Encrypt(hk, tw("hello", window), body));
  return { eph, nonceC, window, helloWire: toWords(helloModel(wordsIkm), wire), ltRaw, ikm, features, wordsIkm, es };
}

export type GatePending3 = {
  sk: Uint8Array; window: number; ltC: Uint8Array; peerId: string; nonceC: Uint8Array; nonceS: Uint8Array;
  serverWire: string; kdf: ArgonParams; features: number;
  /** kept only until gateAccept3: ephemeral DH secret, our seed, and the transcript. */
  ssE: Uint8Array; seedS: Uint8Array; tr: Uint8Array;
};

export async function gateRespond3(
  gate: MeshNode,
  peers: { id?: string; publicRawB64: string }[],
  helloWire: string,
  opts: { token?: string; kdf?: ArgonParams; sourceIp?: string; now?: number } = {},
): Promise<GatePending3> {
  const ltS = unb64(gate.publicRawB64);
  if (ltS.length !== LT) return fail("point");
  let gateSeed: Uint8Array;
  try {
    gateSeed = x25519SeedFromJwk(gate.privateJwk);
  } catch {
    return fail("point");
  }
  const wordsIkm = gateIkm(opts.token || "", ltS);
  let bytes: Uint8Array;
  try {
    bytes = fromWords(helloModel(wordsIkm), helloWire);
  } catch {
    return fail("parse");
  }
  if (bytes.length < 32 + HELLO_MIN) fail("parse");
  const repC = bytes.slice(0, 32);
  const ct = bytes.subarray(32);
  // Noise NK es: gate_static_priv * client_eph_pub (from Elligator rep)
  const es = sharedFromRep(gateSeed, repC, true);
  const ikm = helloIkm(opts.token || "", es);
  let body: Uint8Array | null = null;
  let window = 0;
  for (const w of windowCandidates(opts.now ?? Date.now())) {
    const hk = hctr2Key(k(ikm, repC, `hello|${w}`));
    const pt = hctr2Decrypt(hk, tw("hello", w), ct);
    const ok = constantTimeEqual(pt.subarray(0, 16), k(ikm, new Uint8Array(0), `admit-c|${w}`, 16));
    if (ok && !body) {
      body = pt;
      window = w;
    }
  }
  if (!body) return fail("admit");
  let o = 16;
  const ltC = body.slice(o, (o += LT));
  const nonceC = body.slice(o, (o += 16));
  const kdfC = decodeKdf(body, o);
  o += 4;
  const features = body[o] & 0xff;
  let peerId: string | null = null;
  for (const peer of peers) {
    if (!peer.publicRawB64) continue;
    const pinned = unb64(peer.publicRawB64);
    if (pinned.length === LT && constantTimeEqual(pinned, ltC) && peerId === null) peerId = peer.id || "";
  }
  if (peerId === null) return fail("peer");
  try {
    claimHello(window, nonceC, { peer: peerId, ip: opts.sourceIp || "" });
  } catch {
    return fail("replay");
  }
  let ssS: Uint8Array;
  try {
    ssS = sharedFromPub(gateSeed, ltC, true);
  } catch {
    return fail("point");
  }
  const ephS = elligatorKeyPair();
  const ssE = sharedFromRep(ephS.seed, repC);
  const nonceS = rand(16);
  const agreed = clampKdf(opts.kdf ?? kdfC);
  const kdfBytes = encodeKdf(agreed);
  const derived = await deriveSessionKeyAsync(ssE, ssS, nonceC, nonceS, window, features, agreed);
  const sk = derived.key;
  const tr = transcript({ repC, repS: ephS.rep, ltC, ltS, window, nonceC, nonceS, kdf: kdfBytes, features });
  const confirmS = confirmS_(ssE, sk, tr);
  const seedS = rand(16);
  const ikmS = concat(ikm, ssE);
  const admitS = k(ikmS, new Uint8Array(0), `admit-s|${window}`, 16);
  const body2 = concat(admitS, nonceS, kdfBytes, new Uint8Array([features]), seedS, confirmS, rand(rand(1)[0] % 48));
  const hkS = hctr2Key(k(ikmS, ephS.rep, `server|${window}`));
  const wire = concat(ephS.rep, hctr2Encrypt(hkS, tw("server", window), body2));
  return {
    sk, window, ltC, peerId, nonceC, nonceS, kdf: agreed, features,
    serverWire: toWords(helloModel(wordsIkm), wire),
    ssE, seedS, tr,
  };
}

export async function edgeFinish3(edge: MeshNode, pending: EdgePending3, gatePubB64: string, serverWire: string) {
  const fails = (why: string): never => {
    throw new Error(`握手失败（${why}）`);
  };
  let bytes: Uint8Array;
  try {
    bytes = fromWords(helloModel(pending.wordsIkm), serverWire);
  } catch {
    return fails("回包无法解析");
  }
  if (bytes.length < 32 + SERVER_MIN) fails("回包太短");
  const repS = bytes.slice(0, 32);
  const ssE = sharedFromRep(pending.eph.seed, repS);
  const ikmS = concat(pending.ikm, ssE);
  const w = pending.window;
  const body = hctr2Decrypt(hctr2Key(k(ikmS, repS, `server|${w}`)), tw("server", w), bytes.subarray(32));
  if (!constantTimeEqual(body.subarray(0, 16), k(ikmS, new Uint8Array(0), `admit-s|${w}`, 16))) fails("闸门回包校验不过");
  let o = 16;
  const nonceS = body.slice(o, (o += 16));
  const kdfBytes = body.slice(o, o + 4);
  const kdf = decodeKdf(body, o);
  o += 4;
  const features = body[o++] & 0xff;
  const seedS = body.slice(o, (o += 16));
  const confirmS = body.slice(o, o + 16);
  const ltS = unb64(gatePubB64);
  const edgeSeed = x25519SeedFromJwk(edge.privateJwk);
  const ssS = sharedFromPub(edgeSeed, ltS);
  const t0 = Date.now();
  const derived = await deriveSessionKeyAsync(ssE, ssS, pending.nonceC, nonceS, w, features, kdf);
  const kdfMs = Date.now() - t0;
  const sk = derived.key;
  const tr = transcript({ repC: pending.eph.rep, repS, ltC: pending.ltRaw, ltS, window: w, nonceC: pending.nonceC, nonceS, kdf: kdfBytes, features });
  if (!constantTimeEqual(confirmS, confirmS_(ssE, sk, tr))) fails("密钥确认失败：会话密钥不一致");
  const seedC = rand(16);
  const mnemonicBase = mnemonicBaseOf(ssE, seedC, seedS);
  const keys = deriveV2Keys(sk, 0, mnemonicBase);
  const finishWire = sealFinish(ssE, sk, keys, w, seedC, confirmC_(mnemonicBase, tr));
  return { sk, window: w, kdf, features, kdfMs, finishWire, keys, mnemonicBase };
}

function sealFinish(ssE: Uint8Array, sk: Uint8Array, keys: V2Keys, window: number, seedC: Uint8Array, tag: Uint8Array) {
  return toWords(keys.model, hctr2Encrypt(finishKey(ssE, sk), tw("finish", window), concat(seedC, tag, rand(rand(1)[0] % 32))));
}

/** Verifies the finish; returns the session keys and the per-handshake mnemonic base. */
export function gateAccept3(pending: GatePending3, finishWire: string): { keys: V2Keys; mnemonicBase: Uint8Array } {
  const wordKeys = deriveV2Keys(pending.sk, 0); // the word model depends on sk only
  let bytes: Uint8Array;
  try {
    bytes = fromWords(wordKeys.model, finishWire);
  } catch {
    return fail("finish parse");
  }
  if (bytes.length < 32) fail("finish short");
  const pt = hctr2Decrypt(finishKey(pending.ssE, pending.sk), tw("finish", pending.window), bytes);
  const seedC = pt.slice(0, 16);
  const mnemonicBase = mnemonicBaseOf(pending.ssE, seedC, pending.seedS);
  if (!constantTimeEqual(pt.subarray(16, 32), confirmC_(mnemonicBase, pending.tr))) fail("finish");
  return { keys: deriveV2Keys(pending.sk, 0, mnemonicBase), mnemonicBase };
}

export { b64 };
