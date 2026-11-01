import { b64, concat, timingSafeEqual, u32be, unb64, utf8 } from "./bytes";
import { decodeStatic, encodeStatic } from "./codec";
import {
  assertPoint,
  createIdentity,
  ecdh,
  fingerprintOf,
  hmac,
  importPrivateJwk,
  importRawPublic,
  LexisError,
  type KeyMaterial,
} from "./crypto";
import {
  clampKdf,
  clampOffer,
  decodeKdf,
  deriveSessionKeyAsync,
  encodeKdf,
  featureByte,
  honeyFromFeatures,
  type ArgonParams,
  type SessionOffer,
} from "./kdf";
import { invertLexicon, sessionLexicon } from "./lexicon";
import { SPEC } from "./spec";
import type { MeshNode } from "./types";

export type Direction = "e2g" | "g2e";

export type LiveSession = {
  sk: Uint8Array;
  skFp: string;
  window: number;
  lexicon: string[];
  inverse: Map<string, number>;
  counters: { e2g: number; g2e: number };
  seen: { e2g: number; g2e: number };
  helloWire: string;
  serverWire: string;
  finishWire: string;
  edgeName: string;
  gateName: string;
  edgeFp: string;
  gateFp: string;
  kdf: ArgonParams;
  honey: boolean;
  kdfMs: number;
};

export type EdgePending = {
  eph: KeyMaterial;
  nonceC: Uint8Array;
  window: number;
  helloWire: string;
  ltRaw: Uint8Array;
};

export type GatePending = {
  sk: Uint8Array;
  window: number;
  ephC: Uint8Array;
  ephS: Uint8Array;
  ltC: Uint8Array;
  ltS: Uint8Array;
  nonceC: Uint8Array;
  nonceS: Uint8Array;
  serverWire: string;
  expectFinish: Uint8Array;
  kdf: ArgonParams;
  features: number;
};

export function currentWindow(now = Date.now()): number {
  return Math.floor(now / 1000 / SPEC.windowSec);
}

export function windowRemain(now = Date.now()): number {
  const sec = Math.floor(now / 1000);
  return SPEC.windowSec - (sec % SPEC.windowSec);
}

const HELLO_CORE = 2 + 65 + 65 + 4 + 16 + 4 + 1;
const SERVER_CORE = 2 + 65 + 65 + 16 + 16 + 4 + 1;
const seenHellos = new Map<number, Set<string>>();

export function resetHandshakeGuards() {
  seenHellos.clear();
}

/** Current window, plus the previous one only in the first 20 seconds (clock skew). */
export function assertHelloWindow(helloWindow: number, now = Date.now()) {
  const current = currentWindow(now);
  const into = Math.floor(now / 1000) % SPEC.windowSec;
  const ok = helloWindow === current || (helloWindow === current - 1 && into < 20);
  if (!ok) throw new LexisError("握手时间窗已经过期");
}

function nonceId(nonce: Uint8Array): string {
  let hex = "";
  for (const b of nonce) hex += b.toString(16).padStart(2, "0");
  return hex;
}

export function claimHello(window: number, nonce: Uint8Array) {
  for (const key of [...seenHellos.keys()]) {
    if (key < window - 1) seenHellos.delete(key);
  }
  let bag = seenHellos.get(window);
  if (!bag) {
    bag = new Set();
    seenHellos.set(window, bag);
  }
  const id = nonceId(nonce);
  if (bag.has(id)) throw new LexisError("握手被重放");
  if (bag.size >= 4096) throw new LexisError("这个时间窗的握手太多");
  bag.add(id);
}

async function tokenMac(token: string, body: Uint8Array): Promise<Uint8Array> {
  return (await hmac(utf8(token), concat(utf8("lexis-admit-v1"), body))).subarray(0, 16);
}

export type AdmitOpts = {
  token?: string;
  /** Gate's own Argon2 parameters. The client's offer cannot raise this cost. */
  kdf?: ArgonParams;
  now?: number;
};

function transcript(parts: {
  ephC: Uint8Array;
  ephS: Uint8Array;
  ltC: Uint8Array;
  ltS: Uint8Array;
  window: number;
  nonceC: Uint8Array;
  nonceS: Uint8Array;
  kdf: Uint8Array;
  features: number;
}): Uint8Array {
  return concat(
    utf8("LEXIS2"),
    parts.ephC,
    parts.ephS,
    parts.ltC,
    parts.ltS,
    u32be(parts.window),
    parts.nonceC,
    parts.nonceS,
    parts.kdf,
    new Uint8Array([parts.features & 0xff]),
  );
}

export async function edgeStart(
  edge: MeshNode,
  now = Date.now(),
  offer?: Partial<SessionOffer>,
  token = "",
): Promise<EdgePending> {
  const wanted = clampOffer(offer);
  const eph = await createIdentity();
  const ltRaw = unb64(edge.publicRawB64);
  assertPoint(ltRaw, "内网端");
  assertPoint(eph.publicRaw, "内网端临时");
  const nonceC = crypto.getRandomValues(new Uint8Array(16));
  const window = currentWindow(now);
  let blob = concat(
    new Uint8Array([1, 1]),
    eph.publicRaw,
    ltRaw,
    u32be(window),
    nonceC,
    encodeKdf(wanted),
    new Uint8Array([featureByte(wanted.honey)]),
  );
  if (token) blob = concat(blob, await tokenMac(token, blob));
  const helloWire = await encodeStatic(blob);
  return { eph, nonceC, window, helloWire, ltRaw };
}

function parseHello(buf: Uint8Array) {
  if (buf.length !== HELLO_CORE && buf.length !== HELLO_CORE + 16) throw new LexisError("客户端问候长度不对");
  if (buf[0] !== 1 || buf[1] !== 1) throw new LexisError("客户端问候版本不对");
  const mac = buf.length === HELLO_CORE + 16 ? buf.slice(HELLO_CORE) : null;
  const ephRaw = buf.slice(2, 67);
  const ltRaw = buf.slice(67, 132);
  const window = (buf[132] << 24) | (buf[133] << 16) | (buf[134] << 8) | buf[135];
  const nonce = buf.slice(136, 152);
  const kdf = decodeKdf(buf, 152);
  const features = buf[156];
  assertPoint(ephRaw, "对端临时");
  assertPoint(ltRaw, "对端长期");
  return { ephRaw, ltRaw, window: window >>> 0, nonce, kdf, features, mac };
}

function parseServer(buf: Uint8Array) {
  if (buf.length !== SERVER_CORE && buf.length !== SERVER_CORE + 16) throw new LexisError("服务端问候长度不对");
  if (buf[0] !== 1 || buf[1] !== 2) throw new LexisError("服务端问候版本不对");
  const mac = buf.length === SERVER_CORE + 16 ? buf.slice(SERVER_CORE) : null;
  const ephRaw = buf.slice(2, 67);
  const ltRaw = buf.slice(67, 132);
  const nonce = buf.slice(132, 148);
  const confirm = buf.slice(148, 164);
  const kdf = decodeKdf(buf, 164);
  const features = buf[168];
  assertPoint(ephRaw, "闸门临时");
  assertPoint(ltRaw, "闸门长期");
  return { ephRaw, ltRaw, nonce, confirm, kdf, features, mac };
}

export async function gateRespond(
  gate: MeshNode,
  peerRawB64: string,
  helloWire: string,
  opts: AdmitOpts = {},
): Promise<GatePending> {
  const raw = await decodeStatic(helloWire);
  const hello = parseHello(raw);
  assertHelloWindow(hello.window, opts.now ?? Date.now());
  const token = opts.token || "";
  if (token) {
    if (!hello.mac) throw new LexisError("缺少握手口令");
    const expect = await tokenMac(token, raw.slice(0, HELLO_CORE));
    if (!timingSafeEqual(expect, hello.mac)) throw new LexisError("握手口令不对");
  } else if (hello.mac) {
    throw new LexisError("对端带了口令，这边没有");
  }
  const pinned = unb64(peerRawB64);
  if (!timingSafeEqual(hello.ltRaw, pinned)) {
    throw new LexisError("内网端长期公钥和闸门上的绑定不一致");
  }
  claimHello(hello.window, hello.nonce);
  const ephS = await createIdentity();
  const ltS = unb64(gate.publicRawB64);
  const nonceS = crypto.getRandomValues(new Uint8Array(16));
  const ssE = await ecdh(await importPrivateJwk(ephS.privateJwk), await importRawPublic(hello.ephRaw));
  const ssS = await ecdh(await importPrivateJwk(gate.privateJwk), await importRawPublic(hello.ltRaw));
  const agreed = clampKdf(opts.kdf ?? hello.kdf);
  const kdfBytes = encodeKdf(agreed);
  const features = hello.features & 0xff;
  const derived = await deriveSessionKeyAsync(ssE, ssS, hello.nonce, nonceS, hello.window, features, agreed);
  const sk = derived.key;
  const tr = transcript({
    ephC: hello.ephRaw,
    ephS: ephS.publicRaw,
    ltC: hello.ltRaw,
    ltS,
    window: hello.window,
    nonceC: hello.nonce,
    nonceS,
    kdf: kdfBytes,
    features,
  });
  const confirmS = (await hmac(sk, concat(utf8("lexis-srv-v1"), tr))).subarray(0, 16);
  const expectFinish = (await hmac(sk, concat(utf8("lexis-cli-v1"), tr))).subarray(0, 16);
  let blob = concat(new Uint8Array([1, 2]), ephS.publicRaw, ltS, nonceS, confirmS, kdfBytes, new Uint8Array([features]));
  if (token) blob = concat(blob, await tokenMac(token, blob));
  const serverWire = await encodeStatic(blob);
  return {
    sk,
    window: hello.window,
    ephC: hello.ephRaw,
    ephS: ephS.publicRaw,
    ltC: hello.ltRaw,
    ltS,
    nonceC: hello.nonce,
    nonceS,
    serverWire,
    expectFinish,
    kdf: agreed,
    features,
  };
}

export async function edgeFinish(
  edge: MeshNode,
  pending: EdgePending,
  gateRawB64: string,
  serverWire: string,
  token = "",
): Promise<{ sk: Uint8Array; finishWire: string; window: number; kdf: ArgonParams; honey: boolean; kdfMs: number }> {
  const raw = await decodeStatic(serverWire);
  const server = parseServer(raw);
  const pinned = unb64(gateRawB64);
  if (!timingSafeEqual(server.ltRaw, pinned)) {
    throw new LexisError("闸门长期公钥和内网端上的绑定不一致");
  }
  if (token) {
    if (!server.mac) throw new LexisError("闸门没有带回口令");
    const expectMac = await tokenMac(token, raw.slice(0, SERVER_CORE));
    if (!timingSafeEqual(expectMac, server.mac)) throw new LexisError("握手口令不对");
  } else if (server.mac) {
    throw new LexisError("对端带了口令，这边没有");
  }
  const ssE = await ecdh(
    await importPrivateJwk(pending.eph.privateJwk),
    await importRawPublic(server.ephRaw),
  );
  const ssS = await ecdh(
    await importPrivateJwk(edge.privateJwk),
    await importRawPublic(server.ltRaw),
  );
  const features = server.features & 0xff;
  const derived = await deriveSessionKeyAsync(ssE, ssS, pending.nonceC, server.nonce, pending.window, features, server.kdf);
  const sk = derived.key;
  const tr = transcript({
    ephC: pending.eph.publicRaw,
    ephS: server.ephRaw,
    ltC: pending.ltRaw,
    ltS: server.ltRaw,
    window: pending.window,
    nonceC: pending.nonceC,
    nonceS: server.nonce,
    kdf: encodeKdf(server.kdf),
    features,
  });
  const expectS = (await hmac(sk, concat(utf8("lexis-srv-v1"), tr))).subarray(0, 16);
  if (!timingSafeEqual(expectS, server.confirm)) {
    throw new LexisError("闸门确认标记对不上，会话密钥没有对齐");
  }
  const confirmC = (await hmac(sk, concat(utf8("lexis-cli-v1"), tr))).subarray(0, 16);
  const finishWire = await encodeStatic(concat(new Uint8Array([1, 3]), confirmC));
  return {
    sk,
    finishWire,
    window: pending.window,
    kdf: server.kdf,
    honey: honeyFromFeatures(features),
    kdfMs: derived.ms,
  };
}

export async function gateAccept(pending: GatePending, finishWire: string): Promise<void> {
  const buf = await decodeStatic(finishWire);
  if (buf.length !== 18 || buf[0] !== 1 || buf[1] !== 3) throw new LexisError("结束握手的报文不对");
  const confirm = buf.slice(2);
  if (!timingSafeEqual(confirm, pending.expectFinish)) {
    throw new LexisError("内网端确认标记对不上");
  }
}

export async function openSession(opts: {
  edge: MeshNode;
  gate: MeshNode;
  sk: Uint8Array;
  window: number;
  helloWire: string;
  serverWire: string;
  finishWire: string;
  kdf: ArgonParams;
  honey: boolean;
  kdfMs: number;
}): Promise<LiveSession> {
  const lexicon = await sessionLexicon(opts.sk, opts.window);
  const inverse = invertLexicon(lexicon);
  const skFp = await fingerprintOf(opts.sk);
  return {
    sk: opts.sk,
    skFp,
    window: opts.window,
    lexicon,
    inverse,
    counters: { e2g: 0, g2e: 0 },
    seen: { e2g: 0, g2e: 0 },
    helloWire: opts.helloWire,
    serverWire: opts.serverWire,
    finishWire: opts.finishWire,
    edgeName: opts.edge.name,
    gateName: opts.gate.name,
    edgeFp: opts.edge.fingerprint,
    gateFp: opts.gate.fingerprint,
    kdf: opts.kdf,
    honey: opts.honey,
    kdfMs: opts.kdfMs,
  };
}

/** Both roles, in order. The browser lab runs this; a real split process would run each step on its host. */
export async function establish(
  edge: MeshNode,
  gate: MeshNode,
  now = Date.now(),
  offer?: Partial<SessionOffer>,
): Promise<LiveSession> {
  if (edge.role !== "edge" || gate.role !== "gate") {
    throw new LexisError("需要一个内网端和一个公网闸门");
  }
  if (edge.pinnedPeerId !== gate.id || gate.pinnedPeerId !== edge.id) {
    throw new LexisError("两端还没有互相绑定");
  }
  const started = await edgeStart(edge, now, offer);
  const responded = await gateRespond(gate, edge.publicRawB64, started.helloWire);
  const finished = await edgeFinish(edge, started, gate.publicRawB64, responded.serverWire);
  await gateAccept(responded, finished.finishWire);
  if (!timingSafeEqual(finished.sk, responded.sk)) {
    throw new LexisError("两端会话密钥不一致");
  }
  return openSession({
    edge,
    gate,
    sk: finished.sk,
    window: finished.window,
    helloWire: started.helloWire,
    serverWire: responded.serverWire,
    finishWire: finished.finishWire,
    kdf: finished.kdf,
    honey: finished.honey,
    kdfMs: finished.kdfMs,
  });
}
