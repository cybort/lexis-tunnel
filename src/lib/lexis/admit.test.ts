import assert from "node:assert/strict";
import { b64 } from "./bytes.ts";
import { createIdentity } from "./crypto.ts";
import { assertHelloWindow, claimHello, currentWindow, establish3, resetHandshakeGuards } from "./handshake.ts";
import { clampKdf } from "./kdf.ts";
import { SPEC } from "./spec.ts";
import type { MeshNode } from "./types.ts";
import { edgeStart3, gateRespond3, HandshakeDrop } from "./v2/handshake3.ts";

const FAST = { memoryKiB: 32, iterations: 1, parallelism: 1, honey: false };
const TOKEN = "v3-test-token-9f3a2c1b0e7d6a5c";

async function makeNode(name: string, role: MeshNode["role"]): Promise<MeshNode> {
  const key = await createIdentity();
  return {
    id: crypto.randomUUID(),
    name,
    role,
    publicJwk: key.publicJwk,
    privateJwk: key.privateJwk,
    publicRawB64: b64(key.publicRaw),
    fingerprint: key.fingerprint,
    pinnedPeerId: null,
    createdAt: Date.now(),
    kdf: null,
  };
}

async function main() {
  assert.equal(clampKdf({ memoryKiB: 65536, iterations: 9, parallelism: 4 }).memoryKiB, 16384);
  resetHandshakeGuards();
  const gate = await makeNode("闸门", "gate");
  const edge = await makeNode("内网", "edge");
  gate.pinnedPeerId = edge.id;
  edge.pinnedPeerId = gate.id;

  const live = await establish3(edge, gate, Date.now(), FAST, TOKEN);
  assert.equal(live.kdf.memoryKiB, 32);
  assert.ok(live.v2);
  assert.ok(!live.helloWire.includes(edge.publicRawB64));

  resetHandshakeGuards();
  const peers = [{ id: edge.id, publicRawB64: edge.publicRawB64 }];
  const heavy = { memoryKiB: 16384, iterations: 4, parallelism: 2 };
  const pending = edgeStart3(edge, gate.publicRawB64, Date.now(), { memoryKiB: 65536, iterations: 4, parallelism: 2, honey: false }, TOKEN);
  const responded = await gateRespond3(gate, peers, pending.helloWire, { token: TOKEN, kdf: FAST });
  assert.equal(responded.kdf.memoryKiB, 32);

  const badStarted = Date.now();
  await assert.rejects(
    () => gateRespond3(gate, peers, pending.helloWire, { token: "other-token-0123456789abcdef", kdf: heavy }),
    (err: unknown) => err instanceof HandshakeDrop,
  );
  assert.ok(Date.now() - badStarted < 2000, "坏口令或重放不应跑到重 Argon2");

  resetHandshakeGuards();
  const forged = edgeStart3(edge, gate.publicRawB64, Date.now(), FAST, "wrong-token-0123456789abcdef");
  const t0 = Date.now();
  await assert.rejects(
    () => gateRespond3(gate, peers, forged.helloWire, { token: TOKEN, kdf: heavy }),
    (err: unknown) => err instanceof HandshakeDrop,
  );
  assert.ok(Date.now() - t0 < 2000, "口令不对必须在派生之前拒绝");

  resetHandshakeGuards();
  const once = edgeStart3(edge, gate.publicRawB64, Date.now(), FAST, TOKEN);
  await gateRespond3(gate, peers, once.helloWire, { token: TOKEN, kdf: FAST });
  await assert.rejects(
    () => gateRespond3(gate, peers, once.helloWire, { token: TOKEN, kdf: FAST }),
    (err: unknown) => err instanceof HandshakeDrop,
  );

  const stale = edgeStart3(edge, gate.publicRawB64, Date.now() - 600_000, FAST, TOKEN);
  await assert.rejects(
    () => gateRespond3(gate, peers, stale.helloWire, { token: TOKEN, kdf: FAST, now: Date.now() }),
    (err: unknown) => err instanceof HandshakeDrop,
  );

  assert.throws(() => assertHelloWindow(currentWindow() - 3), /过期/);
  const skewNow = currentWindow() * SPEC.windowSec * 1000;
  const skewId = currentWindow(skewNow);
  assert.doesNotThrow(() => assertHelloWindow(skewId, skewNow + 1000));
  assert.doesNotThrow(() => assertHelloWindow(skewId - 1, skewNow + (SPEC.skewSec - 1) * 1000));
  assert.throws(() => assertHelloWindow(skewId - 1, skewNow + (SPEC.skewSec + 1) * 1000), /过期/);
  assert.doesNotThrow(() => assertHelloWindow(skewId + 1, skewNow + (SPEC.windowSec - 30) * 1000));
  assert.throws(() => assertHelloWindow(skewId + 1, skewNow + 150 * 1000), /过期/);
  resetHandshakeGuards();
  const nonce = crypto.getRandomValues(new Uint8Array(16));
  claimHello(currentWindow(), nonce);
  assert.throws(() => claimHello(currentWindow(), nonce), /重放/);
  resetHandshakeGuards();
  const win = currentWindow();
  for (let i = 0; i < 16; i += 1) {
    const n = new Uint8Array(16);
    n[0] = i + 1;
    claimHello(win, n, { peer: "node-a" });
  }
  const crowded = new Uint8Array(16);
  crowded[0] = 200;
  assert.throws(() => claimHello(win, crowded, { peer: "node-a" }), /节点的握手太密/);
  const otherPeer = new Uint8Array(16);
  otherPeer[0] = 201;
  claimHello(win, otherPeer, { peer: "node-b" });
  for (let i = 0; i < 32; i += 1) {
    const n = new Uint8Array(16);
    n[1] = i + 1;
    claimHello(win, n, { ip: "203.0.113.9" });
  }
  const crowdedIp = new Uint8Array(16);
  crowdedIp[1] = 200;
  assert.throws(() => claimHello(win, crowdedIp, { ip: "203.0.113.9" }), /地址的握手太密/);
  console.log("admit ok");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
