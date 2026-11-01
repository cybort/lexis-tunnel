import assert from "node:assert/strict";
import { b64 } from "./bytes.ts";
import { createIdentity, LexisError } from "./crypto.ts";
import { assertHelloWindow, claimHello, currentWindow, edgeFinish, edgeStart, establish, gateRespond, resetHandshakeGuards } from "./handshake.ts";
import { clampKdf } from "./kdf.ts";
import type { MeshNode } from "./types.ts";

const FAST = { memoryKiB: 32, iterations: 1, parallelism: 1, honey: false };
const TOKEN = "token-12345678";

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

  const live = await establish(edge, gate, Date.now(), FAST);
  assert.equal(live.kdf.memoryKiB, 32);
  assert.ok(!live.helloWire.includes(TOKEN));

  resetHandshakeGuards();
  const pending = await edgeStart(edge, Date.now(), { memoryKiB: 65536, iterations: 4, parallelism: 2 }, TOKEN);
  const responded = await gateRespond(gate, edge.publicRawB64, pending.helloWire, { token: TOKEN, kdf: FAST });
  assert.equal(responded.kdf.memoryKiB, 32);
  const finished = await edgeFinish(edge, pending, gate.publicRawB64, responded.serverWire, TOKEN);
  assert.equal(finished.kdf.memoryKiB, 32);

  const badStarted = Date.now();
  await assert.rejects(
    () => gateRespond(gate, edge.publicRawB64, pending.helloWire, { token: "other-token-99", kdf: { memoryKiB: 16384, iterations: 4, parallelism: 2 } }),
    (err: unknown) => err instanceof LexisError && /重放|口令/.test((err as Error).message),
  );
  assert.ok(Date.now() - badStarted < 400, "坏口令或重放不应跑到重 Argon2");

  resetHandshakeGuards();
  const forged = await edgeStart(edge, Date.now(), FAST, "wrong-token-xx");
  const t0 = Date.now();
  await assert.rejects(
    () => gateRespond(gate, edge.publicRawB64, forged.helloWire, { token: TOKEN, kdf: { memoryKiB: 16384, iterations: 4, parallelism: 2 } }),
    (err: unknown) => err instanceof LexisError && (err as Error).message.includes("口令"),
  );
  assert.ok(Date.now() - t0 < 200, "口令不对必须在派生之前拒绝");

  resetHandshakeGuards();
  const once = await edgeStart(edge, Date.now(), FAST, TOKEN);
  await gateRespond(gate, edge.publicRawB64, once.helloWire, { token: TOKEN, kdf: FAST });
  await assert.rejects(
    () => gateRespond(gate, edge.publicRawB64, once.helloWire, { token: TOKEN, kdf: FAST }),
    (err: unknown) => err instanceof LexisError && (err as Error).message.includes("重放"),
  );

  const stale = await edgeStart(edge, Date.now() - 600_000, FAST, TOKEN);
  await assert.rejects(
    () => gateRespond(gate, edge.publicRawB64, stale.helloWire, { token: TOKEN, kdf: FAST, now: Date.now() }),
    (err: unknown) => err instanceof LexisError && (err as Error).message.includes("过期"),
  );

  assert.throws(() => assertHelloWindow(currentWindow() - 3), /过期/);
  resetHandshakeGuards();
  const nonce = crypto.getRandomValues(new Uint8Array(16));
  claimHello(currentWindow(), nonce);
  assert.throws(() => claimHello(currentWindow(), nonce), /重放/);
  console.log("admit ok");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
