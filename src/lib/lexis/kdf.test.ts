import assert from "node:assert/strict";
import { fromUtf8, randomBytes, utf8 } from "./bytes.ts";
import { createIdentity } from "./crypto.ts";
import { establish } from "./handshake.ts";
import { clampKdf, deriveIdentity } from "./kdf.ts";
import { packPayload, unpackPayload, ZSTD_TAG } from "./pack.ts";
import { open, seal } from "./seal.ts";
import { b64 } from "./bytes.ts";
import type { MeshNode } from "./types.ts";

const FAST = { memoryKiB: 32, iterations: 1, parallelism: 1 };

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
  const clamped = clampKdf({ memoryKiB: 999999, iterations: 9, parallelism: 4 });
  assert.equal(clamped.memoryKiB, 65536);
  assert.equal(clamped.iterations, 4);
  assert.equal(clamped.parallelism, 2);

  const salt = randomBytes(16);
  const a = await deriveIdentity("口令", salt, FAST);
  const b = await deriveIdentity("口令", salt, FAST);
  const c = await deriveIdentity("另一句", salt, FAST);
  assert.equal(a.fingerprint, b.fingerprint);
  assert.notEqual(a.fingerprint, c.fingerprint);
  assert.equal(a.publicRaw.length, 65);
  assert.equal(a.publicRaw[0], 0x04);
  assert.equal(c.publicRaw[0], 0x04);

  const raw = utf8("hello ".repeat(40));
  const packed = await packPayload(raw, { enabled: true, level: 3 });
  assert.equal(packed.compressed, true);
  assert.equal(packed.bytes[0], ZSTD_TAG);
  assert.equal(packed.bytes[1], 0x28);
  assert.equal(packed.bytes[2], 0xb5);
  const back = await unpackPayload(packed.bytes, false);
  assert.equal(back.compressed, true);
  assert.equal(fromUtf8(back.data), fromUtf8(raw));

  const tiny = await packPayload(utf8("hi"), { enabled: true, level: 3 });
  assert.equal(tiny.compressed, false);
  assert.equal(tiny.bytes[0], 0);

  const gate = await makeNode("闸门", "gate");
  const edge = await makeNode("内网", "edge");
  gate.pinnedPeerId = edge.id;
  edge.pinnedPeerId = gate.id;
  const session = await establish(edge, gate, Date.now(), { ...FAST, honey: true });
  assert.equal(session.kdf.memoryKiB, 32);
  assert.equal(session.honey, true);
  assert.ok(session.kdfMs >= 1);

  const prose = await seal({
    key: session.sk,
    lexicon: session.lexicon,
    counter: 1,
    window: session.window,
    direction: "g2e",
    plaintext: packed.bytes,
  });
  assert.match(prose, /^[a-z .]+$/);
  const wire = utf8(prose);
  for (let i = 0; i < wire.length - 3; i++) {
    assert.ok(!(wire[i] === 0x28 && wire[i + 1] === 0xb5), "zstd magic leaked onto the wire");
  }
  const opened = await open({
    key: session.sk,
    inverse: session.inverse,
    window: session.window,
    direction: "g2e",
    prose,
    lastSeen: 0,
    honey: true,
  });
  assert.equal(opened.honey, false);
  const unpacked = await unpackPayload(opened.plaintext, false);
  assert.equal(fromUtf8(unpacked.data), fromUtf8(raw));

  const decoy = await open({
    key: randomBytes(32),
    inverse: session.inverse,
    window: session.window,
    direction: "g2e",
    prose,
    lastSeen: 0,
    honey: true,
  });
  assert.equal(decoy.honey, true);
  assert.match(fromUtf8(decoy.plaintext), /^the /);
  assert.notEqual(fromUtf8(decoy.plaintext), fromUtf8(raw));

  await assert.rejects(() =>
    open({
      key: randomBytes(32),
      inverse: session.inverse,
      window: session.window,
      direction: "g2e",
      prose,
      lastSeen: 0,
      honey: false,
    }),
  );

  await assert.rejects(
    () =>
      open({
        key: session.sk,
        inverse: session.inverse,
        window: session.window,
        direction: "g2e",
        prose,
        lastSeen: opened.counter,
        honey: true,
      }),
    (err: unknown) => err instanceof Error && /回放/.test(err.message),
  );

  console.log("kdf ok");
}

await main();
