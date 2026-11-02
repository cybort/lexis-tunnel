import assert from "node:assert/strict";
import { fromUtf8, randomBytes, utf8 } from "./bytes.ts";
import { createIdentity } from "./crypto.ts";
import { establish } from "./handshake.ts";
import { clampKdf, clampVaultKdf, deriveIdentity, VAULT_KDF } from "./kdf.ts";
import { packPayload, unpackPayload, ZSTD_TAG } from "./pack.ts";
import { legacyKeyTag, open, peelTail, seal } from "./seal.ts";
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
  assert.equal(clamped.memoryKiB, 16384);
  assert.equal(clamped.iterations, 4);
  assert.equal(clamped.parallelism, 2);
  assert.equal(clampVaultKdf({ memoryKiB: 65536, iterations: 3, parallelism: 1 }).memoryKiB, 65536);
  assert.equal(clampVaultKdf(undefined).memoryKiB, VAULT_KDF.memoryKiB);
  assert.equal(clampKdf({ memoryKiB: 65536 }).memoryKiB, 16384);

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
  const tail = await peelTail({
    key: session.sk,
    inverse: session.inverse,
    window: session.window,
    direction: "g2e",
    prose,
  });
  const realLegacy = await legacyKeyTag(session.sk, "g2e", 1, packed.bytes);
  const wrongLegacy = await legacyKeyTag(randomBytes(32), "g2e", 1, packed.bytes);
  assert.ok(tail);
  assert.equal(tail.length, 16);
  const realMiss = Buffer.compare(tail, realLegacy) !== 0;
  const wrongMiss = Buffer.compare(tail, wrongLegacy) !== 0;
  assert.equal(realMiss, true);
  assert.equal(wrongMiss, true);
  assert.equal(realMiss, wrongMiss);

  const decoy = await open({
    key: randomBytes(32),
    inverse: new Map(),
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
      key: session.sk,
      inverse: new Map(),
      window: session.window,
      direction: "g2e",
      prose,
      lastSeen: 0,
      honey: false,
    }),
  );

  const replay = await open({
    key: session.sk,
    inverse: session.inverse,
    window: session.window,
    direction: "g2e",
    prose,
    lastSeen: opened.counter,
    honey: true,
  });
  assert.equal(replay.honey, true);
  assert.match(fromUtf8(replay.plaintext), /^the /);

  await assert.rejects(
    () =>
      open({
        key: session.sk,
        inverse: session.inverse,
        window: session.window,
        direction: "g2e",
        prose,
        lastSeen: opened.counter,
        honey: false,
      }),
    (err: unknown) => err instanceof Error && /回放/.test(err.message),
  );

  console.log("kdf ok");
}

await main();
