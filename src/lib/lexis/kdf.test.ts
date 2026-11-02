import assert from "node:assert/strict";
import { fromUtf8, randomBytes, utf8 } from "./bytes.ts";
import { createIdentity } from "./crypto.ts";
import { establish3 } from "./handshake.ts";
import { clampKdf, clampVaultKdf, deriveIdentity, VAULT_KDF } from "./kdf.ts";
import { packPayload, unpackPayload, ZSTD_TAG } from "./pack.ts";
import { FrameError, deriveV2Keys, openV2, openV2Honey, sealV2 } from "./v2/frame2.ts";
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
  assert.equal(a.publicRaw.length, 32);
  assert.equal(c.publicRaw.length, 32);

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
  const session = await establish3(edge, gate, Date.now(), { ...FAST, honey: true }, "v3-test-token-9f3a2c1b0e7d6a5c");
  assert.equal(session.kdf.memoryKiB, 32);
  assert.equal(session.honey, true);
  assert.ok(session.v2);
  if (!session.v2) throw new Error("no v2");
  assert.ok(session.kdfMs >= 0);

  const keys = session.v2;
  const prose = sealV2({
    keys,
    counter: 1,
    window: session.window,
    dir: "g2e",
    plaintext: packed.bytes,
    maxExpansion: 5,
  });
  assert.match(prose, /^[a-z]+(?: [a-z]+)*$/);
  const wire = utf8(prose);
  for (let i = 0; i < wire.length - 3; i++) {
    assert.ok(!(wire[i] === 0x28 && wire[i + 1] === 0xb5), "zstd magic leaked onto the wire");
  }
  const opened = openV2({ keys, counter: 1, window: session.window, dir: "g2e", prose });
  const unpacked = await unpackPayload(opened, false);
  assert.equal(fromUtf8(unpacked.data), fromUtf8(raw));

  const view = openV2Honey({
    keys: deriveV2Keys(randomBytes(32)),
    counter: 1,
    window: session.window,
    dir: "g2e",
    prose,
  });
  assert.equal(view.mnemonic.length, 16);
  assert.ok(view.body.length !== packed.bytes.length || Buffer.compare(view.body, packed.bytes) !== 0);
  assert.throws(
    () => openV2({ keys, counter: 2, window: session.window, dir: "g2e", prose }),
    (err: unknown) => err instanceof FrameError,
  );
  assert.throws(
    () => openV2({ keys, counter: 1, window: session.window + 1, dir: "g2e", prose }),
    (err: unknown) => err instanceof FrameError,
  );

  console.log("kdf ok");
}

await main();
