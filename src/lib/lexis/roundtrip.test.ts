import assert from "node:assert/strict";
import { fromUtf8, utf8 } from "./bytes";
import { decodeStatic, encodeStatic } from "./codec";
import { shannonEntropy } from "./entropy";
import { establish } from "./handshake";
import { LexisError } from "./crypto";
import { sessionLexicon } from "./lexicon";
import { decodeRecord, encodeRecord, RECORD } from "./records";
import { open, seal } from "./seal";
import { b64 } from "./bytes";
import { createIdentity } from "./crypto";
import { SPEC } from "./spec";
import type { MeshNode } from "./types";

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
  };
}

async function main() {
  const blob = crypto.getRandomValues(new Uint8Array(180));
  const wire = await encodeStatic(blob);
  const back = await decodeStatic(wire);
  assert.deepEqual(back, blob);
  const wireH = shannonEntropy(utf8(wire));
  assert.ok(wireH < 5.3, `static wire entropy ${wireH}`);

  const gate = await makeNode("闸门", "gate");
  const edge = await makeNode("内网", "edge");
  gate.pinnedPeerId = edge.id;
  edge.pinnedPeerId = gate.id;

  const t0 = Date.now();
  const session = await establish(edge, gate);
  const elapsed = Date.now() - t0;
  console.log("handshake+lexicon ms", elapsed);
  assert.equal(session.lexicon.length, SPEC.lexiconSize);
  assert.equal(session.inverse.size, SPEC.lexiconSize);

  const other = await sessionLexicon(session.sk, session.window + 1);
  assert.notDeepEqual(session.lexicon.slice(0, 12), other.slice(0, 12));

  const http = utf8("GET /health HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n");
  const frame = encodeRecord(RECORD.data, 7, 1, http);
  const prose = await seal({
    key: session.sk,
    lexicon: session.lexicon,
    counter: 1,
    window: session.window,
    direction: "g2e",
    plaintext: frame,
  });
  const h = shannonEntropy(utf8(prose));
  const rnd = shannonEntropy(crypto.getRandomValues(new Uint8Array(utf8(prose).length)));
  console.log("data entropy", h.toFixed(3), "random", rnd.toFixed(3), "chars", prose.length);
  assert.ok(h < 5.2, `data entropy ${h}`);
  assert.ok(rnd > 7.2, `random entropy ${rnd}`);
  assert.ok(!prose.includes("\u0000"));
  assert.match(prose, /^[a-z .]+$/);

  const opened = await open({
    key: session.sk,
    inverse: session.inverse,
    window: session.window,
    direction: "g2e",
    prose,
    lastSeen: 0,
  });
  assert.equal(opened.counter, 1);
  const rec = decodeRecord(opened.plaintext);
  assert.equal(rec.conn, 7);
  assert.equal(fromUtf8(rec.payload), fromUtf8(http));

  await assert.rejects(
    () =>
      open({
        key: session.sk,
        inverse: session.inverse,
        window: session.window,
        direction: "g2e",
        prose,
        lastSeen: 1,
      }),
    (err: unknown) => err instanceof LexisError && /回放/.test(err.message),
  );

  const badLex = new Map<string, number>();
  other.forEach((w, i) => badLex.set(w, i));
  await assert.rejects(() =>
    open({
      key: session.sk,
      inverse: badLex,
      window: session.window + 1,
      direction: "g2e",
      prose,
      lastSeen: 0,
    }),
  );

  const flipped = prose.replace(/ [a-z]{3,} /, " zzznotaword ");
  await assert.rejects(() =>
    open({
      key: session.sk,
      inverse: session.inverse,
      window: session.window,
      direction: "g2e",
      prose: flipped,
      lastSeen: 0,
    }),
  );

  const stranger = await makeNode("旁人", "edge");
  stranger.pinnedPeerId = gate.id;
  await assert.rejects(() => establish(stranger, gate), (err: unknown) => err instanceof LexisError);

  console.log("lexis roundtrip ok");
}

await main();
