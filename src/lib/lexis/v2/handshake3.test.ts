import assert from "node:assert/strict";
import { b64 } from "../bytes.ts";
import { createIdentity } from "../crypto.ts";
import { resetHandshakeGuards } from "../handshake.ts";
import type { MeshNode } from "../types.ts";
import { edgeFinish3, edgeStart3, gateAccept3, gateRespond3, HandshakeDrop } from "./handshake3.ts";
import { openV2, sealV2 } from "./frame2.ts";

const FAST = { memoryKiB: 32, iterations: 1, parallelism: 1, honey: false };
async function makeNode(name: string, role: MeshNode["role"]): Promise<MeshNode> {
  const key = await createIdentity();
  return { id: crypto.randomUUID(), name, role, publicJwk: key.publicJwk, privateJwk: key.privateJwk, publicRawB64: b64(key.publicRaw), fingerprint: key.fingerprint, pinnedPeerId: null, createdAt: Date.now(), kdf: null };
}
const drop = async (p: Promise<unknown>) => assert.rejects(p, (e) => e instanceof HandshakeDrop);

resetHandshakeGuards();
const gate = await makeNode("g", "gate");
const edge = await makeNode("e", "edge");
const other = await makeNode("x", "edge");
const peers = [{ id: "e1", publicRawB64: edge.publicRawB64 }];
const T = "v3-test-token-9f3a2c1b0e7d6a5c";

const p = edgeStart3(edge, gate.publicRawB64, Date.now(), FAST, T);
assert.ok(!p.helloWire.includes(edge.publicRawB64));
const g = await gateRespond3(gate, peers, p.helloWire, { token: T, kdf: FAST });
assert.equal(g.peerId, "e1");
const f = await edgeFinish3(edge, p, gate.publicRawB64, g.serverWire);
assert.deepEqual(f.sk, g.sk);
const { keys, mnemonicBase } = gateAccept3(g, f.finishWire);
assert.deepEqual(mnemonicBase, f.mnemonicBase);
assert.deepEqual(keys.mnemonic, f.keys.mnemonic);
const msg = new TextEncoder().encode("hello over v3");
assert.deepEqual(openV2({ keys, counter: 1, window: g.window, dir: "e2g", prose: sealV2({ keys: f.keys, counter: 1, window: f.window, dir: "e2g", plaintext: msg }) }), msg);

// replay of the same hello
await drop(gateRespond3(gate, peers, p.helloWire, { token: T, kdf: FAST }));
// wrong token, unknown peer, garbage, truncated: all the same HandshakeDrop
await drop(gateRespond3(gate, peers, edgeStart3(edge, gate.publicRawB64, Date.now(), FAST, "wrong-token-xx").helloWire, { token: T, kdf: FAST }));
await drop(gateRespond3(gate, peers, edgeStart3(other, gate.publicRawB64, Date.now(), FAST, T).helloWire, { token: T, kdf: FAST }));
await drop(gateRespond3(gate, peers, "the of and to a in is it you that", { token: T, kdf: FAST }));
await drop(gateRespond3(gate, peers, "zzzzqqq notaword", { token: T, kdf: FAST }));
const h2 = edgeStart3(edge, gate.publicRawB64, Date.now(), FAST, T).helloWire.split(" ");
await drop(gateRespond3(gate, peers, h2.slice(0, h2.length - 3).join(" "), { token: T, kdf: FAST }));
// MITM swaps the server reply for another session's: edge rejects (key confirmation)
const pa = edgeStart3(edge, gate.publicRawB64, Date.now(), FAST, T);
const pb = edgeStart3(edge, gate.publicRawB64, Date.now(), FAST, T);
const gb = await gateRespond3(gate, peers, pb.helloWire, { token: T, kdf: FAST });
await assert.rejects(edgeFinish3(edge, pa, gate.publicRawB64, gb.serverWire), /握手失败/);
// tampered finish
const fb = await edgeFinish3(edge, pb, gate.publicRawB64, gb.serverWire);
const fw = fb.finishWire.split(" ");
fw[0] = fw[0] === "the" ? "and" : "the";
assert.throws(() => gateAccept3(gb, fw.join(" ")), (e) => e instanceof HandshakeDrop);
console.log("handshake3 ok: roundtrip, ltRaw not in clear, replay/wrong-token/unknown-peer/garbage/truncated -> HandshakeDrop, reply swap + tampered finish rejected");
