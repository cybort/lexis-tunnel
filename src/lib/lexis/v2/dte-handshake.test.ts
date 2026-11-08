// frame.dteCheck: frame.dte is bound into the key-confirmation transcript.
// on (default): every mismatched pair of bb-k-v4 / bb-c8-v4 / bb-v4 fails at edgeFinish3 (confirmS),
// and a forged finish under the other dte is a HandshakeDrop at the gate; matching pairs work.
// off: mismatched handshakes complete (old behaviour) and the data frames are what fail.
// Wire sizes are identical with the check on or off.
import assert from "node:assert/strict";
import { b64 } from "../bytes.ts";
import { createIdentity } from "../crypto.ts";
import { resetHandshakeGuards } from "../handshake.ts";
import type { MeshNode } from "../types.ts";
import { edgeFinish3, edgeStart3, gateAccept3, gateRespond3, HandshakeDrop, setDteCheck, getDteCheck } from "./handshake3.ts";
import { openV2, sealV2, setDefaultDte, getDefaultDte } from "./frame2.ts";

const FAST = { memoryKiB: 32, iterations: 1, parallelism: 1, honey: false };
async function makeNode(name: string, role: MeshNode["role"]): Promise<MeshNode> {
  const key = await createIdentity();
  return { id: crypto.randomUUID(), name, role, publicJwk: key.publicJwk, privateJwk: key.privateJwk, publicRawB64: b64(key.publicRaw), fingerprint: key.fingerprint, pinnedPeerId: null, createdAt: Date.now(), kdf: null };
}
resetHandshakeGuards();
assert.equal(getDteCheck(), true);
assert.equal(getDefaultDte(), "bb-k-v4");
const gate = await makeNode("g", "gate"), edge = await makeNode("e", "edge");
const peers = [{ id: "e1", publicRawB64: edge.publicRawB64 }];
const T = "dte-test-token-0123456789ab";
const D = ["bb-k-v4", "bb-c8-v4", "bb-v4"];
const msg = new TextEncoder().encode("dte handshake probe payload ".repeat(8));

type R = { edgeOk: boolean; gateOk: boolean; dataOk: boolean; sizes: number[] };
async function hs(ed: string, gd: string): Promise<R> {
  resetHandshakeGuards();
  const p = edgeStart3(edge, gate.publicRawB64, Date.now(), FAST, T);
  setDefaultDte(gd); const g = await gateRespond3(gate, peers, p.helloWire, { token: T, kdf: FAST });
  setDefaultDte(ed);
  const sizes = [p.helloWire.split(" ").length, g.serverWire.split(" ").length];
  let f;
  try { f = await edgeFinish3(edge, p, gate.publicRawB64, g.serverWire); } catch {
    // edge refuses confirmS and closes; the gate never receives a finish (its timeout path,
    // covered in src/agent/dte-silent.test.ts).
    setDefaultDte("bb-k-v4"); return { edgeOk: false, gateOk: false, dataOk: false, sizes };
  }
  sizes.push(f.finishWire.split(" ").length);
  setDefaultDte(gd);
  let acc;
  try { acc = gateAccept3(g, f.finishWire); } catch (e) { assert.ok(e instanceof HandshakeDrop); setDefaultDte("bb-k-v4"); return { edgeOk: true, gateOk: false, dataOk: false, sizes }; }
  let dataOk = true;
  for (let c = 1; c <= 4 && dataOk; c++) {
    setDefaultDte(ed); const e2g = sealV2({ keys: f.keys, counter: c, window: f.window, dir: "e2g", plaintext: msg });
    setDefaultDte(gd); const g2e = sealV2({ keys: acc.keys, counter: c, window: g.window, dir: "g2e", plaintext: msg });
    try { assert.deepEqual(openV2({ keys: acc.keys, counter: c, window: g.window, dir: "e2g", prose: e2g }), msg); assert.deepEqual(openV2({ keys: f.keys, counter: c, window: f.window, dir: "g2e", prose: g2e }), msg); } catch { dataOk = false; }
  }
  setDefaultDte("bb-k-v4");
  return { edgeOk: true, gateOk: true, dataOk, sizes };
}
const out: string[] = [];
for (const on of [true, false]) {
  setDteCheck(on);
  for (const ed of D) for (const gd of D) {
    const r = await hs(ed, gd);
    out.push(`check=${on ? "on" : "off"} edge=${ed} gate=${gd}: edgeConfirm=${r.edgeOk} gateAccept=${r.gateOk} data=${r.dataOk}`);
    if (ed === gd) assert.ok(r.edgeOk && r.gateOk && r.dataOk, `same dte ${ed} check=${on}`);
    else if (on) assert.ok(!r.edgeOk && !r.gateOk, `mismatch must fail in handshake ${ed}/${gd}`);
    else { assert.ok(r.edgeOk && r.gateOk, `check off: handshake completes ${ed}/${gd}`); assert.ok(!r.dataOk, `check off: data fails ${ed}/${gd}`); }
  }
}
setDteCheck(true);
// an edge with the check off still refuses confirmS from a check-on gate (different transcript)
{
  const p = edgeStart3(edge, gate.publicRawB64, Date.now(), FAST, T);
  const g = await gateRespond3(gate, peers, p.helloWire, { token: T, kdf: FAST }); // gate bb-k-v4, check on
  setDteCheck(false); setDefaultDte("bb-v4");
  let f; try { f = await edgeFinish3(edge, p, gate.publicRawB64, g.serverWire); } catch { f = null; }
  setDteCheck(true); setDefaultDte("bb-k-v4");
  assert.ok(f === null);
}
// mismatched check setting with the same dte also fails (both ends must agree on frame.dteCheck)
{
  const p = edgeStart3(edge, gate.publicRawB64, Date.now(), FAST, T);
  const g = await gateRespond3(gate, peers, p.helloWire, { token: T, kdf: FAST });
  setDteCheck(false); await assert.rejects(edgeFinish3(edge, p, gate.publicRawB64, g.serverWire)); setDteCheck(true);
}
console.log(out.join("\n"));
console.log("dte-handshake ok: 3 same-dte pairs pass, 6 mismatches fail in handshake (check on), complete+data fails (check off), check setting must match");
