/* frame.dteCheck at the agent layer: a gate whose frame.dte differs from the edge's (within the 4.0
 * values, same hello model) writes exactly what it writes for any valid hello (one server reply), then behaves like every other failed
 * handshake: no further byte, half-open slot released early, connection held silent until the
 * handshake deadline. The edge rejects with the key-confirmation error. */
import assert from "node:assert/strict";
import { acceptSession, connectSession, halfOpen, setFrameOptions, type ProsePipe } from "./frame.ts";
import { createIdentity } from "../lib/lexis/crypto.ts";
import { b64 } from "../lib/lexis/bytes.ts";
import { resetHandshakeGuards } from "../lib/lexis/handshake.ts";

const node = async (role: string) => { const k = await createIdentity(); return { id: crypto.randomUUID(), name: role, role, publicJwk: k.publicJwk, privateJwk: k.privateJwk, publicRawB64: b64(k.publicRaw), fingerprint: k.fingerprint, pinnedPeerId: null, createdAt: Date.now(), kdf: null } as any; };
const gate = await node("gate"), edge = await node("edge");
const T = "dte-silent-token-0123456789";
const FAST = { memoryKiB: 32, iterations: 1, parallelism: 1, honey: false };
resetHandshakeGuards();

// in-memory duplex; onGateWrite lets the test switch frame.dte to the edge's value (one process)
function duplex(edgeDte: string, gateDte: string) {
  const q: Record<string, string[]> = { e2g: [], g2e: [] }, w: Record<string, ((s: string) => void)[]> = { e2g: [], g2e: [] };
  let closed = false; const gateWrites: number[] = [];
  const push = (d: string, s: string) => { const r = w[d].shift(); if (r) r(s); else q[d].push(s); };
  const dead: ((e: Error) => void)[] = [];
  const pull = (d: string, ms = 10000) => q[d].length ? Promise.resolve(q[d].shift()!) : closed ? Promise.reject(new Error("closed")) : new Promise<string>((res, rej) => { const t = setTimeout(() => rej(new Error("timeout")), ms); dead.push((e) => { clearTimeout(t); rej(e); }); w[d].push((s) => { clearTimeout(t); res(s); }); });
  const ep: ProsePipe = { async write(s) { if (closed) throw new Error("closed"); setFrameOptions({ dte: gateDte }); push("e2g", s); }, read: async (ms) => { const s = await pull("g2e", ms); setFrameOptions({ dte: edgeDte }); return s; }, close() { closed = true; for (const f of dead.splice(0)) f(new Error("peer closed")); } };
  const gp: ProsePipe = { async write(s) { gateWrites.push(Date.now()); push("g2e", s); }, read: (ms) => pull("e2g", ms), close() {}, firstByte: Promise.resolve() };
  return { ep, gp, gateWrites };
}
const W = 1500;
async function run(edgeDte: string, gateDte: string) {
  const { ep, gp, gateWrites } = duplex(edgeDte, gateDte);
  setFrameOptions({ dte: edgeDte });
  const t0 = Date.now();
  const g = acceptSession({ pipe: gp, self: gate, peers: [{ id: "e1", publicRawB64: edge.publicRawB64 }], token: T, kdf: FAST, handshakeMs: W, sourceIp: "10.7.0.1" } as any).then(() => "ok", (e) => `fail ${e.message}@${Date.now() - t0}`);
  const e = connectSession({ pipe: ep, self: edge, peerRawB64: gate.publicRawB64, token: T, offer: FAST, handshakeMs: W } as any).then((s: any) => { s.close?.(); return "ok"; }, (err) => `fail ${err.message}`); // connectSession closes the pipe itself on confirm failure
  const er = await e;
  await new Promise((r) => setTimeout(r, 100));
  const totalMid = halfOpen.total, silentMid = halfOpen.silent;
  const gr = await g;
  return { er, gr, writes: gateWrites.length, totalMid, silentMid, ms: Date.now() - t0 };
}
const early = halfOpen.earlyReleased;
const r = await run("bb-v4", "bb-k-v4");
assert.match(r.er, /密钥确认失败/);
assert.equal(r.writes, 1, "gate wrote only the server reply");
assert.equal(r.totalMid, 0, "half-open slot released early");
assert.equal(r.silentMid, 1, "connection held silent");
const m = Number(r.gr.split("@")[1]);
assert.ok(/握手超时/.test(r.gr) && m >= W - 20 && m < W + 300, `held to deadline ${r.gr}`);
assert.equal(halfOpen.earlyReleased, early + 1);
assert.equal(halfOpen.total, 0); assert.equal(halfOpen.silent, 0);
// bb-k-v4s (default) vs bb-k-v4 (explicit fallback): the hello word models differ, so the gate cannot
// admit the hello and writes NOTHING (same as a bad token), holds the connection silent to the
// deadline; the edge never gets a server reply and fails its handshake. Both directions.
const s2: string[] = [];
for (const [ed, gd] of [["bb-k-v4s", "bb-k-v4"], ["bb-k-v4", "bb-k-v4s"]]) {
  const early2 = halfOpen.earlyReleased;
  const r2 = await run(ed, gd);
  assert.ok(r2.er.startsWith("fail"), `edge must fail ${ed}/${gd}: ${r2.er}`);
  assert.equal(r2.writes, 0, `gate wrote nothing ${ed}/${gd}`);
  const m2 = Number(r2.gr.split("@")[1]);
  assert.ok(/握手超时/.test(r2.gr) && m2 >= W - 20 && m2 < W + 300, `held to deadline ${r2.gr}`);
  assert.equal(halfOpen.total, 0); assert.equal(halfOpen.silent, 0);
  s2.push(`${ed}->${gd}: edge "${r2.er}", gate 0 writes, silent until ${m2} ms, early release +${halfOpen.earlyReleased - early2}`);
}
setFrameOptions({ dte: "bb-k-v4s" });
console.log(`dte-silent ok: mismatch -> edge "${r.er}", gate 1 write, slot released early, silent until ${m} ms (deadline ${W}); ${s2.join("; ")}`);
