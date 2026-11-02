import assert from "node:assert/strict";
import { acceptSession, connectSession, createIdentity, frameStats } from "../public/agent/lexis-frame.mjs";

function pipePair() {
  const mk = () => ({ q: [], waiters: [], closed: false });
  const a = mk(), b = mk();
  const end = (me, peer) => ({
    async write(s) { if (peer.closed || me.closed) throw new Error("连接关闭"); const w = peer.waiters.shift(); w ? w.res(s) : peer.q.push(s); },
    read(t) { if (me.q.length) return Promise.resolve(me.q.shift()); if (me.closed) return Promise.reject(new Error("连接关闭"));
      return new Promise((res, rej) => { const w = { res, rej }; me.waiters.push(w); if (t) setTimeout(() => rej(new Error("读取超时")), t).unref?.(); }); },
    close() { for (const x of [me, peer]) { x.closed = true; while (x.waiters.length) x.waiters.shift().rej(new Error("连接关闭")); } },
  });
  return [end(a, b), end(b, a)];
}
async function node(role) {
  const k = await createIdentity();
  return { id: role, name: role, role, publicJwk: k.publicJwk, privateJwk: k.privateJwk, publicRawB64: Buffer.from(k.publicRaw).toString("base64"), fingerprint: k.fingerprint, pinnedPeerId: null, createdAt: Date.now(), kdf: null };
}
const FAST = { memoryKiB: 32, iterations: 1, parallelism: 1 };
const gate = await node("gate"), edge = await node("edge");
async function pair(rekeyAt) {
  const [pe, pg] = pipePair();
  let gs;
  const gp = acceptSession({ pipe: pg, self: gate, peers: [{ id: "e", publicRawB64: edge.publicRawB64 }], token: "v3-test-token-9f3a2c1b0e7d6a5c", kdf: FAST, heartbeatMs: 0, rekeyAt,
    onStream: (st) => { void (async () => { await st.accept?.(); for (;;) { const c = await st.read(); if (!c) break; await st.write(c); } await st.close(); })(); } });
  const es = await connectSession({ pipe: pe, self: edge, peerRawB64: gate.publicRawB64, token: "v3-test-token-9f3a2c1b0e7d6a5c", offer: FAST, heartbeatMs: 0, rekeyAt });
  gs = await gp;
  return { es, gs, pe, pg };
}
// echo + rekey every 8 frames
const { es, gs } = await pair(8);
const st = await es.open("echo");
let got = 0;
for (let i = 0; i < 60; i++) { await st.write(Buffer.from(`ping ${i} `.repeat(20))); const r = await st.read(); got += r.length; }
assert.ok(es.live.v2.gen >= 3, `gen ${es.live.v2.gen}`);
console.log("echo bytes", got, "generations", es.live.v2.gen);
// END frame
es.shutdown();
await gs.whenClosed();
assert.equal(frameStats.ended, 1);
// truncation: close the pipe without END
const t = await pair(0xffff00);
t.pe.close();
await t.gs.whenClosed();
await new Promise((r) => setTimeout(r, 50));
assert.ok(frameStats.truncated >= 1);
// silent drop timing: bad hello vs no hello
const [x1, y1] = pipePair();
const t0 = Date.now();
const bad = acceptSession({ pipe: y1, self: gate, peers: [{ id: "e", publicRawB64: edge.publicRawB64 }], token: "v3-test-token-9f3a2c1b0e7d6a5c", handshakeMs: 1500 }).catch((e) => e.message);
await x1.write("the of and to in is that it was");
const badMsg = await bad; const tBad = Date.now() - t0;
const [, y2] = pipePair();
const t1 = Date.now();
const none = await acceptSession({ pipe: y2, self: gate, peers: [], token: "v3-test-token-9f3a2c1b0e7d6a5c", handshakeMs: 1500 }).catch((e) => e.message);
const tNone = Date.now() - t1;
assert.equal(badMsg, none);
assert.ok(Math.abs(tBad - tNone) < 100, `${tBad} vs ${tNone}`);
console.log(`silent drop: bad hello ${tBad} ms, no hello ${tNone} ms, same error "${badMsg}"`);
console.log("lexis v2 session ok", JSON.stringify(frameStats));
process.exit(0);
