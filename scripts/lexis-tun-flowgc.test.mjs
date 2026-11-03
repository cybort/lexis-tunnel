import assert from "node:assert/strict";
import net from "node:net";
import test from "node:test";
import { buildTcpPacket, createEngine, parseIpv4, parseTcp } from "../public/agent/lexis-tun.mjs";

const SYN = 0x02, ACK = 0x10, FIN = 0x01, RST = 0x04, PSH = 0x08;
const C = "10.99.0.2", S = "10.99.0.1";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function rig({ serverEnds, ...opts }) {
  const sockets = [];
  const srv = net.createServer((s) => {
    sockets.push(s);
    s.on("error", () => undefined);
    s.on("data", (d) => s.write(d));
    if (serverEnds) s.on("end", () => s.end());
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const port = srv.address().port;
  const seen = [];
  const engine = createEngine({
    dialTcp: () => new Promise((res, rej) => { const s = net.connect(port, "127.0.0.1", () => res(s)); s.once("error", rej); }),
    dialUdp: async () => { throw new Error("no udp"); },
    emit: (pkt) => setImmediate(() => seen.push(parseTcp(parseIpv4(pkt).payload))),
    ...opts,
  });
  let cseq = 1000, ack = 0;
  const send = (flags, payload) => engine.push(buildTcpPacket({ src: C, dst: S, sport: 40000, dport: 80, seq: cseq, ack, flags, payload }));
  const waitFor = async (pred) => { for (let i = 0; i < 200; i++) { const hit = seen.find(pred); if (hit) return hit; await sleep(5); } return null; };
  const done = () => { engine.close(); srv.close(); for (const s of sockets) s.destroy(); };
  // handshake + 3 bytes + FIN
  await send(SYN);
  const synAck = await waitFor((t) => (t.flags & SYN) && (t.flags & ACK));
  ack = (synAck.seq + 1) >>> 0; cseq++;
  await send(ACK);
  await send(ACK | PSH, Buffer.from("abc")); cseq += 3;
  await send(ACK | FIN); cseq++;
  return { engine, seen, send, waitFor, done, ackTo: (v) => { ack = v >>> 0; }, finSeq: () => cseq - 1, setSeq: (v) => { cseq = v; } };
}

test("gracefully closed tun flow is dropped after TIME_WAIT", async () => {
  const r = await rig({ serverEnds: true, timeWaitMs: 60 });
  try {
    const fin = await r.waitFor((t) => t.flags & FIN);
    assert.ok(fin, "engine sends FIN after remote close");
    r.ackTo(fin.seq + fin.data.length + 1);
    await r.send(ACK);
    await sleep(10);
    // Retransmitted FIN during TIME_WAIT still gets an ACK.
    r.seen.length = 0;
    r.setSeq(r.finSeq());
    await r.send(ACK | FIN);
    assert.ok(await r.waitFor((t) => t.flags === ACK), "ACK during TIME_WAIT");
    await sleep(120);
    r.seen.length = 0;
    await r.send(ACK | FIN);
    await sleep(40);
    assert.equal(r.seen.length, 0, "flow forgotten after TIME_WAIT");
  } finally {
    r.done();
  }
});

test("half-closed tun flow is reset after finLingerMs", async () => {
  const r = await rig({ serverEnds: false, finLingerMs: 80 });
  try {
    const rst = await r.waitFor((t) => t.flags & RST);
    assert.ok(rst, "RST after linger");
  } finally {
    r.done();
  }
});
