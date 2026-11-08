import assert from "node:assert/strict";
import net from "node:net";
import test from "node:test";
import { buildTcpPacket, createEngine, parseIpv4, parseTcp } from "../public/agent/lexis-tun.mjs";

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const SYN = 0x02;
const ACK = 0x10;
const FIN = 0x01;
const RST = 0x04;
const u32 = (n) => n >>> 0;

function listen(onSocket) {
  return new Promise((resolve) => {
    const server = net.createServer(onSocket);
    server.listen(0, "127.0.0.1", () => resolve(server));
  });
}

function dial(port) {
  return new Promise((resolve, reject) => {
    const socket = net.connect(port, "127.0.0.1", () => resolve(socket));
    socket.once("error", reject);
  });
}

async function setup(body, opts, clientSeq = 5000) {
  const server = await listen((socket) => {
    socket.on("error", () => socket.destroy());
    socket.write(body);
    if (opts.end) socket.end();
  });
  const port = server.address().port;
  const out = [];
  const engine = createEngine({
    dialTcp: () => dial(port),
    dialUdp: async () => {
      throw new Error("udp");
    },
    emit: (packet) => out.push(Object.assign(parseTcp(parseIpv4(Buffer.from(packet)).payload), { at: performance.now() })),
    rtoMs: 20,
    rtoMaxMs: 40,
    maxRetries: 2,
    giveUpMs: 0,
    ...opts,
  });
  await engine.push(buildTcpPacket({ src: "10.9.0.2", dst: "127.0.0.1", sport: 45000, dport: port, seq: clientSeq, ack: 0, flags: SYN, window: 65535 }));
  const deadline = Date.now() + 2000;
  while (!out.some((t) => t.flags & SYN) && Date.now() < deadline) await sleep(5);
  const synAck = out.find((t) => t.flags & SYN);
  assert.ok(synAck, "没有 SYN-ACK");
  await engine.push(buildTcpPacket({ src: "10.9.0.2", dst: "127.0.0.1", sport: 45000, dport: port, seq: u32(clientSeq + 1), ack: u32(synAck.seq + 1), flags: ACK, window: 65535 }));
  return { engine, server, out, port, synAck, clientSeq };
}

function rsts(out) {
  return out.filter((t) => t.flags & RST);
}

async function waitRst(out) {
  const deadline = Date.now() + 3000;
  while (!rsts(out).length && Date.now() < deadline) await sleep(10);
  assert.ok(rsts(out).length, "没有 RST");
  return rsts(out);
}

test("tun: RST uses sndUna while data is unacked, and retransmission does not move that sequence", async () => {
  const body = Buffer.from("never-acked-body!!");
  const { engine, server, out, synAck, clientSeq } = await setup(body, {});
  try {
    const data = () => out.filter((t) => t.data.equals(body));
    const deadline = Date.now() + 2000;
    while (data().length < 2 && Date.now() < deadline) await sleep(5);
    assert.ok(data().length >= 2, "没有重传");
    assert.equal(new Set(data().map((t) => t.seq)).size, 1, "重传序号变了");
    const seg = data()[0];
    const got = await waitRst(out);
    const seqs = got.map((t) => t.seq >>> 0);
    assert.ok(seqs.includes(seg.seq >>> 0), `RST 没用未确认起点 ${seg.seq}，实际 ${seqs}`);
    assert.ok(seqs.includes(u32(seg.seq + body.length)), `对端若已收完全部数据，RST 还应覆盖 sndNxt，实际 ${seqs}`);
    assert.equal(seqs[0], seg.seq >>> 0, "第一条 RST 必须是 sndUna，不能先发数据末端");
    for (const rst of got) {
      assert.equal(rst.ack >>> 0, u32(clientSeq + 1));
      assert.ok(rst.flags & ACK);
      assert.equal(rst.data.length, 0);
    }
    assert.notEqual(u32(seg.seq + body.length), seg.seq >>> 0);
  } finally {
    engine.close();
    server.close();
  }
});

test("tun: a partial ACK moves the RST sequence to the new sndUna", async () => {
  const body = Buffer.alloc(250, 0x71);
  const { engine, server, out, port, clientSeq } = await setup(body, { mss: 100 });
  try {
    const data = () => out.filter((t) => t.data.length > 0);
    const deadline = Date.now() + 2000;
    while (data().reduce((n, t) => n + (t.seq === data()[0]?.seq ? 1 : 0), 0) < 1 && Date.now() < deadline) await sleep(5);
    const first = data()[0];
    assert.ok(first, "没有数据段");
    const covered = u32(first.seq + 100);
    await engine.push(buildTcpPacket({ src: "10.9.0.2", dst: "127.0.0.1", sport: 45000, dport: port, seq: u32(clientSeq + 1), ack: covered, flags: ACK, window: 65535 }));
    const got = await waitRst(out);
    const seqs = got.map((t) => t.seq >>> 0);
    assert.equal(seqs[0], covered, `部分确认后 RST 起点应为 ${covered}，实际 ${seqs}`);
    assert.ok(!seqs.includes(first.seq >>> 0) || first.seq >>> 0 === covered);
  } finally {
    engine.close();
    server.close();
  }
});

test("tun: wrapped sndNxt is not used as the RST sequence; wrapped rcvNxt is the ACK", async () => {
  const body = Buffer.alloc(32, 0x62);
  const clientSeq = 0xfffffff0;
  const { engine, server, out, port, synAck } = await setup(body, { iss: 0xfffffff0 }, clientSeq);
  try {
    const data = () => out.filter((t) => t.data.length === 32);
    const deadline = Date.now() + 2000;
    while (!data().length && Date.now() < deadline) await sleep(5);
    assert.ok(data().length, "没有跨回绕的数据段");
    const una = u32(synAck.seq + 1);
    assert.equal(una, 0xfffffff1);
    await engine.push(buildTcpPacket({
      src: "10.9.0.2",
      dst: "127.0.0.1",
      sport: 45000,
      dport: port,
      seq: u32(clientSeq + 1),
      ack: una,
      flags: ACK,
      payload: Buffer.alloc(20, 0x63),
      window: 65535,
    }));
    const got = await waitRst(out);
    const seqs = got.map((t) => t.seq >>> 0);
    const sndNxt = u32(una + body.length);
    assert.equal(sndNxt, 0x11);
    assert.equal(seqs[0], una, `回绕后第一条 RST 应为 sndUna ${una}，实际 ${seqs}`);
    assert.ok(seqs.includes(sndNxt), `应同时覆盖回绕后的 sndNxt ${sndNxt}，实际 ${seqs}`);
    assert.equal(got[0].ack >>> 0, u32(clientSeq + 1 + 20));
    assert.equal(got[0].ack >>> 0, 0x05);
  } finally {
    engine.close();
    server.close();
  }
});

test("tun: half-close RST acks the peer FIN and does not use our unacked FIN sequence", async () => {
  const body = Buffer.from("half-close-data");
  const clientSeq = 8000;
  const { engine, server, out, port, synAck } = await setup(body, { end: true }, clientSeq);
  try {
    const fin = () => out.find((t) => (t.flags & FIN) && !(t.flags & SYN));
    const deadline = Date.now() + 2000;
    while (!fin() && Date.now() < deadline) await sleep(5);
    const ourFin = fin();
    assert.ok(ourFin, "没有发出 FIN");
    await engine.push(buildTcpPacket({
      src: "10.9.0.2",
      dst: "127.0.0.1",
      sport: 45000,
      dport: port,
      seq: u32(clientSeq + 1),
      ack: u32(synAck.seq + 1),
      flags: ACK | FIN,
      window: 65535,
    }));
    const got = await waitRst(out);
    const una = u32(synAck.seq + 1);
    assert.equal(got[0].seq >>> 0, una, `半关闭后 RST 仍应从数据起点 ${una} 开始，实际 ${got.map((t) => t.seq)}`);
    assert.notEqual(got[0].seq >>> 0, ourFin.seq >>> 0);
    assert.equal(got[0].ack >>> 0, u32(clientSeq + 2), "RST 的 ACK 应确认对端 FIN");
  } finally {
    engine.close();
    server.close();
  }
});

test("tun: a challenge ACK inside the sent range is answered once at that sequence", async () => {
  const body = Buffer.alloc(250, 0x74);
  const { engine, server, out, port, clientSeq } = await setup(body, { mss: 100 });
  try {
    const got = await waitRst(out);
    const una = got[0].seq >>> 0;
    const nxt = got.map((t) => t.seq >>> 0).find((s) => s !== una);
    assert.ok(nxt !== undefined, "没有 sndNxt RST");
    const mid = u32(una + 100);
    assert.notEqual(mid, una);
    assert.notEqual(mid, nxt);
    const before = out.length;
    await engine.push(buildTcpPacket({ src: "10.9.0.2", dst: "127.0.0.1", sport: 45000, dport: port, seq: u32(clientSeq + 1), ack: mid, flags: ACK, window: 65535 }));
    await sleep(30);
    const extra = out.slice(before).filter((t) => t.flags & RST);
    assert.equal(extra.length, 1);
    assert.equal(extra[0].seq >>> 0, mid);
    assert.equal(extra[0].ack >>> 0, u32(clientSeq + 1));
  } finally {
    engine.close();
    server.close();
  }
});

test("tun: an ACK past sndNxt does not become a forged RST sequence", async () => {
  const body = Buffer.from("bounds-check!!!!!!");
  const { engine, server, out, port, clientSeq } = await setup(body, {});
  try {
    const got = await waitRst(out);
    const una = got[0].seq >>> 0;
    const forged = u32(una + body.length + 5000);
    const before = out.length;
    await engine.push(buildTcpPacket({ src: "10.9.0.2", dst: "127.0.0.1", sport: 45000, dport: port, seq: u32(clientSeq + 1), ack: forged, flags: ACK, window: 65535 }));
    await sleep(30);
    const extra = out.slice(before).filter((t) => t.flags & RST);
    assert.equal(extra.length, 0, `越界 ACK 被编成了 RST ${extra.map((t) => t.seq)}`);
    assert.equal(out.slice(before).some((t) => (t.seq >>> 0) === forged), false);
  } finally {
    engine.close();
    server.close();
  }
});
