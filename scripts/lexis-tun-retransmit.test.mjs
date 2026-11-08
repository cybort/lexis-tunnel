import assert from "node:assert/strict";
import net from "node:net";
import test from "node:test";
import { buildTcpPacket, createEngine, parseIpv4, parseTcp } from "../public/agent/lexis-tun.mjs";

// Lossy link model: every segment the engine emits toward the tun client is "dropped"
// (recorded but never acknowledged). Without a retransmission timer wired into the
// engine the data is sent once and the flow stays stuck forever.

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const SYN = 0x02;
const ACK = 0x10;
const RST = 0x04;

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

async function setup(body, opts) {
  let serverClosed = false;
  const server = await listen((socket) => {
    socket.on("error", () => socket.destroy());
    socket.on("close", () => { serverClosed = true; });
    socket.write(body);
  });
  const port = server.address().port;
  const out = [];
  const engine = createEngine({
    dialTcp: () => dial(port),
    dialUdp: async () => { throw new Error("udp"); },
    emit: (packet) => out.push(Object.assign(parseTcp(parseIpv4(Buffer.from(packet)).payload), { at: performance.now() })),
    ...opts,
  });
  const clientSeq = 5000;
  await engine.push(buildTcpPacket({ src: "10.9.0.2", dst: "127.0.0.1", sport: 45000, dport: port, seq: clientSeq, ack: 0, flags: SYN, window: 65535 }));
  const deadline = Date.now() + 2000;
  while (!out.some((t) => t.flags & SYN) && Date.now() < deadline) await sleep(5);
  const synAck = out.find((t) => t.flags & SYN);
  assert.ok(synAck, "没有 SYN-ACK");
  // Client completes the handshake (acks the SYN only) then all later data is lost.
  await engine.push(buildTcpPacket({ src: "10.9.0.2", dst: "127.0.0.1", sport: 45000, dport: port, seq: clientSeq + 1, ack: (synAck.seq + 1) >>> 0, flags: ACK, window: 65535 }));
  return { engine, server, out, port, synAck, clientSeq, closed: () => serverClosed };
}

test("tun: unacked data segment is retransmitted on timeout without an external call", async () => {
  const body = Buffer.from("lost-segment-payload");
  const { engine, server, out } = await setup(body, { rtoMs: 50, rtoMaxMs: 200, maxRetries: 20 });
  try {
    const copies = () => out.filter((t) => t.data.length && t.data.equals(body)).length;
    const deadline = Date.now() + 1500;
    while (copies() < 3 && Date.now() < deadline) await sleep(10);
    assert.ok(copies() >= 3, `丢包后没有超时重传（数据段只发了 ${copies()} 次）`);
    const seqs = new Set(out.filter((t) => t.data.equals(body)).map((t) => t.seq));
    assert.equal(seqs.size, 1, "重传的序号必须与原段一致");
  } finally {
    engine.close();
    server.close();
  }
});

test("tun: an ACK covering the data stops retransmission", async () => {
  const body = Buffer.from("acked-later");
  const { engine, server, out, port, clientSeq } = await setup(body, { rtoMs: 40, rtoMaxMs: 1000, maxRetries: 20 });
  try {
    const data = () => out.filter((t) => t.data.equals(body));
    const deadline = Date.now() + 1500;
    while (data().length < 3 && Date.now() < deadline) await sleep(5);
    assert.ok(data().length >= 3, "没有重传");
    const seg = data()[0];
    await engine.push(buildTcpPacket({ src: "10.9.0.2", dst: "127.0.0.1", sport: 45000, dport: port, seq: clientSeq + 1, ack: (seg.seq + body.length) >>> 0, flags: ACK, window: 65535 }));
    const n = data().length;
    await sleep(400);
    assert.equal(data().length, n, "确认之后还在重传");
  } finally {
    engine.close();
    server.close();
  }
});

test("tun: retransmission is bounded; flow is reset with RST and its socket closed", async () => {
  const body = Buffer.from("never-acked");
  const { engine, server, out, closed } = await setup(body, { rtoMs: 20, rtoMaxMs: 80, maxRetries: 3, giveUpMs: 0 });
  try {
    const deadline = Date.now() + 3000;
    while (!out.some((t) => t.flags & RST) && Date.now() < deadline) await sleep(10);
    assert.ok(out.some((t) => t.flags & RST), "重传上限后没有发 RST");
    const copies = out.filter((t) => t.data.equals(body)).length;
    assert.equal(copies, 1 + 3, "原段 1 次 + 重传 maxRetries 次");
    const at = out.filter((t) => t.data.equals(body)).map((t) => t.at);
    assert.ok(at[3] - at[2] > (at[1] - at[0]) * 1.5, `没有指数退避：${at.map((x) => x.toFixed(0)).join(",")}`);
    await sleep(300);
    assert.equal(out.filter((t) => t.data.equals(body)).length, copies, "RST 之后仍在重传");
    const until = Date.now() + 1000;
    while (!closed() && Date.now() < until) await sleep(10);
    assert.ok(closed(), "RST 之后上游连接没有关闭");
  } finally {
    engine.close();
    server.close();
  }
});

test("tun: RST needs both maxRetries and giveUpMs without progress", async () => {
  const body = Buffer.from("slow-give-up");
  const { engine, server, out } = await setup(body, { rtoMs: 20, rtoMaxMs: 40, maxRetries: 2, giveUpMs: 400 });
  try {
    const start = performance.now();
    const deadline = Date.now() + 3000;
    while (!out.some((t) => t.flags & RST) && Date.now() < deadline) await sleep(10);
    const rst = out.find((t) => t.flags & RST);
    assert.ok(rst, "giveUpMs 之后没有发 RST");
    assert.ok(rst.at - start >= 350, `RST 早于 giveUpMs：${(rst.at - start).toFixed(0)} ms`);
  } finally {
    engine.close();
    server.close();
  }
});

test("tun: after a retransmitted SYN-ACK without RTT sample, data starts with RTO = synRtoMs (RFC 6298 5.7)", async () => {
  const body = Buffer.from("after-syn-retx");
  let port;
  const server = await listen((socket) => {
    socket.on("error", () => socket.destroy());
    setTimeout(() => socket.write(body), 300); // after the handshake ACK
  });
  port = server.address().port;
  const out = [];
  const engine = createEngine({
    dialTcp: () => dial(port),
    dialUdp: async () => { throw new Error("udp"); },
    emit: (packet) => out.push(Object.assign(parseTcp(parseIpv4(Buffer.from(packet)).payload), { at: performance.now() })),
    rtoMs: 40, rtoMaxMs: 5000, maxRetries: 20, synRtoMs: 400,
  });
  try {
    await engine.push(buildTcpPacket({ src: "10.9.0.2", dst: "127.0.0.1", sport: 45001, dport: port, seq: 7000, ack: 0, flags: SYN, window: 65535 }));
    const deadline = Date.now() + 2000;
    while (out.filter((t) => t.flags & SYN).length < 2 && Date.now() < deadline) await sleep(5);
    const syns = out.filter((t) => t.flags & SYN);
    assert.ok(syns.length >= 2, "SYN-ACK 没有超时重发");
    await engine.push(buildTcpPacket({ src: "10.9.0.2", dst: "127.0.0.1", sport: 45001, dport: port, seq: 7001, ack: (syns[0].seq + 1) >>> 0, flags: ACK, window: 65535 }));
    const data = () => out.filter((t) => t.data.equals(body));
    const until = Date.now() + 2000;
    while (data().length < 2 && Date.now() < until) await sleep(5);
    assert.ok(data().length >= 2, "数据段没有重传");
    const gap = data()[1].at - data()[0].at;
    assert.ok(gap >= 350, `SYN-ACK 重发后数据 RTO 应为 synRtoMs，实际 ${gap.toFixed(0)} ms`);
  } finally {
    engine.close();
    server.close();
  }
});
