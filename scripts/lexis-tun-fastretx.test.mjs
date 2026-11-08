import assert from "node:assert/strict";
import net from "node:net";
import test from "node:test";
import { buildTcpPacket, createEngine, parseIpv4, parseTcp } from "../public/agent/lexis-tun.mjs";

// Fast retransmit: duplicate ACKs from the tun client trigger a resend before the RTO.
// (recorded but never acknowledged). Without a retransmission timer wired into the

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

async function setup(body, opts, hsDelay = 0) {
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
  await engine.push(buildTcpPacket({ src: "10.9.0.2", dst: "127.0.0.1", sport: 45000, dport: port, seq: clientSeq, ack: 0, flags: SYN, window: 65535, mss: opts?.mss }));
  const deadline = Date.now() + 2000;
  while (!out.some((t) => t.flags & SYN) && Date.now() < deadline) await sleep(5);
  const synAck = out.find((t) => t.flags & SYN);
  assert.ok(synAck, "没有 SYN-ACK");
  if (hsDelay) await sleep(hsDelay); // handshake RTT sample = hsDelay
  // Client completes the handshake (acks the SYN only) then all later data is lost.
  await engine.push(buildTcpPacket({ src: "10.9.0.2", dst: "127.0.0.1", sport: 45000, dport: port, seq: clientSeq + 1, ack: (synAck.seq + 1) >>> 0, flags: ACK, window: 65535 }));
  return { engine, server, out, port, synAck, clientSeq, closed: () => serverClosed };
}

const MSS = 1000;
const body = Buffer.alloc(MSS * 5, 7);
const opts = { mss: MSS, rtoMs: 5000, rtoMaxMs: 10000, maxRetries: 20 };

async function segsOf(out) {
  const deadline = Date.now() + 2000;
  let segs;
  while (Date.now() < deadline) {
    segs = out.filter((t) => t.data.length);
    if (segs.reduce((n, t) => n + t.data.length, 0) >= body.length) break;
    await sleep(5);
  }
  return segs.slice();
}

function ackPkt(ctx, ack, window = 65535) {
  return buildTcpPacket({ src: "10.9.0.2", dst: "127.0.0.1", sport: 45000, dport: ctx.port, seq: ctx.clientSeq + 1, ack: ack >>> 0, flags: ACK, window });
}

test("tun: 3 duplicate ACKs resend the oldest segment before the RTO, once per recovery", async () => {
  // SRTT ~20 ms (guard window ~25 ms); without an RTT sample the guard would wait a whole RTO.
  const ctx = await setup(body, opts, 20);
  try {
    const segs = await segsOf(ctx.out);
    await sleep(40); // head older than the guard window
    assert.equal(segs.length, 5);
    const first = segs[0].seq;
    const count = (s) => ctx.out.filter((t) => t.data.length && t.seq === s).length;
    // Segment 0 lost: client acks nothing new (ack = first) for segs 1..4 -> 4 dup ACKs.
    await ctx.engine.push(ackPkt(ctx, first));
    await ctx.engine.push(ackPkt(ctx, first));
    assert.equal(count(first), 1, "2 个重复 ACK 不应触发");
    await ctx.engine.push(ackPkt(ctx, first));
    assert.equal(count(first), 2, "第 3 个重复 ACK 没有快速重传");
    for (let i = 0; i < 5; i += 1) await ctx.engine.push(ackPkt(ctx, first));
    assert.equal(count(first), 2, "同一恢复期内重复触发");
    // Partial ACK (segment 0 arrived, 2 also lost) -> resend new oldest (seg 1 → here seg at first+MSS).
    await ctx.engine.push(ackPkt(ctx, first + MSS));
    assert.equal(count(first + MSS), 2, "部分确认没有重发新的最早段");
    // Full ACK ends recovery; nothing else resent.
    await ctx.engine.push(ackPkt(ctx, first + body.length));
    await sleep(100);
    assert.equal(ctx.out.filter((t) => t.data.length).length, 7);
  } finally {
    ctx.engine.close();
    ctx.server.close();
  }
});

test("tun: window updates are not duplicate ACKs; new recovery after recover point", async () => {
  const ctx = await setup(body, opts);
  try {
    const segs = await segsOf(ctx.out);
    const first = segs[0].seq;
    const count = (s) => ctx.out.filter((t) => t.data.length && t.seq === s).length;
    await ctx.engine.push(ackPkt(ctx, first, 60000));
    await ctx.engine.push(ackPkt(ctx, first, 50000));
    await ctx.engine.push(ackPkt(ctx, first, 40000));
    assert.equal(count(first), 1, "窗口更新被当成重复 ACK");
    await ctx.engine.push(ackPkt(ctx, first + 3 * MSS, 40000));
    for (let i = 0; i < 3; i += 1) await ctx.engine.push(ackPkt(ctx, first + 3 * MSS, 40000));
    const deadline = Date.now() + 120; // well below the 200 ms RTO floor; may be deferred by the reordering guard (SRTT*1.25)
    while (count(first + 3 * MSS) < 2 && Date.now() < deadline) await sleep(5);
    assert.equal(count(first + 3 * MSS), 2, "新的丢包没有快速重传");
  } finally {
    ctx.engine.close();
    ctx.server.close();
  }
});

test("tun: reordering guard defers fast retransmit until the head is older than SRTT*1.25", async () => {
  // SRTT ~150 ms from the handshake (a ~0-1 ms handshake sample would make the guard
  // window ~20 ms and the test timing-dependent).
  const ctx = await setup(body, opts, 150);
  try {
    const segs = await segsOf(ctx.out);
    const first = segs[0].seq;
    const count = (s) => ctx.out.filter((t) => t.data.length && t.seq === s).length;
    await ctx.engine.push(ackPkt(ctx, first + MSS)); // segment 0 sent ~150 ms ago
    for (let i = 0; i < 3; i += 1) await ctx.engine.push(ackPkt(ctx, first + MSS));
    assert.equal(count(first + MSS), 1, "头段未超时就快速重传（可能只是乱序）");
    await ctx.engine.push(ackPkt(ctx, first + 2 * MSS)); // reordered segment arrives
    await sleep(100);
    assert.equal(count(first + MSS), 1, "乱序后 ACK 已前进，延迟的快速重传不应再发");
    for (let i = 0; i < 3; i += 1) await ctx.engine.push(ackPkt(ctx, first + 2 * MSS));
    const deadline = Date.now() + 120; // below the RTO (~450 ms here)
    while (count(first + 2 * MSS) < 2 && Date.now() < deadline) await sleep(5);
    assert.equal(count(first + 2 * MSS), 2, "头段够老后没有快速重传");
  } finally {
    ctx.engine.close();
    ctx.server.close();
  }
});
