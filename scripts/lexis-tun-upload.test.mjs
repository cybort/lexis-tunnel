import assert from "node:assert/strict";
import net from "node:net";
import test from "node:test";
import { buildTcpPacket, createEngine, parseIpv4, parseTcp } from "../public/agent/lexis-tun.mjs";

// Upload direction (tun client -> engine -> upstream socket): MSS negotiation in the
// handshake and the bounded multi-segment out-of-order queue.

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const SYN = 0x02;
const ACK = 0x10;
const FIN = 0x01;
const RST = 0x04;
const PSH = 0x08;

async function waitFor(fn, ms = 2000) {
  const end = Date.now() + ms;
  while (!fn() && Date.now() < end) await sleep(5);
  return fn();
}

async function setup({ synMss, serverWrite = null, sport = 46000, ...opts } = {}) {
  const got = [];
  let ended = false;
  const server = await new Promise((resolve) => {
    const s = net.createServer((socket) => {
      socket.on("error", () => socket.destroy());
      socket.on("data", (d) => got.push(d));
      socket.on("end", () => { ended = true; });
      if (serverWrite) socket.write(serverWrite);
    });
    s.listen(0, "127.0.0.1", () => resolve(s));
  });
  const port = server.address().port;
  const out = [];
  const engine = createEngine({
    dialTcp: () => new Promise((resolve, reject) => { const c = net.connect(port, "127.0.0.1", () => resolve(c)); c.once("error", reject); }),
    dialUdp: async () => { throw new Error("udp"); },
    emit: (packet) => out.push(parseTcp(parseIpv4(Buffer.from(packet)).payload)),
    rtoMs: 5000,
    ...opts,
  });
  const iss = 9000;
  const pkt = (o) => buildTcpPacket({ src: "10.9.0.2", dst: "127.0.0.1", sport, dport: port, ack: 0, window: 65535, ...o });
  await engine.push(pkt({ seq: iss, flags: SYN, mss: synMss }));
  assert.ok(await waitFor(() => out.some((t) => t.flags & SYN)), "没有 SYN-ACK");
  const synAck = out.find((t) => t.flags & SYN);
  const ackNo = (synAck.seq + 1) >>> 0;
  await engine.push(pkt({ seq: iss + 1, ack: ackNo, flags: ACK }));
  // send(off, bytes[, flags]) puts client payload at stream offset off.
  const send = (off, data, flags = ACK | PSH) => engine.push(pkt({ seq: (iss + 1 + off) >>> 0, ack: ackNo, flags, payload: data }));
  const body = () => Buffer.concat(got);
  const lastAck = () => [...out].reverse().find((t) => t.flags & ACK)?.ack;
  const done = () => { engine.close(); server.close(); };
  return { engine, server, out, synAck, send, body, lastAck, iss, done, ended: () => ended, pkt, ackNo };
}

const pattern = (n, salt = 0) => Buffer.from(Array.from({ length: n }, (_, i) => (i * 7 + salt) & 0xff));

test("tun MSS: SYN|ACK announces mtu-40; send MSS is min(local, peer SYN MSS)", async () => {
  const a = await setup({ synMss: 1400, serverWrite: Buffer.alloc(20000, 1) });
  try {
    assert.equal(a.synAck.mss, 1460, "默认 mtu 1500 应宣告 1460");
    await waitFor(() => a.out.filter((t) => t.data.length).length >= 5);
    const sizes = a.out.filter((t) => t.data.length).map((t) => t.data.length);
    assert.equal(Math.max(...sizes), 1400, `发送段长应取对端 1400：${sizes}`);
  } finally {
    a.done();
  }
  const b = await setup({ synMss: 1460, mtu: 1280, serverWrite: Buffer.alloc(20000, 1), sport: 46001 });
  try {
    assert.equal(b.synAck.mss, 1240);
    await waitFor(() => b.out.filter((t) => t.data.length).length >= 5);
    assert.equal(Math.max(...b.out.filter((t) => t.data.length).map((t) => t.data.length)), 1240);
  } finally {
    b.done();
  }
  const c = await setup({ serverWrite: Buffer.alloc(20000, 1), sport: 46002 });
  try {
    await waitFor(() => c.out.filter((t) => t.data.length).length >= 5);
    assert.equal(Math.max(...c.out.filter((t) => t.data.length).map((t) => t.data.length)), 536, "对端没带 MSS 时按 536");
  } finally {
    c.done();
  }
  const d = await setup({ synMss: 1460, mss: 1000, sport: 46003 });
  try {
    assert.equal(d.synAck.mss, 1000, "tun.mss 覆盖 mtu");
    // A retransmitted SYN|ACK keeps the option.
    d.engine.retransmit();
  } finally {
    d.done();
  }
});

test("tun reorder: several out-of-order segments are held and delivered in order", async () => {
  const s = await setup({ synMss: 1000 });
  try {
    const data = pattern(5000);
    const seg = (i) => s.send(i * 1000, data.subarray(i * 1000, (i + 1) * 1000));
    await seg(4);
    await seg(2);
    await seg(3);
    await seg(1);
    assert.equal(s.engine.stats().ooo.segs, 1, "2,3,4 连续应合并成一段（1 已到达 4 之前只差 0）");
    assert.equal(s.engine.stats().ooo.bytes, 4000);
    assert.equal(s.lastAck(), (s.iss + 1) >>> 0, "缺第 0 段时 ACK 不动");
    await seg(0);
    assert.ok(await waitFor(() => s.body().length === 5000), `收到 ${s.body().length}`);
    assert.ok(s.body().equals(data), "字节不一致");
    assert.equal(s.lastAck(), (s.iss + 1 + 5000) >>> 0);
    assert.equal(s.engine.stats().ooo.bytes, 0, "补洞后缓存应清空");
    assert.equal(s.engine.stats().ooo.segs, 0);
  } finally {
    s.done();
  }
});

test("tun reorder: overlapping segments and partial retransmissions merge without duplication", async () => {
  const s = await setup({ synMss: 1000 });
  try {
    const data = pattern(4000, 3);
    const part = (a, b) => s.send(a, data.subarray(a, b));
    await part(2000, 3000);
    await part(2500, 3500); // overlaps queued tail
    await part(1500, 2200); // overlaps queued head
    await part(1800, 2600); // fully covered
    await part(0, 1000);
    await part(500, 1600); // overlaps rcvNxt: only the new tail is used, then fills the hole
    await part(3400, 4000);
    assert.ok(await waitFor(() => s.body().length >= 4000));
    assert.ok(s.body().equals(data), "重叠合并后字节不一致");
    await part(0, 4000); // full duplicate after the fact
    await sleep(30);
    assert.equal(s.body().length, 4000, "重复段不应再交付");
    assert.equal(s.engine.stats().ooo.bytes, 0);
  } finally {
    s.done();
  }
});

test("tun reorder caps: segment and byte limits drop the farthest pieces; out-of-window is dropped", async () => {
  const s = await setup({ synMss: 1000, oooMaxSegs: 2, oooMaxBytes: 1500 });
  try {
    const data = pattern(9000, 5);
    const seg = (i) => s.send(i * 1000, data.subarray(i * 1000, (i + 1) * 1000));
    await seg(6);
    await seg(4);
    await seg(2); // 3 holes-separated pieces > 2 segs, and 3000 B > 1500 B: keep nearest only
    let st = s.engine.stats().ooo;
    assert.equal(st.segs, 1, JSON.stringify(st));
    assert.equal(st.bytes, 1000);
    assert.equal(st.dropped, 2);
    // Beyond rcvNxt + 65535 is outside the window.
    await s.send(70000, Buffer.alloc(100, 9));
    st = s.engine.stats().ooo;
    assert.equal(st.outOfWindow, 1);
    assert.equal(st.bytes, 1000);
    // The sender retransmits; everything still arrives intact.
    for (const i of [0, 1, 3, 4, 5, 6, 7, 8]) await seg(i);
    assert.ok(await waitFor(() => s.body().length === 9000), `收到 ${s.body().length}`);
    assert.ok(s.body().equals(data));
    assert.equal(s.engine.stats().ooo.bytes, 0);
  } finally {
    s.done();
  }
  const z = await setup({ synMss: 1000, oooMaxSegs: 0, sport: 46010 });
  try {
    await z.send(1000, Buffer.alloc(1000, 1));
    assert.equal(z.engine.stats().ooo.bytes, 0, "oooMaxSegs=0 不缓存");
  } finally {
    z.done();
  }
  const g = await setup({ synMss: 1000, oooTotalBytes: 1200, sport: 46011 });
  try {
    await g.send(1000, Buffer.alloc(1000, 1));
    await g.send(3000, Buffer.alloc(1000, 1));
    assert.equal(g.engine.stats().ooo.bytes, 1000, "整机上限 1200 只留一段");
  } finally {
    g.done();
  }
});

test("tun reorder: queued bytes are released on RST, on FIN completion and on flow drop", async () => {
  const s = await setup({ synMss: 1000 });
  try {
    await s.send(1000, Buffer.alloc(1000, 1));
    await s.send(3000, Buffer.alloc(500, 1));
    assert.equal(s.engine.stats().ooo.bytes, 1500);
    await s.engine.push(s.pkt({ seq: (s.iss + 1) >>> 0, ack: s.ackNo, flags: RST }));
    assert.deepEqual([s.engine.stats().ooo.bytes, s.engine.stats().ooo.segs], [0, 0], "RST 后应释放");
  } finally {
    s.done();
  }
  const f = await setup({ synMss: 1000, sport: 46020 });
  try {
    const data = pattern(3000, 1);
    await f.send(2000, data.subarray(2000), ACK | FIN); // FIN arrives out of order
    await f.send(1000, data.subarray(1000, 2000));
    assert.equal(f.engine.stats().ooo.bytes, 2000);
    await f.send(0, data.subarray(0, 1000));
    assert.ok(await waitFor(() => f.ended()), "乱序 FIN 补齐后应结束上游写");
    assert.ok(f.body().equals(data));
    assert.equal(f.lastAck(), (f.iss + 1 + 3000 + 1) >>> 0, "ACK 应覆盖 FIN");
    assert.equal(f.engine.stats().ooo.bytes, 0);
  } finally {
    f.done();
  }
  const r = await setup({ synMss: 1000, sport: 46021 });
  try {
    await r.send(1000, Buffer.alloc(1000, 1));
    r.engine.close();
    assert.equal(r.engine.stats().ooo.bytes, 0, "引擎关闭后应释放");
  } finally {
    r.done();
  }
});
