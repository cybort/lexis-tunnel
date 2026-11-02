import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { connect, createServer, Socket } from "node:net";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { serveHttpProxy } from "../public/agent/lexis-http.mjs";
import { buildDnsQuery, buildTcpPacket, buildUdpPacket, createEngine, createFakeIp, parseIpv4, parseTcp, parseUdp } from "../public/agent/lexis-tun.mjs";

function listen(handler) {
  const server = createServer((socket) => {
    socket.on("error", () => socket.destroy());
    handler(socket);
  });
  server.on("error", () => undefined);
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve(server));
  });
}

function dial(port) {
  return new Promise((resolve, reject) => {
    const socket = connect({ host: "127.0.0.1", port });
    socket.on("error", reject);
    socket.once("connect", () => resolve(socket));
  });
}

function readResponse(socket) {
  return new Promise((resolve, reject) => {
    let buf = Buffer.alloc(0);
    const timer = setTimeout(() => reject(new Error(`响应超时 ${buf.toString("latin1").slice(0, 180)}`)), 2000);
    const onData = (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      const at = buf.indexOf("\r\n\r\n");
      if (at < 0) return;
      const head = buf.subarray(0, at).toString("latin1");
      const match = head.match(/content-length:\s*(\d+)/i);
      const status = Number((head.match(/^HTTP\/1\.[01]\s+(\d+)/i) || [])[1]);
      if (!match) {
        if (buf.length > at + 4) return;
        clearTimeout(timer);
        socket.off("data", onData);
        resolve({ status, head, body: Buffer.alloc(0) });
        return;
      }
      const length = Number(match[1]);
      if (buf.length < at + 4 + length) return;
      clearTimeout(timer);
      socket.off("data", onData);
      const body = buf.subarray(at + 4, at + 4 + length);
      const rest = buf.subarray(at + 4 + length);
      if (rest.length) socket.unshift(rest);
      resolve({ status, head, body });
    };
    socket.on("data", onData);
  });
}

function readUntilClose(socket) {
  return new Promise((resolve, reject) => {
    let buf = Buffer.alloc(0);
    const timer = setTimeout(() => reject(new Error(`响应超时 ${buf.toString("latin1").slice(0, 180)}`)), 2000);
    socket.on("data", (chunk) => {
      buf = Buffer.concat([buf, chunk]);
    });
    socket.on("end", () => {
      clearTimeout(timer);
      resolve(buf.toString("latin1"));
    });
    socket.on("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

function scripted() {
  return listen((socket) => {
    let buf = Buffer.alloc(0);
    let done = false;
    socket.on("data", (chunk) => {
      if (done) return;
      buf = Buffer.concat([buf, chunk]);
      if (!buf.includes(Buffer.from("\r\n\r\n"))) return;
      done = true;
      const reply = socket.reply;
      if (reply) reply(socket, buf.toString("latin1"));
    });
  });
}

function origin() {
  const hits = [];
  return listen((socket) => {
    let buf = Buffer.alloc(0);
    let replied = false;
    socket.on("data", (chunk) => {
      if (replied) return;
      buf = Buffer.concat([buf, chunk]);
      const at = buf.indexOf("\r\n\r\n");
      if (at < 0) return;
      const head = buf.subarray(0, at).toString("latin1");
      let body = Buffer.alloc(0);
      if (/transfer-encoding:\s*chunked/i.test(head)) {
        const raw = buf.subarray(at + 4).toString("latin1");
        const mark = raw.indexOf("\r\n");
        if (mark < 0 || !raw.includes("\r\n0\r\n")) return;
        const size = Number.parseInt(raw.slice(0, mark), 16);
        if (!Number.isFinite(size)) return;
        body = Buffer.from(raw.slice(mark + 2, mark + 2 + size), "latin1");
      } else {
        const length = Number((head.match(/content-length:\s*(\d+)/i) || [])[1] || 0);
        if (buf.length < at + 4 + length) return;
        body = buf.subarray(at + 4, at + 4 + length);
      }
      replied = true;
      const path = (head.match(/^[A-Z]+ (\S+)/) || [])[1] || "";
      hits.push({ head, body: body.toString("latin1"), path });
      const text = `ok ${path}`;
      socket.end(`HTTP/1.1 200 OK\r\nContent-Length: ${Buffer.byteLength(text)}\r\nConnection: close\r\n\r\n${text}`);
    });
  }).then((server) => ({ server, hits, port: server.address().port }));
}

async function main() {
  const a = await origin();
  const b = await origin();
  const opened = [];
  const proxy = await listen((socket) => {
    void serveHttpProxy(socket, {
      authorize: () => true,
      openUpstream(host, port) {
        opened.push(`${host}:${port}`);
        return dial(port);
      },
      count() {},
    });
  });
  const proxyPort = proxy.address().port;
  const client = await dial(proxyPort);
  const req = (hostPort, path, extra = "") =>
    `GET http://${hostPort}${path} HTTP/1.1\r\nHost: ${hostPort}\r\nProxy-Authorization: Basic c2VjcmV0\r\n${extra}Connection: keep-alive\r\n\r\n`;
  const send = (socket, raw) => {
    const pending = readResponse(socket);
    socket.write(raw);
    return pending;
  };
  const first = await send(client, req(`127.0.0.1:${a.port}`, "/one"));
  const second = await send(client, req(`127.0.0.1:${b.port}`, "/two"));
  assert.equal(first.body.toString(), "ok /one");
  assert.equal(second.body.toString(), "ok /two");
  assert.deepEqual(opened.slice(0, 2), [`127.0.0.1:${a.port}`, `127.0.0.1:${b.port}`]);
  const one = a.hits.find((hit) => hit.path === "/one");
  const two = b.hits.find((hit) => hit.path === "/two");
  assert.ok(one && two);
  assert.ok(!/proxy-authorization/i.test(one.head));
  assert.ok(!/proxy-authorization/i.test(two.head));

  const smuggle = await dial(proxyPort);
  const before = opened.length;
  const denied = await send(smuggle, `POST http://127.0.0.1:${a.port}/x HTTP/1.1\r\nHost: 127.0.0.1:${a.port}\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n`);
  assert.equal(denied.status, 400);
  assert.equal(opened.length, before);
  smuggle.destroy();

  const mismatch = await dial(proxyPort);
  const badHost = await send(mismatch, `GET http://127.0.0.1:${a.port}/one HTTP/1.1\r\nHost: evil.test\r\n\r\n`);
  assert.equal(badHost.status, 400);
  assert.equal(opened.length, before);
  mismatch.destroy();

  const chunked = await dial(proxyPort);
  const posted = await send(chunked, `POST http://127.0.0.1:${a.port}/up HTTP/1.1\r\nHost: 127.0.0.1:${a.port}\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n`);
  assert.equal(posted.status, 200);
  const uploaded = a.hits.find((hit) => hit.path === "/up");
  assert.equal(uploaded?.body, "hello");
  chunked.destroy();
  client.destroy();

  async function expectClosed(method, path, reply, check) {
    const server = await scripted();
    server.on("connection", (socket) => {
      socket.reply = reply;
    });
    const port = server.address().port;
    const sock = await dial(proxyPort);
    const pending = readUntilClose(sock);
    const started = Date.now();
    sock.write(`${method} http://127.0.0.1:${port}${path} HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nConnection: close\r\n\r\n`);
    const raw = await pending;
    assert.ok(Date.now() - started < 1500, `${method} ${path} 不该挂到空闲超时`);
    check(raw);
    sock.destroy();
    server.close();
  }
  await expectClosed("HEAD", "/head", (socket) => {
    socket.end("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello");
  }, (raw) => {
    assert.match(raw, /^HTTP\/1\.1 200 /);
    assert.equal(raw.includes("hello"), false);
    assert.equal(/content-length/i.test(raw), false);
  });
  await expectClosed("GET", "/empty", (socket) => {
    socket.end("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
  }, (raw) => {
    assert.match(raw, / 204 /);
    assert.equal(raw.split("\r\n\r\n")[1] || "", "");
  });
  await expectClosed("GET", "/cached", (socket) => {
    socket.end("HTTP/1.1 304 Not Modified\r\nContent-Length: 3\r\nConnection: close\r\n\r\nnah");
  }, (raw) => {
    assert.match(raw, / 304 /);
    assert.equal(raw.includes("nah"), false);
  });
  await expectClosed("GET", "/cont", (socket) => {
    socket.write("HTTP/1.1 100 Continue\r\n\r\n");
    socket.end("HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\npong");
  }, (raw) => {
    assert.match(raw, /100 Continue/);
    assert.match(raw, /200 OK/);
    assert.equal(raw.endsWith("pong"), true);
  });
  const tail = "y".repeat(20000);
  await expectClosed("GET", "/close", (socket) => {
    socket.write("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n");
    socket.end(tail);
  }, (raw) => {
    const at = raw.indexOf("\r\n\r\n");
    assert.equal(raw.slice(at + 4), tail);
  });

  const echo = await listen((socket) => {
    socket.on("data", (chunk) => socket.end(chunk));
  });
  const echoPort = echo.address().port;
  const packets = [];
  const engine = createEngine({
    dialTcp: (host, port) => dial(port === echoPort ? echoPort : port).then((socket) => (host ? socket : socket)),
    dialUdp: async () => {
      throw new Error("udp");
    },
    emit: (packet) => packets.push(Buffer.from(packet)),
  });
  const clientSeq = 1000;
  await engine.push(buildTcpPacket({ src: "10.1.1.1", dst: "127.0.0.1", sport: 44000, dport: echoPort, seq: clientSeq, ack: 0, flags: 0x02 }));
  const synAck = () => packets.map((packet) => parseTcp(parseIpv4(packet).payload)).find((tcp) => tcp && tcp.flags & 0x02 && tcp.flags & 0x10);
  const deadline = Date.now() + 2000;
  while (!synAck() && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 10));
  const shook = synAck();
  assert.ok(shook, "没有 SYN-ACK");
  await engine.push(buildTcpPacket({
    src: "10.1.1.1",
    dst: "127.0.0.1",
    sport: 44000,
    dport: echoPort,
    seq: (clientSeq + 1) >>> 0,
    ack: (shook.seq + 1) >>> 0,
    flags: 0x18,
    payload: Buffer.from("ping"),
  }));
  const pong = () => packets.map((packet) => {
    const ip = parseIpv4(packet);
    const tcp = parseTcp(ip.payload);
    return tcp?.data?.toString() === "ping" ? tcp : null;
  }).find(Boolean);
  while (!pong() && Date.now() < deadline + 2000) await new Promise((resolve) => setTimeout(resolve, 10));
  assert.ok(pong(), "虚拟网卡没有把数据送回来");
  engine.close();

  const bigBody = Buffer.alloc(2500, 0x61);
  const bulk = await listen((socket) => {
    socket.on("error", () => socket.destroy());
    socket.end(bigBody);
  });
  const bulkPort = bulk.address().port;
  const bulkPackets = [];
  const bulkEngine = createEngine({
    dialTcp: () => dial(bulkPort),
    dialUdp: async () => {
      throw new Error("udp");
    },
    emit: (packet) => bulkPackets.push(Buffer.from(packet)),
  });
  const bulkSeq = 2000;
  await bulkEngine.push(buildTcpPacket({ src: "10.1.1.2", dst: "127.0.0.1", sport: 44010, dport: bulkPort, seq: bulkSeq, ack: 0, flags: 0x02, window: 65535 }));
  const bulkDeadline = Date.now() + 2000;
  const bulkData = () => bulkPackets.map((packet) => parseTcp(parseIpv4(packet).payload)).filter((tcp) => tcp && tcp.data.length);
  while (bulkData().reduce((sum, tcp) => sum + tcp.data.length, 0) < 2500 && Date.now() < bulkDeadline) {
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  const pieces = bulkData();
  assert.ok(pieces.length >= 3, "长响应没有按段切开");
  assert.ok(pieces.every((tcp) => tcp.data.length <= 1200));
  assert.equal(Buffer.concat(pieces.map((tcp) => tcp.data)).length, 2500);
  const sentBefore = pieces.length;
  bulkEngine.retransmit();
  assert.ok(bulkData().length > sentBefore, "重传没有把未确认的段再发出去");
  bulkEngine.close();
  bulk.close();

  let got = Buffer.alloc(0);
  const held = await listen((socket) => {
    socket.on("error", () => socket.destroy());
    socket.on("data", (chunk) => {
      got = Buffer.concat([got, chunk]);
    });
  });
  const heldPort = held.address().port;
  const order = createEngine({
    dialTcp: () => dial(heldPort),
    dialUdp: async () => {
      throw new Error("udp");
    },
    emit: () => undefined,
  });
  const orderSeq = 3000;
  await order.push(buildTcpPacket({ src: "10.1.1.3", dst: "127.0.0.1", sport: 44020, dport: heldPort, seq: orderSeq, ack: 0, flags: 0x02 }));
  await order.push(buildTcpPacket({
    src: "10.1.1.3",
    dst: "127.0.0.1",
    sport: 44020,
    dport: heldPort,
    seq: (orderSeq + 1 + 4) >>> 0,
    ack: 1,
    flags: 0x18,
    payload: Buffer.from("later"),
  }));
  await order.push(buildTcpPacket({
    src: "10.1.1.3",
    dst: "127.0.0.1",
    sport: 44020,
    dport: heldPort,
    seq: (orderSeq + 1) >>> 0,
    ack: 1,
    flags: 0x18,
    payload: Buffer.from("abcd"),
  }));
  const orderDeadline = Date.now() + 2000;
  while (got.toString() !== "abcdlater" && Date.now() < orderDeadline) await new Promise((resolve) => setTimeout(resolve, 10));
  assert.equal(got.toString(), "abcdlater");
  order.close();
  held.close();

  const quiet = await listen((socket) => {
    socket.on("error", () => socket.destroy());
    socket.end(Buffer.from("Z"));
  });
  const quietPort = quiet.address().port;
  const quietPackets = [];
  const paused = createEngine({
    dialTcp: () => dial(quietPort),
    dialUdp: async () => {
      throw new Error("udp");
    },
    emit: (packet) => quietPackets.push(Buffer.from(packet)),
  });
  const quietSeq = 4000;
  await paused.push(buildTcpPacket({ src: "10.1.1.4", dst: "127.0.0.1", sport: 44030, dport: quietPort, seq: quietSeq, ack: 0, flags: 0x02, window: 0 }));
  await new Promise((resolve) => setTimeout(resolve, 80));
  const quietData = () => quietPackets.map((packet) => parseTcp(parseIpv4(packet).payload)).filter((tcp) => tcp && tcp.data.length);
  assert.equal(quietData().length, 0);
  const synOnly = quietPackets.map((packet) => parseTcp(parseIpv4(packet).payload)).find((tcp) => tcp && tcp.flags & 0x02);
  assert.ok(synOnly);
  await paused.push(buildTcpPacket({
    src: "10.1.1.4",
    dst: "127.0.0.1",
    sport: 44030,
    dport: quietPort,
    seq: (quietSeq + 1) >>> 0,
    ack: (synOnly.seq + 1) >>> 0,
    flags: 0x10,
    window: 65535,
  }));
  const quietDeadline = Date.now() + 2000;
  while (!quietData().some((tcp) => tcp.data.toString() === "Z") && Date.now() < quietDeadline) {
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  assert.ok(quietData().some((tcp) => tcp.data.toString() === "Z"), "窗口打开后没有继续发");
  paused.close();
  quiet.close();

  const names = createFakeIp();
  const dnsPackets = [];
  const dnsDials = [];
  const dns = createEngine({
    dialTcp: async (host) => {
      dnsDials.push(host);
      throw new Error("tcp");
    },
    dialUdp: async (host) => {
      dnsDials.push(host);
      throw new Error("udp");
    },
    emit: (packet) => dnsPackets.push(Buffer.from(packet)),
    fakeIp: names,
  });
  await dns.push(buildUdpPacket({ src: "10.1.1.5", dst: "1.1.1.1", sport: 53000, dport: 53, payload: buildDnsQuery("www.baidu.com", 1) }));
  await dns.push(buildUdpPacket({ src: "10.1.1.5", dst: "1.1.1.1", sport: 53001, dport: 53, payload: buildDnsQuery("www.baidu.com", 28) }));
  const answers = dnsPackets.map((packet) => parseUdp(parseIpv4(packet).payload)).filter(Boolean);
  assert.equal(answers.length, 2);
  assert.equal(answers[0].data.readUInt16BE(6), 1);
  assert.equal(answers[1].data.readUInt16BE(6), 0);
  const fakeIp = names.lookup ? [...answers[0].data.subarray(answers[0].data.length - 4)].join(".") : "";
  assert.equal(names.lookup(fakeIp), "www.baidu.com");
  assert.equal(dnsDials.length, 0);
  await dns.push(buildTcpPacket({ src: "10.1.1.5", dst: fakeIp, sport: 44040, dport: 443, seq: 1, ack: 0, flags: 0x02 }));
  assert.deepEqual(dnsDials, ["www.baidu.com"]);
  dns.close();

  if (process.platform === "linux") {
    const require = createRequire(join(dirname(fileURLToPath(import.meta.url)), "../public/agent/lexis-agent.mjs"));
    const addon = require(join(dirname(fileURLToPath(import.meta.url)), "../public/agent/linux/lexis-sockopt.node"));
    const probe = await listen(() => undefined);
    const pending = [];
    probe.on("connection", (socket) => {
      socket.on("error", () => socket.destroy());
      pending.push(socket);
    });
    const local = await dial(probe.address().port);
    const waitRemote = async () => {
      const found = () => pending.find((socket) => socket.remotePort === local.localPort);
      const deadline = Date.now() + 1000;
      while (!found() && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 10));
      return found();
    };
    const remote = await waitRemote();
    assert.ok(remote);
    assert.equal(addon.originalDest(remote._handle.fd), null);
    assert.throws(() => addon.listenTransparent(1), /IP_TRANSPARENT/);
    assert.throws(() => addon.listenTransparentUdp(1), /IP_TRANSPARENT/);
    assert.throws(() => addon.markFd(remote._handle.fd, 255), /SO_MARK/);
    const markedAt = Date.now();
    assert.throws(() => addon.createMarked(255, 4), /SO_MARK/);
    assert.throws(() => addon.connectMarked(255, "127.0.0.1", probe.address().port, 10000), /SO_MARK/);
    assert.ok(Date.now() - markedAt < 500, "打标记不应在主线程里等拨号超时");
    const fd = addon.openSocket(4);
    const sock = new Socket({ fd });
    sock.on("error", () => sock.destroy());
    const started = Date.now();
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("连接没有回来")), 1000);
      sock.once("connect", () => {
        clearTimeout(timer);
        resolve();
      });
      sock.once("error", (err) => {
        clearTimeout(timer);
        reject(err);
      });
      sock.connect({ host: "127.0.0.1", port: probe.address().port, family: 4 });
    });
    assert.ok(Date.now() - started < 500, "Node 连接不应卡住");
    sock.destroy();
    for (const extra of pending) extra.destroy();
    assert.throws(() => addon.openTun("lexis0"), /虚拟网卡没有创建/);
    local.destroy();
    remote.destroy();
    probe.close();
  }

  proxy.close();
  a.server.close();
  b.server.close();
  echo.close();
  console.log("lexis proxy ok");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
