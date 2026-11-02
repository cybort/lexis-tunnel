import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { connect, createServer } from "node:net";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { serveHttpProxy } from "../public/agent/lexis-http.mjs";
import { buildTcpPacket, createEngine, parseIpv4, parseTcp } from "../public/agent/lexis-tun.mjs";

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
    assert.throws(() => addon.markFd(remote._handle.fd, 255), /SO_MARK/);
    assert.throws(() => addon.connectMarked(255, "127.0.0.1", probe.address().port, 500), /SO_MARK/);
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
