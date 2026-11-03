import assert from "node:assert/strict";
import { connect, createServer } from "node:net";
import test from "node:test";
import { serveHttpProxy } from "../public/agent/lexis-http.mjs";

function listen(handler) {
  const server = createServer((socket) => { socket.on("error", () => socket.destroy()); handler(socket); });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server)));
}

// Upstream answers one request with the given raw head + body, then closes (mode none) or stays idle.
async function setup(respHead, body, closeAfter) {
  const upstream = await listen((s) => {
    s.once("data", () => { s.write(respHead + body); if (closeAfter) s.end(); });
  });
  const proxy = await listen((s) => {
    void serveHttpProxy(s, { openUpstream: (h, p) => new Promise((r) => { const u = connect(p, h, () => r(u)); u.on("error", () => {}); }) });
  });
  return { upstream, proxy, uport: upstream.address().port, pport: proxy.address().port };
}

function exchange(pport, req) {
  return new Promise((resolve, reject) => {
    const s = connect(pport, "127.0.0.1", () => s.write(req));
    let buf = "";
    const timer = setTimeout(() => { s.destroy(); resolve({ buf, closed: false }); }, 400);
    s.on("data", (d) => { buf += d.toString("latin1"); });
    s.on("end", () => { clearTimeout(timer); s.destroy(); resolve({ buf, closed: true }); });
    s.on("error", reject);
  });
}

const cases = [
  { name: "客户端 close", ver: "1.1", reqConn: "close", resp: "Content-Length: 2\r\n", want: "close" },
  { name: "上游 close 不影响客户端", ver: "1.1", reqConn: "", resp: "Content-Length: 2\r\nConnection: close\r\n", want: "keep-alive" },
  { name: "双方都不带 close", ver: "1.1", reqConn: "", resp: "Content-Length: 2\r\n", want: "keep-alive" },
  { name: "HTTP/1.0 不带 keep-alive", ver: "1.0", reqConn: "", resp: "Content-Length: 2\r\n", want: "close" },
  { name: "HTTP/1.0 带 keep-alive", ver: "1.0", reqConn: "keep-alive", resp: "Content-Length: 2\r\n", want: "keep-alive" },
  { name: "长度未知 mode none", ver: "1.1", reqConn: "", resp: "", want: "close", closeAfter: true },
];

for (const c of cases) {
  test(`Connection 处理：${c.name}`, async () => {
    const env = await setup(`HTTP/1.1 200 OK\r\n${c.resp}\r\n`, "ok", c.closeAfter);
    try {
      const req = `GET http://127.0.0.1:${env.uport}/ HTTP/${c.ver}\r\nHost: 127.0.0.1:${env.uport}\r\n${c.reqConn ? `Connection: ${c.reqConn}\r\n` : ""}\r\n`;
      const { buf, closed } = await exchange(env.pport, req);
      const head = buf.split("\r\n\r\n")[0];
      assert.match(head, /^HTTP\/1\.1 200/);
      const conns = head.match(/^connection:.*$/gim) || [];
      assert.deepEqual(conns.map((l) => l.split(":")[1].trim().toLowerCase()), [c.want]);
      assert.ok(buf.endsWith("ok"));
      assert.equal(closed, c.want === "close", `连接${c.want === "close" ? "应" : "不应"}被代理关闭`);
    } finally { env.upstream.close(); env.proxy.close(); }
  });
}

// Read exactly one Content-Length response from a persistent client socket.
function readOne(s) {
  return new Promise((resolve, reject) => {
    let buf = "";
    const timer = setTimeout(() => { s.off("data", on); reject(new Error(`响应超时 ${buf.slice(0, 120)}`)); }, 1500);
    const on = (d) => {
      buf += d.toString("latin1");
      const at = buf.indexOf("\r\n\r\n");
      if (at < 0) return;
      const len = Number((buf.slice(0, at).match(/^content-length:\s*(\d+)/im) || [])[1]);
      if (buf.length < at + 4 + len) return;
      clearTimeout(timer); s.off("data", on);
      resolve({ head: buf.slice(0, at), body: buf.slice(at + 4, at + 4 + len) });
    };
    s.on("data", on);
  });
}

async function pathServer(conn) {
  return listen((s) => s.once("data", (d) => {
    const path = d.toString("latin1").split(" ")[1];
    const body = `ok ${path}`;
    s.write(`HTTP/1.1 200 OK\r\nContent-Length: ${body.length}\r\n${conn ? `Connection: ${conn}\r\n` : ""}\r\n${body}`);
    if (conn === "close") s.end();
  }));
}

async function reuse(origins, ver, reqConn) {
  const ups = await Promise.all(origins.map((c) => pathServer(c)));
  let accepted = 0;
  const proxy = await listen((s) => {
    // Count only absolute-form proxy clients. A local health probe may also hit the ephemeral port.
    s.once("data", (chunk) => {
      if (Buffer.from(chunk).includes("http://")) accepted++;
    });
    void serveHttpProxy(s, { openUpstream: (h, p) => new Promise((r) => { const u = connect(p, h, () => r(u)); u.on("error", () => {}); }) });
  });
  const s = connect(proxy.address().port, "127.0.0.1");
  await new Promise((r) => s.once("connect", r));
  let closed = false; s.on("end", () => { closed = true; });
  const out = [];
  try {
    for (let i = 0; i < ups.length; i++) {
      const port = ups[i].address().port;
      const pending = readOne(s);
      s.write(`GET http://127.0.0.1:${port}/r${i} HTTP/${ver}\r\nHost: 127.0.0.1:${port}\r\nConnection: ${reqConn}\r\n\r\n`);
      out.push(await pending);
    }
    await new Promise((r) => setTimeout(r, 100));
    return { out, closed, accepted };
  } finally { s.destroy(); proxy.close(); for (const u of ups) u.close(); }
}

test("HTTP/1.0 带 keep-alive：同一连接连发两次都成功并复用", async () => {
  const { out, closed, accepted } = await reuse(["", ""], "1.0", "keep-alive");
  assert.deepEqual(out.map((r) => r.body), ["ok /r0", "ok /r1"]);
  for (const r of out) assert.match(r.head, /^connection: keep-alive$/im);
  assert.equal(accepted, 1);
  assert.equal(closed, false);
});

test("同一连接访问两个上游，其中一个回 close：两次都成功", async () => {
  const { out, closed, accepted } = await reuse(["close", ""], "1.1", "keep-alive");
  assert.deepEqual(out.map((r) => r.body), ["ok /r0", "ok /r1"]);
  for (const r of out) assert.match(r.head, /^connection: keep-alive$/im);
  assert.equal(accepted, 1);
  assert.equal(closed, false);
});
