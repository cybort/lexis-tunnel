import assert from "node:assert/strict";
import { createSocket as createUdp } from "node:dgram";
import fs from "node:fs";
import test from "node:test";

const src = fs.readFileSync(new URL("../public/agent/lexis-agent.mjs", import.meta.url), "utf8");
function extract(name) {
  const i = src.indexOf(name);
  assert.ok(i >= 0, name);
  let d = 0, j = src.indexOf("{", i);
  for (let k = j; k < src.length; k++) { if (src[k] === "{") d++; else if (src[k] === "}" && --d === 0) { j = k + 1; break; } }
  return src.slice(i, j);
}
const exitUdp = new Function("createUdp", "activeConfig", "linkOf", extract("async function exitUdp(") + "; return exitUdp;")(createUdp, { link: { udpIdleMs: 200 } }, (c) => c.link);

async function echoServer() {
  const echo = createUdp("udp4");
  echo.on("message", (m, r) => echo.send(m, r.port, r.address));
  await new Promise((r) => echo.bind(0, "127.0.0.1", r));
  return echo;
}
function trapUncaught() {
  const seen = [];
  const h = (e) => seen.push(e.code || e.message);
  process.on("uncaughtException", h);
  return { seen, off: () => process.off("uncaughtException", h) };
}

test("exitUdp: replies after the stream ended close the socket once (no ERR_SOCKET_DGRAM_NOT_RUNNING)", async () => {
  const echo = await echoServer(); const t = trapUncaught();
  let n = 0;
  const s = { accept: async () => {}, close: async () => {}, write: () => new Promise((_, rej) => setTimeout(() => rej(new Error("ended")), 30)),
    read: async () => (n++ < 4 ? Buffer.from("y") : new Promise((r) => setTimeout(() => r(null), 300))) };
  await exitUdp(s, "127.0.0.1", echo.address().port);
  await new Promise((r) => setTimeout(r, 100));
  t.off(); echo.close();
  assert.deepEqual(t.seen, []);
});

test("exitUdp: reads after the socket closed stop the loop instead of throwing", async () => {
  const echo = await echoServer(); const t = trapUncaught();
  let n = 0;
  const s = { accept: async () => {}, close: async () => {}, write: async () => { throw new Error("closed"); },
    read: async () => { await new Promise((r) => setTimeout(r, 30)); return n++ < 5 ? Buffer.from("x") : null; } };
  await assert.doesNotReject(exitUdp(s, "127.0.0.1", echo.address().port));
  t.off(); echo.close();
  assert.deepEqual(t.seen, []);
});

test("exitUdp: async socket errors after bind are absorbed", { timeout: 5000 }, async () => {
  const t = trapUncaught();
  const real = createUdp;
  let sock;
  const fn = new Function("createUdp", "activeConfig", "linkOf", extract("async function exitUdp(") + "; return exitUdp;")(
    (type) => (sock = real(type)), { link: { udpIdleMs: 200 } }, (c) => c.link);
  let rr;
  const s = { accept: async () => {}, close: async () => rr?.(null), write: async () => {}, read: () => new Promise((r) => (rr = r)) };
  const p = fn(s, "127.0.0.1", 9);
  await new Promise((r) => setTimeout(r, 30));
  sock.emit("error", new Error("boom1"));
  sock.emit("error", new Error("boom2"));
  rr(null);
  await p;
  t.off();
  assert.deepEqual(t.seen, []);
});

test("unhandled rejection guard logs and counts instead of exiting", async () => {
  const lines = [];
  const box = new Function("process", "log", "let unhandledCount = 0;\n" + extract("function installUnhandledGuard(") + "; installUnhandledGuard(); return () => unhandledCount;");
  const handlers = {};
  const count = box({ on: (ev, fn) => (handlers[ev] = fn) }, (l) => lines.push(l));
  assert.equal(typeof handlers.unhandledRejection, "function");
  handlers.unhandledRejection(new Error("stray"));
  assert.equal(count(), 1);
  assert.match(lines[0], /stray/);
});
