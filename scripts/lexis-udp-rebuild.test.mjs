import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

const src = fs.readFileSync(new URL("../public/agent/lexis-agent.mjs", import.meta.url), "utf8");
function extract(name) {
  const i = src.indexOf(name);
  let d = 0, j = src.indexOf(") {\n", i) + 2;
  for (let k = j; k < src.length; k++) { if (src[k] === "{") d++; else if (src[k] === "}" && --d === 0) { j = k + 1; break; } }
  return src.slice(i, j);
}
const make = () => new Function("let udpRebuildRetries = 0; const sessionFor = null; const REBUILD_WAIT_MS = 3000;\n" + extract("async function openAcrossRebuild(") + "; return { openAcrossRebuild, retries: () => udpRebuildRetries };")();

const fakeSession = (behaviour) => ({ closed: false, opens: 0, async open(cmd) { this.opens++; return behaviour(this, cmd); } });

test("open on a live session: no retry", async () => {
  const { openAcrossRebuild, retries } = make();
  const s = fakeSession(() => "stream");
  assert.equal(await openAcrossRebuild({}, {}, "udp a 53", { open: async () => s }), "stream");
  assert.equal(retries(), 0);
});

test("session closes during open: waits for the rebuilt session and retries once", async () => {
  const { openAcrossRebuild, retries } = make();
  const old = fakeSession((self) => { self.closed = true; throw new Error("连接关闭"); });
  const fresh = fakeSession(() => "stream2");
  let calls = 0;
  // first lookup returns the dying session, the next still returns it (not yet evicted), then the rebuilt one after 120 ms
  const t0 = Date.now();
  const open = async () => (++calls <= 2 ? old : (await new Promise((r) => setTimeout(r, Math.max(0, 120 - (Date.now() - t0)))), fresh));
  assert.equal(await openAcrossRebuild({}, {}, "udp a 53", { open }), "stream2");
  assert.equal(fresh.opens, 1);
  assert.equal(retries(), 1);
});

test("open fails on a session that is still up (e.g. remote refused): error passes through, no retry", async () => {
  const { openAcrossRebuild } = make();
  const s = fakeSession(() => { throw new Error("对端拒绝"); });
  let calls = 0;
  await assert.rejects(openAcrossRebuild({}, {}, "udp a 53", { open: async () => (calls++, s) }), /对端拒绝/);
  assert.equal(calls, 1);
});

test("rebuild slower than the wait budget: original error after the budget", async () => {
  const { openAcrossRebuild } = make();
  const old = fakeSession((self) => { self.closed = true; throw new Error("连接关闭"); });
  let calls = 0;
  const open = async () => (++calls === 1 ? old : new Promise(() => undefined));
  const t0 = Date.now();
  await assert.rejects(openAcrossRebuild({}, {}, "udp a 53", { open, waitMs: 200 }), /连接关闭/);
  assert.ok(Date.now() - t0 >= 190 && Date.now() - t0 < 1000);
});
