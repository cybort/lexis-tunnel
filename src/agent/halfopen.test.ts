/* V3-5/V3-6: half-open accounting. node --import jiti/register src/agent/halfopen.test.ts */
import assert from "node:assert/strict";
import { acceptSession, halfOpen, type ProsePipe } from "./frame.ts";
import { createIdentity } from "../lib/lexis/crypto.ts";
import { b64 } from "../lib/lexis/bytes.ts";

const k = await createIdentity();
const self = { id: "g", name: "g", role: "gate", publicJwk: k.publicJwk, privateJwk: k.privateJwk, publicRawB64: b64(k.publicRaw), fingerprint: k.fingerprint, pinnedPeerId: null, createdAt: Date.now(), kdf: null } as any;
function pipe(hello: string | null) {
  let closed = false;
  const p: ProsePipe & { closedAt?: number } = {
    async write() { throw new Error("must stay silent"); },
    async read(ms = 0) { if (hello !== null) { const h = hello; hello = null; return h; } await new Promise((r) => setTimeout(r, ms)); throw new Error("timeout"); },
    close() { closed = true; },
  };
  return p;
}
const W = 600;
const run = (ip: string, hello: string | null, extra: Record<string, unknown> = {}) => {
  const t0 = Date.now();
  return acceptSession({ pipe: pipe(hello), self, peers: [], token: "t".repeat(24), handshakeMs: W, sourceIp: ip, maxHalfOpen: 4, maxHalfOpenPerIp: 2, ...extra } as any).then(
    () => assert.fail("accepted"), () => Date.now() - t0);
};
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// V3-5: a bad hello frees its slot at once but the connection is still held until handshakeMs
const bad = Array.from({ length: 4 }, (_, i) => run(`10.0.${i}.1`, "the of and to a in is it you that"));
await sleep(100);
assert.equal(halfOpen.total, 0, "slots released early");
assert.equal(halfOpen.silent, 4, "connections still silent");
const ms = await Promise.all(bad);
for (const m of ms) assert.ok(m >= W - 5 && m < W + 150, `timing unchanged ${m}`);
assert.equal(halfOpen.total, 0); assert.equal(halfOpen.silent, 0); assert.equal(halfOpen.perIp.size, 0);
assert.ok(halfOpen.earlyReleased >= 4);
// silent holders (no hello) still occupy slots until the deadline
const holders = Array.from({ length: 4 }, (_, i) => run(`10.1.${i}.1`, null));
await sleep(50);
assert.equal(halfOpen.total, 4);
const refusedBefore = halfOpen.refused;
const over = run("10.9.9.9", "x");
await sleep(50);
assert.equal(halfOpen.refused, refusedBefore + 1);
await Promise.all([...holders, over]);
assert.equal(halfOpen.total, 0); assert.equal(halfOpen.silent, 0);
// maxSilent hard cap: beyond it, close early (only externally visible change)
const capped = Array.from({ length: 3 }, (_, i) => run(`10.2.${i}.1`, "zz", { maxSilent: 2 }));
const cm = (await Promise.all(capped)).sort((a, b) => a - b);
assert.ok(cm[0] < 100 && cm[2] >= W - 5, `maxSilent ${cm}`);
assert.ok(halfOpen.silentOverflow >= 1);
assert.equal(halfOpen.total, 0); assert.equal(halfOpen.silent, 0);
console.log("halfopen V3-5 ok: early release, silent timing unchanged, holders still capped, maxSilent overflow, counters never negative");

// V3-6: prefix bucketing
import { halfOpenKey } from "./frame.ts";
assert.equal(halfOpenKey("10.0.5.7"), "10.0.5.0/24");
assert.equal(halfOpenKey("::ffff:10.0.5.7"), "10.0.5.0/24");
assert.equal(halfOpenKey("::FFFF:10.0.5.200"), "10.0.5.0/24");
assert.equal(halfOpenKey("::ffff:a00:507"), "10.0.5.0/24");
assert.equal(halfOpenKey("10.0.5.7", 32), "10.0.5.7/32");
assert.equal(halfOpenKey("10.0.5.7", 16), "10.0.0.0/16");
assert.equal(halfOpenKey("2001:db8:1:2:aaaa:bbbb:cccc:dddd"), "2001:db8:1:2:0:0:0:0/64");
assert.equal(halfOpenKey("2001:db8:1:2::1"), halfOpenKey("2001:db8:1:2:ffff::9"));
assert.notEqual(halfOpenKey("2001:db8:1:2::1"), halfOpenKey("2001:db8:1:3::1"));
assert.equal(halfOpenKey("2001:db8::1", 64, 48), "2001:db8:0:0:0:0:0:0/48");
assert.equal(halfOpenKey("fe80::1%eth0"), "fe80:0:0:0:0:0:0:0/64");
assert.equal(halfOpenKey("2001:db8::1", 64, 128), "2001:db8:0:0:0:0:0:1/128");
assert.equal(halfOpenKey("garbage"), "garbage");
// 3 holders from one /24 with per-prefix cap 2: third is refused even with different IPs
const r0 = halfOpen.refused;
const same = [run("10.7.7.1", null), run("10.7.7.2", null), run("10.7.7.3", null)];
await sleep(50);
assert.equal(halfOpen.total, 2); assert.equal(halfOpen.refused, r0 + 1);
assert.equal(halfOpen.perIp.get("10.7.7.0/24"), 2);
await Promise.all(same);
// prefix 32 restores old per-IP semantics
const r1 = halfOpen.refused;
const per = [run("10.8.8.1", null, { halfOpenPrefixV4: 32 }), run("10.8.8.2", null, { halfOpenPrefixV4: 32 }), run("10.8.8.3", null, { halfOpenPrefixV4: 32 })];
await sleep(50);
assert.equal(halfOpen.total, 3); assert.equal(halfOpen.refused, r1);
await Promise.all(per);
assert.equal(halfOpen.total, 0); assert.equal(halfOpen.perIp.size, 0);
console.log("halfopen V3-6 ok: v4/24, mapped v6, v6/64, configurable prefixes, per-prefix cap");

// V3-8: first-byte timeout
function fbPipe(lateMs: number | null, firstByteAt: number | null) {
  let gotByte!: () => void;
  const firstByte = new Promise<void>((r) => (gotByte = r));
  if (firstByteAt !== null) setTimeout(gotByte, firstByteAt);
  let writes = 0;
  const p: ProsePipe & { writes: () => number } = {
    firstByte,
    async write() { writes++; throw new Error("must stay silent"); },
    async read(ms = 0) {
      if (lateMs !== null) { await new Promise((r) => setTimeout(r, lateMs)); return "the of and to a in is it you that"; }
      await new Promise((r) => setTimeout(r, ms)); throw new Error("timeout");
    },
    close() {},
    writes: () => writes,
  };
  return p;
}
const runP = (ip: string, pp: ProsePipe, extra: Record<string, unknown> = {}) => {
  const t0 = Date.now();
  return acceptSession({ pipe: pp, self, peers: [], token: "t".repeat(24), handshakeMs: W, sourceIp: ip, maxHalfOpen: 4, maxHalfOpenPerIp: 2, firstByteMs: 150, ...extra } as any).then(
    () => assert.fail("accepted"), () => Date.now() - t0);
};
const fbBefore = halfOpen.firstByteTimeouts;
// 4 silent holders from 4 /24s: slots are free again after firstByteMs, closing time unchanged
const fbHold = Array.from({ length: 4 }, (_, i) => runP(`10.3.${i}.1`, fbPipe(null, null)));
await sleep(60); assert.equal(halfOpen.total, 4);
await sleep(200); assert.equal(halfOpen.total, 0, "released after first-byte timeout"); assert.equal(halfOpen.silent, 4);
assert.equal(halfOpen.firstByteTimeouts, fbBefore + 4);
// late bytes after the timeout are ignored: no write, still closes at handshakeMs
const late = fbPipe(300, 300);
const lateRun = runP("10.4.0.1", late);
for (const m of await Promise.all(fbHold)) assert.ok(m >= W - 5 && m < W + 150, `fb timing ${m}`);
assert.ok((await lateRun) >= W - 5); assert.equal(late.writes(), 0);
// a byte arriving before the timeout keeps the normal path (slot held until the hello fails)
const early = runP("10.5.0.1", fbPipe(300, 50));
await sleep(200); assert.equal(halfOpen.total, 1, "slot kept: byte seen in time");
await early;
// firstByteMs 0 = off
const off = runP("10.6.0.1", fbPipe(null, null), { firstByteMs: 0 });
await sleep(300); assert.equal(halfOpen.total, 1); await off;
assert.equal(halfOpen.total, 0); assert.equal(halfOpen.silent, 0);
console.log("halfopen V3-8 ok: first-byte timeout releases once, timing unchanged, late bytes ignored, early byte keeps slot, 0=off");
