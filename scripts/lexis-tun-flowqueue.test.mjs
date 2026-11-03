import assert from "node:assert/strict";
import test from "node:test";
import { buildTcpPacket, buildUdpPacket, createFlowQueue, flowKeyOf } from "../public/agent/lexis-tun.mjs";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const tcp = (sport, seq) => buildTcpPacket({ src: "10.7.0.1", dst: "45.67.90.10", sport, dport: 80, seq, ack: 0, flags: 0x10, payload: Buffer.from([seq & 0xff]) });
const udp = (sport, b) => buildUdpPacket({ src: "10.7.0.1", dst: "45.67.90.10", sport, dport: 53, payload: Buffer.from([b]) });

test("flowKeyOf separates protocol and both endpoints", () => {
  assert.notEqual(flowKeyOf(tcp(1000, 1)), flowKeyOf(tcp(1001, 1)));
  assert.notEqual(flowKeyOf(tcp(1000, 1)), flowKeyOf(udp(1000, 1)));
  assert.equal(flowKeyOf(tcp(1000, 1)), flowKeyOf(tcp(1000, 2)));
});

test("same flow: strictly in order and one at a time, even when early packets are slow", async () => {
  const order = [];
  let running = 0, maxRunning = 0;
  const q = createFlowQueue({
    capMs: 10000,
    push: async (p) => {
      running++; maxRunning = Math.max(maxRunning, running);
      const seq = p[p.length - 1];
      await sleep(seq === 0 ? 60 : Math.random() * 10);
      order.push(seq); running--;
    },
  });
  const all = [];
  for (let i = 0; i < 20; i++) all.push(q.dispatch(tcp(2000, i)));
  await Promise.all(all);
  assert.deepEqual(order, [...Array(20).keys()]);
  assert.equal(maxRunning, 1);
});

test("a stalled flow does not block other flows, and stays ordered past the cap", async () => {
  const done = [], stalls = [];
  const q = createFlowQueue({
    capMs: 50,
    onStall: (k) => stalls.push(k),
    push: async (p) => {
      const isSlow = flowKeyOf(p) === flowKeyOf(udp(5353, 0));
      if (isSlow && p[p.length - 1] === 0) await sleep(200); // e.g. UDP open during an outage
      done.push(`${isSlow ? "slow" : "fast"}${p[p.length - 1]}`);
    },
  });
  const slow0 = q.dispatch(udp(5353, 0));
  const slow1 = q.dispatch(udp(5353, 1));
  await Promise.all([q.dispatch(tcp(3000, 1)), q.dispatch(tcp(3001, 2)), q.dispatch(udp(4000, 3))]);
  assert.deepEqual(done, ["fast1", "fast2", "fast3"], "other flows finished while the slow one waits");
  await Promise.all([slow0, slow1]);
  assert.deepEqual(done.slice(3), ["slow0", "slow1"], "slow flow kept its order beyond the cap");
  assert.equal(stalls.length, 1);
});

test("bounds: per-flow depth drops extra packets; reader waits at maxInflight", async () => {
  let release;
  const gate = new Promise((r) => (release = r));
  const drops = [];
  const q = createFlowQueue({ capMs: 10000, perFlowMax: 3, maxInflight: 5, onDrop: (k) => drops.push(k), push: () => gate });
  for (let i = 0; i < 5; i++) q.dispatch(tcp(6000, i));
  assert.equal(drops.length, 2);
  assert.equal(q.inflight, 3);
  q.dispatch(tcp(6001, 0)); q.dispatch(tcp(6002, 0));
  assert.equal(q.inflight, 5);
  let ready = false;
  void q.ready().then(() => (ready = true));
  await sleep(10);
  assert.equal(ready, false, "reader paused at maxInflight");
  release();
  await sleep(10);
  assert.equal(ready, true);
  assert.equal(q.inflight, 0);
  assert.equal(q.flows, 0);
});

test("push errors are reported and do not wedge the flow", async () => {
  const errs = [], seen = [];
  const q = createFlowQueue({ capMs: 1000, onError: (e) => errs.push(e.message), push: async (p) => { const s = p[p.length - 1]; if (s === 0) throw new Error("x"); seen.push(s); } });
  await Promise.all([q.dispatch(tcp(7000, 0)), q.dispatch(tcp(7000, 1))]);
  assert.deepEqual(errs, ["x"]);
  assert.deepEqual(seen, [1]);
});
