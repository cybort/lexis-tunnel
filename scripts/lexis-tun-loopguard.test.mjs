import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { buildTcpPacket, buildUdpPacket, createEngine } from "../public/agent/lexis-tun.mjs";

const GATE = "10.240.2.2";
function rig() {
  const dials = [], drops = [];
  const engine = createEngine({
    dialTcp: async (h, p) => { dials.push(`tcp ${h}:${p}`); throw new Error("no"); },
    dialUdp: async (h, p) => { dials.push(`udp ${h}:${p}`); throw new Error("no"); },
    emit: () => undefined,
    loopGuard: [GATE],
    onLoopDrop: (ip) => drops.push(ip.dst),
  });
  return { engine, dials, drops };
}

test("loop guard: packets to a peer are dropped, never dialled", async () => {
  const { engine, dials, drops } = rig();
  await engine.push(buildTcpPacket({ src: "10.7.0.1", dst: GATE, sport: 40000, dport: 18443, seq: 1, ack: 0, flags: 0x02 }));
  await engine.push(buildUdpPacket({ src: "10.7.0.1", dst: GATE, sport: 40001, dport: 18443, payload: Buffer.from("x") }));
  assert.deepEqual(drops, [GATE, GATE]);
  assert.deepEqual(dials, []);
  engine.close();
});

test("loop guard: other destinations still dial", async () => {
  const { engine, dials, drops } = rig();
  await engine.push(buildTcpPacket({ src: "10.7.0.1", dst: "45.67.90.10", sport: 40002, dport: 80, seq: 1, ack: 0, flags: 0x02 }));
  await new Promise((r) => setTimeout(r, 20));
  assert.deepEqual(drops, []);
  assert.equal(dials.length, 1);
  engine.close();
});

test("tun install script blocks peers after main lookup (unreachable, before the tun table)", () => {
  const src = fs.readFileSync(new URL("../public/agent/lexis-agent.mjs", import.meta.url), "utf8");
  const m = src.match(/prio=150\n\s+for ip in \$PEERS; do[\s\S]*?ip rule add to "\$ip\/32" unreachable priority "\$prio"[\s\S]*?done\n\s+ip route replace default dev lexis0 table "\$TABLE"/);
  assert.ok(m, "unreachable rules for peers present between fwmark(100) and tun table(200)");
});
