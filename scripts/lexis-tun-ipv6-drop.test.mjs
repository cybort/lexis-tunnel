// S0 (C8): packets the IPv4-only tun engine cannot parse are reported by IP version
// through onDrop6 instead of vanishing; IPv4 handling is unchanged.
import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { buildUdpPacket, createEngine, dropInfo } from "../public/agent/lexis-tun.mjs";

function v6(next, len = 40) {
  const b = Buffer.alloc(len);
  b[0] = 0x60;
  b.writeUInt16BE(Math.max(0, len - 40), 4);
  b[6] = next;
  b[7] = 64;
  b.set([0x20, 0x01, 0x0d, 0xb8], 8);
  b.set([0x20, 0x01, 0x0d, 0xb8, 0, 0x45], 24);
  return b;
}

function rig() {
  const drops = [], dials = [];
  const engine = createEngine({
    dialTcp: async (h, p) => { dials.push(`tcp ${h}:${p}`); throw new Error("no"); },
    dialUdp: async (h, p) => { dials.push(`udp ${h}:${p}`); throw new Error("no"); },
    emit: () => undefined,
    onDrop6: (info) => drops.push(info),
  });
  return { engine, drops, dials };
}

test("dropInfo classifies IPv6 by next header and flags truncated / non-IP packets", () => {
  assert.deepEqual(dropInfo(v6(6, 60)), { version: 6, proto: "tcp", reason: "no_ipv6_engine" });
  assert.deepEqual(dropInfo(v6(17, 48)), { version: 6, proto: "udp", reason: "no_ipv6_engine" });
  assert.deepEqual(dropInfo(v6(58, 48)), { version: 6, proto: "icmpv6", reason: "no_ipv6_engine" });
  assert.deepEqual(dropInfo(v6(0, 48)), { version: 6, proto: "other", reason: "no_ipv6_engine" });
  assert.deepEqual(dropInfo(v6(6, 40).subarray(0, 30)), { version: 6, proto: "", reason: "truncated" });
  assert.deepEqual(dropInfo(Buffer.from([0x45, 0, 0])), { version: 4, proto: "", reason: "bad_ipv4" });
  assert.deepEqual(dropInfo(Buffer.from([0x00, 1, 2, 3])), { version: 0, proto: "", reason: "not_ip" });
  assert.deepEqual(dropInfo(Buffer.alloc(0)), { version: 0, proto: "", reason: "not_ip" });
});

test("engine.push reports every unparsable packet once and never dials for it", async () => {
  const { engine, drops, dials } = rig();
  for (const p of [v6(6, 60), v6(17, 48), v6(58, 48), v6(6, 40).subarray(0, 20), Buffer.from([0x45, 0, 0])]) await engine.push(p);
  assert.deepEqual(drops.map((d) => `${d.version}/${d.proto}/${d.reason}`), ["6/tcp/no_ipv6_engine", "6/udp/no_ipv6_engine", "6/icmpv6/no_ipv6_engine", "6//truncated", "4//bad_ipv4"]);
  assert.deepEqual(dials, []);
  engine.close();
});

test("IPv4 packets do not touch onDrop6 and still dial", async () => {
  const { engine, drops, dials } = rig();
  await engine.push(buildUdpPacket({ src: "10.7.0.1", dst: "45.67.89.10", sport: 40000, dport: 5353, payload: Buffer.from("x") }));
  await new Promise((r) => setTimeout(r, 20));
  assert.deepEqual(drops, []);
  assert.deepEqual(dials, ["udp 45.67.89.10:5353"]);
  engine.close();
});

test("createEngine without onDrop6 keeps the old silent behaviour (no throw)", async () => {
  const engine = createEngine({ dialTcp: async () => { throw new Error("no"); }, dialUdp: async () => { throw new Error("no"); }, emit: () => undefined });
  await engine.push(v6(17, 48));
  engine.close();
});

test("agent wires onDrop6 and exports the IPv6 observation metrics", () => {
  const src = fs.readFileSync(new URL("../public/agent/lexis-agent.mjs", import.meta.url), "utf8");
  assert.match(src, /onDrop6: onTunDrop,/);
  for (const name of ["lexis_ipv6_rx_total{proto=", "lexis_ipv6_drop_total{reason=", "lexis_ipv6_flow_open_total{proto=", "lexis_tun_unparsed_total{version="]) assert.ok(src.includes(name), name);
  assert.match(src, /function decide\(config, query\) \{\n {2}const decision = decideRule\(config, query\);/);
});
