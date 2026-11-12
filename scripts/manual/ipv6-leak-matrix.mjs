#!/usr/bin/env node
// S0 dual-stack leak matrix (manual, root, Linux). Builds three throwaway netns (app / phys / gate),
// runs a real edge agent (system-forward) in app and a real gate agent in gate for each cell, probes
// IPv4 + IPv6 TCP / UDP / DNS from app with plain sockets (no lexis code), captures the physical
// interface (phys:p0) with tcpdump and counts direct packets with BPF filters (independent of
// every lexis counter), and scrapes the agent's /metrics (lexis_ipv6_*, lexis_dns_*).
// Never touches the host network: everything lives in the three netns (plus /etc/netns/<ns>
// resolv.conf/hosts, removed at exit); host ip rule / ip -6 rule / nft / netns are snapshotted
// before and after and compared.
//
// Usage (run a copy, never the file of a tree under test while it runs):
//   sudo nice -n 19 taskset -c 6,7 node scripts/manual/ipv6-leak-matrix.mjs --out DIR \
//     --tree base=/path/c2c9754 --tree p=/path/c2c9754+P ... \
//     --cell NAME:TREE:METHOD:IPV6[:opt,opt] ... [--n 1000] [--small 200] [--conc 20]
//     [--path-prefix DIR:DIR] [--tcpdump /path/tcpdump]
//   METHOD redirect|tproxy|tun, IPV6 block|off. opts: dnsoff (linux.dnsRedirect=false),
//   force6 (after start, route the IPv6 target prefix into lexis0 so IPv6 packets reach the tun
//   engine: proves the S0 observation points count them).
// Internal subcommands (run by the matrix inside a netns): --serve QLOG, --probe KIND N CONC.
import { spawn, execFileSync } from "node:child_process";
import { createSocket } from "node:dgram";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { fileURLToPath } from "node:url";

const SELF = fileURLToPath(import.meta.url);
const NS = { app: "s0m-app", phys: "s0m-phys", gate: "s0m-gate" };
const T4 = "45.67.89.10", T6 = "2001:db8:45::10", ECHO_TCP = 8080, ECHO_UDP = 5353;
const DNS4 = ["1.1.1.1", "8.8.8.8", "192.168.77.1"], DNS6 = ["2606:4700:4700::1111", "fd00:99::1"];
const ROUTER = "192.168.77.1", GATE = "10.98.0.2", GATE_PORT = 18443;
const A4 = "93.184.216.34";

// ---------------------------------------------------------------- DNS wire helpers
function dnsQuery(id, name, qtype) {
  const labels = name.split(".").map((l) => Buffer.concat([Buffer.from([l.length]), Buffer.from(l)]));
  const h = Buffer.alloc(12);
  h.writeUInt16BE(id, 0); h.writeUInt16BE(0x0100, 2); h.writeUInt16BE(1, 4);
  const t = Buffer.alloc(4); t.writeUInt16BE(qtype, 0); t.writeUInt16BE(1, 2);
  return Buffer.concat([h, ...labels, Buffer.from([0]), t]);
}
function dnsAnswer(q) {
  if (q.length < 12) return null;
  let i = 12;
  while (i < q.length && q[i] !== 0) i += q[i] + 1;
  if (i + 5 > q.length) return null;
  const qtype = q.readUInt16BE(i + 1), qend = i + 5;
  const h = Buffer.from(q.subarray(0, 12));
  h.writeUInt16BE(0x8180, 2); h.writeUInt16BE(1, 4); h.writeUInt16BE(qtype === 1 || qtype === 28 ? 1 : 0, 6); h.writeUInt32BE(0, 8);
  let ans = Buffer.alloc(0);
  if (qtype === 1 || qtype === 28) {
    const rd = qtype === 1 ? Buffer.from(A4.split(".").map(Number)) : ipv6Bytes(T6);
    const a = Buffer.alloc(12); a.writeUInt16BE(0xc00c, 0); a.writeUInt16BE(qtype, 2); a.writeUInt16BE(1, 4); a.writeUInt32BE(60, 6); a.writeUInt16BE(rd.length, 10);
    ans = Buffer.concat([a, rd]);
  }
  return Buffer.concat([h, q.subarray(12, qend), ans]);
}
function ipv6Bytes(a) {
  const [l, r = ""] = a.split("::");
  const ls = l ? l.split(":") : [], rs = r ? r.split(":") : [];
  const all = [...ls, ...Array(8 - ls.length - rs.length).fill("0"), ...rs];
  const b = Buffer.alloc(16); all.forEach((x, k) => b.writeUInt16BE(parseInt(x, 16), k * 2)); return b;
}
const qtypeOf = (q) => { let i = 12; while (i < q.length && q[i] !== 0) i += q[i] + 1; return i + 3 <= q.length ? q.readUInt16BE(i + 1) : -1; };

// ---------------------------------------------------------------- --serve (inside phys)
function serve(qlogPath) {
  const qlog = qlogPath ? fs.openSync(qlogPath, "a") : null;
  const logq = (proto, addr, q) => { if (qlog) fs.writeSync(qlog, `dnsq ${proto} ${addr} ${qtypeOf(q)}\n`); };
  for (const host of [T4, T6]) {
    net.createServer((c) => { c.setTimeout(5000, () => c.destroy()); c.once("data", (d) => c.end(d)); c.on("error", () => undefined); }).listen({ host, port: ECHO_TCP, backlog: 1024 });
    const u = createSocket(host.includes(":") ? "udp6" : "udp4"); u.on("message", (m, r) => u.send(m, r.port, r.address)); u.bind(ECHO_UDP, host);
  }
  for (const host of [...DNS4, ...DNS6]) {
    const u = createSocket(host.includes(":") ? "udp6" : "udp4");
    u.on("message", (m, r) => { logq("udp", host, m); const a = dnsAnswer(m); if (a) u.send(a, r.port, r.address); });
    u.bind(53, host);
    net.createServer((c) => {
      let buf = Buffer.alloc(0);
      c.setTimeout(5000, () => c.destroy()); c.on("error", () => undefined);
      c.on("data", (d) => {
        buf = Buffer.concat([buf, d]);
        if (buf.length < 2 || buf.length < 2 + buf.readUInt16BE(0)) return;
        const q = buf.subarray(2, 2 + buf.readUInt16BE(0)); logq("tcp", host, q);
        const a = dnsAnswer(q); const l = Buffer.alloc(2); l.writeUInt16BE(a ? a.length : 0); c.end(a ? Buffer.concat([l, a]) : undefined);
      });
    }).listen({ host, port: 53, backlog: 256 });
  }
  console.log("serving");
}

// ---------------------------------------------------------------- --probe (inside app)
const PROBES = {
  v4tcp: { desc: `TCP echo ${T4}:${ECHO_TCP}`, run: () => tcpEcho(T4, ECHO_TCP, randomBytes(16)) },
  v4udp: { desc: `UDP echo ${T4}:${ECHO_UDP} (non-53 UDP)`, run: () => udpEcho(T4, ECHO_UDP, randomBytes(12)) },
  v6tcp: { desc: `TCP echo [${T6}]:${ECHO_TCP}`, run: () => tcpEcho(T6, ECHO_TCP, randomBytes(16)) },
  v6udp: { desc: `UDP echo [${T6}]:${ECHO_UDP}`, run: () => udpEcho(T6, ECHO_UDP, randomBytes(12)) },
  dns1u: { desc: "dig @1.1.1.1 (A, connected UDP)", run: (i) => udpDns("1.1.1.1", i) },
  dns1t: { desc: "dig +tcp @1.1.1.1 (A)", run: (i) => tcpDns("1.1.1.1", i) },
  dnsru: { desc: `A via the resolv.conf router ${ROUTER} (UDP)`, run: (i) => udpDns(ROUTER, i) },
  dns6u: { desc: "dig @2606:4700:4700::1111 (A over UDP/IPv6)", run: (i) => udpDns(DNS6[0], i) },
  dnsula: { desc: "dig @fd00:99::1 (ULA resolver, UDP/IPv6)", run: (i) => udpDns(DNS6[1], i) },
  socks6: { desc: `SOCKS5 CONNECT [${T6}]:${ECHO_TCP} via 127.0.0.1:18180 (flow-open counter)`, run: () => socks6() },
};
const TIMEOUT = 1500;
function timed(p) { return Promise.race([p, new Promise((_, rej) => setTimeout(() => rej(Object.assign(new Error("timeout"), { code: "TIMEOUT" })), TIMEOUT))]); }
function tcpEcho(host, port, payload) {
  return timed(new Promise((res, rej) => {
    const c = net.connect({ host, port }); let got = Buffer.alloc(0);
    c.on("connect", () => c.write(payload)); c.on("error", (e) => { c.destroy(); rej(e); });
    c.on("data", (d) => { got = Buffer.concat([got, d]); if (got.length >= payload.length) { c.destroy(); if (got.subarray(0, payload.length).equals(payload)) res("ok"); else rej(Object.assign(new Error("mismatch"), { code: "MISMATCH" })); } });
    c.setTimeout(TIMEOUT, () => c.destroy());
  }));
}
function udpRound(host, port, payload, check) {
  const s = createSocket(host.includes(":") ? "udp6" : "udp4");
  return timed(new Promise((res, rej) => {
    s.on("error", rej);
    s.connect(port, host, (err) => { if (err) return rej(err); s.send(payload, (e) => { if (e) rej(e); }); });
    s.on("message", (m) => { const r = check(m); if (r) res(r); });
  })).finally(() => { try { s.close(); } catch { /* closed */ } });
}
const udpEcho = (h, p, payload) => udpRound(h, p, payload, (m) => (m.equals(payload) ? "ok" : null));
function dnsOk(id, m) { if (m.length < 12 || m.readUInt16BE(0) !== id) return null; return m.readUInt16BE(6) > 0 ? "ok" : "noanswer"; }
function udpDns(server, i) { const id = (i * 7 + 1) & 0xffff; return udpRound(server, 53, dnsQuery(id, `s0-${i}-${randomBytes(3).toString("hex")}.example.com`, 1), (m) => dnsOk(id, m)); }
function tcpDns(server, i) {
  const id = (i * 7 + 3) & 0xffff, q = dnsQuery(id, `s0t-${i}-${randomBytes(3).toString("hex")}.example.com`, 1), l = Buffer.alloc(2); l.writeUInt16BE(q.length);
  return timed(new Promise((res, rej) => {
    const c = net.connect({ host: server, port: 53 }); let got = Buffer.alloc(0);
    c.on("connect", () => c.write(Buffer.concat([l, q]))); c.on("error", (e) => { c.destroy(); rej(e); });
    c.on("data", (d) => { got = Buffer.concat([got, d]); if (got.length >= 2 && got.length >= 2 + got.readUInt16BE(0)) { c.destroy(); const r = dnsOk(id, got.subarray(2)); if (r) res(r); else rej(new Error("bad")); } });
  }));
}
function socks6() {
  return timed(new Promise((res, rej) => {
    const c = net.connect({ host: "127.0.0.1", port: 18180 }); let stage = 0, got = Buffer.alloc(0); const payload = randomBytes(16);
    c.on("error", (e) => { c.destroy(); rej(e); });
    c.on("connect", () => c.write(Buffer.from([5, 1, 0])));
    c.on("data", (d) => {
      got = Buffer.concat([got, d]);
      if (stage === 0 && got.length >= 2) { got = got.subarray(2); stage = 1; const p = Buffer.alloc(2); p.writeUInt16BE(ECHO_TCP); c.write(Buffer.concat([Buffer.from([5, 1, 0, 4]), ipv6Bytes(T6), p])); }
      if (stage === 1 && got.length >= 2) { if (got[1] !== 0) { c.destroy(); return rej(Object.assign(new Error("socks"), { code: `SOCKS_${got[1]}` })); } if (got.length >= 10) { got = got.subarray(got[3] === 4 ? 22 : 10); stage = 2; c.write(payload); } }
      if (stage === 2 && got.length >= 16) { c.destroy(); if (got.subarray(0, 16).equals(payload)) res("ok"); else rej(new Error("mismatch")); }
    });
  }));
}
async function probe(kind, n, conc) {
  const p = PROBES[kind]; if (!p) throw new Error(`unknown probe ${kind}`);
  const out = { kind, desc: p.desc, n, conc, ok: 0, results: {} }; let next = 0;
  const worker = async () => { while (next < n) { const i = next++; let r; try { r = await p.run(i); } catch (e) { r = e.code || e.message; } out.results[r] = (out.results[r] || 0) + 1; if (r === "ok") out.ok += 1; } };
  await Promise.all(Array.from({ length: Math.min(conc, n) }, worker));
  console.log(JSON.stringify(out));
}

// ---------------------------------------------------------------- matrix (host side, root)
const sh = (cmd, args, opt = {}) => { try { return execFileSync(cmd, args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], ...opt }); } catch (e) { if (opt.must) throw e; return `${e.stdout || ""}${e.stderr || ""}`; } };
const nsx = (ns, ...a) => sh("ip", ["netns", "exec", ns, ...a]);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
function hostSnap() { return { rule4: sh("ip", ["rule"]), rule6: sh("ip", ["-6", "rule"]), nft: sh("nft", ["list", "ruleset"]), netns: sh("ip", ["netns", "list"]) }; }
function delns(pids) {
  for (const p of pids) { try { process.kill(p, "SIGCONT"); process.kill(p, "SIGTERM"); } catch { /* gone */ } }
  for (const ns of Object.values(NS)) for (const pid of sh("ip", ["netns", "pids", ns]).split(/\s+/).filter(Boolean)) { try { process.kill(Number(pid), "SIGKILL"); } catch { /* gone */ } }
  for (const ns of Object.values(NS)) sh("ip", ["netns", "del", ns]);
}
function mkns(out, tag, pids) {
  const ip = (...a) => sh("ip", a, { must: true });
  for (const ns of Object.values(NS)) { ip("netns", "add", ns); ip("-n", ns, "link", "set", "lo", "up"); }
  ip("link", "add", "eth0", "netns", NS.app, "type", "veth", "peer", "name", "p0", "netns", NS.phys);
  ip("link", "add", "g0", "netns", NS.gate, "type", "veth", "peer", "name", "q0", "netns", NS.phys);
  const addr = [[NS.app, "10.99.0.2/24", "eth0"], [NS.app, "192.168.77.2/24", "eth0"], [NS.phys, "10.99.0.1/24", "p0"], [NS.phys, "192.168.77.1/24", "p0"], [NS.gate, "10.98.0.2/24", "g0"], [NS.phys, "10.98.0.1/24", "q0"]];
  for (const [ns, a, d] of addr) ip("-n", ns, "addr", "add", a, "dev", d);
  const addr6 = [[NS.app, "2001:db8:99::2/64", "eth0"], [NS.app, "fd00:99::2/64", "eth0"], [NS.phys, "2001:db8:99::1/64", "p0"], [NS.phys, "fd00:99::1/64", "p0"], [NS.gate, "2001:db8:98::2/64", "g0"], [NS.phys, "2001:db8:98::1/64", "q0"]];
  for (const [ns, a, d] of addr6) ip("-n", ns, "-6", "addr", "add", a, "dev", d, "nodad");
  for (const [ns, d] of [[NS.app, "eth0"], [NS.phys, "p0"], [NS.phys, "q0"], [NS.gate, "g0"]]) ip("-n", ns, "link", "set", d, "up");
  nsx(NS.phys, "sysctl", "-qw", "net.ipv4.ip_forward=1"); nsx(NS.phys, "sysctl", "-qw", "net.ipv6.conf.all.forwarding=1");
  for (const a of [T4, ...DNS4.filter((d) => d !== ROUTER)]) ip("-n", NS.phys, "addr", "add", `${a}/32`, "dev", "lo");
  for (const a of [T6, DNS6[0]]) ip("-n", NS.phys, "-6", "addr", "add", `${a}/128`, "dev", "lo", "nodad");
  ip("-n", NS.app, "route", "add", "default", "via", "10.99.0.1"); ip("-n", NS.gate, "route", "add", "default", "via", "10.98.0.1");
  ip("-n", NS.app, "-6", "route", "add", "default", "via", "2001:db8:99::1"); ip("-n", NS.gate, "-6", "route", "add", "default", "via", "2001:db8:98::1");
  const t = spawn("ip", ["netns", "exec", NS.phys, process.execPath, SELF, "--serve", path.join(out, `${tag}.qlog`)], { stdio: ["ignore", fs.openSync(path.join(out, `${tag}.targets.log`), "w"), "inherit"] });
  pids.push(t.pid);
}
function install(tree, dir) {
  fs.mkdirSync(path.join(dir, "linux"), { recursive: true });
  const src = path.join(tree, "public/agent");
  for (const f of fs.readdirSync(src)) if (f.endsWith(".mjs") || f === "zstd.wasm" || f === "lexis.config.json") fs.copyFileSync(path.join(src, f), path.join(dir, f));
  for (const d of [dir, path.join(dir, "linux")]) fs.copyFileSync(path.join(src, "linux/lexis-sockopt.node"), path.join(d, "lexis-sockopt.node"));
}
async function genconf(edgeDir, gateDir, method, ipv6, opts) {
  const { createIdentity } = await import(`${edgeDir}/lexis-frame.mjs?${Date.now()}`);
  const b64 = (u) => Buffer.from(u).toString("base64");
  const base = JSON.parse(fs.readFileSync(`${edgeDir}/lexis.config.json`, "utf8"));
  const e = await createIdentity(), g = await createIdentity(), token = randomBytes(18).toString("hex");
  const ident = (x, id) => ({ id, name: id, publicJwk: x.publicJwk, privateJwk: x.privateJwk, publicRawB64: b64(x.publicRaw) });
  const common = { geositeUrl: "", geoipUrl: "", heartbeatSec: 15 };
  const edge = { ...base, ...common, role: "edge", mode: "system-forward", statusHost: "127.0.0.1", statusPort: 18790,
    inbounds: [{ id: "s", tag: "socks", protocol: "socks", listen: "127.0.0.1", port: 18180, targetHost: "", targetPort: 0 },
      { id: "x", tag: "transparent", protocol: "transparent", listen: "127.0.0.1", port: 12345, targetHost: "", targetPort: 0 }],
    linux: { method, mark: 4732, table: 166, dnsRedirect: !opts.includes("dnsoff"), ipv6 },
    link: { ...base.link, token }, identity: ident(e, "edge1"),
    peers: [{ id: "gate1", name: "gate1", publicRawB64: b64(g.publicRaw), endpoint: `${GATE}:${GATE_PORT}` }] };
  const gate = { ...base, ...common, role: "gate", mode: "fixed-port", statusHost: "127.0.0.1", statusPort: 18791,
    inbounds: [{ id: "t", tag: "tunnel", protocol: "tunnel", listen: "0.0.0.0", port: GATE_PORT, targetHost: "", targetPort: 0 }],
    link: { ...base.link, token }, identity: ident(g, "gate1"),
    peers: [{ id: "edge1", name: "edge1", publicRawB64: b64(e.publicRaw), endpoint: "10.99.0.2:1", exit: true }] };
  fs.writeFileSync(`${edgeDir}/lexis.config.json`, JSON.stringify(edge, null, 2));
  fs.writeFileSync(`${gateDir}/lexis.config.json`, JSON.stringify(gate, null, 2));
}
// Independent pcap counts on phys:p0 (the app's physical uplink). "direct" = the packet left the
// app netns towards a target itself instead of inside the tunnel to the gate.
const FILTERS = {
  v6_to_target: `ip6 and dst host ${T6}`,
  v6_tcp_to_target: `ip6 and tcp and dst host ${T6}`,
  v6_udp_to_target: `ip6 and udp and dst host ${T6}`,
  v6_dst53: "ip6 and dst port 53",
  v6_any_out: "ip6 and src net 2001:db8:99::/64 and not icmp6",
  v4_udp_to_target: `ip and udp and dst host ${T4}`,
  v4_tcp_to_target: `ip and tcp and dst host ${T4}`,
  v4_udp_dst53: "ip and udp and dst port 53",
  v4_tcp_dst53: "ip and tcp and dst port 53",
  v4_udp53_to_1111: "ip and udp and dst port 53 and dst host 1.1.1.1",
  v4_dst53_router: `ip and dst port 53 and dst host ${ROUTER}`,
  v4_udp_non53_out: "ip and udp and src net 10.99.0.0/24 and not dst port 53 and not dst host 10.98.0.2",
  to_gate: `dst host ${GATE} and dst port ${GATE_PORT}`,
  total: "",
};
function pcapCount(td, file) {
  const out = {};
  for (const [k, f] of Object.entries(FILTERS)) out[k] = sh(td, ["-Z", "root", "-nn", "-r", file, ...(f ? [f] : [])]).split("\n").filter((l) => /^\d/.test(l)).length;
  return out;
}
async function metrics() {
  const txt = nsx(NS.app, process.execPath, "-e", "fetch('http://127.0.0.1:18790/metrics').then(r=>r.text()).then(t=>console.log(t)).catch(e=>console.log('ERR '+e.message))");
  const want = {};
  for (const line of txt.split("\n")) if (/^lexis_(ipv6_|tun_unparsed|dns_hijacked|dns_local_listening|system_refused|tun_packets)/.test(line)) { const i = line.lastIndexOf(" "); want[line.slice(0, i)] = Number(line.slice(i + 1)); }
  return { raw: txt, picked: want };
}
async function cell(cfg, spec) {
  const [tag, treeName, method, ipv6, optStr = ""] = spec.split(":"); const opts = optStr.split(",").filter(Boolean);
  const tree = cfg.trees[treeName]; if (!tree) throw new Error(`cell ${tag}: unknown tree ${treeName}`);
  const out = cfg.out, R = path.join(out, `${tag}.run`), pids = [];
  fs.rmSync(R, { recursive: true, force: true }); install(tree, `${R}/edge`); install(tree, `${R}/gate`);
  await genconf(`${R}/edge`, `${R}/gate`, method, ipv6, opts);
  mkns(out, tag, pids); await sleep(500);
  const PATH = `${cfg.pathPrefix ? `${cfg.pathPrefix}:` : ""}/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`;
  const rules = () => ["iptables-save", "ip6tables-save"].map((c) => `## ${c}\n${nsx(NS.app, "env", `PATH=${PATH}`, c)}`).join("\n") + `\n## nft\n${nsx(NS.app, "nft", "list", "ruleset")}\n## ip rule\n${nsx(NS.app, "ip", "rule")}\n## ip -6 rule\n${nsx(NS.app, "ip", "-6", "rule")}\n## ip -6 route all\n${nsx(NS.app, "ip", "-6", "route", "show", "table", "all")}`;
  const g = spawn("ip", ["netns", "exec", NS.gate, "env", `PATH=${PATH}`, process.execPath, `${R}/gate/lexis-agent.mjs`, "--config", `${R}/gate/lexis.config.json`], { stdio: ["ignore", fs.openSync(`${out}/${tag}.gate.log`, "w"), "inherit"] }); pids.push(g.pid);
  await sleep(1500);
  const edgeLog = `${out}/${tag}.edge.log`;
  const e = spawn("ip", ["netns", "exec", NS.app, "env", `PATH=${PATH}`, process.execPath, `${R}/edge/lexis-agent.mjs`, "--config", `${R}/edge/lexis.config.json`], { stdio: ["ignore", fs.openSync(edgeLog, "w"), fs.openSync(`${out}/${tag}.edge.err`, "w")] }); pids.push(e.pid);
  for (let i = 0; i < 60 && !/状态页|常驻中/.test(fs.readFileSync(edgeLog, "utf8")); i += 1) await sleep(250);
  await sleep(4000);
  if (opts.includes("force6")) fs.writeFileSync(`${out}/${tag}.force6.txt`, nsx(NS.app, "ip", "-6", "route", "replace", "2001:db8:45::/64", "dev", "lexis0") + nsx(NS.app, "ip", "-6", "route", "get", T6));
  fs.writeFileSync(`${out}/${tag}.rules.txt`, rules());
  const m0 = await metrics();
  const pcap = `${out}/${tag}.p0.pcap`;
  const td = spawn("ip", ["netns", "exec", NS.phys, cfg.tcpdump, "-Z", "root", "-i", "p0", "-U", "--immediate-mode", "-B", "8192", "-s", "128", "-w", pcap], { stdio: ["ignore", "ignore", fs.openSync(`${out}/${tag}.tcpdump.err`, "w")] });
  await sleep(1500);
  const probes = {};
  for (const [kind, n] of cfg.plan) {
    const r = nsx(NS.app, process.execPath, SELF, "--probe", kind, String(n), String(cfg.conc));
    try { probes[kind] = JSON.parse(r.trim().split("\n").pop()); } catch { probes[kind] = { kind, error: r.slice(0, 400) }; }
  }
  await sleep(2000); td.kill("SIGINT"); await new Promise((r) => td.once("exit", r));
  const m1 = await metrics();
  fs.writeFileSync(`${out}/${tag}.metrics.txt`, m1.raw);
  const qlog = fs.existsSync(`${out}/${tag}.qlog`) ? fs.readFileSync(`${out}/${tag}.qlog`, "utf8").split("\n").filter(Boolean) : [];
  const qcount = {}; for (const l of qlog) { const k = l.split(" ").slice(1, 3).join(" "); qcount[k] = (qcount[k] || 0) + 1; }
  const res = { tag, tree: treeName, treePath: tree, method, ipv6, opts, probes, p0: pcapCount(cfg.tcpdump, pcap), targetDnsQueries: qcount, metricsBefore: m0.picked, metricsAfter: m1.picked,
    // takeover refused: the agent's own gauge when it has one, else the script's LEXIS-REFUSE line
    refused: "lexis_system_refused" in m1.picked ? m1.picked.lexis_system_refused === 1 : /LEXIS-REFUSE/.test(fs.readFileSync(edgeLog, "utf8")) };
  fs.writeFileSync(`${out}/${tag}.json`, JSON.stringify(res, null, 2));
  delns(pids); await sleep(300);
  fs.chmodSync(pcap, 0o600);
  return res;
}
function table(rows) {
  const h = ["cell", "tree", "method", "ipv6", "v6tcp ok", "v6udp ok", "p0 v6→target", "v4udp ok", "p0 v4 udp→target", "dns1u ok", "p0 v4 udp53", "p0 v4 tcp53", "p0 v6 53", "p0 →gate", "ipv6_rx", "ipv6_open", "refused"];
  const sum = (o, re) => Object.entries(o || {}).filter(([k]) => re.test(k)).reduce((a, [, v]) => a + v, 0);
  const lines = [`| ${h.join(" | ")} |`, `|${h.map(() => "---").join("|")}|`];
  for (const r of rows) {
    const pr = (k) => (r.probes[k] ? `${r.probes[k].ok}/${r.probes[k].n}` : "-");
    lines.push(`| ${[r.tag, r.tree, r.method, r.ipv6, pr("v6tcp"), pr("v6udp"), r.p0.v6_to_target, pr("v4udp"), r.p0.v4_udp_to_target, pr("dns1u"), r.p0.v4_udp_dst53, r.p0.v4_tcp_dst53, r.p0.v6_dst53, r.p0.to_gate, sum(r.metricsAfter, /^lexis_ipv6_rx_total/), sum(r.metricsAfter, /^lexis_ipv6_flow_open_total/), r.refused ? "y" : ""].join(" | ")} |`);
  }
  return lines.join("\n");
}
async function matrix(argv) {
  const cfg = { trees: {}, cells: [], n: 1000, small: 200, conc: 20, tcpdump: "tcpdump", pathPrefix: "", out: "" };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i], v = argv[i + 1];
    if (a === "--tree") { const [k, p] = v.split("="); cfg.trees[k] = path.resolve(p); i += 1; }
    else if (a === "--cell") { cfg.cells.push(v); i += 1; }
    else if (["--n", "--small", "--conc"].includes(a)) { cfg[a.slice(2)] = Number(v); i += 1; }
    else if (a === "--out") { cfg.out = path.resolve(v); i += 1; }
    else if (a === "--tcpdump") { cfg.tcpdump = v; i += 1; }
    else if (a === "--path-prefix") { cfg.pathPrefix = v; i += 1; }
    else throw new Error(`unknown arg ${a}`);
  }
  if (!cfg.out || !cfg.cells.length) throw new Error("need --out and --cell");
  if (process.getuid?.() !== 0) throw new Error("run as root");
  for (const ns of Object.values(NS)) if (sh("ip", ["netns", "list"]).split("\n").some((l) => l.split(" ")[0] === ns)) throw new Error(`refuse: netns ${ns} exists`);
  for (const ns of [NS.app, NS.gate]) if (fs.existsSync(`/etc/netns/${ns}`)) throw new Error(`refuse: /etc/netns/${ns} exists`);
  cfg.plan = [["v6tcp", cfg.n], ["v6udp", cfg.n], ["v4udp", cfg.n], ["dns1u", cfg.n], ["dns1t", cfg.small], ["dnsru", cfg.small], ["dns6u", cfg.small], ["dnsula", cfg.small], ["v4tcp", cfg.small], ["socks6", cfg.small]];
  fs.mkdirSync(cfg.out, { recursive: true });
  const before = hostSnap(); fs.writeFileSync(`${cfg.out}/host-before.json`, JSON.stringify(before, null, 2));
  fs.mkdirSync(`/etc/netns/${NS.app}`, { recursive: true }); fs.mkdirSync(`/etc/netns/${NS.gate}`, { recursive: true });
  fs.writeFileSync(`/etc/netns/${NS.app}/resolv.conf`, `nameserver ${ROUTER}\noptions timeout:2 attempts:1\n`);
  fs.writeFileSync(`/etc/netns/${NS.gate}/resolv.conf`, "nameserver 1.1.1.1\noptions timeout:2 attempts:1\n");
  const cleanup = () => { delns([]); for (const ns of [NS.app, NS.gate]) fs.rmSync(`/etc/netns/${ns}`, { recursive: true, force: true }); try { fs.rmdirSync("/etc/netns"); } catch { /* not empty / absent */ } };
  process.on("SIGINT", () => { cleanup(); process.exit(130); }); process.on("SIGTERM", () => { cleanup(); process.exit(143); });
  const rows = [];
  try {
    for (const spec of cfg.cells) { const t0 = Date.now(); const r = await cell(cfg, spec); rows.push(r); console.log(`cell ${r.tag} done in ${Math.round((Date.now() - t0) / 1000)}s`); fs.writeFileSync(`${cfg.out}/MATRIX.md`, `${table(rows)}\n`); }
  } finally { cleanup(); }
  const after = hostSnap(); fs.writeFileSync(`${cfg.out}/host-after.json`, JSON.stringify(after, null, 2));
  const cmp = Object.keys(before).map((k) => `host ${k}: ${before[k] === after[k] ? "identical" : "DIFFERENT"}`).join("\n");
  fs.writeFileSync(`${cfg.out}/host-compare.txt`, `${cmp}\n`); console.log(cmp);
  fs.writeFileSync(`${cfg.out}/MATRIX.json`, JSON.stringify({ trees: cfg.trees, plan: cfg.plan, filters: FILTERS, rows }, null, 2));
}

const [mode, ...rest] = process.argv.slice(2);
if (mode === "--serve") serve(rest[0]);
else if (mode === "--probe") await probe(rest[0], Number(rest[1]), Number(rest[2] || 20));
else await matrix([mode, ...rest].filter((x) => x !== undefined));
