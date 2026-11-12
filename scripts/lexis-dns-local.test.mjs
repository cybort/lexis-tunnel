// U2 (dns-local-server): the local DNS service (UDP+TCP on 127.0.0.1 and ::1) and the 53 hijack
// that apply-forward.sh installs for redirect, tproxy and tun. Script runs use fake
// id/ip/iptables/ip6tables/nft. r2: hijack whatever dnsRedirect says, IPv6 53, no half state.
import assert from "node:assert/strict";
import { createSocket } from "node:dgram";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import { connect } from "node:net";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { dnsQtype, startDnsLocal } from "../public/agent/lexis-dns-local.mjs";
import { buildDnsQuery, createFakeIp } from "../public/agent/lexis-tun.mjs";

const src = fs.readFileSync(new URL("../public/agent/lexis-agent.mjs", import.meta.url), "utf8");
function extract(name) {
  const i = src.indexOf(name);
  let d = 0, j = src.indexOf("{", i);
  for (let k = j; k < src.length; k++) { if (src[k] === "{") d++; else if (src[k] === "}" && --d === 0) { j = k + 1; break; } }
  return src.slice(i, j);
}
const forwardScript = new Function("platform", "transparentPort", "GEOIP",
  extract("function peerAddrs(") + "\n" + extract("function forwardScript(") + "; return forwardScript;")(() => "linux", () => 12345, { private: [] });

function udpAsk(port, query, host = "127.0.0.1") {
  return new Promise((resolve, reject) => {
    const s = createSocket(host.includes(":") ? "udp6" : "udp4");
    const timer = setTimeout(() => { s.close(); resolve(null); }, 1500);
    s.on("message", (msg) => { clearTimeout(timer); s.close(); resolve(msg); });
    s.send(query, port, host, (err) => err && reject(err));
  });
}
function tcpAsk(port, queries) {
  return new Promise((resolve, reject) => {
    const c = connect(port, "127.0.0.1");
    let buf = Buffer.alloc(0);
    const out = [];
    c.on("error", reject);
    c.on("data", (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      while (buf.length >= 2 && buf.length >= 2 + buf.readUInt16BE(0)) {
        out.push(buf.subarray(2, 2 + buf.readUInt16BE(0)));
        buf = buf.subarray(2 + buf.readUInt16BE(0));
      }
      if (out.length === queries.length) { c.destroy(); resolve(out); }
    });
    // all queries in one write: pipelined TCP DNS
    c.write(Buffer.concat(queries.map((q) => { const h = Buffer.alloc(2); h.writeUInt16BE(q.length); return Buffer.concat([h, q]); })));
  });
}

test("dnsQtype labels", () => {
  assert.equal(dnsQtype(buildDnsQuery("a.example", 1)), "A");
  assert.equal(dnsQtype(buildDnsQuery("a.example", 28)), "AAAA");
  assert.equal(dnsQtype(buildDnsQuery("a.example", 15)), "other");
  assert.equal(dnsQtype(Buffer.alloc(5)), "bad");
});

test("service: A -> FakeIP, AAAA empty, MX relayed (udp and tcp), counters", async () => {
  const fake = createFakeIp();
  const relayed = [];
  const svc = await startDnsLocal({
    fakeIp: fake,
    upstream: { host: "192.0.2.53", port: 53 },
    relay: async (proto, query, upstream) => {
      relayed.push([proto, dnsQtype(query), upstream.host]);
      const r = Buffer.from(query);
      r.writeUInt16BE(0x8180, 2);
      return r;
    },
  });
  try {
    assert.ok(svc.port > 0);
    const a = await udpAsk(svc.port, buildDnsQuery("www.example.com", 1));
    assert.equal(a.readUInt16BE(6), 1);
    const ip = [...a.subarray(a.length - 4)].join(".");
    assert.match(ip, /^198\.1[89]\./);
    assert.equal(fake.lookup(ip), "www.example.com");
    const aaaa = await udpAsk(svc.port, buildDnsQuery("www.example.com", 28));
    assert.equal(aaaa.readUInt16BE(6), 0);
    const mx = await udpAsk(svc.port, buildDnsQuery("example.com", 15));
    assert.equal(mx.readUInt16BE(2), 0x8180);
    const [ta, tmx] = await tcpAsk(svc.port, [buildDnsQuery("tcp.example.com", 1), buildDnsQuery("example.com", 15)]);
    assert.equal(ta.readUInt16BE(6), 1);
    assert.equal(tmx.readUInt16BE(2), 0x8180);
    assert.deepEqual(relayed, [["udp", "other", "192.0.2.53"], ["tcp", "other", "192.0.2.53"]]);
    assert.equal(svc.stats.queries.get("udp,A,fakeip"), 1);
    assert.equal(svc.stats.queries.get("udp,AAAA,empty"), 1);
    assert.equal(svc.stats.queries.get("udp,other,relay"), 1);
    assert.equal(svc.stats.queries.get("tcp,A,fakeip"), 1);
    assert.equal(svc.stats.hijack.get("udp,ipv4"), 3);
    assert.equal(svc.stats.hijack.get("tcp,ipv4"), 2);
  } finally {
    svc.close();
  }
});

test("service: a failed relay gives no answer (no fallback) and is counted", async () => {
  const svc = await startDnsLocal({ fakeIp: createFakeIp(), relay: async () => { throw new Error("down"); } });
  try {
    assert.equal(await udpAsk(svc.port, buildDnsQuery("example.com", 16)), null);
    assert.equal(svc.stats.queries.get("udp,other,relay_fail"), 1);
  } finally {
    svc.close();
  }
});

test("service: a fixed port that is taken rejects (caller must fail closed)", async () => {
  const holder = createSocket("udp4");
  await new Promise((r) => holder.bind(0, "127.0.0.1", r));
  try {
    await assert.rejects(startDnsLocal({ port: holder.address().port, fakeIp: createFakeIp(), relay: async () => null }), /绑不上/);
  } finally {
    holder.close();
  }
});

test("r2 service: no FakeIP pool (dnsRedirect=false) relays every query, A included; ::1 too", async () => {
  const relayed = [];
  const svc = await startDnsLocal({
    host6: "::1",
    fakeIp: null,
    relay: async (proto, query) => {
      relayed.push([proto, dnsQtype(query)]);
      const r = Buffer.from(query);
      r.writeUInt16BE(0x8180, 2);
      return r;
    },
  });
  try {
    assert.equal(svc.port6, svc.port, "same port on ::1");
    const a = await udpAsk(svc.port, buildDnsQuery("www.example.com", 1));
    assert.equal(a.readUInt16BE(2), 0x8180, "relayed answer, not FakeIP");
    const a6 = await udpAsk(svc.port6, buildDnsQuery("v6.example.com", 1), "::1");
    assert.equal(a6.readUInt16BE(2), 0x8180);
    assert.deepEqual(relayed, [["udp", "A"], ["udp", "A"]]);
    assert.equal(svc.stats.queries.get("udp,A,relay"), 2);
    assert.equal(svc.stats.hijack.get("udp,ipv4"), 1);
    assert.equal(svc.stats.hijack.get("udp,ipv6"), 1);
  } finally {
    svc.close();
  }
});

function run(method, opts = {}) {
  const o = { iptables: true, ip6tables: true, nft: true, nftNat: true, nftNat6: true, xtNat: true, xtNat6: true, dns: 5399, dns6: 5399, have6: true, failNft: "", dnsRedirect: undefined, ...opts };
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "lexis-u2-"));
  const logf = path.join(dir, "cmd.log");
  const w = (name, body) => fs.writeFileSync(path.join(dir, name), `#!/bin/sh\n${body}\n`, { mode: 0o755 });
  w("id", "echo 0");
  w("unshare", 'echo "unshare $*" >> ' + logf + '\nshift\nexec "$@"');
  w("ip", `echo "ip $*" >> ${logf}\ncase "$*" in "link show"*) exit 1;; "-6 rule del"*|"rule del"*|"route del"*|"-6 route del"*) exit 1;; esac\nexit 0`);
  if (o.iptables) w("iptables", `echo "iptables $*" >> ${logf}\ncase "$*" in *" -C "*|*" -S "*) exit 1;; esac\n${o.xtNat ? "" : 'case "$*" in *"--dport 53 -j REDIRECT"*) exit 2;; esac\n'}exit 0`);
  if (o.ip6tables) w("ip6tables", `echo "ip6tables $*" >> ${logf}\ncase "$*" in *" -C "*|*" -S "*) exit 1;; esac\n${o.xtNat6 ? "" : 'case "$*" in *"--dport 53 -j REDIRECT"*) exit 2;; esac\n'}exit 0`);
  if (o.nft) w("nft", `echo "nft $*" >> ${logf}\nif [ "$1" = "-c" ] || [ "$1" = "-f" ]; then f=$(eval echo \\$$#); cat "$f" >> ${dir}/nft-files.txt; ${o.nftNat ? "" : 'if grep -q "table ip lexis_dns" "$f"; then exit 1; fi;'} ${o.nftNat6 ? "" : 'if grep -q "table ip6 lexis_dns" "$f"; then exit 1; fi;'} fi\n${o.failNft ? `if [ "$1" = "-f" ] && grep -q "${o.failNft}" "$2"; then exit 1; fi\n` : ""}case "$1" in list) exit 1;; esac\nexit 0`);
  const if6 = path.join(dir, "if_inet6");
  fs.writeFileSync(if6, o.have6 ? "00000000000000000000000000000001 01 80 10 80       lo\n" : "");
  const linux = { method, mark: 4731, table: 165, ...(o.dnsRedirect === undefined ? {} : { dnsRedirect: o.dnsRedirect }) };
  const { body } = forwardScript({ mode: "system-forward", linux, peers: [{ endpoint: "203.0.113.9:7000" }] }, o.dns, o.dns6);
  const sh = path.join(dir, "apply.sh");
  fs.writeFileSync(sh, body.replace("IF6=/proc/net/if_inet6", `IF6=${if6}`), { mode: 0o755 });
  let out = "", status = 0;
  try {
    out = execFileSync("/bin/sh", [sh], { env: { PATH: `${dir}:/usr/bin:/bin` }, encoding: "utf8" });
  } catch (err) {
    out = String(err.stdout || "");
    status = err.status;
  }
  const log = fs.existsSync(logf) ? fs.readFileSync(logf, "utf8").trim().split("\n") : [];
  const nftFiles = fs.existsSync(path.join(dir, "nft-files.txt")) ? fs.readFileSync(path.join(dir, "nft-files.txt"), "utf8") : "";
  fs.rmSync(dir, { recursive: true, force: true });
  return { out, status, log, nftFiles };
}
const mutating = (log) => log.filter((l) => /^ip (-6 )?(rule add|route replace|route add|tuntap|addr|link set)|^ip6?tables -t \S+ -[AIN] (?!LEXIS_PROBE)|^nft -f/.test(l));
const has = (log, re) => log.some((l) => re.test(l));

test("all three methods: nft 53 hijack before iptables nat, mark and loopback return, installed last", () => {
  for (const method of ["redirect", "tproxy", "tun"]) {
    const { status, out, log, nftFiles } = run(method);
    assert.equal(status, 0, `${method}: ${out}`);
    assert.match(nftFiles, /table ip lexis_dns \{[\s\S]*type nat hook output priority -110;[\s\S]*meta mark 4731 return\n\s*ip daddr 127\.0\.0\.0\/8 return\n\s*meta l4proto \{ tcp, udp \} th dport 53 redirect to :5399/, method);
    assert.ok(!/lexis_dns[\s\S]*10\.0\.0\.0\/8[\s\S]*redirect to/.test(nftFiles.slice(nftFiles.lastIndexOf("table ip lexis_dns {"))), "53 is never bypassed for private ranges");
    assert.match(nftFiles, /table ip6 lexis_dns \{[\s\S]*type nat hook output priority -110;[\s\S]*meta mark 4731 return\n\s*ip6 daddr ::1 return\n\s*meta l4proto \{ tcp, udp \} th dport 53 redirect to :5399/, `${method}: IPv6 53 (ULA / link-local included)`);
    const fs2 = log.filter((l) => /^nft -f/.test(l));
    assert.ok(fs2.length >= 2, method);
    assert.deepEqual(mutating(log).slice(-2), fs2.slice(-2), `${method}: v4 then v6 hijack are the last changes`);
    assert.match(out, /LEXIS-DNS-HIJACK: nft v6/);
  }
});

test("r2: no IPv6 in the kernel -> IPv4 hijack only, marker without v6", () => {
  for (const method of ["redirect", "tproxy", "tun"]) {
    const { status, out, nftFiles } = run(method, { have6: false, dns6: 0 });
    assert.equal(status, 0, out);
    assert.ok(!/ip6 lexis_dns/.test(nftFiles));
    assert.match(out, /LEXIS-DNS-HIJACK: nft：/);
  }
});

test("r2: dnsRedirect=false still installs the same hijack (53 never leaves directly)", () => {
  for (const method of ["redirect", "tproxy", "tun"]) {
    const on = run(method);
    const off = run(method, { dnsRedirect: false });
    assert.equal(off.status, 0, off.out);
    const norm = (log) => mutating(log).map((l) => l.replace(/\/tmp\/\S+/g, "<tmp>"));
    assert.deepEqual(norm(off.log), norm(on.log), method);
    assert.match(off.out, /LEXIS-DNS-HIJACK: nft v6/);
  }
});

test("iptables fallback: chain LEXIS_DNS first in nat OUTPUT (after redirect's own -I rules)", () => {
  for (const method of ["redirect", "tun"]) {
    const { status, out, log } = run(method, { nft: false });
    assert.equal(status, 0, out);
    assert.ok(has(log, /^iptables -t nat -A LEXIS_DNS -m mark --mark 4731 -j RETURN$/));
    assert.ok(has(log, /^iptables -t nat -A LEXIS_DNS -d 127\.0\.0\.0\/8 -j RETURN$/));
    assert.ok(has(log, /^iptables -t nat -A LEXIS_DNS -p udp --dport 53 -j REDIRECT --to-ports 5399$/));
    assert.ok(has(log, /^iptables -t nat -A LEXIS_DNS -p tcp --dport 53 -j REDIRECT --to-ports 5399$/));
    const jump = log.findIndex((l) => /^iptables -t nat -I OUTPUT -j LEXIS_DNS$/.test(l));
    const lastInsert = log.map((l, i) => [l, i]).filter(([l]) => /^iptables -t nat -I OUTPUT /.test(l)).at(-1)[1];
    assert.equal(jump, lastInsert, `${method}: jump inserted after the method's own -I`);
    assert.ok(has(log, /^ip6tables -t nat -A LEXIS_DNS -d ::1\/128 -j RETURN$/));
    assert.ok(has(log, /^ip6tables -t nat -A LEXIS_DNS -p udp --dport 53 -j REDIRECT --to-ports 5399$/));
    assert.ok(has(log, /^ip6tables -t nat -I OUTPUT -j LEXIS_DNS$/));
    assert.match(out, /LEXIS-DNS-HIJACK: xt v6/);
  }
});

test("refusal: no way to hijack 53 -> exit 3 before any rule, all three methods", () => {
  for (const method of ["redirect", "tproxy", "tun"]) {
    for (const opts of [{ nft: false, iptables: false }, { nftNat: false, xtNat: false }]) {
      if (method !== "tun" && !opts.iptables && opts.iptables !== undefined) continue; // U1 refuses first there
      const { status, out, log } = run(method, opts);
      assert.equal(status, 3, `${method} ${JSON.stringify(opts)}: ${out}`);
      assert.match(out, /LEXIS-REFUSE: 装不了 53 劫持/);
      assert.deepEqual(mutating(log), [], log.join("\n"));
    }
  }
});

test("r2 refusal: service not listening (DNS=0) or not on ::1 while the kernel has IPv6 -> exit 3, nothing installed", () => {
  for (const method of ["redirect", "tproxy", "tun"]) {
    for (const [opts, re] of [[{ dns: 0 }, /本机 DNS 服务没有在听/], [{ dns6: 0 }, /没有在 ::1 上听/], [{ nftNat6: false, ip6tables: false }, /装不了 IPv6 的 53 劫持/], [{ nftNat6: false, xtNat6: false }, /装不了 IPv6 的 53 劫持/]]) {
      const { status, out, log } = run(method, opts);
      assert.equal(status, 3, `${method} ${JSON.stringify(opts)}: ${out}`);
      assert.match(out, re);
      assert.deepEqual(mutating(log), [], log.join("\n"));
    }
  }
  const src2 = forwardScript({ mode: "system-forward", linux: { method: "tun" } }).body;
  assert.match(src2, /^DNS=0$/m);
});

test("r2 no half state: a failure after the first change rolls everything back and refuses", () => {
  for (const method of ["redirect", "tproxy", "tun"]) {
    for (const failNft of ["table ip lexis_dns", "table ip6 lexis_dns"]) {
      const { status, out, log } = run(method, { failNft });
      assert.equal(status, 3, `${method} ${failNft}: ${out}`);
      assert.match(out, /LEXIS-REFUSE: 规则装到一半失败（exit 1），已撤掉本程序装的全部规则/);
      const failed = log.map((l, i) => [l, i]).filter(([l]) => /^nft -f/.test(l)).at(-1)[1];
      const after = log.slice(failed + 1);
      assert.ok(after.some((l) => /^ip rule del fwmark 4731 lookup main priority 100/.test(l)), `${method}: rollback ran`);
      assert.ok(after.some((l) => /^ip rule del to 10\.0\.0\.0\/8 lookup main priority 41/.test(l)), `${method}: private bypass rules removed`);
      assert.ok(after.some((l) => /^ip -6 rule del lookup 165 priority 200/.test(l)), `${method}: IPv6 block removed`);
      assert.ok(!after.some((l) => /^ip (-6 )?rule add|^nft -f/.test(l)), `${method}: nothing added during rollback`);
    }
  }
});

test("r2b: tun rollback takes lexis0's address back, a refusal closes the tun fd", () => {
  const src = fs.readFileSync(new URL("../public/agent/lexis-agent.mjs", import.meta.url), "utf8");
  const rb = src.slice(src.indexOf("rollback() {"), src.indexOf("STAGE=install"));
  assert.match(rb, /if \[ "\$METHOD" = "tun" \]; then ip addr flush dev lexis0 2>\/dev\/null; ip link set lexis0 down 2>\/dev\/null; fi/);
  assert.match(src, /takeover\.closers\.push\(\(\) => closeSync\(opened\.fd\)\);/);
});
