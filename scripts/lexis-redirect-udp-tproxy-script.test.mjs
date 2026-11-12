// U1 (redirect-udp-tproxy): redirect is mixed (TCP nat REDIRECT, UDP TPROXY), tproxy uses
// TPROXY for both, the TPROXY backend is native nft first then iptables, and a missing
// capability refuses before any rule. Runs apply-forward.sh against fake id/ip/iptables/nft.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

const src = fs.readFileSync(new URL("../public/agent/lexis-agent.mjs", import.meta.url), "utf8");
function extract(name) {
  const i = src.indexOf(name);
  let d = 0, j = src.indexOf("{", i);
  for (let k = j; k < src.length; k++) { if (src[k] === "{") d++; else if (src[k] === "}" && --d === 0) { j = k + 1; break; } }
  return src.slice(i, j);
}
const forwardScript = new Function("platform", "transparentPort", "GEOIP",
  extract("function peerAddrs(") + "\n" + extract("function forwardScript(") + "; return forwardScript;")(() => "linux", () => 12345, { private: [] });

// opts: iptables, xtTproxy (kernel accepts -j TPROXY), nft, nftTproxy (nft -c accepts the table), ip.
// ("no ip command" is not unit-tested: /usr/bin/ip is on the fixed PATH; covered by reading the script.)
function run(method, opts = {}) {
  const o = { iptables: true, xtTproxy: true, nft: false, nftTproxy: true, ip: true, ...opts };
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "lexis-u1-"));
  const logf = path.join(dir, "cmd.log");
  const w = (name, body) => fs.writeFileSync(path.join(dir, name), `#!/bin/sh\n${body}\n`, { mode: 0o755 });
  w("id", "echo 0");
  w("unshare", 'echo "unshare $*" >> ' + logf + '\nshift\nexec "$@"');
  if (o.ip) w("ip", `echo "ip $*" >> ${logf}\ncase "$*" in "link show"*) exit 1;; "-6 rule del"*|"rule del"*|"route del"*|"-6 route del"*) exit 1;; esac\nexit 0`);
  if (o.iptables) w("iptables", `echo "iptables $*" >> ${logf}\ncase "$*" in *" -C "*) exit 1;; esac\n${o.xtTproxy ? "" : 'case "$*" in *TPROXY*) exit 2;; esac\n'}exit 0`);
  if (o.nft) w("nft", `echo "nft $*" >> ${logf}\nif [ "$1" = "-c" ] || [ "$1" = "-f" ]; then f=$(eval echo \\$$#); grep -q lexis_tproxy "$f" && cp "$f" ${dir}/nft-file.txt; fi\n${o.nftTproxy ? "" : '[ "$1" = "-c" ] && exit 1\n'}case "$1" in list) exit 1;; esac\nexit 0`);
  const body = forwardScript({ mode: "system-forward", linux: { method, mark: 4731, table: 165 }, peers: [{ endpoint: "203.0.113.9:7000" }] }, 5399).body.replace("IF6=/proc/net/if_inet6", "IF6=/dev/null"); // U2 r2: DNS service port (always hijacked), no IPv6 53 here
  const sh = path.join(dir, "apply.sh");
  fs.writeFileSync(sh, body, { mode: 0o755 });
  let out = "", status = 0;
  try {
    out = execFileSync("/bin/sh", [sh], { env: { PATH: `${dir}:/usr/bin:/bin` }, encoding: "utf8" });
  } catch (err) {
    out = String(err.stdout || "");
    status = err.status;
  }
  const log = fs.existsSync(logf) ? fs.readFileSync(logf, "utf8").trim().split("\n") : [];
  const nftFile = fs.existsSync(path.join(dir, "nft-file.txt")) ? fs.readFileSync(path.join(dir, "nft-file.txt"), "utf8") : "";
  fs.rmSync(dir, { recursive: true, force: true });
  return { out, status, log, nftFile };
}
const mutating = (log) => log.filter((l) => /^ip (-6 )?(rule add|route replace|route add|tuntap|addr|link set)|^iptables -t \S+ -[AIN] (?!LEXIS_PROBE)|^nft -f/.test(l));
const has = (log, re) => log.some((l) => re.test(l));

test("redirect (iptables backend): TCP nat REDIRECT, UDP TPROXY + OUTPUT mark, no TCP TPROXY", () => {
  const { log, status, out } = run("redirect");
  assert.equal(status, 0, out);
  assert.ok(has(log, /^iptables -t nat -A OUTPUT -p tcp -j REDIRECT --to-ports 12345$/), log.join("\n"));
  assert.ok(has(log, /^iptables -t mangle -A PREROUTING -p udp -j TPROXY --on-port 12345 --tproxy-mark 1$/));
  assert.ok(has(log, /^iptables -t mangle -A OUTPUT -p udp -j MARK --set-mark 1$/));
  assert.ok(has(log, /^iptables -t mangle -I OUTPUT -p udp -m mark --mark 4731 -j RETURN$/));
  assert.ok(has(log, /^iptables -t mangle -I OUTPUT -p udp -d 203\.0\.113\.9 -j RETURN$/));
  assert.ok(!has(log, /-A (PREROUTING|OUTPUT) -p tcp -j (TPROXY|MARK)/), "TCP must stay on REDIRECT");
  assert.ok(has(log, /^ip rule add fwmark 1 lookup 165 priority 90$/));
  assert.ok(has(log, /^ip route replace local 0\.0\.0\.0\/0 dev lo table 165$/));
  assert.ok(has(log, /^ip rule add fwmark 4731 lookup main priority 100$/));
  assert.match(out, /UDP 不再直连/);
});

test("redirect: capability probes run (in a throwaway netns) before the first rule", () => {
  const { log } = run("redirect");
  const firstRule = log.findIndex((l) => mutating([l]).length);
  const probes = log.map((l, i) => [l, i]).filter(([l]) => /^unshare -n/.test(l)).map(([, i]) => i);
  assert.ok(probes.length >= 2 && probes.every((i) => i < firstRule), log.join("\n"));
});

test("redirect (nft backend preferred): UDP-only tproxy table, TCP still nat REDIRECT", () => {
  const { log, status, nftFile } = run("redirect", { nft: true });
  assert.equal(status, 0);
  assert.ok(log.indexOf(log.find((l) => /^nft -c -f/.test(l))) < log.indexOf(log.find((l) => /^nft -f/.test(l))));
  assert.match(nftFile, /meta l4proto \{ udp \} tproxy to :12345 meta mark set 1 accept/);
  assert.match(nftFile, /meta mark 4731 return/);
  assert.match(nftFile, /elements = \{ [^}]*203\.0\.113\.9 \}/);
  assert.ok(!has(log, /-j TPROXY --on-port 12345 --tproxy-mark 1$/) || !has(log, /-A PREROUTING/));
  assert.ok(has(log, /^iptables -t nat -A OUTPUT -p tcp -j REDIRECT --to-ports 12345$/));
});

test("tproxy (nft backend): TCP and UDP in the tproxy table, nat REDIRECT not installed", () => {
  const { log, status, nftFile } = run("tproxy", { nft: true, iptables: false });
  assert.equal(status, 0);
  assert.match(nftFile, /meta l4proto \{ tcp, udp \} tproxy to :12345/);
  assert.ok(!has(log, /REDIRECT/));
});

test("refusal: no TPROXY anywhere -> exit 3, nothing installed (IPv4 or IPv6)", () => {
  for (const method of ["redirect", "tproxy"]) {
    for (const opts of [{ xtTproxy: false }, { xtTproxy: false, nft: true, nftTproxy: false }, { iptables: false }]) {
      const { status, out, log } = run(method, opts);
      assert.equal(status, 3, `${method} ${JSON.stringify(opts)}`);
      assert.match(out, /LEXIS-REFUSE: .*TPROXY/);
      assert.deepEqual(mutating(log), [], log.join("\n"));
      assert.ok(!has(log, /^ip -6/), "IPv6 block must not run either");
    }
  }
});

test("refusal: redirect with nft TPROXY but no iptables (TCP REDIRECT impossible) -> exit 3, nothing installed", () => {
  const { status, out, log } = run("redirect", { nft: true, iptables: false });
  assert.equal(status, 3);
  assert.match(out, /LEXIS-REFUSE: 没有 iptables/);
  assert.deepEqual(mutating(log), []);
});

test("tun is not preflighted for TPROXY and removes the transparent methods' routing", () => {
  const { status, log } = run("tun", { iptables: false, nft: true }); // r2: tun needs a nat backend for the 53 hijack
  assert.equal(status, 0);
  assert.ok(has(log, /^ip route del local 0\.0\.0\.0\/0 dev lo table 165$/), log.join("\n"));
  assert.ok(has(log, /^ip rule del fwmark 1 lookup 165 priority 90$/));
  assert.ok(has(log, /^ip route replace default dev lexis0 table 165$/));
});

test("redirect/tproxy remove tun's table default and lookup rule", () => {
  for (const method of ["redirect", "tproxy"]) {
    const { log } = run(method);
    assert.ok(has(log, /^ip route del default dev lexis0 table 165$/), method);
    assert.ok(has(log, /^ip rule del lookup 165 priority 200$/), method);
  }
});
