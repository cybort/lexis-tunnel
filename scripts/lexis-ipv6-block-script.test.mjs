// P (legacy-ipv6-block): linux.ipv6=block must take effect for redirect, tproxy and tun,
// keep v6 peers and fwmark $MARK on the main table, and "off" must only delete this
// program's own IPv6 rules. Runs the generated apply-forward.sh against fake id/ip/iptables.
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

const PEERS = [
  { endpoint: "203.0.113.9:7000" },
  { endpoint: "[2001:DB8:88:0::8]:18443" },
  { endpoint: "[2001:db8:88::8]:18444" },
  { endpoint: "[fe80::1%eth0]:1" },
  { endpoint: "[not:an:ip:zz]:1" },
  { endpoint: "gate.example:443" },
];

function run(method, linux = {}, { withIptables = true, ipv6Works = true } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "lexis-p6-"));
  const logf = path.join(dir, "cmd.log");
  fs.writeFileSync(path.join(dir, "id"), "#!/bin/sh\necho 0\n", { mode: 0o755 });
  // U1 probes iptables in a throwaway netns via unshare; the fake just runs the command.
  fs.writeFileSync(path.join(dir, "unshare"), "#!/bin/sh\nshift\nexec \"$@\"\n", { mode: 0o755 });
  const v6 = ipv6Works ? "" : `"-6 route show"*) exit 1;; `;
  fs.writeFileSync(path.join(dir, "ip"), `#!/bin/sh\necho "ip $*" >> ${logf}\ncase "$*" in ${v6}"link show"*) exit 1;; "-6 rule del"*|"rule del"*) exit 1;; esac\nexit 0\n`, { mode: 0o755 });
  if (withIptables) fs.writeFileSync(path.join(dir, "iptables"), `#!/bin/sh\necho "iptables $*" >> ${logf}\ncase "$*" in *" -C "*) exit 1;; esac\nexit 0\n`, { mode: 0o755 });
  const body = forwardScript({ mode: "system-forward", linux: { method, mark: 4731, table: 165, ...linux }, peers: PEERS }, 5399).body.replace("IF6=/proc/net/if_inet6", "IF6=/dev/null"); // U2 r2: DNS service port (always hijacked), no IPv6 53 here
  const sh = path.join(dir, "apply.sh");
  fs.writeFileSync(sh, body, { mode: 0o755 });
  const out = execFileSync("/bin/sh", [sh], { env: { PATH: `${dir}:/usr/bin:/bin` }, encoding: "utf8" });
  const log = fs.existsSync(logf) ? fs.readFileSync(logf, "utf8").trim().split("\n") : [];
  fs.rmSync(dir, { recursive: true, force: true });
  return { out, log, body };
}
const v6adds = (log) => log.filter((l) => /^ip -6 (rule add|route replace|route add)/.test(l));

for (const method of ["redirect", "tproxy", "tun"]) {
  test(`${method}: block installs local ranges, v6 peers, fwmark and unreachable default`, () => {
    const { log, out } = run(method);
    const adds = v6adds(log);
    const want = [
      "ip -6 rule add to ::1/128 lookup main priority 40",
      "ip -6 rule add to fe80::/10 lookup main priority 41",
      "ip -6 rule add to fc00::/7 lookup main priority 42",
      "ip -6 rule add to ff00::/8 lookup main priority 43",
      "ip -6 rule add to 2001:db8:88::8/128 lookup main priority 44",
      "ip -6 rule add fwmark 4731 lookup main priority 100",
      "ip -6 route replace unreachable default table 165",
      "ip -6 rule add lookup 165 priority 200",
    ];
    assert.deepEqual(adds, want, log.join("\n"));
    assert.match(out, /公网 IPv6 已设为不可达/);
    // every add is preceded by its delete (idempotent re-run)
    for (const line of ["ip -6 rule del lookup 165 priority 200", "ip -6 route del unreachable default table 165", "ip -6 rule del fwmark 4731 lookup main priority 100", "ip -6 rule del to 2001:db8:88::8/128 lookup main priority 44"]) {
      assert.ok(log.indexOf(line) >= 0 && log.indexOf(line) < log.indexOf("ip -6 rule add to ::1/128 lookup main priority 40"), line);
    }
    // scope-ids, invalid literals and hostnames never reach the script
    assert.equal(log.filter((l) => /%|zz|example/.test(l)).length, 0);
  });

  test(`${method}: off deletes only this program's IPv6 rules and adds none`, () => {
    const { log, out } = run(method, { ipv6: "off" });
    assert.equal(v6adds(log).length, 0, log.join("\n"));
    assert.equal(log.filter((l) => l.includes("flush")).length, 0);
    for (const line of [
      "ip -6 rule del to ::1/128 lookup main priority 40",
      "ip -6 rule del to ff00::/8 lookup main priority 43",
      "ip -6 rule del to 2001:db8:88::8/128 lookup main priority 44",
      "ip -6 rule del fwmark 4731 lookup main priority 100",
      "ip -6 route del unreachable default table 165",
      "ip -6 rule del lookup 165 priority 200",
    ]) assert.ok(log.includes(line), line);
    assert.equal(log.filter((l) => l.startsWith("ip -6") && !/^ip -6 (rule del|route del|route show)/.test(l)).length, 0);
    assert.match(out, /不处理 IPv6/);
  });
}

test("redirect/tproxy without any TPROXY backend (U1): refused before any rule, IPv6 included", () => {
  for (const method of ["redirect", "tproxy"]) {
    let failure;
    try {
      run(method, {}, { withIptables: false });
    } catch (err) {
      failure = err;
    }
    assert.ok(failure, method);
    assert.equal(failure.status, 3, method);
    assert.match(String(failure.stdout), /LEXIS-REFUSE/);
  }
});

test("no IPv6 in the kernel: block adds nothing and does not fail", () => {
  for (const method of ["redirect", "tproxy", "tun"]) {
    const { log } = run(method, {}, { ipv6Works: false });
    assert.equal(v6adds(log).length, 0, method);
  }
});

test("v6 peers stay out of peerAddrs (Android/Windows output unchanged)", () => {
  const { body } = run("redirect");
  assert.match(body, /^PEERS="203\.0\.113\.9"$/m);
  assert.match(body, /^PEERS6="2001:db8:88::8"$/m);
});
