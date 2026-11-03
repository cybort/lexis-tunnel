// Runs the generated Linux tun apply-forward.sh against fake `id`/`ip` binaries and checks
// the rules it would install (loop guard for peers, linux.ipv6 block/off).
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

function runScript(linux) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "lexis-fwd-"));
  const logf = path.join(dir, "ip.log");
  fs.writeFileSync(path.join(dir, "id"), "#!/bin/sh\necho 0\n", { mode: 0o755 });
  fs.writeFileSync(path.join(dir, "ip"), `#!/bin/sh\necho "$*" >> ${logf}\ncase "$*" in "link show"*) exit 1;; "-6 rule del"*|"rule del"*) exit 1;; esac\nexit 0\n`, { mode: 0o755 });
  const { body } = forwardScript({ mode: "system-forward", linux: { method: "tun", mark: 4731, table: 165, ...linux }, peers: [{ endpoint: "10.240.2.2:18443" }, { endpoint: "203.0.113.9:7000" }] });
  const sh = path.join(dir, "apply.sh");
  fs.writeFileSync(sh, body, { mode: 0o755 });
  const out = execFileSync("/bin/sh", [sh], { env: { PATH: `${dir}:/usr/bin:/bin` }, encoding: "utf8" });
  const log = fs.readFileSync(logf, "utf8").trim().split("\n");
  fs.rmSync(dir, { recursive: true, force: true });
  return { out, log };
}
const idx = (log, re) => log.findIndex((l) => re.test(l));

test("tun script: each peer gets main lookup then unreachable, both before the tun table rule", () => {
  const { log } = runScript({});
  for (const peer of ["10.240.2.2", "203.0.113.9"]) {
    const main = idx(log, new RegExp(`^rule add to ${peer}/32 lookup main priority 4\\d$`));
    const unr = idx(log, new RegExp(`^rule add to ${peer}/32 unreachable priority 15\\d$`));
    assert.ok(main >= 0 && unr > main, `${peer}: ${log.join(" | ")}`);
  }
  assert.ok(idx(log, /^rule add lookup 165 priority 200$/) >= 0);
});

test("tun script: linux.ipv6 defaults to block (unreachable default in the tun table, local ranges kept)", () => {
  const { log, out } = runScript({});
  assert.ok(idx(log, /^-6 route replace unreachable default table 165$/) >= 0, log.join(" | "));
  assert.ok(idx(log, /^-6 rule add lookup 165 priority 200$/) >= 0);
  for (const net of ["::1/128", "fe80::/10", "fc00::/7", "ff00::/8"]) assert.ok(idx(log, new RegExp(`^-6 rule add to ${net.replace(/[/.]/g, "\\$&")} lookup main`)) >= 0, net);
  assert.match(out, /IPv6 已设为不可达/);
});

test("tun script: linux.ipv6 = off leaves IPv6 alone", () => {
  const { log } = runScript({ ipv6: "off" });
  assert.equal(log.filter((l) => l.startsWith("-6 rule add") || l.startsWith("-6 route replace")).length, 0, log.join(" | "));
});
