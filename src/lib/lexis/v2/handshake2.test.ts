/* handshake2 (2.x hello) is deprecated since 3.0: it assumed the P-256 era long-term key layout
 * and fails by design with X25519 identities. This test only guards that nothing ships it. */
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
const root = new URL("../../../../", import.meta.url).pathname;
const offenders: string[] = [];
function walk(dir: string) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) { if (name !== "accept" && name !== "node_modules") walk(p); continue; } // accept/: 2.x acceptance scripts (dev only)
    if (!/\.(ts|tsx|mjs)$/.test(name) || /\.test\./.test(name) || /handshake2\.ts$/.test(name)) continue;
    if (/v2\/handshake2|\.\/handshake2/.test(readFileSync(p, "utf8"))) offenders.push(p);
  }
}
walk(join(root, "src"));
assert.deepEqual(offenders, [], "handshake2 must not be imported");
for (const f of ["lexis-frame.mjs", "lexis-agent.mjs"]) assert.ok(!readFileSync(join(root, "public/agent", f), "utf8").includes("edgeStart2"), `${f} ships handshake2`);
console.log("handshake2 deprecated: not imported by src, not in the agent bundle");
