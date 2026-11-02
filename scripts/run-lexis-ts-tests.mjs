// Runs the lexis TypeScript tests (each is a standalone script) and reports pass/fail.
import { spawnSync } from "node:child_process";
import { readdirSync } from "node:fs";
const dirs = ["src/lib/lexis", "src/lib/lexis/v2", "src/agent"];
const files = dirs.flatMap((d) => readdirSync(d).filter((f) => f.endsWith(".test.ts")).map((f) => `${d}/${f}`));
let fail = 0;
for (const f of files) {
  const r = spawnSync(process.execPath, ["--import", "jiti/register", f], { encoding: "utf8", timeout: 600000 });
  const ok = r.status === 0;
  if (!ok) fail++;
  const last = (r.stdout || "").trim().split("\n").pop() || "";
  console.log(`${ok ? "ok  " : "FAIL"} ${f}${ok ? "" : `\n${(r.stderr || "").split("\n").slice(0, 8).join("\n")}`}${ok ? `  # ${last.slice(0, 100)}` : ""}`);
}
console.log(`lexis-ts: ${files.length - fail}/${files.length} passed`);
process.exit(fail ? 1 : 0);
