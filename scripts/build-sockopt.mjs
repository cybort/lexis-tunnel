import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const src = join(root, "public/agent/linux/sockopt.c");
const out = join(root, "public/agent/linux/lexis-sockopt.node");
const candidates = [join(dirname(dirname(process.execPath)), "include", "node"), "/usr/include/node"];
const include = candidates.find((dir) => existsSync(join(dir, "node_api.h")));
if (!include) {
  console.error("没有 Node 头文件", candidates.join(", "));
  process.exit(1);
}
execFileSync("cc", ["-shared", "-fPIC", "-O2", "-o", out, src, `-I${include}`], { stdio: "inherit" });
console.log("sockopt", out);
