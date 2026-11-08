// Print apply-forward.sh for a tun linux.ipv6 mode. Used by the netns switch test.
import fs from "node:fs";

const src = fs.readFileSync(new URL("../../public/agent/lexis-agent.mjs", import.meta.url), "utf8");

function extract(name) {
  const i = src.indexOf(name);
  if (i < 0) throw new Error(`missing ${name}`);
  let depth = 0;
  let j = src.indexOf("{", i);
  for (let k = j; k < src.length; k++) {
    if (src[k] === "{") depth += 1;
    else if (src[k] === "}" && --depth === 0) {
      j = k + 1;
      break;
    }
  }
  return src.slice(i, j);
}

const forwardScript = new Function(
  "platform",
  "transparentPort",
  "GEOIP",
  `${extract("function peerAddrs(")}\n${extract("function forwardScript(")}; return forwardScript;`,
)(() => "linux", () => 12345, { private: [] });

const ipv6 = process.argv[2] === "off" ? "off" : "block";
const { body } = forwardScript({
  mode: "system-forward",
  linux: { method: "tun", mark: 4731, table: 165, ipv6 },
  peers: [{ endpoint: "203.0.113.9:7000" }],
});
process.stdout.write(body);
