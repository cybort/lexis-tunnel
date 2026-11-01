#!/usr/bin/env node
/**
 * LEXIS resident agent. Same lexis.config.json on Windows, Linux, and Android (Termux).
 * Fixed-port mode listens for SOCKS, plain TCP maps, and tunnel prefaces.
 * System-forward mode writes the platform takeover file and tries to apply it.
 */
import { execFile } from "node:child_process";
import { createServer as createTcp, connect as connectTcp } from "node:net";
import { createServer as createHttp } from "node:http";
import { mkdirSync, readFileSync, writeFileSync, existsSync, readdirSync, readlinkSync } from "node:fs";
import { homedir, platform } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const configPath = process.argv.includes("--config")
  ? process.argv[process.argv.indexOf("--config") + 1]
  : join(here, "lexis.config.json");

const GEOSITE = {
  private: ["localhost", "local", "localdomain", "invalid"],
  cn: ["cn", "baidu.com", "qq.com", "taobao.com", "aliyun.com", "bilibili.com", "jd.com"],
  google: ["google.com", "gstatic.com", "googleapis.com", "youtube.com", "gmail.com"],
  telegram: ["telegram.org", "t.me", "telegra.ph"],
};
const GEOIP = {
  private: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16"],
  cn: ["114.114.114.114/32", "223.5.5.5/32", "119.29.29.29/32", "180.76.76.76/32"],
};

const started = Date.now();
const state = {
  config: null,
  listeners: [],
  beats: 0,
  lastBeat: 0,
  decisions: [],
  system: "固定端口，未请求系统接管",
  resources: "未配置远程词表",
  errors: [],
};
let remoteGeosite = "";
let remoteGeoip = "";

function log(line) {
  const text = `${new Date().toISOString()} ${line}`;
  if (state.config?.logLevel === "debug" || !line.startsWith("debug")) console.log(text);
}

function loadConfig() {
  const raw = JSON.parse(readFileSync(configPath, "utf8"));
  if (!raw || raw.version !== 1) throw new Error("lexis.config.json 版本不是 1");
  return raw;
}

function absorb(geosite, geoip, text, fallback) {
  const cidr = (value) => /^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/.test(value);
  for (const line of String(text || "").split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const [head, ...rest] = trimmed.split(/\s+/);
    const value = rest.join(" ");
    if (!head) continue;
    if (head.toLowerCase().startsWith("geoip:")) {
      const tag = head.slice(6).toLowerCase();
      if (tag && value) geoip[tag] = [...(geoip[tag] || []), value];
      continue;
    }
    if (!value) {
      if (fallback === "geoip" && head.includes("/")) geoip.remote = [...(geoip.remote || []), head];
      else if (fallback === "geosite") geosite.remote = [...(geosite.remote || []), head.toLowerCase()];
      continue;
    }
    if (fallback === "geoip" && cidr(value)) {
      geoip[head.toLowerCase()] = [...(geoip[head.toLowerCase()] || []), value];
      continue;
    }
    if (fallback === "geoip") continue;
    geosite[head.toLowerCase()] = [...(geosite[head.toLowerCase()] || []), value.toLowerCase()];
  }
}

function lists(config) {
  const geosite = Object.fromEntries(Object.entries(GEOSITE).map(([k, v]) => [k, [...v]]));
  const geoip = Object.fromEntries(Object.entries(GEOIP).map(([k, v]) => [k, [...v]]));
  absorb(geosite, geoip, config.extras, "");
  absorb(geosite, geoip, remoteGeosite, "geosite");
  absorb(geosite, geoip, remoteGeoip, "geoip");
  return { geosite, geoip };
}

async function pullText(url) {
  const res = await fetch(url, { signal: AbortSignal.timeout(4000), redirect: "follow" });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const text = await res.text();
  if (text.length > 512 * 1024) throw new Error("超过 512KB");
  return text;
}

async function pullResources(config) {
  const jobs = [
    ["geosite", config.geositeUrl],
    ["geoip", config.geoipUrl],
  ];
  const notes = [];
  for (const [kind, url] of jobs) {
    if (!url || !/^https?:\/\//i.test(String(url))) continue;
    try {
      const text = await pullText(url);
      if (kind === "geosite") remoteGeosite = text;
      else remoteGeoip = text;
      notes.push(`${kind} ${text.length} 字节`);
      log(`已拉取 ${kind} ${text.length} 字节`);
    } catch (err) {
      const msg = `${kind} 未拉取：${err.message || err}`;
      state.errors.push(msg);
      notes.push(msg);
      log(msg);
    }
  }
  state.resources = notes.length ? notes.join(" · ") : "未配置远程词表";
}

function ip4(ip) {
  return ip.split(".").reduce((acc, part) => ((acc << 8) | Number(part)) >>> 0, 0);
}

function isIp(value) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(value);
}

function cidrContains(cidr, ip) {
  const [base, bitsRaw] = cidr.split("/");
  if (!isIp(base) || !isIp(ip)) return false;
  const bits = bitsRaw === undefined ? 32 : Number(bitsRaw);
  if (!Number.isInteger(bits) || bits < 0 || bits > 32) return false;
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return (ip4(base) & mask) === (ip4(ip) & mask);
}

function processHits(actual, ruleName) {
  const want = String(ruleName || "").trim().toLowerCase();
  if (!want) return false;
  const bare = String(actual || "").toLowerCase().replace(/\.exe$/, "");
  const wantBare = want.replace(/\.exe$/, "");
  return bare === wantBare || bare.includes(wantBare);
}

function decide(config, query) {
  const book = lists(config);
  const host = String(query.host || "").toLowerCase().replace(/\.$/, "");
  const ip = query.ip || (isIp(host) ? host : "");
  const processName = String(query.process || "").toLowerCase();
  if (processName) {
    const named = (config.processes || []).find((item) => processHits(processName, item.name));
    if (named) return { action: named.action, reason: `程序 ${named.name}` };
  }
  for (const rule of config.rules || []) {
    const value = String(rule.value || "").trim().toLowerCase();
    let hit = false;
    if (rule.type === "MATCH") hit = true;
    else if (rule.type === "DOMAIN") hit = host === value;
    else if (rule.type === "DOMAIN-SUFFIX") hit = host === value || host.endsWith(`.${value}`);
    else if (rule.type === "DOMAIN-KEYWORD") hit = value && host.includes(value);
    else if (rule.type === "IP-CIDR") hit = ip && cidrContains(rule.value.trim(), ip);
    else if (rule.type === "GEOIP") hit = ip && (book.geoip[value] || []).some((cidr) => cidrContains(cidr, ip));
    else if (rule.type === "GEOSITE") hit = host && (book.geosite[value] || []).some((domain) => host === domain || host.endsWith(`.${domain}`));
    else if (rule.type === "PROCESS-NAME") hit = processName && processHits(processName, rule.value);
    else if (rule.type === "PORT") hit = String(query.port || "") === String(rule.value || "").trim();
    else if (rule.type === "NETWORK") hit = String(query.network || "tcp").toLowerCase() === value;
    if (hit) return { action: rule.action, reason: `${rule.type} ${rule.value}` };
  }
  return { action: config.processDefault || "proxy", reason: "默认" };
}

function note(decision, host) {
  state.decisions.unshift({ at: Date.now(), host, ...decision });
  state.decisions = state.decisions.slice(0, 12);
  log(`${decision.action} ${host} (${decision.reason})`);
}

function pipe(a, b) {
  a.pipe(b);
  b.pipe(a);
  const close = () => {
    a.destroy();
    b.destroy();
  };
  a.on("error", close);
  b.on("error", close);
  a.on("close", () => b.destroy());
  b.on("close", () => a.destroy());
}

function dial(host, port) {
  return connectTcp({ host, port });
}

function relayProxy(socket, config, host, port) {
  const endpoint = String(config.peerEndpoint || "");
  const match = endpoint.match(/^(.+):(\d+)$/);
  if (!match) {
    log(`接入 ${host}:${port} 失败：没有对端主机:端口`);
    socket.destroy();
    return;
  }
  const peer = dial(match[1], Number(match[2]));
  peer.on("connect", () => {
    peer.write(`LEXIS1\n${host}\n${port}\n`);
    pipe(socket, peer);
  });
  peer.on("error", () => socket.destroy());
}

function relayDirect(socket, host, port) {
  const remote = dial(host, port);
  remote.on("connect", () => pipe(socket, remote));
  remote.on("error", () => socket.destroy());
}

function applyAction(socket, config, decision, host, port) {
  note(decision, `${host}:${port}`);
  if (decision.action === "reject") {
    socket.destroy();
    return;
  }
  if (decision.action === "proxy") relayProxy(socket, config, host, port);
  else relayDirect(socket, host, port);
}

function readPreface(socket) {
  return new Promise((resolve, reject) => {
    let buf = "";
    const timer = setTimeout(() => reject(new Error("隧道头超时")), 10000);
    const onData = (chunk) => {
      buf += chunk.toString("utf8");
      const parts = buf.split("\n");
      if (parts.length >= 4 && parts[0] === "LEXIS1") {
        clearTimeout(timer);
        socket.off("data", onData);
        const rest = Buffer.from(parts.slice(3).join("\n"));
        if (rest.length) socket.unshift(rest);
        resolve({ host: parts[1], port: Number(parts[2]) });
      }
    };
    socket.on("data", onData);
    socket.on("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

async function findProcess(port) {
  if (platform() === "linux" || platform() === "android") {
    try {
      const hex = port.toString(16).toUpperCase().padStart(4, "0");
      let inode = "";
      for (const table of ["/proc/net/tcp", "/proc/net/tcp6"]) {
        if (!existsSync(table)) continue;
        for (const line of readFileSync(table, "utf8").split("\n")) {
          const parts = line.trim().split(/\s+/);
          if (parts.length < 10) continue;
          if ((parts[1].split(":")[1] || "").toUpperCase() === hex) {
            inode = parts[9];
            break;
          }
        }
        if (inode) break;
      }
      if (!inode || inode === "0") return "";
      for (const pid of readdirSync("/proc")) {
        if (!/^\d+$/.test(pid)) continue;
        let fds = [];
        try {
          fds = readdirSync(`/proc/${pid}/fd`);
        } catch {
          continue;
        }
        for (const fd of fds) {
          try {
            const target = readlinkSync(`/proc/${pid}/fd/${fd}`);
            if (target === `socket:[${inode}]`) {
              const comm = readFileSync(`/proc/${pid}/comm`, "utf8").trim();
              return comm;
            }
          } catch {
            /* next fd */
          }
        }
      }
    } catch {
      return "";
    }
  }
  if (platform() === "win32") {
    return await new Promise((resolve) => {
      execFile(
        "powershell.exe",
        ["-NoProfile", "-Command", `(Get-NetTCPConnection -RemotePort ${Number(port)} -ErrorAction SilentlyContinue | Select-Object -First 1).OwningProcess`],
        { timeout: 2500 },
        (err, stdout) => {
          const pid = String(stdout || "").trim();
          if (err || !/^\d+$/.test(pid)) return resolve("");
          execFile(
            "powershell.exe",
            ["-NoProfile", "-Command", `(Get-Process -Id ${pid} -ErrorAction SilentlyContinue).ProcessName`],
            { timeout: 2500 },
            (err2, out2) => resolve(err2 ? "" : String(out2 || "").trim()),
          );
        },
      );
    });
  }
  return "";
}

function handleSocks(socket, config) {
  let stage = 0;
  let pending = Buffer.alloc(0);
  socket.on("data", (chunk) => {
    pending = Buffer.concat([pending, chunk]);
    if (stage === 0) {
      if (pending.length < 2) return;
      const n = pending[1];
      if (pending.length < 2 + n) return;
      pending = pending.subarray(2 + n);
      socket.write(Buffer.from([0x05, 0x00]));
      stage = 1;
    }
    if (stage === 1) {
      if (pending.length < 4) return;
      const atyp = pending[3];
      let host = "";
      let port = 0;
      let offset = 4;
      if (atyp === 1) {
        if (pending.length < 10) return;
        host = [...pending.subarray(4, 8)].join(".");
        port = pending.readUInt16BE(8);
        offset = 10;
      } else if (atyp === 3) {
        const len = pending[4];
        if (pending.length < 5 + len + 2) return;
        host = pending.subarray(5, 5 + len).toString("utf8");
        port = pending.readUInt16BE(5 + len);
        offset = 7 + len;
      } else if (atyp === 4) {
        if (pending.length < 22) return;
        const words = [];
        for (let i = 0; i < 16; i += 2) words.push(pending.readUInt16BE(4 + i).toString(16));
        host = words.join(":");
        port = pending.readUInt16BE(20);
        offset = 22;
      } else {
        socket.end(Buffer.from([0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
        return;
      }
      const rest = pending.subarray(offset);
      pending = Buffer.alloc(0);
      stage = 2;
      socket.removeAllListeners("data");
      if (rest.length) socket.unshift(rest);
      void (async () => {
        const processName = await findProcess(socket.remotePort);
        const decision = decide(config, { host, ip: isIp(host) ? host : "", process: processName, port: String(port), network: "tcp" });
        if (decision.action === "reject") {
          note(decision, `${host}:${port}`);
          socket.end(Buffer.from([0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
          return;
        }
        socket.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
        applyAction(socket, config, decision, host, port);
      })();
    }
  });
  socket.on("error", () => socket.destroy());
}

function serveInbound(config, inbound) {
  const server = createTcp((socket) => {
    if (inbound.protocol === "socks") {
      handleSocks(socket, config);
      return;
    }
    if (inbound.protocol === "tunnel") {
      void readPreface(socket)
        .then(({ host, port }) => {
          const decision = decide(config, { host, ip: isIp(host) ? host : "", port: String(port), network: "tcp" });
          if (decision.action === "reject" || decision.action === "bypass") {
            note(decision, `${host}:${port}`);
            socket.destroy();
            return;
          }
          note({ action: "direct", reason: decision.reason }, `${host}:${port}`);
          relayDirect(socket, host, port);
        })
        .catch(() => socket.destroy());
      return;
    }
    void (async () => {
      const processName = await findProcess(socket.remotePort);
      const host = inbound.targetHost;
      const port = inbound.targetPort;
      const decision = decide(config, { host, ip: isIp(host) ? host : "", process: processName, port: String(port), network: "tcp" });
      applyAction(socket, config, decision, host, port);
    })();
  });
  server.on("error", (err) => {
    state.errors.push(`${inbound.tag} ${inbound.port}: ${err.message}`);
    log(`入站失败 ${inbound.tag}: ${err.message}`);
  });
  server.listen(inbound.port, inbound.listen, () => {
    state.listeners.push(`${inbound.protocol} ${inbound.listen}:${inbound.port}`);
    log(`监听 ${inbound.protocol} ${inbound.listen}:${inbound.port}`);
  });
  return server;
}

function forwardScript(config) {
  const port = (config.inbounds || []).find((item) => item.protocol === "socks")?.port || config.inbounds?.[0]?.port || 1080;
  if (platform() === "win32") {
    const gateway = String(config.windows?.gateway || "10.7.0.1").replace(/[^0-9a-fA-F:.]/g, "") || "10.7.0.1";
  const winMethod = config.windows?.method === "windivert" ? "windivert" : "portproxy";
  return {
      file: "apply-forward.ps1",
      body: `$port = ${port}
$gateway = "${gateway}"
if ("${winMethod}" -eq "portproxy") {
  netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=$port connectaddress=127.0.0.1 connectport=$port
  Write-Output "portproxy -> 127.0.0.1:$port"
} else {
  Write-Output "WinDivert 过滤已记录，网关 $gateway。驱动需要单独安装后由本进程的监听端口承接。"
}
`,
    };
  }
  if (platform() === "android") {
    const session = {
      method: "vpn",
      mtu: config.android?.mtu || 1500,
      address: config.android?.address || "10.7.0.2/32",
      dns: config.android?.dns || "1.1.1.1",
      routes: ["0.0.0.0/0"],
      bypass: (GEOIP.private || []).concat(["127.0.0.0/8"]),
      processes: config.processes || [],
    };
    return { file: "vpn-session.json", body: JSON.stringify(session, null, 2) };
  }
  const mark = config.linux?.mark || 255;
  const method = config.linux?.method === "tproxy" ? "tproxy" : "redirect";
  return {
    file: "apply-forward.sh",
    body: `#!/bin/sh
set -eu
PORT=${port}
MARK=${mark}
if [ "$(id -u)" -ne 0 ]; then
  echo "没有 root，规则留在本文件，未改系统转发"
  exit 0
fi
if [ "${method}" = "tproxy" ]; then
  iptables -t mangle -C PREROUTING -p tcp -j TPROXY --on-port "$PORT" --tproxy-mark "$MARK" 2>/dev/null || iptables -t mangle -A PREROUTING -p tcp ! -d 127.0.0.0/8 -j TPROXY --on-port "$PORT" --tproxy-mark "$MARK"
else
  iptables -t nat -N LEXIS 2>/dev/null || true
  iptables -t nat -F LEXIS
  iptables -t nat -A LEXIS -d 127.0.0.0/8 -j RETURN
  iptables -t nat -A LEXIS -p tcp -j REDIRECT --to-ports "$PORT"
  iptables -t nat -C OUTPUT -p tcp -j LEXIS 2>/dev/null || iptables -t nat -A OUTPUT -p tcp -j LEXIS
fi
echo "系统转发已指向 $PORT"
`,
  };
}

function applySystem(config) {
  if (config.mode !== "system-forward") {
    state.system = "固定端口模式，不改系统转发";
    return;
  }
  const script = forwardScript(config);
  const path = join(here, script.file);
  writeFileSync(path, script.body);
  if (script.file.endsWith(".sh")) {
    execFile("sh", [path], { timeout: 8000 }, (err, stdout, stderr) => {
      state.system = `${stdout || ""}${stderr || ""}${err ? err.message : ""}`.trim() || "已执行 Linux 转发脚本";
      log(state.system);
    });
    return;
  }
  if (script.file.endsWith(".ps1")) {
    execFile("powershell.exe", ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", path], { timeout: 8000 }, (err, stdout, stderr) => {
      state.system = `${stdout || ""}${stderr || ""}${err ? err.message : ""}`.trim() || "已执行 Windows 转发脚本";
      log(state.system);
    });
    return;
  }
  state.system = "已写出 vpn-session.json。Android 的 VpnService 读取这份会话；Termux 进程本身不能打开系统 VPN。";
  log(state.system);
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (ch) => {
    const name = { "&": "amp", "<": "lt", ">": "gt", '"': "quot", "'": "#39" }[ch];
    return "&" + name + ";";
  });
}

function startStatus(config) {
  const server = createHttp((req, res) => {
    const up = Math.floor((Date.now() - started) / 1000);
    const rows = state.decisions
      .map((item) => `<li>${escapeHtml(new Date(item.at).toLocaleTimeString())} ${escapeHtml(item.action)} ${escapeHtml(item.host)} <span>${escapeHtml(item.reason)}</span></li>`)
      .join("");
    const body = `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>词隙客户端</title>
<style>
body{margin:0;background:#10140f;color:#e7e4d8;font:16px/1.5 "Noto Sans SC",sans-serif}
main{max-width:40rem;margin:0 auto;padding:1.25rem}
h1{font-size:1.4rem;margin:0} .sage{color:#b7c4a4} .mist{color:#b4bbae}
section{border:1px solid #343c31;background:#1a2019;border-radius:.75rem;padding:1rem;margin-top:1rem}
ul{padding-left:1.1rem} li span{color:#b4bbae}
</style>
<main>
<h1>词隙 <span class="sage">客户端</span></h1>
<p class="mist">${escapeHtml(platform())} · 角色 ${escapeHtml(config.role)} · ${escapeHtml(config.mode === "system-forward" ? "系统接管" : "固定端口")}</p>
<section><p>已运行 ${up} 秒 · 心跳 ${state.beats}</p><p>${escapeHtml(state.listeners.join(" · ") || "还没有入站")}</p></section>
<section><p>${escapeHtml(state.system)}</p><p class="mist">${escapeHtml(state.resources)}</p></section>
<section><ul>${rows || "<li class='mist'>还没有连接</li>"}</ul></section>
</main>`;
    res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    res.end(body);
  });
  server.listen(config.statusPort || 17890, config.statusHost || "127.0.0.1");
  return server;
}

function selfCheck() {
  const sample = {
    version: 1,
    processDefault: "proxy",
    processes: [{ name: "ssh", action: "bypass" }],
    rules: [
      { type: "GEOSITE", value: "cn", action: "direct" },
      { type: "GEOIP", value: "private", action: "direct" },
      { type: "MATCH", value: "", action: "proxy" },
    ],
    extras: "",
  };
  const a = decide(sample, { host: "www.baidu.com" });
  const b = decide(sample, { host: "example.com", process: "ssh" });
  const c = decide(sample, { ip: "10.0.0.8" });
  remoteGeosite = "only.remote.test\n";
  const d = decide(
    { ...sample, rules: [{ type: "GEOSITE", value: "remote", action: "reject" }, ...sample.rules] },
    { host: "a.only.remote.test" },
  );
  remoteGeosite = "";
  if (a.action !== "direct" || b.action !== "bypass" || c.action !== "direct" || d.action !== "reject") {
    console.error("self-check failed", a, b, c, d);
    process.exit(1);
  }
  console.log("lexis-agent check ok");
}

async function main() {
  if (process.argv.includes("--check")) {
    selfCheck();
    return;
  }
  const config = loadConfig();
  state.config = config;
  await pullResources(config);
  mkdirSync(here, { recursive: true });
  writeFileSync(join(here, "lexis-agent.pid"), String(process.pid));
  for (const inbound of config.inbounds || []) serveInbound(config, inbound);
  applySystem(config);
  startStatus(config);
  const beat = () => {
    state.beats += 1;
    state.lastBeat = Date.now();
    writeFileSync(join(here, "lexis-agent.state.json"), JSON.stringify({ pid: process.pid, beats: state.beats, at: state.lastBeat, listeners: state.listeners }, null, 2));
    log(`debug 心跳 ${state.beats}`);
  };
  beat();
  const timer = setInterval(beat, Math.max(5, config.heartbeatSec || 15) * 1000);
  const stop = () => {
    clearInterval(timer);
    process.exit(0);
  };
  process.on("SIGINT", stop);
  process.on("SIGTERM", stop);
  log(`词隙客户端常驻中，状态页 http://${config.statusHost || "127.0.0.1"}:${config.statusPort || 17890}/  家目录 ${homedir()}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
