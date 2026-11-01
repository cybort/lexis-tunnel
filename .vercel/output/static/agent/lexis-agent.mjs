#!/usr/bin/env node
/**
 * LEXIS resident agent.
 * The forwarding payload is the same lexicon seal as the console.
 * TCP, TLS and WebSocket only carry the prose. SOCKS may ask for a username.
 */
import { execFile, execFileSync } from "node:child_process";
import { timingSafeEqual } from "node:crypto";
import { createSocket as createUdp } from "node:dgram";
import { lookup } from "node:dns";
import { createServer as createTcp, connect as connectTcp } from "node:net";
import { createServer as createHttp } from "node:http";
import { mkdirSync, readFileSync, writeFileSync, existsSync, readdirSync, readlinkSync, statSync } from "node:fs";
import { platform } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { acceptSession, connectSession, dialOuter, hopCount, listenOuter, nodeFromIdentity, parseOpen, pipeMux, startKdfPool } from "./lexis-frame.mjs";

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
let liveConns = 0;
let activeConfig = null;

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

function linkOf(config) {
  const link = config.link || {};
  const idle = Number(link.idleMs);
  const max = Number(link.maxConns);
  const header = Number(link.headerBytes);
  return {
    token: String(link.token || "").trim(),
    idleMs: Number.isInteger(idle) && idle >= 1000 ? idle : 120000,
    maxConns: Number.isInteger(max) && max >= 1 ? max : 128,
    headerBytes: Number.isInteger(header) && header >= 256 ? header : 8192,
    allowLan: link.allowLan === true,
    handshakeMs: Number.isInteger(Number(link.handshakeMs)) && Number(link.handshakeMs) >= 1000 ? Number(link.handshakeMs) : 10000,
    dialMs: Number.isInteger(Number(link.dialMs)) && Number(link.dialMs) >= 1000 ? Number(link.dialMs) : 10000,
    maxHandshakes: Number.isInteger(Number(link.maxHandshakes)) && Number(link.maxHandshakes) >= 1 ? Number(link.maxHandshakes) : 2,
  };
}

function arm(socket, config) {
  socket.setTimeout(linkOf(config).idleMs);
  socket.on("timeout", () => {
    log("空闲超时");
    socket.destroy();
  });
}

function admit(socket, config) {
  if (liveConns >= linkOf(config).maxConns) {
    log("连接数已满");
    socket.destroy();
    return false;
  }
  liveConns += 1;
  let closed = false;
  socket.once("close", () => {
    if (closed) return;
    closed = true;
    liveConns -= 1;
  });
  return true;
}

function ipv4Parts(ip) {
  const parts = String(ip).split(".");
  if (parts.length !== 4) return null;
  const nums = parts.map((part) => Number(part));
  if (nums.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  return nums;
}

function expandV6(ip) {
  let text = ip.toLowerCase();
  const dotted = text.match(/^(.*:)(\d+\.\d+\.\d+\.\d+)$/);
  if (dotted) {
    const nums = ipv4Parts(dotted[2]);
    if (!nums) return null;
    const tail = ((nums[0] << 8) | nums[1]).toString(16) + ":" + ((nums[2] << 8) | nums[3]).toString(16);
    text = dotted[1] + tail;
  }
  const halves = text.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(":") : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  if (halves.length === 1 && head.length !== 8) return null;
  const missing = 8 - head.length - tail.length;
  if (missing < 0) return null;
  const full = [...head, ...Array(missing).fill("0"), ...tail];
  if (full.length !== 8 || full.some((part) => !/^[0-9a-f]{1,4}$/.test(part))) return null;
  return full.map((part) => part.padStart(4, "0")).join(":");
}

function isBlockedV4(ip) {
  if (!ipv4Parts(ip)) return true;
  const nets = [
    ["0.0.0.0", 8],
    ["10.0.0.0", 8],
    ["100.64.0.0", 10],
    ["127.0.0.0", 8],
    ["169.254.0.0", 16],
    ["172.16.0.0", 12],
    ["192.0.0.0", 24],
    ["192.0.2.0", 24],
    ["192.168.0.0", 16],
    ["198.18.0.0", 15],
    ["198.51.100.0", 24],
    ["203.0.113.0", 24],
    ["224.0.0.0", 4],
    ["240.0.0.0", 4],
  ];
  return nets.some(([base, bits]) => cidrContains(`${base}/${bits}`, ip));
}

function isBlockedAddress(ip) {
  let raw = String(ip || "").trim().toLowerCase();
  if (raw.startsWith("[") && raw.endsWith("]")) raw = raw.slice(1, -1);
  if (raw.startsWith("::ffff:") && ipv4Parts(raw.slice(7))) return isBlockedV4(raw.slice(7));
  if (ipv4Parts(raw)) return isBlockedV4(raw);
  if (!raw.includes(":")) return true;
  const expanded = expandV6(raw);
  if (!expanded) return true;
  if (expanded === "0000:0000:0000:0000:0000:0000:0000:0000") return true;
  if (expanded === "0000:0000:0000:0000:0000:0000:0000:0001") return true;
  const first = Number.parseInt(expanded.slice(0, 4), 16);
  if ((first & 0xfe00) === 0xfc00) return true;
  if ((first & 0xffc0) === 0xfe80) return true;
  if ((first & 0xff00) === 0xff00) return true;
  if (expanded.startsWith("2001:0db8")) return true;
  if (expanded.startsWith("0000:0000:0000:0000:0000:ffff:")) {
    const hex = expanded.split(":").slice(6).join("");
    const v4 = [0, 1, 2, 3].map((i) => Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16)).join(".");
    return isBlockedV4(v4);
  }
  return false;
}

function allowHit(config, host, port) {
  const name = String(host || "").trim().toLowerCase().replace(/^\[|\]$/g, "");
  const list = Array.isArray(config.egress?.allow) ? config.egress.allow : [];
  for (const raw of list) {
    const item = String(raw || "").trim().toLowerCase();
    if (!item) continue;
    if (item.includes("/")) {
      const base = item.split("/")[0];
      if (ipv4Parts(base) && ipv4Parts(name) && cidrContains(item, name)) return true;
      continue;
    }
    const bracket = item.match(/^\[(.+)\]:(\d+)$/);
    if (bracket) {
      if (bracket[1] === name && Number(bracket[2]) === Number(port)) return true;
      continue;
    }
    const colon = item.lastIndexOf(":");
    if (colon > 0 && item.indexOf(":") === colon && /^\d+$/.test(item.slice(colon + 1))) {
      if (item.slice(0, colon) === name && Number(item.slice(colon + 1)) === Number(port)) return true;
      continue;
    }
    if (item === name) return true;
  }
  return false;
}

function lookupAll(host) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("dns")), 3000);
    lookup(host, { all: true, verbatim: true }, (err, rows) => {
      clearTimeout(timer);
      if (err) reject(err);
      else resolve(rows || []);
    });
  });
}

async function assessTarget(config, host, port) {
  const name = String(host || "").trim();
  const nport = Number(port);
  if (!name || !Number.isInteger(nport) || nport < 1 || nport > 65535) return { ok: false, reason: "目标无效" };
  if (config.egress?.blockPrivate === false) return { ok: true, host: name, port: nport };
  if (allowHit(config, name, nport)) return { ok: true, host: name, port: nport };
  if (ipv4Parts(name) || name.includes(":")) {
    if (isBlockedAddress(name)) return { ok: false, reason: "目标地址被拦截" };
    return { ok: true, host: name, port: nport };
  }
  let addrs = [];
  try {
    addrs = await lookupAll(name);
  } catch {
    return { ok: false, reason: "域名无法解析" };
  }
  if (!addrs.length) return { ok: false, reason: "域名无法解析" };
  for (const addr of addrs) {
    if (isBlockedAddress(addr.address)) return { ok: false, reason: "解析到内网地址" };
  }
  return { ok: true, host: addrs[0].address, port: nport };
}

const SOCKS_OK = Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
const SOCKS_FAIL = Buffer.from([0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);

function okSocks(socket) {
  if (!socket._lexisSocks || socket._lexisReplied) return;
  socket._lexisReplied = true;
  socket.write(SOCKS_OK);
}

function failSocks(socket) {
  if (socket.destroyed) return;
  if (socket._lexisSocks && !socket._lexisReplied) {
    socket._lexisReplied = true;
    socket.end(SOCKS_FAIL);
    return;
  }
  socket.destroy();
}

function pipe(a, b) {
  a.resume();
  b.resume();
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

function dial(host, port, config) {
  const bare = String(host).replace(/^\[|\]$/g, "");
  const socket = connectTcp({ host: bare, port, family: bare.includes(":") ? 6 : 4 });
  socket.on("error", () => socket.destroy());
  const onTimeout = () => {
    log("拨号超时");
    socket.destroy();
  };
  socket.setTimeout(linkOf(config).dialMs);
  socket.once("timeout", onTimeout);
  socket.once("connect", () => {
    socket.off("timeout", onTimeout);
    arm(socket, config);
  });
  return socket;
}

const lexSessions = new Map();
const inboundSessions = new Map();
const downUntil = new Map();
let poolReady = false;

function ensurePool(config) {
  if (poolReady) return;
  poolReady = true;
  startKdfPool(linkOf(config).maxHandshakes);
}

function requireToken(config) {
  const token = linkOf(config).token;
  if (token.length < 8) throw new Error("握手口令至少 8 个字符");
  return token;
}

function argonOf(config) {
  const offer = offerOf(config);
  return { memoryKiB: offer.memoryKiB, iterations: offer.iterations, parallelism: offer.parallelism };
}

function outerOf(config) {
  const outer = config.outer || {};
  const transport = ["tcp", "tls", "ws", "wss"].includes(outer.transport) ? outer.transport : "tcp";
  return {
    transport,
    wsPath: typeof outer.wsPath === "string" && outer.wsPath.startsWith("/") ? outer.wsPath : "/lexis",
    tlsVerify: outer.tlsVerify !== false,
  };
}

function zstdOf(config) {
  return { enabled: Boolean(config.zstd?.enabled), level: Number(config.zstd?.level) || 3 };
}

function offerOf(config) {
  const kdf = config.kdf || {};
  return {
    memoryKiB: Number(kdf.memoryKiB) || 4096,
    iterations: Number(kdf.iterations) || 2,
    parallelism: Number(kdf.parallelism) || 1,
    honey: config.honey === true,
  };
}

function peerList(config) {
  return (Array.isArray(config.peers) ? config.peers : []).filter((peer) => peer && peer.publicRawB64 && peer.endpoint);
}

function splitEndpoint(endpoint) {
  const text = String(endpoint || "").trim();
  const bracket = text.match(/^\[(.+)\]:(\d+)$/);
  if (bracket) return [bracket[1], Number(bracket[2])];
  const match = text.match(/^([^:]+):(\d+)$/);
  if (!match) throw new Error("对端地址要写成 主机:端口");
  return [match[1], Number(match[2])];
}

function choosePeer(config) {
  config = activeConfig || config;
  const now = Date.now();
  const peers = peerList(config).filter((peer) => (downUntil.get(peer.id || peer.publicRawB64) || 0) < now);
  const list = peers.length ? peers : peerList(config);
  if (!list.length) return null;
  const want = String(config.peerEndpoint || "");
  return list.find((peer) => peer.endpoint === want) || list[0];
}

async function sessionFor(config, peer) {
  config = activeConfig || config;
  ensurePool(config);
  const token = requireToken(config);
  const key = peer.id || peer.publicRawB64;
  if (lexSessions.has(key)) return lexSessions.get(key);
  const job = (async () => {
    const [host, port] = splitEndpoint(peer.endpoint);
    const outer = outerOf(config);
    const link = linkOf(config);
    const pipe = await dialOuter({
      transport: peer.transport || outer.transport,
      host,
      port,
      path: peer.wsPath || outer.wsPath,
      wsHost: peer.wsHost || host,
      tlsVerify: outer.tlsVerify,
      timeoutMs: link.dialMs,
    });
    const self = await nodeFromIdentity(config.identity, "edge");
    const session = await connectSession({
      pipe,
      self,
      peerRawB64: peer.publicRawB64,
      offer: offerOf(config),
      token,
      zstd: zstdOf(config),
      maxStreams: link.maxConns,
      heartbeatMs: Math.max(5, config.heartbeatSec || 15) * 1000,
      handshakeMs: link.handshakeMs,
      peerId: peer.id || "",
      onStream: (stream) => void handleRemoteStream(stream, config, { peerId: stream.session.peerId || peer.id || "" }),
    });
    void session.whenClosed().then(() => {
      if (lexSessions.get(key) === job) lexSessions.delete(key);
    });
    return session;
  })();
  lexSessions.set(key, job);
  try {
    return await job;
  } catch (err) {
    lexSessions.delete(key);
    downUntil.set(key, Date.now() + 1500);
    throw err;
  }
}

function bridgeSocket(stream, socket) {
  socket.on("data", (chunk) => {
    void stream.write(chunk).catch(() => socket.destroy());
  });
  socket.on("error", () => void stream.close());
  socket.on("close", () => void stream.close());
  const pull = async () => {
    try {
      for (;;) {
        const chunk = await stream.read();
        if (!chunk) {
          socket.end();
          return;
        }
        if (!socket.write(chunk)) await new Promise((resolve) => socket.once("drain", resolve));
      }
    } catch {
      socket.destroy();
    }
  };
  void pull();
}

function namedPeer(config, name) {
  const key = String(name || "");
  return peerList(config).find((peer) => peer.id === key || peer.name === key) || null;
}

function inboundSessionFor(config, name) {
  const peer = namedPeer(config, name);
  const id = peer?.id || String(name || "");
  const session = id ? inboundSessions.get(id) : null;
  if (!session || session.closed) throw new Error("没有来自该节点的会话");
  return session;
}

function reverseName(config, host) {
  const text = String(host || "");
  const parts = text.split(":");
  if (parts.length !== 2 || !parts[0] || !parts[1]) return null;
  if (!namedPeer(config, parts[0])) return null;
  return { peer: parts[0], service: parts[1] };
}

function targetAllowed(peer, rest) {
  const list = Array.isArray(peer.targets) ? peer.targets.map((item) => String(item).trim()).filter(Boolean) : [];
  if (!list.length) return true;
  const parsed = parseOpen(rest);
  const plain = parsed.host ? `${parsed.host}:${parsed.port}` : "";
  const cmd = parsed.host ? `${parsed.udp ? "udp" : "tcp"} ${parsed.host} ${parsed.port}` : String(rest || "").trim();
  const trimmed = String(rest || "").trim();
  return list.some((item) => item === trimmed || item === plain || item === cmd);
}

function replyReady(socket) {
  if (typeof socket._lexisReady === "function") {
    const fn = socket._lexisReady;
    socket._lexisReady = null;
    socket._lexisReplied = true;
    fn();
    return;
  }
  okSocks(socket);
}

function replyFail(socket) {
  if (typeof socket._lexisFail === "function") {
    const fn = socket._lexisFail;
    socket._lexisFail = null;
    socket._lexisReady = null;
    socket._lexisReplied = true;
    fn();
    return;
  }
  failSocks(socket);
}

async function exitUdp(stream, host, port) {
  const bare = String(host).replace(/^\[|\]$/g, "");
  const udp = createUdp(bare.includes(":") ? "udp6" : "udp4");
  await new Promise((resolve, reject) => {
    udp.once("error", reject);
    udp.bind(0, () => resolve());
  });
  await stream.accept();
  udp.on("message", (msg) => {
    void stream.write(msg).catch(() => udp.close());
  });
  try {
    for (;;) {
      const chunk = await stream.read();
      if (!chunk) break;
      await new Promise((resolve, reject) => udp.send(chunk, port, bare, (err) => (err ? reject(err) : resolve())));
    }
  } finally {
    udp.close();
    await stream.close().catch(() => undefined);
  }
}

async function handleRemoteStream(stream, config, via) {
  try {
    config = activeConfig || config;
    const command = stream.command || "";
    if (hopCount(command) > 4) {
      await stream.reject("中继跳数过多");
      return;
    }
    const parsed = parseOpen(command);
    if (parsed.expose) {
      const door = (config.exposes || []).find((item) => item.name === parsed.expose);
      if (!door) {
        await stream.reject("没有这个服务");
        return;
      }
      const who = via?.peerId || "";
      const caller = namedPeer(config, who);
      const allow = Array.isArray(door.allow) ? door.allow : [];
      const permitted = allow.includes(who) || (caller && (allow.includes(caller.id) || allow.includes(caller.name)));
      if (!permitted) {
        await stream.reject("这个节点不在允许名单里");
        return;
      }
      const remote = dial(door.host, door.port, config);
      let up = false;
      remote.once("error", () => {
        if (!up) void stream.reject("拨号失败");
        remote.destroy();
      });
      remote.once("connect", () => {
        up = true;
        note({ action: "direct", reason: `暴露 ${door.name}` }, `${door.host}:${door.port}`);
        void stream.accept().then(() => bridgeSocket(stream, remote)).catch(() => remote.destroy());
      });
      return;
    }
    if (parsed.relay) {
      const next = namedPeer(config, parsed.relay);
      if (!next) {
        await stream.reject("没有这个节点");
        return;
      }
      if (via && via.peerId && via.peerId === next.id) {
        await stream.reject("拒绝把流送回上一跳");
        return;
      }
      const caller = namedPeer(config, via?.peerId || "");
      if (!caller || caller.relay !== true) {
        await stream.reject("这个节点没有中继权限");
        return;
      }
      if (!targetAllowed(caller, parsed.rest)) {
        await stream.reject("这个目标不在中继名单里");
        return;
      }
      const down = await sessionFor(config, next);
      const remote = await down.open(parsed.rest);
      await stream.accept();
      note({ action: "proxy", reason: `中继 ${next.name}` }, parsed.rest);
      await pipeMux(stream, remote);
      return;
    }
    if (!parsed.host || !parsed.port) {
      await stream.reject("目标无效");
      return;
    }
    const decision = decide(config, {
      host: parsed.host,
      ip: isIp(parsed.host) ? parsed.host : "",
      port: String(parsed.port),
      network: parsed.udp ? "udp" : "tcp",
    });
    if (decision.action === "reject" || decision.action === "bypass") {
      note(decision, `${parsed.host}:${parsed.port}`);
      await stream.reject(decision.reason);
      return;
    }
    const verdict = await assessTarget(config, parsed.host, parsed.port);
    if (!verdict.ok) {
      note({ action: "reject", reason: verdict.reason }, `${parsed.host}:${parsed.port}`);
      await stream.reject(verdict.reason);
      return;
    }
    if (parsed.udp) {
      await exitUdp(stream, verdict.host, verdict.port);
      return;
    }
    const remote = dial(verdict.host, verdict.port, config);
    let up = false;
    remote.once("error", () => {
      if (!up) void stream.reject("拨号失败");
      remote.destroy();
    });
    remote.once("connect", () => {
      up = true;
      note({ action: "direct", reason: decision.reason }, `${parsed.host}:${parsed.port}`);
      void stream.accept().then(() => bridgeSocket(stream, remote)).catch(() => remote.destroy());
    });
  } catch (err) {
    log(`流转发失败 ${err.message || err}`);
    try {
      await stream.reject("转发失败");
    } catch {
      /* already closed */
    }
  }
}

function relayProxy(socket, config, host, port, network = "tcp") {
  void (async () => {
    try {
      config = activeConfig || config;
      if (!config.identity?.privateJwk) throw new Error("没有本机身份");
      const rev = reverseName(config, host);
      let stream;
      if (rev) {
        const session = inboundSessionFor(config, rev.peer);
        stream = await session.open(`expose ${rev.service}`);
      } else {
        const peer = choosePeer(config);
        if (!peer) throw new Error("没有加入的节点");
        const session = await sessionFor(config, peer);
        stream = await session.open(`${network} ${host} ${port}`);
      }
      replyReady(socket);
      bridgeSocket(stream, socket);
    } catch (err) {
      log(`接入 ${host}:${port} 失败：${err.message || err}`);
      replyFail(socket);
    }
  })();
}

function relayDirect(socket, host, port, config) {
  const remote = dial(host, port, config);
  remote.on("connect", () => {
    replyReady(socket);
    pipe(socket, remote);
  });
  remote.on("error", () => {
    remote.destroy();
    replyFail(socket);
  });
}

function applyAction(socket, config, decision, host, port) {
  note(decision, `${host}:${port}`);
  if (decision.action === "reject") {
    replyFail(socket);
    return;
  }
  if (decision.action === "proxy") relayProxy(socket, config, host, port);
  else relayDirect(socket, host, port, config);
}

async function acceptTunnel(socket, pipeReady, config) {
  let session = null;
  try {
    config = activeConfig || config;
    ensurePool(config);
    const token = requireToken(config);
    if (!config.identity?.privateJwk) throw new Error("没有本机身份");
    const pipe = await pipeReady;
    const self = await nodeFromIdentity(config.identity, "gate");
    const link = linkOf(config);
    session = await acceptSession({
      pipe,
      self,
      peers: peerList(config),
      token,
      kdf: argonOf(config),
      zstd: zstdOf(config),
      maxStreams: link.maxConns,
      heartbeatMs: Math.max(5, config.heartbeatSec || 15) * 1000,
      handshakeMs: link.handshakeMs,
      onReady: (ready) => {
        if (ready.peerId) inboundSessions.set(ready.peerId, ready);
      },
      onStream: (stream) => void handleRemoteStream(stream, activeConfig || config, { peerId: stream.session.peerId || "" }),
    });
    if (session.peerId) inboundSessions.set(session.peerId, session);
    await session.whenClosed();
  } catch (err) {
    log(`隧道拒绝 ${err.message || err}`);
    socket.destroy();
  } finally {
    if (session?.peerId && inboundSessions.get(session.peerId) === session) inboundSessions.delete(session.peerId);
  }
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
  socket._lexisSocks = true;
  let stage = 0;
  let pending = Buffer.alloc(0);
  const cap = linkOf(config).headerBytes;
  socket.on("data", (chunk) => {
    pending = Buffer.concat([pending, chunk]);
    if (pending.length > cap) {
      socket.destroy();
      return;
    }
    if (stage === 0) {
      if (pending.length < 2) return;
      const methods = pending[1];
      if (pending.length < 2 + methods) return;
      const offered = [...pending.subarray(2, 2 + methods)];
      pending = pending.subarray(2 + methods);
      const user = String(config.socksAuth?.user || "");
      const pass = String(config.socksAuth?.pass || "");
      if (user || pass) {
        if (!user || !pass || !offered.includes(0x02)) {
          socket.end(Buffer.from([0x05, 0xff]));
          return;
        }
        socket.write(Buffer.from([0x05, 0x02]));
        stage = 0.5;
      } else {
        socket.write(Buffer.from([0x05, 0x00]));
        stage = 1;
      }
    }
    if (stage === 0.5) {
      if (pending.length < 2) return;
      const ulen = pending[1];
      if (pending.length < 2 + ulen + 1) return;
      const plen = pending[2 + ulen];
      if (pending.length < 3 + ulen + plen) return;
      const user = pending.subarray(2, 2 + ulen).toString("utf8");
      const pass = pending.subarray(3 + ulen, 3 + ulen + plen).toString("utf8");
      pending = pending.subarray(3 + ulen + plen);
      const okUser = sameSecret(user, config.socksAuth?.user || "");
      const okPass = sameSecret(pass, config.socksAuth?.pass || "");
      if (!okUser || !okPass) {
        socket.end(Buffer.from([0x01, 0x01]));
        return;
      }
      socket.write(Buffer.from([0x01, 0x00]));
      stage = 1;
    }
    if (stage !== 1) return;
    if (pending.length < 4) return;
    const cmd = pending[1];
    if (cmd !== 0x01 && cmd !== 0x03) {
      socket._lexisReplied = true;
      socket.removeAllListeners("data");
      socket.end(Buffer.from([0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
      return;
    }
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
      socket._lexisReplied = true;
      socket.removeAllListeners("data");
      socket.end(Buffer.from([0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
      return;
    }
    const rest = pending.subarray(offset);
    pending = Buffer.alloc(0);
    stage = 2;
    socket.pause();
    socket.removeAllListeners("data");
    if (rest.length) socket.unshift(rest);
    if (cmd === 0x03) {
      socket.resume();
      startUdpAssociate(socket, config);
      return;
    }
    void (async () => {
      const processName = await findProcess(socket.remotePort);
      const decision = decide(config, { host, ip: isIp(host) ? host : "", process: processName, port: String(port), network: "tcp" });
      if (decision.action === "reject") {
        note(decision, `${host}:${port}`);
        socket._lexisReplied = true;
        socket.resume();
        socket.end(Buffer.from([0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
        return;
      }
      applyAction(socket, config, decision, host, port);
    })();
  });
  socket.on("error", () => socket.destroy());
}

function sameSecret(left, right) {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  if (a.length !== b.length || a.length === 0) return false;
  return timingSafeEqual(a, b);
}

function parseSocksUdp(msg) {
  if (msg.length < 10 || msg[2] !== 0) return null;
  const atyp = msg[3];
  if (atyp === 1) {
    const host = [...msg.subarray(4, 8)].join(".");
    return { host, port: msg.readUInt16BE(8), data: msg.subarray(10) };
  }
  if (atyp === 3) {
    const len = msg[4];
    if (msg.length < 7 + len) return null;
    return {
      host: msg.subarray(5, 5 + len).toString("utf8"),
      port: msg.readUInt16BE(5 + len),
      data: msg.subarray(7 + len),
    };
  }
  if (atyp === 4) {
    if (msg.length < 22) return null;
    const words = [];
    for (let i = 0; i < 16; i += 2) words.push(msg.readUInt16BE(4 + i).toString(16));
    return { host: words.join(":"), port: msg.readUInt16BE(20), data: msg.subarray(22) };
  }
  return null;
}

function ipv6Wire(host) {
  const expanded = expandV6(String(host).replace(/^\[|\]$/g, ""));
  if (!expanded) return null;
  const out = Buffer.alloc(16);
  expanded.split(":").forEach((part, i) => out.writeUInt16BE(Number.parseInt(part, 16), i * 2));
  return out;
}

function socksUdpPacket(host, port, data) {
  const clean = String(host).replace(/^\[|\]$/g, "");
  const v6 = clean.includes(":") ? ipv6Wire(clean) : null;
  if (v6) {
    const out = Buffer.alloc(22 + data.length);
    out[3] = 4;
    v6.copy(out, 4);
    out.writeUInt16BE(port, 20);
    Buffer.from(data).copy(out, 22);
    return out;
  }
  if (isIp(clean)) {
    const out = Buffer.alloc(10 + data.length);
    out[3] = 1;
    clean.split(".").forEach((part, i) => {
      out[4 + i] = Number(part);
    });
    out.writeUInt16BE(port, 8);
    Buffer.from(data).copy(out, 10);
    return out;
  }
  const name = Buffer.from(clean);
  const out = Buffer.alloc(7 + name.length + data.length);
  out[3] = 3;
  out[4] = name.length;
  name.copy(out, 5);
  out.writeUInt16BE(port, 5 + name.length);
  Buffer.from(data).copy(out, 7 + name.length);
  return out;
}

function startUdpAssociate(socket, config) {
  const udp = createUdp("udp4");
  const streams = new Map();
  const directs = new Map();
  let client = null;
  const closeAll = () => {
    try {
      udp.close();
    } catch {
      /* already closed */
    }
    for (const stream of streams.values()) void stream.close();
    for (const direct of directs.values()) {
      try {
        direct.close();
      } catch {
        /* already closed */
      }
    }
    directs.clear();
  };
  udp.on("error", () => socket.destroy());
  udp.bind(0, "127.0.0.1", () => {
    const reply = Buffer.from([0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0]);
    reply.writeUInt16BE(udp.address().port, 8);
    socket._lexisReplied = true;
    socket.write(reply);
  });
  socket.on("close", closeAll);
  udp.on("message", (msg, rinfo) => {
    if (!client) client = { address: rinfo.address, port: rinfo.port };
    else if (client.address !== rinfo.address || client.port !== rinfo.port) return;
    const parsed = parseSocksUdp(msg);
    if (!parsed || !parsed.port) return;
    void (async () => {
      try {
        const decision = decide(config, {
          host: parsed.host,
          ip: isIp(parsed.host) ? parsed.host : "",
          port: String(parsed.port),
          network: "udp",
        });
        note(decision, `udp ${parsed.host}:${parsed.port}`);
        if (decision.action === "reject") return;
        const sendBack = (chunk) => {
          if (!client) return;
          udp.send(socksUdpPacket(parsed.host, parsed.port, chunk), client.port, client.address);
        };
        if (decision.action !== "proxy") {
          const key = `d:${parsed.host}:${parsed.port}`;
          let direct = directs.get(key);
          if (!direct) {
            direct = createUdp(String(parsed.host).includes(":") ? "udp6" : "udp4");
            direct.on("message", sendBack);
            direct.on("error", () => {
              directs.delete(key);
              try {
                direct.close();
              } catch {
                /* already closed */
              }
            });
            directs.set(key, direct);
          }
          direct.send(parsed.data, parsed.port, parsed.host);
          return;
        }
        const key = `${parsed.host}:${parsed.port}`;
        let stream = streams.get(key);
        if (!stream) {
          const peer = choosePeer(config);
          if (!peer || !config.identity?.privateJwk) return;
          const session = await sessionFor(config, peer);
          stream = await session.open(`udp ${parsed.host} ${parsed.port}`);
          streams.set(key, stream);
          const pump = async () => {
            for (;;) {
              const chunk = await stream.read();
              if (!chunk) return;
              sendBack(chunk);
            }
          };
          void pump();
        }
        await stream.write(parsed.data);
      } catch (err) {
        log(`udp ${parsed.host}:${parsed.port} 失败：${err.message || err}`);
      }
    })();
  });
}

function headerValue(lines, name) {
  const prefix = `${name.toLowerCase()}:`;
  const line = lines.find((item) => item.toLowerCase().startsWith(prefix));
  return line ? line.slice(prefix.length).trim() : "";
}

function basicOk(value, user, pass) {
  const matched = String(value || "").match(/^Basic\s+(\S+)/i);
  if (!matched) return false;
  let decoded = "";
  try {
    decoded = Buffer.from(matched[1], "base64").toString("utf8");
  } catch {
    return false;
  }
  const idx = decoded.indexOf(":");
  if (idx < 0) return false;
  return sameSecret(decoded.slice(0, idx), user) && sameSecret(decoded.slice(idx + 1), pass);
}

function httpAuthOk(lines, config) {
  const user = String(config.socksAuth?.user || "");
  const pass = String(config.socksAuth?.pass || "");
  if (!user && !pass) return true;
  return basicOk(headerValue(lines, "proxy-authorization"), user, pass);
}

function routeHttp(socket, config, host, port) {
  void (async () => {
    try {
      const decision = decide(config, { host, ip: isIp(host) ? host : "", port: String(port), network: "tcp" });
      if (decision.action === "reject") {
        note(decision, `${host}:${port}`);
        replyFail(socket);
        return;
      }
      applyAction(socket, config, decision, host, port);
    } catch (err) {
      log(`http ${host}:${port} 失败：${err.message || err}`);
      replyFail(socket);
    }
  })();
}

function handleHttp(socket, config) {
  let buf = Buffer.alloc(0);
  const cap = linkOf(config).headerBytes;
  const onData = (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    if (buf.length > cap) {
      socket.destroy();
      return;
    }
    const end = buf.indexOf("\r\n\r\n");
    if (end < 0) return;
    socket.removeListener("data", onData);
    const head = buf.subarray(0, end).toString("utf8");
    const rest = buf.subarray(end + 4);
    const lines = head.split("\r\n");
    const matched = (lines[0] || "").match(/^([A-Z]+)\s+(\S+)\s+HTTP\/1\.[01]$/i);
    if (!matched) {
      socket.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
      return;
    }
    const method = matched[1].toUpperCase();
    const target = matched[2];
    if (!httpAuthOk(lines, activeConfig || config)) {
      socket.end('HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="lexis"\r\nConnection: close\r\n\r\n');
      return;
    }
    const fail = () => {
      if (!socket.destroyed) socket.end("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n");
    };
    if (method === "CONNECT") {
      const hostPort = target.match(/^(?:\[([^\]]+)\]|([^:]+)):(\d+)$/);
      if (!hostPort) {
        socket.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
        return;
      }
      socket._lexisReady = () => {
        socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
        if (rest.length) socket.unshift(rest);
      };
      socket._lexisFail = fail;
      socket.pause();
      routeHttp(socket, activeConfig || config, hostPort[1] || hostPort[2], Number(hostPort[3]));
      return;
    }
    let url;
    try {
      url = new URL(target);
    } catch {
      socket.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
      return;
    }
    const path = `${url.pathname || "/"}${url.search || ""}`;
    const kept = lines.slice(1).filter((line) => line && !/^proxy-/i.test(line));
    const rebuilt = Buffer.from(`${method} ${path} HTTP/1.1\r\n${kept.join("\r\n")}\r\n\r\n`);
    const prefix = Buffer.concat([rebuilt, rest]);
    socket._lexisReady = () => {
      if (prefix.length) socket.unshift(prefix);
    };
    socket._lexisFail = fail;
    socket.pause();
    const port = Number(url.port || (url.protocol === "https:" ? 443 : 80));
    routeHttp(socket, activeConfig || config, url.hostname, port);
  };
  socket.on("data", onData);
  socket.on("error", () => socket.destroy());
}

function listenHost(config, inbound) {
  const listen = inbound.listen || "127.0.0.1";
  if (inbound.protocol === "tunnel") return listen;
  if (linkOf(config).allowLan) return listen;
  if (listen !== "127.0.0.1" && listen !== "::1") log(`${inbound.tag || inbound.protocol} 改绑 127.0.0.1`);
  return "127.0.0.1";
}

function ensureTlsMaterial() {
  const certPath = join(here, "lexis-tls.crt");
  const keyPath = join(here, "lexis-tls.key");
  if (existsSync(certPath) && existsSync(keyPath)) return { certPath, keyPath };
  try {
    execFileSync(
      "openssl",
      ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-keyout", keyPath, "-out", certPath, "-days", "365", "-nodes", "-subj", "/CN=lexis"],
      { stdio: "ignore" },
    );
  } catch {
    throw new Error("没有 TLS 证书。请把证书和私钥放在程序旁边，或安装 openssl 后由程序自己生成。安装包不再附带私钥。");
  }
  log("已在本机生成 TLS 证书。正式部署请换成自己的证书。这把私钥不要分发出去。");
  return { certPath, keyPath };
}

function serveInbound(config, inbound) {
  const host = listenHost(config, inbound);
  if (inbound.protocol === "tunnel") {
    const outer = outerOf(config);
    let material = {};
    if (outer.transport === "tls" || outer.transport === "wss") {
      try {
        material = ensureTlsMaterial();
      } catch (err) {
        const message = err.message || String(err);
        state.errors.push(message);
        log(message);
        return null;
      }
    }
    const tunnel = listenOuter({
      transport: outer.transport,
      host,
      port: inbound.port,
      path: outer.wsPath,
      certPath: material.certPath,
      keyPath: material.keyPath,
      onSocket(socket, pipeReady) {
        if (!admit(socket, config)) return;
        arm(socket, config);
        void acceptTunnel(socket, pipeReady, config);
      },
    });
    void tunnel.listening().then(() => {
      const suffix = outer.transport === "ws" || outer.transport === "wss" ? outer.wsPath : "";
      state.listeners.push(`tunnel ${outer.transport} ${host}:${inbound.port}${suffix}`);
      log(`监听词表 ${outer.transport} ${host}:${inbound.port}${suffix}`);
    });
    return tunnel;
  }
  const server = createTcp((socket) => {
    socket.on("error", () => socket.destroy());
    if (!admit(socket, config)) return;
    arm(socket, config);
    if (inbound.protocol === "socks") {
      handleSocks(socket, config);
      return;
    }
    if (inbound.protocol === "http") {
      handleHttp(socket, config);
      return;
    }
    void (async () => {
      const processName = await findProcess(socket.remotePort);
      const targetHost = inbound.targetHost;
      const targetPort = inbound.targetPort;
      const decision = decide(activeConfig || config, { host: targetHost, ip: isIp(targetHost) ? targetHost : "", process: processName, port: String(targetPort), network: "tcp" });
      applyAction(socket, activeConfig || config, decision, targetHost, targetPort);
    })();
  });
  server.on("error", (err) => {
    state.errors.push(`${inbound.tag} ${inbound.port}: ${err.message}`);
    log(`入站失败 ${inbound.tag}: ${err.message}`);
  });
  server.listen(inbound.port, host, () => {
    state.listeners.push(`${inbound.protocol} ${host}:${inbound.port}`);
    log(`监听 ${inbound.protocol} ${host}:${inbound.port}`);
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
  netsh interface portproxy add v4tov4 listenaddress=127.0.0.1 listenport=$port connectaddress=127.0.0.1 connectport=$port
  Write-Output "portproxy 只绑 127.0.0.1:$port，不向局域网公布"
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

const reverseOn = new Set();

function serveReverse(door) {
  const host = door.listen || "127.0.0.1";
  const server = createTcp((socket) => {
    socket.on("error", () => socket.destroy());
    const config = activeConfig;
    if (config) arm(socket, config);
    void (async () => {
      try {
        if (!activeConfig) throw new Error("没有配置");
        const session = inboundSessionFor(activeConfig, door.peer);
        const stream = await session.open(`expose ${door.service}`);
        bridgeSocket(stream, socket);
      } catch (err) {
        log(`反向 ${door.peer}:${door.service} 失败：${err.message || err}`);
        socket.destroy();
      }
    })();
  });
  server.on("error", (err) => {
    state.errors.push(`反向 ${door.port}: ${err.message}`);
    log(`反向入口失败 ${door.service}: ${err.message}`);
  });
  server.listen(door.port, host, () => {
    state.listeners.push(`reverse ${host}:${door.port} ${door.peer}:${door.service}`);
    log(`反向 ${host}:${door.port} → ${door.peer} 的 ${door.service}`);
  });
  return server;
}

function bootReverses() {
  const config = activeConfig;
  if (!config) return;
  for (const door of config.reverses || []) {
    const key = `${door.listen || "127.0.0.1"}:${door.port}:${door.peer}:${door.service}`;
    if (reverseOn.has(key)) continue;
    reverseOn.add(key);
    serveReverse(door);
  }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

const peerLoops = new Set();

function keepPeers() {
  const config = activeConfig;
  if (!config || config.role === "gate") return;
  for (const peer of peerList(config)) {
    const key = peer.id || peer.publicRawB64;
    if (!key || peerLoops.has(key)) continue;
    peerLoops.add(key);
    void (async () => {
      let delay = 1000;
      while (activeConfig && activeConfig.role !== "gate" && namedPeer(activeConfig, key)) {
        const current = namedPeer(activeConfig, key);
        if (!current) break;
        try {
          const session = await sessionFor(activeConfig, current);
          delay = 1000;
          await session.whenClosed();
          log(`和 ${current.name} 断了，准备重连`);
        } catch (err) {
          log(`连 ${current.name} 失败：${err.message || err}`);
        }
        if (!activeConfig || !namedPeer(activeConfig, key)) break;
        downUntil.set(key, Date.now() + delay);
        await sleep(delay);
        delay = Math.min(30000, Math.round(delay * 1.6));
      }
      peerLoops.delete(key);
    })();
  }
}

function runtimeDir() {
  if (process.argv.includes("--config")) return dirname(resolve(configPath));
  return here;
}

function watchConfig() {
  let last = 0;
  try {
    last = statSync(configPath).mtimeMs;
  } catch {
    /* config appears later */
  }
  const timer = setInterval(() => {
    let mtime = 0;
    try {
      mtime = statSync(configPath).mtimeMs;
    } catch {
      return;
    }
    if (mtime === last) return;
    last = mtime;
    try {
      const next = loadConfig();
      const prevIds = new Set(peerList(activeConfig || {}).map((peer) => peer.id).filter(Boolean));
      const nextIds = new Set(peerList(next).map((peer) => peer.id).filter(Boolean));
      activeConfig = next;
      state.config = next;
      for (const id of prevIds) {
        if (nextIds.has(id)) continue;
        const pending = lexSessions.get(id);
        lexSessions.delete(id);
        inboundSessions.get(id)?.shutdown?.();
        inboundSessions.delete(id);
        void Promise.resolve(pending).then((session) => session?.shutdown?.()).catch(() => undefined);
        log(`节点 ${id} 已从名单摘掉`);
      }
      keepPeers();
      bootReverses();
      log("配置已热加载");
    } catch (err) {
      log(`配置没读上：${err.message || err}`);
    }
  }, 1000);
  timer.unref?.();
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
  if (hopCount("relay a relay b tcp h 1") !== 2 || !parseOpen("udp h 9").udp || parseOpen("expose ssh").expose !== "ssh") {
    console.error("open grammar failed");
    process.exit(1);
  }
  if (!isBlockedAddress("127.0.0.1") || !isBlockedAddress("10.0.0.8") || !isBlockedAddress("169.254.169.254") || !isBlockedAddress("::1") || isBlockedAddress("8.8.8.8")) {
    console.error("address check failed");
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
  activeConfig = config;
  state.config = config;
  if (!outerOf(config).tlsVerify) {
    log("词隙：没有校验 TLS 证书。正式部署请换成自己的证书并打开校验。试验证书的私钥不要放进安装包。");
  }
  try {
    requireToken(config);
  } catch (err) {
    console.error(err.message || err);
    process.exit(1);
  }
  ensurePool(config);
  await pullResources(config);
  const home = runtimeDir();
  mkdirSync(home, { recursive: true });
  writeFileSync(join(home, "lexis-agent.pid"), String(process.pid));
  for (const inbound of config.inbounds || []) serveInbound(config, inbound);
  bootReverses();
  applySystem(config);
  startStatus(config);
  keepPeers();
  watchConfig();
  const beat = () => {
    state.beats += 1;
    state.lastBeat = Date.now();
    writeFileSync(join(home, "lexis-agent.state.json"), JSON.stringify({ pid: process.pid, beats: state.beats, at: state.lastBeat, listeners: state.listeners }, null, 2));
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
  log(`词隙客户端常驻中，状态页 http://${config.statusHost || "127.0.0.1"}:${config.statusPort || 17890}/`);
}

function isDirectRun() {
  const entry = process.argv[1];
  if (!entry) return false;
  try {
    return fileURLToPath(import.meta.url) === resolve(entry);
  } catch {
    return false;
  }
}

if (isDirectRun()) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}

export { isBlockedAddress, assessTarget, serveInbound };
