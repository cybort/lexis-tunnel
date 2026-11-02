import { clampKdf, clampVaultKdf, DEFAULT_KDF, type ArgonParams } from "./kdf";
import { vaultFromStored, vaultToStored } from "./honey";
import type { StoredProgram, StoredVault } from "./types";

export const PROFILE_VERSION = 1 as const;

export type RunMode = "fixed-port" | "system-forward";
export type ClientRole = "edge" | "gate";
export type RuleAction = "proxy" | "direct" | "bypass" | "reject";
export type InboundProtocol = "socks" | "tcp" | "tunnel" | "http" | "transparent";

export type RuleType =
  | "DOMAIN"
  | "DOMAIN-SUFFIX"
  | "DOMAIN-KEYWORD"
  | "IP-CIDR"
  | "GEOIP"
  | "GEOSITE"
  | "PROCESS-NAME"
  | "PORT"
  | "NETWORK"
  | "MATCH";

export type RouteRule = {
  id: string;
  type: RuleType;
  value: string;
  action: RuleAction;
};

export type Inbound = {
  id: string;
  tag: string;
  protocol: InboundProtocol;
  listen: string;
  port: number;
  targetHost: string;
  targetPort: number;
};

export type ProcessRule = {
  id: string;
  name: string;
  action: RuleAction;
};

export type OuterTransport = "tcp" | "tls" | "ws" | "wss";

export type NodeIdentity = {
  id: string;
  name: string;
  publicJwk: JsonWebKey;
  privateJwk: JsonWebKey;
  publicRawB64: string;
  fingerprint: string;
};

export type NetPeer = {
  id: string;
  name: string;
  endpoint: string;
  transport: OuterTransport;
  publicRawB64: string;
  wsPath: string;
  wsHost: string;
  relay: boolean;
  /** This peer may ask us to dial the public Internet. Default off. */
  exit: boolean;
  targets: string[];
};

export type ExposeService = {
  id: string;
  name: string;
  host: string;
  port: number;
  allow: string[];
};

export type ReverseDoor = {
  id: string;
  listen: string;
  port: number;
  peer: string;
  service: string;
};

export type LexisProfile = {
  version: typeof PROFILE_VERSION;
  name: string;
  role: ClientRole | "";
  mode: RunMode;
  logLevel: "info" | "debug";
  peerEndpoint: string;
  inbounds: Inbound[];
  processDefault: RuleAction;
  processes: ProcessRule[];
  rules: RouteRule[];
  extras: string;
  geositeUrl: string;
  geoipUrl: string;
  statusHost: string;
  statusPort: number;
  /** Required before /metrics or the status page leaves loopback. /health stays open. */
  statusToken: string;
  heartbeatSec: number;
  linux: { method: "tproxy" | "redirect" | "tun"; mark: number; table: number; dnsRedirect: boolean };
  windows: { method: "windivert" | "portproxy"; gateway: string };
  android: { method: "vpn"; mtu: number; address: string; dns: string };
  kdf: ArgonParams;
  honey: boolean;
  /** Cover coefficients. Keys used to compile it are not stored. */
  honeyProgram: StoredProgram | null;
  /** Long-term key coefficients. Exported config drops this and the scalar. */
  seal: StoredVault | null;
  zstd: { enabled: boolean; level: number };
  /** Wire budget and sender-only pad policy. Exported for the resident agent. */
  frame: {
    maxExpansion: number;
    smallFramePolicy: "expansion" | "honey";
    coalesceTarget: number;
  };
  link: {
    token: string;
    idleMs: number;
    maxConns: number;
    headerBytes: number;
    allowLan: boolean;
    handshakeMs: number;
    dialMs: number;
    maxHandshakes: number;
    udpIdleMs: number;
    udpMax: number;
    maxHalfOpen: number;
    /** per network prefix since 3.0.1 (IPv4 /halfOpenPrefixV4, IPv6 /halfOpenPrefixV6) */
    maxHalfOpenPerIp: number;
    halfOpenPrefixV4: number;
    halfOpenPrefixV6: number;
    /** hard cap on silently held (refused / failed) tunnel connections */
    maxSilent: number;
    /** release the half-open slot if no byte arrives within this many ms (0 = off) */
    firstByteMs: number;
  };
  egress: { blockPrivate: boolean; allow: string[] };
  outer: { transport: OuterTransport; wsPath: string; tlsVerify: boolean };
  socksAuth: { user: string; pass: string };
  identity: NodeIdentity | null;
  peers: NetPeer[];
  exposes: ExposeService[];
  reverses: ReverseDoor[];
};

export const RULE_TYPES: RuleType[] = [
  "DOMAIN",
  "DOMAIN-SUFFIX",
  "DOMAIN-KEYWORD",
  "IP-CIDR",
  "GEOIP",
  "GEOSITE",
  "PROCESS-NAME",
  "PORT",
  "NETWORK",
  "MATCH",
];

export const ACTIONS: RuleAction[] = ["proxy", "direct", "bypass", "reject"];

export const GEOSITE: Record<string, string[]> = {
  private: ["localhost", "local", "localdomain", "invalid"],
  cn: ["cn", "baidu.com", "qq.com", "taobao.com", "aliyun.com", "bilibili.com", "jd.com"],
  google: ["google.com", "gstatic.com", "googleapis.com", "youtube.com", "gmail.com"],
  telegram: ["telegram.org", "t.me", "telegra.ph"],
};

export const GEOIP: Record<string, string[]> = {
  private: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16"],
  cn: ["114.114.114.114/32", "223.5.5.5/32", "119.29.29.29/32", "180.76.76.76/32"],
};

const ACTION_ALIAS: Record<string, RuleAction> = {
  proxy: "proxy",
  接入: "proxy",
  PROXY: "proxy",
  词隙: "proxy",
  direct: "direct",
  DIRECT: "direct",
  直连: "direct",
  bypass: "bypass",
  BYPASS: "bypass",
  绕行: "bypass",
  reject: "reject",
  REJECT: "reject",
  拒绝: "reject",
};

export function defaultProfile(): LexisProfile {
  return {
    version: PROFILE_VERSION,
    name: "词隙",
    role: "edge",
    mode: "fixed-port",
    logLevel: "info",
    peerEndpoint: "",
    inbounds: [
      {
        id: "in-socks",
        tag: "本地 SOCKS",
        protocol: "socks",
        listen: "127.0.0.1",
        port: 1080,
        targetHost: "",
        targetPort: 0,
      },
    ],
    processDefault: "proxy",
    processes: [
      { id: "proc-browser", name: "chrome", action: "proxy" },
      { id: "proc-ssh", name: "ssh", action: "bypass" },
    ],
    rules: [
      { id: "r-private-site", type: "GEOSITE", value: "private", action: "direct" },
      { id: "r-private-ip", type: "GEOIP", value: "private", action: "direct" },
      { id: "r-cn-site", type: "GEOSITE", value: "cn", action: "direct" },
      { id: "r-cn-ip", type: "GEOIP", value: "cn", action: "direct" },
      { id: "r-ssh", type: "PROCESS-NAME", value: "ssh", action: "bypass" },
      { id: "r-match", type: "MATCH", value: "", action: "proxy" },
    ],
    extras: "",
    geositeUrl: "",
    geoipUrl: "",
    statusHost: "127.0.0.1",
    statusPort: 17890,
    statusToken: "",
    heartbeatSec: 15,
    linux: { method: "redirect", mark: 255, table: 100, dnsRedirect: true },
    windows: { method: "portproxy", gateway: "10.7.0.1" },
    android: { method: "vpn", mtu: 1500, address: "10.7.0.2/32", dns: "1.1.1.1" },
    kdf: { ...DEFAULT_KDF },
    honey: false,
    honeyProgram: null,
    seal: null,
    zstd: { enabled: false, level: 3 },
    frame: { maxExpansion: 5, smallFramePolicy: "expansion", coalesceTarget: 1024 },
    link: {
      token: "",
      idleMs: 120000,
      maxConns: 1024,
      headerBytes: 8192,
      allowLan: false,
      handshakeMs: 10000,
      dialMs: 10000,
      maxHandshakes: 2,
      udpIdleMs: 60000,
      udpMax: 64,
      maxHalfOpen: 512,
      maxHalfOpenPerIp: 8,
      halfOpenPrefixV4: 24,
      halfOpenPrefixV6: 64,
      maxSilent: 1024,
      firstByteMs: 2000,
    },
    egress: { blockPrivate: true, allow: [] },
    outer: { transport: "tcp", wsPath: "/lexis", tlsVerify: true },
    socksAuth: { user: "", pass: "" },
    identity: null,
    peers: [],
    exposes: [],
    reverses: [],
  };
}

export function actionLabel(action: RuleAction): string {
  switch (action) {
    case "proxy":
      return "接入";
    case "direct":
      return "直连";
    case "bypass":
      return "绕行";
    case "reject":
      return "拒绝";
  }
}

function newId(prefix: string): string {
  return `${prefix}-${Math.random().toString(36).slice(2, 8)}`;
}

function linuxOf(base: LexisProfile["linux"], raw?: Partial<LexisProfile["linux"]> | null): LexisProfile["linux"] {
  const method = raw?.method === "tproxy" || raw?.method === "tun" || raw?.method === "redirect" ? raw.method : base.method;
  return {
    ...base,
    ...(raw ?? {}),
    method,
    mark: clampNum(raw?.mark, 1, 255, base.mark),
    table: clampNum(raw?.table, 1, 65535, base.table),
    dnsRedirect: raw?.dnsRedirect !== false,
  };
}

export function normalizeProfile(input: unknown): LexisProfile {
  const base = defaultProfile();
  if (!input || typeof input !== "object") return base;
  const raw = input as Partial<LexisProfile>;
  return {
    ...base,
    ...raw,
    version: PROFILE_VERSION,
    role: raw.role === "gate" ? "gate" : raw.role === "edge" ? "edge" : "",
    mode: raw.mode === "system-forward" ? "system-forward" : "fixed-port",
    logLevel: raw.logLevel === "debug" ? "debug" : "info",
    processDefault: isAction(raw.processDefault) ? raw.processDefault : base.processDefault,
    inbounds: Array.isArray(raw.inbounds) ? raw.inbounds.map(normalizeInbound) : base.inbounds,
    processes: Array.isArray(raw.processes) ? raw.processes.map(normalizeProcess) : base.processes,
    rules: Array.isArray(raw.rules) ? raw.rules.map(normalizeRule) : base.rules,
    linux: linuxOf(base.linux, raw.linux),
    windows: { ...base.windows, ...(raw.windows ?? {}) },
    android: { ...base.android, ...(raw.android ?? {}) },
    heartbeatSec: clampNum(raw.heartbeatSec, 5, 120, base.heartbeatSec),
    statusHost: typeof raw.statusHost === "string" && raw.statusHost.trim() ? raw.statusHost.trim() : base.statusHost,
    statusPort: clampNum(raw.statusPort, 1, 65535, base.statusPort),
    statusToken: typeof raw.statusToken === "string" ? raw.statusToken : "",
    kdf: clampKdf(raw.kdf),
    honey: raw.honey === true,
    honeyProgram: normalizeProgram(raw.honeyProgram),
    seal: normalizeSeal(raw.seal),
    zstd: {
      enabled: Boolean(raw.zstd && raw.zstd.enabled),
      level: clampNum(raw.zstd?.level, 1, 19, base.zstd.level),
    },
    frame: frameOf(base.frame, raw.frame),
    link: {
      token: typeof raw.link?.token === "string" ? raw.link.token : "",
      idleMs: clampNum(raw.link?.idleMs, 1000, 600000, base.link.idleMs),
      maxConns: clampNum(raw.link?.maxConns, 1, 10000, base.link.maxConns),
      headerBytes: clampNum(raw.link?.headerBytes, 256, 65536, base.link.headerBytes),
      allowLan: raw.link?.allowLan === true,
      handshakeMs: clampNum(raw.link?.handshakeMs, 1000, 60000, base.link.handshakeMs),
      dialMs: clampNum(raw.link?.dialMs, 1000, 60000, base.link.dialMs),
      maxHandshakes: clampNum(raw.link?.maxHandshakes, 1, 8, base.link.maxHandshakes),
      udpIdleMs: clampNum(raw.link?.udpIdleMs, 1000, 600000, base.link.udpIdleMs),
      udpMax: clampNum(raw.link?.udpMax, 4, 4096, base.link.udpMax),
      maxHalfOpen: clampNum(raw.link?.maxHalfOpen, 1, 10000, base.link.maxHalfOpen),
      maxHalfOpenPerIp: clampNum(raw.link?.maxHalfOpenPerIp, 1, 1024, base.link.maxHalfOpenPerIp),
      halfOpenPrefixV4: clampNum(raw.link?.halfOpenPrefixV4, 0, 32, base.link.halfOpenPrefixV4),
      halfOpenPrefixV6: clampNum(raw.link?.halfOpenPrefixV6, 0, 128, base.link.halfOpenPrefixV6),
      maxSilent: clampNum(raw.link?.maxSilent, 0, 100000, base.link.maxSilent),
      firstByteMs: clampNum(raw.link?.firstByteMs, 0, 60000, base.link.firstByteMs),
    },
    egress: {
      blockPrivate: raw.egress?.blockPrivate !== false,
      allow: Array.isArray(raw.egress?.allow) ? raw.egress.allow.map((item) => String(item).trim()).filter(Boolean) : [],
    },
    outer: normalizeOuter(raw.outer),
    socksAuth: {
      user: typeof raw.socksAuth?.user === "string" ? raw.socksAuth.user : "",
      pass: typeof raw.socksAuth?.pass === "string" ? raw.socksAuth.pass : "",
    },
    identity: normalizeIdentity(raw.identity),
    peers: Array.isArray(raw.peers) ? raw.peers.map((item) => normalizePeer(item)).filter((item): item is NetPeer => item !== null) : [],
    exposes: Array.isArray(raw.exposes) ? raw.exposes.map((item) => normalizeExpose(item)) : [],
    reverses: Array.isArray(raw.reverses) ? raw.reverses.map((item) => normalizeReverse(item)) : [],
  };
}

function normalizeProgram(raw: unknown): StoredProgram | null {
  if (!raw || typeof raw !== "object") return null;
  const rec = raw as { saltB64?: unknown; coeffsB64?: unknown };
  if (typeof rec.saltB64 !== "string" || !rec.saltB64) return null;
  if (!Array.isArray(rec.coeffsB64) || rec.coeffsB64.length < 1 || rec.coeffsB64.length > 8) return null;
  if (!rec.coeffsB64.every((item) => typeof item === "string" && item.length > 0)) return null;
  return { saltB64: rec.saltB64, coeffsB64: [...rec.coeffsB64] };
}

function normalizeSeal(raw: unknown): StoredVault | null {
  const vault = vaultFromStored(raw);
  if (!vault) return null;
  const stored = vaultToStored(vault);
  const kdf = clampVaultKdf(stored);
  return { ...stored, memoryKiB: kdf.memoryKiB, iterations: kdf.iterations, parallelism: kdf.parallelism };
}

function withoutScalar(jwk: JsonWebKey): JsonWebKey {
  if (!jwk.d) return jwk;
  const { d: _scalar, ...rest } = jwk;
  return rest;
}

/** Public config. A seal stays in lexis.seal.json, never beside the public key. */
export function exportedConfig(profile: LexisProfile): LexisProfile {
  if (!profile.seal) return profile;
  const identity = profile.identity
    ? { ...profile.identity, privateJwk: withoutScalar(profile.identity.privateJwk) }
    : profile.identity;
  return { ...profile, identity, seal: null };
}

function isOuter(value: unknown): value is OuterTransport {
  return value === "tcp" || value === "tls" || value === "ws" || value === "wss";
}

function normalizeOuter(raw: LexisProfile["outer"] | undefined): LexisProfile["outer"] {
  const base = defaultProfile().outer;
  return {
    transport: isOuter(raw?.transport) ? raw.transport : base.transport,
    wsPath: typeof raw?.wsPath === "string" && raw.wsPath.startsWith("/") ? raw.wsPath : base.wsPath,
    tlsVerify: raw?.tlsVerify !== false,
  };
}

function normalizeIdentity(raw: Partial<NodeIdentity> | null | undefined): NodeIdentity | null {
  if (!raw || typeof raw !== "object") return null;
  if (!raw.publicJwk || !raw.privateJwk || typeof raw.publicRawB64 !== "string" || !raw.publicRawB64) return null;
  return {
    id: raw.id || newId("id"),
    name: raw.name || "本机",
    publicJwk: raw.publicJwk,
    privateJwk: raw.privateJwk,
    publicRawB64: raw.publicRawB64,
    fingerprint: raw.fingerprint || "",
  };
}

function normalizePeer(raw: Partial<NetPeer> | null | undefined): NetPeer | null {
  if (!raw || typeof raw !== "object") return null;
  return {
    id: raw.id || newId("peer"),
    name: raw.name || "节点",
    endpoint: String(raw.endpoint || "").trim(),
    transport: isOuter(raw.transport) ? raw.transport : "tcp",
    publicRawB64: String(raw.publicRawB64 || "").trim(),
    wsPath: typeof raw.wsPath === "string" && raw.wsPath.startsWith("/") ? raw.wsPath : "/lexis",
    wsHost: String(raw.wsHost || "").trim(),
    relay: raw.relay === true,
    exit: raw.exit === true,
    targets: Array.isArray(raw.targets) ? raw.targets.map((item) => String(item).trim()).filter(Boolean) : [],
  };
}

function normalizeExpose(raw: Partial<ExposeService> | null | undefined): ExposeService {
  const row = raw && typeof raw === "object" ? raw : {};
  return {
    id: row.id || newId("expose"),
    name: String(row.name || "").trim() || "服务",
    host: String(row.host || "127.0.0.1").trim(),
    port: clampNum(row.port, 1, 65535, 22),
    allow: Array.isArray(row.allow) ? row.allow.map((item) => String(item).trim()).filter(Boolean) : [],
  };
}

function normalizeReverse(raw: Partial<ReverseDoor> | null | undefined): ReverseDoor {
  const row = raw && typeof raw === "object" ? raw : {};
  return {
    id: row.id || newId("rev"),
    listen: String(row.listen || "127.0.0.1").trim(),
    port: clampNum(row.port, 1, 65535, 2222),
    peer: String(row.peer || "").trim(),
    service: String(row.service || "").trim(),
  };
}

function isAction(value: unknown): value is RuleAction {
  return value === "proxy" || value === "direct" || value === "bypass" || value === "reject";
}

function clampNum(value: unknown, min: number, max: number, fallback: number): number {
  const n = typeof value === "number" ? value : Number(value);
  if (!Number.isInteger(n) || n < min || n > max) return fallback;
  return n;
}

function normalizeInbound(raw: Partial<Inbound>): Inbound {
  const protocol: InboundProtocol =
    raw.protocol === "tcp" || raw.protocol === "tunnel" || raw.protocol === "http" || raw.protocol === "transparent"
      ? raw.protocol
      : "socks";
  return {
    id: raw.id || newId("in"),
    tag: raw.tag || "入站",
    protocol,
    listen: raw.listen || "127.0.0.1",
    port: clampNum(raw.port, 1, 65535, 1080),
    targetHost: raw.targetHost || "",
    targetPort: clampNum(raw.targetPort, 0, 65535, 0),
  };
}

function normalizeProcess(raw: Partial<ProcessRule>): ProcessRule {
  return {
    id: raw.id || newId("proc"),
    name: (raw.name || "").trim(),
    action: isAction(raw.action) ? raw.action : "proxy",
  };
}

function normalizeRule(raw: Partial<RouteRule>): RouteRule {
  const type = RULE_TYPES.includes(raw.type as RuleType) ? (raw.type as RuleType) : "DOMAIN-SUFFIX";
  return {
    id: raw.id || newId("rule"),
    type,
    value: (raw.value || "").trim(),
    action: isAction(raw.action) ? raw.action : "proxy",
  };
}

export type RouteQuery = {
  host?: string;
  ip?: string;
  process?: string;
  port?: string;
  network?: string;
};

export type RouteHit = { rule: RouteRule | null; action: RuleAction; reason: string };

type Lists = { geosite: Record<string, string[]>; geoip: Record<string, string[]> };

export function resourceLists(profile: LexisProfile): Lists {
  const geosite: Record<string, string[]> = {};
  const geoip: Record<string, string[]> = {};
  for (const [tag, list] of Object.entries(GEOSITE)) geosite[tag] = [...list];
  for (const [tag, list] of Object.entries(GEOIP)) geoip[tag] = [...list];
  for (const line of profile.extras.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const [head, ...rest] = trimmed.split(/\s+/);
    const value = rest.join(" ");
    if (!head || !value) continue;
    if (head.startsWith("geoip:")) {
      const tag = head.slice(6).toLowerCase();
      geoip[tag] = [...(geoip[tag] ?? []), value];
    } else {
      const tag = head.toLowerCase();
      geosite[tag] = [...(geosite[tag] ?? []), value.toLowerCase()];
    }
  }
  return { geosite, geoip };
}

export function matchRoute(profile: LexisProfile, query: RouteQuery): RouteHit {
  const lists = resourceLists(profile);
  const host = (query.host || "").toLowerCase().replace(/\.$/, "");
  const ip = query.ip || (isIp(host) ? host : "");
  const processName = (query.process || "").toLowerCase();
  if (processName) {
    const named = profile.processes.find((item) => processHits(processName, item.name));
    if (named) {
      return { rule: null, action: named.action, reason: `程序 ${named.name} → ${actionLabel(named.action)}` };
    }
  }
  for (const rule of profile.rules) {
    if (ruleMatches(rule, { host, ip, processName, port: query.port || "", network: (query.network || "tcp").toLowerCase() }, lists)) {
      return { rule, action: rule.action, reason: `${rule.type} ${rule.value} → ${actionLabel(rule.action)}` };
    }
  }
  return { rule: null, action: profile.processDefault, reason: `没有命中规则，程序默认 ${actionLabel(profile.processDefault)}` };
}

function processHits(actual: string, ruleName: string): boolean {
  const want = ruleName.trim().toLowerCase();
  if (!want) return false;
  const bare = actual.replace(/\.exe$/, "");
  const wantBare = want.replace(/\.exe$/, "");
  return bare === wantBare || bare.includes(wantBare);
}

function ruleMatches(
  rule: RouteRule,
  query: { host: string; ip: string; processName: string; port: string; network: string },
  lists: Lists,
): boolean {
  const value = rule.value.trim().toLowerCase();
  switch (rule.type) {
    case "MATCH":
      return true;
    case "DOMAIN":
      return query.host === value;
    case "DOMAIN-SUFFIX":
      return query.host === value || query.host.endsWith(`.${value}`);
    case "DOMAIN-KEYWORD":
      return value.length > 0 && query.host.includes(value);
    case "IP-CIDR":
      return query.ip !== "" && cidrContains(rule.value.trim(), query.ip);
    case "GEOIP":
      return query.ip !== "" && (lists.geoip[value] ?? []).some((cidr) => cidrContains(cidr, query.ip));
    case "GEOSITE":
      return query.host !== "" && (lists.geosite[value] ?? []).some((domain) => query.host === domain || query.host.endsWith(`.${domain}`));
    case "PROCESS-NAME":
      return query.processName !== "" && processHits(query.processName, rule.value);
    case "PORT":
      return query.port === rule.value.trim();
    case "NETWORK":
      return query.network === value;
    default:
      return false;
  }
}

function isIp(value: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(value);
}

export function cidrContains(cidr: string, ip: string): boolean {
  const [base, bitsRaw] = cidr.split("/");
  if (!isIp(base) || !isIp(ip)) return false;
  const bits = bitsRaw === undefined ? 32 : Number(bitsRaw);
  if (!Number.isInteger(bits) || bits < 0 || bits > 32) return false;
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return (ip4(base) & mask) === (ip4(ip) & mask);
}

function ip4(ip: string): number {
  return ip.split(".").reduce((acc, part) => ((acc << 8) | Number(part)) >>> 0, 0);
}

export function importClashRules(text: string): RouteRule[] {
  const rules: RouteRule[] = [];
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim().replace(/^-\s+/, "");
    if (!trimmed || trimmed.startsWith("#")) continue;
    const parts = trimmed.split(",").map((part) => part.trim());
    if (parts.length < 2) continue;
    const type = parts[0].toUpperCase();
    if (type === "MATCH" && parts.length >= 2 && isRuleType("MATCH")) {
      rules.push({ id: newId("rule"), type: "MATCH", value: "", action: mapAction(parts[1]) });
      continue;
    }
    if (parts.length < 3 || !isRuleType(type)) continue;
    rules.push({ id: newId("rule"), type, value: parts[1], action: mapAction(parts[2]) });
  }
  if (rules.length === 0) throw new Error("没有读到 Clash 规则。每行像这样：DOMAIN-SUFFIX,example.com,PROXY");
  return rules;
}

export function importSingBox(text: string): RouteRule[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error("sing-box 配置不是合法的 JSON");
  }
  const route = (parsed as { route?: { rules?: unknown[] }; rules?: unknown[] }).route;
  const list = route?.rules ?? (parsed as { rules?: unknown[] }).rules;
  if (!Array.isArray(list)) throw new Error("没有找到 route.rules");
  const rules: RouteRule[] = [];
  for (const item of list) {
    if (!item || typeof item !== "object") continue;
    const row = item as Record<string, unknown>;
    const action = mapAction(String(row.outbound ?? row.action ?? "proxy"));
    pushSing(rules, "domain", row.domain, "DOMAIN", action);
    pushSing(rules, "domain_suffix", row.domain_suffix, "DOMAIN-SUFFIX", action);
    pushSing(rules, "domain_keyword", row.domain_keyword, "DOMAIN-KEYWORD", action);
    pushSing(rules, "ip_cidr", row.ip_cidr, "IP-CIDR", action);
    pushSing(rules, "process_name", row.process_name, "PROCESS-NAME", action);
    if (typeof row.geosite === "string") rules.push({ id: newId("rule"), type: "GEOSITE", value: row.geosite, action });
    if (typeof row.geoip === "string") rules.push({ id: newId("rule"), type: "GEOIP", value: row.geoip, action });
    if (typeof row.port === "number") rules.push({ id: newId("rule"), type: "PORT", value: String(row.port), action });
    if (typeof row.network === "string") rules.push({ id: newId("rule"), type: "NETWORK", value: row.network, action });
  }
  if (rules.length === 0) throw new Error("sing-box 规则是空的");
  return rules;
}

function pushSing(rules: RouteRule[], key: string, value: unknown, type: RuleType, action: RuleAction) {
  const list = Array.isArray(value) ? value : typeof value === "string" ? [value] : [];
  for (const item of list) {
    if (typeof item === "string" && item) rules.push({ id: newId("rule"), type, value: item, action });
  }
  void key;
}

function isRuleType(value: string): value is RuleType {
  return RULE_TYPES.includes(value as RuleType);
}

function mapAction(value: string): RuleAction {
  return ACTION_ALIAS[value] ?? ACTION_ALIAS[value.toUpperCase()] ?? "proxy";
}

function frameOf(base: LexisProfile["frame"], raw?: Partial<LexisProfile["frame"]> | null): LexisProfile["frame"] {
  const policy = raw?.smallFramePolicy === "honey" ? "honey" : raw?.smallFramePolicy === "expansion" ? "expansion" : base.smallFramePolicy;
  return {
    maxExpansion: clampNum(raw?.maxExpansion, 1, 16, base.maxExpansion),
    smallFramePolicy: policy,
    coalesceTarget: clampNum(raw?.coalesceTarget, 64, 4096, base.coalesceTarget),
  };
}

/** Same charset heuristic as the resident agent. Not a cryptographic entropy estimate. */
export function estimateTokenBits(token: string): number {
  if (!token) return 0;
  const seen = new Set(token);
  let alphabet = 0;
  if (/[a-z]/.test(token)) alphabet += 26;
  if (/[A-Z]/.test(token)) alphabet += 26;
  if (/[0-9]/.test(token)) alphabet += 10;
  if (/[^a-zA-Z0-9]/.test(token)) alphabet += 20;
  if (alphabet < 10) alphabet = Math.max(seen.size, 2);
  return Math.floor(token.length * Math.log2(alphabet));
}

/** 16 random bytes, base64url. Matches `lexis-agent --gen-token`. */
export function mintHandshakeToken(): string {
  const raw = crypto.getRandomValues(new Uint8Array(16));
  let s = "";
  for (const b of raw) s += String.fromCharCode(b);
  return btoa(s).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/g, "");
}

export function profileIssues(profile: LexisProfile): string[] {
  const issues: string[] = [];
  if (profile.role !== "edge" && profile.role !== "gate") {
    issues.push("常驻进程不接受缺省角色。写成 edge 或 gate");
  }
  if (profile.link.maxConns < profile.link.maxHalfOpen) {
    issues.push(
      `连接上限 ${profile.link.maxConns} 小于半开上限 ${profile.link.maxHalfOpen}。半开中的连接也占连接上限，实际半开会被截住。建议连接上限至少比半开上限大出平时的会话数`,
    );
  }
  const statusHost = profile.statusHost.trim().toLowerCase();
  const statusLoopback = statusHost === "127.0.0.1" || statusHost === "::1" || statusHost === "localhost";
  if (!statusLoopback && !profile.statusToken.trim()) {
    issues.push("状态页不在回环上，要填状态口令，否则指标和页面会拒绝");
  }
  const seen = new Set<string>();
  for (const inbound of profile.inbounds) {
    const key = `${inbound.listen}:${inbound.port}`;
    if (seen.has(key)) issues.push(`入站端口重复：${key}`);
    seen.add(key);
    if (inbound.protocol === "tcp" && (!inbound.targetHost || inbound.targetPort < 1)) {
      issues.push(`${inbound.tag} 是固定转发，但目标主机或端口是空的`);
    }
  }
  if (profile.mode === "fixed-port" && profile.inbounds.length === 0) issues.push("固定端口模式至少要有一个入站");
  for (const proc of profile.processes) {
    if (!proc.name.trim()) issues.push("有一条程序规则没有名字");
  }
  if (profile.peerEndpoint && !/^.+:\d+$/.test(profile.peerEndpoint)) {
    issues.push("对端地址要写成 主机:端口");
  }
  const joined =
    profile.peers.length > 0 ||
    profile.inbounds.some((item) => item.protocol === "tunnel") ||
    profile.reverses.length > 0 ||
    profile.exposes.length > 0;
  if ((joined || profile.role === "gate" || profile.peerEndpoint) && !profile.identity) {
    issues.push("常驻转发要有本机身份。在节点页把一把密钥写成常驻身份");
  }
  if (joined && estimateTokenBits(profile.link.token.trim()) < 128) {
    issues.push("常驻握手口令熵不足（需要至少 128 bit）。用「生成 128 bit 口令」，两端写成同一个。不要用手写短口令");
  }
  if (!profile.outer.tlsVerify) issues.push("没有校验证书。正式部署请换成自己的证书并打开校验");
  if (profile.inbounds.some((item) => item.protocol === "tunnel") && profile.peers.length === 0) {
    issues.push("隧道入口还没有对端公钥，握不上手");
  }
  for (const peer of profile.peers) {
    if (!/^.+:\d+$/.test(peer.endpoint)) issues.push(`${peer.name} 的地址要写成 主机:端口`);
    if (peer.publicRawB64.length < 16) issues.push(`${peer.name} 缺少公钥，不能加入词表握手`);
  }
  if (profile.inbounds.some((item) => item.protocol === "tunnel") && profile.peers.length > 0 && !profile.peers.some((peer) => peer.exit)) {
    issues.push("隧道入口还没有节点被允许把本机当出口");
  }
  for (const door of profile.exposes) {
    if (!door.allow.length) issues.push(`${door.name} 没有写允许访问的节点`);
  }
  for (const door of profile.reverses) {
    if (!door.peer || !door.service) issues.push("反向入口要写节点和服务名");
    const host = door.listen || "127.0.0.1";
    if (!profile.link.allowLan && host !== "127.0.0.1" && host !== "::1") {
      issues.push("反向入口写了非回环地址。没有允许局域网时会改绑回环，避免把后面的服务公开");
    }
  }
  if ((profile.socksAuth.user && !profile.socksAuth.pass) || (!profile.socksAuth.user && profile.socksAuth.pass)) {
    issues.push("SOCKS 用户名和密码要一起填，或都留空");
  }
  return issues;
}

export function gatePreset(): Pick<LexisProfile, "role" | "inbounds"> {
  return {
    role: "gate",
    inbounds: [
      {
        id: "in-tunnel",
        tag: "词隙入口",
        protocol: "tunnel",
        listen: "0.0.0.0",
        port: 18443,
        targetHost: "",
        targetPort: 0,
      },
    ],
  };
}

export function edgePreset(): Pick<LexisProfile, "role" | "inbounds"> {
  return {
    role: "edge",
    inbounds: defaultProfile().inbounds,
  };
}
