import { i as __toESM } from "../_runtime.mjs";
import { q as require_react, x as require_jsx_runtime, y as Link } from "../_libs/@tanstack/react-router+[...].mjs";
import { a as Radio, c as ArrowRight, n as Trash2, s as Download } from "../_libs/lucide-react.mjs";
import { n as persist, r as create, t as createJSONStorage } from "../_libs/zustand.mjs";
import { a as Cell, i as Bar, n as YAxis, o as ResponsiveContainer, r as XAxis, s as Tooltip, t as BarChart } from "../_libs/recharts+[...].mjs";
//#region node_modules/.nitro/vite/services/ssr/assets/routes-B8ZDsch2.js
var import_react = /* @__PURE__ */ __toESM(require_react());
var import_jsx_runtime = require_jsx_runtime();
function concat(...parts) {
	let n = 0;
	for (const p of parts) n += p.length;
	const out = new Uint8Array(n);
	let o = 0;
	for (const p of parts) {
		out.set(p, o);
		o += p.length;
	}
	return out;
}
function utf8(s) {
	return new TextEncoder().encode(s);
}
function fromUtf8(b) {
	return new TextDecoder("utf-8", { fatal: false }).decode(b);
}
function u16be(n) {
	return new Uint8Array([n >> 8 & 255, n & 255]);
}
function u32be(n) {
	return new Uint8Array([
		n >>> 24 & 255,
		n >>> 16 & 255,
		n >>> 8 & 255,
		n & 255
	]);
}
function readU16(b, o) {
	return (b[o] << 8 | b[o + 1]) >>> 0;
}
function readU32(b, o) {
	return (b[o] << 24 | b[o + 1] << 16 | b[o + 2] << 8 | b[o + 3]) >>> 0;
}
function hex(b, max) {
	const v = max === void 0 ? b : b.subarray(0, max);
	let s = "";
	for (let i = 0; i < v.length; i++) s += v[i].toString(16).padStart(2, "0");
	return s;
}
function b64(b) {
	let s = "";
	for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
	return btoa(s);
}
function unb64(s) {
	const bin = atob(s);
	const out = new Uint8Array(bin.length);
	for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
	return out;
}
function randomBytes(n) {
	const b = new Uint8Array(n);
	crypto.getRandomValues(b);
	return b;
}
function timingSafeEqual(a, b) {
	if (a.length !== b.length) return false;
	let d = 0;
	for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
	return d === 0;
}
function isPrintableText(b) {
	for (let i = 0; i < b.length; i++) {
		const c = b[i];
		if (c !== 9 && c !== 10 && c !== 13 && (c < 32 || c > 126)) return false;
	}
	return true;
}
/** 12-bit big-endian groups. A short tail is padded with zero bits. */
function bytesToChunks(data) {
	const out = [];
	let acc = 0;
	let bits = 0;
	for (let i = 0; i < data.length; i++) {
		acc = acc << 8 | data[i];
		bits += 8;
		while (bits >= 12) {
			bits -= 12;
			out.push(acc >> bits & 4095);
			acc &= (1 << bits) - 1;
		}
	}
	if (bits > 0) out.push(acc << 12 - bits & 4095);
	return out;
}
/** Inverse of bytesToChunks. Trailing partial-byte padding is left for the caller to trim. */
function chunksToBytes(chunks) {
	const tmp = [];
	let acc = 0;
	let bits = 0;
	for (let i = 0; i < chunks.length; i++) {
		acc = acc << 12 | chunks[i] & 4095;
		bits += 12;
		while (bits >= 8) {
			bits -= 8;
			tmp.push(acc >> bits & 255);
			acc &= (1 << bits) - 1;
		}
	}
	return new Uint8Array(tmp);
}
var ECDH = {
	name: "ECDH",
	namedCurve: "P-256"
};
var HKDF_CAP = 8e3;
function buf(data) {
	const out = new ArrayBuffer(data.byteLength);
	new Uint8Array(out).set(data);
	return out;
}
function asBytes(data) {
	const view = new Uint8Array(data);
	const out = new Uint8Array(view.length);
	out.set(view);
	return out;
}
var LexisError = class extends Error {
	constructor(message) {
		super(message);
		this.name = "LexisError";
	}
};
async function sha256(data) {
	return asBytes(await crypto.subtle.digest("SHA-256", buf(data)));
}
async function fingerprintOf(raw) {
	const h = hex((await sha256(raw)).subarray(0, 8));
	return (h.match(/.{1,4}/g) ?? [h]).join("-");
}
async function createIdentity() {
	const pair = await crypto.subtle.generateKey(ECDH, true, ["deriveBits"]);
	const publicJwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
	const privateJwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
	const publicRaw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
	return {
		publicJwk,
		privateJwk,
		publicRaw,
		fingerprint: await fingerprintOf(publicRaw)
	};
}
async function importPrivateJwk(jwk) {
	return crypto.subtle.importKey("jwk", jwk, ECDH, true, ["deriveBits"]);
}
async function importRawPublic(raw) {
	return crypto.subtle.importKey("raw", buf(raw), ECDH, true, []);
}
async function ecdh(priv, pub) {
	return asBytes(await crypto.subtle.deriveBits({
		name: "ECDH",
		public: pub
	}, priv, 256));
}
async function hkdf(ikm, salt, info, bytes) {
	const base = await crypto.subtle.importKey("raw", buf(ikm), "HKDF", false, ["deriveBits"]);
	return asBytes(await crypto.subtle.deriveBits({
		name: "HKDF",
		hash: "SHA-256",
		salt: buf(salt),
		info: buf(info)
	}, base, bytes * 8));
}
/** HKDF-Expand past the 255-block cap by splitting on an info counter. */
async function hkdfStream(ikm, salt, infoLabel, nbytes) {
	const parts = [];
	let left = nbytes;
	let i = 0;
	while (left > 0) {
		const n = Math.min(HKDF_CAP, left);
		parts.push(await hkdf(ikm, salt, concat(utf8(infoLabel), u32be(i)), n));
		left -= n;
		i += 1;
	}
	return concat(...parts);
}
async function hmac(key, data) {
	const k = await crypto.subtle.importKey("raw", buf(key), {
		name: "HMAC",
		hash: "SHA-256"
	}, false, ["sign"]);
	return asBytes(await crypto.subtle.sign("HMAC", k, buf(data)));
}
function assertPoint(raw, label) {
	if (raw.length !== 65 || raw[0] !== 4) throw new LexisError(`${label}公钥不是 P-256 未压缩点`);
}
async function identityFromJwks(publicJwk, privateJwk) {
	if (publicJwk.kty !== "EC" || publicJwk.crv !== "P-256") throw new LexisError("侧车里的公钥不是 P-256");
	if (privateJwk.x && publicJwk.x && privateJwk.x !== publicJwk.x) throw new LexisError("侧车里的私钥和公钥不是一对");
	const pub = await crypto.subtle.importKey("jwk", publicJwk, ECDH, true, []);
	await importPrivateJwk(privateJwk);
	const publicRaw = new Uint8Array(await crypto.subtle.exportKey("raw", pub));
	return {
		publicJwk,
		privateJwk,
		publicRaw,
		fingerprint: await fingerprintOf(publicRaw)
	};
}
/** LEXIS codebook-CTR v1. Wire image is prose; secrecy is the session key. */
var SPEC = {
	name: "lexis-codebook-ctr-v1",
	curve: "P-256",
	kdf: "HKDF-SHA-256",
	mac: "HMAC-SHA-256",
	macBytes: 16,
	lexiconSize: 4096,
	bitsPerWord: 12,
	windowSec: 300,
	counterBits: 24
};
var GLUE_SET = /* @__PURE__ */ new Set([
	"the",
	"our",
	"its",
	"that",
	"and"
]);
var LEADS = [
	"the",
	"our",
	"its",
	"that"
];
var useMesh = create()(persist((set) => ({
	nodes: [],
	mappings: [],
	addNode: (node) => set((s) => ({ nodes: [...s.nodes, node] })),
	updateNode: (id, patch) => set((s) => ({ nodes: s.nodes.map((n) => n.id === id ? {
		...n,
		...patch
	} : n) })),
	removeNode: (id) => set((s) => ({
		nodes: s.nodes.filter((n) => n.id !== id).map((n) => n.pinnedPeerId === id ? {
			...n,
			pinnedPeerId: null
		} : n),
		mappings: s.mappings.filter((m) => m.gateId !== id)
	})),
	bindPair: (a, b) => set((s) => ({ nodes: s.nodes.map((n) => {
		if (n.id === a) return {
			...n,
			pinnedPeerId: b
		};
		if (n.id === b) return {
			...n,
			pinnedPeerId: a
		};
		return n;
	}) })),
	addMapping: (mapping) => set((s) => ({ mappings: [...s.mappings, mapping] })),
	updateMapping: (id, patch) => set((s) => ({ mappings: s.mappings.map((m) => m.id === id ? {
		...m,
		...patch
	} : m) })),
	removeMapping: (id) => set((s) => ({ mappings: s.mappings.filter((m) => m.id !== id) })),
	seed: (nodes, mappings) => set({
		nodes,
		mappings
	}),
	reset: () => set({
		nodes: [],
		mappings: []
	})
}), {
	name: "lexis-mesh-v1",
	storage: createJSONStorage(() => localStorage),
	skipHydration: true,
	version: 1
}));
async function makeNode(name, role) {
	const key = await createIdentity();
	return {
		id: crypto.randomUUID(),
		name,
		role,
		publicJwk: key.publicJwk,
		privateJwk: key.privateJwk,
		publicRawB64: b64(key.publicRaw),
		fingerprint: key.fingerprint,
		pinnedPeerId: null,
		createdAt: Date.now()
	};
}
var seeding = false;
async function ensureSeed() {
	if (useMesh.getState().nodes.length > 0) return;
	if (seeding) return;
	seeding = true;
	try {
		if (useMesh.getState().nodes.length > 0) return;
		const gate = await makeNode("港区闸门", "gate");
		const edge = await makeNode("内网工作室", "edge");
		gate.pinnedPeerId = edge.id;
		edge.pinnedPeerId = gate.id;
		const mappings = [{
			id: crypto.randomUUID(),
			gateId: gate.id,
			proto: "tcp",
			listenPort: 18443,
			targetHost: "127.0.0.1",
			targetPort: 8080,
			priority: 10,
			enabled: true,
			note: "工作室控制台"
		}, {
			id: crypto.randomUUID(),
			gateId: gate.id,
			proto: "udp",
			listenPort: 51820,
			targetHost: "10.0.0.8",
			targetPort: 51820,
			priority: 5,
			enabled: true,
			note: "内网报文"
		}];
		if (useMesh.getState().nodes.length === 0) useMesh.getState().seed([gate, edge], mappings);
	} finally {
		seeding = false;
	}
}
function sidecarOf(node, peer) {
	return {
		cipher: SPEC.name,
		role: node.role,
		name: node.name,
		fingerprint: node.fingerprint,
		publicJwk: node.publicJwk,
		privateJwk: node.privateJwk,
		pinnedPeerFingerprint: peer?.fingerprint ?? null,
		pinnedPeerPublicJwk: peer?.publicJwk ?? null,
		windowSeconds: SPEC.windowSec,
		lexiconSize: SPEC.lexiconSize,
		handshake: "p256-ecdh-ephemeral-plus-static",
		wire: "secret-lexicon-prose"
	};
}
function downloadJson(filename, data) {
	const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
	const url = URL.createObjectURL(blob);
	const a = document.createElement("a");
	a.href = url;
	a.download = filename;
	a.click();
	URL.revokeObjectURL(url);
}
var RULE_TYPES = [
	"DOMAIN",
	"DOMAIN-SUFFIX",
	"DOMAIN-KEYWORD",
	"IP-CIDR",
	"GEOIP",
	"GEOSITE",
	"PROCESS-NAME",
	"PORT",
	"NETWORK",
	"MATCH"
];
var ACTIONS = [
	"proxy",
	"direct",
	"bypass",
	"reject"
];
var GEOSITE = {
	private: [
		"localhost",
		"local",
		"localdomain",
		"invalid"
	],
	cn: [
		"cn",
		"baidu.com",
		"qq.com",
		"taobao.com",
		"aliyun.com",
		"bilibili.com",
		"jd.com"
	],
	google: [
		"google.com",
		"gstatic.com",
		"googleapis.com",
		"youtube.com",
		"gmail.com"
	],
	telegram: [
		"telegram.org",
		"t.me",
		"telegra.ph"
	]
};
var GEOIP = {
	private: [
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16"
	],
	cn: [
		"114.114.114.114/32",
		"223.5.5.5/32",
		"119.29.29.29/32",
		"180.76.76.76/32"
	]
};
var ACTION_ALIAS = {
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
	拒绝: "reject"
};
function defaultProfile() {
	return {
		version: 1,
		name: "词隙",
		role: "edge",
		mode: "fixed-port",
		logLevel: "info",
		peerEndpoint: "",
		inbounds: [{
			id: "in-socks",
			tag: "本地 SOCKS",
			protocol: "socks",
			listen: "127.0.0.1",
			port: 1080,
			targetHost: "",
			targetPort: 0
		}],
		processDefault: "proxy",
		processes: [{
			id: "proc-browser",
			name: "chrome",
			action: "proxy"
		}, {
			id: "proc-ssh",
			name: "ssh",
			action: "bypass"
		}],
		rules: [
			{
				id: "r-private-site",
				type: "GEOSITE",
				value: "private",
				action: "direct"
			},
			{
				id: "r-private-ip",
				type: "GEOIP",
				value: "private",
				action: "direct"
			},
			{
				id: "r-cn-site",
				type: "GEOSITE",
				value: "cn",
				action: "direct"
			},
			{
				id: "r-cn-ip",
				type: "GEOIP",
				value: "cn",
				action: "direct"
			},
			{
				id: "r-ssh",
				type: "PROCESS-NAME",
				value: "ssh",
				action: "bypass"
			},
			{
				id: "r-match",
				type: "MATCH",
				value: "",
				action: "proxy"
			}
		],
		extras: "",
		geositeUrl: "",
		geoipUrl: "",
		statusHost: "127.0.0.1",
		statusPort: 17890,
		heartbeatSec: 15,
		linux: {
			method: "redirect",
			mark: 255,
			table: 100,
			dnsRedirect: true
		},
		windows: {
			method: "portproxy",
			gateway: "10.7.0.1"
		},
		android: {
			method: "vpn",
			mtu: 1500,
			address: "10.7.0.2/32",
			dns: "1.1.1.1"
		}
	};
}
function actionLabel(action) {
	switch (action) {
		case "proxy": return "接入";
		case "direct": return "直连";
		case "bypass": return "绕行";
		case "reject": return "拒绝";
	}
}
function newId(prefix) {
	return `${prefix}-${Math.random().toString(36).slice(2, 8)}`;
}
function normalizeProfile(input) {
	const base = defaultProfile();
	if (!input || typeof input !== "object") return base;
	const raw = input;
	return {
		...base,
		...raw,
		version: 1,
		role: raw.role === "gate" ? "gate" : "edge",
		mode: raw.mode === "system-forward" ? "system-forward" : "fixed-port",
		logLevel: raw.logLevel === "debug" ? "debug" : "info",
		processDefault: isAction(raw.processDefault) ? raw.processDefault : base.processDefault,
		inbounds: Array.isArray(raw.inbounds) ? raw.inbounds.map(normalizeInbound) : base.inbounds,
		processes: Array.isArray(raw.processes) ? raw.processes.map(normalizeProcess) : base.processes,
		rules: Array.isArray(raw.rules) ? raw.rules.map(normalizeRule) : base.rules,
		linux: {
			...base.linux,
			...raw.linux ?? {}
		},
		windows: {
			...base.windows,
			...raw.windows ?? {}
		},
		android: {
			...base.android,
			...raw.android ?? {}
		},
		heartbeatSec: clampNum(raw.heartbeatSec, 5, 120, base.heartbeatSec),
		statusPort: clampNum(raw.statusPort, 1, 65535, base.statusPort)
	};
}
function isAction(value) {
	return value === "proxy" || value === "direct" || value === "bypass" || value === "reject";
}
function clampNum(value, min, max, fallback) {
	const n = typeof value === "number" ? value : Number(value);
	if (!Number.isInteger(n) || n < min || n > max) return fallback;
	return n;
}
function normalizeInbound(raw) {
	const protocol = raw.protocol === "tcp" || raw.protocol === "tunnel" ? raw.protocol : "socks";
	return {
		id: raw.id || newId("in"),
		tag: raw.tag || "入站",
		protocol,
		listen: raw.listen || "127.0.0.1",
		port: clampNum(raw.port, 1, 65535, 1080),
		targetHost: raw.targetHost || "",
		targetPort: clampNum(raw.targetPort, 0, 65535, 0)
	};
}
function normalizeProcess(raw) {
	return {
		id: raw.id || newId("proc"),
		name: (raw.name || "").trim(),
		action: isAction(raw.action) ? raw.action : "proxy"
	};
}
function normalizeRule(raw) {
	const type = RULE_TYPES.includes(raw.type) ? raw.type : "DOMAIN-SUFFIX";
	return {
		id: raw.id || newId("rule"),
		type,
		value: (raw.value || "").trim(),
		action: isAction(raw.action) ? raw.action : "proxy"
	};
}
function resourceLists(profile) {
	const geosite = {};
	const geoip = {};
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
			geoip[tag] = [...geoip[tag] ?? [], value];
		} else {
			const tag = head.toLowerCase();
			geosite[tag] = [...geosite[tag] ?? [], value.toLowerCase()];
		}
	}
	return {
		geosite,
		geoip
	};
}
function matchRoute(profile, query) {
	const lists = resourceLists(profile);
	const host = (query.host || "").toLowerCase().replace(/\.$/, "");
	const ip = query.ip || (isIp(host) ? host : "");
	const processName = (query.process || "").toLowerCase();
	if (processName) {
		const named = profile.processes.find((item) => processHits(processName, item.name));
		if (named) return {
			rule: null,
			action: named.action,
			reason: `程序 ${named.name} → ${actionLabel(named.action)}`
		};
	}
	for (const rule of profile.rules) if (ruleMatches(rule, {
		host,
		ip,
		processName,
		port: query.port || "",
		network: (query.network || "tcp").toLowerCase()
	}, lists)) return {
		rule,
		action: rule.action,
		reason: `${rule.type} ${rule.value} → ${actionLabel(rule.action)}`
	};
	return {
		rule: null,
		action: profile.processDefault,
		reason: `没有命中规则，程序默认 ${actionLabel(profile.processDefault)}`
	};
}
function processHits(actual, ruleName) {
	const want = ruleName.trim().toLowerCase();
	if (!want) return false;
	const bare = actual.replace(/\.exe$/, "");
	const wantBare = want.replace(/\.exe$/, "");
	return bare === wantBare || bare.includes(wantBare);
}
function ruleMatches(rule, query, lists) {
	const value = rule.value.trim().toLowerCase();
	switch (rule.type) {
		case "MATCH": return true;
		case "DOMAIN": return query.host === value;
		case "DOMAIN-SUFFIX": return query.host === value || query.host.endsWith(`.${value}`);
		case "DOMAIN-KEYWORD": return value.length > 0 && query.host.includes(value);
		case "IP-CIDR": return query.ip !== "" && cidrContains(rule.value.trim(), query.ip);
		case "GEOIP": return query.ip !== "" && (lists.geoip[value] ?? []).some((cidr) => cidrContains(cidr, query.ip));
		case "GEOSITE": return query.host !== "" && (lists.geosite[value] ?? []).some((domain) => query.host === domain || query.host.endsWith(`.${domain}`));
		case "PROCESS-NAME": return query.processName !== "" && processHits(query.processName, rule.value);
		case "PORT": return query.port === rule.value.trim();
		case "NETWORK": return query.network === value;
		default: return false;
	}
}
function isIp(value) {
	return /^\d{1,3}(\.\d{1,3}){3}$/.test(value);
}
function cidrContains(cidr, ip) {
	const [base, bitsRaw] = cidr.split("/");
	if (!isIp(base) || !isIp(ip)) return false;
	const bits = bitsRaw === void 0 ? 32 : Number(bitsRaw);
	if (!Number.isInteger(bits) || bits < 0 || bits > 32) return false;
	const mask = bits === 0 ? 0 : -1 << 32 - bits >>> 0;
	return (ip4(base) & mask) === (ip4(ip) & mask);
}
function ip4(ip) {
	return ip.split(".").reduce((acc, part) => (acc << 8 | Number(part)) >>> 0, 0);
}
function importClashRules(text) {
	const rules = [];
	for (const line of text.split(/\r?\n/)) {
		const trimmed = line.trim().replace(/^-\s+/, "");
		if (!trimmed || trimmed.startsWith("#")) continue;
		const parts = trimmed.split(",").map((part) => part.trim());
		if (parts.length < 2) continue;
		const type = parts[0].toUpperCase();
		if (type === "MATCH" && parts.length >= 2 && isRuleType("MATCH")) {
			rules.push({
				id: newId("rule"),
				type: "MATCH",
				value: "",
				action: mapAction(parts[1])
			});
			continue;
		}
		if (parts.length < 3 || !isRuleType(type)) continue;
		rules.push({
			id: newId("rule"),
			type,
			value: parts[1],
			action: mapAction(parts[2])
		});
	}
	if (rules.length === 0) throw new Error("没有读到 Clash 规则。每行像这样：DOMAIN-SUFFIX,example.com,PROXY");
	return rules;
}
function importSingBox(text) {
	let parsed;
	try {
		parsed = JSON.parse(text);
	} catch {
		throw new Error("sing-box 配置不是合法的 JSON");
	}
	const list = parsed.route?.rules ?? parsed.rules;
	if (!Array.isArray(list)) throw new Error("没有找到 route.rules");
	const rules = [];
	for (const item of list) {
		if (!item || typeof item !== "object") continue;
		const row = item;
		const action = mapAction(String(row.outbound ?? row.action ?? "proxy"));
		pushSing(rules, "domain", row.domain, "DOMAIN", action);
		pushSing(rules, "domain_suffix", row.domain_suffix, "DOMAIN-SUFFIX", action);
		pushSing(rules, "domain_keyword", row.domain_keyword, "DOMAIN-KEYWORD", action);
		pushSing(rules, "ip_cidr", row.ip_cidr, "IP-CIDR", action);
		pushSing(rules, "process_name", row.process_name, "PROCESS-NAME", action);
		if (typeof row.geosite === "string") rules.push({
			id: newId("rule"),
			type: "GEOSITE",
			value: row.geosite,
			action
		});
		if (typeof row.geoip === "string") rules.push({
			id: newId("rule"),
			type: "GEOIP",
			value: row.geoip,
			action
		});
		if (typeof row.port === "number") rules.push({
			id: newId("rule"),
			type: "PORT",
			value: String(row.port),
			action
		});
		if (typeof row.network === "string") rules.push({
			id: newId("rule"),
			type: "NETWORK",
			value: row.network,
			action
		});
	}
	if (rules.length === 0) throw new Error("sing-box 规则是空的");
	return rules;
}
function pushSing(rules, key, value, type, action) {
	const list = Array.isArray(value) ? value : typeof value === "string" ? [value] : [];
	for (const item of list) if (typeof item === "string" && item) rules.push({
		id: newId("rule"),
		type,
		value: item,
		action
	});
}
function isRuleType(value) {
	return RULE_TYPES.includes(value);
}
function mapAction(value) {
	return ACTION_ALIAS[value] ?? ACTION_ALIAS[value.toUpperCase()] ?? "proxy";
}
function profileIssues(profile) {
	const issues = [];
	const seen = /* @__PURE__ */ new Set();
	for (const inbound of profile.inbounds) {
		const key = `${inbound.listen}:${inbound.port}`;
		if (seen.has(key)) issues.push(`入站端口重复：${key}`);
		seen.add(key);
		if (inbound.protocol === "tcp" && (!inbound.targetHost || inbound.targetPort < 1)) issues.push(`${inbound.tag} 是固定转发，但目标主机或端口是空的`);
	}
	if (profile.mode === "fixed-port" && profile.inbounds.length === 0) issues.push("固定端口模式至少要有一个入站");
	for (const proc of profile.processes) if (!proc.name.trim()) issues.push("有一条程序规则没有名字");
	if (profile.peerEndpoint && !/^.+:\d+$/.test(profile.peerEndpoint)) issues.push("对端地址要写成 主机:端口");
	return issues;
}
function gatePreset() {
	return {
		role: "gate",
		inbounds: [{
			id: "in-tunnel",
			tag: "词隙入口",
			protocol: "tunnel",
			listen: "0.0.0.0",
			port: 18443,
			targetHost: "",
			targetPort: 0
		}]
	};
}
function edgePreset() {
	return {
		role: "edge",
		inbounds: defaultProfile().inbounds
	};
}
var useProfile = create()(persist((set) => ({
	profile: defaultProfile(),
	setProfile: (profile) => set({ profile: normalizeProfile(profile) }),
	patch: (partial) => set((state) => ({ profile: normalizeProfile({
		...state.profile,
		...partial
	}) }))
}), {
	name: "lexis-profile-v1",
	storage: createJSONStorage(() => localStorage),
	skipHydration: true,
	version: 1,
	merge: (persisted, current) => {
		const saved = persisted;
		return {
			...current,
			profile: normalizeProfile(saved?.profile ?? current.profile)
		};
	}
}));
/**
* Pronounceable triples. Empty onset/coda are omitted so every word is at least 3 letters
* and the letter distribution stays inside a small alphabet (low byte entropy on the wire).
*/
var ONSETS = [
	"b",
	"c",
	"d",
	"f",
	"g",
	"h",
	"j",
	"k",
	"l",
	"m",
	"n",
	"p",
	"r",
	"s",
	"t",
	"v",
	"w",
	"z",
	"bl",
	"br",
	"ch",
	"cl",
	"cr",
	"dr",
	"fl",
	"fr",
	"gl",
	"gr",
	"pl",
	"pr",
	"sc",
	"sh",
	"sk",
	"sl",
	"sm",
	"sn",
	"sp",
	"st",
	"sw",
	"th",
	"tr",
	"tw",
	"wh",
	"qu"
];
var NUCLEI = [
	"a",
	"e",
	"i",
	"o",
	"u",
	"ae",
	"ai",
	"au",
	"ea",
	"ee",
	"ia",
	"ie",
	"io",
	"oa",
	"oe",
	"oo",
	"ou"
];
var CODAS = [
	"d",
	"k",
	"l",
	"m",
	"n",
	"p",
	"r",
	"s",
	"t",
	"x",
	"ld",
	"ll",
	"nd",
	"nt",
	"rd",
	"rn",
	"sh",
	"st",
	"th"
];
var SPACE = ONSETS.length * NUCLEI.length * CODAS.length;
function wordFromIndex(n) {
	const coda = n % CODAS.length;
	const nucleus = Math.floor(n / CODAS.length) % NUCLEI.length;
	return ONSETS[Math.floor(n / (CODAS.length * NUCLEI.length))] + NUCLEI[nucleus] + CODAS[coda];
}
async function buildLexicon(seed) {
	if (SPACE < SPEC.lexiconSize || SPACE >= 65536) throw new Error("音节空间尺寸不对");
	const used = new Uint8Array(SPACE);
	const seen = /* @__PURE__ */ new Set();
	const words = [];
	const limit = Math.floor(65536 / SPACE) * SPACE;
	let round = 0;
	let pool = /* @__PURE__ */ new Uint8Array(0);
	let pos = 0;
	const pull = async () => {
		pool = await hkdfStream(seed, utf8(`LEXIS-LEX-STREAM-${round}`), "idx", 16e3);
		round += 1;
		pos = 0;
	};
	const next16 = async () => {
		if (pos + 2 > pool.length) await pull();
		const v = pool[pos] << 8 | pool[pos + 1];
		pos += 2;
		return v;
	};
	let guard = 0;
	while (words.length < SPEC.lexiconSize) {
		if (guard++ > SPACE * 4) throw new Error("词表生成失败");
		let draw = await next16();
		while (draw >= limit) draw = await next16();
		const n = draw % SPACE;
		if (used[n]) continue;
		used[n] = 1;
		const w = wordFromIndex(n);
		if (w.length < 3 || GLUE_SET.has(w) || seen.has(w)) continue;
		seen.add(w);
		words.push(w);
	}
	return words;
}
var staticCache = null;
/** Public codebook used only before a session key exists. Not a secret. */
function staticLexicon() {
	if (!staticCache) staticCache = (async () => {
		return buildLexicon(await sha256(utf8("LEXIS-STATIC-ALPHABET-v1")));
	})();
	return staticCache;
}
/** Secret codebook: HKDF(sessionKey, window) then the same generator both ends run. */
async function sessionLexicon(sessionKey, window) {
	return buildLexicon(await hkdfStream(sessionKey, utf8("LEXIS-LEX-SALT"), `win-${window}`, 32));
}
function invertLexicon(words) {
	const map = /* @__PURE__ */ new Map();
	for (let i = 0; i < words.length; i++) {
		const w = words[i];
		if (map.has(w)) throw new Error(`词表有重复词 ${w}`);
		map.set(w, i);
	}
	if (map.size !== SPEC.lexiconSize) throw new Error("词表长度不对");
	return map;
}
function dress(words, counter) {
	const parts = [];
	for (let i = 0; i < words.length; i += 4) {
		const group = words.slice(i, i + 4);
		const head = i === 0 ? LEADS[counter & 3] : "and";
		parts.push(`${head} ${group.join(" ")}.`);
	}
	return parts.join(" ");
}
function undress(prose) {
	return prose.trim().toLowerCase().replace(/[.]/g, " ").split(/\s+/).filter((w) => w.length > 0 && !GLUE_SET.has(w));
}
async function encodeStatic(data) {
	const lex = await staticLexicon();
	return dress(bytesToChunks(concat(u16be(data.length), data)).map((c) => {
		if (c < 0 || c >= SPEC.lexiconSize) throw new Error("静态编码越界");
		return lex[c];
	}), 0);
}
async function decodeStatic(prose) {
	const lex = await staticLexicon();
	const inverse = /* @__PURE__ */ new Map();
	for (let i = 0; i < lex.length; i++) inverse.set(lex[i], i);
	const chunks = [];
	for (const w of undress(prose)) {
		const idx = inverse.get(w);
		if (idx === void 0) throw new Error(`握手词不在静态词表里：${w}`);
		chunks.push(idx);
	}
	const raw = chunksToBytes(chunks);
	if (raw.length < 2) throw new Error("握手报文过短");
	const len = readU16(raw, 0);
	if (raw.length < 2 + len) throw new Error("握手报文被截断");
	return raw.slice(2, 2 + len);
}
function currentWindow(now = Date.now()) {
	return Math.floor(now / 1e3 / SPEC.windowSec);
}
function windowRemain(now = Date.now()) {
	const sec = Math.floor(now / 1e3);
	return SPEC.windowSec - sec % SPEC.windowSec;
}
function transcript(parts) {
	return concat(utf8("LEXIS1"), parts.ephC, parts.ephS, parts.ltC, parts.ltS, u32be(parts.window), parts.nonceC, parts.nonceS);
}
async function deriveSk(ssE, ssS, nonceC, nonceS, window) {
	return hkdf(concat(ssE, ssS), concat(nonceC, nonceS, u32be(window)), utf8("LEXIS-SK-v1"), 32);
}
async function edgeStart(edge, now = Date.now()) {
	const eph = await createIdentity();
	const ltRaw = unb64(edge.publicRawB64);
	assertPoint(ltRaw, "内网端");
	assertPoint(eph.publicRaw, "内网端临时");
	const nonceC = crypto.getRandomValues(/* @__PURE__ */ new Uint8Array(16));
	const window = currentWindow(now);
	return {
		eph,
		nonceC,
		window,
		helloWire: await encodeStatic(concat(new Uint8Array([1, 1]), eph.publicRaw, ltRaw, u32be(window), nonceC)),
		ltRaw
	};
}
function parseHello(buf) {
	if (buf.length !== 152) throw new LexisError("客户端问候长度不对");
	if (buf[0] !== 1 || buf[1] !== 1) throw new LexisError("客户端问候版本不对");
	const ephRaw = buf.slice(2, 67);
	const ltRaw = buf.slice(67, 132);
	const window = buf[132] << 24 | buf[133] << 16 | buf[134] << 8 | buf[135];
	const nonce = buf.slice(136, 152);
	assertPoint(ephRaw, "对端临时");
	assertPoint(ltRaw, "对端长期");
	return {
		ephRaw,
		ltRaw,
		window: window >>> 0,
		nonce
	};
}
function parseServer(buf) {
	if (buf.length !== 164) throw new LexisError("服务端问候长度不对");
	if (buf[0] !== 1 || buf[1] !== 2) throw new LexisError("服务端问候版本不对");
	const ephRaw = buf.slice(2, 67);
	const ltRaw = buf.slice(67, 132);
	const nonce = buf.slice(132, 148);
	const confirm = buf.slice(148, 164);
	assertPoint(ephRaw, "闸门临时");
	assertPoint(ltRaw, "闸门长期");
	return {
		ephRaw,
		ltRaw,
		nonce,
		confirm
	};
}
async function gateRespond(gate, peerRawB64, helloWire) {
	const hello = parseHello(await decodeStatic(helloWire));
	const pinned = unb64(peerRawB64);
	if (!timingSafeEqual(hello.ltRaw, pinned)) throw new LexisError("内网端长期公钥和闸门上的绑定不一致");
	const ephS = await createIdentity();
	const ltS = unb64(gate.publicRawB64);
	const nonceS = crypto.getRandomValues(/* @__PURE__ */ new Uint8Array(16));
	const sk = await deriveSk(await ecdh(await importPrivateJwk(ephS.privateJwk), await importRawPublic(hello.ephRaw)), await ecdh(await importPrivateJwk(gate.privateJwk), await importRawPublic(hello.ltRaw)), hello.nonce, nonceS, hello.window);
	const tr = transcript({
		ephC: hello.ephRaw,
		ephS: ephS.publicRaw,
		ltC: hello.ltRaw,
		ltS,
		window: hello.window,
		nonceC: hello.nonce,
		nonceS
	});
	const confirmS = (await hmac(sk, concat(utf8("lexis-srv-v1"), tr))).subarray(0, 16);
	const expectFinish = (await hmac(sk, concat(utf8("lexis-cli-v1"), tr))).subarray(0, 16);
	const serverWire = await encodeStatic(concat(new Uint8Array([1, 2]), ephS.publicRaw, ltS, nonceS, confirmS));
	return {
		sk,
		window: hello.window,
		ephC: hello.ephRaw,
		ephS: ephS.publicRaw,
		ltC: hello.ltRaw,
		ltS,
		nonceC: hello.nonce,
		nonceS,
		serverWire,
		expectFinish
	};
}
async function edgeFinish(edge, pending, gateRawB64, serverWire) {
	const server = parseServer(await decodeStatic(serverWire));
	const pinned = unb64(gateRawB64);
	if (!timingSafeEqual(server.ltRaw, pinned)) throw new LexisError("闸门长期公钥和内网端上的绑定不一致");
	const sk = await deriveSk(await ecdh(await importPrivateJwk(pending.eph.privateJwk), await importRawPublic(server.ephRaw)), await ecdh(await importPrivateJwk(edge.privateJwk), await importRawPublic(server.ltRaw)), pending.nonceC, server.nonce, pending.window);
	const tr = transcript({
		ephC: pending.eph.publicRaw,
		ephS: server.ephRaw,
		ltC: pending.ltRaw,
		ltS: server.ltRaw,
		window: pending.window,
		nonceC: pending.nonceC,
		nonceS: server.nonce
	});
	if (!timingSafeEqual((await hmac(sk, concat(utf8("lexis-srv-v1"), tr))).subarray(0, 16), server.confirm)) throw new LexisError("闸门确认标记对不上，会话密钥没有对齐");
	const confirmC = (await hmac(sk, concat(utf8("lexis-cli-v1"), tr))).subarray(0, 16);
	return {
		sk,
		finishWire: await encodeStatic(concat(new Uint8Array([1, 3]), confirmC)),
		window: pending.window
	};
}
async function gateAccept(pending, finishWire) {
	const buf = await decodeStatic(finishWire);
	if (buf.length !== 18 || buf[0] !== 1 || buf[1] !== 3) throw new LexisError("结束握手的报文不对");
	if (!timingSafeEqual(buf.slice(2), pending.expectFinish)) throw new LexisError("内网端确认标记对不上");
}
async function openSession(opts) {
	const lexicon = await sessionLexicon(opts.sk, opts.window);
	const inverse = invertLexicon(lexicon);
	const skFp = await fingerprintOf(opts.sk);
	return {
		sk: opts.sk,
		skFp,
		window: opts.window,
		lexicon,
		inverse,
		counters: {
			e2g: 0,
			g2e: 0
		},
		seen: {
			e2g: 0,
			g2e: 0
		},
		helloWire: opts.helloWire,
		serverWire: opts.serverWire,
		finishWire: opts.finishWire,
		edgeName: opts.edge.name,
		gateName: opts.gate.name,
		edgeFp: opts.edge.fingerprint,
		gateFp: opts.gate.fingerprint
	};
}
/** Both roles, in order. The browser lab runs this; a real split process would run each step on its host. */
async function establish(edge, gate, now = Date.now()) {
	if (edge.role !== "edge" || gate.role !== "gate") throw new LexisError("需要一个内网端和一个公网闸门");
	if (edge.pinnedPeerId !== gate.id || gate.pinnedPeerId !== edge.id) throw new LexisError("两端还没有互相绑定");
	const started = await edgeStart(edge, now);
	const responded = await gateRespond(gate, edge.publicRawB64, started.helloWire);
	const finished = await edgeFinish(edge, started, gate.publicRawB64, responded.serverWire);
	await gateAccept(responded, finished.finishWire);
	if (!timingSafeEqual(finished.sk, responded.sk)) throw new LexisError("两端会话密钥不一致");
	return openSession({
		edge,
		gate,
		sk: finished.sk,
		window: finished.window,
		helloWire: started.helloWire,
		serverWire: responded.serverWire,
		finishWire: finished.finishWire
	});
}
/** Shannon entropy in bits per byte. Uniform ciphertext sits near 8; prose sits near 4. */
function shannonEntropy(bytes) {
	if (bytes.length === 0) return 0;
	const freq = new Array(256).fill(0);
	for (let i = 0; i < bytes.length; i++) freq[bytes[i]] += 1;
	let h = 0;
	for (let i = 0; i < 256; i++) {
		if (!freq[i]) continue;
		const p = freq[i] / bytes.length;
		h -= p * Math.log2(p);
	}
	return h;
}
function entropyPair(prose) {
	const bytes = utf8(prose);
	const rnd = randomBytes(Math.max(bytes.length, 1));
	return {
		wire: shannonEntropy(bytes),
		random: shannonEntropy(rnd.subarray(0, bytes.length)),
		nbytes: bytes.length
	};
}
var RECORD = {
	heartbeat: 1,
	data: 2,
	open: 3,
	close: 4
};
function encodeRecord(type, conn, seq, payload) {
	const out = new Uint8Array(11 + payload.length);
	out[0] = type & 255;
	out.set(u32be(conn), 1);
	out.set(u32be(seq), 5);
	out[9] = payload.length >> 8 & 255;
	out[10] = payload.length & 255;
	out.set(payload, 11);
	return out;
}
function decodeRecord(frame) {
	if (frame.length < 11) throw new Error("内层帧过短");
	const len = readU16(frame, 9);
	if (frame.length < 11 + len) throw new Error("内层帧被截断");
	return {
		type: frame[0],
		conn: readU32(frame, 1),
		seq: readU32(frame, 5),
		payload: frame.slice(11, 11 + len)
	};
}
function recordLabel(type) {
	switch (type) {
		case RECORD.heartbeat: return "心跳";
		case RECORD.data: return "数据";
		case RECORD.open: return "打开";
		case RECORD.close: return "关闭";
		default: return "未知";
	}
}
function heartbeatPayload(now = Date.now()) {
	return utf8(`hb ${now}`);
}
function mask24(mac) {
	return (mac[0] << 16 | mac[1] << 8 | mac[2]) >>> 0;
}
/**
* Codebook stream seal.
* Counter is hidden by a window mask, then each 12-bit plaintext digit is
* added (mod 4096) to a keystream digit and emitted as lexicon[sum].
* HMAC covers direction, counter, and plaintext.
*/
async function seal(input) {
	const { key, lexicon, counter, window, direction, plaintext } = input;
	if (counter < 1 || counter > 16777215) throw new LexisError("计数器超出 24 位范围");
	if (lexicon.length !== SPEC.lexiconSize) throw new LexisError("词表长度不对");
	const tag = (await hmac(key, concat(utf8(`lexis-mac-v1|${direction}|`), u32be(counter), plaintext))).subarray(0, SPEC.macBytes);
	const chunks = bytesToChunks(concat(u16be(plaintext.length), plaintext, tag));
	const ks = await hkdfStream(key, concat(utf8(`lexis-body-v1|${direction}|${window}|`), u32be(counter)), "LEXIS-KS-v1", chunks.length * 2);
	const body = chunks.map((c, i) => {
		const ks12 = (ks[i * 2] << 8 | ks[i * 2 + 1]) & 4095;
		return lexicon[(c + ks12) % SPEC.lexiconSize];
	});
	const masked = (counter ^ mask24(await hmac(key, utf8(`lexis-counter-mask-v1|${direction}|${window}`)))) & 16777215;
	const c0 = lexicon[masked >> 12 & 4095];
	const c1 = lexicon[masked & 4095];
	return dress([
		c0,
		c1,
		...body
	], counter);
}
async function open(input) {
	const { key, inverse, window, direction, prose, lastSeen } = input;
	const words = undress(prose);
	if (words.length < 3) throw new LexisError("报文太短，不像一帧词隙");
	const take = (w) => {
		const idx = inverse.get(w);
		if (idx === void 0) throw new LexisError("有词不在本时间窗的词表里。密钥或时间窗不一致，或报文被改过。");
		return idx;
	};
	const mask = mask24(await hmac(key, utf8(`lexis-counter-mask-v1|${direction}|${window}`)));
	const counter = (((take(words[0]) & 4095) << 12 | take(words[1]) & 4095) ^ mask) & 16777215;
	if (counter < 1) throw new LexisError("计数器无效");
	if (counter <= lastSeen) throw new LexisError("计数器没有前进，按回放丢弃");
	const bodyWords = words.slice(2);
	const ks = await hkdfStream(key, concat(utf8(`lexis-body-v1|${direction}|${window}|`), u32be(counter)), "LEXIS-KS-v1", bodyWords.length * 2);
	const raw = chunksToBytes(bodyWords.map((w, i) => {
		const ks12 = (ks[i * 2] << 8 | ks[i * 2 + 1]) & 4095;
		return (take(w) - ks12 + SPEC.lexiconSize) % SPEC.lexiconSize;
	}));
	if (raw.length < 2 + SPEC.macBytes) throw new LexisError("正文长度不够");
	const len = readU16(raw, 0);
	if (2 + len + SPEC.macBytes > raw.length) throw new LexisError("正文字段被截断");
	const plaintext = raw.slice(2, 2 + len);
	if (!timingSafeEqual(raw.slice(2 + len, 2 + len + SPEC.macBytes), (await hmac(key, concat(utf8(`lexis-mac-v1|${direction}|`), u32be(counter), plaintext))).subarray(0, SPEC.macBytes))) throw new LexisError("校验失败。密钥、计数器或词表对不上。");
	return {
		counter,
		plaintext
	};
}
function EntropyMeter({ wire, random }) {
	const data = [{
		name: "词隙",
		bits: Number(wire.toFixed(2))
	}, {
		name: "随机",
		bits: Number(random.toFixed(2))
	}];
	return /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
		className: "h-40 w-full",
		children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ResponsiveContainer, {
			width: "100%",
			height: "100%",
			children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(BarChart, {
				data,
				margin: {
					top: 8,
					right: 8,
					left: 0,
					bottom: 0
				},
				children: [
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)(XAxis, {
						dataKey: "name",
						tick: {
							fill: "var(--color-mist)",
							fontSize: 12
						},
						axisLine: false,
						tickLine: false
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)(YAxis, {
						domain: [0, 8],
						tick: {
							fill: "var(--color-mist)",
							fontSize: 12
						},
						axisLine: false,
						tickLine: false,
						width: 32
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Tooltip, {
						cursor: { fill: "var(--color-panel-2)" },
						contentStyle: {
							background: "var(--color-ink)",
							border: "1px solid var(--color-line)",
							borderRadius: 6,
							color: "var(--color-fg)"
						},
						formatter: (value) => [`${value} bit/B`, "字节熵"]
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Bar, {
						dataKey: "bits",
						radius: 4,
						maxBarSize: 48,
						children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Cell, { fill: "var(--color-sage)" }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Cell, { fill: "var(--color-ember)" })]
					})
				]
			})
		})
	});
}
function Btn({ kind = "solid", className = "", ...props }) {
	return /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
		className: `inline-flex min-h-11 items-center justify-center gap-2 rounded-sm px-4 text-sm font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50 ${kind === "solid" ? "bg-sage text-ink hover:bg-fg" : kind === "ember" ? "bg-ember text-ink hover:bg-paper" : "border border-line bg-panel text-fg hover:border-sage"} ${className}`,
		...props
	});
}
function Field({ label, children }) {
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("label", {
		className: "flex flex-col gap-2 text-sm",
		children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
			className: "text-mist",
			children: label
		}), children]
	});
}
var control = "min-h-11 w-full rounded-sm border border-line bg-ink px-3 text-base text-fg";
function Panel({ title, action, children }) {
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("section", {
		className: "rounded-md border border-line bg-panel p-4",
		children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
			className: "mb-4 flex items-center justify-between gap-3",
			children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h2", {
				className: "text-base font-medium",
				children: title
			}), action]
		}), children]
	});
}
function Paper({ kicker, children }) {
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
		className: "rounded-md bg-paper px-4 py-4 text-paper-ink",
		children: [kicker ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
			className: "mb-2 font-mono text-xs text-paper-mist",
			children: kicker
		}) : null, /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
			className: "text-base leading-relaxed break-words",
			children
		})]
	});
}
function showPayload(payload) {
	if (isPrintableText(payload)) return fromUtf8(payload);
	return hex(payload);
}
function Wire({ item, copied, onCopy }) {
	const [open, setOpen] = (0, import_react.useState)(false);
	const prose = item.prose ?? "";
	const long = prose.length > 180;
	const shown = !long || open ? prose : `${prose.slice(0, 180)}…`;
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("article", {
		className: "flex flex-col gap-2",
		children: [
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
				className: "flex flex-wrap items-center justify-between gap-2",
				children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h3", {
					className: `text-sm font-medium ${item.bad ? "text-ember" : "text-fg"}`,
					children: item.title
				}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
					className: "flex gap-3",
					children: [long ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
						type: "button",
						className: "min-h-11 text-sm text-mist",
						onClick: () => setOpen((v) => !v),
						children: open ? "收起" : "展开"
					}) : null, item.prose ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
						type: "button",
						className: "min-h-11 text-sm text-sage",
						onClick: onCopy,
						children: copied ? "已复制" : "复制原文"
					}) : null]
				})]
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
				className: "break-all font-mono text-xs text-mist",
				children: item.meta
			}),
			item.prose ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Paper, { children: shown }) : null
		]
	});
}
function Bench({ session, onSession }) {
	const nodes = useMesh((s) => s.nodes);
	const mappings = useMesh((s) => s.mappings);
	const edges = nodes.filter((n) => n.role === "edge");
	const gates = nodes.filter((n) => n.role === "gate");
	const [edgeId, setEdgeId] = (0, import_react.useState)(edges[0]?.id ?? "");
	const [gateId, setGateId] = (0, import_react.useState)(gates[0]?.id ?? "");
	const [busy, setBusy] = (0, import_react.useState)(false);
	const [error, setError] = (0, import_react.useState)(null);
	const [logs, setLogs] = (0, import_react.useState)([]);
	const [draft, setDraft] = (0, import_react.useState)("GET /health HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n");
	const [direction, setDirection] = (0, import_react.useState)("g2e");
	const [copied, setCopied] = (0, import_react.useState)(null);
	const [lastFrame, setLastFrame] = (0, import_react.useState)(null);
	function push(item) {
		setLogs((prev) => [{
			...item,
			id: crypto.randomUUID()
		}, ...prev].slice(0, 12));
	}
	async function handshake() {
		const edge = nodes.find((n) => n.id === (edgeId || edges[0]?.id));
		const gate = nodes.find((n) => n.id === (gateId || gates[0]?.id));
		if (!edge || !gate) {
			setError("需要一个内网端和一个闸门");
			return;
		}
		setBusy(true);
		setError(null);
		setLogs([]);
		setLastFrame(null);
		onSession(null);
		try {
			const next = await establish(edge, gate);
			onSession(next);
			for (const item of [
				{
					title: "内网端 → 闸门 · 问候",
					prose: next.helloWire
				},
				{
					title: "闸门 → 内网端 · 临时公钥和确认",
					prose: next.serverWire
				},
				{
					title: "内网端 → 闸门 · 结束握手",
					prose: next.finishWire
				}
			]) {
				const ent = entropyPair(item.prose);
				push({
					title: item.title,
					prose: item.prose,
					meta: `${ent.nbytes} 字节 · 熵 ${ent.wire.toFixed(2)} · 随机对照 ${ent.random.toFixed(2)}`,
					wire: ent.wire,
					random: ent.random
				});
			}
		} catch (err) {
			setError(err instanceof Error ? err.message : "握手失败");
		} finally {
			setBusy(false);
		}
	}
	async function transmit(dir, plaintext, title) {
		if (!session) throw new LexisError("还没有会话");
		const counter = session.counters[dir] + 1;
		const prose = await seal({
			key: session.sk,
			lexicon: session.lexicon,
			counter,
			window: session.window,
			direction: dir,
			plaintext
		});
		const opened = await open({
			key: session.sk,
			inverse: session.inverse,
			window: session.window,
			direction: dir,
			prose,
			lastSeen: session.seen[dir]
		});
		const next = {
			...session,
			counters: {
				...session.counters,
				[dir]: opened.counter
			},
			seen: {
				...session.seen,
				[dir]: opened.counter
			}
		};
		onSession(next);
		setLastFrame({
			prose,
			direction: dir
		});
		const ent = entropyPair(prose);
		const rec = decodeRecord(opened.plaintext);
		push({
			title,
			prose,
			meta: `${dir === "g2e" ? "闸门 → 内网" : "内网 → 闸门"} · 计数器 ${opened.counter} · ${recordLabel(rec.type)} · conn ${rec.conn} · seq ${rec.seq} · ${ent.nbytes} 字节 · 熵 ${ent.wire.toFixed(2)}`,
			wire: ent.wire,
			random: ent.random
		});
		return {
			prose,
			payload: rec.payload,
			session: next
		};
	}
	async function sendDraft() {
		if (!session) return;
		setBusy(true);
		setError(null);
		try {
			const conn = session.counters[direction] + 1;
			await transmit(direction, encodeRecord(RECORD.data, conn, conn, utf8(draft)), "手动封装");
		} catch (err) {
			setError(err instanceof Error ? err.message : "封装失败");
		} finally {
			setBusy(false);
		}
	}
	async function sendHeartbeat() {
		if (!session) return;
		setBusy(true);
		setError(null);
		try {
			await transmit("e2g", encodeRecord(RECORD.heartbeat, 0, session.counters.e2g + 1, heartbeatPayload()), "心跳");
		} catch (err) {
			setError(err instanceof Error ? err.message : "心跳失败");
		} finally {
			setBusy(false);
		}
	}
	async function sendRandom() {
		if (!session) return;
		setBusy(true);
		setError(null);
		try {
			const raw = randomBytes(48);
			push({
				title: "对端拆出的字节",
				meta: hex((await transmit("g2e", encodeRecord(RECORD.data, 9, 1, raw), "随机字节")).payload)
			});
		} catch (err) {
			setError(err instanceof Error ? err.message : "发送失败");
		} finally {
			setBusy(false);
		}
	}
	async function runMap() {
		if (!session) return;
		const gate = nodes.find((n) => n.fingerprint === session.gateFp);
		const map = mappings.filter((m) => m.enabled && (!gate || m.gateId === gate.id)).sort((a, b) => b.priority - a.priority)[0];
		if (!map) {
			setError("这个闸门没有启用的映射");
			return;
		}
		setBusy(true);
		setError(null);
		let current = session;
		try {
			const run = async (dir, type, conn, seq, body, title) => {
				const counter = current.counters[dir] + 1;
				const prose = await seal({
					key: current.sk,
					lexicon: current.lexicon,
					counter,
					window: current.window,
					direction: dir,
					plaintext: encodeRecord(type, conn, seq, utf8(body))
				});
				const opened = await open({
					key: current.sk,
					inverse: current.inverse,
					window: current.window,
					direction: dir,
					prose,
					lastSeen: current.seen[dir]
				});
				current = {
					...current,
					counters: {
						...current.counters,
						[dir]: opened.counter
					},
					seen: {
						...current.seen,
						[dir]: opened.counter
					}
				};
				setLastFrame({
					prose,
					direction: dir
				});
				const ent = entropyPair(prose);
				const rec = decodeRecord(opened.plaintext);
				push({
					title,
					prose,
					meta: `${recordLabel(rec.type)} · ${ent.nbytes} B · 熵 ${ent.wire.toFixed(2)} / 随机 ${ent.random.toFixed(2)} · 拆出 ${showPayload(rec.payload).replace(/\s+/g, " ").slice(0, 80)}`,
					wire: ent.wire,
					random: ent.random
				});
			};
			await run("g2e", RECORD.open, 1, 1, `open ${map.proto} ${map.targetHost}:${map.targetPort}`, `公网进入 :${map.listenPort}`);
			await run("g2e", RECORD.data, 1, 2, `GET /health HTTP/1.1\r\nHost: ${map.targetHost}:${map.targetPort}\r\n\r\n`, "请求封进词隙");
			await run("e2g", RECORD.data, 1, 1, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nlexis-ok\r\n", "目标返回，内网端封回去");
			await run("e2g", RECORD.close, 1, 2, "close", "连接关闭");
			onSession(current);
		} catch (err) {
			onSession(current);
			setError(err instanceof Error ? err.message : "演练中断");
		} finally {
			setBusy(false);
		}
	}
	async function wrongWindow() {
		if (!session || !lastFrame) {
			setError("先发出一帧数据，再拿相邻时间窗去拆");
			return;
		}
		setBusy(true);
		setError(null);
		try {
			const lex = await sessionLexicon(session.sk, session.window + 1);
			await open({
				key: session.sk,
				inverse: invertLexicon(lex),
				window: session.window + 1,
				direction: lastFrame.direction,
				prose: lastFrame.prose,
				lastSeen: 0
			});
			setError("这一帧居然被下一窗拆开了。不该发生。");
		} catch (err) {
			push({
				title: "下一时间窗拒绝了上一帧",
				meta: err instanceof Error ? err.message : "拆不开",
				bad: true
			});
		} finally {
			setBusy(false);
		}
	}
	async function copy(id, prose) {
		try {
			await navigator.clipboard.writeText(prose);
			setCopied(id);
		} catch {
			setCopied(null);
			setError("复制没有成功");
		}
	}
	const latest = logs.find((item) => item.wire !== void 0 && item.random !== void 0);
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
		className: "grid gap-4 lg:grid-cols-4",
		children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
			className: "flex flex-col gap-4 lg:col-span-1",
			children: [
				/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("section", {
					className: "rounded-md border border-line bg-panel p-4",
					children: [
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h2", {
							className: "text-base font-medium",
							children: "两端"
						}),
						/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
							className: "mt-3 flex flex-col gap-3",
							children: [
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
									label: "内网端",
									children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("select", {
										className: control,
										value: edgeId || edges[0]?.id || "",
										onChange: (e) => setEdgeId(e.target.value),
										children: edges.map((n) => /* @__PURE__ */ (0, import_jsx_runtime.jsx)("option", {
											value: n.id,
											children: n.name
										}, n.id))
									})
								}),
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
									label: "公网闸门",
									children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("select", {
										className: control,
										value: gateId || gates[0]?.id || "",
										onChange: (e) => setGateId(e.target.value),
										children: gates.map((n) => /* @__PURE__ */ (0, import_jsx_runtime.jsx)("option", {
											value: n.id,
											children: n.name
										}, n.id))
									})
								}),
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Btn, {
									disabled: busy,
									onClick: () => void handshake(),
									children: busy ? "进行中" : "握手"
								})
							]
						}),
						session ? /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("dl", {
							className: "mt-4 space-y-2 text-sm",
							children: [
								/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("dt", {
									className: "text-mist",
									children: "会话密钥"
								}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("dd", {
									className: "break-all font-mono text-xs",
									children: session.skFp
								})] }),
								/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("dt", {
									className: "text-mist",
									children: "时间窗"
								}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("dd", {
									className: "font-mono text-xs",
									children: session.window
								})] }),
								/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("dt", {
									className: "text-mist",
									children: "计数器"
								}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("dd", {
									className: "font-mono text-xs",
									children: [
										"闸门→内网 ",
										session.counters.g2e,
										" · 内网→闸门 ",
										session.counters.e2g
									]
								})] })
							]
						}) : /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
							className: "mt-4 text-sm text-mist",
							children: "握手之后，这里留下密钥指纹和两个方向的计数器。"
						}),
						/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
							className: "mt-4 flex flex-col gap-2",
							children: [
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Btn, {
									disabled: !session || busy,
									onClick: () => void runMap(),
									children: "走一条映射"
								}),
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Btn, {
									kind: "ghost",
									disabled: !session || busy,
									onClick: () => void sendHeartbeat(),
									children: "心跳"
								}),
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Btn, {
									kind: "ghost",
									disabled: !session || busy,
									onClick: () => void sendRandom(),
									children: "随机字节"
								}),
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Btn, {
									kind: "ghost",
									disabled: !session || busy,
									onClick: () => void wrongWindow(),
									children: "用下一窗拆上一帧"
								})
							]
						})
					]
				}),
				error ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
					className: "text-sm text-ember",
					children: error
				}) : null,
				/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("section", {
					className: "rounded-md border border-line bg-panel p-4",
					children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h2", {
						className: "text-base font-medium",
						children: "自己写一帧"
					}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
						className: "mt-3 grid gap-3",
						children: [
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
								label: "方向",
								children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("select", {
									className: control,
									value: direction,
									onChange: (e) => setDirection(e.target.value),
									children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("option", {
										value: "g2e",
										children: "闸门 → 内网端"
									}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("option", {
										value: "e2g",
										children: "内网端 → 闸门"
									})]
								})
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
								label: "载荷",
								children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("textarea", {
									className: "min-h-32 w-full rounded-sm border border-line bg-ink px-3 py-3 font-mono text-sm text-fg",
									value: draft,
									"aria-label": "载荷",
									onChange: (e) => setDraft(e.target.value)
								})
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Btn, {
								disabled: !session || busy,
								onClick: () => void sendDraft(),
								children: "封装并让对端拆开"
							})
						]
					})]
				})
			]
		}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
			className: "flex flex-col gap-4 lg:col-span-3",
			children: [latest && latest.wire !== void 0 && latest.random !== void 0 ? /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("section", {
				className: "rounded-md border border-line bg-panel p-4",
				children: [
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h2", {
						className: "text-base font-medium",
						children: "最近一帧的字节熵"
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)(EntropyMeter, {
						wire: latest.wire,
						random: latest.random
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
						className: "text-sm text-mist",
						children: "纵轴是 bit/字节。词隙应明显低于等长随机字节。"
					})
				]
			}) : null, /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
				className: "flex flex-col gap-3",
				children: [logs.length === 0 ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Paper, {
					kicker: "线上",
					children: "握手之后，报文会落在这张纸上。"
				}) : null, logs.map((item) => /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Wire, {
					item,
					copied: copied === item.id,
					onCopy: () => void copy(item.id, item.prose ?? "")
				}, item.id))]
			})]
		})]
	});
}
function rid(prefix) {
	return `${prefix}-${crypto.randomUUID().slice(0, 8)}`;
}
function ConfigPanel() {
	const profile = useProfile((s) => s.profile);
	const patch = useProfile((s) => s.patch);
	const [importKind, setImportKind] = (0, import_react.useState)("clash");
	const [importText, setImportText] = (0, import_react.useState)("DOMAIN-SUFFIX,example.com,PROXY\nGEOSITE,cn,DIRECT\nMATCH,PROXY");
	const [importError, setImportError] = (0, import_react.useState)(null);
	const [host, setHost] = (0, import_react.useState)("www.baidu.com");
	const [ip, setIp] = (0, import_react.useState)("");
	const [proc, setProc] = (0, import_react.useState)("");
	const hit = matchRoute(profile, {
		host,
		ip,
		process: proc
	});
	const issues = profileIssues(profile);
	function setInbounds(inbounds) {
		patch({ inbounds });
	}
	function setProcesses(processes) {
		patch({ processes });
	}
	function setRules(rules) {
		patch({ rules });
	}
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
		className: "flex flex-col gap-4",
		children: [
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("section", {
				className: "rounded-md border border-line bg-panel p-4",
				children: [
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h2", {
						className: "text-base font-medium",
						children: "通用配置"
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
						className: "mt-2 text-sm text-mist",
						children: "同一份档案给 Windows、Linux、Android 客户端。固定端口只监听；系统接管还会写出平台转发脚本。程序规则优先于域名和地址规则。"
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
						className: "mt-4 flex flex-wrap gap-2",
						children: [
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Btn, {
								kind: profile.mode === "fixed-port" ? "solid" : "ghost",
								onClick: () => patch({ mode: "fixed-port" }),
								children: "固定端口"
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Btn, {
								kind: profile.mode === "system-forward" ? "solid" : "ghost",
								onClick: () => patch({ mode: "system-forward" }),
								children: "系统接管"
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Btn, {
								kind: "ghost",
								onClick: () => patch(edgePreset()),
								children: "边缘预设"
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Btn, {
								kind: "ghost",
								onClick: () => patch(gatePreset()),
								children: "闸门预设"
							})
						]
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
						className: "mt-4 grid gap-3 sm:grid-cols-2",
						children: [
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
								label: "名称",
								children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
									className: control,
									value: profile.name,
									onChange: (e) => patch({ name: e.target.value })
								})
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
								label: "角色",
								children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("select", {
									className: control,
									value: profile.role,
									onChange: (e) => patch({ role: e.target.value }),
									children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("option", {
										value: "edge",
										children: "边缘客户端"
									}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("option", {
										value: "gate",
										children: "公网闸门"
									})]
								})
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
								label: "对端 主机:端口",
								children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
									className: control,
									value: profile.peerEndpoint,
									placeholder: "203.0.113.8:18443",
									onChange: (e) => patch({ peerEndpoint: e.target.value })
								})
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
								label: "程序未命中时",
								children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("select", {
									className: control,
									value: profile.processDefault,
									onChange: (e) => patch({ processDefault: e.target.value }),
									children: ACTIONS.map((action) => /* @__PURE__ */ (0, import_jsx_runtime.jsx)("option", {
										value: action,
										children: actionLabel(action)
									}, action))
								})
							})
						]
					})
				]
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("section", {
				className: "rounded-md border border-line bg-panel p-4",
				children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
					className: "flex items-center justify-between gap-3",
					children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h2", {
						className: "text-base font-medium",
						children: "入站"
					}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Btn, {
						kind: "ghost",
						onClick: () => setInbounds([...profile.inbounds, {
							id: rid("in"),
							tag: "新入站",
							protocol: "socks",
							listen: "127.0.0.1",
							port: 1080,
							targetHost: "",
							targetPort: 0
						}]),
						children: "添加入站"
					})]
				}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
					className: "mt-4 flex flex-col gap-3",
					children: profile.inbounds.map((inbound) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
						className: "grid gap-2 rounded-sm bg-panel-2 p-3 sm:grid-cols-2",
						children: [
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
								className: control,
								"aria-label": "入站名称",
								value: inbound.tag,
								onChange: (e) => setInbounds(profile.inbounds.map((item) => item.id === inbound.id ? {
									...item,
									tag: e.target.value
								} : item))
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("select", {
								className: control,
								"aria-label": "入站协议",
								value: inbound.protocol,
								onChange: (e) => setInbounds(profile.inbounds.map((item) => item.id === inbound.id ? {
									...item,
									protocol: e.target.value
								} : item)),
								children: [
									/* @__PURE__ */ (0, import_jsx_runtime.jsx)("option", {
										value: "socks",
										children: "SOCKS"
									}),
									/* @__PURE__ */ (0, import_jsx_runtime.jsx)("option", {
										value: "tcp",
										children: "固定转发"
									}),
									/* @__PURE__ */ (0, import_jsx_runtime.jsx)("option", {
										value: "tunnel",
										children: "隧道入口"
									})
								]
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
								className: control,
								"aria-label": "监听地址",
								value: inbound.listen,
								onChange: (e) => setInbounds(profile.inbounds.map((item) => item.id === inbound.id ? {
									...item,
									listen: e.target.value
								} : item))
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
								className: control,
								"aria-label": "监听端口",
								inputMode: "numeric",
								value: inbound.port,
								onChange: (e) => setInbounds(profile.inbounds.map((item) => item.id === inbound.id ? {
									...item,
									port: Number(e.target.value)
								} : item))
							}),
							inbound.protocol === "tcp" ? /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(import_jsx_runtime.Fragment, { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
								className: control,
								"aria-label": "目标主机",
								value: inbound.targetHost,
								placeholder: "目标主机",
								onChange: (e) => setInbounds(profile.inbounds.map((item) => item.id === inbound.id ? {
									...item,
									targetHost: e.target.value
								} : item))
							}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
								className: control,
								"aria-label": "目标端口",
								inputMode: "numeric",
								value: inbound.targetPort,
								onChange: (e) => setInbounds(profile.inbounds.map((item) => item.id === inbound.id ? {
									...item,
									targetPort: Number(e.target.value)
								} : item))
							})] }) : null,
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Btn, {
								kind: "ember",
								onClick: () => setInbounds(profile.inbounds.filter((item) => item.id !== inbound.id)),
								children: "删除"
							})
						]
					}, inbound.id))
				})]
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("section", {
				className: "rounded-md border border-line bg-panel p-4",
				children: [
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h2", {
						className: "text-base font-medium",
						children: "系统接管"
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
						className: "mt-2 text-sm text-mist",
						children: profile.mode === "system-forward" ? "客户端启动时会按当前系统写出并尝试执行。" : "现在走固定端口。这些参数会跟着配置走，切到系统接管才生效。"
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
						className: "mt-4 grid gap-3 lg:grid-cols-3",
						children: [
							/* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Platform, {
								title: "Linux",
								body: "iptables redirect 或 tproxy。需要 root 才会改规则。",
								children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("select", {
									className: control,
									value: profile.linux.method,
									onChange: (e) => patch({ linux: {
										...profile.linux,
										method: e.target.value
									} }),
									children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("option", {
										value: "redirect",
										children: "redirect"
									}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("option", {
										value: "tproxy",
										children: "tproxy"
									})]
								}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
									className: control,
									"aria-label": "fwmark",
									inputMode: "numeric",
									value: profile.linux.mark,
									onChange: (e) => patch({ linux: {
										...profile.linux,
										mark: Number(e.target.value)
									} })
								})]
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Platform, {
								title: "Windows",
								body: "portproxy 转发到本地端口，或只记录 WinDivert 过滤。",
								children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("select", {
									className: control,
									value: profile.windows.method,
									onChange: (e) => patch({ windows: {
										...profile.windows,
										method: e.target.value
									} }),
									children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("option", {
										value: "portproxy",
										children: "portproxy"
									}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("option", {
										value: "windivert",
										children: "WinDivert"
									})]
								}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
									className: control,
									"aria-label": "网关",
									value: profile.windows.gateway,
									onChange: (e) => patch({ windows: {
										...profile.windows,
										gateway: e.target.value
									} })
								})]
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Platform, {
								title: "Android",
								body: "写出 VpnService 会话。地址、MTU、DNS 和绕行网段。",
								children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
									className: control,
									"aria-label": "VPN 地址",
									value: profile.android.address,
									onChange: (e) => patch({ android: {
										...profile.android,
										address: e.target.value
									} })
								}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
									className: control,
									"aria-label": "DNS",
									value: profile.android.dns,
									onChange: (e) => patch({ android: {
										...profile.android,
										dns: e.target.value
									} })
								})]
							})
						]
					})
				]
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("section", {
				className: "rounded-md border border-line bg-panel p-4",
				children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
					className: "flex items-center justify-between gap-3",
					children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h2", {
						className: "text-base font-medium",
						children: "按程序接入或绕行"
					}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Btn, {
						kind: "ghost",
						onClick: () => setProcesses([...profile.processes, {
							id: rid("proc"),
							name: "",
							action: "proxy"
						}]),
						children: "添加程序"
					})]
				}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
					className: "mt-4 flex flex-col gap-2",
					children: profile.processes.map((item) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
						className: "grid gap-2 sm:grid-cols-[1fr_8rem_auto]",
						children: [
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
								className: control,
								"aria-label": "程序名",
								placeholder: "chrome 或 ssh.exe",
								value: item.name,
								onChange: (e) => setProcesses(profile.processes.map((row) => row.id === item.id ? {
									...row,
									name: e.target.value
								} : row))
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)("select", {
								className: control,
								"aria-label": "程序动作",
								value: item.action,
								onChange: (e) => setProcesses(profile.processes.map((row) => row.id === item.id ? {
									...row,
									action: e.target.value
								} : row)),
								children: ACTIONS.map((action) => /* @__PURE__ */ (0, import_jsx_runtime.jsx)("option", {
									value: action,
									children: actionLabel(action)
								}, action))
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Btn, {
								kind: "ghost",
								onClick: () => setProcesses(profile.processes.filter((row) => row.id !== item.id)),
								children: "删除"
							})
						]
					}, item.id))
				})]
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("section", {
				className: "rounded-md border border-line bg-panel p-4",
				children: [
					/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
						className: "flex items-center justify-between gap-3",
						children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h2", {
							className: "text-base font-medium",
							children: "路由"
						}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Btn, {
							kind: "ghost",
							onClick: () => setRules([...profile.rules, {
								id: rid("rule"),
								type: "DOMAIN-SUFFIX",
								value: "",
								action: "proxy"
							}]),
							children: "添加规则"
						})]
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
						className: "mt-4 flex flex-col gap-2",
						children: profile.rules.map((rule) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
							className: "grid gap-2 sm:grid-cols-[10rem_1fr_8rem_auto]",
							children: [
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)("select", {
									className: control,
									"aria-label": "规则类型",
									value: rule.type,
									onChange: (e) => setRules(profile.rules.map((row) => row.id === rule.id ? {
										...row,
										type: e.target.value
									} : row)),
									children: RULE_TYPES.map((type) => /* @__PURE__ */ (0, import_jsx_runtime.jsx)("option", {
										value: type,
										children: type
									}, type))
								}),
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
									className: control,
									"aria-label": "规则值",
									value: rule.value,
									placeholder: rule.type === "MATCH" ? "留空" : "值",
									onChange: (e) => setRules(profile.rules.map((row) => row.id === rule.id ? {
										...row,
										value: e.target.value
									} : row))
								}),
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)("select", {
									className: control,
									"aria-label": "规则动作",
									value: rule.action,
									onChange: (e) => setRules(profile.rules.map((row) => row.id === rule.id ? {
										...row,
										action: e.target.value
									} : row)),
									children: ACTIONS.map((action) => /* @__PURE__ */ (0, import_jsx_runtime.jsx)("option", {
										value: action,
										children: actionLabel(action)
									}, action))
								}),
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Btn, {
									kind: "ghost",
									onClick: () => setRules(profile.rules.filter((row) => row.id !== rule.id)),
									children: "删除"
								})
							]
						}, rule.id))
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
						className: "mt-4 grid gap-3",
						children: [
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
								label: "导入格式",
								children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("select", {
									className: control,
									value: importKind,
									onChange: (e) => setImportKind(e.target.value),
									children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("option", {
										value: "clash",
										children: "Clash 规则"
									}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("option", {
										value: "sing-box",
										children: "sing-box route.rules"
									})]
								})
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)("textarea", {
								className: "min-h-32 w-full rounded-sm border border-line bg-ink px-3 py-3 font-mono text-sm text-fg",
								value: importText,
								onChange: (e) => setImportText(e.target.value)
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Btn, {
								kind: "ghost",
								onClick: () => {
									try {
										setRules(importKind === "clash" ? importClashRules(importText) : importSingBox(importText));
										setImportError(null);
									} catch (err) {
										setImportError(err instanceof Error ? err.message : "导入失败");
									}
								},
								children: "用这段替换路由"
							}),
							importError ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
								className: "text-sm text-ember",
								children: importError
							}) : null
						]
					})
				]
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("section", {
				className: "rounded-md border border-line bg-panel p-4",
				children: [
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h2", {
						className: "text-base font-medium",
						children: "geosite / geoip"
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
						className: "mt-2 text-sm text-mist",
						children: "内置 private、cn、google、telegram，以及 private/cn 的一小段地址。cn 地址只放了常见公共 DNS。完整库填文本 URL，客户端启动时拉。带类别写 `类别 域名` 或 `geoip:cn 1.2.3.0/24`；单独一行域名或地址段归到 remote。额外行写在下面，立刻参与本页试匹配。"
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
						className: "mt-4 grid gap-3",
						children: [
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
								label: "geosite 文本 URL",
								children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
									className: control,
									value: profile.geositeUrl,
									onChange: (e) => patch({ geositeUrl: e.target.value })
								})
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
								label: "geoip 文本 URL",
								children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
									className: control,
									value: profile.geoipUrl,
									onChange: (e) => patch({ geoipUrl: e.target.value })
								})
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
								label: "额外条目",
								children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("textarea", {
									className: "min-h-24 w-full rounded-sm border border-line bg-ink px-3 py-3 font-mono text-sm text-fg",
									value: profile.extras,
									onChange: (e) => patch({ extras: e.target.value })
								})
							})
						]
					})
				]
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("section", {
				className: "rounded-md border border-line bg-panel p-4",
				children: [
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h2", {
						className: "text-base font-medium",
						children: "试一条"
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
						className: "mt-4 grid gap-3 sm:grid-cols-3",
						children: [
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
								label: "域名",
								children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
									className: control,
									value: host,
									onChange: (e) => setHost(e.target.value)
								})
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
								label: "地址",
								children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
									className: control,
									value: ip,
									onChange: (e) => setIp(e.target.value)
								})
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
								label: "程序",
								children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
									className: control,
									value: proc,
									onChange: (e) => setProc(e.target.value)
								})
							})
						]
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
						className: "mt-3 text-sm",
						children: hit.reason
					})
				]
			}),
			issues.length > 0 ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("ul", {
				className: "text-sm text-ember",
				children: issues.map((issue) => /* @__PURE__ */ (0, import_jsx_runtime.jsx)("li", { children: issue }, issue))
			}) : null,
			/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
				className: "flex flex-wrap gap-2",
				children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Btn, {
					onClick: () => downloadJson("lexis.config.json", profile),
					children: "导出配置"
				})
			})
		]
	});
}
function Platform({ title, body, children }) {
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
		className: "flex flex-col gap-2 rounded-sm bg-panel-2 p-3",
		children: [
			/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h3", {
				className: "text-sm font-medium",
				children: title
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
				className: "text-sm text-mist",
				children: body
			}),
			children
		]
	});
}
function LexiconPanel({ session }) {
	const [query, setQuery] = (0, import_react.useState)("");
	const [source, setSource] = (0, import_react.useState)("session");
	const [staticWords, setStaticWords] = (0, import_react.useState)(null);
	const [busy, setBusy] = (0, import_react.useState)(false);
	const [error, setError] = (0, import_react.useState)(null);
	async function loadStatic() {
		setBusy(true);
		setError(null);
		try {
			setStaticWords(await staticLexicon());
			setSource("static");
		} catch (err) {
			setError(err instanceof Error ? err.message : "静态词表没有生成");
		} finally {
			setBusy(false);
		}
	}
	const words = source === "session" ? session?.lexicon ?? null : staticWords;
	const shown = (0, import_react.useMemo)(() => {
		if (!words) return [];
		const q = query.trim().toLowerCase();
		const rows = [];
		for (let i = 0; i < words.length && rows.length < 96; i++) if (!q || words[i].includes(q)) rows.push({
			word: words[i],
			index: i
		});
		return rows;
	}, [words, query]);
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
		className: "flex flex-col gap-4",
		children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("section", {
			className: "rounded-md border border-line bg-panel p-4",
			children: [
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h2", {
					className: "text-base font-medium",
					children: "本窗词表"
				}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", {
					className: "mt-2 text-sm text-mist",
					children: [SPEC.lexiconSize, " 个可发音词，每个词 12 比特。秘密词表由会话密钥和时间窗号决定；静态词表是公开的，只用来把握手字节写成同样的散文，因为那时候会话密钥还不存在。"]
				}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
					className: "mt-4 flex flex-wrap gap-2",
					children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Btn, {
						kind: source === "session" ? "solid" : "ghost",
						onClick: () => setSource("session"),
						children: "当前会话"
					}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Btn, {
						kind: "ghost",
						disabled: busy,
						onClick: () => void loadStatic(),
						children: busy ? "生成中" : "静态握手词表"
					})]
				}),
				error ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
					className: "mt-3 text-sm text-ember",
					children: error
				}) : null
			]
		}), !words ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
			className: "text-sm text-mist",
			children: source === "session" ? "先在隧道页完成一次握手，秘密词表才会出现。" : "静态词表还没生成。"
		}) : /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("section", {
			className: "rounded-md border border-line bg-panel p-4",
			children: [
				/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
					className: "flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between",
					children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", {
						className: "font-mono text-xs text-mist",
						children: [
							source === "session" ? `窗 ${session?.window}` : "静态",
							" · ",
							words.length,
							" 词"
						]
					}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
						className: `${control} sm:max-w-xs`,
						placeholder: "过滤",
						"aria-label": "过滤词表",
						value: query,
						onChange: (e) => setQuery(e.target.value)
					})]
				}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)("ul", {
					className: "mt-4 grid grid-cols-2 gap-2 sm:grid-cols-4",
					children: shown.map((row) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("li", {
						className: "rounded-sm bg-panel-2 px-3 py-2 font-mono text-sm",
						children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
							className: "mr-2 text-mist",
							children: String(row.index).padStart(4, "0")
						}), row.word]
					}, `${row.index}-${row.word}`))
				}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
					className: "mt-3 text-sm text-mist",
					children: "只列出前 96 个匹配。下标就是这个词在加解密里的序号。"
				})
			]
		})]
	});
}
function MapsPanel() {
	const nodes = useMesh((s) => s.nodes);
	const mappings = useMesh((s) => s.mappings);
	const addMapping = useMesh((s) => s.addMapping);
	const updateMapping = useMesh((s) => s.updateMapping);
	const removeMapping = useMesh((s) => s.removeMapping);
	const gates = nodes.filter((n) => n.role === "gate");
	const [gateId, setGateId] = (0, import_react.useState)(gates[0]?.id ?? "");
	const [proto, setProto] = (0, import_react.useState)("tcp");
	const [listenPort, setListenPort] = (0, import_react.useState)("18443");
	const [targetHost, setTargetHost] = (0, import_react.useState)("127.0.0.1");
	const [targetPort, setTargetPort] = (0, import_react.useState)("8080");
	const [priority, setPriority] = (0, import_react.useState)("10");
	const [note, setNote] = (0, import_react.useState)("");
	const [error, setError] = (0, import_react.useState)(null);
	function add() {
		const listen = Number(listenPort);
		const target = Number(targetPort);
		const rank = Number(priority);
		const gate = gateId || gates[0]?.id;
		if (!gate) {
			setError("先建一个公网闸门");
			return;
		}
		if (!Number.isInteger(listen) || listen < 1 || listen > 65535) {
			setError("监听端口要在 1 到 65535");
			return;
		}
		if (!targetHost.trim()) {
			setError("目标主机不能空");
			return;
		}
		if (!Number.isInteger(target) || target < 1 || target > 65535) {
			setError("目标端口要在 1 到 65535");
			return;
		}
		setError(null);
		const mapping = {
			id: crypto.randomUUID(),
			gateId: gate,
			proto,
			listenPort: listen,
			targetHost: targetHost.trim(),
			targetPort: target,
			priority: Number.isFinite(rank) ? rank : 0,
			enabled: true,
			note: note.trim()
		};
		addMapping(mapping);
		setNote("");
	}
	const sorted = [...mappings].sort((a, b) => b.priority - a.priority || a.listenPort - b.listenPort);
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
		className: "flex flex-col gap-4",
		children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("section", {
			className: "rounded-md border border-line bg-panel p-4",
			children: [
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h2", {
					className: "text-base font-medium",
					children: "新映射"
				}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
					className: "mt-1 text-sm text-mist",
					children: "同一协议和端口上，优先级高的那条生效。闸门收包，内网端把它交给目标。"
				}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
					className: "mt-4 grid gap-3 sm:grid-cols-2",
					children: [
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
							label: "闸门",
							children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("select", {
								className: control,
								value: gateId || gates[0]?.id || "",
								onChange: (e) => setGateId(e.target.value),
								children: [gates.length === 0 ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("option", {
									value: "",
									children: "没有闸门"
								}) : null, gates.map((g) => /* @__PURE__ */ (0, import_jsx_runtime.jsx)("option", {
									value: g.id,
									children: g.name
								}, g.id))]
							})
						}),
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
							label: "协议",
							children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("select", {
								className: control,
								value: proto,
								onChange: (e) => setProto(e.target.value),
								children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("option", {
									value: "tcp",
									children: "TCP"
								}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("option", {
									value: "udp",
									children: "UDP"
								})]
							})
						}),
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
							label: "监听端口",
							children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
								className: control,
								inputMode: "numeric",
								value: listenPort,
								onChange: (e) => setListenPort(e.target.value)
							})
						}),
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
							label: "优先级",
							children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
								className: control,
								inputMode: "numeric",
								value: priority,
								onChange: (e) => setPriority(e.target.value)
							})
						}),
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
							label: "目标主机",
							children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
								className: control,
								value: targetHost,
								onChange: (e) => setTargetHost(e.target.value)
							})
						}),
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
							label: "目标端口",
							children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
								className: control,
								inputMode: "numeric",
								value: targetPort,
								onChange: (e) => setTargetPort(e.target.value)
							})
						}),
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
							label: "备注",
							children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
								className: control,
								value: note,
								onChange: (e) => setNote(e.target.value)
							})
						})
					]
				}),
				error ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
					className: "mt-3 text-sm text-ember",
					children: error
				}) : null,
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
					className: "mt-4",
					children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Btn, {
						onClick: add,
						children: "加上这条"
					})
				})
			]
		}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
			className: "flex flex-col gap-3",
			children: [sorted.length === 0 ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
				className: "text-sm text-mist",
				children: "还没有映射。"
			}) : null, sorted.map((map) => {
				const gate = nodes.find((n) => n.id === map.gateId);
				return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("article", {
					className: "rounded-md border border-line bg-panel p-4",
					children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
						className: "flex items-start justify-between gap-3",
						children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [
							/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", {
								className: "font-mono text-sm text-sage",
								children: [
									map.proto.toUpperCase(),
									" :",
									map.listenPort
								]
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", {
								className: "mt-1 text-base",
								children: [
									gate?.name ?? "未知闸门",
									" → ",
									map.targetHost,
									":",
									map.targetPort
								]
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", {
								className: "text-sm text-mist",
								children: [
									"优先级 ",
									map.priority,
									map.note ? ` · ${map.note}` : ""
								]
							})
						] }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
							type: "button",
							className: "inline-flex min-h-11 min-w-11 items-center justify-center text-mist hover:text-ember",
							"aria-label": "删除映射",
							onClick: () => removeMapping(map.id),
							children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Trash2, { className: "size-4" })
						})]
					}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
						className: "mt-3",
						children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Btn, {
							kind: "ghost",
							onClick: () => updateMapping(map.id, { enabled: !map.enabled }),
							children: map.enabled ? "停用" : "启用"
						})
					})]
				}, map.id);
			})]
		})]
	});
}
function roleLabel(role) {
	return role === "gate" ? "公网闸门" : "内网端";
}
function NodesPanel() {
	const nodes = useMesh((s) => s.nodes);
	const addNode = useMesh((s) => s.addNode);
	const updateNode = useMesh((s) => s.updateNode);
	const removeNode = useMesh((s) => s.removeNode);
	const bindPair = useMesh((s) => s.bindPair);
	const reset = useMesh((s) => s.reset);
	const [busy, setBusy] = (0, import_react.useState)(false);
	const [error, setError] = (0, import_react.useState)(null);
	const fileRef = (0, import_react.useRef)(null);
	async function create(role) {
		setBusy(true);
		setError(null);
		try {
			addNode(await makeNode(role === "gate" ? "新闸门" : "新内网端", role));
		} catch (err) {
			setError(err instanceof Error ? err.message : "密钥没有生成");
		} finally {
			setBusy(false);
		}
	}
	async function onImport(file) {
		setError(null);
		try {
			const data = JSON.parse(await file.text());
			if (data.cipher !== SPEC.name) throw new LexisError("这不是词隙侧车");
			if (data.role !== "gate" && data.role !== "edge") throw new LexisError("角色不对");
			const publicJwk = data.publicJwk;
			const privateJwk = data.privateJwk;
			const ident = await identityFromJwks(publicJwk, privateJwk);
			const node = {
				id: crypto.randomUUID(),
				name: typeof data.name === "string" && data.name ? data.name : "导入节点",
				role: data.role,
				publicJwk: ident.publicJwk,
				privateJwk: ident.privateJwk,
				publicRawB64: b64(ident.publicRaw),
				fingerprint: ident.fingerprint,
				pinnedPeerId: null,
				createdAt: Date.now()
			};
			addNode(node);
			const peerFp = data.pinnedPeerFingerprint;
			if (typeof peerFp === "string") {
				const peer = useMesh.getState().nodes.find((n) => n.fingerprint === peerFp && n.id !== node.id);
				if (peer) bindPair(node.id, peer.id);
			}
		} catch (err) {
			setError(err instanceof Error ? err.message : "侧车读不了");
		}
	}
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
		className: "flex flex-col gap-4",
		children: [
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
				className: "flex flex-wrap gap-2",
				children: [
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Btn, {
						disabled: busy,
						onClick: () => create("gate"),
						children: "新建闸门"
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Btn, {
						kind: "ghost",
						disabled: busy,
						onClick: () => create("edge"),
						children: "新建内网端"
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Btn, {
						kind: "ghost",
						onClick: () => fileRef.current?.click(),
						children: "导入侧车"
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Btn, {
						kind: "ember",
						onClick: () => {
							if (confirm("清空这台浏览器里的节点和映射？私钥也会一起删掉。")) reset();
						},
						children: "清空"
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
						ref: fileRef,
						type: "file",
						accept: "application/json,.json",
						className: "sr-only",
						onChange: (e) => {
							const file = e.target.files?.[0];
							if (file) onImport(file);
							e.target.value = "";
						}
					})
				]
			}),
			error ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
				className: "text-sm text-ember",
				children: error
			}) : null,
			/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
				className: "text-sm text-mist",
				children: "私钥只留在这台浏览器。导出的侧车等于节点身份，不要公开传输。"
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
				className: "grid gap-3 lg:grid-cols-2",
				children: nodes.map((node) => /* @__PURE__ */ (0, import_jsx_runtime.jsx)(NodeCard, {
					node,
					peers: nodes.filter((n) => n.role !== node.role),
					peer: nodes.find((n) => n.id === node.pinnedPeerId),
					onName: (name) => updateNode(node.id, { name }),
					onBind: (peerId) => bindPair(node.id, peerId),
					onRemove: () => removeNode(node.id)
				}, node.id))
			})
		]
	});
}
function NodeCard({ node, peers, peer, onName, onBind, onRemove }) {
	const [peerId, setPeerId] = (0, import_react.useState)(node.pinnedPeerId ?? "");
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("article", {
		className: "rounded-md border border-line bg-panel p-4",
		children: [
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
				className: "flex items-start justify-between gap-3",
				children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
					className: "min-w-0 flex-1",
					children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
						className: "text-sm text-sage",
						children: roleLabel(node.role)
					}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
						className: `${control} mt-2`,
						value: node.name,
						"aria-label": "节点名称",
						onChange: (e) => onName(e.target.value)
					})]
				}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
					type: "button",
					className: "inline-flex min-h-11 min-w-11 items-center justify-center text-mist hover:text-ember",
					"aria-label": `删除${node.name}`,
					onClick: onRemove,
					children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Trash2, { className: "size-4" })
				})]
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
				className: "mt-3 break-all font-mono text-xs text-mist",
				children: node.fingerprint
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
				className: "mt-3 flex flex-col gap-2 sm:flex-row",
				children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
					label: "绑定到",
					children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("select", {
						className: control,
						value: peerId,
						onChange: (e) => setPeerId(e.target.value),
						children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("option", {
							value: "",
							children: "未绑定"
						}), peers.map((p) => /* @__PURE__ */ (0, import_jsx_runtime.jsx)("option", {
							value: p.id,
							children: p.name
						}, p.id))]
					})
				})
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
				className: "mt-3 flex flex-wrap gap-2",
				children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Btn, {
					kind: "ghost",
					disabled: !peerId,
					onClick: () => onBind(peerId),
					children: "互相绑定"
				}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Btn, {
					kind: "ghost",
					onClick: () => downloadJson(`${node.role}-${node.fingerprint}.json`, sidecarOf(node, peer)),
					children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Download, {
						className: "size-4",
						"aria-hidden": "true"
					}), "导出侧车"]
				})]
			}),
			node.pinnedPeerId ? /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", {
				className: "mt-3 text-sm text-mist",
				children: ["已指向 ", peer?.name ?? "一个已经删掉的节点"]
			}) : /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
				className: "mt-3 text-sm text-ember",
				children: "还没有绑定对端，隧道不会握上手。"
			})
		]
	});
}
var STEPS = [
	{
		n: "01",
		title: "绑定身份，而不是发证书",
		body: "闸门和内网端各持一对 P-256 长期密钥。控制台只负责把两端钉在一起。业务流量不进控制台。"
	},
	{
		n: "02",
		title: "非对称握手取出会话密钥",
		body: "内网端主动连出。双方各出临时公钥，做两次 ECDH：临时对临时，长期对长期。HKDF 合成会话密钥。这一层不是 TLS。"
	},
	{
		n: "03",
		title: "密钥加时间窗，生成词表",
		body: `同一个会话密钥、同一个 ${SPEC.windowSec} 秒时间窗，两端生成同一份 ${SPEC.lexiconSize} 词的秘密词表。窗一变，词表整本换掉。`
	},
	{
		n: "04",
		title: "密钥、计数器、词表一起封装",
		body: "每个方向一个计数器。计数器先被密钥掩住，正文每 12 比特加上一段密钥流，再写成词表里的词。虚词只负责节奏，不携带内容。HMAC 负责发现改词。"
	}
];
function Overview({ onOpen }) {
	const nodes = useMesh((s) => s.nodes);
	const mappings = useMesh((s) => s.mappings);
	const gates = nodes.filter((n) => n.role === "gate").length;
	const edges = nodes.filter((n) => n.role === "edge").length;
	const liveMaps = mappings.filter((m) => m.enabled).length;
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
		className: "flex flex-col gap-4",
		children: [
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("section", {
				className: "grid gap-3 sm:grid-cols-3",
				children: [
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Stat, {
						k: "节点",
						v: `${gates} 闸门 · ${edges} 内网`
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Stat, {
						k: "映射",
						v: `${liveMaps} 条在用`
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Stat, {
						k: "线上形态",
						v: "散文，不是记录层"
					})
				]
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Panel, {
				title: "路径",
				action: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Btn, {
					onClick: onOpen,
					children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Radio, {
						className: "size-4",
						"aria-hidden": "true"
					}), "打开隧道"]
				}),
				children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("ol", {
					className: "grid gap-2 md:grid-cols-4",
					children: [
						["访客", "打到闸门的公网端口"],
						["闸门", "把字节封成一帧词"],
						["词隙", "低熵散文穿过中间网络"],
						["内网端", "拆开后交给本机目标"]
					].map(([title, body], i) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("li", {
						className: "flex items-stretch gap-2",
						children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
							className: "flex-1 rounded-sm bg-panel-2 px-3 py-3",
							children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
								className: "text-sm font-medium",
								children: title
							}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
								className: "text-sm text-mist",
								children: body
							})]
						}), i < 3 ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ArrowRight, {
							className: "mt-4 hidden size-4 shrink-0 text-sage md:block",
							"aria-hidden": "true"
						}) : null]
					}, title))
				}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
					className: "mt-4 text-sm text-mist",
					children: "浏览器里不能守一个真正的 TCP 端口。这条控制台把握手、词表和封装真实跑完，端口映射按同一帧格式演练。侧车文件留给以后要常驻的进程。"
				})]
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
				className: "grid gap-3 md:grid-cols-2",
				children: STEPS.map((step) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("article", {
					className: "rounded-md border border-line bg-panel p-4",
					children: [
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
							className: "font-mono text-xs text-sage",
							children: step.n
						}),
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h2", {
							className: "mt-1 text-base font-medium",
							children: step.title
						}),
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
							className: "mt-2 text-sm text-mist",
							children: step.body
						})
					]
				}, step.n))
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Panel, {
				title: "低熵指的是什么",
				children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
					className: "text-sm text-mist",
					children: "线上只有小写字母、空格和句号，字节分布靠近书面文字，香农熵通常落在 4 到 5 bit/字节。等长的随机密文接近 8。保密不靠“看起来像句子”，靠会话密钥、随时间窗旋转的词表，以及和计数器绑定的密钥流。词表对中间人是秘密的，所以看到单词也不知道下标。"
				})
			})
		]
	});
}
function Stat({ k, v }) {
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
		className: "rounded-md border border-line bg-panel px-4 py-3",
		children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
			className: "text-sm text-mist",
			children: k
		}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
			className: "mt-1 text-base font-medium",
			children: v
		})]
	});
}
var TABS = [
	{
		id: "overview",
		label: "总览"
	},
	{
		id: "nodes",
		label: "节点"
	},
	{
		id: "maps",
		label: "映射"
	},
	{
		id: "tunnel",
		label: "隧道"
	},
	{
		id: "lexicon",
		label: "词表"
	},
	{
		id: "config",
		label: "配置"
	}
];
function tabFromLocation() {
	if (typeof window === "undefined") return "overview";
	const value = new URLSearchParams(window.location.search).get("tab");
	return TABS.some((item) => item.id === value) ? value : "overview";
}
function Console() {
	const [tab, setTab] = (0, import_react.useState)("overview");
	const [booted, setBooted] = (0, import_react.useState)(false);
	const [bootError, setBootError] = (0, import_react.useState)(null);
	const [now, setNow] = (0, import_react.useState)(0);
	const [session, setSession] = (0, import_react.useState)(null);
	(0, import_react.useEffect)(() => {
		let live = true;
		(async () => {
			try {
				await useMesh.persist.rehydrate();
				await useProfile.persist.rehydrate();
				await ensureSeed();
				if (live) {
					setTab(tabFromLocation());
					setBooted(true);
				}
			} catch (err) {
				if (live) setBootError(err instanceof Error ? err.message : "节点没有读出来");
			}
		})();
		return () => {
			live = false;
		};
	}, []);
	(0, import_react.useEffect)(() => {
		if (!booted) return;
		setNow(Date.now());
		const timer = setInterval(() => setNow(Date.now()), 1e3);
		return () => clearInterval(timer);
	}, [booted]);
	const windowId = now ? currentWindow(now) : null;
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
		className: "min-h-screen",
		children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("header", {
			className: "border-b border-line bg-ink",
			children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
				className: "mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-3 px-4 py-4",
				children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
					className: "flex items-center gap-3",
					children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("span", {
						className: "relative inline-flex h-8 w-8 items-center justify-center",
						"aria-hidden": "true",
						children: [
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", { className: "absolute inset-x-1 top-1 h-1.5 bg-sage" }),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", { className: "absolute inset-x-1 bottom-1 h-1.5 bg-sage" }),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", { className: "h-1.5 w-1.5 bg-ember" })
						]
					}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
						className: "flex items-baseline gap-2",
						children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h1", {
							className: "text-xl font-bold tracking-wide",
							children: "词隙"
						}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
							className: "font-mono text-sm text-sage",
							children: "LEXIS"
						})]
					}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
						className: "text-sm text-mist",
						children: "低熵远程组网"
					})] })]
				}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
					className: "flex items-center gap-4",
					children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
						className: "font-mono text-xs text-mist",
						children: windowId === null ? `窗长 ${SPEC.windowSec}s` : `时间窗 ${windowId} · 剩余 ${windowRemain(now)}s`
					}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Link, {
						to: "/download",
						className: "inline-flex min-h-11 items-center text-sm text-sage",
						children: "下载"
					})]
				})]
			}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("nav", {
				className: "mx-auto flex max-w-6xl gap-1 overflow-x-auto px-4",
				"aria-label": "分区",
				children: TABS.map((item) => /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
					type: "button",
					"aria-selected": tab === item.id,
					onClick: () => setTab(item.id),
					className: `min-h-11 shrink-0 border-b-2 px-3 text-sm ${tab === item.id ? "border-sage text-fg" : "border-transparent text-mist"}`,
					children: item.label
				}, item.id))
			})]
		}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("main", {
			className: "mx-auto max-w-6xl px-4 py-5",
			children: [
				bootError ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
					className: "text-sm text-ember",
					children: bootError
				}) : null,
				!booted && !bootError ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
					className: "text-sm text-mist",
					children: "正在这台浏览器里准备闸门和内网端。"
				}) : null,
				booted && tab === "overview" ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Overview, { onOpen: () => setTab("tunnel") }) : null,
				booted && tab === "nodes" ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)(NodesPanel, {}) : null,
				booted && tab === "maps" ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)(MapsPanel, {}) : null,
				booted && tab === "tunnel" ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Bench, {
					session,
					onSession: setSession
				}) : null,
				booted && tab === "lexicon" ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)(LexiconPanel, { session }) : null,
				booted && tab === "config" ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ConfigPanel, {}) : null
			]
		})]
	});
}
function Home() {
	return /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Console, {});
}
//#endregion
export { Home as component };
