import { i as __toESM } from "../_runtime.mjs";
import { q as require_react, x as require_jsx_runtime, y as Link } from "../_libs/@tanstack/react-router+[...].mjs";
import { a as Radio, c as ArrowRight, n as Trash2, s as Download } from "../_libs/lucide-react.mjs";
import { n as persist, r as create, t as createJSONStorage } from "../_libs/zustand.mjs";
import { i as x25519, n as ed25519, t as p256 } from "../_libs/noble__curves+noble__hashes.mjs";
import { i as argon2id, n as hkdf, r as hmac, t as sha256 } from "../_libs/noble__hashes.mjs";
import { n as unsafe, r as polyval, t as ctr } from "../_libs/noble__ciphers.mjs";
import { t as require_index_node } from "../_libs/bokuweb__zstd-wasm.mjs";
import { a as Cell, i as Bar, n as YAxis, o as ResponsiveContainer, r as XAxis, s as Tooltip, t as BarChart } from "../_libs/recharts+[...].mjs";
//#region node_modules/.nitro/vite/services/ssr/assets/routes-BVNBR6CP.js
var import_react = /* @__PURE__ */ __toESM(require_react());
var import_jsx_runtime = require_jsx_runtime();
var import_index_node = require_index_node();
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
function unb64$1(s) {
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
async function sha256$1(data) {
	return asBytes(await crypto.subtle.digest("SHA-256", buf(data)));
}
async function fingerprintOf(raw) {
	const h = hex((await sha256$1(raw)).subarray(0, 8));
	return (h.match(/.{1,4}/g) ?? [h]).join("-");
}
/** v3: long-term identity is X25519 (32-byte raw pub). P-256 configs from <=2.x will not load. */
async function createIdentity() {
	try {
		const pair = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
		const publicJwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
		const privateJwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
		const publicRaw = jwkOkpToRaw(publicJwk);
		return {
			publicJwk,
			privateJwk,
			publicRaw,
			fingerprint: await fingerprintOf(publicRaw)
		};
	} catch {
		const { x25519 } = await import("../_libs/noble__curves+noble__hashes.mjs").then((n) => n.r);
		const d = crypto.getRandomValues(/* @__PURE__ */ new Uint8Array(32));
		const x = x25519.getPublicKey(d);
		return {
			publicJwk: {
				kty: "OKP",
				crv: "X25519",
				x: b64url$1(x)
			},
			privateJwk: {
				kty: "OKP",
				crv: "X25519",
				x: b64url$1(x),
				d: b64url$1(d)
			},
			publicRaw: x,
			fingerprint: await fingerprintOf(x)
		};
	}
}
function b64url$1(u) {
	let s = "";
	for (const b of u) s += String.fromCharCode(b);
	return btoa(s).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/g, "");
}
function b64urlDecode(s) {
	const pad = "=".repeat((4 - s.length % 4) % 4);
	const bin = atob(s.replaceAll("-", "+").replaceAll("_", "/") + pad);
	const out = new Uint8Array(bin.length);
	for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
	return out;
}
function jwkOkpToRaw(jwk) {
	if (!jwk.x) throw new LexisError("OKP 公钥缺少 x");
	return b64urlDecode(jwk.x);
}
function x25519SeedFromJwk(jwk) {
	if (jwk.kty !== "OKP" || jwk.crv !== "X25519" || !jwk.d) throw new LexisError("需要 X25519 私钥");
	return b64urlDecode(jwk.d);
}
function x25519PubFromJwk(jwk) {
	if (jwk.kty !== "OKP" || jwk.crv !== "X25519") throw new LexisError("需要 X25519 公钥");
	return jwkOkpToRaw(jwk);
}
async function hkdf$1(ikm, salt, info, bytes) {
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
		parts.push(await hkdf$1(ikm, salt, concat(utf8(infoLabel), u32be(i)), n));
		left -= n;
		i += 1;
	}
	return concat(...parts);
}
async function hmac$1(key, data) {
	const k = await crypto.subtle.importKey("raw", buf(key), {
		name: "HMAC",
		hash: "SHA-256"
	}, false, ["sign"]);
	return asBytes(await crypto.subtle.sign("HMAC", k, buf(data)));
}
async function identityFromJwks(publicJwk, privateJwk) {
	if (publicJwk.kty === "EC" || privateJwk.kty === "EC") throw new LexisError("侧车里仍是 P-256 身份。词隙 3.0 起长期密钥改为 X25519：请重新生成身份，两端一起升级。旧配置无法自动迁移（私钥曲线不同）。");
	if (publicJwk.kty !== "OKP" || publicJwk.crv !== "X25519") throw new LexisError("侧车里的公钥不是 X25519");
	if (privateJwk.kty !== "OKP" || privateJwk.crv !== "X25519" || !privateJwk.d) throw new LexisError("侧车里的私钥不是 X25519");
	const publicRaw = jwkOkpToRaw(publicJwk);
	const seed = b64urlDecode(privateJwk.d);
	const { x25519 } = await import("../_libs/noble__curves+noble__hashes.mjs").then((n) => n.r);
	const expect = x25519.getPublicKey(seed);
	if (publicRaw.length !== 32 || !expect.every((b, i) => b === publicRaw[i])) throw new LexisError("侧车里的私钥和公钥不是一对");
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
	kdf: "Argon2id",
	expand: "HKDF-SHA-256",
	mac: "HMAC-SHA-256",
	macBytes: 16,
	lexiconSize: 4096,
	bitsPerWord: 12,
	windowSec: 300,
	/** Accept the previous window this many seconds in, and the next window this many seconds before the roll. */
	skewSec: 120,
	counterBits: 24
};
var GLUE_SET = /* @__PURE__ */ new Set([
	"the",
	"our",
	"its",
	"that",
	"and"
]);
/** Disk copy drops the scalar when a vault holds it. The running tab keeps `d`. */
function persistedNode(node) {
	if (!node.vault || !node.privateJwk.d) return node;
	const { d: _scalar, ...privateJwk } = node.privateJwk;
	return {
		...node,
		privateJwk
	};
}
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
	setIdentity: (id, next) => set((s) => ({ nodes: s.nodes.map((n) => n.id === id ? {
		...n,
		...next
	} : n) })),
	reset: () => set({
		nodes: [],
		mappings: []
	})
}), {
	name: "lexis-mesh-v1",
	storage: createJSONStorage(() => localStorage),
	skipHydration: true,
	version: 2,
	migrate: (persisted, version) => {
		if (version < 2) return {
			nodes: [],
			mappings: []
		};
		return persisted;
	},
	partialize: (state) => ({
		nodes: state.nodes.map(persistedNode),
		mappings: state.mappings
	})
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
		createdAt: Date.now(),
		kdf: null,
		vault: null
	};
}
var seeding = null;
function ensureSeed() {
	if (useMesh.getState().nodes.length > 0) return Promise.resolve();
	if (seeding) return seeding;
	seeding = (async () => {
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
			seeding = null;
		}
	})();
	return seeding;
}
function sealFileOf(vault) {
	return {
		saltB64: vault.saltB64,
		memoryKiB: vault.memoryKiB,
		iterations: vault.iterations,
		parallelism: vault.parallelism,
		lo: vault.lo,
		hi: vault.hi
	};
}
function sidecarOf(node, peer) {
	const secret = node.vault ? void 0 : node.privateJwk;
	return {
		cipher: SPEC.name,
		role: node.role,
		name: node.name,
		fingerprint: node.fingerprint,
		publicJwk: node.publicJwk,
		privateJwk: secret,
		pinnedPeerFingerprint: peer?.fingerprint ?? null,
		pinnedPeerPublicJwk: peer?.publicJwk ?? null,
		windowSeconds: SPEC.windowSec,
		lexiconSize: SPEC.lexiconSize,
		handshake: "p256-ecdh-argon2id",
		kdf: node.kdf,
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
var DEFAULT_KDF = {
	memoryKiB: 4096,
	iterations: 2,
	parallelism: 1
};
/** At-rest private key. Not the handshake cap. A guess costs this much even if the public key is known. */
var VAULT_KDF = {
	memoryKiB: 65536,
	iterations: 3,
	parallelism: 1
};
var LIMITS = {
	memoryKiB: {
		min: 8,
		max: 16384
	},
	iterations: {
		min: 1,
		max: 4
	},
	parallelism: {
		min: 1,
		max: 2
	}
};
function clampInt(value, min, max, fallback) {
	const n = typeof value === "number" ? value : Number(value);
	if (!Number.isInteger(n)) return fallback;
	if (n < min) return min;
	if (n > max) return max;
	return n;
}
/** Gate-side cap. A peer cannot ask this process to spend more than these costs. */
function clampKdf(input) {
	const parallelism = clampInt(input?.parallelism, LIMITS.parallelism.min, LIMITS.parallelism.max, DEFAULT_KDF.parallelism);
	const minMemory = 8 * parallelism;
	return {
		memoryKiB: Math.max(clampInt(input?.memoryKiB, LIMITS.memoryKiB.min, LIMITS.memoryKiB.max, DEFAULT_KDF.memoryKiB), minMemory),
		iterations: clampInt(input?.iterations, LIMITS.iterations.min, LIMITS.iterations.max, DEFAULT_KDF.iterations),
		parallelism
	};
}
/** Vault cost. Explicit small values stay, so tests can use a tiny memory. Missing values become VAULT_KDF.
*  This does not use the handshake ceiling of 16384 KiB. */
function clampVaultKdf(input) {
	return {
		memoryKiB: clampInt(input?.memoryKiB, 8, 262144, VAULT_KDF.memoryKiB),
		iterations: clampInt(input?.iterations, 1, 8, VAULT_KDF.iterations),
		parallelism: clampInt(input?.parallelism, 1, 1, VAULT_KDF.parallelism)
	};
}
function encodeKdf(params) {
	const c = clampKdf(params);
	return new Uint8Array([
		c.memoryKiB >> 8 & 255,
		c.memoryKiB & 255,
		c.iterations,
		c.parallelism
	]);
}
function decodeKdf(bytes, offset) {
	return clampKdf({
		memoryKiB: (bytes[offset] << 8 | bytes[offset + 1]) >>> 0,
		iterations: bytes[offset + 2],
		parallelism: bytes[offset + 3]
	});
}
function featureByte(honey) {
	return honey ? 1 : 0;
}
function honeyFromFeatures(features) {
	return (features & 1) !== 0;
}
/** Session key from the two ECDH shares. Salt is the handshake nonces, not a config file. */
function deriveSessionKey(ssE, ssS, nonceC, nonceS, window, features, params) {
	const c = clampKdf(params);
	const t0 = Date.now();
	return {
		key: argon2id(concat(ssE, ssS, u32be(window), new Uint8Array([features & 255])), concat(nonceC, nonceS), {
			t: c.iterations,
			m: c.memoryKiB,
			p: c.parallelism,
			dkLen: 32
		}),
		ms: Math.max(1, Date.now() - t0)
	};
}
var sessionDeriver = async (ssE, ssS, nonceC, nonceS, window, features, params) => deriveSessionKey(ssE, ssS, nonceC, nonceS, window, features, params);
function deriveSessionKeyAsync(ssE, ssS, nonceC, nonceS, window, features, params) {
	return sessionDeriver(ssE, ssS, nonceC, nonceS, window, features, params);
}
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
		return buildLexicon(await sha256$1(utf8("LEXIS-STATIC-ALPHABET-v1")));
	})();
	return staticCache;
}
/** Secret codebook: HKDF(key, window) then the same generator. Any key yields a lexicon of the same shape. */
var lexiconCache = /* @__PURE__ */ new Map();
function cacheId(key, window) {
	let hex = `${window}:`;
	for (const b of key) hex += b.toString(16).padStart(2, "0");
	return hex;
}
async function sessionLexicon(sessionKey, window) {
	const id = cacheId(sessionKey, window);
	const hit = lexiconCache.get(id);
	if (hit) return hit;
	const pending = (async () => {
		return buildLexicon(await hkdfStream(sessionKey, utf8("LEXIS-LEX-SALT"), `win-${window}`, 32));
	})();
	lexiconCache.set(id, pending);
	if (lexiconCache.size > 32) {
		const oldest = lexiconCache.keys().next().value;
		if (oldest !== void 0) lexiconCache.delete(oldest);
	}
	return pending;
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
/**
* One evaluation for every key. Programmed keys fall out of the polynomial;
* nothing here compares a key against a list.
*/
var POLY = 1n << 128n | 135n;
var MASK = (1n << 128n) - 1n;
function bitLength(n) {
	return n === 0n ? 1 : n.toString(2).length;
}
function add(a, b) {
	return a ^ b;
}
function mul(a, b) {
	let res = 0n;
	let x = a;
	let y = b;
	while (y > 0n) {
		if (y & 1n) res ^= x;
		x <<= 1n;
		if (x & 1n << 128n) x ^= POLY;
		y >>= 1n;
	}
	return res & MASK;
}
function inv(a) {
	if (a === 0n) throw new Error("零没有逆元");
	let u = a;
	let v = POLY;
	let g1 = 1n;
	let g2 = 0n;
	while (u !== 1n) {
		let j = bitLength(u) - bitLength(v);
		if (j < 0) {
			const su = u;
			u = v;
			v = su;
			const sg = g1;
			g1 = g2;
			g2 = sg;
			j = -j;
		}
		u ^= v << BigInt(j);
		g1 ^= g2 << BigInt(j);
	}
	return g1 & MASK;
}
function fromBytes(bytes) {
	let n = 0n;
	for (const b of bytes) n = n << 8n | BigInt(b);
	return n & MASK;
}
function toBytes(n) {
	const out = /* @__PURE__ */ new Uint8Array(16);
	let x = n & MASK;
	for (let i = 15; i >= 0; i -= 1) {
		out[i] = Number(x & 255n);
		x >>= 8n;
	}
	return out;
}
function xor16(a, b) {
	const out = /* @__PURE__ */ new Uint8Array(16);
	for (let i = 0; i < 16; i += 1) out[i] = a[i] ^ b[i];
	return out;
}
function polyMul(p1, p2) {
	const res = Array(p1.length + p2.length - 1).fill(0n);
	for (let i = 0; i < p1.length; i += 1) {
		if (p1[i] === 0n) continue;
		for (let j = 0; j < p2.length; j += 1) res[i + j] ^= mul(p1[i], p2[j]);
	}
	return res;
}
function horner(coeffs, x) {
	let result = 0n;
	for (let i = coeffs.length - 1; i >= 0; i -= 1) result = add(mul(result, x), coeffs[i]);
	return result;
}
function lagrange(points) {
	const n = points.length;
	const final = Array(n).fill(0n);
	for (let i = 0; i < n; i += 1) {
		const xi = points[i][0];
		const yi = points[i][1];
		let numerator = [1n];
		let denominator = 1n;
		for (let m = 0; m < n; m += 1) {
			if (i === m) continue;
			const xm = points[m][0];
			numerator = polyMul(numerator, [xm, 1n]);
			denominator = mul(denominator, xi ^ xm);
		}
		const scale = mul(yi, inv(denominator));
		for (let deg = 0; deg < numerator.length; deg += 1) final[deg] ^= mul(numerator[deg], scale);
	}
	return final;
}
async function lane(key, salt, label) {
	return (await hmac$1(key, concat(salt, utf8(label)))).subarray(0, 16);
}
function indicesFrom(block) {
	const out = [
		0,
		0,
		0,
		0
	];
	for (let i = 0; i < 4; i += 1) {
		const v = (block[i * 2] << 8 | block[i * 2 + 1]) & 65535;
		out[i] = v % SPEC.lexiconSize;
	}
	return out;
}
function packIndices(indices) {
	const out = /* @__PURE__ */ new Uint8Array(16);
	for (let i = 0; i < 4; i += 1) {
		const n = indices[i] & 65535;
		out[i * 2] = n >> 8 & 255;
		out[i * 2 + 1] = n & 255;
	}
	return out;
}
/** Coefficients only. The same Horner step serves every key. */
async function compileBlocks(entries, slots = 4, salt = randomBytes(16)) {
	if (entries.length < 1 || entries.length > slots) throw new Error("可编程槽位数量不对");
	const points = [];
	const seen = /* @__PURE__ */ new Set();
	for (const entry of entries) {
		if (entry.block.length !== 16) throw new Error("可编程明文要 16 字节");
		const x = await lane(entry.key, salt, "x");
		const r = await lane(entry.key, salt, "r");
		const id = fromBytes(x).toString(16);
		if (seen.has(id)) throw new Error("横坐标撞上了");
		seen.add(id);
		points.push([fromBytes(x), fromBytes(xor16(entry.block, r))]);
	}
	while (points.length < slots) {
		const x = fromBytes(randomBytes(16));
		const id = x.toString(16);
		if (x === 0n || seen.has(id)) continue;
		seen.add(id);
		points.push([x, fromBytes(randomBytes(16))]);
	}
	return {
		salt,
		coeffs: lagrange(points).map(toBytes)
	};
}
async function evalHoney(program, key) {
	const x = await lane(key, program.salt, "x");
	const r = await lane(key, program.salt, "r");
	return xor16(toBytes(horner(program.coeffs.map(fromBytes), fromBytes(x))), r);
}
async function honeyPhrase(key, window, seed, program) {
	const lex = await sessionLexicon(key, window);
	const idx = indicesFrom(program ? await evalHoney(program, key) : await hkdf$1(key, u32be(window), seed.length ? seed : utf8("honey"), 16));
	return `the ${lex[idx[0]]} and our ${lex[idx[1]]} that its ${lex[idx[2]]} and the ${lex[idx[3]]}`;
}
function b64url(bytes) {
	let s = "";
	for (const b of bytes) s += String.fromCharCode(b);
	return btoa(s).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/g, "");
}
async function stretch(passphrase, salt, params) {
	const c = clampVaultKdf(params);
	return argon2id(utf8(passphrase), salt, {
		t: c.iterations,
		m: c.memoryKiB,
		p: c.parallelism,
		dkLen: 32
	});
}
/** Real passphrase and any programmed spare all sit in the same coefficients. */
async function sealIdentityVault(entries, salt, params, slots = 4) {
	const c = clampVaultKdf(params);
	const seenPass = /* @__PURE__ */ new Set();
	for (const entry of entries) {
		if (seenPass.has(entry.passphrase)) throw new Error("口令重复，封不进同一条求值");
		seenPass.add(entry.passphrase);
	}
	for (;;) {
		const pepper = randomBytes(16);
		try {
			const loEntries = [];
			const hiEntries = [];
			for (const entry of entries) {
				if (entry.scalar.length !== 32) throw new Error("私钥标量要 32 字节");
				const dk = await stretch(entry.passphrase, salt, c);
				loEntries.push({
					key: dk,
					block: entry.scalar.subarray(0, 16)
				});
				hiEntries.push({
					key: dk,
					block: entry.scalar.subarray(16, 32)
				});
			}
			return {
				salt,
				kdf: c,
				lo: await compileBlocks(loEntries, slots, pepper),
				hi: await compileBlocks(hiEntries, slots, pepper)
			};
		} catch (err) {
			if (err instanceof Error && err.message === "横坐标撞上了") continue;
			throw err;
		}
	}
}
/** Same steps for every passphrase. A spare one is not a separate branch. */
async function openIdentityVault(vault, passphrase) {
	const dk = await stretch(passphrase, vault.salt, vault.kdf);
	const lo = await evalHoney(vault.lo, dk);
	const hi = await evalHoney(vault.hi, dk);
	const joined = /* @__PURE__ */ new Uint8Array(32);
	joined.set(lo, 0);
	joined.set(hi, 16);
	const seed = joined;
	const x = b64url(x25519.getPublicKey(seed));
	const d = b64url(seed);
	return identityFromJwks({
		kty: "OKP",
		crv: "X25519",
		x,
		ext: true
	}, {
		kty: "OKP",
		crv: "X25519",
		x,
		d,
		ext: true
	});
}
/** Scalar bytes of an unlocked key. Absent after a sealed key is reloaded. */
function freshScalar() {
	return p256.utils.randomSecretKey();
}
function programToStored(program) {
	return {
		saltB64: b64(program.salt),
		coeffsB64: program.coeffs.map((item) => b64(item))
	};
}
/** One shape for every stored program. Bad input is null, not a special key. */
function programFromStored(raw) {
	if (!raw || typeof raw !== "object") return null;
	const rec = raw;
	if (typeof rec.saltB64 !== "string" || !Array.isArray(rec.coeffsB64) || rec.coeffsB64.length < 1 || rec.coeffsB64.length > 8) return null;
	try {
		const salt = unb64$1(rec.saltB64);
		if (salt.length !== 16) return null;
		return {
			salt,
			coeffs: rec.coeffsB64.map((item) => {
				if (typeof item !== "string") throw new Error("系数不对");
				const bytes = unb64$1(item);
				if (bytes.length !== 16) throw new Error("系数不对");
				return bytes;
			})
		};
	} catch {
		return null;
	}
}
function vaultToStored(vault) {
	return {
		saltB64: b64(vault.salt),
		memoryKiB: vault.kdf.memoryKiB,
		iterations: vault.kdf.iterations,
		parallelism: vault.kdf.parallelism,
		lo: programToStored(vault.lo),
		hi: programToStored(vault.hi)
	};
}
function vaultFromStored(raw) {
	if (!raw || typeof raw !== "object") return null;
	const rec = raw;
	if (typeof rec.saltB64 !== "string") return null;
	const lo = programFromStored(rec.lo);
	const hi = programFromStored(rec.hi);
	if (!lo || !hi) return null;
	try {
		const salt = unb64$1(rec.saltB64);
		if (salt.length < 8) return null;
		return {
			salt,
			kdf: clampVaultKdf({
				memoryKiB: rec.memoryKiB,
				iterations: rec.iterations,
				parallelism: rec.parallelism
			}),
			lo,
			hi
		};
	} catch {
		return null;
	}
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
		statusToken: "",
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
		},
		kdf: { ...DEFAULT_KDF },
		honey: false,
		honeyProgram: null,
		seal: null,
		zstd: {
			enabled: false,
			level: 3
		},
		frame: {
			maxExpansion: 5,
			smallFramePolicy: "expansion",
			coalesceTarget: 1024
		},
		link: {
			token: "",
			idleMs: 12e4,
			maxConns: 128,
			headerBytes: 8192,
			allowLan: false,
			handshakeMs: 1e4,
			dialMs: 1e4,
			maxHandshakes: 2,
			udpIdleMs: 6e4,
			udpMax: 64,
			maxHalfOpen: 64,
			maxHalfOpenPerIp: 8
		},
		egress: {
			blockPrivate: true,
			allow: []
		},
		outer: {
			transport: "tcp",
			wsPath: "/lexis",
			tlsVerify: true
		},
		socksAuth: {
			user: "",
			pass: ""
		},
		identity: null,
		peers: [],
		exposes: [],
		reverses: []
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
function linuxOf(base, raw) {
	const method = raw?.method === "tproxy" || raw?.method === "tun" || raw?.method === "redirect" ? raw.method : base.method;
	return {
		...base,
		...raw ?? {},
		method,
		mark: clampNum(raw?.mark, 1, 255, base.mark),
		table: clampNum(raw?.table, 1, 65535, base.table),
		dnsRedirect: raw?.dnsRedirect !== false
	};
}
function normalizeProfile(input) {
	const base = defaultProfile();
	if (!input || typeof input !== "object") return base;
	const raw = input;
	return {
		...base,
		...raw,
		version: 1,
		role: raw.role === "gate" ? "gate" : raw.role === "edge" ? "edge" : "",
		mode: raw.mode === "system-forward" ? "system-forward" : "fixed-port",
		logLevel: raw.logLevel === "debug" ? "debug" : "info",
		processDefault: isAction(raw.processDefault) ? raw.processDefault : base.processDefault,
		inbounds: Array.isArray(raw.inbounds) ? raw.inbounds.map(normalizeInbound) : base.inbounds,
		processes: Array.isArray(raw.processes) ? raw.processes.map(normalizeProcess) : base.processes,
		rules: Array.isArray(raw.rules) ? raw.rules.map(normalizeRule) : base.rules,
		linux: linuxOf(base.linux, raw.linux),
		windows: {
			...base.windows,
			...raw.windows ?? {}
		},
		android: {
			...base.android,
			...raw.android ?? {}
		},
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
			level: clampNum(raw.zstd?.level, 1, 19, base.zstd.level)
		},
		frame: frameOf(base.frame, raw.frame),
		link: {
			token: typeof raw.link?.token === "string" ? raw.link.token : "",
			idleMs: clampNum(raw.link?.idleMs, 1e3, 6e5, base.link.idleMs),
			maxConns: clampNum(raw.link?.maxConns, 1, 1e4, base.link.maxConns),
			headerBytes: clampNum(raw.link?.headerBytes, 256, 65536, base.link.headerBytes),
			allowLan: raw.link?.allowLan === true,
			handshakeMs: clampNum(raw.link?.handshakeMs, 1e3, 6e4, base.link.handshakeMs),
			dialMs: clampNum(raw.link?.dialMs, 1e3, 6e4, base.link.dialMs),
			maxHandshakes: clampNum(raw.link?.maxHandshakes, 1, 8, base.link.maxHandshakes),
			udpIdleMs: clampNum(raw.link?.udpIdleMs, 1e3, 6e5, base.link.udpIdleMs),
			udpMax: clampNum(raw.link?.udpMax, 4, 4096, base.link.udpMax),
			maxHalfOpen: clampNum(raw.link?.maxHalfOpen, 1, 1e4, base.link.maxHalfOpen),
			maxHalfOpenPerIp: clampNum(raw.link?.maxHalfOpenPerIp, 1, 1024, base.link.maxHalfOpenPerIp)
		},
		egress: {
			blockPrivate: raw.egress?.blockPrivate !== false,
			allow: Array.isArray(raw.egress?.allow) ? raw.egress.allow.map((item) => String(item).trim()).filter(Boolean) : []
		},
		outer: normalizeOuter(raw.outer),
		socksAuth: {
			user: typeof raw.socksAuth?.user === "string" ? raw.socksAuth.user : "",
			pass: typeof raw.socksAuth?.pass === "string" ? raw.socksAuth.pass : ""
		},
		identity: normalizeIdentity(raw.identity),
		peers: Array.isArray(raw.peers) ? raw.peers.map((item) => normalizePeer(item)).filter((item) => item !== null) : [],
		exposes: Array.isArray(raw.exposes) ? raw.exposes.map((item) => normalizeExpose(item)) : [],
		reverses: Array.isArray(raw.reverses) ? raw.reverses.map((item) => normalizeReverse(item)) : []
	};
}
function normalizeProgram(raw) {
	if (!raw || typeof raw !== "object") return null;
	const rec = raw;
	if (typeof rec.saltB64 !== "string" || !rec.saltB64) return null;
	if (!Array.isArray(rec.coeffsB64) || rec.coeffsB64.length < 1 || rec.coeffsB64.length > 8) return null;
	if (!rec.coeffsB64.every((item) => typeof item === "string" && item.length > 0)) return null;
	return {
		saltB64: rec.saltB64,
		coeffsB64: [...rec.coeffsB64]
	};
}
function normalizeSeal(raw) {
	const vault = vaultFromStored(raw);
	if (!vault) return null;
	const stored = vaultToStored(vault);
	const kdf = clampVaultKdf(stored);
	return {
		...stored,
		memoryKiB: kdf.memoryKiB,
		iterations: kdf.iterations,
		parallelism: kdf.parallelism
	};
}
function withoutScalar(jwk) {
	if (!jwk.d) return jwk;
	const { d: _scalar, ...rest } = jwk;
	return rest;
}
/** Public config. A seal stays in lexis.seal.json, never beside the public key. */
function exportedConfig(profile) {
	if (!profile.seal) return profile;
	const identity = profile.identity ? {
		...profile.identity,
		privateJwk: withoutScalar(profile.identity.privateJwk)
	} : profile.identity;
	return {
		...profile,
		identity,
		seal: null
	};
}
function isOuter(value) {
	return value === "tcp" || value === "tls" || value === "ws" || value === "wss";
}
function normalizeOuter(raw) {
	const base = defaultProfile().outer;
	return {
		transport: isOuter(raw?.transport) ? raw.transport : base.transport,
		wsPath: typeof raw?.wsPath === "string" && raw.wsPath.startsWith("/") ? raw.wsPath : base.wsPath,
		tlsVerify: raw?.tlsVerify !== false
	};
}
function normalizeIdentity(raw) {
	if (!raw || typeof raw !== "object") return null;
	if (!raw.publicJwk || !raw.privateJwk || typeof raw.publicRawB64 !== "string" || !raw.publicRawB64) return null;
	return {
		id: raw.id || newId("id"),
		name: raw.name || "本机",
		publicJwk: raw.publicJwk,
		privateJwk: raw.privateJwk,
		publicRawB64: raw.publicRawB64,
		fingerprint: raw.fingerprint || ""
	};
}
function normalizePeer(raw) {
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
		targets: Array.isArray(raw.targets) ? raw.targets.map((item) => String(item).trim()).filter(Boolean) : []
	};
}
function normalizeExpose(raw) {
	const row = raw && typeof raw === "object" ? raw : {};
	return {
		id: row.id || newId("expose"),
		name: String(row.name || "").trim() || "服务",
		host: String(row.host || "127.0.0.1").trim(),
		port: clampNum(row.port, 1, 65535, 22),
		allow: Array.isArray(row.allow) ? row.allow.map((item) => String(item).trim()).filter(Boolean) : []
	};
}
function normalizeReverse(raw) {
	const row = raw && typeof raw === "object" ? raw : {};
	return {
		id: row.id || newId("rev"),
		listen: String(row.listen || "127.0.0.1").trim(),
		port: clampNum(row.port, 1, 65535, 2222),
		peer: String(row.peer || "").trim(),
		service: String(row.service || "").trim()
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
	const protocol = raw.protocol === "tcp" || raw.protocol === "tunnel" || raw.protocol === "http" || raw.protocol === "transparent" ? raw.protocol : "socks";
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
function frameOf(base, raw) {
	const policy = raw?.smallFramePolicy === "honey" ? "honey" : raw?.smallFramePolicy === "expansion" ? "expansion" : base.smallFramePolicy;
	return {
		maxExpansion: clampNum(raw?.maxExpansion, 1, 16, base.maxExpansion),
		smallFramePolicy: policy,
		coalesceTarget: clampNum(raw?.coalesceTarget, 64, 4096, base.coalesceTarget)
	};
}
/** Same charset heuristic as the resident agent. Not a cryptographic entropy estimate. */
function estimateTokenBits(token) {
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
function mintHandshakeToken() {
	const raw = crypto.getRandomValues(/* @__PURE__ */ new Uint8Array(16));
	let s = "";
	for (const b of raw) s += String.fromCharCode(b);
	return btoa(s).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/g, "");
}
function profileIssues(profile) {
	const issues = [];
	if (profile.role !== "edge" && profile.role !== "gate") issues.push("常驻进程不接受缺省角色。写成 edge 或 gate");
	const statusHost = profile.statusHost.trim().toLowerCase();
	if (!(statusHost === "127.0.0.1" || statusHost === "::1" || statusHost === "localhost") && !profile.statusToken.trim()) issues.push("状态页不在回环上，要填状态口令，否则指标和页面会拒绝");
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
	const joined = profile.peers.length > 0 || profile.inbounds.some((item) => item.protocol === "tunnel") || profile.reverses.length > 0 || profile.exposes.length > 0;
	if ((joined || profile.role === "gate" || profile.peerEndpoint) && !profile.identity) issues.push("常驻转发要有本机身份。在节点页把一把密钥写成常驻身份");
	if (joined && estimateTokenBits(profile.link.token.trim()) < 128) issues.push("常驻握手口令熵不足（需要至少 128 bit）。用「生成 128 bit 口令」，两端写成同一个。不要用手写短口令");
	if (!profile.outer.tlsVerify) issues.push("没有校验证书。正式部署请换成自己的证书并打开校验");
	if (profile.inbounds.some((item) => item.protocol === "tunnel") && profile.peers.length === 0) issues.push("隧道入口还没有对端公钥，握不上手");
	for (const peer of profile.peers) {
		if (!/^.+:\d+$/.test(peer.endpoint)) issues.push(`${peer.name} 的地址要写成 主机:端口`);
		if (peer.publicRawB64.length < 16) issues.push(`${peer.name} 缺少公钥，不能加入词表握手`);
	}
	if (profile.inbounds.some((item) => item.protocol === "tunnel") && profile.peers.length > 0 && !profile.peers.some((peer) => peer.exit)) issues.push("隧道入口还没有节点被允许把本机当出口");
	for (const door of profile.exposes) if (!door.allow.length) issues.push(`${door.name} 没有写允许访问的节点`);
	for (const door of profile.reverses) {
		if (!door.peer || !door.service) issues.push("反向入口要写节点和服务名");
		const host = door.listen || "127.0.0.1";
		if (!profile.link.allowLan && host !== "127.0.0.1" && host !== "::1") issues.push("反向入口写了非回环地址。没有允许局域网时会改绑回环，避免把后面的服务公开");
	}
	if (profile.socksAuth.user && !profile.socksAuth.pass || !profile.socksAuth.user && profile.socksAuth.pass) issues.push("SOCKS 用户名和密码要一起填，或都留空");
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
function persistedProfile(profile) {
	if (!profile.seal || !profile.identity?.privateJwk.d) return profile;
	const { d: _scalar, ...privateJwk } = profile.identity.privateJwk;
	return {
		...profile,
		identity: {
			...profile.identity,
			privateJwk
		}
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
	partialize: (state) => ({ profile: persistedProfile(state.profile) }),
	merge: (persisted, current) => {
		const saved = persisted;
		return {
			...current,
			profile: normalizeProfile(saved?.profile ?? current.profile)
		};
	}
}));
/**
* T21: X25519 ephemeral keys whose public value is sent as an Elligator2
* representative (32 bytes indistinguishable from uniform).
*
* - Keys are "dirty": pub = clamp(seed)*B + T with T a random point of order
*   dividing 8, so the decoded point is not always in the prime-order subgroup
*   (a clean X25519 key would be a distinguisher). The clamped scalar is a
*   multiple of 8, so X25519 shared secrets are unchanged.
* - Both inverse branches are used at random, so the forward map's square/non-
*   square branch is balanced.
* - The forward map is cross-checked against @noble/curves'
*   RFC 9380 map_to_curve_elligator2_curve25519 in elligator.test.ts.
*/
var Fp = ed25519.Point.Fp;
var p = Fp.ORDER;
var A = 486662n;
var N = ed25519.Point.Fn.ORDER;
var T8 = ed25519.Point.fromHex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a");
var HALF = (p - 1n) / 2n;
function leBytesToBig(b) {
	let x = 0n;
	for (let i = b.length - 1; i >= 0; i--) x = x << 8n | BigInt(b[i]);
	return x;
}
function bigToLe(x, len = 32) {
	const out = new Uint8Array(len);
	for (let i = 0; i < len; i++) {
		out[i] = Number(x & 255n);
		x >>= 8n;
	}
	return out;
}
function isSquare(x) {
	if (x === 0n) return true;
	return Fp.pow(x, HALF) === 1n;
}
function clampScalar(seed) {
	const s = seed.slice();
	s[0] &= 248;
	s[31] &= 127;
	s[31] |= 64;
	return leBytesToBig(s);
}
/** Representative (32 bytes, top two bits ignored) -> Montgomery u (32 bytes LE). */
function elligatorMap(rep) {
	const r = leBytesToBig(rep) & (1n << 254n) - 1n;
	const den = Fp.add(1n, Fp.mul(2n, Fp.sqr(Fp.create(r))));
	const w = Fp.neg(Fp.mul(A, Fp.inv(den)));
	return bigToLe(isSquare(Fp.add(Fp.mul(Fp.sqr(w), Fp.add(w, A)), w)) ? w : Fp.sub(Fp.neg(w), A));
}
function rand$1(n) {
	return crypto.getRandomValues(new Uint8Array(n));
}
/** Retry until the dirty public key is representable on a randomly chosen branch. */
function elligatorKeyPair() {
	for (let tries = 0; tries < 256; tries++) {
		const seed = rand$1(32);
		const s = clampScalar(seed);
		const extra = rand$1(2);
		const k = BigInt(extra[0] & 7);
		let Pe = ed25519.Point.BASE.multiply(s % N);
		if (k > 0n) Pe = Pe.add(T8.multiplyUnsafe(k));
		const y = Pe.toAffine().y;
		if (y === 1n) continue;
		const u = Fp.mul(Fp.add(1n, y), Fp.inv(Fp.sub(1n, y)));
		if (u === 0n || u === Fp.neg(A)) continue;
		const rad = extra[1] & 1 ? Fp.neg(Fp.mul(u, Fp.inv(Fp.mul(2n, Fp.add(u, A))))) : Fp.neg(Fp.mul(Fp.add(u, A), Fp.inv(Fp.mul(2n, u))));
		if (!isSquare(rad)) continue;
		let r = Fp.sqrt(rad);
		if (r > HALF) r = p - r;
		const top = BigInt(extra[1] >> 6) << 254n;
		const rep = bigToLe(r | top);
		const pub = bigToLe(u);
		if (!elligatorMap(rep).every((b, i) => b === pub[i])) continue;
		return {
			seed,
			rep,
			pub
		};
	}
	throw new Error("elligator key generation failed");
}
/** X25519 with our seed and the peer's representative. */
function sharedFromRep(seed, peerRep) {
	return x25519.getSharedSecret(seed, elligatorMap(peerRep));
}
/** X25519 with our seed and a raw 32-byte peer public key (long-term or mapped). */
function sharedFromPub(seed, peerPub) {
	return x25519.getSharedSecret(seed, peerPub);
}
/**
* HCTR2 (Crowley, Huckleberry, Biggers 2021) over AES-256: a tweakable,
* length-preserving wide-block SPRP. Built only from @noble/ciphers' audited
* AES block function and POLYVAL; checked against google/hctr2 official vectors
* (hctr2.test.ts). Minimum message length is one block (16 bytes).
*/
var BLOCK = 16;
function block(src) {
	const out = new Uint8Array(BLOCK);
	if (src) out.set(src.subarray(0, BLOCK));
	return out;
}
function aesEnc(k, input) {
	return unsafe.encryptBlock(k.enc, block(input));
}
function aesDec(k, input) {
	return unsafe.decryptBlock(k.dec, block(input));
}
function hctr2Key(key) {
	if (key.length !== 32) throw new Error("HCTR2 needs a 32-byte AES-256 key");
	const k = {
		enc: unsafe.expandKeyLE(key),
		dec: unsafe.expandKeyDecLE(key),
		h: new Uint8Array(BLOCK),
		L: new Uint8Array(BLOCK)
	};
	k.h = aesEnc(k, new Uint8Array(BLOCK));
	const one = new Uint8Array(BLOCK);
	one[0] = 1;
	k.L = aesEnc(k, one);
	return k;
}
function le128(n) {
	const out = new Uint8Array(BLOCK);
	let v = n;
	for (let i = 0; i < 8 && v > 0; i++) {
		out[i] = v % 256;
		v = Math.floor(v / 256);
	}
	return out;
}
function padTo(data, mult) {
	const len = Math.ceil(data.length / mult) * mult;
	const out = new Uint8Array(len);
	out.set(data);
	return out;
}
/** H_h(T, N): POLYVAL over tweak-length block || pad(T) || pad'(N). */
function hash(k, tweak, n) {
	const full = n.length % BLOCK === 0;
	const lenBlock = le128(2 * tweak.length * 8 + (full ? 2 : 3));
	let tail;
	if (full) tail = n;
	else {
		const t = new Uint8Array(n.length + 1);
		t.set(n);
		t[n.length] = 1;
		tail = padTo(t, BLOCK);
	}
	const msg = new Uint8Array(BLOCK + padTo(tweak, BLOCK).length + tail.length);
	msg.set(lenBlock, 0);
	msg.set(padTo(tweak, BLOCK), BLOCK);
	msg.set(tail, BLOCK + padTo(tweak, BLOCK).length);
	return polyval(msg, k.h);
}
function xor(a, b) {
	const out = new Uint8Array(a.length);
	for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
	return out;
}
/** XCTR: block i (from 1) = E_K(S xor LE128(i)). */
function xctr(k, s, data) {
	const out = new Uint8Array(data.length);
	for (let off = 0, i = 1; off < data.length; off += BLOCK, i++) {
		const ks = aesEnc(k, xor(s, le128(i)));
		const n = Math.min(BLOCK, data.length - off);
		for (let j = 0; j < n; j++) out[off + j] = data[off + j] ^ ks[j];
	}
	return out;
}
function hctr2Encrypt(k, tweak, plaintext) {
	if (plaintext.length < BLOCK) throw new Error("HCTR2 input shorter than one block");
	const m = plaintext.subarray(0, BLOCK);
	const n = plaintext.subarray(BLOCK);
	const mm = xor(m, hash(k, tweak, n));
	const uu = aesEnc(k, mm);
	const v = xctr(k, xor(xor(mm, uu), k.L), n);
	const u = xor(uu, hash(k, tweak, v));
	const out = new Uint8Array(plaintext.length);
	out.set(u, 0);
	out.set(v, BLOCK);
	return out;
}
function hctr2Decrypt(k, tweak, ciphertext) {
	if (ciphertext.length < BLOCK) throw new Error("HCTR2 input shorter than one block");
	const u = ciphertext.subarray(0, BLOCK);
	const v = ciphertext.subarray(BLOCK);
	const uu = xor(u, hash(k, tweak, v));
	const mm = aesDec(k, uu);
	const n = xctr(k, xor(xor(mm, uu), k.L), v);
	const m = xor(mm, hash(k, tweak, n));
	const out = new Uint8Array(ciphertext.length);
	out.set(m, 0);
	out.set(n, BLOCK);
	return out;
}
var STATE_WEIGHTS = "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";
/**
* English vocabulary, top 32768 alphabetic tokens by frequency.
* Adapted from FrequencyWords by Hermit Dave, https://github.com/hermitdave/FrequencyWords
* (content/2018/en/en_50k.txt, OpenSubtitles 2018 counts).
* This file is licensed CC BY-SA 4.0 (https://creativecommons.org/licenses/by-sa/4.0/);
* full text in vocab-en.LICENSE.txt, attribution and modifications in vocab-en.NOTICE.md.
* Modifications: filtered to [a-z]+, deduplicated, top 32768 by count, descending order.
*/
var VOCAB_WORDS = "you i the to a it and that of is in what we me this he for my on have your do was no not be are don know can with but all so just there here they like get she go if right out about up at him now oh one come well her how yeah will got want think as see did good who why from let his yes when going time an okay back look us would them where were take then had or been our gonna tell really man some say hey could didn by need something has too more way down make very never only people over because little please love should mean said sorry give off am thank any two even much doing sure thing these help first into anything still find life nothing sir day god work their uh again maybe must before other wait stop call after won talk away than thought home night put great those last better everything told new things always keep long years leave does money around doesn name place ever feel guys father guy made old isn which big lot done hello nice believe girl someone fine thanks wanted kind coming house every ok through being course stay left dad enough happened came may mother wrong world bad might three today listen another understand hear remember ask own same show else kill talking found next getting care car looking son try woman went hi dead many mind wasn friend best mom hell morning trying boy together yourself job saw family real without baby room wouldn already move most seen live miss actually huh shit both heard once ready head called used idea knew hold happy door such fuck brother also pretty bit took haven yet men whole start use while since wife days guess tomorrow matter meet bring tonight everyone run wanna hard ah alone myself school gone um end saying phone play looks couldn fucking problem few friends gotta ago open anyone killed hope face until lost police excuse turn business case wants says true die heart soon each worry later year watch music hand having probably beautiful doctor sit eat thinking young second working water person part kids late stuff exactly under death minute pay crazy forget everybody kid change gave happen damn five drink far knows its whatever eyes shut aren hit taking easy times check hands minutes deal different means point inside makes asked somebody mine making body afraid sleep chance dear quite four anyway close ain party fun against word comes important set shall story number daughter least waiting hurt wish moment fight week husband girls rest married fire game nobody mr children side stand read though cut started sister supposed between child goes hours speak women behind almost truth blood able lady anymore playing gets shot reason trouble break war city walk town trust met office question brought yours welcome high wow couple half died cool free either seems power whoa bye buy telling honey tried front team answer gun boys line send news stupid bed hurry full months save sometimes become along hate food outside light l needs dog country clear order em fact lord captain six hot funny black alive pick feeling living cause ahead lose king plan dinner sighs sort leaving shouldn running boss alright promise taken safe ma book sent white hour anybody small perfect lives special parents s john himself perhaps sounds serious sick company ha scared uncle poor red past earth possible shoot touch sound top ass laughs cannot asking win glad control hmm human drive hair jack bitch luck murder happens air ten daddy finally chuckles fast cold seem laughing words hospital street hang dance meeting till others catch follow sense sex lie evening master known dream write million voice sweet rather felt sign lucky somewhere bet o jesus longer calling worked quiet looked less pull beat careful coffee return secret weeks weren date seeing fall given ooh fault straight takes song future gentlemen loved changed road calm wonderful mad turned drop ladies learn step absolutely early explain clean piece yesterday throw picture land feet wonder questions speaking worth darling dude giving president eye quick moving figure state strong sam none amazing ones works act needed weird law worried report goodbye missing choice happening chief wedding strange general pain kidding decided ya pass tired class officer kept wake worse busy eh mistake kiss court building finish during age ship caught marry meant sell dark watching system suppose evidence movie ride t completely mouth totally birthday tv forgive born imagine information instead definitely security certainly film month lying unless train seven wear clothes michael hotel christmas attack hasn round expect sing terrible george bag history blue near broke station seriously forever david frank except thinks message entire joe table talked across rock lovely handle middle buddy paid protect using floor ran swear spend situation ring anywhere dangerous bill york army lead bought finished fair sun letter fool attention club simple interesting space test box group single sitting marriage join fear d peace forgot force short normal charlie present enjoy mike crime horse ground american count area charge honor lunch miles radio idiot ball surprise paper key boat quickly gold bar fish mark tom wearing crying accident government eight fell cover certain interested deep star sea agree problems detective prison major stick offer difficult smart personal record stopped hide whether bank trip relax america public list afternoon brain fix bastard proud tea service screaming forward angry park soul fighting peter rich agent blow paul dress mary missed scene killing standing saved mm respect killer ice mess tough feels church sad cell drunk share camera within card fly ben girlfriend laugh smell broken mum honest often starting calls y spent third english visit mama judge window hungry dare relationship moved prove private wall seat position lieutenant realize lt especially machine walking art pleasure bloody college french involved cry became lived impossible obviously neither accept boyfriend besides queen teacher cops sake loves carry teach apartment upset green la liked cute evil professor contact joke cop huge holy store jail likes lawyer doubt continue appreciate cat shop driving congratulations wrote village quit field james wine decision south sleeping slow laughter island glass beginning cash dying hundred whose difference plane push continues mmm singing eating north mrs tree madam gift truck putting bear board grab beer stuck magic support rules grunts partner reach wind colonel max immediately seconds thousand gives experience cheers victim upon computer christ planet promised bus henry dirty search staying dreams arrest holding suddenly usually lots shoes er jump rid yo knock owe harry grow worst river aunt patient kitchen aah fat passed m final summer bob listening escape everywhere moon arms turns address ow match gasps grand yep shh nervous de choose themselves decide mate drinking press bother foot hadn blame crap drugs type rings mission named heaven picked paris race risk books further danny action allowed orders learned price arrived nick otherwise pictures fit smoke favor played notice awesome smile director guard begin spot surprised innocent narrator herself london feelings enemy battle ourselves alex dollars allow nine gay department guilty apart earlier duty jim suit bell west legs hero destroy stage bunch according chicken bigger grunting low helping admit closed names witness upstairs arm steal jimmy kick twice cross ways sergeant indeed gas keeping energy pregnant waste helped fired favorite tony taste locked places writing adam brothers starts prince form sold silly mention build throat hole figured track ringing lock leg above hiding steve seemed breakfast engine written complete video applause however pressure fresh weapon sky stole study burn reading crowd treat roll double spirit danger cost empty level memory itself acting interest nose plans following bathroom built closer ray sarah band groans apparently excited richard losing animals flight nature raise pop client bomb neck suspect warm extra bottle van heavy mommy dogs wild ridiculous simply lee animal showed billy shooting keeps camp guns medical shame hoping whom bird majesty flowers famous asleep beauty driver keys rain awful large local deserve goddamn stone jane grace consider weekend wondering lay plenty willing pants sweetheart skin excellent asshole beach c faith beg fuckin responsible military cheering opportunity common bottom german whoever cook walked papers justice hall commander drug main knife devil necessary although princess lights flying dick rose knowing clearly hat agreed johnny corner code note tommy due correct apologize language stars faster cars folks bullshit fellow several grandma shows leader leaves restaurant east shouting blind ghost cup gotten tight conversation tells lies nor pulled hanging speed stories health advice held murdered beyond rule hardly possibly inspector cousin trial emergency ought eddie somehow hearing states account spoke file understood angel tape milk powerful weapons practice manager pardon vote jake national career minister super taught robert biggest plays natural dancing copy plus martin cake freedom among breath operation chris crew challenge market meat towards bringing dropped student lied strength size breathe color monster loud photo aw nearly sight greatest games bridge dressed arrested horrible coach planning checked breaking noticed fantastic screams serve ideas investigation center older pack soldiers nonsense doc project training example trick prepared science united travel incredible grandpa paying character teeth criminal charles chinese truly honestly bro survive bobby target feed nurse e fake records breathing sweetie numbers oil suicide belong whoo perfectly amy forgotten remain original papa onto concerned credit ugh invited discuss research easier view chair hurts strike roger fill condition mountain dr nowhere sheriff kim turning brown recognize heads audience jealous pretend society finding shirt comfortable meaning guest pieces dry letting began aye jeff female release ho cards pray unfortunately balls destroyed ended universe prepare opinion movies soldier wash program heat usual ticket stolen prefer aware surely male base matters lift lab command proof cream selling believed create h afford sunday total dumb threw france birth created realized british noise nuts students birds social brilliant bodies tie opened ours bucks kevin mister ugly ryan focus dan opens exist followed england draw purpose letters daniel opening bullet anna lately stayed falling season ends suggest joy distance responsibility whenever issue thousands process sword shower weak fucked lonely happiness eric tiny desk pool property forced settle indistinct weight received gang bite friday disappeared interview expecting kinda surgery horses mayor babe ancient handsome thomas saturday staff lines unit fan gentleman introduce fate split recently expected add ordered slowly alarm member slept signed enter spanish garden brings brave pig model finger medicine access failed flat easily discovered based screw insane cares weather fingers san scott path soft harm style community sees basically al signal nope spare speech covered shake loose snow russian lake bright roof ohh sending paint remind pal naked post sugar heading streets damage silence doors pete ed success wet nah amount members kate manage safety returned harder fbi block showing fancy chef contract dig chest drinks dave buried brian trade journey stomach changes details thoughts divorce funeral maria football reality theory gosh ruined gate william spread outta japanese sudden coat sooner cheese larry spring page ears simon castle hidden storm cos personally artist hill exciting permission jerry expensive tickets forest barely eggs goin regret lesson lover bread andy subject legal growing ill jason mood owner caused beeping points dating loss secretary revenge santa likely rent connection assistant reasons yelling painting trees doctors rush foreign rough murderer century nights pair runs pocket farm matt bike obvious ate grew professional tim goodness parts alan university square grandfather europe genius cases ruin winter tongue memories da buying cancer clock ocean dna liar tour thief bleep lisa rights including competition smith planned emily boring victims mentioned bones plant bless warning knocking re crash bedroom lower silver groaning madame defense results toilet event complicated shape priest royal cheap romantic downstairs invite fortune tears avoid reached higher familiar telephone burning filled kelly alice airport jobs grown walter rachel giant insurance woods n scare pleased period political player stops secrets laura repeat photos finds statement suck younger china humans delicious particular proper rome belongs attacked bath hired site knowledge b led guests celebrate map horn eventually pity powers ashamed assume glasses rise fixed request officers pounds data carefully per depends jury waited positive attorney direction families doin forces location walls useless grant saving speaks fought meal deliver answers changing temple scary millions offered regular carrying official jacket switch grave chase role odd sexy faces becomes closes badly tall confused affair television shock raised panting pizza image clears golden patients watched committed sexual suffer arthur wherever plate appear chocolate clever hm mercy shots lucy dealing trap charges phil bang poison butt drove yourselves headed babies yellow soup mystery picking sat wound traffic courage hunt indian rat terms italian emma checking disease managed winner council appointment monday crack threat jenny physical nation source chose healthy carl victory rick stood kicked annie disgusting palace below shopping neighborhood march lips midnight piss advantage pure india aside jerk mail dawn effect spell freak wood screwed enemies gary awake chuckling vacation violence leo grandmother modern luke firm prime heh touched talent whore piano license cooking honour concern moves available factory gods value central union mirror studio media taxi dies iron hearts desire rob claire fred songs washington monkey pride pills miracle swim burned smells joking christian bleeding hook beating protection treatment ear carter metal disappear grateful extremely treasure rescue capable passing chatter result suffering sisters laid governor guards louis text literally remove becoming performance stronger rate deeply scream desert vehicle illegal pulling throwing josh unbelievable ted zero dean curious sean candy bone tied edge load susan ahh mountains boom former holiday riding scoffs hundreds motherfucker sue bags stealing appears arrive remains decent issues tip fail bride pissed penny claim friendship desperate flower dramatic refuse solve theme loving properly dragon mostly chuck directly surface false cast junior hunting silent thou egg germany punch africa woke intelligence borrow winning falls popular escaped witch convinced warn announcer champagne dust kyle someday fallen stranger presence tear internet monsieur therefore technology tires toast wise clark americans notes smoking hank ls april wolf precious rooms coast treated material released uniform hated considered rice exchange steps blake convince beast cow files signs drag cab hung carried ordinary successful eve mistakes houses chattering brains japan creature fourth separate cleaning california lf ll shift elizabeth chicago exact karen goal expert served direct score row marks twenty receive series section pilot jackson darkness thy sale destiny cure spoken armed rare helen grade juice wide tower solution schedule explosion wheel cigarette julie fruit blew victor talks sacrifice range button reports prisoner pie effort youth pot eaten taylor knees garage parking ambulance staring chances circumstances sin gordon progress unusual county stairs campaign vision reporter equipment moments joey mass alien trapped helps route defend trace nasty tests magazine rocks dump rude searching clue connected amen pushed merry zone senior closing freeze emperor incident snake mexico lily actor newspaper sentence greg leading friendly jones chosen engaged julia charming mustn anger spending learning spy sharp shadow warrant elevator kingdom ricky jamie squad shoulder wave amanda highness kinds fishing sometime attitude sucks negative screen workers bored cameras similar understanding beeps chain bull gasping fully robin collect gorgeous morgan passion writer empire international curse hire bastards puts leads id blows sons estate customers maggie gunshot device troops hug design movement thunder object loser pen sobbing politics despite alcohol climb clients conference provide marty seek witnesses earn trash valley fashion howard episode prize previously sports wanting debt wishes hitler wire thee circle approach stock facts remembered percent normally tail joined education bravo library rape wings growling thrown tank exhales authority current failure nightmare hitting glory knocked studying barry agency apple border rope duck reputation confidence yard beloved lack actual skills films mental salt flesh anne secure highly federal sand emotional setting nothin senator services robbery hates fed reward theater johnson commit patrick entirely extraordinary ships opposite parties stands terry chat events mummy bay slip disappointed settled begins andrew alert detail pink fellas accepted background garbage panic minds belt blowing hollywood agreement jackie pushing ability tiger whispering culture saint jesse task solid doll intend district pa gee custody ignore naturally useful attempt abandoned cutting kissed guarantee barking gather policy violent maid embarrassing childhood wasting bow chick sara disaster revolution online f demon heavily coincidence perform thin terrific mac crown identity virgin impressive windows potential guitar committee dozen delivery advance quietly stan teaching hunter latest hurting swing capital counting drew dirt whistle marie hits doug deny urgent threatened behavior molly mixed stays assure subtitles explanation wins unique chasing billion duke production slave agents carol lets cruel mask sally behave bury massive pathetic species approaching jo loan struggle dish trusted jumped firing channel abby stopping asks jean swimming daily basement linda quarter erm bound navy article guide accused transfer guts quality fella roman greater damned couch cheer vegas shoe title shy punishment los clicks closet fever coward flash impressed bruce siren prisoners sides bowl katie supply sensitive hopefully rolling roy dollar tone voices g cheating confess demand museum unknown drama suspicious adult todd frightened warned steady kills crossed lou particularly sandwich laws joint bullets package trained thursday boots possibility albert civil june germans baseball express miserable tuesday parker lion joseph refused shine assault hong jokes breaks argue trail option recall mighty collection oliver wilson accent believes decisions embarrassed mobile customer terribly sec charity considering pussy donna protecting flag kidnapped italy balance creatures nuclear wallet shout vincent entered impression angela jay degrees favour reaction network jessica version concert gear singer diamond defeat steven lane blast wounded anytime partners ages charlotte ceremony league bars orange specific conditions plastic crisis fifth term self offering bud suffered reported commissioner rip mysterious entrance messed tunnel designed neighbor aboard sweat justin ghosts crimes costs deserves dreaming bust el teddy kong messages enjoying afterwards comfort mason surrender gym kitty crush yup arranged suits pee stress cave wing jordan arrange comrade noble tricks betty launch legend mix golf imagination fox kissing butter tax gross edward texas insist marcus classic selfish skull frankie shown bat survived print champion bills therapy lifetime throughout nathan toward sauce experiment margaret describe ross grass cheat attend homework lewis betrayed servant cap tyler bible practically catherine steel wipe burns j generation cabin financial industry bond sheep scientists beaten heck deck fans script brand degree painful coughing religion cats stephen influence fuel drawing rabbit exercise attractive touching virus realise torture blessed plain rebecca recent barbara footsteps sacred removed pretending wasted jewish goodnight robot crystal confirm lad mile division scratch reminds walks ending russia contest valuable distant dumped motion electricity centre murders tina jeremy seal standard ellen wore surrounded struck inform gentle status purse prints players charged begging delivered kenny buck nina construction confirmed confession trigger cells frankly ali exit response cancel argument principal turkey lucas clinic greetings neighbors vice toy hannah everyday generous gain idiots holly enjoyed jungle link underground smiling mistress teams product beef whispers religious presents identify chip chffffff surveillance carlos vampire routine uses michelle underneath systems temperature waves tribe brad deputy sophie headquarters equal phones ken reckon related incredibly chill spit tracks oscar makeup bug sounded spirits nerve divorced stake port doorbell worries nephew miller units proceed landing traitor outfit chloe bail fields patience recording foolish loaded tokyo davis costume wayne injured somethin ian pet cage digging spain seats awkward cleaned pattern filthy visiting jews answering concentrate someplace citizens aim nancy affairs thick sport basic electric pleasant cliff nail russell environment western average ease raped interrupt judy satisfied beep starving documents anniversary beth election warrior r forth fetch banks placed timing stones complex frozen replace prayer skip angeles guilt tune woo actions conscience officially martha machines smaller determined blown hail unhappy booth pour berlin cleared packed wrap randy behalf reasonable trunk homes festival tradition cigarettes le beside harvey motive beings bishop dealer defendant backup wounds ouch ann nearby drank effects jonathan dennis benefit adventure p territory ve apology dylan unlike owns boxes thus clay developed busted pipe gray goods favourite salad loyal atmosphere eva freaking dropping strangers mouse downtown francisco heroes pit rotten paradise meantime jess organization hills exam cock fairy earl comment activity frame knight testing habit shelter flow jennifer holes prevent anthony lend cooper figures boston sample strip landed buzzing monk slightly produce annoying judgment laundry ron lousy souls existence belly tries foster returning answered ward plants actress chairman individual hopes tattoo fence sink punk confident yay mistaken limit bothering st uncomfortable wednesday gifts policeman na precisely lawyers greek merely criminals underwear hoped earned reveal appeared derek heavens personality batman virginia wives colour worker pope instructions intelligent worrying vince comin cried traveling bells x impact robbed relief host footage odds patrol circus mud captured lessons occasion sets pulse ad invented diamonds matthew auntie cloud francis angels hers classes signature complain blah monitor options claims flies pat britain hid wailing listened countries vic yell rats wondered smooth resist companies fantasy passport pitch hammer homicide casey holds flew jacob noon helicopter dishes spin charm slap apply fools screeching discover previous kit authorities moaning photograph sales fifty mickey beneath farewell clouds slipped represent deaf facing offense citizen clown snap messing hood twelve interests cheated liz informed humanity producer technically accounts extreme gettin cia ii pays profile oxygen jeez gene shed minor ex theatre scientific lovers chaos rocket math stubborn august oi chips intense grey talkin terrorist angle invitation gus gambling respond thirty procedure absolute investigate tragedy stable session capture marrying ripped attacks stretch bush dates unable gates mars artists increase tastes cared bottles highest whirring meanwhile nate grabbed pigs chop olivia wheels shocked reverend commercial escort engagement corpse louise worthy scale beats williams threatening exists academy acts hop judges furniture shared ralph consequences engineer schools softly bombs caroline shark transport population succeed creepy sneak studies destruction keith protected monsters joining punished lightning malcolm shell fascinating chamber ethan romance instance jumping groups exhausted testify studied walker pin imagined drill investigating ye experienced elena necklace loyalty junk cole cries stanley rita southern blocks emotions begun maya liver serving matches surgeon granted jazz july supplies deeper typical kicking obey dancer remote daughters moron latin teachers toby sandy dragged strategy parent jin album compared rubbish helpful powder sync bum passes joan fort choices alley supper penis alibi sammy pole coke scientist fighter highway blade alpha diet liquor jet widow liberty philip moral carrie award grief thirsty ashley random suspects intention julian active tools driven trauma headache safely alexander knee lads novel conversations waters lookin invisible internal peaceful humming washed drives talented li aid elephant troubles core serial painted divine jam goat opera thieves guessing objection whiskey florida resistance dressing attached aaron brief punish eternal lois required victoria fabulous twins characters cooked ln ruth dreamed arts naughty stabbed tend diane tap soap locker development images prick global string bitter sharing corn craig fits tent forms votes harold propose monica constantly granny nicely nerves arguing abuse relatives survival gloves tracking zoe u bend review connect separated elder beard admiral diana salary areas disturb pro maintain solved wealth bitches possession sang gimme plates shoulders burnt recorded upper counts tale profit colleague warehouse hostage shore porn miami fifteen visitors bo net insult owen cities causing lemon heal banging honeymoon appeal marshall critical creating scotland crane enormous testimony praise fights indians commission growls nicole sins fraud branch happily bout covering occurred beans raw muscle pages tense relationships management assignment blonde catching exposed canada dont han von comedy marco stroke whistling buildings shaking facility appropriate remarkable transferred drawn tits clicking symbol motor employees ambassador mothers pile feeding soda checks bears cookies slut awfully stepped toys levels differently magnificent steak tube leaders superior herr pan expression currently throne deadly bee tooth depressed potatoes wicked resources native centuries karl poetry multiple cable shortly buzz socks fingerprints goddess chin anxious september colors basketball promises explained appearance musical sends slide aii shawn ultimate pork communication payment structure paperwork obsessed lazy russians actors squeeze magical colleagues admire madness roads entry injury burden racing manner freezing bits norman mount battery dessert pound visited motel rumbling cinema fond halfway rifle reception statue fridge brick abandon lap natalie wars recommend brush nelson pill concept w delay quarters korea janet rub mall soil complaint sail baker coughs bucket description badge measure hip function indistinctly harris foundation labor willie waiter homeless proved unfortunate log meetings giggles combat poem polish handed mia weed raymond tons satellite jersey eagle privacy chapter treating wisdom flip entering barn farmer clan budget pub temporary effective sonny wendy juan lamb plot riley proposal sticks searched blessing rage bothered sydney basis manners recover twist neil leak item catholic sighing retired kings inner cents affect forbidden patch drops necessarily provided meters booked returns gloria fires humor torn rocky introduced creative betray soviet various added discovery cowboy suspected suggested delighted sticking dive shane radar prosecutor amber vast quinn owned cookie finest felix pump valentine counter sorts coin warren slaves marine illness sack bid require moscow largest washing achieve causes k mo dope nest palm logan constant boo medication gravity booze noah evan abroad christine rising analysis cuts eats employee vodka damaged solar height pops yards terrified suitcase chemical preparing advanced fund wears chirping web phase prom suggesting fleet lame irish editor october assumed whip mel region amongst temper discussion engines operate sunshine acted undercover horror tested smash contrary roses poker wrapped korean graham mi fu ivan focused liam tragic carla demons rounds entertainment gathered uhh yells lincoln crossing blanket nut travis pockets limited paintings sober caesar sis intended niece computers tennis needle chicks traditional delicate independent leslie lauren grandson repair brandon executive colin recognized holmes regarding weakness aliens gunshots european method tool demands permit towel daisy nowadays spider northern rangers zoo praying antonio passengers con australia technique cellphone gently operations planes bunny gunfire shining backwards skill baron kidnapping iike marshal petty sealed massage raising menu diary fucker wagon audition mitch mexican casino bacon diego dutch promotion click forgiveness burst permanent interfere chanting dammit spencer recovered registered sunny packing scenes superman questioning unfair admitted ancestors polite completed swallow conduct prayers sheet fried avenue poisoned reverse newspapers ford complaining senses investment absurd potato understands grows inspired ruby celebrating tag ram requires bonnie bugs leonard elliot hooked jill ranch safer worn crashing lands heather ash leather grounds assuming nails dana conspiracy thanksgiving pierre guardian rumors yen megan ashes terror misunderstanding tire boats parade halt immunity adults steam kang closely pearl soccer adrian priority shouts donald happier khan struggling root larger november boot conflict laughed debbie cherry honking concerns celebration sore unconscious cattle breasts fairly fee recognise wade radiation holidays raining forgetting lungs register shadows specifically sarge ideal turtle spoil deserved ronnie gina candidate lance types bloke explode immediate belonged identified di hunger closest combination nanny seth gabriel develop detectives severe en organized franklin gut splendid dismissed pm yang halloween ellie vulnerable continued vital comrades bureau drawer harper retreat carson benny pillow troy ace cart nap chan ham announce borrowed parked galaxy voted muffled sebastian jewelry kisses luggage groom oops lighter masters alliance buddies clothing denied drown alike excellency relative photographs burger dough alicia wreck approve produced christina physically stations eli samantha spiritual sire roaring stab inch servants limits unexpected arrival whimpering basket sheets scandal stink homer tara christopher toes shield shooter instant objects rehearsal disturbing directed scan electronic republic overnight counsel sirens dorothy bait dignity explains lean heroin tracy rex barney gossip humble economy worlds impress clara tissue threaten et bump supreme bingo mitchell excitement mankind document broad vietnam vessel lit dale killers connor mario foul stare deaths hut elements coma laying coffin paula cocaine puppy louder handled announcement oath mob cotton deposit taxes injuries jen autopsy advise gig lecture posted skinny lo include revealed infected relieved assistance solo determine terrorists elsewhere lamp practical marked adorable rubber purple operating suite apologies personnel beam poet samples arrow counselor carpet allen audrey spotted floating corrected located journalist insisted operator rely singh fooled arrives leon walt eastern ay shave remaining toss anderson lip acid nora si december anonymous inn planted oldest breast sixth error reporting egypt islands jules roommate sings scum visitor giggling described geez inches commitment hercules react cows protest misery theft embrace darn harsh andrea communicate fathers faithful hector flame medal silk photographer trevor cemetery rear freddy banana allison emotion chap dated excuses shitty bin jew gum crushed efforts content corporal realised del rap hopeless debate era luckily ton liquid swell peggy feast murphy attracted application profession bench vanessa ahem symptoms scout crashed keen aircraft formed hon aggressive pale significant duncan clubs visual embassy defence cabinet display fame gibbs drowned wolves filming dunno cursed twin sorrow vault defeated watson quote penalty bargain pepper speaker compare satan helmet scar copies fuss envelope perry stinks african arrangements wished honored believing discussed assigned rosa oven jenna attacking tin sonic collar mere romeo belief storage rusty psycho climbing melissa fears sum dedicated ladder alternative raid dining ms corporate folk jon replaced bailey un heels duties smarter existed surprising chess requested cruise primary rhythm drum models motorcycle adopted barrel cargo planets shove wha surprises rosie dings trailer cannon tables arse ally lawrence wee tapes dull sandra teenage kent cooperate risks dug worthless arriving kindness ties items grip relations rumor skirt frog paige lloyd claimed perfume instrumental flames association loses january spike israel eleven gallery ginger activities iraq boarding fist stuffed improve creation connie infection strikes wiped tension whistles kindly certificate curtis bold threats claudia sid twisted suspended affected envy whale dial cameron martial controlled lung nigga coal upside imperial pam paranoid signing congress villa candles filling becky comic faint recovery volunteer tech bleed positions cindy narrow forbid stuart perspective faced neat pierce observe cycle psychic handling goose accidentally conclusion designer sits importance spots francs sweep destroying communist blackmail pacific risky glorious filed hatred cam deals pos fooling persons scotch executed brakes blank tender kurt turner tub sucker slight addition campus ritual prey graduate anyways ew fry genuine ned judging doubts warden ceiling practicing somewhat established attempted zombie generations gathering warriors mick electrical collins sobs couples depend institute miranda principle fixing therapist compete compliment worship residence democracy joel published myth helpless screwing kennedy execution appetite formal strictly sucked tanks chickens gwen technical stella rod meets shepherd brazil brutal alison vain switched chi deer brooklyn dresses retire overcome inspiration cunt benjamin nicky thrilled tae suggestion dummy sailor destination bass picnic assholes idol trucks rank denise yu veronica blocked strict hiya formula clerk samurai disturbed vera cafe wandering consciousness val nikki min bare hans caleb butcher arrangement chased ministry brandy sweater boobs locate apologise nazi parole examine trains candle prior stream passage reaching organ directions asses outer proves morris luxury pistol v losers funds sunset strings fortunately gotcha tomb freddie engineering element balloon ty broadcast spray ninja eternity handy crawl slice nations behaviour pace stiff lick concrete allah vegetables euros sausage constable spinning rolls genetic loudly marvelous subway creep scheme performed plug rejected brenda respected backs protocol muscles kidney finishing products im wu invasion affection woody endless discipline horns absence waking dudes philosophy cracked nicholas reed verdict drake connections privilege anyhow scent naive daylight controls airplane values jolly swore blaring consent puzzle disagree argh winds vanished wizard ranger celebrity sniffles stores aha intentions plague farmers breeze rascal convenient bonus dong hush instinct entitled porter maurice wrist originally coins drain physics phoebe furious sniffs vampires defending sector income finn offended decides laser fled beers boxing accurate kung snakes thumb bald sharon suspicion convicted roots shares bernard jessie wang harrison blues confusing lobby recipe las winston generally seeking secretly declare freaked missile ensure tricky pointed hockey bubble contacts maximum reminded carriage curtain clues hostages circles author wallace receiving debts cellar tortured tips mates mortal reporters associate honesty laptop jung katherine rainbow seed mature deed kay expenses discussing pirate meals performing remained prostitute adams retirement platform claus erica beds writes illusion mill dealt hears tryin manhattan mole rang prosecution fatal copper troubled heir traces owners length dentist zach lesbian enterprise tournament travelling confessed roast website ja mikey flood harbor lola rory richie mansion mademoiselle auction desires bachelor haunted distracted smashed rodney scheduled negotiate champ allows shotgun nigger cocktail donkey pointing butler dizzy methods reference georgia bully lydia collapse alfred ana minimum chairs hee patty owes included carmen civilization prices wealthy bart depression tide rented bra lin fellows rot password th kirk pedro spill cured naomi hardest deceased sleepy static hawaii almighty murray offers bruno phrase disgrace sources approval turtles screech snack collected ding fur jewels jan cheek legally ditch benefits roars arnold dime domestic chuckle hack ransom chang bore muslim loads waitress nurses glenn spite rebel clearing andre fortunate survivors reply disappoint orbit expose gin austin toe sympathy intel growth psychiatrist slams encounter daphne passenger monkeys accompany hats column sigh pounding economic tales theirs brat follows spreading burt hilarious hallway hamilton exclusive chimes greet decades bowling buttons confusion thud hooker ruining dreadful collecting lions sheila douglas february elvis forty sleeps sung brass shrink zack whimpers sworn email proven tasty covers sandwiches rarely wyatt programme irene dee contacted chemistry assured applied elected subjects lust label shakespeare tan ego forgiven phoenix companion lottery worm publicity butterfly dialogue cal tremendous pervert establish dearest intimate eager se cathy atlantic contains thompson shirley bets inhales presentation allergic den wells spoiled chen accomplished repay politicians logic gratitude afghanistan exception ultimately pablo compromise majority journal signals bent dock meg essential campbell climate experiments ink magazines rivers teresa administration passionate precise lawn via jeans murmuring resort announced buddha fries capacity lena opponent chains minus caitlyn apples angie seattle aww instrument healing convention messenger explore sonia versus survivor ruled boyd clarence madison cough experts disguise archer bicycle noises inviting pregnancy declared yi vicky drums wooden innocence mouths bees creaking cloth sasha unh skies painter allies miguel pond runway robbie assist lana presented mona sickness civilian fighters facebook customs florence remembers sharks juliet shrimp tore seventh ou avoiding dawson isaac rolled championship household float chad ballet cracking raj possessed harmless curiosity vicious officials glove nearest manny begged que withdraw shocking guessed nightmares greedy forehead corps pirates rudy reservation hunters fog flu hint peanut stark gamble erin autumn bracelet contain arrogant simpson piper knocks sperm gesture materials lindsay alexis ticking standards ribs receipt regards whatsoever homeland leap targets snoring damon leaf jar brooke proposed savage caring ivy approximately kidnap carries bounce creek pony cleaner businessman lunatic unlikely gal situations colony sells choi chambers volume sweets panties respects reads seeds engage explosives stewart violet mutual lighting scores lenny savings beware stephanie educated complaints cassie doomed offensive harvest qualified relaxed cape buffalo triple fireworks palmer armor poverty leadership rode ambition cakes trousers bean melt racist bam ankle occupied nicer correctly terrifying hugh gasp villain willy marc draft factor whew countess portrait suggests font blair learnt pencil coordinates collapsed reserve jeffrey shirts umbrella stevie ta traveled auto logical chew eliminate beverly carbon cancelled crawling stepping independence medium canceled tess fanny seated upbeat asian drowning messy quest represents fletcher memorial doyle stressed bearing watches spoon cooperation tucker earthquake sailing involve houston asia spectacular reliable breach sophisticated echo indicate swamp vehicles manual elegant compound serves scares rattling pursue dreamt stefan revolutionary wa rig convincing fiona tribal cleveland lex depth blaming aids elaine wakes occur camping fart stamp kathy assassin approved crucial annual torch dallas fulfill bon resting reunion witnessed graduated sub howling clyde hospitals stall legacy otto riot shops whereabouts teenager samuel squealing mines danced crowded orleans literature morgue strongest agnes transmission panel sole sequence sexually georgie hugo denny smack congratulate anxiety choking tolerate mode communications welfare dice orphan locks settlement advertising uniforms mcgee devoted shoots principles circuit nickname dot elderman scenario choir stunt smoked isolated equally statements gil shaw lipstick courtesy hobby hesitate hatch luis sylvia phoned experiences popped quid fragile husbands fiction persuade pastor dolls pose ji ming rupees tricked ruins sadly owed importantly louie industrial musician labour evolution salute ba cent bartender calendar hal miracles balcony horny regard valerie fold organs nigel theo einstein boris suitable inaudible melody phillip movements differences barbecue trading strongly fluid scholarship translation cricket shuttle moans quicker picks murderers videos initial perimeter questioned yea cousins divided linked laboratory crab pulls landlord reggie hostile classified cultural measures update cottage backyard amateur chopper rash despair honorable shiny hawk shorts ni representative wong pouring distress tanner telegram pimp dip trophy marilyn hallelujah neal es howdy misses flush magician dynamite cuba conquer unpleasant jealousy regrets lifted increased toxic broadway sakes pudding rally needing bloom corporation buys disorder interrupting sadness needn cease barnes scoundrel sensible evans specialist dragging bribe burke bothers interrogation prescription referring knives graduation liking bubbles grid haircut regardless lodge poisoning feathers edgar software marina sophia queens oak trips scaring avery awhile sofa conscious swords instincts deliberately starve venus olive maniac psychological robinson soo belle landscape straw dam mandy sayin accuse rehab switzerland agenda glue salesman diner projects floors mainly biological sincere weigh pad swiss cue witches opposed tourists sneaking harvard spying sketch parliament behold blamed topic offices sacrificed loop drivers battles blond plead races tanya salmon bizarre rico isabel wig reaches heights possibilities wax travels confidential pursuit herd scissors cd spies exams invention explaining replacement bombing erik springs chelsea sabrina kicks integrity dash jae senate mentally flee gangster beautifully roberts slim choosing promising objective joyce altogether attract ernie melanie prep neighbours nailed briefcase buzzer quitting puppet restore dozens betting pancakes corridor embarrass visits database cheryl achieved sucking encourage grades gps barks patterns relevant mafia hudson expense intact occasionally kiddo heartbeat identical cigar billions alec gained venice classical noodles consistent clip resign insects failing organic seize charging mug iris crow ella fountain observation abortion railroad straighten legitimate sting youngest fork du flynn ciao coroner jonas marching touches jade feared griffin expedition forcing neighbour digital deeds milan bernie attic jr whores sentimental cooler eun bert feds reese plea polly metres harmony difficulty bands dried aunty maker randall supporting brake girlfriends features photography vengeance inappropriate vacuum throws kane residents endure substance corrupt potter investigator thread priests gap whining scarf institution immortal marsh chapel desperately accidents alcoholic fabric nazis railway sal dame rebels custom pension cans possess kira poster developing addict feature cope lords delightful wrestling rio reduce rescued peg mercedes guaranteed emotionally poland accountant theories tumor automatic amusing unnecessary higgins voting buster stadium visible easter jeep dj les garcia tracked ignorant pledge deserted esther rum fisher wheelchair salvation lester wonders clattering maintenance tobacco underwater divide slightest discount yoga vagina rushing modest wes reduced whisper pressing tops variety ignored helena writers grain essentially archie ofthe individuals meredith gavin subtle interviews pinky cord sites brennan maddie vienna issued lasted explosive origin unto rogue superintendent cody jacques ol challenges corruption sullivan shutter erase ski forensics flavor fastest joon vet civilians lobster housing canal robots shade ambitious orchestra succeeded guidance hence bella seoul jose inevitable tick rival refuses purchase wander ireland hanna hanged napoleon elite craft cult whisky profits shelf kai allowing chart accusing buzzes weekends humiliated hissing treats granddaughter serena submit supervisor sniffing resident tearing obliged opportunities knights hangs jerusalem stew counted instruments triumph nun frequency resume marines distract satisfaction historical creates costumes swedish lizzie depending sour spark freely scotty freaks shan globe peak sentenced fierce scam hollow anton hoo concentration presume invest eleanor radical protective smiles stunning frustrated suspenseful breed adore controlling reagan pasta precinct swallowed execute towels architect delta honks preserve dose stove codes instantly bugger vivian yoon doo haul orphanage bolt autograph sharply habits villagers cracks dwight omar assembly meds marge magnetic romans joshua sorted assets insulted outstanding essence wardrobe ling nam benson restaurants disco flirting abilities dolly handful mice pumpkin bennett sweating anchor thankful interior moore urge surrounding strain curtains gypsy tomato blanche bonds compassion greece ceo arabic examination participate veins cups additional sofia obsession responsibilities ridge intent axe reckless missiles razor corners frightening rains mutant wally whereas heavenly promoted dang maiden comments batteries bark seas congressman canyon casual rack expectations flowing adjust decade pine tails baxter wires pigeon finance respectable demonstration prank appointed treason views violin stir lifestyle realm monty roosevelt missy fitting tuna tuck inspection nursing jared poop cardinal altar herman carlo tourist conviction jelly thrill lounge cha zip hogan dimension choke backing pains bodyguard rug jaw ants popcorn courtroom reynolds pointless documentary donor mortgage tunnels enforcement demanding cocks eliminated agh rapidly refer shipment tasted fails michel rushed ordering efficient outrageous gracious slaughter marijuana monroe pipes backed vest approached mechanic mumbai arizona legendary delayed resolve relation amelia mechanical fare karma jefferson chorus nana extend info saddle pretended equals motherfuckers artificial accomplish burial lynn detention vow bake breakdown dvd delhi selected lightly dealers layer gown courtney incoming reid countryside cheaper smelled devon ducks lethal swan attending moonlight ropes dispatch notebook punched identification contracts scattered trusting susie prayed volunteers remembering adopt calvin worms consideration bandits moses zombies lionel non transplant crackling loneliness frasier epic gladly marcel mon frost registration prophet launched constitution roland claude sock dragons buyer regulations mimi volcano accomplice bounty hotels favors opinions pressed asylum blunt duel niles consult nevertheless carnival au baba hah paths rides tray cynthia te handcuffs shannon barrier supposedly faggot hunch disposal yacht stain thoughtful healed thinkin syndrome hairy kansas happiest entertain ambush recommended childish meter gilbert lease climbed nadia unstable exploded apollo rogers politician rs awaits abraham evelyn particles violation lined amazed lure lyrics pod fran universal hulk drunken hyah continuing goals warming dc chemicals owl xena compromised grounded cane avenge dexter phantom notion directors tease forensic doe outcome slam shattered cheque baked sought racket hammond rider exotic cory extent eighth stack wheat shipping satisfy kara departure finch blocking regiment kin klaus surf kilometers rises frighten abused gerald colours hath marvin texts spaghetti chester bosses elephants snarling contained laurie arab bumped chili yah sustained abducted panicked shallow diving artie harriet generator federation mulder arresting techniques feather printed untie jupiter hay stalking conrad phony brett whack scored continent articles oxford z organize sensors shanghai wh sniper noisy framed horizon twilight reflection masks godfather merchant wages robe waist stinking disappointment venture voyage curry ominous sunlight oui overseas casualties aaah mattress grill marketing accepting occupation deadline freed exhibit poems echoing shin compliments til define urine foreman facial combined brody probation reject catches dances gemma pinch ingredients ra hurricane chatting mini heel adding bandit destined limo spa graves turkish listed corpses matty evacuate publish judith banned snaps cheeks predict ohio holland confront utterly pals pilots umm jonah ironic improved popping mills farther delivering skipper flattered coconut acknowledge shuts sweden hooray sip blessings grocery terminal parks meaningless awards fade hiring burton fees wretched krishna thoroughly exhibition spends denver winners doris luther disappearance madrid supported advised regina supermarket hereby pier shorter betrayal philadelphia christians psychology danielle trent keeper detroit canadian su associates gerry restless collector marvellous physician exposure grudge lid followers glow submarine towns pawn edith includes lu proposition joker spilled opposition jang haley hose partnership usa timmy breathes whoops astronaut porch leonardo responding wishing boil kneel tammy clumsy rapid xiao stevens invested janice roller thai justify garlic yelled simone ammunition sushi shaft definition gardens chandler ne notify brady beasts setup greed dared unlucky classroom treaty hike dagger spine detect chow des teenagers handwriting mock challenging salon virtue lawsuit shelly clap mustache offence med sultan attraction franco courts fortress peel petrol disappears asset warp workshop traps jeannie appreciated condemned garrett muttering shook naval egyptian expand sunrise swine jingle lordship peach filmed pakistan oughta selection squeaking condom sadie barbie alongside risking democratic nerd dancers crook mack grasp translate behaving humiliating quarrel lively fury policemen sensei elders battlefield sticky glen liu primitive reign eugene stash evolved shifts unlock devices peculiar talents anita foreigners snacks mint pissing fuse manuel towers freezer inheritance villages beckett jewel bollocks shells swept recognition shovel artistic qualities ferry darren misunderstood portal atomic javier ava claiming examined defensive kenneth kat sensation ahhh increasing fugitive urban visions bathing gregory delight iot genes boundaries caution ellis strangled thorough ike bites nude tidy patricia tate obligation ari clearance reserved nasa spock marion reflect jammed sleeve classy fag angelo bradley bananas saints longest confirmation mushrooms cyrus toni finals millionaire adoption wired comet handing cheerful deb acceptable realistic waits sufficient cosmic nolan gabe intellectual vomit warmth magnum associated alas engineers offend overwhelming sherry inherited antoine whooping scars sheldon purposes robbing refrigerator instructor darrin moms overtime percy laurel females sacrifices representing drift ruthless po arguments crappy musicians sidney depressing lasts doom milo cant backpack aisle insulting edition losses sh preacher schmidt swinging managing sinking lacey casting trials demonstrate diseases beggar amounts traced raven activate slapped heroic roar queer uk matching trump resignation newton sincerely stacy saul madman jenkins poke spicy swap programs sheer spaceship schultz blink steer males injection ant reform properties virtually camps tapping tequila inquiry fainted formation shields escaping unemployed murdering interviewed striking vows donovan antique il sherlock puke hysterical taller employment thats agrees dodge unite mumbling rabbits repeating mule locals neighbourhood hayes bats beliefs spared vegetable liv bunker channels phenomenon hips grayson expelled camille languages iv premises pronounce ng bridges ape julius bruises convict prettier elections annoyed hometown earrings discreet poured morphine henderson jun narrating rookie peanuts camel abe chewing imagining runner hyun tomatoes sponsor fulfilled probe karate grease dinosaurs rebellion marta lone nan underestimate acres carlton hacked barber mining aged designs preferred onions stray void sixteen slower hannibal sabotage rabbi concerning dixon holt mannix noted peterson dental obama squirrel committing werewolf slipping matthews explosions seo russ whitney ignoring infinite cavalry lam suzanne bomber ruling boiling needles semester irrelevant savior veil tramp roberto deepest perfection shutting iii tiffany mentor branches enthusiasm arena listens hardware greatly battalion moustache irresponsible audio ga initiative sweaty noel requests distraction parrot steed entertaining whipped proving assaulted piggy pause surviving funding dinosaur acquaintance bedtime rail rooster cowards hastings container lori secured tossed stripper steele waving clamoring banker bacteria indicates assassination starring drawings cupboard sanctuary surgical pairs purely temptation elderly geoffrey vibe profound gong transformed crop detailed scrap abigail careless dove sloppy atlanta hideous lizard separation intern tab psych ranks parish booty peasant squeal oooh comb bash restored platoon junkie involves rupert norm carrier fatty difficulties producers superb tha candidates summoned refuge righteous carolina onion natasha pickup spells wesley carrington armies seasons senor billie specialty thirst select rendezvous smiled colorado visa spice caller foods rational scottish cunning grunt knot hairs payments granddad massacre competitive herb mae immune grenade regularly stakes kilos monks gail guinea invent nursery protein elbow keller clowns thirteen tattoos flown mustard terrace alter franz transportation lens alaska interference freakin wont weep clive mourning crooked trainer janitor gradually immigration filth momma jackass cho reminder culprit gabrielle innit magistrate jasmine womb texting injustice figuring fracture insanity peasants blossom etc agony sounding oz elementary seized teaches lovejoy phillips eighteen shack teen definite scrub ruler mold contents bitten antidote saves bunk thor republican graveyard attempts poirot aspect relate lemonade flour nypd biology dusty felony jax fundamental jai successfully potentially donnie strangely condoms quantum utter activated installed interrupted discharge devastated substitute splash julio exile aspirin authentic summit beck addiction lent drone involving boyfriends tango permanently province attempting deceived triangle skipped strawberry mirrors preston overwhelmed swift creeps token temporarily poisonous heidi diagnosis ninth locations retrieve robbers conclusions joanna disabled ira extension lining yuri freeman scoop merlin bridget revving transform shelby hospitality brooks survey hunted cozy recommendation providing microphone skeleton muslims toll reconsider creaks extended spear overboard ai clinton petition baggage scumbag tribute weddings facilities bangs claw donation isabelle traitors mei jasper borders australian colby boxer whilst misfortune elaborate sights maestro mysteries loosen gifted involvement affects summon sherman churchill theresa solitary wilderness baltimore olympic undo mechanism vietnamese vanish dome biting ronald texted sage yummy tactics slack snapped weekly bushes grandparents henri obtain hart flights adventures hottest eden mild dom fourteen smuggling blend chancellor biscuits gorilla dynasty acquired businesses countless fritz brent gardener barracks flirt cooks distorted carved jumps superhero forests clapping psychiatric snuck roughly screamed raja disappearing establishment whales lump dwarf environmental mam pint loading diplomatic exclaims context volunteered risked gangs boost fax dante partial refusing gaze rene nuisance terrorism jerome ungrateful donate relieve grandchildren felicity maureen represented co neutral philippe workin steering rm presidential rental challenged julien feeds je vegetarian teasing surprisingly iran shrine automatically timer gasoline juliette scouts millie google dorm athlete shiva robber convent balloons crawford barb enters maps meth ifyou fruits colored poppy metro clarke fernando scully resolved sessions conservative rates forged legends arrows charley dismiss authorized slavery attended flows employed decorated parallel detected grove coverage hen pyramid overall hum specially rebuild exclaiming producing sewing occasions boards trumpet shaped matched ammo typing macgyver blades thailand becca wo debris luca cement hamlet nat communists showers tougher sailors kitt comedian harassment missus monitoring smashing shaved inventory housekeeper tribes vile gotham imaginary artillery ping cereal zoom portion irony exceptional slit ss despise waltz humour crashes gu stammering coaches joo await bryan celebrated encouraged devils gag telescope verse stalin iet babysitter pr distinguished licence addicted bauer speeches wit programmed bliss donny elsa com recorder hides shameless apartments tipped turf tang tu discharged psychologist duh delete jock wrath estimate tutor jurisdiction impulse penguin tubes playground sew nickel claws giants daring posters peacefully rag caves nikita stern condolences ohhh dearly humiliation worldwide cartoon disrespect shhh underworld marble lilly chun curly judged bidding erased confuse masterpiece pentagon oppa tow seduce bathtub pets bricks goa hotter regime contempt batch ramsay speeding compartment tackle wage shines lifting hustle inmates km psst scooter relatively stoned supernatural darwin viewers lorenzo treasures yankee lang taco charts brigade bankrupt marianne bikes lookout merchandise slippery duchess gulf foam steals numerous ripping trusts flock potion fiance glimpse invincible compensation kettle stroll trish brendan cafeteria sane currency amsterdam radius verify founded medic peek sewer vernon callie bbc hull solomon madonna toad powell maxwell moose souvenir stitch compass mercury locking edwards frederick dislike stu rib pamela brace ban gracias stitches thrust referred achievement links denying monastery newly impatient recruit sunk ignorance drugged predicted floyd creator mississippi civilized artery dynamic competing buffy distribution turk voiceover stereo ethel ark carpenter warner industries melted upsetting cruz labs bluff bender unbearable narcotics juicy eerie ingrid mwah slippers freaky vip troop footprints dani pact apparent repeated foreigner feelin journalists employer penelope grim medieval damien frustrating rehearse travelled preparation microwave denial flute juvenile paddy retarded memo canvas fa symbols mccoy daly driveway funky kitten nicest deceive negro chopped consultant rifles heating rays architecture gideon butch warmer contribution advisor peoples groceries behaved experiencing settling tractor unacceptable imitating squadron briggs smallest ethics gibson devotion plumber burgers knots broom briefing curve informant applauding whites app andrews blog ox vase glance collective poles sixty fantasies heritage motherfucking fisherman armstrong nder complained nightclub willow preliminary server provides mat appreciation historic jorge promote processing naples pumping stalker goats francine smokes introduction valid portuguese negotiations wheeler overheard iove breeding barge refugees wah observed tigers brothel missions ashore panda discretion yale disappointing insect prophecy wanda absent machinery generals carrot ferrari wrecked gestapo greene suggestions puff supportive punching lulu intervention layers hughes scholar libby predators accusations olympics accounting jj expertise strap fitz darryl butts approaches flags embarrassment faking jamal vanilla grapes dominic beacon handkerchief rubbing mallory rustling lighten flora cuban polar translator congrats passports grabbing alf brotherhood ernest professionals yuan understandable banner academic thuds sa publicly orphans pearls predator frances addison syrup cartel nash walsh norma bluffing permitted unpredictable wagner suspension addresses stamps category transition peas cautious isabella comparison coats islam thugs grams freshman toilets banquet coup shaken investigations toothbrush expressed vulgar haunt improvement zeus murdoch smelling kirby repairs jeong conducted ollie bakery busting investigated admission essay twitter depths fewer guarding altered filing ecstasy snatch stored tropical pharmacy dalton altitude admired dickhead priya mamma moe grind bombay lowest makin sentences mute scratching imprisoned danish glowing zhang martini leah empress equipped finale tarzan storms sniff slick unarmed violated vent dd breakthrough stud addressed tactical vessels procedures ching dine draws crowds limb wool montana giovanni jerks numb oceans priceless rocking commanding relaxing clatters merci gerard packs parlor cabbage intruder considerable argued paladin tellin pupils inspire positively igor traded shipped feminine vague partly insight lucia stages screenplay marquis rahul ripe awaiting pigeons clayton tempted inherit decline pennsylvania fang shitting tens gigantic guv readings headmaster tenth seals peyton avoided blankets overlapping flipped yield ads backstage quiz mosque weaver puppies stated vicki weirdo belongings functions reservations chilly betsy eldest traditions factories feedback repeatedly exquisite pickle masses pauline frogs crosses headaches arctic reinforcements secondary pajamas roles asteroid unsub mixing courier jeanne carrots fuckers translated longing cigars manipulate liberal investors bun sly pickles temperatures sweetest motto moss yum melting yan requesting lava kris monthly noses tickle ufo timothy stacey midst herbert purchased tis convenience flashlight dewey tripped easiest shouted splitting bryce commands demanded cuff cosmos curfew instructed notorious prague q streak equivalent pitiful fin greeting propaganda doorstep hilda butterflies fascinated jude beatrice miriam dumping karan condo fearless cripple errand halls imitates harley ravi gretchen sailed nico baking connecting bourbon cathedral malone bong tying lists strangle stripped loans manchester briefly tessa unfinished experimental greeks lil mainland judgement stammers pike liars slot amazon flooded torment mermaid rapist sanders triggered expects lisbon reader keyboard roam seventeen openly deacon olga jackpot soaked printing yuck shorty extract prostitutes cherish logs takin sponge bates cuffs virginity torturing unity coop forge morse guru tai skilled dev insists calf oof allowance homosexual vijay shapes rosemary idle slaughtered resent cassandra leaking likewise riddle ghetto sunglasses vega newest valve geek fucks gangsters pies publisher troubling trembling marathon douche conducting sundays shrieks fiancee frankenstein summers wei liang burglar spiders norway crops infant falcon pursuing humiliate hydrogen karaoke encountered alberto corey scope cultures speakers superstar orgasm byron gravy calculations vocal severely hating novels mindy boiled metaphor kindergarten fades anders fi brazilian devastating bea interfering dripping ops cuz holden suited merciful hayley affirmative runaway shoo italians wales santiago adapt renee mal smartest blacks struggled prostitution payback buenos vintage diapers killings courthouse tong cubs surfing indiana spotlight frontier monte stocks patterson holiness denmark isolation starters resigned acquainted meow appearances loft snitch ribbon dares greatness fallon coolest decency mayday michigan reactor buckle vanity simmons earning marriages docks lopez alleged asap preparations bugging conquered cuckoo crib yogurt secondly nixon portland fishy flick scratched muffin hale tailor chimney nuns ezra packet homemade farming genuinely rumours daniels blouse kite buses hassan rhyme invaded quentin equation transmitter morons lime rotting remorse otis marker aiming adds chores gem blasted grabs courageous determination beaver publishing crickets exercises testament apocalypse phew dicks paralyzed headlines stripes santos breaths abort heap ketchup responded edmund gracie protects tummy hog yakuza weeping fragments catastrophe bp churches pins shaving legit yoo targeted simpler noticing rover lars moreover releasing fascist greta spitting colt tristan hardy truce plaza bronze guarded airline ramon incapable punches sanchez hq privately vatican surround barrett edna alvin consolation gutter lan astonishing broker seizure fright runnin leaning mic scarlett berry paulie lacking verge lucifer contribute jewellery richards erotic feng siblings est dre cass disk op comics obstacle ale coral hamburger biscuit redemption thug concussion martinez disgust wright nsa arise celebrities kev dolphins kidneys leaked solving plasma singapore scram regain conductor ministers gender removing cocky richest deciding poo dispute brute incidents telly capsule chefs psychopath dumpster lire jarod bind chops crust poorly weighs bundle vibrating ricardo encouraging dwayne polo singers ada meteor firmly prettiest hormones starboard chauffeur download garrison recovering heated hillary cctv postcard darlin convert celia abi sissy reef treasury calmly mathematics ar ups shameful abbey strategic wrists payroll beethoven immense heartless magnus banged montgomery protector michelangelo teller raging applying mop sol atom paolo unload detector switching handles favorites stinky lina norton regional heil richer secrecy thighs rigged thesis zeke consumed ahold tuned atlantis repaired leverage winnie weary costa rue cowboys employ provoke stool postpone extensive beau urgently optimistic lotus apologizing spooky skate maze arrests dialing fireplace gt vicar beetle horace suspicions stupidity restricted skating pupil homo thumbs hostess cheng sneaky swollen por unlocked eliza gladys mixture porsche diagnosed vaughn ri liberation nay crows rockets starfleet reindeer shampoo milton mai skiing overhead disturbance cohen spits crank crocodile bulls medals sierra motivation dangers exploring mist galaxies ju sculpture marjorie adrenaline malik allied manor convoy carly elliott merit cutter stressful forming bikini sway virgil soy nell salty elf belts yvonne disney contractor rodeo crackers playboy arch operated crews scanner dads limbs bathe cardiac persuaded argentina velvet hyde stem rewarded taiwan warfare lakhs filter pumped sterling gran fills chet disc percentage bravery edges diaper lyle ida preserved sutton katrina champions partying sergei pd morality crate mina complications sausages smoothly rafael cradle leopard chu gardner athens abu kramer magnet psychotic vaccine motivated aggression courses willis expanding vance bases burglary stumbled buns confronted geneva increasingly sidewalk shady defended resolution chooses tapped exploding punks scenery hitch severed wink initially assessment shredder villains miners introducing focusing rainy amendment getaway recognised blackout leash muhammad eyebrows livin bouncing nipples raft pharaoh pots refreshing wandered roz abel beatles confined contagious madeline beijing frequently operational shakes thanking suffers basil babylon drilling agencies buffet farms motives cocoa perception targeting thudding blares dense pinned pending nod crunch stains nervously caribbean bouquet stabbing screws boone philosopher bulb sinner ongoing editing veteran drip mara inspiring gale flint nova nevada manning membership puerto raphael chalk liable manuscript organised clanging markets rama austria chocolates trafficking philly unaware loot perish processed clone whooshing hangover flatter wretch weasel columbia israeli shatters lace indication allan cora drifting grady undress dolphin faked depart monument tyres marissa lorraine pow invade scooby hazel rep heavier tart mocking forgets sinister christy dex judas assemble shortcut transformation posts generosity amusement beta counseling bobo honors snatched phyllis measured gamma squeals evidently mildred caitlin dubai lantern combine nero trey toughest limp implying matrix dots kilometres evacuation earliest incompetent closure descent parachute analyze crushing classmates excessive tighter hump fuzzy tad punishing pageant wan reveals wildlife clare poking rehearsing homecoming swelling shrieking squawking tardis caine statues practiced christianity hazard stretched dea trudy slug frustration edie deception lillian trespassing elimination comforting len preach practise damages exits yer appointments significance drummer specimen voodoo cleo misunderstand asthma errands hypocrite snorts advocate cutie obtained cristina radioactive richmond ideals apprentice unreasonable inmate siege cobra increases harbour illegally rattle trim noodle antibiotics mattered declaration virtual intuition revs darcy scales testified gigi bypass pneumonia manly medicines slowing groan dungeon chaps ncis consequence intercept badass examples fists klink substantial brag pitcher onboard amigo courtyard royalty spontaneous ca restroom peep negotiating ache swat emerge gambler references bonjour darkest insecure attendant sympathetic lila heroine choked unidentified plumbing darker ariel crude dictionary sparks auditions demo oppose fingernails mineral collateral istanbul venom tempting relay bamboo particle ying torres broadcasting banking reminding cassidy axl ferguson estimated hebrew electronics octopus meaningful stranded daytime dowry starved collision admitting comeback hungarian faculty operative liza tenants revealing ko ounce mediterranean gadget paramedics console cyril drawers caravan spinal bummer crippled bled defy luna herbs hwang queue blinded studios goddammit recess countdown maddy dracula alarms gaining quarterback maxine eminence willingly investigators speculation clearer gino cheeky powerless lapd cruelty external arjun quarantine shush allegations tito sands spelling che headline taliban tablet founder gandhi squash josie jets saloon tuition tame occasional apologized clinical serpent criticism sawyer fading viktor prop shoved mend lonesome separately reg evie waitin legion tsk arabs accompanied tread findings toronto exploit proposing shi scorpion zoey curb opium athletic bombed jumper weaker suing bianca seminar confirms commence plains debra readers neglected tavern worthwhile morale cleaners caviar welcoming kimberly evaluation occurs rituals morton disguised precision cube revelation titanic realizing doggy babbling cheung dora tenant riches diabetes alternate diversion effectively dedication wager companions sinclair bailed smelly ratings trench cameraman dillon hawkins stanton ajay edison batter dye abduction prospect morrison brighter wider alma manslaughter remedy damp thigh cologne accusation outsider serum whats spaces oral shades woe elise receipts alias notified apron kentucky vein tonic squeaks dim steep sod presenting cinderella cub chung eyewitness flattering overdose kathleen doubled della suckers automobile cain loo brittany bullied humphrey tyson kidnapper dispose margarita hash grieving initials hound boogie dawg perp cloak crabs pastry successor hola michele cheerleader slips critics recruited macho stunned fuller mornings accidental lara convey prototype superiors barcelona fling froze atoms kidnappers cupcake athletes warsaw pleasures ax kumar uptight inclined stockings scrooge fingerprint harmed sensational jockey mourn intercom tory penthouse forthe eileen ginny quack peck gospel presumably signatures hyung aspects assumption rumbles hugging sideways theodore organisation lowered youtube ct jaws troll squid designers mushroom freeway believer possessions tunes tornado cowardly notch routes winters elijah annoy loaf commercials idiotic inconvenience plum solicitor amnesia deborah distinct sweeping arson doubted furthermore quarry puss farts guo depot evenings ole circulation socialist melinda dryer mutters vomiting brock fei candis moody donated reich receiver semen converted rags harness slate padre sonya necessity emails rumpole orderly dinners assassins scold certainty marian knox upright trek patron reborn reel typewriter babes sorrows utmost havin patsy governments bhai privileges throats remotely glee revolver lockdown woof brunch dwell coyote squat manic groove bangkok uncovered mailbox objections lynch scrape commandant swings conventional stockholm raises transaction iced oy paulo ignition beaches interpol epidemic honoured shaggy friggin policies statistics shattering bah intercourse charms flashing destructive grilled oregon copied hookers paycheck solitude panther performances maids exhausting lambert omega belgium stationed yankees liability whichever hunk trout crystals learns repent prosperity literary assembled ounces martyr northwest connecticut privileged webster excess unemployment viking blackmailing munich install arrogance jeopardy hacker tongues pleases reset risen dependent sued perkins goons macleod milady wolfe abnormal bandage heed mabel pronounced bullying charter shelley turks litter standby izzy ltd peaches angles kerry baths generate cobb residue composed paco kilo immigrants probable enjoys seeks newman vicinity flank der clint functioning horatio predictable jedi scrambled expansion pittsburgh angus natives bing scarlet itchy stirring bedrooms structures penn ensign barrels voters madeleine geoff haste existing mcdonald commotion belonging extinct joints bumper mao mare coleman influenced heist cynical input recite cary eagles expired palms slash bottoms columbus georges vous exaggerate guided pineapple spence ankles morals builds colleen posing fireman thorn communities lawson workout extraterrestrial raylan conceived tightly orlando tennessee yeon diaz fraser sleeves vacant infantry gallagher booking oranges rhodes breakup layla purity honourable militia mechanics mackenzie bronx realizes hasty colorful ramp boulevard xavier intriguing rook papi callen atm acquire necks sinners gents episodes oswald dedicate rests pi milord debut interviewing occupy aimed emerged sloan restraining cod clarity daft islamic calculated lakes grumpy ki picasso eddy consulting obstacles pesos nicolas plotting infirmary sermon manipulated scratches aidan deeks critic greasy seung zealand supports anatomy agreeing straightforward prejudice placing flare milky masterchef vladimir premiere glamorous cinnamon syd referee threshold civilisation sensor tends louisa savages emil torpedo ere housewife tours fossil replied abdomen soak contestants stretching princes hoffman truman bumps educational outfits resurrection latte huang politically pratt whoosh ds wiser rejection clutch fusion gloomy madly cambridge cocktails lighthouse treatments chronic fluids deleted sustain stanford ahmed couid buyers valet darius nobel sank southeast condemn resemblance suicidal wed packages taped avatar wireless paddle lice tablets spreads itch gibberish ingredient emilio prevented withdrawal porno pry sexuality br vinnie considerate sovereign pas voicemail cadet clarify immature marguerite banished chemo nicki dairy attach murdock sliding spectacle pushes yin delusional allegiance slope pooja awareness jed decker dino roaming shores competitors tomas overreacting observing paste wits fiery typically eclipse produces oysters scraping pros impose revenue alabama departed user cracker hu undoubtedly arnie mozart dent charmed spiral scans hmmm ka louisiana rumour kirsten touchdown nadine posh correction mornin chubby manifest safest steroids fleeing genie dakota witchcraft archives trance symphony traumatic rocco skipping frequent modeling sporting affecting spacecraft negotiation talbot reno benton calculate fiddle sails stein persistent despicable bruise salem escapes mischief mckay cupcakes brussels arc ripper ritchie vitamins cognac careers sim caps imbecile steaks cove lair directing stepfather slammed viral congregation illinois helicopters coco crisp outrage flexible goo licking funk prefers tao captive montreal zen cee knuckles canteen credibility disconnected flats controversial enthusiastic janey cork priorities acute icy wormhole flyer bladder caretaker pep roommates programming grape astronauts drained metallic sergio seldom destroys riders poetic hacking transported contaminated duct dimensions insensitive echoes initiate nonetheless emmett grinding composition adjourned indulge wrench flaw messiah concluded accustomed napkin movin doorway muddy steph saturn intentionally chiming canned appearing ballistics nicked suction hideout startled replacing solemn pillows submitted francesca override carver lea mateo mosquito fragrance pennies detained meadow chopping satellites cables youngsters needy refugee luc whitey inhabitants yun harassing ro interpretation burying bree incomplete blimey titan retard agatha dilemma mutt prominent temples hoover lindsey cesar temp consul hairdresser planting drones justified jensen stuffing norwegian dork stalling birthdays intimacy tucked examiner qualify imminent masked diesel meditation bulk allie prosecute mumbles defined oklahoma paw default crawled doughnuts margot haunting staircase advances solutions plaster proceedings amends fraternity freud cannons kendall armored colonies perez birdie volcanic samson cleopatra carve fishermen brink playin martian hybrid knockout chunk constructed confiscated interrogate voyager oprah commerce tasks precaution printer finishes rossi boob nagging stephens hag skinner lunchtime imported transcript iife conceal holler chug silas paranoia compelled styles airborne sentiment syria pea babysitting improving hare connects withdrawn staged englishman hopkins pumps admirable vouch indicated reviews kristen yuki vey trivial parcel scroll desired appealing weighed designated bubba imprisonment ferris fleming cooling containing giles impressions advantages cartwright uncertain deliberate anticipated isolate tighten corporations petra venue irritating revolt whatcha lunar rightful bombers southwest maine marvel chained colder tit snooping trunks sully excused seduced communicating beams bloodshed offender offspring monstrous bruising doorman prohibited props penetrate intervene tobias osaka aiden niggers cairo jonny patriot bowls rufus barton surgeons pits infamous crooks shag lettuce exaggerating inferior zac foryou boredom amos tolerance cashier polls caliber underpants katy seller sensed vertical dart sections zipper gabby shankar acceptance traveler timeline emerald gays pc hassle thrilling hopeful stokes sneakers conditioning supporters rodriguez teal insults instruction flipping clatter flaming freight representatives invitations undressed lucille boiler edo uneasy oneself alfredo benedict davey davies efficiency gomez yelps counterfeit afterlife smiley twat eccentric wand vi memphis consume praised formidable luthor lesser gel surrendered welcomed wendell tee launching cocksucker crores downs retiring spears vikram authorization outsiders pancake probability accessory peters deported contrast hooks remarks liaison blokes crater distribute vocalizing adele chiefs photographed rehearsals salvatore whoop credits shalt hup stability woken stench taps flea compelling dolores strawberries allright convictions hubby threatens suburbs clocks peacock bragging gabi hurrah moo silently subconscious fatso pluck reactions lacks adolf mira refined lays bungalow surge practices precautions thanked jody uranium carolyn menace ernesto fractured christie aka cone sauna extinction randolph bonding equality bourgeois insert csi kiki teens downhill pedal levi peru stables irving buddhist ambitions terrain turbo hae screening mu riots coaching explodes premature lsn undone qi communism fitted treacherous inspect hurray irresistible joanne elias northeast sparrow gypsies performer brew titles ingenious snapping turd challenger baghdad bulletin preview jinx immortality recruits ditched tempt procession eduardo melon weaknesses aires knob domain conclude dresser bao berries straining beads windy patent merchants profitable ryder prisons salvage mentioning lass tox sonja poof productive hosting doth ewing derby goldfish capitol leisure buff illusions notices odin springfield tracker kyoto peed vitamin heave bryant dickie goodwill euro strapped boar slater bogus rhymes brunette jab hippie ting incidentally gi webb compensate tasting outbreak sow hallucinations golly factors pyramids copenhagen hiv dandy detour desperation wrestle entrusted parting resisting err bursting warrants savannah concealed dreamer mandatory gagging finances nightingale lamps grenades premier squire periods uhm kgb parasite borrowing rodrigo influential mammy absorb investments cece concentrated tyrant laps underestimated measuring origins applies britney exchanged portugal niggas maths decorations orion pepe kyung ownership tweet raspberry racial firstly suv intimidated skunk parsons nearer yong audible bmw communion whinnies hindu leroy sphere renaissance anomaly pursued klein chant outlaw surname penguins awarded mid classmate applications emmy subtitle laden economics ballroom sinned shortage mort phenomenal czech maneuver tremble hooking screeches moons ae sweetness disrespectful dane consulate bounced parenting robberies remark hilary logo describing scalpel cecilia strangest jaime seymour competent bein bi lectures basics texture leftovers wimp conquest norris mounted pens contestant algorithm columns chile wails decree jeremiah rewrite momentum cadillac attorneys apes captioning desmond lesbians fairies monitors hua weighing roasted discovering alzheimer subpoena foe hicks cm circuits nag hiking stepmother personalities formally revive unnatural pip betraying renting prizes onstage comfy heath marrow blaine minority marcos portable popularity telegraph hayden hesitation sylvester alistair cluster grandad jog slay sparkling shithead tiring ooo germs fuhrer handbag unlimited thumping vinegar splinter supposing faults remarkably sketches nineteen enchanted hari respectful bien honk doughnut tags wrapping tar om dinozzo ducky unfaithful delia rae jojo stance barker financially clam clanking sarcastic blur organizing nosy boyle pasha attacker horribly inject descend wi liberated burner fluffy melancholy puppets anal grieve awe gallons earring unprecedented yank jamaica brutally extortion guardians disciples simultaneously elves malibu lupin postman neville senseless chapman sittin hostel marcia melvin cockroach clamp poets chemist professionally faded vargas gunpowder inc gala surroundings wisconsin rivals cackling withstand contemporary harlem marlon endured arsenal underway donuts daryl frickin injected digs siegfried elisabeth billionaire cardboard hugs bandages everlasting liverpool cooperative diploma neural fortunes rural abbott receptionist antiques labels sizes millennium layout immoral manages hisses usher impulsive pollution admirer rejoice iowa marlene hindi holder squeezed merge journalism nominated sundown assistants miraculous stared prescribed lotta swearing guarantees massachusetts junction consumption astrid metropolis iceland bridal virgins victorious squirt pads modified hanson casket blaze kimble cliffs destroyer offshore tendency nip scanning viva intensive gustav endangered va circling ave stashed das backward hai chamberlain sari thermal opponents fiber toto circumstance geography stargate interpret sicily pisses preaching transporter bosom salsa eighty shred dread duration beggars mein josephine networks formality heater par smug ordeal rhonda agriculture aigoo katya fowler descended lasting abyss marries aurora sleigh frenchman rouge survives margo redhead terrence creativity dominant isis kip corny aubrey graphic irrational mathematical sacked paws chariot havoc andreas midget celestial cetera nino upgrade blasting skulls videotape wedded babysit ancestor transit rained thingy wellington abide reserves rim chico settles decisive motors cheesy symbolic roxy clink handicapped mating cranky brightest molecules meyer sheridan animation grail voluntarily creeping furnace thine titus pierced bu chinatown slade sai toothpaste cuddle langley egyptians bankruptcy lever shaman nipple weeds becker reacted mashed sloane regent bentley tiles decoy crusade vivid slides jennings catering dishonest subs lurking airplanes shaky barren alligator moth uncover lorna axel expressing clacking doggie airlines dum unicorn jackets goofy marcy businessmen bums folded defender alarmed goody noose chic forgiving thatcher index blush fertile amateurs deliveries armour werner shits twinkle parted syndicate alexandra righty regions technician waffles skirts baroness castro malfunction memorable thea calories cuisine motorbike snoop acknowledged spelled evolve cox sedative array tenderness klingon garland smuggled nicola raju reversed royce beforehand continuous yoko cecil seniors mri synthetic forgave discoveries kimmy agitated attendance maple pools wanker casa firearms offenders obligations moan signor graffiti supplied linen defect patriotic ethical pest lengths vin minnie spectrum distinction decorate bounds hums mandarin reluctant rand retain justine educate minnesota mp cruiser permits screwdriver exploration mace newborn shivering slime oddly badger bruised luigi attaboy eyeballs institutions panama boundary hypothesis drought rembrandt absorbed clinking executioner darts catalina lured lingerie gon flaws thinner lucien tug cornered bertie uptown clash aerial hansen relentless viable raul wen scholars marley limitations shelves funerals criticize jacqueline forrest shaun continental bookstore balanced workplace theta ramsey dixie bankers dumbass superstitious clause fudge bennet assignments councilman slogan trinity quadrant boarded ivory velocity composer mccarthy initiated covert builder insignificant dire gears comply credentials organizations applaud trend providence sparkle chump derrick donations flooding maintained snowing shaolin ladyship artifacts allegedly howl deploy showtime thornton deposition fractures handshake neglect adapted patrols bess cyber hetty protocols overdue slayer headphones identities appoint rotation solely tasha aging pitching examining viewing memorize freshen mango valued sonar crichton decay eu nightfall olives miniature omen kristin bai chum posse mutiny toaster span jumbo blames mystical researchers exposing dung welsh frat waterfall lifts disgusted yikes windshield akira maintaining receives plantation antenna bodyguards havana anya edit superficial allergies invites comparing dirk cartoons mexicans timber supervision siberia winding rust intensity hiccup francois johan jogging confrontation flyers trustworthy jarvis coaster paragraph mosquitoes adios lovin unexpectedly russo amuse splashing soviets lorry dominate bundy howie jp unreal screens mouthing ziggy failures commanded recon representation bending gallant satisfying cheater pornography urn assign uncles vine auspicious tripping seafood mellow announcing resumes hawaiian ac centers adultery scatter lotion opposing dominated unpack violate transmit testicles zhao ames kayla hungary albums porridge gavel prem rattles eliot titties strengthen sensitivity fitzgerald tamara removal sacks downloaded morocco sniffling crowns saddam nerds accepts hive radha outdoor raquel dew ing mt currents explanations soaking tanaka vitals navigation joins intrigued harp margin everett anthem aa kylie distracting fertility amazingly horrific indictment superstition ultrasound shifted sincerity hamburg davy trashed casper dumplings digest whacked jacks kiddin casualty bethany thump proportion quantity janine deceiving weave hikaru sdh corrupted gallows budge fraction afar hiroshi leela measurements landlady certified dusk luisa insisting hilton indoors hawkeye saliva homey whispered maura cyanide marched accounted diver eligible robbins messes abandoning blossoms wiggle awaken cid stained ballard elevated ryo transparent unclear strokes aria hwa solidarity sidekick starter regarded corinne vulcan bradford godzilla belgian seemingly cling components vibrates missouri constance batting chanel sap marbles shifting wiping refill famine sneeze puzzles provisions shite walkin syringe platinum preferably oyster exhaust electromagnetic consumer lasagna barnaby catastrophic winchester woah evacuated serge relic describes merger muck buds socially enlisted deposits philippines archbishop smuggle climax progressive wheezing singles pillar fearful spade saucer ratio craving addicts clifford orson nashville beauties obscure signora troublesome rubble largely fong irina ahn admiration lizzy flap brutality mariana prevail tattooed brats anguish whim nada leaks cum cupid hana colonial frau speeds perpetrator watermelon emptied sponsored rooftop athena managers extraction stat rhino diarrhea disregard warmed goggles colombia struggles fitness scalp veterans suitcases kensi watchman caress devlin exclusively disciple misty aura helm crockett inhale buckets adored shillings kari tents revoir hedge snorting viper digger breaker meatballs suppress witty wonderfully shogun encouragement intercepted goddamned posting cleanse competitor abbot trenches sizzling lyon mustang stewie kg rested reflected habitat molecular obnoxious wraith sarcasm tung renowned tofu wildly blondie refund goon pulp exaggerated embedded chateau harlan provoked antony guido nile alfie cages skates resemble sticker lennox unstoppable veal fe isle characteristics earthquakes ambushed zap reaper deployed biblical puck mystic aya gaby intends muffins speedy republicans bolts enrique hoax raided intersection presently supplier shuffle edited rubbed vegan outdoors distinctive upcoming brighton wagons granger peeing oracle glitter amulet suspend guild convertible squared battling steward weston gateway rites distributed pavement projector rugby jt fragment baldwin obscene zebra raping analyst eta elbows detonator disneyland rails earthly modesty assess vinci librarian moran suffice gravitational crowley slumber homie bribes aces sodium hubert trajectory credible declined canary eyesight jug duplicate developments capitalism polished defenses xi crates fences differ hodgins enzo chaotic gardening gram tinker forecast ti pinched tangled macy plunge bulletproof module firewood pizzas overly retail novak grover arturo appalling rows felicia concentrating transferring mash growl sliced rewards braces livestock users recruiting gunman dictate bathrooms nobles picky linus platter vultures organism sweeter scarecrow manufacturing pup mitzvah crackles proudly interpreter leigh genetically frying redeem cara ledge qing tyranny charleston cutest skins rosy nomination textbook descendants sabine saunders hast dubois finland loretta unsolved pioneer ramirez suzie hugged angelica cesare throttle powered carving thrive allergy icu suzy pong squares alphabet threesome accordingly sect maternity scarce internship morty tones sirs unwell nellie import temporal mohammed anticipate democrats pfft terminated spree ami interviewer respectfully futile dictator stuffy wai mammals fasten neptune giggle grandchild pharmaceutical persian tactic itching observer tesla wallpaper thorne jiang austrian output goliath trophies joyful spouse giorgio rightly hobbies vito naming yates stale teamwork obedient switches rating regulation raving dioxide boner bc implant mari satisfactory espresso bach sleeper construct rations munch anjali coordinate stag dominique backseat chrissy analyzed reschedule uphold sorority bono princeton inconvenient crumbs reconstruction pipeline reunited confidentiality embraced overruled enlightenment puddle mortals comfortably vlad misha ukraine swam annette demonic sora demise donatello fungus barefoot tacos skeletons beak fanfare maryland felipe picard mascot lemonis drastic proceeding presidents intrude stiles sums deprived advertisement farting straightened foremost adjustment charade blanks stig puncture spank utah booing abs minimal gals flashes andrei requirements greenhouse marx vermont comprehend canoe baton arsehole graduating partially sensing kinky titans microscope intimidating ren babu territories vaguely geese hardship karin exceptions jing gramps florrick doubles knitting slowed administrator blacksmith ctu tolling correspondence fashionable overlooked siobhan matron arcade gestures lonnie quits outnumbered lockhart verbal mc terminate hosts rye chirps presidency roberta devote dumps hallo improvise monique pooh starship spades fumes cawing aluminum squeak drafted ssh everest michaels commonwealth candace cappuccino cucumber inventor folder slamming favours peppers appeals walton reasoning adequate snickers glued ifs nets hangar godmother forum joys foolishness sybil crest playful peers horrors bleach disastrous lineup glamour coronation halo sookie highlight ziva ponies errors viv alvarez pluto weights arabia imperative trader galileo tainted drugstore lenses obstruction segment envious gertrude twisting nikolai insured overlook icon rollin commentator pitt camilla cerebral qin zelda spoiling tsar frames cushion divers hallowed chute cavity reds volcanoes angelina sahib strung watts monopoly bros immigrant apache caffeine squeezing postponed encounters stuttering rut calmed opener baek impotent tabs franchise entity slimy hygiene andi containment knickers jumpy pistols irregular lowly controller rung hades anarchy wisely blackmailed dudley dramatically researching borg touchy fay seventy bullies stealth divya divisions yearbook abdul poll blinds sneezes bigfoot ninety dharma cramp cockpit truthful lilith ghastly hangin edwin whines corrections missionary infinity cola penance moist sham investor founding krystle caldwell orientation captains flop columbo jamming crossroads infrared pleading sven carroll flushed magda gaming gurgling vinny prairie component saudi slapping gases aching lau abusive vermin bracelets tyre rift wiring gauge robby lifelong abstract pilgrimage theoretically mythology johnnie photographers wilma render rocked iq licked android rhythmic pianist clover unwanted salvador troupe feat primarily preposterous drying unseen raoul vulture constantine outlet git pictured functional nitrogen cc lest speechless delusions peeping refrain jerking engaging accountable piles ch intro rescuing orgy zane jaguar prue concerts schemes abusing fatigue taj charitable lili attracts stirred invaders wench kittens riggs gras heartbroken suffocating youse underage amar bugged dimitri klinger metropolitan unions worf cds hamster omelet humility grad obedience grub victorian lassie posed conway resentment didi locke dat booming aunts shay brigadier intrusion hedgehog recipes tacky hk saviour physicist yonder admiring anyplace forfeit lullaby oasis unleash avengers indifferent boxers truthfully organise actresses grin arranging voila hydra shutters pearson genesis daria energetic postal henrik aloud hmph archive nauseous funniest muse ernst constitutional recital covenant cloudy prestige olivier pencils gunnar helper decks astray leland ip casing cooing ozzy sterile bagel releases recognizes lorelai intimidate forgery kenya bred dunn vector huck nausea sakura detonate lenin inhuman horsepower violating pascal informer hooting plugged oriental pretends tram reyes spoils chaplain farce parasites whipping cruising violently tile ashtray und neighing zones donut spoilt nobility decoration sharpe scoot kelso abdominal updated blueprints dealings pitched resource coalition hoss professors espionage dishwasher minded cheyenne resulted brewster wrestler cons protesting barbarians loony kangaroo rite dialect counsellor tsunami locket sorcerer pilgrims incorrect parameters risotto unreliable geniuses agricultural willard marital wilkes scramble hera swears starvation summons aquarium flavors sanity roxanne caste wedge bedside experimenting truths tribunal emerson darlene automated treachery explorer greens dunk amused fishes kappa oleg goblin appreciates lark commissioned reassuring disclose seaside politely preoccupied incense folly pear vikings irs lavender graceful stretcher grande simulation lasers groovy discussions basin sacrificing luncheon disobey snot mil sinful yearning gruesome aide shen haha masculine mortimer extras hopper guides banjo dina camelot blazing dos crowned gonzalo painkillers rave foley silvia sylvie cassette sorting misplaced sprung practising prehistoric howls enterprises designing suspense patti japs renounce paints relying rendered herald randomly stylish spleen mugged investing protestant circumstantial smear pantry guiding flavour hollis cursing erection gravel artifact raccoon classics enlighten enhance delivers spinach binding goldman invalid touring johns fashioned gilmore spilling ledger quieter meadows majestic frequencies zhou historian containers marisa diplomat wrinkles aryan subtitling para nationals natalia rudolph palestine insulin torpedoes pagan swimmer disgraced bygones intellect accommodate posture adjusting giraffe peer petersburg religions hammering audiences ruben gigs damaging colossal renew iceberg vigilante emile dougie biggie pietro chewed cellular indecent dangerously duane bribed rascals chai ramona grammar thrash hutch runners pager stumble dispatcher thankyou iast stump wraps gator teammates skye weakest disconnect melts morally feud apiece theatrical distinguish cooperating passions strive flourish reeves unnecessarily janie perceive upstate accuracy cosmo bitterness fundraiser reflects insolent strauss circular generated rumble pilgrim squirrels purge xander mingle manufacture firemen casually handler hobbs slain phd multiply confinement patches divert alfonso protests versions ambrose adriana ia mit youthful numbered mustafa herbal kathryn gunther lawful stacked damian reasonably suzuki myra logged prospects mainstream sykes alimony stating budapest nelly awakened curses ore slices curl uprising cabaret manufacturer ration boulder manpower badges mush recycling disarm elusive snarls chiu flawless considers youre harmful horseback owens admits morales helene thankfully recreate travelers navigate pun ethnic kono esteemed exterior duffy triad licensed gems moira mutants testifying dissolve iraqi robes wildest portfolio tossing pussycat booby nbc simms knack lodged cpr lei racism nato mayo gillian stingy kaiser shooters napkins continents registry fags shah blinking duo gymnastics jag bernadette valiant exploited attachment trans intruders owning mega crispy administrative hawks crave qu reviewed persuasive turmoil promoting shoving bette unworthy elevators fulfilling ronny rooting irma mcqueen stoop ee greer panicking panels demonstrated myths mattie volleyball cheats chord berkeley oblige radiant anticipation fibers daleks aroused paralysis ferocious heinous roulette emergencies olaf enjoyable torso compassionate softer delegation fangs plaque alonso moi bowman uterus buggy kristina denies tally neighs unusually tibet fez charcoal healer weirdest eel recordings tamil naw camouflage seagulls hub shoulda mailman buckley furry pronto sedan kermit amir edible trifle delusion foundations calcutta cubes colon crotch tariq costing resisted leila snail ursula strippers vista sorta fiend ultra restrain pinkie voluntary widely uncommon blackie farrell infiltrate erika sophomore radios ringo medallion eiffel yamato wilder dyke bailiff peril plaintiff emilia transmitted bonnet assassinated emptiness helmets normandy cheetah clips thicker whiz saga bullock binoculars duckman accord diva jeanette birmingham bawk sita concierge clams questionable volunteering lunches spooked pinpoint hereafter brook weakened verses marshals deposited cleans ironically bodily distances hypnosis secretive dominion civic tori bursts uncertainty streams vortex tights sponsors tickles cello herring ab disability griffith orchid hostility conflicts pans housekeeping panthers wonderland ruiz interrogated andromeda premium broccoli garfield mussolini pottery shrapnel planner jacked robyn rounded giuseppe cactus motherland defendants wilt jia executives spoons belinda unbelievably fairness continuously spices organisms regretted monarch narrative roth catcher dictatorship controversy manu alejandro josef dignified bonded tilt beginnings peaks tissues pretentious dell jeopardize osborne diversity shabby brownies overdo sharma crunching tel marnie separating horrid overrated harmon rethink mastered eww reopen camels tux denis depended tak whine axis orchard cherries pleasing unforgivable craziest rods distressed bubbling interact manipulating rewind burgundy blacked trillion onwards reservoir participation caucasian flushing serbian manhood lao matilda exhale dinah caramel slander identifying drunkard blooming stocking rinse artwork catholics stormy refresh elisa cor floats expanded chilling congo afghan backside antarctica sandals investigative wills searches yawns collaboration untouched psyched hussein departments tuxedo mak bummed heinrich finer manure compatible moor keg monsignor peeled dona stings seeker watering ids malaria aj walters sinatra lending dodgers fortnight reassure braun meddling overthrow postmortem achievements excellence latch coppers raids dickens drifted leeds obsessive upwards lynette oatmeal midday implants unmarried murat sewers bowie mercenary perks outrun copying upload freya helga shu bumping inland yorkshire humbly injections participating python laurent cockroaches puberty technologies crumble toots miki roscoe clot exterminate rake cholesterol deli augustus sublime bottled fung charlene demolition methane appendix aches ahoy distractions dashing plank medications chevy zurich makers invading loner comm grissom miner senile commando mantle manufactured broth interaction lsd sesame auschwitz restraint devour zachary sardines orb govern respiratory elope webber wreckage lumber consists operates needless faulty alps assassinate santo edinburgh staggering jillian murmurs bologna unleashed brushing surgeries coffees advancing celeste trixie commonly mentality cordelia hammered meltdown rayna mastermind luciano olsen brow galactic muriel strand tedious burrito builders encrypted threads wronged judd gill cremated collectors prosper sheppard terri ferdinand handicap disciplinary hardcore hens inventions export alain vowed snappy kingdoms vocabulary cromwell tj reacting conceive sling transporting murderous marius checkmate patio rebound baptized hooves payday jodie pranks seizures enable seaweed delirious cyborg telephoned bravely huey markings widows gianni hologram fielding dibs triumphant washes wilbur lexi hauling buckingham steadily processes bey projection creed acquitted mink meddle buts kwon scoundrels spectators blushing faye frigging torches kato barlow horseman prescott vacations avalanche marking fret pacey glasgow editorial fleas eyeball trails insides bonfire micah anu urgency bearer provincial clueless chaplin mercer tempo conner capitalist bumpy maternal harass stomp cheeseburger didnt chime oppression resembles festive mayhem fleeting zodiac geezer thorns gags freelance whatnot scots brutus cylinder teri pouch sato fossils marko crosby plausible disgraceful dax brushed dai holed encore ludwig impulses takeoff ceremonies resulting refers shatter fascists entertained mckenzie rin lama specialists phenomena preventing affectionate precedent contributed blindfold schmuck raf hatchet bambi statute offscreen gao carefree pollen endurance dialed virtues coping penitentiary hallucinating combo bowel hypothetically jana mayonnaise vineyard tam digits myers evolutionary ribbons kabir francesco advertise saline edgy girlie rao regained parental barbarian brewing tat disrupt unanimous implications candice scallops vibrations homesick stung casanova tormented steamed baptism leagues kwan thunderclap harassed velma chimp consulted scripts restoration retribution bows unforgettable afterward adventurous swab inevitably expectation xu carcass notary lukas armand alphahff perverted surrogate spat dazzling snipers lai cartman capabilities midwife gains grumbling retainer bleak houdini inquiries expel berger markers reap specs morn deceit carole coloured degenerate adi petals dues tensed battered withdrew darlings starbuck patton mound accurately frenzy senators saturdays nemesis rocker whiff tagged fearing fringe peninsula carey radiator tolerated tor clucking stun specimens reuben accomplices somber assailant mutation ke straightaway spun reclaim paramedic capturing gaston biopsy proportions colleges doubting theoretical funnier whee indefinitely disasters sen forwards quo addressing iolaus pakistani neon slurping felon inflation zordon stallion blackjack passive milligrams irritated worldly manipulation strips hijacked jingling pushy macaroni bulldog rigid maxim checkpoint soothing hateful folding reduction loaned undermine frontal victories empathy achilles overload topanga piercing stamped potent bristol snob hypothetical detection unharmed subjected boils crocodiles coupons culinary mahjong fleur niko lira nonstop giddy teachings seong clinging silenced ramen goodman disposition enforce gunner ragnar ploy suburban sleepover slutty imply cheerleaders conception werewolves catalog paranormal shun aaaah biker jellyfish municipal ruckus adviser alerted commune granite fr formalities proximity unavailable fargo defenseless innovation paradox koreans valleys walden trooper infrastructure barrow interns taro bertha proctor hovering feminist declan observations prone spins conversion emerging sheffield dustin ares crazier od goldie bulbs blindly rabies smurf brownie formerly chastity desirable barriers hoops grains considerably anand baptist decorating proposals lahey staging diabetic baskets macbeth rehabilitation muscular revolting glacier expressions hiroshima imitation footprint beaumont stupidest unborn jacobs displayed commanders confirming garment latter indonesia enlightened plight hel dorian ogre warnings incision inquire tampered prophets listener substances rapping kisser hind apb ulysses butters dci tripp dublin meows preference minding mirage prediction dodgy drenched backbone sightings goku bessie virtuous earns grizzly slob floods enquiry begs juror strained monitored brethren oblivion contracted bookie painters amnesty cot cosmetics mortar wilfred friction drunks correspondent marlowe outskirts veer gaga wacky mann sparky adieu informing swung trina hamburgers interruption mediocre fulfil schedules sinks pathologist disposed knit excluded marcie scraps sob unhealthy borgia prestigious rotate tracey concubine sanjay ridden ballot fischer complexion bugle humanitarian gurney whit hoot sumo holocaust io yao servers hartley fabio salim sleepless fern forbes calcium frown deranged exhaustion rebuilt legislation sighting discomfort tru technological saigon lacked bermuda wept disperse kosher entrepreneur tyra worshipped wasrt siu unauthorized romanian melbourne flanders connors drinker hedley wyoming hotshot joaquin myrtle europeans deputies ther highlights musashi cate plateau remy sordid placement quota adjusted tuning rockefeller bartlett hormone apparatus gringo vancouver samaritan curves perceived catalogue gall luckiest escobar vending thelma greeted scoring housewives beverage fellowship thieving tidal genre unfit fetus lanes socialism outlaws entrust rosalie oversight reflex vacate goldberg mercenaries exercising bev prosperous symptom certificates larsen suffocate roadblock detain inquisition qualifications paparazzi eater prefect flapping discrimination incorporated callahan strengths rowdy productions publication collects winslow hodges astronomers prevents museums windsor nebraska lobe poses inscription outpost snuff luxurious contributions purgatory documented showcase delilah jurors unimportant moisture lefty hendrix replica wondrous horoscope hampshire esteban departing instruct morbid disagreement misguided optimism traders humane commodore rink initiation calamity nectar operatives judicial callin swarm drumming shithole annabelle spartacus trolley theorists rowan bowels density iong researcher timid meself garth denton romania earnings stalk righteousness fours kel slaps confide bravest fencing laurence masturbate vale triggers wiener painless believers eruption obligated mojo essex eternally dispatched repulsive ness devised headlights exiled impeccable oome donors crucified customary billboard costly imitate definitive simplicity waved pavel scolded separates carr nichols kommandant setback lakh liters relics clockwork cdc ventilation civilizations brawl bog pressures chills tex pussies phrases gob pricks jars rivera disable lancaster godfrey pickled novelty equations doubtful sexist capone buffer castles reproduce goodwin blueberry ryu oskar flo potty algeria geometry dumbest bahamas bleating horizontal assisted indebted spook fertilizer techno hinges zhu helium imposed financing restrictions implied idaho simplest traits implement supervise evident skank lucious gogh analyzing drooling princesses coastal bargaining matrimony airfield sensual takashi lennon cycles grimes feeble moreno hutton spikes rugged reviewing potassium tombs mimics elton homage devious postcards crimson activist rulers rowing conditioner quoting filmmaker softball outline doses perjury etiquette joyous intestines residential envelopes tortoise unjust fetish blasts completion davenport heartbreak safari brochure larson limousine hiccups boast portraits escorted magnitude collapsing selina coupon utility gourmet wrecking snore motions courting suicides meera apprehended prescribe aldo lian installation likeness interface metals blindness sluts thakur accelerator awol firms kale stretches tack auxiliary swipe shelters childbirth livelihood longed swordsman resourceful sabbath stormed gaps incentive showdown harding ref molten frosty franky henceforth renewed sitter petey richardson fingertips handcuffed cocking catfish johann charger disciplined outing como una glitch grants porcelain remarried firepower captioned hampton flawed uno griff scarcely rips roach stairwell memorized coded negligence belgrade arteries toot stunts buttocks forks mentions loco cedric mika adler bellows snowy pelvis hymn audit slashed frantic negroes calves pao aloha sahara freshly sabotaged poodle archaeologists gore meatball maggots horrifying prosecuted briefed cider pompous boomer coulson waiters abundance barricade gallon kali literal scrubbing implies discouraged kowalski almond chestnut syphilis criteria contacting trainee haskell elvira rambo rad poe farmhouse hallucination heals samba lizards straws silicon reptiles waldo paces fenton slugs leftover ze freighter bashed convicts jerky solemnly accommodation slag lemons whitman lemme verified jethro fancied partridge defiance laila hottie rohan lyla stripping pant mutton hypocrisy dyson invaluable ce lucrative cbs slows penal uploaded akbar orchestral endlessly hitchcock broads redo illegitimate dmv ceased blender accordance brandt dobbs makeover viagra enhanced unprofessional scanned mow whiskers tourism listeners rebirth predicament vendor confessions patriots jakob illiterate hounds malicious labyrinth psyche cher honda florist nathaniel extraterrestrials unthinkable frail plato planetary hitched elle flair ruse observatory heavyweight diplomacy tonya sri ev nutty extravagant caterpillar skeptical ideology pak chainsaw healthier linking prudent cutler mugs junkies rudder hermann ot laundering kaufman pints succession possesses urges structural lollipop atmospheric weirder sory stride blizzard extracted administer meghan pinocchio grimm fireball individually flask obeyed swain hubble burgess rohit coffins booster erratic undergo typed bearded salami ports hamptons marsha versa oval downfall warwick ulcer friendships domination dementia arthritis refusal juvie journals volatile performers beneficial seaman iranian sputtering sled mortality carlson hysteria hui beseech endings shea miscarriage patrons moya hun racer plots hoop dojo vents unfamiliar slab persecution monarchy himmler philosophical soften celine carmichael herpes riddles foggy coz specialized corridors parvati mikhail deemed astronomy reins yous duet beginner viewed nebula fascination fussy elect collier evaluate microscopic hearty mammoth oppressed diameter tailing intoxicated photographic shocks descending stakeout pioneers towed submission prostate ointment hr bids recalled gaius electrician aneurysm neha sulking actively mortuary ey serenity funded mmmm shreds pearce mixer rockin draining bolted tania assurance zapping bossy venezuela commentary beheaded waffle unnoticed onward rollins cnn cleanup cosy branded plow schneider farley deluxe aft neurotic rani chords tanker tides settlers bio rosen snowman berta geisha transactions reflexes extraordinarily chunks shekhar assaulting obsolete consultation agreeable impostor lobo wasp maturity sheik liberate brilliantly surfer hattie selma lowell sameer snores assumptions capability bridegroom mysteriously priors leanne defective joss tombstone rach writings delicacy tumble silva hospitalized fig speculate sha yeh fidel inflicted stabilize outs violations deuce significantly newcomer youngster engineered sighted riddance seasoned picket abc aziz mecca jeeves insomnia pendant harmonica listing viruses ich heartache trumpets dvds ruthie jace proceeds intruding betcha reddy pasture inspectors horrified neighborhoods sprained lambs democrat jameson lovebirds rivalry vial rv bret peeking talisman stats arsenic buchanan intake sheikh takeover scanners gareth foreplay acquaintances alphonse thames lotte championships pines swallows rewarding cornell recession brands firearm squawks shepard ukrainian superboy infectious morrow yahoo robertson pious brainwashed quantities societies sedated milly wines jimbo colourful superheroes bribery jacuzzi pours geological valuables crossword bunnies undead bathed linger roster rebuilding comms moods grinder weber harem proxy kincaid timed toxins mendoza originated tracing wham ironing quotes nemo mar hauled docking sciences accelerate relive aggravated rabb downright brushes adjustments chandi steaming confessing xiang lucie paso wary hemisphere quaint magically accordion aisha cowardice cramped bailing instagram curt fo stamina cheesecake testosterone updates fend lumps lux crummy lise coil discovers upbringing geronimo transmitting manolo franny barbaric thong trespass ballerina genetics lilies elegance kenji sats casinos yak paged welles streaming navigator cleaver anew marseille odor raiders sprayed crypt spam teeny twig anesthesia scandalous esteem carmine ripley breached benji givin spanking devi trot selfie strategies bb thriving haunts kyoko snails compose hopping coconuts amidst powering indigenous awakening bop hippies exorcism swiftly gamblers jd scoob maddox blinding engraved kahn labeled maude comforts ample hyo clang understatement disqualified taels brando meteorite seok trio centimeters fae reconnaissance darnell flares leukemia gupta alexei palermo shareholders kelsey commandments optimus din isa camper smoker frankfurt serene jocelyn trolls intentional icing fore bali gorge hermit countrymen vibrant smuggler dosage fictional fakes runt antonia intolerable pavilion livia pretext wail madge skid adores ibrahim cunningham jekyll swapped phoning barbed pledged galactica ecstatic mtv genitals ancients yee weakly typhoon citizenship terra turbulence responds lowe perpetual skis tipping irons lash trades shagging marshmallows possum jericho saxon enchanting sleazy abner upsets imaging dis stefano amaze kimono fleischman johannes disobeyed firsthand vans smallpox accomplishment vu complicate voltage traction lifeguard mcbride universities swimsuit discarded romano infiltrated goodbyes guillotine ipod specifics nuke katz khun chipped limbo rehearsed davidson lima moto marketplace rj cleansing scientifically pepperoni dissolved auggie cholera packets punctual mockery rafe migraine cedar bends myung fancies margie fallout casserole girly graft yvette stickers benefactor vendetta arun chiang fatherland boon lazarus participated dottie banish lush talker leavin gulps pups washroom soar frightens firefighter wipes infect desserts concepts stimulating indicating sequel sherwood earnest disposable noir lem sturdy finnish wook traditionally abomination compact samir hyderabad chino grandkids rec souvenirs shredded minerals hints forsaken rubles lucius anus pharmacist puffs diaries unannounced honolulu calculating blindfolded kingsley battleship presumed exceptionally topless scouting durant alarming bias estates fatima pods assisting molested offerings believable airports overrun parlour fearsome ticks widower versailles draper endanger dummies sook exploitation summary joanie drool plugs taelons piled informal stabler authorize promptly dover robotnik faithfully gemini selfless phelps leech sentencing perverts sassy vegetation nab lim carton featuring scapegoat burr provinces nd regroup heller machete micky rebellious celebrations reconcile technicians merits prosecutors eunuch unrelated captivity aroma barred pe crumbling manila snowball armenian penetrated atlas volts yolanda evasive piling watkins eisenhower cullen commodity bimbo starbucks riverside dismissal dada afternoons ballad cheerleading haystack perv contamination hye blurry lowlife malaysia reddington gah recreation authors wrongs regulars fascism fridays scheming outgoing penniless weaken wrongly whirs sandoval sweeney patiently birch incompetence spartan colombian kobe kaos prohibition gorillas oakland requirement skateboard zo lew similarities grazie aviation despised accessories perished wilhelm inferno swoop linden quill diverse hawking payoff retaliation raines whorehouse wigs megatron patel relevance novelist carpets brenner mambo shoplifting amp suffocated soho grotesque stewardess cochran jukebox minors oo detecting pillars interfered establishing atheist algae uni krista haiti mouthful algebra luka conor energies pandora collections punjab trojan disadvantage regan nevermind headless cortex ganga valium berserk ritz flack transfers adamant shortest distinctly kimi doorknob ruptured indoor millionaires carts cords carmela arlene celery jonesy residency conveniently ranking foil responses sweety jaffa troublemaker slum landry palestinian floss hap maw shushing carnage rapper bucky poole vogue troopers squeaky aditya undertaker compromising daisuke eureka privy sacramento encryption burrows hoist emphasis moderate retro cincinnati mainframe sociopath elmo nighttime namely mads mistook delaney cannabis aims spraying craziness stares ballistic fussing uncanny salaam rainforest arlo lunatics ebay futures confederate kelvin benito hunts ridicule unethical nai flushes gregor aeryn groot yue jer ringtone manson monuments crafty cooled jingles chronicle vested trademark trampled ku mules piglet cherished shang alba clem persuasion genocide brilliance toledo persecuted tuesdays inability quincy shalom toil weiss hes alexandria sdi epi orthodox custard bosnia wuss mondo detonation cylon evicted mailed liberties martine newport untrue berg bland heirs praises osama ancestral relish romero toxin seating bras medici flattery unspeakable reincarnation evolving marin muster cramps characteristic schizophrenic enjoyment bangalore britt employers casings painfully delays overweight dreary canceling viola behaves tragically mindless colette poisons unheard pyjamas contractors cisco flashy commend cinch presses mater plucked repeats carriers gen omaha participants payne yawning conan faraway mackerel loki flakes meyers raincoat thereby sewn reilly fyi nostalgia descendant hopped handyman lagoon merciless bouncer speck lifeless westminster donner lancelot anarchist amish ophelia mart sympathize croft susanna sneaked shiver pointy tod fad dwelling decipher acre animated predictions ehh penetration queenie tampering suk unsafe conned merrick contractions chaperone clipped masha ap singular loathe manipulative outraged lurch ultimatum delegate pedophile directive pleaded reducing hurtful latino wick smoothie traumatized thermometer vines fugitives persona channing herbie aargh marcello pritchard ist taping arkansas norfolk yamamoto congressional askin haze macau bazaar enabled deserts steiner eloped mutilated walnut excite pegasus swallowing plutonium doomsday talia moriarty cycling cougar guillaume spaniards asparagus quagmire thorpe donnelly nathalie centauri sims blasphemy rents continually nu newlyweds huddle adolescent crescent loch saddest gustavo bleeds giulia turnout nudity alternatives intoxication doves interstate spokesman itinerary slipper monsoon unfold appetizers scripture relaxation pox pilar rabid cackles kiddies lovable termination coy eyelids motorcycles insufficient ceremonial malt leaned muller soames hectic sudan nba owls displays brewery primal narrowed bidder dipped dormant asher diagnostic galen selfridge breathtaking saber specials xo apt winnings embracing louvre homosexuality georg solace gladiator chapters foxy whinnying scuba lui kessler deprive reckons fender areyou mags damsel brah cannibal chilled leopold milwaukee supplying rightfully vandalism atleast shrinking reginald robotic rolf krauts hiro karim pj garibaldi ragged bilko hoyt roma surplus judo doctrine accessible crazed audi purposely sleet yugoslavia ostrich gunning estelle oversee atrocities landmark holdings generators cheerio unimaginable stimulate incriminating jap clangs fanatic surreal sewage dehydrated acoustic ante afloat kapoor genevieve charisma sadistic zeo iconic enormously constructive elk exhaling admissions inexperienced misjudged mast clubhouse meade illustrious prepping declaring nucleus whomever councillor curls camden cowl townsend unsure mag colton prentiss costello chul henrietta cures marla swanson autographs borderline provocation perverse nutrients occult cadets socket shawl mio markham framing junkyard cabot twitch influences browning jfk upward cooped rooted deserving goro dost burps ludicrous demonstrations biography cy concludes retreating satin bridesmaid penicillin murmur martinis deployment pence predecessor feeny canon tian underlying avon accessed blowjob ashton transfusion blockade mischievous doreen jiffy repressed driscoll kaplan showered biff yarn astonished catchy titanium maguire deserter dah documentation guineas hotch explored bom dunham playoffs faraday feisty explorers blanca imam plainly federico theaters inadequate caddy astounding highlands hustler clans paternity washer borne gilles disclosure negotiated attracting andie indigestion spur cabe mayer schnapps hagen renegade barley koji spiked complains repairing cheapest foxes barf sox magicians inquest humidity featured keiko midwest reptile priscilla mythical paramount bitching unpaid neatly abbie volvo hippo smacked smokin brigitte dodger fallin rigby shepherds swamped hailey prepped frivolous copyright witnessing duly glide enclosed fai nameless rai armando electrons constellation howe inhabited sketchy implore malice agreements johanna deformed billing cornwall crusher strains orchids riker outdated reinforced yamada newark trainers janis provocative hemingway ci complimentary bethlehem suppressed bordeaux goodies geeks festivities checkers migration brig bloodstream distraught grasshopper ashok hardships tickling desolate masturbation fiasco jem rudi sufficiently hereditary psychologically orient gullible falsely friar tuvok underwood abed gunpoint jiro luo vern realtor attire clientele passages dreaded hatched hardened navid innovative kroner patched guidelines juices lockup delgado slopes conclusive latex chennai rey deathbed collapses schoolgirl fuzz imposing settings nationwide schoolteacher dealership kei hearings negotiator drills brightly dames neutralize rosario ninjas manicure meditate eavesdropping viewer mormon dipping splits muzzle redneck seatbelt richter atone envoy sentiments poorer tia sweeps forgives improper niagara highland hardworking enlist wilcox medically chittering pappy scarred claps gia outcast faucet prepares taboo weaponry consensus breathed maneuvers archaeologist tolls gobble gibbering rican maud darby hernandez smitty rica widespread scraped boutique quake ignite provider sprinkle serbia contradict realities valentina shaping powdered indestructible electrocuted silverware disorders everytime terence albany armory delegates pathology inspires poked scumbags cyclops floated intrigue auditorium kashmir inspirational doodle raisins sibling emery anomalies forrester honorary concession midway reload sweaters dormitory accelerated fluke larkin dwarves nutrition kendra warlock exploiting bloated proclaim middleton choreography patriotism sash detached niki fest intensely raced sprint endorsement gage carlisle hobo gauntlet crowbar progressing groin prudence inseparable chopsticks guthrie foo cavanaugh saxophone fiat drains thrusters tink visibility passionately wannabe klara tiresome complexity homicidal succeeds rom scolding indicted prix alexa uninvited insider kamal moz bondage chao taser indifference tum slang tending compton gunn campaigns resistant baines urged reacts snag fidelity mcnally rattled stalls quickest copycat wilde damnation burma cashed dodging canopy ridley ilana ogden goof twister rolex seriousness toothless reckoned macdonald retching immensely overlooking airway lm rickshaw esposito propulsion elsie butchered orbiting herds comprehensive reckoning shelton israelis thursdays fabian journeys confiscate coworkers checkup wad aeroplane innocents endeavor shootings daybreak mandate estimates inflict drapes bellamy wolverine socrates subspace notebooks unrest annika hyuk shiro lala cram salts infinitely exemplary bearings replicate perfected cao olympus baboon reproach completing medusa sewed teased karev adversary captions doyou stitched abruptly stacks sioux rapes ether hoodie namaste extradition vincenzo ange cambodia clicked tallest jeb unison ion bozo undertaking relating enrolled sprouts secretaries projected turkeys irwin fink zedd sipping africans macarthur visionary borden talkative alyssa sie kemp jeffries unkind pegged conservation veto blondes heartfelt outlook wrinkled valeria teleport interrogating diabolical breather desks eyebrow tut sightseeing unwilling profoundly barclay dearie dae nearing hester franks rashid auditioning dyed pharmaceuticals cantonese pika martina clarkson toki outright ito coincidences downside oats ortiz administered downward okinawa graduates palate jihad nakamura emmet lucrezia martians nasal enduring winged thrashing dumber faggots bernice vibration musketeers tumour stature petrified erich ieast hiss baht rematch lakshmi lightweight rah eunice pharrell attentive dunbar negatives ge fates equity ringer tvs brooch delinquent schizophrenia bangles sculptor netherlands inca ado odessa marisol neurological slums comets strife coordinator chokes santana guerrilla charismatic xev garret startling historically funnel curator improvements campfire castillo himalayas storeroom jez tulip looting pinball decaf marshmallow guitars sharpen darla refreshments tensions mckinley hathaway leaping reconciliation vou greenwich waterloo isaiah ofyou idols induce cosmetic grooming dalek rejecting cortez schooling wasteland blueprint biz smokey nostalgic lon leprechaun zulu dinging hoof timetable transmissions barkley analogy stomping judgmental bagels levine meowing wallets nightgown demolished bobbie lafayette electron cones motherfuckin calculation dreamy vigilant asgard suppliers vogel companionship dangling pic rushes paired withholding clones burnett bolivia commitments airs tubbs demented apprehend learner minions toro scenarios sandro fda overreacted contradiction gregg vat nia bellies mardi horizons rev puny nominee insolence wartime fm shing grapefruit deodorant concede homosexuals hierarchy remnants detectors sever hendricks nachos jens munitions gyu trailing rochelle folds attitudes twain develops stomachs emerges chilli hotline dries acceleration gruber surya homicides scrubbed murph seduction trait ezekiel translating chemotherapy hazardous taelon hackers pancho asteroids defines meatloaf nephews boobies collide mohan iphone flores salaries porky coulda sheltered revoked cinematography variation maia railways burglars asa milkshake newbie undertake fergus stellar dud abode isles elmer tiniest latitude crucify salazar clarice sledge shrewd blurred spatter menus nostrils filet lexx locally consistently synchronized tres bumblebee mccall thrashed annabel tutoring ingenuity scriptures visualize juggling beige oslo hypnotized enigma lanterns marseilles memento bedford uphill prosecuting volumes contraband claudio debating bagged albanian staten cahill ravine protesters writ stalked heroism prolonged benevolent squashed baloney sweethearts sweatshirt nutcase lecturing developer deity quebec unni jailed attain distributor hype shackles portions housework ferret mami snort kiev ghostly chandelier dubious mstoll mammal suspecting bubbly jacky follower starling sup albuquerque smugglers consuming burp jams neighboring mathias explicit titty dual anwar plastered gums extends bitchy nicotine edmond alumni boop tremendously madhouse hearse snickering wizards oaks humankind belfast partisans recollection holdup mantis martyrs micki birthmark baldy supporter fundamentally exclude traveller ichi vp unravel ratted tucson stabilized banter drilled malloy architects taxis consecutive untouchable trough nisha wither pew pesetas accelerating brides inventing embark stalled chameleon spawn selves nicholson taggart quad sellers stevenson fatter tendencies rodent soaring bolton commits measles schwartz slid yanks tyrone kaylie charities vamos benign charmer aligned topped gnome wholesale sur plunged paddles laddie blitz dole barging mildly reflecting tended staked cylons boldly vocation leung memoirs infidelity nugget cecile operators aki swells securities rejects dialysis lineage notions wharf comedians polygraph recipient atta beetles nests puttin recommendations adopting complication hemorrhage annalise reconstruct anesthetic consort revived mats chaz owing unorthodox slop meticulous seagull damnit forthcoming dion carnegie cobbler quark freezes simpsons honours manually resigning polishing vibes attila cranberry gigolo persist puffy swiped fir hawke startle wingman submarines daffy erect mutually roadside prodigy horton kerosene editors governess integrated canine reformed lifeline lockers hors mondays brighten chavez achieving scottie optical lug lag spirited hark hopelessly bouncy respecting bueno beirut mounting hurried kimchi jong moretti slaughterhouse davina shilling tarts overslept grinning collars yuen kneeling billings selfishness unloading mets sanderson straps eviction rog eliminating bae manhunt whirlwind dodo munna lobsters riviera millimeter jimi fished wield detachment mps legions hasan hooper crabtree fragrant marek glands palaces delaware hurley faction ive rooney nominees sleepwalking hairstyle cryin pastries eloise casts tijuana marple cabs synchro spotless sobriety beka gulp intensifies theres heirloom merrily unified fixes briefs aesthetic swarming campers directory tabitha cheered priestess entertainer whirl aspen pia ipad devastation bernstein lumpy wrinkle podium evils guesses discreetly squads chunky cj gadgets advising discredit awoke grammy custer ajax lebanon stumbling furs chucked pulmonary pawnee compel midtown ottoman mano ramos messengers parrish walkers makoto gibbons ammonia markus kitchens ru swans pretzels drags yumi fickle punctured visitation rounding lavon commute adama carousel fronts stutters whips wholly checkbook stronghold jubilee offenses specialize diagram civilised mould revival compulsive parisian egan bergman lawsuits shui cubic jennie yogi seasonal pressured restart kryptonite kinder friedrich bosco hesitated proverb wanderer exchanging alibis weaving airlock gambled finalists medicinal depraved mimicking bullshitting roofs contemplate physicists heathen urgh addictive solves heartbreaking dynamics advisors restoring outward rambling boxed camped praising topics conservatory horsemen tatiana clarissa frisbee defining momo cognitive braddock diminished donating stoked biologist riff fasting elm councilor oww starr appliances conspicuous gloom pacing gopal scrolls muy errol garza handcuff verma crusaders creations shep fines implanted intellectuals soprano vanishing frightful omelette conquering polka ordinarily travers cipher tonnes bolo chou denounce impersonating taxpayers perceptive wilkins hugely lowering prescriptions activists affidavit premeditated paloma moths patrolling anthrax shipyard notre gloss adjacent phoney territorial mannequin pratap toyota bren cuter nooo koran paxton papal yorker keepers yearn calming farnsworth carp bel fluent minivan rochester lister descriptions takeout ahjussi enrico hillbilly generating raghu unconditional unofficial tiara gowns hearsay renovation lucinda misled pastures clogged lax clank remington pimps footing twists securing fiesta sweetly jie tien lashes illicit degrading similarly repaid raffle gs denzel sulfur homing mead delphine stasis dicky nobleman adelaide fuji momentarily newt slender implicated reece maverick contraption dancin fester stairway earp bins flake cubicle harrington mans flashed rainer indispensable trivia alderman manifesto wednesdays bickering bruv prized dodged hurrying kimura entourage pretzel hickey conspired mints thaw unexplained tampa acquisition amigos leeches unholy profiles keypad imposter gutted conceited landscapes hewes pubs pubic infernal defiant correctional rated utopia insanely mousse finder dividing veterinarian puking huff lyin puked naught georgina greenland bane merle tribune gauze dredge crutches rabble handgun vaginal announcements infections corral renata augustine climbs universes rommel ditto likelihood archaeological coastline nestor javi rigor misconduct lucid dolan majors donkeys imagery preservation masturbating presley skinned ornament shrunk sneezing glare hanuman watchin exceeded aston flaps sculptures accompanying sami mahoney scrutiny invoice revelations sprout mime diverted alms tilly garner shiv domino escorting maris ephram aiding penises upgraded inserted aspirations furnished oop gunmen unprotected smallville temperament roper chimps stressing rejoin madhu cordon freeing suitor tangible emir limping lol naina arouse caffrey travellers monumental bipolar hurl baylor unwind supervised chandra drinkin devout architectural killin larceny trilling medina originals lear paved decrease appetizer hamish almonds crunchy treasurer waterfront elixir perrine miley unmarked knuckle guatemala tenure seein abundant calms knicks miraculously beatings gots milking tumbling bead nurture uber kebab salads redundant yuko populated goalie yusuf celtic superiority bernardo giovanna uncool mileage cocoon mako starlight valves shucks surrounds suture landslide okey hover marches foyle tinkling rimmer bojack terminator rainbows circled mellie restrained lodging claudius rupture thinker variations magma galley jodi gloat wayward wolfgang nein strolling corpus reproduction babs cannes railing turin ridiculously horrendous chases positioned angrily bowler bot naruto yeung caterer cultivate fullest mcnamara rampage extending holloway forbids odo forsake mocked jerri nightly petting ust severance varsity damascus digestive retained jagger quoted skips throbbing firefighters exploits scientology reeks deficit barrister pepsi dunes relied evade goner doggone gallo christening gothic ethiopia bri shroud dingo smacks spurs stimulation betrothed relies warped justification candid scrabble vcr visually liter isobel koo evenly emissions dooley counselors tahiti revolutionaries putin metre conqueror qui favorable marv montague tarp hancock mayan overturned holster herriot christa crowe realization faintly hawthorne tuberculosis statistically capri odette tolerant modify clary inhaling plough exceed flutter jackal detest kingston rhys sapphire andres scariest duff foresee unsuccessful sy odyssey premonition psychiatry sexiest fathom montecito pears seizing hani austen therese templar hoods hospice creak yip maniacs rotating keaton behavioral subtitled adaptation eyewitnesses meatwad indies mavis swede intricate nirvana offline cyprus selena devoured coloring aristotle quail suh cheques independently robust danke cannibals zeb mitsuko deduction fives bombings impolite dependable darrell mundane extremes duran introductions pledges pestering carlin patrice injunction windmill pebble closets relapse char retrieved jamaican dismantle lingering reside rachael entrances claustrophobic hick bison barack chivalry meena judah sanjana poseidon bonkers surfaces jest teammate toddler lager antoinette incarcerated stylist propeller novice scarier bloodthirsty nightcap entries curved chants juanita warms viceroy cornelius rustle vertigo communal pu hemorrhaging springtime avi puzzled syrian pedestrian marino blazer ballpark plagued consistency deena bronson untraceable relativity grazing paging regretting recharge ahhhh polluted karthik plotted drivin smoky bertrand buggers katia revered aman nandu cassius uss deepak vittorio bloodbath psychosis mulligan backgrounds downing ramesh affections cbi finley repercussions krang humping shone dietrich bub hornet emperors mme rhetorical unsettling wacko famished distortion vishnu publishers meek reunite carotid chinaman terrance starsky telephones tock competitions lapse gayle plunder unloaded plump trendy sears vasquez bureaucracy carlotta rhode fins intending conspiring sadist seminary bicycles sculpting condescending orgasms lenore moonshine incurable pamphlet clinics nottingham nominate wholesome termites thunderbird mckenna frigid aviv occurring ese summertime skype bikers induced missionaries arabian lacrosse rarity gaines dumpling brood creamy weenie eggman goddam supergirl roadblocks lennie seductive ornaments annoys wards tintin dimensional reverence charly belches hooligans lavatory cabbie adrien extinguisher vader madagascar breeds audacity cadaver fluff yoshida raina willpower sicilian bewitched cannonball esta sampson aorta sidelines candies defeating kruger penetrating aqua quitter wil hydraulic pulitzer trucker clinks pooped calculus tau peeling filters overtake ell kobayashi transforming cultured magnets cartridge langston choppers sera nuggets honoring historians shanti fainting dears delights soothe gazette unhappiness bertram continuity pauly packaging suns sheba enmity mansfield scorn staple sitcom commie toasted coyotes vary singin decorator laird liner eggplant alliances huts appealed molecule mossad petite synagogue palestinians quilt gynecologist stutter warhead articulate giulio nudge os jumong mordecai bombshell monaco brooding vertebrae therapeutic booker coordination atf mathematician smeared mizuki uncontrollable stampede giselle amor prospective limestone conduit kabul dipper willoughby avenger orbits sentry scrapes mishap lyric disapprove intimidation doubling impending sachin shootin shrinks themes shamed indications senora crumb limitless ahmad tiberius caveman bonny faintest hawkes grandeur deke prasad showering dildo executions corroborate contingency suri avenged defenders translates mila primo bestow combinations godforsaken pedestal stout glaciers mahal moby valentino dishonor otter eminent supernova weir java seasick populations flips mooing mani cabins pang presumptuous subversive tokugawa elastic libya pristine width sweats accomplishments remainder resides impaired yellowstone retreated lateral remembrance smelt biased strangulation prying hermes sphinx internally rhoda fisk sympathies nickels galloping lamar dara downloading douchebag lotto danvers rephrase casablanca ventilator kraut sanitation ekg diseased eskimo confessor aladdin rutledge ruddy brodie flashback caged imperfect routines reconnect plymouth quantico sanctioned vulnerability rearrange synced citadel guillermo nibble forcibly insinuating malignant enslaved canister intersect zeros undefeated gunned candlelight clancy mythbusters meng salesmen britta daisies maxie thad hairdo oblivious yoda criticizing truffle vie crisps strangling petit shootout abduct cloning ranked dazzle stork coronary jive mathieu lard shedding massages poaching immaculate hefty stocked buddhism monologue mehmet satanic linear swami blackmailer bora endorse enid kimmie liege looky subsequent madden snip hernia philosophers rapists recommending highways bloodline septic categories graces hammers yeast mueller cummings avocado logically oaf corbett prompt alonzo mushy shinji ei campsite eels safeguard bling farted auf flex fruitcake danes fulton heiress amaar beets izzie racetrack ganesh escorts leaps rajesh parson gazing pap imprint jigsaw coven palin ach discourage recycle constantinople sheesh appalled lisbeth unlawful birthplace wank thriller hepatitis clutches yves publicist briscoe insistent hires tentacles archangel schiller submerged brianna manuela rd intoxicating crock hither cliche castor anastasia timeless enquiries occurrence pilates hypocritical sharper healy manufacturers governed proteins resurrected hearst cushions psychiatrists halves menopause butchers preserving environments ponytail louse dilated garbled prognosis neutron airtight jazzy ufos compounds blazes bulgarian lebeau coney bulgaria armageddon contributing sinbad inauguration slicing restraints accents frederic cavern kremlin warship olly militant objectives newscaster verne calculator nicknames kiddie replay tibetan daycare abuses zee righto programmes yung snout rein dwarfs mono darned embryo frosting obituary tickled truffles susceptible heaps tingling canvass brits cherokee tov twenties neanderthals perk pebbles braid fleece sensory chirp assaults pheasant variables mas moping docked websites bj popeye minefield sp histories distrust yapping vigil problematic conventions smitten craps invoke unconventional ralphie barnett rundown oily giacomo coordinated prejudiced scrambling seams googled eyelashes frannie arose corky discard purchasing ignacio hijack yam masquerade logging arises dempsey michiko settlements fetching goebbels eagerly wring orbital janeway maggot umbrellas nationality cheddar mana keel meryl alignment heterosexual fats narrows heinz eatin irritate emissary taunting hangman bjorn cunts comma whimsical format peachy godspeed sony hitman bleeping demonstrating jove overflowing tully censorship hispanic rizzo bestowed shuddering fitch pathological silhouette seema mccann obsessing sugars bachelorette bonaparte impartial metabolism astronomical newcomers tabloid vanquish zorro willa slurps preschool remake heresy homeboy ag ravishing finesse minimize boca woodrow nigh nil astronomer selective choo arraignment crawley superpowers springer impenetrable underdog gossiping jig poached sculpt hokkaido daniela equator sexier incorporate cath shivers vinyl accumulated malpractice ascend ecosystem vs forefathers grit etienne emilie soles determines nylon blob snug gladiators valentin collaborate clothed uproar avail gentry defied stef parkinson prune hem krusty ellison ning lawfully fairfax tumors hots cade ver mimic nacho gordo thoughtless shitload thrice schoolboy dusting ori tabloids mermaids residual sancho striped dod blisters aftermath stems inhaler reinforce qualifies lube provoking continuum guan uma observant peng peppermint fused csu neanderthal dukes pierrot measurement prima sergey authenticity swagger soundtrack taipei forman strut ensemble duval tantrum motivate annihilate signore disrupted divorcing medics confided beale brandi wreath maui bale clergy aida bieber retaliate genome vacancy tranquilizer diligence loops neela impertinent hwan advancement armpit districts cavalier specializes chong combing mascara massa revised compulsion bran buoy criticized adversity beneficiary punjabi openings arne graphics huntsmen ozone interpreted incomprehensible kaoru lenient perky herod unavoidable retract flowed compression demolish prodigal generously anonymously peabody crocker amid youths dispense roe telepathy occupational osgood roxie loudspeaker torched stardate yawn hyena reiko milkman dal hillside transcripts prevention tout toenails mazel imaginative heretic hives squawk repression arithmetic dramas subsequently cardassian clanks renewal shocker spectacles interval quickie proceeded prometheus performs senorita deadbeat burbank mooney geology withdrawing nav thi sinus kennel feldman millennia subscription marquise warlord zed governors unintelligible dag gaia withheld involuntary reciting massacred rosetta boa oils pelt brittle unprepared willingness cutters ins coarse frieda mala walrus portrayed contemplating blaster tricia scrubs bebe defeats hollering simmer valencia annihilation textbooks filipino jawohl filmmakers tennyson ps luv firewall lyons weld facade conserve stepdad khanna divulge gab kieran ravens wiley weirdos sapna quartet conferences dusted silicone clocked tanning breathless smacking mantra vests epiphany joseon motherhood decor perch flux maynard totem cherie secluded smother patronize mower keung pediatrician bridesmaids jehovah dem informants thunk tract pliers harming pooch anti reinstated gland stricken dials zeta exes haines tandy disputes dizziness knowingly frida newcastle groves stalag festivals grudges blabbering plural curriculum firehouse coo pug clerks savvy chopin rebekah dictated siding dios peking valor dahlia liras affordable scrawny disorderly psi unattractive eulogy marlow felonies gingerbread gent misdemeanor spaniard flagged optimist mori commons waitresses wanders mugging crammed cayman accommodations possessive shutdown compressed czechoslovakia geologist crossbow kovac aspiring autism commandment fateful rooftops leningrad lexington archers cremation petroleum diem moped clair blooms lamborghini dysfunctional picturing ifl purchases debrief pulses devin barbershop rana condone excitedly antarctic manned crafts awaited atkins beards chaser subbing chatty inez maintains readily gunny baffled insatiable archibald skater jungles upstanding spacious probst sheng foolproof nutter confine fam diablo leone daydreaming incest abba mathilde unanswered exaggeration shorten ramu biggs guise graze clarinet cuddly americas scavenger middleman garde alot crusader mcduck baa propane skaar sickening thrills toothache overhear altercation tudor freckles furthest fuses swamps ambassadors zhen superpower enraged esmeralda aagh loomis unpopular locating fitzpatrick ordinance grocer courtship zak pics ripple smashes conjure winch shipments hustling glorified spied cabinets cylinders mongrel ifwe dui chlorine radiology hadley oscars projections soggy regal assumes boycott klingons progressed telescopes bradshaw pats unclean banners mesa consumers germ stafford excursion heartland jenn gm mmhmm spontaneously takeda dun initiating modifications feces droid alcoholics trev horde grips roderick premise scorpions campaigning obstinate fiver outburst diaphragm handbook rudolf serbs derived croak executing interim snowed rosary scourge pippi drowns crore tic adrift bisexual pointers eradicate spunk snyder hyper inning expendable addams noelle chandu ono sutter hazy relocate alleys sunflower financials irritable hanger neuro clooney silky tricking kalinda popsicle yau urging moroccan encyclopedia stripe stationary ptsd sermons dink parched guinness ravioli predicting masterson helsinki excruciating callum consensual compute trays nikhil overjoyed liberals mcguire warehouses durga harald stereotype cartridges whitaker raiding sustainable commissar soiled standpoint fruity stayin rafa creams watcher thereafter egon drifter financed fairytale intimately keisha wrapper spectator purest raisin alchemy antimatter withered saki maki rutherford shovels holling piers deprivation loren landon curing deluded wynn rumored eject kouji banzai qc caved mackey binds keating nailing botched takeshi botox pinto tinkle nfl supplement tragedies overcooked immersed rollo crucifix tamed czar withhold seismic muppet asphalt bobbi charred bowed floorboards tycoon defects aristocrat vocals recurring epilepsy shakily weller wakey poachers garments welcomes balm nagasaki cooker swaying georgetown pardoned mach moors yeong yippee sheds fifi quirky steamer ritter nim flunked sparring sabina ceases lexie nesting blackberry fiercely impound ucla bengal cache lifeboat daeso creme hallie rhine consequently revolutions shim shyam rosewood larvae hos yeti fluttering gregson mandela occupying jeanie aphrodite cools lasse snuggle sharona riled turnover misleading presiding accessing kicker pre hosted ordained nassau hombre brazen eah prof stitching nook splashes cyclone zheng lovingly colonists researched physicians hogs unwise affliction aspire dow hooch pai lacerations tasteless deirdre welch unbreakable carnal generic melodramatic distressing sentinel lifetimes yelping projecting takahashi nepal bela unattended hellhole renault efficiently gonzales wobbly recruitment lasalle wilhelmina hashtag reek emphasize melons dept chore scat aired chardonnay nigeria ofyour meats monetary lowry notjust tormenting combining vixen napping deactivate goblins merrier busts regrettable ugliest tac evasion clementine overworked pta waterproof alamo salome halibut seon communicator laced fuels phi supervising slogans garnish kam mendez spruce seducing implicate leper unpacking germaine ponder nicknamed chakotay femur detonated technicality situated vindictive twit obeying lutz waldorf larissa gopi hypocrites shogunate mural enlarged glittering woven contender orpheus illnesses captures margaritas hammock prolong gallop lieutenants whistler chihuahua tehran pasadena stroller bs issuing ie foes tig proprietor speciality centered rosita granting hindus gills puyo sos edwina mistresses fingernail starry hubbard lolly cardio delaying savoy fahrenheit chaste buttercup barricades berth stoner hitter anonymity clippings mod dia dodd insecurity contests incriminate variable startin chloroform essays poised abrupt hauser exodus refinery browns gonzo proclaimed techs kuwait rustic dislocated celsius intervened mane confessional tagging pinching sideshow allegation polio hoe motorway sayonara lastly duped spout mun rupa undergoing smothered sulu nowt micro garvey teapot diplomats exhibits confronting healthcare mattresses buick toxicology liberating climber opal reba contend lamont switchboard sana yap insights disoriented meditating nightclubs cater emeralds facilitate vigorous intervals excel fraulein appetit reggae plastics revere lore creditors resented blossomed activating composite hindsight mummies bedding craven shitless songwriter scented plankton baird locomotive ticked mapped jolt reforms gucci overcoat bishops conscientious venetian evey calder logistics ahmet dieter rampant waverly whitehall hock chrome sandman balancing canals oxen superhuman ein rogues dossier pikachu waxed infested benz kolchak folklore turban carriages lanka ade recycled alden busiest courteous baptize bowing ventura pamphlets amiss michaela hex swapping detergent afflicted dethklok overalls reboot pining nazareth insubordination sputters slammer vices dungeons binary hesitating attendants fined sanford volkswagen excrement dictates epstein swims ethic boulders lockwood bucharest twos cornelia founders tb locksmith circulating seine rattlesnake toying cardiff chitchat chimpanzee envied nocturnal peppino galleries partisan cluck falco hobson clandestine doctorate blackadder smudge bona pressuring kindest moray cuddy beastly agile sodas visas portia specter det nabbed integration granville bayou sorceress harvesting bakers litigation misa disruption shellfish kerala grasping prakash apostles kraft extermination arsonist morphin gathers tsui tubby refreshment bony tuttle diligent handiwork disguises sneaks installing betrays malhotra transvestite darth secular newer watery pecker surrendering intestine md repentance burdens mont plums kolya sulk arden cleavage blunder panty detox thyself anticipating scoffing recognizing judgments headmistress goddamnit telepathic spineless astrology reza dopey drummond trusty loveliest ditching reassigned elly faber pusher col chucky dashed sisko cashmere cams etcetera mistletoe sorcery teas innkeeper maidens seol delinda tranquility mais indicator phaser nutritious rb mutated varied heightened blatant proclamation guerrillas trident keepin collin corvette ticklish gaping ideally oars scandals vengeful widowed brit emmanuel salted surpassed exert poorest systematically evac radically purify vibrate announces transgender lofty sequences nance addy tulips illustrated unlocking shudders nurturing merrill generates disloyal aggressively skywalker asbestos haru improv ems hayat unpunished displaced andersen bowen thundering semi crutch silo yokohama rubs dipshit levy symmetry inflammation unaccounted nikola licorice applauds homeroom kabaddi grievous counselling ortega trample nani tipsy rigorous brewer hurdle chisel kiran bistro hao wainwright chests newkirk bottomless combustion erupted autobots clifton forwarded katrine tidings stubbornness dix pelican matchmaker howell geiger moles mucho binge piping tiff penalties enables irrigation hunchback margins provenza relocated centres pitches vaults hyacinth gable swirling filly putty revisit fanatics concerto unbeatable rupaul matey kemal carthage loophole replies beeper injure cookbook align sanctity spilt whence geographic admirers mislead treadmill ferrara fated resurrect rina fetal coca qaeda nona hoots tampons crept mania unplug veggie keyes subordinate timely telugu proofs ivanovich appropriately vendors recap roo dinky accountants archaeology mikael strangler genghis freshmen nic nothingness katarina authorised brightness maximus payson bogart urinating dok violets compromises defences ibm scanlon corp compulsory seasoning taft famously surfaced gibraltar cuckold uneven reopened blip valhalla midori similarity frodo gizmo swindler indulgence wat topper alligators garry dives minneapolis reeling bene outlets siamese rupee unrealistic endangering gonzalez gist adventurer prosthetic bayonet julianne bismarck dresden paro encoded ruff luce supermodel pollock calmer chestnuts parsley overgrown storming rahl alfa sicker maru ohhhh abbas inge resilient ly monet abominable empires revise vets arches condor apaches blackouts advertised quixote labored excavation salud ironed francie bartholomew laboratories riddled flung yanked sadder neurons licenses communicated nutshell scofield savor cbc bedrock tempered kenzi bunty pol cleansed favourites rigging dawned inconclusive graph twigs callous tyr bosch embezzlement decapitated seinfeld bannister mccain clusters annex samuels royalties seville admittedly gimmick lobos verb fightin mistaking abrasions frazer stow unchanged andes neglecting daggers hypnotic distributing stonehenge hailing vapor clemens blanchard waive lavish cultivated sunscreen buffoon hooded obstructing bonuses rapture olympia seenu grate inconsiderate armchair floppy loitering clement drainage sho mongolia woodland looted scruples frisky rubies sovereignty ofthis recovers betrayer promoter ugliness cancellation bribing merged aggie barons regression susana punishable ganges bachelors forgetful asha pilate disgruntled fireflies deceitful splat movers mended plating misunderstandings iittle cryptic monika jefe marmalade coals ignores rhythms sculpted vicente pounce lesley completes pim assert ht favored curled pelvic pansy requiring entities tenor measly tino hoodlums indie ladders tasteful lassiter shaker maritime absorbing mclaren splendor sax denounced antics hailed meanest sprinkles trampoline swag roaches othello profiling lifesaver slurring platonic hoi cretin hyenas harshly camila krypton autobiography humorous seamus hussy nodding stinkin comp lyman keenan fiscal baltic hallways gracefully comforted promenade champs exorcist courtesan clubbing alloy guitarist suede roasting kun simran plaid rollers nyu flannel niche census mata braver verona hysterically shriek klan bathrobe atrocious calleigh borough chalice frazier airspace hesitant aborted jeweler rhetoric brice strickland seamstress feverish saffron storing mla regeneration augusta scorpio algiers forbade hushed suitors governing dotty matured tropics threes trapping chantal swann warrick slots dune horseshit extinguish juggle yon goguryeo mobilize trucking berman hakeem framework kan attackers prenup orphaned parry respective dario prerogative chipper ramiro woulda attenborough mortified bitcoin crusoe axes pickpocket flammable apos kickin leicester archery blanc henchmen talon hardison purses glucose whims muff cauldron roundabout gorman estranged phobia aang vanishes watchers banning navel ascension piazza goth projectile fueled brothels jitters crybaby upstream notification bennie fabricated grumbles ck ish regis inga textile realism dominance circulate autistic sickly ambulances sac siri spiritually recreational forwarding tetanus fliers prowl quot atop itches meningitis mcgarrett emailed dimes suburb hartman aztec mocha accursed dmitri sarajevo kern launcher improvised defying sofie mohammad halley ducking alexandre uglier mitt taurus warheads apps inspected undoing counties perm shuffling vanya shifu takumi touya bengali weakling grampa humid infants barman straits annulment qiu mapping spotting eyed zing decode umbilical blackboard probes cutlery booger hasta shoelaces redeemed morgana bleedin hue exterminator aristocracy wavelength replacements bongo fittest glum farnon deanna gloucester perilous snooze commandos wasps abhi jimmie processor pendleton ascertain deadliest reproductive prophecies instinctively commencing mined reassured dislikes jokers phasers strayed feller templeton curling winthrop monoxide xin rankin armada overreact twirl kits hanks fountains sawdust firefly interstellar subdue massimo fabrics simulate libraries arbitrary petrov ratchet vascular poldark coos handmade ahjumma bluebell ultraviolet obesity sensations deem higgs charissa reigns dub bounces nicaragua dawes shrek basque burrow pawned boardwalk poultry scrapbook fantasize watered offending roswell magdalena overkill sodom antelope discord henna pigsty aristocrats downstream undies dashboard chez inconsistent wickedness bok disagreed susannah piccolo vila soto pauper oxide cauliflower roxton fiddler ivo matteo nitro guacamole branson cosette pawns cardinals tailed verde vd rikers fiji extinguished enquire prude lik boundless climbers romantically hefner strands arrivals hula combed sou corresponding kindred repel pil genoa durham squish shopkeeper grownups nik showroom warts overdoing laxmi laundromat humanoid dreadfully cheery shards shenanigans std rhythmically ronaldo hbo atticus bligh masons encourages barrage blockhead sealing annihilated glover harvested trisha overloaded narc tulsa persia spills timo taxpayer ser menacing clippers flirted spiderman foreboding exhilarating understudy cv maman castile tact schematics roseanne smarts provision mccartney manga housed doghouse milhouse anchovies ny fab warbling ofcourse huntington ghouls applicants tigger stringer critters topher yemen vantage canadians abandonment theology commemorate compressions nerdy aegisshi raleigh frenchmen ld nourishment sender nursed gulls argentine oan consciously tenner waiver magnetism woodwork remission nils hooligan dysfunction hijacking dickinson vanquished widen mobility rafi microphones provisional hamper mcallister membrane anarchists horst hahaha lecturer tampon maxi sanatorium tangle hearted gabriella succumb scab dissatisfied cali butting lain presentable prompted nietzsche boating eichmann relates bashir swedes trumps yuk hypothermia sasquatch binder unlocks lookie potions insure bohemian ilya skylar petrovich jester excites uniquely cris regulate factions irreplaceable pied smithers unofficially canterbury shank alpine prowess fernandez trashy blower tenderly depicted carlyle disturbs mussels mali sigma croissant charades mince kilograms homies boasting dined xanax passageway ranting pixie pharaohs nitrate hyperspace insurgents ferengi yiddish trends elevation figaro litres pastime altering fricking ussr brie spec abolished earthlings evict janeiro pricey mending pesky turbulent attributes nessa downey gerda baekje albino activation flamingo polling eggnog lor bashing expulsion verity granddaddy dominican flattened mba analyse untimely reversal elka kensington ambiguous tortures glock clouded chakra percival sundae housewarming lum frylock diagnose emblem posterity thermos lookit perseverance vivien hamid mayfield midge garrity untied bulge forsyte sheen greased optic pasquale ridin ridges twitching myron mariano exterminated grrr crossfire topping impudent bloods lupe gravely manifestation moat prefecture esme kwang hei noticeable muir mausoleum claudette consignment algorithms alrighty tonsils wrongful knackered lacy successes daddies grilling zeppelin lok smartass catalyst bergen checkout jobless rhea dotted tarot promotions dangle firecracker laces concessions aphrodisiac expresses crowning worships quarrels launches vicodin utensils walnuts snare croissants neelix parrots deficiency sores destroyers firecrackers conjecture airways saucy terrors swindle taffy coerced pornographic imaginable digestion kraang craze watt metaphors ooooh critique veterinary warships potts presto depleted shapiro har sarcophagus slump hooky improves ruxin workings thunderstorm hellish keegan trickster probie decadent lordy henning fiddling saroyan armani gaul devise triplets navarro humbled cabo pacino asians triumphs gout dubbed devoid compensated johnston rika karel bombardment frightfully piero salvo licks overflow multiplied attributed spores orchestrated slasher uncharted pimple quench rendering stubbs purcell disks giver sunil hayward sm rapids ulterior yelp deduct confer stockton khalid fares perpetrators impure summat oar keyhole pertinent domingo purring standstill groupie danube interruptions vroom integral femme loins dar untold wickham progression maja undeniable acapulco inadvertently alaikum inexplicable radish albright lingo illogical shindo yosemite sieg snows thefts exceedingly herc crushes stint flustered alto violinist rishi bonehead kravitz optional passwords fontaine sanctions staking playback lomax spinster fawn vials spouting osman melville refreshed jessi stooges disfigured reefs conversing anubis takers ronin intuitive hippy scarves albania excalibur xing dinnertime harboring watanabe chas orville productivity injecting wouid loyalties unresolved froggy messin stub teo kao derivative sparing wichita shayne denim asano bonsoir grievances undetected scams rugs subjective cicero converting transformer noone inventive eloquent soot amalia umpire quicksand succeeding georgian bitterly sloth contraction fondue physiology britches removes longevity intergalactic lupus sms extremists remi golfing dab gaza tapestry lithium sacrificial confetti experimented gurgles debs typhoid racers advert conditioned myka siddharth inconceivable rusted gazelle cartels burdened murky ros sayid artemis divinity prays warranty ceramic chilean harker canton obese enzyme repetition kosovo silencer bores multitude improbable hybrids cubans juliana scepter jailer baldrick manuscripts concealing bureaucratic branding pompeii zoya pedigree halifax declares killian revolving wexler trippin indirectly dragonfly contusions holographic catheter aimee dao fenner augie friedman blowout beaming dutchman testicle stationery hitomi stardust dismount scenic lorelei dill carbs scarface puzzling defends practised suites cranes masseuse caper def marquez amit sectors lengthy fortified thierry dory hewitt chink psychics decorative karla geraldine correspond graciously bronco mangy shipwreck trustee bellowing vagabond goofing forte absolve eros vomited dismal arkady telegrams discs mor buyeo aerobics ut melrose alexx wren bogey forging hodja guesthouse bohannon nandini helmut regency conroy lebanese harlot gauri bashful coached rommie vietcong shambles yoghurt olson geordie woodward enron demi saito committees debates evacuating striker wentworth circumcised deva brainless inherent maniacally bourne reluctantly pellets abstinence ieft trombone boomerang readiness realms antidepressants vibrator dumbo astrologer ghoul attribute sparkly torah acp magnifying coding latimer hatches rump pampered noona stinker remus greener ives mittens pessimistic angelic midsummer snowflake wrecks quartz emt kanan humpty caruso stalingrad willows barged wishful concur stupidly narayan temptations enforced dougal alcatraz playwright striving grazed negligent pulsing psychopaths benches mesh iggy kee hymns treasured musk gould musket nukes geologists renoir corabeth rem intermission grits redirect gaulle zara disrupting sable svetlana connelly woes armoured suarez lackey erupt stank shao sanction hinder demoted surfers blackbird eveything adjourn bile sunken sprain misaki commendable upfront jolie maroon possessing prematurely tok manfred uganda madras cleanliness stephan swayed antichrist skim irishman doofus costas pounded sedate hurricanes oink moreau zi foolishly radicals momentous une sheena disengage landfill jolene disturbances kilometer rigs faulkner lula inbound stetson partake paralysed pinot romulan shakin emi katerina musicals subdued weeps commies indisposed fro pyo beagle plumb culprits momentary adrianna fawlty sanitary ria gretel skyler constitutes installments lecter unsuspecting asphyxiation gita consented swimmers voter robs lolita fresno xbox studs peri shudder benoit taker dowager heartburn mccabe imaginations modelling dopamine grr severity abdullah leaflets evilly extensions glimmer arlington vex khrushchev twerp rajiv resonance garnet bavaria sasaki mcgill mer expire presenter koenig hess sas beryl lyndon ticker entrees nr lindy miao connolly signorina duress bacterial groundbreaking sabotaging networking jocks crazies locusts lodgings dozed bitty kepler frenchy sunbae milt uranus matador daktari bala unfriendly checklist niels imports devilish octavia britannia cappie hospitable staples sociable frederik bikinis bazooka weirdly transylvania paintball alcoholism droppings flier scorching flexibility minotaur narcissistic matinee absolution arman splashed floral peralta toads electoral violins compliance pathway nielsen juries unconditionally pacemaker cuss persistence disobedience interestingly franck revolves icebox birkoff transports mistrial disclosed dalai remand welding fruitful ergo fodder disarmed adolescence jugs examinations rayburn puree converse uttered graders trustees lorne christophe tweets lament mccord essentials goran weatherman ebola turnip vishal galilee queasy armpits albeit installment hedges corset scorched leaky latent chatted dorms cardigan surpass chuckie sophistication tada midterm icarus viki sickle thrones famed farrow slew leprosy registrar beecher sparked onset helpers tragg lawman conflicted descends happenin suraj birthright akiko lynne eiji yourjob kwai wastes fortitude latrine sawing beret dianne acids queers groping busboy feathered albatross rookies voight frock maury shyness platforms luftwaffe delirium trapeze rheumatism olden croc tosh dominating trickery ob vasu ripples sharpened microsoft glances holdin juniors forearm dribble trespasses daimon gourd lev freedoms tier zhi elevate scatting barter godless crackpot jeering rygel mechanisms vc itunes appease playtime minx kazakhstan thunderbolt catacombs bleachers auditioned entrepreneurs autopilot tidying shinjuku gummy fibre herrmann births sacrilege millicent luminous mums shoemaker bollywood alvaro vee sanitarium marlin opposites dentists abracadabra unicorns observers microbes charlatan admiralty specify pancreas inflatable janek overcame docket redding klaxon divorces capt invisibility ducked gilligan buttermilk coupled palanquin sized mailing alchemist spaced babble nodded ep yoshi stinger adverse eastwood dirtbag croatia pinnacle gastric tweeting noriko uneducated koala booms rodents kites mhm reardon trotter parchment zucchini vasectomy toolbox pained proverbial stirs gassed spielberg kazuo melodrama tobin magnesium nola donahue dehydration cad braking hematoma tuba kiosk prada impacts organising brainiac insufferable auld munching roped yeo rudeness oye jugular lewd tramps nieces chem mcclaren tryouts ravaged cues clutching knowledgeable usage squatting chugging englishmen surveyor roamed instances defuse prawns leif soundly spanked droids longitude skillful clipping stabs transponder nappy bowers retrospect kajal shes leased talyn parliamentary braxton shard hansel farthest inquisitive tablecloth kamikaze didier milestone meh preeti comparable anointed lmpossible looker vanguard waxing coworker landings fulfillment diminish enroll expiration snoopy fixer anson segregation tempest petrie deceptive voss doesnt druid erected kendrick comprehension fondness determining iguana pogue exiting thinkers stepson cavendish lowers sisterhood mongol izumi kleenex pores hobbes annabeth wobble packer nos corkscrew respiration boing celebrates capsules backdoor suki wakefield aristocratic bilal figs gregorio policing playbook versatile aliases flatten foghorn scorned lourdes beatriz gusto daren pappu dias mayfair libel psychologists sandi galapagos scot mockingbird uhhh tremors vitality starch vastly nando chit critter shears rube banshee mistreated referendum sacrament liftoff pendulum spokesperson zeal lesions statistical indy agha warhol uplifting blanco williamson alia complement cornerstone birdsong wiz juarez geetha bureaucrats tinny rapport acne ebony cordial traci homophobic landline portray torque buford kellerman bawling canning scratchy submissive ouija antibodies collaborator slingshot anchored crowing embryos antlers winifred prussian protectors brochures otherworldly janelle checkpoints malls parcels goldilocks girdle ageing chadwick critically minerva crete axle chummy decreased bose roc blockbuster smog wildfire amethyst collided prussia invoices mir infidel rogelio wart forceful lieu iodine decreed hairline theatres wreak karina limelight duffel calais gandalf hassling mau mj clout shafts adoptive expires lakers scruffy parmesan consultants tunisia flagship hasten stead teamed ofthem backfired autographed deportation vida pumpkins oda coveted vive objected conniving sicko astute ridiculed priesthood heretics tranquil bonner flunk assembling wallow whoring stapler hep imbalance tins gp bulldozer hormonal towering catwoman rhubarb gertie bla workmen leviathan safekeeping faxed imprison triage conjugal yorkers incognito jenner mindset blended akash sparkles laverne aurelie croaking allez specified crusty overlap luscious gladstone anthropology hermione jacking roost spouses greyhound ecuador particulars unforeseen cleverly gordy placenta unspoken beamed coachman knave foyer escalate tiki palette embarked zion serenade miser uday inhabit inhibitions stills rant dainty daley trask worshipping rarest wiedersehen augusto batty participant raph cheon senpai nike billboards lis sabre manchuria implication deejay scholarships disobeying migraines urinate downer dinars holli leblanc rizzoli spoiler foxtrot renato keats sous superstitions coordinating wisest atwood woodstock dutchy diners inadmissible cally displaying radioactivity connoisseur barbeque mixes scrotum smoother craigslist avalon mutations baja roddy vidal degraded horseshoe pathways sailboat devereaux birdy coincidentally ofa lund mamie dazed overwhelm tahoe automobiles huxley breakers conform comanche miserably deactivated defies fazio ingested watchdog addie prawn hells delinquents heathrow tot kayo koichi loosely constitute haynes keane nannies acupuncture displeased runny blot reduces eyeing cossacks stumped royals heo clamps dede canvassing exited exalted gander necktie hordes vomits calhoun conceivable ibiza entangled moshe misread vaccines sexes conjunction scheduling undressing twelfth gash grubby sao chien shimmering holders nautical confucius pushover enlarge dawkins neurologist mangled wag urinal malfunctioning intolerant clerical privates reconciled tackled pesticides euphoria retake jessup bluebird apostle temperance calligraphy brotherly solstice shagged bowled bastille ignited therein camaro nationalist eoraha documentaries storyteller clingy splinters insulation shakira outhouse byrd asuka scones subscribe swirl beavers tingle jordi gymnasium frisk eren paola appliance reprimand yuu gopher marcella cruelly draught buzzed taint bystander lp consummate vigilance hing raptor astro countenance choreographer obliterated massively indict sachs busan zhong cashing neutralized befriend tatsuya empowered appendicitis outlive ph australians indianapolis jails leary interacting foretold syracuse condos dialogues dimples astral pus airship bulkhead sic manoeuvre ake illuminate pimples admin fife mea constituents renal topside contingent vane clasp bagpipes precarious ur delicately yul burkhalter harpoon relentlessly photographing rei equilibrium flimsy vocalist torments pimping phases wesen teeming wrestlers antiquities burglaries baddest flicks joni jetson chipping yearly linc nami wilkinson canisters silvio tsai plumbers workforce frostbite kath mes selim corona mortgages ejected recount stirling sparta vo desist ciro rune alleyway doggett sutra jb dermot disliked dissect physique fowl showbiz afoot engagements stifling milner irreversible haters abetting hague remarry cassio sixes hobbit manon aram offences stacking feral fide reportedly chrysler coherent coated gambit laborers selecting newsreel chimpanzees peddling catapult sedatives shoppers formations questionnaire beverages josiah retches mistrust lill chowder lavinia kimber brokers varieties fennel leann curd delenn gushing saheb jerked neo cossack expeditions coldest nosebleed helplessness ft satchel layman butthole cuddling policewoman instability ceilings yuka ketamine pippa flanagan mathis hodge pryor goethe haywire firstborn lestrade gory kanye hypnotize airing peruvian eyre bundles socialize rallies rouse luckier hildy citation handsomely faceless grownup finely nitwit beckham periscope shimmy kaleido kaori nt lovemaking sutures beet hatter fraudulent grange minh laceration venison hoshi reinforcement flak shrew homeworld toothpick vasco taunt alina ascent frobisher flirty hoodlum destitute inclination abrams wankers shielding cited arf immortals dispersed deliverance intellectually noooo creamed unwelcome piracy heats milena adapting geeta pretense nifty amplified ninny seam cheeseburgers gramophone expo consumes necessities hartford deux acquiring socialists southampton hou fairbanks katja fairest broader rhinoceros coincidental guinevere offends cloned brant kellogg sandhya radcliffe illustrate sorely internationally ambient snatching duce crematorium podcast partition slaying leopards puma donaldson blimp misfortunes chillin sheryl prickly anxiously pestilence unruly papaya trenton lal troublemakers yagyuu municipality bebop holodeck gnarly hanukkah skimming stuntman thom saucers snapshot jurassic mobster craftsman khloe cissy ismail lexus fastened santi longtime sander looming requisition tenacious unpacked reps shorthand plait contented centurion realising padded saddled octave bewildered pandey koko entice chau playmate integrate nao dissertation sasuke abolish lightening tanned outreach norah eaters fatalities thickness censor oxy cabal nostradamus skippy soaps crass einar glaring professionalism baber cale mgm gnomes proposes nicht aquaman desiree osiris alana snagged strays collaborators sabbatical industrialist shana craftsmanship remedies antibiotic bard gutters motels burlesque gaelic acorn maitre eavesdrop arcadia nomad sweeten exclamation calamari thomson compares golfer alberta manger ensuring blackness subterranean fryer seniority cheaters rectify snotty shauna newfound iook experimentation cucumbers jagged gilly unbalanced databases protons rasputin ovaries spatial nhs metaphorically aaaaah decepticons sardine tarek milos eruptions heartily tweed relaxes heaviest clogs chaudhary rallo av masseur joxer baptiste goldstein soph hideo freshwater quarantined erosion partied mite leyla marigold itjust ewan hairpin knucklehead mopping montenegro hanky rousseau gangway payal darken quiche clairvoyant pearly ballast configuration oversized subpoenaed trapper doh cosby compartments admires vamp viggo reactionary idly pout approximate walkie playstation compiled sprang mg ama magnolia commissions angered pero stoke primed bragg unearthed ingram hortense heartbeats conflicting tami frontline vita approves utilize stuffs habib lnspector gutless transplants ahab kasey bolsheviks ventured snowstorm headset grovel appreciative urchin tata litre balu hostiles newsletter berk subordinates mansions rayyan informs pistachio gilda gleaming yaah relinquish railroads standin fondly crewman finnegan forger ans contradictions accuses kissinger poppins truckers outcasts ducts sae starfish nix kudos baboons terrorizing pubes reversing midgets snooker parades jansen shindig mahir susanne daydream southfork chibs whittaker luau styling repairman schubert surgically sped crikey analysts simplify gangsta michal agonizing bibi inscribed induction fetched carmel congratulated apex deserters koi xia fibres composing malia terrorized comedies systematic engulfed cosimo hourly congresswoman rummy flinch mongolian unforgiving receptive neurosurgeon miyuki operas programmer ankara luxuries revoke abortions narration liquids multinational goddard robo toddy garter oppressive procure counterattack kiwi pail sacha gymnast glenda rages scaffolding hearth wharton bots sigmund judaism cmdr couture viewpoint toffee spud helsing decaying ranges cellphones caterina blossoming hacks anakin transforms booths thirds infallible gaurav nobunaga incarceration mumble conveyor cobwebs godsend avert problemo airmen jammer ulrich highlighted mma faa frye intubate salinger instantaneous bettina stowaway baggy arguably paternal boardroom flaunt kimball gradient retrace stockholders proton tt isnt mallard reincarnated planks enforcer trumpeting crouch foie whacking thane rowena escalating spender brim duster thumps ideological entree bangladesh atrocity preached hpd tre chats sans nimble halftime supremacy warlords prism soulful sundance intrepid whoopee putz rigsby regenerate mystique maxed janus blending jumpin rhett scarring swish juniper ginseng ligature cramping reflections bodega vesuvius assad pegs aaargh mongols therapists sampling fairchild methadone stereotypes corned gluten prose eep rainfall anklets callers angrier attractions jacko jud photon commoner inquiring implemented gustave regionals feride aoi centimetres justifies chernobyl montage rumba hilt minna norse lib luxembourg athos azul corrigan reb abuela peeps hammerhead eraser trinkets patented kook renfield monstrosity strides veritable nomads exempt sonata fuentes averted ozzie spheres sauerkraut pawnshop wildcat differential degradation bourgeoisie coils endearing weakening rong trimmed slaughtering freestyle ts dayton dismantled svu fray forefront khaled uv indiscreet tarmac fer doable probing groupies jumpers bookkeeper siegel mangoes granada yoshiko sachiko pheromones expedite apparition hallmark shareholder furnish meringue kinks subaru criminally caw raccoons lute battled mozzarella nasser scooped correcting economical holm antisocial negativity rotted vaudeville docile constructing escalated benjy remanded tether daresay poignant loafers stahl miso rubin humanly relieving irena dalia continuation violates landlords smokers registering seiji oozing buildup avenging etched loon paddling keeler whooshes tenacity wheelbarrow giveaway hazards clinically cubby paroled indonesian vidya accumulate angelique flashlights whiny cranking lumberjack bargained developers laszlo taiwanese byrne appetites baz streetcar levin northwestern nak mccormick atonement nightstand bristow armistice shinichi kolkata clowning tightening bakersfield singsong advisory dyin fundraising upped headstrong prevailed hungover birthing stagecoach simulated megumi peddler belmont perfumes demonstrates ecological ola grievance goddesses figment smalls debriefing minorities shelling daredevil punctuality kush leapt burnin businesswoman sulphur organizer tal ringleader tantrums idealist inkling captives chloride musa ang foresight pram crippling bungee fashions hemp gunfight registers celibacy anthropologist ressler libido modification deviant jib pests aaa pensions hummer disagreeable daunting consolidated breen barbra slipstream tr moderation blissful moly europa innate viii patents jerrod yoke necklaces comical physiological naps gan valdez ware varies jimenez hanley budding carburetor traffickers unveiling billiard suresh longs klutz benefited outlawed homestead cooke guantanamo dugan balboa bingham soju loosened alessandro watergate pompey expands protestants dima adhere constipated fixation decently chrissake epileptic booted rockwell meteors mowing ocd yuji bup aftershave malta animosity whisk lilac greets marwan marika lombard comatose glows aided burroughs greats altman sentries grendizer dentures swindled tnt nobu hadji resin fictitious kelp slush predatory contention navigational pairing emptying pacifist fdr atropine compress unser quart wgbh chamomile spiteful brawn putt spirituality tyrants valedictorian bureaucrat poacher porters associations formulas hackett embroidery gratifying cps westen reputable glaze wrestled sufferings yume aragon relocation harden amour rammed unites helo dupont jiggle symbolizes brainwashing seer gui symmetrical wikipedia cervical hoon bajoran usable voyages sumner lurcio runaways elemental terrier chiana mothership shielded promotional tweak fixated mistakenly hellfire juju auctioneer flickering ak tutu isolde merlyn receding underestimating defibrillator chassis incomparable padding hazmat mosaic craters cheeses sickbay locator yielded turbine sporty paz idling disdain mitts hounding inflamed inverted corresponds rosalind gulping suspiciously polyester affinity sforza shifty whitechapel realises treading snotlout triggering crowder celibate getup wedlock mucus metamorphosis tourniquet danni signe irv ablaze illuminated cardiologist schanke inflated artiste lindbergh highs bookshop tc impotence muted chevalier unhand tambourine gro jus venerable doberman mogo giuliano wanton transient stepdaughter responsive supermarkets invasive ofhis rots greendale wimps bajor blister bray exchanges attagirl doubly islanders befall psychedelic faust porcupine deteriorating escrow sprinklers saracen notoriously gifford passover spidey anterior backfire tokens ajob apricot venomous brisk dhs pac nativity mahogany kunal kondo microchip cai spar massey ardent orin psychos jumpsuit amin stinging rustles woolly clitoris verification admissible uther caws poppa patronizing scandinavian ailing triads detailing magdalene standoff specifications resumed braids bridger townspeople brainstorm dei breakout tangerine tzu insidious gumbo icons watchful cruisers somalia crucifixion piranha darkened ratty protagonist pyre huffs ima zoning bracket scrappy decorum childress stifled ballots bayonets applejack dmitry decomposition voucher taoist shat raindrops wrought converge paisley almeida changer chipmunk bloc airstrip amore clog tinder dreamers lien tolstoy molester transference lightman algerian lucio stomped buenas qualification perps repertoire stoker pester backdrop optics bff counters statutory deport waterfalls cuffed rosebud molasses baltar strengthened renovations haw ville mastery marci feasible gospels sixties drastically flourished pokemon priced borneo header quigley inhaled considerations towing cranial purified summoning attachments ngo mcgregor moot opus nonexistent meaner poncho paulette sheriffs agitation indiscretion escalator outsmart undying armin bilfran trav glazed fairer vino heathens flicker weirdness stomachache downed stony charmaine enema rector platt alight ransacked bartlet shortcomings wedged skyscrapers goto krieger femoral forcefully overseeing rosalee sparrows polaroid beaut dori woozy pediatric holla slacks barr mikado pleas infatuation tlhe tuscany tasked churning aloof extremist billiards plentiful kingpin gull assurances faculties existential loudest sixpence nodes tremor incorrigible hanover overprotective cui llama wearin coupe inexcusable botanical pastrami cooperated mortgaged dimwit nurtured subtlety quarreled whiplash zhan flipper kristy fie racks hp interferes stroking recklessly thyroid scaffold epa livingstone instructors burritos thereof drat yagyu protestors lode tripod mcmanus tris mullet teyla squeamish euphemism tarnished brahms ancestry becks ramifications tracer pedals steamy beginners babcock skydiving liqueur tribeca conspirators renard napalm infidels shrimps outbursts tosser hops dramafever dictation yukiko quivering rationally alleviate cloaking crayons cheekbones complicity blowtorch avoids gettysburg veggies departs duds conservatives endowed meanings coon clutter mahmoud leona cob endeavour hoses jackals tightened infatuated tamper kishan bagging mallet bram clemency plummer suffocation ikea pointer nugent strapping shoddy juanito saturated husky jase cornish smooches shik prejudices incapacitated gar precedes anaesthetic skyscraper assigning imperialism sinai validate robotics apprehension boning bharat objectively amputate sanskrit calibre attained computing confuses sprinkler unfairly shhhh unused evidences dwyer waged revision melodies soulless amorous screwy reinvent pesticide adulthood lessen amjad balkans confines footballer renovated begone cynicism ditches lun pitied innings tuppence deserting seedy robb luanne korsak broadcasts sociology unparalleled chomping crawls shortcuts punishments portals antiquity peaked reigning banal rihanna dinghy cynic constables paulson custodian knowles coughed hornblower acquittal anja handover lipton manhole launchpad caresses marksman sultry impressionable ofhere clipper jayne preferable amazes confesses retrieval timers petal matisse merc hastily vaginas flowery nosey omg transparency stimulus clad gondola hooters schwarzenegger browsing pecking matti henson rockford alluring demographic adalind drips zorn foa strategically absorbs scamp inaccurate forthwith sponges grapevine womanizer periodic occupants nae piggyback malachi cite parachutes brunt seekers disagreements shalini filmmaking suffolk schnell adjoining gooey slacking lyndsey luz speculating screened cleary aberdeen simultaneous lint oft mariko bartowski stooge drafts titled symbolism gradual clack impatience enlightening migrants ludo anchors declining rena protested secondhand terrorize ineffective dobson syllable verbally wrongdoing rourke utilities acknowledging primate lout stratton bookies revert racked congratulation dorrit sarcastically aquarius atari chalet greenberg bern disgusts unfolding pax persuading nicks kia adhesive miyamoto understandably crease resists todo bello carina dekker ojai cu spasm kafka tweeted mahesh recapture anemia disbanded dorky aptitude dominoes trini ovens hutchinson carelessness simpleton lll indigo chewy nom icelandic amend daze candidacy foreseen playa sondra muffler unfulfilled pertaining cardassians tegan caribou gangrene dunne coliseum splatter rectum tripe lawless zimmerman salutations willful sludge imbeciles cockney cantor negotiable squirm foon flaky spaceships contaminate mcneil syllables nines ichabod discriminate enclosure gagged tabatha warmly warmest sweeper grader moldy clemenza wicker koto caracas embraces gully muad decimated docs inward romances piety takeaway deflect kryten lanie pomp rebelled indulging zapped wer sandbox buttered lange bingley invader feeder pla behead forceps reopening reinstate legislative veg carpool zest jeju defer topple mutilation cloths secretariat shrill reliving adorned quarterly ailment contagion parading sustenance desertion assures egghead sledgehammer simulator temperamental edict sensibility farkle fuehrer impetuous notable dollhouse stimulated succumbed corrine shalimar tightrope conspire goatee eduard tigress eugenia bulky endo hemlock scoops salisbury quint headway carelessly incinerated grisly gait unscathed zinc midsomer sneezed stethoscope raking bibles sono lobbying strait xiii owt erickson finlay leveled vipers hookup commonplace resentful crick boyz ranjit supersonic bigelow exclaim patronage dieu burmese somethings academics egos constabulary deadlines morley farid bonanza nozzle distasteful prod cleave henshaw wessex discourse overcoming magna philanthropist crapped expanse yow typhus betel remo disrespected yasmin electra buzzard marlo darrow expectancy madmen jutsu dazzled waller dogg citrus needlessly attends aoki truckload aramis cancelling unsettled seared singularity thaddeus noo chartered godson cuthbert venting contradictory cahoots bridgette decidedly lac knobs artificially athletics schoolwork faux copped gecko competed trois barring polk spanner dropout uhtred ina couscous hikari sherri mumps napa enchantment reprieve headstone icky drago siberian audacious pecan skylight juno twittering ronda barmaid commendation cartilage mucking suppression plume delores madre helix sultana twinkling zola prentice pajama informative suave badminton yoshioka graff karp lander guevara bolshevik halstead unmanned stair idealistic breakin disowned doormat conquests pronunciation discontent vaughan perversion tyrell hartmann disbelief racehorse scallop leases shadowy hurdles gulliver executor slashing glider leans hydrant leonid raceman adorn aku consist twas hoarding inquisitor differentiate slaving puffed pleasantly primates mogul prius deter ter robson simeon piccadilly veranda merging breezy quan capped knowwhat ponds sided overthere landmarks converts outback deja shotguns squaw eluded ifhe tetsu satomi paella erasing tupac upholstery pbs baseline neighbouring lioness crackhead likeable kibbutz katharine moonlighting bumpkin gant laborer scorsese droning fernand gunter letty dawning setbacks zhaan trouser whatyou bosnian rancid balthazar velcro emit wherein aron brahma stockbroker blackwell insightful enoch prancing enzymes bellevue vhs santini tatum unconsciously ummm geraldo pt updating grotto dams hahn unscrupulous bryn vick eleventh crises resembling electrodes payload picnics loathsome darnley singsongy ruffian goulash dov tartar sunburn littered supplemental lawton disruptive killjoy hourglass pasty turnaround carte franc meteorites blackpool brainy haruko suze grappling patrik misfits mover molesting downton strumming hater mobilized bung solitaire barbados hummus vips resorts maniacal chaney solange drivel rodgers microfilm combs memos looney batgirl mariah squint honky tyrannosaurus sediment brava coincide voltaire apparel mockingly lia gawd ordnance gatherings ged ponce sapiens jaclyn amputation bustle jockeys toru golem sandstorm cloaked squander setsuko proudest yanking regimen deluca khalil vickie exhibited constituency plagues hitchhiking gouge stigma storytelling otters ove pooper toasting purification despises positioning lashed blinked francoise extracting flavours creators destinies xiu spector huntley lynda genji uniting legislature bloomed strenuous blakely masterpieces squishy lows afro liven orgies babette outdone nintendo curiously matthias saab pantyhose stavros warns interactions biologically fresher wasteful centipede banger balki stickler arya perpetrated computerized ulcers vickers caspar kasper scavengers bugsy bitchin semper kaya moronic humbug overbearing rosenberg cheapskate toupee structured sakamoto kaz ovation plunger visor kowloon tongs rancher sportsman patriarch null blueberries frisco cartons exceeds daedalus feudal arses paradigm guerrero edema chutney guten deo recollect proletariat kaboom interrogations scuffle henchman rasmus molest tootsie thayer yolk hisself explicitly arterial methodical saver launder spaz undertaken hummingbird intestinal horsey prowling givens douse ooze dupree riggins beehive elroy chechnya luring gazebo gatsby angelus mathews wretches spotter petersen nautilus recluse mortis covet pringle ranchers finite tonto angola platypus veronika waging skyline desdemona copernicus kiyoshi amazons marys ric bearable travesty frontiers refuel korra monogamous lull remnant nascar smirk routed omer haas affiliated tush laughingstock uns commodities smithsonian blockage ventriloquist yams beaucoup analysed seeming dumont mayans coasters landscaping pleasurable sandrine navajo unknowingly exercised quotation hercule stalks embalming bunkers supplements politeness consisted doings revolve unfounded torrance astor visiontext winking hinting scylla johansson uncalled screenwriter reimburse ugo woodhouse christened rsvp cannae virile hol hankmed motivational spotty patching tranquilizers mork extort nominations celebratory crud puta pate mercilessly battering insignia demeaning raider jangling hipster reels upto triangles individuality debauchery cecily plucking moritz loin identifies phineas macabre hurled varnish cosmopolitan wack pino surly obtaining riffraff compost toured gook halle toxie anklet hoskins expressive singled employing migrate sass validation broaden mortars yields chimneys gonorrhea buzzers paprika sharif adjutant furlough nefarious overpower flogged shakti hibernation piston adventurers swabs rioting demetrius cannibalism pickin reluctance embroidered nome sia gimp whitmore breeder jafar margherita sizzle reflective inger condemning endgame boathouse chilton manageable disintegrate ethereal brimstone preferences cookin phonograph workload gautam credited evading mouthpiece farmland fouled eights carnations scissor sponsoring farrah hairless defenceless narcissist reappear undisturbed bittersweet tusk memoir plunging alaric lawns manta concorde pleads iranians regulated compadre arming sarin prowler antwerp armadillo tanked whisperer magpie wealthiest sig halliwell sedation ljust ayesha impersonate fabrication mediocrity zapata crafted nog suppressing metric scurvy yukon photocopy impromptu fable alterations striptease attentions crunches chae pryce felton printers coating rims salamander succubus seatbelts rotary maxime mirza huddled frm vulcans undermining racking soliciting repetitive lighted parma daniella barracuda conga mizuno shimizu bumble shined liberator hyeon tillman kiera misbehave incarnation stupendous whereby pouting decked virgo forthat diddle scour lidocaine fatality pinning cobalt rudely jailhouse restrict amuses ducats enthusiast chronicles scorpius interactive happend kooky shih devouring emancipation alaskan headman harmonious noi infiltration hothead midas wholeheartedly gugu erwin kaitlin hepburn classrooms leia bulging rousing wherefore pulpit monogamy craftsmen harv linens ladybug pooping steered aimlessly calendars firefight kohl ijust wynonna grog purged lukewarm ultraman minion dissection advisers demeanor archaic sentient lazar uninhabited falter yourfather reactors realistically windscreen destinations fremont louisville paulina iceman thrift opie uploading mcgrath shoveling eee sideline fathered creeper dade waltzing rackets broots stryker eppes shel smythe posterior disbarred disconnects disappearances snapper stace unveil delko gr wheezes trailers willed inspecting tote caro autonomy warring vetted mnh cronies whiter felons dysentery binky nous nadya harcourt chekov township lunacy jas vegeta insistence handwritten crusades feline westinghouse rami pasa chrissie tuan mindful alla oona bacchus footwear overture tolliver mcleod aussie freda drowsy fluorescent pretender sawmill shunned konrad frauds cemeteries bhavani nutmeg buggered turquoise correlation pinkerton conning aversion recommends mongoose kaput powerhouse excavated gripping derelict marshes overturn embodiment twila rapunzel hatching jamison elwood bathhouse lends circuitry hideaway mcnulty eames lingers livingston confederacy terrify inaccessible catwalk tater tots darkroom visuals sikes carvings lorena depict spaceman nuremberg aquatic anvil mediation avenues baroque lahore systolic harms maximize jangle messer headin tweedle mariachi larrabee tournaments kes ventures belize cheney saltwater cesspool salve hazing nudist melancholic futon westchester bestseller hangout arbor thermostat picturesque castrated ambience entirety enabling olds leisurely hella deposed opted pickings pivotal mis loafer congressmen genital signaling unis flog austrians sleepin als surfboard sil preserves gripped accelerant satya incubator nigerian arty houseboat seminars mohawk caressing gaz capricorn konstantin vaccinated footwork promiscuous flagpole hinge alyosha methinks pave miko grouse clipboard swahili gennaro jot electrified carlito ders mugger chiropractor nutcracker shortened hogging confound tundra chickened megaphone ramses blindsided incite caption tackling iraqis unjustly turds awkwardly dispensary demonstrators catdog bod clung extracurricular renovating cyst perchance abbs illustrations dismembered laughable lemur balances cato hangers unification civilisations vilma porterhouse prob cabana leipzig budgets orry collarbone reeds lithuania somerset fernanda dynamo jarrod sponsorship familiarity hakim bogged boudoir housemaid crayon pfeiffer perrin hinted pom frustrations motif shipwrecked transformers caligula pullman hanne omens suis extremities deduce popov dwells unplugged seaboard nishi publications druids pedicure pym apophis falcone gul yui finalize mounts overdone assorted varun tubs whitley finalized superstars immaterial stainless disinfectant damning whitehead storybrooke mope anchorage loom kinetic turnips foothold chlamydia fifties krystal ashby umberto webs cavities mormons postage rothschild dreading doolittle captivated saddened trolling capitalists gruntlng cyndi hoes signify nucky myles dips dimple bannerman holliday ascended tidied shrouded alienated wop childs satoshi debit newsstand akemi bodie lovey molding mays harlow monotonous symposium grasped displacement barnabas blackburn competence saiyan sniffed midlife zit djaro advisable suzette sienna scribbling skateboarding feats madder undermined cinematic overpriced ephraim whimper parishioners hungarians tapioca ry slumming effie homely vineyards ec vics heathcliff spartans crapper enslave cocked megazord bucking repellent langford perched paraguay flabby defiled dolce choosy narcotic battalions motorcade kelley beaks sleek vividly koch judi classification esquire nitrous vouchers cascade frees shabbat winona walled wagging mew regrettably unsuitable esperanza winger injun dented remodeling heroics rie evaporate cramer withdrawals easton economically eloping gilroy blogs dunkirk carpenters bleeps mookie fib hoarse recognizable oldie pardons seawater dwellers pelham fusco everglades crowding wetting fizz manifests overdid kinch roomie ofthat haircuts myriad confounded faruk cupboards subconsciously catchphrase agility panzer ir supple winery filippo inflate pane rodolfo flamenco trachea rakesh mph kinney domesticated molded hardball reena eveyone consenting reston repugnant oates corrupting flocks gunnery devotee ails stepan ester entrails keepsake dahl versed mycroft foundry fido wordy formaldehyde prepaid gesundheit villager orhan reassurance outcomes bitte trillions liquidate cheaply niklas romi drax kilt judea bigot hayashi autonomous unbroken osbourne awry radley alternating ontario spooks detach coax lorenz volker mumbo cr tilted outnumber preceded morph bedbugs zillion hopin allahu batmobile cometh distinguishing goya lashing veiled freshness matsumoto commissary kalle sorrowful drab accommodating springsteen tonino tweezers chuen sternum debacle cellars ariadne knowed fastball chopra sown sunsets impractical reputations morsel nymph gleason zora manuals subatomic exonerated nawab bettie letterman roughed sima gutierrez musically ethiopian junko samar satoru healey sandal fabrizio monterey yada bapu fletch disillusioned karol befriended enticing gloating gust lubricant sergeants hymie ibn overdosed simulations soren pivot makings insecurities eldridge martyrdom ultron apologising craves wilshire bequeath clacks halted irritation som smarty cafes divides uri apu pandas incantation compels rams alphabetical bavarian amputated rebelling duckula empties ascending habitable blackened kevlar improvising photoshop tome juana cami uruguay leniency crepe rendition margaux archimedes crenshaw squishing fingered coffers offset educating slugger gpa viscount unanimously jabbar leapinlar gentleness drizzle pontiac serpents impacted meager nappies insurrection ely replicators gargoyle kerr seclusion reroute cyclist incarnate congratulating besieged wicket incinerator epitome cutthroat esp millimeters tranny moonlit sor elin tano chica impudence precedence heaving shirin kala doa dominguez diff basing cadence davide fleed ulrik wesson ied estrogen severide guilders yoshio vermouth obeys nazir dissolving akane ght forthis trashing presumption temps falk braves goosebumps inhalation gnawing economist brung ohm tractors gohan emp arduous consortium starred ludlow althea dandelion raspberries netflix goalkeeper seamen impounded validity rappers desi sockets skeeter realist iga households masculinity disappointments stiffs quiver envisioned kwok corleone acrobat bubs peripheral niro dabble leng sweatpants twine misinformed flemish rpg mishra ackerman allure impediment malory hone assassinations cicely disrespecting choy shaq calloway spares psychoanalysis giddyup salman reminisce cajun merlot nita retards ulla televised milano doctored scorch saskia bingum guzman pioneering pinhead flashbacks anika hoard brewed squandered predecessors seward telemetry noa masao primordial botany strategist fluctuations prat morten chucking hennessy allende apprehensive highlander camaraderie precipice caliph sodding intrigues misuse oj tripled relays inherently violette inexpensive cushy prozac claudine vandals collectively munchies nanites frolic disorganized dispenser fillet beyonce mightn aced redecorating diwali blythe maximilian optimal lasso recourse brittas mediator apologizes tunic memorabilia caterpillars sodomy anselmo photogenic referral knope invulnerable closeness koh bobbing bleats bleu unwittingly twentieth yuriko sanctum mouthwash copilot picker xian whirlpool bombarded quacking stillness ieyasu raged heung putnam applauded perfectionist thwarted blight pitchfork oren glutton arnaud piotr trimming poppin fiends madsen columnist vadim priory overdrive innuendo davie retina molotov lobes wheeled jian tireless feminism tandem mather angst eonni allowances suntan attest sluice armitage barrymore jeepers unresponsive inhumane teleportation geographical loosing schoolyard gaff philips misinterpreted siam sutherland node felice flyin hemorrhoids renzo comer wikileaks thruster chatsworth phipps infamy infuriating og swelled rejoicing wooster groomed res karsten grumble bilbo gim uzi montalbano suspenders counterpart sanna boozing workshops florian zu undergone tiptoe solvent hatcher soapy thatyou gutsy nath nordic instinctive martino dishonesty masako kipling ichiro misconception corday croatian accountability sleepyhead spoonful heywood sei saree impersonal haji reinhardt figuratively biceps bluetooth trickle exports caterers belittle chromosome inoue gardeners cokes classify aztecs chiaki chews cog ambrosia batista sieve thang leda finney gisborne horne oedipus spasms smithy yuuki tibia hoyle wooing rockers carney candlestick bolder gert lodger chappelle unrequited poly flogging ong mundo zimmer capricious sgt earpiece renounced zeroes impaled largo treaties bankroll beowulf squadrons akiyama nissan nothings glades biryani patrolman valjean tamsin editions tupperware combines newsroom hannes chemically nara corcoran fanatical cellmate judiciary imagines masa pulsating richness sideburns goodie guerilla romana sprinkled drape rollie noggin smut corbin checkin illuminating dulcinea vagrant springing grouchy conn kunta fausto thrives maimed incurred kerrigan kareem porthos cong pellet stools evaluations rotterdam kal imogen invariably laos stepmom pomegranate flourishing idiocy quince compatriots bois surrey loaves galore maltese belch unguarded superfluous toshio impoverished inter segments constellations filtered appraisal trinket attica drunkenness enigmatic bayliss grundy toulouse corals quacks crumbled abductions estimation solly shibuya plantations carne mounds eons depravity drumroll withers fluttershy adept ensured paychecks cully drafting equinox ricci schoolmaster terrifies toshi murthy mauled aeroplanes satire montoya bountiful splendidly undue lunchbox ora rhyming unmistakable lauderdale fresco strudel och busier estonia squirming colds moines stewed absinthe tachibana replaces definitively mares psychopathic couriers discrepancy gendarmes foryour giraffes unpleasantness summarize query replicator srjanapala undesirable originality lobotomy mightiest glanced afforded gritty hiroko makeshift riveting lucian nyet indignation pissy clergyman krueger ilsa irregularities bandaged judson pollack tash cripples merritt darhk culmination backstabbing documenting bullpen collisions plaything ashram floozy jiminy rockies thingies inefficient sheath splattered wristwatch appa reformation durable spatula rallying debated oncologist subtract vegetarians amaya etta maserati brisket childrens sluggish obscurity mitzi focal marcellus morelli shou contenders unsaid kelli treads poltergeist lebron doubtless zilch evaporated laure disagrees dandruff silvery affront tardy eaton slinging lollipops tinted stringing blowin eoe norbert zou lactose dishonorable roundup avec discrete ciccio apprenticeship arno muddled remodel walkman adonis kyushu jezebel bixby harrow messieurs hanoi holger ginza bogeyman workaholic tailored pda pina noches flowering enriched foal legitimacy theyre arrhythmia lehman indulged restitution vigilantes reconvene subxpacio deteriorated unconfirmed pondering rewriting ode poise flavia mcpherson composure camillo swastika chickenshit gearbox jizz sahil overheated inspections pandit beech plop livid tron serviced cayenne impossibility petri vigorously tomboy persevere tatsuo bower cuppa lentils odour continuance incompatible bootleg coordinators arrivederci spinner pesto expressly hollister brutes transcend infestation leach kidnappings whup circumcision rearranged yonkers shashi frak broomstick stamping discounts templars diffuse eyeliner danton reared glories katana ballgame lurks obsess lar termite aravind unraveling urko recited noor inept fyodor parody trending amino hostilities hobart marsden futuristic journeyed falsified bystanders pierson germain tse applicant packard cristal cyrano hussain guam duckling israelites patting souffle matias gorbachev rougher dissent kojak adoring spanky contracting baffling dressmaker annulled minbari mui rudimentary shakedown sevens farsi causton dorset ryland infusion securely valera mails croquet lottie fattening bleeder upriver marti disown incendiary groggy gliding santino bukowski stardom arisen dans collaborating consecrated advent rui duvet siesta beanie childless hiromi bragged lachlan corsica culturally rancho looser dived bookcase cremate translations padma magog akin sussex motionless placebo andrey fishlegs deviation kidd matilde bonita supervisors gaddafi mohamed grope kenobi grandmothers odie welded caprice parnell gerson rubbers nas connery womanhood draco wimbledon mosley undivided deterioration detonators webcam cypress lbs lepers radioed serrano rikki diligently kano lucked lovesick likable metabolic hillman droplets vigor sirius delano automotive fema hyungnim snowflakes stabilizing nanna hindenburg undiscovered hydraulics bossing prelude oppenheimer tonio slacker dio resolute avid miro florentine unc zimbabwe respirator chatters frantically lansing feasting andros plowing moro scotia dorks aahh canvases aluminium eastman grantham focuses wilton conveyed bask frick cristo plugging toughen gilded clemente johannesburg chasm zev naoko codis mulberry cheerios boars zeynep chromosomes respite donaghy shoreline gazed lumbar influenza wok whirrs redmond mahatma sizable colossus arif macgregor hacienda heifer caverns wiretap tch squatters fumble textiles huns indicators cirque goering cabbages geordi pedestrians aline genitalia dialling mollie peacekeepers stackhouse plundered payout cur grasses odysseus aloft nourish miyagi staggered handout sipowicz moll aortic filial hightower fayed pagoda stalemate pamper dickheads androids subtext uncuff profiler ballsy gleam trainees oot fundamentals pokey swig hasselhoff coercion exec indra unhook boosted strutting volga epidural capulet spiritus fredo gringos cybermen calum duggan balzac soledad rectal finders prologue dowd obliterate burners harnessed munchkin wielding solicitation bullion inquired scoff alby reactive gasket deviate castiel behaviors bide eckhart speakerphone christmases philharmonic jittery percussion dominates unwrap clovis rwanda jilted deterrent installations valkyrie informers haughty iwo briar audra oakley overhaul searing multiplying inactive solos qualifying pizzeria prevails expressway laxative convene thebes hairbrush castrate molina mette solano lupo bachchan shortness watchtower ando planetarium advertisements mamas awakens idealism losin surveys restriction cosa nexus callaghan tusks copperfield artistry spewing barabbas deepa aviator stopwatch thyme shania boatman jeter blubbering effectiveness devotees boise diets humvee wanking grogan pocahontas professions crandall blistering vandal churn grinds mommies tobey motown medicated fritters doping counteract conundrum folsom thurston nervousness dumpty mignon nuthouse egotistical auctioned eradicated mathematically exceeding serb mackay overpowered glistening grooves swoon landers proactive villas kristian flanks blogger myrna clique synonymous uncut calvert affectionately pisa jargon lurk quarreling montmartre nominal decreasing extensively forlorn embers juncture aguilera drc leno maquis jackman persecute meticulously bluntly vail eeg helluva crocs joachim deok pigtails fleets apocalyptic rt barbecued digit resembled winky conglomerate tarrant doppelganger forgeries vases willies shiloh embargo badgering affirm backgammon joked blabbing slant saboteur exponentially chieftain takedown waco chiba loudmouth lacroix romulans filip bangers dicey metaphysical gamer softened domenico introduces aqueduct deathly henley sinan emory sanada yasir clothe downwards zephyr actin moloch camino codex scribe dishonored asunder torben specialised sag anju sl lambda paedophile caressed beckman bei clavicle lids homos philby foliage favourable emits huckleberry nee entrapment defamation scoreboard massaging perth emcee migrating laziness westside tortilla modeled corrado macintosh worthington spelt tempers tresses coulter revel moulin argus bering electronically terrestrial usb headband zander cumberland nosing petr wassup practitioner hitchhiker gangmo siva bannon thru wipers langdon trickling punitive sniveling victimized kamen headlight tweaked boggs blooded painkiller anatoly sharpest braverman congenital okada prunes fora amok playhouse peat riverbank assessed simba spitfire ig christen mcgraw barista cochise flippers torrent replenish buckshot scouring lilo doped nairobi fellini arggh blubber nuptial fantasizing whitfield amara mikes bhola hattori padlock redwood ghb kyra alerts grieves townhouse solicitors zagreb stowed unregistered houlihan mullen flatline sade snowden uniformed deplorable grossly octus fascinates workman sketching triangulate maurizio winked upstart spaniel achtung yusuke employs tannoy pathogen reprogram pp entertainers ani fatherly barricaded foreclosure origami muddle parenthood cooley henriette lattes revenues seb onslaught pune importing sharpening footman grueling tiwari hittin saya tripoli cinco archduke inaugural roving arousing mathematicians lucknow jadzia amazement yamaguchi testifies gerbil cautiously buttoned lowdown heron cores bouts reconstructed smite dundee tomcat tourette anime landowner gannon bloodhound shitter blam outlined shoelace vaporized sprite delphi cranium lettin gomorrah pcp totaled impart jinxed enrich rewinding aqui mcgovern machiko asperger payphone sona hotdog pseudonym wallop mahi wallowing splendour zig typist marga overcrowded inferiority farr ember haruka senna principals fillings laxman manchu lapping bustin geum stresses comprende jackhammer hunnicutt vasily mortem finalist farah victors crumpled infecting prevailing seaquest buckner teahouse rationing kardashian durst nyah degrade breakthroughs evaluated pally hyperventilating grandfathers diverting boosters czechs kha bunks sashimi reina gabriela dictators emitting innermost adversaries willi bahia lego inciting bunting minstrel windmills sayings hunky shale larynx eskimos beretta decedent kryptonian canyons journalistic residing impala dauphin sliver handkerchiefs fredrik knitted rajan forklift butterscotch burping soiree hd steroid unturned putrid luk urdu rearview deflector ahsoka sappy nightie telecast peddle envision backwater monseigneur catholicism copier rafferty hirsch intertwined improvisation standish ravenous jakey digby capitals earthling baze suez surging daytona appleby kangaroos cipri raps eliminates leni callisto ofher scone shorted whelan honeys trembles edouard mija mythological bianchi munster matheson nadu undecided sungkyunkwan stumps schooled advocates carols outage ulf pigment thumbprint petitions ivar humph stateside dorsey makeups dupe crackle collage boogeyman outspoken fiirst redecorate creole haired yamazaki kirkland livers reade afresh transpired shackled chivalrous fen handbags semifinals iqbal fatally eyelid tsoukalos regiments munro turret tomie stimuli profess benevolence belvedere tybalt cocksuckers panicky canoes fillmore trinidad stumpy hippos obstruct rowe aslam deliberation impregnated knockin toga reasoned comme apologised tora indescribable leena usefulness argues tommaso bloodstains commoners anxieties marilla crabby num chett sathya shamelessly reconsidered erectus upheaval constraints earplugs childlike colbert cas bastion vinick lifelike hijackers latham obscured mosca unselfish alexi artefacts hiram hud shitheads williamsburg doggies contessa nuh disband braised adequately dishonour cancers cybertron uncovering zebras postponing fraught skedaddle stian irreparable amador lustful portsmouth shopper wory mehra seeley barkeep maitland nikos hardwood riddler follies clapped perfumed ecology unbecoming enhancement marston tilda discern rios za charlton lenox aoyama brigades venues verna servitude xerox mains pagans poach receptors constipation shadowing flamboyant punters wozniak cravings clawed courted zoos mobiles mowgli militants merton rafters pedophiles kama amphetamines tadpole peacekeeper masterful ortho regulator hajji streaks yearns muchas immerse mischa freebie clenched limiting costco itwas punt deafening deng subrip opt byzantium zenith knoll exeter bozos uhuh fess minami birkhoff weathers wonka fantastically ukulele westerners whaddya abalone defected doozy impertinence sowing boyce raspy yusef shimmer sheri cray punishes rodger rectory ithaca overhearing emulate dugout landowners gaye renu laptops ranging marburg abernathy disintegrated porto risa django routinely kanji granola bahadur barrington racketeering endorsed jaded seltzer rehabilitated rox nagar chums kahlan royale clashes wimpy haggle sips airman astra lifeboats smothering memorandum refinement chariots grading byun thirties cinematographer profane surges underwent cutbacks andersson demos qualms fornication beater hitchhike hatfield geometric gio pereira cornbread musketeer larue ghostbusters sorbonne suggestive trimester unseemly evenin goldar aish turing doer excluding objectivity tou resuscitate indicative keyed wavy coot fait ceasefire unexplored muppets tamura gossips aides stately spines cornfield kaye conquers tolerable bionic peroxide imposition kana hornets exorcise michelin cemal southbound beaker commenting smooch drunkards bakshi whizzing blacky chumps gillespie juilliard uplink clobber madan theseus alton aaagh wantto aditi betrothal goldsmith gsw allo wolff totes abstain lymphoma elated oldies grassy pessimist joffrey missin untoward puddles cagney sauces squabble nanette phantoms midterms engraving floored isi translators mancini statistic resync byzantine predicts tutti wrappers wylie thoroughbred fairs payton maneuvering symbiote chechen gratification recruiter rentals mehta complacent undetectable throwin bargains westerns syne forbidding ingrate cheerfully sakai gruff impersonation remover corinth usc infancy folders ungodly tarantula uneventful somali opposes este nui holi tomoko marr fittings buckled cordoba emporium phosphorus vii authorisation forts medea smithereens dewitt bookkeeping byers ashe assessing nie coventry renovate dirtier sucky biking quadruple wasabi hines halsey legitimately freudian tromaville stagger overpass honduras schumann depositions cragen ionger flay jos lido radium swill interplanetary eugh achmed unhinged bassam mins xie substantially uhura hickory pancreatic chalmers iou baal concubines shrug toma arkham reptilian lombardo shirtless laughin whistled navigating viet chandni allotted impregnable strewn swerve innovations massacres kudo descartes wordsworth alastair rawlings auditor albie checkered dorado puffing contusion hounded abject medevac economies trampling handouts scabs ailments straitjacket dumbledore derailed selfies intolerance haddock bleached digested thanos vanderbilt unintentionally razors clump poon ilona knut monasteries stockade proust lucrecia barret convulsions sunbathing fixtures undercooked flemming sharky sawed yugo quartermaster khaki hur apathy embolism dignitaries starscream panorama ricki regimental aint deploying oceanic magnate mongo synth mong salma sprays labrador seashore collusion holbrook detainees lowlifes mishima pollute complicit thirdly horowitz quarrelling orsini overstepped firework snipe retriever cleanly vizier fizzy unafraid jinn prenatal waver pianos badgers untrained naka eighties lilah sadako carpe handlers mee entails gilliam wildebeest ulises fiind teaspoon splutters reunions statesman chupacabra caplan incorrectly iaw woodpecker groundwork delicacies pineapples cultivating commented cufflinks composers onedin dreamin amenities snooty cosima hilly whaling foiled vectors mckinney slowest decoded turbines debatable rhinos repo cheri unopened evo decompression hydrated pitchers garb versace triton vichy echoed infused tendon bubblegum norms hashish tutorial ringside macon inequality tarnish browse mourned acclaimed cameramen humongous activates skanky vassal haitian hanzo indirect socializing shilla trackers scranton stifle stunk magistrates wehrmacht provost vacated underprivileged spurt ent mayflower kurtz kepner zod embezzling factual dieting girard gruel deedee brows kayak dismissing kaji giza quahog tricycle nomadic outsmarted adrienne ottawa rotor kashi lainey skulking fracking syringes chuy marquee candor buh timbers argyle nevins reputed odious cartier cults carlitos mita heartbreaker exclusion bunter centigrade billionaires soups scandinavia sunita loveless radiance jabbering joplin rummage banishment tories havent abscess malaysian playlist scoured lino grisha gawking lures endeavors flees rebuttal runes terminally americano doze shue wily longo drifts haddie draped outset inoperable mountaintop leith skaters subtly cornflakes ivanovna huzzah backpacks narcisse hideyoshi ogata bizarro chaka fujiko digitally anecdote garages arroyo tryout overseer emigrated shima steadfast intermittent whopper tchaikovsky malaya sta wheelhouse kc unaffected clarification hardin impunity iz opportunist conspiracies marxist steadman abandons renko aerospace covington marcelo fabricate seaver disinfect refute ftl paving potus tabby sweated orwell subbu parkway clennam guangzhou ricochet autopsies responders rachid ymca coates rescheduled tesco blud derail lifespan monsanto incoherent beto wriggle theorem circumference albanians pacify sleepers dunce blasphemous bolivian preachers excessively spew unzip dictating drier nanda symbolize hunches christi oriented prohibit retraction sceptical turtleneck payable maisie defile unbutton chimera depress meeks mah buries breech oughtn mullins paralyze bhanu landis isolating abiding cowgirl weakens ornery ahhhhh lithuanian sterilize knelt fatten arid gaffer decimal clarified ungh greco kinship desolation prouder ines convened kaede beckons haggard smiths ensures dou riya ishida notches blowjobs esophagus baez fanning pythagoras epinephrine antiseptic tapeworm redford scythe escalation kol educator mantel revue jour safes muay rerun royally witsec demelza northbound cleverer ramadan paddock anaconda discontinued straightening argumentative mauser randi wallis carpentry vaccination preying fsb wedgie disarray bullhorn crumbles breaches arn corpsman nelle ennis indu jc robespierre cranston dissuade imp hsiao kltt buzzards grooms grinch kendal coolant fauna artichoke chemists kipper overlord mesmerized pretenses semantics silverman snobs colord layton leavenworth butyou sloshing sparking texan silences recalling negatively jett camouflaged joao salvaged fulcrum booklet splint ueda aberration trapdoor abundantly vexed rhydian oaths slink christos nair sensuality distantly flavored appreciating kostya oncology influencing ronan joes roan battleships boned frayed mott softness aries occupies govinda mummified bustling rewritten exhibiting putter canaan pk calgary pocketbook yadav reefer uppity dens hachi retreats innocently circulated akshay partnered latina chickie yachts abhay distilled geller cicadas technicolor tsa anemic kubrick globes pinging clammy modem dismay frosted gators amaro jacksonville masaki didst mackie clarisse helle russel spawned saxena perceptions winnipeg varying frenchie thwart congee gabbar nicking wonderin newspaperman carjacking availability couches dawns utw rojas indecisive fatma instigated paining thoracic kms sr promo murugan cleanest categorically chevron distributors windpipe kurdish plowed jeanine intents wormholes overpowering scuse ehm godsey wheeling daph grandmaster interpreting aga anka submitting bassett ladle braying jeeva savory zips qur disprove xun barba pleasantries sentimentality cs precincts pascoe lilli shamrock toothpicks tubing diagrams shivani sark allocated clegg degenerates pollard overheating liberace emts presidente steppe alisha neighborly sorenson winfield vaseline deluge leonora foolin disconcerting incumbent amplify riko payin morel arlen pucker potholes conjured denominator succulent buckles expenditure solis speedboat arriba kebabs buddhists hygienic galloway recalls dartmouth unscheduled clench confidant ratting bravado inbred garvin breezes astaire ofit tibbs waived katrin paralegal irrefutable larva lymph illegals deteriorate scrumptious acquit capisce crimea sanctimonious gerhardt antiquated captors babbles arabella labors falafel winces christoph statutes excelsior emergence paused catalan clotting cheol cb simons lillie banco rr skinhead warpath pterodactyl veils subsidiary jubei outgrown provence clunk terminology surveying upscale wifey colombians turnin foaming keystone bays confidently piloting outwit kau strengthening dn carnation complimented discouraging simona mvp marcela cinder comparative stepbrother gyro dissolves dribbling karachi majored kandahar mustangs goblet punchy servicing buren synch boku streisand surrenders marginal farhad tooting mozzie minibar addons trove satisfies doody consolidate gearing breastfeeding accelerates sargent jakarta populace kota misfit wavering grating romancing fey goingto ayako haemorrhage spongebob circa feckin billed reminders milked criticise minibus advises rajeev faithless milf easing blackbeard amplifier plywood suzu peacocks caboose kegs grandiose deline ueno gravestone toya absurdity strychnine redheads ozu carrion riccardo lissa blameless intrusive extenuating fubuki fozzie ood blatantly pruitt lividity facto rambaldi puns barone persians pemberton ruffians vw danilo thinkyou transmitters nyssa pragmatic leeway favoured abnormalities condensed burkhardt suspending falsetto stillman foothills tirelessly foreskin citing soleil decepticon presbyterian calista sardar viennese quirks theatrics hubris hyeong mayhew testimonies abdel imperfections sill creighton schroeder niner pretence hitching canes philistines booties unnamed depp devdas espn sidle pricked cred heimlich diagnostics zooming shackleton musty yukio eased mandrake compressor spontaneity neapolitan ayla signifies mcgowan ramble zoinks mire sniffer cfo subcommittee obituaries dutiful pursuits aiko debutante channeling kirsty wieners arr torchwood dokey contentment ventricle kurosawa nostril dyer jumble osborn raggedy aspiration hav exonerate mears swivel cougars lamppost jetty ronon psalm marat bereaved plucky hobie chrissakes shortages noblest margene homeowner gyeong untidy romy northumberland illustration wading cassettes tosa gentler fixture lovelier travolta dali kfc centimeter martins openness octavio mou harlee godly polymer cervix tumbled gato shuttles thrived realty fentanyl pena sanju garbo trudi pariah cameo pyongyang bilge ruskin inflicting embezzled numero colliding pings tinkering phooey tempura littering babel creeped monarchs mook tuts gare emancipated laguna bellboy roosters daylights concocted shockingly unsupervised hara marthe fuego stipend guang boasted sinuses habitual toussaint synchronize moonbase kringle aboriginal spiking migrant methodology watertight seance playfully tester obelisk loopy elude blare winn molds mahler ponzi pappa janos retrieving dogma kenichi purr underside normans marquesa racists cady levers eyesore aguilar pees colbyco sidetracked tactful entreat flor alphaff dialog toenail degas shredding neutrons pantheon numbness danville eton annoyance wildcats mok lob ply yessir moderately waah blane brinkley eyelash airy swanky irritates coupling yamashita blye barnum amiga hubba antsy sherif rednecks hagan seventies primer hotchner ao institutionalized paragon broderick canst tran elinor hadrian peugeot displeasure lynching snowboarding linebacker inanimate assertive hargrove zim jiao peppy blackwood assortment minty penner gung warleggan habeas parton blab nationalists meir fonda billa chekhov chambermaid kernel creatively ducktales gillette brazilians saws directorate clockwise hamsters soulmate doraemon hoy mingling bryson collared slurp didem southerners gayatri woong kree boden denning alvey capitan triangular evoke unfolds muskets joyride ethanol contemplation sabu foursome eventual femininity toke apartheid gunvald munni leakage welder stallone snuffed imf pushkin heady coleslaw tay horoscopes tropic counterfeiting organisations anyhoo littlest limitation diarrhoea aggravation unsavory yagami pogo clinch complexes atwater yash mijo radial retaining congestion bringin werert inconsistencies plush ruthlessly labourers rainey sift valour basta kinsey tankers enacted macpherson smoothies caprica tingly murderess dez kristi mcmahon sissies zipping euthanasia fondle roshan dispel belay naoki eustace motorboat sullen dior kerem bordering doherty curie testy sagar raffaele throes mccullough unnerving herding lemurs exposes huo badlands uncouth disposing destruct evers intubation twitchy malfunctioned cuddles idyllic narf meaty paddington typo hereto slider affluent cappella wiggling medicare teething sinha invoked kuo swordfish willem christmastime dumas whiting reiterate dulles dawdle nene orac reliability sear bookings tapas witherspoon template prissy adaptable advertisers quotas treble sneaker administering perils mowed boldness nettles tattooing grouch rallied telford gump merde kroll jeopardizing trafficker nong malnutrition groundhog jaya nutritional contemptible dykes resuscitation toi gaetano bales calderon mews hollander awkwardness redeemer diplomas hilliard veda nightlife gnocchi tipper farber balkan emigrate knighthood kathie desai migrated dominus octavian matsuda namesake weepy shiner grifter basking opa adolfo sagittarius smurfs censored wares memorizing seabed weasels councilwoman nationalism hsu technodrome handball mayumi pacifier magnificence atheists zbz paine embankment upgrades outed siphon shoals kilometre neutrality rhade radishes bas coined sequins baudelaire impersonator concoction incessant whirling chevrolet menstrual nesbitt ven ogling trig mauricio kaylee tylenol hectares spiro lynched glorify pl soraya triumphed masking prolific mutts magoo lectured thirteenth protege lobbyist directs impressing plantagenet jakes furies flatmate taki meta recuperate crossover lyrical shunt forsythe youll jesuit arrgh concord silvana yeogu durand tivo shopped blacklisted unsatisfied infantile niang decadence motherless unbridled momoko backlash leftist myspace acronym clots lorries barometer raucous mournful redheaded swerved peeked lundy ovulating obelix energon ferg dermatologist murtaugh daniele mahdi antwon naga kaze duvall stilts assimilate grieved fermented siddhu occupant ala derivatives spectacularly narrate reenactment gwi palma goren krakow quiero machiavelli laney chitti pistons bumming rawlins swordsmanship pennant dillinger marooned storehouse crouching pernell storybook hickok mailer dl sandstone gault mouch emanating godard sidewalks breadth baywatch synergy labelled coexist rasta ashleigh coldness crais orthopedic quimby workhouse panics brainwash perplexed hustled untill muldoon anni dinesh tish tosses specializing tiller newfoundland medellin causeway midlands vouched extraordinaire natsumi scarab illumination barns argo chunghae oddball larsson emo reprehensible pips convoys gunderson mutter dijon muthu diocese bartenders licensing restful workup getcha scotsman sycamore reappeared malay jami poppers backhand lawnmower cleric kickoff bethesda numerical cordy watermelons carnivorous guadalcanal governmental endures wellness boeing sher tamer certification reminiscing omo sul sunder shire bludgeoned futility halliday alli keita cla impervious yukawa weiner paltry jemma skeet unreachable analytical fruitless corsage bangin rife masquerading kt bullfighter graced bookshelf toxicity taxation subsidies barron camcorder tamra kneecap perforated wrinkly armenians gaudy lesion nibbling macao nss perfecting amicable veera claustrophobia periodically pennington prado zuko carats notoriety fungi nev landau nzt aggravating doused toothbrushes immersion afis skeletal beatty bhagat scents mitya endowment bookworm vertically pelant prioritize luciana loman bancroft intermediary myeong firestorm centerpiece proprietary jayden hindrance biologists obscenity mothra dake retires meridian oboe blurt tallahassee inflammatory coochie treatable hubbub fractions entail narrowing tetsuo lida festering wetter stumbles battleground pantomime voracious fleshy hamada traverse repose stimulates madhuri decontamination clapton peering foust remiss omi nauseating underfoot discredited acquisitions magnanimous slovak ishikawa tenement karine derive reiner schoolgirls hilltop soared palle cotillion poplar radford depressive underlined bib stroked separatist mothefrucker lynx nudes tectonic danforth crixus empirical eunuchs oregano inhospitable ryoko discerning kidder chantelle gobbling kodai acoustics pecs schuyler sunflowers galvin tomi ziegfeld toyou dilly sellin pittman incas lasagne prototypes elective vulgarity drinkers moos mortician youve dirtiest voluptuous aprons sibley gillis tortoises leighton masochist trilogy evergreen transcribed porta proletarian pygmy endora bogs shaka shetty fixin walmart deities hovel lazlo niklaus forester bracken dickson yuma indefinite matrimonial fullness abbi frey airwaves bhabhi cruises damper damnedest bushy shizuko remix romney emission revolutionize plummet mojito rickie exemption subways leticia carruthers poser moomin impasse angling gibby kronor mousetrap cassini echelon inconspicuous skepticism smoldering birgitte undisputed strikers penchant dependence livery clucks adela roark blackstone huffing infront iive viciously browne schnitzel hms racine scribble nobodies morrissey pheebs odile spic offed eiko atkinson battlestar fatherhood silks trembled rudd balding trifles blinky pres worshiped fabrice isak knuckleheads catty burgled giddap yearned faii mulcahy reprimanded saintly hedgehogs alters natsu pei breeland ack truer chesapeake traitorous ayn industrious agnew cottages goings shari renegotiate epicenter cantaloupe dapper sais upton sant perseus overtaken nother millionth compile touche dosed lightbulb mourners desktop krissi carcasses togetherness listenin kink disobedient packaged selby gables enterprising leaped gentlemanly wry hippopotamus discrepancies hashimoto rowland kawasaki margarine parameter mahmut router convinces applesauce ills agra confidentially rydell nunnery regaining aground pah mcdeere sommers abducting insulated unwritten respectability rooming mirrored fishin suman quay recoil brash dweeb iearn palpable shanty gatekeeper recreated insemination mojave schoolhouse figurines elongated lifestyles boos adoration quoi virginie strictest oiled mics continual teacup fertilized hertz manet matte scrapped spaulding inventors mendel baiting mobilization jeannette beady screamer faker weighted adjective stupor intensified sleaze randal stimulant nis cl grigory mitigating tosca pillage financier headquarter naidu talons reruns whither babysitters saori maison noting pio geared af sunup cheshire parr pulley pled fringes grasshoppers stupider unending morpheus hondo comprised cohesive sigrid belgians jilly juli infer trifling nursemaid mens magenta justly stuttgart diya roadie disabilities armoury ogami lyme yeow norwood onlookers sizeable martel taxing arseholes foxxy somersault clings backups mocks snitched clamped michi scamming tucking sumptuous doodles unlicensed grandest flagg jerseys steers autobot councils sebastien volley advocating bestest varma infiltrating grounding reclaimed macedonia ajar ramone drawbridge brahmin lucca writhing momento pisces refueling nonviolent ua shil manoeuvres queuing jovi saratoga hieroglyphics magi tentative ml reprisals sethu dividends nietzschean scammed taub graeme quinlan cilla subliminal disapproval grug oahu fenwick manju ebb sidebar eclair purdy iffy manifested promotes reminiscent unveiled choral hernando pattering grendel gallivanting bosh matchbox probate zipped dissected gae mammoths magnify marlboro scaled gallbladder madea asami waring vapour floorboard dismantling tippi bak zords fuckhead snide squabbling rescues cropped roams het boosting sikh yadda roadkill modesto kant restlessness conti khurana telecom ellingham tierney noreen mohini flaherty conch inescapable rc steeped hilde diluted orangutan progeny busybody clawing dreyfuss vacancies conquerors tra beheading annapolis cogs chatterbox grossman annually farewells jarrett glossy tama traumas lieut jeweller braden hennessey medley slugged paraphernalia departmental squealed jabba counterparts snapshots kneecaps belligerent fissure puppeteer costanza orestes rosanna allotment sincerest transcends gagarin djinn cancun fuselage wembley abuser capers propel murderface shortstop mathew mima showman popper kumbaya transgressions buyin pensioners brimming soya windowsill methamphetamine unquote marky noun rouen gerber baguette patter mediate patties kita eugenio ponderosa hows bedridden imperialist behest ourself originate squalor canaries arraigned endangerment messaging tethered thrifty vash adnan buongiorno hyperdrive backwoods catered formulate lovell croaks uncooperative craved thankless antennae carabinieri snazzy refrigeration inert gamekeeper textures argentinean skirmish specialties ela holiest ganesha manservant verdun cheech mariel intermediate parkman nips palpitations jacinto spans emanuel vivaldi polarity smokescreen smudged adriano collaborated skimmed unrecognizable overzealous rea ariane freer mannequins mclane nk kraken shekels gauls biotech sterilized pressurized scattering ziegler assange naz jeopardized consoling appointing wiper harping carmelo cinemas midland petticoat broyles flippin harrowing tearful clavin truest kwun cleft wray malware kanzaki riverdale bream justifiable fretting frowning potomac sten barked cancels homeowners fiendish shinobu notwithstanding redskins voyeur havers chronos abilene auctions mincemeat prosthetics hershey procured loathed decrepit bly eventful shimada skinheads petya oomph polluting hochstetter multiplication incentives remarked phlox horned pontius matchmaking soma basements barmy stockpile weavers meme hazelnut mailroom saturation ley sinkhole greenwood inertia impossibly westward pff philistine gnaw crepes paki geriatric honorably lope toasts hypertension puritan entropy palo mili baring imprinted sylar petter winks conditional marriott foreseeable evens vandalized garters flatulence samira rusk designation raus shamans garnett gunners captivating impresses extravagance vve chutes sphincter oshin leprechauns eben gsr pastoral beaufort proverbs bade shoebox responsibly sigurd rekha heston deducted oncoming trafalgar persists initiatives listings wameru proficient klondike kenna boog sty gallantry dutton assailants noboru duels forfeited absolved advantageous amps biochemical contraception lago winkle crayfish hotties obsessions accumulation gwendolyn converter deuces percentages assimilated swingers ivanov cobain institutional changeling vertebra hoofbeats sd machu romulus malayalam peacemaker plaintiffs universally corman instructing alissa ladylike loveable humps rien ea turnbull raza forster pentagram familial salutes separatists transistor mirai therapies sensibly spandex sinker incur decomposed informally trollop metz pandemonium marconi telltale mcclane jesper commissioners rosenthal guggenheim detrimental mavericks jogger overdressed narco deniz pageants aldrin monti diy tanzania coolers paratroopers bbq lydecker nomine concentrations dorn lada gwyneth escalade grandsons ame manipulator dustbin excavations edu tornadoes saxons cantina kindling rothstein beggin toulon undocumented barges hypnotist photons inappropriately certify naru amira thorny rosco colosseum diggin twiki electrocution lulla compatibility rudnick mccluskey beauregard seething herschel dents infertile hundredth crone nantucket hardman profanity savi flan pledging pickett narrowly harpy refine prohibits quartered rushmore boyhood implosion aguirre dorota ethically oni leaflet nyang troi bylaws corinthians jogi parakeet guppy pandemic mobsters tendons keynote recreating minori vacuuming characterize salam requiem ragtime stoney biddy pum terminus barrio hy octavius majid knockouts boleyn stapleton placid sirree clio nymphomaniac excommunicated bosoms agata qiao lyra hysterics girlish inhumans misdeeds racquetball amassed motherly vicarage pyotr unchecked turnpike eroded effeminate neely deane extravaganza optimum gad tet substation decomposing topaz depiction pregnancies ponch agrippina gargoyles dimaggio fontana pediatrics grandmama mcveigh dueling colic implementation overthrown administrators gobi dwindling diggle ptolemy earle omnipotent goss mites chia gelatin nought localized leery skittish collie graceland xiv sulfuric marten abnormality legwork trawler apprised wilds harkness christendom guidebook prophetic bakes offhand brixton jeffers weathered forties cohn hydrate ativan uncontrolled ceres yumiko boozer flounder motorbikes munson enact shatner breton menial grasslands bode crucible caputo lookee gena jemaine pruning doobie overestimate meathead drywall foolhardy brownstone basra bilateral aggressor uppercut anorexic bem slouch videotaped cadavers lunge callback battlefields sifting buffaloes michio acorns scouted snitches squarely fragmented parley catatonic trippy cadfael reshma yuppie unprovoked knowthat effortless resounding cymbals narcissism denham elkins reciprocate seminal smartphone aisles ingmar knotted yucky schematic karlsson carpeting katharina styrofoam whosoever ingest montrose precautionary coursing neurosis skint allyson amita dolt fervent upheld pablito ilse tacks wonky kronos franca sikander variance yoichi jeffersonian dregg skittles sanne outlived alienate yielding dedicating empowering borscht sustaining pendrick limber alerting smooching bartleby lilian mmmmm teensy seryozha snowmobile sonnet knifed avril bicker substituted wim wir depriving quaker celts beeswax wiles overview crassus topeka kasim schooner gluttony wladek shetland timbuktu gangnam budd goofed shaz igloo brine sayuri wouldst hallucinate nibbles quinine peels newlywed boasts loneliest reeve avoidance ania metzger sosa mica tugging consisting sombre gollum spacing kaspar celina sturgeon zwei peony augur isla redeeming macmillan puri crewmen organizers dastardly orcs ejaculation untamed streep hogwarts linds inhibitor jerzy tiramisu microwaves bough brendon dank akio underhanded backstreet archeology potency enthusiasts racy bitsy lts bedlam quell commuter workmanship tri natalya middleweight libra lat dominick erupts minsk estella adolph teaming horus kouga evermore feminists looms literacy decoding reelection kazama dispatches rowboat flaunting sonofabitch inscriptions ritalin refills softie twirling mcfarland kaitlyn obligatory shizuka skynet snatcher fingering blum narn malin keene tutors copacabana routing cosgrove cirrhosis transgression ota floater petunia calorie lmperial frowned prodigious libyan tawdry nuys tadashi boyish laurels sugary percell goode herto gardiner macklin virility indictments secnav sclerosis thunders crosshairs lagina cannoli omission substitution whooo twinkie cardassia chippy azusa seabiscuit flicking saba megha desecrated merman summed baller mille restructuring outpatient fundamentalist chitty blemish hayato sokka custodial failings thawed hein amiable elitist baptised stagnant simplistic parasol quibble martell dissolution iab kenyon salons permitting wher princely tolly stonewall amrita manifold bothersome joust pangs yama hume cyborgs laundered kinsman looters relayed rafts athenian uninterrupted asif delve roubles majesties mahendra hustlers sages milford miscalculated madurai laine duquesne sublet kn noblemen hooter diggers drugging furiously yasu deduced feelers sssh condemns hairspray dreamz sherbet erupting taut gentile chins frenzied piet chand deutsch flamingos pungent pensive skeptic distort caving doorways veneration stingray mcclure kees marzipan susi belson frugal claret potted morita elia alvarado mikkel workroom mathilda crapping flailing penetrates dais nincompoop falsehood pullin excesses bwana griggs cookery renamed merriment prospero siddhartha oishi oppressors valuation bidet peekaboo ambiguity javed alisa shacked auburn mikami taillight incheon guarantor sneer misspelled timberlake stiller rpm loca stratosphere doj vowel bigtime psychosomatic aruba mull entwined sistine primrose ivf thunderstorms roughing dozing decreases rerouted grainger pon syllabus reigned lora cultivation cochrane sartre rolly apothecary astounded rainstorm squirts jordy phat robocop chee nuptials lyre ryker duplicates garber dregs ejaculate masonic alteration unzips anthill embody bulldogs retailers uncivilized segregated bijou funnily enos liposuction jaunty quran ano skit quayle repaying dumpsters seneca menon acosta malevolent hesse westlake lieberman backroom recognises husk trod wormwood condolence shenzhen talcum barksdale patagonia normie oat waning latif methodist sombrero lidia scampi nagai drawback culpa valenti wheaton windfall recep befitting fistful auditory ajit magneto neurosurgery offthe weightless fordham skillet fjord breakfasts playroom materialistic flirtation cig crabb lecherous ivana epitaph fuelled filler dogged dietary solids steeple logbook wooed flirts diddy filtering madeira loader affiliation costner saddles atrium aforementioned rotates sousa amelie rubens singed ceramics contrived deductions limes richly hurtin inclusive ruffle shruti convergence frig pfc comparatively recorders hurst tattered renewing lapel dk westmore magellan mettle wheelchairs payed brokerage strengthens fifteenth guddu playdate leek nano sau intercede woohoo ceos oka begrudge faire sketched hamza kramden lexa renny cooties outwith conceptual cp blends yano campo amo bernhard solicit noh sways knockers seeping helmand annals resorted kenan associating bogdan janne blabber drumstick nuna dingy wrecker conjuring patil zelena germanic baseman deco asahi semblance mosques dialled retinal habitats metaphorical pelts rummaging doppler underpaid inconvenienced stealthy barnacles mirth sweatshop meanie oksana hazzard resolutions squirting lather irfan detects katara signaled refunds dreamland tio agua diminishing soils cheong repress leafy ledgers caricature calypso shifter butterfield bumpers pothole kumiko cocker fidgeting unloved satsuma devine kochi steakhouse complicates groucho glade agamemnon lifeblood att strep neverland gelato gusting nooooo electro monde int alek majnu montez rowley takagi graded regains bonk handbrake antennas agendas elliptical locust maul westwood gaunt dearer austerity stubs saluting straker riki starlet directional downpour infact subterfuge calibrated distillery harrigan transplanted buon fabien recant takeo handsomest portrayal haig xxx printout savitri nationally brunswick prim embodied endorphins kitties fugue commenced stoddard beelzebub baggins cleve archipelago sc piercings isha anon receivers kungfu nuria barnard propelled brackets ebenezer trespassers galveston yangtze shaming baritone backstory kibworth bronchitis lasky trappings djs dissecting nilsson jakub designate fatherless transsexual corso mountainside gawain wallander trite crystalline browser helplessly radhika montero precocious withering tweaking elyse palsy salut ick mcginty trotsky countryman acidity burials mathur coolness misgivings fromm poppycock simcoe neel greenery astoria attaching biter wilco honed fete hypodermic shigeru kokoro broadcaster injuns valle cruella winded unqualified thurman bereft raves dagmar exertion krishnan averages freshener dodgeball waistcoat mv alva garrow maryann moustaches dependency philosophies toyama colonoscopy phlegm visceral yangzhou minced pauli bigotry snowfall kuk encased bluegrass aback toddlers midshipman gogo lorca juggler ramya shingles hardwick soloist badshah yasuko motherfuck subscribers gunfighter ottomans featherstone brooms sumerian singleton checker kuala akashi vermeer purrs mulholland fairground foss jumbled hakan horseshoes maloney haa figurine azad rucksack parallels estonian jailbird orderlies courtiers selfishly weldon shear stanhope televisions coasts gower croaked loc ironclad rocksteady acrobats marinated pushers culver gudrun calluses glimpses labourer oppress procedural strasbourg ff dolled chappie mengele scaredy environmentally fianc falklands gosling redundancy chiffon trimmings enamel mcclellan deniability differs kabuki suzi gir inuit garlands bundled conducts eczema masala towne murakami bloodied frigate predominantly retrial bonne joong reliant subside jaan amma adrenalin thrower conceit librarians verdi agos energize encampment bouncers trix nagano shebang woolf kojima investigates sandpaper guardianship turpentine bruiser pookie norwegians galahad controllers hyatt clamouring bowery primeval mcphee devours commodus hitters hovv mists mangal caravans betterment volition sheltering surmise bedpan norwich stalkers hickman curzon utilized hacksaw terminals wellbeing bowden holman midair googling alejandra cobras undignified unchanging showy abhimanyu kavya fatah tadpoles shingo cramming mordred opinionated yeager botanist millet harmonic tinsel bohr toppings preemptive knapsack aldrich elvin hora repayment uninteresting maradona audited prosciutto noonan showgirl cambodian concise lisp kohler combatants algernon hassles peon brainstorming layered invigorating airwolf preceding rajasthan mclean slayers thrush topical barrie hoisted blasters glib nymphs alphas neurology turnoff unrelenting nipping civility pensioner savagery pita deciphered membranes advisement poops guk hoboken abnormally tecumseh shaves cardiovascular cornea govt shino zito overthe batten mylene leasing centaur astern accomplishing summation comstock mirko woodruff progresses globally playoff chie modestly emmalin thunderous excavate hedda shockwave renders bedouin sexting bereavement undersecretary mcginnis kavanaugh ema reals yoyo nastya fob bridle zoidberg polenta embassies venu rashmi emitted macarena zippy prashant tailors sonu jaden instill maim toranaga burrell jeeps havisham loveliness simi hooten interlude maharaja villainous humbling potluck paise foxhole breeders yeller spokes treehouse schaeffer stickup toasty rosina spectral literate hoff cowabunga nipper fatigued mora aaahhh wellesley cheep exposition yura fabled guile steely bartending tomorrows milligan boyer marvels condemnation maori tahir abound boogers cagey maddening decrees catastrophes guadalupe afghans colson wrangle invoking qian snapchat falcons cockeyed apprentices errant fl abductor akron stroud posturing hams ribbit recklessness metin yeoman pulaski repaint pansies kuni outweigh incessantly abrasive earful sion belated knoxville soba gerardo arrowhead skids isotope clocking brunettes muttley nisa implementing equestrian cutlets psalms endorsements stammer bremer waterworks chewie profusely andhra aum cadmus confidante outlines reformatory saddens gat quasimodo worshippers brackett influx electrocute confederates earhart barrack fantasized cou disqualify ruffled spectre undergarments subscriber marauder buxton shaver hogwash broach codeine cardiology bobcat fumbling bouquets thumper philippine traceable ganja oli barbecues janitors mcmillan geeky conners gulag clashing spunky butchering ogle limos feliz manticore occipital nva belching dreyfus jeopardise epsilon starkey frigg melina perpetuate pieter spastic parasitic sprouted roofie hydro georgette handpicked choreographed carstairs seppuku offside birdies caucus launchers laertes mullah richelieu characterized planners yellows bluth lender scribbled bumbling satsuki hypochondriac hanim hikers hosanna interned tommie repulsed wolfie svend ashtrays nadir falconer peyote calliope beavis ramones orifice rehabilitate vas latched sifu presided mcdermott instituted spellman venereal synod inthe fc neutrinos eff marianna coe mistreat wavelengths evolves holistic analog walkway fedor eri kovacs anagram interceptor zoila kanto cathedrals nagoya bogota atreides gd interrogator winchell bearers arvin plunkett hogg pigheaded manifestations executioners admirably chode upkeep yukie remmy plagiarism undisclosed underrated dunphy theological picchu postmaster definitions adolescents hapless malek tali touchdowns bubonic maribel invasions indiscretions maize undersea standup bracing smarten untrustworthy bosun soir nicu alt stenographer defector toda duma idris empathize zina sensibilities kinoshita popes unify eastbound ammonium peacetime gauguin almanac tho lyn motoring inherits terrell dvr downtime geri romain bremen whipple platelets scurry rota roared recipients beatle slurred harmonies kissy unearth excelled disembark spiced ul compiling seti dyslexic okra jena parietal alleluia renewable eng tryst gogol vecchio durango healthiest cowell credence benidorm decoys akita ritu zord taming stunner conclave urquhart eardrums tamika furnishings celtics foraging mms hugger rumplestiltskin thrusting viviane joaquim indignity souza parisians evaluating elites mariner goddaughter groveling orca commandeer backfires miho argos mentoring bulldozers stoic javelin jacobson toner fcc runaround rearranging abercrombie nettie bubbs bardot suckling cower poughkeepsie paraffin slaved espinosa mobs byrnes scooch jointly gravedigger marceau commandeered italia rath glynn debtors zafar alors hurtling presentations mozambique stealthily sellout rinaldi danziger tellers rainwater taxed gentiles bjarne blankenship braille jeon navarre nadja antti innards sangria cabernet fuchsia dreyer ejection tranq reveille candleford defcon dosa vowels madwoman multi deleting overwhelmingly epps salzburg cavemen silken rooks drummers ballantine haiku infringement rashly austere atv newsome hermano holograms glam serotonin sancti feign ditty piranhas oftentimes grids flax tracksuit vivi tonne excavating kendo loopholes bleh personalized speculative sadler nasir eally brawling bally boughs hampstead thimble mutate scripted gaylord barnyard hideously leclerc lugging rocha cleats backer wording eid charlemagne luthorcorp freedman suzanna frequented reykjavik jackasses impede mothballs arbitration brigham poppies radiating kodak kou gervais tobe opportune conduits iota spats malkovich glendale hurling perspectives variant jughead skanks prithee erratically stent discordant quirk mirjana giddyap electrifying backers lando grille sputnik zigzag dilbert leadeth monies rajveer cutlet motivates sada procreation socialite cushing fane colts mundy invades ligament vizag earthy helmsman salmonella calvary gatorade regents copter unconstitutional acidic outlandish pauses sheetal betsey swingin carat maeby reprogrammed muirfield graf debilitating shoeshine deformity ganz goofball trills caliphate accompanies decapitation keyboards amphibious sixteenth wolowitz janette flops lancer cordell keanu indochina guava tobi resolving enforcing pasted bullard hymen pows cusp fukushima slur eclectic alo roping iru fascinate provokes mooning ibuprofen uproot sik renaud triceratops congested exploratory britons clit xvi stacie popsicles nobita preside successive eachother sobered hoffmann mantelpiece ramps slobs molestation armaments sorcerers unfathomable thinning darl reinhold flannery spooner bushel sleight londo videotapes foreground lagging vermilion cordova jutland puffer prankster winnetou depose latinos bevan kiddy coogan vetting bested fon lesbo pheasants guesswork bim happenings traipsing veneer fleetwood nefertiti greenleaf wanderers becket toms kenta knockoff burnside inauspicious sarang belive brentwood wudang attache cataclysmic elgin sichuan cooter startup cripes heyes caped henhouse copeland rumpus venezuelan starfire peewee ishii woz taekwondo inexplicably ladybird forage sek jetta geyser ifthey brisbane pittance karmic familia countermeasures bunches unattainable gere planter jurgen shopkeepers disputed hamas rustlers raffi sedition blocker hasegawa darrah tenderloin tawni tsutomu envoys newbies ight shuttlecraft iniquity cosmology exiles amal miscalculation joana rostov instructive lannister whaddaya depicting screwup sugarcane terminating inaudibly pau thorin batcave squalid forego sprouting thongs obstructed galleys chewbacca mubarak grodd churchyard clod powders tacoma clobbered procreate ferocity higuchi kazumi shabana kamil alienation riverbed songbird aesthetics insertion commemorative waken reparations galt maam hinky complimenting capitalize balfour spicer motivations leonie nylons obliging palazzo wardens padua demarco tardiness guruji stubble arvind jabs chomp styx erotica interconnected fedex thoreau salamanca accumulating aggravate esoteric indulgent undergrad eloquence piglets mimosa ainsley insecticide adeline tanja pickering heaters amended colombo boarder racially winkler sui anoint scaling emmanuelle govind impeachment kerchief particulates urchins arousal mireille refrigerators hanlon nidge hysterectomy genovese scipio radiate grazia bhaskar carnivore bain confronts neigh decayed araki harumi evita felder cagliostro consummated omitted ceci abbess ogres fiercest reddish jacinta ballplayer pillowcase stroh hellman campos bolivar parable elspeth jamboree espheni swordsmen saviors resents stragglers montevideo rickey abhor wooh fondling gdr arenas hermitage krebs chipmunks cleverness anesthesiologist omelets backtrack spitter probabilities communicates premiums garnier jarl affleck fanciful morello outwards waterman netherworld furnaces cloister fitter anibal cartoonist pore internment farmed tortillas";
var VOCAB_COUNTS = "28787591,27086011,22761659,17099834,14484562,13631703,10572938,10203742,8915110,7400675,7337058,6900164,6755687,6444985,5739788,5516364,5174060,4938948,4821861,4764010,4610945,4419883,4401531,4374975,4262273,4210868,4203821,4158644,3892394,3826118,3806977,3631462,3544700,3434152,3334392,3148528,3138591,3060204,2983027,2883193,2778359,2738504,2630800,2576821,2510010,2487348,2459855,2431398,2431059,2298830,2298308,2263956,2203919,2159909,2154982,2140365,2000641,1969807,1968389,1950845,1839473,1792220,1781493,1742764,1741730,1734491,1722797,1709582,1705262,1666361,1634050,1531731,1520767,1453708,1449181,1428884,1405024,1348467,1346903,1340070,1327509,1322226,1315964,1312232,1275502,1274537,1267646,1265150,1191941,1188190,1176290,1174710,1173588,1166914,1153915,1149292,1111837,1100643,1090424,1040131,1038638,1035310,1022558,1010390,1000182,978966,963885,945653,930831,887363,885915,880841,880112,869522,842120,830324,823711,821275,818878,818019,811919,799351,785830,773577,767968,764564,744544,738599,732145,709390,697528,683128,666286,656387,655747,640206,639540,626520,624596,622415,619500,617674,611924,611677,601171,592651,590019,581087,580931,578606,577197,574752,574016,572997,572761,571621,567036,564268,561014,558542,556894,556318,552246,545768,528404,527395,520328,519795,517951,508486,503642,503417,498392,496267,481860,478282,478174,471643,471463,471037,455543,444863,444088,444014,442241,437537,435832,433900,431911,429536,422483,417218,411660,408760,405534,405497,403874,402557,401162,400530,395690,392510,392242,389949,388585,388520,388338,388127,386528,381816,378726,378587,378540,376973,375703,374486,373526,372846,370949,370620,369996,367145,366626,366395,365791,365421,365210,360665,358291,354323,352542,348167,347408,340756,339509,337629,337382,335573,331186,330956,330261,326550,325997,325748,324673,321824,320316,317589,314850,312927,312240,308204,307071,305139,304275,303550,303288,302508,302404,302013,298911,297985,294543,294536,290509,290496,290206,288422,287837,283807,283006,282420,281046,280930,279595,274656,273312,270720,269851,269704,267268,266844,264588,263566,263097,262988,262367,262141,261118,261104,260121,259877,259803,259500,258929,258808,258463,257947,257319,257109,256417,256079,255970,254427,254038,253171,250320,248729,247812,247466,247343,246514,246032,244200,243109,242871,242456,240475,240460,240176,240082,238853,237387,236600,235246,233865,233814,233368,232845,232325,231375,230464,230351,229751,229669,228332,228297,226993,225482,225171,222398,221380,219855,218563,215855,215274,215149,215090,214773,214062,213914,213279,211943,211329,208878,208705,207949,207205,206247,206106,202736,200811,198424,198149,197654,195875,194810,193687,193172,193014,192652,192248,192050,191989,190629,189513,189347,189000,188958,188822,188767,188628,188532,187858,186962,186445,186041,184228,183626,182580,182287,181663,180594,180082,179260,178378,178286,177770,177667,177337,176522,176507,176291,175091,174929,174657,174311,174205,174081,172281,171740,171596,170636,169037,168798,168774,168103,167981,167351,166980,166957,166702,166677,166551,166137,165693,165033,164938,164503,164386,164165,164162,164040,163259,163071,162905,162571,161421,160204,159995,159911,159444,159394,159061,158976,157817,157532,157501,157014,156641,156181,155667,155391,154667,154479,154407,154345,154095,153117,152520,151864,151195,151156,150927,150803,148469,148405,148389,147913,147205,147121,146903,146615,146064,144772,144399,143235,143107,142825,142573,142055,141835,141327,141208,141140,140970,140661,140553,140327,140078,139593,138996,138527,138432,138139,137598,137448,136699,136611,136564,136276,136137,136109,135631,135401,135341,134358,134088,133072,132594,132433,131999,131599,131497,131445,130182,129735,129732,129390,128779,128716,128220,128153,127657,127251,126657,126518,126398,125769,125731,125730,125446,125033,124995,124880,124874,124087,123994,123924,123718,122833,122698,122065,121552,121264,120295,118712,118230,118129,117970,117410,117267,117050,117029,116973,116736,116629,115908,115236,114104,114026,113963,113959,112881,112782,112582,112316,112229,110583,110344,110206,110199,109966,109748,109240,109140,108774,108596,108073,107974,107906,107826,107444,106589,106439,106394,106080,106067,105846,105298,105282,105009,104913,103913,102974,102956,102848,102782,102607,102595,102436,101852,101666,101302,101228,101133,100847,100137,100133,100005,99904,99607,99084,99032,98575,98420,98242,98076,98007,97778,97339,97328,97044,96631,96609,96529,96442,96431,95930,95321,95131,95125,95089,94964,94514,94104,94057,94057,93826,92512,92377,92265,91573,91243,91143,91035,90868,90771,90552,90441,90011,89880,89787,89667,89650,89451,89236,88925,88427,88407,88192,87762,87738,87683,87420,87378,86959,86877,86832,86660,86138,86133,85751,85638,85617,85366,85279,85186,85029,84936,84882,84856,84836,84368,84238,84224,83823,83679,83461,83422,83295,82903,82887,82769,82559,82240,82190,82085,81980,81953,81548,81193,81048,80818,80501,80423,80315,80267,79546,79323,79020,78920,78317,78264,78083,77824,77514,77326,77197,77052,76951,76940,76863,76816,76799,76744,76683,76658,76635,76540,76489,76015,75930,75776,75595,75557,75178,74957,74790,74580,74492,74299,74298,74262,74224,74060,73938,73929,73802,73770,73700,73678,73465,73113,73070,73070,72881,72777,72733,72478,72140,72054,71915,71906,71873,71840,71571,71524,71503,71435,71407,71163,71098,70979,70974,70968,70955,70929,70741,70659,70624,70583,70449,70043,69614,69575,69499,69441,69186,69119,68839,68790,68629,68571,68524,68510,68505,68472,68440,68354,68305,68282,68244,67702,67666,67595,67361,67236,67089,66734,66718,66526,66508,66503,66456,66177,66157,66119,66029,66018,65981,65974,65959,65880,65795,65756,65752,65659,65474,65448,65448,65432,65421,65275,65090,65082,64991,64969,64788,64761,64614,64521,64465,64456,64352,64304,64262,64169,63737,63714,63676,63672,63307,63294,63219,63084,62923,62860,62835,62763,62755,62746,62722,62582,62523,62502,62357,62325,62170,62166,62153,62148,62072,61935,61927,61813,61805,61785,61749,61698,61671,61646,61400,61371,61052,61050,61029,60938,60903,60812,60716,60633,60633,60581,60560,60548,60444,60404,60397,60381,60360,60200,60133,59993,59962,59906,59715,59703,59687,59557,59466,59464,59349,59332,59309,59277,59277,59151,59064,58748,58713,58677,58657,58654,58651,58608,58531,58529,58429,58366,58324,58017,57890,57866,57667,57659,57647,57555,57545,57542,57486,57388,57254,57179,57033,56919,56854,56757,56709,56659,56595,56502,56475,56460,56399,56391,56281,56234,55998,55979,55940,55842,55836,55750,55677,55638,55372,55336,55285,55259,55131,55128,55096,55079,54978,54813,54615,54449,54321,54306,54305,54148,54140,54115,54096,54085,54026,53933,53911,53718,53674,53603,53550,53527,53527,53452,53291,53124,53110,53006,53004,52981,52827,52751,52734,52731,52714,52565,52557,52546,52485,52240,52175,52026,51750,51728,51701,51581,51499,51492,51429,51334,51332,51287,51279,51258,51175,50976,50866,50847,50800,50792,50649,50617,50562,50522,50446,50364,50357,50276,50196,50107,50103,50069,49976,49963,49823,49808,49743,49704,49690,49684,49655,49144,49119,49107,49087,49017,48931,48891,48807,48797,48674,48666,48653,48641,48497,48484,48351,48345,48253,48247,48221,48063,48036,47938,47938,47936,47934,47900,47824,47819,47739,47699,47672,47650,47564,47559,47534,47491,47462,47439,47241,47210,46994,46938,46833,46770,46570,46490,46383,46358,46242,46233,46228,46153,46028,46010,45845,45834,45834,45828,45812,45774,45737,45678,45657,45614,45611,45572,45564,45553,45430,45422,45390,45374,45332,45251,45223,45214,45183,45096,44939,44913,44903,44853,44832,44806,44782,44770,44624,44619,44588,44545,44534,44529,44516,44489,44331,44289,44264,44231,44114,44110,44089,44005,43897,43839,43801,43798,43797,43786,43716,43671,43640,43636,43596,43550,43502,43421,43370,43357,43315,43298,43295,43294,43270,43130,43079,43018,42962,42916,42884,42880,42843,42799,42785,42731,42710,42705,42649,42538,42536,42487,42459,42417,42407,42329,42323,42315,42299,42219,42152,42093,42078,42074,42064,42026,41996,41873,41866,41837,41832,41817,41801,41772,41753,41732,41726,41720,41706,41697,41693,41692,41675,41650,41591,41535,41371,41290,41290,41240,41235,41193,41153,41145,41080,41079,41041,41035,41028,41025,41012,40914,40833,40796,40758,40753,40738,40719,40658,40590,40578,40518,40462,40449,40388,40387,40377,40343,40285,40282,40246,40210,40195,40194,40098,40065,40049,40033,39986,39897,39882,39874,39869,39856,39803,39791,39770,39556,39518,39485,39482,39476,39331,39330,39326,39252,39194,39142,39136,39095,39041,39022,38995,38933,38918,38867,38705,38640,38625,38585,38518,38504,38496,38449,38419,38407,38395,38371,38365,38355,38335,38229,38223,38220,38167,38164,38162,38121,38100,38047,38036,38007,37951,37914,37914,37907,37893,37844,37793,37769,37735,37711,37699,37699,37634,37535,37515,37474,37443,37417,37405,37373,37344,37283,37270,37203,37198,37180,37165,37115,37023,36984,36941,36938,36916,36907,36861,36849,36844,36841,36830,36815,36807,36802,36781,36733,36723,36711,36698,36680,36610,36535,36531,36528,36502,36481,36354,36345,36316,36292,36197,36189,36124,36046,36046,36039,36023,35996,35942,35876,35837,35828,35752,35735,35734,35711,35701,35690,35669,35595,35587,35569,35549,35547,35472,35431,35397,35335,35232,35216,35209,35155,35150,35126,35109,35108,35066,35051,35016,35001,34972,34935,34873,34827,34821,34816,34808,34794,34792,34788,34773,34733,34599,34595,34517,34482,34442,34442,34395,34375,34359,34342,34314,34291,34211,34128,34088,34035,33969,33953,33922,33904,33863,33854,33779,33775,33775,33755,33737,33704,33697,33682,33653,33639,33613,33595,33564,33550,33540,33491,33489,33414,33293,33256,33196,33190,33176,33161,33139,33113,33099,33081,33050,33032,33020,32997,32987,32979,32950,32841,32841,32837,32819,32757,32757,32746,32730,32715,32692,32623,32588,32547,32506,32492,32471,32400,32333,32321,32301,32288,32273,32190,32182,32178,32146,32130,32110,32098,32097,32073,32040,31973,31952,31937,31857,31833,31812,31791,31786,31767,31696,31657,31615,31574,31567,31561,31514,31501,31473,31440,31434,31415,31409,31406,31369,31355,31339,31306,31295,31285,31269,31261,31225,31217,31201,31193,31150,31135,31108,31095,31052,31047,31029,31008,30993,30922,30907,30876,30874,30826,30804,30801,30768,30683,30624,30565,30549,30470,30458,30447,30420,30395,30366,30350,30335,30274,30225,30208,30196,30183,30156,30144,30128,30122,30102,30057,30049,30029,29984,29953,29892,29883,29871,29862,29849,29799,29789,29775,29765,29762,29749,29742,29719,29707,29668,29645,29636,29625,29618,29606,29598,29565,29548,29547,29539,29528,29504,29479,29430,29378,29357,29337,29323,29291,29290,29282,29264,29229,29223,29172,29167,29134,29081,29069,29049,29037,29034,29028,28990,28972,28945,28920,28868,28853,28842,28773,28739,28713,28655,28619,28601,28532,28526,28510,28505,28503,28471,28465,28404,28386,28377,28373,28340,28309,28291,28290,28242,28213,28200,28199,28183,28151,28140,27986,27930,27928,27901,27884,27883,27863,27844,27842,27829,27820,27818,27815,27813,27798,27777,27761,27728,27722,27719,27696,27695,27692,27676,27662,27630,27542,27530,27518,27510,27462,27442,27434,27397,27383,27376,27372,27345,27302,27299,27273,27204,27140,27132,27127,27121,27116,27112,27077,27074,27074,27061,27044,27005,26990,26989,26977,26967,26958,26937,26879,26848,26840,26836,26829,26824,26788,26777,26740,26736,26690,26686,26681,26642,26574,26569,26540,26505,26461,26447,26438,26427,26393,26393,26386,26384,26356,26308,26288,26265,26241,26204,26185,26184,26174,26171,26163,26122,26113,26110,26098,26067,26061,26053,26020,26016,26011,25989,25987,25962,25945,25937,25931,25874,25861,25860,25812,25798,25785,25785,25771,25754,25746,25698,25688,25643,25633,25623,25604,25560,25518,25500,25456,25451,25436,25433,25423,25422,25398,25398,25360,25335,25312,25308,25303,25291,25290,25288,25262,25261,25236,25222,25197,25184,25183,25168,25165,25150,25143,25143,25116,25058,25056,25054,25052,24999,24979,24978,24973,24943,24909,24897,24873,24846,24843,24842,24828,24822,24820,24785,24779,24763,24753,24739,24722,24686,24670,24659,24645,24625,24623,24565,24532,24527,24451,24450,24449,24431,24425,24401,24400,24380,24375,24370,24370,24363,24363,24324,24293,24284,24261,24254,24245,24233,24230,24218,24208,24205,24197,24190,24186,24104,24079,24077,24064,24042,24032,24023,24008,24005,24001,24000,23954,23941,23935,23907,23905,23889,23882,23875,23870,23861,23839,23824,23813,23805,23799,23797,23792,23737,23737,23716,23635,23599,23587,23583,23577,23559,23547,23542,23529,23523,23492,23490,23479,23478,23467,23463,23462,23460,23453,23448,23430,23427,23403,23394,23379,23377,23374,23358,23354,23348,23343,23326,23319,23313,23311,23293,23268,23266,23260,23258,23227,23218,23211,23195,23192,23158,23158,23126,23087,23086,23070,23050,23036,23035,23019,22990,22982,22961,22926,22912,22901,22890,22889,22884,22870,22868,22866,22838,22834,22822,22813,22806,22805,22764,22726,22716,22679,22667,22649,22623,22616,22604,22596,22575,22533,22496,22483,22478,22477,22472,22413,22389,22384,22369,22345,22341,22338,22289,22284,22282,22247,22228,22210,22196,22181,22170,22145,22124,22116,22102,22036,22035,22009,21983,21961,21905,21871,21863,21862,21831,21830,21813,21790,21774,21771,21768,21761,21750,21737,21737,21719,21718,21717,21712,21711,21677,21669,21657,21644,21543,21542,21517,21499,21496,21491,21483,21466,21449,21440,21429,21429,21410,21399,21366,21356,21352,21347,21338,21327,21323,21314,21309,21282,21258,21235,21226,21202,21181,21173,21163,21144,21084,21070,21068,21049,21042,21034,21021,21005,20978,20973,20964,20958,20941,20930,20923,20916,20913,20899,20898,20894,20892,20888,20853,20851,20846,20835,20827,20800,20794,20786,20785,20771,20754,20746,20744,20725,20723,20720,20711,20685,20682,20677,20633,20627,20598,20595,20592,20578,20570,20566,20563,20553,20552,20547,20544,20527,20521,20515,20496,20488,20482,20480,20476,20462,20450,20444,20426,20413,20410,20377,20376,20349,20347,20341,20335,20324,20322,20316,20313,20312,20306,20268,20261,20252,20232,20229,20228,20226,20224,20215,20212,20211,20205,20181,20179,20171,20170,20103,20073,20041,20017,20015,20006,19995,19950,19950,19940,19938,19933,19921,19901,19899,19892,19848,19834,19834,19823,19819,19817,19791,19790,19757,19754,19730,19728,19723,19723,19713,19713,19700,19685,19681,19666,19664,19658,19630,19613,19609,19591,19583,19582,19581,19576,19572,19571,19546,19530,19515,19510,19462,19459,19451,19432,19422,19399,19398,19383,19379,19379,19375,19374,19327,19313,19306,19299,19294,19278,19263,19258,19249,19247,19236,19233,19225,19211,19199,19189,19168,19166,19163,19152,19152,19123,19116,19107,19104,19100,19075,19073,19055,19043,19042,19007,19000,18972,18951,18950,18947,18945,18900,18898,18897,18896,18891,18890,18875,18847,18839,18824,18820,18807,18800,18795,18791,18788,18766,18765,18763,18733,18679,18678,18638,18634,18625,18614,18614,18610,18609,18609,18608,18566,18562,18562,18547,18542,18538,18533,18533,18529,18518,18503,18494,18492,18491,18445,18414,18392,18385,18381,18380,18379,18378,18366,18352,18352,18346,18340,18338,18327,18320,18308,18303,18301,18291,18286,18275,18264,18255,18253,18247,18217,18213,18204,18194,18181,18169,18122,18120,18117,18117,18112,18100,18098,18094,18070,18045,18029,18023,18014,18000,17999,17993,17960,17927,17910,17882,17879,17850,17842,17830,17817,17799,17795,17794,17794,17773,17768,17768,17763,17760,17758,17747,17743,17740,17716,17715,17703,17692,17689,17672,17671,17652,17645,17637,17630,17624,17621,17617,17605,17605,17603,17598,17597,17583,17563,17553,17536,17531,17518,17516,17513,17495,17480,17472,17469,17465,17464,17462,17461,17459,17455,17432,17430,17430,17429,17429,17408,17407,17386,17374,17372,17372,17360,17339,17335,17326,17324,17318,17312,17312,17299,17295,17294,17294,17293,17285,17281,17277,17276,17258,17255,17252,17251,17246,17240,17239,17231,17231,17230,17227,17220,17198,17194,17189,17174,17172,17170,17142,17122,17110,17091,17070,17054,17028,17026,17016,17000,16989,16978,16952,16948,16943,16921,16907,16895,16891,16878,16877,16875,16875,16867,16865,16864,16846,16844,16835,16823,16815,16813,16788,16770,16763,16734,16729,16724,16691,16686,16685,16680,16663,16656,16648,16636,16632,16625,16614,16613,16610,16609,16606,16595,16584,16558,16555,16540,16521,16500,16500,16489,16487,16468,16465,16464,16453,16449,16416,16410,16410,16374,16373,16365,16359,16352,16348,16347,16342,16326,16320,16307,16303,16298,16293,16290,16273,16267,16265,16251,16251,16248,16244,16221,16221,16217,16213,16192,16192,16172,16159,16153,16145,16138,16138,16136,16112,16107,16100,16089,16088,16079,16064,16062,16048,16045,16026,16019,16018,16012,15992,15992,15982,15978,15968,15965,15944,15940,15936,15921,15903,15891,15889,15878,15870,15865,15856,15820,15812,15804,15781,15777,15773,15771,15766,15758,15748,15747,15745,15742,15736,15736,15730,15709,15707,15707,15707,15705,15691,15659,15659,15648,15648,15646,15642,15640,15618,15612,15600,15581,15579,15570,15566,15566,15564,15562,15550,15531,15524,15516,15502,15498,15495,15493,15493,15484,15482,15464,15457,15455,15445,15434,15423,15412,15387,15366,15350,15339,15338,15328,15326,15318,15312,15296,15296,15285,15281,15281,15276,15272,15229,15193,15191,15152,15139,15137,15126,15115,15106,15100,15097,15091,15089,15079,15073,15069,15068,15061,15045,15044,15034,15030,15012,15006,14987,14984,14980,14977,14944,14943,14939,14934,14921,14905,14899,14895,14892,14892,14888,14888,14887,14876,14872,14863,14857,14851,14798,14789,14789,14775,14768,14768,14751,14736,14734,14722,14699,14695,14688,14677,14667,14655,14651,14648,14647,14645,14644,14642,14625,14619,14616,14614,14614,14612,14609,14598,14596,14583,14575,14569,14557,14529,14507,14494,14489,14488,14479,14476,14462,14462,14440,14430,14421,14418,14417,14413,14411,14410,14403,14401,14399,14396,14396,14389,14377,14370,14367,14366,14350,14340,14310,14303,14303,14302,14300,14284,14279,14267,14262,14246,14244,14241,14233,14222,14221,14220,14200,14196,14190,14186,14169,14156,14150,14143,14141,14140,14131,14126,14122,14106,14103,14078,14074,14072,14069,14059,14058,14055,14053,14048,14047,14045,14042,14033,14026,14021,14014,14008,13994,13994,13993,13985,13978,13972,13970,13954,13954,13941,13935,13923,13922,13918,13916,13907,13898,13890,13887,13885,13873,13863,13856,13852,13850,13849,13848,13847,13842,13830,13825,13816,13814,13814,13801,13780,13777,13777,13775,13772,13771,13764,13763,13761,13760,13759,13759,13753,13742,13738,13738,13708,13699,13694,13690,13690,13676,13657,13655,13654,13646,13643,13637,13626,13617,13616,13609,13593,13591,13590,13582,13581,13578,13576,13566,13561,13558,13557,13552,13551,13549,13546,13545,13542,13540,13536,13518,13513,13513,13499,13497,13494,13475,13469,13455,13446,13446,13445,13443,13442,13438,13437,13428,13426,13420,13418,13418,13415,13415,13409,13398,13398,13389,13387,13367,13351,13332,13314,13308,13305,13299,13299,13295,13294,13293,13293,13290,13286,13278,13272,13270,13261,13252,13249,13242,13236,13221,13220,13219,13204,13202,13202,13201,13199,13198,13198,13196,13193,13180,13179,13177,13177,13175,13171,13163,13159,13153,13143,13131,13127,13124,13120,13118,13118,13116,13108,13107,13103,13100,13093,13083,13076,13069,13066,13066,13056,13027,13015,13008,12992,12984,12977,12970,12960,12952,12950,12948,12947,12944,12939,12931,12910,12909,12898,12889,12886,12885,12878,12876,12874,12873,12856,12848,12837,12835,12828,12826,12803,12801,12793,12791,12789,12782,12778,12777,12772,12770,12762,12762,12754,12750,12749,12745,12745,12743,12740,12737,12735,12733,12730,12713,12713,12711,12708,12705,12705,12702,12698,12693,12691,12691,12688,12684,12681,12669,12667,12662,12659,12658,12651,12646,12641,12634,12632,12627,12622,12620,12614,12610,12603,12593,12591,12588,12580,12573,12567,12560,12560,12549,12544,12544,12538,12537,12527,12526,12522,12502,12497,12485,12482,12477,12464,12455,12451,12451,12442,12440,12437,12437,12433,12424,12419,12411,12408,12408,12405,12399,12399,12396,12393,12385,12385,12381,12377,12374,12356,12355,12355,12344,12340,12331,12323,12314,12310,12303,12301,12298,12295,12290,12288,12286,12268,12268,12261,12258,12253,12252,12251,12242,12239,12235,12231,12218,12200,12199,12197,12182,12181,12179,12178,12170,12168,12157,12156,12153,12152,12149,12143,12143,12131,12130,12125,12122,12109,12105,12102,12101,12101,12100,12094,12088,12088,12085,12083,12076,12075,12070,12069,12061,12060,12054,12054,12049,12029,12029,12026,12009,12006,11993,11992,11983,11982,11977,11974,11973,11959,11943,11940,11934,11933,11902,11899,11897,11890,11886,11884,11881,11880,11879,11871,11869,11868,11865,11863,11840,11835,11828,11826,11823,11821,11817,11814,11813,11810,11808,11805,11803,11801,11798,11798,11782,11779,11776,11769,11765,11765,11764,11751,11751,11744,11737,11737,11729,11723,11723,11719,11717,11699,11684,11682,11679,11678,11672,11667,11659,11650,11646,11641,11639,11633,11630,11626,11621,11619,11608,11606,11601,11599,11586,11584,11582,11577,11576,11575,11573,11565,11562,11562,11561,11555,11555,11542,11541,11536,11527,11524,11509,11505,11504,11504,11500,11490,11488,11484,11484,11481,11481,11477,11475,11474,11471,11467,11459,11458,11456,11454,11454,11448,11442,11441,11435,11434,11431,11428,11419,11417,11416,11409,11409,11407,11402,11400,11400,11399,11393,11385,11384,11383,11375,11371,11367,11365,11364,11360,11346,11345,11339,11335,11335,11333,11315,11315,11310,11306,11306,11304,11303,11300,11288,11285,11281,11277,11257,11252,11251,11246,11246,11237,11236,11223,11222,11212,11206,11188,11188,11183,11171,11170,11170,11167,11166,11164,11157,11152,11151,11145,11131,11131,11128,11128,11127,11125,11123,11121,11120,11120,11114,11112,11108,11106,11104,11103,11093,11084,11077,11076,11070,11059,11055,11054,11053,11046,11041,11036,11034,11033,11031,11030,11022,11015,11008,11004,11004,10994,10984,10982,10980,10980,10980,10980,10977,10970,10969,10966,10961,10960,10959,10958,10957,10953,10950,10941,10939,10937,10937,10936,10931,10930,10924,10917,10906,10905,10883,10881,10878,10873,10871,10866,10865,10861,10853,10845,10843,10839,10832,10829,10829,10825,10823,10813,10808,10804,10797,10796,10791,10781,10780,10776,10774,10769,10764,10752,10739,10738,10736,10736,10734,10734,10729,10729,10728,10724,10721,10715,10714,10704,10699,10698,10696,10695,10691,10690,10682,10679,10677,10671,10669,10667,10666,10660,10659,10658,10656,10655,10629,10620,10611,10606,10590,10589,10589,10583,10579,10566,10564,10560,10557,10546,10539,10539,10537,10535,10531,10525,10519,10519,10517,10516,10510,10509,10509,10506,10501,10490,10487,10484,10474,10473,10471,10470,10462,10459,10457,10456,10456,10449,10441,10420,10416,10402,10401,10400,10400,10398,10396,10395,10394,10382,10381,10378,10376,10374,10374,10371,10367,10365,10362,10361,10355,10355,10355,10353,10349,10348,10344,10323,10323,10321,10321,10313,10307,10306,10305,10304,10300,10290,10289,10285,10285,10281,10281,10279,10278,10275,10272,10271,10271,10270,10266,10265,10262,10251,10235,10230,10229,10223,10214,10209,10207,10206,10205,10204,10200,10199,10181,10181,10173,10172,10168,10165,10162,10153,10152,10148,10145,10144,10143,10141,10138,10136,10133,10126,10121,10103,10100,10093,10092,10090,10082,10080,10080,10080,10077,10062,10055,10054,10053,10047,10039,10038,10035,10026,10024,10020,10014,10014,10008,10001,10001,10000,9999,9997,9995,9992,9991,9991,9988,9987,9986,9985,9981,9970,9969,9965,9951,9940,9939,9936,9934,9926,9923,9922,9918,9915,9912,9894,9893,9889,9888,9887,9884,9883,9876,9876,9873,9872,9862,9858,9853,9850,9847,9846,9844,9836,9835,9831,9829,9824,9824,9819,9813,9811,9803,9803,9802,9801,9793,9786,9785,9785,9781,9781,9779,9777,9776,9774,9771,9771,9766,9765,9765,9761,9761,9761,9756,9754,9752,9750,9747,9744,9743,9739,9732,9723,9723,9722,9718,9717,9717,9710,9709,9707,9706,9704,9703,9699,9695,9686,9686,9685,9684,9683,9678,9676,9674,9673,9672,9672,9669,9667,9667,9666,9665,9663,9662,9662,9661,9660,9659,9658,9655,9655,9653,9653,9652,9650,9647,9644,9636,9636,9635,9625,9624,9624,9619,9619,9616,9616,9614,9611,9604,9599,9598,9592,9588,9576,9568,9553,9552,9544,9543,9542,9541,9540,9538,9536,9534,9534,9533,9523,9522,9519,9514,9511,9508,9506,9504,9503,9502,9500,9499,9494,9493,9493,9492,9490,9489,9481,9480,9479,9476,9476,9472,9469,9466,9466,9463,9457,9454,9454,9454,9453,9453,9450,9449,9449,9444,9443,9442,9438,9421,9410,9410,9409,9408,9400,9398,9391,9388,9386,9384,9383,9374,9370,9369,9364,9363,9361,9361,9359,9359,9354,9351,9351,9350,9347,9346,9341,9325,9325,9324,9323,9321,9313,9308,9307,9305,9302,9301,9298,9297,9294,9292,9291,9287,9282,9273,9271,9270,9269,9265,9262,9262,9260,9255,9246,9245,9239,9237,9237,9235,9233,9233,9232,9230,9227,9225,9221,9216,9214,9213,9209,9208,9207,9194,9192,9188,9186,9184,9181,9181,9179,9179,9178,9178,9176,9168,9166,9166,9162,9160,9155,9145,9143,9140,9133,9133,9131,9130,9127,9124,9122,9117,9117,9109,9106,9104,9101,9100,9099,9098,9092,9092,9090,9089,9086,9084,9076,9075,9059,9059,9058,9058,9056,9054,9047,9047,9047,9047,9046,9045,9026,9026,9025,9022,9017,9013,9011,9011,9006,9001,8992,8989,8988,8982,8981,8977,8976,8975,8973,8972,8971,8967,8964,8963,8955,8952,8951,8944,8942,8941,8941,8938,8938,8934,8933,8929,8928,8926,8924,8921,8921,8919,8908,8902,8900,8898,8895,8894,8893,8891,8890,8890,8878,8874,8873,8873,8872,8870,8868,8868,8866,8866,8864,8858,8853,8852,8852,8846,8845,8839,8835,8830,8829,8828,8827,8825,8822,8821,8819,8819,8817,8817,8816,8812,8812,8810,8809,8803,8801,8799,8796,8795,8789,8781,8781,8779,8778,8778,8775,8769,8765,8764,8763,8759,8757,8754,8753,8753,8753,8749,8744,8738,8730,8724,8719,8719,8715,8714,8698,8690,8687,8686,8685,8681,8678,8675,8672,8669,8668,8664,8664,8659,8657,8656,8653,8647,8645,8641,8638,8635,8631,8631,8629,8627,8624,8624,8622,8620,8618,8617,8613,8612,8611,8607,8604,8596,8595,8594,8592,8591,8590,8590,8585,8580,8577,8576,8576,8575,8569,8569,8567,8566,8563,8561,8561,8551,8546,8545,8545,8544,8539,8534,8528,8524,8522,8518,8515,8513,8510,8509,8508,8507,8506,8505,8504,8503,8496,8492,8491,8491,8489,8488,8488,8488,8484,8483,8477,8477,8474,8473,8472,8469,8464,8463,8461,8460,8457,8452,8451,8448,8447,8441,8437,8435,8433,8431,8428,8424,8423,8423,8423,8421,8420,8417,8417,8416,8413,8411,8408,8403,8402,8401,8399,8398,8395,8394,8391,8389,8387,8386,8379,8377,8376,8376,8375,8373,8369,8368,8368,8368,8357,8357,8352,8348,8346,8345,8333,8332,8324,8321,8320,8315,8313,8308,8303,8297,8295,8294,8287,8278,8278,8276,8274,8269,8269,8268,8267,8266,8265,8264,8263,8257,8256,8254,8252,8248,8244,8241,8236,8235,8234,8232,8232,8229,8229,8218,8216,8215,8215,8212,8207,8203,8199,8192,8190,8189,8186,8185,8179,8176,8176,8175,8169,8159,8157,8155,8151,8150,8150,8148,8144,8128,8128,8127,8125,8125,8120,8118,8117,8115,8115,8113,8112,8112,8109,8109,8109,8107,8107,8107,8107,8107,8105,8097,8096,8095,8092,8091,8087,8080,8079,8074,8072,8069,8068,8068,8068,8066,8064,8061,8061,8056,8051,8049,8047,8040,8037,8037,8036,8036,8036,8032,8029,8028,8022,8020,8020,8012,8007,8005,8004,8003,7998,7998,7997,7996,7996,7995,7993,7993,7991,7990,7989,7987,7987,7985,7983,7983,7982,7978,7976,7969,7968,7967,7967,7966,7964,7961,7957,7954,7954,7953,7948,7944,7942,7940,7939,7935,7933,7933,7928,7925,7924,7923,7921,7920,7918,7916,7915,7914,7913,7912,7912,7910,7909,7909,7907,7906,7906,7905,7899,7898,7898,7897,7895,7894,7891,7887,7886,7886,7886,7881,7879,7872,7871,7869,7868,7864,7861,7860,7860,7860,7855,7854,7853,7852,7850,7850,7849,7848,7845,7841,7839,7839,7837,7837,7827,7819,7818,7818,7814,7814,7813,7809,7807,7806,7805,7803,7799,7798,7796,7796,7794,7794,7790,7790,7787,7784,7782,7780,7776,7774,7770,7769,7767,7766,7765,7764,7761,7759,7759,7758,7753,7748,7747,7741,7735,7731,7728,7727,7723,7721,7719,7719,7717,7716,7713,7711,7707,7707,7703,7695,7694,7693,7692,7685,7684,7682,7682,7681,7681,7680,7679,7676,7674,7674,7673,7670,7670,7667,7667,7665,7664,7661,7648,7648,7646,7645,7633,7632,7631,7627,7625,7619,7614,7614,7613,7607,7606,7606,7602,7597,7597,7593,7588,7586,7582,7578,7577,7576,7568,7566,7563,7562,7553,7553,7536,7535,7535,7530,7527,7525,7525,7525,7524,7523,7521,7521,7517,7517,7513,7510,7510,7507,7507,7506,7505,7504,7503,7501,7500,7498,7495,7495,7493,7493,7491,7491,7491,7485,7482,7480,7478,7477,7475,7468,7465,7462,7462,7459,7459,7450,7449,7447,7446,7445,7444,7442,7442,7438,7435,7434,7431,7431,7430,7428,7420,7420,7419,7418,7416,7415,7409,7406,7404,7395,7394,7387,7383,7382,7382,7380,7379,7379,7375,7374,7374,7373,7372,7369,7366,7364,7364,7363,7360,7358,7354,7351,7350,7349,7348,7347,7347,7346,7343,7342,7341,7341,7339,7335,7333,7330,7325,7323,7322,7321,7318,7316,7311,7309,7308,7305,7301,7299,7299,7297,7293,7290,7287,7286,7284,7281,7276,7269,7269,7267,7266,7265,7262,7260,7253,7253,7250,7250,7248,7245,7243,7242,7241,7239,7238,7236,7236,7236,7235,7234,7233,7226,7225,7224,7222,7221,7221,7218,7217,7217,7215,7215,7214,7208,7206,7204,7200,7198,7196,7196,7195,7193,7190,7186,7185,7185,7184,7183,7180,7178,7177,7177,7175,7173,7172,7171,7167,7164,7163,7161,7160,7153,7151,7146,7146,7146,7145,7145,7142,7140,7140,7137,7136,7134,7134,7131,7131,7121,7118,7114,7114,7113,7111,7108,7107,7107,7107,7105,7104,7103,7102,7100,7099,7099,7095,7092,7092,7090,7089,7087,7086,7085,7085,7084,7084,7077,7074,7074,7073,7072,7063,7061,7060,7056,7055,7055,7053,7053,7053,7052,7052,7051,7050,7050,7047,7036,7033,7032,7030,7028,7027,7027,7024,7022,7022,7022,7019,7018,7018,7017,7016,7014,7006,7004,7003,7000,6994,6988,6984,6984,6982,6981,6973,6972,6971,6970,6967,6965,6965,6959,6958,6956,6954,6953,6951,6944,6939,6937,6933,6931,6931,6930,6927,6926,6926,6923,6921,6918,6915,6915,6914,6909,6904,6901,6899,6898,6895,6895,6886,6885,6882,6880,6875,6875,6872,6872,6870,6868,6868,6867,6866,6863,6859,6858,6855,6848,6844,6843,6843,6843,6841,6836,6833,6828,6824,6823,6822,6821,6815,6813,6813,6811,6808,6803,6803,6802,6802,6801,6800,6797,6797,6789,6787,6786,6786,6778,6778,6777,6777,6777,6775,6771,6771,6768,6767,6765,6760,6760,6760,6759,6757,6755,6751,6750,6749,6747,6747,6746,6745,6743,6738,6738,6737,6737,6737,6735,6731,6728,6721,6720,6717,6717,6715,6715,6714,6714,6713,6711,6711,6706,6701,6700,6694,6694,6692,6692,6689,6688,6681,6680,6680,6678,6677,6677,6677,6677,6673,6669,6669,6666,6662,6661,6661,6660,6660,6655,6654,6649,6645,6642,6639,6639,6639,6637,6636,6634,6626,6625,6625,6624,6620,6620,6617,6610,6610,6608,6606,6605,6604,6603,6601,6597,6596,6595,6595,6594,6590,6584,6583,6579,6576,6573,6569,6562,6555,6554,6553,6553,6553,6549,6544,6544,6543,6543,6542,6541,6538,6537,6536,6535,6533,6531,6529,6529,6527,6526,6526,6523,6523,6522,6521,6520,6520,6519,6519,6516,6515,6513,6510,6505,6496,6496,6494,6493,6492,6491,6491,6488,6485,6482,6480,6480,6478,6477,6470,6470,6470,6469,6463,6463,6462,6462,6461,6459,6459,6453,6452,6452,6452,6450,6450,6447,6447,6446,6445,6444,6440,6438,6436,6435,6435,6435,6434,6431,6429,6428,6425,6424,6423,6422,6420,6419,6418,6418,6412,6412,6410,6408,6408,6408,6405,6401,6398,6398,6397,6395,6395,6394,6391,6390,6389,6388,6388,6386,6386,6381,6374,6370,6367,6367,6367,6366,6362,6359,6358,6357,6355,6354,6352,6352,6351,6350,6347,6345,6339,6336,6336,6334,6333,6331,6320,6319,6318,6318,6317,6315,6312,6312,6309,6308,6307,6304,6300,6299,6299,6298,6298,6292,6290,6290,6289,6287,6287,6284,6283,6282,6278,6277,6276,6276,6275,6274,6274,6274,6273,6273,6270,6269,6268,6266,6266,6263,6263,6262,6259,6257,6257,6256,6255,6252,6250,6247,6245,6240,6238,6236,6229,6229,6229,6226,6224,6224,6222,6222,6218,6217,6216,6216,6215,6215,6215,6214,6211,6209,6209,6208,6207,6204,6202,6201,6201,6201,6196,6193,6192,6192,6191,6190,6189,6189,6186,6186,6186,6185,6184,6184,6182,6180,6179,6179,6176,6175,6174,6172,6170,6169,6169,6167,6167,6167,6166,6165,6164,6163,6163,6158,6157,6156,6153,6153,6152,6152,6152,6150,6149,6145,6143,6143,6141,6138,6138,6138,6136,6134,6133,6133,6131,6131,6131,6130,6130,6129,6127,6127,6125,6125,6124,6124,6118,6117,6116,6115,6106,6104,6102,6100,6100,6097,6096,6095,6092,6092,6088,6086,6085,6081,6080,6075,6073,6072,6072,6070,6069,6066,6063,6060,6059,6059,6059,6056,6055,6054,6046,6042,6041,6041,6036,6034,6030,6028,6027,6024,6023,6022,6022,6019,6019,6017,6016,6015,6010,6008,6008,6007,6006,6006,6002,6001,5998,5994,5990,5989,5988,5987,5987,5985,5983,5982,5981,5980,5980,5979,5978,5978,5977,5976,5976,5975,5975,5973,5971,5970,5968,5967,5967,5966,5964,5963,5960,5960,5959,5958,5958,5957,5957,5956,5956,5955,5953,5952,5951,5951,5950,5950,5948,5946,5946,5946,5944,5944,5944,5943,5942,5941,5939,5939,5938,5938,5937,5936,5936,5935,5935,5935,5935,5934,5932,5932,5929,5929,5928,5926,5925,5922,5920,5918,5917,5917,5916,5914,5914,5914,5913,5911,5910,5908,5907,5906,5906,5904,5903,5900,5895,5893,5892,5890,5890,5883,5881,5881,5880,5880,5871,5870,5868,5867,5866,5865,5864,5862,5860,5855,5854,5853,5852,5850,5848,5846,5846,5846,5845,5843,5842,5841,5839,5839,5835,5834,5834,5833,5832,5832,5831,5828,5824,5822,5821,5817,5817,5814,5813,5809,5808,5807,5803,5803,5802,5801,5801,5799,5798,5797,5796,5794,5792,5792,5789,5789,5787,5786,5786,5785,5784,5781,5777,5776,5776,5776,5775,5774,5774,5770,5768,5768,5765,5757,5757,5756,5755,5755,5753,5753,5752,5748,5745,5744,5743,5741,5741,5740,5736,5734,5733,5733,5731,5727,5724,5721,5720,5719,5719,5718,5718,5717,5713,5712,5711,5708,5708,5707,5707,5702,5701,5701,5700,5698,5698,5697,5695,5694,5694,5693,5693,5691,5690,5690,5684,5683,5682,5681,5680,5678,5676,5673,5670,5668,5668,5668,5667,5667,5666,5665,5664,5662,5661,5660,5660,5656,5655,5654,5652,5652,5651,5650,5648,5648,5648,5647,5644,5640,5633,5632,5627,5627,5627,5624,5623,5622,5618,5618,5615,5615,5614,5613,5613,5613,5610,5608,5601,5597,5597,5595,5589,5589,5588,5587,5582,5582,5580,5579,5577,5574,5570,5568,5568,5566,5565,5565,5565,5563,5562,5562,5562,5562,5562,5562,5560,5559,5555,5554,5554,5553,5552,5552,5552,5551,5548,5548,5548,5546,5544,5544,5544,5540,5539,5535,5535,5534,5533,5532,5524,5523,5523,5520,5518,5517,5517,5516,5515,5512,5512,5508,5508,5508,5507,5507,5506,5504,5502,5502,5500,5498,5497,5497,5496,5495,5495,5492,5492,5491,5491,5488,5480,5480,5478,5478,5475,5475,5474,5474,5474,5473,5472,5471,5469,5466,5464,5462,5460,5459,5458,5457,5456,5455,5454,5454,5453,5453,5451,5450,5449,5448,5448,5447,5445,5444,5443,5442,5441,5439,5438,5438,5438,5438,5436,5436,5435,5434,5432,5432,5430,5428,5426,5425,5425,5425,5424,5422,5422,5422,5419,5419,5418,5418,5417,5416,5415,5415,5415,5414,5413,5410,5410,5409,5408,5407,5406,5405,5405,5401,5399,5398,5398,5397,5393,5393,5392,5391,5389,5388,5387,5387,5385,5385,5385,5384,5384,5384,5383,5382,5381,5380,5380,5376,5375,5375,5371,5370,5369,5367,5366,5364,5363,5363,5363,5363,5359,5357,5357,5356,5355,5353,5349,5348,5348,5346,5346,5343,5333,5331,5331,5330,5329,5326,5326,5325,5324,5323,5321,5321,5321,5316,5315,5315,5315,5314,5313,5312,5312,5309,5308,5307,5304,5300,5299,5298,5298,5297,5295,5293,5293,5287,5286,5286,5285,5284,5284,5284,5282,5281,5280,5280,5277,5276,5276,5275,5275,5274,5273,5272,5272,5272,5269,5269,5269,5269,5267,5262,5260,5257,5256,5256,5253,5251,5250,5249,5247,5246,5246,5244,5241,5241,5239,5238,5238,5237,5237,5236,5236,5235,5234,5233,5233,5232,5231,5231,5230,5229,5227,5226,5226,5225,5224,5224,5221,5220,5217,5217,5217,5212,5210,5209,5209,5207,5206,5205,5202,5202,5201,5200,5200,5199,5199,5199,5198,5197,5196,5196,5195,5194,5193,5193,5188,5187,5185,5182,5182,5181,5179,5177,5175,5174,5174,5172,5171,5171,5170,5170,5167,5166,5165,5165,5164,5158,5157,5156,5155,5154,5153,5153,5149,5148,5148,5147,5146,5143,5141,5140,5140,5138,5135,5134,5134,5133,5132,5132,5132,5131,5129,5128,5128,5127,5127,5126,5126,5122,5121,5120,5120,5120,5119,5119,5118,5116,5116,5116,5113,5112,5112,5109,5108,5107,5107,5105,5104,5102,5100,5100,5097,5096,5095,5095,5094,5093,5091,5091,5090,5089,5089,5088,5087,5087,5086,5086,5086,5085,5085,5083,5083,5083,5082,5082,5082,5082,5081,5080,5080,5080,5078,5077,5075,5075,5074,5074,5072,5068,5067,5067,5065,5064,5064,5064,5062,5062,5060,5058,5058,5057,5057,5054,5053,5053,5051,5051,5051,5050,5050,5050,5049,5049,5046,5042,5041,5040,5040,5040,5039,5039,5036,5035,5033,5032,5032,5032,5031,5030,5030,5029,5029,5028,5027,5027,5026,5024,5016,5016,5015,5015,5015,5014,5012,5012,5011,5011,5008,5008,5007,5007,5006,5005,5002,5002,4998,4998,4998,4996,4996,4995,4995,4994,4994,4993,4993,4992,4992,4989,4988,4987,4987,4987,4986,4986,4986,4985,4985,4984,4983,4980,4980,4978,4976,4974,4973,4973,4973,4973,4971,4969,4969,4969,4968,4966,4965,4963,4962,4961,4960,4959,4956,4953,4953,4952,4951,4950,4948,4945,4943,4940,4939,4937,4936,4936,4936,4936,4935,4933,4932,4932,4930,4930,4928,4927,4924,4923,4923,4923,4922,4922,4921,4921,4919,4918,4918,4918,4917,4915,4914,4913,4912,4912,4911,4911,4910,4910,4907,4906,4906,4906,4905,4905,4904,4902,4901,4898,4898,4898,4897,4896,4896,4895,4895,4894,4893,4893,4893,4893,4892,4891,4891,4886,4885,4884,4884,4882,4882,4881,4881,4879,4878,4877,4876,4874,4874,4874,4872,4869,4868,4867,4866,4864,4862,4861,4859,4859,4857,4856,4852,4851,4846,4845,4845,4843,4842,4840,4837,4837,4836,4833,4833,4828,4826,4825,4823,4820,4819,4819,4818,4818,4818,4813,4812,4812,4811,4810,4809,4806,4806,4806,4806,4803,4803,4803,4801,4800,4799,4799,4797,4796,4796,4795,4794,4793,4792,4791,4791,4789,4786,4786,4785,4783,4781,4780,4780,4779,4779,4777,4775,4774,4772,4771,4771,4769,4766,4765,4765,4764,4764,4764,4763,4762,4762,4762,4761,4761,4761,4760,4760,4760,4760,4759,4759,4758,4757,4756,4753,4753,4752,4752,4752,4751,4751,4750,4749,4748,4748,4747,4747,4746,4744,4742,4741,4739,4738,4737,4737,4736,4736,4732,4731,4730,4726,4724,4724,4723,4723,4722,4722,4721,4720,4720,4719,4718,4716,4714,4711,4711,4707,4707,4707,4707,4707,4706,4705,4704,4702,4702,4700,4700,4700,4698,4698,4696,4695,4693,4693,4693,4690,4688,4686,4683,4682,4682,4682,4682,4681,4681,4679,4678,4677,4677,4674,4674,4673,4672,4671,4671,4670,4670,4670,4669,4668,4667,4664,4664,4663,4662,4660,4659,4656,4655,4655,4654,4652,4652,4649,4647,4647,4645,4642,4642,4642,4638,4634,4634,4633,4633,4633,4630,4628,4626,4624,4622,4620,4618,4618,4615,4612,4612,4611,4610,4610,4609,4608,4608,4606,4605,4605,4604,4603,4602,4601,4601,4600,4600,4600,4599,4599,4597,4597,4597,4596,4596,4595,4595,4594,4594,4593,4593,4593,4592,4591,4590,4589,4589,4589,4587,4586,4586,4586,4585,4584,4584,4584,4582,4581,4580,4577,4577,4577,4576,4575,4574,4574,4569,4566,4562,4561,4560,4559,4558,4557,4557,4555,4553,4552,4550,4549,4548,4547,4545,4542,4542,4541,4541,4540,4539,4539,4533,4531,4528,4526,4524,4523,4521,4520,4519,4518,4518,4517,4517,4515,4512,4507,4506,4504,4501,4501,4495,4492,4492,4491,4491,4491,4490,4490,4489,4489,4489,4488,4487,4487,4484,4484,4483,4482,4482,4477,4476,4476,4474,4474,4473,4472,4470,4470,4470,4469,4468,4466,4464,4463,4462,4461,4461,4458,4458,4457,4456,4455,4453,4451,4451,4446,4441,4441,4440,4439,4438,4435,4432,4431,4431,4430,4429,4428,4428,4427,4426,4425,4425,4422,4422,4420,4420,4419,4419,4418,4415,4414,4414,4414,4414,4414,4414,4413,4412,4411,4408,4408,4408,4407,4405,4405,4404,4403,4402,4400,4399,4399,4397,4397,4397,4395,4395,4394,4393,4393,4393,4391,4390,4389,4389,4389,4388,4387,4386,4385,4385,4384,4383,4383,4382,4382,4381,4381,4376,4376,4376,4375,4374,4372,4371,4371,4370,4368,4367,4367,4366,4364,4364,4364,4363,4362,4361,4361,4361,4360,4360,4360,4359,4359,4357,4355,4355,4352,4352,4351,4350,4350,4345,4345,4345,4343,4341,4341,4341,4340,4338,4336,4335,4333,4330,4329,4329,4328,4325,4324,4323,4322,4322,4322,4322,4320,4319,4319,4319,4317,4317,4317,4316,4315,4313,4313,4313,4312,4312,4311,4311,4311,4310,4310,4309,4309,4308,4306,4306,4305,4300,4300,4299,4298,4298,4297,4297,4293,4292,4291,4291,4289,4288,4288,4287,4285,4284,4284,4284,4283,4283,4281,4281,4280,4280,4279,4279,4277,4277,4274,4273,4271,4270,4270,4269,4269,4269,4269,4265,4265,4265,4264,4264,4264,4264,4263,4263,4262,4262,4262,4261,4261,4261,4260,4259,4257,4255,4254,4253,4248,4248,4248,4247,4247,4247,4245,4244,4243,4241,4241,4238,4236,4235,4235,4234,4234,4233,4233,4232,4232,4232,4231,4231,4231,4230,4229,4229,4229,4228,4228,4228,4228,4228,4227,4226,4226,4226,4224,4220,4220,4218,4218,4217,4214,4213,4213,4212,4212,4210,4210,4208,4205,4205,4205,4205,4204,4203,4203,4202,4199,4198,4198,4198,4197,4193,4193,4192,4192,4192,4190,4190,4187,4187,4186,4186,4186,4185,4185,4184,4181,4180,4179,4179,4179,4179,4178,4177,4176,4173,4172,4172,4171,4171,4170,4166,4166,4165,4164,4164,4164,4162,4161,4160,4160,4159,4158,4158,4158,4158,4157,4157,4155,4154,4151,4151,4150,4148,4148,4148,4148,4146,4146,4141,4141,4140,4140,4139,4138,4138,4137,4137,4137,4136,4135,4134,4134,4133,4133,4132,4131,4129,4128,4128,4128,4127,4127,4123,4122,4121,4121,4120,4118,4118,4115,4113,4112,4110,4109,4109,4108,4108,4108,4107,4107,4105,4105,4104,4103,4103,4102,4102,4101,4100,4100,4097,4096,4096,4096,4096,4095,4094,4091,4090,4089,4088,4087,4087,4086,4085,4084,4083,4083,4083,4083,4083,4083,4080,4080,4079,4079,4078,4077,4076,4076,4075,4074,4074,4074,4072,4071,4071,4070,4068,4067,4066,4065,4065,4064,4064,4064,4064,4063,4063,4062,4062,4062,4061,4061,4060,4060,4059,4059,4058,4057,4057,4056,4056,4055,4054,4054,4054,4054,4052,4051,4049,4045,4045,4045,4044,4043,4042,4040,4039,4037,4034,4031,4029,4029,4028,4027,4027,4025,4025,4025,4024,4023,4023,4023,4021,4020,4019,4017,4016,4016,4016,4014,4014,4012,4012,4011,4011,4010,4009,4008,4008,4007,4007,4006,4005,4003,4001,4000,3999,3996,3995,3994,3994,3992,3992,3990,3989,3988,3988,3988,3987,3986,3986,3985,3985,3983,3983,3982,3981,3980,3980,3980,3980,3978,3978,3977,3977,3976,3975,3975,3975,3972,3970,3969,3968,3967,3967,3966,3966,3966,3965,3964,3962,3962,3960,3955,3955,3954,3954,3954,3954,3953,3952,3952,3951,3947,3943,3943,3942,3942,3941,3941,3940,3938,3938,3938,3937,3936,3936,3934,3933,3933,3932,3932,3932,3931,3929,3925,3924,3924,3924,3922,3919,3918,3918,3917,3916,3915,3913,3912,3911,3908,3907,3906,3905,3905,3904,3903,3901,3900,3900,3900,3899,3898,3898,3897,3897,3894,3893,3893,3893,3893,3892,3891,3890,3888,3888,3887,3886,3886,3884,3882,3881,3881,3879,3876,3876,3875,3874,3873,3872,3871,3871,3870,3870,3869,3869,3868,3868,3867,3866,3865,3864,3860,3859,3857,3856,3856,3856,3853,3852,3852,3852,3851,3850,3848,3848,3847,3846,3846,3844,3840,3839,3838,3838,3837,3836,3836,3834,3834,3833,3832,3831,3830,3829,3828,3828,3827,3827,3826,3826,3824,3824,3823,3823,3823,3822,3822,3821,3821,3821,3821,3819,3818,3816,3816,3813,3812,3811,3810,3808,3807,3806,3804,3803,3801,3800,3799,3799,3798,3797,3796,3796,3796,3793,3792,3792,3792,3791,3791,3789,3789,3787,3786,3786,3786,3786,3786,3785,3785,3785,3784,3783,3783,3781,3781,3781,3780,3780,3780,3779,3779,3779,3777,3775,3775,3773,3772,3771,3769,3769,3768,3768,3768,3768,3766,3766,3766,3765,3764,3763,3762,3762,3762,3762,3761,3761,3760,3760,3759,3759,3758,3757,3757,3754,3754,3754,3753,3752,3752,3750,3750,3750,3748,3748,3748,3748,3746,3746,3746,3745,3743,3743,3742,3741,3741,3740,3739,3739,3738,3738,3738,3737,3735,3735,3735,3735,3735,3735,3734,3734,3734,3734,3733,3732,3732,3732,3732,3731,3730,3729,3727,3726,3726,3723,3722,3720,3719,3719,3719,3718,3718,3717,3716,3715,3715,3715,3715,3714,3713,3712,3712,3710,3709,3707,3707,3707,3706,3705,3705,3704,3703,3703,3702,3702,3701,3699,3699,3698,3697,3697,3696,3696,3695,3695,3695,3690,3690,3689,3689,3688,3687,3686,3685,3684,3684,3684,3683,3682,3681,3681,3680,3679,3678,3678,3677,3677,3676,3674,3674,3674,3673,3673,3672,3671,3671,3670,3669,3669,3668,3667,3666,3665,3665,3665,3665,3664,3663,3662,3661,3661,3660,3660,3659,3659,3659,3659,3659,3659,3658,3658,3657,3656,3656,3656,3655,3655,3655,3655,3654,3653,3653,3652,3650,3650,3650,3649,3648,3646,3645,3645,3644,3642,3642,3642,3640,3636,3636,3636,3635,3635,3634,3634,3634,3633,3631,3631,3631,3630,3630,3628,3627,3625,3625,3625,3624,3624,3624,3622,3621,3620,3618,3617,3617,3617,3617,3616,3614,3613,3613,3613,3612,3612,3612,3611,3610,3608,3608,3607,3607,3607,3607,3606,3605,3605,3602,3601,3601,3600,3600,3600,3599,3598,3595,3594,3593,3591,3589,3588,3588,3587,3585,3583,3583,3583,3581,3580,3579,3579,3579,3579,3578,3578,3577,3576,3575,3575,3575,3573,3572,3572,3571,3571,3569,3568,3567,3566,3563,3562,3562,3561,3561,3560,3560,3559,3558,3558,3558,3557,3556,3555,3555,3554,3554,3554,3552,3551,3550,3549,3549,3548,3547,3545,3545,3545,3544,3543,3542,3541,3540,3538,3538,3538,3537,3536,3535,3535,3533,3531,3530,3529,3529,3526,3525,3525,3525,3523,3523,3522,3522,3522,3522,3521,3521,3520,3520,3519,3519,3519,3518,3516,3515,3515,3515,3514,3514,3508,3508,3506,3505,3505,3503,3502,3501,3500,3500,3500,3499,3498,3498,3497,3496,3496,3495,3494,3494,3493,3492,3489,3488,3488,3488,3488,3486,3484,3484,3484,3482,3482,3482,3481,3481,3481,3480,3480,3479,3478,3477,3477,3477,3477,3476,3475,3475,3474,3474,3473,3473,3473,3472,3471,3471,3471,3469,3469,3469,3468,3468,3468,3467,3467,3467,3465,3465,3464,3464,3462,3462,3462,3462,3462,3461,3461,3460,3460,3459,3459,3458,3458,3458,3458,3457,3457,3456,3456,3455,3455,3453,3453,3453,3453,3452,3451,3451,3451,3450,3449,3449,3448,3448,3448,3447,3447,3446,3445,3445,3444,3444,3443,3440,3440,3439,3439,3438,3438,3437,3437,3436,3434,3433,3432,3432,3432,3432,3432,3432,3431,3431,3430,3430,3429,3428,3428,3427,3426,3426,3425,3425,3423,3423,3422,3421,3420,3419,3418,3418,3418,3417,3415,3414,3414,3414,3414,3413,3413,3412,3411,3411,3411,3411,3410,3409,3409,3408,3408,3408,3406,3404,3403,3402,3402,3401,3401,3400,3399,3399,3398,3398,3396,3396,3396,3396,3396,3395,3395,3395,3393,3393,3391,3391,3390,3390,3388,3387,3386,3386,3385,3384,3382,3382,3381,3381,3380,3380,3379,3379,3377,3377,3377,3376,3374,3374,3372,3371,3371,3370,3369,3368,3368,3368,3368,3366,3365,3365,3364,3363,3363,3363,3362,3362,3361,3360,3360,3360,3360,3359,3359,3357,3356,3354,3354,3354,3353,3352,3352,3351,3350,3350,3350,3349,3347,3347,3346,3346,3346,3345,3345,3344,3344,3343,3343,3343,3343,3342,3341,3340,3340,3340,3340,3339,3339,3339,3338,3336,3336,3336,3336,3335,3334,3334,3333,3332,3332,3331,3330,3329,3328,3326,3324,3324,3323,3323,3323,3322,3322,3322,3321,3320,3320,3318,3317,3317,3317,3316,3316,3315,3315,3315,3314,3314,3314,3314,3313,3313,3312,3312,3312,3311,3311,3311,3310,3310,3309,3309,3309,3308,3308,3308,3308,3307,3306,3306,3305,3305,3304,3304,3301,3299,3299,3298,3298,3297,3297,3296,3296,3295,3295,3295,3294,3294,3294,3293,3293,3292,3290,3288,3287,3287,3287,3286,3285,3284,3283,3282,3279,3278,3278,3278,3277,3276,3275,3275,3275,3275,3274,3274,3272,3272,3271,3271,3271,3271,3271,3271,3270,3270,3270,3269,3268,3266,3266,3265,3264,3264,3264,3262,3261,3261,3260,3259,3259,3258,3258,3258,3257,3257,3255,3253,3252,3251,3248,3248,3248,3247,3246,3246,3246,3246,3246,3245,3245,3245,3245,3242,3242,3242,3241,3241,3241,3241,3240,3239,3239,3238,3237,3236,3236,3236,3234,3234,3233,3232,3232,3231,3229,3229,3228,3228,3227,3227,3226,3225,3224,3224,3224,3224,3223,3223,3222,3222,3221,3221,3220,3220,3220,3220,3219,3219,3218,3218,3218,3218,3217,3217,3217,3216,3216,3216,3216,3215,3215,3213,3213,3212,3211,3210,3209,3208,3208,3208,3206,3206,3205,3205,3204,3204,3204,3203,3202,3202,3201,3201,3201,3199,3198,3198,3197,3196,3196,3196,3196,3195,3194,3194,3193,3193,3191,3191,3190,3190,3190,3189,3188,3188,3186,3186,3186,3186,3184,3184,3184,3183,3183,3182,3180,3179,3178,3178,3177,3177,3177,3177,3176,3175,3175,3175,3173,3172,3172,3171,3171,3171,3171,3170,3169,3169,3168,3166,3166,3166,3164,3164,3164,3164,3163,3162,3162,3161,3159,3159,3159,3156,3154,3154,3154,3153,3153,3153,3153,3152,3152,3151,3150,3150,3150,3150,3150,3149,3149,3146,3146,3144,3144,3144,3144,3143,3143,3143,3142,3141,3141,3141,3140,3140,3140,3139,3139,3139,3139,3138,3137,3135,3135,3134,3134,3133,3132,3132,3132,3131,3130,3130,3128,3128,3128,3127,3127,3125,3124,3123,3123,3123,3121,3121,3120,3118,3118,3118,3117,3116,3115,3115,3115,3115,3114,3113,3113,3113,3113,3112,3112,3112,3112,3112,3111,3111,3111,3111,3109,3109,3108,3108,3107,3106,3105,3105,3105,3104,3104,3104,3103,3103,3101,3100,3098,3098,3097,3097,3096,3096,3095,3095,3095,3095,3094,3093,3093,3093,3091,3091,3091,3090,3090,3089,3088,3087,3087,3087,3087,3087,3086,3086,3086,3086,3085,3085,3084,3083,3083,3082,3082,3081,3080,3080,3079,3079,3078,3078,3077,3077,3076,3075,3075,3074,3073,3072,3072,3070,3068,3068,3068,3068,3068,3068,3068,3067,3067,3066,3066,3066,3064,3064,3063,3063,3061,3060,3060,3060,3059,3059,3059,3058,3056,3055,3055,3054,3053,3053,3053,3052,3052,3051,3050,3050,3049,3049,3049,3049,3048,3048,3047,3047,3045,3045,3044,3044,3043,3042,3042,3041,3041,3040,3040,3039,3038,3038,3037,3037,3035,3035,3035,3034,3034,3034,3034,3034,3033,3033,3032,3032,3032,3029,3028,3028,3027,3026,3026,3026,3025,3023,3022,3021,3021,3021,3020,3018,3016,3016,3015,3015,3014,3014,3014,3014,3013,3013,3012,3012,3011,3011,3011,3011,3011,3011,3011,3011,3010,3009,3009,3009,3008,3008,3008,3007,3007,3006,3006,3005,3005,3004,3003,3003,3002,3001,3001,3001,3000,3000,2999,2999,2999,2998,2998,2997,2996,2996,2996,2996,2995,2995,2995,2994,2994,2993,2993,2992,2991,2990,2987,2987,2986,2985,2985,2984,2983,2983,2983,2983,2982,2982,2982,2982,2981,2981,2980,2980,2979,2978,2978,2977,2976,2975,2975,2975,2973,2971,2971,2970,2969,2968,2967,2965,2965,2965,2963,2963,2962,2962,2960,2960,2958,2957,2957,2956,2956,2955,2955,2954,2954,2953,2953,2953,2952,2950,2950,2950,2949,2949,2949,2948,2946,2945,2945,2945,2945,2944,2943,2943,2942,2942,2942,2942,2941,2941,2937,2937,2936,2936,2936,2935,2933,2933,2932,2932,2932,2929,2929,2928,2928,2928,2927,2927,2927,2926,2925,2925,2924,2924,2924,2924,2924,2923,2923,2922,2918,2917,2917,2917,2917,2917,2915,2914,2913,2912,2911,2910,2909,2909,2908,2907,2907,2907,2907,2906,2905,2905,2905,2905,2905,2904,2904,2904,2904,2903,2902,2902,2901,2901,2900,2900,2900,2898,2898,2898,2898,2897,2897,2896,2895,2893,2893,2893,2892,2892,2890,2890,2889,2889,2888,2888,2887,2887,2886,2886,2885,2884,2883,2883,2882,2882,2882,2882,2882,2880,2880,2878,2878,2878,2877,2877,2877,2876,2874,2874,2874,2873,2873,2873,2873,2873,2872,2872,2872,2872,2871,2871,2871,2871,2871,2870,2870,2870,2869,2869,2868,2868,2868,2868,2867,2866,2866,2866,2866,2866,2865,2864,2864,2864,2864,2863,2863,2863,2863,2863,2862,2862,2862,2862,2860,2860,2859,2859,2858,2857,2857,2856,2856,2856,2855,2855,2853,2852,2852,2852,2852,2851,2850,2850,2850,2849,2849,2847,2847,2847,2847,2845,2845,2844,2844,2843,2843,2843,2843,2842,2841,2841,2841,2840,2839,2839,2837,2837,2836,2834,2833,2833,2832,2832,2830,2830,2828,2828,2828,2828,2827,2827,2827,2827,2826,2826,2826,2826,2825,2825,2825,2825,2824,2824,2823,2823,2823,2822,2822,2821,2821,2820,2818,2818,2818,2818,2817,2817,2817,2816,2815,2815,2815,2814,2814,2814,2813,2812,2812,2809,2808,2806,2806,2806,2805,2805,2804,2804,2804,2803,2802,2802,2802,2802,2802,2801,2800,2800,2799,2799,2798,2797,2796,2796,2794,2794,2794,2793,2793,2792,2792,2792,2791,2791,2790,2790,2790,2790,2789,2789,2789,2789,2788,2788,2787,2787,2786,2785,2784,2783,2782,2781,2781,2781,2779,2779,2779,2779,2779,2779,2779,2779,2778,2778,2778,2778,2778,2777,2776,2776,2775,2774,2774,2773,2772,2772,2771,2770,2769,2768,2767,2767,2767,2766,2766,2766,2766,2766,2765,2765,2765,2765,2765,2764,2764,2763,2763,2762,2762,2762,2761,2761,2761,2761,2760,2760,2759,2758,2758,2758,2758,2758,2757,2757,2757,2756,2756,2756,2755,2755,2755,2754,2754,2754,2753,2753,2753,2753,2752,2752,2751,2751,2751,2751,2751,2750,2750,2750,2750,2750,2750,2749,2748,2748,2747,2747,2746,2746,2746,2746,2745,2744,2744,2743,2743,2743,2742,2740,2739,2739,2738,2737,2737,2736,2736,2735,2735,2734,2734,2734,2732,2732,2732,2731,2731,2731,2731,2730,2729,2729,2728,2728,2728,2728,2727,2726,2726,2726,2726,2725,2725,2725,2725,2725,2723,2722,2722,2722,2722,2721,2721,2721,2721,2720,2720,2720,2719,2719,2719,2718,2718,2718,2718,2717,2717,2717,2717,2716,2716,2716,2716,2716,2715,2715,2715,2715,2714,2713,2713,2712,2711,2711,2710,2710,2710,2709,2709,2708,2707,2706,2706,2706,2706,2706,2706,2705,2705,2705,2704,2704,2703,2703,2703,2702,2701,2701,2701,2700,2700,2699,2698,2698,2698,2698,2696,2695,2695,2695,2694,2694,2694,2693,2693,2693,2693,2693,2692,2691,2691,2691,2690,2690,2689,2688,2688,2688,2688,2688,2687,2687,2687,2686,2685,2685,2685,2684,2684,2684,2684,2684,2683,2683,2682,2682,2682,2682,2682,2681,2681,2681,2681,2680,2680,2680,2679,2679,2679,2679,2678,2677,2677,2677,2677,2674,2674,2674,2673,2673,2673,2673,2671,2670,2668,2668,2668,2667,2666,2666,2665,2664,2663,2663,2663,2662,2662,2662,2662,2660,2660,2660,2660,2660,2659,2659,2658,2658,2658,2658,2657,2657,2656,2656,2655,2655,2655,2655,2653,2651,2650,2650,2650,2649,2648,2648,2647,2647,2647,2647,2647,2646,2645,2645,2645,2645,2644,2644,2643,2643,2642,2642,2642,2641,2641,2641,2641,2640,2640,2640,2639,2638,2638,2638,2638,2638,2638,2636,2635,2635,2634,2633,2632,2632,2631,2631,2630,2629,2629,2629,2629,2628,2627,2627,2626,2626,2626,2626,2626,2626,2626,2625,2625,2625,2625,2624,2624,2624,2623,2623,2622,2622,2622,2622,2621,2620,2620,2619,2619,2619,2619,2619,2618,2618,2618,2617,2617,2617,2617,2616,2616,2616,2616,2616,2614,2614,2614,2614,2613,2613,2612,2612,2610,2609,2609,2607,2607,2606,2606,2606,2606,2605,2604,2603,2603,2603,2603,2603,2603,2603,2601,2600,2600,2600,2599,2599,2599,2599,2599,2599,2598,2598,2598,2598,2598,2597,2597,2597,2597,2597,2596,2596,2595,2594,2593,2592,2592,2592,2591,2590,2590,2590,2589,2589,2589,2589,2589,2589,2588,2588,2587,2587,2587,2587,2587,2586,2586,2586,2586,2585,2585,2585,2585,2585,2584,2584,2584,2582,2582,2582,2581,2581,2581,2580,2580,2580,2579,2579,2579,2575,2575,2575,2575,2574,2574,2574,2574,2574,2573,2572,2571,2571,2570,2570,2569,2569,2568,2567,2567,2567,2567,2566,2566,2566,2566,2565,2565,2565,2564,2564,2564,2563,2563,2563,2562,2561,2561,2561,2560,2560,2559,2558,2558,2558,2558,2557,2556,2556,2556,2556,2556,2555,2555,2555,2555,2554,2553,2552,2552,2552,2551,2551,2550,2550,2550,2549,2549,2548,2547,2547,2546,2546,2545,2544,2543,2543,2543,2542,2541,2541,2541,2541,2540,2539,2538,2538,2537,2537,2537,2536,2536,2536,2535,2535,2535,2534,2534,2533,2533,2533,2533,2531,2531,2531,2530,2529,2529,2529,2528,2528,2527,2527,2527,2527,2526,2526,2526,2525,2525,2525,2525,2524,2524,2524,2523,2522,2522,2522,2522,2522,2522,2521,2521,2520,2520,2520,2520,2520,2519,2518,2518,2518,2518,2517,2517,2516,2516,2516,2515,2514,2514,2513,2513,2513,2513,2511,2511,2510,2510,2510,2510,2510,2510,2510,2510,2510,2509,2508,2507,2506,2506,2506,2505,2505,2505,2505,2505,2504,2502,2502,2502,2502,2501,2500,2499,2498,2498,2498,2498,2497,2497,2497,2496,2496,2495,2495,2494,2494,2494,2494,2493,2493,2493,2493,2493,2493,2493,2492,2492,2492,2492,2491,2491,2491,2491,2490,2490,2490,2489,2489,2489,2488,2488,2488,2487,2487,2486,2485,2485,2485,2484,2484,2484,2484,2484,2483,2482,2481,2480,2479,2479,2479,2477,2477,2476,2476,2475,2474,2474,2474,2473,2473,2473,2473,2472,2472,2472,2470,2470,2469,2469,2469,2468,2468,2467,2467,2467,2466,2466,2465,2464,2464,2464,2463,2463,2461,2461,2461,2461,2460,2460,2460,2460,2460,2459,2459,2459,2459,2458,2457,2456,2456,2456,2455,2455,2454,2454,2454,2453,2453,2453,2452,2452,2451,2451,2451,2451,2450,2450,2449,2448,2448,2448,2448,2447,2447,2447,2446,2446,2445,2445,2445,2445,2444,2444,2444,2444,2443,2443,2442,2441,2441,2441,2440,2440,2439,2439,2439,2438,2438,2438,2437,2437,2437,2436,2436,2436,2435,2435,2435,2435,2434,2432,2432,2432,2431,2430,2430,2430,2430,2430,2429,2429,2429,2428,2428,2428,2426,2426,2426,2426,2425,2424,2424,2423,2423,2423,2423,2422,2421,2421,2421,2421,2420,2420,2419,2419,2419,2418,2418,2418,2417,2417,2417,2417,2417,2416,2416,2415,2415,2415,2415,2415,2414,2414,2414,2414,2413,2413,2413,2413,2412,2412,2411,2411,2410,2409,2409,2409,2408,2408,2408,2408,2408,2407,2407,2407,2407,2407,2407,2406,2406,2403,2402,2402,2401,2400,2399,2399,2399,2396,2396,2396,2395,2395,2395,2395,2395,2395,2395,2395,2393,2393,2393,2392,2391,2390,2390,2390,2390,2389,2388,2388,2387,2387,2386,2386,2385,2385,2384,2384,2383,2383,2383,2383,2382,2380,2380,2379,2379,2378,2378,2378,2378,2377,2377,2376,2376,2376,2376,2376,2375,2375,2375,2375,2374,2374,2374,2373,2373,2373,2373,2372,2372,2372,2371,2371,2371,2370,2370,2370,2370,2370,2369,2368,2367,2367,2366,2366,2366,2364,2363,2363,2362,2361,2361,2361,2361,2360,2360,2359,2359,2359,2358,2357,2357,2356,2356,2356,2356,2356,2354,2354,2354,2354,2354,2353,2353,2352,2352,2352,2352,2352,2352,2352,2352,2351,2351,2350,2350,2350,2350,2349,2348,2348,2347,2347,2347,2347,2347,2345,2344,2344,2343,2343,2343,2342,2341,2340,2340,2340,2339,2338,2338,2338,2338,2338,2337,2337,2337,2337,2337,2337,2336,2336,2336,2336,2336,2336,2336,2336,2335,2334,2334,2334,2333,2333,2332,2332,2331,2331,2329,2329,2328,2328,2327,2327,2327,2327,2326,2326,2325,2325,2325,2325,2325,2325,2324,2324,2324,2323,2323,2323,2321,2321,2320,2319,2319,2319,2318,2318,2318,2317,2317,2317,2316,2316,2315,2315,2315,2315,2314,2314,2314,2314,2313,2313,2312,2310,2310,2310,2310,2309,2309,2307,2306,2306,2305,2305,2305,2304,2304,2303,2303,2303,2302,2302,2302,2301,2301,2301,2301,2300,2299,2299,2298,2298,2297,2297,2296,2296,2296,2296,2296,2296,2295,2295,2295,2294,2294,2294,2293,2293,2293,2293,2293,2293,2293,2292,2292,2292,2291,2291,2291,2291,2291,2291,2290,2290,2290,2290,2289,2289,2289,2289,2288,2288,2288,2288,2287,2287,2287,2287,2287,2286,2286,2286,2286,2286,2286,2285,2285,2284,2284,2284,2284,2284,2284,2283,2283,2283,2283,2282,2282,2282,2280,2279,2279,2279,2278,2277,2277,2276,2275,2275,2275,2274,2273,2273,2273,2273,2273,2273,2271,2271,2271,2271,2270,2270,2270,2270,2269,2269,2268,2268,2268,2268,2267,2267,2267,2266,2266,2265,2265,2264,2263,2262,2262,2262,2261,2261,2260,2260,2260,2260,2260,2259,2259,2259,2258,2258,2258,2257,2257,2257,2256,2256,2256,2256,2256,2255,2255,2254,2254,2254,2254,2253,2252,2252,2252,2251,2251,2251,2250,2250,2249,2249,2249,2249,2249,2248,2248,2248,2248,2248,2247,2246,2246,2246,2246,2245,2244,2244,2243,2243,2242,2242,2242,2241,2241,2241,2240,2240,2240,2240,2240,2239,2239,2237,2237,2237,2236,2236,2236,2234,2234,2234,2233,2233,2233,2233,2232,2232,2231,2231,2231,2231,2231,2231,2231,2230,2230,2230,2230,2229,2229,2228,2228,2228,2228,2227,2227,2227,2225,2225,2225,2224,2224,2224,2223,2223,2223,2223,2223,2222,2222,2222,2221,2221,2219,2219,2219,2219,2218,2218,2218,2218,2217,2217,2216,2216,2216,2216,2215,2215,2215,2214,2213,2212,2212,2211,2211,2210,2210,2210,2209,2209,2208,2208,2208,2208,2208,2208,2207,2207,2207,2206,2206,2206,2205,2204,2204,2204,2203,2203,2202,2202,2202,2202,2202,2201,2201,2200,2200,2200,2199,2199,2199,2198,2198,2197,2196,2195,2195,2195,2195,2195,2195,2194,2193,2193,2193,2193,2192,2192,2192,2191,2191,2191,2191,2190,2190,2189,2189,2189,2189,2189,2189,2189,2188,2188,2188,2188,2188,2188,2187,2186,2186,2185,2185,2184,2184,2184,2183,2183,2183,2182,2182,2181,2181,2180,2180,2180,2180,2179,2179,2179,2179,2178,2178,2178,2177,2177,2176,2176,2176,2176,2175,2175,2174,2174,2173,2173,2173,2173,2172,2172,2171,2171,2171,2170,2169,2167,2167,2167,2167,2166,2165,2165,2165,2164,2163,2163,2163,2163,2162,2162,2162,2162,2161,2161,2160,2160,2160,2160,2159,2159,2159,2159,2159,2159,2159,2159,2158,2158,2157,2156,2155,2155,2154,2154,2154,2153,2153,2152,2152,2151,2150,2150,2150,2149,2149,2149,2148,2148,2148,2148,2147,2147,2147,2146,2145,2145,2144,2144,2144,2144,2143,2143,2143,2142,2142,2142,2142,2141,2141,2141,2140,2140,2140,2140,2139,2139,2139,2138,2138,2138,2137,2137,2137,2137,2137,2136,2136,2135,2135,2135,2135,2134,2134,2134,2134,2133,2133,2133,2132,2132,2132,2132,2131,2130,2130,2130,2129,2129,2128,2128,2128,2128,2127,2127,2127,2127,2126,2126,2126,2126,2125,2125,2125,2124,2123,2123,2122,2122,2122,2122,2121,2121,2121,2121,2121,2120,2120,2120,2119,2119,2118,2118,2118,2117,2117,2117,2117,2117,2117,2117,2117,2117,2116,2116,2115,2115,2115,2115,2115,2114,2114,2114,2113,2113,2113,2113,2113,2113,2113,2113,2112,2112,2112,2111,2110,2110,2110,2110,2109,2109,2109,2109,2108,2108,2107,2107,2107,2106,2106,2106,2106,2106,2105,2105,2105,2105,2105,2105,2105,2105,2104,2103,2103,2103,2102,2102,2102,2102,2101,2101,2101,2101,2100,2099,2099,2098,2098,2098,2098,2097,2097,2096,2095,2095,2095,2095,2095,2095,2094,2094,2094,2094,2093,2093,2092,2092,2092,2091,2091,2091,2091,2091,2090,2090,2090,2089,2089,2088,2088,2088,2088,2087,2087,2087,2086,2086,2086,2086,2085,2085,2085,2085,2084,2084,2084,2084,2083,2082,2082,2082,2082,2082,2082,2081,2081,2081,2080,2080,2079,2078,2077,2077,2077,2077,2077,2077,2076,2076,2076,2075,2075,2075,2075,2074,2073,2073,2072,2072,2072,2072,2072,2072,2072,2071,2070,2070,2070,2070,2069,2069,2068,2068,2068,2067,2067,2067,2066,2066,2065,2065,2065,2064,2064,2064,2063,2063,2063,2063,2062,2062,2062,2062,2062,2061,2061,2061,2060,2060,2060,2060,2059,2059,2059,2058,2058,2058,2058,2058,2058,2057,2057,2057,2057,2056,2056,2056,2056,2055,2055,2054,2053,2053,2053,2052,2052,2052,2051,2051,2051,2051,2051,2050,2050,2050,2050,2050,2050,2050,2050,2049,2049,2049,2048,2048,2048,2048,2047,2047,2046,2046,2046,2046,2045,2044,2044,2044,2044,2043,2043,2043,2043,2042,2042,2042,2042,2042,2042,2041,2041,2041,2041,2041,2041,2040,2040,2040,2039,2038,2038,2038,2038,2037,2037,2037,2036,2036,2036,2036,2035,2035,2035,2034,2034,2034,2033,2033,2032,2032,2032,2032,2032,2031,2031,2031,2031,2031,2031,2030,2030,2029,2029,2028,2028,2027,2027,2027,2027,2027,2027,2027,2027,2026,2026,2026,2025,2024,2024,2024,2024,2024,2023,2023,2022,2022,2022,2022,2022,2021,2021,2021,2021,2021,2021,2020,2020,2020,2019,2019,2019,2019,2019,2019,2019,2019,2018,2018,2018,2018,2017,2017,2017,2017,2016,2016,2016,2016,2015,2015,2015,2014,2014,2014,2014,2014,2014,2014,2013,2013,2013,2012,2012,2012,2012,2011,2011,2011,2011,2010,2010,2010,2010,2010,2010,2009,2009,2009,2009,2008,2008,2008,2007,2007,2007,2007,2006,2006,2006,2005,2005,2004,2004,2004,2004,2004,2003,2003,2003,2003,2003,2003,2002,2002,2002,2002,2001,2001,2001,2001,2000,2000,2000,2000,2000,2000,1999,1999,1999,1999,1999,1999,1999,1998,1998,1998,1997,1997,1997,1997,1997,1997,1996,1996,1995,1995,1995,1995,1995,1994,1994,1994,1993,1993,1993,1992,1992,1992,1991,1990,1990,1990,1989,1989,1989,1989,1988,1988,1988,1987,1987,1987,1987,1987,1986,1986,1986,1986,1985,1985,1985,1985,1984,1984,1984,1984,1983,1983,1983,1983,1983,1982,1982,1982,1982,1982,1981,1981,1981,1981,1980,1980,1980,1980,1979,1979,1979,1978,1978,1978,1977,1977,1977,1977,1976,1976,1976,1975,1975,1975,1975,1974,1974,1973,1973,1973,1972,1972,1972,1971,1971,1971,1970,1970,1969,1969,1968,1968,1968,1968,1968,1967,1967,1967,1967,1967,1966,1966,1966,1966,1966,1966,1966,1966,1965,1965,1965,1964,1963,1963,1963,1963,1963,1962,1962,1962,1962,1961,1961,1961,1960,1960,1960,1960,1960,1959,1959,1959,1958,1958,1958,1958,1958,1958,1958,1958,1957,1957,1957,1956,1956,1955,1955,1955,1955,1955,1955,1955,1955,1954,1954,1954,1954,1954,1954,1953,1953,1953,1952,1952,1952,1952,1952,1951,1951,1951,1951,1951,1950,1950,1950,1948,1948,1948,1947,1947,1947,1946,1946,1946,1946,1946,1946,1946,1945,1945,1945,1945,1944,1944,1944,1944,1944,1944,1944,1943,1943,1943,1942,1942,1942,1942,1941,1941,1940,1940,1940,1940,1939,1939,1939,1938,1938,1937,1937,1936,1936,1936,1936,1936,1936,1936,1936,1935,1935,1935,1934,1934,1934,1934,1933,1933,1933,1933,1933,1932,1932,1931,1931,1931,1930,1930,1930,1930,1930,1929,1929,1928,1927,1927,1927,1927,1927,1927,1926,1926,1925,1925,1925,1924,1924,1924,1924,1923,1923,1923,1922,1922,1922,1922,1922,1922,1921,1921,1921,1921,1921,1921,1920,1920,1920,1920,1920,1919,1919,1919,1918,1918,1918,1917,1917,1917,1916,1916,1915,1915,1915,1915,1915,1915,1914,1914,1913,1913,1913,1913,1913,1912,1912,1912,1912,1912,1912,1911,1911,1911,1910,1909,1908,1908,1908,1907,1907,1906,1906,1906,1905,1905,1905,1905,1905,1905,1904,1904,1904,1904,1904,1904,1904,1903,1903,1902,1902,1902,1902,1902,1901,1901,1901,1900,1900,1900,1900,1900,1900,1900,1900,1899,1899,1898,1898,1898,1898,1897,1897,1897,1896,1896,1895,1895,1895,1894,1894,1894,1894,1894,1894,1893,1893,1893,1893,1892,1892,1892,1892,1892,1891,1891,1891,1891,1891,1891,1891,1890,1890,1889,1889,1889,1889,1888,1888,1888,1887,1886,1886,1886,1885,1885,1885,1884,1884,1884,1884,1884,1883,1883,1883,1883,1882,1882,1882,1882,1882,1881,1881,1881,1881,1881,1881,1880,1880,1880,1880,1880,1879,1879,1879,1879,1879,1878,1878,1878,1877,1877,1877,1877,1877,1877,1877,1877,1877,1877,1876,1876,1876,1876,1876,1875,1875,1875,1875,1875,1874,1874,1874,1874,1874,1874,1874,1874,1874,1874,1873,1873,1873,1873,1872,1872,1872,1872,1872,1871,1871,1870,1870,1870,1870,1870,1869,1869,1869,1869,1869,1868,1868,1868,1868,1867,1867,1867,1865,1865,1865,1865,1865,1865,1865,1864,1864,1864,1864,1863,1863,1862,1862,1862,1862,1862,1861,1861,1861,1861,1861,1861,1861,1861,1861,1860,1860,1860,1860,1860,1860,1859,1859,1859,1859,1859,1859,1859,1858,1858,1858,1858,1858,1857,1856,1856,1856,1856,1856,1856,1855,1855,1855,1855,1855,1854,1854,1854,1854,1853,1853,1853,1853,1852,1852,1852,1852,1852,1852,1851,1851,1851,1851,1851,1851,1850,1850,1850,1850,1850,1850,1849,1849,1849,1849,1848,1848,1848,1848,1847,1847,1846,1846,1846,1846,1845,1845,1844,1844,1843,1843,1842,1842,1842,1842,1841,1840,1839,1839,1839,1839,1839,1839,1838,1838,1838,1837,1836,1836,1836,1836,1835,1835,1835,1835,1835,1835,1835,1835,1835,1835,1834,1834,1834,1834,1834,1833,1833,1833,1833,1832,1832,1832,1831,1831,1831,1831,1831,1831,1831,1830,1830,1830,1829,1829,1829,1829,1829,1829,1828,1828,1828,1827,1827,1827,1827,1826,1826,1826,1826,1825,1825,1824,1824,1824,1823,1823,1823,1823,1822,1822,1822,1822,1820,1820,1820,1820,1819,1819,1819,1819,1818,1818,1818,1817,1817,1817,1816,1816,1816,1816,1816,1815,1815,1815,1815,1815,1815,1815,1814,1814,1813,1813,1813,1813,1812,1812,1812,1812,1811,1811,1811,1811,1811,1810,1810,1810,1809,1809,1809,1808,1808,1807,1807,1806,1806,1806,1806,1806,1806,1805,1805,1805,1805,1804,1804,1804,1804,1804,1803,1803,1803,1803,1803,1802,1802,1802,1802,1801,1801,1801,1800,1800,1800,1800,1799,1799,1799,1799,1798,1798,1798,1798,1797,1797,1796,1796,1796,1796,1796,1795,1795,1795,1794,1793,1793,1793,1792,1792,1792,1792,1792,1791,1791,1791,1791,1790,1790,1790,1789,1789,1789,1789,1789,1789,1788,1788,1787,1787,1787,1787,1786,1786,1786,1786,1786,1785,1785,1785,1784,1784,1784,1784,1783,1783,1783,1783,1783,1782,1782,1781,1781,1781,1780,1780,1780,1779,1779,1779,1779,1779,1778,1778,1778,1778,1778,1777,1777,1777,1777,1777,1776,1776,1776,1776,1776,1776,1776,1775,1775,1775,1775,1775,1774,1774,1774,1774,1774,1774,1773,1773,1773,1772,1772,1772,1771,1771,1771,1770,1770,1770,1769,1769,1769,1769,1769,1769,1769,1769,1768,1768,1768,1768,1768,1767,1767,1767,1767,1767,1767,1767,1767,1766,1766,1766,1766,1766,1765,1765,1765,1765,1765,1764,1764,1763,1763,1763,1763,1762,1762,1762,1761,1761,1761,1761,1761,1761,1761,1761,1760,1760,1760,1760,1760,1760,1760,1759,1759,1759,1759,1759,1758,1758,1757,1757,1757,1755,1755,1754,1754,1754,1753,1753,1753,1753,1753,1753,1752,1752,1752,1752,1751,1751,1751,1750,1750,1750,1750,1750,1749,1749,1749,1749,1748,1748,1748,1748,1748,1748,1747,1747,1746,1746,1746,1746,1746,1746,1745,1745,1745,1744,1744,1744,1744,1744,1743,1743,1743,1743,1743,1742,1742,1741,1741,1741,1740,1740,1740,1740,1739,1739,1739,1739,1739,1739,1739,1739,1739,1738,1738,1738,1737,1737,1737,1737,1736,1736,1736,1736,1735,1735,1735,1735,1734,1734,1734,1734,1734,1734,1734,1733,1733,1733,1733,1733,1733,1733,1732,1732,1732,1732,1732,1732,1732,1731,1731,1731,1730,1730,1730,1730,1730,1730,1730,1729,1729,1729,1729,1729,1729,1729,1728,1728,1728,1728,1728,1728,1727,1727,1727,1727,1726,1726,1726,1726,1725,1725,1725,1725,1725,1725,1725,1725,1724,1724,1724,1724,1723,1723,1723,1723,1722,1722,1722,1722,1721,1721,1721,1721,1720,1720,1719,1719,1719,1719,1719,1719,1718,1718,1718,1718,1717,1717,1717,1717,1717,1717,1716,1715,1715,1715,1715,1715,1714,1714,1714,1714,1714,1714,1714,1713,1713,1712,1712,1712,1712,1712,1711,1711,1711,1711,1711,1711,1711,1711,1710,1710,1710,1710,1709,1709,1709,1708,1708,1708,1707,1707,1707,1707,1706,1706,1705,1705,1705,1705,1705,1705,1704,1704,1704,1704,1703,1703,1702,1702,1701,1701,1701,1701,1701,1700,1700,1700,1700,1700,1699,1699,1699,1698,1698,1698,1698,1697,1697,1697,1697,1697,1696,1696,1696,1695,1695,1695,1695,1695,1695,1695,1695,1694,1694,1694,1694,1693,1693,1692,1692,1692,1692,1691,1691,1691,1690,1690,1690,1689,1689,1689,1689,1689,1689,1688,1688,1688,1688,1688,1688,1687,1687,1687,1687,1687,1687,1687,1686,1686,1686,1686,1686,1686,1686,1685,1685,1685,1685,1685,1685,1684,1684,1684,1683,1683,1683,1682,1682,1682,1682,1682,1681,1681,1680,1680,1680,1680,1680,1679,1679,1679,1678,1678,1678,1678,1678,1678,1677,1677,1677,1677,1676,1676,1676,1676,1676,1675,1675,1675,1674,1674,1674,1674,1674,1674,1674,1673,1673,1673,1672,1672,1671,1671,1671,1671,1671,1670,1670,1670,1670,1669,1669,1669,1669,1669,1669,1668,1668,1668,1668,1668,1668,1667,1667,1667,1667,1667,1666,1666,1666,1666,1666,1666,1666,1666,1665,1665,1665,1665,1664,1664,1664,1664,1664,1664,1664,1663,1663,1663,1663,1663,1663,1663,1663,1663,1662,1662,1661,1661,1660,1660,1660,1660,1660,1659,1659,1659,1659,1658,1658,1658,1658,1657,1657,1657,1656,1656,1656,1656,1656,1656,1655,1655,1655,1655,1655,1655,1655,1655,1654,1654,1654,1653,1653,1653,1653,1652,1652,1652,1652,1652,1652,1651,1651,1650,1650,1650,1650,1650,1650,1649,1649,1649,1649,1649,1648,1648,1648,1648,1648,1648,1647,1647,1647,1647,1646,1646,1645,1645,1645,1645,1644,1644,1644,1643,1643,1643,1643,1642,1642,1642,1642,1642,1642,1642,1642,1641,1641,1641,1641,1641,1641,1641,1641,1640,1640,1640,1640,1639,1639,1639,1639,1638,1638,1638,1638,1638,1638,1638,1638,1638,1637,1637,1637,1637,1637,1636,1636,1636,1636,1636,1635,1635,1635,1635,1635,1635,1634,1634,1633,1633,1632,1632,1632,1631,1631,1631,1630,1630,1630,1630,1630,1630,1629,1629,1628,1628,1628,1628,1628,1628,1627,1627,1627,1626,1626,1626,1626,1626,1626,1625,1625,1625,1625,1624,1624,1624,1623,1623,1623,1623,1623,1623,1622,1622,1622,1622,1621,1621,1621,1621,1621,1620,1620,1620,1620,1620,1619,1619,1619,1619,1619,1619,1618,1618,1618,1618,1618,1618,1617,1617,1617,1617,1617,1616,1616,1616,1615,1615,1615,1615,1614,1614,1614,1614,1613,1613,1613,1613,1613,1613,1612,1612,1612,1612,1612,1612,1612,1611,1611,1611,1611,1611,1610,1610,1610,1610,1610,1609,1609,1609,1609,1609,1609,1608,1608,1608,1608,1608,1607,1607,1606,1606,1606,1606,1605,1605,1605,1605,1605,1605,1605,1604,1604,1604,1604,1604,1604,1603,1603,1603,1603,1603,1603,1602,1602,1602,1602,1601,1601,1601,1601,1601,1600,1600,1600,1600,1600,1600,1600,1600,1599,1599,1599,1599,1598,1598,1598,1597,1597,1597,1597,1596,1596,1596,1596,1596,1596,1596,1595,1595,1595,1594,1594,1594,1594,1594,1594,1594,1594,1594,1593,1593,1593,1593,1592,1592,1592,1591,1591,1591,1591,1591,1591,1591,1591,1591,1590,1590,1590,1590,1589,1589,1589,1589,1589,1588,1588,1588,1588,1588,1588,1587,1587,1587,1587,1587,1587,1587,1587,1586,1586,1586,1586,1586,1585,1585,1585,1585,1585,1584,1584,1584,1584,1584,1584,1584,1584,1583,1583,1583,1583,1583,1583,1583,1582,1582,1581,1581,1581,1581,1581,1581,1581,1581,1581,1581,1581,1581,1580,1580,1580,1580,1580,1580,1580,1580,1580,1579,1579,1579,1579,1579,1579,1578,1578,1578,1578,1577,1576,1576,1576,1576,1576,1576,1576,1576,1576,1575,1575,1575,1575,1575,1575,1575,1575,1574,1574,1573,1573,1573,1573,1573,1572,1572,1572,1571,1571,1571,1571,1571,1570,1570,1570,1570,1570,1570,1570,1570,1569,1569,1569,1568,1568,1568,1568,1568,1568,1568,1568,1568,1568,1567,1567,1567,1567,1566,1566,1566,1566,1566,1565,1565,1565,1564,1564,1563,1563,1563,1563,1563,1563,1563,1563,1563,1563,1562,1562,1562,1562,1562,1562,1561,1561,1561,1561,1561,1561,1561,1561,1560,1560,1560,1560,1560,1559,1559,1559,1559,1559,1558,1558,1558,1558,1558,1558,1558,1558,1558,1557,1556,1556,1555,1555,1555,1555,1555,1555,1554,1554,1554,1554,1554,1554,1553,1553,1553,1553,1553,1553,1553,1552,1552,1552,1552,1552,1552,1552,1552,1551,1551,1551,1550,1550,1550,1550,1550,1550,1550,1550,1550,1549,1549,1549,1549,1549,1549,1549,1548,1548,1548,1547,1547,1547,1547,1547,1546,1545,1545,1545,1545,1545,1545,1545,1544,1544,1544,1544,1544,1544,1544,1543,1543,1543,1543,1542,1542,1542,1542,1542,1541,1541,1541,1541,1541,1540,1540,1540,1540,1540,1540,1540,1540,1539,1539,1539,1539,1539,1539,1539,1539,1539,1539,1539,1538,1538,1538,1538,1538,1538,1538,1538,1538,1537,1537,1537,1537,1537,1536,1536,1535,1535,1535,1535,1535,1534,1534,1534,1534,1534,1534,1533,1533,1533,1533,1532,1532,1532,1532,1532,1532,1532,1532,1532,1532,1532,1531,1531,1531,1531,1531,1531,1531,1531,1530,1530,1530,1530,1529,1529,1529,1529,1529,1528,1528,1528,1528,1528,1528,1528,1527,1527,1527,1527,1527,1526,1526,1526,1525,1525,1525,1525,1525,1525,1524,1524,1523,1523,1523,1523,1522,1522,1522,1522,1522,1522,1522,1522,1522,1520,1520,1520,1520,1519,1519,1519,1519,1519,1519,1519,1519,1519,1518,1518,1518,1517,1517,1517,1517,1517,1516,1516,1516,1516,1516,1516,1515,1515,1515,1515,1515,1515,1515,1514,1514,1514,1514,1513,1513,1513,1513,1512,1512,1512,1512,1512,1512,1512,1512,1512,1512,1511,1511,1511,1511,1510,1510,1510,1510,1510,1510,1510,1510,1510,1509,1509,1509,1509,1509,1508,1508,1508,1508,1508,1508,1508,1508,1507,1507,1507,1507,1507,1506,1506,1506,1506,1506,1506,1506,1505,1505,1505,1505,1504,1504,1504,1504,1504,1504,1504,1503,1503,1503,1503,1503,1503,1503,1503,1502,1502,1502,1502,1502,1502,1501,1501,1501,1501,1501,1501,1501,1500,1499,1499,1499,1499,1499,1499,1498,1498,1498,1498,1498,1497,1497,1497,1497,1497,1496,1496,1496,1496,1495,1495,1495,1495,1495,1495,1495,1495,1495,1494,1494,1494,1494,1494,1494,1494,1494,1494,1494,1493,1493,1493,1493,1493,1493,1493,1493,1493,1493,1492,1492,1492,1492,1492,1492,1492,1492,1491,1491,1491,1490,1490,1490,1490,1490,1490,1489,1489,1489,1489,1489,1489,1489,1488,1488,1488,1488,1487,1487,1487,1487,1487,1487,1487,1487,1487,1486,1486,1486,1485,1485,1485,1484,1484,1484,1484,1484,1484,1484,1483,1483,1483,1483,1483,1483,1482,1482,1482,1482,1482,1482,1481,1481,1481,1481,1481,1481,1480,1480,1480,1480,1479,1479,1479,1479,1479,1479,1479,1479,1479,1478,1478,1478,1478,1478,1478,1478,1478,1477,1477,1477,1477,1477,1476,1476,1476,1476,1476,1476,1476,1476,1476,1475,1475,1475,1475,1474,1474,1473,1473,1473,1473,1473,1473,1473,1472,1472,1472,1472,1472,1472,1472,1472,1472,1472,1471,1470,1470,1470,1470,1470,1469,1469,1469,1469,1468,1468,1468,1467,1467,1467,1467,1467,1467,1466,1466,1466,1466,1466,1466,1466,1465,1465,1465,1465,1465,1465,1465,1465,1464,1464,1464,1464,1464,1463,1463,1463,1463,1463,1463,1463,1462,1462,1462,1462,1461,1461,1460,1460,1460,1460,1460,1460,1460,1459,1459,1459,1459,1459,1458,1458,1458,1458,1458,1458,1458,1457,1457,1457,1457,1457,1456,1455,1455,1455,1455,1455,1455,1455,1454,1454,1454,1454,1454,1454,1454,1453,1453,1453,1453,1453,1453,1452,1452,1452,1452,1452,1452,1451,1451,1451,1451,1451,1451,1451,1451,1450,1450,1450,1450,1450,1450,1449,1449,1449,1449,1449,1449,1449,1448,1448,1447,1447,1447,1447,1446,1446,1446,1446,1446,1446,1446,1446,1445,1445,1445,1445,1445,1445,1445,1445,1445,1444,1444,1444,1444,1444,1443,1443,1443,1443,1443,1443,1442,1442,1442,1442,1442,1442,1442,1442,1442,1441,1441,1441,1440,1440,1440,1440,1440,1440,1439,1439,1439,1439,1438,1438,1438,1438,1438,1437,1437,1437,1437,1436,1436,1436,1435,1435,1435,1435,1435,1435,1435,1434,1434,1434,1434,1434,1434,1434,1433,1433,1433,1433,1433,1433,1433,1433,1433,1432,1432,1432,1432,1432,1432,1432,1432,1431,1431,1430,1430,1430,1430,1430,1430,1430,1430,1430,1429,1429,1429,1429,1429,1429,1429,1429,1429,1428,1428,1428,1427,1427,1426,1426,1426,1426,1426,1426,1425,1425,1425,1425,1425,1425,1424,1424,1424,1424,1424,1424,1424,1424,1424,1424,1424,1424,1424,1424,1423,1423,1423,1423,1423,1423,1423,1422,1422,1422,1422,1422,1422,1422,1422,1422,1422,1421,1421,1421,1421,1421,1421,1420,1420,1420,1419,1419,1419,1419,1419,1419,1418,1418,1418,1418,1418,1418,1418,1417,1417,1417,1416,1416,1416,1415,1415,1415,1415,1415,1414,1414,1414,1414,1414,1414,1413,1413,1413,1413,1413,1412,1412,1412,1412,1412,1411,1411,1411,1411,1411,1410,1410,1410,1410,1410,1410,1410,1409,1409,1409,1409,1409,1409,1409,1409,1409,1408,1408,1408,1408,1408,1408,1407,1407,1406,1406,1406,1406,1406,1405,1405,1405,1405,1405,1404,1404,1404,1404,1404,1403,1403,1403,1403,1403,1403,1402,1402,1402,1402,1402,1402,1401,1401,1401,1401,1401,1401,1400,1400,1399,1399,1399,1399,1399,1399,1399,1399,1398,1398,1398,1398,1398,1398,1398,1398,1398,1398,1397,1397,1397,1397,1397,1397,1397,1397,1396,1396,1396,1396,1396,1396,1395,1395,1395,1394,1394,1394,1394,1394,1394,1394,1394,1394,1394,1393,1393,1393,1392,1392,1392,1392,1392,1392,1392,1391,1391,1391,1391,1391,1390,1390,1390,1390,1390,1389,1389,1389,1389,1389,1389,1389,1388,1388,1388,1388,1387,1387,1387,1387,1387,1387,1387,1386,1386,1386,1386,1386,1386,1386,1386,1385,1385,1385,1385,1385,1385,1385,1385,1384,1384,1384,1384,1384,1384,1384,1384,1383,1383,1383,1383,1383,1383,1383,1383,1382,1382,1382,1382,1382,1381,1381,1381,1381,1381,1381,1380,1379,1379,1379,1379,1379,1379,1378,1378,1378,1378,1378,1378,1378,1378,1378,1378,1378,1377,1377,1377,1377,1377,1377,1377,1376,1376,1376,1376,1376,1376,1376,1376,1376,1376,1376,1375,1375,1375,1375,1375,1375,1375,1375,1375,1375,1375,1375,1374,1374,1374,1374,1374,1374,1373,1373,1373,1373,1372,1372,1372,1372,1372,1372,1372,1372,1372,1372,1372,1372,1371,1371,1371,1370,1370,1370,1370,1370,1369,1368,1368,1368,1368,1368,1368,1368,1368,1368,1368,1368,1368,1367,1367,1367,1367,1367,1367,1367,1366,1366,1366,1366,1365,1365,1365,1365,1365,1365,1364,1364,1364,1364,1364,1364,1363,1363,1363,1363,1363,1363,1363,1363,1363,1363,1363,1362,1362,1362,1362,1362,1362,1362,1362,1362,1362,1361,1360,1360,1360,1360,1360,1360,1359,1359,1359,1359,1359,1358,1358,1358,1358,1358,1358,1358,1358,1357,1357,1357,1357,1357,1357,1356,1356,1356,1356,1356,1356,1355,1355,1355,1355,1355,1355,1355,1354,1354,1354,1353,1353,1353,1353,1353,1353,1353,1353,1353,1353,1353,1352,1352,1352,1352,1352,1352,1352,1351,1351,1351,1351,1351,1350,1350,1350,1350,1349,1349,1349,1349,1349,1349,1349,1348,1348,1348,1348,1348,1348,1348,1348,1347,1347,1347,1347,1347,1346,1346,1346,1346,1346,1346,1345,1345,1345,1345,1345,1345,1345,1345,1345,1344,1344,1344,1344,1344,1343,1343,1343,1343,1343,1342,1342,1342,1342,1342,1342,1341,1341,1341,1341,1341,1341,1340,1340,1340,1340,1339,1339,1339,1339,1339,1339,1339,1339,1339,1338,1338,1338,1338,1338,1338,1338,1338,1337,1337,1337,1337,1336,1336,1336,1336,1336,1336,1336,1336,1336,1336,1336,1336,1335,1335,1335,1335,1335,1335,1334,1334,1334,1334,1334,1334,1334,1334,1334,1334,1333,1333,1333,1333,1333,1333,1333,1333,1332,1332,1332,1332,1332,1332,1332,1332,1332,1331,1331,1331,1331,1331,1331,1331,1331,1331,1330,1330,1330,1330,1329,1329,1329,1329,1329,1329,1329,1329,1329,1328,1328,1328,1328,1328,1328,1328,1328,1328,1327,1327,1327,1327,1326,1326,1326,1326,1326,1326,1325,1325,1325,1325,1325,1324,1324,1324,1324,1324,1324,1324,1324,1323,1323,1323,1323,1322,1322,1322,1322,1322,1322,1322,1322,1322,1321,1321,1321,1321,1321,1321,1321,1321,1321,1320,1320,1320,1320,1320,1320,1320,1320,1319,1319,1319,1319,1319,1319,1319,1319,1318,1318,1318,1318,1318,1318,1318,1318,1317,1317,1317,1317,1317,1317,1316,1316,1316,1316,1316,1315,1315,1315,1315,1315,1314,1314,1314,1314,1314,1314,1314,1314,1313,1313,1313,1313,1313,1313,1312,1312,1312,1312,1312,1311,1311,1311,1311,1311,1311,1310,1310,1310,1310,1310,1310,1310,1310,1310,1310,1310,1310,1310,1309,1309,1309,1309,1309,1308,1308,1308,1308,1307,1307,1307,1307,1307,1306,1306,1306,1306,1306,1306,1305,1305,1305,1305,1305,1305,1305,1305,1304,1304,1304,1304,1304,1303,1303,1303,1303,1303,1302,1302,1302,1302,1302,1302,1302,1302,1302,1301,1301,1301,1301,1301,1301,1301,1301,1301,1301,1301,1300,1300,1300,1300,1300,1300,1300,1299,1299,1299,1299,1299,1299,1299,1298,1298,1298,1298,1298,1298,1297,1297,1297,1297,1297,1296,1296,1296,1296,1295,1295,1295,1295,1295,1295,1295,1294,1294,1294,1294,1294,1294,1294,1293,1293,1293,1293,1293,1293,1293,1293,1292,1292,1292,1292,1292,1292,1292,1292,1292,1292,1291,1291,1291,1291,1291,1290,1290,1289,1289,1289,1289,1289,1289,1289,1289,1289,1288,1288,1288,1287,1287,1287,1287,1286,1286,1286,1286,1285,1285,1285,1285,1285,1285,1285,1285,1284,1284,1284,1284,1284,1284,1284,1284,1284,1284,1283,1283,1283,1283,1283,1282,1282,1282,1282,1282,1282,1282,1282,1282,1282,1281,1281,1281,1281,1281,1281,1281,1281,1281,1281,1280,1280,1280,1280,1280,1280,1280,1280,1280,1280,1279,1279,1279,1279,1279,1279,1279,1279,1279,1278,1278,1278,1278,1278,1278,1278,1278,1277,1277,1277,1277,1277,1276,1276,1276,1276,1276,1276,1276,1275,1275,1275,1275,1275,1274,1274,1274,1274,1274,1274,1274,1274,1274,1274,1274,1274,1274,1273,1273,1273,1273,1273,1273,1273,1272,1272,1272,1272,1272,1272,1272,1271,1271,1271,1271,1270,1270,1270,1270,1270,1270,1270,1269,1269,1269,1269,1269,1269,1268,1268,1268,1268,1268,1268,1268,1268,1268,1267,1267,1267,1267,1266,1266,1266,1266,1265,1265,1265,1265,1265,1265,1265,1264,1264,1264,1264,1264,1264,1264,1264,1264,1264,1264,1263,1263,1263,1263,1263,1262,1262,1262,1262,1262,1262,1262,1262,1262,1261,1261,1261,1261,1261,1261,1261,1261,1261,1261,1261,1260,1260,1260,1260,1260,1260,1259,1259,1259,1259,1259,1259,1259,1258,1258,1258,1258,1258,1258,1257,1257,1257,1257,1257,1257,1256,1256,1256,1256,1256,1255,1255,1255,1255,1255,1255,1254,1254,1254,1254,1254,1254,1253,1253,1253,1253,1253,1253,1253,1252,1252,1252,1252,1251,1251,1251,1251,1251,1251,1251,1251,1250,1250,1250,1250,1250,1249,1249,1249,1249,1249,1249,1249,1249,1249,1249,1249,1248,1248,1248,1248,1248,1248,1248,1248,1248,1248,1248,1248,1248,1248,1248,1248,1248,1247,1247,1247,1247,1247,1247,1247,1246,1246,1246,1246,1246,1246,1246,1246,1246,1246,1246,1245,1245,1245,1245,1245,1245,1244,1244,1244,1244,1244,1244,1244,1244,1244,1244,1244,1244,1244,1243,1243,1243,1243,1243,1243,1243,1243,1243,1243,1243,1242,1242,1242,1242,1242,1242,1242,1241,1241,1241,1241,1240,1240,1240,1240,1240,1240,1240,1240,1240,1239,1239,1239,1239,1239,1239,1239,1239,1239,1239,1239,1238,1238,1238,1238,1237,1237,1237,1237,1237,1237,1237,1237,1236,1236,1236,1236,1235,1235,1235,1235,1235,1235,1234,1234,1234,1234,1234,1234,1234,1234,1234,1233,1233,1233,1233,1233,1233,1232,1232,1232,1232,1232,1232,1232,1231,1231,1231,1231,1231,1231,1231,1231,1230,1230,1230,1230,1230,1230,1230,1230,1230,1229,1229,1229,1229,1229,1229,1229,1229,1229,1228,1228,1228,1228,1228,1228,1228,1228,1228,1228,1228,1228,1227,1227,1227,1227,1227,1227,1226,1226,1226,1226,1226,1226,1226,1226,1226,1225,1225,1225,1225,1225,1225,1225,1225,1224,1224,1224,1224,1224,1224,1224,1224,1224,1223,1223,1223,1223,1223,1223,1223,1222,1222,1222,1222,1222,1222,1222,1221,1221,1221,1221,1221,1221,1220,1220,1220,1220,1220,1219,1219,1219,1219,1219,1218,1218,1218,1218,1218,1218,1218,1218,1218,1218,1218,1218,1218,1218,1217,1217,1217,1217,1217,1217,1217,1217,1217,1217,1216,1216,1216,1216,1216,1216,1216,1216,1216,1216,1215,1215,1215,1215,1214,1214,1214,1214,1213,1213,1213,1213,1213,1213,1213,1212,1212,1212,1212,1212,1212,1212,1212,1212,1212,1212,1211,1211,1211,1211,1211,1211,1211,1211,1211,1210,1210,1210,1209,1209,1209,1209,1209,1209,1209,1209,1208,1208,1208,1208,1208,1208,1208,1207,1207,1207,1207,1207,1207,1206,1206,1206,1206,1206,1206,1206,1206,1206,1205,1205,1205,1205,1205,1205,1205,1205,1205,1205,1204,1204,1204,1204,1204,1204,1203,1203,1203,1203,1202,1202,1202,1202,1202,1202,1202,1202,1202,1202,1202,1201,1201,1201,1201,1201,1201,1201,1201,1201,1201,1200,1200,1200,1200,1200,1200,1200,1200,1200,1200,1199,1199,1199,1199,1199,1199,1199,1199,1199,1199,1198,1198,1198,1198,1198,1198,1198,1198,1198,1198,1197,1197,1197,1197,1197,1197,1196,1196,1196,1195,1195,1195,1195,1195,1195,1195,1195,1195,1194,1194,1194,1194,1194,1194,1194,1194,1194,1194,1193,1193,1193,1193,1193,1193,1193,1192,1192,1192,1192,1192,1192,1192,1192,1192,1192,1192,1192,1192,1192,1192,1192,1191,1191,1191,1191,1191,1191,1191,1190,1190,1190,1190,1190,1190,1189,1189,1188,1188,1188,1188,1188,1188,1187,1187,1187,1187,1187,1187,1187,1186,1186,1186,1186,1185,1185,1184,1184,1184,1184,1184,1184,1184,1184,1184,1184,1184,1184,1184,1184,1184,1184,1184,1184,1183,1183,1183,1183,1183,1183,1183,1183,1183,1183,1183,1183,1182,1182,1182,1182,1182,1182,1182,1181,1181,1181,1181,1181,1181,1180,1180,1180,1180,1180,1180,1180,1180,1180,1179,1179,1179,1179,1179,1179,1179,1178,1178,1178,1178,1178,1178,1178,1178,1178,1177,1177,1177,1177,1177,1177,1177,1177,1176,1176,1176,1176,1176,1176,1176,1176,1176,1175,1175,1175,1175,1175,1175,1175,1175,1175,1175,1175,1175,1174,1174,1174,1174,1174,1174,1174,1174,1174,1174,1174,1174,1174,1173,1173,1173,1173,1173,1173,1173,1173,1173,1173,1173,1172,1172,1172,1172,1172,1172,1171,1171,1171,1171,1171,1171,1171,1171,1170,1170,1170,1170,1170,1170,1170,1170,1170,1170,1170,1169,1169,1169,1169,1169,1169,1169,1168,1168,1168,1168,1168,1168,1167,1167,1167,1167,1167,1167,1167,1167,1167,1166,1166,1166,1166,1166,1166,1165,1165,1165,1165,1165,1165,1165,1164,1164,1164,1164,1164,1164,1164,1163,1163,1163,1163,1163,1163,1163,1163,1162,1162,1162,1162,1162,1162,1161,1161,1161,1161,1161,1161,1161,1161,1160,1160,1160,1160,1160,1160,1160,1160,1159,1159,1159,1159,1159,1159,1159,1159,1158,1158,1158,1158,1157,1157,1157,1157,1157,1157,1157,1157,1157,1157,1157,1157,1157,1156,1156,1156,1156,1156,1156,1156,1156,1156,1156,1156,1156,1156,1155,1155,1155,1155,1155,1155,1155,1154,1154,1154,1154,1154,1154,1153,1153,1153,1153,1153,1152,1152,1152,1152,1152,1152,1152,1152,1152,1152,1151,1151,1151,1151,1151,1151,1151,1151,1151,1150,1150,1150,1150,1150,1150,1150,1150,1150,1149,1149,1149,1149,1148,1148,1148,1148,1148,1148,1148,1148,1148,1148,1148,1147,1147,1147,1147,1147,1147,1147,1147,1147,1146,1146,1146,1146,1146,1146,1146,1146,1146,1146,1145,1145,1145,1145,1145,1145,1145,1145,1145,1145,1144,1144,1144,1144,1144,1144,1144,1143,1143,1143,1143,1143,1143,1143,1142,1142,1142,1142,1142,1142,1142,1142,1142,1142,1142,1142,1141,1141,1141,1141,1141,1141,1141,1141,1141,1140,1140,1140,1140,1140,1140,1140,1140,1140,1140,1139,1139,1139,1139,1138,1138,1138,1138,1138,1138,1138,1137,1137,1137,1137,1137,1137,1136,1136,1136,1136,1136,1136,1136,1136,1135,1135,1135,1135,1134,1134,1134,1134,1134,1134,1134,1133,1133,1133,1133,1133,1133,1132,1132,1132,1132,1132,1132,1132,1131,1131,1131,1131,1131,1131,1131,1131,1130,1130,1130,1130,1130,1129,1129,1129,1129,1129,1129,1129,1129,1129,1129,1129,1129,1129,1129,1129,1128,1128,1128,1128,1128,1128,1128,1128,1128,1128,1128,1128,1127,1127,1127,1127,1127,1127,1127,1126,1126,1126,1126,1126,1126,1126,1126,1126,1126,1125,1125,1125,1125,1125,1125,1125,1125,1125,1124,1124,1124,1123,1123,1123,1123,1123,1123,1123,1123,1123,1123,1122,1122,1122,1122,1122,1122,1122,1122,1122,1122,1122,1122,1121,1121,1121,1121,1121,1121,1121,1121,1120,1120,1120,1120,1120,1120,1120,1120,1120,1120,1120,1120,1119,1119,1119,1119,1119,1119,1119,1119,1119,1119,1119,1118,1118,1118,1118,1118,1118,1118,1118,1118,1118,1118,1117,1117,1117,1117,1117,1117,1117,1116,1116,1116,1116,1116,1116,1116,1116,1116,1115,1115,1115,1115,1115,1115,1115,1115,1115,1115,1115,1114,1114,1114,1114,1114,1114,1114,1113,1113,1113,1113,1113,1113,1113,1113,1112,1112,1112,1112,1112,1112,1112,1111,1111,1111,1111,1111,1111,1111,1111,1111,1111,1110,1110,1110,1110,1110,1110,1110,1110,1110,1110,1110,1109,1109,1109,1109,1109,1109,1109,1108,1108,1108,1108,1108,1108,1108,1108,1108,1108,1108,1108,1107,1107,1107,1107,1107,1107,1107,1107,1107,1107,1107,1106,1106,1106,1106,1106,1106,1106,1106,1106,1106,1105,1105,1105,1105,1105,1105,1105,1105,1104,1104,1104,1104,1103,1103,1103,1103,1103,1103,1103,1103,1102,1102,1102,1102,1102,1102,1102,1102,1102,1102,1102,1102,1101,1101,1101,1101,1101,1101,1101,1101,1101,1100,1100,1100,1100,1100,1100,1100,1100,1100,1100,1100,1100,1099,1099,1099,1099,1099,1098,1098,1098,1098,1098,1098,1098,1098,1098,1098,1098,1097,1097,1097,1097,1097,1096,1096,1096,1096,1096,1096,1095,1095,1095,1095,1095,1095,1095,1095,1095,1094,1094,1094,1094,1094,1094,1094,1094,1094,1094,1094,1094,1094,1094,1093,1093,1093,1093,1093,1093,1092,1092,1092,1091,1091,1091,1091,1091,1091,1091,1091,1091,1091,1091,1090,1090,1090,1090,1090,1090,1089,1089,1089,1089,1089,1089,1089,1089,1089,1088,1088,1088,1088,1087,1087,1087,1087,1086,1086,1086,1086,1086,1086,1086,1086,1086,1086,1086,1085,1085,1085,1085,1085,1085,1085,1085,1085,1085,1085,1084,1084,1084,1084,1084,1084,1084,1084,1083,1083,1083,1083,1083,1083,1083,1083,1083,1083,1083,1082,1082,1082,1082,1082,1082,1082,1082,1082,1082,1081,1081,1081,1081,1081,1081,1081,1081,1081,1080,1080,1080,1080,1080,1080,1080,1080,1080,1080,1079,1079,1079,1079,1079,1079,1079,1079,1078,1078,1078,1078,1078,1078,1078,1078,1078,1078,1077,1077,1077,1077,1077,1077,1077,1077,1077,1077,1076,1076,1076,1076,1076,1076,1076,1076,1076,1075,1075,1075,1075,1075,1075,1074,1074,1074,1074,1074,1074,1074,1074,1074,1074,1073,1073,1073,1073,1073,1073,1073,1073,1073,1073,1072,1072,1072,1072,1072,1072,1072,1072,1072,1072,1071,1071,1071,1071,1071,1071,1071,1071,1071,1071,1070,1070,1070,1070,1070,1070,1069,1069,1069,1069,1069,1069,1069,1069,1069,1069,1069,1068,1068,1068,1068,1068,1068,1068,1068,1067,1067,1067,1067,1067,1067,1067,1067,1067,1067,1067,1067,1066,1066,1066,1066,1066,1066,1066,1065,1065,1065,1065,1065,1065,1064,1064,1064,1064,1064,1064,1064,1064,1064,1064,1064,1064,1063,1063,1063,1063,1063,1063,1063,1063,1063,1063,1063,1062,1062,1062,1062,1062,1062,1062,1062,1062,1062,1062,1062,1061,1061,1061,1061,1061,1061,1061,1060,1060,1060,1060,1060,1060,1060,1059,1059,1059,1059,1059,1059,1059,1059,1059,1059,1059,1059,1058,1058,1058,1058,1058,1058,1057,1057,1057,1057,1057,1057,1057,1057,1057,1057,1057,1057,1057,1057,1057,1056,1056,1056,1056,1056,1056,1056,1056,1056,1056,1056,1055,1055,1055,1055,1055,1055,1055,1054,1054,1054,1053,1053,1053,1053,1053,1053,1053,1053,1052,1052,1052,1052,1052,1052,1052,1052,1052,1052,1052,1052,1051,1051,1051,1051,1051,1051,1051,1051,1051,1051,1051,1051,1051,1051,1051,1051,1051,1050,1050,1050,1050,1050,1050,1050,1050,1050,1050,1050,1050,1050,1049,1049,1049,1049,1049,1049,1049,1049,1049,1049,1048,1048,1048,1048,1048,1048,1048,1048,1048,1048,1047,1047,1047,1047,1047,1047,1047,1047,1047,1046,1046,1046,1046,1046,1046,1046,1046,1046,1045,1045,1045,1045,1045,1045,1045,1045,1044,1044,1044,1044,1044,1044,1044,1044,1044,1044,1044,1044,1044,1043,1043,1043,1043,1043,1043,1043,1043,1043,1043,1043,1043,1043,1043,1042,1042,1042,1042,1042,1042,1042,1042,1041,1041,1041,1041,1041,1040,1040,1040,1040,1040,1040,1040,1040,1040,1040,1040,1039,1039,1039,1039,1039,1039,1039,1039,1039,1039,1039,1039,1039,1038,1038,1038,1038,1038,1038,1038,1037,1037,1037,1037,1037,1037,1037,1036,1036,1036,1036,1036,1036,1036,1036,1036,1036,1036,1036,1036,1036,1036,1035,1035,1035,1035,1035,1035,1035,1035,1035,1034,1034,1034,1034,1034,1034,1033,1033,1033,1033,1033,1033,1033,1033,1032,1032,1032,1032,1032,1032,1032,1032,1032,1032,1032,1031,1031,1031,1031,1031,1031,1031,1030,1030,1030,1030,1030,1030,1030,1030,1030,1030,1030,1030,1029,1029,1029,1029,1028,1028,1028,1028,1028,1028,1028,1028,1027,1027,1027,1027,1027,1027,1027,1027,1026,1026,1026,1026,1026,1026,1026,1026,1026,1026,1026,1026,1026,1026,1026,1025,1025,1025,1025,1025,1025,1025,1025,1025,1024,1024,1024,1024,1024,1024,1024,1024,1024,1024,1023,1023,1023,1023,1023,1023,1023,1023,1023,1023,1023,1023,1023,1023,1022,1022,1022,1022,1022,1022,1022,1021,1021,1021,1021,1021,1021,1021,1021,1021,1021,1020,1020,1020,1020,1020,1020,1020,1020,1020,1020,1019,1019,1019,1019,1019,1019,1019,1019,1019,1019,1019,1019,1018,1018,1018,1018,1018,1018,1018,1017,1017,1017,1017,1017,1017,1017,1017,1017,1017,1017,1016,1016,1016,1016,1016,1016,1015,1015,1015,1015,1015,1015,1015,1015,1015,1015,1015,1015,1015,1015,1015,1014,1014,1014,1014,1014,1014,1014,1013,1013,1013,1013,1013,1013,1013,1013,1012,1012,1012,1012,1012,1012,1012,1011,1011,1011,1011,1011,1011,1011,1011,1011,1011,1011,1011,1011,1011,1010,1010,1010,1010,1010,1010,1010,1009,1009,1009,1009,1009,1009,1009,1008,1008,1008,1008,1008,1008,1008,1008,1007,1007,1007,1007,1007,1007,1007,1007,1006,1006,1006,1006,1006,1006,1006,1006,1006,1006,1006,1006,1006,1005,1005,1005,1005,1005,1005,1004,1004,1004,1004,1004,1004,1004,1004,1004,1004,1003,1003,1003,1003,1003,1003,1003,1003,1003,1003,1003,1003,1002,1002,1002,1002,1002,1002,1002,1001,1001,1001,1001,1001,1001,1001,1001,1001,1001,1001,1001,1001,1001,1000,1000,1000,1000,1000,1000,1000,1000,1000,1000,1000,1000,1000,1000,1000,999,999,999,999,999,999,999,999,999,999,999,999,999,998,998,998,998,998,997,997,997,997,997,997,997,997,997,996,996,996,996,996,996,996,996,996,995,995,995,995,995,995,995,995,995,995,994,994,994,994,994,994,994,994,994,994,994,994,994,994,993,993,993,993,993,993,993,993,993,993,993,993,993,993,993,993,992,992,992,992,992,992,992,992,992,992,992,992,992,992,992,992,991,991,991,991,991,991,991,991,991,990,990,990,990,990,990,990,989,989,989,989,989,989,989,989,989,989,989,989,989,988,988,988,988,988,988,988,987,987,987,987,987,987,987,987,987,987,987,987,987,987,986,986,986,986,986,986,986,986,985,985,985,985,985,985,985,985,985,985,985,985,985,985,985,985,985,985,984,984,984,984,984,984,984,984,984,984,984,983,983,983,983,983,983,982,982,982,982,982,982,982,982,982,982,981,981,981,981,981,981,981,980,980,980,980,979,979,979,979,979,979,979,979,979,979,978,978,978,978,978,978,978,978,978,978,978,978,978,978,978,978,978,977,977,977,977,977,977,977,976,976,976,976,976,976,975,975,975,975,975,975,975,975,975,975,975,975,975,975,975,974,974,974,974,974,974,974,974,974,974,974,974,974,974,973,973,973,973,973,973,973,973,973,973,972,972,972,972,972,972,972,972,972,972,972,971,971,971,971,971,971,971,971,971,971,971,971,971,970,970,970,970,970,970,970,970,970,970,970,969,969,969,969,969,969,969,969,969,969,969,969,969,969,968,968,968,968,968,968,968,968,968,968,967,967,967,967,967,967,967,967,967,967,966,966,966,966,966,966,966,966,966,966,966,966,965,965,965,965,965,965,965,965,964,964,964,964,964,964,964,964,964,964,964,964,964,964,963,963,963,963,963,963,963,963,963,963,963,963,962,962,962,962,962,962,962,962,962,962,962,961,961,961,961,961,961,961,961,961,961,961,961,960,960,960,960,960,960,960,960,960,960,959,959,959,959,959,959,959,959,958,958,958,958,957,957,957,957,957,957,957,957,957,957,957,957,957,957,957,957,956,956,956,956,956,956,956,956,955,955,955,955,955,955,955,955,955,955,955,955,955,955,955,955,954,954,954,954,954,954,954,954,954,954,954,953,953,953,953,953,953,953,953,953,953,953,953,953,952,952,952,952,952,952,952,952,952,952,952,951,951,951,951,951,951,951,951,951,951,951,951,950,950,950,950,950,950,950,950,950,950,950,950,950,950,950,949,949,949,949,949,949,949,949,949,949,949,949,948,948,948,948,948,948,948,948,948,948,948,948,948,948,947,947,947,947,947,947,947,947,947,947,947,947,946,946,946,946,946,946,946,946,946,945,945,945,945,945,945,945,945,945,945,945,945,945,944,944,944,944,944,944,944,944,944,944,944,943,943,943,943,943,943,943,943,943,943,943,943,943,943,943,942,942,942,942,942,942,942,941,941,941,941,941,941,941,941,941,941,941,941,941,941,940,940,940,940,940,940,940,940,940,940,940,939,939,939,939,939,939,939,939,939,938,938,938,938,938,938,938,938,938,938,938,938,938,938,938,938,937,937,937,937,937,937,937,936,936,936,936,936,936,936,936,936,936,935,935,935,935,935,935,935,935,935,935,935,935,935,935,935,935,935,934,934,934,934,934,934,934,934,934,933,933,933,933,933,933,933,933,933,933,933,932,932,932,932,932,932,932,932,932,932,932,932,932,932,931,931,931,931,931,931,931,931,931,931,931,931,931,931,931,931,930,930,930,930,930,930,930,930,930,930,930,930,930,930,930,930,930,929,929,929,929,929,929,929,929,929,928,928,928,928,928,928,928,928,928,928,928,928,928,928,928,927,927,927,927,927,927,927,926,926,926,926,926,926,926,926,926,926,925,925,925,925,925,925,925,925,925,925,925,925,925,925,925,924,924,924,924,924,924,924,924,924,924,924,924,923,923,923,923,923,923,923,923,923,922,922,922,922,922,922,922,922,922,922,922,922,922,922,921,921,921,921,921,921,921,921,921,921,921,921,921,921,921,920,920,920,920,920,920,920,919,919,919,919,919,919,919,919,919,919,919,919,919,919,919,919,919,919,919,919,919,919,918,918,918,918,918,918,918,918,918,918,918,918,918,918,918,918,917,917,917,917,917,917,917,917,917,917,917,917,917,917,917,916,916,916,916,916,916,916,916,916,916,916,915,915,915,915,915,915,915,915,915,915,915,914,914,914,914,914,914,914,914,914,913,913,913,913,913,913,913,913,913,913,913,913,913,913,913,913,913,913,912,912,912,912,912,912,912,912,912,911,911,911,911,911,911,911,911,911,911,911,911,911,911,911,911,910,910,910,910,910,910,910,910,910,910,910,910,910,910,909,909,909,909,909,909,909,909,909,909,909,908,908,908,908,908,908,908,908,908,908,908,908,908,907,907,907,907,907,907,907,907,907,907,907,907,907,907,906,906,906,906,906,906,906,906,906,906,906,905,905,905,905,905,905,905,904,904,904,904,904,904,904,904,904,904,904,904,904,903,903,903,903,903,903,902,902,902,902,902,902,902,902,902,902,902,902,902,901,901,901,901,901,901,901,901,901,901,901,900,900,900,900,900,900,900,900,900,900,900,900,899,899,899,899,899,899,899,899,899,899,899,899,899,899,899,899,899,898,898,898,898,898,898,898,898,898,898,898,898,898,898,897,897,897,897,897,897,897,897,897,897,896,896,896,896,896,896,896,896,895,895,895,895,895,895,895,895,895,894,894,894,894,894,894,894,894,894,894,894,894,894,894,893,893,893,893,893,893,893,893,893,893,893,893,893,893,892,892,892,892,892,892,892,892,892,892,892,892,892,892,892,892,891,891,891,891,891,891,891,891,891,891,891,891,890,890,890,890,890,890,890,890,890,890,890,890,890,890,890,890,889,889,889,889,889,889,889,889,888,888,888,888,888,888,888,888,888,888,888,888,888,887,887,887,887,887,887,887,887,887,887,887,887,887,886,886,886,886,886,886,886,886,885,885,885,885,885,885,885,885,885,885,885,885,884,884,884,884,884,884,884,884,884,884,884,884,884,884,883,883,883,883,883,883,883,883,883,883,883,883,883,883,882,882,882,882,882,882,882,882,882,882,882,882,881,881,881,881,881,881,881,881,881,880,880,880,880,880,880,880,880,880,880,880,879,879,879,879,879,879,879,879,879,879,879,878,878,878,878,878,878,878,878,878,878,878,877,877,877,877,877,877,877,877,877,877,877,876,876,876,876,876,876,876,876,876,876,876,876,876,876,876,876,876,875,875,875,875,875,874,874,874,874,874,874,874,874,874,874,874,874,873,873,873,873,873,873,873,873,873,873,873,873,873,873,873,873,872,872,872,872,872,872,872,872,872,872,872,871,871,871,871,871,871,871,871,871,870,870,870,870,870,870,870,870,870,870,870,869,869,869,869,869,869,869,869,869,869,868,868,868,868,868,868,867,867,867,867,867,867,867,867,867,866,866,866,866,866,866,866,866,866,866,866,866,866,866,865,865,865,865,865,865,865,865,865,865,865,865,865,865,865,864,864,864,864,864,864,864,864,864,864,864,864,864,864,863,863,863,863,863,863,863,862,862,862,862,862,862,862,862,862,862,862,862,862,862,862,862,862,862,861,861,861,861,861,861,861,861,861,861,861,861,861,861,861,861,861,860,860,860,860,860,860,860,860,860,860,860,859,859,859,859,859,859,859,859,859,859,859,859,858,858,858,858,858,858,858,858,858,858,858,858,858,858,858,858,858,858,857,857,857,857,857,857,857,857,857,856,856,856,856,856,856,856,856,856,856,856,856,856,856,856,856,855,855,855,855,855,855,855,855,855,855,855,855,854,854,854,854,854,854,854,853,853,853,853,853,853,853,853,853,853,852,852,852,852,852,852,852,852,852,852,851,851,851,851,851,851,851,851,851,851,851,851,851,851,850,850,850,850,850,850,850,850,850,850,850,849,849,849,848,848,848,848,848,848,848,848,848,848,848,847,847,847,847,847,847,847,847,847,847,847,847,846,846,846,846,846,846,846,846,846,846,846,846,846,846,846,845,845,845,845,845,845,845,845,845,845,845,844,844,844,844,844,844,844,844,844,844,844,844,843,843,843,843,843,843,843,843,842,842,842,842,842,842,842,842,841,841,841,841,841,841,841,841,841,841,841,841,840,840,840,840,840,840,840,840,840,840,840,840,840,840,840,840,840,840,839,839,839,839,839,839,839,839,839,839,838,838,838,838,838,838,838,838,838,838,838,837,837,837,837,837,837,837,837,837,837,837,837,837,837,836,836,836,836,836,836,836,836,836,836,836,836,836,836,835,835,835,835,835,835,835,835,835,835,835,834,834,834,834,834,834,834,834,834,834,834,834,834,834,834,834,833,833,833,833,833,833,833,833,833,833,833,833,833,832,832,832,832,832,832,832,832,832,832,832,831,831,831,831,831,831,831,831,831,831,831,831,830,830,830,830,830,830,830,830,830,830,830,830,829,829,829,829,829,829,829,829,829,829,829,829,829,829,829,828,828,828,828,828,828,828,828,828,828,828,828,827,827,827,827,827,827,827,827,827,826,826,826,826,826,826,826,826,826,826,826,826,826,826,826,825,825,825,825,825,825,825,825,825,824,824,824,824,824,824,824,824,824,824,824,824,824,824,824,823,823,823,823,823,823,823,822,822,822,822,822,822,822,822,822,822,822,822,822,822,822,821,821,821,821,821,821,821,821,821,821,821,821,821,821,821,821,821,820,820,820,820,820,820,820,820,820,820,819,819,819,819,819,819,819,819,819,819,819,819,819,819,819,819,819,819,818,818,818,818,818,818,818,818,818,818,818,817,817,817,817,817,817,817,817,817,817,817,817,817,817,817,817,817,816,816,816,816,816,816,816,816,816,816,816,815,815,815,815,815,815,815,815,815,815,815,815,815,815,815,815,815,815,815,815,815,814,814,814,814,814,814,814,814,814,814,814,814,814,814,814,813,813,813,813,813,813,813,813,813,813,813,813,812,812,812,812,812,812,812,812,812,812,812,812,812,812,811,811,811,811,811,811,811,811,810,810,810,810,810,810,810,810,810,810,810,810,810,810,810,810,809,809,809,809,809,809,809,809,809,809,809,809,809,809,809,809,809,809,808,808,808,808,808,808,808,808,808,808,808,808,808,808,808,808,807,807,807,807,807,807,807,807,807,807,807,807,807,807,807,807,807,807,807,807,807,807,806,806,806,806,806,806,806,806,806,806,806,806,806,806,805,805,805,805,805,805,805,805,805,805,805,805,805,805,805,805,805,805,805,805,805,804,804,804,804,804,804,804,804,804,804,804,804,804,803,803,803,803,803,803,803,803,803,803,803,803,803,803,803,803,803,803,803,803,802,802,802,802,802,802,802,802,802,802,802,802,802,802,802,802,802,802,802,801,801,801,801,801,801,801,801,801,801,801,801,801,801,800,800,800,800,800,800,800,800,800,800,800,800,800,800,800,799,799,799,799,799,799,799,799,799,799,799,799,799,799,799,798,798,798,798,798,798,798,798,798,798,798,798,798,798,798,798,798,797,797,797,797,797,797,797,797,797,797,797,797,797,797,797,797,796,796,796,796,796,796,796,796,796,796,796,796,796,796,796,796,796,795,795,795,795,795,795,795,795,795,795,794,794,794,794,794,794,794,794,794,794,794,794,794,794,793,793,793,793,793,793,793,793,793,793,793,793,793,793,793,792,792,792,792,792,792,792,792,792,792,792,792,792,791,791,791,791,791,791,791,791,791,791,791,791,791,791,791,791,791,791,791,790,790,790,790,790,790,790,790,790,790,790,789,789,789,789,789,789,789,789,789,789,789,789,788,788,788,788,788,788,788,788,788,788,788,788,787,787,787,787,787,787,787,787,787,787,787,787,787,787,787,787,787,787,786,786,786,786,786,786,786,786,786,786,786,786,786,786,786,786,786,786,786,785,785,785,785,785,785,785,785,785,785,785,785,785,784,784,784,784,784,784,784,784,784,784,784,784,784,784,784,784,784,784,784,783,783,783,783,783,783,783,783,783,783,783,783,783,783,783,783,783,783,782,782,782,782,782,782,782,782,782,782,782,782,782,781,781,781,781,781,781,781,781,781,780,780,780,780,780,780,780,780,780,780,780,780,779,779,779,779,779,779,779,779,779,779,779,779,779,779,778,778,778,778,778,778,778,778,778,778,778,778,778,778,778,778,778,777,777,777,777,777,777,777,777,777,777,776,776,776,776,776,776,776,776,776,776,776,776,775,775,775,775,775,775,775,774,774,774,774,774,774,774,774,774,774,774,773,773,773,773,773,773,773,773,773,773,773,773,773,773,773,773,773,772,772,772,772,772,772,772,772,772,772,772,772,772,772,772,771,771,771,771,771,771,771,771,771,771,771,771,770,770,770,770,770,770,770,770,770,770,769,769,769,769,769,769,769,769,769,769,769,769,769,768,768,768,768,768,768,768,768,768,767,767,767,767,767,767,767,767,767,767,766,766,766,766,766,766,766,766,766,766,766,765,765,765,765,765,765,765,765,765,765,765,765,765,765,765,765,765,765,765,765,764,764,764,764,764,764,764,764,764,764,764,764,764,764,764,764,764,764,764,763,763,763,763,763,763,763,763,763,763,763,763,763,763,763,763,763,762,762,762,762,762,762,762,762,762,762,762,762,762,762,762,761,761,761,761,761,761,761,761,761,761,760,760,760,760,760,760,760,760,760,760,760,760,760,760,760,760,759,759,759,759,759,759,759,759,759,759,759,759,758,758,758,758,758,758,758,757,757,757,757,757,757,757,757,757,757,757,757,757,757,757,756,756,756,756,756,756,756,756,756,756,756,756,756,756,755,755,755,755,755,755,755,755,755,755,755,755,755,755,755,755,755,754,754,754,754,754,754,754,754,754,754,754,754,754,753,753,753,753,753,753,753,753,753,753,753,753,753,752,752,752,752,752,752,752,752,752,752,752,752,752,752,752,752,752,752,751,751,751,751,751,751,751,751,751,751,751,751,751,751,751,750,750,750,750,750,750,750,750,750,750,750,750,750,750,750,750,750,750,750,750,750,749,749,749,749,749,749,749,749,749,749,749,749,749,749,749,749,749,749,749,749,749,749,749,749,748,748,748,748,748,748,748,748,748,748,748,747,747,747,747,747,747,747,747,747,747,747,747,747,747,747,746,746,746,746,746,746,746,746,746,746,746,746,746,746,746,745,745,745,745,745,745,745,745,745,745,745,745,745,745,745,745,745,745,745,745,744,744,744,744,744,744,744,744,744,744,744,744,744,743,743,743,743,743,743,743,743,743,743,742,742,742,742,742,742,742,742,742,742,742,742,742,742,742,742,742,742,741,741,741,741,741,741,741,741,741,741,741,741,741,741,741,741,741,741,741,740,740,740,740,740,740,740,740,740,740,740,740,740,740,740,740,740,739,739,739,739,739,739,739,739,739,739,739,739,739,739,739,738,738,738,738,738,738,738,738,738,738,738,738,738,738,738,738,737,737,737,737,737,737,737,737,737,737,737,737,737,737,737,737,737,736,736,736,736,736,736,736,736,736,736,736,736,736,736,735,735,735,735,735,735,735,735,735,735,735,735,735,735,735,734,734,734,734,734,734,734,734,734,734,734,734,734,734,734,734,734,734,733,733,733,733,733,733,733,733,733,733,733,733,733,733,733,732,732,732,732,732,732,732,732,732,732,732,732,732,732,731,731,731,731,731,731,731,731,731,731,731,731,731,731,731,731,730,730,730,730,730,730,730,730,730,730,730,730,730,730,729,729,729,729,729,729,729,729,729,729,729,729,729,729,729,729,729,728,728,728,728,728,728,728,728,727,727,727,727,727,727,727,727,727,727,727,727,727,726,726,726,726,726,726,726,726,726,726,726,726,726,726,726,725,725,725,725,725,725,725,725,725,725,725,725,725,725,725,725,725,725,725,725,725,725,725,725,724,724,724,724,724,724,724,724,724,724,724,724,724,724,724,724,724,723,723,723,723,723,723,723,723,723,723,723,723,723,723,723,723,723,723,723,723,723,723,723,722,722,722,722,722,722,722,722,722,722,721,721,721,721,721,721,721,721,721,721,721,721,721,721,721,721,721,721,720,720,720,720,720,720,720,720,720,720,720,720,720,719,719,719,719,719,719,719,719,719,719,719,719,719,719,719,719,718,718,718,718,718,718,718,718,718,718,718,718,718,718,717,717,717,717,717,717,717,717,717,717,717,717,717,717,717,717,717,716,716,716,716,716,716,716,716,716,716,716,716,716,716,716,716,716,716,716,715,715,715,715,715,715,715,715,715,715,715,715,715,715,715,715,715,715,715,714,714,714,714,714,714,714,714,714,714,714,714,714,714,714,714,713,713,713,713,713,713,713,713,713,713,713,713,713,713,713,713,713,713,713,712,712,712,712,712,712,712,712,712,712,712,712,712,712,712,712,712,711,711,711,711,711,711,711,711,711,711,711,711,711,711,711,710,710,710,710,710,710,710,710,710,710,710,710,710,710,710,710,710,710,710,710,710,709,709,709,709,709,709,709,709,709,709,709,708,708,708,708,708,708,708,708,708,708,708,708,708,708,708,708,708,708,708,708,708,708,708,708,708,708,708,708,708,707,707,707,707,707,707,707,707,707,707,707,707,707,707,707,707,707,707,707,706,706,706,706,706,706,706,706,706,706,706,705,705,705,705,705,705,705,705,705,705,705,705,704,704,704,704,704,704,704,704,704,704,704,704,704,704,704,704,704,704,704,703,703,703,703,703,703,703,703,703,703,703,703,702,702,702,702,702,702,702,702,702,702,702,702,702,702,702,701,701,701,701,701,701,701,701,701,701,701,701,701,701,701,701,701,701,701,701,701,701,700,700,700,700,700,700,700,700,700,700,700,700,700,700,700,700,700,700,700,700,700,699,699,699,699,699,699,699,699,699,699,699,699,699,699,699,699,698,698,698,698,698,698,698,698,698,698,698,698,698,697,697,697,697,697,697,697,697,697,697,697,697,697,697,697,697,697,697,697,697,696,696,696,696,696,696,696,696,696,696,696,696,696,696,696,696,696,696,696,696,695,695,695,695,695,695,695,695,695,695,695,695,694,694,694,694,694,694,694,694,694,694,694,694,694,694,694,693,693,693,693,693,693,693,693,693,693,693,693,693,693,693,693,693,693,693,693,693,693,693,693,692,692,692,692,692,692,692,692,692,692,692,692,692,692,692,692,692,692,692,692,692,692,692,692,691,691,691,691,691,691,691,691,691,691,691,691,691,691,691,691,691,691,691,691,690,690,690,690,690,690,690,690,690,690,690,690,690,690,690,690,689,689,689,689,689,689,689,689,689,689,689,689,689,689,689,689,689,689,689,689,689,689,689,689,689,688,688,688,688,688,688,688,688,688,688,688,688,688,688,688,688,688,688,688,687,687,687,687,687,687,687,687,687,687,687,687,686,686,686,686,686,686,686,686,686,686,686,686,686,686,686,686,685,685,685,685,685,685,685,685,685,685,685,685,685,685,685,685,685,684,684,684,684,684,684,684,684,684,684,684,684,684,684,683,683,683,683,683,683,683,683,683,683,683,683,683,683,683,683,683,682,682,682,682,682,682,682,682,682,682,682,682,682,682,682,682,682,682,681,681,681,681,681,681,681,681,681,681,681,681,681,681,681,681,681,681,680,680,680,680,680,680,680,680,680,680,680,680,680,680,680,680,680,679,679,679,679,679,679,679,679,679,679,679,679,679,679,679,679,679,679,679,679,679,679,678,678,678,678,678,678,678,678,678,678,678,678,678,678,678,677,677,677,677,677,677,677,677,677,676,676,676,676,676,676,676,676,676,676,676,676,676,676,676,676,676,676,676,676,675,675,675,675,675,675,675,675,675,675,675,675,675,675,674,674,674,674,674,674,674,674,674,674,674,674,674,674,674,674,674,674,674,674,674,674,674,673,673,673,673,673,673,673,673,673,673,673,673,673,673,673,673,672,672,672,672,672,672,672,672,672,672,672,672,672,672,672,672,672,671,671,671,671,671,671,671,671,671,671,671,671,671,671,671,671,671,671,671,671,671,670,670,670,670,670,670,670,670,670,670,670,670,670,670,670,670,670,670,670,669,669,669,669,669,669,669,669,669,669,669,669,669,669,669,669,669,669,669,669,669,669,668,668,668,668,668,668,668,668,668,668,668,668,668,668,668,668,668,668,668,668,667,667,667,667,667,667,667,667,667,667,667,667,667,667,667,667,667,667,667,667,667,667,667,667,667,667,667,666,666,666,666,666,666,666,666,666,666,666,666,666,666,666,666,666,665,665,665,665,665,665,665,665,665,665,665,665,665,665,665,665,665,665,665,664,664,664,664,664,664,664,664,664,664,664,664,664,664,664,664,663,663,663,663,663,663,663,663,663,663,663,662,662,662,662,662,662,662,662,662,662,662,662,662,662,662,662,662,661,661,661,661,661,661,661,661,661,661,661,661,661,661,661,661,661,661,661,661,661,661,660,660,660,660,660,660,660,660,660,660,660,660,660,660,660,660,660,660,660,660,660,660,659,659,659,659,659,659,659,659,659,659,659,659,659,659,658,658,658,658,658,658,658,658,658,658,658,658,658,658,658,658,658,658,657,657,657,657,657,657,657,657,657,657,657,657,657,657,657,657,657,657,657,657,657,656,656,656,656,656,656,656,656,656,656,656,656,656,656,656,656,656,656,656,656,656,656,656,655,655,655,655,655,655,655,655,655,655,655,655,655,655,655,655,655,655,654,654,654,654,654,654,654,654,654,654,654,654,654,653,653,653,653,653,653,653,653,653,653,653,653,653,653,653,653,653,653,653,653,653,652,652,652,652,652,652,652,652,652,652,652,652,652,652,652,652,651,651,651,651,651,651,651,651,651,651,651,651,651,651,651,651,651,650,650,650,650,650,650,650,650,650,650,650,650,649,649,649,649,649,649,649,649,649,649,649,649,649,649,649,649,649,648,648,648,648,648,648,648,648,648,648,648,648,648,648,648,648,648,648,648,648,648,648,647,647,647,647,647,647,647,647,647,647,647,647,647,647,647,647,647,647,647,647,646,646,646,646,646,646,646,646,646,646,646,646,646,646,646,646,646,646,646,646,645,645,645,645,645,645,645,645,645,645,645,645,645,645,645,645,645,645,644,644,644,644,644,644,644,644,644,644,644,644,644,644,644,644,644,643,643,643,643,643,643,643,643,643,643,643,643,643,643,643,643,643,643,643,642,642,642,642,642,642,642,642,642,642,642,642,642,642,642,642,642,642,641,641,641,641,641,641,641,641,641,641,641,641,641,641,641,641,641,641,641,641,641,641,641,641,640,640,640,640,640,640,640,640,640,640,640,640,640,640,640,640,640,639,639,639,639,639,639,639,639,639,639,639,639,639,639,639,639,639,639,639,639,639,639,638,638,638,638,638,638,638,638,638,638,638,638,638,638,638,638,638,638,638,638,638,638,638,638,638,638,638,638,638,638,637,637,637,637,637,637,637,637,637,637,637,637,637,637,637,637,636,636,636,636,636,636,636,636,636,636,636,636,636,636,636,636,636,636,636,636,636,636,636,636,636,636,636,635,635,635,635,635,635,635,635,635,635,635,635,635,635,635,635,635,635,635,634,634,634,634,634,634,634,634,634,634,634,634,634,634,634,634,634,634,634,634,634,634,634,633,633,633,633,633,633,633,633,633,633,633,633,633,633,633,633,633,633,633,633,633,633,633,632,632,632,632,632,632,632,632,632,632,632,632,632,632,632,632,631,631,631,631,631,631,631,631,631,631,631,631,631,631,631,631,631,631,631,630,630,630,630,630,630,630,630,630,630,630,630,630,630,630,630,630,629,629,629,629,629,629,629,629,629,629,629,629,629,629,629,629,629,629,629,629,629,629,629,629,628,628,628,628,628,628,628,628,628,628,628,628,628,628,628,628,628,628,628,628,628,628,628,628,627,627,627,627,627,627,627,627,627,627,627,627,627,626,626,626,626,626,626,626,626,626,626,626,626,626,626,626,626,626,626,626,626,626,626,626,626,625,625,625,625,625,625,625,625,625,625,625,625,625,625,625,625,625,625,624,624,624,624,624,624,624,624,624,624,624,624,624,624,624,624,624,624,624,624,623,623,623,623,623,623,623,623,623,623,623,623,623,623,623,623,623,623,623,623,623,623,623,623,623,623,623,623,623,623,623,622,622,622,622,622,622,622,622,622,622,622,622,622,622,622,621,621,621,621,621,621,621,621,621,621,621,621,621,621,621,621,621,621,621,621,621,620,620,620,620,620,620,620,620,620,620,620,620,620,620,620,620,620,620,620,620,620,619,619,619,619,619,619,619,619,619,619,619,619,619,619,619,619,619,619,619,619,618,618,618,618,618,618,618,618,618,618,618,618,618,618,618,618,618,618,618,618,618,618,617,617,617,617,617,617,617,617,617,617,617,617,617,617,617,617,617,617,617,617,617,617,617,617,617,616,616,616,616,616,616,616,616,616,616,616,616,616,616,616,616,616,616,616,616,616,616,615,615,615,615,615,615,615,615,615,615,615,615,615,614,614,614,614,614,614,614,614,614,614,614,613,613,613,613,613,613,613,613,613,613,613,613,613,613,613,613,613,612,612,612,612,612,612,612,612,612,612,612,612,612,612,612,612,612,611,611,611,611,611,611,611,611,611,611,611,611,611,611,611,611,611,611,611,611,611,611,611,611,611,611,611,611,610,610,610,610,610,610,610,610,610,610,610,610,610,610,610,610,610,610,610,609,609,609,609,609,609,609,609,609,609,609,609,609,609,609,609,609,609,609,609,609,609,609,609,609,609,608,608,608,608,608,608,608,608,608,608,608,608,608,608,608,608,607,607,607,607,607,607,607,607,607,607,607,607,607,607,607,607,607,607,607,607,607,607,607,607,607,607,607,607,607,606,606,606,606,606,606,606,606,606,606,606,606,606,606,606,606,606,606,605,605,605,605,605,605,605,605,605,605,605,605,605,605,605,605,605,605,605,605,605,605,605,604,604,604,604,604,604,604,604,604,604,604,604,604,604,604,604,604,604,604,604,604,604,604,603,603,603,603,603,603,603,603,603,603,603,603,603,603,603,603,603,603,603,603,603,603,603,603,603,603,603,603,603,603,603,603,602,602,602,602,602,602,602,602,602,602,602,602,602,602,602,602,602,602,601,601,601,601,601,601,601,601,601,601,601,601,601,601,601,601,601,601,601,601,601,601,601,601,600,600,600,600,600,600,600,600,600,600,600,600,600,600,600,600,600,600,600,599,599,599,599,599,599,599,599,599,599,599,599,599,599,599,599,599,599,599,599,599,599,599,598,598,598,598,598,598,598,598,598,598,598,598,598,598,598,598,598,598,598,598,598,597,597,597,597,597,597,597,597,597,597,597,597,597,597,597,597,597,597,597,597,597,597,597,597,597,597,597,596,596,596,596,596,596,596,596,596,596,596,596,596,596,596,596,596,596,596,596,596,596,596,595,595,595,595,595,595,595,595,595,595,595,595,595,595,595,595,595,595,595,595,595,594,594,594,594,594,594,594,594,594,594,594,594,594,594,594,594,594,594,594,594,594,594,594,594,593,593,593,593,593,593,593,593,593,593,593,593,593,593,593,593,593,593,593,593,593,593,593,593,593,593,593,593,593,593,593,592,592,592,592,592,592,592,592,592,592,592,592,592,592,592,592,592,592,592,591,591,591,591,591,591,591,591,591,591,591,591,591,591,591,591,591,591,591,591,591,591,591,590,590,590,590,590,590,590,590,590,590,590,590,590,590,590,590,589,589,589,589,589,589,589,589,589,589,589,589,589,589,589,589,589,589,589,589,589,589,589,589,589,589,589,589,589,589,589,589,588,588,588,588,588,588,588,588,588,588,588,588,588,588,588,588,588,588,588,588,588,588,588,588,588,588,588,587,587,587,587,587,587,587,587,587,587,587,587,587,587,587,587,587,587,587,587,587,587,587,587,587,587,587,587,586,586,586,586,586,586,586,586,586,586,586,586,586,586,586,586,586,586,586,586,586,586,586,586,586,586,585,585,585,585,585,585,585,585,585,585,585,585,585,585,585,585,585,585,585,585,585,585,585,585,585,585,584,584,584,584,584,584,584,584,584,584,584,584,584,584,584,584,584,584,584,584,584,584,584,584,584,584,584,584,583,583,583,583,583,583,583,583,583,583,583,583,583,583,583,583,583,583,583,583,583,583,582,582,582,582,582,582,582,582,582,582,582,582,582,582,582,581,581,581,581,581,581,581,581,581,581,581,581,581,581,581,580,580,580,580,580,580,580,580,580,580,580,580,580,580,580,580,580,580,580,580,580,580,580,580,580,580,580,580,580,580,580,580,580,580,579,579,579,579,579,579,579,579,579,579,579,579,579,579,579,579,579,579,579,579,578,578,578,578,578,578,578,578,578,578,578,578,578,578,578,578,578,578,578,578,578,578,577,577,577,577,577,577,577,577,577,577,577,577,577,577,577,577,577,577,577,577,577,577,577,577,577,577,577,577,577,577,577,576,576,576,576,576,576,576,576,576,576,576,576,576,576,576,576,576,576,576,576,575,575,575,575,575,575,575,575,575,575,575,575,575,575,575,575,575,575,575,575,575,574,574,574,574,574,574,574,574,574,574,574,574,574,574,574,574,574,574,574,574,574,573,573,573,573,573,573,573,573,573,573,573,573,573,573,573,573,573,573,573,573,573,573,573,573,573,572,572,572,572,572,572,572,572,572,572,572,572,572,572,572,572,572,572,572,572,572,572,572,572,572,572,571,571,571,571,571,571,571,571,571,571,571,571,571,571,571,571,571,571,571,571,571,570,570,570,570,570,570,570,570,570,570,570,570,570,570,570,570,570,570,570,570,570,570,570,570,569,569,569,569,569,569,569,569,569,569,569,569,569,569,569,569,569,569,569,569,569,569,569,569,569,568,568,568,568,568,568,568,568,568,568,568,568,568,568,568,568,568,568,568,568,567,567,567,567,567,567,567,567,567,567,567,567,567,567,567,567,567,567,567,567,567,567,567,567,567,567,567,567,567,567,567,567,566,566,566,566,566,566,566,566,566,566,566,566,566,566,566,566,566,566,566,566,566,566,566,566,566,566,566,566,566,566,566,566,566,566,565,565,565,565,565,565,565,565,565,565,565,565,565,565,565,565,565,565,565,564,564,564,564,564,564,564,564,564,564,564,564,564,564,564,564,564,564,564,564,564,564,564,564,564,564,564,564,564,564,564,564,564,563,563,563,563,563,563,563,563,563,563,563,563,563,563,563,563,562,562,562,562,562,562,562,562,562,562,562,562,562,562,562,562,561,561,561,561,561,561,561,561,561,561,561,561,561,561,561,561,561,561,561,561,561,561,561,561,561,560,560,560,560,560,560,560,560,560,560,560,560,560,560,560,560,559,559,559,559,559,559,559,559,559,559,559,559,559,559,559,559,559,559,559,559,559,559,559,559,559,559,558,558,558,558,558,558,558,558,558,558,558,558,558,558,558,558,558,558,558,558,558,558,558,558,558,557,557,557,557,557,557,557,557,557,557,557,557,557,557,557,557,557,557,557,557,557,557,557,557,557,556,556,556,556,556,556,556,556,556,556,556,556,556,556,556,556,556,555,555,555,555,555,555,555,555,555,555,555,555,555,555,555,555,555,555,555,555,555,555,555,555,555,555,555,555,555,555,555,555,554,554,554,554,554,554,554,554,554,554,554,554,554,554,554,554,554,554,554,554,554,554,554,554,554,554,554,553,553,553,553,553,553,553,553,553,553,553,553,553,553,553,553,553,553,553,553,553,553,553,553,552,552,552,552,552,552,552,552,552,552,552,552,552,552,552,552,552,552,552,552,552,552,552,552,552,552,552,552,551,551,551,551,551,551,551,551,551,551,551,551,551,551,551,551,551,551,551,551,551,551,551,551,551,551,551,550,550,550,550,550,550,550,550,550,550,550,550,550,550,550,550,550,550,550,550,550,550,550,549,549,549,549,549,549,549,549,549,549,549,549,549,549,549,549,549,549,549,549,548,548,548,548,548,548,548,548,548,548,548,548,548,548,548,548,548,548,548,548,547,547,547,547,547,547,547,547,547,547,547,547,547,547,547,547,547,547,547,547,547,547,547,546,546,546,546,546,546,546,546,546,546,546,546,546,546,546,546,546,546,546,546,546,546,546,545,545,545,545,545,545,545,545,545,545,545,545,545,545,545,545,545,545,545,545,545,545,545,545,545,545,545,545,545,545,544,544,544,544,544,544,544,544,544,544,544,544,544,544,544,544,544,544,544,544,544,544,544,544,544,544,544,544,544,544,544,544,544,544,544,543,543,543,543,543,543,543,543,543,543,543,543,543,543,543,543,543,543,543,543,543,543,543,543,542,542,542,542,542,542,542,542,542,542,542,542,542,542,542,542,542,542,542,542,542,542,542,542,542,542,542,542,542,542,542,541,541,541,541,541,541,541,541,541,541,541,541,541,541,541,541,541,541,540,540,540,540,540,540,540,540,540,540,540,540,540,540,540,540,540,540,540,540,540,540,540,540,540,540,540,540,540,539,539,539,539,539,539,539,539,539,539,539,539,539,539,539,539,539,539,539,539,539,539,539,539,539,539,539,539,539,539,539,539,539,539,539,539,539,539,538,538,538,538,538,538,538,538,538,538,538,538,538,538,538,538,538,538,538,538,538,538,538,538,538,538,538,538,538,538,537,537,537,537,537,537,537,537,537,537,537,537,537,537,537,537,537,536,536,536,536,536,536,536,536,536,536,536,536,536,536,536,536,536,536,535,535,535,535,535,535,535,535,535,535,535,535,535,535,535,535,535,535,535,535,535,535,534,534,534,534,534,534,534,534,534,534,534,534,534,534,534,534,534,534,534,534,534,534,534,534,534,534,534,534,534,533,533,533,533,533,533,533,533,533,533,533,533,533,533,533,533,533,533,533,533,532,532,532,532,532,532,532,532,532,532,532,532,532,532,532,532,532,532,532,532,532,532,532,532,532,532,532,532,532,532,532,531,531,531,531,531,531,531,531,531,531,531,531,531,531,531,531,531,531,531,531,531,531,531,531,531,531,531,531,530,530,530,530,530,530,530,530,530,530,530,530,530,530,530,530,530,530,530,530,530,530,530,530,530,530,530,530,530,530,530,530,529,529,529,529,529,529,529,529,529,529,529,529,529,529,529,529,529,529,529,529,529,529,529,529,529,529,529,529,529,529,529,528,528,528,528,528,528,528,528,528,528,528,528,528,528,528,528,528,528,528,528,528,528,528,528,528,528,528,528,528,528,528,528,528,528,528,528,528,528,528,528,527,527,527,527,527,527,527,527,527,527,527,527,527,527,527,527,527,527,527,527,527,527,527,526,526,526,526,526,526,526,526,526,526,526,526,526,526,526,526,526,526,526,526,526,526,526,526,526,526,526,526,526,525,525,525,525,525,525,525,525,525,525,525,525,525,525,525,525,525,525,525,525,525,525,525,525,525,525,525,525,525,525,524,524,524,524,524,524,524,524,524,524,524,524,524,524,524,524,524,524,524,524,524,524,524,523,523,523,523,523,523,523,523,523,523,523,523,523,523,523,523,523,523,523,523,523,523,523,523,523,523,522,522,522,522,522,522,522,522,522,522,522,522,522,522,522,522,522,522,522,522,522,522,522,522,522,522,521,521,521,521,521,521,521,521,521,521,521,521,521,521,521,521,521,521,521,521,521,521,521,521,521,521,521,521,521,521,521,520,520,520,520,520,520,520,520,520,520,520,520,520,520,520,520,520,520,520,520,520,520,520,520,520,520,520,520,520,520,519,519,519,519,519,519,519,519,519,519,519,519,519,519,519,519,519,519,519,519,519,519,519,519,519,519,518,518,518,518,518,518,518,518,518,518,518,518,518,518,518,518,518,518,518,518,518,518,518,518,518,518,518,518,518,517,517,517,517,517,517,517,517,517,517,517,517,517,517,517,517,517,517,517,517,517,517,517,517,517,517,517,517,517,517,516,516,516,516,516,516,516,516,516,516,516,516,516,516,516,516,516,516,516,516,516,516,515,515,515,515,515,515,515,515,515,515,515,515,515,515,515,515,515,515,515,515,515,515,515,515,515,515,515,515,514,514,514,514,514,514,514,514,514,514,514,514,514,514,514,514,514,514,514,514,514,514,513,513,513,513,513,513,513,513,513,513,513,513,513,513,513,513,513,513,513,513,513,513,513,513,513,513,512,512,512,512,512,512,512,512,512,512,512,512,512,512,512,512,512,512,512,512,512,512,512,512,512,512,511,511,511,511,511,511,511,511,511,511,511,511,511,511,511,511,511,511,511,511,511,511,511,511,511,511,510,510,510,510,510,510,510,510,510,510,510,510,510,510,510,510,510,510,510,510,510,509,509,509,509,509,509,509,509,509,509,509,509,509,509,509,509,509,509,509,509,509,509,509,509,509,509,509,508,508,508,508,508,508,508,508,508,508,508,508,508,508,508,508,508,508,508,508,508,508,508,508,508,508,508,507,507,507,507,507,507,507,507,507,507,507,507,507,507,507,507,507,507,507,507,507,507,507,507,506,506,506,506,506,506,506,506,506,506,506,506,506,506,506,506,506,506,506,506,506,506,505,505,505,505,505,505,505,505,505,505,505,505,505,505,505,505,505,505,505,505,505,505,505,505,505,505,505,505,505,504,504,504,504,504,504,504,504,504,504,504,504,504,504,504,504,504,504,504,504,503,503,503,503,503,503,503,503,503,503,503,503,503,503,503,503,503,503,503,503,503,503,503,503,503,503,503,503,503,503,503,503,502,502,502,502,502,502,502,502,502,502,502,502,502,502,502,502,502,502,502,502,502,502,502,502,502,502,502,502,502,501,501,501,501,501,501,501,501,501,501,501,501,501,501,501,501,501,501,501,501,501,501,501,501,501,501,500,500,500,500,500,500,500,500,500,500,500,500,500,500,500,500,500,500,500,500,500,500,500,500,500,499,499,499,499,499,499,499,499,499,499,499,499,499,499,499,499,499,499,499,499,499,499,499,499,499,499,499,499,499,499,499,499,499,498,498,498,498,498,498,498,498,498,498,498,498,498,498,498,498,498,498,498,498,498,498,498,498,498,497,497,497,497,497,497,497,497,497,497,497,497,497,497,497,497,497,497,497,497,497,497,497,497,496,496,496,496,496,496,496,496,496,496,496,496,496,496,496,496,496,496,496,496,496,496,496,496,496,496,496,496,496,496,496,496,495,495,495,495,495,495,495,495,495,495,495,495,495,495,495,495,495,495,495,495,495,495,495,495,495,495,495,495,495,495,495,495,495,494,494,494,494,494,494,494,494,494,494,494,494,494,494,494,494,494,494,494,494,494,494,494,494,494,494,494,494,494,494,494,494,494,494,493,493,493,493,493,493,493,493,493,493,493,493,493,493,493,493,493,493,493,493,493,493,493,493,493,493,493,493,493,493,493,493,493,493,492,492,492,492,492,492,492,492,492,492,492,492,492,492,492,492,492,492,492,492,492,492,492,492,492,492,492,492,492,492,492,492,492,492,492,492,492,492,492,492,491,491,491,491,491,491,491,491,491,491,491,491,491,491,491,491,491,491,491,491,491,491,491,491,491,491,491,491,491,491,491,491,490,490,490,490,490,490,490,490,490,490,490,490,490,490,490,490,490,490,490,490,490,490,490,490,490,490,490,490,490,490,490,489,489,489,489,489,489,489,489,489,489,489,489,489,489,489,489,489,489,489,489,489,489,489,489,489,489,488,488,488,488,488,488,488,488,488,488,488,488,488,488,488,488,488,488,488,488,488,488,488,488,488,488,488,488,488,488,488,488,488,487,487,487,487,487,487,487,487,487,487,487,487,487,487,487,487,487,487,487,487,487,487,487,487,487,487,487,487,487,487,486,486,486,486,486,486,486,486,486,486,486,486,486,486,486,486,486,486,486,486,486,486,486,486,486,486,486,486,486,485,485,485,485,485,485,485,485,485,485,485,485,485,485,485,485,485,485,485,485,485,485,485,485,485,485,485,485,485,484,484,484,484,484,484,484,484,484,484,484,484,484,484,484,484,484,484,484,484,484,484,484,484,484,484,483,483,483,483,483,483,483,483,483,483,483,483,483,483,483,483,483,483,483,483,483,483,483,483,483,483,483,483,483,483,483,483,483,483,483,483,482,482,482,482,482,482,482,482,482,482,482,482,482,482,482,482,482,482,482,482,482,482,482,482,482,482,482,482,482,482,481,481,481,481,481,481,481,481,481,481,481,481,481,481,481,481,481,481,481,481,481,481,481,481,481,481,481,481,481,480,480,480,480,480,480,480,480,480,480,480,480,480,480,480,480,480,480,480,480,480,480,480,480,479,479,479,479,479,479,479,479,479,479,479,479,479,479,479,479,479,479,479,479,479,479,479,479,479,479,479,479,478,478,478,478,478,478,478,478,478,478,478,478,478,478,478,478,478,478,478,478,478,478,478,478,478,478,478,478,478,478,478,478,478,478,478,478,478,478,478,478,478,477,477,477,477,477,477,477,477,477,477,477,477,477,477,477,477,477,477,477,477,477,477,477,477,477,477,477,477,477,477,477,477,477,477,477,477,477,477,477,477,477,477,477,476,476,476,476,476,476,476,476,476,476,476,476,476,476,476,476,476,476,476,476,476,476,476,476,476,476,476,476,475,475,475,475,475,475,475,475,475,475,475,475,475,475,475,475,475,475,475,475,475,475,475,475,475,475,475,475,475,475,475,475,475,475,475,474,474,474,474,474,474,474,474,474,474,474,474,474,474,474,474,474,474,474,474,474,474,474,474,474,473,473,473,473,473,473,473,473,473,473,473,473,473,473,473,473,473,473,473,473,473,473,473,473,473,473,473,473,473,473,473,473,473,473,473,473,473,473,473,473,472,472,472,472,472,472,472,472,472,472,472,472,472,472,472,472,472,472,472,472,472,472,472,472,472,472,472,472,472,471,471,471,471,471,471,471,471,471,471,471,471,471,471,471,471,471,471,471,471,471,471,471,471,471,471,471,471,471,471,471,471,471,470,470,470,470,470,470,470,470,470,470,470,470,470,470,470,470,470,469,469,469,469,469,469,469,469,469,469,469,469,469,469,469,469,469,469,469,469,468,468,468,468,468,468,468,468,468,468,468,468,468,468,468,468,468,468,468,468,468,468,468,468,468,468,468,468,468,468,468,468,468,468,467,467,467,467,467,467,467,467,467,467,467,467,467,467,467,467,467,467,467,467,467,467,467,467,467,467,467,467,466,466,466,466,466,466,466,466,466,466,466,466,466,466,466,466,466,466,466,466,466,466,466,466,466,466,466,466,466,466,465,465,465,465,465,465,465,465,465,465,465,465,465,465,465,465,465,465,465,465,465,465,465,465,465,465,465,465,465,465,465,465,465,465,465,465,464,464,464,464,464,464,464,464,464,464,464,464,464,464,464,464,464,464,464,464,464,464,464,464,464,464,464,464,464,464,463,463,463,463,463,463,463,463,463,463,463,463,463,463,463,463,463,463,463,463,463,463,463,463,463,463,463,463,463,463,463,463,463,463,463,463,463,463,463,463,462,462,462,462,462,462,462,462,462,462,462,462,462,462,462,462,462,462,462,462,462,462,462,462,462,462,462,462,462,462,462,462,462,462,462,462,462,462,461,461,461,461,461,461,461,461,461,461,461,461,461,461,461,461,461,461,461,461,461,461,461,461,461,461,461,461,461,461,461,460,460,460,460,460,460,460,460,460,460,460,460,460,460,460,460,460,460,460,460,460,460,460,460,460,460,460,460,460,460,460,460,460,460,460,460,460,459,459,459,459,459,459,459,459,459,459,459,459,459,459,459,459,459,459,459,459,459,459,459,459,459,459,459,459,459,459,459,458,458,458,458,458,458,458,458,458,458,458,458,458,458,458,458,458,458,458,458,458,458,457,457,457,457,457,457,457,457,457,457,457,457,457,457,457,457,457,457,457,457,457,457,457,457,456,456,456,456,456,456,456,456,456,456,456,456,456,456,456,456,456,456,456,456,456,456,456,456,456,456,456,456,456,456,456,456,455,455,455,455,455,455,455,455,455,455,455,455,455,455,455,455,455,455,455,455,455,455,455,455,455,455,455,455,455,455,455,455,455,455,455,455,454,454,454,454,454,454,454,454,454,454,454,454,454,454,454,454,454,454,454,454,454,454,454,454,454,454,454,454,454,453,453,453,453,453,453,453,453,453,453,453,453,453,453,453,453,453,453,453,453,453,453,453,453,453,453,453,453,453,453,453,453,453,452,452,452,452,452,452,452,452,452,452,452,452,452,452,452,452,452,452,452,452,452,452,452,452,452,452,452,452,452,452,452,452,452,452,452,452,452,452,451,451,451,451,451,451,451,451,451,451,451,451,451,451,451,451,451,451,451,451,451,451,451,451,451,451,451,451,451,451,451,451,451,451,451,451,451,451,451,451,451,450,450,450,450,450,450,450,450,450,450,450,450,450,450,450,450,450,450,450,450,450,450,450,450,450,450,450,450,450,450,450,450,450,450,450,450,450,450,450,450,450,450,450,450,450,450,450,450,450,449,449,449,449,449,449,449,449,449,449,449,449,449,449,449,449,449,449,449,449,449,449,449,449,449,449,449,449,449,449,448,448,448,448,448,448,448,448,448,448,448,448,448,448,448,448,448,448,448,448,448,448,448,448,448,448,448,448,447,447,447,447,447,447,447,447,447,447,447,447,447,447,447,447,447,447,447,447,447,447,447,447,447,447,447,447,447,447,446,446,446,446,446,446,446,446,446,446,446,446,446,446,446,446,446,446,446,446,446,446,446,446,446,446,446,445,445,445,445,445,445,445,445,445,445,445,445,445,445,445,445,445,445,445,445,445,445,445,445,445,445,445,445,445,445,445,445,445,445,444,444,444,444,444,444,444,444,444,444,444,444,444,444,444,444,444,444,444,444,444,444,444,444,444,444,444,444,444,444,444,444,444,444,444,443,443,443,443,443,443,443,443,443,443,443,443,443,443,443,443,443,443,443,443,443,443,443,443,443,443,443,443,443,443,443,443,443,443,443,443,442,442,442,442,442,442,442,442,442,442,442,442,442,442,442,442,442,442,442,442,442,442,442,442,442,442,442,442,442,442,442,442,442,442,442,441,441,441,441,441,441,441,441,441,441,441,441,441,441,441,441,441,441,441,441,441,441,441,441,441,441,441,441,441,441,441,441,441,441,441,441,441,440,440,440,440,440,440,440,440,440,440,440,440,440,440,440,440,440,440,440,440,440,440,440,440,439,439,439,439,439,439,439,439,439,439,439,439,439,439,439,439,439,439,439,439,439,439,439,439,439,439,439,439,439,439,439,439,439,439,439,439,438,438,438,438,438,438,438,438,438,438,438,438,438,438,438,438,438,438,438,438,438,438,438,438,438,438,438,438,438,438,438,438,438,438,437,437,437,437,437,437,437,437,437,437,437,437,437,437,437,437,437,437,437,437,437,437,436,436,436,436,436,436,436,436,436,436,436,436,436,436,436,436,436,436,436,436,436,436,436,436,436,436,436,436,436,436,436,436,436,436,436,436,436,436,436,436,436,436,436,436,435,435,435,435,435,435,435,435,435,435,435,435,435,435,435,435,435,435,435,435,435,435,435,435,435,435,435,435,435,435,435,435,435,435,435,435,435,435,435,435,435,435,435,434,434,434,434,434,434,434,434,434,434,434,434,434,434,434,434,434,434,434,434,434,434,434,434,434,434,434,434,434,434,434,433,433,433,433,433,433,433,433,433,433,433,433,433,433,433,433,433,433,433,433,433,433,433,433,433,433,433,432,432,432,432,432,432,432,432,432,432,432,432,432,432,432,432,432,432,432,432,432,432,432,432,432,432,432,432,432,432,432,432,432,432,432,432,432,432,432,432,432,431,431,431,431,431,431,431,431,431,431,431,431,431,431,431,431,431,431,431,431,431,431,431,431,431,431,431,431,431,430,430,430,430,430,430,430,430,430,430,430,430,430,430,430,430,430,430,430,430,430,430,430,430,430,430,430,430,430,430,430,430,430,430,430,430,430,430,430,430,430,430,430,430,430,430,429,429,429,429,429,429,429,429,429,429,429,429,429,429,429,429,429,429,429,429,429,429,429,429,429,429,429,428,428,428,428,428,428,428,428,428,428,428,428,428,428,428,428,428,428,428,428,428,428,428,428,428,428,428,428,427,427,427,427,427,427,427,427,427,427,427,427,427,427,427,427,427,427,427,427,427,427,427,427,427,427,427,427,427,427,427,427,427,427,427,427,427,427,427,427,426,426,426,426,426,426,426,426,426,426,426,426,426,426,426,426,426,426,426,426,426,426,426,426,426,426,426,426,426,426,426,426,426,426,426,426,426,426,426,426,426,426,425,425,425,425,425,425,425,425,425,425,425,425,425,425,425,425,425,425,425,425,425,425,425,425,425,425,425,425,425,425,425,425,425,425,425,425,424,424,424,424,424,424,424,424,424,424,424,424,424,424,424,424,424,424,424,424,424,424,424,424,424,424,424,424,424,424,424,423,423,423,423,423,423,423,423,423,423,423,423,423,423,423,423,423,423,423,423,423,423,423,423,423,423,423,423,423,423,423,423,423,423,423,423,423,423,423,423,423,423,423,422,422,422,422,422,422,422,422,422,422,422,422,422,422,422,422,422,422,422,422,422,422,422,422,422,422,422,422,422,422,422,422,422,422,422,422,422,422,422,421,421,421,421,421,421,421,421,421,421,421,421,421,421,421,421,421,421,421,421,421,421,421,421,421,421,421,421,421,421,421,421,421,421,421,421,421,421,421,421,421,421,421,421,421,420,420,420,420,420,420,420,420,420,420,420,420,420,420,420,420,420,420,420,420,420,420,420,420,420,420,420,420,420,420,420,420,420,420,420,420,419,419,419,419,419,419,419,419,419,419,419,419,419,419,419,419,419,419,419,419,419,419,419,419,419,419,419,419,419,419,419,419,419,418,418,418,418,418,418,418,418,418,418,418,418,418,418,418,418,418,418,418,418,418,418,418,418,418,418,418,417,417,417,417,417,417,417,417,417,417,417,417,417,417,417,417,417,417,417,417,417,417,417,417,417,417,417,417,417,417,417,417,417,417,417,417,417,417,417,417,417,417,417,417,417,417,417,417,417,417,417,417,416,416,416,416,416,416,416,416,416,416,416,416,416,416,416,416,416,416,416,416,416,416,416,416,416,416,416,416,416,416,416,416,416,416,415,415,415,415,415,415,415,415,415,415,415,415,415,415,415,415,415,415,415,415,415,415,415,415,415,415,415,415,415,415,415,415,415,415,415,414,414,414,414,414,414,414,414,414,414,414,414,414,414,414,414,414,414,414,414,414,414,414,414,414,414,414,414,414,414,414,414,414,413,413,413,413,413,413,413,413,413,413,413,413,413,413,413,413,413,413,413,413,413,413,413,413,413,413,413,413,413,413,413,413,413,413,413,413,413,413,413,412,412,412,412,412,412,412,412,412,412,412,412,412,412,412,412,412,412,412,412,412,412,412,412,412,412,412,412,412,412,411,411,411,411,411,411,411,411,411,411,411,411,411,411,411,411,411,411,411,411,411,411,411,411,411,411,411,411,411,411,411,411,411,411,410,410,410,410,410,410,410,410,410,410,410,410,410,410,410,410,410,410,410,410,410,410,410,410,410,410,410,410,410,410,410,410,410,410,409,409,409,409,409,409,409,409,409,409,409,409,409,409,409,409,409,409,409,409,409,409,409,409,409,409,409,409,409,409,409,409,409,409,408,408,408,408,408,408,408,408,408,408,408,408,408,408,408,408,408,408,408,408,408,408,408,408,408,408,408,408,408,408,408,408,408,408,408,408,408,408,408,408,408,408,408,407,407,407,407,407,407,407,407,407,407,407,407,407,407,407,407,407,407,407,407,407,407,407,407,407,407,407,407,407,407,407,407,407,407,407,407,406,406,406,406,406,406,406,406,406,406,406,406,406,406,406,406,406,406,406,406,406,406,406,406,406,406,406,406,406,406,406,406,406,406,406,406,406,406,406,406,405,405,405,405,405,405,405,405,405,405,405,405,405,405,405,405,405,405,405,405,405,405,405,405,405,405,405,405,405,405,405,405,405,405,404,404,404,404,404,404,404,404,404,404,404,404,404,404,404,404,404,404,404,404,404,404,404,404,404,404,404,404,404,404,404,404,404,404,404,403,403,403,403,403,403,403,403,403,403,403,403,403,403,403,403,403,403,403,403,403,403,403,403,403,403,403,403,403,403,403,403,402,402,402,402,402,402,402,402,402,402,402,402,402,402,402,402,402,402,402,402,402,402,402,402,402,402,402,402,402,402,402,402,402,402,402,402,402,402,402,401,401,401,401,401,401,401,401,401,401,401,401,401,401,401,401,401,401,401,401,401,401,401,401,401,401,401,401,401,401,401,401,401,401,401,401,401,401,401,401,401,401,401,400,400,400,400,400,400,400,400,400,400,400,400,400,400,400,400,400,400,400,400,400,400,400,400,400,400,400,400,400,400,400,400,400,400,400,400,400,400,400,400,400,400,400,399,399,399,399,399,399,399,399,399,399,399,399,399,399,399,399,399,399,399,399,399,399,399,399,399,399,399,399,399,399,399,399,399,399,399,399,399,399,398,398,398,398,398,398,398,398,398,398,398,398,398,398,398,398,398,398,398,398,398,398,398,398,398,398,398,398,398,398,398,398,398,398,398,398,398,398,398,398,398,397,397,397,397,397,397,397,397,397,397,397,397,397,397,397,397,397,397,397,397,397,397,397,397,397,397,397,397,397,397,397,397,397,397,397,397,397,397,397,397,397,397,397,397,397,397,397,397,397,397,397,396,396,396,396,396,396,396,396,396,396,396,396,396,396,396,396,396,396,396,396,396,396,396,396,396,396,396,396,396,396,396,396,395,395,395,395,395,395,395,395,395,395,395,395,395,395,395,395,395,395,395,395,395,395,395,395,395,395,395,395,395,395,395,395,395,395,395,395,395,395,395,395,395,395,394,394,394,394,394,394,394,394,394,394,394,394,394,394,394,394,394,394,394,394,394,394,394,394,394,394,394,394,394,394,394,394,394,393,393,393,393,393,393,393,393,393,393,393,393,393,393,393,393,393,393,393,393,393,393,393,393,393,393,393,393,393,393,393,393,393,393,393,393,393,393,392,392,392,392,392,392,392,392,392,392,392,392,392,392,392,392,392,392,392,392,392,392,392,392,392,392,392,392,392,392,392,392,392,392,392,392,392,392,392,392,392,391,391,391,391,391,391,391,391,391,391,391,391,391,391,391,391,391,391,391,391,391,391,391,391,391,391,391,391,391,391,391,391,391,391,390,390,390,390,390,390,390,390,390,390,390,390,390,390,390,390,390,390,390,390,390,390,390,390,390,390,390,390,390,390,390,390,390,390,390,390,390,390,390,390,390,390,389,389,389,389,389,389,389,389,389,389,389,389,389,389,389,389,389,389,389,389,389,389,389,389,389,389,389,389,389,389,389,389,389,389,389,389,389,389,389,389,389,389,389,388,388,388,388,388,388,388,388,388,388,388,388,388,388,388,388,388,388,388,388,388,388,388,388,388,388,388,388,388,388,388,388,388,388,388,388,388,388,388,387,387,387,387,387,387,387,387,387,387,387,387,387,387,387,387,387,387,387,387,387,387,387,387,387,387,387,387,387,387,387,387,387,387,387,387,387,387,387,387,387,386,386,386,386,386,386,386,386,386,386,386,386,386,386,386,386,386,386,386,386,386,386,386,386,386,386,386,386,386,386,386,386,386,386,386,386,386,386,386,386,386,386,386,386,386,386,386,385,385,385,385,385,385,385,385,385,385,385,385,385,385,385,385,385,385,385,385,385,385,385,385,385,385,385,385,385,385,385,385,385,385,385,385,385,385,385,385,385,385,385,385,385,385,385,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,384,383,383,383,383,383,383,383,383,383,383,383,383,383,383,383,383,383,383,383,383,383,383,383,383,383,383,383,383,383,383,383,383,383,383,383,383,383,383,383,383,383,383,383,383,382,382,382,382,382,382,382,382,382,382,382,382,382,382,382,382,382,382,382,382,382,382,382,382,382,382,382,382,382,382,382,382,382,382,382,382,382,382,382,381,381,381,381,381,381,381,381,381,381,381,381,381,381,381,381,381,381,381,381,381,381,381,381,381,381,381,381,381,381,381,381,381,381,381,381,381,381,381,381,381,381,381,380,380,380,380,380,380,380,380,380,380,380,380,380,380,380,380,380,380,380,380,380,380,380,380,380,380,380,380,380,380,380,380,380,379,379,379,379,379,379,379,379,379,379,379,379,379,379,379,379,379,379,379,379,379,379,379,379,379,379,379,379,379,379,379,379,379,379,379,379,379,379,379,379,379,379,379,379,378,378,378,378,378,378,378,378,378,378,378,378,378,378,378,378,378,378,378,378,378,378,378,378,378,378,378,378,378,378,378,378,378,378,378,378,378,378,378,377,377,377,377,377,377,377,377,377,377,377,377,377,377,377,377,377,377,377,377,377,377,377,377,377,377,377,377,377,377,377,377,377,377,377,377,377,377,377,377,377,377,377,377,377,377,377,377,376,376,376,376,376,376,376,376,376,376,376,376,376,376,376,376,376,376,376,376,376,376,376,376,376,376,376,376,376,376,376,376,376,375,375,375,375,375,375,375,375,375,375,375,375,375,375,375,375,375,375,375,375,375,375,375,375,375,375,375,375,375,375,375,375,375,375,375,375,375,375,375,375,375,375,375,375,375,375,374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,374,373,373,373,373,373,373,373,373,373,373,373,373,373,373,373,373,373,373,373,373,373,373,373,373,373,373,373,373,373,373,373,373,373,373,373,373,373,372,372,372,372,372,372,372,372,372,372,372,372,372,372,372,372,372,372,372,372,372,372,372,372,372,372,372,372,372,372,372,372,372,372,372,372,371,371,371,371,371,371,371,371,371,371,371,371,371,371,371,371,371,371,371,371,371,371,371,371,371,371,371,371,371,371,371,371,371,371,371,371,371,371,371,371,371,371,371,371,371,371,371,371,371,371,371,370,370,370,370,370,370,370,370,370,370,370,370,370,370,370,370,370,370,370,370,370,370,370,370,370,370,370,370,370,370,370,370,370,370,370,370,370,370,370,369,369,369,369,369,369,369,369,369,369,369,369,369,369,369,369,369,369,369,369,369,369,369,369,369,369,369,369,369,369,369,369,369,369,369,369,369,369,368,368,368,368,368,368,368,368,368,368,368,368,368,368,368,368,368,368,368,368,368,368,368,368,368,368,368,368,368,368,368,368,368,368,368,368,368,368,368,368,367,367,367,367,367,367,367,367,367,367,367,367,367,367,367,367,367,367,367,367,367,367,367,367,367,367,367,367,367,367,367,367,367,367,367,367,367,367,367,367,366,366,366,366,366,366,366,366,366,366,366,366,366,366,366,366,366,366,366,366,366,366,366,366,366,366,366,366,366,366,366,366,366,366,366,366,366,366,366,366,366,366,366,366,366,366,366,366,366,366,365,365,365,365,365,365,365,365,365,365,365,365,365,365,365,365,365,365,365,365,365,365,365,365,365,365,365,365,365,365,365,365,365,365,365,365,365,365,365,365,365,365,365,365,365,365,365,365,365,365,364,364,364,364,364,364,364,364,364,364,364,364,364,364,364,364,364,364,364,364,364,364,364,364,364,364,364,364,364,364,364,364,364,364,364,364,364,364,364,364,364,364,364,364,364,364,364,364,364,364,363,363,363,363,363,363,363,363,363,363,363,363,363,363,363,363,363,363,363,363,363,363,363,363,363,363,363,363,363,363,363,363,363,363,363,363,363,363,363,363,363,363,363,363,363,363,363,363,363,363,363,363,363,363,362,362,362,362,362,362,362,362,362,362,362,362,362,362,362,362,362,362,362,362,362,362,362,362,362,362,362,362,362,362,362,362,362,362,362,362,362,362,362,362,362,362,362,361,361,361,361,361,361,361,361,361,361,361,361,361,361,361,361,361,361,361,361,361,361,361,361,361,361,361,361,361,361,361,361,361,361,361,361,361,361,361,361,361,361,361,361,361,360,360,360,360,360,360,360,360,360,360,360,360,360,360,360,360,360,360,360,360,360,360,360,360,360,360,360,360,360,360,360,360,360,360,359,359,359,359,359,359,359,359,359,359,359,359,359,359,359,359,359,359,359,359,359,359,359,359,359,359,359,359,359,359,359,359,359,359,359,359,359,359,359,359,359,359,359,359,359,358,358,358,358,358,358,358,358,358,358,358,358,358,358,358,358,358,358,358,358,358,358,358,358,358,358,358,358,358,358,358,358,358,358,358,358,358,358,358,358,358,358,358,358,357,357,357,357,357,357,357,357,357,357,357,357,357,357,357,357,357,357,357,357,357,357,357,357,357,357,357,357,357,357,357,357,357,357,357,357,357,357,357,357,357,357,357,357,357,356,356,356,356,356,356,356,356,356,356,356,356,356,356,356,356,356,356,356,356,356,356,356,356,356,356,356,356,356,356,356,356,356,356,356,356,356,356,356,356,355,355,355,355,355,355,355,355,355,355,355,355,355,355,355,355,355,355,355,355,355,355,355,355,355,355,355,355,355,355,355,355,355,355,355,355,355,355,355,355,355,355,355,355,355,355,355,355,355,355,354,354,354,354,354,354,354,354,354,354,354,354,354,354,354,354,354,354,354,354,354,354,354,354,354,354,354,354,354,354,354,354,354,354,354,354,354,354,354,354,353,353,353,353,353,353,353,353,353,353,353,353,353,353,353,353,353,353,353,353,353,353,353,353,353,353,353,353,353,353,353,353,353,353,353,353,353,353,353,353,353,353,353,353,353,353,353,353,353,353,353,353,353,353,353,352,352,352,352,352,352,352,352,352,352,352,352,352,352,352,352,352,352,352,352,352,352,352,352,352,352,352,352,352,352,352,352,352,352,352,352,352,352,352,352,352,352,352,352,352,352,352,352,351,351,351,351,351,351,351,351,351,351,351,351,351,351,351,351,351,351,351,351,351,351,351,351,351,351,351,351,351,351,351,351,351,351,351,351,351,351,351,351,351,351,351,351,351,351,351,351,351,351,351,351,351,351,351,351,350,350,350,350,350,350,350,350,350,350,350,350,350,350,350,350,350,350,350,350,350,350,350,350,350,350,350,350,350,350,350,350,350,350,350,350,350,350,350,350,350,349,349,349,349,349,349,349,349,349,349,349,349,349,349,349,349,349,349,349,349,349,349,349,349,349,349,349,349,349,349,349,349,349,349,349,349,349,349,349,349,349,349,349,349,349,349,349,349,348,348,348,348,348,348,348,348,348,348,348,348,348,348,348,348,348,348,348,348,348,348,348,348,348,348,348,348,348,348,348,348,348,348,348,348,348,348,348,348,348,348,348,348,347,347,347,347,347,347,347,347,347,347,347,347,347,347,347,347,347,347,347,347,347,347,347,347,347,347,347,347,347,347,347,347,347,347,347,347,347,347,347,346,346,346,346,346,346,346,346,346,346,346,346,346,346,346,346,346,346,346,346,346,346,346,346,346,346,346,346,346,346,346,346,346,346,346,346,346,346,346,346,346,346,346,346,346,345,345,345,345,345,345,345,345,345,345,345,345,345,345,345,345,345,345,345,345,345,345,345,345,345,345,345,345,345,345,345,345,345,345,345,345,345,345,345,345,345,345,345,345,345,345,345,345,345,345,345,345,345,345,345,344,344,344,344,344,344,344,344,344,344,344,344,344,344,344,344,344,344,344,344,344,344,344,344,344,344,344,344,344,344,344,344,344,344,344,344,344,344,344,344,344,344,344,344,344,344,344,344,343,343,343,343,343,343,343,343,343,343,343,343,343,343,343,343,343,343,343,343,343,343,343,343,343,343,343,343,343,343,343,343,343,343,343,343,343,343,343,343,343,343,343,343,343,343,343,342,342,342,342,342,342,342,342,342,342,342,342,342,342,342,342,342,342,342,342,342,342,342,342,342,342,342,342,342,342,342,342,342,342,342,342,342,342,342,342,342,342,342,342,342,341,341,341,341,341,341,341,341,341,341,341,341,341,341,341,341,341,341,341,341,341,341,341,341,341,341,341,341,341,341,341,341,341,341,341,341,341,341,341,341,341,341,341,341,341,341,341,341,341,341,341,341,341,340,340,340,340,340,340,340,340,340,340,340,340,340,340,340,340,340,340,340,340,340,340,340,340,340,340,340,340,340,340,340,340,340,340,340,340,340,340,340,339,339,339,339,339,339,339,339,339,339,339,339,339,339,339,339,339,339,339,339,339,339,339,339,339,339,339,339,339,339,339,339,339,339,339,339,339,339,339,339,339,339,339,339,339,339,339,339,339,339,339,339,339,339,339,339,339,338,338,338,338,338,338,338,338,338,338,338,338,338,338,338,338,338,338,338,338,338,338,338,338,338,338,338,338,338,338,338,338,338,338,338,338,338,338,338,338,338,338,338,338,338,338,338,338,338,337,337,337,337,337,337,337,337,337,337,337,337,337,337,337,337,337,337,337,337,337,337,337,337,337,337,337,337,337,337,337,337,337,337,337,337,337,337,337,337,337,337,337,337,337,337,337,337,337,337,337,337,337,336,336,336,336,336,336,336,336,336,336,336,336,336,336,336,336,336,336,336,336,336,336,336,336,336,336,336,336,336,336,336,336,336,336,336,336,336,336,336,336,336,336,336,336,336,336,336,336,336,336,335,335,335,335,335,335,335,335,335,335,335,335,335,335,335,335,335,335,335,335,335,335,335,335,335,335,335,335,335,335,335,335,335,335,335,335,335,335,335,335,335,335,335,335,334,334,334,334,334,334,334,334,334,334,334,334,334,334,334,334,334,334,334,334,334,334,334,334,334,334,334,334,334,334,334,334,334,334,334,334,334,334,334,334,334,334,334,334,334,334,334,334,334,334,334,333,333,333,333,333,333,333,333,333,333,333,333,333,333,333,333,333,333,333,333,333,333,333,333,333,333,333,333,333,333,333,333,333,333,333,333,333,333,333,333,333,333,333,333,333,333,333,332,332,332,332,332,332,332,332,332,332,332,332,332,332,332,332,332,332,332,332,332,332,332,332,332,332,332,332,332,332,332,332,332,332,332,332,332,332,332,332,332,332,332,332,332,332,332,332,332,332,332,332,332,332,332,331,331,331,331,331,331,331,331,331,331,331,331,331,331,331,331,331,331,331,331,331,331,331,331,331,331,331,331,331,331,331,331,331,331,331,331,331,331,331,331,331,331,331,331,331,331,331,331,331,331,331,331,331,331,331,331,331,331,331,331,331,331,331,331,331,331,331,331,331,331,331,331,331,330,330,330,330,330,330,330,330,330,330,330,330,330,330,330,330,330,330,330,330,330,330,330,330,330,330,330,330,330,330,330,330,330,330,330,330,330,330,330,330,330,330,330,330,330,329,329,329,329,329,329,329,329,329,329,329,329,329,329,329,329,329,329,329,329,329,329,329,329,329,329,329,329,329,329,329,329,329,329,329,329,329,329,329,329,329,329,329,329,329,329,329,329,329,329,329,329,329,329,329,328,328,328,328,328,328,328,328,328,328,328,328,328,328,328,328,328,328,328,328,328,328,328,328,328,328,328,328,328,328,328,328,328,328,328,328,328,328,328,328,328,328,328,328,328,328,328,328,328,327,327,327,327,327,327,327,327,327,327,327,327,327,327,327,327,327,327,327,327,327,327,327,327,327,327,327,327,327,327,327,327,327,327,327,327,327,327,327,327,327,327,327,327,327,327,327,327,326,326,326,326,326,326,326,326,326,326,326,326,326,326,326,326,326,326,326,326,326,326,326,326,326,326,326,326,326,326,326,326,326,326,326,326,326,326,326,326,326,326,326,326,326,326,326,326,326,326,326,325,325,325,325,325,325,325,325,325,325,325,325,325,325,325,325,325,325,325,325,325,325,325,325,325,325,325,325,325,325,325,325,325,325,325,325,325,325,325,325,325,325,325,325,325,325,325,325,325,325,325,325,325,325,325,325,325,324,324,324,324,324,324,324,324,324,324,324,324,324,324,324,324,324,324,324,324,324,324,324,324,324,324,324,324,324,324,324,324,324,324,324,324,324,324,324,324,324,324,324,324,324,324,324,324,324,324,324,324,324,324,324,324,323,323,323,323,323,323,323,323,323,323,323,323,323,323,323,323,323,323,323,323,323,323,323,323,323,323,323,323,323,323,323,323,323,323,323,323,323,323,323,323,323,323,323,323,323,323,323,323,323,323,323,323,323,323,323,323,323,323,323,323,323,323,322,322,322,322,322,322,322,322,322,322,322,322,322,322,322,322,322,322,322,322,322,322,322,322,322,322,322,322,322,322,322,322,322,322,322,322,322,322,322,322,322,322,322,322,322,322,322,322,322,322,322,322,322,322,322,321,321,321,321,321,321,321,321,321,321,321,321,321,321,321,321,321,321,321,321,321,321,321,321,321,321,321,321,321,321,321,321,321,321,321,321,321,321,321,321,321,321,321,321,321,320,320,320,320,320,320,320,320,320,320,320,320,320,320,320,320,320,320,320,320,320,320,320,320,320,320,320,320,320,320,320,320,320,320,320,320,320,320,320,320,320,320,320,320,320,319,319,319,319,319,319,319,319,319,319,319,319,319,319,319,319,319,319,319,319,319,319,319,319,319,319,319,319,319,319,319,319,319,319,319,319,319,319,319,319,319,319,319,319";
var M = 2 ** 24;
var L = 2 ** 32;
var XMAX_UNIT = L / M * 256;
var WORDS = VOCAB_WORDS.split(" ");
var COUNTS = VOCAB_COUNTS.split(",").map(Number);
WORDS.length;
/** Deterministic keystream for model construction and padding bits. */
var KeyStream = class {
	key;
	label;
	buf = /* @__PURE__ */ new Uint8Array(0);
	pos = 0;
	block = 0;
	constructor(key, label) {
		this.key = key;
		this.label = label;
		if (key.length !== 32) throw new Error("model key must be 32 bytes");
	}
	refill() {
		const nonce = /* @__PURE__ */ new Uint8Array(16);
		nonce[0] = this.label & 255;
		let b = this.block++;
		for (let i = 15; i >= 8 && b > 0; i--) {
			nonce[i] = b % 256;
			b = Math.floor(b / 256);
		}
		this.buf = ctr(this.key, nonce).encrypt(/* @__PURE__ */ new Uint8Array(4096));
		this.pos = 0;
	}
	byte() {
		if (this.pos >= this.buf.length) this.refill();
		return this.buf[this.pos++];
	}
	u32() {
		return (this.byte() << 24 | this.byte() << 16 | this.byte() << 8 | this.byte()) >>> 0;
	}
	below(n) {
		const limit = Math.floor(2 ** 32 / n) * n;
		for (;;) {
			const v = this.u32();
			if (v < limit) return v % n;
		}
	}
};
/** Rank groups: consecutive ranks whose counts are within 1.5x, at most 256 wide. */
var GROUPS = (() => {
	const out = [];
	let start = 0;
	for (let i = 1; i <= WORDS.length; i++) if (i === WORDS.length || COUNTS[i] * 1.5 < COUNTS[start] || i - start >= 256) {
		out.push([start, i]);
		start = i;
	}
	return out;
})();
/** Quantized frequencies by rank, summing exactly to 2^24, each >= 1. */
var FREQ_BY_RANK = (() => {
	const total = COUNTS.reduce((a, b) => a + b, 0);
	const f = new Uint32Array(WORDS.length);
	let sum = 0;
	for (let i = 0; i < f.length; i++) {
		f[i] = Math.max(1, Math.floor(COUNTS[i] / total * M));
		sum += f[i];
	}
	let i = 0;
	while (sum < M) {
		f[i % 64] += 1;
		sum += 1;
		i++;
	}
	while (sum > M) {
		if (f[i % 64] > 1) {
			f[i % 64] -= 1;
			sum -= 1;
		}
		i++;
	}
	return f;
})();
var modelCache$1 = /* @__PURE__ */ new Map();
function hexOf(b) {
	let s = "";
	for (const x of b) s += x.toString(16).padStart(2, "0");
	return s;
}
function huffmanLengths(freq) {
	const n = freq.length;
	const order = Array.from({ length: n }, (_, i) => i).sort((a, b) => freq[a] - freq[b] || a - b);
	const weight = [];
	const parent = [];
	for (const s of order) {
		weight.push(freq[s]);
		parent.push(-1);
	}
	let leafPos = 0;
	let nodePos = n;
	const take = () => {
		if (nodePos < weight.length && (leafPos >= n || weight[nodePos] < weight[leafPos])) return nodePos++;
		return leafPos++;
	};
	while (weight.length < 2 * n - 1) {
		const a = take();
		const b = take();
		const id = weight.length;
		weight.push(weight[a] + weight[b]);
		parent.push(-1);
		parent[a] = id;
		parent[b] = id;
	}
	const depth = new Array(weight.length).fill(0);
	for (let i = weight.length - 2; i >= 0; i--) depth[i] = depth[parent[i]] + 1;
	const lens = new Uint8Array(n);
	for (let k = 0; k < n; k++) lens[order[k]] = depth[k];
	return lens;
}
function buildModel(lexKey, padKey) {
	const id = hexOf(lexKey) + hexOf(padKey);
	const hit = modelCache$1.get(id);
	if (hit) return hit;
	const ks = new KeyStream(lexKey, 1);
	const words = WORDS.slice();
	for (const [a, b] of GROUPS) for (let i = b - 1; i > a; i--) {
		const j = a + ks.below(i - a + 1);
		const t = words[i];
		words[i] = words[j];
		words[j] = t;
	}
	const index = /* @__PURE__ */ new Map();
	words.forEach((w, i) => index.set(w, i));
	const freq = FREQ_BY_RANK;
	const cum = new Uint32Array(freq.length + 1);
	for (let i = 0; i < freq.length; i++) cum[i + 1] = cum[i] + freq[i];
	const codeLen = huffmanLengths(freq);
	const syms = Array.from({ length: freq.length }, (_, i) => i).sort((a, b) => codeLen[a] - codeLen[b] || a - b);
	const code = new Uint32Array(freq.length);
	const decodeTree = /* @__PURE__ */ new Map();
	let c = 0;
	let prevLen = codeLen[syms[0]];
	for (const s of syms) {
		c <<= codeLen[s] - prevLen;
		prevLen = codeLen[s];
		code[s] = c;
		decodeTree.set(`${codeLen[s]}:${c}`, s);
		c++;
	}
	const model = {
		words,
		index,
		freq,
		cum,
		codeLen,
		code,
		decodeTree,
		maxLen: prevLen,
		padKey
	};
	modelCache$1.set(id, model);
	if (modelCache$1.size > 16) modelCache$1.delete(modelCache$1.keys().next().value);
	return model;
}
var LOW_BITS = 28;
var stateCode = null;
function stateCoder() {
	if (stateCode) return stateCode;
	const bin = atob(STATE_WEIGHTS);
	const raw = new Uint8Array(bin.length);
	for (let i = 0; i < bin.length; i++) raw[i] = bin.charCodeAt(i);
	const w = new Uint32Array(raw.buffer, raw.byteOffset, raw.byteLength >>> 2);
	const len = huffmanLengths(w);
	const syms = Array.from({ length: w.length }, (_, i) => i).sort((a, b) => len[a] - len[b] || a - b);
	const code = new Uint32Array(w.length);
	const tree = /* @__PURE__ */ new Map();
	let c = 0;
	let prev = len[syms[0]];
	for (const s of syms) {
		c <<= len[s] - prev;
		prev = len[s];
		code[s] = c;
		tree.set(`${len[s]}:${c}`, s);
		c++;
	}
	stateCode = {
		len,
		code,
		tree
	};
	return stateCode;
}
function findSym(model, slot) {
	let lo = 0;
	let hi = model.freq.length - 1;
	while (lo < hi) {
		const mid = lo + hi + 1 >> 1;
		if (model.cum[mid] <= slot) lo = mid;
		else hi = mid - 1;
	}
	return lo;
}
/** rANS: bytes (>= 4) -> word symbols. Never throws. */
function bytesToWords(model, data, padSeed) {
	if (data.length < 4) throw new Error("rANS mapping needs at least 4 bytes");
	let x = L + ((data[0] << 24 | data[1] << 16 | data[2] << 8 | data[3]) >>> 0);
	let pos = 4;
	let virt = 0;
	let vks = null;
	const syms = [];
	while (pos < data.length) {
		const slot = x % M;
		const s = findSym(model, slot);
		syms.push(s);
		x = model.freq[s] * Math.floor(x / M) + slot - model.cum[s];
		while (x < L) if (pos < data.length) x = x * 256 + data[pos++];
		else {
			vks ??= new KeyStream(model.padKey, 1e3 + (padSeed & 255));
			x = x * 256 + vks.byte();
			virt++;
		}
	}
	const sc = stateCoder();
	const hs = (Math.floor(x / 2 ** LOW_BITS) - 16) * 4 + virt;
	let bits = sc.code[hs].toString(2).padStart(sc.len[hs], "0");
	bits += (x % 2 ** LOW_BITS).toString(2).padStart(LOW_BITS, "0");
	const ks = new KeyStream(model.padKey, 2 + (padSeed & 255));
	const head = [];
	let acc = "";
	const pull = (i) => i < bits.length ? bits[i] : (ks.byte() & 1).toString();
	let i = 0;
	while (i < bits.length) {
		acc += pull(i++);
		const s = model.decodeTree.get(`${acc.length}:${parseInt(acc, 2)}`);
		if (s !== void 0) {
			head.push(s);
			acc = "";
		}
	}
	while (acc.length > 0) {
		acc += pull(i++);
		const s = model.decodeTree.get(`${acc.length}:${parseInt(acc, 2)}`);
		if (s !== void 0) {
			head.push(s);
			acc = "";
		}
		if (acc.length > 40) acc = "";
	}
	return [...head, ...syms].map((s) => model.words[s]);
}
/** rANS inverse: words -> bytes. Unknown words count as symbol 0. Never throws. */
function wordsToBytes(model, words) {
	const syms = words.map((w) => model.index.get(w) ?? 0);
	const sc = stateCoder();
	let bits = "";
	let k = 0;
	let hs = -1;
	let used = 0;
	while (k < syms.length) {
		if (hs < 0) for (let n = 1; n <= bits.length && n <= 40; n++) {
			const v = sc.tree.get(`${n}:${parseInt(bits.slice(0, n), 2)}`);
			if (v !== void 0) {
				hs = v;
				used = n;
				break;
			}
		}
		if (hs >= 0 && bits.length >= used + LOW_BITS) break;
		const s = syms[k++];
		bits += model.code[s].toString(2).padStart(model.codeLen[s], "0");
	}
	if (hs < 0) for (let n = 1; n <= bits.length && n <= 40; n++) {
		const v = sc.tree.get(`${n}:${parseInt(bits.slice(0, n), 2)}`);
		if (v !== void 0) {
			hs = v;
			used = n;
			break;
		}
	}
	if (hs < 0) hs = 0;
	const low = parseInt(bits.slice(used, used + LOW_BITS).padEnd(LOW_BITS, "0"), 2);
	const virt = hs % 4;
	let x = (Math.floor(hs / 4) + 16) * 2 ** LOW_BITS + low;
	const out = [];
	for (let j = syms.length - 1; j >= k; j--) {
		const s = syms[j];
		const f = model.freq[s];
		const xmax = XMAX_UNIT * f;
		while (x >= xmax) {
			out.push(x % 256);
			x = Math.floor(x / 256);
		}
		x = Math.floor(x / f) * M + x % f + model.cum[s];
	}
	const head = ((x - L) % L + L) % L;
	const body = out.reverse();
	const keep = Math.max(0, body.length - virt);
	const res = new Uint8Array(4 + keep);
	res[0] = head >>> 24 & 255;
	res[1] = head >>> 16 & 255;
	res[2] = head >>> 8 & 255;
	res[3] = head & 255;
	for (let j = 0; j < keep; j++) res[4 + j] = body[j];
	return res;
}
/**
* T19: lexis frame v2.
*
*   inner  = compressed || pad || mnemonic(16) || u16be(len(compressed))
*   cipher = HCTR2-AES256(K_perm, tweak = u64 counter || dir || u32 window || u16 gen || "LX", inner)
*   wire   = rANS(K_lex model)(cipher)  -> corpus words
*
* - The 128-bit mnemonic comes from the session key (HKDF), so it is fixed per
*   key generation; any change to any wire word, a wrong counter (replay, deletion,
*   reorder), a wrong direction or window turns the whole SPRP output into noise and
*   the mnemonic check (constant time) fails.
* - Counters are strictly consecutive and continue across rekeys (gen increments).
* - Separate HKDF keys: permutation, word list, padding, mnemonic.
* - Padding length is keyed (K_pad, counter) and bounded by maxExpansion over the
*   compressed size; the fixed 18-byte overhead is not counted against small frames.
*/
var enc$1 = new TextEncoder();
function derive(sk, label, gen, len = 32) {
	return hkdf(sha256, sk, enc$1.encode("lexis-v2"), enc$1.encode(`${label}|gen=${gen}`), len);
}
function deriveV2Keys(sk, gen = 0, mnemonicBase) {
	const lexKey = derive(sk, "lex", gen);
	const padKey = derive(sk, "pad", gen);
	const mnemonic = mnemonicBase ? hkdf(sha256, mnemonicBase, enc$1.encode("lexis-v2-mnemonic"), enc$1.encode(`mnemonic|gen=${gen}`), 16) : derive(sk, "mnemonic", gen, 16);
	return {
		gen,
		perm: hctr2Key(derive(sk, "perm", gen)),
		model: buildModel(lexKey, padKey),
		padKey,
		mnemonic
	};
}
function tweakOf(counter, dir, window, gen) {
	const t = /* @__PURE__ */ new Uint8Array(16);
	let c = counter;
	for (let i = 7; i >= 0; i--) {
		t[i] = c % 256;
		c = Math.floor(c / 256);
	}
	t[8] = dir === "e2g" ? 1 : 2;
	t[9] = window >>> 24 & 255;
	t[10] = window >>> 16 & 255;
	t[11] = window >>> 8 & 255;
	t[12] = window & 255;
	t[13] = gen >>> 8 & 255;
	t[14] = gen & 255;
	t[15] = 76;
	return t;
}
function constantTimeEqual(a, b) {
	if (a.length !== b.length) return false;
	let d = 0;
	for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
	return d === 0;
}
function padModulus(capacity) {
	return Math.min(255, capacity) + 1;
}
function encodeLenField(len, capacity) {
	const pad = capacity - len;
	const m = padModulus(capacity);
	if (pad < 0 || pad >= m) throw new Error("pad out of range");
	const count = Math.floor((65535 - pad) / m) + 1;
	return pad + crypto.getRandomValues(/* @__PURE__ */ new Uint32Array(1))[0] % count * m;
}
function decodeLenField(field, capacity) {
	return capacity - field % padModulus(capacity);
}
/** Measured wire bytes (UTF-8 chars incl. spaces) per sealed inner byte for the rANS word
* stream (accept C/D: 4.16). D1: frame.maxExpansion is a WIRE budget over the compressed
* size, so the pad budget is maxExpansion*|P|/WIRE_PER_INNER_BYTE - |P| - OVERHEAD. */
var WIRE_PER_INNER_BYTE = 4.16;
function padLength(keys, counter, dir, len, maxExpansion, policy = "expansion") {
	if (policy === "honey") {
		const mix = sha256(new Uint8Array([...keys.padKey, ...tweakOf(counter, dir, 0, keys.gen)]));
		return (mix[0] << 8 | mix[1]) % 256;
	}
	const budget = Math.floor(maxExpansion * Math.max(len, 1) / WIRE_PER_INNER_BYTE) - len;
	const maxPad = Math.max(0, Math.min(255, budget - 18));
	if (maxPad === 0) return 0;
	const mix = sha256(new Uint8Array([...keys.padKey, ...tweakOf(counter, dir, 0, keys.gen)]));
	return (mix[0] << 8 | mix[1]) % (maxPad + 1);
}
function sealV2(opts) {
	const { keys, counter, window, dir, plaintext } = opts;
	if (plaintext.length > 65535) throw new Error("frame too large");
	if (!Number.isSafeInteger(counter) || counter < 1) throw new Error("bad counter");
	const pad = padLength(keys, counter, dir, plaintext.length, opts.maxExpansion ?? 2, opts.smallFramePolicy ?? "expansion");
	const inner = new Uint8Array(plaintext.length + pad + 18);
	inner.set(plaintext, 0);
	if (pad) {
		const fill = sha256(new Uint8Array([
			...keys.padKey,
			112,
			...tweakOf(counter, dir, window, keys.gen)
		]));
		for (let i = 0; i < pad; i++) inner[plaintext.length + i] = fill[i % 32] ^ i >> 5;
	}
	inner.set(keys.mnemonic, plaintext.length + pad);
	const field = encodeLenField(plaintext.length, plaintext.length + pad);
	inner[inner.length - 2] = field >> 8 & 255;
	inner[inner.length - 1] = field & 255;
	const cipher = hctr2Encrypt(keys.perm, tweakOf(counter, dir, window, keys.gen), inner);
	return bytesToWords(keys.model, cipher, counter & 255).join(" ");
}
var FrameError = class extends Error {};
/**
* D2 honey decrypt. With ANY key this returns a 16-byte mnemonic and a body and never
* throws: a wrong key simply yields a different (random) mnemonic and a random body,
* both valid in format. This is the view an attacker who guesses/seizes a key gets;
* the frame layer adds no explicit key-confirmation value. `formatValid` is the canonical
* re-encoding check (words -> bytes -> words must reproduce the prose). It is NOT
* key-independent: the rANS word model is keyed, so the check passes ~100% under the
* right key and only ~2-3% under a wrong key (measured AUC 0.987 from one frame). Anyone
* holding a candidate session key can therefore confirm it from a single frame; this is
* an accepted boundary (user decision 2026-11-02, Zipf rANS kept, no GF bijection).
* Other confirmations available to a candidate-key holder: body structure (batch/record
* headers, zstd magic) and, on small unpadded frames, the decoded pad share. Honey only
* defends against brute-forcing the long-term private key / passphrase, never against a
* candidate session key. Session keys are not reachable from long-term keys + transcript
* (ephemeral DH).
*/
function openV2Honey(opts) {
	const words = opts.prose.trim().toLowerCase().split(/\s+/).filter(Boolean);
	const cipher = wordsToBytes(opts.keys.model, words);
	const inner = cipher.length >= 16 ? hctr2Decrypt(opts.keys.perm, tweakOf(opts.counter, opts.dir, opts.window, opts.keys.gen), cipher) : cipher;
	if (inner.length < 18) return {
		mnemonic: /* @__PURE__ */ new Uint8Array(16),
		body: /* @__PURE__ */ new Uint8Array(0),
		formatValid: false
	};
	const mnemonic = inner.slice(inner.length - 18, inner.length - 2);
	const len = decodeLenField(inner[inner.length - 2] << 8 | inner[inner.length - 1], inner.length - 18);
	let canonical = true;
	if (cipher.length >= 16) {
		const again = bytesToWords(opts.keys.model, cipher, opts.counter & 255);
		canonical = again.length === words.length && again.every((w, i) => w === words[i]);
	}
	const formatValid = canonical;
	return {
		mnemonic,
		body: inner.slice(0, len),
		formatValid
	};
}
function openV2(opts) {
	const words = opts.prose.trim().toLowerCase().split(/\s+/).filter(Boolean);
	const cipher = wordsToBytes(opts.keys.model, words);
	if (cipher.length < 18) throw new FrameError("帧完整性校验失败");
	const again = bytesToWords(opts.keys.model, cipher, opts.counter & 255);
	if (again.length !== words.length || again.some((w, i) => w !== words[i])) throw new FrameError("帧完整性校验失败");
	const inner = hctr2Decrypt(opts.keys.perm, tweakOf(opts.counter, opts.dir, opts.window, opts.keys.gen), cipher);
	if (inner.length < 18) throw new FrameError("帧完整性校验失败");
	const ok = constantTimeEqual(inner.subarray(inner.length - 18, inner.length - 2), opts.keys.mnemonic);
	const len = decodeLenField(inner[inner.length - 2] << 8 | inner[inner.length - 1], inner.length - 18);
	if (!ok) throw new FrameError("帧完整性校验失败");
	return inner.slice(0, len);
}
function packBatch(segs) {
	let total = 0;
	for (const s of segs) total += 4 + s.data.length;
	const out = new Uint8Array(total);
	let o = 0;
	for (const s of segs) {
		if (s.data.length > 16777215) throw new Error("segment too large");
		out[o] = s.flag & 255;
		out[o + 1] = s.data.length >>> 16 & 255;
		out[o + 2] = s.data.length >>> 8 & 255;
		out[o + 3] = s.data.length & 255;
		out.set(s.data, o + 4);
		o += 4 + s.data.length;
	}
	return out;
}
function unpackBatch(buf) {
	const segs = [];
	let o = 0;
	while (o < buf.length) {
		if (o + 4 > buf.length) throw new FrameError("批量段头被截断");
		const flag = buf[o];
		const len = buf[o + 1] << 16 | buf[o + 2] << 8 | buf[o + 3];
		o += 4;
		if (flag > 2 || o + len > buf.length) throw new FrameError("批量段越界");
		segs.push({
			flag,
			data: buf.slice(o, o + len)
		});
		o += len;
	}
	return segs;
}
/**
* v3: handshake with Noise-NK-style hello (es = X25519(eph, gate_static)).
*
* hello  = words_H( repC(32) || HCTR2(K_h, "hello"|w, admitC || ltC || nonceC || kdf || feat || pad) )
* server = words_H( repS(32) || HCTR2(K_s, "server"|w, admitS || nonceS || kdf || feat || confirmS || pad) )
* finish = words_session( HCTR2(K_f, "finish"|w, confirmC || pad) )
*
* - repC/repS: Elligator2 representatives of dirty X25519 ephemerals (uniform 256-bit strings).
* - K_h / admit-c = HKDF(token || es, ... ) where es = X25519(client_eph, gate_static_pub).
*   Only the gate private key holder can compute es, so token+gatePub alone cannot check admit
*   or read ltRaw (fixes the v2 offline oracle). Word model stays keyed by token||ltS so the
*   wire can still be parsed into bytes without es; those bytes are useless without es.
* - K_s additionally mixes the ephemeral-ephemeral secret ssE.
* - Session key: ssE = X25519 eph-eph, ssS = X25519 static-static, through deriveSessionKeyAsync.
* - Key confirmation restored: confirmS / confirmC = HMAC(HKDF(sk), transcript).
* - The gate treats every failure the same way (HandshakeDrop): the caller drops silently.
*/
var enc = new TextEncoder();
var HandshakeDrop = class extends Error {};
var fail = (why) => {
	throw new HandshakeDrop(why);
};
function rand(n) {
	return crypto.getRandomValues(new Uint8Array(n));
}
function unb64(s) {
	return unb64$1(s);
}
var modelCache = /* @__PURE__ */ new Map();
function helloModel(ikm) {
	const id = hex(sha256(ikm));
	let m = modelCache.get(id);
	if (!m) {
		m = buildModel(hkdf(sha256, ikm, enc.encode("lexis-v3-hello"), enc.encode("lex"), 32), hkdf(sha256, ikm, enc.encode("lexis-v3-hello"), enc.encode("pad"), 32));
		if (modelCache.size > 16) modelCache.clear();
		modelCache.set(id, m);
	}
	return m;
}
function gateIkm(token, gatePubRaw) {
	return concat(enc.encode(token), new Uint8Array([0]), gatePubRaw);
}
/** Secret hello IKM: token concatenated with the Noise-NK `es` shared secret. */
function helloIkm(token, es) {
	return concat(enc.encode(token), new Uint8Array([0]), es);
}
function tw(label, window) {
	return concat(enc.encode(label), u32be(window >>> 0));
}
function k(ikm, salt, info, len = 32) {
	return hkdf(sha256, ikm, salt, enc.encode(info), len);
}
function toWords(model, data) {
	return bytesToWords(model, data, rand(1)[0]).join(" ");
}
function fromWords(model, prose) {
	return wordsToBytes(model, prose.trim().toLowerCase().split(/\s+/).filter(Boolean));
}
var LT = 32;
function windowCandidates(now = Date.now()) {
	const current = currentWindow(now);
	const into = Math.floor(now / 1e3) % SPEC.windowSec;
	const out = [current];
	if (into < SPEC.skewSec) out.push(current - 1);
	if (into >= SPEC.windowSec - SPEC.skewSec) out.push(current + 1);
	return out;
}
function transcript(p) {
	return sha256(concat(enc.encode("lexis-v3-transcript"), p.repC, p.repS, p.ltC, p.ltS, u32be(p.window >>> 0), p.nonceC, p.nonceS, p.kdf, new Uint8Array([p.features & 255])));
}
function confirmS_(ssE, sk, tr) {
	return hmac(sha256, k(concat(ssE, sk), /* @__PURE__ */ new Uint8Array(0), "lexis-v3-confirm-s"), tr).slice(0, 16);
}
function confirmC_(mnemonicBase, tr) {
	return hmac(sha256, k(mnemonicBase, /* @__PURE__ */ new Uint8Array(0), "lexis-v3-confirm-c"), tr).slice(0, 16);
}
function mnemonicBaseOf(ssE, seedC, seedS) {
	return hkdf(sha256, ssE, concat(seedC, seedS), enc.encode("lexis-v3-mnemonic-base"), 32);
}
function finishKey(ssE, sk) {
	return hctr2Key(k(concat(ssE, sk), /* @__PURE__ */ new Uint8Array(0), "lexis-v3-finish"));
}
function edgeStart3(edge, gatePubB64, now = Date.now(), offer, token = "") {
	const ltRaw = unb64(edge.publicRawB64);
	if (ltRaw.length !== LT) throw new Error("edge 长期公钥必须是 32 字节 X25519");
	const ltS = unb64(gatePubB64);
	if (ltS.length !== LT) throw new Error("gate 长期公钥必须是 32 字节 X25519");
	const wordsIkm = gateIkm(token, ltS);
	const window = currentWindow(now);
	const eph = elligatorKeyPair();
	const es = sharedFromPub(eph.seed, ltS);
	const ikm = helloIkm(token, es);
	const nonceC = rand(16);
	const kdf = encodeKdf(clampKdf(offer));
	const features = featureByte(!!offer?.honey);
	const admit = k(ikm, /* @__PURE__ */ new Uint8Array(0), `admit-c|${window}`, 16);
	const pad = rand(rand(1)[0] % 48);
	const body = concat(admit, ltRaw, nonceC, kdf, new Uint8Array([features]), pad);
	const hk = hctr2Key(k(ikm, eph.rep, `hello|${window}`));
	const wire = concat(eph.rep, hctr2Encrypt(hk, tw("hello", window), body));
	return {
		eph,
		nonceC,
		window,
		helloWire: toWords(helloModel(wordsIkm), wire),
		ltRaw,
		ikm,
		features,
		wordsIkm,
		es
	};
}
async function gateRespond3(gate, peers, helloWire, opts = {}) {
	const ltS = unb64(gate.publicRawB64);
	if (ltS.length !== LT) return fail("point");
	let gateSeed;
	try {
		gateSeed = x25519SeedFromJwk(gate.privateJwk);
	} catch {
		return fail("point");
	}
	const wordsIkm = gateIkm(opts.token || "", ltS);
	let bytes;
	try {
		bytes = fromWords(helloModel(wordsIkm), helloWire);
	} catch {
		return fail("parse");
	}
	if (bytes.length < 101) fail("parse");
	const repC = bytes.slice(0, 32);
	const ct = bytes.subarray(32);
	const es = sharedFromRep(gateSeed, repC);
	const ikm = helloIkm(opts.token || "", es);
	let body = null;
	let window = 0;
	for (const w of windowCandidates(opts.now ?? Date.now())) {
		const pt = hctr2Decrypt(hctr2Key(k(ikm, repC, `hello|${w}`)), tw("hello", w), ct);
		if (constantTimeEqual(pt.subarray(0, 16), k(ikm, /* @__PURE__ */ new Uint8Array(0), `admit-c|${w}`, 16)) && !body) {
			body = pt;
			window = w;
		}
	}
	if (!body) return fail("admit");
	let o = 16;
	const ltC = body.slice(o, o += LT);
	const nonceC = body.slice(o, o += 16);
	const kdfC = decodeKdf(body, o);
	o += 4;
	const features = body[o] & 255;
	let peerId = null;
	for (const peer of peers) {
		if (!peer.publicRawB64) continue;
		const pinned = unb64(peer.publicRawB64);
		if (pinned.length === LT && constantTimeEqual(pinned, ltC) && peerId === null) peerId = peer.id || "";
	}
	if (peerId === null) return fail("peer");
	try {
		claimHello(window, nonceC, {
			peer: peerId,
			ip: opts.sourceIp || ""
		});
	} catch {
		return fail("replay");
	}
	let ssS;
	try {
		ssS = sharedFromPub(gateSeed, ltC);
	} catch {
		return fail("point");
	}
	const ephS = elligatorKeyPair();
	const ssE = sharedFromRep(ephS.seed, repC);
	const nonceS = rand(16);
	const agreed = clampKdf(opts.kdf ?? kdfC);
	const kdfBytes = encodeKdf(agreed);
	const sk = (await deriveSessionKeyAsync(ssE, ssS, nonceC, nonceS, window, features, agreed)).key;
	const tr = transcript({
		repC,
		repS: ephS.rep,
		ltC,
		ltS,
		window,
		nonceC,
		nonceS,
		kdf: kdfBytes,
		features
	});
	const confirmS = confirmS_(ssE, sk, tr);
	const seedS = rand(16);
	const ikmS = concat(ikm, ssE);
	const body2 = concat(k(ikmS, /* @__PURE__ */ new Uint8Array(0), `admit-s|${window}`, 16), nonceS, kdfBytes, new Uint8Array([features]), seedS, confirmS, rand(rand(1)[0] % 48));
	const hkS = hctr2Key(k(ikmS, ephS.rep, `server|${window}`));
	const wire = concat(ephS.rep, hctr2Encrypt(hkS, tw("server", window), body2));
	return {
		sk,
		window,
		ltC,
		peerId,
		nonceC,
		nonceS,
		kdf: agreed,
		features,
		serverWire: toWords(helloModel(wordsIkm), wire),
		ssE,
		seedS,
		tr
	};
}
async function edgeFinish3(edge, pending, gatePubB64, serverWire) {
	const fails = (why) => {
		throw new Error(`握手失败（${why}）`);
	};
	let bytes;
	try {
		bytes = fromWords(helloModel(pending.wordsIkm), serverWire);
	} catch {
		return fails("回包无法解析");
	}
	if (bytes.length < 101) fails("回包太短");
	const repS = bytes.slice(0, 32);
	const ssE = sharedFromRep(pending.eph.seed, repS);
	const ikmS = concat(pending.ikm, ssE);
	const w = pending.window;
	const body = hctr2Decrypt(hctr2Key(k(ikmS, repS, `server|${w}`)), tw("server", w), bytes.subarray(32));
	if (!constantTimeEqual(body.subarray(0, 16), k(ikmS, /* @__PURE__ */ new Uint8Array(0), `admit-s|${w}`, 16))) fails("闸门回包校验不过");
	let o = 16;
	const nonceS = body.slice(o, o += 16);
	const kdfBytes = body.slice(o, o + 4);
	const kdf = decodeKdf(body, o);
	o += 4;
	const features = body[o++] & 255;
	const seedS = body.slice(o, o += 16);
	const confirmS = body.slice(o, o + 16);
	const ltS = unb64(gatePubB64);
	const ssS = sharedFromPub(x25519SeedFromJwk(edge.privateJwk), ltS);
	const t0 = Date.now();
	const derived = await deriveSessionKeyAsync(ssE, ssS, pending.nonceC, nonceS, w, features, kdf);
	const kdfMs = Date.now() - t0;
	const sk = derived.key;
	const tr = transcript({
		repC: pending.eph.rep,
		repS,
		ltC: pending.ltRaw,
		ltS,
		window: w,
		nonceC: pending.nonceC,
		nonceS,
		kdf: kdfBytes,
		features
	});
	if (!constantTimeEqual(confirmS, confirmS_(ssE, sk, tr))) fails("密钥确认失败：会话密钥不一致");
	const seedC = rand(16);
	const mnemonicBase = mnemonicBaseOf(ssE, seedC, seedS);
	const keys = deriveV2Keys(sk, 0, mnemonicBase);
	return {
		sk,
		window: w,
		kdf,
		features,
		kdfMs,
		finishWire: sealFinish(ssE, sk, keys, w, seedC, confirmC_(mnemonicBase, tr)),
		keys,
		mnemonicBase
	};
}
function sealFinish(ssE, sk, keys, window, seedC, tag) {
	return toWords(keys.model, hctr2Encrypt(finishKey(ssE, sk), tw("finish", window), concat(seedC, tag, rand(rand(1)[0] % 32))));
}
/** Verifies the finish; returns the session keys and the per-handshake mnemonic base. */
function gateAccept3(pending, finishWire) {
	const wordKeys = deriveV2Keys(pending.sk, 0);
	let bytes;
	try {
		bytes = fromWords(wordKeys.model, finishWire);
	} catch {
		return fail("finish parse");
	}
	if (bytes.length < 32) fail("finish short");
	const pt = hctr2Decrypt(finishKey(pending.ssE, pending.sk), tw("finish", pending.window), bytes);
	const seedC = pt.slice(0, 16);
	const mnemonicBase = mnemonicBaseOf(pending.ssE, seedC, pending.seedS);
	if (!constantTimeEqual(pt.subarray(16, 32), confirmC_(mnemonicBase, pending.tr))) fail("finish");
	return {
		keys: deriveV2Keys(pending.sk, 0, mnemonicBase),
		mnemonicBase
	};
}
function currentWindow(now = Date.now()) {
	return Math.floor(now / 1e3 / SPEC.windowSec);
}
function windowRemain(now = Date.now()) {
	const sec = Math.floor(now / 1e3);
	return SPEC.windowSec - sec % SPEC.windowSec;
}
var seenHellos = /* @__PURE__ */ new Map();
var helloByPeer = /* @__PURE__ */ new Map();
var helloByIp = /* @__PURE__ */ new Map();
var HELLO_PEER_CAP = 16;
var HELLO_IP_CAP = 32;
function nonceId(nonce) {
	let hex = "";
	for (const b of nonce) hex += b.toString(16).padStart(2, "0");
	return hex;
}
function claimHello(window, nonce, scope) {
	const current = currentWindow();
	for (const key of [...seenHellos.keys()]) if (key < current - 1 || key > current + 1) seenHellos.delete(key);
	pruneHelloScope(helloByPeer, current);
	pruneHelloScope(helloByIp, current);
	let bag = seenHellos.get(window);
	if (!bag) {
		bag = /* @__PURE__ */ new Set();
		seenHellos.set(window, bag);
	}
	const id = nonceId(nonce);
	if (bag.has(id)) throw new LexisError("握手被重放");
	if (scope?.peer) bumpHelloScope(helloByPeer, scope.peer, window, HELLO_PEER_CAP, "这个节点的握手太密");
	if (scope?.ip) bumpHelloScope(helloByIp, scope.ip, window, HELLO_IP_CAP, "这个地址的握手太密");
	if (bag.size >= 4096) throw new LexisError("这个时间窗的握手太多");
	bag.add(id);
}
function pruneHelloScope(map, current) {
	for (const [key, row] of map) if (row.window < current - 1 || row.window > current + 1) map.delete(key);
}
function bumpHelloScope(map, key, window, cap, message) {
	const prev = map.get(key);
	const row = prev && prev.window === window ? prev : {
		window,
		n: 0
	};
	if (row.n >= cap) throw new LexisError(message);
	row.n += 1;
	map.set(key, row);
}
async function openSession(opts) {
	const lexicon = opts.lexicon ?? await sessionLexicon(opts.sk, opts.window);
	const inverse = opts.lexicon ? indexWords(lexicon) : invertLexicon(lexicon);
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
		gateFp: opts.gate.fingerprint,
		kdf: opts.kdf,
		honey: opts.honey,
		kdfMs: opts.kdfMs,
		program: opts.program ?? null,
		v2: opts.v2,
		v2MnemonicBase: opts.v2MnemonicBase
	};
}
function indexWords(words) {
	const map = /* @__PURE__ */ new Map();
	for (let i = 0; i < words.length; i++) map.set(words[i], i);
	return map;
}
/** Browser lab. Same Noise-NK handshake and HCTR2 frame keys as the 3.0.0 agent. */
async function establish3(edge, gate, now = Date.now(), offer, token = "") {
	if (edge.role !== "edge" || gate.role !== "gate") throw new LexisError("需要一个内网端和一个公网闸门");
	if (edge.pinnedPeerId !== gate.id || gate.pinnedPeerId !== edge.id) throw new LexisError("两端还没有互相绑定");
	const shared = token.trim();
	const bits = estimateTokenBits(shared);
	if (bits < 128) throw new LexisError(`握手口令熵不足（估约 ${bits} bit，需要至少 128）。在配置页生成一口令，两端写成同一个`);
	const started = edgeStart3(edge, gate.publicRawB64, now, offer, shared);
	let responded;
	try {
		responded = await gateRespond3(gate, [{
			id: edge.id,
			publicRawB64: edge.publicRawB64
		}], started.helloWire, {
			token: shared,
			kdf: offer ? clampKdf(offer) : void 0,
			now
		});
	} catch (err) {
		if (err instanceof HandshakeDrop) throw new LexisError("闸门丢弃了这次握手");
		throw err;
	}
	const finished = await edgeFinish3(edge, started, gate.publicRawB64, responded.serverWire);
	try {
		gateAccept3(responded, finished.finishWire);
	} catch (err) {
		if (err instanceof HandshakeDrop) throw new LexisError("闸门丢弃了结束握手");
		throw err;
	}
	if (!timingSafeEqual(finished.sk, responded.sk)) throw new LexisError("两端会话密钥不一致");
	return openSession({
		edge,
		gate,
		sk: finished.sk,
		window: finished.window,
		helloWire: started.helloWire,
		serverWire: responded.serverWire,
		finishWire: finished.finishWire,
		kdf: finished.kdf,
		honey: honeyFromFeatures(finished.features),
		kdfMs: finished.kdfMs,
		lexicon: finished.keys.model.words,
		v2: finished.keys,
		v2MnemonicBase: finished.mnemonicBase
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
var zstdReady = null;
function ensureZstd() {
	if (!zstdReady) zstdReady = (0, import_index_node.init)();
	return zstdReady;
}
function clampLevel(level) {
	if (!Number.isInteger(level) || level < 1) return 1;
	if (level > 19) return 19;
	return level;
}
/**
* Sender-side choice. The peer does not need this preference:
* the tag byte and the zstd frame header travel inside the plaintext.
* Level picks the window; the decompressor reads that window from the frame.
*/
async function packPayload(data, pref) {
	if (!pref.enabled) return {
		bytes: concat(new Uint8Array([0]), data),
		compressed: false,
		level: 0
	};
	await ensureZstd();
	const level = clampLevel(pref.level);
	const zipped = (0, import_index_node.compress)(data, level);
	if (zipped.length < data.length && zipped.length >= 4) return {
		bytes: concat(new Uint8Array([1]), zipped),
		compressed: true,
		level
	};
	return {
		bytes: concat(new Uint8Array([0]), data),
		compressed: false,
		level: 0
	};
}
/**
* After a successful open, look at the first plaintext byte.
* 0x00 is raw. 0x01 is a zstd frame; level and window are in that frame.
* Honey mode maps a broken frame onto a sentence from this byte string's own lexicon.
*/
async function unpackPayload(bytes, honey) {
	if (bytes.length >= 1 && bytes[0] === 0) return {
		data: bytes.subarray(1),
		compressed: false,
		honey: false
	};
	if (bytes.length >= 5 && bytes[0] === 1) try {
		await ensureZstd();
		return {
			data: (0, import_index_node.decompress)(bytes.subarray(1)),
			compressed: true,
			honey: false
		};
	} catch {
		if (!honey) throw new LexisError("zstd 帧解不开");
	}
	else if (!honey) throw new LexisError("明文类型字节不认识");
	return {
		data: utf8(await honeySentence(bytes)),
		compressed: false,
		honey: true
	};
}
/** Same sentence shape for every seed. Words come from that seed's lexicon, not the public list. */
async function honeySentence(seed) {
	const material = seed.length ? seed : utf8("empty");
	return honeyPhrase(material, 0, material);
}
var RECORD = {
	heartbeat: 1,
	data: 2,
	open: 3,
	close: 4,
	credit: 5,
	rekey: 6,
	/** v2: authenticated end of session. A close without it is a truncation. */
	end: 7
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
		case RECORD.credit: return "信用";
		case RECORD.rekey: return "换钥";
		default: return "未知";
	}
}
function heartbeatPayload(now = Date.now()) {
	return utf8(`hb ${now}`);
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
	const profile = useProfile((s) => s.profile);
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
			const next = await establish3(edge, gate, Date.now(), {
				...profile.kdf,
				honey: profile.honey
			}, profile.link.token);
			onSession(next);
			push({
				title: "会话密钥已按握手回声派生",
				meta: `3.0 · HCTR2 + rANS · Argon2id ${next.kdf.memoryKiB} KiB · t${next.kdf.iterations} · p${next.kdf.parallelism} · ${next.kdfMs} ms · 词表 ${next.lexicon.length} · ${next.honey ? "握手带蜜文标志" : "坏帧会拆掉会话"}`
			});
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
	async function frame(current, dir, plaintext) {
		if (!current.v2) throw new LexisError("这次会话没有 3.0 帧密钥");
		const packed = await packPayload(plaintext, profile.zstd);
		const counter = current.counters[dir] + 1;
		const batch = packBatch([{
			flag: 0,
			data: packed.bytes
		}]);
		const prose = sealV2({
			keys: current.v2,
			counter,
			window: current.window,
			dir,
			plaintext: batch,
			maxExpansion: profile.frame.maxExpansion,
			smallFramePolicy: profile.frame.smallFramePolicy
		});
		const segs = unpackBatch(openV2({
			keys: current.v2,
			counter,
			window: current.window,
			dir,
			prose
		}));
		if (segs.length !== 1 || segs[0].flag !== 0) throw new LexisError("这一帧不是一条完整记录");
		const unpacked = await unpackPayload(segs[0].data, false);
		return {
			prose,
			unpacked,
			next: {
				...current,
				counters: {
					...current.counters,
					[dir]: counter
				},
				seen: {
					...current.seen,
					[dir]: counter
				}
			},
			counter,
			sense: unpacked.compressed ? `对端看见类型 1，按帧头解开 zstd ${packed.level}` : "对端看见类型 0，按原文使用"
		};
	}
	async function transmit(dir, plaintext, title) {
		if (!session) throw new LexisError("还没有会话");
		const framed = await frame(session, dir, plaintext);
		onSession(framed.next);
		setLastFrame({
			prose: framed.prose,
			direction: dir,
			counter: framed.counter
		});
		const ent = entropyPair(framed.prose);
		const rec = decodeRecord(framed.unpacked.data);
		push({
			title,
			prose: framed.prose,
			meta: `${dir === "g2e" ? "闸门 → 内网" : "内网 → 闸门"} · 计数器 ${framed.counter} · ${recordLabel(rec.type)} · conn ${rec.conn} · seq ${rec.seq} · ${ent.nbytes} 字节 · 熵 ${ent.wire.toFixed(2)} · ${framed.sense}`,
			wire: ent.wire,
			random: ent.random
		});
		return {
			prose: framed.prose,
			payload: rec.payload,
			session: framed.next
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
				const framed = await frame(current, dir, encodeRecord(type, conn, seq, utf8(body)));
				current = framed.next;
				setLastFrame({
					prose: framed.prose,
					direction: dir,
					counter: framed.counter
				});
				const ent = entropyPair(framed.prose);
				const rec = decodeRecord(framed.unpacked.data);
				push({
					title,
					prose: framed.prose,
					meta: `${recordLabel(rec.type)} · ${ent.nbytes} B · 熵 ${ent.wire.toFixed(2)} / 随机 ${ent.random.toFixed(2)} · ${framed.sense} · 拆出 ${showPayload(rec.payload).replace(/\s+/g, " ").slice(0, 80)}`,
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
	async function wrongKey() {
		if (!session || !lastFrame) {
			setError("先发出一帧，再用一把错误密钥去拆");
			return;
		}
		setBusy(true);
		setError(null);
		try {
			if (!session.v2) throw new LexisError("这次会话没有 3.0 帧密钥");
			const view = openV2Honey({
				keys: deriveV2Keys(randomBytes(32)),
				counter: lastFrame.counter,
				window: session.window,
				dir: lastFrame.direction,
				prose: lastFrame.prose
			});
			push({
				title: "错误密钥没有还原这一帧",
				meta: `${view.formatValid ? "规范性检查碰巧通过（错误密钥大约 2%–3%）。正文仍不是原文。" : "规范性检查没过。错误密钥大约 97% 会这样。"} 单靠这一步就能确认候选会话密钥，蜜文挡不住。助记码 ${view.mnemonic.length} 字节，正文 ${view.body.length} 字节。`
			});
		} catch (err) {
			push({
				title: "错误密钥没有按预期解开",
				meta: err instanceof Error ? err.message : "拆不开",
				bad: true
			});
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
			if (!session.v2) throw new LexisError("这次会话没有 3.0 帧密钥");
			openV2({
				keys: session.v2,
				counter: lastFrame.counter,
				window: session.window + 1,
				dir: lastFrame.direction,
				prose: lastFrame.prose
			});
			setError("这一帧居然被下一窗拆开了。不该发生。");
		} catch (err) {
			if (err instanceof FrameError || err instanceof LexisError) push({
				title: "下一时间窗拒绝了上一帧",
				meta: err.message,
				bad: true
			});
			else setError(err instanceof Error ? err.message : "拆不开");
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
									children: "会话密钥 · Argon2id"
								}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("dd", {
									className: "break-all font-mono text-xs",
									children: session.skFp
								})] }),
								/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("dt", {
									className: "text-mist",
									children: "派生"
								}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("dd", {
									className: "font-mono text-xs",
									children: [
										session.kdf.memoryKiB,
										" KiB · t",
										session.kdf.iterations,
										" · p",
										session.kdf.parallelism,
										" · ",
										session.kdfMs,
										" ms ·",
										" ",
										profile.frame.smallFramePolicy === "honey" ? "小帧按蜜文填充" : "小帧优先压膨胀",
										" · 预算 ",
										profile.frame.maxExpansion,
										"×"
									]
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
									disabled: !session || busy || !lastFrame,
									onClick: () => void wrongKey(),
									children: "用错误密钥拆上一帧"
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
function parseKeyHex(text) {
	const cleaned = text.trim().toLowerCase();
	if (!/^[0-9a-f]{64}$/.test(cleaned)) return null;
	const out = /* @__PURE__ */ new Uint8Array(32);
	for (let i = 0; i < 32; i += 1) out[i] = Number.parseInt(cleaned.slice(i * 2, i * 2 + 2), 16);
	return out;
}
function parseIndices(text) {
	const parts = text.trim().split(/\s+/).map((item) => Number(item));
	if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n >= SPEC.lexiconSize)) return null;
	return [
		parts[0],
		parts[1],
		parts[2],
		parts[3]
	];
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
	const [minting, setMinting] = (0, import_react.useState)(false);
	const [coverKey, setCoverKey] = (0, import_react.useState)("");
	const [coverIdx, setCoverIdx] = (0, import_react.useState)("4 8 15 16");
	const [coverKey2, setCoverKey2] = (0, import_react.useState)("");
	const [coverIdx2, setCoverIdx2] = (0, import_react.useState)("");
	const [coverError, setCoverError] = (0, import_react.useState)(null);
	const [covering, setCovering] = (0, import_react.useState)(false);
	const hit = matchRoute(profile, {
		host,
		ip,
		process: proc
	});
	const issues = profileIssues(profile);
	async function sealCover() {
		const first = parseKeyHex(coverKey);
		const idx = parseIndices(coverIdx);
		if (!first || !idx) {
			setCoverError("第一把密钥要 64 位十六进制，词序要四个 0 到 4095 的整数");
			return;
		}
		const entries = [{
			key: first,
			block: packIndices(idx)
		}];
		if (coverKey2.trim() || coverIdx2.trim()) {
			const second = parseKeyHex(coverKey2);
			const idx2 = parseIndices(coverIdx2);
			if (!second || !idx2) {
				setCoverError("第二把密钥或词序没写全");
				return;
			}
			entries.push({
				key: second,
				block: packIndices(idx2)
			});
		}
		setCovering(true);
		setCoverError(null);
		try {
			const program = await compileBlocks(entries, 4);
			patch({ honeyProgram: programToStored(program) });
			setCoverKey("");
			setCoverKey2("");
		} catch (err) {
			setCoverError(err instanceof Error ? err.message : "封存失败");
		} finally {
			setCovering(false);
		}
	}
	function setInbounds(inbounds) {
		patch({ inbounds });
	}
	async function mintIdentity() {
		setMinting(true);
		try {
			const ident = await createIdentity();
			patch({
				identity: {
					id: crypto.randomUUID(),
					name: profile.name || "本机",
					publicJwk: ident.publicJwk,
					privateJwk: ident.privateJwk,
					publicRawB64: b64(ident.publicRaw),
					fingerprint: ident.fingerprint
				},
				seal: null
			});
		} finally {
			setMinting(false);
		}
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
									children: [
										profile.role === "" ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("option", {
											value: "",
											children: "要指定"
										}) : null,
										/* @__PURE__ */ (0, import_jsx_runtime.jsx)("option", {
											value: "edge",
											children: "边缘客户端"
										}),
										/* @__PURE__ */ (0, import_jsx_runtime.jsx)("option", {
											value: "gate",
											children: "公网闸门"
										})
									]
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
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
						className: "mt-2 text-sm text-mist",
						children: "常驻进程不接受缺省角色，要写成边缘或闸门。控制台里新建一份时仍默认是边缘。"
					})
				]
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("section", {
				className: "rounded-md border border-line bg-panel p-4",
				children: [
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h2", {
						className: "text-base font-medium",
						children: "密钥与压缩"
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
						className: "mt-2 text-sm text-mist",
						children: "会话密钥的 Argon2id 由常驻进程自己的参数决定，不听客户端把内存抬高。上限 16384 KiB。口令不对的问候在派生之前就被丢掉。长期私钥的封存在节点页，用另一档 65536 KiB、3 次迭代。系数不写进这份配置。"
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
						className: "mt-2 text-sm text-mist",
						children: "压缩不靠这份配置在对端对齐。明文第一个字节是类型：0 是原文，1 是 zstd 帧。等级决定窗口，窗口写在帧头里，对端解开以后自己读。比原文更大时这一帧会改回类型 0。"
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
						className: "mt-2 text-sm text-mist",
						children: "蜜文只挡对长期私钥和口令的暴力猜测。它不挡已经拿到候选会话密钥的人：一帧词重编码回去，对的密钥对得上，错的密钥大约只有 2%–3% 对得上。握手确认用临时密钥的共享秘密来算。两端的蜜文开关要写成一样，它会进入会话密钥；帧本身不再把坏帧落成另一句词。封面系数仍按旧的句式封存，3.0 的线上帧不用这句式。长期私钥的封存在节点页。这一版和 2.0 及更早的对端对不上。"
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
						className: "mt-4 grid gap-3 sm:grid-cols-3",
						children: [
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
								label: "Argon2 内存 KiB",
								children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("select", {
									className: control,
									value: profile.kdf.memoryKiB,
									onChange: (e) => patch({ kdf: clampKdf({
										...profile.kdf,
										memoryKiB: Number(e.target.value)
									}) }),
									children: [
										1024,
										4096,
										8192,
										16384
									].map((n) => /* @__PURE__ */ (0, import_jsx_runtime.jsx)("option", {
										value: n,
										children: n
									}, n))
								})
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
								label: "迭代",
								children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("select", {
									className: control,
									value: profile.kdf.iterations,
									onChange: (e) => patch({ kdf: clampKdf({
										...profile.kdf,
										iterations: Number(e.target.value)
									}) }),
									children: [
										1,
										2,
										3,
										4
									].map((n) => /* @__PURE__ */ (0, import_jsx_runtime.jsx)("option", {
										value: n,
										children: n
									}, n))
								})
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
								label: "并行",
								children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("select", {
									className: control,
									value: profile.kdf.parallelism,
									onChange: (e) => patch({ kdf: clampKdf({
										...profile.kdf,
										parallelism: Number(e.target.value)
									}) }),
									children: [1, 2].map((n) => /* @__PURE__ */ (0, import_jsx_runtime.jsx)("option", {
										value: n,
										children: n
									}, n))
								})
							})
						]
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
						className: "mt-4 flex flex-wrap gap-2",
						children: [
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Btn, {
								kind: profile.honey ? "solid" : "ghost",
								onClick: () => patch({ honey: true }),
								children: "蜜文打开"
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Btn, {
								kind: !profile.honey ? "solid" : "ghost",
								onClick: () => patch({ honey: false }),
								children: "蜜文关闭"
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Btn, {
								kind: profile.zstd.enabled ? "solid" : "ghost",
								onClick: () => patch({ zstd: {
									...profile.zstd,
									enabled: true
								} }),
								children: "发送时尝试 zstd"
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Btn, {
								kind: !profile.zstd.enabled ? "solid" : "ghost",
								onClick: () => patch({ zstd: {
									...profile.zstd,
									enabled: false
								} }),
								children: "不压缩"
							})
						]
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
						className: "mt-4 grid gap-3",
						children: [
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
								className: "text-sm text-mist",
								children: "封面系数按旧的四词句式封存。3.0 的线上帧不再读这句式。密钥写成 64 位十六进制。封存之后只留系数。长期私钥的封存在节点页，任意口令都会解开一把合法的 X25519 私钥。"
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
								label: "密钥",
								children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
									className: control,
									value: coverKey,
									autoComplete: "off",
									spellCheck: false,
									placeholder: "64 位十六进制",
									"aria-label": "封面密钥",
									onChange: (e) => setCoverKey(e.target.value)
								})
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
								label: "词序",
								children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
									className: control,
									value: coverIdx,
									autoComplete: "off",
									"aria-label": "封面词序",
									onChange: (e) => setCoverIdx(e.target.value)
								})
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
								label: "第二把密钥",
								children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
									className: control,
									value: coverKey2,
									autoComplete: "off",
									spellCheck: false,
									placeholder: "可留空",
									"aria-label": "第二把封面密钥",
									onChange: (e) => setCoverKey2(e.target.value)
								})
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
								label: "第二组词序",
								children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
									className: control,
									value: coverIdx2,
									autoComplete: "off",
									placeholder: "可留空",
									"aria-label": "第二组封面词序",
									onChange: (e) => setCoverIdx2(e.target.value)
								})
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
								className: "flex flex-wrap gap-2",
								children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Btn, {
									kind: "ghost",
									disabled: covering || !coverKey.trim(),
									onClick: () => void sealCover(),
									children: covering ? "封存中" : "把封面写进同一条求值"
								}), profile.honeyProgram ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Btn, {
									kind: "ghost",
									onClick: () => patch({ honeyProgram: null }),
									children: "清掉封面系数"
								}) : null]
							}),
							profile.honeyProgram ? /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", {
								className: "text-sm text-mist",
								children: [
									"已封存 ",
									profile.honeyProgram.coeffsB64.length,
									" 个系数。密钥没有留下。导出配置会带上这组系数。"
								]
							}) : /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
								className: "text-sm text-mist",
								children: "还没有封面系数。不封存时，蜜文句子仍从这把密钥和当前时间窗的词表里取，只是词序不由你指定。"
							}),
							coverError ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
								className: "text-sm text-ember",
								children: coverError
							}) : null
						]
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
						className: "mt-4 max-w-xs",
						children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
							label: "zstd 等级",
							children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("select", {
								className: control,
								value: profile.zstd.level,
								onChange: (e) => patch({ zstd: {
									...profile.zstd,
									level: Number(e.target.value)
								} }),
								children: [
									1,
									3,
									6,
									9,
									19
								].map((n) => /* @__PURE__ */ (0, import_jsx_runtime.jsx)("option", {
									value: n,
									children: n
								}, n))
							})
						})
					})
				]
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("section", {
				className: "rounded-md border border-line bg-panel p-4",
				children: [
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h2", {
						className: "text-base font-medium",
						children: "链路"
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
						className: "mt-2 text-sm text-mist",
						children: "常驻进程和这条控制台用同一套 3.0 帧。握手是 X25519，问候用临时密钥和闸门长期公钥的共享秘密加密。TCP、TLS、WebSocket 只负责协议和头，用来过 CDN。路径默认 /lexis。CDN 若自己终结 TLS，源站可以听 WebSocket。"
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
						className: "mt-2 text-sm text-mist",
						children: "一条会话上可以开多路。打开写成 tcp 主机 端口、udp 主机 端口、relay 节点 再接后面的命令，或 expose 服务名。中继和出口都要逐个节点打开。暴露不能经中继绕过去。跳数到 4 就停。慢的那一路只堵住自己。SOCKS 的用户名和密码留空就是不认证，HTTP 代理共用这一对。"
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
						className: "mt-4 flex flex-wrap gap-2",
						children: [
							"tcp",
							"tls",
							"ws",
							"wss"
						].map((name) => /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Btn, {
							kind: profile.outer.transport === name ? "solid" : "ghost",
							onClick: () => patch({ outer: {
								...profile.outer,
								transport: name
							} }),
							children: name
						}, name))
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
						className: "mt-4 grid gap-3 sm:grid-cols-2",
						children: [
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
								label: "握手口令",
								children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
									className: control,
									autoComplete: "off",
									spellCheck: false,
									value: profile.link.token,
									onChange: (e) => patch({ link: {
										...profile.link,
										token: e.target.value
									} })
								})
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
								className: "text-sm text-mist",
								children: "口令"
							}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
								className: "mt-2",
								children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Btn, {
									kind: "ghost",
									onClick: () => patch({ link: {
										...profile.link,
										token: mintHandshakeToken()
									} }),
									children: "生成 128 bit 口令"
								})
							})] }),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
								label: "同时握手数",
								children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
									className: control,
									inputMode: "numeric",
									value: profile.link.maxHandshakes,
									onChange: (e) => patch({ link: {
										...profile.link,
										maxHandshakes: Number(e.target.value)
									} })
								})
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
								label: "握手超时（秒）",
								children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
									className: control,
									inputMode: "numeric",
									value: Math.round(profile.link.handshakeMs / 1e3),
									onChange: (e) => patch({ link: {
										...profile.link,
										handshakeMs: Math.round(Number(e.target.value) * 1e3)
									} })
								})
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
								label: "拨号超时（秒）",
								children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
									className: control,
									inputMode: "numeric",
									value: Math.round(profile.link.dialMs / 1e3),
									onChange: (e) => patch({ link: {
										...profile.link,
										dialMs: Math.round(Number(e.target.value) * 1e3)
									} })
								})
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
								label: "WebSocket 路径",
								children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
									className: control,
									value: profile.outer.wsPath,
									onChange: (e) => patch({ outer: {
										...profile.outer,
										wsPath: e.target.value
									} })
								})
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
								className: "text-sm text-mist",
								children: "校验证书"
							}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
								className: "mt-2 flex flex-wrap gap-2",
								children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Btn, {
									kind: profile.outer.tlsVerify ? "solid" : "ghost",
									onClick: () => patch({ outer: {
										...profile.outer,
										tlsVerify: true
									} }),
									children: "校验"
								}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Btn, {
									kind: !profile.outer.tlsVerify ? "solid" : "ghost",
									onClick: () => patch({ outer: {
										...profile.outer,
										tlsVerify: false
									} }),
									children: "实验室自签"
								})]
							})] }),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
								label: "SOCKS 用户名",
								children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
									className: control,
									autoComplete: "off",
									value: profile.socksAuth.user,
									onChange: (e) => patch({ socksAuth: {
										...profile.socksAuth,
										user: e.target.value
									} })
								})
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
								label: "SOCKS 密码",
								children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
									className: control,
									type: "password",
									autoComplete: "off",
									value: profile.socksAuth.pass,
									onChange: (e) => patch({ socksAuth: {
										...profile.socksAuth,
										pass: e.target.value
									} })
								})
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
								label: "半开上限",
								children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
									className: control,
									inputMode: "numeric",
									value: profile.link.maxHalfOpen,
									onChange: (e) => patch({ link: {
										...profile.link,
										maxHalfOpen: Number(e.target.value)
									} })
								})
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
								label: "每地址半开",
								children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
									className: control,
									inputMode: "numeric",
									value: profile.link.maxHalfOpenPerIp,
									onChange: (e) => patch({ link: {
										...profile.link,
										maxHalfOpenPerIp: Number(e.target.value)
									} })
								})
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
								label: "UDP 空闲（秒）",
								children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
									className: control,
									inputMode: "numeric",
									value: Math.round(profile.link.udpIdleMs / 1e3),
									onChange: (e) => patch({ link: {
										...profile.link,
										udpIdleMs: Math.round(Number(e.target.value) * 1e3)
									} })
								})
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
								label: "UDP 路数",
								children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
									className: control,
									inputMode: "numeric",
									value: profile.link.udpMax,
									onChange: (e) => patch({ link: {
										...profile.link,
										udpMax: Number(e.target.value)
									} })
								})
							})
						]
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", {
						className: "mt-2 text-sm text-mist",
						children: [
							"握手口令在 Argon2 之前参与问候。估约 ",
							estimateTokenBits(profile.link.token.trim()),
							" bit，需要至少 128。两端写成同一个。手写短口令会被常驻进程拒绝。半开超限的连接和坏问候一样，等到握手超时再关，外面看不出差别。校验关掉时，外层 TLS 认不出对端，正式部署请换自己的证书。"
						]
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
						className: "mt-4 rounded-sm bg-panel-2 p-3",
						children: [
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
								className: "text-sm text-mist",
								children: "本机身份"
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
								className: "mt-2 break-all font-mono text-xs text-fg",
								children: profile.identity?.fingerprint || "还没有"
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
								className: "mt-3 flex flex-wrap gap-2",
								children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Btn, {
									kind: "ghost",
									disabled: minting,
									onClick: () => void mintIdentity(),
									children: minting ? "生成中" : profile.identity ? "换一把常驻身份" : "生成本机身份"
								}), profile.identity ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Btn, {
									kind: "ember",
									onClick: () => patch({ identity: null }),
									children: "清掉身份"
								}) : null]
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
								className: "mt-2 text-sm text-mist",
								children: "导出配置会带上这把私钥。只放到你自己的常驻进程里。对端只需要公钥。"
							})
						]
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
						className: "mt-4",
						children: [
							/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
								className: "flex items-center justify-between gap-3",
								children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h3", {
									className: "text-sm font-medium",
									children: "加入的节点"
								}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Btn, {
									kind: "ghost",
									onClick: () => patch({ peers: [...profile.peers, {
										id: rid("peer"),
										name: "节点",
										endpoint: profile.peerEndpoint,
										transport: profile.outer.transport,
										publicRawB64: "",
										wsPath: profile.outer.wsPath,
										wsHost: "",
										relay: false,
										exit: false,
										targets: []
									}] }),
									children: "添加节点"
								})]
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
								className: "mt-2 text-sm text-mist",
								children: "默认不借本机中继。要借，就在那个节点上打开，并可以限定目标。地址写成 主机:端口。WebSocket 主机名留给 CDN，空着就用地址里的主机。"
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
								className: "mt-3 flex flex-col gap-3",
								children: profile.peers.map((peer) => /* @__PURE__ */ (0, import_jsx_runtime.jsx)(PeerEditor, {
									peer,
									onChange: (next) => patch({ peers: profile.peers.map((item) => item.id === peer.id ? next : item) }),
									onRemove: () => patch({ peers: profile.peers.filter((item) => item.id !== peer.id) })
								}, peer.id))
							})
						]
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
						className: "mt-4 text-sm text-mist",
						children: "闸门拨号前会解析域名。回环、内网、链路本地、运营商级 NAT 和文档地址默认拒绝。白名单写成主机、主机:端口或 IPv4 网段。这道拦截不作用于本机 SOCKS 的直连和绕行。公网端口不单独封禁。"
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
						className: "mt-4 grid gap-3 sm:grid-cols-2",
						children: [
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
								label: "空闲超时（秒）",
								children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
									className: control,
									inputMode: "numeric",
									value: Math.round(profile.link.idleMs / 1e3),
									onChange: (e) => patch({ link: {
										...profile.link,
										idleMs: Math.round(Number(e.target.value) * 1e3)
									} })
								})
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
								label: "连接上限",
								children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
									className: control,
									inputMode: "numeric",
									value: profile.link.maxConns,
									onChange: (e) => patch({ link: {
										...profile.link,
										maxConns: Number(e.target.value)
									} })
								})
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
								className: "text-sm text-mist",
								children: "内网拦截"
							}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
								className: "mt-2 flex flex-wrap gap-2",
								children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Btn, {
									kind: profile.egress.blockPrivate ? "solid" : "ghost",
									onClick: () => patch({ egress: {
										...profile.egress,
										blockPrivate: true
									} }),
									children: "拦截"
								}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Btn, {
									kind: !profile.egress.blockPrivate ? "solid" : "ghost",
									onClick: () => patch({ egress: {
										...profile.egress,
										blockPrivate: false
									} }),
									children: "放行"
								})]
							})] })
						]
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
						className: "mt-4",
						children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
							label: "出站白名单，一行一条",
							children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(AllowList, {
								allow: profile.egress.allow,
								onChange: (allow) => patch({ egress: {
									...profile.egress,
									allow
								} })
							})
						})
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
						className: "mt-4 flex flex-wrap gap-2",
						children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Btn, {
							kind: profile.link.allowLan ? "solid" : "ghost",
							onClick: () => patch({ link: {
								...profile.link,
								allowLan: true
							} }),
							children: "允许局域网监听"
						}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Btn, {
							kind: !profile.link.allowLan ? "solid" : "ghost",
							onClick: () => patch({ link: {
								...profile.link,
								allowLan: false
							} }),
							children: "只监听回环"
						})]
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
						className: "mt-2 text-sm text-mist",
						children: profile.link.allowLan ? "SOCKS 和固定转发会按填写的地址监听，可能暴露到局域网。" : "SOCKS 和固定转发强制绑在回环。隧道入口仍按填写的地址监听，方便以后做端口映射。"
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
						className: "mt-4 max-w-md",
						children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
							label: "状态口令",
							children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
								className: control,
								value: profile.statusToken,
								autoComplete: "off",
								placeholder: "回环上可留空",
								onChange: (e) => patch({ statusToken: e.target.value })
							})
						})
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
						className: "mt-2 text-sm text-mist",
						children: "状态页离开回环时，指标和页面要带这句口令。健康检查不带。没有口令又没有允许局域网时，状态页改绑回环。"
					})
				]
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("section", {
				className: "rounded-md border border-line bg-panel p-4",
				children: [
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h2", {
						className: "text-base font-medium",
						children: "帧"
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
						className: "mt-2 text-sm text-mist",
						children: "膨胀预算是线上字节相对压缩后正文的倍数，默认 5，范围 1 到 16。大约 256 字节以下的单发帧仍会超过这个倍数，常驻进程把同一时刻的小记录并进一帧。合并阈值默认 1024 字节，只给常驻进程；浏览器里每次封装单独成帧。"
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
						className: "mt-2 text-sm text-mist",
						children: "小帧策略默认「压膨胀」：预算内才填充，短帧常常不填。改成「蜜文填充」后，短帧也在 0 到 255 字节里取填充，填充占比更接近一把错误密钥解出来的样子，短帧会胀得更大。这是发送端的选择，两端可以不一样。"
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
						className: "mt-4 grid gap-3 sm:grid-cols-2",
						children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
							label: "线上膨胀预算",
							children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("select", {
								className: control,
								value: profile.frame.maxExpansion,
								onChange: (e) => patch({ frame: {
									...profile.frame,
									maxExpansion: Number(e.target.value)
								} }),
								children: [
									1,
									2,
									3,
									4,
									5,
									8,
									12,
									16
								].map((n) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("option", {
									value: n,
									children: [n, "×"]
								}, n))
							})
						}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
							label: "合并阈值（字节）",
							children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
								className: control,
								inputMode: "numeric",
								value: profile.frame.coalesceTarget,
								onChange: (e) => patch({ frame: {
									...profile.frame,
									coalesceTarget: Number(e.target.value)
								} })
							})
						})]
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
						className: "mt-4 flex flex-wrap gap-2",
						children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Btn, {
							kind: profile.frame.smallFramePolicy === "expansion" ? "solid" : "ghost",
							onClick: () => patch({ frame: {
								...profile.frame,
								smallFramePolicy: "expansion"
							} }),
							children: "小帧压膨胀"
						}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Btn, {
							kind: profile.frame.smallFramePolicy === "honey" ? "solid" : "ghost",
							onClick: () => patch({ frame: {
								...profile.frame,
								smallFramePolicy: "honey"
							} }),
							children: "小帧蜜文填充"
						})]
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
										value: "http",
										children: "HTTP 代理"
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
					/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
						className: "flex items-center justify-between gap-3",
						children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h2", {
							className: "text-base font-medium",
							children: "暴露给已经连上的节点"
						}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Btn, {
							kind: "ghost",
							onClick: () => patch({ exposes: [...profile.exposes, {
								id: rid("expose"),
								name: "ssh",
								host: "127.0.0.1",
								port: 22,
								allow: []
							}] }),
							children: "添加服务"
						})]
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
						className: "mt-2 text-sm text-mist",
						children: "NAT 后面的机器主动连出去之后，对端可以按服务名过来。允许名单写节点的名字或编号，空着谁也不让进。这里拨的是你自己填的本机地址，不走公网出站拦截。"
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
						className: "mt-4 flex flex-col gap-3",
						children: profile.exposes.map((door) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
							className: "grid gap-2 rounded-sm bg-panel-2 p-3 sm:grid-cols-2",
							children: [
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
									className: control,
									"aria-label": "服务名",
									value: door.name,
									onChange: (e) => patch({ exposes: profile.exposes.map((item) => item.id === door.id ? {
										...item,
										name: e.target.value
									} : item) })
								}),
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
									className: control,
									"aria-label": "本机主机",
									value: door.host,
									onChange: (e) => patch({ exposes: profile.exposes.map((item) => item.id === door.id ? {
										...item,
										host: e.target.value
									} : item) })
								}),
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
									className: control,
									"aria-label": "本机端口",
									inputMode: "numeric",
									value: door.port,
									onChange: (e) => patch({ exposes: profile.exposes.map((item) => item.id === door.id ? {
										...item,
										port: Number(e.target.value)
									} : item) })
								}),
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
									className: control,
									"aria-label": "允许的节点",
									placeholder: "节点名，逗号分开",
									value: door.allow.join(", "),
									onChange: (e) => patch({ exposes: profile.exposes.map((item) => item.id === door.id ? {
										...item,
										allow: e.target.value.split(",").map((part) => part.trim()).filter(Boolean)
									} : item) })
								}),
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Btn, {
									kind: "ember",
									onClick: () => patch({ exposes: profile.exposes.filter((item) => item.id !== door.id) }),
									children: "删除"
								})
							]
						}, door.id))
					})
				]
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("section", {
				className: "rounded-md border border-line bg-panel p-4",
				children: [
					/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
						className: "flex items-center justify-between gap-3",
						children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h2", {
							className: "text-base font-medium",
							children: "反向入口"
						}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Btn, {
							kind: "ghost",
							onClick: () => patch({ reverses: [...profile.reverses, {
								id: rid("rev"),
								listen: "127.0.0.1",
								port: 2222,
								peer: "",
								service: "ssh"
							}] }),
							children: "添加入口"
						})]
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
						className: "mt-2 text-sm text-mist",
						children: "公网这一侧听一个端口，从那个节点已经连进来的会话里打开同名服务。没有允许局域网时，写成 0.0.0.0 也会改绑回环，并且和别的入站共用连接数上限。会话不在时会说没有来自该节点的会话。"
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
						className: "mt-4 flex flex-col gap-3",
						children: profile.reverses.map((door) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
							className: "grid gap-2 rounded-sm bg-panel-2 p-3 sm:grid-cols-2",
							children: [
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
									className: control,
									"aria-label": "反向监听地址",
									value: door.listen,
									onChange: (e) => patch({ reverses: profile.reverses.map((item) => item.id === door.id ? {
										...item,
										listen: e.target.value
									} : item) })
								}),
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
									className: control,
									"aria-label": "反向端口",
									inputMode: "numeric",
									value: door.port,
									onChange: (e) => patch({ reverses: profile.reverses.map((item) => item.id === door.id ? {
										...item,
										port: Number(e.target.value)
									} : item) })
								}),
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
									className: control,
									"aria-label": "节点",
									placeholder: "节点名或编号",
									value: door.peer,
									onChange: (e) => patch({ reverses: profile.reverses.map((item) => item.id === door.id ? {
										...item,
										peer: e.target.value
									} : item) })
								}),
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
									className: control,
									"aria-label": "服务名",
									value: door.service,
									onChange: (e) => patch({ reverses: profile.reverses.map((item) => item.id === door.id ? {
										...item,
										service: e.target.value
									} : item) })
								}),
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Btn, {
									kind: "ember",
									onClick: () => patch({ reverses: profile.reverses.filter((item) => item.id !== door.id) }),
									children: "删除"
								})
							]
						}, door.id))
					})
				]
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
								body: "redirect、tproxy 或虚拟网卡。需要 root 才会改规则，并读取原始目的地址。",
								children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("select", {
									className: control,
									value: profile.linux.method,
									onChange: (e) => patch({ linux: {
										...profile.linux,
										method: e.target.value
									} }),
									children: [
										/* @__PURE__ */ (0, import_jsx_runtime.jsx)("option", {
											value: "redirect",
											children: "redirect"
										}),
										/* @__PURE__ */ (0, import_jsx_runtime.jsx)("option", {
											value: "tproxy",
											children: "tproxy"
										}),
										/* @__PURE__ */ (0, import_jsx_runtime.jsx)("option", {
											value: "tun",
											children: "虚拟网卡"
										})
									]
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
								body: "portproxy 只绑回环。WinDivert 只有源码，驱动不在包里，选了也不会改系统流量。",
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
								body: "写出会话和本机包通道。VpnService 只有源码，Termux 不能弹出系统 VPN。",
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
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
				className: "flex flex-wrap gap-2",
				children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Btn, {
					onClick: () => downloadJson("lexis.config.json", exportedConfig(profile)),
					children: "导出配置"
				}), profile.seal ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Btn, {
					kind: "ghost",
					onClick: () => downloadJson("lexis.seal.json", sealFileOf(profile.seal)),
					children: "导出封存"
				}) : null]
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
				className: "text-sm text-mist",
				children: "没有封存时，配置里带着本机私钥。封存之后，导出的配置去掉标量，系数在另一个文件 lexis.seal.json。两个文件不要合成一个：公钥写在对端名单里，和系数放在一起就能离线试口令。放到常驻目录后，权限应收成仅本人可读。口令用环境变量 LEXIS_PASSPHRASE，或同目录的 lexis.passphrase。常驻进程不会拿解开的公钥去对配置里的公钥。"
			})
		]
	});
}
function PeerEditor({ peer, onChange, onRemove }) {
	const [targetsText, setTargetsText] = (0, import_react.useState)((peer.targets || []).join("\n"));
	const [targetsFocus, setTargetsFocus] = (0, import_react.useState)(false);
	(0, import_react.useEffect)(() => {
		if (!targetsFocus) setTargetsText((peer.targets || []).join("\n"));
	}, [peer.targets, targetsFocus]);
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
		className: "grid gap-2 rounded-sm bg-panel-2 p-3",
		children: [
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
				className: "grid gap-2 sm:grid-cols-2",
				children: [
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
						className: control,
						"aria-label": "节点名称",
						value: peer.name,
						onChange: (e) => onChange({
							...peer,
							name: e.target.value
						})
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
						className: control,
						"aria-label": "节点地址",
						placeholder: "主机:端口",
						value: peer.endpoint,
						onChange: (e) => onChange({
							...peer,
							endpoint: e.target.value
						})
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("select", {
						className: control,
						"aria-label": "外层协议",
						value: peer.transport,
						onChange: (e) => onChange({
							...peer,
							transport: e.target.value
						}),
						children: [
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)("option", {
								value: "tcp",
								children: "tcp"
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)("option", {
								value: "tls",
								children: "tls"
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)("option", {
								value: "ws",
								children: "ws"
							}),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)("option", {
								value: "wss",
								children: "wss"
							})
						]
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
						className: control,
						"aria-label": "WebSocket 主机",
						placeholder: "CDN 主机名，可空",
						value: peer.wsHost,
						onChange: (e) => onChange({
							...peer,
							wsHost: e.target.value
						})
					})
				]
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsx)("textarea", {
				className: "min-h-20 w-full rounded-sm border border-line bg-ink px-3 py-3 font-mono text-xs text-fg",
				"aria-label": "节点公钥",
				placeholder: "公钥",
				value: peer.publicRawB64,
				onChange: (e) => onChange({
					...peer,
					publicRawB64: e.target.value.trim()
				})
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
				className: "flex flex-wrap gap-2",
				children: [
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Btn, {
						kind: peer.relay ? "solid" : "ghost",
						onClick: () => onChange({
							...peer,
							relay: !peer.relay
						}),
						children: peer.relay ? "允许借本机中继" : "不借本机中继"
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Btn, {
						kind: peer.exit ? "solid" : "ghost",
						onClick: () => onChange({
							...peer,
							exit: !peer.exit
						}),
						children: peer.exit ? "允许把本机当出口" : "不把本机当出口"
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Btn, {
						kind: "ember",
						onClick: onRemove,
						children: "移出名单"
					})
				]
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsx)("textarea", {
				className: "min-h-16 w-full rounded-sm border border-line bg-ink px-3 py-3 font-mono text-xs text-fg",
				"aria-label": "中继目标",
				placeholder: "允许的目标，一行一条。空着表示不限制。例如 tcp 203.0.113.8 22",
				value: targetsText,
				onFocus: () => setTargetsFocus(true),
				onBlur: () => {
					setTargetsFocus(false);
					onChange({
						...peer,
						targets: targetsText.split("\n").map((item) => item.trim()).filter(Boolean)
					});
				},
				onChange: (e) => setTargetsText(e.target.value)
			})
		]
	});
}
function AllowList({ allow, onChange }) {
	const [text, setText] = (0, import_react.useState)(allow.join("\n"));
	const [focused, setFocused] = (0, import_react.useState)(false);
	(0, import_react.useEffect)(() => {
		if (!focused) setText(allow.join("\n"));
	}, [allow, focused]);
	return /* @__PURE__ */ (0, import_jsx_runtime.jsx)("textarea", {
		className: "min-h-24 w-full rounded-sm border border-line bg-ink px-3 py-3 font-mono text-sm text-fg",
		value: text,
		onFocus: () => setFocused(true),
		onBlur: () => {
			setFocused(false);
			onChange(text.split(/\r?\n/).map((line) => line.trim()).filter(Boolean));
		},
		onChange: (e) => setText(e.target.value)
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
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
					className: "mt-2 text-sm text-mist",
					children: "握手之后这里是这把会话密钥打乱过的英文词序，大约三万词，只在频次接近的词之间换位置。它不是公开的音节表。静态按钮仍会生成旧的握手音节表，只作对照，线上帧不用它。词表来自 FrequencyWords，许可是 CC BY-SA 4.0。"
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
function readKdf(value) {
	if (!value || typeof value !== "object") return null;
	const raw = value;
	if (typeof raw.saltB64 !== "string" || !raw.saltB64) return null;
	return {
		saltB64: raw.saltB64,
		...clampVaultKdf(raw)
	};
}
function omitScalar(jwk) {
	if (!jwk.d) return jwk;
	const { d: _scalar, ...rest } = jwk;
	return rest;
}
async function materialFromSidecar(data) {
	const publicJwk = data.publicJwk;
	const privateJwk = data.privateJwk;
	if (privateJwk?.d) return identityFromJwks(publicJwk, privateJwk);
	if (!publicJwk || publicJwk.kty !== "OKP" || publicJwk.crv !== "X25519" || !publicJwk.x) throw new LexisError("侧车里没有 X25519 公钥。旧的 P-256 侧车不能迁移");
	const publicRaw = x25519PubFromJwk(publicJwk);
	const fingerprint = typeof data.fingerprint === "string" && data.fingerprint ? data.fingerprint : await fingerprintOf(publicRaw);
	return {
		publicJwk,
		privateJwk: {
			kty: "OKP",
			crv: "X25519",
			x: publicJwk.x,
			ext: true
		},
		publicRaw,
		fingerprint
	};
}
function readVault(value) {
	const vault = vaultFromStored(value);
	return vault ? vaultToStored(vault) : null;
}
function NodesPanel() {
	const nodes = useMesh((s) => s.nodes);
	const addNode = useMesh((s) => s.addNode);
	const updateNode = useMesh((s) => s.updateNode);
	const removeNode = useMesh((s) => s.removeNode);
	const bindPair = useMesh((s) => s.bindPair);
	const reset = useMesh((s) => s.reset);
	const setIdentity = useMesh((s) => s.setIdentity);
	const profile = useProfile((s) => s.profile);
	const patch = useProfile((s) => s.patch);
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
			if (data.lo && data.hi && typeof data.saltB64 === "string" && data.cipher !== SPEC.name) throw new LexisError("这是封存文件，不是侧车。放到常驻目录，命名为 lexis.seal.json，不要和公钥写在一起。");
			if (data.cipher !== SPEC.name) throw new LexisError("这不是词隙侧车");
			if (data.role !== "gate" && data.role !== "edge") throw new LexisError("角色不对");
			const ident = await materialFromSidecar(data);
			const node = {
				id: crypto.randomUUID(),
				name: typeof data.name === "string" && data.name ? data.name : "导入节点",
				role: data.role,
				publicJwk: ident.publicJwk,
				privateJwk: ident.privateJwk,
				publicRawB64: b64(ident.publicRaw),
				fingerprint: ident.fingerprint,
				pinnedPeerId: null,
				createdAt: Date.now(),
				kdf: readKdf(data.kdf),
				vault: readVault(data.vault)
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
	async function deriveNode(id, passphrase, spare) {
		const trimmed = passphrase.trim();
		const alt = spare.trim();
		if (!trimmed) {
			setError("先写口令");
			return;
		}
		if (alt && alt === trimmed) {
			setError("备用口令要和原口令不同");
			return;
		}
		setBusy(true);
		setError(null);
		try {
			const params = VAULT_KDF;
			const salt = randomBytes(16);
			const entries = [{
				passphrase: trimmed,
				scalar: freshScalar()
			}];
			if (alt) entries.push({
				passphrase: alt,
				scalar: freshScalar()
			});
			const sealed = await sealIdentityVault(entries, salt, params, 4);
			const opened = await openIdentityVault(sealed, trimmed);
			const kdf = {
				saltB64: b64(salt),
				...params
			};
			setIdentity(id, {
				publicJwk: opened.publicJwk,
				privateJwk: opened.privateJwk,
				publicRawB64: b64(opened.publicRaw),
				fingerprint: opened.fingerprint,
				kdf,
				vault: vaultToStored(sealed)
			});
		} catch (err) {
			setError(err instanceof Error ? err.message : "派生失败");
		} finally {
			setBusy(false);
		}
	}
	async function unlockNode(id, passphrase) {
		const trimmed = passphrase.trim();
		if (!trimmed) {
			setError("先写口令");
			return;
		}
		const node = useMesh.getState().nodes.find((item) => item.id === id);
		const sealed = node?.vault ? vaultFromStored(node.vault) : null;
		if (!node || !sealed) {
			setError("这把私钥还没有封存");
			return;
		}
		setBusy(true);
		setError(null);
		try {
			const opened = await openIdentityVault(sealed, trimmed);
			setIdentity(id, {
				publicJwk: opened.publicJwk,
				privateJwk: opened.privateJwk,
				publicRawB64: b64(opened.publicRaw),
				fingerprint: opened.fingerprint,
				kdf: node.kdf,
				vault: node.vault
			});
		} catch (err) {
			setError(err instanceof Error ? err.message : "解不开");
		} finally {
			setBusy(false);
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
				children: "长期密钥是 X25519。旧的 P-256 侧车读不进来，两端要一起换新身份。封存用自己的 Argon2id：65536 KiB、3 次迭代，不跟握手那一档的 16 MiB 上限。点下去这页会卡几秒，那是在算。每次封存换一把随机私钥，口令只负责打开它。任意一句口令都会解开一把合法私钥，不会提示哪一句是当初那句。解开之后，卡片上的指纹换成这句口令对应的那把。对端对不上时说绑定不一致，不说口令错误。侧车和配置不写标量，也不写系数。系数单独是 lexis.seal.json。两边都拿到的人仍可以离线试口令，只是更慢。会话词序在隧道页握手之后才有，不由这把长期私钥单独决定。"
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
				className: "grid gap-3 lg:grid-cols-2",
				children: nodes.map((node) => /* @__PURE__ */ (0, import_jsx_runtime.jsx)(NodeCard, {
					node,
					peers: nodes.filter((n) => n.role !== node.role),
					peer: nodes.find((n) => n.id === node.pinnedPeerId),
					onName: (name) => updateNode(node.id, { name }),
					onBind: (peerId) => bindPair(node.id, peerId),
					onRemove: () => removeNode(node.id),
					onExport: () => {
						if (!node.vault && !node.privateJwk.d) {
							setError("这把私钥不在浏览器里，侧车带不走标量");
							return;
						}
						downloadJson(`${node.role}-${node.fingerprint}.json`, sidecarOf(node, nodes.find((n) => n.id === node.pinnedPeerId)));
					},
					onExportSeal: () => {
						if (!node.vault) return;
						downloadJson("lexis.seal.json", sealFileOf(node.vault));
					},
					onDerive: (passphrase, spare) => deriveNode(node.id, passphrase, spare),
					onUnlock: (passphrase) => unlockNode(node.id, passphrase),
					resident: profile.identity?.id === node.id,
					joined: profile.peers.some((peer) => peer.id === node.id),
					onResident: () => {
						if (!node.vault && !node.privateJwk.d) {
							setError("先解开，常驻身份才拿得到私钥");
							return;
						}
						patch({
							identity: {
								id: node.id,
								name: node.name,
								publicJwk: node.publicJwk,
								privateJwk: node.vault ? omitScalar(node.privateJwk) : node.privateJwk,
								publicRawB64: node.publicRawB64,
								fingerprint: node.fingerprint
							},
							seal: node.vault ?? null
						});
					},
					onJoin: () => {
						const next = {
							id: node.id,
							name: node.name,
							endpoint: profile.peerEndpoint,
							transport: profile.outer.transport,
							publicRawB64: node.publicRawB64,
							wsPath: profile.outer.wsPath,
							wsHost: "",
							relay: false,
							exit: false,
							targets: []
						};
						patch({ peers: [...profile.peers.filter((peer) => peer.id !== node.id), next] });
					}
				}, node.id))
			})
		]
	});
}
function NodeCard({ node, peers, peer, onName, onBind, onRemove, onExport, onExportSeal, onDerive, onUnlock, resident, joined, onResident, onJoin }) {
	const [peerId, setPeerId] = (0, import_react.useState)(node.pinnedPeerId ?? "");
	const [passphrase, setPassphrase] = (0, import_react.useState)("");
	const [spare, setSpare] = (0, import_react.useState)("");
	const [deriving, setDeriving] = (0, import_react.useState)(false);
	const sealed = Boolean(node.vault);
	const unlocked = Boolean(node.privateJwk.d);
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
			node.kdf ? /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", {
				className: "mt-2 text-sm text-mist",
				children: [
					"Argon2id · 内存 ",
					node.kdf.memoryKiB,
					" KiB · 迭代 ",
					node.kdf.iterations,
					" · 并行 ",
					node.kdf.parallelism,
					sealed ? " · 私钥以系数封存" : ""
				]
			}) : /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
				className: "mt-2 text-sm text-mist",
				children: "这把私钥是随机生成的，还没有用口令派生。"
			}),
			sealed && !unlocked ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
				className: "mt-2 text-sm text-mist",
				children: "标量不在这台浏览器里。输入任意口令都会解开一把合法私钥。"
			}) : null,
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
				children: [
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Btn, {
						kind: "ghost",
						disabled: !peerId,
						onClick: () => onBind(peerId),
						children: "互相绑定"
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Btn, {
						kind: resident ? "solid" : "ghost",
						onClick: onResident,
						children: resident ? "已是常驻身份" : "当作常驻身份"
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Btn, {
						kind: joined ? "solid" : "ghost",
						onClick: onJoin,
						children: joined ? "已在中继名单" : "加入中继名单"
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Btn, {
						kind: "ghost",
						onClick: onExport,
						children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Download, {
							className: "size-4",
							"aria-hidden": "true"
						}), "导出侧车"]
					}),
					sealed ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Btn, {
						kind: "ghost",
						onClick: onExportSeal,
						children: "导出封存"
					}) : null
				]
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
				className: "mt-3 grid gap-2",
				children: [
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
						label: "口令",
						children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
							className: control,
							type: "password",
							autoComplete: "off",
							value: passphrase,
							"aria-label": `${node.name}的口令`,
							onChange: (e) => setPassphrase(e.target.value)
						})
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, {
						label: "备用口令",
						children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
							className: control,
							type: "password",
							autoComplete: "off",
							value: spare,
							placeholder: "只在封存时写入，可留空",
							"aria-label": `${node.name}的备用口令`,
							onChange: (e) => setSpare(e.target.value)
						})
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
						className: "flex flex-wrap gap-2",
						children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Btn, {
							kind: "ghost",
							disabled: deriving || !passphrase.trim(),
							onClick: () => {
								setDeriving(true);
								onDerive(passphrase, spare).finally(() => {
									setPassphrase("");
									setSpare("");
									setDeriving(false);
								});
							},
							children: deriving ? "封存中" : "派生并封存"
						}), sealed ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Btn, {
							kind: "ghost",
							disabled: deriving || !passphrase.trim(),
							onClick: () => {
								setDeriving(true);
								onUnlock(passphrase).finally(() => {
									setPassphrase("");
									setDeriving(false);
								});
							},
							children: "用这句口令解开"
						}) : null]
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
						className: "text-sm text-mist",
						children: "封存不读配置页里的握手参数。刷新之后标量不在浏览器里。导出封存不需要先解开。解开不比较公钥。"
					})
				]
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
		body: "闸门和内网端各持一对 X25519 长期密钥。旧的 P-256 身份读不进来，也不能自动换过去。控制台只负责把两端钉在一起。业务流量不进控制台。"
	},
	{
		n: "02",
		title: "临时密钥握出会话密钥",
		body: "内网端主动连出。问候用临时密钥和闸门长期公钥算出的共享秘密来加密，只拿口令和闸门公钥解不出里面的长期公钥。会话密钥还混入两把临时密钥的共享秘密，再交给 Argon2id。握手确认用这个临时秘密来算，不再是公开的转录。这一层不是 TLS。两端都要是 3.0.0。"
	},
	{
		n: "03",
		title: "会话密钥打乱英文词序",
		body: `线上词来自一份约三万词的英文词频表，按这把会话密钥在相近频次里打乱。时间窗仍是 ${SPEC.windowSec} 秒。窗变了，计数器继续往后数，不从零开始。`
	},
	{
		n: "04",
		title: "宽块置换以后写成词",
		body: "正文、填充和 16 字节助记码放进 HCTR2，再按密钥词表写成英文词。持有候选会话密钥的人，可以用词序重编码确认这把密钥（大约 97% 的错误密钥对不上，对的密钥对得上）。蜜文挡的是对长期私钥和口令的暴力猜测，不挡已经拿到候选会话密钥的人。会话密钥从临时密钥来，拿长期私钥和转录推不回去。小帧默认少填充，所以很短的帧会超过 5 倍；要让填充占比靠近错误密钥，把小帧策略改成蜜文。压不压缩看明文第一个字节。"
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
					children: "浏览器里不能守一个真正的 TCP 端口。这条控制台把握手和封装按 3.0 跑完，和下载的常驻进程是同一套帧。两端都要是这一版，口令至少 128 比特，长期密钥都是 X25519。TLS 和 WebSocket 只包在外面，方便过 CDN。安装包不再附带 TLS 私钥。时钟对不齐时，时间窗两边各留 120 秒。HTTP 代理按每个请求重写，去掉代理认证，并拒绝长度和分块写在一起。状态页在回环上可以看指标；离开回环要状态口令，健康检查仍然公开。Linux 上的用户态栈会切段、重传、暂存一段乱序，并按对端窗口停发。系统接管时，53 端口的查询答成 198.18.0.0/15 里的假地址，再映射回域名，假地址本身不会被拨出去。这不是 gVisor，也没有在这台机器上证明虚拟网卡或透明代理已经接住流量。Windows 的 WinDivert 只有源码，驱动不在包里。Android 只带 VpnService 源码和本机包通道，没有装好的系统 VPN。中继默认关闭。缺了角色的配置不会被当成边缘。"
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
					children: "线上是小写英文词和空格。每个词大约携带 9.5 比特，摊到字符上大约 1.9 比特，所以一字节密文大约变成 4.2 个线上字节。看起来像书面文字，保密不靠这个。保密靠会话密钥。拿到候选会话密钥的人可以对上词序。拿不到的人看见的仍是词。"
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
