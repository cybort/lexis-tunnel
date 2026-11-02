import { i as __toESM } from "../_runtime.mjs";
import { q as require_react, x as require_jsx_runtime, y as Link } from "../_libs/@tanstack/react-router+[...].mjs";
import { a as Radio, c as ArrowRight, n as Trash2, s as Download } from "../_libs/lucide-react.mjs";
import { n as persist, r as create, t as createJSONStorage } from "../_libs/zustand.mjs";
import { t as p256 } from "../_libs/noble__curves+noble__hashes.mjs";
import { t as argon2id } from "../_libs/noble__hashes.mjs";
import { t as require_index_node } from "../_libs/bokuweb__zstd-wasm.mjs";
import { a as Cell, i as Bar, n as YAxis, o as ResponsiveContainer, r as XAxis, s as Tooltip, t as BarChart } from "../_libs/recharts+[...].mjs";
//#region node_modules/.nitro/vite/services/ssr/assets/routes-O5dWWAqD.js
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
var LEADS = [
	"the",
	"our",
	"its",
	"that"
];
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
	version: 1,
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
function clampOffer(input) {
	return {
		...clampKdf(input),
		honey: input?.honey === true
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
		return buildLexicon(await sha256(utf8("LEXIS-STATIC-ALPHABET-v1")));
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
	return (await hmac(key, concat(salt, utf8(label)))).subarray(0, 16);
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
	const idx = indicesFrom(program ? await evalHoney(program, key) : await hkdf(key, u32be(window), seed.length ? seed : utf8("honey"), 16));
	return `the ${lex[idx[0]]} and our ${lex[idx[1]]} that its ${lex[idx[2]]} and the ${lex[idx[3]]}`;
}
function scalarFromSeed(seed) {
	let hex = "";
	for (const b of seed) hex += b.toString(16).padStart(2, "0");
	let n = p256.Point.Fn.create(BigInt(`0x${hex}`));
	if (n === 0n) n = 1n;
	return p256.Point.Fn.toBytes(n);
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
	const secret = scalarFromSeed(joined);
	const pub = p256.getPublicKey(secret, false);
	const x = b64url(pub.subarray(1, 33));
	const y = b64url(pub.subarray(33, 65));
	const d = b64url(secret);
	return identityFromJwks({
		kty: "EC",
		crv: "P-256",
		x,
		y,
		ext: true
	}, {
		kty: "EC",
		crv: "P-256",
		x,
		y,
		d,
		ext: true
	});
}
function unb64url(text) {
	const pad = text.length % 4 === 0 ? "" : "=".repeat(4 - text.length % 4);
	return unb64(text.replaceAll("-", "+").replaceAll("_", "/") + pad);
}
/** Scalar bytes of an unlocked key. Absent after a sealed key is reloaded. */
function freshScalar() {
	return p256.utils.randomSecretKey();
}
function privateScalar(jwk) {
	if (!jwk.d) throw new Error("私钥不在内存里");
	const raw = unb64url(jwk.d);
	if (raw.length !== 32) throw new Error("私钥标量长度不对");
	return raw;
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
		const salt = unb64(rec.saltB64);
		if (salt.length !== 16) return null;
		return {
			salt,
			coeffs: rec.coeffsB64.map((item) => {
				if (typeof item !== "string") throw new Error("系数不对");
				const bytes = unb64(item);
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
		const salt = unb64(rec.saltB64);
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
function blendBytes(real, cover, takeReal) {
	const m = takeReal & 1;
	const inv = 1 - m;
	const n = m * real.length + inv * cover.length;
	const out = new Uint8Array(n);
	for (let i = 0; i < n; i += 1) {
		const a = i < real.length ? real[i] : 0;
		const b = i < cover.length ? cover[i] : 0;
		out[i] = a * m + b * inv & 255;
	}
	return out;
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
		link: {
			token: "",
			idleMs: 12e4,
			maxConns: 128,
			headerBytes: 8192,
			allowLan: false,
			handshakeMs: 1e4,
			dialMs: 1e4,
			maxHandshakes: 2
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
		link: {
			token: typeof raw.link?.token === "string" ? raw.link.token : "",
			idleMs: clampNum(raw.link?.idleMs, 1e3, 6e5, base.link.idleMs),
			maxConns: clampNum(raw.link?.maxConns, 1, 1e4, base.link.maxConns),
			headerBytes: clampNum(raw.link?.headerBytes, 256, 65536, base.link.headerBytes),
			allowLan: raw.link?.allowLan === true,
			handshakeMs: clampNum(raw.link?.handshakeMs, 1e3, 6e4, base.link.handshakeMs),
			dialMs: clampNum(raw.link?.dialMs, 1e3, 6e4, base.link.dialMs),
			maxHandshakes: clampNum(raw.link?.maxHandshakes, 1, 8, base.link.maxHandshakes)
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
	if (joined && profile.link.token.trim().length < 16) issues.push("常驻握手要有至少 16 个字符的口令，用来在 Argon2 之前挡掉伪造问候");
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
var HELLO_CORE = 157;
var SERVER_CORE = 169;
var seenHellos = /* @__PURE__ */ new Map();
var helloByPeer = /* @__PURE__ */ new Map();
var helloByIp = /* @__PURE__ */ new Map();
var HELLO_PEER_CAP = 16;
var HELLO_IP_CAP = 32;
/** Current window, the previous one during the first skewSec, and the next one during the last skewSec. */
function assertHelloWindow(helloWindow, now = Date.now()) {
	const current = currentWindow(now);
	const into = Math.floor(now / 1e3) % SPEC.windowSec;
	const skew = SPEC.skewSec;
	const prevOk = helloWindow === current - 1 && into < skew;
	const nextOk = helloWindow === current + 1 && into >= SPEC.windowSec - skew;
	if (helloWindow === current || prevOk || nextOk) return;
	throw new LexisError("握手时间窗已经过期");
}
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
async function tokenMac(token, body) {
	return (await hmac(utf8(token), concat(utf8("lexis-admit-v1"), body))).subarray(0, 16);
}
/**
* Tag over the public transcript. The HMAC key is a constant, not the session key.
* A recorded handshake plus a guessed long-term key must not be confirmed by this tag.
* Anyone who can see the public handshake can recompute it, so it does not prove the
* peer derived the same session key. A mismatch shows up when a data frame does not unpack.
*/
async function publicConfirm(label, tr) {
	return (await hmac(utf8("lexis-pub-confirm-v1"), concat(utf8(label), tr))).subarray(0, 16);
}
function transcript(parts) {
	return concat(utf8("LEXIS2"), parts.ephC, parts.ephS, parts.ltC, parts.ltS, u32be(parts.window), parts.nonceC, parts.nonceS, parts.kdf, new Uint8Array([parts.features & 255]));
}
async function edgeStart(edge, now = Date.now(), offer, token = "") {
	const wanted = clampOffer(offer);
	const eph = await createIdentity();
	const ltRaw = unb64(edge.publicRawB64);
	assertPoint(ltRaw, "内网端");
	assertPoint(eph.publicRaw, "内网端临时");
	const nonceC = crypto.getRandomValues(/* @__PURE__ */ new Uint8Array(16));
	const window = currentWindow(now);
	let blob = concat(new Uint8Array([1, 1]), eph.publicRaw, ltRaw, u32be(window), nonceC, encodeKdf(wanted), new Uint8Array([featureByte(wanted.honey)]));
	if (token) blob = concat(blob, await tokenMac(token, blob));
	return {
		eph,
		nonceC,
		window,
		helloWire: await encodeStatic(blob),
		ltRaw
	};
}
function parseHello(buf) {
	if (buf.length !== HELLO_CORE && buf.length !== 173) throw new LexisError("客户端问候长度不对");
	if (buf[0] !== 1 || buf[1] !== 1) throw new LexisError("客户端问候版本不对");
	const mac = buf.length === 173 ? buf.slice(HELLO_CORE) : null;
	const ephRaw = buf.slice(2, 67);
	const ltRaw = buf.slice(67, 132);
	const window = buf[132] << 24 | buf[133] << 16 | buf[134] << 8 | buf[135];
	const nonce = buf.slice(136, 152);
	const kdf = decodeKdf(buf, 152);
	const features = buf[156];
	assertPoint(ephRaw, "对端临时");
	assertPoint(ltRaw, "对端长期");
	return {
		ephRaw,
		ltRaw,
		window: window >>> 0,
		nonce,
		kdf,
		features,
		mac
	};
}
function parseServer(buf) {
	if (buf.length !== SERVER_CORE && buf.length !== 185) throw new LexisError("服务端问候长度不对");
	if (buf[0] !== 1 || buf[1] !== 2) throw new LexisError("服务端问候版本不对");
	const mac = buf.length === 185 ? buf.slice(SERVER_CORE) : null;
	const ephRaw = buf.slice(2, 67);
	const ltRaw = buf.slice(67, 132);
	const nonce = buf.slice(132, 148);
	const confirm = buf.slice(148, 164);
	const kdf = decodeKdf(buf, 164);
	const features = buf[168];
	assertPoint(ephRaw, "闸门临时");
	assertPoint(ltRaw, "闸门长期");
	return {
		ephRaw,
		ltRaw,
		nonce,
		confirm,
		kdf,
		features,
		mac
	};
}
async function gateRespond(gate, peerRawB64, helloWire, opts = {}) {
	const raw = await decodeStatic(helloWire);
	const hello = parseHello(raw);
	assertHelloWindow(hello.window, opts.now ?? Date.now());
	const token = opts.token || "";
	if (token) {
		if (!hello.mac) throw new LexisError("缺少握手口令");
		if (!timingSafeEqual(await tokenMac(token, raw.slice(0, HELLO_CORE)), hello.mac)) throw new LexisError("握手口令不对");
	} else if (hello.mac) throw new LexisError("对端带了口令，这边没有");
	const pinned = unb64(peerRawB64);
	if (!timingSafeEqual(hello.ltRaw, pinned)) throw new LexisError("内网端长期公钥和闸门上的绑定不一致");
	claimHello(hello.window, hello.nonce, {
		peer: opts.peerId || "",
		ip: opts.sourceIp || ""
	});
	const ephS = await createIdentity();
	const ltS = unb64(gate.publicRawB64);
	const nonceS = crypto.getRandomValues(/* @__PURE__ */ new Uint8Array(16));
	const ssE = await ecdh(await importPrivateJwk(ephS.privateJwk), await importRawPublic(hello.ephRaw));
	const ssS = await ecdh(await importPrivateJwk(gate.privateJwk), await importRawPublic(hello.ltRaw));
	const agreed = clampKdf(opts.kdf ?? hello.kdf);
	const kdfBytes = encodeKdf(agreed);
	const features = hello.features & 255;
	const sk = (await deriveSessionKeyAsync(ssE, ssS, hello.nonce, nonceS, hello.window, features, agreed)).key;
	const tr = transcript({
		ephC: hello.ephRaw,
		ephS: ephS.publicRaw,
		ltC: hello.ltRaw,
		ltS,
		window: hello.window,
		nonceC: hello.nonce,
		nonceS,
		kdf: kdfBytes,
		features
	});
	const confirmS = await publicConfirm("lexis-srv-pub-v1", tr);
	const expectFinish = await publicConfirm("lexis-cli-pub-v1", tr);
	let blob = concat(new Uint8Array([1, 2]), ephS.publicRaw, ltS, nonceS, confirmS, kdfBytes, new Uint8Array([features]));
	if (token) blob = concat(blob, await tokenMac(token, blob));
	const serverWire = await encodeStatic(blob);
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
		expectFinish,
		kdf: agreed,
		features
	};
}
async function edgeFinish(edge, pending, gateRawB64, serverWire, token = "") {
	const raw = await decodeStatic(serverWire);
	const server = parseServer(raw);
	const pinned = unb64(gateRawB64);
	if (!timingSafeEqual(server.ltRaw, pinned)) throw new LexisError("闸门长期公钥和内网端上的绑定不一致");
	if (token) {
		if (!server.mac) throw new LexisError("闸门没有带回口令");
		if (!timingSafeEqual(await tokenMac(token, raw.slice(0, SERVER_CORE)), server.mac)) throw new LexisError("握手口令不对");
	} else if (server.mac) throw new LexisError("对端带了口令，这边没有");
	const ssE = await ecdh(await importPrivateJwk(pending.eph.privateJwk), await importRawPublic(server.ephRaw));
	const ssS = await ecdh(await importPrivateJwk(edge.privateJwk), await importRawPublic(server.ltRaw));
	const features = server.features & 255;
	const derived = await deriveSessionKeyAsync(ssE, ssS, pending.nonceC, server.nonce, pending.window, features, server.kdf);
	const sk = derived.key;
	const tr = transcript({
		ephC: pending.eph.publicRaw,
		ephS: server.ephRaw,
		ltC: pending.ltRaw,
		ltS: server.ltRaw,
		window: pending.window,
		nonceC: pending.nonceC,
		nonceS: server.nonce,
		kdf: encodeKdf(server.kdf),
		features
	});
	if (!timingSafeEqual(await publicConfirm("lexis-srv-pub-v1", tr), server.confirm)) throw new LexisError("闸门确认标记对不上");
	const confirmC = await publicConfirm("lexis-cli-pub-v1", tr);
	return {
		sk,
		finishWire: await encodeStatic(concat(new Uint8Array([1, 3]), confirmC)),
		window: pending.window,
		kdf: server.kdf,
		honey: honeyFromFeatures(features),
		kdfMs: derived.ms
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
		gateFp: opts.gate.fingerprint,
		kdf: opts.kdf,
		honey: opts.honey,
		kdfMs: opts.kdfMs,
		program: opts.program ?? null
	};
}
/** Both roles, in order. The browser lab runs this; a real split process would run each step on its host. */
async function establish(edge, gate, now = Date.now(), offer) {
	if (edge.role !== "edge" || gate.role !== "gate") throw new LexisError("需要一个内网端和一个公网闸门");
	if (edge.pinnedPeerId !== gate.id || gate.pinnedPeerId !== edge.id) throw new LexisError("两端还没有互相绑定");
	const started = await edgeStart(edge, now, offer);
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
		finishWire: finished.finishWire,
		kdf: finished.kdf,
		honey: finished.honey,
		kdfMs: finished.kdfMs
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
	rekey: 6
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
function mask24(mac) {
	return (mac[0] << 16 | mac[1] << 8 | mac[2]) >>> 0;
}
/**
* Codebook stream seal.
* Counter is hidden by a window mask, then each 12-bit plaintext digit is
* added (mod 4096) to a keystream digit and emitted as lexicon[sum].
* HMAC covers direction, counter, and plaintext only for the counter mask.
* The 16-byte tail is random. It is not HMAC(sessionKey, plaintext): a guessed
* session key must not be able to confirm itself by recomputing that tag.
*/
async function seal(input) {
	const { key, lexicon, counter, window, direction, plaintext } = input;
	if (counter < 1 || counter > 16777215) throw new LexisError("计数器超出 24 位范围");
	if (lexicon.length !== SPEC.lexiconSize) throw new LexisError("词表长度不对");
	const tag = randomBytes(SPEC.macBytes);
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
async function recover(input) {
	const { key, inverse, window, direction, prose } = input;
	const words = undress(prose);
	if (words.length < 3) throw new LexisError("报文太短，不像一帧词隙");
	let missing = false;
	const take = (w) => {
		const idx = inverse.get(w);
		if (idx === void 0) {
			missing = true;
			return 0;
		}
		return idx;
	};
	const mask = mask24(await hmac(key, utf8(`lexis-counter-mask-v1|${direction}|${window}`)));
	const counter = (((take(words[0]) & 4095) << 12 | take(words[1]) & 4095) ^ mask) & 16777215;
	const bodyWords = words.slice(2);
	const ks = await hkdfStream(key, concat(utf8(`lexis-body-v1|${direction}|${window}|`), u32be(counter)), "LEXIS-KS-v1", bodyWords.length * 2);
	const chunks = bodyWords.map((w, i) => {
		const ks12 = (ks[i * 2] << 8 | ks[i * 2 + 1]) & 4095;
		return (take(w) - ks12 + SPEC.lexiconSize) % SPEC.lexiconSize;
	});
	return {
		missing,
		counter,
		raw: chunksToBytes(chunks)
	};
}
async function open(input) {
	const { key, window, prose, lastSeen } = input;
	const honey = input.honey === true;
	const { missing, counter, raw } = await recover(input);
	const seed = raw.length ? raw : utf8(prose);
	const coverOf = () => honeyPhrase(key, window, seed, input.program);
	const release = async (takeReal, real) => {
		const cover = honey ? utf8(await coverOf()) : real;
		const bit = honey ? takeReal & 1 : 1;
		return {
			counter: bit * counter + (1 - bit) * lastSeen,
			plaintext: blendBytes(real, cover, bit),
			honey: honey && bit === 0
		};
	};
	if (missing || raw.length < 2 + SPEC.macBytes) {
		if (!honey) throw new LexisError(missing ? "有词不在本时间窗的词表里。密钥或时间窗不一致，或报文被改过。" : "正文长度不够");
		return release(0, /* @__PURE__ */ new Uint8Array());
	}
	const len = readU16(raw, 0);
	if (2 + len + SPEC.macBytes > raw.length) {
		if (!honey) throw new LexisError("正文字段被截断");
		return release(0, /* @__PURE__ */ new Uint8Array());
	}
	const plaintext = raw.slice(2, 2 + len);
	if (counter < 1 || counter <= lastSeen) {
		if (!honey) throw new LexisError(counter < 1 ? "计数器无效" : "计数器没有前进，按回放丢弃");
		return release(0, plaintext);
	}
	return release(1, plaintext);
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
			const next = await establish(edge, gate, Date.now(), {
				...profile.kdf,
				honey: profile.honey
			});
			onSession(next);
			push({
				title: "会话密钥已按握手回声派生",
				meta: `Argon2id ${next.kdf.memoryKiB} KiB · t${next.kdf.iterations} · p${next.kdf.parallelism} · ${next.kdfMs} ms · ${next.honey ? "蜜文" : "坏帧会被拒绝"}`
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
		const packed = await packPayload(plaintext, profile.zstd);
		const counter = current.counters[dir] + 1;
		const prose = await seal({
			key: current.sk,
			lexicon: current.lexicon,
			counter,
			window: current.window,
			direction: dir,
			plaintext: packed.bytes
		});
		const opened = await open({
			key: current.sk,
			inverse: current.inverse,
			window: current.window,
			direction: dir,
			prose,
			lastSeen: current.seen[dir],
			honey: current.honey
		});
		if (opened.honey) throw new LexisError("正确密钥不该落到蜜文");
		const unpacked = await unpackPayload(opened.plaintext, false);
		const next = {
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
		const sense = unpacked.compressed ? `对端看见类型 1，按帧头解开 zstd ${packed.level}` : "对端看见类型 0，按原文使用";
		return {
			prose,
			unpacked,
			next,
			counter: opened.counter,
			sense
		};
	}
	async function transmit(dir, plaintext, title) {
		if (!session) throw new LexisError("还没有会话");
		const framed = await frame(session, dir, plaintext);
		onSession(framed.next);
		setLastFrame({
			prose: framed.prose,
			direction: dir
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
					direction: dir
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
			const opened = await open({
				key: randomBytes(32),
				inverse: session.inverse,
				window: session.window,
				direction: lastFrame.direction,
				prose: lastFrame.prose,
				lastSeen: 0,
				honey: session.honey,
				program: programFromStored(profile.honeyProgram)
			});
			const text = isPrintableText(opened.plaintext) ? fromUtf8(opened.plaintext) : hex(opened.plaintext);
			push({
				title: opened.honey ? "错误密钥落到一句蜜文" : "错误密钥居然拆开了原文",
				meta: text,
				bad: !opened.honey
			});
		} catch (err) {
			push({
				title: "错误密钥被校验挡住",
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
										session.honey ? "蜜文" : "结构或回放即拒绝"
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
						children: "蜜文在握手时谈定。打开以后，词不在词表里、正文结构不对、或者计数器回放，都不报错，落成这把密钥和当前时间窗自己的词表里的一句话。关掉时，回放仍会拆掉这条会话。帧尾是随机字节，不是会话密钥的校验：猜中会话密钥的人和猜错的人，比对这段尾部都对不上。握手确认也不再拿会话密钥来算。词表仍由会话密钥导出，对得上词表本身仍说明这把密钥是对的。换一把密钥，或换一个时间窗，词表格式不变、用词不同。备用明文写进同一条求值，不会为某一把密钥另开判断。线上没有「这是蜜文」的位。这一版和 1.7 及更早的对端对不上。"
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
							/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", {
								className: "text-sm text-mist",
								children: [
									"封面按会话密钥封进同一条求值。密钥写成 64 位十六进制，词序是四个 0 到 ",
									SPEC.lexiconSize - 1,
									" 的整数。封存之后只留系数。拆开时每一把密钥都走这一条，没有单独的判断。对得上的用你写的词序，对不上的仍是同一句式，词从那把密钥和当时的时间窗里取。"
								]
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
						children: "常驻进程和这条控制台用同一套词表。握手仍是两次 ECDH 加 Argon2id，正文是密钥、计数器和秘密词表。TCP、TLS、WebSocket 只负责协议和头，用来过 CDN。路径默认 /lexis。CDN 若自己终结 TLS，源站可以听 WebSocket。"
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
									type: "password",
									autoComplete: "off",
									value: profile.link.token,
									onChange: (e) => patch({ link: {
										...profile.link,
										token: e.target.value
									} })
								})
							}),
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
							})
						]
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
						className: "mt-2 text-sm text-mist",
						children: "握手口令在 Argon2 之前校验，用来挡伪造问候，不是词表密钥。两端要写成同一个，至少 16 个字符。校验关掉时，外层 TLS 认不出对端，正式部署请换自己的证书。"
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
	if (!publicJwk || publicJwk.kty !== "EC" || publicJwk.crv !== "P-256" || !publicJwk.x || !publicJwk.y) throw new LexisError("侧车里没有 P-256 公钥");
	const pub = await crypto.subtle.importKey("jwk", publicJwk, {
		name: "ECDH",
		namedCurve: "P-256"
	}, true, []);
	const publicRaw = new Uint8Array(await crypto.subtle.exportKey("raw", pub));
	const fingerprint = typeof data.fingerprint === "string" && data.fingerprint ? data.fingerprint : await fingerprintOf(publicRaw);
	return {
		publicJwk,
		privateJwk: {
			kty: "EC",
			crv: "P-256",
			x: publicJwk.x,
			y: publicJwk.y,
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
				children: "封存用自己的 Argon2id：65536 KiB、3 次迭代，不跟握手那一档的 16 MiB 上限。点下去这页会卡几秒，那是在算。每次封存换一把随机私钥，口令只负责打开它。任意一句口令都会解开一把合法私钥，不会提示哪一句是当初那句。解开之后，卡片上的指纹换成这句口令对应的那把。对端对不上时说绑定不一致，不说口令错误。侧车和配置不写标量，也不写系数。系数单独是 lexis.seal.json。两边都拿到的人仍可以离线试口令，只是更慢。"
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
	const [words, setWords] = (0, import_react.useState)("");
	const sealed = Boolean(node.vault);
	const unlocked = Boolean(node.privateJwk.d);
	(0, import_react.useEffect)(() => {
		let cancel = false;
		if (!node.privateJwk.d) {
			setWords("");
			return;
		}
		sessionLexicon(privateScalar(node.privateJwk), currentWindow()).then((lex) => {
			if (!cancel) setWords(`${lex[0]} · ${lex[1]} · ${lex[2]} · ${lex[3]}`);
		}).catch(() => {
			if (!cancel) setWords("");
		});
		return () => {
			cancel = true;
		};
	}, [node.privateJwk.d, node.fingerprint]);
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
			words ? /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", {
				className: "mt-2 text-sm text-mist",
				children: ["本窗词表开头：", words]
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
		body: "闸门和内网端各持一对 P-256 长期密钥。控制台只负责把两端钉在一起。业务流量不进控制台。"
	},
	{
		n: "02",
		title: "非对称握手取出会话密钥",
		body: "内网端主动连出。双方各出临时公钥，做两次 ECDH：临时对临时，长期对长期。共享秘密交给 Argon2id。内存、迭代和蜜文开关写在握手里，闸门压到上限后回声，两端按回声派生。这一层不是 TLS。"
	},
	{
		n: "03",
		title: "密钥加时间窗，生成词表",
		body: `Argon2id 得到的会话密钥，再用 HKDF 按同一个 ${SPEC.windowSec} 秒时间窗展开。两端得到同一份 ${SPEC.lexiconSize} 词的秘密词表。窗一变，词表整本换掉。`
	},
	{
		n: "04",
		title: "密钥、计数器、词表一起封装",
		body: "计数器先被密钥掩住，正文每 12 比特加上密钥流，再写成词。帧尾是随机字节，不是会话密钥的校验，猜对和猜错比对这段都对不上。握手确认也不再拿会话密钥来算。词表仍由会话密钥导出，词能对上词表，本身仍说明密钥是对的。蜜文打开时，词对不上或计数器回放不报错，落成这把密钥和当前时间窗自己的一句话。换钥匙或换窗，词表仍是同样的格式，词不一样。压不压缩看明文第一个字节，zstd 的等级在帧头里，对端不用另配一份开关。"
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
					children: "浏览器里不能守一个真正的 TCP 端口。这条控制台把握手、词表和封装真实跑完。下载的常驻进程走同一套词表，两端都要是这一版。TLS 和 WebSocket 只包在外面，方便过 CDN。安装包不再附带 TLS 私钥。时钟对不齐时，时间窗两边各留 120 秒。HTTP 代理按每个请求重写，去掉代理认证，并拒绝长度和分块写在一起。状态页在回环上可以看指标；离开回环要状态口令，健康检查仍然公开。Linux 上的用户态栈会切段、重传、暂存一段乱序，并按对端窗口停发。系统接管时，53 端口的查询答成 198.18.0.0/15 里的假地址，再映射回域名，假地址本身不会被拨出去。这不是 gVisor，也没有在这台机器上证明虚拟网卡或透明代理已经接住流量。Windows 的 WinDivert 只有源码，驱动不在包里。Android 只带 VpnService 源码和本机包通道，没有装好的系统 VPN。中继默认关闭。缺了角色的配置不会被当成边缘。"
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
