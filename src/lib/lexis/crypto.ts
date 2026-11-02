import { concat, hex, u32be, utf8 } from "./bytes";

export type KeyMaterial = {
  publicJwk: JsonWebKey;
  privateJwk: JsonWebKey;
  publicRaw: Uint8Array;
  fingerprint: string;
};

const ECDH = { name: "ECDH", namedCurve: "P-256" } as const;
const HKDF_CAP = 8000;

function buf(data: Uint8Array): ArrayBuffer {
  const out = new ArrayBuffer(data.byteLength);
  new Uint8Array(out).set(data);
  return out;
}

function asBytes(data: ArrayBuffer): Uint8Array {
  const view = new Uint8Array(data);
  const out = new Uint8Array(view.length);
  out.set(view);
  return out;
}

export class LexisError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "LexisError";
  }
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return asBytes(await crypto.subtle.digest("SHA-256", buf(data)));
}

export async function fingerprintOf(raw: Uint8Array): Promise<string> {
  const d = await sha256(raw);
  const h = hex(d.subarray(0, 8));
  return (h.match(/.{1,4}/g) ?? [h]).join("-");
}

/** v3: long-term identity is X25519 (32-byte raw pub). P-256 configs from <=2.x will not load. */
export async function createIdentity(): Promise<KeyMaterial> {
  try {
    const pair = (await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"])) as CryptoKeyPair;
    const publicJwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
    const privateJwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
    const publicRaw = jwkOkpToRaw(publicJwk);
    const fingerprint = await fingerprintOf(publicRaw);
    return { publicJwk, privateJwk, publicRaw, fingerprint };
  } catch {
    // Node without SubtleCrypto X25519: fall back to noble
    const { x25519 } = await import("@noble/curves/ed25519.js");
    const d = crypto.getRandomValues(new Uint8Array(32));
    const x = x25519.getPublicKey(d);
    const publicJwk = { kty: "OKP", crv: "X25519", x: b64url(x) } as JsonWebKey;
    const privateJwk = { kty: "OKP", crv: "X25519", x: b64url(x), d: b64url(d) } as JsonWebKey;
    return { publicJwk, privateJwk, publicRaw: x, fingerprint: await fingerprintOf(x) };
  }
}

function b64url(u: Uint8Array): string {
  let s = "";
  for (const b of u) s += String.fromCharCode(b);
  return btoa(s).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/g, "");
}
function b64urlDecode(s: string): Uint8Array {
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  const bin = atob(s.replaceAll("-", "+").replaceAll("_", "/") + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function jwkOkpToRaw(jwk: JsonWebKey): Uint8Array {
  if (!jwk.x) throw new LexisError("OKP 公钥缺少 x");
  return b64urlDecode(jwk.x);
}
export function x25519SeedFromJwk(jwk: JsonWebKey): Uint8Array {
  if (jwk.kty !== "OKP" || jwk.crv !== "X25519" || !jwk.d) throw new LexisError("需要 X25519 私钥");
  return b64urlDecode(jwk.d);
}
export function x25519PubFromJwk(jwk: JsonWebKey): Uint8Array {
  if (jwk.kty !== "OKP" || jwk.crv !== "X25519") throw new LexisError("需要 X25519 公钥");
  return jwkOkpToRaw(jwk);
}

export async function importPrivateJwk(jwk: JsonWebKey): Promise<CryptoKey> {
  return crypto.subtle.importKey("jwk", jwk, ECDH, true, ["deriveBits"]);
}

export async function importRawPublic(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", buf(raw), ECDH, true, []);
}

export async function ecdh(priv: CryptoKey, pub: CryptoKey): Promise<Uint8Array> {
  const bits = await crypto.subtle.deriveBits({ name: "ECDH", public: pub }, priv, 256);
  return asBytes(bits);
}

export async function hkdf(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  bytes: number,
): Promise<Uint8Array> {
  const base = await crypto.subtle.importKey("raw", buf(ikm), "HKDF", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: buf(salt), info: buf(info) },
    base,
    bytes * 8,
  );
  return asBytes(bits);
}

/** HKDF-Expand past the 255-block cap by splitting on an info counter. */
export async function hkdfStream(
  ikm: Uint8Array,
  salt: Uint8Array,
  infoLabel: string,
  nbytes: number,
): Promise<Uint8Array> {
  const parts: Uint8Array[] = [];
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

export async function hmac(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey(
    "raw",
    buf(key),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return asBytes(await crypto.subtle.sign("HMAC", k, buf(data)));
}

export function assertPoint(raw: Uint8Array, label: string): void {
  // v3: X25519 raw pub is 32 bytes. Keep a clear error for leftover P-256 points.
  if (raw.length === 32) return;
  if (raw.length === 65 && raw[0] === 0x04) {
    throw new LexisError(`${label}公钥仍是 P-256；词隙 3.0 起长期密钥改为 X25519，两端需一起升级并重新生成身份`);
  }
  throw new LexisError(`${label}公钥长度不对（需要 32 字节 X25519）`);
}

export async function identityFromJwks(
  publicJwk: JsonWebKey,
  privateJwk: JsonWebKey,
): Promise<KeyMaterial> {
  if (publicJwk.kty === "EC" || privateJwk.kty === "EC") {
    throw new LexisError("侧车里仍是 P-256 身份。词隙 3.0 起长期密钥改为 X25519：请重新生成身份，两端一起升级。旧配置无法自动迁移（私钥曲线不同）。");
  }
  if (publicJwk.kty !== "OKP" || publicJwk.crv !== "X25519") {
    throw new LexisError("侧车里的公钥不是 X25519");
  }
  if (privateJwk.kty !== "OKP" || privateJwk.crv !== "X25519" || !privateJwk.d) {
    throw new LexisError("侧车里的私钥不是 X25519");
  }
  const publicRaw = jwkOkpToRaw(publicJwk);
  const seed = b64urlDecode(privateJwk.d);
  const { x25519 } = await import("@noble/curves/ed25519.js");
  const expect = x25519.getPublicKey(seed);
  if (publicRaw.length !== 32 || !expect.every((b, i) => b === publicRaw[i])) {
    throw new LexisError("侧车里的私钥和公钥不是一对");
  }
  return { publicJwk, privateJwk, publicRaw, fingerprint: await fingerprintOf(publicRaw) };
}
