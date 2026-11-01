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

export async function createIdentity(): Promise<KeyMaterial> {
  const pair = await crypto.subtle.generateKey(ECDH, true, ["deriveBits"]);
  const publicJwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
  const privateJwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
  const publicRaw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  const fingerprint = await fingerprintOf(publicRaw);
  return { publicJwk, privateJwk, publicRaw, fingerprint };
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
  if (raw.length !== 65 || raw[0] !== 0x04) {
    throw new LexisError(`${label}公钥不是 P-256 未压缩点`);
  }
}

export async function identityFromJwks(
  publicJwk: JsonWebKey,
  privateJwk: JsonWebKey,
): Promise<KeyMaterial> {
  if (publicJwk.kty !== "EC" || publicJwk.crv !== "P-256") {
    throw new LexisError("侧车里的公钥不是 P-256");
  }
  if (privateJwk.x && publicJwk.x && privateJwk.x !== publicJwk.x) {
    throw new LexisError("侧车里的私钥和公钥不是一对");
  }
  const pub = await crypto.subtle.importKey("jwk", publicJwk, ECDH, true, []);
  await importPrivateJwk(privateJwk);
  const publicRaw = new Uint8Array(await crypto.subtle.exportKey("raw", pub));
  const fingerprint = await fingerprintOf(publicRaw);
  return { publicJwk, privateJwk, publicRaw, fingerprint };
}
