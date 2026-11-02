import { x25519 } from "@noble/curves/ed25519.js";
import { argon2id } from "@noble/hashes/argon2.js";
import { concat, u32be, utf8 } from "./bytes";
import { identityFromJwks, type KeyMaterial } from "./crypto";

/** Argon2id parameters. Memory is kibibytes. */
export type ArgonParams = {
  memoryKiB: number;
  iterations: number;
  parallelism: number;
};

export type SessionOffer = ArgonParams & { honey: boolean };

export const DEFAULT_KDF: ArgonParams = {
  memoryKiB: 4096,
  iterations: 2,
  parallelism: 1,
};

/** At-rest private key. Not the handshake cap. A guess costs this much even if the public key is known. */
export const VAULT_KDF: ArgonParams = {
  memoryKiB: 65536,
  iterations: 3,
  parallelism: 1,
};

const LIMITS = {
  memoryKiB: { min: 8, max: 16384 },
  iterations: { min: 1, max: 4 },
  parallelism: { min: 1, max: 2 },
};

function clampInt(value: unknown, min: number, max: number, fallback: number): number {
  const n = typeof value === "number" ? value : Number(value);
  if (!Number.isInteger(n)) return fallback;
  if (n < min) return min;
  if (n > max) return max;
  return n;
}

/** Gate-side cap. A peer cannot ask this process to spend more than these costs. */
export function clampKdf(input?: Partial<ArgonParams> | null): ArgonParams {
  const parallelism = clampInt(input?.parallelism, LIMITS.parallelism.min, LIMITS.parallelism.max, DEFAULT_KDF.parallelism);
  const minMemory = 8 * parallelism;
  const memoryKiB = Math.max(
    clampInt(input?.memoryKiB, LIMITS.memoryKiB.min, LIMITS.memoryKiB.max, DEFAULT_KDF.memoryKiB),
    minMemory,
  );
  const iterations = clampInt(input?.iterations, LIMITS.iterations.min, LIMITS.iterations.max, DEFAULT_KDF.iterations);
  return { memoryKiB, iterations, parallelism };
}

export function clampOffer(input?: Partial<SessionOffer> | null): SessionOffer {
  return { ...clampKdf(input), honey: input?.honey === true };
}

/** Vault cost. Explicit small values stay, so tests can use a tiny memory. Missing values become VAULT_KDF.
 *  This does not use the handshake ceiling of 16384 KiB. */
export function clampVaultKdf(input?: Partial<ArgonParams> | null): ArgonParams {
  return {
    memoryKiB: clampInt(input?.memoryKiB, 8, 262144, VAULT_KDF.memoryKiB),
    iterations: clampInt(input?.iterations, 1, 8, VAULT_KDF.iterations),
    parallelism: clampInt(input?.parallelism, 1, 1, VAULT_KDF.parallelism),
  };
}

export function encodeKdf(params: ArgonParams): Uint8Array {
  const c = clampKdf(params);
  return new Uint8Array([(c.memoryKiB >> 8) & 0xff, c.memoryKiB & 0xff, c.iterations, c.parallelism]);
}

export function decodeKdf(bytes: Uint8Array, offset: number): ArgonParams {
  const memoryKiB = ((bytes[offset] << 8) | bytes[offset + 1]) >>> 0;
  return clampKdf({
    memoryKiB,
    iterations: bytes[offset + 2],
    parallelism: bytes[offset + 3],
  });
}

export const FEATURE_HONEY = 0x01;

export function featureByte(honey: boolean): number {
  return honey ? FEATURE_HONEY : 0;
}

export function honeyFromFeatures(features: number): boolean {
  return (features & FEATURE_HONEY) !== 0;
}

function b64url(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/g, "");
}

/**
 * Long-term private key = hash-to-scalar(Argon2id(passphrase, salt)).
 * There is no password verifier. A different passphrase is a different valid key.
 */
export async function deriveIdentity(
  passphrase: string,
  salt: Uint8Array,
  params: ArgonParams,
): Promise<KeyMaterial> {
  const c = clampKdf(params);
  const dk = argon2id(utf8(passphrase), salt, {
    t: c.iterations,
    m: c.memoryKiB,
    p: c.parallelism,
    dkLen: 32,
  });
  const secret = dk;
  const pub = x25519.getPublicKey(secret);
  const x = b64url(pub);
  const d = b64url(secret);
  return identityFromJwks(
    { kty: "OKP", crv: "X25519", x, ext: true },
    { kty: "OKP", crv: "X25519", x, d, ext: true },
  );
}

/** Session key from the two ECDH shares. Salt is the handshake nonces, not a config file. */
export function deriveSessionKey(
  ssE: Uint8Array,
  ssS: Uint8Array,
  nonceC: Uint8Array,
  nonceS: Uint8Array,
  window: number,
  features: number,
  params: ArgonParams,
): { key: Uint8Array; ms: number } {
  const c = clampKdf(params);
  const t0 = Date.now();
  const key = argon2id(concat(ssE, ssS, u32be(window), new Uint8Array([features & 0xff])), concat(nonceC, nonceS), {
    t: c.iterations,
    m: c.memoryKiB,
    p: c.parallelism,
    dkLen: 32,
  });
  return { key, ms: Math.max(1, Date.now() - t0) };
}

type SessionDeriver = (
  ssE: Uint8Array,
  ssS: Uint8Array,
  nonceC: Uint8Array,
  nonceS: Uint8Array,
  window: number,
  features: number,
  params: ArgonParams,
) => Promise<{ key: Uint8Array; ms: number }>;

let sessionDeriver: SessionDeriver = async (ssE, ssS, nonceC, nonceS, window, features, params) =>
  deriveSessionKey(ssE, ssS, nonceC, nonceS, window, features, params);

/** Node agent points this at a worker pool. The browser keeps the inline call. */
export function setSessionKeyDeriver(fn: SessionDeriver | null) {
  sessionDeriver =
    fn ??
    (async (ssE, ssS, nonceC, nonceS, window, features, params) =>
      deriveSessionKey(ssE, ssS, nonceC, nonceS, window, features, params));
}

export function deriveSessionKeyAsync(
  ssE: Uint8Array,
  ssS: Uint8Array,
  nonceC: Uint8Array,
  nonceS: Uint8Array,
  window: number,
  features: number,
  params: ArgonParams,
) {
  return sessionDeriver(ssE, ssS, nonceC, nonceS, window, features, params);
}
