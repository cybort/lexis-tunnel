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
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { hctr2Decrypt, hctr2Encrypt, hctr2Key, type Hctr2Key } from "./hctr2";
import { buildModel, bytesToWords, wordsToBytes, type WordModel } from "./model";

/** Wire protocol identity. Deliberately NOT sent on the wire (a version byte is a fingerprint);
 *  both ends must run the same protocol. Incompatible with 1.8.0 (lexis-codebook-ctr-v1). */
export const PROTOCOL = { name: "lexis-hctr2-rans-v3", version: 3, agent: "3.0.3" } as const;

export type Dir = "e2g" | "g2e";
const enc = new TextEncoder();

export type V2Keys = {
  gen: number;
  perm: Hctr2Key;
  model: WordModel;
  padKey: Uint8Array;
  mnemonic: Uint8Array;
};

function derive(sk: Uint8Array, label: string, gen: number, len = 32): Uint8Array {
  return hkdf(sha256, sk, enc.encode("lexis-v2"), enc.encode(`${label}|gen=${gen}`), len);
}

export function deriveV2Keys(sk: Uint8Array, gen = 0, mnemonicBase?: Uint8Array | null): V2Keys {
  const lexKey = derive(sk, "lex", gen);
  const padKey = derive(sk, "pad", gen);
  // D2 honey: the mnemonic is derived from a per-handshake secret (mnemonicBase) that
  // both ends contribute to and that is transported encrypted under the ephemeral DH
  // secret. It is NOT derivable from sk-via-public, long-term keys, or the transcript.
  // (When mnemonicBase is omitted -- unit tests -- it falls back to sk.)
  const mnemonic = mnemonicBase
    ? hkdf(sha256, mnemonicBase, enc.encode("lexis-v2-mnemonic"), enc.encode(`mnemonic|gen=${gen}`), 16)
    : derive(sk, "mnemonic", gen, 16);
  return {
    gen,
    perm: hctr2Key(derive(sk, "perm", gen)),
    model: buildModel(lexKey, padKey),
    padKey,
    mnemonic,
  };
}

/** Rekey: next generation from the current key and the 20-byte rekey payload. */
export function nextSessionKey(sk: Uint8Array, payload: Uint8Array): Uint8Array {
  return hkdf(sha256, sk, payload, enc.encode("lexis-v2-rekey"), 32);
}

export function tweakOf(counter: number, dir: Dir, window: number, gen: number): Uint8Array {
  const t = new Uint8Array(16);
  let c = counter;
  for (let i = 7; i >= 0; i--) {
    t[i] = c % 256;
    c = Math.floor(c / 256);
  }
  t[8] = dir === "e2g" ? 1 : 2;
  t[9] = (window >>> 24) & 0xff;
  t[10] = (window >>> 16) & 0xff;
  t[11] = (window >>> 8) & 0xff;
  t[12] = window & 0xff;
  t[13] = (gen >>> 8) & 0xff;
  t[14] = gen & 0xff;
  t[15] = 0x4c;
  return t;
}

export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

export const OVERHEAD = 18;

/* D2: the length field must decode to an in-range value under ANY key, otherwise
 * "is the length plausible?" is a key-verification oracle (measured: 0.5% of wrong
 * keys vs 100% of right keys before df74b5a).
 * D2b (honey length share): df74b5a stored len mod (C+1), which made len/C uniform for a
 * wrong key but ~1 - pad/C for the right key (AUC ~1.0 on large frames). The field now
 * carries the PAD: pad = field mod (min(255, C) + 1), len = C - pad. A wrong key gets a
 * pad uniform on [0, min(255, C)]; the right key's pad is the sender's PRF pad, uniform
 * on [0, maxPad(len)], so whenever maxPad is saturated (255) the two are identical.
 * The sender stores a uniformly random representative in [0, 65535]. */
export function padModulus(capacity: number): number {
  return Math.min(255, capacity) + 1;
}
export function encodeLenField(len: number, capacity: number): number {
  const pad = capacity - len;
  const m = padModulus(capacity);
  if (pad < 0 || pad >= m) throw new Error("pad out of range");
  const count = Math.floor((0xffff - pad) / m) + 1;
  const r = crypto.getRandomValues(new Uint32Array(1))[0] % count;
  return pad + r * m;
}
export function decodeLenField(field: number, capacity: number): number {
  return capacity - (field % padModulus(capacity));
}

/** Measured wire bytes (UTF-8 chars incl. spaces) per sealed inner byte for the rANS word
 * stream (accept C/D: 4.16). D1: frame.maxExpansion is a WIRE budget over the compressed
 * size, so the pad budget is maxExpansion*|P|/WIRE_PER_INNER_BYTE - |P| - OVERHEAD. */
export const WIRE_PER_INNER_BYTE = 4.16;

/** frame.smallFramePolicy. "expansion" (default): pad only within the maxExpansion wire
 * budget, so small frames get no pad. "honey": always allow up to 255 B of pad so the
 * real pad share matches the wrong-key decode (uniform on [0, min(255, C)]) on every
 * frame size, at the cost of expansion on small frames. Sender-only: the receiver reads
 * the pad from the length field, so both policies interoperate on the same protocol id. */
export type SmallFramePolicy = "expansion" | "honey";

export function padLength(keys: V2Keys, counter: number, dir: Dir, len: number, maxExpansion: number, policy: SmallFramePolicy = "expansion"): number {
  if (policy === "honey") {
    const mix = sha256(new Uint8Array([...keys.padKey, ...tweakOf(counter, dir, 0, keys.gen)]));
    return ((mix[0] << 8) | mix[1]) % 256;
  }
  const budget = Math.floor((maxExpansion * Math.max(len, 1)) / WIRE_PER_INNER_BYTE) - len;
  const maxPad = Math.max(0, Math.min(255, budget - OVERHEAD));
  if (maxPad === 0) return 0;
  const mix = sha256(new Uint8Array([...keys.padKey, ...tweakOf(counter, dir, 0, keys.gen)]));
  return ((mix[0] << 8) | mix[1]) % (maxPad + 1);
}

export function sealV2(opts: {
  keys: V2Keys;
  counter: number;
  window: number;
  dir: Dir;
  plaintext: Uint8Array;
  maxExpansion?: number;
  smallFramePolicy?: SmallFramePolicy;
}): string {
  const { keys, counter, window, dir, plaintext } = opts;
  if (plaintext.length > 0xffff) throw new Error("frame too large");
  if (!Number.isSafeInteger(counter) || counter < 1) throw new Error("bad counter");
  const pad = padLength(keys, counter, dir, plaintext.length, opts.maxExpansion ?? 2, opts.smallFramePolicy ?? "expansion");
  const inner = new Uint8Array(plaintext.length + pad + OVERHEAD);
  inner.set(plaintext, 0);
  if (pad) {
    const fill = sha256(new Uint8Array([...keys.padKey, 0x70, ...tweakOf(counter, dir, window, keys.gen)]));
    for (let i = 0; i < pad; i++) inner[plaintext.length + i] = fill[i % 32] ^ (i >> 5);
  }
  inner.set(keys.mnemonic, plaintext.length + pad);
  const field = encodeLenField(plaintext.length, plaintext.length + pad);
  inner[inner.length - 2] = (field >> 8) & 0xff;
  inner[inner.length - 1] = field & 0xff;
  const cipher = hctr2Encrypt(keys.perm, tweakOf(counter, dir, window, keys.gen), inner);
  return bytesToWords(keys.model, cipher, counter & 0xff).join(" ");
}

/** Raw SPRP inverse without any check: used by the wrong-key randomness tests. */
export function unsealRawV2(keys: V2Keys, counter: number, window: number, dir: Dir, prose: string): Uint8Array {
  const words = prose.trim().toLowerCase().split(/\s+/).filter(Boolean);
  const cipher = wordsToBytes(keys.model, words);
  if (cipher.length < 16) return cipher;
  return hctr2Decrypt(keys.perm, tweakOf(counter, dir, window, keys.gen), cipher);
}

export class FrameError extends Error {}

export type HoneyView = { mnemonic: Uint8Array; body: Uint8Array; formatValid: boolean };

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
export function openV2Honey(opts: { keys: V2Keys; counter: number; window: number; dir: Dir; prose: string }): HoneyView {
  const words = opts.prose.trim().toLowerCase().split(/\s+/).filter(Boolean);
  const cipher = wordsToBytes(opts.keys.model, words);
  const inner = cipher.length >= 16 ? hctr2Decrypt(opts.keys.perm, tweakOf(opts.counter, opts.dir, opts.window, opts.keys.gen), cipher) : cipher;
  if (inner.length < OVERHEAD) return { mnemonic: new Uint8Array(16), body: new Uint8Array(0), formatValid: false };
  const mnemonic = inner.slice(inner.length - OVERHEAD, inner.length - 2);
  const len = decodeLenField((inner[inner.length - 2] << 8) | inner[inner.length - 1], inner.length - OVERHEAD);
  let canonical = true;
  if (cipher.length >= 16) {
    const again = bytesToWords(opts.keys.model, cipher, opts.counter & 0xff);
    canonical = again.length === words.length && again.every((w, i) => w === words[i]);
  }
  const formatValid = canonical; // the length is in range for every key by construction
  const body = inner.slice(0, len);
  return { mnemonic, body, formatValid };
}

export function openV2(opts: { keys: V2Keys; counter: number; window: number; dir: Dir; prose: string }): Uint8Array {
  const words = opts.prose.trim().toLowerCase().split(/\s+/).filter(Boolean);
  const cipher = wordsToBytes(opts.keys.model, words);
  if (cipher.length < OVERHEAD) throw new FrameError("帧完整性校验失败");
  // Canonical encoding: the rANS tail can carry virtual bytes that do not reach the
  // ciphertext, so re-encode and require the exact word sequence (no wire malleability).
  const again = bytesToWords(opts.keys.model, cipher, opts.counter & 0xff);
  if (again.length !== words.length || again.some((w, i) => w !== words[i])) throw new FrameError("帧完整性校验失败");
  const inner = hctr2Decrypt(opts.keys.perm, tweakOf(opts.counter, opts.dir, opts.window, opts.keys.gen), cipher);
  if (inner.length < OVERHEAD) throw new FrameError("帧完整性校验失败");
  const mn = inner.subarray(inner.length - OVERHEAD, inner.length - 2);
  const ok = constantTimeEqual(mn, opts.keys.mnemonic);
  const len = decodeLenField((inner[inner.length - 2] << 8) | inner[inner.length - 1], inner.length - OVERHEAD);
  if (!ok) throw new FrameError("帧完整性校验失败");
  return inner.slice(0, len);
}

/* ---------- D1: coalescing / splitting container (inside the SPRP) ----------
 * The sealed plaintext of every frame is a batch of segments:
 *   segment = u8 flag || u24be len || bytes
 *   flag 0 = one complete packed record
 *   flag 1 = fragment of a record, more fragments follow in the next frame(s)
 *   flag 2 = last fragment; the receiver joins the buffered fragments + this one
 * The batch is the SPRP plaintext, so segment boundaries and fragment flags are
 * encrypted and authenticated (any change fails the mnemonic check). There is no
 * separate on-wire length: the only externally visible size is the sealed frame,
 * which is padded exactly as before. */
export const SEG_COMPLETE = 0;
export const SEG_MORE = 1;
export const SEG_LAST = 2;
export const SEG_HEADER = 4;

export type Segment = { flag: number; data: Uint8Array };

export function packBatch(segs: Segment[]): Uint8Array {
  let total = 0;
  for (const s of segs) total += SEG_HEADER + s.data.length;
  const out = new Uint8Array(total);
  let o = 0;
  for (const s of segs) {
    if (s.data.length > 0xffffff) throw new Error("segment too large");
    out[o] = s.flag & 0xff;
    out[o + 1] = (s.data.length >>> 16) & 0xff;
    out[o + 2] = (s.data.length >>> 8) & 0xff;
    out[o + 3] = s.data.length & 0xff;
    out.set(s.data, o + SEG_HEADER);
    o += SEG_HEADER + s.data.length;
  }
  return out;
}

export function unpackBatch(buf: Uint8Array): Segment[] {
  const segs: Segment[] = [];
  let o = 0;
  while (o < buf.length) {
    if (o + SEG_HEADER > buf.length) throw new FrameError("批量段头被截断");
    const flag = buf[o];
    const len = (buf[o + 1] << 16) | (buf[o + 2] << 8) | buf[o + 3];
    o += SEG_HEADER;
    if (flag > SEG_LAST || o + len > buf.length) throw new FrameError("批量段越界");
    segs.push({ flag, data: buf.slice(o, o + len) });
    o += len;
  }
  return segs;
}

/** Reassembles fragments across frames (frames are strictly ordered, so one buffer). */
export class Reassembler {
  private parts: Uint8Array[] = [];
  private size = 0;
  constructor(private readonly cap = 1 << 20) {}
  /** Returns the complete packed records carried by one batch, in order. */
  feed(segs: Segment[]): Uint8Array[] {
    const out: Uint8Array[] = [];
    for (const s of segs) {
      if (s.flag === SEG_COMPLETE) {
        if (this.parts.length) throw new FrameError("分片未结束就来了完整记录");
        out.push(s.data);
        continue;
      }
      this.size += s.data.length;
      if (this.size > this.cap) throw new FrameError("分片重组超过上限");
      this.parts.push(s.data);
      if (s.flag === SEG_LAST) {
        const whole = new Uint8Array(this.size);
        let o = 0;
        for (const p of this.parts) {
          whole.set(p, o);
          o += p.length;
        }
        out.push(whole);
        this.parts = [];
        this.size = 0;
      }
    }
    return out;
  }
}
