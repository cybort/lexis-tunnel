/**
 * HCTR2 (Crowley, Huckleberry, Biggers 2021) over AES-256: a tweakable,
 * length-preserving wide-block SPRP. Built only from @noble/ciphers' audited
 * AES block function and POLYVAL; checked against google/hctr2 official vectors
 * (hctr2.test.ts). Minimum message length is one block (16 bytes).
 */
import { aes256Block, type AesBlock } from "../native";
import { polyval } from "@noble/ciphers/_polyval.js";

const BLOCK = 16;

export type Hctr2Key = { aes: AesBlock; h: Uint8Array; L: Uint8Array };

function block(src?: Uint8Array): Uint8Array {
  const out = new Uint8Array(BLOCK);
  if (src) out.set(src.subarray(0, BLOCK));
  return out;
}

function aesEnc(k: Hctr2Key, input: Uint8Array): Uint8Array {
  return k.aes.enc(block(input));
}

function aesDec(k: Hctr2Key, input: Uint8Array): Uint8Array {
  return k.aes.dec(block(input));
}

export function hctr2Key(key: Uint8Array): Hctr2Key {
  if (key.length !== 32) throw new Error("HCTR2 needs a 32-byte AES-256 key");
  const k: Hctr2Key = { aes: aes256Block(key), h: new Uint8Array(BLOCK) as Uint8Array, L: new Uint8Array(BLOCK) as Uint8Array };
  k.h = aesEnc(k, new Uint8Array(BLOCK)); // h = E_K(0^128)
  const one = new Uint8Array(BLOCK);
  one[0] = 1;
  k.L = aesEnc(k, one); // L = E_K(bin(1))
  return k;
}

function le128(n: number): Uint8Array {
  const out = new Uint8Array(BLOCK);
  let v = n;
  for (let i = 0; i < 8 && v > 0; i++) {
    out[i] = v % 256;
    v = Math.floor(v / 256);
  }
  return out;
}

function padTo(data: Uint8Array, mult: number): Uint8Array {
  const len = Math.ceil(data.length / mult) * mult;
  const out = new Uint8Array(len);
  out.set(data);
  return out;
}

/** H_h(T, N): POLYVAL over tweak-length block || pad(T) || pad'(N). */
function hash(k: Hctr2Key, tweak: Uint8Array, n: Uint8Array): Uint8Array {
  const full = n.length % BLOCK === 0;
  const lenBlock = le128(2 * tweak.length * 8 + (full ? 2 : 3));
  let tail: Uint8Array;
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

function xor(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
  return out;
}

/** XCTR: block i (from 1) = E_K(S xor LE128(i)). */
function xctr(k: Hctr2Key, s: Uint8Array, data: Uint8Array): Uint8Array {
  const out = new Uint8Array(data.length);
  const nb = Math.ceil(data.length / BLOCK);
  const ctrs = new Uint8Array(nb * BLOCK);
  for (let i = 1; i <= nb; i++) ctrs.set(xor(s, le128(i)), (i - 1) * BLOCK);
  const ks = nb ? k.aes.enc(ctrs) : ctrs;
  for (let j = 0; j < data.length; j++) out[j] = data[j] ^ ks[j];
  return out;
}

export function hctr2Encrypt(k: Hctr2Key, tweak: Uint8Array, plaintext: Uint8Array): Uint8Array {
  if (plaintext.length < BLOCK) throw new Error("HCTR2 input shorter than one block");
  const m = plaintext.subarray(0, BLOCK);
  const n = plaintext.subarray(BLOCK);
  const mm = xor(m, hash(k, tweak, n));
  const uu = aesEnc(k, mm);
  const s = xor(xor(mm, uu), k.L);
  const v = xctr(k, s, n);
  const u = xor(uu, hash(k, tweak, v));
  const out = new Uint8Array(plaintext.length);
  out.set(u, 0);
  out.set(v, BLOCK);
  return out;
}

export function hctr2Decrypt(k: Hctr2Key, tweak: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  if (ciphertext.length < BLOCK) throw new Error("HCTR2 input shorter than one block");
  const u = ciphertext.subarray(0, BLOCK);
  const v = ciphertext.subarray(BLOCK);
  const uu = xor(u, hash(k, tweak, v));
  const mm = aesDec(k, uu);
  const s = xor(xor(mm, uu), k.L);
  const n = xctr(k, s, v);
  const m = xor(mm, hash(k, tweak, n));
  const out = new Uint8Array(ciphertext.length);
  out.set(m, 0);
  out.set(n, BLOCK);
  return out;
}
