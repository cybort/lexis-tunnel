/**
 * T20: keyed corpus word model and the two byte<->word mappings.
 *
 * The model always contains every vocabulary word, so any key parses any word
 * sequence (no "word not in this list" distinguisher). The key only decides which
 * word sits on which frequency rank, and only among ranks whose corpus counts are
 * within a factor of 1.5, so the rank/frequency (Zipf) curve is kept exactly and each
 * word's frequency stays close to its real corpus frequency.
 *
 * Mapping A (chosen): rANS. Ciphertext bytes are *decoded* as an rANS stream under the
 * word model, which turns uniform bytes into words drawn with the model's (Zipf)
 * probabilities; the receiver *encodes* the words back. The decoder's final state
 * (42 bits: 40-bit state + 2-bit count of virtual tail bytes) is sent first as a
 * prefix-coded (Huffman, same model) word header, so the header words are Zipf-like too.
 *
 * Mapping B (prototype, for comparison): GF(2^14) bijection. Each 14-bit chunk goes
 * through a keyed affine map in GF(2^14) to one of 16384 words. Dense, but every word
 * is equally likely, so it fails the Zipf requirement.
 */
import { ctr } from "@noble/ciphers/aes.js";
import { STATE_WEIGHTS } from "./state-table";
import { VOCAB_COUNTS, VOCAB_WORDS } from "./vocab-en";

export const SCALE_BITS = 24;
const M = 2 ** SCALE_BITS;
const L = 2 ** 32;
const XMAX_UNIT = (L / M) * 256; // 2^16

const WORDS: string[] = VOCAB_WORDS.split(" ");
const COUNTS: number[] = VOCAB_COUNTS.split(",").map(Number);
export const VOCAB_SIZE = WORDS.length;

/** Deterministic keystream for model construction and padding bits. */
export class KeyStream {
  private buf = new Uint8Array(0);
  private pos = 0;
  private block = 0;
  constructor(private key: Uint8Array, private label: number) {
    if (key.length !== 32) throw new Error("model key must be 32 bytes");
  }
  private refill() {
    const nonce = new Uint8Array(16);
    nonce[0] = this.label & 0xff;
    let b = this.block++;
    for (let i = 15; i >= 8 && b > 0; i--) {
      nonce[i] = b % 256;
      b = Math.floor(b / 256);
    }
    this.buf = ctr(this.key, nonce).encrypt(new Uint8Array(4096));
    this.pos = 0;
  }
  byte(): number {
    if (this.pos >= this.buf.length) this.refill();
    return this.buf[this.pos++];
  }
  u32(): number {
    return ((this.byte() << 24) | (this.byte() << 16) | (this.byte() << 8) | this.byte()) >>> 0;
  }
  below(n: number): number {
    const limit = Math.floor(2 ** 32 / n) * n;
    for (;;) {
      const v = this.u32();
      if (v < limit) return v % n;
    }
  }
}

/** Rank groups: consecutive ranks whose counts are within 1.5x, at most 256 wide. */
const GROUPS: Array<[number, number]> = (() => {
  const out: Array<[number, number]> = [];
  let start = 0;
  for (let i = 1; i <= WORDS.length; i++) {
    if (i === WORDS.length || COUNTS[i] * 1.5 < COUNTS[start] || i - start >= 256) {
      out.push([start, i]);
      start = i;
    }
  }
  return out;
})();

/** Quantized frequencies by rank, summing exactly to 2^24, each >= 1. */
const FREQ_BY_RANK: Uint32Array = (() => {
  const total = COUNTS.reduce((a, b) => a + b, 0);
  const f = new Uint32Array(WORDS.length);
  let sum = 0;
  for (let i = 0; i < f.length; i++) {
    f[i] = Math.max(1, Math.floor((COUNTS[i] / total) * M));
    sum += f[i];
  }
  // Put the rounding remainder on the most common ranks so sum === M.
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

export type WordModel = {
  words: string[]; // symbol -> word (symbol == rank)
  index: Map<string, number>; // word -> symbol
  freq: Uint32Array;
  cum: Uint32Array; // cum[s] = sum freq[<s]
  codeLen: Uint8Array; // canonical Huffman lengths for the header
  code: Uint32Array;
  decodeTree: Map<string, number>; // "len:code" -> symbol
  maxLen: number;
  padKey: Uint8Array;
};

const modelCache = new Map<string, WordModel>();

function hexOf(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += x.toString(16).padStart(2, "0");
  return s;
}

function huffmanLengths(freq: Uint32Array): Uint8Array {
  // Package-free Huffman via two queues on sorted frequencies (freq is non-increasing by rank).
  const n = freq.length;
  const order = Array.from({ length: n }, (_, i) => i).sort((a, b) => freq[a] - freq[b] || a - b);
  const weight: number[] = [];
  const parent: number[] = [];
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
  const depth = new Array<number>(weight.length).fill(0);
  for (let i = weight.length - 2; i >= 0; i--) depth[i] = depth[parent[i]] + 1;
  const lens = new Uint8Array(n);
  for (let k = 0; k < n; k++) lens[order[k]] = depth[k];
  return lens;
}

export function buildModel(lexKey: Uint8Array, padKey: Uint8Array): WordModel {
  const id = hexOf(lexKey) + hexOf(padKey);
  const hit = modelCache.get(id);
  if (hit) return hit;
  const ks = new KeyStream(lexKey, 1);
  const words = WORDS.slice();
  for (const [a, b] of GROUPS) {
    for (let i = b - 1; i > a; i--) {
      const j = a + ks.below(i - a + 1);
      const t = words[i];
      words[i] = words[j];
      words[j] = t;
    }
  }
  const index = new Map<string, number>();
  words.forEach((w, i) => index.set(w, i));
  const freq = FREQ_BY_RANK;
  const cum = new Uint32Array(freq.length + 1);
  for (let i = 0; i < freq.length; i++) cum[i + 1] = cum[i] + freq[i];
  const codeLen = huffmanLengths(freq);
  // Canonical codes.
  const syms = Array.from({ length: freq.length }, (_, i) => i).sort((a, b) => codeLen[a] - codeLen[b] || a - b);
  const code = new Uint32Array(freq.length);
  const decodeTree = new Map<string, number>();
  let c = 0;
  let prevLen = codeLen[syms[0]];
  for (const s of syms) {
    c <<= codeLen[s] - prevLen;
    prevLen = codeLen[s];
    code[s] = c;
    decodeTree.set(`${codeLen[s]}:${c}`, s);
    c++;
  }
  const model: WordModel = { words, index, freq, cum, codeLen, code, decodeTree, maxLen: prevLen, padKey };
  modelCache.set(id, model);
  if (modelCache.size > 16) modelCache.delete(modelCache.keys().next().value as string);
  return model;
}

/* Header for the rANS final state. The state is not uniform (rANS states follow a
 * roughly 1/x law, and the virtual-byte count is mostly 0), so sending its raw bits
 * made the first word of every frame ~7x more likely to be the top-ranked word
 * (measured). The coarse part (x >> 28, virt) is entropy-coded with a prefix code
 * built from the measured distribution (state-table.ts), which turns it into
 * near-uniform bits; the low 28 bits are close to uniform already. */
const LOW_BITS = 28;
let stateCode: { len: Uint8Array; code: Uint32Array; tree: Map<string, number> } | null = null;
function stateCoder() {
  if (stateCode) return stateCode;
  const bin = atob(STATE_WEIGHTS);
  const raw = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) raw[i] = bin.charCodeAt(i);
  const w = new Uint32Array(raw.buffer, raw.byteOffset, raw.byteLength >>> 2);
  const len = huffmanLengths(w);
  const syms = Array.from({ length: w.length }, (_, i) => i).sort((a, b) => len[a] - len[b] || a - b);
  const code = new Uint32Array(w.length);
  const tree = new Map<string, number>();
  let c = 0;
  let prev = len[syms[0]];
  for (const s of syms) {
    c <<= len[s] - prev;
    prev = len[s];
    code[s] = c;
    tree.set(`${len[s]}:${c}`, s);
    c++;
  }
  stateCode = { len, code, tree };
  return stateCode;
}

function findSym(model: WordModel, slot: number): number {
  let lo = 0;
  let hi = model.freq.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (model.cum[mid] <= slot) lo = mid;
    else hi = mid - 1;
  }
  return lo;
}

/** rANS: bytes (>= 4) -> word symbols. Never throws. */
export function bytesToWords(model: WordModel, data: Uint8Array, padSeed: number): string[] {
  if (data.length < 4) throw new Error("rANS mapping needs at least 4 bytes");
  let x = L + (((data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3]) >>> 0);
  let pos = 4;
  let virt = 0;
  let vks: KeyStream | null = null;
  const syms: number[] = [];
  while (pos < data.length) {
    const slot = x % M;
    const s = findSym(model, slot);
    syms.push(s);
    x = model.freq[s] * Math.floor(x / M) + slot - model.cum[s];
    while (x < L) {
      if (pos < data.length) x = x * 256 + data[pos++];
      else {
        // Virtual tail bytes are dropped by the receiver; fill them with keyed
        // pseudo-random bytes (zeros biased the low state bits in the header).
        vks ??= new KeyStream(model.padKey, 1000 + (padSeed & 0xff));
        x = x * 256 + vks.byte();
        virt++;
      }
    }
  }
  // Header: prefix-coded (x >> 28, virt), then the low 28 bits; Huffman-decoded into words.
  const sc = stateCoder();
  const hs = (Math.floor(x / 2 ** LOW_BITS) - 16) * 4 + virt;
  let bits = sc.code[hs].toString(2).padStart(sc.len[hs], "0");
  bits += (x % 2 ** LOW_BITS).toString(2).padStart(LOW_BITS, "0");
  const ks = new KeyStream(model.padKey, 2 + (padSeed & 0xff));
  const head: number[] = [];
  let acc = "";
  const pull = (i: number) => (i < bits.length ? bits[i] : (ks.byte() & 1).toString());
  let i = 0;
  while (i < bits.length) {
    acc += pull(i++);
    const s = model.decodeTree.get(`${acc.length}:${parseInt(acc, 2)}`);
    if (s !== undefined) {
      head.push(s);
      acc = "";
    }
  }
  while (acc.length > 0) {
    acc += pull(i++);
    const s = model.decodeTree.get(`${acc.length}:${parseInt(acc, 2)}`);
    if (s !== undefined) {
      head.push(s);
      acc = "";
    }
    if (acc.length > 40) acc = ""; // unreachable for a complete prefix code
  }
  return [...head, ...syms].map((s) => model.words[s]);
}

/** rANS inverse: words -> bytes. Unknown words count as symbol 0. Never throws. */
export function wordsToBytes(model: WordModel, words: string[]): Uint8Array {
  const syms = words.map((w) => model.index.get(w) ?? 0);
  const sc = stateCoder();
  let bits = "";
  let k = 0;
  let hs = -1;
  let used = 0;
  while (k < syms.length) {
    if (hs < 0) {
      for (let n = 1; n <= bits.length && n <= 40; n++) {
        const v = sc.tree.get(`${n}:${parseInt(bits.slice(0, n), 2)}`);
        if (v !== undefined) {
          hs = v;
          used = n;
          break;
        }
      }
    }
    if (hs >= 0 && bits.length >= used + LOW_BITS) break;
    const s = syms[k++];
    bits += model.code[s].toString(2).padStart(model.codeLen[s], "0");
  }
  if (hs < 0) {
    for (let n = 1; n <= bits.length && n <= 40; n++) {
      const v = sc.tree.get(`${n}:${parseInt(bits.slice(0, n), 2)}`);
      if (v !== undefined) {
        hs = v;
        used = n;
        break;
      }
    }
  }
  if (hs < 0) hs = 0;
  const low = parseInt(bits.slice(used, used + LOW_BITS).padEnd(LOW_BITS, "0"), 2);
  const virt = hs % 4;
  let x = (Math.floor(hs / 4) + 16) * 2 ** LOW_BITS + low;
  const out: number[] = [];
  for (let j = syms.length - 1; j >= k; j--) {
    const s = syms[j];
    const f = model.freq[s];
    const xmax = XMAX_UNIT * f;
    while (x >= xmax) {
      out.push(x % 256);
      x = Math.floor(x / 256);
    }
    x = Math.floor(x / f) * M + (x % f) + model.cum[s];
  }
  const head = ((x - L) % L + L) % L;
  const body = out.reverse();
  const keep = Math.max(0, body.length - virt);
  const res = new Uint8Array(4 + keep);
  res[0] = (head >>> 24) & 0xff;
  res[1] = (head >>> 16) & 0xff;
  res[2] = (head >>> 8) & 0xff;
  res[3] = head & 0xff;
  for (let j = 0; j < keep; j++) res[4 + j] = body[j];
  return res;
}

/* ---------- Mapping B: GF(2^14) affine bijection (prototype) ---------- */

const GF_M = 14;
const GF_POLY = 0x402b; // x^14 + x^5 + x^3 + x + 1 (primitive)

function gfMul(a: number, b: number): number {
  let r = 0;
  while (b) {
    if (b & 1) r ^= a;
    b >>= 1;
    a <<= 1;
    if (a & (1 << GF_M)) a ^= GF_POLY;
  }
  return r;
}

function gfInv(a: number): number {
  // a^(2^14 - 2)
  let r = 1;
  let e = (1 << GF_M) - 2;
  let base = a;
  while (e) {
    if (e & 1) r = gfMul(r, base);
    base = gfMul(base, base);
    e >>= 1;
  }
  return r;
}

export type GfModel = { a: number; ainv: number; b: number; words: string[]; index: Map<string, number> };

export function buildGfModel(lexKey: Uint8Array): GfModel {
  const ks = new KeyStream(lexKey, 9);
  let a = 0;
  while (a === 0) a = ks.below(1 << GF_M);
  const b = ks.below(1 << GF_M);
  const words = WORDS.slice(0, 1 << GF_M);
  for (let i = words.length - 1; i > 0; i--) {
    const j = ks.below(i + 1);
    const t = words[i];
    words[i] = words[j];
    words[j] = t;
  }
  const index = new Map<string, number>();
  words.forEach((w, i) => index.set(w, i));
  return { a, ainv: gfInv(a), b, words, index };
}

export function gfBytesToWords(model: GfModel, data: Uint8Array): string[] {
  const out: string[] = [];
  let acc = 0;
  let nbits = 0;
  for (let i = 0; i < data.length; i++) {
    acc = (acc << 8) | data[i];
    nbits += 8;
    while (nbits >= GF_M) {
      nbits -= GF_M;
      const c = (acc >> nbits) & ((1 << GF_M) - 1);
      out.push(model.words[gfMul(model.a, c) ^ model.b]);
    }
    acc &= (1 << nbits) - 1;
  }
  if (nbits > 0) out.push(model.words[gfMul(model.a, (acc << (GF_M - nbits)) & ((1 << GF_M) - 1)) ^ model.b]);
  return out;
}

export function gfWordsToBytes(model: GfModel, words: string[], byteLen: number): Uint8Array {
  const out = new Uint8Array(byteLen);
  let acc = 0;
  let nbits = 0;
  let o = 0;
  for (const w of words) {
    const y = model.index.get(w) ?? 0;
    const c = gfMul(model.ainv, y ^ model.b);
    acc = (acc << GF_M) | c;
    nbits += GF_M;
    while (nbits >= 8 && o < byteLen) {
      nbits -= 8;
      out[o++] = (acc >> nbits) & 0xff;
    }
    acc &= (1 << nbits) - 1;
  }
  return out;
}

export const CORPUS = { words: WORDS, counts: COUNTS, freqByRank: FREQ_BY_RANK, groups: GROUPS };
