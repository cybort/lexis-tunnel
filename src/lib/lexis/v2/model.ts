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
import { aesCtrKeystream } from "../native";
import { STATE_WEIGHTS } from "./state-table";
import { VOCAB_COUNTS, VOCAB_WORDS } from "./vocab-en";
import { ALLOWED_COUNTS, ALLOWED_MU, ALLOWED_PACK, ALLOWED_SIG, ALLOWED_WORDS } from "./vocab-allowed";

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
    this.buf = new Uint8Array(aesCtrKeystream(this.key, nonce, 4096));
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
function groupsOf(counts: number[]): Array<[number, number]> {
  const out: Array<[number, number]> = [];
  let start = 0;
  for (let i = 1; i <= counts.length; i++) {
    if (i === counts.length || counts[i] * 1.5 < counts[start] || i - start >= 256) {
      out.push([start, i]);
      start = i;
    }
  }
  return out;
}
const GROUPS: Array<[number, number]> = groupsOf(COUNTS);

/** Quantized frequencies by rank, summing exactly to 2^24, each >= 1. */
function quantize(counts: number[]): Uint32Array {
  const total = counts.reduce((a, b) => a + b, 0);
  const f = new Uint32Array(counts.length);
  let sum = 0;
  for (let i = 0; i < f.length; i++) {
    f[i] = Math.max(1, Math.floor((counts[i] / total) * M));
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
}
const FREQ_BY_RANK: Uint32Array = quantize(COUNTS);

/** bb-k-v4s: GROUP-FLAT quantized frequencies (sum exactly 2^24, each >= 1). Every rank of a group
 * gets the same frequency (group share / group size, rounded), so the in-group key permutation
 * never changes any word's probability: the word distribution, and with it any candidate-key
 * likelihood statistic, is the same for every key. The rounding remainder is fixed exactly on the
 * first two groups of coprime sizes. Must match scripts/build-vocab-allowed.mjs (v4s.test.ts). */
export function quantizeFlat(counts: number[], gs: Array<[number, number]>): Uint32Array {
  const total = counts.reduce((x, y) => x + y, 0);
  const fg = gs.map(([a, b]) => {
    let g = 0;
    for (let i = a; i < b; i++) g += counts[i];
    return Math.max(1, Math.round(((g / total) * M) / (b - a)));
  });
  let R = M;
  gs.forEach(([a, b], j) => {
    R -= fg[j] * (b - a);
  });
  const gcd = (x: number, y: number): number => (y ? gcd(y, x % y) : x);
  let ja = -1;
  let jb = -1;
  outer: for (let x = 0; x < gs.length; x++)
    for (let y = x + 1; y < gs.length; y++)
      if (gcd(gs[x][1] - gs[x][0], gs[y][1] - gs[y][0]) === 1) {
        ja = x;
        jb = y;
        break outer;
      }
  if (ja < 0) throw new Error("no coprime group sizes");
  const sa = gs[ja][1] - gs[ja][0];
  const sb = gs[jb][1] - gs[jb][0];
  const sg = Math.sign(R);
  const r = Math.abs(R);
  let y = 0;
  while ((r - y * sb) % sa !== 0) y++;
  if (r - y * sb < 0) throw new Error("remainder not representable");
  fg[ja] += sg * ((r - y * sb) / sa);
  fg[jb] += sg * y;
  if (fg[ja] < 1 || fg[jb] < 1) throw new Error("flat quantize underflow");
  const out = new Uint32Array(counts.length);
  gs.forEach(([a, b], j) => out.fill(fg[j], a, b));
  return out;
}

export type WordModel = {
  words: string[]; // symbol -> word (symbol == rank)
  index: Map<string, number>; // word -> symbol
  freq: Uint32Array;
  cum: Uint32Array; // cum[s] = sum freq[<s]
  codeLen: Uint8Array; // canonical Huffman lengths for the header
  code: Uint32Array;
  decodeTree: Map<number, number>; // treeKey(len, code) -> symbol (shared by every model)
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

/** Numeric prefix-code key: code < 2^40 and len < 64, so code * 64 + len is an exact safe integer. */
function treeKey(len: number, code: number): number {
  return code * 64 + len;
}

type PrefixCode = { len: Uint8Array; code: Uint32Array; tree: Map<number, number>; maxLen: number };

/** Canonical prefix code (lengths, codes, decode map) for a weight table. */
function canonicalCode(w: Uint32Array): PrefixCode {
  const len = huffmanLengths(w);
  const syms = Array.from({ length: w.length }, (_, i) => i).sort((a, b) => len[a] - len[b] || a - b);
  const code = new Uint32Array(w.length);
  const tree = new Map<number, number>();
  let c = 0;
  let prev = len[syms[0]];
  for (const s of syms) {
    c <<= len[s] - prev;
    prev = len[s];
    code[s] = c;
    tree.set(treeKey(len[s], c), s);
    c++;
  }
  return { len, code, tree, maxLen: prev };
}

/* Frequencies, cumulative table and the header Huffman code depend only on the corpus
 * (FREQ_BY_RANK), never on the session key, so they are built once per process and shared
 * read-only by every model (they used to be rebuilt on every handshake, ~2.3 MB each). */
/** One word corpus (words by rank, counts, rank groups, quantized frequencies) and its lazily
 * built key-independent tables. The legacy corpus (vocab-en.ts, public 32768 words) serves every dte
 * except bb-k-v4s; the allowed corpus (vocab-allowed.ts) serves bb-k-v4s only. */
type Corpus = {
  words: string[];
  counts: number[];
  groups: Array<[number, number]>;
  freq: Uint32Array;
  tables: { cum: Uint32Array; pc: PrefixCode } | null;
  cache: Map<string, WordModel>;
};
const LEGACY: Corpus = { words: WORDS, counts: COUNTS, groups: GROUPS, freq: FREQ_BY_RANK, tables: null, cache: modelCache };
function corpusTablesOf(c: Corpus) {
  if (c.tables) return c.tables;
  const freq = c.freq;
  const cum = new Uint32Array(freq.length + 1);
  for (let i = 0; i < freq.length; i++) cum[i + 1] = cum[i] + freq[i];
  c.tables = { cum, pc: canonicalCode(freq) };
  return c.tables;
}
export function buildModel(lexKey: Uint8Array, padKey: Uint8Array): WordModel {
  return buildModelOn(LEGACY, lexKey, padKey);
}

function buildModelOn(corpus: Corpus, lexKey: Uint8Array, padKey: Uint8Array): WordModel {
  const id = hexOf(lexKey) + hexOf(padKey);
  const modelCache = corpus.cache;
  const hit = modelCache.get(id);
  if (hit) return hit;
  const ks = new KeyStream(lexKey, 1);
  const words = corpus.words.slice();
  for (const [a, b] of corpus.groups) {
    for (let i = b - 1; i > a; i--) {
      const j = a + ks.below(i - a + 1);
      const t = words[i];
      words[i] = words[j];
      words[j] = t;
    }
  }
  const index = new Map<string, number>();
  words.forEach((w, i) => index.set(w, i));
  const { cum, pc } = corpusTablesOf(corpus);
  const model: WordModel = { words, index, freq: corpus.freq, cum, codeLen: pc.len, code: pc.code, decodeTree: pc.tree, maxLen: pc.maxLen, padKey };
  modelCache.set(id, model);
  if (modelCache.size > 16) modelCache.delete(modelCache.keys().next().value as string);
  return model;
}

/** v4 DTE (rans-v4): ONE key-independent word model (corpus rank order). Because every
 * key parses the wire with the same model, words -> bytes is the same function for
 * every candidate key, so re-encoding / canonicality / header / tail checks carry no
 * key information. The sender fills virtual tail bytes and header pad bits from a
 * CSPRNG (B1: randomized, non-canonical), so a re-encode does not even reproduce the
 * wire under the right key. See docs/design/frame-v4-dte.md. */
let v4Model: WordModel | null = null;
export function buildModelV4(): WordModel {
  if (v4Model) return v4Model;
  const words = WORDS.slice();
  const index = new Map<string, number>();
  words.forEach((w, i) => index.set(w, i));
  const base = buildModel(new Uint8Array(32), new Uint8Array(32));
  v4Model = { ...base, words, index, padKey: new Uint8Array(32) };
  return v4Model;
}

/* ---------- bb-k-v4s: shared allowed set (D-pool) ----------
 * One allowed word set for every session (vocab-allowed.ts: the cleaned FrequencyWords list
 * with a small set of specified whole words removed at build time). Frequencies, cumulative
 * table and header code depend only on this set and are built once per process. A session key
 * only permutes words among ranks of the same near-equal-frequency group (counts within 1.5x,
 * at most 256 wide), exactly like buildModel: EVERY keyed model contains EVERY allowed word, so
 * a candidate key never yields a "word not in this model" test. There is no secret subset.
 * Frequencies are group-flat (quantizeFlat), so the permutation also never changes a word's
 * probability (no candidate-key likelihood test). */
let allowed: Corpus | null = null;
function allowedCorpus(): Corpus {
  if (allowed) return allowed;
  const words = ALLOWED_WORDS.split(" ");
  const counts = ALLOWED_COUNTS.split(",").map(Number);
  const groups = groupsOf(counts);
  allowed = { words, counts, groups, freq: quantizeFlat(counts, groups), tables: null, cache: new Map() };
  return allowed;
}
/** Keyed model over the allowed set (bb-k-v4s hello: wordsIkm; data/finish: session key sk). */
export function buildModelS(lexKey: Uint8Array, padKey: Uint8Array): WordModel {
  return buildModelOn(allowedCorpus(), lexKey, padKey);
}
/** Allowed-set corpus (measurement and tests). */
export function corpusS() {
  const c = allowedCorpus();
  return { pack: ALLOWED_PACK, words: c.words, counts: c.counts, freqByRank: c.freq, groups: c.groups, mu: ALLOWED_MU, sig: ALLOWED_SIG };
}

/** CSPRNG byte source for the v4 sender (buffered). */
export function csprngFill(): () => number {
  let buf = new Uint8Array(0);
  let pos = 0;
  return () => {
    if (pos >= buf.length) {
      buf = crypto.getRandomValues(new Uint8Array(256));
      pos = 0;
    }
    return buf[pos++];
  };
}

/* Header for the rANS final state. The state is not uniform (rANS states follow a
 * roughly 1/x law, and the virtual-byte count is mostly 0), so sending its raw bits
 * made the first word of every frame ~7x more likely to be the top-ranked word
 * (measured). The coarse part (x >> 28, virt) is entropy-coded with a prefix code
 * built from the measured distribution (state-table.ts), which turns it into
 * near-uniform bits; the low 28 bits are close to uniform already. */
const LOW_BITS = 28;
let stateCode: PrefixCode | null = null;
function stateCoder(): PrefixCode {
  if (stateCode) return stateCode;
  const bin = atob(STATE_WEIGHTS);
  const raw = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) raw[i] = bin.charCodeAt(i);
  stateCode = canonicalCode(new Uint32Array(raw.buffer, raw.byteOffset, raw.byteLength >>> 2));
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
export function bytesToWords(model: WordModel, data: Uint8Array, padSeed: number, fill?: () => number): string[] {
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
        // v4 (fill given): CSPRNG bytes, so the tail is not a function of any key.
        if (fill) x = x * 256 + (fill() & 0xff);
        else {
          vks ??= new KeyStream(model.padKey, 1000 + (padSeed & 0xff));
          x = x * 256 + vks.byte();
        }
        virt++;
      }
    }
  }
  // Header: prefix-coded (x >> 28, virt), then the low 28 bits; Huffman-decoded into words.
  const sc = stateCoder();
  const hs = (Math.floor(x / 2 ** LOW_BITS) - 16) * 4 + virt;
  let bits = sc.code[hs].toString(2).padStart(sc.len[hs], "0");
  bits += (x % 2 ** LOW_BITS).toString(2).padStart(LOW_BITS, "0");
  const ks = fill ? null : new KeyStream(model.padKey, 2 + (padSeed & 0xff));
  const head: number[] = [];
  let acc = "";
  const pull = (i: number) => (i < bits.length ? bits[i] : ((ks ? ks.byte() : fill!()) & 1).toString());
  let i = 0;
  while (i < bits.length) {
    acc += pull(i++);
    const s = model.decodeTree.get(treeKey(acc.length, parseInt(acc, 2)));
    if (s !== undefined) {
      head.push(s);
      acc = "";
    }
  }
  while (acc.length > 0) {
    acc += pull(i++);
    const s = model.decodeTree.get(treeKey(acc.length, parseInt(acc, 2)));
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
        const v = sc.tree.get(treeKey(n, parseInt(bits.slice(0, n), 2)));
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
      const v = sc.tree.get(treeKey(n, parseInt(bits.slice(0, n), 2)));
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

/** Measurement helper (acceptance scripts only): the rANS header a receiver parses from a
 * word sequence -- the coded (x >> 28, virt) symbol, the virtual-tail count and the
 * number of header words. */
export function headerOf(model: WordModel, words: string[]): { hs: number; virt: number; headWords: number } {
  const sc = stateCoder();
  let bits = "";
  let k = 0;
  for (const w of words) {
    const s = model.index.get(w) ?? 0;
    bits += model.code[s].toString(2).padStart(model.codeLen[s], "0");
    k++;
    for (let n = 1; n <= bits.length && n <= 40; n++) {
      const v = sc.tree.get(treeKey(n, parseInt(bits.slice(0, n), 2)));
      if (v !== undefined) {
        if (bits.length >= n + LOW_BITS) return { hs: v, virt: v % 4, headWords: k };
        break;
      }
    }
  }
  return { hs: -1, virt: -1, headWords: k };
}
