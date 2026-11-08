/**
 * v4 comparison DTEs A1-A4 (frame.dte). See docs/design/frame-v4-a1-a4.md.
 *
 * All variants share the bb-v4 exact range partition over the public model (bb.ts) and
 * differ in four switches:
 *   c8    (A1, A3)  scheme 2: 8-bit trajectory closure. parse(W) = X(W) xor G(d(W)) where
 *                   X = top 8n bits of low(W), d = r8(W) xor H8(W), r8 = the 8 bits right below X,
 *                   H8 = public hash of every symbol. G(0) = 0, G(d)[0] = d. A tail-word change
 *                   leaves X but changes d w.p. 255/256, so it changes the ciphertext.
 *                   Sender: d0 uniform, X = C xor G(d0), resample the CSPRNG tail until d(W) = d0.
 *   tilt  (A2, A3)  scheme 1: OU mean reversion. Before each word the coder picks one of 5
 *                   public tables p^beta (beta in .92 .96 1 1.04 1.08) from the integer bit-level
 *                   deviation dev = I_t - mu*t (I_t = E - bitlen(range) + 1, exact, both ends).
 *                   The length margin becomes Z*min(sigma*sqrt(m), S_INF) + K0.
 *   ring  (A3r)     scheme 3A analogue for small frames: tighter margin (Z_S, K0_S) for m <= 64
 *                   words, failures resampled on the CSPRNG tail (bb has no start-of-stack debt).
 *   canon (A4)      scheme 3B: no bits-back. Deterministic canonical encoding (tail bits =
 *                   PRG(C)), variable word count, n = floor((I(W) - KC)/8) from the information
 *                   of the word string. The sender retries with another pad when n is skipped.
 */
import { buildModelV4 } from "./model";

const M = 2 ** 24;
const RANGE0 = 2 ** 48;
const RENORM = 2 ** 45;
const MU = 9.440050343452276;
const SIG = 3.8180439073346966;
const MU_FP = Math.round(MU * 65536);

export type BbxDte = "bb-c8-v4" | "bb-ou-v4" | "bb-ouc8-v4" | "bb-ouc8r-v4" | "dfa-v4";
export const BBX_DTES: readonly BbxDte[] = ["bb-c8-v4", "bb-ou-v4", "bb-ouc8-v4", "bb-ouc8r-v4", "dfa-v4"];
export type Spec = { c8: boolean; tilt: boolean; ring: boolean; canon: boolean };
export function specOf(d: BbxDte): Spec {
  return { c8: d === "bb-c8-v4" || d === "bb-ouc8-v4" || d === "bb-ouc8r-v4", tilt: d === "bb-ou-v4" || d === "bb-ouc8-v4" || d === "bb-ouc8r-v4", ring: d === "bb-ouc8r-v4", canon: d === "dfa-v4" };
}

/* ---------- tilt tables ---------- */
export const BETAS = [0.92, 0.96, 1, 1.04, 1.08];
/** deviation threshold (bits) between tables; tuned in docs (T=3). */
export const TILT_T = Number(process.env.LEXIS_TILT_T || 3);
/** stationary sd bound (bits) of the tilted information walk, measured (docs). */
export const S_INF = Number(process.env.LEXIS_TILT_SINF || 13);
type Table = { f0: number; cum: Uint32Array; freq: Uint32Array };
let tables: Table[] | null = null;
let words: string[] = [];
let index = new Map<string, number>();
function T(): Table[] {
  if (tables) return tables;
  const m = buildModelV4();
  words = m.words; index = m.index;
  const base = m.freq, nS = base.length;
  tables = BETAS.map((b) => {
    if (b === 1) return { f0: base[0], cum: m.cum, freq: base };
    const w = new Float64Array(nS); let z = 0;
    for (let s = 0; s < nS; s++) { w[s] = Math.pow(base[s] / M, b); z += w[s]; }
    const freq = new Uint32Array(nS); let tot = 0;
    for (let s = 1; s < nS; s++) { freq[s] = Math.max(1, Math.floor((w[s] / z) * M)); tot += freq[s]; }
    freq[0] = M - tot;
    const cum = new Uint32Array(nS + 1);
    for (let s = 0; s < nS; s++) cum[s + 1] = cum[s] + freq[s];
    return { f0: freq[0], cum, freq };
  });
  return tables;
}
export function tableBytes(): number { return T().reduce((a, t) => a + (t.freq === buildModelV4().freq ? 0 : t.freq.byteLength + t.cum.byteLength), 0); }
function bitlen(range: number): number { let b = 46; while (range >= 2 ** b) b++; return b; }
/** information consumed so far, integer bits (exact on both ends). */
function infoBits(E: number, range: number): number { return E - bitlen(range) + 1; }
function pickTable(sp: Spec, t: number, E: number, range: number): number {
  if (!sp.tilt) return 2;
  const dev = infoBits(E, range) * 65536 - t * MU_FP, th = TILT_T * 65536;
  return dev > 2 * th ? 4 : dev > th ? 3 : dev < -2 * th ? 0 : dev < -th ? 1 : 2;
}

/* ---------- length ---------- */
const Z = 4, K0 = 24, Z_S = 2, K0_S = 8, RING_M = 64, KC = 8;
function margin(sp: Spec, m: number): number {
  if (sp.ring && m <= RING_M) return Z_S * SIG * Math.sqrt(m) + K0_S;
  return Z * (sp.tilt ? Math.min(SIG * Math.sqrt(m), S_INF) : SIG * Math.sqrt(m)) + K0;
}
export function bytesForWordsX(sp: Spec, m: number): number {
  if (m < 1) return 0;
  return Math.max(0, Math.floor((MU * m - margin(sp, m)) / 8));
}
export function wordsForBytesX(sp: Spec, n: number): number[] {
  let m = Math.max(1, Math.floor((8 * n) / MU) - 2);
  while (bytesForWordsX(sp, m) < n) m++;
  const out: number[] = [];
  while (bytesForWordsX(sp, m) === n) out.push(m++);
  return out;
}
/** wire words for an inner length n (padding budget). */
export function wordsMinX(sp: Spec, n: number): number {
  if (sp.canon) return Math.ceil((8 * n + KC + 4) / MU);
  for (let k = 0; k < 4; k++) { const ms = wordsForBytesX(sp, n + k); if (ms.length) return ms[ms.length - 1]; }
  return Math.ceil((8 * n) / MU);
}
export function alignX(sp: Spec, fixed: number, pad: number): number {
  if (sp.canon) return pad;
  const ok = (n: number) => wordsForBytesX(sp, n).length > 0;
  if (ok(fixed + pad)) return pad;
  if (pad < 255 && ok(fixed + pad + 1)) return pad + 1;
  if (pad > 0 && ok(fixed + pad - 1)) return pad - 1;
  for (let d = 2; d < 16; d++) if (pad + d <= 255 && ok(fixed + pad + d)) return pad + d;
  throw new Error("bbx: no representable length");
}

/* ---------- coupling ---------- */
function h8Step(h: number, s: number): number { h ^= s & 0xffff; h = Math.imul(h, 0x01000193); h ^= s >>> 16; return Math.imul(h, 0x01000193) >>> 0; }
const H0 = 0x811c9dc5;
function h8Final(h: number): number { h ^= h >>> 16; h = Math.imul(h, 0x45d9f3b) >>> 0; h ^= h >>> 16; return (h ^ (h >>> 8) ^ (h >>> 24)) & 255; }
function gMask(d: number, n: number): Uint8Array {
  const g = new Uint8Array(n);
  if (d === 0 || n === 0) return g;
  g[0] = d;
  let x = (Math.imul(d, 0x9e3779b1) ^ Math.imul(n, 0x85ebca6b)) >>> 0;
  for (let i = 1; i < n; i++) { x ^= x << 13; x >>>= 0; x ^= x >>> 17; x ^= x << 5; x >>>= 0; g[i] = x & 255; }
  return g;
}

/* ---------- parse ---------- */
type St = { low: bigint; range: number; E: number; t: number; h: number };
function symOf(w: string): number { T(); return index.get(w) ?? 0; }
function stepSt(sp: Spec, st: St, s: number): St {
  const tb = T()[pickTable(sp, st.t, st.E, st.range)];
  const r = Math.floor(st.range / M);
  let start: number, size: number;
  if (s === 0) { start = r * (M - tb.f0); size = st.range - start; } else { start = r * (tb.cum[s] - tb.f0); size = r * tb.freq[s]; }
  let low = st.low + BigInt(start), range = size, E = st.E;
  while (range < RENORM) { range *= 256; low <<= 8n; E += 8; }
  return { low, range, E, t: st.t + 1, h: sp.c8 ? h8Step(st.h, s) : 0 };
}
const ST0: St = { low: 0n, range: RANGE0, E: 48, t: 0, h: H0 };
function topBits(low: bigint, E: number, bits: number): bigint { return E >= bits ? low >> BigInt(E - bits) : low << BigInt(bits - E); }
function nOf(sp: Spec, st: St, m: number): number { return sp.canon ? Math.max(0, Math.floor((infoBits(st.E, st.range) - KC) / 8)) : bytesForWordsX(sp, m); }
function toBytes(v: bigint, n: number): Uint8Array { const out = new Uint8Array(n); for (let i = n - 1; i >= 0; i--) { out[i] = Number(v & 255n); v >>= 8n; } return out; }
/** final ciphertext from the end state */
function finish(sp: Spec, st: St, m: number): Uint8Array {
  const n = nOf(sp, st, m);
  const X = toBytes(topBits(st.low, st.E, 8 * n), n);
  if (!sp.c8) return X;
  const r8 = Number(topBits(st.low, st.E, 8 * n + 8) & 255n);
  const d = r8 ^ h8Final(st.h);
  const g = gMask(d, n);
  for (let i = 0; i < n; i++) X[i] ^= g[i];
  return X;
}
export function parseX(sp: Spec, ws: string[]): Uint8Array {
  let st = ST0;
  for (const w of ws) st = stepSt(sp, st, symOf(w));
  return finish(sp, st, ws.length);
}

/* ---------- seal ---------- */
function rng(): () => number {
  let buf = new Uint8Array(0), bp = 0;
  return () => { if (bp >= buf.length) { buf = crypto.getRandomValues(new Uint8Array(256)); bp = 0; } return buf[bp++]; };
}
function prg(seed: Uint8Array): () => number {
  let x = 0x9e3779b9;
  for (const b of seed) x = (Math.imul(x ^ b, 0x01000193) >>> 0);
  return () => { x ^= x << 13; x >>>= 0; x ^= x >>> 17; x ^= x << 5; x >>>= 0; return x & 255; };
}
type Dec = { code: number; range: number; E: number; t: number; pos: number; out: number[]; h: number; I: number };
function findSym(tb: Table, slot: number): number {
  let lo = 1, hi = tb.freq.length - 1;
  while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (tb.cum[mid] <= slot) lo = mid; else hi = mid - 1; }
  return lo;
}
/** decode words from the point X||tail. stop(): canon stop rule or fixed m. Returns words and,
 *  for fixed-m, the snapshot taken at the last word boundary before tail bytes enter the code. */
function decode(sp: Spec, X: Uint8Array, m: number, tail: () => number, from?: Dec, lazy = false): { syms: number[]; snap: Dec | null; end: Dec } {
  let d: Dec;
  let pos = from ? from.pos : 0;
  const next = () => (pos < X.length ? X[pos++] : (pos++, tail() & 255));
  if (from) d = { ...from, out: lazy ? [] : from.out.slice() };
  else { let code = 0; for (let i = 0; i < 6; i++) code = code * 256 + next(); d = { code, range: RANGE0, E: 48, t: 0, pos, out: [], h: H0, I: 0 }; }
  let snap: Dec | null = from ? from : null;
  const nTarget = X.length;
  for (;;) {
    if (!sp.canon && d.t >= m) break;
    if (sp.canon && Math.floor((infoBits(d.E, d.range) - KC) / 8) >= nTarget) break;
    if (!from && pos <= X.length) snap = { ...d, pos, out: d.out.slice() };
    const tb = T()[pickTable(sp, d.t, d.E, d.range)];
    const r = Math.floor(d.range / M), split = r * (M - tb.f0);
    let s: number, start: number, size: number;
    if (d.code >= split) { s = 0; start = split; size = d.range - split; }
    else { s = findSym(tb, Math.floor(d.code / r) + tb.f0); start = r * (tb.cum[s] - tb.f0); size = r * tb.freq[s]; }
    d.out.push(s); d.code -= start; d.range = size; d.t++;
    if (sp.c8) d.h = h8Step(d.h, s);
    while (d.range < RENORM) { d.range *= 256; d.code = d.code * 256 + next(); d.E += 8; }
    if (d.t > 200000) break;
  }
  d.pos = pos;
  return { syms: d.out, snap, end: d };
}
export const bbxStats = { seals: 0, tries: 0, fails: 0, fast: 0, slow: 0 };
const eq = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);
/** LEXIS_C8_SLOW=1 restores the original per-try BigInt re-parse (reference path for equivalence tests). */
export const c8Opts = { slow: process.env.LEXIS_C8_SLOW === "1" };
/**
 * c8 closure check straight from the decoder end state (no BigInt re-parse of the frame).
 * Invariant of decode(): low_E = U_E - code, U_E = first E/8 bytes of the point X||tail, 0 <= code < range.
 * With k = E - 8n - 8 >= 64 and Uhi = X||b, Ulo = the k/8 tail bytes after b:
 *   top 8n+8 bits of low = Uhi - borrow, borrow = [code > Ulo].
 * So X(W) = X and r8(W) = b - borrow unless (borrow && b == 0); d(W) = r8 ^ H8(W).
 * Returns 1 accept, 0 reject, -1 undecided (caller uses the exact reference check).
 */
function c8Fast(n: number, end: Dec, rec: number[], d0: number): number {
  const k = end.E - 8 * n - 8;
  if (n === 0 || k < 64 || rec.length !== 1 + k / 8 || end.pos !== end.E / 8) return -1;
  const b = rec[0], L = rec.length;
  let hi = false; for (let i = 1; i < L - 8; i++) if (rec[i]) { hi = true; break; }
  let borrow = false;
  if (!hi) { let lo = 0n; for (let i = L - 8; i < L; i++) lo = (lo << 8n) | BigInt(rec[i]); borrow = BigInt(end.code) > lo; }
  if (borrow && b === 0) return -1;
  const r8 = (b - (borrow ? 1 : 0)) & 255;
  return (r8 ^ h8Final(end.h)) === d0 ? 1 : 0;
}
/** Sender. Returns null only for canon when n is skipped/inconsistent (caller changes the pad). */
export function sealX(sp: Spec, C: Uint8Array, randIn?: () => number): string[] | null {
  T(); bbxStats.seals++;
  if (sp.canon) {
    const { syms } = decode(sp, C, 0, prg(C));
    const w = syms.map((s) => words[s]);
    bbxStats.tries++;
    if (eq(parseX(sp, w), C)) return w;
    bbxStats.fails++;
    return null;
  }
  const ms = wordsForBytesX(sp, C.length);
  if (!ms.length) throw new Error("bbx: length not representable");
  const rand = randIn ?? rng();
  for (let outer = 0; outer < 64; outer++) {
    const m = ms.length === 1 ? ms[0] : ms[rand() % ms.length];
    const d0 = sp.c8 ? rand() : 0;
    const X = C.slice(); if (sp.c8) { const g = gMask(d0, C.length); for (let i = 0; i < X.length; i++) X[i] ^= g[i]; }
    let snap: Dec | null = null, pst: St | null = null;
    const inner = sp.c8 ? 8192 : sp.ring ? 64 : 4;
    const fast = sp.c8 && !c8Opts.slow;
    const rec: number[] = [];
    const tap = fast ? () => { const v = rand(); rec.push(v & 255); return v; } : rand;
    for (let k = 0; k < inner; k++) {
      bbxStats.tries++;
      rec.length = 0;
      const lz = fast && !!snap;
      const r = decode(sp, X, m, tap, snap ?? undefined, lz);
      const full = () => (lz ? (snap as Dec).out.concat(r.syms) : r.syms);
      if (!snap) snap = r.snap;
      if (fast && snap) {
        const v = c8Fast(C.length, r.end, rec, d0);
        if (v === 0) { bbxStats.fast++; continue; }
        if (v === 1) { bbxStats.fast++; const w = full().map((s) => words[s]); if (eq(parseX(sp, w), C)) return w; continue; }
        bbxStats.slow++;
      }
      const syms = full();
      if (!pst) { pst = ST0; for (let j = 0; j < (snap ? snap.t : 0); j++) pst = stepSt(sp, pst, syms[j]); }
      let st = pst as St;
      for (let j = st.t; j < syms.length; j++) st = stepSt(sp, st, syms[j]);
      if (eq(finish(sp, st, syms.length), C)) return syms.map((s) => words[s]);
    }
    bbxStats.fails++;
  }
  throw new Error("bbx: encode failed");
}

/* ---------- measurement helpers ---------- */
/** acc[i] = fraction of K model-sampled single-word substitutions at i with parse(W') == parse(W). */
export function probeX(sp: Spec, ws: string[], K: number, sample: () => number): Float32Array {
  const syms = ws.map(symOf), L = syms.length;
  const pre: St[] = []; let st = ST0;
  for (let i = 0; i < L; i++) { pre.push(st); st = stepSt(sp, st, syms[i]); }
  const C = finish(sp, st, L), n = C.length, bits = 8 * n;
  const X = topBits(st.low, st.E, bits);
  const acc = new Float32Array(L);
  for (let i = 0; i < L; i++) {
    let a = 0;
    for (let k = 0; k < K; k++) {
      let s2 = sample(), g = 0; while (s2 === syms[i] && g++ < 50) s2 = sample(); if (s2 === syms[i]) continue;
      let c = stepSt(sp, pre[i], s2);
      {
        const Xp = Math.max(c.E, bits), sh = BigInt(Xp - c.E), cs = BigInt(Xp - bits);
        const L1 = c.low << sh, H1 = (c.low + BigInt(c.range)) << sh, cl = X << cs, ch = (X + 1n) << cs;
        if (H1 <= cl || L1 >= ch) continue;
        if (!sp.c8 && !sp.canon && L1 >= cl && H1 <= ch) { a++; continue; }
      }
      for (let j = i + 1; j < L; j++) c = stepSt(sp, c, syms[j]);
      if (eq(finish(sp, c, L), C)) a++;
    }
    acc[i] = a / K;
  }
  return acc;
}
/** public information walk (for features / KL): per-step table index and deviation. */
export function walkX(sp: Spec, ws: string[]): { tables: number[]; dev: number[]; info: number } {
  let st = ST0; const tb: number[] = [], dev: number[] = [];
  for (const w of ws) { tb.push(pickTable(sp, st.t, st.E, st.range)); dev.push(infoBits(st.E, st.range) - MU * st.t); st = stepSt(sp, st, symOf(w)); }
  return { tables: tb, dev, info: infoBits(st.E, st.range) };
}
export function tablesX(): { freq: Uint32Array }[] { return T(); }
/** decode m words at a uniformly random point (what any wrong key / random ciphertext yields). */
export function randomWordsX(sp: Spec, nOrM: number): string[] {
  T();
  const rand = rng();
  const X = new Uint8Array(sp.canon ? nOrM : 0);
  for (let i = 0; i < X.length; i++) X[i] = rand();
  return decode(sp, X, nOrM, rand).syms.map((s) => words[s]);
}
