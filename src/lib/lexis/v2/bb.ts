/**
 * v4 bits-back surjective DTE (frame.dte = "bb-v4"). See docs/design/frame-v4-bitsback.md.
 *
 * One public word model (corpus rank order, same 24-bit frequencies as v3). Word sequences
 * are nested sub-intervals of [0,1) under an exact integer range partition (48..53-bit range,
 * the leftover of every split goes to the most common word, so all splits are exact).
 *
 *   parse(W)  (receiver, total):  n = bytesForWords(|W|);  C = first 8n bits of low(W).
 *   seal(C)   (sender): pick m with bytesForWords(m) = n; point u = C || CSPRNG bits;
 *             decode m words at u; accept if parse(words) == C (fails with prob ~1e-5,
 *             then resample the CSPRNG tail).
 *
 * Surjective: for ANY word sequence W (|W| >= minWords), C = parse(W) satisfies
 * low(W) in cell(C), so a tail exists with u in I(W) and seal(C) can output W.
 * There is no rANS state header and no terminal state: the length comes from the word
 * count, the bits below C are uniform CSPRNG bits, so the words are i.i.d. draws of the
 * model conditioned only on the (rare) acceptance test.
 */
import { buildModelV4, type WordModel } from "./model";

const M = 2 ** 24;
const RANGE0 = 2 ** 48;
const RENORM = 2 ** 45;
/** Per-word information of the model (bits): mean / sd, measured from the frequency table. */
const MU = 9.440050343452276;
const SIG = 3.8180439073346966;
const Z = 4; // margin in standard deviations
const K0 = 24; // fixed margin bits

export function bytesForWords(m: number): number {
  if (m < 1) return 0;
  return Math.max(0, Math.floor((MU * m - Z * SIG * Math.sqrt(m) - K0) / 8));
}
/** All word counts m with bytesForWords(m) == n (empty if n is not representable). */
export function wordsForBytes(n: number): number[] {
  let m = Math.max(1, Math.floor((8 * n) / MU));
  while (bytesForWords(m) < n) m++;
  const out: number[] = [];
  while (bytesForWords(m) === n) out.push(m++);
  return out;
}
export function representable(n: number): boolean {
  return wordsForBytes(n).length > 0;
}
/** Pad adjustment so that the inner length is representable: returns pad, pad+1 or pad-1.
 *  `fixed` = inner length without pad. (Image gaps are at most 1 byte wide for n >= 1.) */
export function bbAlign(fixed: number, pad: number): number {
  if (representable(fixed + pad)) return pad;
  if (pad < 255 && representable(fixed + pad + 1)) return pad + 1;
  if (pad > 0 && representable(fixed + pad - 1)) return pad - 1;
  for (let d = 2; d < 8; d++) if (pad + d <= 255 && representable(fixed + pad + d)) return pad + d;
  throw new Error("bb: no representable length");
}

type Part = { f0: number; cum: Uint32Array; freq: Uint32Array; words: string[]; index: Map<string, number> };
let part: Part | null = null;
function P(): Part {
  if (part) return part;
  const m: WordModel = buildModelV4();
  part = { f0: m.freq[0], cum: m.cum, freq: m.freq, words: m.words, index: m.index };
  return part;
}
function findSym(p: Part, slot: number): number {
  let lo = 1, hi = p.freq.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (p.cum[mid] <= slot) lo = mid;
    else hi = mid - 1;
  }
  return lo;
}

/** Receiver: total function, never throws. Unknown words count as the most common word. */
export function bbParse(words: string[]): Uint8Array {
  const p = P();
  const n = bytesForWords(words.length);
  let low = 0n;
  let range = RANGE0;
  let E = 48;
  for (const w of words) {
    const s = p.index.get(w) ?? 0;
    const r = Math.floor(range / M);
    let start: number, size: number;
    if (s === 0) { start = r * (M - p.f0); size = range - start; }
    else { start = r * (p.cum[s] - p.f0); size = r * p.freq[s]; }
    low += BigInt(start);
    range = size;
    while (range < RENORM) { range *= 256; low <<= 8n; E += 8; }
  }
  const bits = 8 * n;
  const c = E >= bits ? low >> BigInt(E - bits) : low << BigInt(bits - E);
  const out = new Uint8Array(n);
  let v = c;
  for (let i = n - 1; i >= 0; i--) { out[i] = Number(v & 255n); v >>= 8n; }
  return out;
}

function decodeAt(C: Uint8Array, m: number, rand: () => number): string[] {
  const p = P();
  let pos = 0;
  const next = () => (pos < C.length ? C[pos++] : (pos++, rand() & 255));
  let code = 0;
  for (let i = 0; i < 6; i++) code = code * 256 + next();
  let range = RANGE0;
  const out: string[] = [];
  for (let i = 0; i < m; i++) {
    const r = Math.floor(range / M);
    const split = r * (M - p.f0);
    let s: number, start: number, size: number;
    if (code >= split) { s = 0; start = split; size = range - split; }
    else { s = findSym(p, Math.floor(code / r) + p.f0); start = r * (p.cum[s] - p.f0); size = r * p.freq[s]; }
    out.push(p.words[s]);
    code -= start;
    range = size;
    while (range < RENORM) { range *= 256; code = code * 256 + next(); }
  }
  return out;
}

export const bbStats = { seals: 0, retries: 0 };
/** Sender: randomized, CSPRNG tail. C.length must be representable (see bbAlign).
 *  `tail` (bb-k-v4): byte source for the word-count choice and the bits below C; when given
 *  (a keyed deterministic stream) the output is a function of (stream, C) only. */
export function bbSeal(C: Uint8Array, tail?: () => number): string[] {
  const ms = wordsForBytes(C.length);
  if (!ms.length) throw new Error("bb: length not representable");
  let buf = new Uint8Array(0), bp = 0;
  const rand = tail ?? (() => { if (bp >= buf.length) { buf = crypto.getRandomValues(new Uint8Array(256)); bp = 0; } return buf[bp++]; });
  bbStats.seals++;
  for (let tries = 0; tries < 64; tries++) {
    const m = ms.length === 1 ? ms[0] : ms[rand() % ms.length];
    const w = decodeAt(C, m, rand);
    const back = bbParse(w);
    let ok = back.length === C.length;
    for (let i = 0; ok && i < C.length; i++) ok = back[i] === C[i];
    if (ok) return w;
    bbStats.retries++;
  }
  throw new Error("bb: encode failed");
}

/** Test/measurement helper: is W a possible output of bbSeal(bbParse(W))? Decodes at the
 *  point u = low(W) (whose top 8n bits are bbParse(W)) and compares. */
export function bbInSupport(words: string[]): boolean {
  const p = P();
  let low = 0n, range = RANGE0, E = 48;
  for (const w of words) {
    const s = p.index.get(w) ?? 0;
    const r = Math.floor(range / M);
    let start: number, size: number;
    if (s === 0) { start = r * (M - p.f0); size = range - start; } else { start = r * (p.cum[s] - p.f0); size = r * p.freq[s]; }
    low += BigInt(start); range = size;
    while (range < RENORM) { range *= 256; low <<= 8n; E += 8; }
  }
  const nb = E / 8; const bytes = new Uint8Array(nb); let v = low;
  for (let i = nb - 1; i >= 0; i--) { bytes[i] = Number(v & 255n); v >>= 8n; }
  const again = decodeAt(bytes, words.length, () => 0);
  const norm = words.map((w) => (p.index.has(w) ? w : p.words[0]));
  return again.length === norm.length && again.every((x, i) => x === norm[i]);
}
