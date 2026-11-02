/* D2 honey indistinguishability: real key vs wrong keys on the same frames.
 * Usage: node --import jiti/register honey-accept.ts [out.json]  (N env = frames per class) */
import { randomBytes } from "node:crypto";
import { writeFileSync } from "node:fs";
import { deriveV2Keys, openV2Honey, packBatch, sealV2, unpackBatch, SEG_COMPLETE, OVERHEAD, unsealRawV2 } from "../frame2.ts";
import { bytesToWords, CORPUS } from "../model.ts";
import { chiP, shannon } from "./stats.ts";

const R = (n: number) => Uint8Array.from(randomBytes(n));
const N = Number(process.env.N || 2000);
const W = 123456;
const BUCKETS: [string, number, number][] = [["1-64", 1, 64], ["65-256", 65, 256], ["257-1K", 257, 1024], ["1-4K", 1025, 4096]];
const out: Record<string, unknown> = {};
const log = (k: string, v: unknown) => { out[k] = v; console.log(k, JSON.stringify(v)); };
const rnd = (a: number, b: number) => a + Math.floor(Math.random() * (b - a + 1));

type Row = { cls: 0 | 1; bucket: string; formatValid: number; padShare: number; bodyEnt: number; bodyChiP: number; mnMean: number; batchParses: number; mnWords: string[]; bodyLen: number };
const rows: Row[] = [];
function bodyChi(b: Uint8Array) { if (b.length < 32) return 0.5; const c = new Array(16).fill(0); for (const x of b) c[x >> 4]++; const e = b.length / 16; return chiP(c.reduce((s, x) => s + (x - e) ** 2 / e, 0), 15); }
function ent(b: Uint8Array) { if (!b.length) return 0; const m = new Map<number, number>(); for (const x of b) m.set(x, (m.get(x) || 0) + 1); return shannon([...m.values()]) / Math.min(8, Math.log2(Math.max(2, b.length))); }
function feat(cls: 0 | 1, bucket: string, view: { mnemonic: Uint8Array; body: Uint8Array; formatValid: boolean }, capacity: number, model: any): Row {
  let parses = 0; try { const s = unpackBatch(view.body); parses = s.length > 0 && s.every((x) => x.flag === SEG_COMPLETE) ? 1 : 0; } catch { parses = 0; }
  return { cls, bucket, formatValid: view.formatValid ? 1 : 0, padShare: capacity ? (capacity - view.body.length) / capacity : 0, bodyEnt: ent(view.body), bodyChiP: bodyChi(view.body),
    mnMean: view.mnemonic.reduce((s, x) => s + x, 0) / 16 / 255, batchParses: parses, mnWords: bytesToWords(model, view.mnemonic, 0), bodyLen: view.body.length };
}
for (const [name, lo, hi] of BUCKETS) for (let i = 0; i < N; i++) {
  const real = deriveV2Keys(R(32), 0, R(32));
  const size = rnd(lo, hi);
  // a realistic batch: one packed record per segment (random = incompressible payload)
  const plaintext = packBatch([{ flag: SEG_COMPLETE, data: R(Math.max(1, size - 4)) }]);
  const c = rnd(1, 1e6);
  const prose = sealV2({ keys: real, counter: c, window: W, dir: "e2g", plaintext, maxExpansion: 5, smallFramePolicy: (process.env.POLICY as any) || "expansion" });
  const capacity = unsealRawV2(real, c, W, "e2g", prose).length - OVERHEAD;
  rows.push(feat(1, name, openV2Honey({ keys: real, counter: c, window: W, dir: "e2g", prose }), capacity, real.model));
  const wrong = deriveV2Keys(R(32), 0, R(32));
  rows.push(feat(0, name, openV2Honey({ keys: wrong, counter: c, window: W, dir: "e2g", prose }), capacity, wrong.model));
}
// --- logistic regression (5-fold), AUC ---
function auc(scores: number[], y: number[]) { const idx = scores.map((s, i) => [s, y[i]]).sort((a, b) => a[0] - b[0]); let rank = 0, pos = 0, sum = 0; idx.forEach(([, l], i) => { if (l) { pos++; sum += i + 1; } }); const neg = y.length - pos; rank = (sum - (pos * (pos + 1)) / 2) / (pos * neg); return rank; }
function lr(X: number[][], y: number[]) { const d = X[0].length; let w = new Array(d + 1).fill(0); for (let ep = 0; ep < 300; ep++) { const g = new Array(d + 1).fill(0); X.forEach((x, i) => { const z = w[d] + x.reduce((s, v, j) => s + v * w[j], 0); const p = 1 / (1 + Math.exp(-z)); const e = p - y[i]; x.forEach((v, j) => (g[j] += e * v)); g[d] += e; }); w = w.map((v, j) => v - (0.5 * g[j]) / X.length); } return (x: number[]) => w[d] + x.reduce((s, v, j) => s + v * w[j], 0); }
function cvAuc(sel: (r: Row) => number[], subset: Row[]) { const sh = [...subset].sort(() => Math.random() - 0.5); const k = 5, sc: number[] = [], ys: number[] = []; for (let f = 0; f < k; f++) { const te = sh.filter((_, i) => i % k === f), tr = sh.filter((_, i) => i % k !== f); const m = lr(tr.map(sel), tr.map((r) => r.cls)); te.forEach((r) => { sc.push(m(sel(r))); ys.push(r.cls); }); } const a = auc(sc, ys); return +Math.max(a, 1 - a).toFixed(3); }
const noStruct = (r: Row) => [r.formatValid, r.padShare, r.bodyEnt, r.bodyChiP, r.mnMean];
const withStruct = (r: Row) => [...noStruct(r), r.batchParses];
const per: Record<string, unknown> = {};
const exp = (name: string) => { const sub = rows.filter((r) => r.cls === 1 && r.bucket === name); return sub; };
void exp;
for (const [name] of BUCKETS) {
  const sub = rows.filter((r) => r.bucket === name);
  const m = (cls: number, f: (r: Row) => number) => +(sub.filter((r) => r.cls === cls).reduce((s, r) => s + f(r), 0) / N).toFixed(4);
  per[name] = {
    formatValid: [m(1, (r) => r.formatValid), m(0, (r) => r.formatValid)],
    padShareMean: [m(1, (r) => r.padShare), m(0, (r) => r.padShare)],
    padShareAUC: cvAuc((r) => [r.padShare], sub),
    bodyEntropyNorm: [m(1, (r) => r.bodyEnt), m(0, (r) => r.bodyEnt)],
    batchParses: [m(1, (r) => r.batchParses), m(0, (r) => r.batchParses)],
    aucNoStructure: cvAuc(noStruct, sub),
    aucNoStructureNoCanonical: cvAuc((r) => [r.padShare, r.bodyEnt, r.bodyChiP, r.mnMean], sub),
    aucOnlyCanonical: cvAuc((r) => [r.formatValid], sub),
    aucWithBodyStructure: cvAuc(withStruct, sub),
  };
}
log("H.perBucket[real,wrong]", per);
// mnemonic words: frequency, Zipf slope, chi-square real vs wrong
const freq = (cls: number) => { const m = new Map<number, number>(); for (const r of rows) if (r.cls === cls) for (const w of r.mnWords) { const rank = CORPUS.words.indexOf(w); const b = rank < 0 ? 99 : Math.min(98, Math.floor(Math.log2(rank + 1) * 6)); m.set(b, (m.get(b) || 0) + 1); } return m; };
const fr = freq(1), fw = freq(0);
const keys = [...new Set([...fr.keys(), ...fw.keys()])]; const nr = [...fr.values()].reduce((s, x) => s + x, 0), nw = [...fw.values()].reduce((s, x) => s + x, 0);
let chi = 0, df = 0; for (const k of keys) { const a = fr.get(k) || 0, b = fw.get(k) || 0; if (a + b < 10) continue; const ea = ((a + b) * nr) / (nr + nw), eb = ((a + b) * nw) / (nr + nw); chi += (a - ea) ** 2 / ea + (b - eb) ** 2 / eb; df++; }
const zipf = (cls: number) => { const m = new Map<string, number>(); for (const r of rows) if (r.cls === cls) for (const w of r.mnWords) m.set(w, (m.get(w) || 0) + 1); const s = [...m.values()].sort((a, b) => b - a).slice(0, 300); const p = s.map((c, i) => [Math.log(i + 1), Math.log(c)]); const mx = p.reduce((a, q) => a + q[0], 0) / p.length, my = p.reduce((a, q) => a + q[1], 0) / p.length; return +(p.reduce((a, q) => a + (q[0] - mx) * (q[1] - my), 0) / p.reduce((a, q) => a + (q[0] - mx) ** 2, 0)).toFixed(3); };
const wl = (cls: number) => { const r = rows.filter((x) => x.cls === cls); return +(r.reduce((s, x) => s + x.mnWords.length, 0) / r.length).toFixed(2); };
log("H.mnemonicWords", { inCorpusShare: [1, 1], wordsPerMnemonic: [wl(1), wl(0)], zipfSlopeTop300: [zipf(1), zipf(0)], rankBucketChi2: +chi.toFixed(1), df: df - 1, p: +chiP(chi, Math.max(1, df - 1)).toFixed(4) });
if (process.argv[2]) writeFileSync(process.argv[2], JSON.stringify(out, null, 2));
