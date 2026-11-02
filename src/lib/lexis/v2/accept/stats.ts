// Small statistics toolkit: NIST SP 800-22 subsets, ent-like stats, chi-square p-values.
export function erfc(x: number): number {
  const z = Math.abs(x), t = 1 / (1 + 0.5 * z);
  const r = t * Math.exp(-z * z - 1.26551223 + t * (1.00002368 + t * (0.37409196 + t * (0.09678418 + t * (-0.18628806 + t * (0.27886807 + t * (-1.13520398 + t * (1.48851587 + t * (-0.82215223 + t * 0.17087277)))))))));
  return x >= 0 ? r : 2 - r;
}
function lgamma(x: number): number {
  const c = [76.18009172947146, -86.50532032941677, 24.01409824083091, -1.231739572450155, 0.1208650973866179e-2, -0.5395239384953e-5];
  let y = x, tmp = x + 5.5; tmp -= (x + 0.5) * Math.log(tmp);
  let ser = 1.000000000190015; for (const v of c) ser += v / ++y;
  return -tmp + Math.log((2.5066282746310005 * ser) / x);
}
/** Regularized upper incomplete gamma Q(a, x). */
export function igamc(a: number, x: number): number {
  if (x <= 0) return 1;
  if (x < a + 1) {
    let sum = 1 / a, del = sum, ap = a;
    for (let n = 0; n < 1000; n++) { ap++; del *= x / ap; sum += del; if (Math.abs(del) < Math.abs(sum) * 1e-14) break; }
    return 1 - sum * Math.exp(-x + a * Math.log(x) - lgamma(a));
  }
  let b = x + 1 - a, c = 1e300, d = 1 / b, h = d;
  for (let i = 1; i < 1000; i++) {
    const an = -i * (i - a); b += 2; d = an * d + b; if (Math.abs(d) < 1e-300) d = 1e-300;
    c = b + an / c; if (Math.abs(c) < 1e-300) c = 1e-300; d = 1 / d; const del = d * c; h *= del; if (Math.abs(del - 1) < 1e-14) break;
  }
  return Math.exp(-x + a * Math.log(x) - lgamma(a)) * h;
}
export const chiP = (chi: number, df: number) => igamc(df / 2, chi / 2);
function bits(data: Uint8Array): Uint8Array {
  const out = new Uint8Array(data.length * 8);
  for (let i = 0; i < data.length; i++) for (let j = 0; j < 8; j++) out[i * 8 + j] = (data[i] >> (7 - j)) & 1;
  return out;
}
export function nistMonobit(data: Uint8Array) {
  const b = bits(data); let s = 0; for (const x of b) s += x ? 1 : -1;
  return erfc(Math.abs(s) / Math.sqrt(b.length) / Math.SQRT2);
}
export function nistBlockFrequency(data: Uint8Array, M = 128) {
  const b = bits(data), N = Math.floor(b.length / M); let chi = 0;
  for (let i = 0; i < N; i++) { let o = 0; for (let j = 0; j < M; j++) o += b[i * M + j]; chi += (o / M - 0.5) ** 2; }
  return igamc(N / 2, (4 * M * chi) / 2);
}
export function nistRuns(data: Uint8Array) {
  const b = bits(data), n = b.length; let ones = 0; for (const x of b) ones += x; const pi = ones / n;
  if (Math.abs(pi - 0.5) >= 2 / Math.sqrt(n)) return 0;
  let v = 1; for (let i = 1; i < n; i++) if (b[i] !== b[i - 1]) v++;
  return erfc(Math.abs(v - 2 * n * pi * (1 - pi)) / (2 * Math.sqrt(2 * n) * pi * (1 - pi)));
}
export function nistCusum(data: Uint8Array) {
  const b = bits(data), n = b.length; let s = 0, z = 0;
  for (const x of b) { s += x ? 1 : -1; z = Math.max(z, Math.abs(s)); }
  const Phi = (x: number) => 0.5 * erfc(-x / Math.SQRT2), sq = Math.sqrt(n);
  let a = 0, c = 0;
  for (let k = Math.floor((-n / z + 1) / 4); k <= Math.floor((n / z - 1) / 4); k++) a += Phi(((4 * k + 1) * z) / sq) - Phi(((4 * k - 1) * z) / sq);
  for (let k = Math.floor((-n / z - 3) / 4); k <= Math.floor((n / z - 1) / 4); k++) c += Phi(((4 * k + 3) * z) / sq) - Phi(((4 * k + 1) * z) / sq);
  return 1 - a + c;
}
/** ent(1)-style summary. */
export function ent(data: Uint8Array) {
  const f = new Float64Array(256); for (const x of data) f[x]++;
  const n = data.length, e = n / 256; let H = 0, chi = 0, sum = 0;
  for (let i = 0; i < 256; i++) { const p = f[i] / n; if (p) H -= p * Math.log2(p); chi += (f[i] - e) ** 2 / e; sum += i * f[i]; }
  let t1 = 0, t2 = 0, t3 = 0;
  for (let i = 0; i < n; i++) { const a = data[i], b = data[(i + 1) % n]; t1 += a * b; t2 += a; t3 += a * a; }
  const scc = (n * t1 - t2 * t2) / (n * t3 - t2 * t2);
  return { bytes: n, entropyBitsPerByte: H, chiSquare: chi, chiP: chiP(chi, 255), mean: sum / n, serialCorr: scc };
}
/** Two-sample chi-square homogeneity over byte values. */
export function twoSampleChi(a: number[], b: number[], bins = 256) {
  const fa = new Float64Array(bins), fb = new Float64Array(bins);
  for (const x of a) fa[x]++; for (const x of b) fb[x]++;
  const na = a.length, nb = b.length; let chi = 0, df = -1;
  for (let i = 0; i < bins; i++) { const t = fa[i] + fb[i]; if (!t) continue; df++; const ea = (t * na) / (na + nb), eb = (t * nb) / (na + nb); chi += (fa[i] - ea) ** 2 / ea + (fb[i] - eb) ** 2 / eb; }
  return { chi, df, p: chiP(chi, df) };
}
export function shannon(counts: Map<string, number> | number[]) {
  const v = Array.isArray(counts) ? counts : [...counts.values()];
  const n = v.reduce((x, y) => x + y, 0); let H = 0; for (const c of v) if (c) H -= (c / n) * Math.log2(c / n); return H;
}
