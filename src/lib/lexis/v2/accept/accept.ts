/* Acceptance measurements for T19-T21. Usage: node --import jiti/register accept.ts [outJson] */
import { randomBytes } from "node:crypto";
import { writeFileSync } from "node:fs";
import { b64 } from "../../bytes.ts";
import { createIdentity } from "../../crypto.ts";
import type { MeshNode } from "../../types.ts";
import { deriveV2Keys, openV2, sealV2, unsealRawV2, OVERHEAD } from "../frame2.ts";
import { edgeStart2, gateRespond2 } from "../handshake2.ts";
import { resetHandshakeGuards } from "../../handshake.ts";
import { buildGfModel, buildModel, bytesToWords, CORPUS, gfBytesToWords, VOCAB_SIZE } from "../model.ts";
import { ent, nistBlockFrequency, nistCusum, nistMonobit, nistRuns, shannon, twoSampleChi, chiP } from "./stats.ts";

const R = (n: number) => Uint8Array.from(randomBytes(n));
const out: Record<string, unknown> = {};
const log = (k: string, v: unknown) => { out[k] = v; console.log(k, JSON.stringify(v)); };
const N_WRONG = Number(process.env.N_WRONG || 2000);
const W = 5900000;

// ---------- A. wrong keys ----------
{
  const sk = R(32), keys = deriveV2Keys(sk);
  const P = new TextEncoder().encode(("GET /index.html HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n").repeat(4));
  const prose = sealV2({ keys, counter: 7, window: W, dir: "e2g", plaintext: P });
  const trueInner = unsealRawV2(keys, 7, W, "e2g", prose);
  const lens: number[] = [], chunks: Uint8Array[] = [], mono: number[] = [], runs: number[] = [];
  const posA: number[][] = Array.from({ length: 34 }, () => []), posR: number[][] = Array.from({ length: 34 }, () => []);
  let lenFieldOk = 0, mnemonicHits = 0, ham = 0, hamBits = 0;
  const t0 = Date.now();
  for (let i = 0; i < N_WRONG; i++) {
    const wk = deriveV2Keys(R(32));
    const o = unsealRawV2(wk, 7, W, "e2g", prose);
    lens.push(o.length); chunks.push(o); mono.push(nistMonobit(o)); runs.push(nistRuns(o));
    const rnd = R(o.length);
    for (let j = 0; j < 16; j++) { posA[j].push(o[j]); posR[j].push(rnd[j]); }
    for (let j = 0; j < 18; j++) { posA[16 + j].push(o[o.length - 18 + j]); posR[16 + j].push(rnd[o.length - 18 + j]); }
    const len = (o[o.length - 2] << 8) | o[o.length - 1];
    if (len <= o.length - OVERHEAD) lenFieldOk++;
    try { openV2({ keys: wk, counter: 7, window: W, dir: "e2g", prose }); mnemonicHits++; } catch { /* expected */ }
    const m = Math.min(o.length, trueInner.length);
    for (let j = 0; j < m; j++) { let x = o[j] ^ trueInner[j]; while (x) { ham += x & 1; x >>= 1; } }
    hamBits += m * 8;
  }
  const ctrl = chunks.map((c) => R(c.length));
  const ctrlMono = ctrl.map((c) => nistMonobit(c)), ctrlRuns = ctrl.map((c) => nistRuns(c));
  const all = new Uint8Array(chunks.reduce((s, c) => s + c.length, 0));
  let off = 0; for (const c of chunks) { all.set(c, off); off += c.length; }
  const pass = (ps: number[]) => ps.filter((p) => p >= 0.01).length / ps.length;
  const pUniform = (ps: number[]) => { const f = new Array(10).fill(0); for (const p of ps) f[Math.min(9, Math.floor(p * 10))]++; const e = ps.length / 10; return chiP(f.reduce((s, x) => s + (x - e) ** 2 / e, 0), 9); };
  const posChi = posA.map((a, j) => twoSampleChi(a, posR[j]).p);
  const avgLen = lens.reduce((s, x) => s + x, 0) / lens.length;
  log("A.wrongKeys", {
    n: N_WRONG, seconds: (Date.now() - t0) / 1000, frameWords: prose.split(" ").length, trueInnerBytes: trueInner.length,
    outLen: { min: Math.min(...lens), max: Math.max(...lens), mean: avgLen },
    ent: ent(all),
    nistConcat: { monobit: nistMonobit(all), blockFrequency128: nistBlockFrequency(all, 128), runs: nistRuns(all), cusum: nistCusum(all) },
    nistPerOutput: { monobitPassRate: pass(mono), monobitPvalueUniformityP: pUniform(mono), runsPassRate: pass(runs), runsPvalueUniformityP: pUniform(runs),
      control_trueRandomSameLengths: { monobitPassRate: pass(ctrlMono), monobitPvalueUniformityP: pUniform(ctrlMono), runsPassRate: pass(ctrlRuns), runsPvalueUniformityP: pUniform(ctrlRuns) } },
    distinguish: {
      perPositionChiVsRandom_minP: Math.min(...posChi), perPositionChiVsRandom_positions: posChi.length,
      positionsBelow001: posChi.filter((p) => p < 0.01).length,
      lengthFieldPlausibleRate: lenFieldOk / N_WRONG, lengthFieldPlausibleExpectedRandom: (avgLen - OVERHEAD + 1) / 65536,
      mnemonicAcceptedByWrongKey: mnemonicHits,
      hammingVsTrueInner: ham / hamBits,
    },
  });
  // key distinguishability: can two wrong keys be told apart? outputs under K1 vs K2 on 400 frames each
  const k1 = deriveV2Keys(R(32)), k2 = deriveV2Keys(R(32));
  const a1: number[] = [], a2: number[] = [];
  for (let c = 1; c <= 400; c++) {
    const pr = sealV2({ keys, counter: c, window: W, dir: "e2g", plaintext: P });
    for (const x of unsealRawV2(k1, c, W, "e2g", pr)) a1.push(x);
    for (const x of unsealRawV2(k2, c, W, "e2g", pr)) a2.push(x);
  }
  log("A.keyVsKey", twoSampleChi(a1, a2));
}

// ---------- B. tamper / deletion / replay / reorder ----------
{
  const keys = deriveV2Keys(R(32));
  const vocab = CORPUS.words;
  const frames = Array.from({ length: 200 }, (_, i) => sealV2({ keys, counter: i + 1, window: W, dir: "g2e", plaintext: R(20 + (i % 300)) }));
  const tries = (f: () => unknown) => { try { f(); return false; } catch { return true; } };
  const res: Record<string, [number, number]> = {};
  const bump = (k: string, rej: boolean) => { res[k] ??= [0, 0]; res[k][0]++; if (rej) res[k][1]++; };
  for (let t = 0; t < 2000; t++) {
    const i = t % 200, w = frames[i].split(" "), c = i + 1;
    const pos = Math.floor(Math.random() * w.length);
    const op = (x: string[]) => tries(() => openV2({ keys, counter: c, window: W, dir: "g2e", prose: x.join(" ") }));
    const sub = [...w]; let nw = sub[pos]; while (nw === sub[pos]) nw = vocab[Math.floor(Math.random() * vocab.length)]; sub[pos] = nw;
    bump("substituteWord", op(sub));
    bump("deleteWord", op(w.filter((_, j) => j !== pos)));
    bump("insertWord", op([...w.slice(0, pos), vocab[Math.floor(Math.random() * 5000)], ...w.slice(pos)]));
    if (w.length > 1) { const sw = [...w]; const q = Math.min(pos, w.length - 2); [sw[q], sw[q + 1]] = [sw[q + 1], sw[q]]; if (sw[q] !== sw[q + 1]) bump("swapAdjacentWords", op(sw)); }
    const j = (i + 1 + Math.floor(Math.random() * 199)) % 200;
    bump("replayOrReorderFrame", tries(() => openV2({ keys, counter: c, window: W, dir: "g2e", prose: frames[j] })));
    bump("deleteFrame(next frame at expected counter)", tries(() => openV2({ keys, counter: c, window: W, dir: "g2e", prose: frames[(i + 1) % 200] })));
    bump("reflectDirection", tries(() => openV2({ keys, counter: c, window: W, dir: "e2g", prose: frames[i] })));
  }
  log("B.rejections[total,rejected]", res);
}

// ---------- C. expansion ----------
{
  const keys = deriveV2Keys(R(32));
  const rows = [];
  for (const maxExpansion of [2, 1.5, 1.25]) for (const size of [1, 16, 64, 256, 1024, 4096, 16000]) {
    let inner = 0, chars = 0, words = 0; const n = size > 4000 ? 20 : 100;
    for (let c = 1; c <= n; c++) {
      const P = R(size), pr = sealV2({ keys, counter: c, window: W, dir: "e2g", plaintext: P, maxExpansion });
      inner += unsealRawV2(keys, c, W, "e2g", pr).length; chars += Buffer.byteLength(pr); words += pr.split(" ").length;
    }
    rows.push({ maxExpansion, size, innerOverP: +(inner / n / size).toFixed(3), padOnlyBudgetOK: inner / n - OVERHEAD <= maxExpansion * size + 1e-9, wireBytesOverP: +(chars / n / size).toFixed(3), wireBytesOverInner: +(chars / inner).toFixed(3), wordsPerInnerByte: +(words / inner).toFixed(3) });
  }
  log("C.expansion", rows);
}

// ---------- D. rANS vs GF(2^14) ----------
{
  const lex = R(32), pad = R(32), model = buildModel(lex, pad), gf = buildGfModel(lex);
  const data = R(262144);
  const t0 = Date.now(); const ra = bytesToWords(model, data, 1); const tR = Date.now() - t0;
  const t1 = Date.now(); const ga = gfBytesToWords(gf, data); const tG = Date.now() - t1;
  const corpusTotal = CORPUS.counts.reduce((s: number, x: number) => s + x, 0);
  const corpusLen = new Map<number, number>(), corpusChar = new Map<string, number>();
  CORPUS.words.forEach((w: string, i: number) => { const c = CORPUS.counts[i]; corpusLen.set(w.length, (corpusLen.get(w.length) || 0) + c); for (const ch of w) corpusChar.set(ch, (corpusChar.get(ch) || 0) + c); });
  const tvd = (a: Map<any, number>, b: Map<any, number>) => { const na = [...a.values()].reduce((s, x) => s + x, 0), nb = [...b.values()].reduce((s, x) => s + x, 0); let d = 0; for (const k of new Set([...a.keys(), ...b.keys()])) d += Math.abs((a.get(k) || 0) / na - (b.get(k) || 0) / nb); return d / 2; };
  const describe = (ws: string[], ms: number) => {
    const freq = new Map<string, number>(), len = new Map<number, number>(), ch = new Map<string, number>();
    for (const w of ws) { freq.set(w, (freq.get(w) || 0) + 1); len.set(w.length, (len.get(w.length) || 0) + 1); for (const c of w) ch.set(c, (ch.get(c) || 0) + 1); }
    // Zipf: rank/frequency curve of the output vs the corpus (rank buckets, TVD), plus log-log slope.
    const sorted = [...freq.values()].sort((a, b) => b - a);
    const buckets = [1, 10, 100, 1000, 10000, 40000];
    const outB = new Map<number, number>(), corB = new Map<number, number>();
    sorted.forEach((c, r) => { const b = buckets.findIndex((x) => r < x); outB.set(b, (outB.get(b) || 0) + c); });
    Array.from(CORPUS.freqByRank as ArrayLike<number>).forEach((c: number, r: number) => { const b = buckets.findIndex((x) => r < x); corB.set(b, (corB.get(b) || 0) + c); });
    const pts = sorted.slice(0, 2000).map((c, r) => [Math.log(r + 1), Math.log(c)]);
    const mx = pts.reduce((s, p) => s + p[0], 0) / pts.length, my = pts.reduce((s, p) => s + p[1], 0) / pts.length;
    const slope = pts.reduce((s, p) => s + (p[0] - mx) * (p[1] - my), 0) / pts.reduce((s, p) => s + (p[0] - mx) ** 2, 0);
    const text = ws.join(" ");
    return {
      words: ws.length, bitsPerWord: +((data.length * 8) / ws.length).toFixed(3), wireBytesPerCipherByte: +(Buffer.byteLength(text) / data.length).toFixed(3),
      avgWordLen: +([...ws].reduce((s, w) => s + w.length, 0) / ws.length).toFixed(3), distinctWords: freq.size,
      wordEntropyBits: +shannon(freq).toFixed(3), charEntropyBits: +shannon(new Map([...ch, [" ", ws.length]])).toFixed(3),
      zipfSlopeTop2000: +slope.toFixed(3), rankBucketTVDvsCorpus: +tvd(outB, corB).toFixed(4),
      lengthTVDvsCorpus: +tvd(len, corpusLen).toFixed(4), charTVDvsCorpus: +tvd(ch, corpusChar).toFixed(4), ms,
    };
  };
  // corpus reference slope
  const cp = Array.from(CORPUS.freqByRank as ArrayLike<number>).slice(0, 2000).map((c: number, r: number) => [Math.log(r + 1), Math.log(c)]);
  const cmx = cp.reduce((s: number, p: number[]) => s + p[0], 0) / cp.length, cmy = cp.reduce((s: number, p: number[]) => s + p[1], 0) / cp.length;
  const cslope = cp.reduce((s: number, p: number[]) => s + (p[0] - cmx) * (p[1] - cmy), 0) / cp.reduce((s: number, p: number[]) => s + (p[0] - cmx) ** 2, 0);
  log("D.mapping", { vocab: VOCAB_SIZE, corpusTotalTokens: corpusTotal, corpusZipfSlopeTop2000: +cslope.toFixed(3), rANS: describe(ra, tR), gf2_14: describe(ga, tG) });
  // keyed vocab: overlap of the top-100 word slots between two keys
  const m2 = buildModel(R(32), R(32));
  let same = 0; for (let r = 0; r < 1000; r++) if (model.words[r] === m2.words[r]) same++;
  log("D.keyedRanks", { top1000SameWordSameRank: same });
}

// ---------- E. hellos ----------
{
  resetHandshakeGuards();
  const mk = async (role: MeshNode["role"]): Promise<MeshNode> => { const k = await createIdentity(); return { id: role, name: role, role, publicJwk: k.publicJwk, privateJwk: k.privateJwk, publicRawB64: b64(k.publicRaw), fingerprint: k.fingerprint, pinnedPeerId: null, createdAt: Date.now(), kdf: null }; };
  const gate = await mk("gate"), edge = await mk("edge");
  const FAST = { memoryKiB: 32, iterations: 1, parallelism: 1, honey: false };
  const hellos: string[] = [], servers: string[] = [];
  for (let i = 0; i < 500; i++) hellos.push(edgeStart2(edge, gate.publicRawB64, Date.now(), FAST, "v3-test-token-9f3a2c1b0e7d6a5c").helloWire);
  for (let i = 0; i < 100; i++) resetHandshakeGuards(), servers.push((await gateRespond2(gate, [{ id: "e", publicRawB64: edge.publicRawB64 }], hellos[i], { token: "v3-test-token-9f3a2c1b0e7d6a5c", kdf: FAST })).serverWire);
  const shape = (xs: string[]) => {
    const wc = xs.map((h) => h.split(" ").length), cl = xs.map((h) => h.length);
    const st = (v: number[]) => { const m = v.reduce((s, x) => s + x, 0) / v.length; return { min: Math.min(...v), max: Math.max(...v), mean: +m.toFixed(1), sd: +Math.sqrt(v.reduce((s, x) => s + (x - m) ** 2, 0) / v.length).toFixed(1), distinct: new Set(v).size }; };
    const posTop = Array.from({ length: 8 }, (_, p) => { const f = new Map<string, number>(); for (const h of xs) { const w = h.split(" ")[p]; f.set(w, (f.get(w) || 0) + 1); } return Math.max(...f.values()) / xs.length; });
    const lastTop = (() => { const f = new Map<string, number>(); for (const h of xs) { const w = h.split(" ").at(-1)!; f.set(w, (f.get(w) || 0) + 1); } return Math.max(...f.values()) / xs.length; })();
    let lcp = 0; for (let i = 1; i < xs.length; i++) { let k = 0; while (k < xs[i].length && xs[i][k] === xs[i - 1][k]) k++; lcp = Math.max(lcp, k); }
    return { n: xs.length, unique: new Set(xs).size, words: st(wc), chars: st(cl), maxShareOfMostCommonWordAtPositions0to7: posTop.map((x) => +x.toFixed(3)), lastWordMaxShare: +lastTop.toFixed(3), maxCommonPrefixChars: lcp };
  };
  log("E.hello", shape(hellos));
  log("E.server", shape(servers));
  // what share of the hello words fall in a fixed 'first word' set compared with rANS data words
  log("E.example", { hello: hellos[0].slice(0, 160), server: servers[0].slice(0, 160) });
}
if (process.argv[2]) writeFileSync(process.argv[2], JSON.stringify(out, null, 2));

// ---------- F. per-position word distribution of data frames ----------
{
  const keys = deriveV2Keys(R(32));
  const N = 4000, pos = Array.from({ length: 10 }, () => new Map<string, number>());
  for (let c = 1; c <= N; c++) { const w = sealV2({ keys, counter: c, window: W, dir: "e2g", plaintext: R(60 + (c % 200)) }).split(" "); for (let p = 0; p < 10; p++) pos[p].set(w[p], (pos[p].get(w[p]) || 0) + 1); }
  log("F.dataFramePositions", { frames: N, maxSharePos0to9: pos.map((m) => +(Math.max(...m.values()) / N).toFixed(3)), modelTopWordProb: +(keys.model.freq[0] / 2 ** 24).toFixed(3) });
  if (process.argv[2]) writeFileSync(process.argv[2], JSON.stringify(out, null, 2));
}
