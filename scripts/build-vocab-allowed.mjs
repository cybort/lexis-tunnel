#!/usr/bin/env node
/* Build-machine only: generates src/lib/lexis/v2/vocab-allowed.ts (the shared allowed word set for
 * frame.dte = bb-k-v4s) from FrequencyWords content/2018/en/en_50k.txt and an INTERNAL exclusion
 * list. The exclusion list is a build input only: it is never written to the output, never
 * printed, and must not be committed or shipped. Only counts are reported.
 *
 *   node scripts/build-vocab-allowed.mjs --src <en_50k.txt> --exclude <internal list> \
 *        [--size all|<n>] [--pack <id>] [--out src/lib/lexis/v2/vocab-allowed.ts] [--check]
 *
 * Exclusion list format: one entry per line, either `word` or `<label>\t<word>`; `#` comments.
 * Only entries that are a single [a-z]+ token are applied (multi-word entries are ignored: a
 * phrase is not split into common words). Cleaning rule (same as vocab-en.ts): keep tokens
 * matching [a-z]+, drop duplicates keeping the first (highest-count) one, descending count.
 * --size all (default): every allowed word (pack fw50k-all-d1-gf); --size <n>: keep the n most
 * frequent allowed words (measurement only).
 * Frequencies are GROUP-FLAT: every word of a rank group (counts within 1.5x, at most 256 wide)
 * gets the same quantized frequency, so a session's in-group shuffle cannot change any word's
 * probability (no candidate-key likelihood test). Must match quantizeFlat() in model.ts
 * (checked by v4s.test.ts).
 * --check: rebuild in memory and compare with --out (exit 1 on difference). */
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";

const arg = (k, d) => { const i = process.argv.indexOf(k); return i > 0 ? process.argv[i + 1] : d; };
const src = arg("--src"), exclude = arg("--exclude");
const size = arg("--size", "all");
const out = arg("--out", new URL("../src/lib/lexis/v2/vocab-allowed.ts", import.meta.url).pathname);
const pack = arg("--pack", size === "all" ? "fw50k-all-d1-gf" : `fw50k-t${Math.round(Number(size) / 1024)}k-d1-gf`);
const check = process.argv.includes("--check");
if (!src || !exclude) { console.error("need --src and --exclude"); process.exit(2); }

const srcText = readFileSync(src, "utf8");
const srcSha = createHash("sha256").update(srcText).digest("hex");
const ex = new Set();
let exLines = 0, exSkipped = 0;
for (const line of readFileSync(exclude, "utf8").split("\n")) {
  const t = line.trim();
  if (!t || t.startsWith("#")) continue;
  exLines++;
  const w = (t.includes("\t") ? t.split("\t").pop() : t).trim().toLowerCase();
  if (/^[a-z]+$/.test(w)) ex.add(w);
  else exSkipped++;
}
const seen = new Set(), words = [], counts = [];
let cleaned = 0, removed = 0;
for (const line of srcText.split("\n")) {
  const [w, c] = line.trim().split(/\s+/);
  if (!w || !/^[a-z]+$/.test(w) || seen.has(w)) continue;
  seen.add(w); cleaned++;
  if (ex.has(w)) { removed++; continue; }
  words.push(w); counts.push(Number(c));
}
for (let i = 1; i < counts.length; i++) if (counts[i] > counts[i - 1]) throw new Error("source not in descending count order");
const n = size === "all" ? words.length : Number(size);
if (!Number.isInteger(n) || n < 1024 || n > words.length) throw new Error(`bad --size ${size}`);
const W = words.slice(0, n), C = counts.slice(0, n);

// bb-v4 per-word information (bits): mean / sd of -log2(f/2^24) under the quantized table.
// Group-flat quantization, identical to quantizeFlat() in model.ts.
const M = 2 ** 24;
const groups = [];
{ let st = 0; for (let i = 1; i <= n; i++) if (i === n || C[i] * 1.5 < C[st] || i - st >= 256) { groups.push([st, i]); st = i; } }
const f = quantizeFlat(C, groups);
function quantizeFlat(counts, gs) {
  const total = counts.reduce((x, y) => x + y, 0);
  const fg = gs.map(([a, b]) => { let g = 0; for (let i = a; i < b; i++) g += counts[i]; return Math.max(1, Math.round((g / total) * M / (b - a))); });
  let R = M; gs.forEach(([a, b], j) => { R -= fg[j] * (b - a); });
  // Exact fix with the first two groups of coprime sizes (x*sa + y*sb = |R|); tiny relative change.
  const gcd = (x, y) => (y ? gcd(y, x % y) : x);
  let ja = -1, jb = -1;
  outer: for (let x = 0; x < gs.length; x++) for (let y = x + 1; y < gs.length; y++) if (gcd(gs[x][1] - gs[x][0], gs[y][1] - gs[y][0]) === 1) { ja = x; jb = y; break outer; }
  if (ja < 0) throw new Error("no coprime group sizes");
  const sa = gs[ja][1] - gs[ja][0], sb = gs[jb][1] - gs[jb][0], sg = Math.sign(R), r = Math.abs(R);
  let y = 0; while ((r - y * sb) % sa !== 0) y++;
  if (r - y * sb < 0) throw new Error("remainder not representable");
  fg[ja] += sg * ((r - y * sb) / sa); fg[jb] += sg * y;
  if (fg[ja] < 1 || fg[jb] < 1) throw new Error("flat quantize underflow");
  const out = new Uint32Array(counts.length);
  gs.forEach(([a, b], j) => out.fill(fg[j], a, b));
  return out;
}
let mu = 0, m2 = 0;
for (const x of f) { const p = x / M, b = -Math.log2(p); mu += p * b; m2 += p * b * b; }
const sig = Math.sqrt(m2 - mu * mu);
const listSha = createHash("sha256").update(W.join(" ") + "\n" + C.join(",")).digest("hex");

const body = `/**
 * Allowed English word set for frame.dte = "bb-k-v4s" (shared by every session; generated).
 * Adapted from FrequencyWords by Hermit Dave, https://github.com/hermitdave/FrequencyWords
 * (content/2018/en/en_50k.txt, OpenSubtitles 2018 counts).
 * This file is licensed CC BY-SA 4.0 (https://creativecommons.org/licenses/by-sa/4.0/);
 * full text in vocab-en.LICENSE.txt, attribution and modifications in vocab-allowed.NOTICE.md.
 * Modifications: filtered to [a-z]+, deduplicated, a small set of specified whole words removed
 * at build time, top ${n} by count, descending order. Frequencies: group-flat (see model.ts).
 * Generated by scripts/build-vocab-allowed.mjs; do not edit by hand.
 */
export const ALLOWED_GROUPS = ${groups.length};
export const ALLOWED_PACK = "${pack}";
export const ALLOWED_SOURCE_SHA256 = "${srcSha}";
export const ALLOWED_LIST_SHA256 = "${listSha}";
/** bits-back length constants for this table (mean / sd of per-word information, bits). */
export const ALLOWED_MU = ${mu};
export const ALLOWED_SIG = ${sig};
export const ALLOWED_WORDS = "${W.join(" ")}";
export const ALLOWED_COUNTS = "${C.join(",")}";
`;
if (check) {
  const cur = readFileSync(out, "utf8");
  const same = cur === body;
  console.log(`check ${same ? "ok" : "DIFFERS"}: pack=${pack} size=${n}`);
  process.exit(same ? 0 : 1);
}
writeFileSync(out, body);
// counts only (never the entries themselves)
console.log(JSON.stringify({ pack, size: n, sourceSha256: srcSha, cleaned, excludeEntries: exLines, excludeApplied: ex.size, excludeSkippedNonToken: exSkipped, removedFromCleaned: removed, allowedTotal: words.length, kept: n, mu, sig, listSha256: listSha, groups: groups.length }));
