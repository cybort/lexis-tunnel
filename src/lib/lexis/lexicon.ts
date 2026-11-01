import { utf8 } from "./bytes";
import { hkdfStream, sha256 } from "./crypto";
import { GLUE_SET, SPEC } from "./spec";

/**
 * Pronounceable triples. Empty onset/coda are omitted so every word is at least 3 letters
 * and the letter distribution stays inside a small alphabet (low byte entropy on the wire).
 */
const ONSETS = [
  "b", "c", "d", "f", "g", "h", "j", "k", "l", "m", "n", "p", "r", "s", "t", "v", "w", "z",
  "bl", "br", "ch", "cl", "cr", "dr", "fl", "fr", "gl", "gr", "pl", "pr",
  "sc", "sh", "sk", "sl", "sm", "sn", "sp", "st", "sw", "th", "tr", "tw", "wh", "qu",
];

const NUCLEI = [
  "a", "e", "i", "o", "u",
  "ae", "ai", "au", "ea", "ee", "ia", "ie", "io", "oa", "oe", "oo", "ou",
];

const CODAS = [
  "d", "k", "l", "m", "n", "p", "r", "s", "t", "x",
  "ld", "ll", "nd", "nt", "rd", "rn", "sh", "st", "th",
];

const SPACE = ONSETS.length * NUCLEI.length * CODAS.length;

function wordFromIndex(n: number): string {
  const coda = n % CODAS.length;
  const nucleus = Math.floor(n / CODAS.length) % NUCLEI.length;
  const onset = Math.floor(n / (CODAS.length * NUCLEI.length));
  return ONSETS[onset] + NUCLEI[nucleus] + CODAS[coda];
}

export async function buildLexicon(seed: Uint8Array): Promise<string[]> {
  if (SPACE < SPEC.lexiconSize || SPACE >= 65536) {
    throw new Error("音节空间尺寸不对");
  }
  const used = new Uint8Array(SPACE);
  const seen = new Set<string>();
  const words: string[] = [];
  const limit = Math.floor(65536 / SPACE) * SPACE;
  let round = 0;
  let pool: Uint8Array = new Uint8Array(0);
  let pos = 0;

  const pull = async () => {
    pool = await hkdfStream(seed, utf8(`LEXIS-LEX-STREAM-${round}`), "idx", 16000);
    round += 1;
    pos = 0;
  };

  const next16 = async () => {
    if (pos + 2 > pool.length) await pull();
    const v = (pool[pos] << 8) | pool[pos + 1];
    pos += 2;
    return v;
  };

  let guard = 0;
  while (words.length < SPEC.lexiconSize) {
    if (guard++ > SPACE * 4) throw new Error("词表生成失败");
    let draw = await next16();
    while (draw >= limit) draw = await next16();
    const n = draw % SPACE;
    if (used[n]) continue;
    used[n] = 1;
    const w = wordFromIndex(n);
    if (w.length < 3 || GLUE_SET.has(w) || seen.has(w)) continue;
    seen.add(w);
    words.push(w);
  }
  return words;
}

let staticCache: Promise<string[]> | null = null;

/** Public codebook used only before a session key exists. Not a secret. */
export function staticLexicon(): Promise<string[]> {
  if (!staticCache) {
    staticCache = (async () => {
      const seed = await sha256(utf8("LEXIS-STATIC-ALPHABET-v1"));
      return buildLexicon(seed);
    })();
  }
  return staticCache;
}

/** Secret codebook: HKDF(sessionKey, window) then the same generator both ends run. */
export async function sessionLexicon(sessionKey: Uint8Array, window: number): Promise<string[]> {
  const seed = await hkdfStream(
    sessionKey,
    utf8("LEXIS-LEX-SALT"),
    `win-${window}`,
    32,
  );
  return buildLexicon(seed);
}

export function invertLexicon(words: string[]): Map<string, number> {
  const map = new Map<string, number>();
  for (let i = 0; i < words.length; i++) {
    const w = words[i];
    if (map.has(w)) throw new Error(`词表有重复词 ${w}`);
    map.set(w, i);
  }
  if (map.size !== SPEC.lexiconSize) throw new Error("词表长度不对");
  return map;
}
