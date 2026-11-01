import { chunksToBytes, bytesToChunks, concat, readU16, u16be } from "./bytes";
import { staticLexicon } from "./lexicon";
import { GLUE_SET, LEADS, SPEC } from "./spec";

export function dress(words: string[], counter: number): string {
  const parts: string[] = [];
  for (let i = 0; i < words.length; i += 4) {
    const group = words.slice(i, i + 4);
    const head = i === 0 ? LEADS[counter & 3] : "and";
    parts.push(`${head} ${group.join(" ")}.`);
  }
  return parts.join(" ");
}

export function undress(prose: string): string[] {
  return prose
    .trim()
    .toLowerCase()
    .replace(/[.]/g, " ")
    .split(/\s+/)
    .filter((w) => w.length > 0 && !GLUE_SET.has(w));
}

export async function encodeStatic(data: Uint8Array): Promise<string> {
  const lex = await staticLexicon();
  const framed = concat(u16be(data.length), data);
  const words = bytesToChunks(framed).map((c) => {
    if (c < 0 || c >= SPEC.lexiconSize) throw new Error("静态编码越界");
    return lex[c];
  });
  return dress(words, 0);
}

export async function decodeStatic(prose: string): Promise<Uint8Array> {
  const lex = await staticLexicon();
  const inverse = new Map<string, number>();
  for (let i = 0; i < lex.length; i++) inverse.set(lex[i], i);
  const chunks: number[] = [];
  for (const w of undress(prose)) {
    const idx = inverse.get(w);
    if (idx === undefined) throw new Error(`握手词不在静态词表里：${w}`);
    chunks.push(idx);
  }
  const raw = chunksToBytes(chunks);
  if (raw.length < 2) throw new Error("握手报文过短");
  const len = readU16(raw, 0);
  if (raw.length < 2 + len) throw new Error("握手报文被截断");
  return raw.slice(2, 2 + len);
}
