import { init, compress, decompress } from "@bokuweb/zstd-wasm";
import { concat, utf8 } from "./bytes";
import { LexisError, sha256 } from "./crypto";
import { staticLexicon } from "./lexicon";

/** Inside the encrypted plaintext. Not a cleartext header and not a shared switch. */
export const PLAIN_TAG = 0x00;
export const ZSTD_TAG = 0x01;

export type ZstdPref = { enabled: boolean; level: number };

let zstdReady: Promise<void> | null = null;

function ensureZstd(): Promise<void> {
  if (!zstdReady) zstdReady = init();
  return zstdReady;
}

export function clampLevel(level: number): number {
  if (!Number.isInteger(level) || level < 1) return 1;
  if (level > 19) return 19;
  return level;
}

/**
 * Sender-side choice. The peer does not need this preference:
 * the tag byte and the zstd frame header travel inside the plaintext.
 * Level picks the window; the decompressor reads that window from the frame.
 */
export async function packPayload(
  data: Uint8Array,
  pref: ZstdPref,
): Promise<{ bytes: Uint8Array; compressed: boolean; level: number }> {
  if (!pref.enabled) {
    return { bytes: concat(new Uint8Array([PLAIN_TAG]), data), compressed: false, level: 0 };
  }
  await ensureZstd();
  const level = clampLevel(pref.level);
  const zipped = compress(data, level);
  if (zipped.length < data.length && zipped.length >= 4) {
    return { bytes: concat(new Uint8Array([ZSTD_TAG]), zipped), compressed: true, level };
  }
  return { bytes: concat(new Uint8Array([PLAIN_TAG]), data), compressed: false, level: 0 };
}

export type Unpacked = { data: Uint8Array; compressed: boolean; honey: boolean };

/**
 * After a successful open, look at the first plaintext byte.
 * 0x00 is raw. 0x01 is a zstd frame; level and window are in that frame.
 * Honey mode maps a broken frame onto a public-lexicon sentence instead of throwing.
 */
export async function unpackPayload(bytes: Uint8Array, honey: boolean): Promise<Unpacked> {
  if (bytes.length >= 1 && bytes[0] === PLAIN_TAG) {
    return { data: bytes.subarray(1), compressed: false, honey: false };
  }
  if (bytes.length >= 5 && bytes[0] === ZSTD_TAG) {
    try {
      await ensureZstd();
      const data = decompress(bytes.subarray(1));
      return { data, compressed: true, honey: false };
    } catch {
      if (!honey) throw new LexisError("zstd 帧解不开");
    }
  } else if (!honey) {
    throw new LexisError("明文类型字节不认识");
  }
  return { data: utf8(await honeySentence(bytes)), compressed: false, honey: true };
}

/** Distribution-transforming decoder: any seed becomes one sentence in the public lexicon. */
export async function honeySentence(seed: Uint8Array): Promise<string> {
  const lex = await staticLexicon();
  const words: string[] = [];
  let material = seed.length ? seed : utf8("empty");
  for (let i = 0; i < 4; i++) {
    material = await sha256(concat(material, new Uint8Array([i])));
    const idx = (((material[0] << 8) | material[1]) & 0xfff) % lex.length;
    words.push(lex[idx]);
  }
  return `the ${words[0]} and our ${words[1]} that its ${words[2]} and the ${words[3]}`;
}
