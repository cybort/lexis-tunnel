import { randomBytes, utf8 } from "./bytes";

/** Shannon entropy in bits per byte. Uniform ciphertext sits near 8; prose sits near 4. */
export function shannonEntropy(bytes: Uint8Array): number {
  if (bytes.length === 0) return 0;
  const freq = new Array<number>(256).fill(0);
  for (let i = 0; i < bytes.length; i++) freq[bytes[i]] += 1;
  let h = 0;
  for (let i = 0; i < 256; i++) {
    if (!freq[i]) continue;
    const p = freq[i] / bytes.length;
    h -= p * Math.log2(p);
  }
  return h;
}

export function entropyPair(prose: string): { wire: number; random: number; nbytes: number } {
  const bytes = utf8(prose);
  const rnd = randomBytes(Math.max(bytes.length, 1));
  return {
    wire: shannonEntropy(bytes),
    random: shannonEntropy(rnd.subarray(0, bytes.length)),
    nbytes: bytes.length,
  };
}
