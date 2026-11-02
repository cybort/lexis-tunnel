import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { hctr2Decrypt, hctr2Encrypt, hctr2Key } from "./hctr2";

const hex = (s: string) => Uint8Array.from(Buffer.from(s, "hex"));
const vectors = JSON.parse(readFileSync(new URL("./vectors/HCTR2_AES256.json", import.meta.url), "utf8"));
let n = 0;
for (const v of vectors) {
  const key = hctr2Key(hex(v.input.key_hex));
  const tweak = hex(v.input.tweak_hex);
  const pt = hex(v.plaintext_hex);
  const ct = hex(v.ciphertext_hex);
  assert.equal(Buffer.from(hctr2Encrypt(key, tweak, pt)).toString("hex"), v.ciphertext_hex, `encrypt ${v.description}`);
  assert.equal(Buffer.from(hctr2Decrypt(key, tweak, ct)).toString("hex"), v.plaintext_hex, `decrypt ${v.description}`);
  n++;
}
console.log(`hctr2 ok: ${n} official google/hctr2 AES-256 vectors`);
