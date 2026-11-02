import assert from "node:assert/strict";
import { p256 } from "@noble/curves/nist.js";
import { hex, randomBytes, utf8 } from "./bytes.ts";
import { compileBlocks, evalHoney, honeyPhrase, indicesFrom, openIdentityVault, packIndices, privateScalar, sealIdentityVault } from "./honey.ts";
import { sessionLexicon } from "./lexicon.ts";

const FAST = { memoryKiB: 32, iterations: 1, parallelism: 1 };

async function main() {
  const a = randomBytes(32);
  const b = randomBytes(32);
  const window = 11;
  const lexA = await sessionLexicon(a, window);
  const lexB = await sessionLexicon(b, window);
  const lexA2 = await sessionLexicon(a, window + 1);
  assert.equal(lexA.length, 4096);
  assert.equal(lexB.length, 4096);
  assert.equal(lexA2.length, 4096);
  assert.notEqual(lexA.join(" "), lexB.join(" "));
  assert.notEqual(lexA.join(" "), lexA2.join(" "));
  assert.equal(lexA[3], (await sessionLexicon(a, window))[3]);
  for (const word of [lexA[0], lexB[20], lexA2[100]]) assert.match(word, /^[a-z]{3,}$/);

  const indices: [number, number, number, number] = [4, 8, 15, 16];
  const program = await compileBlocks([{ key: a, block: packIndices(indices) }], 2);
  assert.deepEqual(indicesFrom(await evalHoney(program, a)), indices);
  assert.notDeepEqual(indicesFrom(await evalHoney(program, b)), indices);
  const phrase = await honeyPhrase(a, window, utf8(""), program);
  assert.equal(phrase, `the ${lexA[4]} and our ${lexA[8]} that its ${lexA[15]} and the ${lexA[16]}`);
  const other = await honeyPhrase(b, window, utf8("seed"));
  assert.match(other, /^the \S+ and our \S+ that its \S+ and the \S+$/);
  assert.notEqual(phrase, other);
  const shifted = await honeyPhrase(a, window + 1, utf8(""), program);
  assert.notEqual(shifted, phrase);

  const salt = randomBytes(16);
  const scalar = p256.utils.randomSecretKey();
  const spareScalar = p256.utils.randomSecretKey();
  const vault = await sealIdentityVault(
    [
      { passphrase: "真口令", scalar },
      { passphrase: "备用", scalar: spareScalar },
    ],
    salt,
    FAST,
    4,
  );
  const opened = await openIdentityVault(vault, "真口令");
  const again = await openIdentityVault(vault, "真口令");
  const spare = await openIdentityVault(vault, "备用");
  const third = await openIdentityVault(vault, "另一句");
  assert.equal(hex(opened.publicRaw), hex(p256.getPublicKey(scalar, false)));
  assert.equal(hex(spare.publicRaw), hex(p256.getPublicKey(spareScalar, false)));
  assert.equal(opened.fingerprint, again.fingerprint);
  assert.notEqual(opened.fingerprint, spare.fingerprint);
  assert.notEqual(opened.fingerprint, third.fingerprint);
  assert.notEqual(spare.fingerprint, third.fingerprint);
  assert.equal(third.publicRaw[0], 0x04);
  assert.equal(third.publicRaw.length, 65);

  const windowKey = 4;
  const lexReal = await sessionLexicon(privateScalar(opened.privateJwk), windowKey);
  const lexSpare = await sessionLexicon(privateScalar(spare.privateJwk), windowKey);
  const lexThird = await sessionLexicon(privateScalar(third.privateJwk), windowKey);
  const lexNext = await sessionLexicon(privateScalar(third.privateJwk), windowKey + 1);
  for (const lex of [lexReal, lexSpare, lexThird, lexNext]) {
    assert.equal(lex.length, 4096);
    assert.match(lex[0], /^[a-z]{3,}$/);
  }
  assert.notEqual(lexReal.join(" "), lexSpare.join(" "));
  assert.notEqual(lexSpare.join(" "), lexThird.join(" "));
  assert.notEqual(lexThird.join(" "), lexNext.join(" "));

  console.log("honey ok");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
