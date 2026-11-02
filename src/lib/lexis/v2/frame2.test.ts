import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { deriveV2Keys, nextSessionKey, openV2, sealV2 } from "./frame2";

const sk = Uint8Array.from(randomBytes(32));
const keys = deriveV2Keys(sk, 0);
const w = 1234567;
const msgs = Array.from({ length: 50 }, (_, i) => Uint8Array.from(randomBytes(1 + ((i * 97) % 900))));
const wire = msgs.map((m, i) => sealV2({ keys, counter: i + 1, window: w, dir: "e2g", plaintext: m }));
wire.forEach((p, i) => assert.deepEqual(openV2({ keys, counter: i + 1, window: w, dir: "e2g", prose: p }), msgs[i]));
const rej = (f: () => unknown) => assert.throws(f, /完整性/);
// replay: frame 3 presented again where 51 is expected
rej(() => openV2({ keys, counter: 51, window: w, dir: "e2g", prose: wire[2] }));
// deletion: frame 5 skipped, frame 6 presented as 5
rej(() => openV2({ keys, counter: 5, window: w, dir: "e2g", prose: wire[5] }));
// reorder
rej(() => openV2({ keys, counter: 7, window: w, dir: "e2g", prose: wire[7] }));
// reflection (other direction), wrong window, next generation
rej(() => openV2({ keys, counter: 1, window: w, dir: "g2e", prose: wire[0] }));
rej(() => openV2({ keys, counter: 1, window: w + 1, dir: "e2g", prose: wire[0] }));
rej(() => openV2({ keys: deriveV2Keys(nextSessionKey(sk, new Uint8Array(20)), 1), counter: 1, window: w, dir: "e2g", prose: wire[0] }));
// tamper: replace one word, drop one word, swap two words
const words = wire[10].split(" ");
rej(() => openV2({ keys, counter: 11, window: w, dir: "e2g", prose: [...words.slice(0, 5), "hello", ...words.slice(6)].join(" ") }));
rej(() => openV2({ keys, counter: 11, window: w, dir: "e2g", prose: [...words.slice(0, 5), ...words.slice(6)].join(" ") }));
rej(() => openV2({ keys, counter: 11, window: w, dir: "e2g", prose: [words[1], words[0], ...words.slice(2)].join(" ") }));
// wrong key
rej(() => openV2({ keys: deriveV2Keys(Uint8Array.from(randomBytes(32))), counter: 1, window: w, dir: "e2g", prose: wire[0] }));
console.log("frame2 ok: roundtrip 50, replay/deletion/reorder/reflection/window/gen/tamper(replace,drop,swap)/wrong-key rejected");
