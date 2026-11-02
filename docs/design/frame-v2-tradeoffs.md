# Frame v2 trade-offs (lexis-hctr2-rans-v2 / agent 2.0.0)

User decisions 2026-11-02 01:38–01:39 PST. Numbers marked **[measured]** come from
`/workspace/lexis-test/fixes-v18/accept-d/` and the earlier accept suite; **[inferred]**
are from code inspection. Line numbers are for `fix/v18` at the v2-final tag.

Honey only defends against brute-forcing the long-term private key and the passphrase.
It does **not** defend against someone who already holds a candidate session key.

---

## (a) Word mapping: Zipf rANS vs GF(2^14) bijection

### Current choice
Keep the keyed Zipf rANS mapping (`buildModel` / `bytesToWords` / `wordsToBytes` in
`src/lib/lexis/v2/model.ts`). Reason: the wire must look like natural English word
streams (Zipf, length and char distributions match the FrequencyWords corpus).

### Rejected alternative: GF(2^14) bijection
Already implemented as a reference (`buildGfModel` / `gfBytesToWords` /
`gfWordsToBytes`, same file). **[measured]** on 256 KiB (`accept/accept.json` D.mapping,
and `accept-d/accept.log`):

| | rANS | GF(2^14) |
|---|---|---|
| bits/word | 9.451 | 14 |
| wire bytes / cipher byte | 4.171 | 4.329 |
| avg word length | 3.927 | 6.577 |
| Zipf slope (top 2000) | −1.198 | **−0.099** |
| rank-bucket TVD vs corpus | 0.0145 | **0.7344** |
| length TVD vs corpus | 0.007 | 0.5323 |
| char TVD vs corpus | 0.0119 | 0.1327 |
| encode ms (256 KiB) | 28 | 13 |

GF fails the Zipf / length / char statistical targets completely. Cost of switching:
every peer must upgrade; old frames become unreadable; the corpus look is lost.

### Cost of keeping rANS
The canonical re-encoding check (`openV2` / `openV2Honey`, `frame2.ts` around the
`bytesToWords(...); again.every(...)` lines) is **key-dependent**. **[measured]** right
key passes 100%, wrong key ~2–3%, logistic AUC ≈ 0.987 from one frame
(`accept-d/honey.json`). A holder of a candidate session key can confirm it. Accepted.

### Config switch?
**No.** Changing the mapping changes the wire alphabet and the ciphertext→prose
bijection. A silent `frame.wordMapping="gf"` would break interop with peers that
still speak rANS. A future switch needs a **new protocol id** (e.g.
`lexis-hctr2-gf-vN`) and a coordinated upgrade. The GF helpers stay in-tree as a
reference only.

### What a future switch touches
- `src/lib/lexis/v2/model.ts`: `buildModel`/`bytesToWords`/`wordsToBytes` (≈159–340)
  vs `buildGfModel`/`gfBytesToWords`/`gfWordsToBytes` (≈383–437).
- `src/lib/lexis/v2/frame2.ts`: `deriveV2Keys` (builds the model), `sealV2` /
  `openV2` / `openV2Honey` / `unsealRawV2` (call the mapping).
- `src/lib/lexis/v2/handshake2.ts`: hello/server/finish encoding (same mapping).
- `PROTOCOL` in `frame2.ts` (name + version) — **must bump**.
- Browser lab (`handshake.ts` / seal modules) if it is ever ported.

---

## (b) Small-frame expansion vs honey pad share

### Current choice
`frame.smallFramePolicy = "expansion"` (default). Pad only within the
`maxExpansion` wire budget (`padLength` in `frame2.ts`). Small frames often get
**zero** pad so expansion stays as low as the fixed overhead allows. Reason: the
user prioritised the expansion rate for small frames.

### Rejected alternative: always pad (honey-friendly)
`frame.smallFramePolicy = "honey"`: pad uniform on `[0, 255]` regardless of budget.
Sender-only; the receiver reads pad from the length field, so both policies
interoperate on the same protocol id (`lexis-hctr2-rans-v2`).

**[measured]** pad-share AUC, real vs wrong key (`accept-d/honey.json` vs
`accept-d/honey-policy-honey.json`, N=500–1000 pairs/bucket):

| Bucket | expansion (default) padShareAUC | honey policy padShareAUC |
|---|---|---|
| 1–64 B | **0.973** | 0.708 |
| 65–256 B | **0.961** | 0.530 |
| 257 B–1 K | 0.785 | 0.514 |
| 1–4 K | 0.529 | 0.534 |

**[measured]** wire expansion under both policies (`accept-d/expansion-*.json`):

| Bucket | expansion single mean | honey single mean | expansion burst mean | honey burst mean |
|---|---|---|---|---|
| 1–64 B | 14.4 | **63.9** | 7.1 | 8.8 |
| 65–256 B | 5.42 | **8.69** | 5.15 | 5.50 |
| 257 B–1 K | 4.81 | 5.33 | 4.70 | 4.74 |
| 1–4 K | 4.47 | 4.47 | 4.42 | 4.43 |
| 4–16 K | 4.36 | 4.35 | 4.35 | 4.35 |

Honey policy makes small-frame pad share nearly indistinguishable (≥65 B AUC ≈ 0.53)
but roughly **4× worse** expansion on 1–64 B singles. Accepted trade: keep expansion
default; honey fails on small frames (AUC ≈ 0.97).

### Config switch
**Yes.** `frame.smallFramePolicy`: `"expansion"` (default) | `"honey"`.
Wired through `setFrameOptions` (`src/agent/frame.ts`) and `lexis-agent.mjs` on
load/hot-reload. Default-path pad lengths verified unchanged over 2142 cases
(`src/lib/lexis/v2/policy.test.ts`).

### What a future change touches
- `padLength` / `sealV2` options in `src/lib/lexis/v2/frame2.ts`.
- `setFrameOptions` + agent config `frame.smallFramePolicy`.
- No protocol bump (sender-only).

---

## (c) Frames under ~256 B that exceed the 5× cap

### Current choice
Accept that singles under ~256 B exceed 5×. Rely on **coalescing** (batch small
records inside the SPRP before sealing) to bring the ratio down. Split only when a
record exceeds `MAX_FRAME_PAYLOAD` (4096 B). Reason: the 18 B mnemonic+length plus
segment/record headers encode to ~100+ wire characters; a 1-byte payload is ~170×
by arithmetic, not by a tunable.

### Per-bucket expansion table **[measured]**
Default policy, `accept-d/expansion-expansion.json` / `expansion.json`.
"Single-write" = one write then flush; "coalesced" = 8 writes in one tick.

| Bucket | Mode | mean | p95 | max | frames/write | ≤5× share |
|---|---|---|---|---|---|---|
| 1–64 B | single-write | 14.4–15.4 | 39 | 172 | 1.00 | 0% |
| 1–64 B | coalesced (8-burst) | 7.1 | 8.0–8.3 | 10.2 | 0.125 | 0% |
| 65–256 B | single-write | 5.36–5.42 | 6.1 | 6.5 | 1.00 | 13–16% |
| 65–256 B | coalesced | 5.11–5.15 | 5.4–5.6 | 5.6 | 0.24 | 32–33% |
| 257 B–1 K | single-write | 4.80–4.81 | 5.15 | 5.4 | 1.00 | 72–78% |
| 257 B–1 K | coalesced | 4.70 | 4.85–4.87 | 4.95 | 0.49 | 100% |
| 1–4 K | single-write | 4.46–4.47 | 4.8 | 5.1 | 1.00 | 99% |
| 1–4 K | coalesced | 4.42 | 4.51–4.54 | 4.53 | 1.00 | 100% |
| 4–16 K | single-write | 4.34–4.36 | 4.47 | 4.53 | ~3.0 (split) | 100% |
| 4–16 K | coalesced | 4.32–4.35 | 4.35–4.39 | 4.35 | ~3.0 | 100% |

### Rejected / deferred alternatives
1. **Raise the cap** (e.g. 16×): hides the issue, worsens traffic analysis. Not chosen.
2. **Refuse / buffer until ≥256 B**: adds latency for interactive traffic (SSH keystrokes).
   Not chosen; coalescing already batches same-tick writes without a timer.
3. **Force honey-style pad on small frames**: see (b); expansion gets worse.
4. **Higher-entropy alphabet**: see (a); fails Zipf.

### Config switch
**Partial.** `frame.coalesceTarget` (default **1024** bytes of queued record payload
before an urgent flush) is configurable via `setFrameOptions` / agent
`frame.coalesceTarget`. Smaller values coalesce less (worse expansion on bursts);
larger values add latency waiting for more records. `MAX_FRAME_PAYLOAD` (4096) stays
fixed — changing it alters the split boundary fingerprint and is not exposed.
No protocol bump (internal batching is inside the SPRP).

### What a future change touches
- `COALESCE_TARGET` / `kickDrain` / `drain` / `sendSplit` in `src/agent/frame.ts`
  (≈36–825).
- `packBatch` / `Reassembler` / `SEG_*` in `src/lib/lexis/v2/frame2.ts`.
- Agent `frame.coalesceTarget`. Timer-based coalescing (if added later) would need
  careful interaction with rekey/END urgent frames; still no protocol bump unless
  the batch container format changes.

---

## Related accepted boundaries (not trade-offs above)
- Canonical-check + body-structure confirmation by a **candidate session key** holder
  (see honey docstring in `frame2.ts`). Honey is not a session-key deniability mechanism.
- ltRaw offline oracle when the attacker has **token + gate public key** (unchanged;
  listed as a known item). Closing it needs a protocol change (gate static DH on hello).
