# Handshake v3: close the ltRaw offline oracle

User decision 2026-11-02 01:42 PST. Protocol `lexis-hctr2-rans-v3`, agent **3.0.0**.
Incompatible with v2; both ends must upgrade together and regenerate identities.

## What changed

### Hello key (Noise NK style)
- `es = X25519(client_ephemeral, gate_static_pub)`
- Secret IKM for admit / HCTR2 hello body: `helloIkm = token || 0x00 || es`
- Word model still keyed by `token || gate_pub` so the wire can be parsed to bytes
  without the gate private key; those bytes do not decrypt without `es`.
- **[measured]** (`accept-d/v3-oracle.json`, N=500): admit matches with token+gatePub
  (v2-style IKM) = **0**; with random IKM = **0**; with correct `es` = **500**.
  Decrypted-under-wrong-key plaintext entropy 7.996 bit/B, monobit p=0.67, runs p=0.79.

### Tokens
- Reject if estimated entropy < 128 bits (`estimateTokenBits` in `lexis-agent.mjs`).
  Chose **reject** (not warn): a weak token re-opens online guessing; fail-closed is safer.
- `node lexis-agent.mjs --gen-token` prints a 128-bit base64url token.

### Long-term keys
- P-256 (65 B uncompressed) → **X25519** (32 B). Hello word count **[measured]**
  mean 107 (81–138) vs v2 mean ~133 (106–163).
- Migration: **breaking**. `identityFromJwks` rejects EC/P-256 with a clear Chinese
  error. No automatic conversion (different curve). Regenerate identity on both ends.

## Alternatives considered

| Alternative | Cost | Why not now |
|---|---|---|
| Argon2id stretch of the token into hello IKM | Tens–hundreds of ms per hello on the gate; needs a salt in the clear or derived; still needs something only the gate knows to stop token+gatePub offline decrypt unless combined with DH | Optional later hardening against weak tokens; does not replace DH. Would be a **protocol bump** if the wire gains a salt/params field. |
| PAKE (CPace / OPAQUE) | Extra round trip or larger hello; heavier CPU; more code | Stronger against token guessing online; larger change. Protocol bump. |
| Keep P-256 static, only add eph–static X25519 for hello | Gate would need **two** long-term keys (P-256 + X25519) | Rejected: one X25519 identity is simpler and shortens ltC. |

## Config / switches
- No silent switch between v2 and v3 (wire incompatible).
- Token policy is hard reject <128 bits (not configurable) — intentional.
- Future Argon2/PAKE would add e.g. `link.tokenKdf` and need a new protocol id.

## Modules to touch for a later change
- `src/lib/lexis/v2/handshake3.ts` — `helloIkm`, `edgeStart3`, `gateRespond3`
- `src/lib/lexis/crypto.ts` — identity curve
- `src/lib/lexis/v2/frame2.ts` — `PROTOCOL`
- `public/agent/lexis-agent.mjs` — `requireToken`, `--gen-token`
