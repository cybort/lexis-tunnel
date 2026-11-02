/** LEXIS 3.x. Wire image is prose; secrecy is the session key.
 * Wire format: HCTR2 wide-block + keyed rANS corpus words (v2/frame2.ts, v2/handshake3.ts).
 * `lexiconSize` / `bitsPerWord` / `mac*` below describe the legacy v1 codebook record layer
 * (seal.ts, lexicon.ts), which is still in the lib but not used on the wire. */

export const SPEC = {
  name: "lexis-hctr2-rans-v3",
  /** Sidecar `cipher` values written by older builds; recognised on import. */
  legacyNames: ["lexis-codebook-ctr-v1", "lexis-hctr2-rans-v2"] as readonly string[],
  curve: "X25519",
  kdf: "Argon2id",
  expand: "HKDF-SHA-256",
  mac: "HMAC-SHA-256",
  macBytes: 16,
  /** legacy v1 codebook size (seal.ts); the v3 vocabulary is the corpus model (v2/model.ts). */
  lexiconSize: 4096,
  bitsPerWord: 12,
  windowSec: 300,
  /** Accept the previous window this many seconds in, and the next window this many seconds before the roll. */
  skewSec: 120,
  counterBits: 24,
} as const;

/** Closed-class glue. These words carry no payload bits and never enter a lexicon. */
export const GLUE = ["the", "our", "its", "that", "and"] as const;

export const GLUE_SET = new Set<string>(GLUE);

export const LEADS = ["the", "our", "its", "that"] as const;
