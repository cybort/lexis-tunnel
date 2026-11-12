/** LEXIS 4.x. Default frame.dte is bb-k-v4s (protocolName); bb-k-v4 / bb-v4 / bb-c8-v4 stay selectable. Hello, server and finish keep
 * their 3.x layout and lengths. With frame.dteCheck (default on) the confirmation transcript
 * also binds frame.dte, so a 3.0 peer does not finish unless this end uses rans-v3 and the
 * check is off. Setting rans-v3 alone is not enough. Wire image is prose; secrecy is the session key.
 * Wire format: HCTR2 wide-block plus corpus words. K uses a public model and a keyed tail.
 * rans-v3 is the keyed rANS fallback. There is no separate byte-distribution proof for K
 * beyond that model. (v2/frame2.ts, v2/handshake3.ts).
 * `lexiconSize` / `bitsPerWord` / `mac*` below describe the legacy v1 codebook record layer
 * (seal.ts, lexicon.ts), which is still in the lib but not used on the wire. */

export const SPEC = {
  name: "lexis-hctr2-bb-k-v4s",
  /** Sidecar `cipher` values written by older builds; recognised on import. */
  legacyNames: ["lexis-codebook-ctr-v1", "lexis-hctr2-rans-v2", "lexis-hctr2-rans-v3", "lexis-hctr2-bb-v4", "lexis-hctr2-bb-k-v4"] as readonly string[],
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
