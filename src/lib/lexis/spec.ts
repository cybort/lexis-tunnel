/** LEXIS codebook-CTR v1. Wire image is prose; secrecy is the session key. */

export const SPEC = {
  name: "lexis-codebook-ctr-v1",
  curve: "P-256",
  kdf: "Argon2id",
  expand: "HKDF-SHA-256",
  mac: "HMAC-SHA-256",
  macBytes: 16,
  lexiconSize: 4096,
  bitsPerWord: 12,
  windowSec: 300,
  counterBits: 24,
} as const;

/** Closed-class glue. These words carry no payload bits and never enter a lexicon. */
export const GLUE = ["the", "our", "its", "that", "and"] as const;

export const GLUE_SET = new Set<string>(GLUE);

export const LEADS = ["the", "our", "its", "that"] as const;
