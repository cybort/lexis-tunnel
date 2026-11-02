export type NodeRole = "gate" | "edge";

export type NodeKdf = {
  saltB64: string;
  memoryKiB: number;
  iterations: number;
  parallelism: number;
};

/** Coefficients only. The passphrases that were sealed are not stored. */
export type StoredProgram = {
  saltB64: string;
  coeffsB64: string[];
};

/** At-rest long-term private key. Any passphrase evaluates the same polynomial. */
export type StoredVault = {
  saltB64: string;
  memoryKiB: number;
  iterations: number;
  parallelism: number;
  lo: StoredProgram;
  hi: StoredProgram;
};

export type MeshNode = {
  id: string;
  name: string;
  role: NodeRole;
  publicJwk: JsonWebKey;
  privateJwk: JsonWebKey;
  publicRawB64: string;
  fingerprint: string;
  pinnedPeerId: string | null;
  createdAt: number;
  /** Set when the long-term key was derived from a passphrase. The passphrase is not stored. */
  kdf: NodeKdf | null;
  /** Present when the scalar is stored as coefficients. `privateJwk.d` is memory-only then. */
  vault?: StoredVault | null;
};

export type PortMap = {
  id: string;
  gateId: string;
  proto: "tcp" | "udp";
  listenPort: number;
  targetHost: string;
  targetPort: number;
  priority: number;
  enabled: boolean;
  note: string;
};