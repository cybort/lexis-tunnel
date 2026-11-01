export type NodeRole = "gate" | "edge";

export type NodeKdf = {
  saltB64: string;
  memoryKiB: number;
  iterations: number;
  parallelism: number;
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
