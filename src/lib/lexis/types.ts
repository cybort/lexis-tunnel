export type NodeRole = "gate" | "edge";

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
