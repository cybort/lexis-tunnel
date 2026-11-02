import { create } from "zustand";
import { persist, createJSONStorage } from "zustand/middleware";
import { b64 } from "./bytes";
import { createIdentity } from "./crypto";
import { SPEC } from "./spec";
import type { MeshNode, PortMap, StoredVault } from "./types";

/** Disk copy drops the scalar when a vault holds it. The running tab keeps `d`. */
function persistedNode(node: MeshNode): MeshNode {
  if (!node.vault || !node.privateJwk.d) return node;
  const { d: _scalar, ...privateJwk } = node.privateJwk;
  return { ...node, privateJwk };
}

type MeshState = {
  nodes: MeshNode[];
  mappings: PortMap[];
  addNode: (node: MeshNode) => void;
  updateNode: (id: string, patch: Partial<Pick<MeshNode, "name" | "pinnedPeerId">>) => void;
  removeNode: (id: string) => void;
  bindPair: (a: string, b: string) => void;
  addMapping: (mapping: PortMap) => void;
  updateMapping: (id: string, patch: Partial<PortMap>) => void;
  removeMapping: (id: string) => void;
  seed: (nodes: MeshNode[], mappings: PortMap[]) => void;
  setIdentity: (
    id: string,
    next: Pick<MeshNode, "publicJwk" | "privateJwk" | "publicRawB64" | "fingerprint" | "kdf"> & { vault?: StoredVault | null },
  ) => void;
  reset: () => void;
};

export const useMesh = create<MeshState>()(
  persist(
    (set) => ({
      nodes: [],
      mappings: [],
      addNode: (node) => set((s) => ({ nodes: [...s.nodes, node] })),
      updateNode: (id, patch) =>
        set((s) => ({
          nodes: s.nodes.map((n) => (n.id === id ? { ...n, ...patch } : n)),
        })),
      removeNode: (id) =>
        set((s) => ({
          nodes: s.nodes
            .filter((n) => n.id !== id)
            .map((n) => (n.pinnedPeerId === id ? { ...n, pinnedPeerId: null } : n)),
          mappings: s.mappings.filter((m) => m.gateId !== id),
        })),
      bindPair: (a, b) =>
        set((s) => ({
          nodes: s.nodes.map((n) => {
            if (n.id === a) return { ...n, pinnedPeerId: b };
            if (n.id === b) return { ...n, pinnedPeerId: a };
            return n;
          }),
        })),
      addMapping: (mapping) => set((s) => ({ mappings: [...s.mappings, mapping] })),
      updateMapping: (id, patch) =>
        set((s) => ({
          mappings: s.mappings.map((m) => (m.id === id ? { ...m, ...patch } : m)),
        })),
      removeMapping: (id) => set((s) => ({ mappings: s.mappings.filter((m) => m.id !== id) })),
      seed: (nodes, mappings) => set({ nodes, mappings }),
      setIdentity: (id, next) =>
        set((s) => ({
          nodes: s.nodes.map((n) => (n.id === id ? { ...n, ...next } : n)),
        })),
      reset: () => set({ nodes: [], mappings: [] }),
    }),
    {
      name: "lexis-mesh-v1",
      storage: createJSONStorage(() => localStorage),
      skipHydration: true,
      version: 2,
      migrate: (persisted, version) => {
        if (version < 2) return { nodes: [], mappings: [] };
        return persisted as { nodes: MeshNode[]; mappings: PortMap[] };
      },
      partialize: (state) => ({
        nodes: state.nodes.map(persistedNode),
        mappings: state.mappings,
      }),
    },
  ),
);

export async function makeNode(name: string, role: MeshNode["role"]): Promise<MeshNode> {
  const key = await createIdentity();
  return {
    id: crypto.randomUUID(),
    name,
    role,
    publicJwk: key.publicJwk,
    privateJwk: key.privateJwk,
    publicRawB64: b64(key.publicRaw),
    fingerprint: key.fingerprint,
    pinnedPeerId: null,
    createdAt: Date.now(),
    kdf: null,
    vault: null,
  };
}

let seeding: Promise<void> | null = null;

export function ensureSeed(): Promise<void> {
  if (useMesh.getState().nodes.length > 0) return Promise.resolve();
  if (seeding) return seeding;
  seeding = (async () => {
    try {
      if (useMesh.getState().nodes.length > 0) return;
      const gate = await makeNode("港区闸门", "gate");
      const edge = await makeNode("内网工作室", "edge");
      gate.pinnedPeerId = edge.id;
      edge.pinnedPeerId = gate.id;
      const mappings: PortMap[] = [
        {
          id: crypto.randomUUID(),
          gateId: gate.id,
          proto: "tcp",
          listenPort: 18443,
          targetHost: "127.0.0.1",
          targetPort: 8080,
          priority: 10,
          enabled: true,
          note: "工作室控制台",
        },
        {
          id: crypto.randomUUID(),
          gateId: gate.id,
          proto: "udp",
          listenPort: 51820,
          targetHost: "10.0.0.8",
          targetPort: 51820,
          priority: 5,
          enabled: true,
          note: "内网报文",
        },
      ];
      if (useMesh.getState().nodes.length === 0) {
        useMesh.getState().seed([gate, edge], mappings);
      }
    } finally {
      seeding = null;
    }
  })();
  return seeding;
}

export function sealFileOf(vault: NonNullable<MeshNode["vault"]>) {
  return {
    saltB64: vault.saltB64,
    memoryKiB: vault.memoryKiB,
    iterations: vault.iterations,
    parallelism: vault.parallelism,
    lo: vault.lo,
    hi: vault.hi,
  };
}

export function sidecarOf(node: MeshNode, peer: MeshNode | undefined) {
  const secret = node.vault ? undefined : node.privateJwk;
  return {
    cipher: SPEC.name,
    role: node.role,
    name: node.name,
    fingerprint: node.fingerprint,
    publicJwk: node.publicJwk,
    privateJwk: secret,
    pinnedPeerFingerprint: peer?.fingerprint ?? null,
    pinnedPeerPublicJwk: peer?.publicJwk ?? null,
    windowSeconds: SPEC.windowSec,
    lexiconSize: SPEC.lexiconSize,
    curve: SPEC.curve,
    handshake: "x25519-noise-nk-argon2id",
    kdf: node.kdf,
    wire: "hctr2-rans-prose",
  };
}

export function downloadJson(filename: string, data: unknown) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
