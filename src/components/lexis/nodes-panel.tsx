import { useEffect, useRef, useState } from "react";
import { Download, Trash2 } from "lucide-react";
import { b64, randomBytes } from "@/lib/lexis/bytes";
import { identityFromJwks, LexisError } from "@/lib/lexis/crypto";
import { currentWindow } from "@/lib/lexis/handshake";
import { openIdentityVault, privateScalar, sealIdentityVault, vaultFromStored, vaultToStored } from "@/lib/lexis/honey";
import { clampKdf, deriveIdentity } from "@/lib/lexis/kdf";
import { sessionLexicon } from "@/lib/lexis/lexicon";
import { useProfile } from "@/lib/lexis/profile-store";
import type { NetPeer } from "@/lib/lexis/profile";
import { SPEC } from "@/lib/lexis/spec";
import { downloadJson, makeNode, sidecarOf, useMesh } from "@/lib/lexis/store";
import type { MeshNode, NodeKdf, NodeRole, StoredVault } from "@/lib/lexis/types";
import { Btn, control, Field } from "./ui";

function roleLabel(role: NodeRole) {
  return role === "gate" ? "公网闸门" : "内网端";
}

function readKdf(value: unknown): NodeKdf | null {
  if (!value || typeof value !== "object") return null;
  const raw = value as Partial<NodeKdf>;
  if (typeof raw.saltB64 !== "string" || !raw.saltB64) return null;
  return { saltB64: raw.saltB64, ...clampKdf(raw) };
}

function readVault(value: unknown): StoredVault | null {
  const vault = vaultFromStored(value);
  return vault ? vaultToStored(vault) : null;
}

export function NodesPanel() {
  const nodes = useMesh((s) => s.nodes);
  const addNode = useMesh((s) => s.addNode);
  const updateNode = useMesh((s) => s.updateNode);
  const removeNode = useMesh((s) => s.removeNode);
  const bindPair = useMesh((s) => s.bindPair);
  const reset = useMesh((s) => s.reset);
  const setIdentity = useMesh((s) => s.setIdentity);
  const profile = useProfile((s) => s.profile);
  const patch = useProfile((s) => s.patch);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  async function create(role: NodeRole) {
    setBusy(true);
    setError(null);
    try {
      const name = role === "gate" ? "新闸门" : "新内网端";
      addNode(await makeNode(name, role));
    } catch (err) {
      setError(err instanceof Error ? err.message : "密钥没有生成");
    } finally {
      setBusy(false);
    }
  }

  async function onImport(file: File) {
    setError(null);
    try {
      const data = JSON.parse(await file.text()) as Record<string, unknown>;
      if (data.cipher !== SPEC.name) throw new LexisError("这不是词隙侧车");
      if (data.role !== "gate" && data.role !== "edge") throw new LexisError("角色不对");
      const publicJwk = data.publicJwk as JsonWebKey;
      const privateJwk = data.privateJwk as JsonWebKey;
      const ident = await identityFromJwks(publicJwk, privateJwk);
      const node: MeshNode = {
        id: crypto.randomUUID(),
        name: typeof data.name === "string" && data.name ? data.name : "导入节点",
        role: data.role,
        publicJwk: ident.publicJwk,
        privateJwk: ident.privateJwk,
        publicRawB64: b64(ident.publicRaw),
        fingerprint: ident.fingerprint,
        pinnedPeerId: null,
        createdAt: Date.now(),
        kdf: readKdf(data.kdf),
        vault: readVault(data.vault),
      };
      addNode(node);
      const peerFp = data.pinnedPeerFingerprint;
      if (typeof peerFp === "string") {
        const peer = useMesh.getState().nodes.find((n) => n.fingerprint === peerFp && n.id !== node.id);
        if (peer) bindPair(node.id, peer.id);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "侧车读不了");
    }
  }

  async function deriveNode(id: string, passphrase: string, spare: string) {
    const trimmed = passphrase.trim();
    const alt = spare.trim();
    if (!trimmed) {
      setError("先写口令");
      return;
    }
    if (alt && alt === trimmed) {
      setError("备用口令要和原口令不同");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const params = clampKdf(useProfile.getState().profile.kdf);
      const salt = randomBytes(16);
      const primary = await deriveIdentity(trimmed, salt, params);
      const entries = [{ passphrase: trimmed, scalar: privateScalar(primary.privateJwk) }];
      if (alt) {
        const other = await deriveIdentity(alt, salt, params);
        entries.push({ passphrase: alt, scalar: privateScalar(other.privateJwk) });
      }
      const sealed = await sealIdentityVault(entries, salt, params, 4);
      const opened = await openIdentityVault(sealed, trimmed);
      const kdf: NodeKdf = { saltB64: b64(salt), ...params };
      setIdentity(id, {
        publicJwk: opened.publicJwk,
        privateJwk: opened.privateJwk,
        publicRawB64: b64(opened.publicRaw),
        fingerprint: opened.fingerprint,
        kdf,
        vault: vaultToStored(sealed),
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : "派生失败");
    } finally {
      setBusy(false);
    }
  }

  async function unlockNode(id: string, passphrase: string) {
    const trimmed = passphrase.trim();
    if (!trimmed) {
      setError("先写口令");
      return;
    }
    const node = useMesh.getState().nodes.find((item) => item.id === id);
    const sealed = node?.vault ? vaultFromStored(node.vault) : null;
    if (!node || !sealed) {
      setError("这把私钥还没有封存");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const opened = await openIdentityVault(sealed, trimmed);
      setIdentity(id, {
        publicJwk: opened.publicJwk,
        privateJwk: opened.privateJwk,
        publicRawB64: b64(opened.publicRaw),
        fingerprint: opened.fingerprint,
        kdf: node.kdf,
        vault: node.vault,
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : "解不开");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap gap-2">
        <Btn disabled={busy} onClick={() => create("gate")}>
          新建闸门
        </Btn>
        <Btn kind="ghost" disabled={busy} onClick={() => create("edge")}>
          新建内网端
        </Btn>
        <Btn kind="ghost" onClick={() => fileRef.current?.click()}>
          导入侧车
        </Btn>
        <Btn
          kind="ember"
          onClick={() => {
            if (confirm("清空这台浏览器里的节点和映射？私钥也会一起删掉。")) reset();
          }}
        >
          清空
        </Btn>
        <input
          ref={fileRef}
          type="file"
          accept="application/json,.json"
          className="sr-only"
          onChange={(e) => {
            const file = e.target.files?.[0];
            if (file) void onImport(file);
            e.target.value = "";
          }}
        />
      </div>
      {error ? <p className="text-sm text-ember">{error}</p> : null}
      <p className="text-sm text-mist">
        初始私钥按口令派生后，封成同一条求值的系数，口令本身不留下。任意一句口令都会解开一把合法私钥，再叠上当前时间窗，得到一份同样格式的词表。口令不同，或时间窗不同，词就不同，两句错误口令之间也不会撞成同一份。不会提示哪一句是当初那句。刷新之后标量不在浏览器里，要再解一次。
      </p>
      <div className="grid gap-3 lg:grid-cols-2">
        {nodes.map((node) => (
          <NodeCard
            key={node.id}
            node={node}
            peers={nodes.filter((n) => n.role !== node.role)}
            peer={nodes.find((n) => n.id === node.pinnedPeerId)}
            onName={(name) => updateNode(node.id, { name })}
            onBind={(peerId) => bindPair(node.id, peerId)}
            onRemove={() => removeNode(node.id)}
            onExport={() => {
              if (node.vault && !node.privateJwk.d) {
                setError("先解开，导出的侧车才带得走常驻进程要的私钥");
                return;
              }
              downloadJson(`${node.role}-${node.fingerprint}.json`, sidecarOf(node, nodes.find((n) => n.id === node.pinnedPeerId)));
            }}
            onDerive={(passphrase, spare) => deriveNode(node.id, passphrase, spare)}
            onUnlock={(passphrase) => unlockNode(node.id, passphrase)}
            resident={profile.identity?.id === node.id}
            joined={profile.peers.some((peer) => peer.id === node.id)}
            onResident={() => {
              if (node.vault && !node.privateJwk.d) {
                setError("先解开，常驻身份才拿得到私钥");
                return;
              }
              patch({
                identity: {
                  id: node.id,
                  name: node.name,
                  publicJwk: node.publicJwk,
                  privateJwk: node.privateJwk,
                  publicRawB64: node.publicRawB64,
                  fingerprint: node.fingerprint,
                },
              });
            }}
            onJoin={() => {
              const next: NetPeer = {
                id: node.id,
                name: node.name,
                endpoint: profile.peerEndpoint,
                transport: profile.outer.transport,
                publicRawB64: node.publicRawB64,
                wsPath: profile.outer.wsPath,
                wsHost: "",
                relay: false,
                exit: false,
                targets: [],
              };
              patch({ peers: [...profile.peers.filter((peer) => peer.id !== node.id), next] });
            }}
          />
        ))}
      </div>
    </div>
  );
}

function NodeCard({
  node,
  peers,
  peer,
  onName,
  onBind,
  onRemove,
  onExport,
  onDerive,
  onUnlock,
  resident,
  joined,
  onResident,
  onJoin,
}: {
  node: MeshNode;
  peers: MeshNode[];
  peer: MeshNode | undefined;
  onName: (name: string) => void;
  onBind: (peerId: string) => void;
  onRemove: () => void;
  onExport: () => void;
  onDerive: (passphrase: string, spare: string) => Promise<void>;
  onUnlock: (passphrase: string) => Promise<void>;
  resident: boolean;
  joined: boolean;
  onResident: () => void;
  onJoin: () => void;
}) {
  const [peerId, setPeerId] = useState(node.pinnedPeerId ?? "");
  const [passphrase, setPassphrase] = useState("");
  const [spare, setSpare] = useState("");
  const [deriving, setDeriving] = useState(false);
  const [words, setWords] = useState("");
  const sealed = Boolean(node.vault);
  const unlocked = Boolean(node.privateJwk.d);

  useEffect(() => {
    let cancel = false;
    if (!node.privateJwk.d) {
      setWords("");
      return;
    }
    void sessionLexicon(privateScalar(node.privateJwk), currentWindow())
      .then((lex) => {
        if (!cancel) setWords(`${lex[0]} · ${lex[1]} · ${lex[2]} · ${lex[3]}`);
      })
      .catch(() => {
        if (!cancel) setWords("");
      });
    return () => {
      cancel = true;
    };
  }, [node.privateJwk.d, node.fingerprint]);

  return (
    <article className="rounded-md border border-line bg-panel p-4">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <p className="text-sm text-sage">{roleLabel(node.role)}</p>
          <input
            className={`${control} mt-2`}
            value={node.name}
            aria-label="节点名称"
            onChange={(e) => onName(e.target.value)}
          />
        </div>
        <button
          type="button"
          className="inline-flex min-h-11 min-w-11 items-center justify-center text-mist hover:text-ember"
          aria-label={`删除${node.name}`}
          onClick={onRemove}
        >
          <Trash2 className="size-4" />
        </button>
      </div>
      <p className="mt-3 break-all font-mono text-xs text-mist">{node.fingerprint}</p>
      {node.kdf ? (
        <p className="mt-2 text-sm text-mist">
          Argon2id · 内存 {node.kdf.memoryKiB} KiB · 迭代 {node.kdf.iterations} · 并行 {node.kdf.parallelism}
          {sealed ? " · 私钥以系数封存" : ""}
        </p>
      ) : (
        <p className="mt-2 text-sm text-mist">这把私钥是随机生成的，还没有用口令派生。</p>
      )}
      {sealed && !unlocked ? <p className="mt-2 text-sm text-mist">标量不在这台浏览器里。输入任意口令都会解开一把合法私钥。</p> : null}
      {words ? <p className="mt-2 text-sm text-mist">本窗词表开头：{words}</p> : null}
      <div className="mt-3 flex flex-col gap-2 sm:flex-row">
        <Field label="绑定到">
          <select
            className={control}
            value={peerId}
            onChange={(e) => setPeerId(e.target.value)}
          >
            <option value="">未绑定</option>
            {peers.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </select>
        </Field>
      </div>
      <div className="mt-3 flex flex-wrap gap-2">
        <Btn kind="ghost" disabled={!peerId} onClick={() => onBind(peerId)}>
          互相绑定
        </Btn>
        <Btn kind={resident ? "solid" : "ghost"} onClick={onResident}>
          {resident ? "已是常驻身份" : "当作常驻身份"}
        </Btn>
        <Btn kind={joined ? "solid" : "ghost"} onClick={onJoin}>
          {joined ? "已在中继名单" : "加入中继名单"}
        </Btn>
        <Btn kind="ghost" onClick={onExport}>
          <Download className="size-4" aria-hidden="true" />
          导出侧车
        </Btn>
      </div>
      <div className="mt-3 grid gap-2">
        <Field label="口令">
          <input
            className={control}
            type="password"
            autoComplete="off"
            value={passphrase}
            aria-label={`${node.name}的口令`}
            onChange={(e) => setPassphrase(e.target.value)}
          />
        </Field>
        <Field label="备用口令">
          <input
            className={control}
            type="password"
            autoComplete="off"
            value={spare}
            placeholder="只在封存时写入，可留空"
            aria-label={`${node.name}的备用口令`}
            onChange={(e) => setSpare(e.target.value)}
          />
        </Field>
        <div className="flex flex-wrap gap-2">
          <Btn
            kind="ghost"
            disabled={deriving || !passphrase.trim()}
            onClick={() => {
              setDeriving(true);
              void onDerive(passphrase, spare).finally(() => {
                setPassphrase("");
                setSpare("");
                setDeriving(false);
              });
            }}
          >
            {deriving ? "封存中" : "派生并封存"}
          </Btn>
          {sealed ? (
            <Btn
              kind="ghost"
              disabled={deriving || !passphrase.trim()}
              onClick={() => {
                setDeriving(true);
                void onUnlock(passphrase).finally(() => {
                  setPassphrase("");
                  setDeriving(false);
                });
              }}
            >
              用这句口令解开
            </Btn>
          ) : null}
        </div>
        <p className="text-sm text-mist">参数用配置页里的内存和迭代。封存会换掉指纹，绑定仍按节点编号。解开不区分原口令和备用口令。</p>
      </div>
      {node.pinnedPeerId ? (
        <p className="mt-3 text-sm text-mist">已指向 {peer?.name ?? "一个已经删掉的节点"}</p>
      ) : (
        <p className="mt-3 text-sm text-ember">还没有绑定对端，隧道不会握上手。</p>
      )}
    </article>
  );
}
