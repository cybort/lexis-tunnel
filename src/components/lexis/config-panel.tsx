import { useEffect, useState, type ReactNode } from "react";
import { b64 } from "@/lib/lexis/bytes";
import { createIdentity } from "@/lib/lexis/crypto";
import { compileBlocks, packIndices, programToStored } from "@/lib/lexis/honey";
import { SPEC } from "@/lib/lexis/spec";
import {
  ACTIONS,
  RULE_TYPES,
  actionLabel,
  edgePreset,
  gatePreset,
  importClashRules,
  importSingBox,
  matchRoute,
  profileIssues,
  exportedConfig,
  estimateTokenBits,
  mintHandshakeToken,
  type Inbound,
  type LexisProfile,
  type NetPeer,
  type OuterTransport,
  type ProcessRule,
  type ReverseDoor,
  type RouteRule,
} from "@/lib/lexis/profile";
import { clampKdf } from "@/lib/lexis/kdf";
import { useProfile } from "@/lib/lexis/profile-store";
import { downloadJson, sealFileOf } from "@/lib/lexis/store";
import { Btn, control, Field } from "./ui";

function rid(prefix: string) {
  return `${prefix}-${crypto.randomUUID().slice(0, 8)}`;
}

function parseKeyHex(text: string): Uint8Array | null {
  const cleaned = text.trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(cleaned)) return null;
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) out[i] = Number.parseInt(cleaned.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function parseIndices(text: string): [number, number, number, number] | null {
  const parts = text.trim().split(/\s+/).map((item) => Number(item));
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n >= SPEC.lexiconSize)) return null;
  return [parts[0], parts[1], parts[2], parts[3]];
}

export function ConfigPanel() {
  const profile = useProfile((s) => s.profile);
  const patch = useProfile((s) => s.patch);
  const [importKind, setImportKind] = useState<"clash" | "sing-box">("clash");
  const [importText, setImportText] = useState("DOMAIN-SUFFIX,example.com,PROXY\nGEOSITE,cn,DIRECT\nMATCH,PROXY");
  const [importError, setImportError] = useState<string | null>(null);
  const [host, setHost] = useState("www.baidu.com");
  const [ip, setIp] = useState("");
  const [proc, setProc] = useState("");
  const [minting, setMinting] = useState(false);
  const [coverKey, setCoverKey] = useState("");
  const [coverIdx, setCoverIdx] = useState("4 8 15 16");
  const [coverKey2, setCoverKey2] = useState("");
  const [coverIdx2, setCoverIdx2] = useState("");
  const [coverError, setCoverError] = useState<string | null>(null);
  const [covering, setCovering] = useState(false);
  const [a1Ask, setA1Ask] = useState(false);
  const [tunDraft, setTunDraft] = useState<Partial<Record<"mtu" | "mss" | "oooMaxBytes" | "oooMaxSegs" | "oooTotalBytes", string>>>({});
  const commonDtes = ["bb-k-v4s", "bb-k-v4", "rans-v3"] as const;
  const experimentalDtes = ["bb-v4", "bb-c8-v4", "bb-ou-v4", "bb-ouc8-v4", "bb-ouc8r-v4", "dfa-v4"] as const;
  const dteExperimental = experimentalDtes.includes(profile.frame.dte as (typeof experimentalDtes)[number]);
  function setFrame(partial: Partial<LexisProfile["frame"]>) {
    patch({ frame: { ...profile.frame, ...partial } });
  }
  const tunField = (key: "mtu" | "mss" | "oooMaxBytes" | "oooMaxSegs" | "oooTotalBytes", min: number, max: number, fallback: number, emptyNull = false) => ({
    value: tunDraft[key] ?? (emptyNull ? (profile.tun?.mss ?? "") : (profile.tun?.[key] ?? fallback)),
    onChange: (e: { target: { value: string } }) => {
      const text = e.target.value;
      setTunDraft((draft) => ({ ...draft, [key]: text }));
      const trimmed = text.trim();
      if (trimmed === "") {
        if (emptyNull) patch({ tun: { ...profile.tun, mss: null } });
        return;
      }
      if (!/^\d+$/.test(trimmed)) return;
      const n = Number(trimmed);
      if (emptyNull && n === 0) {
        patch({ tun: { ...profile.tun, mss: null } });
        setTunDraft((draft) => {
          const next = { ...draft };
          delete next[key];
          return next;
        });
        return;
      }
      if (n < min || n > max) return;
      patch({ tun: { ...profile.tun, [key]: n } });
      setTunDraft((draft) => {
        const next = { ...draft };
        delete next[key];
        return next;
      });
    },
    onBlur: () =>
      setTunDraft((draft) => {
        const next = { ...draft };
        delete next[key];
        return next;
      }),
  });
  const hit = matchRoute(profile, { host, ip, process: proc });
  const issues = profileIssues(profile);

  async function sealCover() {
    const first = parseKeyHex(coverKey);
    const idx = parseIndices(coverIdx);
    if (!first || !idx) {
      setCoverError("第一把密钥要 64 位十六进制，词序要四个 0 到 4095 的整数");
      return;
    }
    const entries = [{ key: first, block: packIndices(idx) }];
    if (coverKey2.trim() || coverIdx2.trim()) {
      const second = parseKeyHex(coverKey2);
      const idx2 = parseIndices(coverIdx2);
      if (!second || !idx2) {
        setCoverError("第二把密钥或词序没写全");
        return;
      }
      entries.push({ key: second, block: packIndices(idx2) });
    }
    setCovering(true);
    setCoverError(null);
    try {
      const program = await compileBlocks(entries, 4);
      patch({ honeyProgram: programToStored(program) });
      setCoverKey("");
      setCoverKey2("");
    } catch (err) {
      setCoverError(err instanceof Error ? err.message : "封存失败");
    } finally {
      setCovering(false);
    }
  }

  function setInbounds(inbounds: Inbound[]) {
    patch({ inbounds });
  }

  async function mintIdentity() {
    setMinting(true);
    try {
      const ident = await createIdentity();
      patch({
        identity: {
          id: crypto.randomUUID(),
          name: profile.name || "本机",
          publicJwk: ident.publicJwk,
          privateJwk: ident.privateJwk,
          publicRawB64: b64(ident.publicRaw),
          fingerprint: ident.fingerprint,
        },
        seal: null,
      });
    } finally {
      setMinting(false);
    }
  }
  function setProcesses(processes: ProcessRule[]) {
    patch({ processes });
  }
  function setRules(rules: RouteRule[]) {
    patch({ rules });
  }

  return (
    <div className="flex flex-col gap-4">
      <section className="rounded-md border border-line bg-panel p-4">
        <h2 className="text-base font-medium">通用配置</h2>
        <p className="mt-2 text-sm text-mist">
          同一份档案给 Windows、Linux、Android 客户端。固定端口只监听；系统接管还会写出平台转发脚本。程序规则优先于域名和地址规则。
        </p>
        <div className="mt-4 flex flex-wrap gap-2">
          <Btn kind={profile.mode === "fixed-port" ? "solid" : "ghost"} onClick={() => patch({ mode: "fixed-port" })}>
            固定端口
          </Btn>
          <Btn kind={profile.mode === "system-forward" ? "solid" : "ghost"} onClick={() => patch({ mode: "system-forward" })}>
            系统接管
          </Btn>
          <Btn kind="ghost" onClick={() => patch(edgePreset())}>
            边缘预设
          </Btn>
          <Btn kind="ghost" onClick={() => patch(gatePreset())}>
            闸门预设
          </Btn>
        </div>
        <div className="mt-4 grid gap-3 sm:grid-cols-2">
          <Field label="名称">
            <input className={control} value={profile.name} onChange={(e) => patch({ name: e.target.value })} />
          </Field>
          <Field label="角色">
            <select className={control} value={profile.role} onChange={(e) => patch({ role: e.target.value as LexisProfile["role"] })}>
              {profile.role === "" ? <option value="">要指定</option> : null}
              <option value="edge">边缘客户端</option>
              <option value="gate">公网闸门</option>
            </select>
          </Field>
          <Field label="对端 主机:端口">
            <input className={control} value={profile.peerEndpoint} placeholder="203.0.113.8:18443" onChange={(e) => patch({ peerEndpoint: e.target.value })} />
          </Field>
          <Field label="程序未命中时">
            <select className={control} value={profile.processDefault} onChange={(e) => patch({ processDefault: e.target.value as LexisProfile["processDefault"] })}>
              {ACTIONS.map((action) => (
                <option key={action} value={action}>
                  {actionLabel(action)}
                </option>
              ))}
            </select>
          </Field>
        </div>
        <p className="mt-2 text-sm text-mist">常驻进程不接受缺省角色，要写成边缘或闸门。控制台里新建一份时仍默认是边缘。</p>
      </section>

      <section className="rounded-md border border-line bg-panel p-4">
        <h2 className="text-base font-medium">密钥与压缩</h2>
        <p className="mt-2 text-sm text-mist">
          会话密钥的 Argon2id 由常驻进程自己的参数决定，不听客户端把内存抬高。上限 16384 KiB。口令不对的问候在派生之前就被丢掉。长期私钥的封存在节点页，用另一档 65536 KiB、3 次迭代。系数不写进这份配置。
        </p>
        <p className="mt-2 text-sm text-mist">
          压缩不靠这份配置在对端对齐。明文第一个字节是类型：0 是原文，1 是 zstd 帧。等级决定窗口，窗口写在帧头里，对端解开以后自己读。比原文更大时这一帧会改回类型 0。
        </p>
        <p className="mt-2 text-sm text-mist">
          蜜文只挡对长期私钥和口令的暴力猜测，不挡已经拿到候选会话密钥的人。默认 bb-k-v4s 的允许词表全体会话共用，会话密钥只在频次相近的组里改词序，同组频次相同，打乱不改变出现概率。密钥仍参与尾部；重封对得上只说明这把密钥能生成这条尾，不能证明帧来自对端。错钥的蜜文视图仍是一句格式合法的词，检查不在那条路径上。回退到 bb-k-v4 时词模型公开、不随密钥改词序。旧的 rans-v3 才用词序重编码确认密钥：对的密钥几乎总能对上，错的大约 2%–3%。握手确认用临时密钥的共享秘密来算。两端的蜜文开关要写成一样，它会进入会话密钥。封面系数仍按旧的句式封存，线上帧不用这句式。长期私钥的封存在节点页。这一版和 2.0 及更早的对端对不上。
        </p>
        <div className="mt-4 grid gap-3 sm:grid-cols-3">
          <Field label="Argon2 内存 KiB">
            <select
              className={control}
              value={profile.kdf.memoryKiB}
              onChange={(e) => patch({ kdf: clampKdf({ ...profile.kdf, memoryKiB: Number(e.target.value) }) })}
            >
              {[1024, 4096, 8192, 16384].map((n) => (
                <option key={n} value={n}>
                  {n}
                </option>
              ))}
            </select>
          </Field>
          <Field label="迭代">
            <select
              className={control}
              value={profile.kdf.iterations}
              onChange={(e) => patch({ kdf: clampKdf({ ...profile.kdf, iterations: Number(e.target.value) }) })}
            >
              {[1, 2, 3, 4].map((n) => (
                <option key={n} value={n}>
                  {n}
                </option>
              ))}
            </select>
          </Field>
          <Field label="并行">
            <select
              className={control}
              value={profile.kdf.parallelism}
              onChange={(e) => patch({ kdf: clampKdf({ ...profile.kdf, parallelism: Number(e.target.value) }) })}
            >
              {[1, 2].map((n) => (
                <option key={n} value={n}>
                  {n}
                </option>
              ))}
            </select>
          </Field>
        </div>
        <div className="mt-4 flex flex-wrap gap-2">
          <Btn kind={profile.honey ? "solid" : "ghost"} onClick={() => patch({ honey: true })}>
            蜜文打开
          </Btn>
          <Btn kind={!profile.honey ? "solid" : "ghost"} onClick={() => patch({ honey: false })}>
            蜜文关闭
          </Btn>
          <Btn kind={profile.zstd.enabled ? "solid" : "ghost"} onClick={() => patch({ zstd: { ...profile.zstd, enabled: true } })}>
            发送时尝试 zstd
          </Btn>
          <Btn kind={!profile.zstd.enabled ? "solid" : "ghost"} onClick={() => patch({ zstd: { ...profile.zstd, enabled: false } })}>
            不压缩
          </Btn>
        </div>
        <div className="mt-4 grid gap-3">
          <p className="text-sm text-mist">
            封面系数按旧的四词句式封存。线上帧不再读这句式。密钥写成 64 位十六进制。封存之后只留系数。长期私钥的封存在节点页，任意口令都会解开一把合法的 X25519 私钥。
          </p>
          <Field label="密钥">
            <input className={control} value={coverKey} autoComplete="off" spellCheck={false} placeholder="64 位十六进制" aria-label="封面密钥" onChange={(e) => setCoverKey(e.target.value)} />
          </Field>
          <Field label="词序">
            <input className={control} value={coverIdx} autoComplete="off" aria-label="封面词序" onChange={(e) => setCoverIdx(e.target.value)} />
          </Field>
          <Field label="第二把密钥">
            <input className={control} value={coverKey2} autoComplete="off" spellCheck={false} placeholder="可留空" aria-label="第二把封面密钥" onChange={(e) => setCoverKey2(e.target.value)} />
          </Field>
          <Field label="第二组词序">
            <input className={control} value={coverIdx2} autoComplete="off" placeholder="可留空" aria-label="第二组封面词序" onChange={(e) => setCoverIdx2(e.target.value)} />
          </Field>
          <div className="flex flex-wrap gap-2">
            <Btn kind="ghost" disabled={covering || !coverKey.trim()} onClick={() => void sealCover()}>
              {covering ? "封存中" : "把封面写进同一条求值"}
            </Btn>
            {profile.honeyProgram ? (
              <Btn kind="ghost" onClick={() => patch({ honeyProgram: null })}>
                清掉封面系数
              </Btn>
            ) : null}
          </div>
          {profile.honeyProgram ? (
            <p className="text-sm text-mist">已封存 {profile.honeyProgram.coeffsB64.length} 个系数。密钥没有留下。导出配置会带上这组系数。</p>
          ) : (
            <p className="text-sm text-mist">还没有封面系数。不封存时，封面句子仍从这把密钥和当前时间窗的词表里取，只是词序不由你指定。数据帧不读这组系数。</p>
          )}
          {coverError ? <p className="text-sm text-ember">{coverError}</p> : null}
        </div>
        <div className="mt-4 max-w-xs">
          <Field label="zstd 等级">
            <select
              className={control}
              value={profile.zstd.level}
              onChange={(e) => patch({ zstd: { ...profile.zstd, level: Number(e.target.value) } })}
            >
              {[1, 3, 6, 9, 19].map((n) => (
                <option key={n} value={n}>
                  {n}
                </option>
              ))}
            </select>
          </Field>
        </div>
      </section>

      <section className="rounded-md border border-line bg-panel p-4">
        <h2 className="text-base font-medium">链路</h2>
        <p className="mt-2 text-sm text-mist">
          控制台和安装包都是 4.1.0，默认 bb-k-v4s。和 4.0 的 bb-k-v4 不互通，混用在问候阶段就失败关闭，关掉检查也没用。和 3.0.x 默认也不互通。握手是 X25519，问候用临时密钥和闸门长期公钥的共享秘密加密。默认把词编码绑进密钥确认，两端必须相同。TCP、TLS、WebSocket 只负责协议和头，用来过 CDN。路径默认 /lexis。CDN 若自己终结 TLS，源站可以听 WebSocket。
        </p>
        <p className="mt-2 text-sm text-mist">
          一条会话上可以开多路。打开写成 tcp 主机 端口、udp 主机 端口、relay 节点 再接后面的命令，或 expose 服务名。中继和出口都要逐个节点打开。暴露不能经中继绕过去。跳数到 4 就停。慢的那一路只堵住自己。SOCKS 的用户名和密码留空就是不认证，HTTP 代理共用这一对。
        </p>
        <div className="mt-4 flex flex-wrap gap-2">
          {(["tcp", "tls", "ws", "wss"] as OuterTransport[]).map((name) => (
            <Btn key={name} kind={profile.outer.transport === name ? "solid" : "ghost"} onClick={() => patch({ outer: { ...profile.outer, transport: name } })}>
              {name}
            </Btn>
          ))}
        </div>
        <div className="mt-4 grid gap-3 sm:grid-cols-2">
          <Field label="握手口令">
            <input
              className={control}
              autoComplete="off"
              spellCheck={false}
              value={profile.link.token}
              onChange={(e) => patch({ link: { ...profile.link, token: e.target.value } })}
            />
          </Field>
          <div>
            <p className="text-sm text-mist">口令</p>
            <div className="mt-2">
              <Btn kind="ghost" onClick={() => patch({ link: { ...profile.link, token: mintHandshakeToken() } })}>
                生成 128 bit 口令
              </Btn>
            </div>
          </div>
          <Field label="同时握手数">
            <input
              className={control}
              inputMode="numeric"
              value={profile.link.maxHandshakes}
              onChange={(e) => patch({ link: { ...profile.link, maxHandshakes: Number(e.target.value) } })}
            />
          </Field>
          <Field label="握手超时（秒）">
            <input
              className={control}
              inputMode="numeric"
              value={Math.round(profile.link.handshakeMs / 1000)}
              onChange={(e) => patch({ link: { ...profile.link, handshakeMs: Math.round(Number(e.target.value) * 1000) } })}
            />
          </Field>
          <Field label="拨号超时（秒）">
            <input
              className={control}
              inputMode="numeric"
              value={Math.round(profile.link.dialMs / 1000)}
              onChange={(e) => patch({ link: { ...profile.link, dialMs: Math.round(Number(e.target.value) * 1000) } })}
            />
          </Field>
          <Field label="WebSocket 路径">
            <input className={control} value={profile.outer.wsPath} onChange={(e) => patch({ outer: { ...profile.outer, wsPath: e.target.value } })} />
          </Field>
          <div>
            <p className="text-sm text-mist">校验证书</p>
            <div className="mt-2 flex flex-wrap gap-2">
              <Btn kind={profile.outer.tlsVerify ? "solid" : "ghost"} onClick={() => patch({ outer: { ...profile.outer, tlsVerify: true } })}>
                校验
              </Btn>
              <Btn kind={!profile.outer.tlsVerify ? "solid" : "ghost"} onClick={() => patch({ outer: { ...profile.outer, tlsVerify: false } })}>
                实验室自签
              </Btn>
            </div>
          </div>
          <Field label="SOCKS 用户名">
            <input className={control} autoComplete="off" value={profile.socksAuth.user} onChange={(e) => patch({ socksAuth: { ...profile.socksAuth, user: e.target.value } })} />
          </Field>
          <Field label="SOCKS 密码">
            <input className={control} type="password" autoComplete="off" value={profile.socksAuth.pass} onChange={(e) => patch({ socksAuth: { ...profile.socksAuth, pass: e.target.value } })} />
          </Field>
          <Field label="半开上限">
            <input
              className={control}
              inputMode="numeric"
              value={profile.link.maxHalfOpen}
              onChange={(e) => patch({ link: { ...profile.link, maxHalfOpen: Number(e.target.value) } })}
            />
          </Field>
          <Field label="每网段半开">
            <input
              className={control}
              inputMode="numeric"
              value={profile.link.maxHalfOpenPerIp}
              onChange={(e) => patch({ link: { ...profile.link, maxHalfOpenPerIp: Number(e.target.value) } })}
            />
          </Field>
          <Field label="网段长度 IPv4">
            <input
              className={control}
              inputMode="numeric"
              value={profile.link.halfOpenPrefixV4}
              onChange={(e) => patch({ link: { ...profile.link, halfOpenPrefixV4: Number(e.target.value) } })}
            />
          </Field>
          <Field label="网段长度 IPv6">
            <input
              className={control}
              inputMode="numeric"
              value={profile.link.halfOpenPrefixV6}
              onChange={(e) => patch({ link: { ...profile.link, halfOpenPrefixV6: Number(e.target.value) } })}
            />
          </Field>
          <Field label="静默连接上限">
            <input
              className={control}
              inputMode="numeric"
              value={profile.link.maxSilent}
              onChange={(e) => patch({ link: { ...profile.link, maxSilent: Number(e.target.value) } })}
            />
          </Field>
          <Field label="首字节超时（毫秒，0 关闭）">
            <input
              className={control}
              inputMode="numeric"
              value={profile.link.firstByteMs}
              onChange={(e) => patch({ link: { ...profile.link, firstByteMs: Number(e.target.value) } })}
            />
          </Field>
          <Field label="UDP 空闲（秒）">
            <input
              className={control}
              inputMode="numeric"
              value={Math.round(profile.link.udpIdleMs / 1000)}
              onChange={(e) => patch({ link: { ...profile.link, udpIdleMs: Math.round(Number(e.target.value) * 1000) } })}
            />
          </Field>
          <Field label="UDP 关联空闲（秒）">
            <input
              className={control}
              inputMode="numeric"
              value={Math.round(profile.link.udpAssociateIdleMs / 1000)}
              onChange={(e) => patch({ link: { ...profile.link, udpAssociateIdleMs: Math.round(Number(e.target.value) * 1000) } })}
            />
          </Field>
          <Field label="UDP 路数">
            <input
              className={control}
              inputMode="numeric"
              value={profile.link.udpMax}
              onChange={(e) => patch({ link: { ...profile.link, udpMax: Number(e.target.value) } })}
            />
          </Field>
        </div>
        <p className="mt-2 text-sm text-mist">
          UDP 关联空闲只作用于 SOCKS UDP ASSOCIATE 的控制连接：合法 UDP 活动续命，无活动按本值回收。它不改变其它连接的空闲超时。握手口令在 Argon2 之前参与问候。估约 {estimateTokenBits(profile.link.token.trim())} bit，需要至少 128。两端写成同一个。手写短口令会被常驻进程拒绝。半开按网段计，IPv4 默认 /24，IPv6 默认 /64，写成 32 和 128 就回到按单个地址。校验失败会马上让出名额，连接仍等到握手超时再关，外面看不出差别。一个字节都没有的连接，到首字节超时也会让出名额，晚到的字节不再处理。静默连接超过上限才会马上关掉，这是外面能看出来的。半开中的连接也占连接上限，所以连接上限要大于半开上限。新配置默认 1024 和 512。旧配置里写死 128 的，要自己改大。校验关掉时，外层 TLS 认不出对端，正式部署请换自己的证书。
        </p>
        <div className="mt-4 rounded-sm bg-panel-2 p-3">
          <p className="text-sm text-mist">本机身份</p>
          <p className="mt-2 break-all font-mono text-xs text-fg">{profile.identity?.fingerprint || "还没有"}</p>
          <div className="mt-3 flex flex-wrap gap-2">
            <Btn kind="ghost" disabled={minting} onClick={() => void mintIdentity()}>
              {minting ? "生成中" : profile.identity ? "换一把常驻身份" : "生成本机身份"}
            </Btn>
            {profile.identity ? (
              <Btn kind="ember" onClick={() => patch({ identity: null })}>
                清掉身份
              </Btn>
            ) : null}
          </div>
          <p className="mt-2 text-sm text-mist">导出配置会带上这把私钥。只放到你自己的常驻进程里。对端只需要公钥。</p>
        </div>
        <div className="mt-4">
          <div className="flex items-center justify-between gap-3">
            <h3 className="text-sm font-medium">加入的节点</h3>
            <Btn
              kind="ghost"
              onClick={() =>
                patch({
                  peers: [
                    ...profile.peers,
                    {
                      id: rid("peer"),
                      name: "节点",
                      endpoint: profile.peerEndpoint,
                      transport: profile.outer.transport,
                      publicRawB64: "",
                      wsPath: profile.outer.wsPath,
                      wsHost: "",
                      relay: false,
                      exit: false,
                      targets: [],
                    },
                  ],
                })
              }
            >
              添加节点
            </Btn>
          </div>
          <p className="mt-2 text-sm text-mist">默认不借本机中继。要借，就在那个节点上打开，并可以限定目标。地址写成 主机:端口。WebSocket 主机名留给 CDN，空着就用地址里的主机。</p>
          <div className="mt-3 flex flex-col gap-3">
            {profile.peers.map((peer) => (
              <PeerEditor
                key={peer.id}
                peer={peer}
                onChange={(next) => patch({ peers: profile.peers.map((item) => (item.id === peer.id ? next : item)) })}
                onRemove={() => patch({ peers: profile.peers.filter((item) => item.id !== peer.id) })}
              />
            ))}
          </div>
        </div>
        <p className="mt-4 text-sm text-mist">
          闸门拨号前会解析域名。回环、内网、链路本地、运营商级 NAT 和文档地址默认拒绝。白名单写成主机、主机:端口或 IPv4 网段。这道拦截不作用于本机 SOCKS 的直连和绕行。公网端口不单独封禁。
        </p>
        <div className="mt-4 grid gap-3 sm:grid-cols-2">
          <Field label="空闲超时（秒）">
            <input
              className={control}
              inputMode="numeric"
              value={Math.round(profile.link.idleMs / 1000)}
              onChange={(e) => patch({ link: { ...profile.link, idleMs: Math.round(Number(e.target.value) * 1000) } })}
            />
          </Field>
          <Field label="连接上限">
            <input
              className={control}
              inputMode="numeric"
              value={profile.link.maxConns}
              onChange={(e) => patch({ link: { ...profile.link, maxConns: Number(e.target.value) } })}
            />
          </Field>
          <div>
            <p className="text-sm text-mist">内网拦截</p>
            <div className="mt-2 flex flex-wrap gap-2">
              <Btn kind={profile.egress.blockPrivate ? "solid" : "ghost"} onClick={() => patch({ egress: { ...profile.egress, blockPrivate: true } })}>
                拦截
              </Btn>
              <Btn kind={!profile.egress.blockPrivate ? "solid" : "ghost"} onClick={() => patch({ egress: { ...profile.egress, blockPrivate: false } })}>
                放行
              </Btn>
            </div>
          </div>
        </div>
        <div className="mt-4">
          <Field label="出站白名单，一行一条">
            <AllowList allow={profile.egress.allow} onChange={(allow) => patch({ egress: { ...profile.egress, allow } })} />
          </Field>
        </div>
        <div className="mt-4 flex flex-wrap gap-2">
          <Btn kind={profile.link.allowLan ? "solid" : "ghost"} onClick={() => patch({ link: { ...profile.link, allowLan: true } })}>
            允许局域网监听
          </Btn>
          <Btn kind={!profile.link.allowLan ? "solid" : "ghost"} onClick={() => patch({ link: { ...profile.link, allowLan: false } })}>
            只监听回环
          </Btn>
        </div>
        <p className="mt-2 text-sm text-mist">
          {profile.link.allowLan
            ? "SOCKS 和固定转发会按填写的地址监听，可能暴露到局域网。"
            : "SOCKS 和固定转发强制绑在回环。隧道入口仍按填写的地址监听，方便以后做端口映射。"}
        </p>
        <div className="mt-4 max-w-md">
          <Field label="状态口令">
            <input
              className={control}
              value={profile.statusToken}
              autoComplete="off"
              placeholder="回环上可留空"
              onChange={(e) => patch({ statusToken: e.target.value })}
            />
          </Field>
        </div>
        <p className="mt-2 text-sm text-mist">状态页离开回环时，指标和页面要带这句口令。健康检查不带。没有口令又没有允许局域网时，状态页改绑回环。</p>
      </section>

      <section className="rounded-md border border-line bg-panel p-4">
        <h2 className="text-base font-medium">帧</h2>
        <p className="mt-2 text-sm text-mist">
          膨胀预算是线上字节相对压缩后正文的倍数，默认 5，范围 1 到 16。大约 256 字节以下的单发帧仍会超过这个倍数，常驻进程把同一时刻的小记录并进一帧。合并阈值默认 1024 字节，只给常驻进程；浏览器里每次封装单独成帧。
        </p>
        <p className="mt-2 text-sm text-mist">
          小帧策略默认「压膨胀」：预算内才填充，短帧常常不填。改成「蜜文填充」后，短帧也在 0 到 255 字节里取填充，填充占比更接近一把错误密钥解出来的样子，短帧会胀得更大。这是发送端的选择，两端可以不一样。
        </p>
        <div className="mt-4 grid gap-3 sm:grid-cols-2">
          <Field label="线上膨胀预算">
            <select
              className={control}
              value={profile.frame.maxExpansion}
              onChange={(e) => patch({ frame: { ...profile.frame, maxExpansion: Number(e.target.value) } })}
            >
              {[1, 2, 3, 4, 5, 8, 12, 16].map((n) => (
                <option key={n} value={n}>
                  {n}×
                </option>
              ))}
            </select>
          </Field>
          <Field label="合并阈值（字节）">
            <input
              className={control}
              inputMode="numeric"
              value={profile.frame.coalesceTarget}
              onChange={(e) => patch({ frame: { ...profile.frame, coalesceTarget: Number(e.target.value) } })}
            />
          </Field>
        </div>
        <div className="mt-4 flex flex-wrap gap-2">
          <Btn
            kind={profile.frame.smallFramePolicy === "expansion" ? "solid" : "ghost"}
            onClick={() => patch({ frame: { ...profile.frame, smallFramePolicy: "expansion" } })}
          >
            小帧压膨胀
          </Btn>
          <Btn
            kind={profile.frame.smallFramePolicy === "honey" ? "solid" : "ghost"}
            onClick={() => patch({ frame: { ...profile.frame, smallFramePolicy: "honey" } })}
          >
            小帧蜜文填充
          </Btn>
        </div>
        <div className="mt-4 grid gap-3 sm:grid-cols-2">
          <Field label="词编码">
            <select
              className={control}
              aria-label="词编码"
              value={(commonDtes as readonly string[]).includes(profile.frame.dte) ? profile.frame.dte : "experimental"}
              onChange={(e) => {
                const dte = e.target.value;
                if (dte === "experimental") return;
                setA1Ask(false);
                setFrame({ dte });
              }}
            >
              <option value="bb-k-v4s">bb-k-v4s · 允许词表，组内打乱（默认）</option>
              <option value="bb-k-v4">bb-k-v4 · 4.0 方案 K，显式回退</option>
              <option value="rans-v3">rans-v3 · 3.0 数据帧</option>
              {dteExperimental ? (
                <option value="experimental">当前是实验编码 {profile.frame.dte}</option>
              ) : null}
            </select>
          </Field>
          <Field label="握手检查">
            <select
              className={control}
              aria-label="握手检查"
              value={profile.frame.dteCheck ? "on" : "off"}
              onChange={(e) => setFrame({ dteCheck: e.target.value === "on" })}
            >
              <option value="on">开 · 词编码写入密钥确认</option>
              <option value="off">关 · 只用于旧版或诊断</option>
            </select>
          </Field>
        </div>
        <p className="mt-2 text-sm text-mist">
          默认 bb-k-v4s：方案 K 的带钥尾，词表是全体会话共用的允许词表，会话密钥只在频次相近的组内打乱，同组频次相同。和 bb-k-v4 不互通，混用在问候阶段失败关闭，关掉检查也没用。要和 4.0 互通，两端都选 bb-k-v4。和 3.0.x 互通要同时选 rans-v3 并关闭检查，只改词编码不够。两端都是 4.1 时仍建议开着检查。检查开着、且不是 bb-k-v4s 混用时，对不上则内网端确认失败后关连接，闸门只回一次应答，放出半开名额后静默到超时，不会立刻回错。bb-k-v4s 和别的词编码混用时，闸门认不出问候，一个字节都不回。线格式不变。改词编码或检查会使浏览器里的旧会话作废。浏览器里以前存过的方案 K 会在这次打开时换成 bb-k-v4s。
        </p>
        <div className="mt-3 flex flex-wrap gap-2">
          <Btn kind="ghost" onClick={() => { setA1Ask(false); setFrame({ dte: "bb-k-v4s", dteCheck: true }); }}>
            回到默认
          </Btn>
          <Btn kind="ghost" onClick={() => { setA1Ask(false); setFrame({ dte: "bb-k-v4", dteCheck: true }); }}>
            填成 4.0 回退
          </Btn>
          <Btn kind="ghost" onClick={() => { setA1Ask(false); setFrame({ dte: "rans-v3", dteCheck: false }); }}>
            填成 3.0 兼容
          </Btn>
        </div>
        <details className="mt-4">
          <summary className="min-h-11 cursor-pointer text-sm">实验词编码（不建议）</summary>
          <div className="mt-2 grid gap-3">
            <Field label="实验编码">
              <select
                className={control}
                aria-label="实验词编码"
                value={dteExperimental ? profile.frame.dte : ""}
                onChange={(e) => {
                  const dte = e.target.value;
                  if (!dte) return;
                  if (dte === "bb-c8-v4") {
                    setA1Ask(true);
                    return;
                  }
                  setA1Ask(false);
                  setFrame({ dte });
                }}
              >
                <option value="">未选实验编码</option>
                <option value="bb-v4">bb-v4 · A0，尾词可改</option>
                <option value="bb-c8-v4">bb-c8-v4 · A1，不建议</option>
                <option value="bb-ou-v4">bb-ou-v4 · A2，实验</option>
                <option value="bb-ouc8-v4">bb-ouc8-v4 · A3，实验</option>
                <option value="bb-ouc8r-v4">bb-ouc8r-v4 · A3r，实验</option>
                <option value="dfa-v4">dfa-v4 · A4，实验</option>
              </select>
            </Field>
            {a1Ask ? (
              <div className="flex flex-col gap-2">
                <p className="text-sm text-ember">
                  A1 有残余可塑性：本轮单词篡改 19/6000 仍被接受，明文不变；K 是 0/6000。测试结果不是安全性证明。不建议使用。
                </p>
                <div className="flex flex-wrap gap-2">
                  <Btn kind="ember" onClick={() => { setA1Ask(false); setFrame({ dte: "bb-c8-v4" }); }}>
                    仍要选用 A1
                  </Btn>
                  <Btn kind="ghost" onClick={() => setA1Ask(false)}>
                    取消
                  </Btn>
                </div>
              </div>
            ) : null}
            {profile.frame.dte === "bb-c8-v4" ? (
              <p className="text-sm text-ember">当前是 A1。残余可塑性没有修掉，不要当成和 K 一样防篡改。</p>
            ) : null}
          </div>
        </details>
      </section>

      <section className="rounded-md border border-line bg-panel p-4">
        <div className="flex items-center justify-between gap-3">
          <h2 className="text-base font-medium">入站</h2>
          <Btn
            kind="ghost"
            onClick={() =>
              setInbounds([
                ...profile.inbounds,
                { id: rid("in"), tag: "新入站", protocol: "socks", listen: "127.0.0.1", port: 1080, targetHost: "", targetPort: 0 },
              ])
            }
          >
            添加入站
          </Btn>
        </div>
        <div className="mt-4 flex flex-col gap-3">
          {profile.inbounds.map((inbound) => (
            <div key={inbound.id} className="grid gap-2 rounded-sm bg-panel-2 p-3 sm:grid-cols-2">
              <input className={control} aria-label="入站名称" value={inbound.tag} onChange={(e) => setInbounds(profile.inbounds.map((item) => (item.id === inbound.id ? { ...item, tag: e.target.value } : item)))} />
              <select className={control} aria-label="入站协议" value={inbound.protocol} onChange={(e) => setInbounds(profile.inbounds.map((item) => (item.id === inbound.id ? { ...item, protocol: e.target.value as Inbound["protocol"] } : item)))}>
                <option value="socks">SOCKS</option>
                <option value="http">HTTP 代理</option>
                <option value="tcp">固定转发</option>
                <option value="tunnel">隧道入口</option>
              </select>
              <input className={control} aria-label="监听地址" value={inbound.listen} onChange={(e) => setInbounds(profile.inbounds.map((item) => (item.id === inbound.id ? { ...item, listen: e.target.value } : item)))} />
              <input className={control} aria-label="监听端口" inputMode="numeric" value={inbound.port} onChange={(e) => setInbounds(profile.inbounds.map((item) => (item.id === inbound.id ? { ...item, port: Number(e.target.value) } : item)))} />
              {inbound.protocol === "tcp" ? (
                <>
                  <input className={control} aria-label="目标主机" value={inbound.targetHost} placeholder="目标主机" onChange={(e) => setInbounds(profile.inbounds.map((item) => (item.id === inbound.id ? { ...item, targetHost: e.target.value } : item)))} />
                  <input className={control} aria-label="目标端口" inputMode="numeric" value={inbound.targetPort} onChange={(e) => setInbounds(profile.inbounds.map((item) => (item.id === inbound.id ? { ...item, targetPort: Number(e.target.value) } : item)))} />
                </>
              ) : null}
              <Btn kind="ember" onClick={() => setInbounds(profile.inbounds.filter((item) => item.id !== inbound.id))}>
                删除
              </Btn>
            </div>
          ))}
        </div>
      </section>

      <section className="rounded-md border border-line bg-panel p-4">
        <div className="flex items-center justify-between gap-3">
          <h2 className="text-base font-medium">暴露给已经连上的节点</h2>
          <Btn
            kind="ghost"
            onClick={() =>
              patch({
                exposes: [...profile.exposes, { id: rid("expose"), name: "ssh", host: "127.0.0.1", port: 22, allow: [] }],
              })
            }
          >
            添加服务
          </Btn>
        </div>
        <p className="mt-2 text-sm text-mist">NAT 后面的机器主动连出去之后，对端可以按服务名过来。允许名单写节点的名字或编号，空着谁也不让进。这里拨的是你自己填的本机地址，不走公网出站拦截。</p>
        <div className="mt-4 flex flex-col gap-3">
          {profile.exposes.map((door) => (
            <div key={door.id} className="grid gap-2 rounded-sm bg-panel-2 p-3 sm:grid-cols-2">
              <input className={control} aria-label="服务名" value={door.name} onChange={(e) => patch({ exposes: profile.exposes.map((item) => (item.id === door.id ? { ...item, name: e.target.value } : item)) })} />
              <input className={control} aria-label="本机主机" value={door.host} onChange={(e) => patch({ exposes: profile.exposes.map((item) => (item.id === door.id ? { ...item, host: e.target.value } : item)) })} />
              <input className={control} aria-label="本机端口" inputMode="numeric" value={door.port} onChange={(e) => patch({ exposes: profile.exposes.map((item) => (item.id === door.id ? { ...item, port: Number(e.target.value) } : item)) })} />
              <input
                className={control}
                aria-label="允许的节点"
                placeholder="节点名，逗号分开"
                value={door.allow.join(", ")}
                onChange={(e) =>
                  patch({
                    exposes: profile.exposes.map((item) =>
                      item.id === door.id ? { ...item, allow: e.target.value.split(",").map((part) => part.trim()).filter(Boolean) } : item,
                    ),
                  })
                }
              />
              <Btn kind="ember" onClick={() => patch({ exposes: profile.exposes.filter((item) => item.id !== door.id) })}>
                删除
              </Btn>
            </div>
          ))}
        </div>
      </section>

      <section className="rounded-md border border-line bg-panel p-4">
        <div className="flex items-center justify-between gap-3">
          <h2 className="text-base font-medium">反向入口</h2>
          <Btn
            kind="ghost"
            onClick={() =>
              patch({
                reverses: [...profile.reverses, { id: rid("rev"), listen: "127.0.0.1", port: 2222, peer: "", service: "ssh" } satisfies ReverseDoor],
              })
            }
          >
            添加入口
          </Btn>
        </div>
        <p className="mt-2 text-sm text-mist">公网这一侧听一个端口，从那个节点已经连进来的会话里打开同名服务。没有允许局域网时，写成 0.0.0.0 也会改绑回环，并且和别的入站共用连接数上限。会话不在时会说没有来自该节点的会话。</p>
        <div className="mt-4 flex flex-col gap-3">
          {profile.reverses.map((door) => (
            <div key={door.id} className="grid gap-2 rounded-sm bg-panel-2 p-3 sm:grid-cols-2">
              <input className={control} aria-label="反向监听地址" value={door.listen} onChange={(e) => patch({ reverses: profile.reverses.map((item) => (item.id === door.id ? { ...item, listen: e.target.value } : item)) })} />
              <input className={control} aria-label="反向端口" inputMode="numeric" value={door.port} onChange={(e) => patch({ reverses: profile.reverses.map((item) => (item.id === door.id ? { ...item, port: Number(e.target.value) } : item)) })} />
              <input className={control} aria-label="节点" placeholder="节点名或编号" value={door.peer} onChange={(e) => patch({ reverses: profile.reverses.map((item) => (item.id === door.id ? { ...item, peer: e.target.value } : item)) })} />
              <input className={control} aria-label="服务名" value={door.service} onChange={(e) => patch({ reverses: profile.reverses.map((item) => (item.id === door.id ? { ...item, service: e.target.value } : item)) })} />
              <Btn kind="ember" onClick={() => patch({ reverses: profile.reverses.filter((item) => item.id !== door.id) })}>
                删除
              </Btn>
            </div>
          ))}
        </div>
      </section>

      <section className="rounded-md border border-line bg-panel p-4">
        <h2 className="text-base font-medium">系统接管</h2>
        <p className="mt-2 text-sm text-mist">
          {profile.mode === "system-forward" ? "客户端启动时会按当前系统写出并尝试执行。" : "现在走固定端口。这些参数会跟着配置走，切到系统接管才生效。"}
        </p>
        <div className="mt-4 grid gap-3 lg:grid-cols-3">
          <Platform title="Linux" body="redirect、tproxy 或虚拟网卡。需要 root 才会改规则。redirect 是混合方式：TCP 用 REDIRECT，UDP 走 TPROXY，UDP 不再直连。redirect 和 tproxy 都要 TPROXY（nft 或 iptables）和透明 UDP；缺了就拒绝系统接管、不装规则，可改用虚拟网卡，两者都不行则这台机器无法系统接管。三种方法都只把 IPv4 接进隧道，IPv6 不经隧道。DNS：系统接管时，启动先在 127.0.0.1 和 ::1 起本机 DNS 服务（UDP 和 TCP），再把本机所有 TCP/UDP 53（IPv4 和 IPv6，含写死的 1.1.1.1、8.8.8.8 和路由器、内网等私网 DNS）劫持过去，两个选项都一样。「本机 DNS 接管（假地址）」A 记录回假地址；「不回假地址，按规则转发」时本机服务把全部查询按规则转发给上游（默认 1.1.1.1，经隧道），不直连原来的解析器。服务、劫持或任何一条规则没装成就整体拒绝系统接管、撤掉已装的规则，状态页显示拒绝接管。默认「公网 IPv6 不可达」：公网 IPv6 在 redirect、tproxy、虚拟网卡下都设为不可达，应用会回落 IPv4；回环、链路本地、ULA、组播、对端的 IPv6 地址和本程序带旁路标记的连接仍走原来的路由。选「不处理 IPv6」则 IPv6 直接走本机网络，不经隧道，并撤掉本程序自己加过的 IPv6 规则。没有在这台机器上证明规则已经接住流量。">
            <select className={control} value={profile.linux.method} onChange={(e) => patch({ linux: { ...profile.linux, method: e.target.value as LexisProfile["linux"]["method"] } })}>
              <option value="redirect">redirect</option>
              <option value="tproxy">tproxy</option>
              <option value="tun">虚拟网卡</option>
            </select>
            <select className={control} aria-label="公网 IPv6" value={profile.linux.ipv6 === "off" ? "off" : "block"} onChange={(e) => patch({ linux: { ...profile.linux, ipv6: e.target.value === "off" ? "off" : "block" } })}>
              <option value="block">公网 IPv6 不可达</option>
              <option value="off">不处理 IPv6（直连，不经隧道）</option>
            </select>
            <input className={control} aria-label="fwmark" inputMode="numeric" value={profile.linux.mark} onChange={(e) => patch({ linux: { ...profile.linux, mark: Number(e.target.value) } })} />
            <select className={control} aria-label="DNS" value={profile.linux.dnsRedirect ? "on" : "off"} onChange={(e) => patch({ linux: { ...profile.linux, dnsRedirect: e.target.value === "on" } })}>
              <option value="on">本机 DNS 接管（假地址）</option>
              <option value="off">不回假地址，本机服务按规则转发</option>
            </select>
            <input className={control} aria-label="本机 DNS 端口（0 为自动）" inputMode="numeric" value={profile.linux.dnsPort} onChange={(e) => patch({ linux: { ...profile.linux, dnsPort: Number(e.target.value) } })} />
          </Platform>
          <Platform title="Windows" body="portproxy 只绑回环。WinDivert 只有源码，驱动不在包里，选了也不会改系统流量。">
            <select className={control} value={profile.windows.method} onChange={(e) => patch({ windows: { ...profile.windows, method: e.target.value as LexisProfile["windows"]["method"] } })}>
              <option value="portproxy">portproxy</option>
              <option value="windivert">WinDivert</option>
            </select>
            <input className={control} aria-label="网关" value={profile.windows.gateway} onChange={(e) => patch({ windows: { ...profile.windows, gateway: e.target.value } })} />
          </Platform>
          <Platform title="Android" body="写出会话和本机包通道。VpnService 只有源码，Termux 不能弹出系统 VPN。">
            <input className={control} aria-label="VPN 地址" value={profile.android.address} onChange={(e) => patch({ android: { ...profile.android, address: e.target.value } })} />
            <input className={control} aria-label="DNS" value={profile.android.dns} onChange={(e) => patch({ android: { ...profile.android, dns: e.target.value } })} />
          </Platform>
        </div>
      </section>

      <section className="rounded-md border border-line bg-panel p-4">
        <h2 className="text-base font-medium">虚拟网卡的用户态 TCP</h2>
        <p className="mt-2 text-sm text-mist">
          只在虚拟网卡的用户态 TCP 上生效，不会改系统网卡的 MTU。没有在这台机器上证明已经接住流量。Windows 的 WinDivert 和 Android 的系统 VPN 仍只是源码。Android 如果没写 tun.mtu，运行时可以退回 android.mtu；这里写出的 tun.mtu 优先。
        </p>
        <p className="mt-2 text-sm text-mist">
          MTU 默认 1500，范围 576–65535，是宣告段长的基准（默认 MTU−40，1500 时为 1460）。宣告段长留空或 0 存成空，按这个基准；填写则用 88–65495 覆盖。实际发送取本地值和对端通告的较小者，对端没写时按 536。不要默认填 1200。
        </p>
        <p className="mt-2 text-sm text-mist">
          单流乱序字节默认 65535（0–65535），0 不缓存乱序正文。单流乱序段数默认 64（0–4096），0 禁用乱序正文缓存，超限先丢离缺口最远的段。这和读包队列的 64 个包不是同一个数。整机乱序字节默认 8388608（8 MiB），范围 0–1073741824；0 不保留乱序数据。每个进程各有一份预算，不是整个系统共用一个上限。接收窗口固定 65535，不做窗口缩放。未确认的段按超时重发，三个重复确认会提前重发最早的一段。
        </p>
        <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          <Field label="MTU">
            <input className={control} aria-label="虚拟网卡 MTU" inputMode="numeric" {...tunField("mtu", 576, 65535, 1500)} />
          </Field>
          <Field label="宣告段长（空则按 MTU）">
            <input className={control} aria-label="宣告段长" inputMode="numeric" placeholder="空" {...tunField("mss", 88, 65495, 0, true)} />
          </Field>
          <Field label="单流乱序字节">
            <input className={control} aria-label="单流乱序字节" inputMode="numeric" {...tunField("oooMaxBytes", 0, 65535, 65535)} />
          </Field>
          <Field label="单流乱序段数">
            <input className={control} aria-label="单流乱序段数" inputMode="numeric" {...tunField("oooMaxSegs", 0, 4096, 64)} />
          </Field>
          <Field label="整机乱序字节（默认 8 MiB）">
            <input className={control} aria-label="整机乱序字节" inputMode="numeric" {...tunField("oooTotalBytes", 0, 1073741824, 8388608)} />
          </Field>
        </div>
      </section>

      <section className="rounded-md border border-line bg-panel p-4">
        <div className="flex items-center justify-between gap-3">
          <h2 className="text-base font-medium">按程序接入或绕行</h2>
          <Btn kind="ghost" onClick={() => setProcesses([...profile.processes, { id: rid("proc"), name: "", action: "proxy" }])}>
            添加程序
          </Btn>
        </div>
        <div className="mt-4 flex flex-col gap-2">
          {profile.processes.map((item) => (
            <div key={item.id} className="grid gap-2 sm:grid-cols-[1fr_8rem_auto]">
              <input className={control} aria-label="程序名" placeholder="chrome 或 ssh.exe" value={item.name} onChange={(e) => setProcesses(profile.processes.map((row) => (row.id === item.id ? { ...row, name: e.target.value } : row)))} />
              <select className={control} aria-label="程序动作" value={item.action} onChange={(e) => setProcesses(profile.processes.map((row) => (row.id === item.id ? { ...row, action: e.target.value as ProcessRule["action"] } : row)))}>
                {ACTIONS.map((action) => (
                  <option key={action} value={action}>
                    {actionLabel(action)}
                  </option>
                ))}
              </select>
              <Btn kind="ghost" onClick={() => setProcesses(profile.processes.filter((row) => row.id !== item.id))}>
                删除
              </Btn>
            </div>
          ))}
        </div>
      </section>

      <section className="rounded-md border border-line bg-panel p-4">
        <div className="flex items-center justify-between gap-3">
          <h2 className="text-base font-medium">路由</h2>
          <Btn kind="ghost" onClick={() => setRules([...profile.rules, { id: rid("rule"), type: "DOMAIN-SUFFIX", value: "", action: "proxy" }])}>
            添加规则
          </Btn>
        </div>
        <div className="mt-4 flex flex-col gap-2">
          {profile.rules.map((rule) => (
            <div key={rule.id} className="grid gap-2 sm:grid-cols-[10rem_1fr_8rem_auto]">
              <select className={control} aria-label="规则类型" value={rule.type} onChange={(e) => setRules(profile.rules.map((row) => (row.id === rule.id ? { ...row, type: e.target.value as RouteRule["type"] } : row)))}>
                {RULE_TYPES.map((type) => (
                  <option key={type} value={type}>
                    {type}
                  </option>
                ))}
              </select>
              <input className={control} aria-label="规则值" value={rule.value} placeholder={rule.type === "MATCH" ? "留空" : "值"} onChange={(e) => setRules(profile.rules.map((row) => (row.id === rule.id ? { ...row, value: e.target.value } : row)))} />
              <select className={control} aria-label="规则动作" value={rule.action} onChange={(e) => setRules(profile.rules.map((row) => (row.id === rule.id ? { ...row, action: e.target.value as RouteRule["action"] } : row)))}>
                {ACTIONS.map((action) => (
                  <option key={action} value={action}>
                    {actionLabel(action)}
                  </option>
                ))}
              </select>
              <Btn kind="ghost" onClick={() => setRules(profile.rules.filter((row) => row.id !== rule.id))}>
                删除
              </Btn>
            </div>
          ))}
        </div>
        <div className="mt-4 grid gap-3">
          <Field label="导入格式">
            <select className={control} value={importKind} onChange={(e) => setImportKind(e.target.value as "clash" | "sing-box")}>
              <option value="clash">Clash 规则</option>
              <option value="sing-box">sing-box route.rules</option>
            </select>
          </Field>
          <textarea className="min-h-32 w-full rounded-sm border border-line bg-ink px-3 py-3 font-mono text-sm text-fg" value={importText} onChange={(e) => setImportText(e.target.value)} />
          <Btn
            kind="ghost"
            onClick={() => {
              try {
                const rules = importKind === "clash" ? importClashRules(importText) : importSingBox(importText);
                setRules(rules);
                setImportError(null);
              } catch (err) {
                setImportError(err instanceof Error ? err.message : "导入失败");
              }
            }}
          >
            用这段替换路由
          </Btn>
          {importError ? <p className="text-sm text-ember">{importError}</p> : null}
        </div>
      </section>

      <section className="rounded-md border border-line bg-panel p-4">
        <h2 className="text-base font-medium">geosite / geoip</h2>
        <p className="mt-2 text-sm text-mist">
          内置 private、cn、google、telegram，以及 private/cn 的一小段地址。cn 地址只放了常见公共 DNS。完整库填文本 URL，客户端启动时拉。带类别写 `类别 域名` 或 `geoip:cn 1.2.3.0/24`；单独一行域名或地址段归到 remote。额外行写在下面，立刻参与本页试匹配。
        </p>
        <div className="mt-4 grid gap-3">
          <Field label="geosite 文本 URL">
            <input className={control} value={profile.geositeUrl} onChange={(e) => patch({ geositeUrl: e.target.value })} />
          </Field>
          <Field label="geoip 文本 URL">
            <input className={control} value={profile.geoipUrl} onChange={(e) => patch({ geoipUrl: e.target.value })} />
          </Field>
          <Field label="额外条目">
            <textarea className="min-h-24 w-full rounded-sm border border-line bg-ink px-3 py-3 font-mono text-sm text-fg" value={profile.extras} onChange={(e) => patch({ extras: e.target.value })} />
          </Field>
        </div>
      </section>

      <section className="rounded-md border border-line bg-panel p-4">
        <h2 className="text-base font-medium">试一条</h2>
        <div className="mt-4 grid gap-3 sm:grid-cols-3">
          <Field label="域名">
            <input className={control} value={host} onChange={(e) => setHost(e.target.value)} />
          </Field>
          <Field label="地址">
            <input className={control} value={ip} onChange={(e) => setIp(e.target.value)} />
          </Field>
          <Field label="程序">
            <input className={control} value={proc} onChange={(e) => setProc(e.target.value)} />
          </Field>
        </div>
        <p className="mt-3 text-sm">
          {hit.reason}
        </p>
      </section>

      {issues.length > 0 ? (
        <ul className="text-sm text-ember">
          {issues.map((issue) => (
            <li key={issue}>{issue}</li>
          ))}
        </ul>
      ) : null}

      <div className="flex flex-wrap gap-2">
        <Btn onClick={() => downloadJson("lexis.config.json", exportedConfig(profile))}>导出配置</Btn>
        {profile.seal ? (
          <Btn kind="ghost" onClick={() => downloadJson("lexis.seal.json", sealFileOf(profile.seal!))}>
            导出封存
          </Btn>
        ) : null}
      </div>
      <p className="text-sm text-mist">
        没有封存时，配置里带着本机私钥。封存之后，导出的配置去掉标量，系数在另一个文件 lexis.seal.json。两个文件不要合成一个：公钥写在对端名单里，和系数放在一起就能离线试口令。放到常驻目录后，权限应收成仅本人可读。口令用环境变量 LEXIS_PASSPHRASE，或同目录的 lexis.passphrase。常驻进程不会拿解开的公钥去对配置里的公钥。
      </p>
    </div>
  );
}

function PeerEditor({ peer, onChange, onRemove }: { peer: NetPeer; onChange: (peer: NetPeer) => void; onRemove: () => void }) {
  const [targetsText, setTargetsText] = useState((peer.targets || []).join("\n"));
  const [targetsFocus, setTargetsFocus] = useState(false);
  useEffect(() => {
    if (!targetsFocus) setTargetsText((peer.targets || []).join("\n"));
  }, [peer.targets, targetsFocus]);
  return (
    <div className="grid gap-2 rounded-sm bg-panel-2 p-3">
      <div className="grid gap-2 sm:grid-cols-2">
        <input className={control} aria-label="节点名称" value={peer.name} onChange={(e) => onChange({ ...peer, name: e.target.value })} />
        <input className={control} aria-label="节点地址" placeholder="主机:端口" value={peer.endpoint} onChange={(e) => onChange({ ...peer, endpoint: e.target.value })} />
        <select className={control} aria-label="外层协议" value={peer.transport} onChange={(e) => onChange({ ...peer, transport: e.target.value as OuterTransport })}>
          <option value="tcp">tcp</option>
          <option value="tls">tls</option>
          <option value="ws">ws</option>
          <option value="wss">wss</option>
        </select>
        <input className={control} aria-label="WebSocket 主机" placeholder="CDN 主机名，可空" value={peer.wsHost} onChange={(e) => onChange({ ...peer, wsHost: e.target.value })} />
      </div>
      <textarea
        className="min-h-20 w-full rounded-sm border border-line bg-ink px-3 py-3 font-mono text-xs text-fg"
        aria-label="节点公钥"
        placeholder="公钥"
        value={peer.publicRawB64}
        onChange={(e) => onChange({ ...peer, publicRawB64: e.target.value.trim() })}
      />
      <div className="flex flex-wrap gap-2">
        <Btn kind={peer.relay ? "solid" : "ghost"} onClick={() => onChange({ ...peer, relay: !peer.relay })}>
          {peer.relay ? "允许借本机中继" : "不借本机中继"}
        </Btn>
        <Btn kind={peer.exit ? "solid" : "ghost"} onClick={() => onChange({ ...peer, exit: !peer.exit })}>
          {peer.exit ? "允许把本机当出口" : "不把本机当出口"}
        </Btn>
        <Btn kind="ember" onClick={onRemove}>
          移出名单
        </Btn>
      </div>
      <textarea
        className="min-h-16 w-full rounded-sm border border-line bg-ink px-3 py-3 font-mono text-xs text-fg"
        aria-label="中继目标"
        placeholder="允许的目标，一行一条。空着表示不限制。例如 tcp 203.0.113.8 22"
        value={targetsText}
        onFocus={() => setTargetsFocus(true)}
        onBlur={() => {
          setTargetsFocus(false);
          onChange({ ...peer, targets: targetsText.split("\n").map((item) => item.trim()).filter(Boolean) });
        }}
        onChange={(e) => setTargetsText(e.target.value)}
      />
    </div>
  );
}

function AllowList({ allow, onChange }: { allow: string[]; onChange: (allow: string[]) => void }) {
  const [text, setText] = useState(allow.join("\n"));
  const [focused, setFocused] = useState(false);
  useEffect(() => {
    if (!focused) setText(allow.join("\n"));
  }, [allow, focused]);
  return (
    <textarea
      className="min-h-24 w-full rounded-sm border border-line bg-ink px-3 py-3 font-mono text-sm text-fg"
      value={text}
      onFocus={() => setFocused(true)}
      onBlur={() => {
        setFocused(false);
        onChange(text.split(/\r?\n/).map((line) => line.trim()).filter(Boolean));
      }}
      onChange={(e) => setText(e.target.value)}
    />
  );
}

function Platform({ title, body, children }: { title: string; body: string; children: ReactNode }) {
  return (
    <div className="flex flex-col gap-2 rounded-sm bg-panel-2 p-3">
      <h3 className="text-sm font-medium">{title}</h3>
      <p className="text-sm text-mist">{body}</p>
      {children}
    </div>
  );
}
