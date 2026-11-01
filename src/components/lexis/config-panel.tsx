import { useEffect, useState, type ReactNode } from "react";
import { b64 } from "@/lib/lexis/bytes";
import { createIdentity } from "@/lib/lexis/crypto";
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
import { downloadJson } from "@/lib/lexis/store";
import { Btn, control, Field } from "./ui";

function rid(prefix: string) {
  return `${prefix}-${crypto.randomUUID().slice(0, 8)}`;
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
  const hit = matchRoute(profile, { host, ip, process: proc });
  const issues = profileIssues(profile);

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
      </section>

      <section className="rounded-md border border-line bg-panel p-4">
        <h2 className="text-base font-medium">密钥与压缩</h2>
        <p className="mt-2 text-sm text-mist">
          会话密钥的 Argon2id 由常驻进程自己的参数决定，不听客户端把内存抬高。上限 16384 KiB。口令不对的问候在派生之前就被丢掉。长期私钥的口令派生仍在节点页。
        </p>
        <p className="mt-2 text-sm text-mist">
          压缩不靠这份配置在对端对齐。明文第一个字节是类型：0 是原文，1 是 zstd 帧。等级决定窗口，窗口写在帧头里，对端解开以后自己读。比原文更大时这一帧会改回类型 0。
        </p>
        <p className="mt-2 text-sm text-mist">
          蜜文在握手时谈定。打开以后，校验对不上不报错，而按公开词表落成另一句话。线上没有「这是蜜文」的位。没有先验明文的人分不出猜对还是猜错。这个模式不再提示报文被改过。
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
          常驻进程和这条控制台用同一套词表。握手仍是两次 ECDH 加 Argon2id，正文是密钥、计数器和秘密词表。TCP、TLS、WebSocket 只负责协议和头，用来过 CDN。路径默认 /lexis。CDN 若自己终结 TLS，源站可以听 WebSocket。
        </p>
        <p className="mt-2 text-sm text-mist">
          一条会话上可以开多路。打开写成 tcp 主机 端口、udp 主机 端口、relay 节点 再接后面的命令，或 expose 服务名。中继要逐个节点打开，跳数到 4 就停。慢的那一路只堵住自己。SOCKS 的用户名和密码留空就是不认证，HTTP 代理共用这一对。
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
              type="password"
              autoComplete="off"
              value={profile.link.token}
              onChange={(e) => patch({ link: { ...profile.link, token: e.target.value } })}
            />
          </Field>
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
        </div>
        <p className="mt-2 text-sm text-mist">握手口令在 Argon2 之前校验，用来挡伪造问候，不是词表密钥。两端要写成同一个，至少 8 个字符。校验关掉时，外层 TLS 认不出对端，正式部署请换自己的证书。</p>
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
        <p className="mt-2 text-sm text-mist">公网这一侧听一个本地端口，从那个节点已经连进来的会话里打开同名服务。会话不在时会说没有来自该节点的会话。也可以直接访问「节点名:服务名」。</p>
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
          <Platform title="Linux" body="iptables redirect 或 tproxy。需要 root 才会改规则。">
            <select className={control} value={profile.linux.method} onChange={(e) => patch({ linux: { ...profile.linux, method: e.target.value as LexisProfile["linux"]["method"] } })}>
              <option value="redirect">redirect</option>
              <option value="tproxy">tproxy</option>
            </select>
            <input className={control} aria-label="fwmark" inputMode="numeric" value={profile.linux.mark} onChange={(e) => patch({ linux: { ...profile.linux, mark: Number(e.target.value) } })} />
          </Platform>
          <Platform title="Windows" body="portproxy 只绑回环，避免把本地端口公布到局域网。WinDivert 只留下记录，驱动不在包里。">
            <select className={control} value={profile.windows.method} onChange={(e) => patch({ windows: { ...profile.windows, method: e.target.value as LexisProfile["windows"]["method"] } })}>
              <option value="portproxy">portproxy</option>
              <option value="windivert">WinDivert</option>
            </select>
            <input className={control} aria-label="网关" value={profile.windows.gateway} onChange={(e) => patch({ windows: { ...profile.windows, gateway: e.target.value } })} />
          </Platform>
          <Platform title="Android" body="写出 VpnService 会话。地址、MTU、DNS 和绕行网段。">
            <input className={control} aria-label="VPN 地址" value={profile.android.address} onChange={(e) => patch({ android: { ...profile.android, address: e.target.value } })} />
            <input className={control} aria-label="DNS" value={profile.android.dns} onChange={(e) => patch({ android: { ...profile.android, dns: e.target.value } })} />
          </Platform>
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
        <Btn onClick={() => downloadJson("lexis.config.json", profile)}>导出配置</Btn>
      </div>
      <p className="text-sm text-mist">导出的 JSON 含本机私钥。覆盖常驻进程目录里的 lexis.config.json 再重启。</p>
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
