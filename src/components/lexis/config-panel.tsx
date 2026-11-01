import { useState, type ReactNode } from "react";
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
  type ProcessRule,
  type RouteRule,
} from "@/lib/lexis/profile";
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
  const hit = matchRoute(profile, { host, ip, process: proc });
  const issues = profileIssues(profile);

  function setInbounds(inbounds: Inbound[]) {
    patch({ inbounds });
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
          <Platform title="Windows" body="portproxy 转发到本地端口，或只记录 WinDivert 过滤。">
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
    </div>
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
