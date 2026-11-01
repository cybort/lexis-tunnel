import { useState } from "react";
import { Trash2 } from "lucide-react";
import { useMesh } from "@/lib/lexis/store";
import type { PortMap } from "@/lib/lexis/types";
import { Btn, control, Field } from "./ui";

export function MapsPanel() {
  const nodes = useMesh((s) => s.nodes);
  const mappings = useMesh((s) => s.mappings);
  const addMapping = useMesh((s) => s.addMapping);
  const updateMapping = useMesh((s) => s.updateMapping);
  const removeMapping = useMesh((s) => s.removeMapping);
  const gates = nodes.filter((n) => n.role === "gate");
  const [gateId, setGateId] = useState(gates[0]?.id ?? "");
  const [proto, setProto] = useState<"tcp" | "udp">("tcp");
  const [listenPort, setListenPort] = useState("18443");
  const [targetHost, setTargetHost] = useState("127.0.0.1");
  const [targetPort, setTargetPort] = useState("8080");
  const [priority, setPriority] = useState("10");
  const [note, setNote] = useState("");
  const [error, setError] = useState<string | null>(null);

  function add() {
    const listen = Number(listenPort);
    const target = Number(targetPort);
    const rank = Number(priority);
    const gate = gateId || gates[0]?.id;
    if (!gate) {
      setError("先建一个公网闸门");
      return;
    }
    if (!Number.isInteger(listen) || listen < 1 || listen > 65535) {
      setError("监听端口要在 1 到 65535");
      return;
    }
    if (!targetHost.trim()) {
      setError("目标主机不能空");
      return;
    }
    if (!Number.isInteger(target) || target < 1 || target > 65535) {
      setError("目标端口要在 1 到 65535");
      return;
    }
    setError(null);
    const mapping: PortMap = {
      id: crypto.randomUUID(),
      gateId: gate,
      proto,
      listenPort: listen,
      targetHost: targetHost.trim(),
      targetPort: target,
      priority: Number.isFinite(rank) ? rank : 0,
      enabled: true,
      note: note.trim(),
    };
    addMapping(mapping);
    setNote("");
  }

  const sorted = [...mappings].sort((a, b) => b.priority - a.priority || a.listenPort - b.listenPort);

  return (
    <div className="flex flex-col gap-4">
      <section className="rounded-md border border-line bg-panel p-4">
        <h2 className="text-base font-medium">新映射</h2>
        <p className="mt-1 text-sm text-mist">同一协议和端口上，优先级高的那条生效。闸门收包，内网端把它交给目标。</p>
        <div className="mt-4 grid gap-3 sm:grid-cols-2">
          <Field label="闸门">
            <select className={control} value={gateId || gates[0]?.id || ""} onChange={(e) => setGateId(e.target.value)}>
              {gates.length === 0 ? <option value="">没有闸门</option> : null}
              {gates.map((g) => (
                <option key={g.id} value={g.id}>
                  {g.name}
                </option>
              ))}
            </select>
          </Field>
          <Field label="协议">
            <select className={control} value={proto} onChange={(e) => setProto(e.target.value as "tcp" | "udp")}>
              <option value="tcp">TCP</option>
              <option value="udp">UDP</option>
            </select>
          </Field>
          <Field label="监听端口">
            <input className={control} inputMode="numeric" value={listenPort} onChange={(e) => setListenPort(e.target.value)} />
          </Field>
          <Field label="优先级">
            <input className={control} inputMode="numeric" value={priority} onChange={(e) => setPriority(e.target.value)} />
          </Field>
          <Field label="目标主机">
            <input className={control} value={targetHost} onChange={(e) => setTargetHost(e.target.value)} />
          </Field>
          <Field label="目标端口">
            <input className={control} inputMode="numeric" value={targetPort} onChange={(e) => setTargetPort(e.target.value)} />
          </Field>
          <Field label="备注">
            <input className={control} value={note} onChange={(e) => setNote(e.target.value)} />
          </Field>
        </div>
        {error ? <p className="mt-3 text-sm text-ember">{error}</p> : null}
        <div className="mt-4">
          <Btn onClick={add}>加上这条</Btn>
        </div>
      </section>

      <div className="flex flex-col gap-3">
        {sorted.length === 0 ? <p className="text-sm text-mist">还没有映射。</p> : null}
        {sorted.map((map) => {
          const gate = nodes.find((n) => n.id === map.gateId);
          return (
            <article key={map.id} className="rounded-md border border-line bg-panel p-4">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <p className="font-mono text-sm text-sage">
                    {map.proto.toUpperCase()} :{map.listenPort}
                  </p>
                  <p className="mt-1 text-base">
                    {gate?.name ?? "未知闸门"} → {map.targetHost}:{map.targetPort}
                  </p>
                  <p className="text-sm text-mist">
                    优先级 {map.priority}
                    {map.note ? ` · ${map.note}` : ""}
                  </p>
                </div>
                <button
                  type="button"
                  className="inline-flex min-h-11 min-w-11 items-center justify-center text-mist hover:text-ember"
                  aria-label="删除映射"
                  onClick={() => removeMapping(map.id)}
                >
                  <Trash2 className="size-4" />
                </button>
              </div>
              <div className="mt-3">
                <Btn kind="ghost" onClick={() => updateMapping(map.id, { enabled: !map.enabled })}>
                  {map.enabled ? "停用" : "启用"}
                </Btn>
              </div>
            </article>
          );
        })}
      </div>
    </div>
  );
}
