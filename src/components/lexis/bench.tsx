import { useState } from "react";
import { fromUtf8, hex, isPrintableText, randomBytes, utf8 } from "@/lib/lexis/bytes";
import { entropyPair } from "@/lib/lexis/entropy";
import type { Direction } from "@/lib/lexis/seal";
import { establish3, type LiveSession } from "@/lib/lexis/handshake";
import { LexisError } from "@/lib/lexis/crypto";
import { packPayload, unpackPayload } from "@/lib/lexis/pack";
import { useProfile } from "@/lib/lexis/profile-store";
import { decodeRecord, encodeRecord, heartbeatPayload, RECORD, recordLabel } from "@/lib/lexis/records";
import { useMesh } from "@/lib/lexis/store";
import { FrameError, openV2, openV2Honey, packBatch, sealV2, SEG_COMPLETE, unpackBatch, deriveV2Keys } from "@/lib/lexis/v2/frame2";
import { EntropyMeter } from "./meter";
import { Btn, control, Field, Paper } from "./ui";

type LogItem = {
  id: string;
  title: string;
  meta: string;
  prose?: string;
  wire?: number;
  random?: number;
  bad?: boolean;
};

function showPayload(payload: Uint8Array): string {
  if (isPrintableText(payload)) return fromUtf8(payload);
  return hex(payload);
}

function Wire({ item, copied, onCopy }: { item: LogItem; copied: boolean; onCopy: () => void }) {
  const [open, setOpen] = useState(false);
  const prose = item.prose ?? "";
  const long = prose.length > 180;
  const shown = !long || open ? prose : `${prose.slice(0, 180)}…`;
  return (
    <article className="flex flex-col gap-2">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 className={`text-sm font-medium ${item.bad ? "text-ember" : "text-fg"}`}>{item.title}</h3>
        <div className="flex gap-3">
          {long ? (
            <button type="button" className="min-h-11 text-sm text-mist" onClick={() => setOpen((v) => !v)}>
              {open ? "收起" : "展开"}
            </button>
          ) : null}
          {item.prose ? (
            <button type="button" className="min-h-11 text-sm text-sage" onClick={onCopy}>
              {copied ? "已复制" : "复制原文"}
            </button>
          ) : null}
        </div>
      </div>
      <p className="break-all font-mono text-xs text-mist">{item.meta}</p>
      {item.prose ? <Paper>{shown}</Paper> : null}
    </article>
  );
}

export function Bench({
  session,
  onSession,
}: {
  session: LiveSession | null;
  onSession: (session: LiveSession | null) => void;
}) {
  const nodes = useMesh((s) => s.nodes);
  const mappings = useMesh((s) => s.mappings);
  const profile = useProfile((s) => s.profile);
  const edges = nodes.filter((n) => n.role === "edge");
  const gates = nodes.filter((n) => n.role === "gate");
  const [edgeId, setEdgeId] = useState(edges[0]?.id ?? "");
  const [gateId, setGateId] = useState(gates[0]?.id ?? "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [logs, setLogs] = useState<LogItem[]>([]);
  const [draft, setDraft] = useState("GET /health HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n");
  const [direction, setDirection] = useState<Direction>("g2e");
  const [copied, setCopied] = useState<string | null>(null);
  const [lastFrame, setLastFrame] = useState<{ prose: string; direction: Direction; counter: number } | null>(null);

  function push(item: Omit<LogItem, "id">) {
    setLogs((prev) => [{ ...item, id: crypto.randomUUID() }, ...prev].slice(0, 12));
  }

  async function handshake() {
    const edge = nodes.find((n) => n.id === (edgeId || edges[0]?.id));
    const gate = nodes.find((n) => n.id === (gateId || gates[0]?.id));
    if (!edge || !gate) {
      setError("需要一个内网端和一个闸门");
      return;
    }
    setBusy(true);
    setError(null);
    setLogs([]);
    setLastFrame(null);
    onSession(null);
    try {
      const next = await establish3(edge, gate, Date.now(), { ...profile.kdf, honey: profile.honey }, profile.link.token);
      onSession(next);
      push({
        title: "会话密钥已按握手回声派生",
        meta: `3.0 · HCTR2 + rANS · Argon2id ${next.kdf.memoryKiB} KiB · t${next.kdf.iterations} · p${next.kdf.parallelism} · ${next.kdfMs} ms · 词表 ${next.lexicon.length} · ${next.honey ? "握手带蜜文标志" : "坏帧会拆掉会话"}`,
      });
      for (const item of [
        { title: "内网端 → 闸门 · 问候", prose: next.helloWire },
        { title: "闸门 → 内网端 · 临时公钥和确认", prose: next.serverWire },
        { title: "内网端 → 闸门 · 结束握手", prose: next.finishWire },
      ]) {
        const ent = entropyPair(item.prose);
        push({
          title: item.title,
          prose: item.prose,
          meta: `${ent.nbytes} 字节 · 熵 ${ent.wire.toFixed(2)} · 随机对照 ${ent.random.toFixed(2)}`,
          wire: ent.wire,
          random: ent.random,
        });
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "握手失败");
    } finally {
      setBusy(false);
    }
  }

  async function frame(current: LiveSession, dir: Direction, plaintext: Uint8Array) {
    if (!current.v2) throw new LexisError("这次会话没有 3.0 帧密钥");
    const packed = await packPayload(plaintext, profile.zstd);
    const counter = current.counters[dir] + 1;
    const batch = packBatch([{ flag: SEG_COMPLETE, data: packed.bytes }]);
    const prose = sealV2({
      keys: current.v2,
      counter,
      window: current.window,
      dir,
      plaintext: batch,
      maxExpansion: profile.frame.maxExpansion,
      smallFramePolicy: profile.frame.smallFramePolicy,
    });
    const opened = openV2({ keys: current.v2, counter, window: current.window, dir, prose });
    const segs = unpackBatch(opened);
    if (segs.length !== 1 || segs[0].flag !== SEG_COMPLETE) throw new LexisError("这一帧不是一条完整记录");
    const unpacked = await unpackPayload(segs[0].data, false);
    const next: LiveSession = {
      ...current,
      counters: { ...current.counters, [dir]: counter },
      seen: { ...current.seen, [dir]: counter },
    };
    const sense = unpacked.compressed
      ? `对端看见类型 1，按帧头解开 zstd ${packed.level}`
      : "对端看见类型 0，按原文使用";
    return { prose, unpacked, next, counter, sense };
  }

  async function transmit(dir: Direction, plaintext: Uint8Array, title: string) {
    if (!session) throw new LexisError("还没有会话");
    const framed = await frame(session, dir, plaintext);
    onSession(framed.next);
    setLastFrame({ prose: framed.prose, direction: dir, counter: framed.counter });
    const ent = entropyPair(framed.prose);
    const rec = decodeRecord(framed.unpacked.data);
    push({
      title,
      prose: framed.prose,
      meta: `${dir === "g2e" ? "闸门 → 内网" : "内网 → 闸门"} · 计数器 ${framed.counter} · ${recordLabel(rec.type)} · conn ${rec.conn} · seq ${rec.seq} · ${ent.nbytes} 字节 · 熵 ${ent.wire.toFixed(2)} · ${framed.sense}`,
      wire: ent.wire,
      random: ent.random,
    });
    return { prose: framed.prose, payload: rec.payload, session: framed.next };
  }

  async function sendDraft() {
    if (!session) return;
    setBusy(true);
    setError(null);
    try {
      const conn = session.counters[direction] + 1;
      await transmit(direction, encodeRecord(RECORD.data, conn, conn, utf8(draft)), "手动封装");
    } catch (err) {
      setError(err instanceof Error ? err.message : "封装失败");
    } finally {
      setBusy(false);
    }
  }

  async function sendHeartbeat() {
    if (!session) return;
    setBusy(true);
    setError(null);
    try {
      await transmit(
        "e2g",
        encodeRecord(RECORD.heartbeat, 0, session.counters.e2g + 1, heartbeatPayload()),
        "心跳",
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "心跳失败");
    } finally {
      setBusy(false);
    }
  }

  async function sendRandom() {
    if (!session) return;
    setBusy(true);
    setError(null);
    try {
      const raw = randomBytes(48);
      const result = await transmit("g2e", encodeRecord(RECORD.data, 9, 1, raw), "随机字节");
      push({ title: "对端拆出的字节", meta: hex(result.payload) });
    } catch (err) {
      setError(err instanceof Error ? err.message : "发送失败");
    } finally {
      setBusy(false);
    }
  }

  async function runMap() {
    if (!session) return;
    const gate = nodes.find((n) => n.fingerprint === session.gateFp);
    const map = mappings
      .filter((m) => m.enabled && (!gate || m.gateId === gate.id))
      .sort((a, b) => b.priority - a.priority)[0];
    if (!map) {
      setError("这个闸门没有启用的映射");
      return;
    }
    setBusy(true);
    setError(null);
    let current = session;
    try {
      const run = async (dir: Direction, type: number, conn: number, seq: number, body: string, title: string) => {
        const framed = await frame(current, dir, encodeRecord(type, conn, seq, utf8(body)));
        current = framed.next;
        setLastFrame({ prose: framed.prose, direction: dir, counter: framed.counter });
        const ent = entropyPair(framed.prose);
        const rec = decodeRecord(framed.unpacked.data);
        push({
          title,
          prose: framed.prose,
          meta: `${recordLabel(rec.type)} · ${ent.nbytes} B · 熵 ${ent.wire.toFixed(2)} / 随机 ${ent.random.toFixed(2)} · ${framed.sense} · 拆出 ${showPayload(rec.payload).replace(/\s+/g, " ").slice(0, 80)}`,
          wire: ent.wire,
          random: ent.random,
        });
      };
      await run("g2e", RECORD.open, 1, 1, `open ${map.proto} ${map.targetHost}:${map.targetPort}`, `公网进入 :${map.listenPort}`);
      await run(
        "g2e",
        RECORD.data,
        1,
        2,
        `GET /health HTTP/1.1\r\nHost: ${map.targetHost}:${map.targetPort}\r\n\r\n`,
        "请求封进词隙",
      );
      await run(
        "e2g",
        RECORD.data,
        1,
        1,
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nlexis-ok\r\n",
        "目标返回，内网端封回去",
      );
      await run("e2g", RECORD.close, 1, 2, "close", "连接关闭");
      onSession(current);
    } catch (err) {
      onSession(current);
      setError(err instanceof Error ? err.message : "演练中断");
    } finally {
      setBusy(false);
    }
  }

  async function wrongKey() {
    if (!session || !lastFrame) {
      setError("先发出一帧，再用一把错误密钥去拆");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      if (!session.v2) throw new LexisError("这次会话没有 3.0 帧密钥");
      const view = openV2Honey({
        keys: deriveV2Keys(randomBytes(32)),
        counter: lastFrame.counter,
        window: session.window,
        dir: lastFrame.direction,
        prose: lastFrame.prose,
      });
      const note = view.formatValid
        ? "规范性检查碰巧通过（错误密钥大约 2%–3%）。正文仍不是原文。"
        : "规范性检查没过。错误密钥大约 97% 会这样。";
      push({
        title: "错误密钥没有还原这一帧",
        meta: `${note} 单靠这一步就能确认候选会话密钥，蜜文挡不住。助记码 ${view.mnemonic.length} 字节，正文 ${view.body.length} 字节。`,
      });
    } catch (err) {
      push({
        title: "错误密钥没有按预期解开",
        meta: err instanceof Error ? err.message : "拆不开",
        bad: true,
      });
    } finally {
      setBusy(false);
    }
  }

  async function wrongWindow() {
    if (!session || !lastFrame) {
      setError("先发出一帧数据，再拿相邻时间窗去拆");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      if (!session.v2) throw new LexisError("这次会话没有 3.0 帧密钥");
      openV2({
        keys: session.v2,
        counter: lastFrame.counter,
        window: session.window + 1,
        dir: lastFrame.direction,
        prose: lastFrame.prose,
      });
      setError("这一帧居然被下一窗拆开了。不该发生。");
    } catch (err) {
      if (err instanceof FrameError || err instanceof LexisError) {
        push({
          title: "下一时间窗拒绝了上一帧",
          meta: err.message,
          bad: true,
        });
      } else {
        setError(err instanceof Error ? err.message : "拆不开");
      }
    } finally {
      setBusy(false);
    }
  }

  async function copy(id: string, prose: string) {
    try {
      await navigator.clipboard.writeText(prose);
      setCopied(id);
    } catch {
      setCopied(null);
      setError("复制没有成功");
    }
  }

  const latest = logs.find((item) => item.wire !== undefined && item.random !== undefined);

  return (
    <div className="grid gap-4 lg:grid-cols-4">
      <div className="flex flex-col gap-4 lg:col-span-1">
        <section className="rounded-md border border-line bg-panel p-4">
          <h2 className="text-base font-medium">两端</h2>
          <div className="mt-3 flex flex-col gap-3">
            <Field label="内网端">
              <select className={control} value={edgeId || edges[0]?.id || ""} onChange={(e) => setEdgeId(e.target.value)}>
                {edges.map((n) => (
                  <option key={n.id} value={n.id}>
                    {n.name}
                  </option>
                ))}
              </select>
            </Field>
            <Field label="公网闸门">
              <select className={control} value={gateId || gates[0]?.id || ""} onChange={(e) => setGateId(e.target.value)}>
                {gates.map((n) => (
                  <option key={n.id} value={n.id}>
                    {n.name}
                  </option>
                ))}
              </select>
            </Field>
            <Btn disabled={busy} onClick={() => void handshake()}>
              {busy ? "进行中" : "握手"}
            </Btn>
          </div>
          {session ? (
            <dl className="mt-4 space-y-2 text-sm">
              <div>
                <dt className="text-mist">会话密钥 · Argon2id</dt>
                <dd className="break-all font-mono text-xs">{session.skFp}</dd>
              </div>
              <div>
                <dt className="text-mist">派生</dt>
                <dd className="font-mono text-xs">
                  {session.kdf.memoryKiB} KiB · t{session.kdf.iterations} · p{session.kdf.parallelism} · {session.kdfMs} ms ·{" "}
                  {profile.frame.smallFramePolicy === "honey" ? "小帧按蜜文填充" : "小帧优先压膨胀"} · 预算 {profile.frame.maxExpansion}×
                </dd>
              </div>
              <div>
                <dt className="text-mist">时间窗</dt>
                <dd className="font-mono text-xs">{session.window}</dd>
              </div>
              <div>
                <dt className="text-mist">计数器</dt>
                <dd className="font-mono text-xs">
                  闸门→内网 {session.counters.g2e} · 内网→闸门 {session.counters.e2g}
                </dd>
              </div>
            </dl>
          ) : (
            <p className="mt-4 text-sm text-mist">握手之后，这里留下密钥指纹和两个方向的计数器。</p>
          )}
          <div className="mt-4 flex flex-col gap-2">
            <Btn disabled={!session || busy} onClick={() => void runMap()}>
              走一条映射
            </Btn>
            <Btn kind="ghost" disabled={!session || busy} onClick={() => void sendHeartbeat()}>
              心跳
            </Btn>
            <Btn kind="ghost" disabled={!session || busy} onClick={() => void sendRandom()}>
              随机字节
            </Btn>
            <Btn kind="ghost" disabled={!session || busy || !lastFrame} onClick={() => void wrongKey()}>
              用错误密钥拆上一帧
            </Btn>
            <Btn kind="ghost" disabled={!session || busy} onClick={() => void wrongWindow()}>
              用下一窗拆上一帧
            </Btn>
          </div>
        </section>
        {error ? <p className="text-sm text-ember">{error}</p> : null}
        <section className="rounded-md border border-line bg-panel p-4">
          <h2 className="text-base font-medium">自己写一帧</h2>
          <div className="mt-3 grid gap-3">
            <Field label="方向">
              <select className={control} value={direction} onChange={(e) => setDirection(e.target.value as Direction)}>
                <option value="g2e">闸门 → 内网端</option>
                <option value="e2g">内网端 → 闸门</option>
              </select>
            </Field>
            <Field label="载荷">
              <textarea
                className="min-h-32 w-full rounded-sm border border-line bg-ink px-3 py-3 font-mono text-sm text-fg"
                value={draft}
                aria-label="载荷"
                onChange={(e) => setDraft(e.target.value)}
              />
            </Field>
            <Btn disabled={!session || busy} onClick={() => void sendDraft()}>
              封装并让对端拆开
            </Btn>
          </div>
        </section>
      </div>

      <div className="flex flex-col gap-4 lg:col-span-3">
        {latest && latest.wire !== undefined && latest.random !== undefined ? (
          <section className="rounded-md border border-line bg-panel p-4">
            <h2 className="text-base font-medium">最近一帧的字节熵</h2>
            <EntropyMeter wire={latest.wire} random={latest.random} />
            <p className="text-sm text-mist">纵轴是 bit/字节。词隙应明显低于等长随机字节。</p>
          </section>
        ) : null}
        <div className="flex flex-col gap-3">
          {logs.length === 0 ? <Paper kicker="线上">握手之后，报文会落在这张纸上。</Paper> : null}
          {logs.map((item) => (
            <Wire key={item.id} item={item} copied={copied === item.id} onCopy={() => void copy(item.id, item.prose ?? "")} />
          ))}
        </div>
      </div>
    </div>
  );
}
