import { Radio, ArrowRight } from "lucide-react";
import { SPEC } from "@/lib/lexis/spec";
import { useMesh } from "@/lib/lexis/store";
import { Btn, Panel } from "./ui";

const STEPS = [
  {
    n: "01",
    title: "绑定身份，而不是发证书",
    body: "闸门和内网端各持一对 P-256 长期密钥。控制台只负责把两端钉在一起。业务流量不进控制台。",
  },
  {
    n: "02",
    title: "非对称握手取出会话密钥",
    body: "内网端主动连出。双方各出临时公钥，做两次 ECDH：临时对临时，长期对长期。共享秘密交给 Argon2id。内存、迭代和蜜文开关写在握手里，闸门压到上限后回声，两端按回声派生。这一层不是 TLS。",
  },
  {
    n: "03",
    title: "密钥加时间窗，生成词表",
    body: `Argon2id 得到的会话密钥，再用 HKDF 按同一个 ${SPEC.windowSec} 秒时间窗展开。两端得到同一份 ${SPEC.lexiconSize} 词的秘密词表。窗一变，词表整本换掉。`,
  },
  {
    n: "04",
    title: "密钥、计数器、词表一起封装",
    body: "计数器先被密钥掩住，正文每 12 比特加上密钥流，再写成词。帧尾是随机字节，不是会话密钥的校验，猜对和猜错比对这段都对不上。握手确认也不再拿会话密钥来算。词表仍由会话密钥导出，词能对上词表，本身仍说明密钥是对的。蜜文打开时，词对不上或计数器回放不报错，落成这把密钥和当前时间窗自己的一句话。换钥匙或换窗，词表仍是同样的格式，词不一样。压不压缩看明文第一个字节，zstd 的等级在帧头里，对端不用另配一份开关。",
  },
];

export function Overview({ onOpen }: { onOpen: () => void }) {
  const nodes = useMesh((s) => s.nodes);
  const mappings = useMesh((s) => s.mappings);
  const gates = nodes.filter((n) => n.role === "gate").length;
  const edges = nodes.filter((n) => n.role === "edge").length;
  const liveMaps = mappings.filter((m) => m.enabled).length;

  return (
    <div className="flex flex-col gap-4">
      <section className="grid gap-3 sm:grid-cols-3">
        <Stat k="节点" v={`${gates} 闸门 · ${edges} 内网`} />
        <Stat k="映射" v={`${liveMaps} 条在用`} />
        <Stat k="线上形态" v="散文，不是记录层" />
      </section>

      <Panel
        title="路径"
        action={
          <Btn onClick={onOpen}>
            <Radio className="size-4" aria-hidden="true" />
            打开隧道
          </Btn>
        }
      >
        <ol className="grid gap-2 md:grid-cols-4">
          {[
            ["访客", "打到闸门的公网端口"],
            ["闸门", "把字节封成一帧词"],
            ["词隙", "低熵散文穿过中间网络"],
            ["内网端", "拆开后交给本机目标"],
          ].map(([title, body], i) => (
            <li key={title} className="flex items-stretch gap-2">
              <div className="flex-1 rounded-sm bg-panel-2 px-3 py-3">
                <p className="text-sm font-medium">{title}</p>
                <p className="text-sm text-mist">{body}</p>
              </div>
              {i < 3 ? (
                <ArrowRight className="mt-4 hidden size-4 shrink-0 text-sage md:block" aria-hidden="true" />
              ) : null}
            </li>
          ))}
        </ol>
        <p className="mt-4 text-sm text-mist">
          浏览器里不能守一个真正的 TCP 端口。这条控制台把握手、词表和封装真实跑完。下载的常驻进程走同一套词表，两端都要是这一版。TLS 和 WebSocket 只包在外面，方便过 CDN。安装包不再附带 TLS 私钥。时钟对不齐时，时间窗两边各留 120 秒。HTTP 代理按每个请求重写，去掉代理认证，并拒绝长度和分块写在一起。状态页在回环上可以看指标；离开回环要状态口令，健康检查仍然公开。Linux 上的用户态栈会切段、重传、暂存一段乱序，并按对端窗口停发。系统接管时，53 端口的查询答成 198.18.0.0/15 里的假地址，再映射回域名，假地址本身不会被拨出去。这不是 gVisor，也没有在这台机器上证明虚拟网卡或透明代理已经接住流量。Windows 的 WinDivert 只有源码，驱动不在包里。Android 只带 VpnService 源码和本机包通道，没有装好的系统 VPN。中继默认关闭。缺了角色的配置不会被当成边缘。
        </p>
      </Panel>

      <div className="grid gap-3 md:grid-cols-2">
        {STEPS.map((step) => (
          <article key={step.n} className="rounded-md border border-line bg-panel p-4">
            <p className="font-mono text-xs text-sage">{step.n}</p>
            <h2 className="mt-1 text-base font-medium">{step.title}</h2>
            <p className="mt-2 text-sm text-mist">{step.body}</p>
          </article>
        ))}
      </div>

      <Panel title="低熵指的是什么">
        <p className="text-sm text-mist">
          线上只有小写字母、空格和句号，字节分布靠近书面文字，香农熵通常落在 4 到 5 bit/字节。等长的随机密文接近 8。保密不靠“看起来像句子”，靠会话密钥、随时间窗旋转的词表，以及和计数器绑定的密钥流。词表对中间人是秘密的，所以看到单词也不知道下标。
        </p>
      </Panel>
    </div>
  );
}

function Stat({ k, v }: { k: string; v: string }) {
  return (
    <div className="rounded-md border border-line bg-panel px-4 py-3">
      <p className="text-sm text-mist">{k}</p>
      <p className="mt-1 text-base font-medium">{v}</p>
    </div>
  );
}
