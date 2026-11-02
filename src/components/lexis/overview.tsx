import { Radio, ArrowRight } from "lucide-react";
import { SPEC } from "@/lib/lexis/spec";
import { useMesh } from "@/lib/lexis/store";
import { Btn, Panel } from "./ui";

const STEPS = [
  {
    n: "01",
    title: "绑定身份，而不是发证书",
    body: "闸门和内网端各持一对 X25519 长期密钥。旧的 P-256 身份读不进来，也不能自动换过去。控制台只负责把两端钉在一起。业务流量不进控制台。",
  },
  {
    n: "02",
    title: "临时密钥握出会话密钥",
    body: "内网端主动连出。问候用临时密钥和闸门长期公钥算出的共享秘密来加密，只拿口令和闸门公钥解不出里面的长期公钥。会话密钥还混入两把临时密钥的共享秘密，再交给 Argon2id。握手确认用这个临时秘密来算，不再是公开的转录。这一层不是 TLS。两端都要是 3.0.0。",
  },
  {
    n: "03",
    title: "会话密钥打乱英文词序",
    body: `线上词来自一份约三万词的英文词频表，按这把会话密钥在相近频次里打乱。时间窗仍是 ${SPEC.windowSec} 秒。窗变了，计数器继续往后数，不从零开始。`,
  },
  {
    n: "04",
    title: "宽块置换以后写成词",
    body: "正文、填充和 16 字节助记码放进 HCTR2，再按密钥词表写成英文词。持有候选会话密钥的人，可以用词序重编码确认这把密钥（大约 97% 的错误密钥对不上，对的密钥对得上）。蜜文挡的是对长期私钥和口令的暴力猜测，不挡已经拿到候选会话密钥的人。会话密钥从临时密钥来，拿长期私钥和转录推不回去。小帧默认少填充，所以很短的帧会超过 5 倍；要让填充占比靠近错误密钥，把小帧策略改成蜜文。压不压缩看明文第一个字节。",
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
          浏览器里不能守一个真正的 TCP 端口。这条控制台把握手和封装按 3.0 跑完，和下载的常驻进程是同一套帧。两端都要是这一版，口令至少 128 比特，长期密钥都是 X25519。TLS 和 WebSocket 只包在外面，方便过 CDN。安装包不再附带 TLS 私钥。时钟对不齐时，时间窗两边各留 120 秒。HTTP 代理按每个请求重写，去掉代理认证，并拒绝长度和分块写在一起。状态页在回环上可以看指标；离开回环要状态口令，健康检查仍然公开。Linux 上的用户态栈会切段、重传、暂存一段乱序，并按对端窗口停发。系统接管时，53 端口的查询答成 198.18.0.0/15 里的假地址，再映射回域名，假地址本身不会被拨出去。这不是 gVisor，也没有在这台机器上证明虚拟网卡或透明代理已经接住流量。Windows 的 WinDivert 只有源码，驱动不在包里。Android 只带 VpnService 源码和本机包通道，没有装好的系统 VPN。中继默认关闭。缺了角色的配置不会被当成边缘。
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
          线上是小写英文词和空格。每个词大约携带 9.5 比特，摊到字符上大约 1.9 比特，所以一字节密文大约变成 4.2 个线上字节。看起来像书面文字，保密不靠这个。保密靠会话密钥。拿到候选会话密钥的人可以对上词序。拿不到的人看见的仍是词。
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
