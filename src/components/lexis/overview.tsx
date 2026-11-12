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
    body: "内网端主动连出。问候用临时密钥和闸门长期公钥算出的共享秘密来加密，只拿口令和闸门公钥解不出里面的长期公钥。会话密钥还混入两把临时密钥的共享秘密，再交给 Argon2id。默认再把词编码绑进密钥确认。两端词编码或检查开关不一致时，内网端确认失败并断开；闸门只回一次应答，放出半开名额后静默到超时。默认 bb-k-v4s 和任何其它词编码混用时更早：闸门认不出问候，一个字节都不回，和检查开关无关。线格式和长度不变。这一层不是 TLS。安装包是 4.1.0，默认和这页一样是 bb-k-v4s。和 4.0 互通要两端都选 bb-k-v4。和 3.0.x 互通要同时选 rans-v3 并关掉检查。",
  },
  {
    n: "03",
    title: "允许词表共用，组内词序随密钥",
    body: `默认 bb-k-v4s。允许词表全体会话共用，频次表不随密钥变，同组词频次相同。会话密钥只在频次相近的组内打乱词序，所以打乱不改变任何一个词的出现概率。时间窗仍是 ${SPEC.windowSec} 秒。窗变了，计数器继续往后数，不从零开始。选回 bb-k-v4 时，帧词模型公开、不随密钥改词序。选回 rans-v3 时，整份词序按会话密钥打乱，那是 3.0 的做法。`,
  },
  {
    n: "04",
    title: "宽块置换以后写成词",
    body: "正文、填充和 16 字节助记码放进 HCTR2，再写成英文词。默认 bb-k-v4s 用允许词表和会话组内词序。方案 K 用会话密钥生成密文以下的尾部，收端重封比对；改任何一个词都会对不上。重封对得上不能证明这一帧来自对端。持有候选会话密钥的人可以自己做这次检查。蜜文挡的是对长期私钥和口令的暴力猜测，不挡已经拿到候选会话密钥的人。A1（bb-c8-v4）有残余可塑性，同一测量里单词篡改 19/6000 仍被接受，K 是 0/6000，这不是安全性证明，不建议使用。小帧默认少填充。压不压缩看明文第一个字节。",
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
          本页和安装包都是 4.1.0，默认 bb-k-v4s。编码仍是方案 K，词表换成全体会话共用的允许词表，会话密钥只在频次相近的组内打乱，同组频次相同，打乱不改变出现概率。和 4.0 的 bb-k-v4 不互通，混用在问候阶段就失败关闭，关掉检查也没用；要和 4.0 互通，两端都显式选 bb-k-v4。和 3.0.x 互通要再选 rans-v3 并关闭检查，只改词编码不够。A1（bb-c8-v4）有残余可塑性，不推荐。默认握手检查开着。两端必须相同。浏览器里不能守一个真正的 TCP 端口，也不等于已经接管系统流量。口令至少 128 比特，长期密钥都是 X25519。闸门半开按网段计，默认全局 512、每段 8，连接上限默认 1024。坏问候会马上让出名额，连接仍静默到握手超时；一个字节都不到，两秒后也会让出名额。静默连接堆过 1024 才会马上关掉。这不是系统层的建连限速，也不是 gVisor。TLS 和 WebSocket 只包在外面，方便过 CDN。安装包不再附带 TLS 私钥。时钟对不齐时，时间窗两边各留 120 秒。HTTP 代理按每个请求重写，去掉代理认证，并拒绝长度和分块写在一起。客户端要求关闭，或 HTTP/1.0 没声明保持连接时，响应后会关掉这条连接。状态页在回环上可以看指标；离开回环要状态口令，健康检查仍然公开。Linux 上的用户态栈会切段，并按对端窗口停发。未确认的段按超时重发，三个重复确认会提前重发最早的一段；连续 7 次超时并且 3 分钟没有新的确认，才发 RST 关掉这条流。RST 序号是对端下一期望字节，不是未确认数据的末端。乱序可以留多段，默认单流 64 段、65535 字节，整机 8 MiB，超了先丢离缺口最远的。SYN|ACK 宣告的段长是 mtu 减 40，默认 1460；实际发送取它和对端通告的较小值，对端没写时按 536。接收窗口固定 65535，不做窗口缩放。虚拟网卡按流排队：同一条流顺序不变，慢的一条不会卡住别的流，单条流排队超过 64 个就丢后面的。发往对端、却掉进虚拟网卡的包会丢掉。虚拟网卡只认 IPv4。三种系统接管都只把 IPv4 送进隧道。公网 IPv6 默认在 redirect、tproxy 和虚拟网卡下都设为不可达，应用会回落 IPv4；回环、链路本地、ULA、组播和对端的 IPv6 仍走原来的路由。选成不处理则 IPv6 直接走本机网络，不经隧道。ICMP 不转发。Linux 系统接管时会先在本机起 DNS 服务，再把本机 53 端口劫持过去；默认答假地址，关掉假地址则按规则转发，不再直连原来的解析器。装到一半失败会撤掉已装的规则。这些都没有在这台机器上证明已经接住流量。Windows 的 WinDivert 只有源码，驱动不在包里。Android 只带 VpnService 源码和本机包通道，没有装好的系统 VPN。中继默认关闭。缺了角色的配置不会被当成边缘。
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
          线上是小写英文词和空格。每个词大约携带 9.5 比特，摊到字符上大约 1.9 比特，所以一字节密文大约变成 4.2 个线上字节。看起来像书面文字，保密不靠这个。保密靠会话密钥。默认 bb-k-v4s 的频次表公开，词序只在组内随密钥变，出现概率不变。拿到候选会话密钥的人可以重封比对尾部，对得上只说明密钥能生成这条尾，不能证明帧来自对端。没有超出这个词模型的单独字节分布证明。选回 rans-v3 时，词序重编码本身也会露出密钥对不对。拿不到密钥的人看见的仍是词。
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
