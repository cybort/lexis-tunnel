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
    body: "内网端主动连出。双方各出临时公钥，做两次 ECDH：临时对临时，长期对长期。HKDF 合成会话密钥。这一层不是 TLS。",
  },
  {
    n: "03",
    title: "密钥加时间窗，生成词表",
    body: `同一个会话密钥、同一个 ${SPEC.windowSec} 秒时间窗，两端生成同一份 ${SPEC.lexiconSize} 词的秘密词表。窗一变，词表整本换掉。`,
  },
  {
    n: "04",
    title: "密钥、计数器、词表一起封装",
    body: "每个方向一个计数器。计数器先被密钥掩住，正文每 12 比特加上一段密钥流，再写成词表里的词。虚词只负责节奏，不携带内容。HMAC 负责发现改词。",
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
          浏览器里不能守一个真正的 TCP 端口。这条控制台把握手、词表和封装真实跑完，端口映射按同一帧格式演练。侧车文件留给以后要常驻的进程。
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
