import { Link } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { Monitor, Smartphone, Terminal } from "lucide-react";

type FileInfo = { file: string; bytes: number; sha256: string };
type Manifest = { version: string; files: Record<string, FileInfo> };

const CARDS = [
  {
    id: "windows",
    title: "Windows",
    icon: Monitor,
    resident: "登录任务常驻，失败会重试",
    listen: "固定端口，或 netsh portproxy / WinDivert 记录",
    process: "按进程名接入或绕行",
  },
  {
    id: "linux",
    title: "Linux",
    icon: Terminal,
    resident: "systemd 用户服务，断了自己拉起",
    listen: "固定端口，或 iptables redirect / tproxy",
    process: "从 /proc 认出程序名",
  },
  {
    id: "android",
    title: "Android",
    icon: Smartphone,
    resident: "Termux 后台，Termux:Boot 开机拉起",
    listen: "固定端口，系统接管写成 VpnService 会话",
    process: "程序规则写在配置里，认不到进程时不乱改动作",
  },
] as const;

function sizeLabel(bytes: number) {
  if (!bytes) return "";
  if (bytes < 1024) return `${bytes} B`;
  return `${(bytes / 1024).toFixed(1)} KB`;
}

export function DownloadPage() {
  const [manifest, setManifest] = useState<Manifest | null>(null);

  useEffect(() => {
    let live = true;
    fetch("/downloads/manifest.json")
      .then((res) => res.json())
      .then((data: Manifest) => {
        if (live) setManifest(data);
      })
      .catch(() => {
        if (live) setManifest(null);
      });
    return () => {
      live = false;
    };
  }, []);

  return (
    <div className="min-h-screen">
      <header className="border-b border-line">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-3 px-4 py-4">
          <div className="flex items-center gap-3">
            <span className="relative inline-flex h-8 w-8 items-center justify-center" aria-hidden="true">
              <span className="absolute inset-x-1 top-1 h-1.5 bg-sage" />
              <span className="absolute inset-x-1 bottom-1 h-1.5 bg-sage" />
              <span className="h-1.5 w-1.5 bg-ember" />
            </span>
            <div>
              <h1 className="text-xl font-bold tracking-wide">词隙</h1>
              <p className="text-sm text-mist">下载客户端</p>
            </div>
          </div>
          <Link to="/" className="inline-flex min-h-11 items-center text-sm text-sage">
            返回控制台
          </Link>
        </div>
      </header>
      <main className="mx-auto flex max-w-6xl flex-col gap-4 px-4 py-5">
        <section className="rounded-md border border-line bg-panel p-4">
          <p className="font-mono text-xs text-sage">LEXIS {manifest?.version ?? "1.0.0"}</p>
          <h2 className="mt-2 text-2xl font-bold">三个系统，同一份配置</h2>
          <p className="mt-2 max-w-2xl text-sm text-mist">
            通信进程安装后留在后台。控制台里的「配置」导出 JSON，覆盖客户端目录里的 lexis.config.json 再重启。需要 Node.js 22。状态页在本机 17890 端口。
          </p>
        </section>
        <div className="grid gap-3 lg:grid-cols-3">
          {CARDS.map((card) => {
            const info = manifest?.files[card.id];
            const Icon = card.icon;
            return (
              <article key={card.id} className="flex flex-col rounded-md border border-line bg-panel p-4">
                <div className="flex items-center gap-2">
                  <Icon className="size-5 text-sage" aria-hidden="true" />
                  <h3 className="text-lg font-medium">{card.title}</h3>
                </div>
                <ul className="mt-3 flex flex-1 flex-col gap-2 text-sm text-mist">
                  <li>{card.resident}</li>
                  <li>{card.listen}</li>
                  <li>{card.process}</li>
                </ul>
                <p className="mt-4 font-mono text-xs text-mist">
                  {info ? `${sizeLabel(info.bytes)} · ${info.sha256.slice(0, 12)}` : "正在读取包信息"}
                </p>
                <a
                  className="mt-3 inline-flex min-h-11 items-center justify-center rounded-sm bg-sage px-4 text-sm font-medium text-ink"
                  href={info ? `/downloads/${info.file}` : `/downloads/lexis-${card.id}.zip`}
                  download
                >
                  下载 {card.title}
                </a>
              </article>
            );
          })}
        </div>
        <section className="rounded-md border border-line bg-panel p-4 text-sm text-mist">
          <p>路由能读 Clash 的逗号规则和 sing-box 的 route.rules。geosite、geoip 内置一份小样，完整库用文本 URL。</p>
          <p className="mt-2">
            先在控制台改好档案。
            <a href="/?tab=config" className="ml-2 text-sage">
              打开配置
            </a>
          </p>
        </section>
      </main>
    </div>
  );
}
