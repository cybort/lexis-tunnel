import { useEffect, useState } from "react";
import { ensureSeed, useMesh } from "@/lib/lexis/store";
import { SPEC } from "@/lib/lexis/spec";
import { currentWindow, windowRemain, type LiveSession } from "@/lib/lexis/handshake";
import { Bench } from "./bench";
import { LexiconPanel } from "./lexicon-panel";
import { MapsPanel } from "./maps-panel";
import { NodesPanel } from "./nodes-panel";
import { Overview } from "./overview";

type Tab = "overview" | "nodes" | "maps" | "tunnel" | "lexicon";

const TABS: { id: Tab; label: string }[] = [
  { id: "overview", label: "总览" },
  { id: "nodes", label: "节点" },
  { id: "maps", label: "映射" },
  { id: "tunnel", label: "隧道" },
  { id: "lexicon", label: "词表" },
];

export function Console() {
  const [tab, setTab] = useState<Tab>("overview");
  const [booted, setBooted] = useState(false);
  const [bootError, setBootError] = useState<string | null>(null);
  const [now, setNow] = useState(0);
  const [session, setSession] = useState<LiveSession | null>(null);

  useEffect(() => {
    let live = true;
    (async () => {
      try {
        await useMesh.persist.rehydrate();
        await ensureSeed();
        if (live) setBooted(true);
      } catch (err) {
        if (live) setBootError(err instanceof Error ? err.message : "节点没有读出来");
      }
    })();
    return () => {
      live = false;
    };
  }, []);

  useEffect(() => {
    if (!booted) return;
    setNow(Date.now());
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, [booted]);

  const windowId = now ? currentWindow(now) : null;

  return (
    <div className="min-h-screen">
      <header className="border-b border-line bg-ink">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-3 px-4 py-4">
          <div className="flex items-center gap-3">
            <span className="relative inline-flex h-8 w-8 items-center justify-center" aria-hidden="true">
              <span className="absolute inset-x-1 top-1 h-1.5 bg-sage" />
              <span className="absolute inset-x-1 bottom-1 h-1.5 bg-sage" />
              <span className="h-1.5 w-1.5 bg-ember" />
            </span>
            <div>
              <div className="flex items-baseline gap-2">
                <h1 className="text-xl font-bold tracking-wide">词隙</h1>
                <span className="font-mono text-sm text-sage">LEXIS</span>
              </div>
              <p className="text-sm text-mist">低熵远程组网</p>
            </div>
          </div>
          <p className="font-mono text-xs text-mist">
            {windowId === null
              ? `窗长 ${SPEC.windowSec}s`
              : `时间窗 ${windowId} · 剩余 ${windowRemain(now)}s`}
          </p>
        </div>
        <nav className="mx-auto flex max-w-6xl gap-1 overflow-x-auto px-4" aria-label="分区">
          {TABS.map((item) => (
            <button
              key={item.id}
              type="button"
              aria-selected={tab === item.id}
              onClick={() => setTab(item.id)}
              className={`min-h-11 shrink-0 border-b-2 px-3 text-sm ${
                tab === item.id ? "border-sage text-fg" : "border-transparent text-mist"
              }`}
            >
              {item.label}
            </button>
          ))}
        </nav>
      </header>

      <main className="mx-auto max-w-6xl px-4 py-5">
        {bootError ? <p className="text-sm text-ember">{bootError}</p> : null}
        {!booted && !bootError ? (
          <p className="text-sm text-mist">正在这台浏览器里准备闸门和内网端。</p>
        ) : null}
        {booted && tab === "overview" ? <Overview onOpen={() => setTab("tunnel")} /> : null}
        {booted && tab === "nodes" ? <NodesPanel /> : null}
        {booted && tab === "maps" ? <MapsPanel /> : null}
        {booted && tab === "tunnel" ? <Bench session={session} onSession={setSession} /> : null}
        {booted && tab === "lexicon" ? <LexiconPanel session={session} /> : null}
      </main>
    </div>
  );
}
