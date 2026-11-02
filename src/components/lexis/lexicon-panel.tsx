import { useMemo, useState } from "react";
import type { LiveSession } from "@/lib/lexis/handshake";
import { staticLexicon } from "@/lib/lexis/lexicon";
import { Btn, control } from "./ui";

export function LexiconPanel({ session }: { session: LiveSession | null }) {
  const [query, setQuery] = useState("");
  const [source, setSource] = useState<"session" | "static">("session");
  const [staticWords, setStaticWords] = useState<string[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function loadStatic() {
    setBusy(true);
    setError(null);
    try {
      setStaticWords(await staticLexicon());
      setSource("static");
    } catch (err) {
      setError(err instanceof Error ? err.message : "静态词表没有生成");
    } finally {
      setBusy(false);
    }
  }

  const words = source === "session" ? session?.lexicon ?? null : staticWords;
  const shown = useMemo(() => {
    if (!words) return [];
    const q = query.trim().toLowerCase();
    const rows: { word: string; index: number }[] = [];
    for (let i = 0; i < words.length && rows.length < 96; i++) {
      if (!q || words[i].includes(q)) rows.push({ word: words[i], index: i });
    }
    return rows;
  }, [words, query]);

  return (
    <div className="flex flex-col gap-4">
      <section className="rounded-md border border-line bg-panel p-4">
        <h2 className="text-base font-medium">本窗词表</h2>
        <p className="mt-2 text-sm text-mist">
          握手之后这里是这把会话密钥打乱过的英文词序，大约三万词，只在频次接近的词之间换位置。它不是公开的音节表。静态按钮仍会生成旧的握手音节表，只作对照，线上帧不用它。词表来自 FrequencyWords，许可是 CC BY-SA 4.0。
        </p>
        <div className="mt-4 flex flex-wrap gap-2">
          <Btn kind={source === "session" ? "solid" : "ghost"} onClick={() => setSource("session")}>
            当前会话
          </Btn>
          <Btn kind="ghost" disabled={busy} onClick={() => void loadStatic()}>
            {busy ? "生成中" : "静态握手词表"}
          </Btn>
        </div>
        {error ? <p className="mt-3 text-sm text-ember">{error}</p> : null}
      </section>

      {!words ? (
        <p className="text-sm text-mist">
          {source === "session" ? "先在隧道页完成一次握手，秘密词表才会出现。" : "静态词表还没生成。"}
        </p>
      ) : (
        <section className="rounded-md border border-line bg-panel p-4">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <p className="font-mono text-xs text-mist">
              {source === "session" ? `窗 ${session?.window}` : "静态"} · {words.length} 词
            </p>
            <input
              className={`${control} sm:max-w-xs`}
              placeholder="过滤"
              aria-label="过滤词表"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
          </div>
          <ul className="mt-4 grid grid-cols-2 gap-2 sm:grid-cols-4">
            {shown.map((row) => (
              <li key={`${row.index}-${row.word}`} className="rounded-sm bg-panel-2 px-3 py-2 font-mono text-sm">
                <span className="mr-2 text-mist">{String(row.index).padStart(4, "0")}</span>
                {row.word}
              </li>
            ))}
          </ul>
          <p className="mt-3 text-sm text-mist">只列出前 96 个匹配。下标就是这个词在加解密里的序号。</p>
        </section>
      )}
    </div>
  );
}
