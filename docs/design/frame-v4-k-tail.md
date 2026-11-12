# 帧词编码 v4 方案 K：带钥规范尾（frame.dte = bb-k-v4，协议 lexis-hctr2-bb-k-v4）

在 bb-v4（A0）之上只改一处：seal 时密文 C 以下的尾随比特和词数选择，不再取 CSPRNG，改取
AES-128-CTR(K_tail, IV = SHA-256(tweak(counter, dir, window, gen) ‖ C)[0..16])。
K_tail = HKDF(sk, "lexis-v2", "tail|gen=N", 16)，与 HCTR2/pad/mnemonic 密钥独立。

- 收端：bbParse 得 C → 用同一流重封 → 词串必须逐词一致，否则"帧完整性校验失败"。
  A0 末尾随机余量词可改（全帧 9.4%、末 8 词 100%）的问题因此消失。
- 线上分布：没有 K_tail 的观察者看到的尾随比特，在 AES-CTR 意义上与 CSPRNG 计算上不可区分，词分布与 bb-v4 相同。这不是超出该公开模型的单独字节分布证明。
- honey：openV2Honey 不做重封检查（formatValid 恒 true），错钥仍得到格式合法的 honey 视图。
  持候选会话密钥的人可以用 openV2（mnemonic）确认密钥，这与 bb-v4 相同；重封本身另给一个确认途径。
- 代价：seal 与 bb-v4 相同；open 多一次封帧（约 2 倍）。密文层与 bb-v4 相同，bb-v4 端能解开 bb-k-v4 帧，反之不行。
- 两端必须相同，不协商。

## Default and interop (4.0, 2026-11-03)

`frame.dte` values: `bb-k-v4` (4.0.0 default, explicit fallback after v4s; protocol `lexis-hctr2-bb-k-v4`), `bb-k-v4s` (**default** from next 4.x, see frame-v4s-session-vocab.md), `bb-c8-v4` (A1 with the
fast closure check, optional, **not recommended**: residual tamper acceptance 19/6000 ≈ 0.3% with
unchanged plaintext, vs 0/6000 for bb-k-v4; kept only for faster open), `bb-v4` (A0, fallback), `rans-v3` (3.0.x data frames only; a 3.0.x handshake also needs `frame.dteCheck=false` — setting rans-v3 alone is not enough), and the experimental
`bb-ou-v4` / `bb-ouc8-v4` / `bb-ouc8r-v4` / `dfa-v4`. Both ends must use the same value; it is not
negotiated. Measured cross-open matrix (400 frames per cell, 1-64 B and 1-4096 B halves,
`src/lib/lexis/v2/dte-interop.test.ts` asserts it):

| sealed by \ opened by | bb-k-v4 | bb-v4 | bb-c8-v4 |
|---|---|---|---|
| bb-k-v4 | 400/400 | 400/400 (one-way) | 0/400 |
| bb-v4 | 0/400 | 400/400 | 2/400 |
| bb-c8-v4 | 0/400 | 2/400 | 400/400 |

Every mixed pair has a direction that refuses (almost) every frame, so a mixed session fails after the
handshake. Single-word tamper (random position and each of the last 8 words, 6000 trials): bb-k-v4 refuses
6000/6000; bb-c8-v4 accepts 19/6000 (~0.3%, plaintext unchanged, mostly within 8 words of the end;
also seen on feat/v4-a1-c8ds c3068ec: fast 7/6000, LEXIS_C8_SLOW 12/6000); bb-v4 leaves the last
words malleable.

## Handshake dte check (`frame.dteCheck`, default `true`)

With the check on, `transcript()` in `handshake3.ts` becomes
`SHA-256("lexis-v4-transcript-dte" || T_v3 || frame.dte)`; both confirmS (gate -> edge) and confirmC
(edge -> gate) are HMACs over it. Nothing new is sent: hello/server/finish keep their layout and
lengths, and the confirm tags are still 16 uniform bytes, so an observer without the keys sees the
same bytes distribution. On a dte mismatch the edge's confirmS check fails ("密钥确认失败"), the edge
closes the pipe and never sends a finish. The gate has already written its one server reply (as for
any admitted hello) and takes its existing failure path: half-open slot released at once, connection
held silent until the handshake deadline, no extra byte (`src/agent/dte-silent.test.ts`). If a
finish does arrive with a different transcript, `gateAccept3` throws HandshakeDrop like any bad finish.

`false` restores the 3.x transcript: mismatched dte completes the handshake and the first data frame
fails integrity. Both ends must use the same `frame.dteCheck` (on/off mismatch fails the handshake
even with equal dte). Measured (`src/lib/lexis/v2/dte-handshake.test.ts`): check on, 3 equal pairs pass,
6 mismatched pairs fail at confirmS; check off, 6 mismatched pairs complete the handshake and fail on
data.

Visible difference on a mismatch only: before, the edge sent a finish and a data frame before the
session died; now the edge closes right after the server reply (same as a wrong gate key).
