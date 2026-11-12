# lexis-tunnel 4.1.0：相对 GitHub main（c2c9754）的合并补丁

写于 2026-11-12 CST。只交文件：没有 push、PR、tag、release，没有改 main 或 remote。
- 基线：`c2c9754ef116ca85e64bc73f0abe6aeb33c68798`（cybort/lexis-tunnel main，2026-11-08 22:06 CST）。
- 本地分支：`local/merge-4.1.0`，HEAD 是 `7592dc2`，worktree 在 `/workspace/lexis-test/merge-to-main/wt`。
- 合并范围（用户 t361u 14:30 和卡片 t361s1727 14:39 决定，22:27 追加 S0 观测补丁）：bb-k-v4s、IPv6 链（P→U1→U1b→U2 r2/r2b）、3A、S0 观测补丁，版本升到 4.1.0。
- 不在范围内：3B、1B+H、OH/OU 诊断补丁、UI 跟进。
- 构建产物：带 `public/agent/lexis-frame.mjs` 和 `public/agent/linux/lexis-sockopt.node`（binary diff）。不带 `.vercel/`、`public/downloads/*.zip`、`public/downloads/manifest.json`。
- 规模：42 个文件，+3470/−419。

## 交付文件
- `lexis-4.1.0-vs-main-c2c9754.patch`：单一补丁，`git diff --binary c2c9754..HEAD`。
- `format-patch/0001…0013`：同一内容的提交序列，用 `git am` 应用。
- `SHA256SUMS`

**应用核验**（在干净的 c2c9754 worktree 上做）：
- `git apply --check` 通过。
- `git apply` 后树是 `47ce4052`，`git am` 整个序列后树也是 `47ce4052`，两者都和 HEAD 的树完全一致。

## Features

| # | 名称 | 来源提交（本分支 ← 原始） | 说明 | 测试状态 |
|---|---|---|---|---|
| F1 | bb-k-v4s 会话词表，成为新的默认 dte | d12545d ← ee03fd5；51c89d3 ← 0e02d5c | 46,701 个词的共用允许词表，组内频次相同，会话密钥打乱组内词序。bb-k-v4 保留为显式回退。与 bb-k-v4 不互通，混用时在 hello 阶段失败关闭 | **通过**：lexis-ts 23/23，npm 失败集合与基线相同；已交的 r2 里整词命中 0，组内词序密钥确认 AUC 0.5。**未测**：跨版本现网互通（按设计不互通） |
| F2 | 允许词表构建脚本 `scripts/build-vocab-allowed.mjs` | 同 F1 | 构建机生成允许词表，并用 `--check` 校验。排除清单不进仓库 | r2 时在构建机上 check ok。本次合并没有重跑，因为排除清单不在 box 上 |
| F3 | redirect 混合接管：TCP REDIRECT + UDP TPROXY | ad97910 ← 9edd000（U1） | redirect 下 UDP 也进隧道。缺能力时拒绝接管，不再静默不接管 | **部分通过**：V 项 PASS，部分项 UNKNOWN（真机、iptables 路径未测） |
| F4 | 系统接管期间本机 DNS 接管全部 53 端口（含内网/IPv6），失败时整体回滚 | e094b59 ← 1f8530a（r1）；f92bbe1 ← fae066c（r2）；cc586f3、c9b0cd5 ← 3455def、8243f75（r2b） | DNS 不再直连。装到一半失败会回滚；tun 回滚时清 lexis0，拒绝接管时关掉 tun fd | **部分通过**：单测通过，部分项 UNKNOWN |
| F5 | S0 IPv6 观测计数（/metrics） | 29c6c3d ← 896b6d6（与 `ipv6-observation-s0.diff` 3282e2c7 逐字节相同） | `lexis_ipv6_rx_total`、`lexis_ipv6_drop_total`、`lexis_ipv6_flow_open_total`、`lexis_tun_unparsed_total`；lexis-tun 新增可选 `onDrop6` 回调和 `dropInfo`；附手动夹具 `scripts/manual/ipv6-leak-matrix.mjs` | 新单测通过（npm +5 项）。**S0 IPv4 官方判定 FAIL**（5 档稳定退化，判定未改）。共用链路对照 60/60 格对齐，「20 档无稳定退化」只是**初步结论**：27/120 次超过 240 s deadline，运行环境受干扰，正在补跑。**S1–S5、S9a、S8、S9b 都没做** |
| F6 | SOCKS 新配置 `link.udpAssociateIdleMs`（默认 120000）和配置页字段 | 1a29dcf ← udp-associate-idle.diff dbbd5bc8（3A） | 见 X4 | 见 X4 |
| F7 | 版本 4.1.0 | 7592dc2 | `PROTOCOL.agent` 改为 4.1.0；使用说明的标题和默认帧说明同步更新。默认帧变成 bb-k-v4s，与现网 4.0 不互通，两端要一起升级 | npm、check 和上一步相同 |

## Fixes

| # | 名称 | 来源提交 | 说明 | 测试状态 |
|---|---|---|---|---|
| X1 | `linux.ipv6=block` 在 redirect、tproxy、tun 三种方法下都生效 | d5752b8 ← 19e9790（P） | 原来只有 tun 生效，redirect/tproxy 下 IPv6 会绕过隧道 | **部分通过**：V1–V5 PASS；iptables 路径和真机 UNKNOWN |
| X2 | 透明 UDP 回包以原目的 ip:port 作源，重编 sockopt .node | 02b37bf ← f354fb1（U1b） | 修 c2c9754 原有缺陷：connect 模式 UDP 和 DNS 不通 | **部分通过**：x64 PASS；arm64 透明收发未验证 |
| X3 | `scripts/lexis-proxy.test.mjs` 的 SO_ORIGINAL_DST 断言 | e094b59（U2 r1 里的测试改动） | 有 conntrack 的环境下，未被改写的连接会返回原始元组；断言改为「null 或等于真实本地目的」。**只改测试，不改产品** | 基线里这一项失败，合并后通过 |
| X4 | SOCKS UDP ASSOCIATE 约 120 s 误杀 | 1a29dcf ← 3A | 关联只按合法 UDP 活动续命，控制 TCP 关闭仍会清理 | 单测 7 项通过。A/B 对比 UDP 错误 4.28%→1.77%，但采样受挂起影响，不算严格复现。**重连门槛 40>24 未通过** |

## 每一步的测试（与 c2c9754 基线对比）

命令是 `npm test` 和 `node public/agent/lexis-agent.mjs --check`，都在 `nice -n 19 taskset -c 0-5` 下运行。日志在 `../logs/`，不随补丁分发。

| 步骤 | HEAD | node --test（scripts） | app-data 等 | lexis-ts | 失败集合 | --check |
|---|---|---|---|---|---|---|
| 0 基线 c2c9754 | c2c9754 | 248 项，过 239，挂 9 | 59/59 | 22/22 | 9 项（见下） | ok |
| 1 bb-k-v4s + 重建 frame | c14b10e | 248 项，过 239，挂 9 | 59/59 | 23/23 | 与基线相同 | ok |
| 2 IPv6 链 P→U2 r2b | c9b0cd5 | 278 项，过 270，挂 8 | 59/59 | 23/23 | 基线的子集（lexis-proxy 转为通过，见 X3） | ok |
| 3 3A | 1a29dcf | 285 项，过 277，挂 8 | 59/59 | 23/23 | 与第 2 步相同 | ok |
| 4 S0 观测 | 29c6c3d | 290 项，过 282，挂 8 | 59/59 | 23/23 | 与第 2 步相同 | ok |
| 5 版本 4.1.0 | 7592dc2 | 290 项，过 282，挂 8 | 59/59 | 23/23 | 与第 2 步相同 | ok |

另外：`tsc --noEmit` 在基线和 HEAD 上都是 0 个错误。

**基线已有、至今仍在的 8 项失败**：都是页面注入或 og 元数据测试，与 lexis 无关，合并没有改动它们。
- document title entities are not double-escaped on og:title
- emits og:image for a public host and prefers a custom card
- injects into documents with no head element
- placeholder og:image appends site.color when it is 6-digit hex
- platform chrome overwrites share-card metas and always sets og:title
- published grok.me slug is still a title fallback
- streaming injector matches </HEAD> case-insensitively
- uses the app name in the injected title tag

IPv6 链第 2 步是整条链应用后跑一次测试，没有在 P、U1、U1b 之间单独跑。

## 冲突与处理
- **cherry-pick ee03fd5**：有 3 处冲突，都在注释或文档里，没有逻辑冲突。处理方式是保留 main 的内容，再加上 v4s 的部分：
  - `src/lib/lexis/spec.ts` 头注释：用 main 的新注释，把默认改成 bb-k-v4s，并说明 bb-k-v4、bb-v4、bb-c8-v4 仍可选。
  - `src/lib/lexis/v2/frame2.ts`：保留 main 的 Dte 注释，首句改为「默认 bb-k-v4s；bb-k-v4 是 4.0.0 默认，现为回退」。`Dte`、`DTES`、`isV4s` 用 v4s 一侧的定义。
  - `public/agent/使用说明.txt`：保留 main 的 4.0 段落。在可选值列表里加 bb-k-v4s（默认）和 bb-k-v4（回退），再插入 v4s 的两段说明。v4s 一侧那份旧的 4.0 长段落没有采用。
- **0e02d5c、IPv6 链、3A、S0**：都没有冲突。IPv6 链用 `git am -3 --exclude='.vercel/*'` 应用，去掉了链里 `.vercel/output` 的两个文件。
- **lexis-frame.mjs**：用 `npx esbuild src/agent/frame.ts --bundle --platform=node --format=esm --target=node22 --preserve-symlinks` 重建。
  - main 自带的 bundle 用 c2c9754 源码重建不出逐字节相同的结果：elligator 模块的位置不同，内容相同。
  - 因此第 0003 号提交里有一段模块位置挪动，属于构建差异，不是代码改动。
  - 版本升级后又重建了一次，结果没有变化，因为 PROTOCOL 不进 bundle。

## 已知缺口
1. **UI 跟进没做（用户定为另做）**：
   - `config-panel.tsx` 的下拉没有 bb-k-v4s，会显示成「实验」。
   - overview、download-page、config-panel 的文案仍写「4.0.0，默认 bb-k-v4」。
   - 浏览器实验室 `handshake.ts` 的 setDefaultDte 是否支持 v4s 还要确认。
2. **下载包和清单仍是 4.0.0**：`public/downloads/manifest.json` 和三个 zip 按决定没有进补丁。下载页显示的版本和包内容要等重新打包后才会变成 4.1.0。
3. **`.vercel/output` 没进补丁**：里面的 sockopt.node 和 sockopt.c 仍是旧版，部署时需要重新构建。
4. **3A**：重连门槛 40>24 未通过，A/B 不是严格复现。
5. **S0**：
   - IPv4 官方判定 FAIL，没有改。
   - 共用链路对照的「无稳定退化」是初步结论：27/120 次超过 240 s deadline，正在补跑。
   - S1–S5、S9a、S8、S9b 都没做。
6. **IPv6 链**：P 的 iptables 路径未测；U1b arm64 透明收发未验证；U1 和 U2 都有 UNKNOWN 项；没有任何一项在真机上验证过。
7. **没有合入**：
   - 3B（验收未完成）；
   - 1B+H（有一档稳定性能退化）；
   - OH、OU 诊断补丁。
8. **F2 词表 `--check`**：本次合并没有重跑，需要在构建机上复核。
