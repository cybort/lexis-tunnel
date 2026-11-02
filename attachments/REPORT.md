# lexis-tunnel 1.8.0（e4b3eac）修复与 v2 帧/握手：报告

- 基线：`e4b3eac`（1.8.0）。只在本地改：`/workspace/lexis-test/v18-repo`，分支 `fix/v18`。origin 已删，没有推送，也没有加任何远端。
- 写报告时上游 main 仍是 `e4b3eac`（2026-11-02 用 `git ls-remote` 只读确认），所以下文的“冲突”指的是：1.8.0 相对旧补丁的改动，以及和 1.8.0 设计意图的冲突。
- 标注规则：**[实测]** 是这次在本机跑出来的结果。**[推断]** 是读代码或推理得出的结论，没有运行验证。
- 时间一律用太平洋时间（PST，UTC-8）。box 的时钟显示 CST（+08:00），已经换算。

> **2026-11-02 第二轮（D1–D5，按 7 项拍板）的结果见第 8 节。** 第 0–7 节是第一轮的记录，保留不改；其中关于 honey 停用、maxExpansion 默认 2、P-256 临时密钥的描述已被第 8 节取代。

## 0. 总状态

| 项 | 状态 | 补丁 |
|---|---|---|
| 02 tun 下 UDP 打开失败导致进程崩溃 | 已移植；修复前后都实测 | `02-tun-udp-reject.patch` |
| 03 HTTP 代理出现重复的 Content-Length | 已移植；修复前后都实测 | `03-http-dup-content-length.patch` |
| 04 transparent 入站端口冲突 | 已移植；修复前后都实测 | `04-transparent-inbound.patch` |
| 05 UDP 流不释放，撞上 128 路上限 | 已移植并加强（DNS 5 s 空闲回收 + udpMax）；修复前后都实测 | `05-udp-idle-close.patch` |
| 06 Android VPN 回环 | 已移植；只做了编译检查（apk 已构建，dexdump 确认调用），**运行时未测** | `06-android-vpn-loop.patch` |
| 07 Windows WinDivert 回环 | 已移植；只做了编译检查（zig 交叉编译通过），**运行时未测**，ps1 没有做语法检查（box 上没有 pwsh） | `07-windows-windivert.patch` |
| T19 帧 v2（HCTR2 + 助记码 + 严格计数器 + END 帧 + 密钥确认） | 完成，已集成 | `T19-frame-v2.patch` 和 `T19-T21-integration.patch` |
| T20 语料词表 + rANS（同时做了 GF(2^14) 对照） | 完成，选定 rANS | `T20-corpus-words.patch` |
| T21 Elligator2 hello、ltRaw 不再明文、闸门静默丢弃 | 完成，已集成 | `T21-handshake-v2.patch` 和 `T19-T21-integration.patch` |
| 验收测量 | 完成 | `acceptance-scripts.patch`，结果在 `accept/accept.json` 和 `accept/accept.log` |
| 合并后的测试与 harness | 完成 | 见第 4 节 |
| soak-v18 | **已后台启动** | 见第 5 节 |

`combined.patch` 是 `e4b3eac..fix/v18` 的完整 diff，已确认可以干净地打到 `e4b3eac` 上（`git apply --check` 通过）。`lexis-frame.mjs.bundle.patch` 只包含重新打包出来的 bundle。打包命令：`npx esbuild src/agent/frame.ts --bundle --platform=node --format=esm --target=node22 --outfile=public/agent/lexis-frame.mjs`。

## 1. 第一阶段：移植旧补丁 02–07（01 已在上游修掉，跳过）

六个旧补丁在 1.8.0 上**全部无法直接打上**（上游改过相关代码），都是逐处手工移植的。

### 02 tun 下 UDP 打开失败使 edge 崩溃
- 根因：`lexis-tun.mjs` 的 `onUdp` 里，对端拒绝（例如“这个节点没有出口权限”）时抛出的异常没有被捕获，serveTun 和 packet-bridge 的 push 也没有 `.catch`，于是成了未处理的 rejection，进程退出。
- 改法：`createEngine` 增加 `log` 参数；`onUdp` 加 try/catch；serveTun 的 push 改为 `.catch(...).finally(pull)`；packet-bridge 的 push 加 `.catch`。
- [实测] 修复前（`runs/02-before`）：闸门 `exit:false`，tun 发 UDP 后 edge 因“这个节点没有出口权限”崩溃退出。修复后（`runs/02-after`、`runs/v2-02`）：每个包只记一行“失败：这个节点没有出口权限”，edge 一直活着，DUR 结束时心跳还在。

### 03 HTTP 代理出现重复的 Content-Length
- 根因：上游在 1.8.0 已经部分修过响应侧，但请求侧和响应侧仍会在重新生成 Content-Length 的同时保留原来的那个。
- 改法：在 `lexis-http.mjs` 加 `withoutLength()`，应用到 `kept` 和 `respKept` 上。
- [实测] 修复前（`runs/03/before.txt`）：请求和响应各有 2 行 Content-Length，Node 客户端报 `HPE_UNEXPECTED_CONTENT_LENGTH`。修复后（`runs/03/after.txt`）：各 1 行，返回 200 world。
- **与上游行为的冲突**：上游的 respKept 对“无 body 的响应”（HEAD/204/304）保留原始 Content-Length。现在仍沿用上游的无 body 判断，但原始 CL 一律去掉。也就是说，HEAD 响应不再带上游给出的 CL。需要你决定是否接受。

### 04 transparent 入站和 serveTransparent 争同一个端口
- 根因：serveInbound 也去监听 protocol 为 `transparent` 的入站，和 serveTransparent 抢同一个端口。
- [实测] 修复前（`runs/04-before`）：EADDRINUSE、`proxy :0`，http=000。修复后（`runs/04-after`、`runs/v2-04`）：http=200。

### 05 UDP 流不释放（128 路上限）
- 根因：tun 引擎对每个新的 UDP 源端口（比如每次 DNS 查询）各开一路 mux 流，从不关闭；出口侧的 UDP socket 也永远不释放。
- 改法：
  - tun 引擎加 `udpSeen` 记录、`closeUdp` 和定时清扫。普通流空闲 `link.udpIdleMs`（默认 60 s）后关闭；DNS（53、5353）流空闲 5 s 后关闭。
  - 加 `link.udpMax`（默认 64），超出时最旧的先淘汰。
  - 出口侧空闲超过 2 倍 udpIdleMs 后也关闭。
- [实测] 负载为 380 个流、每 0.5 s 一个、DUR 200 s，统计闸门 UDP socket 数：
  - 修复前（`05-before`）：从 2 涨到 85 以上，最高 129。约 1.5 分钟时 edge 报“这条链路的连接数已满”。
  - 只有 60 s 空闲回收（`05-after`）：最高 **127**，没有崩，但离上限只差 1。
  - 加上 DNS 5 s 和 udpMax（`v2-05`，合并后的版本）：最高 **15**，没有出现“连接数已满”，edge 一直活着。

### 06 Android VPN 回环
- 改法：Kotlin 部分照旧补丁改；vpn-session 改为 `disallowedApps:["com.termux"]`、`excludeRoutes: peerAddrs(config)`。
- [实测，仅编译] 复制 Android 脚手架到 `fixes-v18/android-build`（applicationId 改为 lexis.vpn.v18），离线 gradle `assembleDebug` 成功。apk sha256 为 `33573bb0…b17270`。dexdump 能看到 `addDisallowedApplication` ×1、`excludeRoute` ×2、`addRoute` ×2（`runs/06/apk-check.txt`）。**没有在模拟器上跑**：另一个 worker 正在用那台模拟器，我没有碰。

### 07 Windows WinDivert 回环
- 改法：
  - C 过滤器排除 argv[2..] 给出的闸门 IP 和代理端口。
  - ps1 用 `peerAddrs` 算出 `$gates`；没有 `lexis-windivert.ready` 就不启动 exe。
  - serveTransparent 在 win32 + windivert 时打错误日志。
- [实测，仅编译] `zig cc -target x86_64-windows-gnu` 链接 WinDivert 2.2.2 成功，exe 的 sha256 为 `3b31f8f0…49fea0`（`runs/07/`）。**运行时未测**，ps1 没有做语法检查。

## 2. 第二阶段设计

### T19 帧 v2（`src/lib/lexis/v2/frame2.ts`）

```
inner  = 压缩后的 P ‖ pad ‖ mnemonic(16) ‖ u16be(len P)
cipher = HCTR2-AES256(K_perm, tweak = u64 counter ‖ dir ‖ u32 window ‖ u16 gen ‖ "L", inner)
wire   = rANS(K_lex 词模型)(cipher) → 语料词
```

- **SPRP**：HCTR2，基于 @noble/ciphers 的 AES 分组原语和 POLYVAL，HCTR2 的组装逻辑没有用 Feistel。[实测] 通过官方 350 条测试向量（tweak 长度 0/1/16/32/47，`v2/vectors/`，Apache-2.0）。
- **助记码**：128 位，由 HKDF(sk, "mnemonic", gen) 生成，常数时间比较。HCTR2 是宽块置换，任何一个 bit 的改动都会让整块解出噪声，所以助记码校验通不过。
- **计数器**：计数器不上线，接收方按“上一个 +1”去解。重放、删帧、乱序、方向反射、窗口不对、代际不对，一律校验失败，然后**关闭会话**。计数器跨换钥继续递增，不清零。
- **编码唯一（验收中发现并修复）**：rANS 尾部的虚拟字节不进入密文，导致改动或删掉最后一个词有时仍能通过（2000 次里各有 1 次，[实测]）。现在 openV2 会把解出的密文重新编码一遍，要求和收到的词序列完全一致，因此线上没有可篡改而不被发现的余地。
- **END 帧**：新记录类型 7。shutdown 时先发 END（最多等 500 ms）。没收到 END 就断开算截断，会打日志“词隙会话被截断：对端没有发送结束帧”，`frameStats.truncated` 加一。
- **密钥分离**：perm、lex、pad、mnemonic 四把 HKDF 密钥，标签里带 gen。换钥：`sk' = HKDF(sk, rekeyPayload)`，gen 加一，四把密钥按同样规则重新派生。
- **pad**：长度由 K_pad 和 counter 的 PRF 决定，上限为 `frame.maxExpansion × |P| − |P| − 18`，同时不超过 255。`frame.maxExpansion` 是新配置项（默认 2，取值 1–16），agent 启动和热更新时都会读。

### T20 词表与映射（`v2/model.ts`、`v2/vocab-en.ts`）
- 词表：hermitdave FrequencyWords en_50k 的前 32768 个词，带真实频次。**许可证是 CC BY-SA 4.0（ShareAlike）**，见 `LICENSE-vocab.md`。需要你确认这个许可是否可以接受（冲突点 4）。
- 按 key 打乱：只在频次相差不到 1.5 倍的同档秩内用 K_lex 打乱（每组最多 256 个）。所有词在任何 key 下都存在，所以“这个词不在词表里”不能用来区分。Zipf 曲线保持不变。[实测] 两把 key 前 1000 个秩上相同词的个数为 15（约 1.5%）。
- 实现并测量了两种映射（第 3 节 D）：rANS 和 GF(2^14) 仿射双射。**选 rANS**，原因是 GF 映射产生的是均匀分布的词，Zipf 和长度分布都对不上。
- rANS 终态头部（验收中发现并修复）：
  - 问题：最初直接发 42 bit 的原始终态，[实测] 每帧第 1 个词有 29% 是秩 0 的词，模型给的概率是 4.2%，这是明显的区分点。
  - 原因有两个：rANS 终态近似服从 1/x 分布；尾部虚拟字节填 0，把低位压偏了。
  - 修复：(x>>28, virt) 用 2000 万次仿真测出的分布（`state-table.ts`，生成脚本是 `gen-state-table.ts`；频次表与 key 无关，所以一张表就够）做前缀码，低 28 位原样放，虚拟字节改用按 key 生成的随机字节。
  - [实测] 修复后数据帧第 0–9 位上最常见词的占比为 0.031–0.045，模型的最高词频是 0.042（`F.dataFramePositions`）。

### T21 握手 v2（`v2/handshake2.ts`、`v2/elligator.ts`）

```
hello  = words_H( repC(32) ‖ HCTR2(K_h, "hello"|w, admitC ‖ ltC ‖ nonceC ‖ kdf ‖ feat ‖ pad0..47) )
server = words_H( repS(32) ‖ HCTR2(K_s, "server"|w, admitS ‖ nonceS ‖ kdf ‖ feat ‖ confirmS ‖ pad0..47) )
finish = words_session( HCTR2(K_f, "finish"|w, confirmC ‖ pad0..31) )
```

- **临时密钥**：改为 X25519，并做成“dirty key”（加随机的 8 阶挠点），用 Elligator2 表示，两个逆分支随机选，最高 2 位随机。[实测] 前向映射在 300 个输入上与 noble 的 RFC 9380 `map_to_curve_elligator2_curve25519` 一致；200 对密钥 DH 结果一致；dirty 公钥中有 176/200 不同于 clean 公钥，理论值是 7/8。
- **ltRaw 不再明文**：K_h = HKDF(token ‖ 闸门公钥, salt=repC, "hello|w")，每个 hello 都不同。[推断] 同时知道闸门长期公钥和 token 的人仍然能解出 ltC。要做到对他们也保密，闸门需要一把静态 X25519 密钥（目前闸门静态密钥是 P-256），这是后续可选的工作。
- K_s 还混入了临时 DH 的结果，所以只有真正的 edge 能读懂回包。
- **会话密钥**：ssE = X25519（临时），ssS = 现有的 P-256 静态 ECDH，仍通过 `deriveSessionKeyAsync`（Argon 参数不变）。
- **密钥确认已恢复**：confirmS 和 confirmC = HMAC(HKDF(sk), transcript)，transcript 覆盖 repC、repS、ltC、ltS、窗口、两个 nonce、kdf、feat。
- **闸门静默丢弃**：无法解析、token 错、admit 不对、未知节点、重放、点非法、finish 不对，全部抛同一种 `HandshakeDrop`。`acceptSession` 遇到这种情况什么也不写，一直等到握手截止时间再关闭。[实测] 坏 hello 1501–1502 ms 关闭，什么都不发 1502 ms 关闭（handshakeMs=1500），两种情况的错误一模一样（“握手超时”）。
- 窗口：按 skew 规则尝试当前、前一个、后一个窗口，每个候选都完整解一遍再比较，计算量固定。

## 3. 验收测量（`accept/accept.json`，脚本 `src/lib/lexis/v2/accept/`）[全部为实测]

**A. 用错误密钥解同一帧（3000 把随机错误 key，帧长 364 词，正确的 inner 为 412 字节）**
- 汇总 123.7 万字节的 ent 式统计：熵 7.99985 bit/字节，χ²=261.5（p=0.38），均值 127.56，串行相关 −0.00056。
- NIST SP 800-22 子集，对拼接后的数据做：monobit p=0.49，block-frequency(128) p=0.70，runs p=0.11，cusum p=0.76。
- 每个输出单独做：monobit 通过率 98.9%，runs 通过率 98.8%，同长度真随机对照分别是 99.2% 和 98.7%。
  - monobit p 值均匀性检验 p=0.002。对照组在三轮运行里有两轮也低于 0.001（短序列的 monobit p 值是离散的，这是已知假象），所以这一项不能下结论。
- 区分性：
  - 错误 key 的输出与真随机逐位置比较（前 16 字节加末 18 字节，共 34 个位置），双样本 χ² 最小 p=0.085，没有一个位置 p<0.01。
  - 长度字段“看起来合理”的比例为 0.50%，随机情况下的期望是 0.60%。
  - 错误 key 通过助记码校验的次数：0/3000。
  - 与正确 inner 的汉明距离 0.49992。
  - 两把错误 key 各解 400 帧，输出的双样本 χ² 为 p=0.97，无法区分。

**B. 篡改、删除、重放、乱序（200 帧，每类 2000 次）**：替换一个词、删一个词、插一个词、交换相邻词、重放或乱序、删帧、方向反射，**全部 100% 拒绝**（交换相邻词里两个词相同的情况被跳过，所以实测是 1984 次）。会话层：截断能检测到，END 能被识别，坏 hello 被静默丢弃（`scripts/lexis-v2-session.test.mjs`）。

**C. 膨胀率（maxExpansion=2）**

| \|P\|（压缩后） | inner/\|P\| | 线上字节/\|P\| | 线上字节/inner |
|---|---|---|---|
| 1 | 19（18 字节固定开销） | 83.5 | 4.40 |
| 16 | 2.13 | 9.12 | 4.29 |
| 64 | 1.65 | 6.91 | 4.19 |
| 256 | 1.52 | 6.31 | 4.16 |
| 1024 | 1.14 | 4.74 | 4.17 |
| 16000 | 1.01 | 4.20 | 4.16 |

- 字节层面的膨胀（pad）在所有情况下都没超过 maxExpansion×|P|（`padOnlyBudgetOK`）。maxExpansion=1.25 时 256 字节帧的 inner/P 是 1.16。
- **但线上（词）膨胀约为 inner 的 4.16 倍**：每词 9.45 bit，平均 3.9 个字符再加 1 个空格。**这和“膨胀不超过 2 倍”的要求正面冲突**（冲突点 3）。

**D. rANS 与 GF(2^14) 对比（262144 个随机字节）**

| | bit/词 | 线上字节/字节 | 平均词长 | 词熵 | Zipf 斜率（前 2000） | 秩档 TVD | 词长 TVD | 字母 TVD |
|---|---|---|---|---|---|---|---|---|
| 语料 | — | — | 3.9 | 9.45 | −1.216 | 0 | 0 | 0 |
| **rANS（选定）** | 9.45 | 4.15 | 3.90 | 9.36 | −1.198 | 0.0125 | 0.0107 | 0.0092 |
| GF(2^14) | 14 | 4.33 | 6.58 | 13.92 | −0.10 | 0.73 | 0.53 | 0.13 |

两者速度：rANS 31 ms，GF 12 ms。

**E. hello 和回包的形态**：500 个 hello 全部不同。词数 105–167（标准差 12.8，58 种取值），字符数 531–799（206 种取值）。第 0–7 位上最常见词的占比为 0.034–0.064，最后一个词最高 0.022，两个 hello 的最长公共前缀为 6 个字符。100 个回包：71–122 个词，各位置最高占比不超过 0.10，全部不同。[推断] hello 的长度在约 105–167 词之间，有统计上的范围，但没有固定值，也没有固定位置的标记。

## 4. 合并后的测试与 harness [实测]
- `npm run test:lexis`：admit、honey、kdf、profile 全部 ok；`lexis-agent --check` ok；`scripts/lexis-proxy.test.mjs` 在干净 netns 里 ok（在宿主 netns 里会失败，因为受正在运行的 soak 的 iptables 影响，和以前一样）。
- v2 新增的测试：hctr2（350 条向量）、model（2000 次 rANS 和 500 次 GF 往返）、elligator、frame2、handshake2、session（跨换钥 echo 60 次，到了第 28 代，END、截断、静默丢弃的计时）全部通过。
- `npm test`：189 通过，9 失败（og-meta 相关的 8 个，加上在宿主 netns 里跑的 proxy 测试）。在集成之前的状态下也是同样的 189/9，所以和本次改动无关。注意：这个对照是在“集成前”的状态上跑的，不是严格的 e4b3eac。
- harness（netns lxv-edge/lxv-gate，mark 4713，agent 快照在 `snap/v2`）：
  - redirect：http=200，UDP 5/5（`v2-redirect`）；闸门日志显示流量确实是经隧道出去的。
  - tun：http=200，UDP 5/5（`v2-tun`）。
  - HTTP 代理入站：GET 200；POST 返回 501，这是测试服务器 servers.py 只实现了 GET 造成的，说明请求已经透传到上游（`v2-httpproxy`）。
  - transparent 入站：200（`v2-04`）。
  - 无出口权限：edge 不崩（`v2-02`）。
  - UDP 负载：最高 15 个 socket（`v2-05`）。
- harness 的 netns 已经拆掉；soak 的 netns 保留。

## 5. soak-v18
- 准备脚本：`fixes-v18/soak-v18-prep/prepare.sh`（已执行）；启动脚本：`fixes-v18/soak-v18-prep/start.sh`（已执行）。
- 隔离措施：目录 `/workspace/lexis-test/soak-v18`，netns `lxv-r-edge/lxv-r-gate/lxv-t-edge/lxv-t-gate`，veth `lxv{r,t}{e,g}0`，子网 10.233.x，fwmark 4713 / 表 149。负载和故障计划直接复用 soak 的 bin 脚本，参数和 soak-fix 一样（`runner.sh r|t 86400 0`）。agent 版本是 `3098f32`（见 `soak-v18/AGENT_COMMIT`）。没有碰 soak、soak-fix、lxs-*、lxz-*，也没有碰 4711 和 4712。
- **启动时间 2026-11-02 00:08:45 PST，计划结束 2026-11-03 00:08:36 PST**（24 h）。启动后 60 s 的采样：两个 runner 的 edge 和 gate 都活着，tcp_ok 16、http_ok 9、udp_ok 9、dns_ok 4，错误都是 0。
- 查看进度：`tail /workspace/lexis-test/soak-v18/{redirect,tun}/metrics.csv /workspace/lexis-test/soak-v18/*/runner.log`；汇总可以用 `bin/summary.mjs`（和 soak 的用法一样）。

## 6. 冲突与需要你决定的事（重要）
1. **蜜罐（honey）可否认性 vs T19 的密钥确认和助记码**：1.8.0 有意去掉了密钥确认，honey 模式依赖“错误 key 无法被察觉”。T19 和 T21 恢复了确认，而且助记码会让正确的 key 可以被验证出来。v2 里 honey 已经停用：features 的 honey 位被忽略，`honey:false`，readLoop 里的 honey 分支也去掉了。两者只能选一个，或者把 v2 和 honey 做成按配置二选一。
2. **曲线**：临时密钥从 P-256 换成了 X25519（Elligator2 需要），静态密钥仍是 P-256。线上协议和 1.8.0 **不兼容**，两端必须同时升级。浏览器实验页的 `establish()`（handshake.ts）仍是 v1 握手，没有迁移；旧的 seal、lexicon、honey 模块还留在代码里，但 agent 已经不用。
3. **“2 倍膨胀” vs “低熵词输出”**：字节层面的上限做到了（可配置），线上大约是 4.2 倍。这是信息量决定的：英文词流每个线上字节只能承载约 1.9 bit。要压到 2 倍以内，只能用更高熵的输出（比如 GF 映射或长词），那样就违反 Zipf 和低熵的要求。另外 18 字节固定开销让很小的帧无法满足 2 倍。
4. **词表许可证 CC BY-SA 4.0**：ShareAlike 条款可能会波及分发方式。如果不能接受，需要换一个许可更宽松的语料（脚本是通用的，可以直接替换）。
5. 03 改变了 HEAD 等响应的 Content-Length 行为（见第 1 节）。
6. 闸门静默丢弃会让每个坏连接占着 socket 直到 handshakeMs 到期（受现有 maxHandshakes 限制）。[推断] 这在拒绝服务方面有一点影响。
7. 新增配置项：`frame.maxExpansion`、`link.udpIdleMs`、`link.udpMax`。
8. 06 和 07 只做了编译检查，**没有在 Android 和 Windows 上实际运行**。

## 7. 文件位置和接着做的方法
- 代码：`/workspace/lexis-test/v18-repo`（`fix/v18`，17 个提交，最新 `3098f32`）。v2 的代码在 `src/lib/lexis/v2/`，集成部分在 `src/agent/frame.ts`。
- 产物：`/workspace/lexis-test/fixes-v18/`，包括 *.patch、combined.patch、runs/、accept/、android-build/、harness/、soak-v18-prep/。
- 重跑验收：`cd v18-repo && N_WRONG=3000 node --import jiti/register src/lib/lexis/v2/accept/accept.ts out.json`。
- 重跑 harness：`sudo sh fixes-v18/harness/netns-up.sh`，然后 `AGENT=... METHOD=... ./run.sh <label>`，跑完用 `netns-down.sh` 拆掉（只会动 lxv-edge 和 lxv-gate）。
- 还没做的：06/07 的运行时测试；ps1 语法检查；浏览器实验页迁移到 v2；第 6 节里各项决定；soak 结束后汇总。


## 8. 第二轮：D1–D5（基于 7 项拍板，分支 `fix/v18`，HEAD `d976e42`）

标注同上：**[实测]** 本机跑出来的；**[推断]** 读代码/推理，没跑。时间为 PST。

### 8.0 提交和补丁

| 项 | 提交 | 补丁（`fixes-v18/`） |
|---|---|---|
| D4 词表 CC BY-SA 4.0 署名、NOTICE、许可全文 | `0fea67c` | `D4-ccbysa-attribution.patch` |
| D3 X25519 临时密钥，版本 2.0.0，协议 `lexis-hctr2-rans-v2` | `8673039` | `D3-x25519-v2.0.0.patch` |
| 08 exitUdp 重复 close（来源：**编码执行官 monitoring** 在 soak 监控里发现，不是用户的改动；提交信息里写成了"user's parallel edit"，以此处为准） | `b46a6c5` | `08-exitudp-double-close.patch` |
| D2 握手侧 honey：每次握手新鲜 seed，用临时 DH 秘密加密传送；助记码由 seed 派生；确认值改用秘密做密钥 | `09b5b9e` | `D2-honey-handshake.patch` |
| **D1/D2 共用的帧层集成**（批量容器在 SPRP 内合并/切片、openV2Honey 永不抛错、maxExpansion 默认 5、长度字段不再当预言机、bundle 重建，含 rekey 竞态修复） | `97cebe9` `df74b5a` `fc90726` | `D1D2-integration-frame.patch`（`git diff 09b5b9e fc90726`） |
| rekey 竞态（单独版本，针对 `3098f32` 的旧 writeRecord，便于单独审阅；内容已包含在上面的集成补丁里，不要和集成补丁同时打） | 含在 `97cebe9` | `D1D2-rekey-race.patch` |
| D2b/D1 收尾：长度字段改为携带 pad；maxExpansion 改为线上预算；合并真正生效（setImmediate） | `a305882` | `D1D2b-pad-field-wire-budget-coalesce.patch` |
| D5 半开连接上限 | `da48613` | `D5-half-open-caps.patch` |
| 验收脚本（honey 区分度） | `d976e42` | `accept-honey.patch`；另有 `accept-d/expansion.mjs`、`d5/` |
| 全部 | `e4b3eac..d976e42` | `combined.patch`，[实测] 在 `e4b3eac` 干净 worktree 上 `git apply --check` 通过 |

### 8.1 D5 半开连接上限 [实测]
- 新配置：`link.maxHalfOpen`（全局，默认 64）、`link.maxHalfOpenPerIp`（每 IP，默认 8）。在 `acceptSession` 里计数（进入握手到握手结束/失败），由 lexis-agent 传入；`/metrics` 新增 `lexis_half_open`、`lexis_half_open_refused`。
- 超限时不解析任何内容，读取并丢弃到同一个 handshakeMs 截止时间，然后关闭，和坏 hello / 无 hello 走同一条路径、抛同一个错误。
- **maxConns 也改成静默**：隧道端口上 `admit()` 满了以后不再立刻 destroy，而是带 `refuse` 进入同一条静默超时路径。socks/http/透明入站这些本机端口仍然立即关闭（只对本机暴露，不需要隐藏）。
- 测量（gate 在 netns `lxq-gate`，探测端在 `lxq-edge`，handshakeMs=3000，每种 3 次，`fixes-v18/d5/out/*/result.jsonl`）：

| 情况 | 到关闭的时间 | 收到字节 | 关闭方式 |
|---|---|---|---|
| 坏 hello | 3004–3011 ms | 0 | FIN |
| 无 hello | 3006–3010 ms | 0 | FIN |
| 超全局上限（maxHalfOpen=2，先占 2 个） | 3002–3004 ms | 0 | FIN（gate 日志 refused=3） |
| 超每 IP 上限（maxHalfOpenPerIp=2） | 3004 ms | 0 | FIN（refused=3） |
| 超 maxConns（maxConns=2）**修复后** | 3002–3004 ms | 0 | FIN |
| 超 maxConns **修复前**（`fc90726`） | 2–3 ms | 0 | **RST**（ECONNRESET） |
| 对照：未超限（上限 100） | 3004 ms | 0 | FIN（refused=0） |

- [推断] 静默持有的代价：每个被拒连接占一个 socket 到 handshakeMs。被 maxConns 拒绝的连接不计入 liveConns，所以理论上可被大量连接占住 fd；建议配合系统层 SYN/conn 限速。这是"行为一致"和"资源立刻释放"之间的取舍。

### 8.2 D1 膨胀率 [实测]（`accept-d/expansion.json`，真实 LexSession 对，随机不可压缩负载，maxExpansion=5）
口径：线上字节（词+空格）/ 应用层负载字节。"单发"=每次写完等它发出；"8 连发"=同一 tick 发 8 次写。

| 档位 | 单发 均值 / p95 / 最大 | 单发每写帧数 | 8 连发 均值 / p95 / 最大 | 连发每写帧数 | ≤5× 占比（单发/连发） |
|---|---|---|---|---|---|
| 1–64 B | 15.4 / 39.3 / 172 | 1 | 7.1 / 8.3 / 10.2 | 0.125 | 0 / 0 |
| 65–256 B | 5.36 / 6.06 / 6.47 | 1 | 5.11 / 5.44 / 5.63 | 0.24 | 16% / 33% |
| 257 B–1 K | 4.80 / 5.15 / 5.37 | 1 | 4.70 / 4.87 / 4.95 | 0.49 | 78% / 100% |
| 1–4 K | 4.46 / 4.83 / 5.06 | 1.00 | 4.42 / 4.51 / 4.53 | 1.00 | 99% / 100% |
| 4–16 K | 4.34 / 4.47 / 4.53 | 2.98（切片） | 4.32 / 4.35 / 4.35 | 3.02 | 100% / 100% |

- **本轮发现并修掉的问题** [实测]：第一轮交付的合并实际上不生效，8 连发时每写 1.00 帧。原因是 drain 用 microtask 调度，第一条记录（异步 packRecord）一到就发走了。改成 setImmediate 后连发每写 0.125 帧（小包），见上表。
- maxExpansion 改为**线上**预算：pad 预算 = 5×|P|/4.16 − |P| − 18（4.16 是实测的每内部字节线上字节数）。之前它约束的是加密前字节，线上实际会到 4.16×5。
- 小帧达不到 5×：每帧固定开销（18 B 助记码+长度、4 B 段头、记录头）编码后约 100+ 个字符，1 字节负载就是 ~170×。这是固定开销决定的，只能靠合并缓解（连发后 1–64 B 降到 ~7×）。[推断] 交互式小包（如 SSH 按键）仍会远超 5×。
- 长度指纹：连发帧和单发帧使用同一个 pad 公式，帧长只取决于"批大小 + PRF pad"；切片帧（4096 B 上限）的词数也由 pad 打散（4–16K 档 p50≈3545 词，单发 156 个不同长度、连发 260 个）。各档单发/连发的词数分布 p5/p50/p95 见 `expansion.json` 的 `lens`。[推断] 没有新增固定长度的帧类型；但"满 4096 B 切片帧"在长度上聚在 pad 宽度（≤255 B）以内，这和以前大记录的情况一样，不是本轮新增的。

### 8.3 D2 honey 区分度 [实测]（`accept-d/honey.json`，每档 1000 对：同一帧分别用正确密钥和随机错误密钥解）

| 档位 | formatValid（真/错） | pad 占比均值（真/错） | 仅 pad 占比 AUC | 不含正文结构、不含规范性 AUC | **仅规范性 AUC** | 正文能解析成批量容器（真/错） |
|---|---|---|---|---|---|---|
| 1–64 | 1.000 / 0.029 | 0 / 0.51 | 0.973 | 0.977 | 0.983 | 1 / 0 |
| 65–256 | 1.000 / 0.020 | 0.037 / 0.51 | 0.961 | 0.961 | 0.988 | 1 / 0 |
| 257–1K | 1.000 / 0.021 | 0.075 / 0.21 | 0.785 | 0.780 | 0.987 | 1 / 0 |
| 1–4K | 1.000 / 0.022 | 0.053 / 0.055 | **0.529** | **0.512** | 0.987 | 1 / 0 |

- 助记码（16 字节，用候选密钥的词模型渲染成词）：真/错都 100% 在语料内，每个助记码平均 14.64/14.66 词，前 300 词 Zipf 斜率 −1.032/−1.039，按秩分档卡方 61.8（df 78，p=0.91）。**助记码本身分不开。**
- pad 占比（第一轮标出的残余信号）：`df74b5a` 的方案下 1–4K 档 AUC 0.946（真 0.052 vs 错 0.497，`accept-d/honey-before-D2b.json`）。本轮改成长度字段携带 pad（pad = 字段 mod (min(255,C)+1)），**大帧降到 0.529（基本随机）**。小帧反而更明显（0.97），因为线上预算下小帧的真实 pad 是 0，而错误密钥解出的 pad 是均匀的。这是"小帧不加 pad 以控制膨胀"和"错误密钥的 pad 分布要和真的一样"之间的直接矛盾；合并后小帧变少，但没有消除。
- **新发现，最重要：规范性（canonical）检查是一个强密钥确认信号。** 词→字节→词的重编码在正确密钥下 100% 一致，在错误密钥下只有约 2–3% 一致（AUC≈0.987，单帧即可）。原因：rANS 词模型是按密钥构造的，错误模型解出的字节再编码回来，词序列通常不一样；第一轮 docstring 里"规范性只取决于线上文本、与密钥无关"的说法是错的（已在本报告更正，代码注释待改）。持有候选会话密钥的攻击者不需要看正文结构，单看这一点就能确认候选密钥。[推断] 要去掉它，需要一个对任何密钥都是双射的词映射（例如第一轮评估过的 GF(2^14) 双射，代价是线上熵更高、Zipf 更差），或者让 rANS 编码对所有模型都规范；两者都是协议改动，需要你决定。
- 正文结构：真密钥解出的正文 100% 能解析成批量容器（段头、记录头），错误密钥 0%。这是已知边界，见 8.4。
- 篡改套件 [实测]（`accept-d/accept.log`，N_WRONG=1000）：换词 2000/2000、删词 2000/2000、插词 2000/2000、相邻交换 1983/1983、重放/乱序 2000/2000、删帧 2000/2000、方向反射 2000/2000 全部拒绝；截断由 session 测试验证（无 END 帧计为 truncated）。错误密钥原始输出熵 7.9992 bit/B，卡方 p=0.23，NIST monobit 0.18；两把错误密钥互比卡方 p=0.51。hello 500 个全不同，词数 106–163；server 100 个全不同。

### 8.4 安全边界（谁能知道/验证什么）
- **只有 token**：[推断] 不能解 hello 里的长期公钥（K_h 还需要闸门公钥）；不能推出任何会话密钥或助记码（需要临时 DH）。可以在线探测闸门，但每次失败都静默且等长超时，并受 D5 每 IP/全局上限限速。
- **只有闸门公钥**：同上，不能解 ltRaw（缺 token），不能推会话密钥。
- **token + 闸门公钥**（已知项，用户决定维持现状）：[推断] 能离线解开每个 hello 里的 ltC（edge 长期公钥），从而识别是哪个 edge；反过来，持有闸门公钥和一个已知 edge 公钥的人可以**离线验证 token 猜测**（ltRaw 离线预言机）。仍然推不出会话密钥/助记码。
- **完整握手记录 + 长期私钥**：[推断] 临时 X25519 密钥用完即弃，所以拿不到历史会话密钥（前向保密）；助记码来自新鲜 seed，在临时 DH 下加密，同样推不出。
- **持有一个候选会话密钥的人**（honey 的场景）：可以用 ①规范性检查（AUC≈0.99，单帧）②正文结构（批量容器/记录头/zstd 魔数，100%）③小帧的 pad 占比 来确认候选密钥是不是真的。**honey 在这一层是失效的**：错误密钥能解出格式和统计上像样的助记码，但不能经受上面三种检查。
- **在线探测**：每次猜测都要一个完整的握手超时，受 D5 限速；外部看不出是哪一种失败。

### 8.5 测试 [实测]
- `npm test`：199 个，190 通过，9 失败。9 个都是和本项目无关的 og-meta/HTML 注入测试，加上在宿主 netns 里跑的 `lexis-proxy.test.mjs`（和第一轮同样的 9 个）。日志 `accept-d/npm-test.log`。
- `npm run test:lexis`：在干净 netns `lxq-clean` 里全部通过（exit 0），日志 `accept-d/test-lexis.log`。
- v2 单元测试：frame2、handshake2、hctr2（350 个官方向量）、model（2000 rANS + 500 GF 往返）、elligator、`scripts/lexis-v2-session.test.mjs`（回显、3 代 rekey、END、截断、坏 hello 1500 ms vs 无 hello 1502 ms）全部通过。
- harness（自建 netns `lxq-edge/lxq-gate`，fwmark 4715，`fixes-v18/harness-q`，结果 `runs-q/`，**跑完已拆除，`ip netns` 里无 lxq-*）：redirect http=200；tun http=200 + UDP 5/5；HTTP 代理入站 200；transparent 入站 200；无出口权限 http=000 且 edge 不崩；全部 self_conn_12345=0。
- Android：离线 gradle `assembleDebug` 通过（kt 本轮没改，apk sha256 不变 `33573bb0…b17270`）。Windows：`zig cc -target x86_64-windows-gnu` 链接 WinDivert 2.2.2 通过，exe sha256 `ef406ff0…73ac1a1`（`accept-d/`）。**两者都只验证到编译通过**，没有运行。

### 8.6 soak-v18b [实测]
- 准备/启动脚本：`fixes-v18/soak-v18b-prep/`（由 soak-v18 的脚本改名得到）。目录 `/workspace/lexis-test/soak-v18b`，netns `lxw-{r,t}-{edge,gate}`，子网 10.234.x，fwmark 4714 / 表 150。负载与故障计划和 soak-v18 相同（`runner.sh r|t 86400 0`）。
- agent 提交 `d976e42`；bundle 已重建并确认变了：`lexis-frame.mjs` sha256 前缀 `1397865d7566`（soak-v18 用的是 `917ceeae844b`），`lexis-agent.mjs` `ad284f534605`（soak-v18 是 `e573b06c2536`）。
- **启动 2026-11-02 01:02:21 PST，计划结束 2026-11-03 约 01:02 PST。**
- 第 180 s 采样：redirect —— edge/gate 存活，RSS 125/125 MB，fd 38/35，tcp_ok 64，http_ok 33，udp_ok 31（udp_err 2），dns_ok 15（dns_err 1），edge 错误行 1，重启 0。tun —— 存活，RSS 126/124 MB，fd 32/45，tcp_ok 64，http_ok 33，udp_ok 33，dns_ok 16，错误 0，重启 0。
- **soak-v18 保留作对照，跑到底**（计划 2026-11-03 00:08 PST 结束）。理由：它是第一轮代码（无 D1–D5、有 rekey 竞态）的基线，可以直接和 soak-v18b 对比 rekey 引起的 integrity 断线和 fd/RSS 走势。soak、soak-fix、soak-v18 及其 netns/mark 都没有碰。

### 8.7 已知项（用户未要求，维持现状）
- HEAD 响应不再透传 Content-Length（补丁 03 的副作用）。
- ltRaw 在同时持有闸门公钥和 token 时可解开（见 8.4，并构成 token 离线验证预言机）。

### 8.8 冲突与需要决定的事
1. **honey 的规范性预言机**（8.3）：当前设计下持有候选会话密钥即可确认，需要决定是否换双射映射。
2. **小帧 pad 和 honey 的矛盾**（8.3）：小帧不加 pad 以控制膨胀，导致 pad 占比可区分。
3. **5× 上限对小帧做不到**（8.2），只能靠合并缓解。
4. `public/downloads/manifest.json` 的 version 写的是 2.0.0，但三个 zip 的 bytes/sha256 还是 1.8.0 的包，没有重新打包。发布前需要重打包并更新哈希。
5. **浏览器实验页仍是 v1 握手**（`handshake.ts` 的 `establish()`）。移植到 v2 需要 X25519+Elligator2、HCTR2、rANS 词模型和新的帧容器在浏览器里实现/打包，工作量不小，**本轮没有做**。2.0.0 的 agent 和浏览器实验页互不兼容。
6. 2.0.0 和 1.8.0 线上不兼容，两端必须同时升级（D3）。
7. 用户并行改代码：本分支只在本地；`b46a6c5` 的提交信息把来源写成了用户，实际来源是编码执行官 monitoring。和上游的冲突需要在上游有新提交后再核对（本轮没有拉取上游）。
