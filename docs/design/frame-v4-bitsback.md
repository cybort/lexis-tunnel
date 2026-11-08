# 帧词编码 v4 bits-back（frame.dte = bb-v4）

协议 `lexis-hctr2-bb-v4`，讲的是 A0，不是 4.0 默认。4.0 默认是 `bb-k-v4`（`lexis-hctr2-bb-k-v4`，见 frame-v4-k-tail.md）。握手报文的布局和长度与 3.0.x 相同，没有新字段。默认 `frame.dteCheck=true` 时，`frame.dte` 绑进密钥确认，和 3.0.x 的 transcript 不同。只把 dte 设成 `rans-v3` 不够，还要 `frame.dteCheck=false`。

## 为什么不用 feat/v4 的 B1（rans-v4）
B1 让词模型与密钥无关，消除了持候选密钥者的重编码泄露，但词模型一公开，观察者也能做 词→字节→词：真帧除状态头/尾外逐词复现，任意文本复现不了（合成分类器 AUC≈0.95）；状态头和末词分布也可区分（≈0.66）。根因是 rANS 映射不是满射，且有一个要单独编码的终态。

## bb-v4 做法
- **一个公开模型**（语料词序，频率表与 v3 相同，24 bit）。
- **区间划分**：每个词串对应 [0,1) 的一个子区间，用 48–53 bit 整数 range 精确切分；每次切分的余量归给最常见的词，所以兄弟区间恰好铺满父区间（无空洞）。
- **接收端解析（全函数，满射）**：`n = bytesForWords(m)`（m = 词数），密文 C = 词串区间左端点的前 8n 位。任何词串都能解析，从不报错。
- **发送端**：选 m 使 `bytesForWords(m) = n`；取点 u = C ‖ CSPRNG 比特，在 u 处解出 m 个词；若解析回来不等于 C（区间跨了格子边界，约 1e-5）就换随机尾重来。
- **满射性**：对任意词串 W，C = parse(W) 时 W 的左端点落在 C 的格子里，取 u = 左端点即可让发送端输出 W。所以“W 是否为合法编码”对任何人、任何文本都恒为真（`bbInSupport`）。
- **没有状态头、没有终态**：帧长由词数给出；密文以下全是 CSPRNG 比特，相当于 rANS 初态被随机比特填满、终态不需要传，所以评审说的“初态常数 / 终态对数偏斜 / 尾部填充边界”都不存在。词串等于模型下的独立同分布抽样，只受极少数重试影响。
- **长度可表示性**：`bytesForWords(m) = floor((μm − 4σ√m − 24)/8)`（μ=9.44、σ=3.82 bit/词）。少数 n 不可表示（间隙 1 字节），发送端把 pad ±1 对齐，长度字段照常携带 pad。

## 代价
- **膨胀**：为保证 m 个词的信息量足够（4σ 余量），词数比 rANS 多：大帧约 +4%，19 B 小帧 28 词（rANS 约 17 词）。实测见 REPORT 第 16 节。
- **可塑性**：密文 8n 位以下的末尾几个词只承载随机比特，换掉后可能解析出同一密文（明文仍由 HCTR2 + 助记码认证，计数器防重放）。这是“编码带随机性 + 满射”的必然结果。
- **CPU**：解析用 BigInt 维护左端点，4 KB 帧约数 ms（B1 rANS 约 0.4 ms）。
- 小帧 pad 占比、正文结构仍是已接受边界，不受 DTE 影响。

## 备选
- `rans-v3`：保留，与 3.0.x 数据帧互通，带重编码泄露。
- B1（feat/v4 的 rans-v4）：持密钥视角干净，但观察者可无密钥识别协议，弃用。
- B2 精确大整数区间编码：O(n²)，弃用。
- 方案 A（GF(2^24) 同音桶）：每词 24 bit，膨胀约 2.5 倍，破 5 倍上限。
- 方案 C（bigram DTE）：只估算，见 REPORT 13.1。

## 切换
`frame.dte`：`"bb-k-v4"`（4.0 默认，方案 K） | `"bb-v4"`（本文件，A0） | `"rans-v3"`（数据帧与 3.0.x 相同；和 3.0.x 握手还要 `frame.dteCheck=false`） | `"bb-c8-v4"` `"bb-ou-v4"` `"bb-ouc8-v4"` `"bb-ouc8r-v4"` `"dfa-v4"`（见 frame-v4-a1-a4.md）。两端必须相同，线上不协商。未知值拒绝启动。

## Pad budget (bb-v4)
bb-v4 carries a fixed ~24-bit + 4σ√m information margin, so short frames cost more words than rANS.
`padLength` therefore checks the real word count (`wordsForBytes`) × 4.89 wire bytes/word against
`maxExpansion·|P|` instead of the rANS constant 4.16 bytes/inner byte. Measured single-frame means:
1-64 19.0×, 65-256 5.98×, 257-1K 4.95×, 1-4K 4.61× (cap met 0/0/57%/96%). Small frames are dominated by
the fixed margin + 18 B overhead and cannot meet 5× at any pad; burst coalescing (8 frames) gives 7.4/5.3/4.8/4.5.
