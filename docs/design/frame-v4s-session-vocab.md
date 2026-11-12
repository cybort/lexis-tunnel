# frame.dte = bb-k-v4s：共用允许词表 + 会话组内打乱（方案 D / D-pool）

状态：next-4.x 本地分支实现，未合并。

## 做了什么

- 编码与 bb-k-v4 相同：HCTR2 → bits-back 满射区间编码 → 带钥规范尾（K_tail AES-CTR），收端重封比对。
- 词表来源换成产品内置的**全体会话共用允许词表** `src/lib/lexis/v2/vocab-allowed.ts`：
  FrequencyWords en_50k（与 vocab-en.ts 相同来源与清洗规则），构建时去掉一小批指定整词，其余全部保留（46,701 词）。
  包标识 `fw50k-all-d1-gf`，由 dte 取值隐含，线上不协商。文件内带来源 sha256 与词表 sha256。
- 频率表只由允许词表的语料频次决定，与密钥无关，并且**组内拉平**：同一组内每个词取相同的量化频次（组总频次 / 组大小，四舍五入；凑整余数精确加在前两个大小互素的组上，合计恰为 2^24）。所以会话打乱不改变任何词的出现概率，持候选密钥者无法用似然检验确认密钥。MU/SIG（bits-back 长度字段）由同一频率表算出。
- 会话密钥只决定**频次相近组内**的词序（相邻频次比 ≤1.5、每组 ≤256，与 4.0 分组规则相同）。没有秘密子集：每个会话模型都包含全部允许词。
- 派生：
  - 数据帧、finish：`buildModelS(HKDF(sk, "", "lexis-v4s-lex"), HKDF(sk, "", "lexis-v4s-pad"))`，sk 为握手后的会话主密钥，不用 wordsIkm。
  - hello / 闸门回包：沿用 v3 hello 标签，从 wordsIkm 派生，但模型建在允许词表上。
- 构建脚本 `scripts/build-vocab-allowed.mjs` 只在构建机运行，需要构建机本地的排除清单（不随产品分发，不进仓库）。`--check` 可复核生成文件。

## 互通

- 与 bb-k-v4 及其它 dte 不互通。hello 词表不同，混用在 hello 即失败关闭：闸门认不出 hello，按坏令牌静默处理（0 字节，保持到握手超时），edge 超时失败。与 frame.dteCheck 开关无关。
- 回退：两端同时显式设 `frame.dte = "bb-k-v4"`。

## 已知限制

- 去掉的整词可通过与上游 FrequencyWords 对比恢复（见 vocab-allowed.NOTICE.md）。
- 组内拉平使单词频次相对语料略有偏差（组内比 ≤1.5，数据见交付包 TEST-REPORT.md）。持候选密钥者仍可用 K 尾重封确认密钥（4.0 已接受）。
- hello / 闸门回包 / finish 的 rANS 头部前缀码长度在组内不完全相等，头部几个词仍有极小的组内位置差；这些帧在 4.0 已可被 rANS 规范重编码确认，不是新路径。
- bits-back 编码在约 5e-6 的帧上确定性失败（4.0 bb 系列已有），建议在 sealV2 换长度字段代表重试。
