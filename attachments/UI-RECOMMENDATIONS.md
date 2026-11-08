# 4.0 线上演示与配置页修改建议（未改页面/未部署）

## 当前缺口与文件位置
| 文件 | 当前状况 | 建议 |
|---|---|---|
| src/components/lexis/overview.tsx:15、20、72 | 仍写3.0/3.0.4兼容、词表随会话密钥打乱 | 改为4.0开发版/K默认，公开且与密钥无关的词模型；保留平台实测边界，勿宣称已实现真实VPN或已验证客户端RST |
| src/components/lexis/bench.tsx:84–138、387附近 | establish3/sealV2实际会调用合并后的v4代码，但日志仍写3.0 HCTR2+rANS；没有传profile.frame.dte/dteCheck | 显示实际选择、握手检查状态和协议名；执行握手前同步明确的dte/check选项；配置变化清空旧会话并重新握手，不能拿旧keys展示新选项 |
| src/lib/lexis/handshake.ts:452–507 | 浏览器的establish3在同一JS上下文模拟双方，使用全局默认选项 | 最小方案：演示只支持双方相同选项，串行握手前设置默认值；明确不能凭这一条路径演示双方配置不一致。更稳方案：把DTE/check放进每端握手上下文，或隔离worker，避免异步交错；后者改动更大但可可靠演示错配，建议中期做 |
| src/components/lexis/config-panel.tsx:598–630 | frame区只有膨胀、小帧策略、合并目标 | 增加frame.dte选择和frame.dteCheck开关；实验DTE折叠，A1标“不推荐”并二次提示 |
| 同文件:783–800 | **3.0.4已添加5项tun控件，不要重复加** | 保留现有输入、失焦校验与mss空值语义，补准确单位/适用平台/默认值说明；见下表 |
| src/lib/lexis/profile.ts:120、246、703–709 | frame类型/default/frameOf没有dte和dteCheck；tun类型/default/normalize已存在 | 扩展frame类型、默认和白名单校验，未知DTE报错而不是悄悄替换；保留缺省向后兼容。新增导入→normalize→持久化→导出的往返测试 |
| src/lib/lexis/profile-store.ts、config-panel.tsx:930、profile.ts:413 | 配置通过normalizeProfile进入持久化/导出链 | 确保新键不丢失，profile版本迁移沿现有机制；实测当前normalize把dte=rans-v3/dteCheck=false都丢掉（profile-dte-loss.log） |
| public/agent/lexis.config.json、使用说明.txt | agent运行时支持4.0键，但样例未明确展示；v4旧文档还写“握手完全相同”和“只设rans-v3即可互通” | 样例显式列dte/check，修正文案为“线格式不变，但默认密钥确认绑定DTE”；删除旧的互通结论冲突 |
| src/lib/lexis/spec.ts、v2/frame2.ts注释、docs/design/frame-v4-*.md | 有“handshake unchanged”/“bb-v4(default)”遗留注释 | 改成K默认与dteCheck条件，协议名用protocolName(selectedDte)，不要写死rANS或bb-v4 |
| src/components/lexis/download-page.tsx:84、public/downloads/manifest.json | 当前实际下载包仍是3.0.4 | 未发4.0前保持真实包版本，标“演示4.0开发协议；下载包3.0.4，默认不互通”；不要只改标签伪装4.0。发版须另获授权，重新生成对应构建物，不在本次做 |

## 控件、默认值和建议文案
| 键 | 默认/范围 | 说明文案 |
|---|---|---|
| frame.dte | bb-k-v4；白名单使用frame2.ts的现有DTES | “默认方案K：密钥派生尾部并重封校验。两端必须相同，线上不协商。”常用只露K与rans-v3；bb-v4/A1/A2/A3/A4移高级实验区 |
| frame.dte=bb-c8-v4 | 非默认，不推荐 | “A1存在残余可塑性：本轮单词篡改19/6000仍被接受；K为0/6000。测试结果不是安全性证明。不建议生产使用。”不要称A1已修或同等防篡改 |
| frame.dteCheck | true，布尔 | “握手密钥确认绑定DTE；不一致时内网端确认失败后关连接，闸门只回一次应答，释放半开名额后静默到超时。线格式不变。两端开关必须相同；关闭仅供旧版兼容/诊断。”不写成gate立刻发错/立刻断开 |
| tun.mtu | 1500；576–65535 | “用户态TCP宣告MSS的基准（默认MTU−40=1460），不是自动修改系统网卡MTU。Android缺少tun.mtu时运行时可退回android.mtu；页面导出明确值后优先tun.mtu。”避免与android.mtu混为同一控件 |
| tun.mss | null/留空；显式88–65495 | “留空自动按tun.mtu−40；填写则覆盖宣告段长。实际发送取本地值与对端MSS较小者；对端不报MSS时按536。不要默认填1200。”0/空值存成null；不写入字符串空值或NaN |
| tun.oooMaxBytes | 65535；0–65535字节/流 | “每流乱序数据字节上限；0不缓存乱序正文。固定接收窗口65535，不代表支持窗口缩放。” |
| tun.oooMaxSegs | 64；0–4096段/流 | “每流乱序段数上限；0禁用乱序正文缓存，超限优先丢离缺口最远的段。”与读包队列64包是不同参数 |
| tun.oooTotalBytes | 8388608（8MiB）；0–1073741824字节/引擎 | “共享乱序缓存总预算；0不保留乱序数据。多个进程各有自己的预算，并非整个操作系统唯一上限。”界面同时显示字节与MiB |
| 现有frame.maxExpansion/smallFramePolicy/coalesceTarget | 5 / expansion / 1024 | 保持默认，不把K切换与调优混为一谈；现有tun重传无需新造开关，勿把未暴露的内部常量做成假控件 |

取舍：DTE选择放高级区，默认K+check=true，避免普通用户误选弱变体；旧3.0互通用独立明确的兼容预设（rans-v3 + dteCheck=false），而不是把默认安全校验关掉。老3.0端没有DTE transcript绑定，**只设rans-v3不够**；两端均4.0时仍推荐check=true。

## 建议直接采用的概要文案
“本页演示4.0开发协议，默认bb-k-v4（方案K）。帧词模型公开且与密钥无关；密钥参与尾部生成和完整性检查。A1（bb-c8-v4）有残余可塑性，不推荐。默认frame.dteCheck=true，在握手密钥确认中校验DTE。两端DTE和检查开关须一致。当前下载包仍为3.0.4时，默认不能与此4.0演示互通；旧版兼容需在4.0端显式选择rans-v3并关闭dteCheck。浏览器演示不等于已接管真实系统流量。”

## 页面验收建议（等补测后实施）
1. 新/旧配置导入、非法DTE报错、dteCheck=false、mss=null/0/空和全部tun边界，导入导出不丢键。
2. K默认、双方同配通过、DTE/开关错配失败，选项变化旧会话失效；若无独立双方状态，明确只展示同配路径。
3. 模拟A1/K的固定规模篡改测试，不把0次误收写成数学保证；日志显示选择的真实DTE。
4. 浏览器回退路径和Node native路径分别检查；下载版本/协议/说明/manifest一致。Windows/Android未补测的继续明确标注，禁止本机启动Android模拟器。
