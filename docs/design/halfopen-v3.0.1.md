# 半开连接缓解（3.0.1：V3-5 / V3-5b / V3-6）

用户决定：2026-11-02 02:15 PST。协议号不变，仍为 `lexis-hctr2-rans-v3`；agent 版本 3.0.1。

## 背景
D5 的规则是：每个进入握手的连接占用一个半开名额（全局 `maxHalfOpen=64`，每 IP `maxHalfOpenPerIp=8`），握手失败的连接静默到 `handshakeMs`（10 s）后用 FIN 关闭。因此，攻击者只需 8 个 IP，每 10 s 发 64 个垃圾 hello，就能占满所有名额，合法用户会被拖到超时。此外，静默连接还计入 `maxConns`（128）。

## V3-5：校验失败立即释放名额
- 握手失败（hello 无法解析、admit 不过、peer 未知、重放、finish 失败）时，立即释放全局计数和网段计数。释放操作是幂等的，计数不会降到负数。
- 连接本身照旧：不写任何数据、不读取，到原定截止时间后用 FIN 关闭，所以线上可观察的时序不变（实测 3003–3013 ms，FIN，0 字节）。
- 静默连接的硬上限是 `link.maxSilent`（默认 1024），计数包括超限连接和已释放名额的失败连接。超过上限后，新到的连接会立即关闭。这是唯一一处外部可见的变化，只在洪泛超过 1024 时才会出现。
- V3-5b：静默连接不再计入 `maxConns`，改由 `maxSilent` 约束。否则，名额释放后，`maxConns` 会成为新的瓶颈。
- 资源 [实测]：洪泛下静默连接达到 1024 时，gate 进程 fd 约 1054，RSS 约 150–290 MB（无攻击、跑过 12 次握手时为 233 MB）。[推断] 每条静默连接在用户态约占数 KB；内核接收缓冲区最坏约 1024 × tcp_rmem（默认 128 KB），约 128 MB。
- 新增指标：`lexis_half_open_silent`、`lexis_half_open_early_released`、`lexis_half_open_silent_overflow`。

## V3-6：按网段计数
- `maxHalfOpenPerIp` 的键名保持不变（兼容旧配置），含义改为“每网段”：IPv4 默认 /24，IPv6 默认 /64，分别由 `link.halfOpenPrefixV4` / `link.halfOpenPrefixV6` 配置。设为 32 / 128 即恢复按单 IP 计数。
- IPv4 映射的 IPv6 地址（`::ffff:a.b.c.d`，以及十六进制写法）按 IPv4 处理；带 zone 的地址（`fe80::1%eth0`）会去掉 zone 后再计算；无法解析的地址按原字符串计数。

## V3-8：首字节超时（`link.firstByteMs`，默认 2000，0=关闭）
- 计时从 gate 开始等 hello 的那一刻算起（ws/wss 在 HTTP 升级完成之后才开始计时；升级之前的连接不占半开名额）。如果 firstByteMs 内**一个字节都没收到**，就释放全局名额和网段名额。这次释放和 V3-5 共用同一个只执行一次的 release，不会重复释放。随后连接转为静默，计入 `maxSilent`，仍然到 handshakeMs 再用 FIN 关闭，关闭时序不变。
- **超时后才到达的字节：一律忽略，连接保持静默。** 不解析、不回复、不重新占用名额，仍按原截止时间关闭。理由有两点：一是如果晚到的 hello 还能被处理，攻击者就可以先占位、在第 1.9 s 发 1 个字节来续命；二是让晚到的 hello 去补占名额，会让“名额是否被占”取决于攻击者可控的时间点。晚到的数据仍然受 `HANDSHAKE_CAP`（握手缓冲上限）约束，超过上限会提前断开。这个行为原本就有，与本次改动无关。
- 只要求“任意 1 字节”，不要求完整的 hello。合法客户端在连上之后会立刻发送 hello，所以首字节的到达时间约等于 1 个 RTT 加上首包重传时间。
- 误伤边界 [推断]：Linux 下首个数据段的重传间隔约为 RTO 200 ms 起，按 0.2、0.4、0.8、1.6 s 递增。以 2 s 为阈值时，大约能容忍 RTT 300 ms 加 2–3 次连续重传。弱网实测见 REPORT 第 12 节。高丢包链路（如 15% 以上、RTT 大于 800 ms）建议调到 4000–5000，或者设为 0 关闭。
- 指标：`lexis_half_open_first_byte_timeouts`。
- 备选方案（未采用）：
  - 要求在 firstByteMs 内收齐完整一行 hello：攻击者用 1 字节就能绕过当前做法，这样能防住，但会误伤慢链路。
  - 按网段动态缩短阈值：实现更复杂，而且会形成可探测的状态。
  - 不按时间而按字节速率判断（slowloris 式检测）：需要逐字节计时，收益有限。

## 取舍
| 项 | 得到 | 代价 |
|---|---|---|
| 提前释放名额 | 垃圾 hello 洪泛不再能挤占合法握手（实测 2/12 → 12/12） | 不发 hello 的静默占位连接不受影响（仍会占名额直到超时）；静默连接数需要另设上限 `maxSilent` |
| maxSilent | fd 和内存有硬上限 | 洪泛超过上限后，多出的连接会提前关闭，攻击者可以借此观察到“已满”。这是可区分信号，但只在 ≥1024 并发时出现 |
| 首字节超时 | 只占位、不发数据的连接在 2 s 后就让出名额（“8 段 × 8 只占位”攻击的修复效果见 REPORT 第 12 节） | 攻击者只要发 1 个字节就能绕过，此后仍要等 hello 解析失败才释放名额（即回到 V3-5 的情况：hello 一到、校验失败就释放）；按 1 字节/连接续命，攻击成本仍然很低，所以还需要系统层限速兜底；弱网下首包重传超过阈值会被误伤 |
| 按网段计数 | 同一 /24 内多个 IP 不能叠加名额（实测 0/12 → 12/12） | NAT 或同网段的合法用户共享 8 个名额；攻击者需要 8 个不同网段才能占满 |

## 备选方案（未做）
- **为已知 peer 预留名额**：hello 解密前无法识别 peer（ltC 在密文里），只能按来源 IP 或网段预留，等于把信任交给 IP，攻击者伪造不了 TCP 来源，但可以从同网段发起。用户已决定不做。
- **静默占位（无 hello）提前释放**：例如 1–2 s 内收不到 hello 就释放名额并转入静默。这需要一个“首字节超时”参数，比 handshakeMs 短，会影响高延迟链路。可作为后续选项。
- **SYN/连接速率限制**：交给系统层（iptables hashlimit / nftables meter），不进 agent。
- **改协议的方案**（hello 携带窗口提示、前置 MAC 等）：用户已决定不做。

## 系统层限速（推荐与 agent 内上限并用）
agent 内的上限只能决定“握手要不要处理”。连接数和建连速率应该在内核层面先挡住一部分。以下示例按 IPv4 /24、IPv6 /64 聚合，隧道端口为 18443，请按实际端口修改。阈值要高于合法 NAT 出口的需求，建议先只计数观察，确认后再 drop。

### nftables（已在本机 netns 中实际加载验证：nft 1.1.3，`nft -f` 成功）
```nft
table inet lexis_guard {
  set v4_rate { type ipv4_addr; size 65536; flags dynamic, timeout; timeout 1m; }
  set v6_rate { type ipv6_addr; size 65536; flags dynamic, timeout; timeout 1m; }
  set v4_conn { type ipv4_addr; size 65536; flags dynamic; }
  set v6_conn { type ipv6_addr; size 65536; flags dynamic; }
  chain input {
    type filter hook input priority filter; policy accept;
    tcp dport 18443 ct state new jump lexis_new
  }
  chain lexis_new {
    # 每 /24（/64）新建连接 ≤ 10/s，突发 20（meter / limit）
    add @v4_rate { ip saddr & 255.255.255.0 limit rate over 10/second burst 20 packets } drop
    add @v6_rate { ip6 saddr & ffff:ffff:ffff:ffff:: limit rate over 10/second burst 20 packets } drop
    # 每 /24（/64）并发连接 ≤ 32（ct count）
    add @v4_conn { ip saddr & 255.255.255.0 ct count over 32 } drop
    add @v6_conn { ip6 saddr & ffff:ffff:ffff:ffff:: ct count over 32 } drop
  }
}
```
加载：`nft -f lexis-guard.nft`；查看：`nft list table inet lexis_guard`；删除：`nft delete table inet lexis_guard`。

### iptables（xt_connlimit / xt_hashlimit）
```sh
# 每 /24 并发 ≤ 32
iptables  -A INPUT -p tcp --dport 18443 --syn -m connlimit --connlimit-above 32 --connlimit-mask 24 -j DROP
ip6tables -A INPUT -p tcp --dport 18443 --syn -m connlimit --connlimit-above 32 --connlimit-mask 64 -j DROP
# 每 /24 新建 ≤ 10/s，突发 20
iptables  -A INPUT -p tcp --dport 18443 --syn -m hashlimit --hashlimit-name lexis  --hashlimit-mode srcip --hashlimit-srcmask 24 --hashlimit-above 10/second --hashlimit-burst 20 -j DROP
ip6tables -A INPUT -p tcp --dport 18443 --syn -m hashlimit --hashlimit-name lexis6 --hashlimit-mode srcip --hashlimit-srcmask 64 --hashlimit-above 10/second --hashlimit-burst 20 -j DROP
```
验证情况：这几条规则都通过了 `iptables-translate` / `ip6tables-translate` 的语法解析（1.8.11），转换结果与上面 nft 示例中的 `ct count` 和 `meter … limit` 一致。但本测试机内核没有 xt_connlimit / xt_hashlimit 扩展模块，`iptables -A` 加载时报 “Extension … not supported”，**无法在本机实际加载**。在带这两个模块的常规发行版内核上应能直接使用；如果内核也缺模块，请改用上面的 nft 版本。

注意：
- 被内核丢弃的 SYN 在外部看来是“连接超时”，和 agent 的静默行为并不相同。不过这类丢弃只在超过阈值后才发生，属于已知并接受的可区分性。
- `ct count` 依赖 conntrack，高并发场景需要相应调大 `nf_conntrack_max`。

## 3.0.2：默认值调整（maxHalfOpen 512，maxConns 1024）

**发现（实测）**：半开中的隧道连接在 lexis-agent 里也算 `liveConns`，因此 `maxConns`（旧默认 128）实际把半开数截在 128 以下。只调大 `maxHalfOpen` 没有用：maxHalfOpen=1024、maxConns=128 时，64 个 /24 × 5 条/s 的滚动占位就让合法连接成功率降到 0/24。

**调整**：
- `maxHalfOpen` 64 → 512，`maxConns` 128 → 1024（样例配置一并修改）。
- `maxHalfOpenPerIp` 8（/24、/64）、`maxSilent` 1024、`firstByteMs` 2000、`handshakeMs` 10000 不变。协议号不变。
- 启动时若 `maxConns < maxHalfOpen` 会打一行提示。旧配置里写死 `maxConns: 128` 的要手动改大。

**攻击模型**：每个占位连接只占名额 `firstByteMs`（2 s）。要占满全局名额，攻击者需要同时满足两点：
- 网段数 ≥ maxHalfOpen / 8 个 /24（每段最多 8 个名额）；
- 补开速率 ≥ maxHalfOpen / 2 条/s。

静默连接数约等于速率 × handshakeMs，超过 maxSilent 后提前断开（溢出时可被区分，属已知取舍）。

**扫描**（lxb netns，24 次合法连接，两个 peer 交替，每 peer hello 上限 16 不截断）：

| maxHalfOpen / maxConns | 攻击（/24 × 每段速率） | 总速率 /s | 合法成功 | p95 ms | 峰值 fd | 峰值 RSS |
|---|---|---|---|---|---|---|
| 64 / 128（旧） | 8 × 5 | 40 | 17/24 | 10004 | 432 | 302M |
| 64 / 128 | 16 × 5 | 80 | 2/24 | 10007 | 838 | 255M |
| 256 / 384 | 32 × 5 | 160 | 24/24 | 172 | 1304 | 346M |
| 512 / 1024 | 64 × 5 | 320 | 23/24 | 285 | 1565 | 358M |
| 512 / 1024 | 256 × 2 | 512 | 24/24 | 167 | 1565 | 354M |
| 512 / 1024 | 128 × 5 | 640 | 6/24 | 10014 | 1567 | 335M |
| 1024 / 1152 | 128 × 5 | 640 | 24/24 | 341 | 2073 | 371M |
| 2048 / 2176 | 256 × 5 | 1280 | 24/24 | 254 | 2078 | 395M |
| 512 / 128（只改 maxHalfOpen） | 64 × 5 | 320 | 0/24 | 10004 | 1183 | 246M |

无攻击时基线 RSS 约 300–320M（含词表模型），攻击带来的额外 RSS 约 +15～+75M。

**代价**：fd 上限约为 maxConns + maxSilent + 出站。512/1024 时实测峰值约 1.6k。
- 内核侧（推断）：没有数据的空闲 socket 每个约 2–4 KB（sock + inode + file，接收和发送缓冲按需分配），1.6k 个约 5 MB；TIME_WAIT 小 sock 每个约 0.3 KB。
- 平台：Node 启动时把 RLIMIT_NOFILE 软限制抬到硬限制（实测）。systemd ≥240 的硬限制默认是 524288；旧 systemd 和一些 Android/Termux 环境硬限制是 4096 或 32768；Windows 没有 fd 上限。

选 512/1024 而不是 1024/2048，是为了让最坏 fd（约 2.1k）在 4096 硬限制下仍有余量。内存 1 GB 以上、ulimit ≥ 65536 的服务器可以改为 1024/2048 或 2048/4096。
