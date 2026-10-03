# HostRouteManager 第一步审查

审查对象：[第一步审计与契约](host-route-manager-step1-audit-and-contract.md)。

审查基线：本地 `main` / `a017dc13`；对涉及 DNS 分支的描述另检查 `feat/dns-policy` / `2569f35f`。2026-10-03 完成静态文档、源码和部分官方 API 文档核对，未修改被审文档，未执行系统路由操作或平台运行测试。

**结论：需要修改，目前不能标记“契约已冻结”，不建议按此文档直接开始第二步。** 总体分层可以保留，但存在 6 项 P1 契约/迁移阻塞问题，另有 2 项 P2 需要补齐。优先级反映按文档实施的风险，而不是当前程序新引入了这些缺陷。

## R1 — P1：manual_routes 的作用域被扩大为全部宿主路由

**位置：** 被审文档第 130–135、279–301 行，尤其第 133 行“0 条业务路由”和第 299–301 行“本机不作为子网网关”“保持 0 路由状态”。

**问题：** 当前 `manual_routes` 只覆盖 proxy CIDR 路由来源的结果，不是清空所有来源的开关，也不控制本节点是否向别人提供子网代理。将其解释为全局禁用会撤销独立的 DNS、接口连通需求或 public IPv6 出口。

**源码证据：**

- `easytier-core/src/gateway/proxy/cidr_monitor.rs:76`：只在 `resolve_proxy_cidrs` 内用手工集合替换 peer CIDR 集合。
- `easytier/src/instance/virtual_nic.rs:1165`：public IPv6 地址/默认路由任务独立运行，不读取 `manual_routes`。
- `easytier/src/instance/dns_server/server_instance.rs:377`：DNS `/32` 的条件是 fake IP 是否处于 TUN 子网和是否存在接口，不受 `manual_routes` 控制。

**反例：** 开启 Magic DNS/public IPv6，并设置 `routes = []`。现有行为是停止自动 proxy CIDR 安装；按文档实施则可能连 DNS 和公网 IPv6 一起断开。

**修改要求：** 给每个配置项规定确切的来源作用域。冻结为 `Some([])` 清空“被 manual_routes 覆盖的那组需求”，其他来源独立计算；本地代理发布、转发能力与宿主路由安装分开描述。若希望引入全局禁用行为，必须使用独立配置和明确的行为变更说明。

**验收反例：** 自动代理、手工路由、DNS、接口前缀、public IPv6 同时存在时，分别切换 `None`、空集合和非空集合，列出每个来源的期望结果。

## R2 — P1：RoutingDomain、ResourceScope 和 InterfaceBinding 被合并，单写者边界不成立

**位置：** 第 175–185 行；第 329–330 行；第 233–234 行。

**问题：** Linux 用 netns + table 当协调域，Windows 用 LUID + AF，Android 用当前 VpnSessionId；然后按这个同一 Scope 建协调器、抢跨进程锁。表和接口是域内资源，VPN 会话则会随重建改变，不能同时充当稳定协调域。

**反例：**

- Linux 两个实例处于同一 netns 的不同表，却要修改同一套 policy rules，按当前域划分无法协调规则优先级冲突。
- 两个进程各自使用不同 TUN、同一个 main 表：按整个 netns+main 的排他锁，第二个实例直接 `ScopeBusy`，阻断原本可行的并行运行。
- Windows 两个接口被分给不同协调器，但路由仍共同影响同一网络环境的选路；跨接口的需求冲突不进入同一协调层。
- Android 重建会话产生新 SessionId：若协调域跟着换，旧操作及恢复记录失去稳定的接管者。
- 同一路由域同时有 no-TUN 和正常实例时，第 329 行给“该路由域”绑定 NoTun 后端，会与正常实例的执行能力冲突。

**修改要求：** 至少分开稳定的路由域、实例所有权作用域、带代际的接口/会话绑定、路由/规则身份。进程内在稳定域内协调冲突；跨进程互斥限制实际可独占的资源作用域，不对共享主表粗粒度独占。no-TUN 是实例执行资格，不改变同域其他实例的后端。明确“撤销实例句柄”和“关闭整个域服务”的区别，以及共享需求最后一个引用释放才允许清理。

**验收反例：** 同域双实例、跨进程不同 TUN、不同表共享规则、VPN 会话重建、一个实例退出及 no-TUN/有 TUN 混合。

## R3 — P1：归属流程允许凭旧记录覆盖外部资源，恢复时存在隐式接管

**位置：** 第 189–206 行，特别是第 198 行；第 376–378 行。

**问题：** “Owned 中存在但属性不同 → Replace”未区分本方主动更新与外部替换；历史 Owned 记录并不能证明现在观察到的不同对象仍归自己。恢复分支又把“目标是 EasyTier 网卡、在当前期望范围内、带辅助标记”判为 `ExplicitAdopt`，没有要求预先授权的接管策略或有效独占作用域证据。

**反例：** Manager 过去创建了前缀 R；外部删除 R 并在同接口安装不同 metric/gateway 的 R。当前流程会直接覆盖它。另一种情况是用户原本就手工添加了通往 TUN 的路由，崩溃重启后被新 Manager 认领，退出时再被删掉。

**修改要求：** 分开期望属性、最后确认安装属性、当前观察属性与证据有效性。外部修改/身份不确定进入冲突状态；明确接管必须来自有效配置或事先建立的独占资源契约。恢复不能因为结果符合 Desired 就获得归属。`AdoptIfMatching` 必须明确启用方式、完整匹配条件和退出后的处置，不能与默认 ExternalSatisfied 混淆。

**身份契约也须补齐：** 不能以 CIDR 作为唯一条目身份，或仅用 CIDR/gateway/interface 判定“完全一致”。必须区分平台身份键、规范化属性、实际可共存条目以及业务选路冲突。第 97 行“外部有相同前缀就必然 FileExists”和第 207 行“相同 CIDR 不同接口就冲突”不能代替平台匹配规则。

**验收反例：** 外部预存相同路由、同前缀不同 metric 的可共存条目、Owned 被外部改写、ACK 丢失、无记录恢复和明确授权接管分别测试。

## R4 — P1：清理要求当前代际，会使旧资源永远失去清理资格

**位置：** 第 230 行；第 219–223、384–386 行。

**问题：** 删除谓词强制 `entry.interface_gen == 当前gen`，但故障恢复恰恰经常需要清理旧代际资源。回调过期时“放弃状态推进、交新代际全量重建”也没有保留实际副作用的清理责任。

**反例：** gen=1 添加超时，接口切换为 gen=2 后，gen=1 的添加最终成功。结果若仅被丢弃，新代际只创建自己的路由；旧路由既无法归入当前 Owned，又永远不满足删除谓词。旧 VPN 会话关闭失败也是相同问题。

**修改要求：** 新需求的应用必须绑定当前代际；旧资源清理则绑定其原始、仍可验证的资源身份和原始代际。保留 retired bindings/旧代际恢复记录；不能把旧操作重定向到新接口，也不能把“业务结果过期”当成“系统副作用不存在”。区分原接口确实不存在、名字/索引复用和仍存在待清理对象。

**验收反例：** 旧代际添加迟到成功、旧会话停止失败、接口同名/索引复用、未完成清理后重启。

## R5 — P1：重新强制 protocol=126，并提前冻结未经验证的宽泛选表规则

**位置：** 第 263–266、305–312、378 行。

**问题：** 第 310 行把 `protocol=126` 规定为“必须携带唯一协议标识”，第 311 行依赖该数字过滤路由，第 378 行又用于恢复认领。这违背总纲“公共归属不依赖 protocol，平台标记只是辅助证据”的约束，也没有协议号分配/冲突检测依据。

同时，第 266 行的 `from all table 10001 priority 100` 已经选定全流量优先查专用表，却没有冻结 LAN 重叠、现有 RPDB、多个实例和外层 bypass 失败时的规则。比如 main 中存在 `192.168.1.0/24`，专用表有 `192.168.0.0/16`，优先查专用表会改变原先同表的选路结果。RPDB 按规则优先级执行查表，成功后可结束后续查找，见 [iproute2 官方 ip-rule 文档](https://github.com/iproute2/iproute2/blob/main/man/man8/ip-rule.8.in)。

**修改要求：** Provider 应基于明确的宿主接口/作用域分类与观测范围排除 EasyTier 出口；在 Linux 上可以使用额外标记辅助，但不能作为必需归属机制，更不能未经定义就把 126 称为唯一标识。多实例下需覆盖其他 EasyTier TUN。选表策略只冻结正确性要求，具体规则留给第七步验证，或现在给出完整的优先级与绕行契约。

**补充：** 当前 Provider 枚举了跨表的 IPv6 路由，单纯“默认路由移出 main”并不能自动消除反馈；见 `easytier/src/instance/public_ipv6_provider/linux.rs:338` 与 `default_route_ifindices`。还需保留 `collect_public_ipv6_tun_routes` 驱动 NDP 同步的依赖，不能一律过滤所有 EasyTier 路由。

## R6 — P1：来源审计遗漏 macOS/FreeBSD 显式前缀路由，可能在迁移时丢失基础连通

**位置：** 第 67 行；第 402 行“已全仓梳理”。

**问题：** 清单把所有桌面接口前缀路由都归为“地址配置后内核派生”，并按随地址删除处理。但主线在 macOS/FreeBSD 上显式添加 IPv4/IPv6 前缀路由。

**源码证据：** `easytier/src/instance/virtual_nic.rs:833` 的 IPv4 分支和 `:850` 的 IPv6 分支，在平台 cfg 内分别调用 `nic.add_route(...)` 和 `nic.add_ipv6_route(...)`。

**后果：** 若按当前清单只迁移 proxy/public IPv6/DNS，把接口路由全部排除出显式需求，NIC 拆分或清理旧写入点后，这两个平台的虚拟网络基础路由可能不再安装。

**修改要求：** 将“内核派生”和“平台需要显式安装”的接口前缀路由拆开。对每个平台分别标注需求方、写入方、归属和删除责任，明确地址与路由安装的依赖屏障。Android/OHOS 对虚拟子网的显式提交也需要单列。

## R7 — P2：能力矩阵混合系统潜力、当前实现与目标实现，平台结论不可信

**位置：** 第 116–122、245–253、268–271 行。

可直接验证的问题：

1. **Android 并非“VPN 仅配 IPv4，忽略所有 IPv6 路由”。** `tauri-plugin-vpnservice/android/src/main/java/TauriVpnService.kt:180` 已调用 `builder.addAddress("fd00::1", 128)`，`:185` 逐条向 `addRoute` 提交路由，没有过滤 IPv6。可以说当前 public IPv6 需求链未完整接入，但不能据此否定后端 IPv6 配置能力。
2. **iOS 的项目实现成熟度没有被标注。** 仓库内 `tauri-plugin-vpnservice/ios/Sources/ExamplePlugin.swift` 只有 ping 和返回 `running=false` 的状态方法，没有文档所说的完整 VPN 配置/应用确认链。系统存在某种 API，不意味着本项目已实现 HostConfirmed。macOS NE、外部宿主支持也应分别提供证据。
3. **OHOS 出现在审计声明和差异表，却没有出现在能力矩阵和后端接入分类中。** 当前存在 `easytier-contrib/easytier-ohrs/crates/easytier-ohos-core/src/routing.rs:80` 的多实例需求聚合，以及 runtime API/bridge 输出；实际应用与确认边界必须追到下游，不能一边宣称完整审计，一边遗漏迁移责任。
4. **macOS/FreeBSD 的系统能力不能用当前 shell 实现作为上限。** 文档需要区分当前 CLI、目标结构化后端及仍待验证的原子性，不能据“当前调用 route 命令”决定永久采用较弱能力。现有 `run_shell_cmd` 按退出状态判断成功，并非第 104 行所说解析本地化文本决定成功；见 `easytier/src/common/ifcfg/mod.rs:150`。
5. **Windows 删除身份缺少 NextHop，metric 契约易被误解。** 官方要求有效 DestinationPrefix、NextHop 和 LUID/Index 至少其一；不是必须“完整 LUID”。MIB route Metric 是 offset，实际选路代价才与接口 metric 相加，不能把求和值重新写回 offset。见 [DeleteIpForwardEntry2](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-deleteipforwardentry2) 和 [MIB_IPFORWARD_ROW2](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_ipforward_row2)。

**修改要求：** 每个平台分列“系统 API 可提供”“当前项目已实现”“本次目标”“已验证/待验证”，覆盖 AF、观测范围、匹配/删除精度、确认强度和宿主责任。把不支持与尚未验证区分开，补充实际支持的 OHOS、WASI/嵌入宿主及相关 feature 组合。

## R8 — P2：标记冻结前，仍需补齐来源、恢复和完成状态的关键契约

**位置：** 第 145–173、211–235、345–407 行。

目前主要给出了对象名称和五类故障，但以下会影响第二步接口及后续状态机的规则仍未确定：

- **来源撤销和共享需求：** 缺少撤销后的版本保留、来源暂不可读与显式空集合的区别、同一资源多个来源同时需要时的合并/释放规则，以及快照订阅初始窗口的契约。
- **归属与状态不是串行阶段：** 第 149 行图将 Desired → Pending → Owned 画成单一状态链，容易与“互相独立的信息维度”矛盾；已拥有路由可以同时处于 Desired、Observed 和 Pending 更新中。平台 ACK 或读回存在也不能单独证明首次创建归属，尤其 AlreadyExists/结果未知。
- **恢复写入顺序：** 第 235 行只明确退出清理失败后的记录动作，未规定正常修改的可恢复意图、结果记录、不确定窗口、日志损坏/磁盘失败时是否允许继续修改。无须第一步选数据库，但必须先给出行为约束。
- **停止屏障：** 未明确停止接收新需求、排空/记录在途操作、清理和释放资源租约的顺序。仅“逆序清理 Owned”不足以防止退出中旧 Add 最后落地。
- **完成语义：** 缺少 Accepted、HostConfirmed、Verified、Superseded、Conflict、Unsupported/Skipped、CleanupIncomplete 的关系及按版本等待的结果。HostConfirmed 已提到，但未形成统一对外契约。
- **故障目录：** 尚缺超时但实际生效、删除失败重试、来源乱序/重启、共享需求撤销、日志失败、委托会话迟到确认、两个进程接管和持续配置变化。

**修改要求：** 不必提前实现第三/第五步，但应将上述不可妥协的行为及反例补进本步骤契约；尚未决策的项明确列为待决，不应全部打勾“冻结完成”。

## 其他审计准确性修正

以下不单独计为阻塞项，但应在修订中一并处理，避免后续 agent 按错误事实迁移：

- 第 76 行将 5 个 async 函数称为 5 个并发任务不准确；`apply_*` 是辅助函数。主线 updater 使用 `JoinSet`，第 81 行“只靠 runtime 强杀”也过于绝对。需要指出真正存在的失败后推进缓存、缺乏系统核对及可靠清理协议。
- 多处“崩溃后永久留在系统”缺少接口生命周期条件。应区分临时 TUN 销毁、持久接口/仍存活会话、以及将来加入的 policy rules 等资源，不能无条件断言泄漏。
- 第 70 行 DNS 分支“由旧 ProxyCidrsMonitor 动态注入”需给出真实调用证据；检查到的该 monitor 只汇集 peer CIDR、手工路由和 VPN portal 客户端网段，本身没有 DNS 注入逻辑。
- 第 121 行 Magic DNS 硬编码路由不是死代码：`mobile_vpn.ts:308` 在 enable_magic_dns 时实际执行。
- 应补独立的事件消费者迁移清单：core/native 事件桥、GUI `event.ts`、Android Tauri 转发、CLI 日志、WASI 事件映射、public IPv6 provider/NDP 观察链。来源表不能代替消费者清单。
- “NetNS guard 未覆盖 DNS 路由操作”有源码依据，但“必然污染默认 namespace”需要附带该执行环境确实未在目标 namespace 的条件。
- 文档 `file://` 链接改为相对路径；代码引用注明分支和当前行号，系统能力结论附官方依据或验证结果。

## 修订后的准入标准

1. 修复 R1–R6 的契约及迁移错误，不再让配置语义、归属授权、协调域和接口代际互相混用。
2. 完成 R7 的分层能力矩阵；项目尚未实现或下游不可见的能力明确列为待验证/不支持。
3. 补齐 R8 中会影响需求接口和状态机的行为约束，更新故障场景目录。
4. 用跨来源、跨实例、接口重建和崩溃恢复的具体反例复核文档，再更新“已冻结”和验收勾选状态。

保持原总纲的分层方向即可，不需要为了修订本文回到 `route-dev` 或提前编写平台实现。
