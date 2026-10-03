# HostRouteManager 第一步：路由审计、规则计算与生命周期规范（第五轮修订版）

状态：已根据第六轮审查意见（[`docs/host-route-manager-step1-review-6.md`](host-route-manager-step1-review-6.md)）与最新实施总纲（[`docs/host-route-manager-master-plan.md`](host-route-manager-master-plan.md)）完成修订。明确了精确删除参数匹配、接口重建与停机的失败可见性、重叠路由交接策略、No-TUN 旁路机制、原生/委托双分支抽象，以及基于当前真实源码树的复用分工。

---

## 1. 概述与核心定位

HostRouteManager 的目标是一个**小型的、实用的系统路由管理器**：一方面直接从现有业务来源拉取信息，使用纯函数计算最终期望路由集合；另一方面通过平台系统接口应用必要变更，在内存中维护已成功安装条目的记录，以支持增删比对、重试及显式退出清理。接管完成后彻底删除 `ProxyCidrMonitor` 和分散在各处的路由写入任务。

```text
现有 Core / Host 业务状态
          ↓ 直接拉取 / 局部一致快照
HostRouteManager：汇总 → 纯函数计算期望路由 → 执行比对并应用变更
          ↓
┌─────────────────────────────────┴─────────────────────────────────┐
│ 原生平台分支 (NativeRouteBackend)   │ 委托宿主分支 (DelegatedRouteBackend) │
│ 逐条增删、精确参数匹配、逐项记账     │ 全量配置下发、宿主确认后整批记账   │
└─────────────────────────────────┬─────────────────────────────────┘
                                  ↓
      宿主操作系统网络栈 (Linux / Windows / macOS / Android VPN)
```

系统严格保持 Core 与 Host/Native 的职责分工：
- **Core (`easytier-core`)**：负责业务规则、OSPF 路由计算、配置管理与纯投影函数，不直接发起宿主操作系统调用。
- **Host (`easytier`)**：负责管理 HostRouteManager 的调度循环、持有实际后端接口、衔接网卡/地址生命周期、执行底层操作并维护已安装记录。

不再在 EasyTier 内部重复开发通用的发布/订阅框架、提交令牌机、多租约文件锁或崩溃恢复日志系统；将代码重心放回 EasyTier 自身的路由业务规则与平台真实行为。

---

## 2. 路由来源、系统写入者与事件消费者全景审计（保留既有成果）

### 2.1 路由分类全景审计清单

全仓代码中受管理的路由共有 8 种类型，其需求方、当前写入点、归属和撤销方式审计如下：

| 路由类别 | 需求来源 (Who Needs) | 当前直接写入点 (Who Writes) | 当前归属 (Who Owns) | 如何撤销 (How Revoked) | 失败如何报告 (Failure Reporting) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **自动子网代理路由**<br>`Peer Proxy CIDR` | 对端 Peer 广播自身代理的网段 (`proxy_cidrs`)，宿主需将流量导向 TUN 设备 | **桌面：** `ProxyCidrMonitor` (1s 轮询) -> `VirtualNic::run_proxy_cidrs_route_updater` -> `IfConfiger::add_ipv4_route`<br>**移动：** `mobile_vpn.ts` 轮询 RPC -> `TauriVpnService.kt` `builder.addRoute` | **无**（直接注入 OS 共享主表或 VPN Session，无归属凭据） | **桌面：** 内存快照做 diff 后调 `remove_ipv4_route`；进程崩溃时泄漏<br>**移动：** 全量重启 VPN Session | **桌面：** 仅 `tracing::trace!` 记录<br>**移动：** 前端 catch 后 `console.error` |
| **手工静态路由**<br>`manual_routes` | 用户在配置中显式指定的 CIDR 网段（仅作用于 proxy CIDR 需求集，目前主线实现为 IPv4） | **桌面：** 同上（在 `ProxyCidrMonitor::resolve_proxy_cidrs` 中覆盖 peer 路由）<br>**移动：** `mobile_vpn.ts` 前端并集拼装后传给 VPN | **无** | 同自动子网代理路由 | 同自动子网代理路由 |
| **接口直连网段路由**<br>`Link Subnet Route` | TUN 网卡分配 IP 与子网掩码（如 `10.144.144.1/24`）时，由内核网络栈派生的链路前缀 | **Linux/Windows：** `VirtualNic::assign_ipv4_to_tun_device` 添加 IP 时由内核栈自动生成<br>**移动端：** `builder.addAddress` | **内核/系统栈派生** | 随 IP 移除或网卡销毁由内核自动收回 | 添加 IP 失败抛出错误；内核派生过程无显式报告 |
| **平台显式接口前缀路由**<br>`Explicit Prefix Route` | **macOS / FreeBSD** 平台特性：内核不自动为 TUN 派生子网路由，必须显式安装 | **macOS/FreeBSD：** [`VirtualNic::assign_ipv4_to_tun_device`](../easytier/src/instance/virtual_nic.rs#L839-L846) 显式调用 `nic.add_route`；[`assign_ipv6_to_tun_device`](../easytier/src/instance/virtual_nic.rs#L856-L863) 显式调用 `nic.add_ipv6_route` | **无**（目前由 NIC 代码显式写入系统路由表） | 仅在网卡被关闭或 IP 移除时清理；若崩溃则残留 | 失败向上返回 `Result<(), Error>`，阻断网卡就绪流程 |
| **Public IPv6 默认路由**<br>`::/0` | 开启 public-ipv6 时，分配到的公网 IPv6 前缀出口，用于导入公网流量 | [`VirtualNic::run_public_ipv6_addr_updater`](../easytier/src/instance/virtual_nic.rs#L1181-L1186) -> `nic.add_ipv6_route_with_cost(::, 0, Some(5))` | **无** | 监听到地址变化时调 `nic.remove_ipv6_route(::, 0)`；崩溃则泄漏 | 仅 `tracing::warn!` 记录日志 |
| **Public IPv6 对等节点路由**<br>`Public IPv6 Routes` | 组网内其他节点声明的 Public IPv6 路由条目（类型为 `Ipv6Inet`，保留地址与前缀信息） | [`VirtualNic::run_public_ipv6_route_updater`](../easytier/src/instance/virtual_nic.rs#L1150) -> `ifcfg.add_ipv6_route` | **无** | 接收事件 diff 后调 `remove_ipv6_route` | 仅 `tracing::trace!` 记录日志 |
| **Magic DNS 虚拟 IP 路由**<br>`fake_ip/32` | Magic DNS 分配的虚拟 IP（如 `7.7.7.7`）不在 TUN 子网内时需导入 TUN（Windows 平台具有固有 `cost = Some(4)`） | **主线桌面：** [`MagicDnsServerInstance::new`](../easytier/src/instance/dns_server/server_instance.rs#L385-L388) 临时实例化 `IfConfiger{}` 写入<br>**移动：** `mobile_vpn.ts` 在启用时追加 `100.100.100.101/32` | **无** | **主线桌面：** `MagicDnsServerInstance::clean_env` 主动调用删除（Drop 中不执行，非正常退出泄漏） | 启动失败返回 `anyhow::Result` |
| **macOS 历史残留清理**<br>`10.0.0.0/24` | `rust-tun` 库在 macOS/FreeBSD 创建网卡时默认注入的死路由 | [`VirtualNic::run`](../easytier/src/instance/virtual_nic.rs#L1256-L1260) -> `nic.ifcfg.remove_ipv4_route("10.0.0.0", 24)` | **无** | 仅开机单次显式删除 | 忽略错误 `let _ = ...` |

> [!NOTE]
> **关于 `feat/dns-policy` 分支的审计核实**：经核对分支 `2569f35f` 源码，其 `ProxyCidrsMonitor::diff_proxy_cidrs` 顶层仅合并了 manual routes、peer proxy CIDRs 以及 VPN portal client CIDRs，不存在活跃读取 `dns.addresses()` 注入 `proxy_cidrs` 的行为；早期历史 commit `86871b14` 中的试验代码未在当前分支生效。DNS 路由在主线仍以 `MagicDnsServerInstance` 的独立写入点为准。

### 2.2 现有系统写入点代码审计与缺陷分析

1. **`easytier/src/instance/virtual_nic.rs`**：
   - 内部包含 3 个由 `tasks: JoinSet` 托管的长期 updater 任务：
     - `run_proxy_cidrs_route_updater`（[Line 1048](../easytier/src/instance/virtual_nic.rs#L1048)）：监听 `GlobalCtxEvent::ProxyCidrsUpdated`。
     - `run_public_ipv6_route_updater`（[Line 1118](../easytier/src/instance/virtual_nic.rs#L1118)）：监听 `GlobalCtxEvent::PublicIpv6RoutesUpdated`。
     - `run_public_ipv6_addr_updater`（[Line 1171](../easytier/src/instance/virtual_nic.rs#L1171)）：监听 `GlobalCtxEvent::PublicIpv6Changed`。
   - **关键缺陷分析**：
     - **错误推进缓存**：以 `apply_route_changes`（[Line 997](../easytier/src/instance/virtual_nic.rs#L997)）为例，无论底层 `ifcfg.add_ipv4_route` 是否报错，均无条件执行 `cur_proxy_cidrs.insert(cidr)`。写入失败后内存缓存假定其已存在，导致永久失去重试机会。
     - **缺乏系统核对**：完全依赖内存 `cur_proxy_cidrs`，外部工具篡改或删除后无法感知与恢复。
     - **缺乏显式停机协议**：`VirtualNic` 仅在销毁时丢弃 `JoinSet`，没有在退出时执行显式的已安装路由清理。
2. **`easytier/src/common/ifcfg/netlink.rs:366–388`（删除匹配参数缺失隐患）**：
   - 当前 Linux `remove_ipv4_route(name, address, cidr_prefix)` 实现为遍历系统路由，仅比对 `destination == address && dst_len == cidr_prefix && oif == ifidx`，匹配到第一条便下发 `RTM_DELROUTE` 删除。
   - **参数缺失风险**：完全未匹配 `table` 与 `metric/priority`。若同接口、同前缀下存在外部创建的其他优先级路由（如外部 metric=100，本方 metric=65535），该方法可能误删外部路由。
   - **修订结论**：必须将“补齐后端删除匹配参数（目标、前缀、网卡、metric、table）”作为复用现有接口的前提条件。
3. **`easytier/src/instance/dns_server/server_instance.rs`**：
   - `MagicDnsServerInstance::new`（[Line 385–388](../easytier/src/instance/dns_server/server_instance.rs#L385-L388)）在 `fake_ip` 不属于 `tun_inet` 时直接临时实例化 `IfConfiger {}` 写入 `/32` 路由，Windows 平台传入 `cost = Some(4)`。
   - **NetNS 作用域隐患**：该调用未持有 `NetNSGuard`，在多 netns 环境下可能在错误的命名空间执行。
   - **清理隐患**：清理代码仅在显式调用 `clean_env` 时执行，`Drop` 中未调用，异常退出必定残留。
4. **`easytier/src/instance/virtual_nic.rs:839 & 856` (macOS / FreeBSD 显式前缀路由)**：
   - macOS 和 FreeBSD 平台上调用 `assign_ipv4_to_tun_device` 和 `assign_ipv6_to_tun_device` 时分别显式调用了 `nic.add_route` 和 `nic.add_ipv6_route`。
   - 解耦 NIC 与路由管理后，必须确保 macOS/FreeBSD 的显式前缀由 Manager 统一托管，否则将丢失虚拟网段基础连通性。

### 2.3 现有事件消费者全景清单

路由变更事件不仅用于网络栈写入，还被全仓以下组件消费：
1. **`CoreEventSink` (`easytier-core/src/events.rs`)**：`CoreEvent::ProxyCidrsUpdated`、`CoreEvent::PublicIpv6RoutesChanged`、`CoreEvent::PublicIpv6Changed`。
2. **`GlobalCtxEvent` 广播总线 (`easytier/src/common/global_ctx.rs`)**：供 CLI 事件日志器（`cli_event_logger.rs:216`）打印日志，以及 Tauri 运行时（`easytier-gui/src-tauri/src/lib.rs:1116`）转发前端。
3. **Android 活跃控制链 (`easytier-gui/src/composables/event.ts`)**：[Line 88–100](../easytier-gui/src/composables/event.ts#L88-L100) 收到 `EVENTS.PROXY_CIDRS_UPDATED` 或 `EVENTS.EVENT_LAGGED` 时主动触发 `onNetworkInstanceUpdate`，发起 Android VPN 配置核对与隧道重建（`prepareVpnService`）。
4. **WASI 适配器 (`easytier-core/src/wasi/adapter/event.rs:52`)**：将 `CoreEvent::ProxyCidrsUpdated` 序列化为 `"proxy_cidrs_updated"`。
5. **Public IPv6 Provider (`easytier/src/instance/public_ipv6_provider/linux.rs`)**：[Line 338](../easytier/src/instance/public_ipv6_provider/linux.rs#L338) 扫描 WAN 上行接口，[Line 523](../easytier/src/instance/public_ipv6_provider/linux.rs#L523) 采集 TUN 上的 public IPv6 路由驱动 Linux NDP 代理。

### 2.4 平台底层接口与真实能力表现

| 平台分类 | 系统底层 API / 工具 | 当前代码实现 | HostRouteManager 接入方式 | 验证状态 |
| :--- | :--- | :--- | :--- | :--- |
| **Linux** | Netlink (rtnetlink route RTM_NEWROUTE / RTM_DELROUTE) | `NetlinkIfConfiger` 支持基本增删与 dump；netns 支持 | 原生后端：复用 `NetlinkIfConfiger`，补齐删除参数匹配 | 常用功能经 CI / 本地测试已验证 |
| **Windows** | IP Helper API (`CreateIpForwardEntry2`, `DeleteIpForwardEntry2`) | `WindowsIfConfiger` 基于 LUID 增删路由 | 原生后端：复用 `WindowsIfConfiger` 增删路由 | CI 具备构建验证；网络调用需真实环境 |
| **macOS** | BSD Route Socket / 系统 `route` 命令 | `MacIfConfiger`（`darwin.rs`）通过 `sh -c route -n` 执行 | 原生后端：复用 `MacIfConfiger` 执行命令 | CI 具备构建验证；网络调用需真实环境 |
| **FreeBSD** | 系统 `route` 命令 | **共用 `darwin.rs` 的 `MacIfConfiger`**（代码库无独立 `FreebsdIfConfiger`） | 原生后端：复用 `MacIfConfiger` | CI 具备构建验证；网络调用需真实环境 |
| **Android** | `VpnService.Builder` | `TauriVpnService.kt` 批次调用 `builder.addRoute` | 委托后端：直接传递计算后的全量期望路由集合重建会话 | 已有 IPv4 实际运行，IPv6 待联调 |
| **iOS** | `NEPacketTunnelNetworkSettings` | `tauri-plugin-vpnservice` 仅为占位 Stub | 标记为未支持（Unsupported Stub） | 未支持 |
| **OpenHarmony** | `VpnExtensionAbility` | `easytier-ohos-core/src/routing.rs` 聚合逻辑 | 委托后端：传递全量计算结果 | 待接入实际闭环 |
| **WASI / No-TUN** | 无原生网卡/路由权限 | 事件字符串映射 / 逻辑空转 | 旁路执行：正常计算但**完全跳过执行分支**，保持已安装记录为空，不报虚假成功 | 纯逻辑与编译已验证 |

---

## 3. 来源与规则：信息读取、路由计算与配置语义

### 3.1 源码基线与信息读取入口

为避免指代模糊，下表明确区分当前代码库真实存在的入口、旧 Step 2 可选取的纯计算部分，以及待新增的接线：

| 来源分类 | 当前主线已存在 (In Main Tree) | 旧 Step 2 可选取复用 (From Old Commits) | 待新增 / 完善 (To Be Added) |
| :--- | :--- | :--- | :--- |
| **Core Peer 路由** | `Route::list_proxy_cidrs_excluding`<br>`Route::list_proxy_cidrs_v6_excluding` | 无（旧通用订阅协议已废弃） | 增加一个局部的一致拉取或精简 watch 接口，无需整套总线 |
| **手工静态配置** | `runtime_config.snapshot().services.manual_routes` | 相同 | 直接读取快照 |
| **Public IPv6** | `peers::public_ipv6` 服务中获取 lease 与 routes | 纯数据结构定义 | 提取 `lease: Option<Ipv6Inet>` 与 `routes: BTreeSet<Ipv6Inet>` |
| **Host Magic DNS** | `server_instance.rs` 中的 `fake_ip: Ipv4Addr` 与启停状态 | 无 | Host 侧提供读取当前 fake IP 与子网状态的方法 |
| **网卡接口事实** | `tun_inet: Option<Ipv4Inet>` 与 IPv6 前缀事实 | 无 | Host 网卡上下文直接获取当前地址与网卡名 |

### 3.2 纯函数计算流程与规则

期望路由的计算是纯函数，无副作用，输入业务事实，输出最终期望的 `BTreeSet<RouteSpec>`：

```rust
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct RouteSpec {
    pub destination: IpCidr,
    pub metric: Option<i32>,
}
```

1. **CIDR 规范化（Clear Host Bits）**：
   - 所有输入的 CIDR 均进行规范化处理，强制将主机位清零（例如 `10.0.0.1/24` 规范化为 `10.0.0.0/24`），确保条目比对的一致性。
2. **代理路由覆盖规则 (`resolve_proxy_cidrs`)**：
   - 维持当前代码库已实现的纯函数规则（当前主线重点为 IPv4）：
     - 若 `manual_routes` 为 `None`：采用动态 OSPF peer 广播的 `proxy_cidrs`。
     - 若 `manual_routes` 为 `Some([])`（显式空集）：输出**空集合**，彻底关闭对端代理路由的安装。
     - 若 `manual_routes` 为 `Some([A, B])`：严格采用 `[A, B]`，对端代理路由被覆盖抑制。
3. **Magic DNS `/32` 路由规则**：
   - 若 Magic DNS 未启用：不产生需求。
   - 若 Magic DNS 已启用且分配了 `fake_ip`：
     - 检查 `tun_inet` 是否包含该 `fake_ip`：
       - 若 `fake_ip` **落在 TUN 虚拟子网内**：内核链路直连路由已涵盖，**不生成额外主机路由**。
       - 若 `fake_ip` **在 TUN 虚拟子网外**：生成一条指向 TUN 的 `fake_ip/32` 主机路由。
     - **Metric 规则**：Windows 平台显式指定 `metric = Some(4)`（对应主线 `server_instance.rs:381`），非 Windows 平台为 `None`。
4. **平台显式接口前缀规则 (macOS / FreeBSD)**：
   - 若运行在 **macOS / FreeBSD** 平台且 TUN 已配置 `tun_inet`：
     - 生成一条接口直连网段路由 `tun_inet.first_address() / prefix_len`。
   - 若运行在 **Linux / Windows** 平台：
     - 内核在配置 IP 时自动派生直连链路路由，Manager **不生成显式需求**，避免与内核派生条目冲突。
5. **Public IPv6 路由规则**：
   - 若处于活动租约期（拥有 `lease: Option<Ipv6Inet>`）：生成目标为 `::/0`、`metric = Some(5)` 的公网 IPv6 默认路由。
   - 对等节点 Public IPv6 路由：按实际通告的网段生成路由条目。
6. **最终期望集合合并与去重策略**：
   - 相同目标若带有不同 metric，属于明确的策略冲突，不能依赖 `BTreeSet` 默认行为盲目去重。
   - **冲突决策**：同一目标网段若同时出现在多个来源，优先保留更具体的显式配置；若优先级相同且 metric 不同，记录告警并选择 metric 较小（优先级更高）者，确保输出集合中同一 destination 唯一。

### 3.3 严格保留的配置语义与平台纠偏

1. **`manual_routes` 作用域严格限定**：
   - `manual_routes` **仅且仅作用于对端子网代理路由（Proxy CIDR）**。
   - 绝对不影响本机向外通告自身的子网代理；
   - 绝对不影响 Magic DNS、Public IPv6 默认路由或接口前缀路由。
   - **验收保证**：即使配置了 `manual_routes = Some([])`，DNS 的 `/32` 和 Public IPv6 的 `::/0` 依然正常计算与安装。
2. **移动端/鸿蒙端行为纠偏**：
   - 历史代码中，移动端 `mobile_vpn.ts` 与鸿蒙 `routing.rs` 采用了 Union（并集）方式拼接 peer 路由与 manual 路由，且显式空数组会错误退化为全部 peer 路由。
   - **本方案统一纠偏**：所有宿主统一采用 Core 的纯函数计算逻辑，废除前端的并集拼接，严格遵循覆盖与禁用语义。
3. **第一阶段范围限定**：
   - 现有主线中的 proxy writer 与 manual routes 均为 IPv4。第二步第一阶段闭环维持这一范围；数据结构支持双栈，但本阶段不在系统层静默开启未经验证的 IPv6 代理路由下发。

---

## 4. 系统接口与生命周期：后端复用、动态变化与停机

### 4.1 系统接口复用：原生与委托双分支抽象

为避免用虚假方法冒充成功，后端抽象明确划分为两个独立分支：

```rust
#[async_trait::async_trait]
pub trait NativeRouteBackend: Send + Sync + 'static {
    /// 添加一条路由，必须传递完整标识参数
    async fn add_route(&self, route: &RouteSpec) -> Result<(), Error>;
    /// 删除一条路由，必须按完整参数精确匹配定位，无法精确定位时返回错误
    async fn remove_route(&self, route: &RouteSpec) -> Result<(), Error>;
}

#[async_trait::async_trait]
pub trait DelegatedRouteBackend: Send + Sync + 'static {
    /// 移动端整批下发完整期望集合
    async fn apply_routes(&self, routes: &BTreeSet<RouteSpec>) -> Result<(), Error>;
    /// 关闭/重置移动端 VPN 会话
    async fn reset_session(&self) -> Result<(), Error>;
}

pub enum RouteBackend {
    Native(Box<dyn NativeRouteBackend>),
    Delegated(Box<dyn DelegatedRouteBackend>),
    NoTun, // 明确的 No-TUN 旁路
}
```

1. **原生桌面分支 (`NativeRouteBackend`)**：
   - 持有 TUN 设备的网卡控制器或 `IfConfiger` 实例；
   - **精确删除改造（必须前提）**：修改现有的 `remove_ipv4_route` / `remove_ipv6_route`，下发删除请求时必须匹配 `destination`、`prefix`、`ifindex`、`metric` 和 `table`。若未找到完全吻合的条目，返回错误，绝不随意删除同网段不同 metric 的条目。
2. **移动端委托分支 (`DelegatedRouteBackend`)**：
   - 实现 `apply_routes`，将全量集合一次性传递给 Android `VpnService.Builder` 重建会话；
   - 仅在宿主系统确认会话建立成功后，才整体更新 `applied_routes`；
   - 退出时调用 `reset_session`，不强求实现虚假的单条增删方法。
3. **No-TUN 旁路 (`RouteBackend::NoTun`)**：
   - 业务层照常计算期望路由，但 Manager 检测到 `NoTun` 时**完全跳过执行分支**；
   - 内存中的 `installed_routes` 严格保持为空，不调用任何底层接口，也不产生虚假的安装成功记录。

### 4.2 协调循环与记账逻辑

Manager 维护内存记录 `installed_routes: BTreeSet<RouteSpec>`，记录**本次运行已明确成功安装但尚未成功删除的路由条目**。

```text
原生平台循环：
  1. 拉取所有输入事实，纯函数计算得出 desired_routes
  2. 计算待删除集合: to_remove = installed - desired
     计算待添加集合: to_add    = desired - installed
  3. 执行删除: 调用 remove_route，底层成功一项，才从 installed 移除一项；失败则保留记录
  4. 执行添加: 调用 add_route，底层成功一项，才向 installed 记入一项；失败则不计入
  5. 等待下一轮定时间隔 (如 1s) 或业务事件唤醒

委托平台循环：
  1. 计算得出 desired_routes
  2. 若 desired != applied，调用 apply_routes(desired)
  3. 宿主确认成功后，applied = desired；若失败，保持原 applied 不变，下一轮重试
```

### 4.3 动态生命周期处理规范

1. **地址变化（DHCP / 静态 IP 更新）**：
   - 当 DHCP 分配了新 IP、租约更新或释放时，唤醒 Manager 重新拉取地址事实。
   - 纯函数重新计算：若前缀变化或 DNS fake IP 的子网内外归属发生变化，新旧 `desired_routes` 自动呈现差异。
   - 协调循环平滑将过期的旧前缀/旧 DNS 路由删除，并添加新条目，无需销毁 Manager。
2. **接口重建（TUN 崩溃 / 重连 / 重新获取 fd）**：
   - 当底层虚拟网卡崩溃、重启或更名重建时，旧接口上的底层路由已被操作系统自动收回或失效。
   - **处理准则**：
     - 新接口生成新的绑定生命周期，**单独开始一套全新的 `installed_routes` 安装记录**。
     - 旧接口上的历史记录仅在底层确认删除成功、或已明确通过接口销毁被操作系统收回时方可释放。
     - **严禁**将旧接口上记录的安装状态误当作新接口已安装，杜绝跨接口代际混淆。
3. **停机与退出清理 (`stop`) 的失败可见性**：
   - 实例收到关闭信号时，执行显式异步 `stop()` 流程：
     1. 首先等待正在执行的在途添加/删除操作完成并如实记账，**绝不强行 abort 一个可能已产生系统副作用的操作**。
     2. 中止后台定时协调循环，拒绝接收后续外部唤醒。
     3. 针对原生后端：遍历当前内存中记录的 `installed_routes`，依次调用后端的精确 `remove_route`。底层删除成功一项，从 `installed_routes` 移除一项。
     4. 针对委托后端：调用 `reset_session` 清理会话。
   - **失败可见性保证**：
     - 若所有条目均删除成功，`stop()` 返回 `Ok(())`。
     - **若存在删除失败的条目**：失败条目**坚决保留在 `installed_routes` 中**，`stop()` 向上返回 `Err(CleanupIncomplete { remaining: installed_routes })`。
     - 允许宿主进程退出，但**绝不向调用方报告清理成功**，错误必须完全可见。不作“系统路由表干净无残留”的空头承诺。
   - **杜绝隐式 Drop**：绝不依赖 Rust 的 `Drop` 方法发起异步清理。

---

## 5. 迁移与复用：代码分工与旧 Writer 退出步骤

### 5.1 `refactor/route-dev` 的复用与改造

经对 `refactor/route-dev` 分支代码（`easytier/src/nic/route/manager.rs`）的核对，确定以下处理策略：

- **保留**：
  - 其小型 `RouteManager` 骨架及单循环顺序消费思路；
  - 直观简洁的 `RouteSpec { destination, metric }` 概念。
- **改写**：
  - **切断 NIC 内部耦合**：删除 `nic.downcast_ref::<Nic>()` 这种通过 Any 寻找控制器的脆弱做法，改为在创建 `HostRouteManager` 时显式注入薄抽象 `RouteBackend`。
  - **实现真实的 `sync()` 闭环**：`route-dev` 中的 `async fn sync(&self) {}` 是完全空白的空函数。将其替换为第 4.2 节所述的期望集合与已安装记录的比对、增删、失败保留及重试闭环。
- **删除**：
  - 删除未接入生产的冗余 `RouteSourceState` 和多余消息结构，直接基于拉取的事实快照计算。

### 5.2 当前 Step 2 提交与主线复用映射表

| 目标能力 | 主线代码处理 | 旧 Step 2 提交选取 | 实施时新增/改写 |
| :--- | :--- | :--- | :--- |
| **纯计算函数** | 保留 `gateway/proxy/cidr_monitor.rs` 纯覆盖逻辑 | 选取 `projection.rs` 中的规范化逻辑与测试用例 | 合并为清晰的纯计算模块 |
| **Peer 路由读取** | 保留 `Route::list_proxy_cidrs_excluding` | 废弃旧通用发布总线与提交 Token 框架 | 增加简单的快照拉取接口，保证串行化不倒退 |
| **后端接口** | 保留 `IfConfiger` | 废弃复杂的只读影子诊断框架 (`route_shadow.rs`) | 补齐 `remove_route` 精确匹配参数；提供双分支 trait |
| **Manager 主体** | 无 | 参考 `route-dev` 骨架 | 实现单循环比对、记账与失败可见的 `stop()` |

### 5.3 对应旧 Writer 的分阶段退出与重叠路由防御

为防止系统发生路由双写冲突，各旧写入者按以下两个阶段严格退出：

```text
阶段一 (第二步实施)：最小闭环接管代理路由
┌─────────────────────────────────────────────────────────┐
│ 1. 接管范围：自动代理路由 (Peer Proxy) + 手工静态路由    │
│ 2. 停写旧链路：禁用 ProxyCidrMonitor 与                │
│    VirtualNic::run_proxy_cidrs_route_updater            │
│ 3. 启用闭环：由 HostRouteManager 唯一负责代理路由的增删   │
│ 4. 排除/交接重叠：禁止 manual_routes 与未迁移项重叠，或 │
│    重叠条目由旧 writer 清理后，新 Manager 才启动接管   │
└─────────────────────────────────────────────────────────┘
                            ↓
阶段二 (第三步实施)：全面收敛并彻底删除旧模块
┌─────────────────────────────────────────────────────────┐
│ 1. 接管范围：Public IPv6 路由/出口 + Magic DNS /32      │
│             + macOS/FreeBSD 显式接口前缀                │
│ 2. 停写旧链路：停止 VirtualNic 中 public_ipv6 的        │
│    2 个 updater 任务；移除 Magic DNS 中的 IfConfiger 写入│
│ 3. 彻底删除：删除 ProxyCidrMonitor 模块及其 feature 分支 │
│ 4. 最终状态：全仓受管路由 100% 收敛至 HostRouteManager   │
└─────────────────────────────────────────────────────────┘
```

**重叠路由防御与交接铁律**：
1. **同路由同批交接**：不同来源若映射到同一条实际系统路由（例如手工路由指定了 DNS fake IP 的 `/32` 或接口前缀），必须在同一批次一起交接相关写入者，严禁只按来源名称拆分写入权。
2. **首期交接排除**：在阶段一中，若检测到手工路由与 DNS / 接口前缀网段重叠，系统明确拒绝该配置或维持旧链路，防止新旧 writer 相互踩踏删除。
3. **干净切换原则**：切换到新 Manager 时优先采用干净实例启动；或由旧 writer 明确确认已完成旧条目清理后，新 Manager 方从空的 `installed_routes` 干净起步。**严禁自动认领未经核实的旧系统路由**。

---

## 6. 基础验收要求

基础版本的质量标准集中于**实际路由控制行为的正确性**，必须通过以下维度的针对性测试：

### 6.1 计算正确性验收

- [ ] **代理路由覆盖**：`manual_routes = None` 时完整投影 OSPF peer 广播的网段；`manual_routes = Some([A, B])` 时严格覆盖为 `[A, B]`，不混入对端网段。
- [ ] **显式空集禁用**：`manual_routes = Some([])` 时代理路由输出为空集，且**绝对不影响** DNS 与 Public IPv6 路由的生成。
- [ ] **CIDR 规范化**：输入包含主机位的网段（如 `192.168.1.50/24`）被正确转换为 `192.168.1.0/24`。
- [ ] **Magic DNS 边界与 Metric**：当 `fake_ip` 位于 TUN 子网内时不产生路由；位于子网外时准确产生 `/32` 主机路由（Windows 下正确附带 metric=4，非 Windows 为 None）；DNS 禁用时输出为空。
- [ ] **显式接口前缀**：macOS/FreeBSD 正确生成虚拟子网网段路由；Linux/Windows 不生成多余显式需求。
- [ ] **冲突去重与裁决**：同一目标网段在不同来源出现时，能够依据明确策略裁决出唯一条目，不依赖集合遍历随机胜出。

### 6.2 失败重试与健壮性验收

- [ ] **失败不记成功**：若底层 `add_route` 系统调用返回错误，该条目**绝不计入** `installed_routes` 内存记录；在下一轮循环中继续尝试重试添加。
- [ ] **删除失败不丢责任**：若底层 `remove_route` 返回错误，该条目**保留在** `installed_routes` 中，下一轮循环继续执行删除。
- [ ] **读取失败跳过**：若某一业务来源暂时读取失败或不可达，Manager 保持当前已有安装记录，跳过本轮破坏性操作，绝不将读取失败当成“需求全空”而误删系统路由。
- [ ] **No-TUN 旁路安全**：在 No-TUN 模式下，期望集合正常计算，但执行分支完全跳过，`installed_routes` 保持为空，不报告虚假成功，也不触发底层网卡错误。

### 6.3 精确删除与不误删验收

- [ ] **精确删除参数匹配测试**：在测试环境中模拟或构造“同网卡、同前缀、但 metric/table 不同”的路由条目（例如系统已有 metric=100 的外部路由，Manager 创建了 metric=65535 的路由）。验证 Manager 调用 `remove_route` 时，精确删除自己创建的 metric=65535 路由，外部 metric=100 的路由完好无损。
- [ ] **外部路由不认领**：若操作系统中已预先存在同名外部路由，或系统调用返回 `AlreadyExists`，Manager 不将其认领为自己安装，退出时绝不执行物理删除。
- [ ] **禁止全表清扫**：严禁按 CIDR 扫描清扫操作系统的共享主路由表。

### 6.4 停机清理与双写防御验收

- [ ] **成功清理场景**：调用 `stop()` 且所有底层删除均返回成功时，`stop()` 返回 `Ok(())`，`installed_routes` 清空。
- [ ] **清理失败可见场景**：构造底层删除失败的注入场景。验证调用 `stop()` 时：
  - 在途操作平稳等待完成并正确记账；
  - 删除失败的条目依然保留在 `installed_routes` 中；
  - `stop()` 明确返回 `Err(CleanupIncomplete { .. })`，剩余条目列表对外完全可见；
  - 进程允许退出，但不伪造“清理干净”的假成功。
- [ ] **单写者互斥**：阶段一与阶段二迁移切换过程中，旧 updater 停写与新闭环生效具备严格的前后顺序，不存在针对同一路由的新旧双写窗口；重叠路由已做交接或前置排除。
- [ ] **接口重建自愈**：网卡销毁后，旧接口记录保留至底层清理完毕或随网卡注销收回；网卡重建后新接口成功重新安装期望路由，不发生状态混淆。
