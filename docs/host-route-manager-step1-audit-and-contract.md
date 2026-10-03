# HostRouteManager 第一步：路由审计、规则计算与生命周期规范（精简修订版）

状态：已根据最新实施总纲（[`docs/host-route-manager-master-plan.md`](host-route-manager-master-plan.md)）完成重写。保留已有源码审计、写入点和平台事实；删除过度设计的通用需求总线、WAL 持久化日志、四维大状态机、排他文件锁与生产影子诊断框架。聚焦于编写实用管理器所需的四个核心要素：**来源与规则**、**系统接口与生命周期**、**迁移与复用**、**基础验收**。

---

## 1. 概述与核心定位

HostRouteManager 的目标是一个**小型的、实用的系统路由管理器**：一方面直接从现有业务来源拉取信息，使用纯函数计算最终期望路由集合；另一方面通过现有系统接口应用必要变更，在内存中维护已成功安装条目的记录，以支持增删比对、重试及显式退出清理。接管完成后彻底删除 `ProxyCidrMonitor` 和分散在各处的路由写入任务。

```text
现有 Core / Host 业务状态
          ↓ 读取 (直接拉取 / watch 快照)
HostRouteManager：汇总 → 纯函数计算期望路由 → 执行比对并应用变更
          ↓
已有平台系统接口 (IfConfiger) / 移动宿主接口 (VpnService.Builder)
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
| **手工静态路由**<br>`manual_routes` | 用户在配置中显式指定的 CIDR 网段（仅作用于 proxy CIDR 需求集） | **桌面：** 同上（在 `ProxyCidrMonitor::resolve_proxy_cidrs` 中覆盖 peer 路由）<br>**移动：** `mobile_vpn.ts` 前端并集拼装后传给 VPN | **无** | 同自动子网代理路由 | 同自动子网代理路由 |
| **接口直连网段路由**<br>`Link Subnet Route` | TUN 网卡分配 IP 与子网掩码（如 `10.144.144.1/24`）时，由内核网络栈派生的链路前缀 | **Linux/Windows：** `VirtualNic::assign_ipv4_to_tun_device` 添加 IP 时由内核栈自动生成<br>**移动端：** `builder.addAddress` | **内核/系统栈派生** | 随 IP 移除或网卡销毁由内核自动收回 | 添加 IP 失败抛出错误；内核派生过程无显式报告 |
| **平台显式接口前缀路由**<br>`Explicit Prefix Route` | **macOS / FreeBSD** 平台特性：内核不自动为 TUN 派生子网路由，必须显式安装 | **macOS/FreeBSD：** [`VirtualNic::assign_ipv4_to_tun_device`](../easytier/src/instance/virtual_nic.rs#L839-L846) 显式调用 `nic.add_route`；[`assign_ipv6_to_tun_device`](../easytier/src/instance/virtual_nic.rs#L856-L863) 显式调用 `nic.add_ipv6_route` | **无**（目前由 NIC 代码显式写入系统路由表） | 仅在网卡被关闭或 IP 移除时清理；若崩溃则残留 | 失败向上返回 `Result<(), Error>`，阻断网卡就绪流程 |
| **Public IPv6 默认路由**<br>`::/0` | 开启 public-ipv6 时，分配到的公网 IPv6 前缀出口，用于导入公网流量 | [`VirtualNic::run_public_ipv6_addr_updater`](../easytier/src/instance/virtual_nic.rs#L1181-L1186) -> `nic.add_ipv6_route_with_cost(::, 0, Some(5))` | **无** | 监听到地址变化时调 `nic.remove_ipv6_route(::, 0)`；崩溃则泄漏 | 仅 `tracing::warn!` 记录日志 |
| **Public IPv6 对等节点路由**<br>`Public IPv6 Routes` | 组网内其他节点声明的 Public IPv6 路由条目 | [`VirtualNic::run_public_ipv6_route_updater`](../easytier/src/instance/virtual_nic.rs#L1150) -> `ifcfg.add_ipv6_route` | **无** | 接收事件 diff 后调 `remove_ipv6_route` | 仅 `tracing::trace!` 记录日志 |
| **Magic DNS 虚拟 IP 路由**<br>`fake_ip/32` | Magic DNS 分配的虚拟 IP（如 `7.7.7.7`）不在 TUN 子网内时需导入 TUN | **主线桌面：** [`MagicDnsServerInstance::new`](../easytier/src/instance/dns_server/server_instance.rs#L385-L388) 临时实例化 `IfConfiger{}` 写入<br>**移动：** `mobile_vpn.ts` 在启用时追加 `100.100.100.101/32` | **无** | **主线桌面：** `MagicDnsServerInstance::clean_env` 主动调用删除（Drop 中不执行，非正常退出泄漏） | 启动失败返回 `anyhow::Result` |
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
2. **`easytier/src/instance/dns_server/server_instance.rs`**：
   - `MagicDnsServerInstance::new`（[Line 385–388](../easytier/src/instance/dns_server/server_instance.rs#L385-L388)）在 `fake_ip` 不属于 `tun_inet` 时直接临时实例化 `IfConfiger {}` 写入 `/32` 路由。
   - **NetNS 作用域隐患**：该调用未持有 `NetNSGuard`，在多 netns 环境下可能在错误的命名空间执行。
   - **清理隐患**：清理代码仅在显式调用 `clean_env` 时执行，`Drop` 中未调用，异常退出必定残留。
3. **`easytier/src/instance/virtual_nic.rs:839 & 856` (macOS / FreeBSD 显式前缀路由)**：
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
| **Linux** | Netlink (rtnetlink route RTM_NEWROUTE / RTM_DELROUTE) | `NetlinkIfConfiger` 支持基本增删与 dump；netns 支持 | 原生后端：复用 `NetlinkIfConfiger` 增删路由 | 常用功能经 CI / 本地测试已验证 |
| **Windows** | IP Helper API (`CreateIpForwardEntry2`, `DeleteIpForwardEntry2`) | `WindowsIfConfiger` 基于 LUID 增删路由 | 原生后端：复用 `WindowsIfConfiger` 增删路由 | CI 具备构建验证；网络调用需真实环境 |
| **macOS** | BSD Route Socket / 系统 `route` 命令 | `MacIfConfiger` 通过 `sh -c route -n` 执行 | 原生后端：复用 `MacIfConfiger` 执行命令 | CI 具备构建验证；网络调用需真实环境 |
| **FreeBSD** | 系统 `route` 命令 | `FreebsdIfConfiger` 通过 `route` 命令执行 | 原生后端：复用 `FreebsdIfConfiger` | CI 具备构建验证；网络调用需真实环境 |
| **Android** | `VpnService.Builder` | `TauriVpnService.kt` 批次调用 `builder.addRoute` | 委托后端：直接传递计算后的全量期望路由集合重建会话 | 已有 IPv4 实际运行，IPv6 待联调 |
| **iOS** | `NEPacketTunnelNetworkSettings` | `tauri-plugin-vpnservice` 仅为占位 Stub | 标记为未支持（Unsupported Stub） | 未支持 |
| **OpenHarmony** | `VpnExtensionAbility` | `easytier-ohos-core/src/routing.rs` 聚合逻辑 | 委托后端：传递全量计算结果 | 待接入实际闭环 |
| **WASI / No-TUN** | 无原生网卡/路由权限 | 事件字符串映射 / 逻辑空转 | 绑定 No-TUN 空后端：正常计算，宿主直接跳过底层下发，不产生虚假错误 | 纯逻辑与编译已验证 |

---

## 3. 来源与规则：信息读取、路由计算与配置语义

### 3.1 信息读取入口

Manager 不在各来源内部植入重型注册状态机，而是通过明确的读取接口直接拉取当前业务事实：

```text
┌────────────────────────────────────────────────────────┐
│                   业务事实输入源                        │
├────────────────────────────┬───────────────────────────┤
│ 1. Core OSPF Peer 路由     │ Route::subscribe_host_... │
│ 2. 用户静态 manual_routes  │ runtime_config.snapshot() │
│ 3. Public IPv6 地址与路由  │ PublicIpv6Snapshot (watch)│
│ 4. Host Magic DNS 配置     │ fake_ip, enabled 标志     │
│ 5. TUN 接口与地址事实      │ tun_inet (IPv4/IPv6 前缀) │
└────────────────────────────┴───────────────────────────┘
```

1. **OSPF Peer 路由**：从 `PeerRouteInput`（由 `Route::subscribe_host_route_inputs()` 订阅，或直接从 OSPF 实例获取）读取当前计算出的 `proxy_cidrs: BTreeSet<Ipv4Cidr>` 与 `proxy_cidrs_v6: BTreeSet<Ipv6Cidr>`。
2. **用户手工路由**：从 `CoreRuntimeConfig` 获取 `services.manual_routes: Option<BTreeSet<Ipv4Cidr>>`。
3. **Public IPv6 事实**：从 `PublicIpv6Snapshot` 读取：
   - 是否拥有公网租约（`lease: Option<Ipv6Cidr>`）；若有，需生成默认出口路由 `::/0`（metric = 5）。
   - 对等节点公网 IPv6 路由集合（`routes: Vec<Ipv6Cidr>`）。
4. **Magic DNS 虚拟 IP**：从 DNS 服务获取当前分配的 `fake_ip: Ipv4Addr` 以及启用状态。
5. **接口地址事实**：从 Host 网卡上下文获取当前分配的虚拟 IP 与子网掩码（`tun_inet: Option<Ipv4Inet>` 及 IPv6 地址）。

### 3.2 纯函数计算流程与规则

期望路由的计算是纯函数，无副作用，输入业务事实，输出最终期望的 `BTreeSet<RouteSpec>`（其中 `RouteSpec` 包含 `destination: IpCidr` 与可选 `metric: Option<i32>`）：

1. **CIDR 规范化（Clear Host Bits）**：
   - 所有输入的 CIDR 均进行规范化处理，强制将主机位清零（例如 `10.0.0.1/24` 规范化为 `10.0.0.0/24`），确保条目比对的一致性。
2. **代理路由覆盖规则 (`resolve_proxy_cidrs`)**：
   - 复用已验证的纯函数 `crate::route_demand::projection::resolve_proxy_cidrs`：
     - 若 `manual_routes` 为 `None`：采用动态 OSPF peer 广播的 `proxy_cidrs`。
     - 若 `manual_routes` 为 `Some([])`（显式空集）：输出**空集合**，彻底关闭对端代理路由的安装。
     - 若 `manual_routes` 为 `Some([A, B])`：严格采用 `[A, B]`，对端代理路由被覆盖抑制。
3. **Magic DNS `/32` 路由规则**：
   - 若 Magic DNS 未启用：不产生需求。
   - 若 Magic DNS 已启用且分配了 `fake_ip`：
     - 检查 `tun_inet` 是否包含该 `fake_ip`：
       - 若 `fake_ip` **落在 TUN 虚拟子网内**：内核链路直连路由已涵盖，**不生成额外主机路由**。
       - 若 `fake_ip` **在 TUN 虚拟子网外**：生成一条指向 TUN 的 `fake_ip/32` 主机路由。
4. **平台显式接口前缀规则 (macOS / FreeBSD)**：
   - 若运行在 **macOS / FreeBSD** 平台且 TUN 已配置 `tun_inet`：
     - 生成一条接口直连网段路由 `tun_inet.first_address() / prefix_len`。
   - 若运行在 **Linux / Windows** 平台：
     - 内核在配置 IP 时自动派生直连链路路由，Manager **不生成显式需求**，避免与内核派生条目冲突。
5. **Public IPv6 路由规则**：
   - 若处于活动租约期：生成目标为 `::/0`、metric = 5 的公网 IPv6 默认路由。
   - 提取活跃的对端 Public IPv6 网段集合。
6. **最终期望集合合并与去重**：
   - 将上述纯投影结果汇总至一个 `BTreeSet<RouteSpec>`，完成自然的跨来源去重。

### 3.3 严格保留的配置语义与平台纠偏

1. **`manual_routes` 作用域严格限定**：
   - `manual_routes` **仅且仅作用于对端子网代理路由（Proxy CIDR）**。
   - 绝对不影响本机向外通告自身的子网代理；
   - 绝对不影响 Magic DNS、Public IPv6 默认路由或接口前缀路由。
   - **验收保证**：即使配置了 `manual_routes = Some([])`，DNS 的 `/32` 和 Public IPv6 的 `::/0` 依然正常计算与安装。
2. **移动端/鸿蒙端行为纠偏**：
   - 历史代码中，移动端 `mobile_vpn.ts` 与鸿蒙 `routing.rs` 采用了 Union（并集）方式拼接 peer 路由与 manual 路由，且显式空数组会错误退化为全部 peer 路由。
   - **本方案统一纠偏**：所有宿主统一采用 Core 的纯函数计算逻辑，废除前端的并集拼接，严格遵循覆盖与禁用语义。

---

## 4. 系统接口与生命周期：后端复用、动态变化与停机

### 4.1 系统接口复用与薄抽象

不再通过复杂的 downcast 寻找网卡内部控制器，而是建立单一、明确的后端接口 `RouteBackend`：

```rust
#[async_trait::async_trait]
pub trait RouteBackend: Send + Sync + 'static {
    /// 添加一条路由
    async fn add_route(&self, route: &RouteSpec) -> Result<(), Error>;
    /// 删除一条路由
    async fn remove_route(&self, route: &RouteSpec) -> Result<(), Error>;
    /// 移动端/委托宿主整批应用完整路由集合 (原生平台提供默认逐条调用实现)
    async fn apply_routes(&self, routes: &BTreeSet<RouteSpec>) -> Result<(), Error> {
        // 默认实现走增量 add/remove
        ...
    }
}
```

- **原生桌面后端 (`NativeRouteBackend`)**：持有当前 TUN 设备的网卡控制器或 `IfConfiger` 实例，复用现有的 `add_ipv4_route`、`remove_ipv4_route`、`add_ipv6_route`、`remove_ipv6_route`。
- **移动端委托后端 (`DelegatedRouteBackend`)**：实现 `apply_routes`，将全量集合转换为 Android `VpnService.Builder` 所需的配置并调用宿主应用。
- **No-TUN 后端 (`NoTunRouteBackend`)**：所有操作为空实现并返回成功，彻底杜绝虚假报错与空转事件。

### 4.2 协调循环与内存记录

Manager 在内存中维护一份 `installed_routes: BTreeSet<RouteSpec>`，记录**本次运行中已明确成功安装但尚未成功删除的路由条目**。

Manager 运行一条顺序的定时/事件驱动循环：
```text
  ┌──────────────────────────────────────────────────────────┐
  │ 1. 拉取所有输入事实，纯函数计算得出 desired_routes        │
  │ 2. 计算待删除集合: to_remove = installed - desired       │
  │    计算待添加集合: to_add    = desired - installed       │
  │ 3. 执行删除: 成功一项从 installed 移除一项                │
  │ 4. 执行添加: 成功一项向 installed 记录一项                │
  │ 5. 等待下一轮定时间隔 (如 1s) 或业务事件唤醒              │
  └──────────────────────────────────────────────────────────┘
```

### 4.3 动态生命周期处理规范

1. **地址变化（DHCP / 静态 IP 更新）**：
   - 当 DHCP 分配了新 IP、租约更新或释放时，唤醒 Manager 重新拉取地址事实。
   - 纯函数重新计算：若前缀变化或 DNS fake IP 的子网内外归属发生变化，新旧 `desired_routes` 自动呈现差异。
   - 协调循环平滑将过期的旧前缀/旧 DNS 路由删除，并添加新条目，无需销毁 Manager。
2. **接口重建（TUN 重连 / Android 重新获取 fd）**：
   - 当底层虚拟网卡崩溃、重启或更名重建时，旧接口上的底层路由已被操作系统自动收回或失效。
   - **处理准则**：
     - 网卡销毁事件到达时，Manager **清空旧接口对应的 `installed_routes` 记录**。
     - 获取新接口句柄与绑定后，以全新的状态触发一轮协调，完整重新下发当前全部 `desired_routes`。
     - **严禁**将旧接口上记录的安装状态误当作新接口已安装，杜绝代际混淆。
3. **显式停机与退出清理 (`stop`)**：
   - 实例收到关闭信号时，执行显式异步 `stop()` 流程：
     1. 中止后台协调循环，拒绝接收后续外部唤醒。
     2. 遍历当前内存中记录的 `installed_routes`，依次调用后端的 `remove_route` 进行精确清理。
     3. 清理失败如实打印警告并记录日志，不吞掉错误。
     4. 清理完毕后清空 `installed_routes` 并正常退出。
   - **杜绝隐式 Drop**：绝不依赖 Rust 的 `Drop` 方法发起异步清理，保证退出时限与清理可见性。

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

### 5.2 当前 Step 2 实现的复用与精简

当前工作区（`refactor/route`）第二步已交付的代码中：

- **保留**：
  - `easytier-core/src/route_demand/projection.rs` 中的纯函数（`resolve_proxy_cidrs`、`normalize_cidr`）；
  - `peer_ospf_route.rs` 与 `peers/public_ipv6` 中支持原子快照订阅的可读输入接口；
  - 针对规则计算、双栈及配置语义的高质量单元测试。
- **删除 / 裁撤**：
  - 裁撤未接入必要业务的通用发布总线与协议：`RouteDemandRegistry`、`ScopedPublisher`、`SourceSubmissionToken`、`SourceEpoch`、`wait_obsolete` 等过度设计的框架；
  - 裁撤未接入生产调用者的只读影子诊断框架（`easytier/src/instance/route_shadow.rs`），将其精简收缩为单元测试校验辅助。

### 5.3 对应旧 Writer 的分阶段退出步骤

为防止系统发生路由双写冲突，各旧写入者按以下两个阶段严格退出：

```text
阶段一 (第二步实施)：最小闭环接管代理路由
┌─────────────────────────────────────────────────────────┐
│ 1. 接管范围：自动代理路由 (Peer Proxy) + 手工静态路由    │
│ 2. 停写旧链路：禁用 ProxyCidrMonitor 与                │
│    VirtualNic::run_proxy_cidrs_route_updater            │
│ 3. 启用闭环：由 HostRouteManager 唯一负责代理路由的增删   │
│ 4. 未迁移项：Public IPv6 与 DNS 仍由旧链路写入，互不重叠  │
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

**双写防御铁律**：在迁移过渡期间，每一类具体的路由条目在任意时刻**只能且必须只有一个活动的系统写入者**。在确认旧 writer 停止执行前，新 Manager 绝不接管该类路由的系统写权限。

---

## 6. 基础验收要求

基础版本的质量标准集中于**实际路由控制行为的正确性**，必须通过以下维度的针对性测试：

### 6.1 计算正确性验收

- [ ] **代理路由覆盖**：`manual_routes = None` 时完整投影 OSPF peer 广播的网段；`manual_routes = Some([A, B])` 时严格覆盖为 `[A, B]`，不混入对端网段。
- [ ] **显式空集禁用**：`manual_routes = Some([])` 时代理路由输出为空集，且**绝对不影响** DNS 与 Public IPv6 路由的生成。
- [ ] **CIDR 规范化**：输入包含主机位的网段（如 `192.168.1.50/24`）被正确转换为 `192.168.1.0/24`。
- [ ] **Magic DNS 边界**：当 `fake_ip` 位于 TUN 子网内时不产生路由；位于子网外时准确产生 `/32` 主机路由；DNS 禁用时输出为空。
- [ ] **显式接口前缀**：macOS/FreeBSD 正确生成虚拟子网网段路由；Linux/Windows 不生成多余显式需求。
- [ ] **双栈共存**：IPv4 与 IPv6 代理路由及直连路由并存时正确计算，互不干扰。

### 6.2 失败重试与健壮性验收

- [ ] **失败不记成功**：若底层 `add_route` 系统调用返回错误，该条目**绝不计入** `installed_routes` 内存记录；在下一轮循环中继续尝试重试添加。
- [ ] **删除失败不丢责任**：若底层 `remove_route` 返回错误，该条目**保留在** `installed_routes` 中，下一轮循环继续执行删除。
- [ ] **读取失败跳过**：若某一业务来源暂时读取失败或不可达，Manager 保持当前已有安装记录，跳过本轮破坏性操作，绝不将读取失败当成“需求全空”而误删系统路由。

### 6.3 不误删验收

- [ ] **精确删除限定**：Manager 仅删除记录在 `installed_routes` 中、且当前不再属于期望集合的路由。
- [ ] **外部路由不认领**：若操作系统中已预先存在同名外部路由，或系统调用返回 `AlreadyExists`，Manager 不将其认领为自己安装，退出时绝不执行物理删除。
- [ ] **禁止全表清扫**：严禁按 CIDR 扫描清扫操作系统的共享主路由表。

### 6.4 不双写与停机验收

- [ ] **单写者互斥**：阶段一与阶段二迁移切换过程中，旧 updater 停写与新闭环生效具备严格的前后顺序，不存在针对同一路由的新旧双写窗口。
- [ ] **停止清理彻底**：调用 `stop()` 时，已成功安装的路由被逐条显式删除，操作完成后系统路由表干净无残留。
- [ ] **接口重建自愈**：网卡销毁后清空旧代际记录；网卡重建后新接口成功重新安装期望路由，不发生状态混淆。
