# HostRouteManager 第二步实施方案：最小 Manager 闭环（第四轮修订版）

状态：已根据复审意见（[`docs/host-route-manager-step2-review-2.md`](host-route-manager-step2-review-2.md)）完成深度修订。严格遵循最新实施总纲（[`docs/host-route-manager-master-plan.md`](host-route-manager-master-plan.md)）与第一步规范（[`docs/host-route-manager-step1-audit-and-contract.md`](host-route-manager-step1-audit-and-contract.md)）。  
基线代码：`refactor/route` 分支；参考分支：`refactor/route-dev` (`8abfb51e`)。

---

## 1. 目标与范围及平台启用边界

### 1.1 核心目标
本阶段交付一个**小型的、实用的 HostRouteManager 闭环**：
1. **范围聚焦**：接管 **IPv4 自动子网代理路由（Peer Proxy CIDR）** 与 **手工静态代理路由（`manual_routes`）**。
2. **直连事实与闭环操作**：直接从 Core 路由表权威快照与配置拉取事实，由 Host 完成纯函数策略计算，通过薄后端接口应用变更，维护携带实际创建参数与接口代际的精确记录（`InstalledRoute`），保存未决操作（`PendingOperation`），支持带退避的失败重试与带超时的显式停机清理。
3. **平滑交接与防双写**：统一定义单一生产后端模式选择（`RouteBackendMode`）；在启用的平台上停用旧 updater 系统写权限；尚未迁移的 Public IPv6、Magic DNS 及接口前缀在第二步暂不接入，但在阶段一通过生命周期时序与显式确认完成重叠范围的动态交接与防御，杜绝新旧双写。
4. **性能与精简约束**：彻底不引入旧版版本化需求框架（无 Registry / Token / Epoch / 生产影子框架）；满足稳态零多余写入、快照与连接复用、消除用户态逐条 dump 等可测量的性能指标。

### 1.2 跨平台启用状态与单一控制开关 (`RouteBackendMode`)

为彻底杜绝“配置声明与生产链路不一致导致的漏写或双写”，采用**单一生产后端控制开关**统一决策：

```rust
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteBackendMode {
    /// 启用全新 HostRouteManager，完全接管系统路由写入
    NativeManager,
    /// 维持现有旧版路由写入链路 (VirtualNic updater / mobile_vpn)
    Legacy,
    /// 旁路模式，不向系统写入任何路由
    NoTun,
}
```

| 平台分类 | 第二步默认模式 | 真实后端 / 宿主接线文件 | 旧 Writer 退出时机 | 第二步验收范围 |
| :--- | :--- | :--- | :--- | :--- |
| **Linux** | **`NativeManager`** | `easytier/src/instance/route/backend/netlink.rs`<br>衔接 `NetlinkIfConfiger` | 启动时 `NativeManager` 生效，跳过创建 `VirtualNic::run_proxy_cidrs_route_updater` | 隔离 netns 下真实 Netlink 系统调用测试；覆盖增删、精确匹配、长连接与退避 |
| **Windows** | **`Legacy`**<br>(测试可显式切 `NativeManager`) | `easytier/src/instance/route/backend/windows.rs`<br>衔接 `WindowsIfConfiger` | 默认维持旧链路；显式切换 `NativeManager` 时停用旧 updater | 隔离环境 Win32 API 增删与默认 Metric (9000) 映射测试 |
| **macOS / FreeBSD** | **`Legacy`**<br>(测试可显式切 `NativeManager`) | `easytier/src/instance/route/backend/darwin.rs`<br>衔接 `MacIfConfiger` | 默认维持旧链路；显式切换 `NativeManager` 时停用旧 updater | CLI 命令执行与状态码检查测试；显式接口前缀暂留旧链路 |
| **Android / 移动委托** | **`Legacy`** | `easytier/src/instance/route/backend/delegated.rs`<br>（适配 `VpnService.Builder` 接口模型） | **生产维持旧链路**：移动端 VPN 需同时携带 DNS 与子网配置，在第二步不切换生产 `mobile_vpn.ts` | 委托后端全量应用契约测试、会话代际确认与会话重置测试 |
| **No-TUN** | **`NoTun`** | `RouteBackend::NoTun` | 停用旧 monitor 路由事件 | 验证正常计算期望，但完全跳过执行分支，已安装记录严格为空 |

---

## 2. 代码落点与复用清单

### 2.1 源码分工与依赖单向性约束

严格遵守 `easytier → easytier-core` 的单向依赖规则，**Core 绝不引用 Host 类型，也不感知 Host 管理器**：
- **`easytier-core`（纯业务事实、不可变快照与规范化）**：
  - 在 `PeerRouteService::update_route_table` 提交边界计算并缓存不可变快照 `Arc<BTreeSet<Ipv4Cidr>>`。
  - 通过 `CorePacketPlane` 导出只读快照及 Core 自有的 `watch` 订阅接口：`subscribe_proxy_cidrs()` 与 `list_proxy_cidrs_snapshot()`，独立于 `proxy-cidr-monitor` feature 开关。
  - 导出配置 `CoreRuntimeConfigStore` 的快照与订阅接口。
  - 导出纯算法函数：
    - `normalize_v4_cidr(addr: Ipv4Addr, prefix: u8) -> Result<Ipv4Cidr, cidr::errors::NetworkParseError>`（CIDR 主机位规范化）。
    - 现有的 `resolve_proxy_cidrs(peer_routes: BTreeSet<Ipv4Cidr>, config: ProxyCidrConfigSnapshot) -> BTreeSet<Ipv4Cidr>`（拥有所有权的手工覆盖计算）。
- **`easytier`（宿主策略、生命周期与系统控制）**：
  - 定义 `RouteSpec`、`InstalledRoute`、`PendingOperation`、`InterfaceBinding` 记录结构与结果枚举。
  - 实现 Host 侧策略函数 `calculate_desired_proxy_routes`：过滤未迁移来源重叠、解析平台默认参数（Linux 65535, Windows 9000）、生成 `RouteSpec`。
  - 实现 `RouteBackend` 及其原生/委托实现（包含长连接 Netlink、Win32 API 等）。
  - 实现 `HostRouteManager` 协调循环、未决操作追踪、多代际记录与生命周期。
  - 接线宿主生命周期组件：`NativeInstanceRuntimeHost`、`tun_desktop.rs`、`tun_common.rs`。
  - 改造 Magic DNS 真实清理路径：`clean_env()` 返回结构化结果，传递至 `DnsRunner` 与 `MagicDnsRuntime::stop()`。

```text
easytier-core/
  └── src/
        ├── instance/
        │     └── packet_plane.rs           [修改] 独立于旧 monitor 导出 list_proxy_cidrs_snapshot 与 watch 订阅
        ├── peers/route/
        │     ├── peer_ospf_route.rs        [修改] 在 update_route_table 提交边界维护 Arc<BTreeSet<Ipv4Cidr>> 快照
        │     └── projection.rs             [纯算法] normalize_v4_cidr (纯网络前缀清除，无 Host 依赖)
        └── gateway/proxy/
              └── cidr_monitor.rs           [修改] 移除向系统写入路由的逻辑，仅保留内部状态；保留 resolve_proxy_cidrs
easytier/
  └── src/
        ├── common/ifcfg/
        │     ├── mod.rs                    [修改] 声明精确删除参数
        │     └── netlink.rs                [修改] 消除遍历 dump，按精确参数直接构造 RTM_DELROUTE
        └── instance/
              ├── route/
              │     ├── mod.rs              [新增] 模块入口
              │     ├── model.rs            [新增] RouteSpec, InstalledRoute, PendingOperation, InterfaceBinding, 结果枚举
              │     ├── policy.rs           [新增] Host 侧策略计算 (未迁移冲突过滤与参数补全，输出 RouteSpec)
              │     ├── backend.rs          [新增] RouteBackend 抽象与 MockBackend
              │     ├── backend/
              │     │     ├── netlink.rs    [新增] Linux 专属实现 (长连接 netns 绑定、req/ACK 匹配、消除 dump)
              │     │     ├── windows.rs    [新增] Windows 专属实现 (Win32 API、默认 Metric 9000)
              │     │     ├── darwin.rs     [新增] macOS/FreeBSD 专属实现
              │     │     └── delegated.rs  [新增] 移动端委托后端 (真实会话所有者契约)
              │     └── manager.rs          [新增] HostRouteManager 核心闭环、未决操作记录与多代际绑定
              ├── dns_server/
              │     ├── server_instance.rs  [修改] clean_env() 真实返回路由清理结果 Result<(), Error>
              │     └── runner.rs           [修改] 传递 clean_env() 路由清理结果至外部
              ├── runtime_host.rs           [修改] 管理器实例生命周期管理 (持留 Handle 并在 shutdown 协调停止)
              ├── runtime_host/
              │     ├── implementation.rs   [修改] 转发宿主运行时接口
              │     ├── magic_dns.rs        [修改] stop() 向上返回真实路由清理结果
              │     ├── tun_desktop.rs      [修改] 静态 TUN 与 DHCP 换卡通过命令通道交接 bind/unbind
              │     └── tun_common.rs       [修改] TunNicState::stop 与 drain 协调解绑与旧网卡销毁确认
              └── virtual_nic.rs            [修改] 按 RouteBackendMode 决策是否启动 run_proxy_cidrs_route_updater
```

### 2.2 `refactor/route-dev` 移植决策

经核对 `refactor/route-dev` (`8abfb51e`) 分支中 `easytier/src/nic/route/manager.rs`：
- **移植并改进**：
  1. `RouteSpec` 概念：移植并精简为包含 `destination: IpCidr` 与 `metric: Option<i32>`，补充基于 `Ipv4Inet::network()` 的安全构造方法。
  2. 单循环顺序处理思路：移植其简洁的循环骨架，填充为真正的比对、执行、记账、未决操作追踪与退避闭环。
- **坚决舍弃**：
  1. **舍弃 `nic.nic_ctx.downcast_ref::<Nic>()`**：切断通过 Any 锁住 NIC 的旧设计，改为构造时显式注入 `RouteBackend`。
  2. **舍弃 `RouteCommand::SyncSource` 通道机制**：舍弃多通道代际状态机，采用拉取模型与单通知唤醒。
  3. **不重新引入 `route_demand` 与 `route_shadow`**：坚决不引入版本化需求注册表与生产影子框架。

---

## 3. 结构与接口定义

### 3.1 核心数据结构与安全构造

```rust
// easytier-core/src/peers/route/projection.rs
use std::net::Ipv4Addr;
use cidr::{Ipv4Cidr, Ipv4Inet};

/// 安全的纯 IPv4 CIDR 规范化函数：清除主机位，非法前缀显式返回错误，严禁 panic
pub fn normalize_v4_cidr(addr: Ipv4Addr, prefix: u8) -> Result<Ipv4Cidr, cidr::errors::NetworkParseError> {
    let inet = Ipv4Inet::new(addr, prefix)?;
    Ok(inet.network())
}

// 现有 Core 中 resolve_proxy_cidrs 的真实函数签名 (easytier-core/src/gateway/proxy/cidr_monitor.rs:76)
// pub(crate) fn resolve_proxy_cidrs(
//     peer_routes: BTreeSet<Ipv4Cidr>,
//     config: ProxyCidrConfigSnapshot,
// ) -> BTreeSet<Ipv4Cidr>;
```

```rust
// easytier/src/instance/route/model.rs
use std::net::Ipv4Addr;
use cidr::{IpCidr, Ipv4Cidr, Ipv4Inet};

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct RouteSpec {
    pub destination: IpCidr,
    pub metric: Option<i32>,
}

impl RouteSpec {
    /// 安全的 IPv4 构造函数：利用 Ipv4Inet 清除主机位，非法前缀显式返回错误
    pub fn try_new_v4(addr: Ipv4Addr, prefix: u8, metric: Option<i32>) -> Result<Self, cidr::errors::NetworkParseError> {
        let inet = Ipv4Inet::new(addr, prefix)?;
        Ok(Self {
            destination: IpCidr::V4(inet.network()),
            metric,
        })
    }

    /// 从已规范化的 Ipv4Cidr 直接构造，避免重复规范化开销
    pub fn from_v4_cidr(cidr: Ipv4Cidr, metric: Option<i32>) -> Self {
        Self {
            destination: IpCidr::V4(cidr),
            metric,
        }
    }
}

/// 实际创建记录：保存底层创建时的真实通用属性与接口代际，支持精确删除
/// 平台专属字段（如 Linux routing table）严格保存在后端内部，不向通用宿主身份扩散
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstalledRoute {
    pub spec: RouteSpec,
    pub binding: InterfaceBinding,
    pub actual_metric: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct InterfaceBinding {
    pub ifname: String,
    pub ifindex: u32,
    pub generation: u64,
}
```

### 3.2 操作结果与未决操作记录 (`PendingOperation`)

为解决“添加产生副作用但确认丢失导致停机漏删”的问题，定义明确的结构化结果，并引入显式的未决操作记录：

```rust
// easytier/src/instance/route/model.rs

pub enum AddRouteOutcome {
    /// 成功在系统中创建了路由，并返回实际生效的底层安装记录
    Created(InstalledRoute),
    /// 系统中已存在相同条目（非本方创建，不予认领，不入账，记录诊断警告）
    AlreadyPresent,
    /// 确定性的系统调用失败（如权限不足、参数非法），记录错误并按退避重试
    Failed(anyhow::Error),
    /// 结果不明（如超时、Netlink 套接字异常中断），记录未决操作，严禁盲目重试
    OutcomeUnknown(anyhow::Error),
}

pub enum RemoveRouteOutcome {
    /// 成功从系统中删除了目标路由
    Removed,
    /// 系统中已经不存在目标路由（已达目标状态，正常销毁账目）
    AlreadyAbsent,
    /// 确定性的删除失败（如正在使用、系统错误），保留账目并按退避重试
    Failed(anyhow::Error),
    /// 结果不明，保留账目并记录未决操作，严禁盲目重试
    OutcomeUnknown(anyhow::Error),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PendingOperationKind {
    Add(RouteSpec),
    Remove(InstalledRoute),
}

/// 未决操作记录：记录因网络/套接字中断而结果不明的操作
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingOperation {
    pub kind: PendingOperationKind,
    pub binding: InterfaceBinding,
    pub error: String,
    pub recorded_at: std::time::Instant,
}
```

**未决操作处理约束（S1 闭合）**：
1. **不因需求撤销而丢弃**：若某条路由添加返回 `OutcomeUnknown`，随后外部需求撤销，该条目的 `PendingOperation` **必须保留**，绝不能因不在 desired 中就直接丢弃。
2. **不冒充认领**：未决添加不能视为 `Created`，也不能仅凭系统中存在同名前缀就草率认领。
3. **阻塞与停机可见性**：未决操作未查明前，允许向宿主明确报告阻塞，但严禁盲目重复下发添加或擅自调用删除；在 `stop(deadline)` 时，若存在未决操作，**必须作为未完成项返回**，绝不返回清理完成。

### 3.3 后端接口抽象 (`RouteBackend`)

```rust
// easytier/src/instance/route/backend.rs
use super::model::*;

#[async_trait::async_trait]
pub trait NativeRouteBackend: Send + Sync + 'static {
    /// 添加一条路由
    async fn add_route(&self, route: &RouteSpec, binding: &InterfaceBinding) -> AddRouteOutcome;
    /// 精确删除一条由本方创建的路由
    async fn remove_route(&self, record: &InstalledRoute) -> RemoveRouteOutcome;
}

#[async_trait::async_trait]
pub trait DelegatedRouteBackend: Send + Sync + 'static {
    /// 移动端全量路由应用契约：由真实会话所有者组装完整 VPN 配置（保留 DNS、接口前缀等非代理需求），
    /// 仅将旧代理路由子集替换为最新的 desired 集合，并等待宿主明确确认
    async fn apply_routes(&self, routes: &std::collections::BTreeSet<RouteSpec>) -> Result<(), anyhow::Error>;
    /// 重置移动端会话（会话失效或注销时清空 applied 状态，不跨实例共享）
    async fn reset_session(&self) -> Result<(), anyhow::Error>;
}

pub enum RouteBackend {
    Native(Box<dyn NativeRouteBackend>),
    Delegated(Box<dyn DelegatedRouteBackend>),
    NoTun,
}
```

#### Linux Netlink 后端细节要求
`easytier/src/instance/route/backend/netlink.rs` 的实现必须满足：
1. **连接与 NetNS 绑定**：创建时在目标 NetNS 中打开长连接 Netlink 套接字并绑定，生命周期内持续复用，消除每请求创建与关闭 socket 的系统开销。
2. **请求 / ACK 匹配**：为每次请求分配单调递增的序列号（`nlmsg_seq`），收包循环严格匹配对应的 `NLMSG_ERROR` ACK，正确处理乱序或插队响应，坚决不假设一发一收。
3. **消除 Dump**：直接构造带 `RTA_DST`、`RTA_OIF`、`RTA_PRIORITY`、`rtm_table` 的单发 `RTM_DELROUTE` 报文下发，单条删除请求数量恒定为 1，杜绝用户态全表扫描。
4. **异步安全**：将阻塞底层网络 I/O 放入 `tokio::task::spawn_blocking` 中执行，不阻塞 Tokio 异步调度器线程；NetNS 绑定固定在专用执行环境中，绝不跨越 `await`。

### 3.4 Manager 结构与有界命令通道

为消除无网卡时的循环等待死锁，并实现确定性的生命周期交接，Manager 引入轻量级内部命令通道：

```rust
// easytier/src/instance/route/manager.rs

pub enum ManagerCommand {
    BindInterface {
        binding: InterfaceBinding,
        backend: Box<dyn NativeRouteBackend>,
        ack: tokio::sync::oneshot::Sender<()>,
    },
    UnbindInterface {
        ack: tokio::sync::oneshot::Sender<()>,
    },
    ConfirmInterfaceDestroyed {
        generation: u64,
        ack: tokio::sync::oneshot::Sender<()>,
    },
    Stop {
        deadline: std::time::Instant,
        ack: tokio::sync::oneshot::Sender<Result<(), CleanupIncomplete>>,
    },
}

pub struct HostRouteManager {
    backend: RouteBackend,
    /// 当前活跃绑定的已安装路由记录 (spec -> InstalledRoute)
    installed_routes: std::collections::BTreeMap<RouteSpec, InstalledRoute>,
    /// 待清理的旧绑定及其专属后端、残留记录与未决操作 (防止接口重建时丢失旧责任)
    retired_bindings: Vec<RetiredBindingContext>,
    /// 未决操作记录表 (记录 OutcomeUnknown 项)
    pending_operations: std::collections::BTreeMap<RouteSpec, PendingOperation>,
    /// 失败重试退避追踪表 (限制事件风暴下的反复重试)
    retry_tracker: std::collections::BTreeMap<RouteSpec, RetryState>,
    /// 当前网卡绑定上下文
    current_binding: Option<InterfaceBinding>,
    /// 缓存的上一轮输入快照指针与路由相关配置
    last_peer_cidrs: Option<Arc<std::collections::BTreeSet<cidr::Ipv4Cidr>>>,
    last_manual_routes: Option<Option<std::collections::BTreeSet<cidr::Ipv4Cidr>>>,
    /// 命令接收通道
    cmd_rx: tokio::sync::mpsc::Receiver<ManagerCommand>,
    /// 停机令牌
    cancel_token: tokio_util::sync::CancellationToken,
}

pub struct RetiredBindingContext {
    pub binding: InterfaceBinding,
    pub backend: Box<dyn NativeRouteBackend>,
    pub installed: std::collections::BTreeMap<RouteSpec, InstalledRoute>,
    pub pending: std::collections::BTreeMap<RouteSpec, PendingOperation>,
}

#[derive(Clone)]
pub struct RouteManagerHandle {
    cmd_tx: tokio::sync::mpsc::Sender<ManagerCommand>,
    join_handle: Arc<tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>>,
    cancel_token: tokio_util::sync::CancellationToken,
}

impl RouteManagerHandle {
    /// 接口创建/重建时更新绑定 (等待 Manager 确认已切换)
    pub async fn bind_interface(&self, binding: InterfaceBinding, backend: Box<dyn NativeRouteBackend>) -> anyhow::Result<()> { ... }
    /// 接口注销/失效时解绑 (等待 Manager 确认已将当前条目归档至 retired，并结算完当前在途操作)
    pub async fn unbind_interface(&self) -> anyhow::Result<()> { ... }
    /// 底层设备已物理销毁确认 (注销对应 generation 的旧责任)
    pub async fn confirm_interface_destroyed(&self, generation: u64) -> anyhow::Result<()> { ... }
    /// 显式停机：借用 Handle，超时返回未完成信息，原持有者继续保留 Handle 与 JoinHandle 以供追踪
    pub async fn stop(&self, deadline: std::time::Instant) -> Result<(), CleanupIncomplete> { ... }
}
```

---

## 4. 输入接线与无冗余调度

### 4.1 输入接线映射表

Manager 绝不通过虚假消息总线通信，而是直接绑定各组件的权威只读入口：

| 来源分类 | 读取入口 (Read API) | 快照提交点 (Commit Point) | 通知方式 (Wakeup) |
| :--- | :--- | :--- | :--- |
| **Core Peer 路由** | `CorePacketPlane::list_proxy_cidrs_snapshot() -> Arc<BTreeSet<Ipv4Cidr>>` | OSPF 路由表更新处 (`peer_ospf_route.rs: update_route_table`) 提交 `ArcSwap` | Core 自有的 `watch::Receiver<Arc<BTreeSet<Ipv4Cidr>>>` 触发唤醒 |
| **手工静态配置** | `CoreRuntimeConfigStore::snapshot().services.manual_routes` | 配置变更原子提交处 | 订阅 `subscribe_service_runtime_changes()` 唤醒 |
| **Host 未迁移事实** | `UnmigratedRouteTracker::snapshot()` | DHCP lease 变更、TUN IP 变更、DNS 启停提交处 | 提交处内部触发 Manager 唤醒通知 |

### 4.2 订阅与初态读取顺序

为杜绝启动初始化期间的事件丢失，严格执行**先订阅、后读初态**（`subscribe -> read_initial`）原则：
1. 先建立 `CorePacketPlane` 的 proxy cidrs `watch` 订阅与 `CoreRuntimeConfigStore` 服务订阅。
2. 立即拉取各来源的初始快照，装配初态。
3. 启动协调循环。在订阅与初态读取之间到达的任何并发更新，均会通过已注册的通道准确唤醒。

### 4.3 稳态零多余计算与零堆分配

为了将稳态开销降至绝对最低，避免每次迭代重新执行 `collect()` 分配堆内存：
1. **输入快照指针校验（Fast-path Check）**：
   协调循环缓存上一轮的不可变快照指针（`Arc::ptr_eq`）与路由相关配置：
   - 比对 `Arc::ptr_eq(&last_peer_cidrs, &current_peer_cidrs)`。
   - 比对 `current_config.services.manual_routes == last_manual_routes`（**忽略与路由无关的其他服务配置变更**，如 Socks5/DHCP 配置变化不引发重算）。
   - 比对未迁移事实快照。
2. **快速跳过机制**：
   协调循环被唤醒后，首先检查上述输入快照。若事实未变、无到期的重试项且 retired 队列为空，**直接跳过计算与拉取**。此时：
   - 0 堆内存分配（无 `collect`，无字符串复制，无树节点创建）。
   - 0 底层系统调用。
3. **输出容量复用**：
   当输入确实变化时，Host 侧策略函数复用排序 `Vec<RouteSpec>` 的预分配容量，避免重复申请堆内存。
4. **低频保底与独立重试**：
   废除原每 1 秒一次的忙碌轮询，将保底一致性检查降低至低频（30 秒）；失败重试由退避计时器在到达最早 `next_retry` 时精准唤醒。

---

## 5. 执行闭环设计与生命周期

### 5.1 协调循环核心算法（解绑清理优先，杜绝死锁）

为解决 S3 中“解绑后因无当前绑定而挂起、导致旧条目无法清理”的循环等待，将**停机与 retired 清理置于当前网卡就绪检查之前**：

```text
       ┌────────────────────────────────────────────────────────┐
       │ 唤醒源: 命令通道 (cmd) OR watch 通知 OR 重试/保底定时器 │
       └──────────────────────────┬─────────────────────────────┘
                                  ↓
       ┌────────────────────────────────────────────────────────┐
       │ 1. 处理所有命令 (Bind/Unbind/ConfirmDestroy/Stop)      │
       │    - Unbind: 当前 binding 归档至 retired, 回复 ack      │
       │    - ConfirmDestroy: 注销指定 generation 的旧记录      │
       │    - Stop: 进入停机清理流程                            │
       └──────────────────────────┬─────────────────────────────┘
                                  ↓
       ┌────────────────────────────────────────────────────────┐
       │ 2. 优先清理 retired_bindings 中的旧条目 (即使无新网卡!)  │
       │    - 遍历 retired 后端执行 remove_route                │
       │    - 成功或确认不存在 -> 移出记录                      │
       │    - 失败 -> 记录退避；结果不明 -> 记入 pending_ops     │
       └──────────────────────────┬─────────────────────────────┘
                                  ↓
       ┌────────────────────────────────────────────────────────┐
       │ 3. 检查当前网卡绑定 current_binding:                   │
       │    - 若为 None: 暂停安装新路由，继续监听并休眠           │
       │    - 若为 Some: 进入正常比对与下发流程                 │
       └──────────────────────────┬─────────────────────────────┘
                                  ↓
       ┌────────────────────────────────────────────────────────┐
       │ 4. 检查输入快照/配置变化: 未变且无到期重试项则休眠     │
       │ 5. 纯策略计算: desired_routes                          │
       │ 6. 计算差异: to_remove = installed - desired           │
       │             to_add    = desired - installed           │
       │ 7. 逐项有界执行 (每 16 项检查一次取消与代际失效):       │
       │    a. 执行 to_remove: 成功 -> 移除记录                 │
       │    b. 执行 to_add:    成功 -> 插入 InstalledRoute      │
       │                       已存在 -> 不入账，记录警告       │
       │                       确定失败 -> 启动指数退避         │
       │                       结果不明 -> 记入 pending_ops     │
       └────────────────────────────────────────────────────────┘
```

### 5.2 失败退避与有界调度

1. **单项指数退避**：
   对执行失败的路由条目（无论添加还是删除），记录其 `RetryState { attempt: u32, next_retry: Instant }`。
   退避序列：100ms, 200ms, 400ms, 800ms, 1.6s, 最高封顶 5s。
   在下一轮循环计算差异时，**尚未到达 `next_retry` 的失败项不被选入当轮执行队列**。当输入变化使该条目不再需要时，重试状态自动释放。这彻底防止了因无关配置变化或频繁 OSPF 广播导致同一个底层错误被高频重试（防事件风暴）。
2. **中途失效丢弃过时计划**：
   在遍历执行 `to_remove` 和 `to_add` 时，每处理 16 项（或每个耗时操作后）检查一次 `cancel_token`、网卡代际与输入版本。若检测到网卡已失效或新输入涌入，**立即终止执行余下过时条目**，将已成功的操作正确记账后，立即进入下一轮最新全量比对。
3. **替换依赖顺序保证**：
   若同一个槽位（相同目标 CIDR）需要替换（例如 metric 变更），必须**先执行并确认删除成功，才允许尝试添加**。删除若失败，严禁盲目执行添加。

### 5.3 接口重建与多代际记录管理

为防止 TUN 重建、更名或 DHCP 换卡时丢失旧责任：
1. **多代际跟踪模型**：
   当 Host 触发网卡重建或切换时，调用 `handle.unbind_interface().await`：
   - Manager 接收命令，将当前 `(current_binding, backend, installed, pending)` 打包为 `RetiredBindingContext` 移入 `retired_bindings`。
   - Manager 确认所有当前单项在途操作完成并记账后，向 Host 回复 ack。
   - Host 收到 ack 后，明确获知旧绑定已解绑且无后台悬挂 I/O，此时可安全关闭或替换旧网卡底层。
2. **旧责任清理与物理销毁确认**：
   - 若旧设备已被底层操作系统物理销毁（内核自动级联清空其路由），Host 调用 `handle.confirm_interface_destroyed(gen).await`，Manager 安全注销对应代际的记录。
   - 若旧网卡仍存在（如仅更改 IP 或逻辑重建），Manager 循环在步骤 2 中调用旧后端的 `remove_route` 执行精确清理。
   - **绝不把旧接口记录挪用给新接口后端删除**，彻底消除代际混淆。

### 5.4 停机流程与超时保证 (`stop(deadline)`)

```rust
pub struct CleanupIncomplete {
    pub uncleaned_active: Vec<InstalledRoute>,
    pub uncleaned_retired: Vec<InstalledRoute>,
    pub pending_unknown: Vec<PendingOperation>,
    pub in_flight_operation: Option<RouteSpec>,
    pub reason: String,
}
```

停机调用 `handle.stop(deadline)` 时严格执行以下步骤（S2 闭合）：
1. **打断调度**：触发 `cancel_token.cancel()`，拒绝接收新添加请求。
2. **限时等待在途单项系统调用**：
   - 使用 `tokio::time::timeout_at(deadline, ...)` 等待当前正在 `spawn_blocking` 中执行的单项系统调用完成。
   - 若系统调用在 deadline 前完成，将其结果如实记入账目或 `pending_operations`。
   - 若 deadline 到期但该底层系统调用仍在执行，**绝不通过粗暴 abort 破坏操作系统状态**，而是将其记录在 `in_flight_operation` 中，立即向调用方返回 `CleanupIncomplete`。
3. **限时精确清理**：
   - 若在途操作及时完成，继续遍历 `installed_routes` 与 `retired_bindings`，调用对应后端的 `remove_route`。
   - 每步操作均检查当前时间是否超过 `deadline`。
4. **失败与未决完全可见**：
   - 仅当全部已安装记录清空且 `pending_operations` 为空、且无在途操作时，返回 `Ok(())`。
   - 若超时、存在删除失败项、或存在未决操作（`PendingOperation`），**返回 `Err(CleanupIncomplete { .. })`**。
   - **宿主保持持有 Handle**：因 `stop(&self)` 采用借用，Host 在收到 `CleanupIncomplete` 后依然持有 `RouteManagerHandle`，可在后续继续通过 `join_handle` 观察后台在途任务的最终退出，绝不提前启动相竞争的新 writer。

---

## 6. 写入权交接与动态冲突防御

### 6.1 写入权控制与开关时序

在启动 Host 时，依据 `RouteBackendMode` 统一决策写入权：

```text
Host 启动 / 初始化
   │
   ├─► 若 RouteBackendMode::NativeManager (Linux 生产默认 / 测试):
   │     ├─► 1. 禁用 ProxyCidrMonitor 的外部路由派发
   │     ├─► 2. VirtualNic 跳过创建 run_proxy_cidrs_route_updater
   │     └─► 3. 启动 HostRouteManager 协调循环，接管路由写入
   │
   └─► 若 RouteBackendMode::Legacy (Windows / macOS / 移动端生产默认):
         ├─► 1. 正常启动 VirtualNic::run_proxy_cidrs_route_updater (或 mobile_vpn)
         └─► 2. 不启动 HostRouteManager，由旧链路安全维持运行
```

### 6.2 动态全量代理的重叠冲突防御与交接时序（S4 闭合）

在第二步中，Magic DNS（`fake_ip/32`）与 macOS/FreeBSD 接口前缀依然由旧代码写入。

**DNS 清理路径真实改造**：
1. 修改 `easytier/src/instance/dns_server/server_instance.rs`：`clean_env(&self) -> Result<(), anyhow::Error>`，捕获并返回 `remove_ipv4_route` 的底层系统结果，不再使用 `let _ =` 吞掉错误。
2. 修改 `dns_server/runner.rs`：`DnsRunner` 退出时向外部传递 `clean_env()` 的执行结果。
3. 修改 `runtime_host/magic_dns.rs`：`MagicDnsRuntime::stop(&mut self) -> Result<(), anyhow::Error>`，向上抛出真实清理结果。

**未迁移上下文动态追踪 (`UnmigratedRouteTracker`)**：
- 动态事实：`dns_status: UnmigratedWriterStatus`（包含 `Active`、`Inactive`、`CleaningFailed(Error)`）、`magic_dns_ip: Option<Ipv4Addr>`、`tun_cidr: Option<Ipv4Cidr>`。
- 冲突判定条件：仅当 DNS 启用且 `magic_dns_ip` **处于 TUN 子网网段之外**时，DNS 才实际需要添加主机路由 `/32`（若在子网内，接口直连路由已涵盖，无冲突）。

**生命周期交接顺序（预留冲突范围 $\to$ 等待原 writer 清理确认 $\to$ 启动接手 writer）**：
1. **场景 A：Manager 已安装代理路由 $P$，随后外部事实变化导致未迁移 DNS 也需要 $P$**：
   - **预留范围**：Host 更新 `UnmigratedRouteTracker`，将 $P$ 标记为待接手预留状态。
   - **触发清理**：Manager 协调循环被唤醒，策略函数将 $P$ 从 desired 中剔除：
     - 若 Manager 从未安装 $P$ 且无在途操作：立即向 Tracker 发放预留确认。
     - 若 $P$ 正在添加（在途）：Manager 等待在途操作完成，若成功则立即触发删除，成功后发放确认。
     - 若 $P$ 已安装：Manager 调用 `remove_route(P)`，成功后发放确认。
   - **启动旧 Writer**：DNS 模块收到确认后，方可调用底层系统接口写入 $P$。
   - **失败防御**：若 Manager 删除 $P$ 失败，Tracker 绝不发放确认，DNS 模块中止写入并报错，绝不产生双写踩踏。
2. **场景 B：反向交接（未迁移 DNS 停止，将 $P$ 释放给 Manager）**：
   - DNS 模块退出并调用 `clean_env()` 删除 $P$。
   - `MagicDnsRuntime::stop()` 向上返回删除结果：
     - 若删除成功：Tracker 将状态置为 `Inactive`，释放预留范围并唤醒 Manager。Manager 策略函数解除抑制，将 $P$ 纳入 desired 并下发安装。
     - 若删除失败：Tracker 将状态置为 `CleaningFailed`，**继续保留排除范围**！Manager 绝不安装 $P$，防止在系统仍残留旧路由时引发冲突。
3. **场景 C：macOS / FreeBSD 显式接口前缀与 TUN 重建**：
   - macOS/FreeBSD 接口直连路由在 TUN 创建时由系统/旧脚本写入；`UnmigratedRouteTracker` 记录 `tun_cidr`，Manager 策略函数自动排除与 `tun_cidr` 相同的代理路由。
   - 换卡时，旧 TUN 必须先完成停止与 drain，确认旧接口销毁或由旧后端清理完路由后，才允许向新 TUN 下发新路由。

---

## 7. 性能开销分析与测量指标

为落实 master plan 对性能选择的明确要求，说明各项优化的实现机理与测量方法：

### 7.1 稳态零多余操作与零堆分配
- **机理说明**：
  现有 `cidr_monitor.rs:165–176` 每 1 秒轮询检查一次更新时间戳与配置指针；当检测到变化时，调用 `collect_proxy_cidr_diff_from_snapshot` 执行 `collect()` 构建新的 `BTreeSet`。
  新方案彻底废除 1 秒定时轮询，改为 Core 快照提交驱动的 `watch` 通知。协调循环利用快照指针（`Arc::ptr_eq`）快速拦截，稳态下不拉取路由表、不创建集合、不执行 diff 比对。
- **测量方法**：
  - 测试手段：MockBackend 统计底层调用计数，结合内存分配跟踪器（如全局 allocator 探针）。
  - 验收基准：在 60 秒稳态运行期间，底层路由调用次数严格为 0；协调循环迭代的堆分配次数为 0。

### 7.2 平台连接复用
- **机理说明**：
  现有实现针对每个路由操作临时建立 Netlink socket。新方案在 Linux 原生后端的单次网卡绑定生命周期内持久持有单个 Netlink socket 实例，跨迭代持续复用。
- **测量方法**：
  - 测试手段：使用 `strace -c -e socket,bind,close` 追踪单次网卡生命周期内的路由操作系统调用。
  - 验收基准：在持续增删 100 次路由场景下，Netlink 相关套接字的创建次数严格等于后端单次绑定的 1 次（允许在网卡重绑或致命连接恢复时重新建连）。

### 7.3 消除用户态逐条 Dump
- **机理说明**：
  现有 Linux `remove_ipv4_route` 每次删除均在用户态全量调用 `list_routes` 进行遍历匹配（产生 $O(N \times M)$ 的 Netlink dump 与遍历开销）。新方案改为直接填入网卡、目标、priority 与 table 参数发送单发 `RTM_DELROUTE` 报文，单条删除请求数量恒定为 1，杜绝用户态全表扫描。
- **测量方法**：
  - 测试手段：编写批量删除 100 条路由的基准测试，统计 Netlink 交互报文类型。
  - 验收基准：删除 100 条路由时，Netlink 请求消息严格为 100 个 `RTM_DELROUTE`，`RTM_GETROUTE` dump 消息数严格为 0。对比记录真实总耗时。

---

## 8. 分批实施顺序与验证矩阵

分批实施划分为 5 个独立可编译、可测试的批次：

```text
Batch 1: 纯计算与轻量模型 (Core 快照与算法 + Host 策略、模型与未决操作)
   ↓
Batch 2: 精确删除改造与平台后端 (Netlink 消除 dump、长连接、Mock 后端)
   ↓
Batch 3: HostRouteManager 核心闭环 (命令通道、退避重试、多代际记录、stop deadline)
   ↓
Batch 4: Host 真实生命周期接线与交接 (runtime_host 挂载、DNS 确认闭合、旧 updater 屏蔽)
   ↓
Batch 5: 隔离环境原生测试与基准度量 (netns 真实系统调用、零 dump、零写度量)
```

### 8.1 分批实施详细任务

#### Batch 1：纯计算与轻量模型
- **代码落点**：
  - `easytier-core/src/peers/route/peer_ospf_route.rs`：在 `update_route_table` 维护 `Arc<BTreeSet<Ipv4Cidr>>` 快照并导出 `watch`。
  - `easytier-core/src/instance/packet_plane.rs`：导出 `list_proxy_cidrs_snapshot` 与 `subscribe_proxy_cidrs`。
  - `easytier-core/src/peers/route/projection.rs`：纯函数 `normalize_v4_cidr`（基于 `Ipv4Inet::network()`）。
  - `easytier/src/instance/route/model.rs`：`RouteSpec`、`InstalledRoute`、`PendingOperation`、`InterfaceBinding` 及结果枚举。
  - `easytier/src/instance/route/policy.rs`：Host 策略计算 `calculate_desired_proxy_routes`。
- **验证**：
  - 单元测试：主机位非零安全规范化（`10.0.0.1/24` $\to$ `10.0.0.0/24`，无 panic）、`/0` 与 `/32` 边界测试、非法前缀（> 32 返回错误）测试、`manual_routes` 三态测试、未迁移 DNS `/32` 碰撞排除测试。

#### Batch 2：精确删除改造与平台后端
- **代码落点**：
  - `easytier/src/common/ifcfg/netlink.rs`：改造 `remove_ipv4_route`，消除全量 dump，直接匹配 destination, oif, priority, table 发送 `RTM_DELROUTE`。
  - `easytier/src/instance/route/backend.rs`：`NativeRouteBackend`、`DelegatedRouteBackend`、`MockRouteBackend`。
- **验证**：
  - 单元测试：同接口、同前缀但不同 metric 的精确删除测试（验证外部 metric 路由不被误删）；Mock 后端记录核对测试。

#### Batch 3：HostRouteManager 核心闭环
- **代码落点**：
  - `easytier/src/instance/route/manager.rs`：实现 `HostRouteManager` 协调循环、命令通道（Bind/Unbind/ConfirmDestroy/Stop）、快照指针比对、未决操作追踪、失败指数退避、中途失效检查、多代际记录跟踪与 `stop(deadline)`。
- **验证**：
  - 基于 `MockRouteBackend` 的闭环测试：
    - 首启全量添加；
    - 输入未变稳态 0 调用与 0 堆分配；
    - 单项失败指数退避与重试（风暴下不频繁重发）；
    - 解绑后无新网卡时，旧条目依然正常执行清理；
    - 未决操作测试：添加注入 `OutcomeUnknown`，随后撤销需求并 stop，验证返回 `CleanupIncomplete` 携带未决项，不误报成功；
    - Stop 超时与跟踪句柄测试：注入耗时操作超过 deadline，验证按时返回未完成状态，且 Host 仍持有 Handle 跟踪后台完成；
    - No-TUN 旁路测试（执行分支跳过，已安装记录保持为空）。

#### Batch 4：Host 真实生命周期接线与交接
- **代码落点**：
  - `easytier/src/instance/dns_server/server_instance.rs` & `runner.rs` & `runtime_host/magic_dns.rs`：`clean_env()` 返回结构化结果并向上抛出。
  - `easytier/src/instance/runtime_host.rs` & `tun_desktop.rs` / `tun_common.rs` / `implementation.rs`：接入 `RouteManagerHandle`，在网卡就绪时（包括 DHCP 延迟建卡与静态卡）调用 `bind_interface`，在关闭时调用 `stop(deadline)`。
  - `easytier/src/instance/virtual_nic.rs`：按 `RouteBackendMode` 停用 `run_proxy_cidrs_route_updater`。
- **验证**：
  - 集成测试：启动集成测试节点，动态推送 `manual_routes`，验证真实 Manager 接管生效且旧 updater 不重复写入；
  - 交接时序测试：
    1. Manager 已装 $P$ $\to$ DNS 需要 $P$ $\to$ DNS 等待 Manager 删除确认 $\to$ Manager 删除成功后 DNS 写入；
    2. 反向交接：DNS 停用并删除 $P$ $\to$ Manager 接手安装 $P$；
    3. 故障注入 A：Manager 删除 $P$ 注入失败 $\to$ 验证 DNS 模块未被提前放行，杜绝双写；
    4. 故障注入 B：DNS 停止删除 $P$ 注入失败 $\to$ 验证 Tracker 保留排除，Manager 不接手，杜绝双写。

#### Batch 5：隔离环境原生测试与基准度量
- **代码落点**：
  - 测试用例：`easytier/src/instance/route/tests/linux_netlink_tests.rs`（使用独立 netns 运行真实系统调用）。
  - 基准测试：`benches/route_manager_bench.rs`。
- **验证**：
  - 在 Linux 隔离 netns 下运行真实 Netlink 路由增删与精确删除；
  - 测量矩阵（遵循 master plan 第 7 节）：
    - 路由规模：100 条、1,000 条、10,000 条路由；
    - 场景：批量下发、单条增删、批量替换、无关配置变动、通知竞态、部分失败；
    - 统计指标：P50 / P99 延迟分位数、系统调用次数、Netlink 报文数；
    - 基准度量：批量删除 100 条路由确认 0 个 `RTM_GETROUTE` dump；稳态运行 60 秒确认 0 次系统调用。

---

## 9. 进入第三步的验收门槛

在宣布第二步完成并进入第三步前，必须逐项核对满足以下门槛：

- [ ] **计算正确且无 Panic**：CIDR 主机位非零（如 `10.0.0.1/24`）通过 `Ipv4Inet::network()` 安全规范化；自动代理、手工覆盖与显式空集均准确计算。
- [ ] **依赖方向合规**：`easytier-core` 绝无引用 `easytier` 类型，所有构建目标独立可编译；Core 快照与 watch 独立于 Host。
- [ ] **精确删除与身份完整**：已安装记录保存实际创建参数与接口代际；同接口同前缀下不同 metric 的外部路由不被误删。
- [ ] **稳态零多余操作**：在网络拓扑与配置稳定的状态下，快照指针比对快速拦截，协调循环不产生多余的底层系统调用和堆内存分配；无关服务配置变动不引发路由重算。
- [ ] **无全表 Dump**：Linux 下删除路由直接构造 `RTM_DELROUTE`，基准测试验证 0 次 `RTM_GETROUTE` dump。
- [ ] **失败退避与未决记账**：添加/删除失败如实记账并不误报成功；失败项执行指数退避；结果不明记录为未决操作，停机时作为未完成项上报。
- [ ] **停机超时与持续追踪**：`stop(deadline)` 限时清理；超时或存在未决项返回 `CleanupIncomplete`，Host 持续持有 Handle 跟踪后台在途操作，绝不虚报成功。
- [ ] **解绑清理不饥饿**：接口解绑后即使处于无网卡状态，旧条目清理仍正常推进，不产生循环等待死锁。
- [ ] **重叠交接安全**：自动或手工代理与未迁移 DNS `/32` 或接口前缀重叠时，通过动态交接防御机制排除冲突条目；DNS 清理结果真实回传，删除失败时不提前放行后续 writer，阶段一不存在同一实际条目的新旧双写。
- [ ] **接口重建代际清晰**：网卡失效后旧记录与新记录分别由各自代际与专属后端跟踪，旧责任在底层物理销毁或删除确认后注销，新接口正常重新下发。
- [ ] **生产控制一致**：在第二步启用的平台（Linux 原生）完全由 HostRouteManager 接管且旧 updater 停写；未迁移平台（Windows、macOS、移动端）由统一开关安全保持旧链路，不发生漏写或双写。
