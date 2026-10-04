# HostRouteManager 第二步实施方案：最小 Manager 闭环（第五轮修订版）

状态：已根据第三次审查意见（[`docs/host-route-manager-step2-review-3.md`](host-route-manager-step2-review-3.md)）完成深度修订。严格遵循最新实施总纲（[`docs/host-route-manager-master-plan.md`](host-route-manager-master-plan.md)）与第一步规范（[`docs/host-route-manager-step1-audit-and-contract.md`](host-route-manager-step1-audit-and-contract.md)）。  
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
  - 在 `PeerRouteServiceImpl::update_route_table` 提交边界计算并缓存不可变快照 `Arc<BTreeSet<Ipv4Cidr>>`。
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
  - 改造 Magic DNS 真实清理路径：解耦系统 DNS 配置恢复与路由删除，`clean_env()` 返回结构化结果，传递至 `DnsRunner` 与 `MagicDnsRuntime::stop()`。

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
              │     ├── server_instance.rs  [修改] clean_env() 解耦系统配置并真实返回路由删除结果 Result<(), Error>
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

**未决操作处理约束（S1 / T4 闭合）**：
1. **不因需求撤销而丢弃**：若某条路由添加返回 `OutcomeUnknown`，随后外部需求撤销，该条目的 `PendingOperation` **必须保留**，绝不能因不在 desired 中就直接丢弃。
2. **不冒充认领**：未决添加不能视为 `Created`，也不能仅凭系统中存在同名前缀就草率认领。
3. **阻塞交接与停机可见性**：
   - 存在对应网段的未决操作时，严禁向 DNS 或外部 writer 发放预留交接确认，保持阻塞；
   - 严禁盲目重复下发添加或擅自调用删除；
   - 在 `stop(deadline)` 时，若存在未决操作，**必须作为未完成项返回**，绝不返回清理完成。

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

### 3.4 Manager 结构与内部控制命令

为消除解绑时的循环等待死锁，并在接口交接中提供明确的所有权和执行屏障，Manager 引入内部控制命令：

```rust
// easytier/src/instance/route/manager.rs

pub enum ManagerCommand {
    /// 绑定新接口：更新 binding，重置 installed，并将 execution_dirty 置为 true 强制下发期望路由
    BindInterface {
        binding: InterfaceBinding,
        backend: Box<dyn NativeRouteBackend>,
        ack: tokio::sync::oneshot::Sender<()>,
    },
    /// 接口解绑：停止该接口的一切新 I/O，归档至 retired，冻结等待宿主决策，回复 ACK
    UnbindInterface {
        ack: tokio::sync::oneshot::Sender<()>,
    },
    /// 宿主确认底层设备已物理销毁（内核已级联删除路由）：直接注销对应代际的旧记录
    ConfirmInterfaceDestroyed {
        generation: u64,
        ack: tokio::sync::oneshot::Sender<()>,
    },
    /// 宿主明确保留旧网卡设备：授权 Manager 启动针对该 retired 后端的精确 remove_route 清理
    CleanupRetiredInterface {
        generation: u64,
        ack: tokio::sync::oneshot::Sender<Result<(), anyhow::Error>>,
    },
    /// 显式停机：携带统一 deadline
    Stop {
        deadline: std::time::Instant,
        ack: tokio::sync::oneshot::Sender<Result<(), CleanupIncomplete>>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetiredBindingState {
    /// 已解绑，已停止所有 I/O，冻结等待宿主决策 (严禁自主发起 remove_route)
    FrozenAwaitingDecision,
    /// 宿主明确保留设备并交回控制，正在执行精确清理
    CleaningActive,
}

pub struct RetiredBindingContext {
    pub binding: InterfaceBinding,
    pub backend: Box<dyn NativeRouteBackend>,
    pub installed: std::collections::BTreeMap<RouteSpec, InstalledRoute>,
    pub pending: std::collections::BTreeMap<RouteSpec, PendingOperation>,
    pub state: RetiredBindingState,
}

pub struct HostRouteManager {
    backend: RouteBackend,
    /// 当前活跃绑定的已安装路由记录 (spec -> InstalledRoute)
    installed_routes: std::collections::BTreeMap<RouteSpec, InstalledRoute>,
    /// 待清理的旧绑定及其专属后端、残留记录、未决操作与状态
    retired_bindings: Vec<RetiredBindingContext>,
    /// 未决操作记录表 (记录 OutcomeUnknown 项)
    pending_operations: std::collections::BTreeMap<RouteSpec, PendingOperation>,
    /// 失败重试退避追踪表 (限制事件风暴下的反复重试)
    retry_tracker: std::collections::BTreeMap<RouteSpec, RetryState>,
    /// 当前网卡绑定上下文
    current_binding: Option<InterfaceBinding>,
    /// 纯业务期望路由投影缓存 (仅当 Core 输入快照变化时重算)
    desired_routes_cache: Option<Arc<Vec<RouteSpec>>>,
    /// 上一轮输入快照指针与路由相关配置
    last_peer_cidrs: Option<Arc<std::collections::BTreeSet<cidr::Ipv4Cidr>>>,
    last_manual_routes: Option<Option<std::collections::BTreeSet<cidr::Ipv4Cidr>>>,
    /// 执行差异标记：当新接口绑定、期望集变化、重试到期或被请求清理时置为 true
    execution_dirty: bool,
    /// 命令接收通道
    cmd_rx: tokio::sync::mpsc::Receiver<ManagerCommand>,
    /// 停机令牌
    cancel_token: tokio_util::sync::CancellationToken,
}

#[derive(Clone)]
pub struct RouteManagerHandle {
    cmd_tx: tokio::sync::mpsc::Sender<ManagerCommand>,
    join_handle: Arc<tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>>,
    cancel_token: tokio_util::sync::CancellationToken,
}

impl RouteManagerHandle {
    /// 接口创建/重建时更新绑定 (等待 Manager 确认切换并置 dirty)
    pub async fn bind_interface(&self, binding: InterfaceBinding, backend: Box<dyn NativeRouteBackend>) -> anyhow::Result<()> { ... }
    /// 接口注销/失效时解绑 (等待 Manager 确认旧条目已冻结归档，且当前在途 I/O 结算完毕)
    pub async fn unbind_interface(&self) -> anyhow::Result<()> { ... }
    /// 宿主销毁网卡后调用确认 (注销对应 generation，无冗余调用)
    pub async fn confirm_interface_destroyed(&self, generation: u64) -> anyhow::Result<()> { ... }
    /// 宿主保留网卡时授权清理 (由 Manager 执行精确清理)
    pub async fn cleanup_retired_interface(&self, generation: u64) -> anyhow::Result<()> { ... }
    /// 显式停机：借用 Handle，整个等待严格受 deadline 约束；超时返回未完成信息，原持有者继续保留 Handle 与 JoinHandle
    pub async fn stop(&self, deadline: std::time::Instant) -> Result<(), CleanupIncomplete> { ... }
}
```

---

## 4. 输入接线与无冗余调度

### 4.1 输入接线映射表

Manager 绝不通过虚假消息总线通信，而是直接绑定各组件的权威只读入口：

| 来源分类 | 读取入口 (Read API) | 快照提交点 (Commit Point) | 通知方式 (Wakeup) |
| :--- | :--- | :--- | :--- |
| **Core Peer 路由** | `CorePacketPlane::list_proxy_cidrs_snapshot() -> Arc<BTreeSet<Ipv4Cidr>>` | OSPF 路由表更新处 (`PeerRouteServiceImpl::update_route_table`) 提交 `ArcSwap` | Core 自有的 `watch::Receiver<Arc<BTreeSet<Ipv4Cidr>>>` 触发唤醒 |
| **手工静态配置** | `CoreRuntimeConfigStore::snapshot().services.manual_routes` | 配置变更原子提交处 | 订阅 `subscribe_service_runtime_changes()` 唤醒 |
| **Host 未迁移事实** | `UnmigratedRouteTracker::snapshot()` | DHCP lease 变更、TUN IP 变更、DNS 启停提交处 | 提交处内部触发 Manager 唤醒通知 |

### 4.2 订阅与初态读取顺序

为杜绝启动初始化期间的事件丢失，严格执行**先订阅、后读初态**（`subscribe -> read_initial`）原则：
1. 先建立 `CorePacketPlane` 的 proxy cidrs `watch` 订阅与 `CoreRuntimeConfigStore` 服务订阅。
2. 立即拉取各来源的初始快照，装配初态。
3. 启动协调循环。在订阅与初态读取之间到达的任何并发更新，均会通过已注册的通道准确唤醒。

### 4.3 稳态零多余计算与执行跳过机制（T3 闭合）

方案严格区分**业务期望投影计算**与**系统差异协调执行**：

1. **业务期望投影计算与快照缓存 (`desired_routes_cache`)**：
   - 比较 `Arc::ptr_eq(&last_peer_cidrs, &current_peer_cidrs)`；
   - 比较 `current_config.services.manual_routes == last_manual_routes`（**忽略与路由无关的其他服务配置变更**，如 Socks5/DHCP 配置变动不引发重算）；
   - 比较未迁移事实快照。
   - 若三者均未改变，**直接复用 `desired_routes_cache: Arc<Vec<RouteSpec>>`**，0 次策略计算，0 次内存分配！
2. **系统差异协调执行标记 (`execution_dirty`)**：
   - `execution_dirty` 独立于业务输入快照。以下情况**必须置为 `true`**：
     - **新网卡绑定**：收到 `BindInterface` 命令时，设置 `execution_dirty = true`；
     - **业务期望集发生实质变更**（计算出新的 `desired_routes`）；
     - **重试定时器到期**（存在到期的失败项需重新尝试）；
     - **旧绑定被授权清理**（收到 `CleanupRetiredInterface` 命令）。
3. **快速跳过执行条件**：
   协调循环仅在同时满足以下条件时跳过执行差异并休眠：
   - `!execution_dirty`；
   - 当前网卡已绑定且已完成协调（`installed_routes` 与 `desired_routes_cache` 一致）；
   - 无到期的重试项；
   - `retired_bindings` 中无处于 `CleaningActive` 的待处理项。
   **当同配置、同地址的新网卡绑定时**，虽然输入快照未变，但 `execution_dirty == true` 强制执行一次协调：复用缓存的 `desired_routes`，计算 `to_add = desired - installed`（全量下发至新网卡），保证新网卡立即安装全部期望路由！

---

## 5. 执行闭环设计与生命周期

### 5.1 协调循环核心算法（解绑交接与执行顺序）

```text
       ┌────────────────────────────────────────────────────────┐
       │ 唤醒源: 命令通道 (cmd) OR watch 通知 OR 重试/保底定时器 │
       └──────────────────────────┬─────────────────────────────┘
                                  ↓
       ┌────────────────────────────────────────────────────────┐
       │ 1. 批量处理当前到达的所有命令:                          │
       │    - Bind: 设置 current_binding, 清空 installed,       │
       │            置 execution_dirty = true, 回复 ack          │
       │    - Unbind: 停止当前 I/O, 归档至 retired (Frozen),     │
       │              回复 ack (承诺绝不自主对旧网卡发起 I/O)    │
       │    - ConfirmDestroy: 注销指定 generation 的旧记录       │
       │    - CleanupRetired: 置对应 retired 为 CleaningActive,  │
       │                      置 execution_dirty = true         │
       │    - Stop: 进入全局限时停机流程                         │
       └──────────────────────────┬─────────────────────────────┘
                                  ↓
       ┌────────────────────────────────────────────────────────┐
       │ 2. 处理已授权清理的 retired_bindings (CleaningActive):  │
       │    - 遍历对应 retired 后端执行 remove_route            │
       │    - 成功或确认不存在 -> 移出记录                      │
       │    - 失败 -> 记录退避；结果不明 -> 记入 pending_ops     │
       │    - (Frozen 状态的旧绑定在此处完全跳过，严禁触碰)      │
       └──────────────────────────┬─────────────────────────────┘
                                  ↓
       ┌────────────────────────────────────────────────────────┐
       │ 3. 检查当前网卡绑定 current_binding:                   │
       │    - 若为 None: 暂停安装新路由，继续监听并休眠           │
       │    - 若为 Some: 检查输入快照并按需更新 desired_routes    │
       └──────────────────────────┬─────────────────────────────┘
                                  ↓
       ┌────────────────────────────────────────────────────────┐
       │ 4. 若 !execution_dirty: 直接休眠 (稳态零多余操作)       │
       │ 5. 计算差异: to_remove = installed - desired           │
       │             to_add    = desired - installed           │
       │ 6. 逐项有界执行 (每 16 项检查一次取消与代际失效):       │
       │    a. 执行 to_remove: 成功 -> 移除记录                 │
       │    b. 执行 to_add:    成功 -> 插入 InstalledRoute      │
       │                       已存在 -> 不入账，记录警告       │
       │                       确定失败 -> 启动指数退避         │
       │                       结果不明 -> 记入 pending_ops     │
       │ 7. 本轮差异处理完毕，重置 execution_dirty = false       │
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

### 5.3 接口重建与解绑交接屏障（T2 闭合）

为彻底杜绝“Manager 在 Host 关闭旧接口后并发发送删除指令导致 ifindex 踩踏”的问题，交接时序严格遵守以下契约：

1. **解绑冻结与无 I/O 承诺 (`UnbindInterface`)**：
   - Host 触发网卡重建或切换时，调用 `handle.unbind_interface().await`；
   - Manager 收到命令后，停止对当前绑定的所有新 I/O，等待当前单项在途操作完成并记账；
   - 将当前绑定及其记录、未决操作打包为 `RetiredBindingContext`，**其状态标记为 `FrozenAwaitingDecision`**；
   - Manager 向 Host 发送 ACK。
   - **关键保证**：在收到 Host 明确指令之前，Manager **绝不主动对该 retired 绑定发起任何系统调用**！
2. **Host 处理网卡底层与分支确认**：
   - **分支 1（销毁网卡，最常见的 TUN 重建路径）**：
     Host 安全关闭/注销底层 TUN 设备（内核自动级联删除其所有路由）。Host 调用 `handle.confirm_interface_destroyed(gen).await`。Manager 收到后，确认设备已物理销毁，直接从 `retired_bindings` 注销丢弃对应代际的所有记录。从 ACK 到销毁确认之间，**旧后端调用数严格为 0**！
   - **分支 2（保留网卡，仅逻辑解绑/换 IP）**：
     Host 保留设备，调用 `handle.cleanup_retired_interface(gen).await` 交回控制。Manager 将其状态转为 `CleaningActive`，并置 `execution_dirty = true`，安全启动精确清理。

### 5.4 停机流程与超时保证 (`stop(deadline)`)（T1 闭合）

```rust
pub struct CleanupIncomplete {
    pub uncleaned_active: Vec<InstalledRoute>,
    pub uncleaned_retired: Vec<InstalledRoute>,
    pub pending_unknown: Vec<PendingOperation>,
    pub in_flight_operation: Option<RouteSpec>,
    pub reason: String,
}
```

停机调用 `handle.stop(deadline)` 时严格执行以下步骤，**确保整个等待过程全程受 deadline 严格约束**：

1. **立即打断调度**：
   在 `handle.stop()` 入口处，**立即触发 `cancel_token.cancel()`**，拒绝接收新添加请求。
2. **外层调用限时约束**：
   `RouteManagerHandle::stop(&self, deadline: Instant)` 的**整个调用被 `tokio::time::timeout_at(deadline, ...)` 包裹**：
   - 发送 `ManagerCommand::Stop { deadline, ack }` 并等待 ACK；
   - 若发送命令等待超时、或 Manager 处理超时，外层 `timeout_at` 准时在 `deadline` 到达时返回 `Err(CleanupIncomplete { reason: "Deadline exceeded during stop", .. })`；
   - **绝不通过 task abort 取消 Manager**：Manager 任务在后台继续平稳运行，等待在途系统调用正常返回并记账；
   - **宿主保持持有 Handle**：因 `stop(&self)` 采用借用，Host 在收到 `CleanupIncomplete` 后依然持有 `RouteManagerHandle`，可继续通过 `join_handle` 观察后台在途任务的最终退出，绝不提前启动相竞争的新 writer。
3. **Manager 内部限时执行与句柄独占**：
   - Manager 处理 Stop 命令时，若当前存在正在 `spawn_blocking` 中执行的在途操作，使用 `tokio::time::timeout_at(deadline, in_flight_rx)` 等待其完成；
   - 若在途操作超时未完，Manager 独占其结果接收句柄，将其记录为 `in_flight_operation`，立即向 ACK 发送 `CleanupIncomplete`；
   - 若在途操作及时完成，Manager 进入清理循环，对 `installed_routes` 与 `retired_bindings` 依次调用 `remove_route`，每项操作均受 `timeout_at(deadline)` 保护；
   - 仅当全部已安装记录清空、`pending_operations` 为空且无在途操作时，返回 `Ok(())`；否则返回包含未完成项的 `CleanupIncomplete`。

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

### 6.2 动态全量代理的重叠冲突防御与交接时序（T4 闭合）

在第二步中，Magic DNS（`fake_ip/32`）与 macOS/FreeBSD 接口前缀依然由旧代码写入。

**DNS 清理路径真实解耦改造**：
在 `easytier/src/instance/dns_server/server_instance.rs` 中，**将路由删除与系统 DNS 配置恢复彻底解耦，绝不将路由删除放在 `if let Some(configer)` 条件内**：

```rust
// dns_server/server_instance.rs
pub async fn clean_env(&self) -> Result<(), anyhow::Error> {
    let mut first_error = None;

    // 1. 系统 DNS 配置恢复 (独立执行，即便为 None 或失败也不跳过路由删除)
    if let Some(configer) = &self.data.system_config {
        if let Err(e) = configer.close() {
            tracing::error!("Failed to close system config: {:?}", e);
            first_error = Some(e);
        }
    }

    // 2. 路由清理：依据是否实际添加了主机路由独立执行，Linux (system_config=None) 正常执行！
    if !self.tun_inet.contains(&self.data.fake_ip)
        && let Some(tun_dev_name) = &self.data.tun_dev
    {
        let ifcfg = IfConfiger {};
        if let Err(e) = ifcfg.remove_ipv4_route(tun_dev_name, self.data.fake_ip, 32).await {
            tracing::error!("Failed to remove DNS ipv4 route: {:?}", e);
            if first_error.is_none() {
                first_error = Some(e.into());
            }
        }
    }

    self.packet_filter.close().await;

    if let Some(err) = first_error {
        Err(err)
    } else {
        Ok(())
    }
}
```
- 修改 `dns_server/runner.rs`：`DnsRunner` 退出时向外部传递 `clean_env()` 的执行结果。
- 修改 `runtime_host/magic_dns.rs`：`MagicDnsRuntime::stop(&mut self) -> Result<(), anyhow::Error>`，向上抛出真实清理结果。

**未迁移上下文动态追踪 (`UnmigratedRouteTracker`)**：
- 动态事实：`dns_status: UnmigratedWriterStatus`（包含 `Active`、`Inactive`、`CleaningFailed(Error)`）、`magic_dns_ip: Option<Ipv4Addr>`、`tun_cidr: Option<Ipv4Cidr>`。
- 冲突判定条件：仅当 DNS 启用且 `magic_dns_ip` **处于 TUN 子网网段之外**时，DNS 才实际需要添加主机路由 `/32`。

**生命周期交接顺序（预留冲突范围 $\to$ 等待原 writer 清理确认 $\to$ 启动接手 writer）**：
1. **场景 A：Manager 已安装代理路由 $P$，随后外部事实变化导致未迁移 DNS 也需要 $P$**：
   - **预留范围**：Host 更新 `UnmigratedRouteTracker`，将 $P$ 标记为待接手预留状态。
   - **触发清理**：Manager 协调循环被唤醒，策略函数将 $P$ 从 desired 中剔除：
     - **未决/在途检查**：若 $P$ 存在于 `pending_operations` 中，或正在在途添加，Manager **绝不发放预留确认，保持阻塞**！在途操作必须先结算，若添加成功则触发删除，若结果不明则持续阻塞。
     - **已安装检查**：若 $P$ 存在于 `installed_routes`（或未清理的 `retired_bindings`）中，Manager 调用 `remove_route(P)`，成功后方发放确认。
     - **完全无冲突**：只有当 $P$ 在本方记录（`installed`、`pending`、`in_flight`、`retired`）中均完全不存在时，才发放预留确认。
   - **启动旧 Writer**：DNS 模块收到确认后，方可调用底层系统接口写入 $P$。
   - **失败防御**：若 Manager 删除 $P$ 失败，Tracker 绝不发放确认，DNS 模块中止写入并报错，绝不产生双写踩踏。
2. **场景 B：反向交接（未迁移 DNS 停止，将 $P$ 释放给 Manager）**：
   - DNS 模块退出并调用解耦后的 `clean_env()` 删除 $P$。
   - `MagicDnsRuntime::stop()` 向上返回真实删除结果：
     - 若删除成功：Tracker 将状态置为 `Inactive`，释放预留范围并唤醒 Manager。Manager 策略函数解除抑制，将 $P$ 纳入 desired 并下发安装。
     - 若删除失败：Tracker 将状态置为 `CleaningFailed`，**继续保留排除范围**！Manager 绝不安装 $P$，防止在系统仍残留旧路由时引发冲突。
3. **场景 C：macOS / FreeBSD 显式接口前缀与 TUN 重建**：
   - macOS/FreeBSD 接口直连路由在 TUN 创建时由系统/旧脚本写入；`UnmigratedRouteTracker` 记录 `tun_cidr`，Manager 策略函数自动排除与 `tun_cidr` 相同的代理路由。
   - 换卡时，旧 TUN 必须先完成停止与解绑确认，旧责任注销或清理完毕后，才允许向新 TUN 下发新路由。

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
Batch 3: HostRouteManager 核心闭环 (命令通道、执行屏障、dirty 机制、stop deadline)
   ↓
Batch 4: Host 真实生命周期接线与交接 (runtime_host 挂载、DNS 确认闭合、旧 updater 屏蔽)
   ↓
Batch 5: 隔离环境原生测试与基准度量 (netns 真实系统调用、零 dump、零写度量)
```

### 8.1 分批实施详细任务

#### Batch 1：纯计算与轻量模型
- **代码落点**：
  - `easytier-core/src/peers/route/peer_ospf_route.rs`：在 `PeerRouteServiceImpl::update_route_table` 维护 `Arc<BTreeSet<Ipv4Cidr>>` 快照并导出 `watch`。
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
  - `easytier/src/instance/route/manager.rs`：实现 `HostRouteManager` 协调循环、命令通道（Bind/Unbind/ConfirmDestroy/CleanupRetired/Stop）、快照指针比对、`execution_dirty` 机制、未决操作追踪、失败指数退避、中途失效检查、多代际记录跟踪与 `stop(deadline)`。
- **验证**：
  - 基于 `MockRouteBackend` 的闭环测试：
    - 首启全量添加；
    - 输入未变稳态 0 调用与 0 堆分配；
    - **T3 验证**：输入和地址完全不变，仅替换 TUN 网卡，验证触发 `execution_dirty` 在新接口安装全部期望路由；测试先有输入后由 DHCP 首次建卡；
    - **T2 验证**：用屏障控制 ACK、设备关闭与销毁确认的先后，验证从 unbind ACK 到销毁确认之间，旧后端调用次数严格为 0；
    - **T1 验证**：分别注入 Stop 前的慢 add、Stop 后的慢 remove 以及命令确认延迟，验证均严格在 `deadline` 到期时返回 `CleanupIncomplete`；随后释放底层阻塞，验证结果被 Manager 正确接收并记账；
    - **T4 验证**：添加注入 `OutcomeUnknown`，随后 DNS 请求同一网段，验证预留确认被严格阻塞；
    - No-TUN 旁路测试（执行分支跳过，已安装记录保持为空）。

#### Batch 4：Host 真实生命周期接线与交接
- **代码落点**：
  - `easytier/src/instance/dns_server/server_instance.rs` & `runner.rs` & `runtime_host/magic_dns.rs`：解耦系统配置与路由清理，`clean_env()` 返回结构化结果并向上抛出。
  - `easytier/src/instance/runtime_host.rs` & `tun_desktop.rs` / `tun_common.rs` / `implementation.rs`：接入 `RouteManagerHandle`，在网卡就绪时（包括 DHCP 延迟建卡与静态卡）调用 `bind_interface`，在关闭时调用 `stop(deadline)`。
  - `easytier/src/instance/virtual_nic.rs`：按 `RouteBackendMode` 停用 `run_proxy_cidrs_route_updater`。
- **验证**：
  - 集成测试：启动集成测试节点，动态推送 `manual_routes`，验证真实 Manager 接管生效且旧 updater 不重复写入；
  - **T4 集成验证**：在 Linux (`system_config=None`) 且实际安装了 DNS /32 时，停止服务验证执行路由删除；若注入删除失败，验证 Tracker 保留排除范围，Manager 不接手，杜绝双写。

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
- [ ] **换网卡不丢路由 (T3)**：输入和地址不变仅替换网卡时，`execution_dirty` 机制确保在新网卡上准确下发全部期望路由。
- [ ] **解绑安全与无竞态 (T2)**：收到 unbind ACK 到销毁确认之间，旧后端系统调用严格为 0；彻底消除在网卡销毁后发起旧删除的竞态。
- [ ] **停机超时全程覆盖与持续追踪 (T1)**：`stop(deadline)` 全程受 deadline 约束，超时按时返回 `CleanupIncomplete`；Host 持续持有 Handle 跟踪后台在途操作，绝不虚报成功。
- [ ] **交接防误放行与 DNS 真实删除 (T4)**：未决操作存在时严格阻塞交接；Linux 等无 `system_config` 环境下 DNS 停止仍如实执行路由删除，删除失败保留排除范围，杜绝双写。
- [ ] **无全表 Dump**：Linux 下删除路由直接构造 `RTM_DELROUTE`，基准测试验证 0 次 `RTM_GETROUTE` dump。
- [ ] **失败退避与未决记账**：添加/删除失败如实记账并不误报成功；失败项执行指数退避；结果不明记录为未决操作，停机时作为未完成项上报。
- [ ] **生产控制一致**：在第二步启用的平台（Linux 原生）完全由 HostRouteManager 接管且旧 updater 停写；未迁移平台（Windows、macOS、移动端）由统一开关安全保持旧链路，不发生漏写或双写。
