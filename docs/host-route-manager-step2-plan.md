# HostRouteManager 第二步实施方案：架构收缩与最小闭环（第十一轮修订版）

状态：已根据第十轮复审审查（[`docs/host-route-manager-step2-review-10.md`](host-route-manager-step2-review-10.md)）完成全面修订。遵循实施总纲（[`docs/host-route-manager-master-plan.md`](host-route-manager-master-plan.md)）与第一步规范（[`docs/host-route-manager-step1-audit-and-contract.md`](host-route-manager-step1-audit-and-contract.md)）。  
基线代码：`refactor/route` 分支；参考分支：`refactor/route-dev` (`8abfb51e`)。

---

## 1. 目标与范围及平台边界

### 1.1 核心目标
本阶段交付一个**小巧、精简、可工作的 HostRouteManager 闭环**：
1. **范围聚焦**：接管 **IPv4 自动子网代理路由（Peer Proxy CIDR）** 与 **手工静态代理路由（`manual_routes`）**。
2. **单一路由模型与设备身份**：以包含确切网络设备身份（`DeviceId { ifname, ifindex }`）的统一 `Route` 结构表达期望集与成功创建集，接口与 Metric 均作为路由属性。同名网卡重建按 `ifindex` 变更精确识别并重新安装，显式指定其他接口的路由安全隔离。
3. **标准错误与结果类型**：统一为一个 `RouteError`（区分 `Failed` 与 `Unknown`），系统操作结果使用标准 `Result<Option<Route>, RouteError>`。
4. **原生异步与明确 Send 契约**：后端 trait 声明返回带 `Send` 约束的 opaque future，兼顾静态分发的零装箱开销与 Tokio / guarden 跨线程调度的线程安全性；仅在实际接管的 `all(target_os = "linux", feature = "linux-netlink")` 条件下编译新模块与管理器，不声明当前阶段不存在的平台别名或 Stub 类型。
5. **真实设备文件描述符保活与解绑/换绑闭环**：通过 `TunDeviceHandle` 直接持有底层网卡设备文件描述符的强引用（Linux 下为 `Arc<OwnedFd>`，独立于转发任务）；建立确定的关闭与解绑顺序（Host 先停止并 join 确认旧转发任务退出，释放原始 fd 与 receiver 锁；Manager 持有保活描述符完成路由精确删除后 `drop(device)` 关闭全系统最后一个描述符，触发内核注销非持久 TUN 设备，再向 Host 发送确认 ACK）；deadline 统一覆盖命令入队与等待 ACK 全过程；解绑到无设备与全局停机清理严格分离，确保 Host 收到完成通知时旧同名设备已在内核中完全销毁，调用方超时不提前释放底层资源。
6. **写入权平滑交接**：Linux 原生环境完全接管并停用旧 updater；未迁移平台保持原有旧链路；Magic DNS 与接口前缀通过生命周期确认杜绝双写。

### 1.2 平台范围与生产接管策略

本阶段不建立长期的公共模式枚举，采用装配处/编译期的确定性选择：

| 平台 / 特性组合 | 第二步接管状态 | 真实后端实现 | 旧 Writer 退出时机 | 第二步验收范围 |
| :--- | :--- | :--- | :--- | :--- |
| **Linux (开启 `feature = "linux-netlink"`，如开启 `tun`)** | **完全原生接管** | `easytier/src/instance/route/backend/netlink.rs` (`PlatformRouteBackend`) | 实例化 `HostRouteManager`，跳过创建 `VirtualNic::run_proxy_cidrs_route_updater` | 隔离 netns 下真实 Netlink 系统调用；增删、精确匹配、长连接与退避验证 |
| **Windows / macOS (含 macOS-NE) / FreeBSD / 移动端 / 未启用 linux-netlink 的 Linux** | **维持原链路** | 暂留后续步骤迁移（不创建空桩或虚假类型别名） | 维持现有 `VirtualNic` 路由更新器或移动端前端拼装 | 保持编译通过与现有功能完整，不提前声称接管，杜绝编译错误 |
| **No-TUN** | **明确旁路** | 在装配处通过 `Option<Backend>` 或空分支旁路 | 停用旧 monitor 路由事件 | 正常执行策略计算，跳过系统写入，已安装集合严格为空 |

---

## 2. 代码落点与复用清单

### 2.1 源码分工与依赖单向性约束

严格遵守 `easytier → easytier-core` 的单向依赖规则，**Core 绝不引用 Host 类型**：
- **`easytier-core`（纯业务事实、不可变快照与规范化）**：
  - 在 `PeerRouteServiceImpl::update_route_table` 提交边界维护不可变快照 `Arc<BTreeSet<Ipv4Cidr>>`。
  - 通过 `CorePacketPlane` 导出只读快照与变更通知能力，独立于 `proxy-cidr-monitor` feature 开关。
  - 导出配置 `CoreRuntimeConfigStore` 的快照与订阅接口。
  - 导出纯算法函数：
    - `normalize_v4_cidr(addr: Ipv4Addr, prefix: u8) -> Result<Ipv4Cidr, cidr::errors::NetworkParseError>`（CIDR 主机位规范化）。
    - 现有的 `resolve_proxy_cidrs(peer_routes: BTreeSet<Ipv4Cidr>, config: ProxyCidrConfigSnapshot) -> BTreeSet<Ipv4Cidr>`。
- **`easytier`（宿主策略、生命周期与系统控制）**：
  - 定义包含网络设备身份（`DeviceId { ifname, ifindex }`）的统一 `Route` 结构与 `RouteError` 枚举；定义真实持有底层设备文件描述符强引用的 `TunDeviceHandle`。
  - 实现 Host 侧策略计算 `calculate_desired_routes`：解析默认接口设备身份与默认 Metric（Linux 65535），过滤未迁移冲突，输出 `BTreeSet<Route>`。
  - 实现具体平台后端（Linux Netlink 长连接、请求/ACK 匹配、消除 dump），提供带 `Send` 约束的 `RouteBackend` trait 静态分发。
  - 实现 `HostRouteManager` 协调循环、失败退避、生命周期解绑与绑定、基于 `guarden` 且先释放设备后发 ACK 的可靠清理。
  - 改造 Magic DNS 清理：解耦系统配置恢复与路由删除，独立返回路由清理结果 `DnsCleanOutcome`。

```text
easytier-core/
  └── src/
        ├── instance/
        │     └── packet_plane.rs           [修改] 独立于旧 monitor 导出 list_proxy_cidrs_snapshot 与变更通知
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
              │     ├── model.rs            [新增] DeviceId, 统一 Route 结构, RouteError
              │     ├── policy.rs           [新增] Host 侧策略计算 (接口/Metric 解析与冲突过滤)
              │     ├── backend.rs          [新增] RouteBackend trait (静态分发 impl Future + Send) 及 Linux 编译期别名
              │     ├── backend/
              │     │     └── netlink.rs    [新增] Linux 专属实现 (长连接 netns 绑定、req/ACK 匹配、消除 dump)
              │     └── manager.rs          [新增] HostRouteManager 核心闭环与 guarden 清理 (持有 TunDeviceHandle 真实设备所有权与解绑支持)
              ├── dns_server/
              │     ├── server_instance.rs  [修改] clean_env() 解耦系统配置并独立返回 DnsCleanOutcome
              │     └── runner.rs           [修改] 传递 clean_env() 结果至外部
              ├── runtime_host.rs           [修改] 管理器实例生命周期挂载与停机协调
              ├── runtime_host/
              │     ├── implementation.rs   [修改] 转发宿主运行时接口
              │     ├── magic_dns.rs        [修改] stop() 向上返回 DnsCleanOutcome
              │     └── tun_desktop.rs      [修改] 网卡重建时先 unbind_tun_device 解绑并 drain，就绪后构造 TunDeviceHandle 可靠换绑
              └── virtual_nic.rs            [修改] 仅在 not(all(target_os = "linux", feature = "linux-netlink")) 下创建 run_proxy_cidrs_route_updater
```

---

## 3. 结构与接口定义

### 3.1 统一路由模型 (`Route`)、设备身份 (`DeviceId`) 与设备句柄 (`TunDeviceHandle`)

合并旧方案中重复的 `RouteSpec` 与 `InstalledRoute`，使用一种完整的 `Route` 结构表达生效参数；引入确切设备身份 `DeviceId` 避免将网卡名称误作为生命周期标识；引入 `TunDeviceHandle` 独立持有真实底层设备文件描述符（R1 闭合）：

```rust
// easytier/src/instance/route/model.rs
use std::net::Ipv4Addr;
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::os::fd::OwnedFd;
use cidr::{IpCidr, Ipv4Cidr, Ipv4Inet};

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct DeviceId {
    /// 接口名称 (如 "tun0", "eth0"，用于显示与日志)
    pub ifname: String,
    /// 系统内核接口索引 (Linux 内核分配的 ifindex，作为单次生命周期的确切身份)
    pub ifindex: u32,
}

impl DeviceId {
    pub fn new(ifname: impl Into<String>, ifindex: u32) -> Self {
        Self {
            ifname: ifname.into(),
            ifindex,
        }
    }
}

/// 真实持有底层设备文件描述符所有权的保活句柄 (R1 闭合)
#[derive(Clone)]
pub struct TunDeviceHandle {
    /// 确切网络设备身份 (包含 ifname 与 ifindex)
    pub id: DeviceId,
    /// 强引用持有底层 TUN 设备的内核文件描述符 (Linux 下持有通过 dup/try_clone_to_owned 获取的独立 OwnedFd)
    #[cfg(target_os = "linux")]
    pub device_file: Arc<OwnedFd>,
}

impl std::fmt::Debug for TunDeviceHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunDeviceHandle")
            .field("id", &self.id)
            .finish()
    }
}

impl TunDeviceHandle {
    #[cfg(target_os = "linux")]
    pub fn new(id: DeviceId, device_file: Arc<OwnedFd>) -> Self {
        Self { id, device_file }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Route {
    /// 目标网络 CIDR
    pub destination: IpCidr,
    /// 解析后的确切网络设备身份 (创建时绑定的具体 ifname 与 ifindex)
    pub interface: DeviceId,
    /// 有效 Metric 跃点数 (执行前若未指定则解析为平台默认值，Linux 为 65535)
    pub metric: u32,
}

impl Route {
    /// 安全的 IPv4 构造函数：利用 Ipv4Inet 清除主机位，非法前缀显式返回错误，杜绝 panic
    pub fn try_new_v4(addr: Ipv4Addr, prefix: u8, interface: DeviceId, metric: u32) -> Result<Self, cidr::errors::NetworkParseError> {
        let inet = Ipv4Inet::new(addr, prefix)?;
        Ok(Self {
            destination: IpCidr::V4(inet.network()),
            interface,
            metric,
        })
    }

    /// 从已规范化的 Ipv4Cidr 构造
    pub fn from_v4_cidr(cidr: Ipv4Cidr, interface: DeviceId, metric: u32) -> Self {
        Self {
            destination: IpCidr::V4(cidr),
            interface,
            metric,
        }
    }
}
```

**模型与行为约束（A1 / R1 闭合）**：
- **设备身份与生命周期分离**：网络接口名称（如 `"tun0"`）仅为用户可见字符串，不构成单次设备生命周期的唯一身份。Linux 内核在网卡销毁与重建时会重新分配递增的 `ifindex`。将 `DeviceId { ifname, ifindex }` 存入 `Route`，使得同名网卡重建（`tun0` $\to$ `tun0`）能被 Manager 的集合比对精准感知并触发重装。
- **真实设备文件描述符所有权与转发任务解耦（R1 闭合）**：
  - 源码事实：`VirtualNic`（`virtual_nic.rs:243`）仅包含配置与上下文，不持有底层设备描述符；`NicCtx`（`virtual_nic.rs:800`）持有的是转发任务的 `JoinSet`，其中发送任务在 `virtual_nic.rs:910` 长期锁定 `peer_packet_receiver`。若强行保活整个 `NicCtx`，不仅无法独立保活内核设备，还会阻塞 Host 的 `nic.drain()` 流程。
  - 确定持有路径：在 Linux 下，网卡创建（`VirtualNic::create_dev`）后，通过 `dev.as_fd().try_clone_to_owned()?`（或 `libc::dup`）克隆一份独立的内核文件描述符 `OwnedFd`，由 `TunDeviceHandle` 强引用持有。这彻底将“内核网络设备保活”与“用户态异步数据转发任务”解耦：Host 在停止网卡或执行 `drain()` 时可以立即中止转发任务并释放 `peer_packet_receiver` 锁；而只要 `TunDeviceHandle` 尚未 drop，Linux 内核网络接口 `tun0` 就绝对存活，保障路由精确清理不产生 `ENODEV`。
  - `TunDeviceHandle` 显式实现 `Debug`（打印设备身份），确保包含其字段的 `DeviceBindError` 派生 `Debug` 正常编译。
- **删除严格依据创建时解析的设备身份**：删除时直接使用 `route.interface.ifindex` 发送精确 Netlink 报文，绝不重新通过网卡名称猜测或二次解析，杜绝将旧网卡路由错删到新网卡上。
- **多接口隔离与显式接口保护**：当实例默认 TUN 网卡重建或退出时，只有绑定到该 TUN `ifindex` 的路由记录会被重装或级联清理；用户通过 `manual_routes` 显式绑定到其他外部接口（如 `eth0`，对应不同的 `ifindex`）的路由不受任何影响，绝不因默认 TUN 的释放而被误删或丢弃。
- **所有权表达权限**：仅仅系统中存在相同前缀或字段齐全，不赋予本方删除权；只有记录在 `installed` 中的路由才允许被本方清理。

### 3.2 标准错误类型 (`RouteError`) 与带 `Send` 约束的后端接口

删除自定义的 `Outcome` 枚举，统一使用标准 `thiserror` 错误与 `Result<Option<T>, RouteError>`。trait 方法采用声明返回 `impl std::future::Future<Output = ...> + Send` 的 opaque future，消除泛型分发下的 `Box<dyn Future>` 装箱分配开销，同时向 Tokio 调度器与 guarden 显式承诺线程安全性（R3 闭合）：

```rust
// easytier/src/instance/route/model.rs

#[derive(thiserror::Error, Debug)]
pub enum RouteError {
    #[error("route operation failed deterministically: {0}")]
    Failed(anyhow::Error),
    #[error("route operation outcome is unknown: {0}")]
    Unknown(anyhow::Error),
}
```

```rust
// easytier/src/instance/route/backend.rs
use super::model::*;

pub trait RouteBackend: Send + 'static {
    /// 添加一条路由
    /// - Ok(Some(actual_route)): 本方成功创建，返回实际生效参数 (记入 installed)
    /// - Ok(None): 系统中已存在相同条目，非本方创建，不予认领 (不入账，记录警告)
    /// - Err(RouteError::Failed(err)): 确定性失败，按指数退避重试
    /// - Err(RouteError::Unknown(err)): 结果不明 (如超时、套接字中断)，记入未决责任，严禁盲目重发
    fn add(
        &mut self,
        route: &Route,
    ) -> impl std::future::Future<Output = Result<Option<Route>, RouteError>> + Send;

    /// 精确删除一条由本方创建的路由
    /// - Ok(Some(())): 成功从系统中删除 (移出 installed)
    /// - Ok(None): 系统中精确目标已不存在，目标状态已达成 (移出 installed)
    /// - Err(RouteError::Failed(err)): 确定性失败，保留账目并按退避重试
    /// - Err(RouteError::Unknown(err)): 结果不明，保留账目并报警，严禁盲目重发
    fn remove(
        &mut self,
        route: &Route,
    ) -> impl std::future::Future<Output = Result<Option<()>, RouteError>> + Send;
}
```

**后端 Future 的 Send 约束说明（R3 闭合）**：
裸 `async fn` 在 Rust trait 中脱糖后默认不声明返回 future 的 `Send` 约束，导致泛型 `HostRouteManager<B: RouteBackend>` 在放入 `tokio::spawn` 或供 `guarden` 默认 Tokio 调度器执行时报 `future cannot be sent between threads safely` 编译错误。通过在 trait 签名中显式约束 `-> impl std::future::Future<Output = ...> + Send`，既保持了静态分发与 0 堆装箱（无需 `Box<dyn Future>`），又严格满足多线程执行器的调度要求。具体实现端（如 `NetlinkRouteBackend` 和 `MockRouteBackend`）仍可直接使用原生 `async fn` 编写，编译器会自动证明其 future 满足 `Send`。

### 3.3 严格编译期平台选择与 Linux Netlink 实现

沿用仓库已有 `common/ifcfg/mod.rs` 模式，删除动态 `Box<dyn Backend>` 分发。**仅在实际接管的 target/feature 组合下声明后端别名，删除不存在的平台别名和 Stub 类型**（R4 闭合）：

```rust
// easytier/src/instance/route/backend.rs

#[cfg(all(target_os = "linux", feature = "linux-netlink"))]
pub type PlatformRouteBackend = netlink::NetlinkRouteBackend;
```

**编译门控与边界说明**：
- **精准接管组合**：仅当编译目标为 Linux 且开启了 `linux-netlink` 特性（在 `easytier/Cargo.toml` 中，启用 `tun` 特性时会自动激活 `linux-netlink`，从而引入可选依赖 `netlink-sys`）时，才编译 `PlatformRouteBackend` 并挂载 `HostRouteManager`。
- **未迁移平台保持旧路径**：Windows、macOS（含 `macos-ne`）、FreeBSD、移动端，以及未开启 `linux-netlink` 的 Linux 构建，**不声明 `PlatformRouteBackend`，也不创建任何 Dummy/Stub 桩类型**。这些构建在装配处自动维持原有的 `VirtualNic::run_proxy_cidrs_route_updater` 路由更新器或移动端前端拼装链路，保证仓库现有的所有平台和特性组合均能直接通过编译，无任何类型解析错误。

#### Linux Netlink 后端细节要求
`easytier/src/instance/route/backend/netlink.rs` 的实现必须满足：
1. **连接与 NetNS 绑定**：创建时在目标 NetNS 中打开长连接 Netlink 套接字并绑定，生命周期内持续复用，消除每请求临时创建 socket 的开销。
2. **请求 / ACK 匹配**：为每次请求分配单调递增的序列号（`nlmsg_seq`），收包循环严格匹配对应的 `NLMSG_ERROR` ACK，正确处理乱序或插队响应。
3. **消除 Dump**：直接构造带 `RTA_DST`、`RTA_OIF`（直接填入 `route.interface.ifindex`）、`RTA_PRIORITY`、`rtm_table` 的单发 `RTM_DELROUTE` 报文下发，单条删除请求数量恒定为 1，杜绝用户态全表 dump 扫描。
4. **异步安全**：将阻塞底层网络 I/O 放入 `tokio::task::spawn_blocking` 中执行，不阻塞 Tokio 异步调度器线程；NetNS 绑定固定在专用执行环境中，绝不跨越 `await`。

### 3.4 Manager 结构与句柄定义

Manager 直接持有编译期确定的具体后端类型（支持泛型以方便单元测试替换 `MockRouteBackend`）：

```rust
// easytier/src/instance/route/manager.rs
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use tokio::sync::Mutex;
use super::model::*;
#[cfg(all(target_os = "linux", feature = "linux-netlink"))]
use super::backend::PlatformRouteBackend;

pub enum ManagerCommand {
    /// 触发刷新：外部通知有新快照或配置变更到达，协调循环被唤醒后统一拉取
    Refresh,
    /// 可靠绑定默认 TUN 设备：携带新的设备句柄 (包含 DeviceId 与独立设备文件描述符)
    BindTunDevice(TunDeviceHandle),
    /// 请求解绑默认 TUN 设备：表达旧设备向无设备过渡，清理该设备路由并释放句柄，返回真实完成结果 (R2 闭合)
    UnbindTunDevice {
        deadline: std::time::Instant,
        ack: tokio::sync::oneshot::Sender<Result<(), CleanupIncomplete>>,
    },
    /// 显式停机：携带统一超时时间
    Stop {
        deadline: std::time::Instant,
        ack: tokio::sync::oneshot::Sender<Result<(), CleanupIncomplete>>,
    },
}

pub struct HostRouteManager<B = PlatformRouteBackend> {
    backend: B,
    /// 本方成功安装的有效路由集合
    installed_routes: BTreeSet<Route>,
    /// 操作结果不明的未决路由责任表 (严禁当成普通失败重试，diff 与清理均跳过，停机时作为未完成项报告)
    unknown_routes: BTreeSet<Route>,
    /// 失败重试退避追踪表
    retry_tracker: BTreeMap<Route, RetryState>,
    /// 当前生效的默认 TUN 设备句柄 (持有 DeviceId 与独立内核文件描述符强引用)
    current_tun_device: Option<TunDeviceHandle>,
    /// 缓存的业务期望路由集合
    desired_routes_cache: Option<BTreeSet<Route>>,
    /// 命令接收通道
    cmd_rx: tokio::sync::mpsc::Receiver<ManagerCommand>,
    /// 停机取消令牌
    cancel_token: tokio_util::sync::CancellationToken,
}

#[derive(thiserror::Error, Debug)]
pub enum DeviceBindError {
    #[error("manager terminated while binding tun device")]
    ManagerTerminated(TunDeviceHandle),
}

#[derive(Clone)]
pub struct RouteManagerHandle {
    cmd_tx: tokio::sync::mpsc::Sender<ManagerCommand>,
    /// 记录停机清理的最终确定结果 (供超时后的调用方或外部观察者查询)
    cleanup_result: Arc<Mutex<Option<Result<(), CleanupIncomplete>>>>,
    join_handle: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
    cancel_token: tokio_util::sync::CancellationToken,
}

impl RouteManagerHandle {
    /// 发送刷新唤醒 (通知到达时合并触发，不逐条排队)
    pub fn notify_refresh(&self) {
        let _ = self.cmd_tx.try_send(ManagerCommand::Refresh);
    }

    /// 可靠通知绑定默认 TUN 设备 (R2 闭合)
    /// 采用 send().await 可靠入队，当协调循环正忙于系统调用或队列已满时通过背压等待，杜绝静默丢失；
    /// 若 Manager 通道已关闭 (停机终止)，将未装配的设备句柄完整返回给调用方，保留资源所有权。
    pub async fn bind_tun_device(&self, device: TunDeviceHandle) -> Result<(), DeviceBindError> {
        self.cmd_tx
            .send(ManagerCommand::BindTunDevice(device))
            .await
            .map_err(|e| match e.0 {
                ManagerCommand::BindTunDevice(dev) => DeviceBindError::ManagerTerminated(dev),
                _ => unreachable!(),
            })
    }

    /// 可靠通知解绑默认 TUN 设备 (R2 闭合)
    /// 请求解除当前生效的默认 TUN 设备，等待 Manager 清理其对应路由并释放设备描述符；
    /// deadline 统一限制命令入队与等待 ACK 全过程：
    /// - 发送入队超时：说明协调循环繁忙且命令队列已满，请求尚未成功入队，返回 Err(CleanupIncomplete) 指明未入队，Manager 未开始解绑；
    /// - 入队成功但等待 ACK 超时：说明请求已进入 Manager 处理队列，返回 Err(CleanupIncomplete) 指明等待超时，Manager 在后台继续持有资源并处理，不提前释放设备；
    /// 成功返回 Ok(())；Manager 本身不退出，继续维持运行并管理其他接口路由。
    pub async fn unbind_tun_device(&self, deadline: std::time::Instant) -> Result<(), CleanupIncomplete> {
        let deadline_instant: tokio::time::Instant = deadline.into();
        let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();

        // 1. 发送入队：严格受 deadline 约束，杜绝队列满时无超时阻塞
        let send_res = tokio::time::timeout_at(
            deadline_instant,
            self.cmd_tx.send(ManagerCommand::UnbindTunDevice { deadline, ack: ack_tx }),
        )
        .await;

        match send_res {
            Err(_) => {
                return Err(CleanupIncomplete {
                    uncleaned_routes: Vec::new(),
                    unknown_routes: Vec::new(),
                    reason: "deadline exceeded while queueing unbind command (request not enqueued)".to_string(),
                });
            }
            Ok(Err(_)) => {
                return Err(CleanupIncomplete {
                    uncleaned_routes: Vec::new(),
                    unknown_routes: Vec::new(),
                    reason: "manager terminated while queueing unbind".to_string(),
                });
            }
            Ok(Ok(())) => {}
        }

        // 2. 等待 ACK：受同一 deadline 约束；若超时 Manager 继续在后台持有资源安全处理
        match tokio::time::timeout_at(deadline_instant, ack_rx).await {
            Ok(Ok(outcome)) => outcome,
            Ok(Err(_)) => Err(CleanupIncomplete {
                uncleaned_routes: Vec::new(),
                unknown_routes: Vec::new(),
                reason: "manager unbind ack channel closed".to_string(),
            }),
            Err(_) => Err(CleanupIncomplete {
                uncleaned_routes: Vec::new(),
                unknown_routes: Vec::new(),
                reason: "deadline exceeded while waiting for manager unbind ACK (manager continuing in background)".to_string(),
            }),
        }
    }

    /// 显式停机：借用 Handle，整个等待严格受 deadline 约束 (覆盖发送与清理等待全过程)；超时返回未完成信息，原持有者继续保留 Handle
    pub async fn stop(&self, deadline: std::time::Instant) -> Result<(), CleanupIncomplete> {
        let deadline_instant: tokio::time::Instant = deadline.into();
        self.cancel_token.cancel();
        let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();

        // 发送入队：受统一 deadline 约束
        let send_res = tokio::time::timeout_at(
            deadline_instant,
            self.cmd_tx.send(ManagerCommand::Stop { deadline, ack: ack_tx }),
        )
        .await;

        match send_res {
            Err(_) => {
                return Err(CleanupIncomplete {
                    uncleaned_routes: Vec::new(),
                    unknown_routes: Vec::new(),
                    reason: "deadline exceeded while queueing stop command".to_string(),
                });
            }
            Ok(Err(_)) => {
                return self.query_cleanup_result().await.unwrap_or(Ok(()));
            }
            Ok(Ok(())) => {}
        }

        match tokio::time::timeout_at(deadline_instant, ack_rx).await {
            Ok(Ok(outcome)) => outcome,
            Ok(Err(_)) => self.query_cleanup_result().await.unwrap_or(Ok(())),
            Err(_) => Err(CleanupIncomplete {
                uncleaned_routes: Vec::new(),
                unknown_routes: Vec::new(),
                reason: "deadline exceeded while waiting for stop cleanup ACK (manager continuing in background)".to_string(),
            }),
        }
    }

    /// 查询最终清理结果 (在 stop 超时后可随时异步获取后台完成状态)
    pub async fn query_cleanup_result(&self) -> Option<Result<(), CleanupIncomplete>> {
        self.cleanup_result.lock().await.clone()
    }
}
```

---

## 4. 输入拉取与无冗余调度

### 4.1 权威输入拉取与唤醒机制（A6 闭合）

Manager 采用**事件驱动拉取**模型，通知只负责唤醒，不逐条重放事件：

| 来源分类 | 读取入口 (Read API) | 快照提交点 (Commit Point) | 通知方式 (Wakeup) |
| :--- | :--- | :--- | :--- |
| **Core Peer 路由** | `CorePacketPlane::list_proxy_cidrs_snapshot() -> Arc<BTreeSet<Ipv4Cidr>>` | OSPF 路由更新处 (`PeerRouteServiceImpl::update_route_table`) 提交 `ArcSwap` | Core 自有通知触发 `handle.notify_refresh()` |
| **手工静态配置** | `CoreRuntimeConfigStore::snapshot().services.manual_routes` | 配置变更原子提交处 | 订阅变更触发 `handle.notify_refresh()` |
| **Host 未迁移事实** | `UnmigratedRouteTracker::snapshot()` | DHCP lease 变更、TUN IP 变更、DNS 启停提交处 | 提交处内部触发 `handle.notify_refresh()` |

### 4.2 订阅与初态读取顺序

为杜绝启动初始化期间的事件丢失，严格执行**先订阅、后读初态**（`subscribe -> read_initial`）原则：
1. 先建立 Core 路由变更监听与配置订阅。
2. 立即拉取各来源的初始快照，装配初态。
3. 启动协调循环。在订阅与初态读取之间到达的任何并发更新，均会通过已注册的通知准确合并唤醒。

### 4.3 稳态零多余计算与执行跳过

1. **输入快照与路由相关配置比较**：
   协调循环被唤醒后，首先比对：
   - `Arc::ptr_eq(&last_peer_cidrs, &current_peer_cidrs)`；
   - `current_config.services.manual_routes == last_manual_routes`（**忽略与路由无关的其他服务配置变更**，如 Socks5/DHCP 配置变动不引发重算）；
   - 未迁移事实快照；
   - 当前生效的默认 TUN 设备身份未变（`current_tun_device.as_ref().map(|d| &d.id) == last_tun_device.as_ref().map(|d| &d.id)`，不仅比对 `ifname`，更严格比对内核 `ifindex`）。
   若输入未变且网卡身份未变，直接复用 `desired_routes_cache`，**0 堆分配，0 策略重算**。
2. **差异跳过机制**：
   比对 `desired_routes_cache` 与 `installed_routes`：若二者集合完全相等且无到期的失败重试项，**直接跳过系统调用并休眠**，稳态系统调用数为 0。
3. **设备解绑、替换与空状态过渡（R1 / R2 / R3 闭合）**：
   明确支持 `旧设备 → unbind_tun_device → 无设备 (None) → bind_tun_device → 新设备` 的生命周期路径：
   - **解绑到空状态（`UnbindTunDevice`）与确定关闭顺序**：
     1. Host 侧发起解绑前，**先停止旧转发任务并等待任务退出**（`JoinSet::shutdown().await` 或 join 等待任务销毁，确认其原始 fd 与 `peer_packet_receiver` 锁已完全释放），同时释放 Host 自身持有的保活副本；此时 Linux 内核非持久 TUN 设备因 Manager 独立持有的 `TunDeviceHandle`（`Arc<OwnedFd>`）继续保活，绝无 `ENODEV`；
     2. Host 调用 `manager.unbind_tun_device(deadline).await`（受统一 deadline 约束入队与等待 ACK 全过程）；
     3. Manager 顺序收束当前在途底层系统调用；通过 `self.current_tun_device.take()` 将默认网卡置为 `None`，并使 `desired_routes` 排除默认 TUN 路由；仅针对旧网卡 `old_device.id.ifindex` 路由执行精确删除；
     4. 路由精确删除完成后，Manager **显式执行 `drop(old_device)`**。此时 Host 转发任务已退出，Manager 的描述符是全系统对该非持久 TUN 设备的**最后一个打开描述符**，彻底关闭它将触发 Linux 内核注销并销毁该接口；
     5. Manager 向 Host 发送确认 ACK。Host 收到 ACK 确认旧非持久网卡已在内核中完全销毁，随后执行 `self.nic.drain()`（因任务已退出故即刻完成）进入无设备状态或安全重建同名新设备；
     6. 若解绑超时（入队超时或等待 ACK 超时）或删除失败，返回 `Err(CleanupIncomplete)`，Host 保持未决状态，绝不盲目判定为已释放或重建同名设备。
   - **无设备稳态**：
     若 Host 进入无设备状态（如 DHCP 续租失败 `next == None`），Manager 维持 `current_tun_device = None` 运行，跳过默认 TUN 路由安装，继续正常管理外部接口路由。
   - **新设备绑定（`BindTunDevice`）**：
     Host 在同名新设备创建就绪后，构造新 `TunDeviceHandle` 并可靠调用 `bind_tun_device`。Manager 设置 `current_tun_device = Some(new_device)`，将默认路由解析为 `new_device.id.ifindex` 并下发安装，彻底解决同名设备重建前旧设备未完全释放导致名称冲突或路由漏装的问题。
   - **精确隔离与范围收割**：解绑与换绑均仅针对默认 TUN 设备 `ifindex` 的路由记录进行清理；用户显式指定绑定到其他外部设备（如 `eth0`，对应不同的 `ifindex`）的路由记录继续完整保留在 `installed_routes` 中，绝不误伤其他接口。
4. **低频保底与独立重试**：
   废除 1 秒忙碌轮询，设 30 秒低频保底核对；失败重试由退避计时器在到达最早 `next_retry` 时精准唤醒。

---

## 5. 执行闭环与 guarden 清理

### 5.1 协调循环核心算法

```text
       ┌────────────────────────────────────────────────────────┐
       │ 唤醒源: ManagerCommand (Refresh/Bind/Unbind/Stop) OR   │
       │         定时器                                         │
       └──────────────────────────┬─────────────────────────────┘
                                  ↓
       ┌────────────────────────────────────────────────────────┐
       │ 1. 检查取消令牌与命令 (若收到 Stop 命令进入停机清理流程) │
       │ 2. 拉取最新权威输入与设备身份 (未变则复用 desired 缓存)  │
       │ 3. 策略计算生成 desired_routes (过滤未迁移冲突, 解析参数)│
       │ 4. 计算差异 (严格排除 unknown_routes，严禁盲目重发):     │
       │    to_remove = (installed - desired) - unknown_routes  │
       │    to_add    = (desired - installed) - unknown_routes  │
       │    若差异为空且无到期重试项 -> 稳态直接休眠             │
       └──────────────────────────┬─────────────────────────────┘
                                  ↓
       ┌────────────────────────────────────────────────────────┐
       │ 5. 逐项有界串行执行 (每 16 项检查一次取消与输入失效):    │
       │    a. 执行 to_remove:                                  │
       │       - Ok(Some(())) / Ok(None) -> 移出 installed      │
       │       - Err(Failed)  -> 记录指数退避                   │
       │       - Err(Unknown) -> 记入 unknown_routes 隔离       │
       │    b. 执行 to_add:                                     │
       │       - Ok(Some(route)) -> 插入 installed              │
       │       - Ok(None)        -> 外部存在不入账，记录警告     │
       │       - Err(Failed)     -> 记录指数退避                │
       │       - Err(Unknown)    -> 记入 unknown_routes 隔离       │
       └────────────────────────────────────────────────────────┘
```

### 5.2 失败退避与有界调度

1. **单项指数退避**：
   对执行失败的路由条目（无论添加还是删除），记录其 `RetryState { attempt: u32, next_retry: Instant }`。
   退避序列：100ms, 200ms, 400ms, 800ms, 1.6s, 最高封顶 5s。
   在下一轮循环计算差异时，**尚未到达 `next_retry` 的失败项不被选入当轮执行队列**。当输入变化使该条目不再需要时，重试状态自动释放。这彻底防止了因无关配置变化或频繁 OSPF 广播导致同一个底层错误被高频重试（防事件风暴）。
2. **在途操作收束保证（R1 / R2 闭合）**：
   Manager 协调循环是单线程顺序执行的，每次调用 `backend.add(&route).await` 或 `backend.remove(&route).await` 均同步等待底层系统调用返回。当收到外部 `ManagerCommand::Stop`、`BindTunDevice` 或取消信号时，**循环必定先等待当前正在执行的底层调用返回并记账**（记入 `installed_routes` 或 `unknown_routes`），然后才进入停机清理或换绑。期间底层设备始终由 `current_tun_device: Option<TunDeviceHandle>` 强引用持有，绝不存在脱离记账或脱离设备保活的在途操作，杜绝迟到结果落到重建后的新网卡上。
3. **中途失效丢弃过时计划**：
   在遍历执行 `to_remove` 和 `to_add` 时，每处理 16 项检查一次取消令牌与输入版本。若检测到网卡失效或新输入涌入，**立即终止执行余下过时条目**，将已成功的操作正确记账后，立即进入下一轮最新全量比对。
4. **替换依赖顺序保证**：
   若同一个槽位（相同目标 CIDR）需要替换（例如 metric 变更），必须**先执行并确认删除成功，才允许尝试添加**。删除若失败，严禁盲目执行添加。

### 5.3 基于独立描述符保活、局部解绑与 guarden 停机清理（R1 / R2 / R3 闭合）

复用仓库现有的 `guarden = "0.3"` 统一管理停机任务与设备资源的所有权，彻底区分局部解绑与全局停机，消除虚假保活与提前释放风险：

#### 1. 真实 Host 设备持有接线、dup 描述符语义与确定关闭顺序（R1 闭合）
在 `easytier/src/instance/runtime_host/tun_desktop.rs` 与 `tun_common.rs` 中建立确定的资源持有与关闭顺序：
- **内核描述符与 dup(2) 语义**：
  在 Linux 原生环境下，非持久 TUN 设备（如 `tun0`）在内核网络协议栈中的存在完全取决于内核中指向 `/dev/net/tun` 的 open file description。网卡创建时（`VirtualNic::create_dev`），Host 从创建好的底层设备中克隆一份独立的内核文件描述符（`dev.as_fd().try_clone_to_owned()?`），封装为 `Arc<OwnedFd>` 注入 `TunDeviceHandle` 交付 Manager。  
  **关键内核语义**：`dup(2)` 产生的新描述符与原始描述符指向**同一个 open file description**。仅当指向该 open file description 的**所有文件描述符均已关闭**时，Linux 内核才会注销并销毁该非持久 TUN 网络接口（参见 [Linux dup(2)](https://man7.org/linux/man-pages/man2/dup.2.html) 与 [Linux TUN/TAP 文档](https://docs.kernel.org/networking/tuntap.html)）。
- **杜绝循环等待与任务退出确认**：
  - 转发任务归属于 `NicCtx` 的 Tokio `JoinSet`，其中发送任务在 `virtual_nic.rs:910` 长期锁定 `peer_packet_receiver`。
  - 不能简单发出取消信号或 Drop `JoinSet` 就假定任务已退出：`JoinSet` 的 Drop 虽会中止任务，但不等待底层 future 真正销毁；原始 fd 与 `peer_packet_receiver` 锁的释放必须等待任务真正退出。
  - 若 Host 先等待 Manager 解绑成功才执行 `nic.drain()`，则在 Manager 执行清理并 `drop(device)` 时，转发任务仍持有原始 fd，Manager 的 ACK 承诺“内核中已销毁”并不成立；若 Manager 等待设备实际销毁再发 ACK 则会导致死锁。
- **确定的 3 步关闭与解绑顺序（统一全文）**：
  1. **Host 停止旧转发任务并等待完全退出**：
     Host 发起换卡或解绑时，首先调用 `old_nic_ctx.tasks.shutdown().await`（或等待全部任务 join 退出），确认转发任务完全退出、原始描述符关闭且 `peer_packet_receiver` 锁彻底释放；随后释放 Host 持有的保活引用（`drop(old_nic_ctx)`）。  
     此时，由于 Manager 独立持有 `TunDeviceHandle`（`Arc<OwnedFd>`），内核中的非持久 TUN 接口及递增 `ifindex` 依然存活，路由依然有效，后续 Netlink 精确删除绝无 `ENODEV`。
  2. **Host 发送解绑请求，Manager 局部清理并释放最后描述符**：
     Host 调用 `manager.unbind_tun_device(deadline).await`（受统一 deadline 约束入队与等待 ACK）。  
     Manager 顺序收束在途操作，取出 `old_device = self.current_tun_device.take()`；  
     Manager 仅精确删除属于 `old_device.id.ifindex` 的路由记录；  
     删除完成后，Manager **显式执行 `drop(old_device)`**。由于 Host 侧所有持有者均已在此前确认释放，此时 Manager 的 drop 是全系统对该非持久 TUN 设备的**最后一个打开描述符**，彻底关闭它将触发 Linux 内核注销并销毁该接口；  
     Manager 发送完成 ACK。
  3. **Host 接收完成确认与安全状态转换**：
     Host 收到 ACK，确认旧非持久 TUN 设备在内核中已绝对销毁，且所有路由与转发任务已彻底清理；  
     Host 执行 `self.nic.drain()`（此时 packet receiver 锁早已释放，drain 即刻完成），安全进入无设备状态（如 DHCP lease 释放）或创建同名全新设备（无内核接口名称冲突或 `EEXIST`），克隆新描述符调用 `bind_tun_device`。
- **设备销毁保证的边界声明**：
  上述设备注销保证**严格限于本实例拥有的非持久 TUN 设备，并以所有持有者（Host 转发任务与 Manager 描述符）确实完全释放为前提**；不能由单次 `Arc::drop` 盲目推导，持久 TUN 设备（`TUNSETPERSIST`）不受文件描述符关闭而自动销毁。

#### 2. 局部设备解绑分支 (`UnbindTunDevice`)：借用 Backend、局部收割、保留其他路由与继续事件循环（R3 闭合）
解绑命令只针对旧默认设备进行局部清理，**Manager 绝不退出主事件循环，不转移 `backend` 的所有权，且绝不误删其他外部接口（如 `eth0`）的路由**：

```rust
// 在 HostRouteManager 主事件循环中处理 UnbindTunDevice 分支
ManagerCommand::UnbindTunDevice { deadline, ack } => {
    // 1. 等待正在执行的单次在途底层系统调用返回并记账
    self.flush_in_flight().await;

    // 2. 取出当前默认 TUN 设备句柄
    let old_device = self.current_tun_device.take();

    match old_device {
        None => {
            // 当前本就处于无设备状态，直接回复成功
            let _ = ack.send(Ok(()));
        }
        Some(dev) => {
            // 3. 精确分区：仅筛选属于旧默认网卡 (dev.id.ifindex) 的路由记录
            // 绑定到外部接口 (如 eth0) 的路由继续保留在 installed_routes 中，绝不误伤！
            let dev_ifindex = dev.id.ifindex;
            let (device_routes, retained_routes): (BTreeSet<Route>, BTreeSet<Route>) =
                std::mem::take(&mut self.installed_routes)
                    .into_iter()
                    .partition(|r| r.interface.ifindex == dev_ifindex);
            self.installed_routes = retained_routes;

            // 4. 局部清理执行：直接借用 &mut self.backend，不消费 backend 所有权
            let mut uncleaned_routes = Vec::new();
            let mut dev_unknown_routes = Vec::new();

            for route in device_routes {
                // 若此条目此前已处于 unknown 状态，严禁盲发重发删除
                if self.unknown_routes.contains(&route) {
                    dev_unknown_routes.push(route);
                    continue;
                }
                match self.backend.remove(&route).await {
                    Ok(Some(())) | Ok(None) => {
                        // 成功从内核移出
                    }
                    Err(RouteError::Failed(err)) => {
                        tracing::error!(?route, ?err, "failed to remove route during tun unbind");
                        // 失败条目保留在 self.installed_routes 中，责任不丢失
                        self.installed_routes.insert(route.clone());
                        uncleaned_routes.push(route);
                    }
                    Err(RouteError::Unknown(err)) => {
                        tracing::error!(?route, ?err, "unknown result during tun unbind");
                        // 未决条目记入 self.unknown_routes 隔离，责任不丢失
                        self.unknown_routes.insert(route.clone());
                        dev_unknown_routes.push(route);
                    }
                }
            }

            // 5. 显式释放全系统最后一个描述符，触发内核注销非持久 TUN 设备 (R1 闭合)
            drop(dev);

            // 6. 计算局部解绑结果并发送 ACK
            let outcome = if uncleaned_routes.is_empty() && dev_unknown_routes.is_empty() {
                Ok(())
            } else {
                Err(CleanupIncomplete {
                    uncleaned_routes,
                    unknown_routes: dev_unknown_routes,
                    reason: "tun unbind incomplete: encountered failed deletions or undetermined states on device".to_string(),
                })
            };

            // 若调用方已超时断开 (ack_rx dropped)，结果已正确保留在 self.installed_routes 与 self.unknown_routes 中
            let _ = ack.send(outcome);
        }
    }
    // 7. 解绑完成后，Manager 维持 current_tun_device = None，继续运行在主循环中！
    // 后端 backend 可用，外部接口路由完好，后续可随时响应 BindTunDevice 绑定新设备
}
```

#### 3. 全局停机清理守卫 (`Stop`)：接管全部资源、guarden 异步保活与终止退出（R3 闭合）
与局部解绑不同，全局停机命令用于整个服务实例退出时的彻底清理，**接管 Manager 的全部资源并在 `guarden::guard!` 内执行终态清理后退出任务**：

```rust
// 在 HostRouteManager 主事件循环中处理 Stop 分支
ManagerCommand::Stop { deadline, ack } => {
    // 1. 等待在途系统调用返回并记账
    self.flush_in_flight().await;

    // 2. 消耗全部资源所有权，退出主事件循环
    let backend = self.backend;
    let installed = std::mem::take(&mut self.installed_routes);
    let unknown = std::mem::take(&mut self.unknown_routes);
    let device = self.current_tun_device.take();

    // 3. 通过 guarden::guard! 构造异步清理守卫，确保调度打断或异常时清理不被半途丢弃
    let (completion_tx, completion_rx) = tokio::sync::oneshot::channel();
    let mut cleanup_guard = guarden::guard! {
        [
            mut backend,
            installed,
            unknown,
            device,
            completion_tx = Some(completion_tx)
        ]
        async move {
            let mut uncleaned_routes = Vec::new();
            let mut unknown_routes_during_cleanup = Vec::new();

            // 逐条精确删除所有已安装路由 (跳过 unknown_routes，严禁盲发重发)
            for route in installed {
                if unknown.contains(&route) {
                    continue;
                }
                match backend.remove(&route).await {
                    Ok(Some(())) | Ok(None) => {}
                    Err(RouteError::Failed(err)) => {
                        tracing::error!(?route, ?err, "failed to remove route during global stop");
                        uncleaned_routes.push(route);
                    }
                    Err(RouteError::Unknown(err)) => {
                        tracing::error!(?route, ?err, "unknown result during global stop");
                        unknown_routes_during_cleanup.push(route);
                    }
                }
            }

            let mut all_unknown: Vec<Route> = unknown.into_iter().collect();
            all_unknown.extend(unknown_routes_during_cleanup);

            let final_outcome = if uncleaned_routes.is_empty() && all_unknown.is_empty() {
                Ok(())
            } else {
                Err(CleanupIncomplete {
                    uncleaned_routes,
                    unknown_routes: all_unknown,
                    reason: "route cleanup incomplete: encountered failed deletions or undetermined route states".to_string(),
                })
            };

            // 释放可能存留的设备描述符
            drop(device);

            if let Some(tx) = completion_tx {
                let _ = tx.send(final_outcome.clone());
            }

            final_outcome
        }
    };

    // 4. 驱动守卫执行直至终态，记录结果并终止 Manager 任务
    let cleanup_task = cleanup_guard.trigger();
    let outcome = cleanup_task.await;
    *self.cleanup_result.lock().await = Some(outcome.clone());
    let _ = ack.send(outcome);
    break; // 彻底退出协调循环
}
```

#### 4. 任务跟踪、超时机制与后台资源保活（R2 闭合）
- **统一 deadline 约束**：
  - `handle.unbind_tun_device(deadline)` 与 `handle.stop(deadline)` 均由外部调用方传入绝对 `deadline`。
  - **命令入队阶段**：采用 `tokio::time::timeout_at(deadline.into(), cmd_tx.send(...))`。若此时 Manager 正卡在 Netlink 系统调用且通道已满，调用在 `deadline` 到达时准时返回 `Err(CleanupIncomplete { reason: "deadline exceeded while queueing ..." })`。调用方明确获知请求未入队，Manager 未开始解绑或停机。
  - **ACK 等待阶段**：入队成功后，对 `ack_rx` 同样以该 `deadline` 执行 `timeout_at`。若底层删除较慢导致超时返回，Manager 此时已接管请求并在后台继续持有资源（`old_device` 或 `backend`）顺序执行，绝不因为调用方超时而提前释放描述符导致内核设备提前销毁。
  - **结果追溯**：对于 `stop`，后台任务完成后将最终真实结果写入 `handle.cleanup_result`，外部可通过 `handle.query_cleanup_result().await` 随时查询最终状态。
- **自有 TUN 级联销毁捷径约束**：
  若 Host 选择通过直接关闭自有 TUN 文件描述符让内核自动级联删除接口路由：
  - 必须先停止 Manager 协调循环并收束在途操作；
  - 必须确认实际设备已被内核关闭销毁；
  - 仅清理绑定在对应 TUN `ifindex` 上的已安装记录；
  - **严禁与逐条 Netlink 删除任务并发执行**；
  - **显式指定到外部接口（如 `eth0`）的静态路由不具备该捷径，必须由守卫逐条执行精确删除**。

### 5.4 设备解绑与全局停机流程及超时保证 (`unbind_tun_device` / `stop`)

```rust
#[derive(Debug, Clone)]
pub struct CleanupIncomplete {
    /// 明确删除失败的条目
    pub uncleaned_routes: Vec<Route>,
    /// 操作结果不明的未决条目 (严禁盲发重试)
    pub unknown_routes: Vec<Route>,
    /// 未完成原因描述
    pub reason: String,
}
```

#### 1. 默认设备解绑流程 (`unbind_tun_device(deadline)`)
用于网卡重建前夕或 DHCP 释放（`next == None`）时的设备解绑（`旧设备 → 无设备`）：
1. **停止转发任务**：Host 首先停止旧转发任务并等待任务实际退出（`JoinSet::shutdown().await`），确认原始 fd 与 `peer_packet_receiver` 锁完全释放，并释放 Host 持有的保活句柄。
2. **限时入队与状态收束**：向 Manager 发送 `ManagerCommand::UnbindTunDevice`（发送受 `deadline` 约束）。Manager 优先等待在途系统调用完成并记账。
3. **空状态过渡与局部清理**：Manager 将 `current_tun_device` 置为 `None`，更新 desired 路由排除默认 TUN 路由；仅针对旧设备 `ifindex` 路由执行精确删除；保留外部接口路由，不退出主循环。
4. **释放最后描述符与回复 ACK**：删除完成后显式 `drop(old_device)`，关闭全系统最后一个打开描述符触发内核注销非持久 TUN 接口，随后发送 ACK。
5. **超时与未完成保护**：若入队超时或等待 ACK 超时，返回 `Err(CleanupIncomplete)`，Host 保持未决状态，绝不盲目判定为已释放或重建同名设备；Manager 在入队成功后于后台继续处理。
6. **Host 排水与状态转换**：Host 收到 ACK 确认设备注销后，执行 `self.nic.drain()` 进入无设备状态或安全创建全新同名设备。

#### 2. 全局停机流程 (`stop(deadline)`)
用于整个服务实例退出时的彻底清理：
1. **立即打断调度**：触发 `cancel_token.cancel()`，拒绝接收新业务操作。
2. **全流程限时入队与清理等待**：发送 `ManagerCommand::Stop` 并限时等待全量已安装路由清理（发送与 ACK 等待统一受 `deadline` 约束）。
3. **guarden 资源彻底释放**：Manager 退出循环，在 `guarden::guard!` 异步块内精确删除全量已安装路由（跳过 unknown），执行 `drop(device)` 与 backend 释放。
4. **真实结果透明判定（R3 闭合）**：仅当无失败且无未决项时返回 `Ok(())`；调用方超时返回 `CleanupIncomplete`，后台任务继续持有资源安全运行直至终态，可随时通过 `query_cleanup_result` 查询。

---

## 6. 写入权交接与动态冲突防御

### 6.1 写入权控制

依据装配处的平台决策统一控制写入权：
- **Linux 生产环境 (`all(target_os = "linux", feature = "linux-netlink")`)**：启用 `HostRouteManager`，宿主在创建网卡时跳过启动 `VirtualNic::run_proxy_cidrs_route_updater`，全仓代理路由仅由单一 Manager 写入。
- **未迁移平台与构建（Windows、macOS 含 macOS-NE、FreeBSD、移动端，及未开启 linux-netlink 的 Linux 构建）**：第二步维持原有旧链路运行，不声明新平台别名或 Stub，不启动新 Manager。旧 updater 继续正常工作，确保系统无双写且全平台无破坏。

### 6.2 动态全量代理的重叠冲突防御与交接时序

在第二步中，Magic DNS（`fake_ip/32`）与 macOS/FreeBSD 接口前缀依然由旧代码写入。

**DNS 清理路径真实解耦与错误分离**：
在 `easytier/src/instance/dns_server/server_instance.rs` 中，**将路由删除与系统 DNS 配置恢复彻底解耦，独立返回路由清理结果**：

```rust
// dns_server/server_instance.rs

#[derive(Debug)]
pub struct DnsCleanOutcome {
    /// 路由删除结果 (用于判定内核中是否已清除主机路由)
    pub route_cleaned: Result<(), anyhow::Error>,
    /// 系统配置恢复结果 (如 resolv.conf，用于诊断，不阻塞路由交接)
    pub system_config_cleaned: Result<(), anyhow::Error>,
}

impl MagicDnsServerInstance {
    pub async fn clean_env(&self) -> DnsCleanOutcome {
        // 1. 系统 DNS 配置恢复 (独立执行，即便为 None 或失败也不影响路由删除)
        let system_config_cleaned = if let Some(configer) = &self.data.system_config {
            configer.close()
        } else {
            Ok(())
        };

        // 2. 路由清理：依据是否实际添加了主机路由独立执行，Linux (system_config=None) 正常执行！
        let route_cleaned = if !self.tun_inet.contains(&self.data.fake_ip)
            && let Some(tun_dev_name) = &self.data.tun_dev
        {
            let ifcfg = IfConfiger {};
            ifcfg.remove_ipv4_route(tun_dev_name, self.data.fake_ip, 32).await
                .map_err(Into::into)
        } else {
            Ok(())
        };

        self.packet_filter.close().await;

        DnsCleanOutcome {
            route_cleaned,
            system_config_cleaned,
        }
    }
}
```
- `MagicDnsRuntime::stop()` 向上返回 `DnsCleanOutcome`。

**未迁移上下文动态追踪 (`UnmigratedRouteTracker`)**：
- 动态事实：`dns_status: UnmigratedWriterStatus`（包含 `Active`、`Inactive`、`CleaningFailed(Error)`）、`magic_dns_ip: Option<Ipv4Addr>`、`tun_cidr: Option<Ipv4Cidr>`。
- 冲突判定条件：仅当 DNS 启用且 `magic_dns_ip` **处于 TUN 子网网段之外**时，DNS 才实际需要添加主机路由 `/32`。

**生命周期交接顺序（预留冲突范围 $\to$ 等待原 writer 清理确认 $\to$ 启动接手 writer）**：
1. **场景 A：Manager 已安装代理路由 $P$，随后外部事实变化导致未迁移 DNS 也需要 $P$**：
   - **预留范围**：Host 更新 `UnmigratedRouteTracker`，将 $P$ 标记为待接手预留状态。
   - **触发清理**：Manager 策略函数将 $P$ 从 desired 中剔除：
     - 若 $P$ 存在于 `unknown_routes` 中：Manager 绝不发放预留确认，保持阻塞！
     - 若 $P$ 存在于 `installed_routes` 中：调用 `remove(&route)` 删除，成功后发放确认。
     - 若 $P$ 本方未安装且无未决操作：立即发放确认。
   - **启动旧 Writer**：DNS 模块收到确认后，方可调用底层系统接口写入 $P$。
   - **失败防御**：若 Manager 删除失败，Tracker 绝不发放确认，DNS 模块中止写入并报错，绝不产生双写踩踏。
2. **场景 B：反向交接（未迁移 DNS 停止，将 $P$ 释放给 Manager）**：
   - DNS 模块退出并调用解耦后的 `clean_env()` 删除 $P$。
   - `MagicDnsRuntime::stop()` 向上返回 `DnsCleanOutcome`，**Tracker 严格依据 `route_cleaned` 判断**：
     - 若 `route_cleaned.is_ok()`：路由已从系统内核完全清除！无论 `system_config_cleaned` 是否失败，Tracker 均将 `dns_status` 置为 `Inactive`，释放预留范围并通知 Manager。Manager 策略函数解除抑制，将 $P$ 纳入 desired 并下发安装。若 `system_config_cleaned` 失败仅记录诊断日志。
     - 若 `route_cleaned.is_err()`：尚未确认路由已清理，**继续保留排除范围并报告错误**！Manager 绝不安装 $P$，防止在系统仍残留旧路由时引发冲突。
3. **场景 C：macOS / FreeBSD 显式接口前缀与 TUN 重建**：
   - macOS/FreeBSD 接口直连路由在 TUN 创建时由系统/旧脚本写入；`UnmigratedRouteTracker` 记录 `tun_cidr`，Manager 策略函数自动排除与 `tun_cidr` 相同的代理路由。

---

## 7. 性能开销分析与测量指标

为落实 master plan 对性能选择的明确要求，说明各项优化的实现机理与测量方法：

### 7.1 稳态零多余操作与零堆分配
- **机理说明**：
  现有 `cidr_monitor.rs:165–176` 每 1 秒轮询检查一次更新时间戳与配置指针；当检测到变化时调用 `collect()` 构建新的 `BTreeSet`。
  新方案彻底废除 1 秒定时轮询，由变更驱动通知唤醒。协调循环利用不可变快照指针（`Arc::ptr_eq`）与设备身份快速拦截，稳态下不拉取路由表、不创建集合、不执行 diff 比对。
- **测量方法**：
  - 测试手段：MockBackend 统计底层调用计数，结合内存分配跟踪器。
  - 验收基准：在 60 秒稳态运行期间，底层路由调用次数严格为 0；协调循环迭代的堆分配次数为 0。

### 7.2 平台连接复用
- **机理说明**：
  现有实现针对每个路由操作临时建立 Netlink socket。新方案在 Linux 原生后端的单次网卡绑定生命周期内持久持有单个 Netlink socket 实例，跨迭代持续复用。
- **测量方法**：
  - 测试手段：使用 `strace -c -e socket,bind,close` 追踪单次网卡生命周期内的路由操作系统调用。
  - 验收基准：在持续增删 100 次路由场景下，Netlink 相关套接字的创建次数严格等于后端单次绑定的 1 次。

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
Batch 1: 纯计算与统一模型 (Core 快照与算法 + Host 策略与统一 Route 模型 + DeviceId + TunDeviceHandle)
   ↓
Batch 2: 精确删除改造与平台后端 (Netlink 消除 dump、长连接、impl Future + Send 静态分发、Mock 后端)
   ↓
Batch 3: HostRouteManager 核心闭环 (统一 RouteError、收束在途操作、可靠 bind/unbind、跳过 unknown、guarden 清理)
   ↓
Batch 4: Host 真实生命周期接线与交接 (TunDeviceHandle 绑定/解绑、独立设备描述符保活、DNS 解耦、旧 updater 屏蔽)
   ↓
Batch 5: 隔离环境原生测试与基准度量 (netns 真实系统调用、零 dump、零写度量)
```

### 8.1 分批实施详细任务

#### Batch 1：纯计算与统一模型
- **代码落点**：
  - `easytier-core/src/peers/route/peer_ospf_route.rs`：在 `PeerRouteServiceImpl::update_route_table` 维护 `Arc<BTreeSet<Ipv4Cidr>>` 快照并导出变更通知。
  - `easytier-core/src/instance/packet_plane.rs`：导出 `list_proxy_cidrs_snapshot`。
  - `easytier-core/src/peers/route/projection.rs`：纯函数 `normalize_v4_cidr`（基于 `Ipv4Inet::network()`）。
  - `easytier/src/instance/route/model.rs`：`DeviceId`、`TunDeviceHandle`（持有内核独立文件描述符 `Arc<OwnedFd>`，实现 `Debug`）、统一 `Route` 结构与 `RouteError` 枚举。
  - `easytier/src/instance/route/policy.rs`：Host 策略计算 `calculate_desired_routes`（解析 `DeviceId`、默认 Metric 与过滤未迁移冲突）。
- **验证**：
  - 单元测试：主机位非零安全规范化（`10.0.0.1/24` $\to$ `10.0.0.0/24`，无 panic）、`/0` 与 `/32` 边界测试、非法前缀测试、`manual_routes` 三态测试、未迁移 DNS `/32` 碰撞排除测试。

#### Batch 2：精确删除改造与平台后端
- **代码落点**：
  - `easytier/src/common/ifcfg/netlink.rs`：改造 `remove_ipv4_route`，消除全量 dump，直接匹配 destination, oif (`route.interface.ifindex`), priority, table 发送 `RTM_DELROUTE`。
  - `easytier/src/instance/route/backend.rs`：`RouteBackend` trait（采用声明返回 `impl Future<Output = ...> + Send` 静态分发，兼顾零装箱与线程安全）、严格门控别名 `PlatformRouteBackend`（仅限 `all(target_os = "linux", feature = "linux-netlink")`）与 `MockRouteBackend`。
- **验证**：
  - 单元测试：同接口、同前缀但不同 metric 的精确删除测试（验证外部 metric 路由不被误删）；Mock 后端记录核对测试；静态分发原生 async 调用与 Send 泛型约束编译验证。

#### Batch 3：HostRouteManager 核心闭环
- **代码落点**：
  - `easytier/src/instance/route/manager.rs`：实现 `HostRouteManager` 协调循环、快照与设备身份比对跳过、串行在途操作收束、可靠命令 `bind_tun_device` 与解绑 `unbind_tun_device`（覆盖入队与等待 ACK 全过程的统一 deadline、借用 backend 执行局部清理、清理完成后显式 `drop(device)` 释放最后描述符后发 ACK）、diff 与清理均跳过 `unknown_routes`、基于 `guarden` 的设备保活清理与 `stop(deadline)`。
- **验证**：
  - 基于 `MockRouteBackend` 的闭环测试：
    - 首启全量添加；
    - 输入未变稳态 0 调用与 0 堆分配；
    - **设备解绑与无设备稳态测试**：验证 `unbind_tun_device` 正确将 Manager 置为无设备状态（`current_tun_device = None`）并清理对应路由；验证在发送完成 ACK 前设备描述符已关闭；验证 Manager 在无设备下保持运行并不丢弃其他接口路由；
    - **同名网卡先解绑后重建测试**：模拟同名重建（`tun0` $\to$ `tun0`），验证必须在旧设备完全释放后才接入新设备；
    - **独立设备描述符保活与解耦验证**：使用真实底层设备接线，先终止转发任务（释放 `peer_packet_receiver` 锁），路由删除仍处于等待中；确认设备文件描述符尚未释放；直到路由清理完成并 drop 后设备才释放，后续关闭能顺畅释放旧 packet receiver，不阻碍 drain 或下一块设备接管；
    - **延迟旧转发任务退出验证 (R1 闭合)**：延迟旧转发任务退出（保持原始描述符未关闭），验证 Host 绝不提前宣告设备销毁或创建同名设备；任务退出后顺利完成解绑与同名重建；
    - **解绑 Deadline 覆盖入队与 ACK 验证 (R2 闭合)**：保持 backend 系统调用未返回，填满命令队列，调用 `unbind_tun_device`；验证其在 deadline 到达时立即超时返回（指出请求未入队），绝不在 send 上无超时挂死；另验证已成功入队但仅 ACK 超时场景下，Manager 在后台继续安全执行并不提前释放资源；
    - **局部解绑与外部接口隔离测试 (R3 闭合)**：同时存在默认 TUN 和其他接口（如 `eth0`）的本方路由时执行 `unbind_tun_device`：验证仅清理前者路由，Manager 不退出；随后外部接口路由仍能正常刷新维护，新 TUN 仍能正常调用 `bind_tun_device` 绑定；局部清理失败或产生 unknown 时，未完成条目妥善保留在 Manager 状态中，绝不丢失；
    - **可靠换绑投递与通道关闭测试**：在 Manager 执行系统调用阻塞时发送高频 Refresh 填满队列，发起 `bind_tun_device`，验证 `send().await` 背压等待且命令不丢失；验证 Manager 停机通道关闭时返回 `DeviceBindError::ManagerTerminated(device)` 保持设备所有权；
    - **在途操作收束**：模拟单次 ADD 阻塞在底层，触发退出并使调用方等待超时，验证在途操作被单线程循环正常收束记账，旧操作绝不落到重建后的网卡上；
    - **未决隔离与真实报告**：操作结果返回 `RouteError::Unknown` 时准确记入 `unknown_routes`；后续 diff 循环与清理循环均自动跳过该条目（不盲发重试）；stop 最终返回 `CleanupIncomplete`，绝不误报成功；
    - **Stop 限时超时与后台保活**：调用方 stop 超时后按时返回，后台 guarden 任务继续持有底层设备（`TunDeviceHandle`）和 backend 安全运行直至结束，设备不被提前释放；外部可通过 `query_cleanup_result` 获得最终完成结果；
    - No-TUN 旁路测试（已安装记录保持为空）。

#### Batch 4：Host 真实生命周期接线与交接
- **代码落点**：
  - `easytier/src/instance/dns_server/server_instance.rs` & `runner.rs` & `runtime_host/magic_dns.rs`：解耦系统配置与路由清理，返回 `DnsCleanOutcome` 并向上抛出。
  - `easytier/src/instance/runtime_host/tun_desktop.rs` & `tun_common.rs` & `implementation.rs`：在 `NativeDhcpIpv4Host::apply` 中实现确定的关闭与解绑顺序：
    1. 首先停止旧转发任务并等待任务实际退出（`tasks.shutdown().await`），确认原始 fd 与 receiver 锁完全释放；
    2. 释放 Host 持有的保活引用（`drop(old_nic_ctx)`）；
    3. 调用 `unbind_tun_device(deadline).await?` 限时解绑（入队与等待 ACK 均受 deadline 约束），等待 Manager 清理路由并释放全系统最后描述符（触发内核注销非持久 TUN 接口）；
    4. 执行 `self.nic.drain()` 进入干净状态；
    5. 若 `next` 为 None 保持无设备稳态；若 `next` 为 Some，创建全新网卡克隆 `OwnedFd` 构造 `TunDeviceHandle` 并可靠调用 `bind_tun_device`；停机时调用 `stop(deadline)`。
  - `easytier/src/instance/virtual_nic.rs`：仅在 `not(all(target_os = "linux", feature = "linux-netlink"))` 下启动 `run_proxy_cidrs_route_updater`。
- **验证**：
  - 跨平台与特性组合编译验证：验证 Linux（开启/未开启 netlink）、Windows、macOS（含 `macos-ne`）、FreeBSD 均能顺利编译，未迁移平台维持原有旧链路；
  - DHCP 无设备过渡与同名重建集成测试：验证 DHCP `Some(ip) → None` 后默认设备释放、Manager 不退出、其他接口路由保留；再从 `None → Some(ip)` 恢复或同名重建，旧设备先释放、新设备后接入；验证解绑等待超时场景下 Host 不误报设备已释放；
  - 动态配置集成测试：动态推送 `manual_routes`，验证真实 Manager 接管生效且旧 updater 不重复写入；
  - DNS 交接集成验证：
    1. 在 Linux (`system_config=None`) 且安装了 DNS /32 时，停止服务验证执行路由删除；
    2. 模拟 `system_config.close()` 失败但 `remove_ipv4_route` 成功：验证路由排除范围成功释放给 Manager；
    3. 模拟 `remove_ipv4_route` 失败但 `system_config.close()` 成功：验证 Tracker 保留排除范围，杜绝双写。

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

- [ ] **统一模型与真实设备描述符所有权**：以包含 `DeviceId { ifname, ifindex }` 的单一 `Route` 模型表达期望与安装路由；`TunDeviceHandle` 独立持有底层真实设备文件描述符（`Arc<OwnedFd>`），与用户态转发任务彻底解耦，实现 `Debug`；CIDR 主机位非零（如 `10.0.0.1/24`）安全规范化，无 panic；自动代理、手工覆盖均准确计算。
- [ ] **完整解绑与同名网卡重建重装**：建立 `旧设备 → unbind_tun_device → 无设备 → bind_tun_device → 新设备` 闭环；确立唯一确定的关闭与解绑顺序（Host 先停止并等待旧转发任务退出释放原始 fd 与 receiver 锁；Manager 持有保活描述符完成路由精确删除后 `drop(old_device)` 关闭全系统最后一个描述符，触发内核注销非持久 TUN 接口后再发 ACK；保证严格以所有持有者释放为前提）；解绑 deadline 统一覆盖命令入队与等待 ACK 全过程（防止队列满挂死）；局部解绑仅针对默认 TUN 路由，借用 backend 并在完成后留在主循环，显式绑定到其他外部接口（如 `eth0`）的路由记录完整保留且责任不丢失。
- [ ] **依赖方向与严格编译门控**：`easytier-core` 绝无引用 `easytier` 类型；`PlatformRouteBackend` 仅在 `all(target_os = "linux", feature = "linux-netlink")` 下声明，不预建未实现的平台别名或 Stub 类型；全平台及特性组合均独立可编译。
- [ ] **带 Send 约束的静态分发后端与精确删除**：`RouteBackend` trait 声明返回 `impl Future<Output = ...> + Send`，兼顾零装箱静态分发与 Tokio / guarden 线程安全性；Linux 精确删除直接按 `ifindex`、目标、metric 与 table 发送单发 `RTM_DELROUTE`，0 次全表 dump。
- [ ] **稳态零多余操作**：在网络拓扑与配置稳定的状态下，快照指针与设备身份比对快速拦截，协调循环不产生多余的底层系统调用和堆内存分配；无关服务配置变动不引发路由重算。
- [ ] **在途操作收束与真实设备保活**：单线程协调循环在停机或换绑前先等待当前在途操作返回并记账；转发任务退出释放 `peer_packet_receiver` 锁不影响内核设备保活，底层设备覆盖正常运行、等待在途和清理全周期，调用方等待超时不提前释放底层设备资源。
- [ ] **未决隔离与真实清理结果**：`unknown_routes` 在 diff 和清理中均被跳过，严禁盲发重发；清理流程收集失败与未决条目；存在未决条目或删除失败时，`stop(deadline)` 如实返回 `CleanupIncomplete`，绝不虚报成功。
- [ ] **交接防误放行与 DNS 真实删除**：未决操作存在时严格阻塞交接；Linux 等无 `system_config` 环境下 DNS 停止仍如实执行路由删除；系统配置恢复错误与路由清理错误分离，路由删除失败保留排除范围，杜绝双写。
- [ ] **生产控制一致**：在第二步启用的平台（Linux + linux-netlink）完全由 HostRouteManager 接管且旧 updater 停写；未迁移平台保持原有旧链路，不发生漏写或双写。
