# HostRouteManager 第二步实施方案：架构收缩与最小闭环（第八轮修订版）

状态：已根据第七轮复审审查（[`docs/host-route-manager-step2-review-7.md`](host-route-manager-step2-review-7.md)）完成全面修订。遵循实施总纲（[`docs/host-route-manager-master-plan.md`](host-route-manager-master-plan.md)）与第一步规范（[`docs/host-route-manager-step1-audit-and-contract.md`](host-route-manager-step1-audit-and-contract.md)）。  
基线代码：`refactor/route` 分支；参考分支：`refactor/route-dev` (`8abfb51e`)。

---

## 1. 目标与范围及平台边界

### 1.1 核心目标
本阶段交付一个**小巧、精简、可工作的 HostRouteManager 闭环**：
1. **范围聚焦**：接管 **IPv4 自动子网代理路由（Peer Proxy CIDR）** 与 **手工静态代理路由（`manual_routes`）**。
2. **单一路由模型与设备身份**：以包含确切网络设备身份（`DeviceId { ifname, ifindex }`）的统一 `Route` 结构表达期望集与成功创建集，接口与 Metric 均作为路由属性。同名网卡重建按 `ifindex` 变更精确识别并重新安装，显式指定其他接口的路由安全隔离。
3. **标准错误与结果类型**：统一为一个 `RouteError`（区分 `Failed` 与 `Unknown`），系统操作结果使用标准 `Result<Option<Route>, RouteError>`。
4. **原生异步与确定性编译门控**：后端 trait 使用原生 `async fn` 静态分发，消除每次调用装箱 future 的开销；仅在实际接管的 `all(target_os = "linux", feature = "linux-netlink")` 条件下编译新模块与管理器，不声明当前阶段不存在的平台别名或 Stub 类型。
5. **guarden 真实设备所有权收束**：复用项目已有 `guarden = "0.3"` 管理清理任务与设备资源生命周期，守卫接管真实设备保活句柄（`device_keepalive`），单线程协调循环收束在途操作后再移交清理，杜绝等待超时导致设备提前释放；清理流程完整处理 `unknown_routes`，跳过盲目重试，如实返回 `CleanupIncomplete`。
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
  - 定义包含网络设备身份（`DeviceId { ifname, ifindex }`）的统一 `Route` 结构与 `RouteError` 枚举。
  - 实现 Host 侧策略计算 `calculate_desired_routes`：解析默认接口设备身份与默认 Metric（Linux 65535），过滤未迁移冲突，输出 `BTreeSet<Route>`。
  - 实现具体平台后端（Linux Netlink 长连接、请求/ACK 匹配、消除 dump），原生 `async fn` 零装箱。
  - 实现 `HostRouteManager` 协调循环、失败退避与基于 `guarden` 且持有 `device_keepalive` 的清理。
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
              │     ├── backend.rs          [新增] RouteBackend trait (原生 async fn) 及 Linux 编译期别名
              │     ├── backend/
              │     │     └── netlink.rs    [新增] Linux 专属实现 (长连接 netns 绑定、req/ACK 匹配、消除 dump)
              │     └── manager.rs          [新增] HostRouteManager 核心闭环与 guarden 清理 (持有 device_keepalive)
              ├── dns_server/
              │     ├── server_instance.rs  [修改] clean_env() 解耦系统配置并独立返回 DnsCleanOutcome
              │     └── runner.rs           [修改] 传递 clean_env() 结果至外部
              ├── runtime_host.rs           [修改] 管理器实例生命周期挂载与停机协调
              ├── runtime_host/
              │     ├── implementation.rs   [修改] 转发宿主运行时接口
              │     ├── magic_dns.rs        [修改] stop() 向上返回 DnsCleanOutcome
              │     └── tun_desktop.rs      [修改] 网卡就绪与重建时传递 DeviceId 触发 Manager 换绑与刷新
              └── virtual_nic.rs            [修改] 仅在 not(all(target_os = "linux", feature = "linux-netlink")) 下创建 run_proxy_cidrs_route_updater
```

---

## 3. 结构与接口定义

### 3.1 统一路由模型 (`Route`) 与设备身份 (`DeviceId`)

合并旧方案中重复的 `RouteSpec` 与 `InstalledRoute`，使用一种完整的 `Route` 结构表达生效参数；引入确切设备身份 `DeviceId` 避免将网卡名称误作为生命周期标识（R1 闭合）：

```rust
// easytier/src/instance/route/model.rs
use std::net::Ipv4Addr;
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
- **删除严格依据创建时解析的设备身份**：删除时直接使用 `route.interface.ifindex` 发送精确 Netlink 报文，绝不重新通过网卡名称猜测或二次解析，杜绝将旧网卡路由错删到新网卡上。
- **多接口隔离与显式接口保护**：当实例默认 TUN 网卡重建或退出时，只有绑定到该 TUN `ifindex` 的路由记录会被重装或级联清理；用户通过 `manual_routes` 显式绑定到其他外部接口（如 `eth0`，对应不同的 `ifindex`）的路由不受任何影响，绝不因默认 TUN 的释放而被误删或丢弃。
- **所有权表达权限**：仅仅系统中存在相同前缀或字段齐全，不赋予本方删除权；只有记录在 `installed` 中的路由才允许被本方清理。

### 3.2 标准错误类型 (`RouteError`) 与原生后端接口

删除自定义的 `Outcome` 枚举，统一使用标准 `thiserror` 错误与 `Result<Option<T>, RouteError>`。trait 方法采用原生 `async fn` 声明，消除泛型分发下的 `Box<dyn Future>` 装箱分配开销：

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
    async fn add(&mut self, route: &Route) -> Result<Option<Route>, RouteError>;

    /// 精确删除一条由本方创建的路由
    /// - Ok(Some(())): 成功从系统中删除 (移出 installed)
    /// - Ok(None): 系统中精确目标已不存在，目标状态已达成 (移出 installed)
    /// - Err(RouteError::Failed(err)): 确定性失败，保留账目并按退避重试
    /// - Err(RouteError::Unknown(err)): 结果不明，保留账目并报警，严禁盲目重发
    async fn remove(&mut self, route: &Route) -> Result<Option<()>, RouteError>;
}
```

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
    /// 换绑默认 TUN 设备：携带新的设备身份 (即使名称相同，ifindex 也会改变)
    BindTunDevice(DeviceId),
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
    /// 当前生效的默认 TUN 设备身份 (包含 ifname 与 ifindex)
    current_tun_device: Option<DeviceId>,
    /// 缓存的业务期望路由集合
    desired_routes_cache: Option<BTreeSet<Route>>,
    /// 命令接收通道
    cmd_rx: tokio::sync::mpsc::Receiver<ManagerCommand>,
    /// 停机取消令牌
    cancel_token: tokio_util::sync::CancellationToken,
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

    /// 通知换绑默认 TUN 设备 (即使名称未变，ifindex 变化也会被精准识别)
    pub fn bind_tun_device(&self, device: DeviceId) {
        let _ = self.cmd_tx.try_send(ManagerCommand::BindTunDevice(device));
    }

    /// 显式停机：借用 Handle，整个等待严格受 deadline 约束；超时返回未完成信息，原持有者继续保留 Handle
    pub async fn stop(&self, deadline: std::time::Instant) -> Result<(), CleanupIncomplete> {
        // 详见 5.4 节
        ...
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
   - 当前生效的默认 TUN 设备身份未变（`current_tun_device == last_tun_device`，不仅比对 `ifname`，更严格比对内核 `ifindex`）。
   若输入未变且网卡身份未变，直接复用 `desired_routes_cache`，**0 堆分配，0 策略重算**。
2. **差异跳过机制**：
   比对 `desired_routes_cache` 与 `installed_routes`：若二者集合完全相等且无到期的失败重试项，**直接跳过系统调用并休眠**，稳态系统调用数为 0。
3. **设备替换强制重算与局部记录交接（R1 闭合）**：
   当收到 `BindTunDevice(new_device)` 或检测到默认 TUN 设备变更（即使名称同为 `"tun0"`，新旧 `ifindex` 不同）：
   - **精确隔离与范围收割**：仅针对旧设备 `old_device.ifindex` 的路由记录进行重装或清理；用户显式指定绑定到其他外部设备（如 `eth0`，对应不同的 `ifindex`）的路由记录继续完整保留在 `installed_routes` 中，绝不误伤其他接口。
   - **强制触发差异执行**：由于 `desired_routes` 中默认路由的目标接口已解析为 `new_device.ifindex`，与 `installed_routes` 中旧设备的 `old_device.ifindex` 产生明确差异。
   - **重装保障**：旧条目被移出（若使用内核级联销毁捷径，则由 Host 确认关闭旧设备后同步清空旧 `ifindex` 记录），新条目被完整下发至新设备，彻底杜绝同名网卡重建漏装路由的问题。
4. **低频保底与独立重试**：
   废除 1 秒忙碌轮询，设 30 秒低频保底核对；失败重试由退避计时器在到达最早 `next_retry` 时精准唤醒。

---

## 5. 执行闭环与 guarden 清理

### 5.1 协调循环核心算法

```text
       ┌────────────────────────────────────────────────────────┐
       │ 唤醒源: ManagerCommand (Refresh/Bind/Stop) OR 定时器   │
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
2. **在途操作收束保证（R2 闭合）**：
   Manager 协调循环是单线程顺序执行的，每次调用 `backend.add(&route).await` 或 `backend.remove(&route).await` 均同步等待底层系统调用返回。当收到外部 `ManagerCommand::Stop`、`BindTunDevice` 或取消信号时，**循环必定先等待当前正在执行的底层调用返回并记账**（记入 `installed_routes` 或 `unknown_routes`），然后才进入停机清理或换绑。绝不存在脱离记账的在途操作，杜绝迟到结果落到重建后的新网卡上。
3. **中途失效丢弃过时计划**：
   在遍历执行 `to_remove` 和 `to_add` 时，每处理 16 项检查一次取消令牌与输入版本。若检测到网卡失效或新输入涌入，**立即终止执行余下过时条目**，将已成功的操作正确记账后，立即进入下一轮最新全量比对。
4. **替换依赖顺序保证**：
   若同一个槽位（相同目标 CIDR）需要替换（例如 metric 变更），必须**先执行并确认删除成功，才允许尝试添加**。删除若失败，严禁盲目执行添加。

### 5.3 基于 `guarden` 的资源收束与设备清理（R2 / R3 闭合）

废除上一轮复杂的自定义冻结协调协议（`FrozenAwaitingDecision`、`CleaningActive`、`ConfirmInterfaceDestroyed` 等），复用仓库现有的 `guarden = "0.3"` 统一管理清理任务与设备资源的所有权：

#### 1. 真实 Host 设备持有接线
在 `easytier/src/instance/runtime_host/tun_desktop.rs` 与 `tun_common.rs` 中明确资源持有关系：
```rust
// runtime_host/tun_common.rs
struct NicCtxContainer {
    nic_ctx: Option<Box<dyn Any + Send>>, // 持有底层 TUN 文件描述符与虚拟网卡
    device_keepalive: Arc<Notify>,        // 设备保活凭证 (只要清理未完成，不得释放)
    magic_dns: MagicDnsRuntime,
}
```
- **保活凭证保护**：`HostRouteManager` 或其清理守卫持有 `device_keepalive`。即使调用方等待超时或触发 `TunNicState::stop()`，只要清理任务尚未完成，`device_keepalive` 就不会被 drop，底层的 `nic_ctx` 和 TUN 接口保持存活，防止内核先销毁设备导致 Netlink 删除请求报错。
- **单线程自然收束**：Manager 在接收到 `Stop` 命令后，首先完成当前在途的单次操作并更新账目，确保账目完整后才构造清理守卫。

#### 2. guarden 清理守卫构造与 Unknown 安全排除
通过 `guarden::guard!` 创建异步清理守卫，**严格跳过 `unknown_routes`，严禁盲目向内核重复发送未知状态的操作，并完整收集结果**：

```rust
let (completion_tx, completion_rx) = tokio::sync::oneshot::channel();
let mut cleanup_guard = guarden::guard! {
    [
        mut backend,
        installed = installed_routes,
        unknown = unknown_routes,
        device_keepalive,
        completion_tx = Some(completion_tx)
    ]
    async move {
        let mut uncleaned_routes = Vec::new();
        let mut unknown_routes_during_cleanup = Vec::new();

        // 1. 逐条精确删除本方创建的有效路由
        for route in installed {
            // 严禁对已知结果不明的条目盲目重发删除！
            if unknown.contains(&route) {
                continue;
            }
            match backend.remove(&route).await {
                Ok(Some(())) | Ok(None) => {
                    // 成功移出系统或系统中已无该精确条目
                }
                Err(RouteError::Failed(err)) => {
                    tracing::error!(?route, ?err, "failed to remove route during cleanup");
                    uncleaned_routes.push(route);
                }
                Err(RouteError::Unknown(err)) => {
                    tracing::error!(?route, ?err, "unknown result during route cleanup");
                    unknown_routes_during_cleanup.push(route);
                }
            }
        }

        // 2. 汇总未决责任 (此前积累的 unknown 与清理期间新增的 unknown)
        let mut all_unknown: Vec<Route> = unknown.into_iter().collect();
        all_unknown.extend(unknown_routes_during_cleanup);

        // 3. 计算最终真实结果：仅当无失败且无未决项时才返回 Ok(())
        let final_outcome = if uncleaned_routes.is_empty() && all_unknown.is_empty() {
            Ok(())
        } else {
            Err(CleanupIncomplete {
                uncleaned_routes,
                unknown_routes: all_unknown,
                reason: "route cleanup incomplete: encountered failed deletions or undetermined route states".to_string(),
            })
        };

        if let Some(tx) = completion_tx {
            let _ = tx.send(final_outcome.clone());
        }
        // 守卫结束：此处才真正释放 device_keepalive 与 backend，允许底层网卡安全释放
        final_outcome
    }
};
```

#### 3. 守卫触发与任务跟踪模型
- **任务触发**：调用 `let cleanup_task = cleanup_guard.trigger();`，返回 `guarden::task::DetachableTask`。
- **任务驱动与结果保存**：Manager 主任务直接执行 `let outcome = cleanup_task.await;`。Manager 任务的 `JoinHandle` 持续追踪该清理过程，直到清理真正完成才退出；同时将 `outcome` 写入 `handle.cleanup_result`。
- **超时与分离机制**：
  - 调用方 `handle.stop(deadline)` 整体受 `deadline` 约束。若在超时前收到 `completion_rx`，如实返回 `Result<(), CleanupIncomplete>`。
  - 若调用方到达 `deadline` 超时，调用方结束等待并返回 `Err(CleanupIncomplete { .. reason: "timeout waiting for cleanup" })`。
  - **关键保障**：调用方超时绝不打断后台任务。后台 `DetachableTask` 继续由 Manager 调度执行并持有 `device_keepalive`，防止设备被提前释放。清理完成后更新 `cleanup_result`，外部可通过 `handle.query_cleanup_result()` 随时获取真实终态。
- **自有 TUN 级联销毁捷径约束**：
  若 Host 选择通过直接关闭自有 TUN 文件描述符让内核自动级联删除接口路由：
  - 必须先停止 Manager 协调循环并收束在途操作；
  - 必须确认实际设备已被内核关闭销毁；
  - 仅清理绑定在对应 TUN `ifindex` 上的已安装记录；
  - **严禁与逐条 Netlink 删除任务并发执行**；
  - **显式指定到外部接口（如 `eth0`）的静态路由不具备该捷径，必须由守卫逐条执行精确删除**。

### 5.4 停机流程与超时保证 (`stop(deadline)`)

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

停机调用 `handle.stop(deadline)` 时严格执行以下步骤：
1. **立即打断调度**：入口处立即触发 `cancel_token.cancel()`，拒绝接收新操作。
2. **全流程限时等待**：
   `RouteManagerHandle::stop(&self, deadline: Instant)` 整体受 `tokio::time::timeout_at(deadline, ...)` 包裹：
   - 发送 `ManagerCommand::Stop` 并等待清理完成通知。
   - 若发送或清理等待超时，准时在 `deadline` 到达时返回 `Err(CleanupIncomplete { .. reason: "deadline exceeded while waiting for route cleanup" })`。
   - 宿主通过借用 `&self` 依然持有 `RouteManagerHandle`，后台清理任务继续安全持有设备保活凭证执行到底。
3. **真实结果透明判定（R3 闭合）**：
   - 仅当 `uncleaned_routes` 为空**且 `unknown_routes` 为空**时返回 `Ok(())`；
   - 若存在任何删除失败条目或未决条目，绝不虚报成功，严格返回 `CleanupIncomplete`；
   - 如实承认系统调用的不确定性边界：guarden 确保任务生命周期不被过早掐断，但在系统调用结果确实无法核实（`RouteError::Unknown`）时，如实上报未完成，绝不向用户虚假承诺“内核绝无未决状态”。

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
Batch 1: 纯计算与统一模型 (Core 快照与算法 + Host 策略与统一 Route 模型 + DeviceId)
   ↓
Batch 2: 精确删除改造与平台后端 (Netlink 消除 dump、长连接、原生 async fn、Mock 后端)
   ↓
Batch 3: HostRouteManager 核心闭环 (统一 RouteError、收束在途操作、跳过 unknown、guarden 清理)
   ↓
Batch 4: Host 真实生命周期接线与交接 (DeviceId 换绑、device_keepalive 保活、DNS 解耦、旧 updater 屏蔽)
   ↓
Batch 5: 隔离环境原生测试与基准度量 (netns 真实系统调用、零 dump、零写度量)
```

### 8.1 分批实施详细任务

#### Batch 1：纯计算与统一模型
- **代码落点**：
  - `easytier-core/src/peers/route/peer_ospf_route.rs`：在 `PeerRouteServiceImpl::update_route_table` 维护 `Arc<BTreeSet<Ipv4Cidr>>` 快照并导出变更通知。
  - `easytier-core/src/instance/packet_plane.rs`：导出 `list_proxy_cidrs_snapshot`。
  - `easytier-core/src/peers/route/projection.rs`：纯函数 `normalize_v4_cidr`（基于 `Ipv4Inet::network()`）。
  - `easytier/src/instance/route/model.rs`：`DeviceId`、统一 `Route` 结构与 `RouteError` 枚举。
  - `easytier/src/instance/route/policy.rs`：Host 策略计算 `calculate_desired_routes`（解析 `DeviceId`、默认 Metric 与过滤未迁移冲突）。
- **验证**：
  - 单元测试：主机位非零安全规范化（`10.0.0.1/24` $\to$ `10.0.0.0/24`，无 panic）、`/0` 与 `/32` 边界测试、非法前缀测试、`manual_routes` 三态测试、未迁移 DNS `/32` 碰撞排除测试。

#### Batch 2：精确删除改造与平台后端
- **代码落点**：
  - `easytier/src/common/ifcfg/netlink.rs`：改造 `remove_ipv4_route`，消除全量 dump，直接匹配 destination, oif (`route.interface.ifindex`), priority, table 发送 `RTM_DELROUTE`。
  - `easytier/src/instance/route/backend.rs`：`RouteBackend` trait（采用原生 `async fn` 零装箱）、严格门控别名 `PlatformRouteBackend`（仅限 `all(target_os = "linux", feature = "linux-netlink")`）与 `MockRouteBackend`。
- **验证**：
  - 单元测试：同接口、同前缀但不同 metric 的精确删除测试（验证外部 metric 路由不被误删）；Mock 后端记录核对测试；静态分发原生 async 调用验证。

#### Batch 3：HostRouteManager 核心闭环
- **代码落点**：
  - `easytier/src/instance/route/manager.rs`：实现 `HostRouteManager` 协调循环、快照与 `DeviceId` 比对跳过、串行在途操作收束、diff 与清理均跳过 `unknown_routes`、基于 `guarden` 且持有 `device_keepalive` 的清理与 `stop(deadline)`。
- **验证**：
  - 基于 `MockRouteBackend` 的闭环测试：
    - 首启全量添加；
    - 输入未变稳态 0 调用与 0 堆分配；
    - **同名网卡重建重装**：重建模似 TUN（`tun0` $\to$ `tun0`，`ifindex` 变更），验证自动触发全量重装；
    - **显式外部接口保护**：默认 TUN 重建或退出时，验证绑定到其他外部接口（如 `eth0`）的路由记录完整保留，不被误删或丢弃；
    - **在途操作收束**：模拟单次 ADD 阻塞在底层，触发退出并使调用方等待超时，验证在途操作被单线程循环正常收束记账，旧操作绝不落到重建后的网卡上；
    - **未决隔离与真实报告**：操作结果返回 `RouteError::Unknown` 时准确记入 `unknown_routes`；后续 diff 循环与清理循环均自动跳过该条目（不盲发重试）；stop 最终返回 `CleanupIncomplete`，绝不误报成功；
    - **Stop 限时超时与后台保活**：调用方 stop 超时后按时返回，后台 guarden 任务继续持有 `device_keepalive` 和 backend 安全运行直至结束，设备不被提前释放；外部可通过 `query_cleanup_result` 获得最终完成结果；
    - No-TUN 旁路测试（已安装记录保持为空）。

#### Batch 4：Host 真实生命周期接线与交接
- **代码落点**：
  - `easytier/src/instance/dns_server/server_instance.rs` & `runner.rs` & `runtime_host/magic_dns.rs`：解耦系统配置与路由清理，返回 `DnsCleanOutcome` 并向上抛出。
  - `easytier/src/instance/runtime_host/tun_desktop.rs` & `tun_common.rs` & `implementation.rs`：传递 `DeviceId` 与 `device_keepalive`，网卡就绪与重建时触发 `bind_tun_device`，停机时调用 `stop(deadline)`。
  - `easytier/src/instance/virtual_nic.rs`：仅在 `not(all(target_os = "linux", feature = "linux-netlink"))` 下启动 `run_proxy_cidrs_route_updater`。
- **验证**：
  - 跨平台与特性组合编译验证：验证 Linux（开启/未开启 netlink）、Windows、macOS（含 `macos-ne`）、FreeBSD 均能顺利编译，未迁移平台维持原有旧链路；
  - 集成测试：启动集成测试节点，动态推送 `manual_routes`，验证真实 Manager 接管生效且旧 updater 不重复写入；
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

- [ ] **统一模型与确切设备身份**：以包含 `DeviceId { ifname, ifindex }` 的单一 `Route` 模型表达期望与安装路由；CIDR 主机位非零（如 `10.0.0.1/24`）安全规范化，无 panic；自动代理、手工覆盖均准确计算。
- [ ] **同名网卡重建重装与多接口隔离**：同名网卡销毁后重建（`tun0` $\to$ `tun0`），Manager 依据 `ifindex` 变更精确触发重新安装；默认 TUN 销毁或换绑时，显式绑定到其他外部接口（如 `eth0`）的路由记录完整保留，不被误删。
- [ ] **依赖方向与严格编译门控**：`easytier-core` 绝无引用 `easytier` 类型；`PlatformRouteBackend` 仅在 `all(target_os = "linux", feature = "linux-netlink")` 下声明，不预建未实现的平台别名或 Stub 类型；全平台及特性组合均独立可编译。
- [ ] **原生异步后端与精确删除**：`RouteBackend` 采用原生 `async fn` 零装箱静态分发；Linux 精确删除直接按 `ifindex`、目标、metric 与 table 发送单发 `RTM_DELROUTE`，0 次全表 dump。
- [ ] **稳态零多余操作**：在网络拓扑与配置稳定的状态下，快照指针与设备身份比对快速拦截，协调循环不产生多余的底层系统调用和堆内存分配；无关服务配置变动不引发路由重算。
- [ ] **在途操作收束与 guarden 设备保活**：单线程协调循环在停机或换绑前先等待当前在途操作返回并记账；guarden 清理守卫持有 `device_keepalive`，调用方等待超时不提前释放底层设备资源，迟到结果安全结算。
- [ ] **未决隔离与真实清理结果**：`unknown_routes` 在 diff 和清理中均被跳过，严禁盲发重发；清理流程收集失败与未决条目；存在未决条目或删除失败时，`stop(deadline)` 如实返回 `CleanupIncomplete`，绝不虚报成功。
- [ ] **交接防误放行与 DNS 真实删除**：未决操作存在时严格阻塞交接；Linux 等无 `system_config` 环境下 DNS 停止仍如实执行路由删除；系统配置恢复错误与路由清理错误分离，路由删除失败保留排除范围，杜绝双写。
- [ ] **生产控制一致**：在第二步启用的平台（Linux + linux-netlink）完全由 HostRouteManager 接管且旧 updater 停写；未迁移平台保持原有旧链路，不发生漏写或双写。
