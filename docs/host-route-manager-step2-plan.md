# HostRouteManager 第二步实施方案：架构收缩与最小闭环（第七轮修订版）

状态：已根据第六轮架构收缩审查（[`docs/host-route-manager-step2-review-6.md`](host-route-manager-step2-review-6.md)）完成全面重构与简化。遵循实施总纲（[`docs/host-route-manager-master-plan.md`](host-route-manager-master-plan.md)）与第一步规范（[`docs/host-route-manager-step1-audit-and-contract.md`](host-route-manager-step1-audit-and-contract.md)）。  
基线代码：`refactor/route` 分支；参考分支：`refactor/route-dev` (`8abfb51e`)。

---

## 1. 目标与范围及平台边界

### 1.1 核心目标
本阶段交付一个**小巧、精简、可工作的 HostRouteManager 闭环**：
1. **范围聚焦**：接管 **IPv4 自动子网代理路由（Peer Proxy CIDR）** 与 **手工静态代理路由（`manual_routes`）**。
2. **单一路由模型**：以统一的完整 `Route` 结构表达期望集与成功创建集，接口与 Metric 均作为路由属性。
3. **标准错误与结果类型**：统一为一个 `RouteError`（区分 `Failed` 与 `Unknown`），系统操作结果使用标准 `Result<Option<Route>, RouteError>`。
4. **编译期后端选择**：沿用仓库现有的 `cfg` 编译期平台选择，删除动态 `Box<dyn Backend>` 运行时分发与临时包装。
5. **guarden 资源收束**：复用项目已有 `guarden = "0.3"` 管理清理任务与设备资源生命周期，删除自定义的冻结协调状态机。
6. **写入权平滑交接**：Linux 原生环境完全接管并停用旧 updater；未迁移平台保持原有旧链路；Magic DNS 与接口前缀通过生命周期确认杜绝双写。

### 1.2 平台范围与生产接管策略

本阶段不建立长期的公共模式枚举，采用装配处/编译期的确定性选择：

| 平台分类 | 第二步接管状态 | 真实后端文件 | 旧 Writer 退出时机 | 第二步验收范围 |
| :--- | :--- | :--- | :--- | :--- |
| **Linux** | **完全原生接管** | `easytier/src/instance/route/backend/netlink.rs` | 实例化 `HostRouteManager`，跳过创建 `VirtualNic::run_proxy_cidrs_route_updater` | 隔离 netns 下真实 Netlink 系统调用；增删、精确匹配、长连接与退避验证 |
| **Windows / macOS** | **维持原链路** | 暂留后续步骤迁移 | 维持现有 `VirtualNic` 路由更新器 | 保持编译通过与现有功能完整，不提前声称接管 |
| **Android / 移动端** | **维持原链路** | 暂留后续步骤迁移 | 维持现有 `mobile_vpn.ts` 前端并集拼装 | 生产保持旧链路，不预建未接入的动态代理分支 |
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
  - 定义统一的 `Route` 结构与 `RouteError` 枚举。
  - 实现 Host 侧策略计算 `calculate_desired_routes`：解析默认接口与默认 Metric（Linux 65535, Windows 9000），过滤未迁移冲突，输出 `BTreeSet<Route>`。
  - 实现具体平台后端（Linux Netlink 长连接、消除 dump）。
  - 实现 `HostRouteManager` 协调循环、失败退避与基于 `guarden` 的清理。
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
              │     ├── model.rs            [新增] 统一 Route 结构, RouteError
              │     ├── policy.rs           [新增] Host 侧策略计算 (接口/Metric 解析与冲突过滤)
              │     ├── backend.rs          [新增] RouteBackend trait 及编译期平台类型别名
              │     ├── backend/
              │     │     └── netlink.rs    [新增] Linux 专属实现 (长连接 netns 绑定、req/ACK 匹配、消除 dump)
              │     └── manager.rs          [新增] HostRouteManager 核心闭环与 guarden 清理
              ├── dns_server/
              │     ├── server_instance.rs  [修改] clean_env() 解耦系统配置并独立返回 DnsCleanOutcome
              │     └── runner.rs           [修改] 传递 clean_env() 结果至外部
              ├── runtime_host.rs           [修改] 管理器实例生命周期挂载与停机协调
              ├── runtime_host/
              │     ├── implementation.rs   [修改] 转发宿主运行时接口
              │     ├── magic_dns.rs        [修改] stop() 向上返回 DnsCleanOutcome
              │     └── tun_desktop.rs      [修改] 网卡就绪与重建时触发 Manager 换绑与刷新
              └── virtual_nic.rs            [修改] Linux 下跳过创建 run_proxy_cidrs_route_updater
```

---

## 3. 结构与接口定义

### 3.1 统一路由模型 (`Route`)

合并旧方案中重复的 `RouteSpec` 与 `InstalledRoute`，使用一种完整的 `Route` 结构表达生效参数：

```rust
// easytier/src/instance/route/model.rs
use std::net::Ipv4Addr;
use cidr::{IpCidr, Ipv4Cidr, Ipv4Inet};

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Route {
    /// 目标网络 CIDR
    pub destination: IpCidr,
    /// 指定出口网卡名称 (执行前若未指定则解析为实例默认 TUN 网卡)
    pub interface: String,
    /// 有效 Metric 跃点数 (执行前若未指定则解析为平台默认值，Linux 为 65535)
    pub metric: u32,
}

impl Route {
    /// 安全的 IPv4 构造函数：利用 Ipv4Inet 清除主机位，非法前缀显式返回错误，杜绝 panic
    pub fn try_new_v4(addr: Ipv4Addr, prefix: u8, interface: String, metric: u32) -> Result<Self, cidr::errors::NetworkParseError> {
        let inet = Ipv4Inet::new(addr, prefix)?;
        Ok(Self {
            destination: IpCidr::V4(inet.network()),
            interface,
            metric,
        })
    }

    /// 从已规范化的 Ipv4Cidr 构造
    pub fn from_v4_cidr(cidr: Ipv4Cidr, interface: String, metric: u32) -> Self {
        Self {
            destination: IpCidr::V4(cidr),
            interface,
            metric,
        }
    }
}
```

**模型与行为约束（A1 闭合）**：
- **完整参数表达**：无论是期望集合（`desired`）还是成功安装集合（`installed`），均使用 `Route`。
- **解析在先、匹配在前**：输入中的缺省接口和默认 Metric 在进入执行前由策略函数完成补全；用户显式指定的接口不得被隐式替换为默认 TUN。不同接口的同 CIDR 视为不同路由。
- **删除以创建记录为准**：系统调用成功后将实际创建参数存入 `installed: BTreeSet<Route>`；删除时严格使用该记录，绝不重新根据当前变化了的默认值猜测接口与 Metric。
- **所有权表达权限**：仅仅系统中存在相同前缀或字段齐全，不赋予本方删除权；只有记录在 `installed` 中的路由才允许被本方清理。

### 3.2 标准错误类型 (`RouteError`) 与后端接口

删除自定义的 `Outcome` 枚举，统一使用标准 `thiserror` 错误与 `Result<Option<T>, RouteError>`：

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

#[async_trait::async_trait]
pub trait RouteBackend: Send + Sync + 'static {
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

### 3.3 编译期平台选择与 Linux Netlink 实现

沿用仓库已有 `common/ifcfg/mod.rs` 模式，通过编译期条件选择具体类型别名，删除生产运行时的 `Box<dyn Backend>` 动态分发（A3 闭合）：

```rust
// easytier/src/instance/route/backend.rs

#[cfg(target_os = "linux")]
pub type PlatformRouteBackend = netlink::NetlinkRouteBackend;

#[cfg(target_os = "windows")]
pub type PlatformRouteBackend = windows::WindowsRouteBackend;

#[cfg(target_os = "macos")]
pub type PlatformRouteBackend = darwin::DarwinRouteBackend;

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
pub type PlatformRouteBackend = stub::StubRouteBackend;
```

#### Linux Netlink 后端细节要求
`easytier/src/instance/route/backend/netlink.rs` 的实现必须满足：
1. **连接与 NetNS 绑定**：创建时在目标 NetNS 中打开长连接 Netlink 套接字并绑定，生命周期内持续复用，消除每请求临时创建 socket 的开销。
2. **请求 / ACK 匹配**：为每次请求分配单调递增的序列号（`nlmsg_seq`），收包循环严格匹配对应的 `NLMSG_ERROR` ACK，正确处理乱序或插队响应。
3. **消除 Dump**：直接构造带 `RTA_DST`、`RTA_OIF`、`RTA_PRIORITY`、`rtm_table` 的单发 `RTM_DELROUTE` 报文下发，单条删除请求数量恒定为 1，杜绝用户态全表 dump 扫描。
4. **异步安全**：将阻塞底层网络 I/O 放入 `tokio::task::spawn_blocking` 中执行，不阻塞 Tokio 异步调度器线程；NetNS 绑定固定在专用执行环境中，绝不跨越 `await`。

### 3.4 Manager 结构与句柄定义

Manager 直接持有编译期确定的具体后端类型（支持泛型以方便单元测试替换）：

```rust
// easytier/src/instance/route/manager.rs
use std::collections::{BTreeMap, BTreeSet};
use super::model::*;
use super::backend::PlatformRouteBackend;

pub enum ManagerCommand {
    /// 触发刷新：外部通知有新快照或配置变更到达，协调循环被唤醒后统一拉取
    Refresh,
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
    /// 操作结果不明的未决路由责任表 (严禁当成普通失败重试，停机时作为未完成项报告)
    unknown_routes: BTreeSet<Route>,
    /// 失败重试退避追踪表
    retry_tracker: BTreeMap<Route, RetryState>,
    /// 当前生效的网卡名称
    current_interface: Option<String>,
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
    join_handle: std::sync::Arc<tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>>,
    cancel_token: tokio_util::sync::CancellationToken,
}

impl RouteManagerHandle {
    /// 发送刷新唤醒 (通知到达时合并触发，不逐条排队)
    pub fn notify_refresh(&self) {
        let _ = self.cmd_tx.try_send(ManagerCommand::Refresh);
    }

    /// 显式停机：借用 Handle，整个等待严格受 deadline 约束；超时返回未完成信息，原持有者继续保留 Handle
    pub async fn stop(&self, deadline: std::time::Instant) -> Result<(), CleanupIncomplete> { ... }
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
   - 未迁移事实快照。
   若输入未变且当前网卡名称未变，直接复用 `desired_routes_cache`，**0 堆分配，0 策略重算**。
2. **差异跳过机制**：
   比对 `desired_routes_cache` 与 `installed_routes`：若二者集合完全相等且无到期的失败重试项，**直接跳过系统调用并休眠**，稳态系统调用数为 0。
3. **网卡替换强制重算**：
   当网卡发生替换（`current_interface` 变化）时，即使 Core 输入快照未变，差异比对会立即发现 `installed_routes` 为空，从而直接下发期望路由，杜绝同配置换卡漏装路由的问题。
4. **低频保底与独立重试**：
   废除 1 秒忙碌轮询，设 30 秒低频保底核对；失败重试由退避计时器在到达最早 `next_retry` 时精准唤醒。

---

## 5. 执行闭环与 guarden 清理

### 5.1 协调循环核心算法

```text
       ┌────────────────────────────────────────────────────────┐
       │ 唤醒源: ManagerCommand (Refresh/Stop) OR 重试/保底定时器 │
       └──────────────────────────┬─────────────────────────────┘
                                  ↓
       ┌────────────────────────────────────────────────────────┐
       │ 1. 检查取消令牌与命令 (若收到 Stop 命令进入停机清理流程) │
       │ 2. 拉取最新权威输入:                                   │
       │    - 比较快照与路由配置 (未变则复用 desired_routes_cache)│
       │ 3. 策略计算生成 desired_routes (过滤未迁移冲突, 解析参数)│
       │ 4. 计算差异:                                           │
       │    to_remove = installed - desired                     │
       │    to_add    = desired - installed                     │
       │    若差异为空且无到期重试项 -> 稳态直接休眠             │
       └──────────────────────────┬─────────────────────────────┘
                                  ↓
       ┌────────────────────────────────────────────────────────┐
       │ 5. 逐项有界执行 (每 16 项检查一次取消与输入失效):       │
       │    a. 执行 to_remove:                                  │
       │       - Ok(Some(())) / Ok(None) -> 移出 installed      │
       │       - Err(Failed)  -> 记录指数退避                   │
       │       - Err(Unknown) -> 记入 unknown_routes            │
       │    b. 执行 to_add:                                     │
       │       - Ok(Some(route)) -> 插入 installed              │
       │       - Ok(None)        -> 外部存在不入账，记录警告     │
       │       - Err(Failed)     -> 记录指数退避                │
       │       - Err(Unknown)    -> 记入 unknown_routes         │
       └────────────────────────────────────────────────────────┘
```

### 5.2 失败退避与有界调度

1. **单项指数退避**：
   对执行失败的路由条目（无论添加还是删除），记录其 `RetryState { attempt: u32, next_retry: Instant }`。
   退避序列：100ms, 200ms, 400ms, 800ms, 1.6s, 最高封顶 5s。
   在下一轮循环计算差异时，**尚未到达 `next_retry` 的失败项不被选入当轮执行队列**。当输入变化使该条目不再需要时，重试状态自动释放。这彻底防止了因无关配置变化或频繁 OSPF 广播导致同一个底层错误被高频重试（防事件风暴）。
2. **中途失效丢弃过时计划**：
   在遍历执行 `to_remove` 和 `to_add` 时，每处理 16 项检查一次取消令牌与输入版本。若检测到网卡失效或新输入涌入，**立即终止执行余下过时条目**，将已成功的操作正确记账后，立即进入下一轮最新全量比对。
3. **替换依赖顺序保证**：
   若同一个槽位（相同目标 CIDR）需要替换（例如 metric 变更），必须**先执行并确认删除成功，才允许尝试添加**。删除若失败，严禁盲目执行添加。

### 5.3 基于 `guarden` 的资源收束与设备清理（A4 闭合）

废除上一轮复杂的自定义冻结协调协议（`FrozenAwaitingDecision`、`CleaningActive`、`ConfirmInterfaceDestroyed` 等），复用仓库现有的 `guarden = "0.3"` 统一管理清理任务与设备资源的所有权：

1. **资源所有权与清理分离**：
   当网卡失效、重建或实例退出时：
   - Manager 停止对对应接口发起新的添加操作。
   - 清理上下文接管相关已安装记录（`installed: BTreeSet<Route>`）、未决责任（`unknown_routes`）以及**底层设备所需资源的所有权**。
2. **guarden 任务承接与超时容忍**：
   通过 `guarden::guard!` 创建异步清理守卫：
   ```rust
   let (completion_tx, completion_rx) = tokio::sync::oneshot::channel();
   let cleanup_guard = guarden::guard! {
       [mut backend, installed, unknown, completion_tx = Some(completion_tx)] {
           async move {
               let mut all_ok = true;
               for route in installed {
                   if let Err(e) = backend.remove(&route).await {
                       all_ok = false;
                       tracing::error!(?route, ?e, "failed to remove route during cleanup");
                   }
               }
               if let Some(tx) = completion_tx {
                   let _ = tx.send(all_ok);
               }
           }
       }
   };
   ```
3. **显式触发与顺序保证**：
   - **正常路径**：宿主或 Manager 显式触发清理任务，并在 `deadline` 内等待 `completion_rx`。
   - **超时路径**：若等待超时，调用方结束等待并报告 `CleanupIncomplete`。**由于 `guarden` 持有后端与底层资源的完整所有权**，清理任务在后台继续平稳调度并结算未决操作，绝不因等待超时粗暴丢弃资源或在内核留下未决状态。
   - **网卡销毁场景**：若宿主关闭底层 TUN 设备（内核自动级联删除其全部路由），宿主释放设备所有权并丢弃对应记录，清理任务不再发起无意义的系统调用，0 次多余系统交互。

### 5.4 停机流程与超时保证 (`stop(deadline)`)

```rust
pub struct CleanupIncomplete {
    pub uncleaned_routes: Vec<Route>,
    pub unknown_routes: Vec<Route>,
    pub reason: String,
}
```

停机调用 `handle.stop(deadline)` 时严格执行以下步骤：
1. **立即打断调度**：入口处立即触发 `cancel_token.cancel()`，拒绝接收新操作。
2. **全流程限时等待**：
   `RouteManagerHandle::stop(&self, deadline: Instant)` 整体受 `tokio::time::timeout_at(deadline, ...)` 包裹：
   - 发送 `ManagerCommand::Stop` 并等待清理完成通知。
   - 若发送或清理等待超时，准时在 `deadline` 到达时返回 `Err(CleanupIncomplete { .. })`。
   - 宿主通过借用 `&self` 依然持有 `RouteManagerHandle`，可继续通过 `join_handle` 观察后台清理任务平稳退出，绝不提前启动竞争 writer。
3. **结果真实透明**：
   仅当 `installed_routes` 全部成功删除且 `unknown_routes` 为空时返回 `Ok(())`；存在删除失败或未决操作时返回 `CleanupIncomplete`，绝不虚报成功。

---

## 6. 写入权交接与动态冲突防御

### 6.1 写入权控制

依据装配处的平台决策统一控制写入权：
- **Linux 生产环境**：启用 `HostRouteManager`，宿主在创建网卡时跳过启动 `VirtualNic::run_proxy_cidrs_route_updater`，全仓代理路由仅由单一 Manager 写入。
- **Windows / macOS / 移动端**：第二步维持原有旧链路运行，不启动新 Manager。

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
  新方案彻底废除 1 秒定时轮询，由变更驱动通知唤醒。协调循环利用不可变快照指针（`Arc::ptr_eq`）快速拦截，稳态下不拉取路由表、不创建集合、不执行 diff 比对。
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
Batch 1: 纯计算与统一模型 (Core 快照与算法 + Host 策略与统一 Route 模型)
   ↓
Batch 2: 精确删除改造与平台后端 (Netlink 消除 dump、长连接、Mock 后端)
   ↓
Batch 3: HostRouteManager 核心闭环 (统一 RouteError、结果映射、失败退避、guarden 清理)
   ↓
Batch 4: Host 真实生命周期接线与交接 (runtime_host 挂载、DNS 错误解耦、旧 updater 屏蔽)
   ↓
Batch 5: 隔离环境原生测试与基准度量 (netns 真实系统调用、零 dump、零写度量)
```

### 8.1 分批实施详细任务

#### Batch 1：纯计算与统一模型
- **代码落点**：
  - `easytier-core/src/peers/route/peer_ospf_route.rs`：在 `PeerRouteServiceImpl::update_route_table` 维护 `Arc<BTreeSet<Ipv4Cidr>>` 快照并导出变更通知。
  - `easytier-core/src/instance/packet_plane.rs`：导出 `list_proxy_cidrs_snapshot`。
  - `easytier-core/src/peers/route/projection.rs`：纯函数 `normalize_v4_cidr`（基于 `Ipv4Inet::network()`）。
  - `easytier/src/instance/route/model.rs`：统一 `Route` 结构与 `RouteError` 枚举。
  - `easytier/src/instance/route/policy.rs`：Host 策略计算 `calculate_desired_routes`。
- **验证**：
  - 单元测试：主机位非零安全规范化（`10.0.0.1/24` $\to$ `10.0.0.0/24`，无 panic）、`/0` 与 `/32` 边界测试、非法前缀测试、`manual_routes` 三态测试、未迁移 DNS `/32` 碰撞排除测试。

#### Batch 2：精确删除改造与平台后端
- **代码落点**：
  - `easytier/src/common/ifcfg/netlink.rs`：改造 `remove_ipv4_route`，消除全量 dump，直接匹配 destination, oif, priority, table 发送 `RTM_DELROUTE`。
  - `easytier/src/instance/route/backend.rs`：`RouteBackend` trait、编译期平台别名与 `MockRouteBackend`。
- **验证**：
  - 单元测试：同接口、同前缀但不同 metric 的精确删除测试（验证外部 metric 路由不被误删）；Mock 后端记录核对测试。

#### Batch 3：HostRouteManager 核心闭环
- **代码落点**：
  - `easytier/src/instance/route/manager.rs`：实现 `HostRouteManager` 协调循环、快照比对跳过、失败指数退避、中途失效检查、基于 `guarden` 的清理与 `stop(deadline)`。
- **验证**：
  - 基于 `MockRouteBackend` 的闭环测试：
    - 首启全量添加；
    - 输入未变稳态 0 调用与 0 堆分配；
    - 换网卡触发全量安装；
    - 失败单项指数退避测试；
    - 操作结果返回 `RouteError::Unknown` 时准确记入 `unknown_routes`，随后 stop 返回 `CleanupIncomplete`，不误报成功；
    - Stop 限时等待超时测试，验证超时后由 guarden 任务在后台继续持有资源并安全退出；
    - No-TUN 旁路测试（已安装记录保持为空）。

#### Batch 4：Host 真实生命周期接线与交接
- **代码落点**：
  - `easytier/src/instance/dns_server/server_instance.rs` & `runner.rs` & `runtime_host/magic_dns.rs`：解耦系统配置与路由清理，返回 `DnsCleanOutcome` 并向上抛出。
  - `easytier/src/instance/runtime_host.rs` & `tun_desktop.rs` / `tun_common.rs` / `implementation.rs`：接入 `RouteManagerHandle`，在网卡就绪与重建时触发换绑与刷新，关闭时调用 `stop(deadline)`。
  - `easytier/src/instance/virtual_nic.rs`：Linux 下跳过创建 `run_proxy_cidrs_route_updater`。
- **验证**：
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

- [ ] **统一模型与计算正确**：以单一 `Route` 模型表达期望与安装路由；CIDR 主机位非零（如 `10.0.0.1/24`）安全规范化，无 panic；自动代理、手工覆盖均准确计算。
- [ ] **依赖方向合规**：`easytier-core` 绝无引用 `easytier` 类型，所有构建目标独立可编译。
- [ ] **精确删除与身份完整**：已安装记录保存实际创建参数；同接口同前缀下不同 metric 的外部路由不被误删。
- [ ] **稳态零多余操作**：在网络拓扑与配置稳定的状态下，快照指针比对快速拦截，协调循环不产生多余的底层系统调用和堆内存分配；无关服务配置变动不引发路由重算。
- [ ] **换网卡不丢路由**：网卡替换时差异比对生效，在新网卡上准确下发全部期望路由。
- [ ] **guarden 资源收束与设备清理**：退出或换网卡时由 guarden 任务持有资源所有权平稳结算，超时不破坏操作系统状态，设备不被提前释放。
- [ ] **停机超时全程覆盖**：`stop(deadline)` 全程受 deadline 约束，超时按时返回 `CleanupIncomplete`；Host 持续持有 Handle 跟踪后台在途操作，绝不虚报成功。
- [ ] **交接防误放行与 DNS 真实删除**：未决操作存在时严格阻塞交接；Linux 等无 `system_config` 环境下 DNS 停止仍如实执行路由删除；系统配置恢复错误与路由清理错误分离，路由删除失败保留排除范围，杜绝双写。
- [ ] **无全表 Dump**：Linux 下删除路由直接构造 `RTM_DELROUTE`，基准测试验证 0 次 `RTM_GETROUTE` dump。
- [ ] **失败退避与结果明确**：标准 `RouteError` 区分确定失败与未知结果；失败项执行指数退避；结果不明记录为未决责任，停机时作为未完成项上报。
- [ ] **生产控制一致**：在第二步启用的平台（Linux 原生）完全由 HostRouteManager 接管且旧 updater 停写；未迁移平台保持原有旧链路，不发生漏写或双写。
