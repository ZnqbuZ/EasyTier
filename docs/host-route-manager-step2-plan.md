# HostRouteManager 第二步实施方案：最小 Manager 闭环（第三轮修订版）

状态：已根据审查意见（[`docs/host-route-manager-step2-review.md`](host-route-manager-step2-review.md)）完成逐条修订。严格遵循最新实施总纲（[`docs/host-route-manager-master-plan.md`](host-route-manager-master-plan.md)）与第一步规范（[`docs/host-route-manager-step1-audit-and-contract.md`](host-route-manager-step1-audit-and-contract.md)）。  
基线代码：`refactor/route` 分支；参考分支：`refactor/route-dev` (`8abfb51e`)。

---

## 1. 目标与范围及平台启用边界

### 1.1 核心目标
本阶段交付一个**小型的、实用的 HostRouteManager 闭环**：
1. **范围聚焦**：接管 **IPv4 自动子网代理路由（Peer Proxy CIDR）** 与 **手工静态代理路由（`manual_routes`）**。
2. **直连事实与闭环操作**：直接从 Core 路由表与配置拉取事实，由 Host 完成纯函数策略计算，通过薄后端接口应用变更，维护携带实际创建参数与接口代际的精确记录（`InstalledRoute`），支持带退避的失败重试与带超时的显式停机清理。
3. **平滑交接与防双写**：停用旧 `ProxyCidrMonitor` 与 `VirtualNic::run_proxy_cidrs_route_updater` 的系统写权限；尚未迁移的 Public IPv6、Magic DNS 及接口前缀在第二步暂不接入，但在阶段一通过生命周期时序完成重叠范围的动态交接与防御，杜绝新旧双写。
4. **性能与精简约束**：彻底不引入旧版版本化需求框架（无 Registry / Token / Epoch / 生产影子框架）；满足稳态零多余写入、快照与连接复用、消除逐条 dump 等可测量的性能指标。

### 1.2 跨平台启用状态与职责边界

| 平台分类 | 第二步启用状态 | 真实后端 / 宿主接线文件 | 旧 Writer 退出条件 | 第二步验收范围 |
| :--- | :--- | :--- | :--- | :--- |
| **Linux** | **原生完全接管** | `easytier/src/instance/route/backend/netlink.rs`<br>衔接 `NetlinkIfConfiger` | 禁用 `ProxyCidrMonitor` 路由事件；停用 `VirtualNic::run_proxy_cidrs_route_updater` | 隔离 netns 下真实 Netlink 系统调用测试；覆盖增删、精确匹配与重试 |
| **Windows** | **原生后端就绪** | `easytier/src/instance/route/backend/windows.rs`<br>衔接 `WindowsIfConfiger` | 保持与 Linux 相同开关；未显式启用时维持旧链路 | 隔离环境 Win32 API 增删与默认 Metric (9000) 映射测试 |
| **macOS / FreeBSD** | **原生后端就绪** | `easytier/src/instance/route/backend/darwin.rs`<br>衔接 `MacIfConfiger` | 保持与 Linux 相同开关；未显式启用时维持旧链路 | CLI 命令执行与状态码检查测试；显式接口前缀暂留旧链路 |
| **Android / 移动委托** | **契约与模拟会话** | `easytier/src/instance/route/backend/delegated.rs`<br>（适配 `VpnService.Builder` 接口模型） | **生产维持旧链路**：因移动端 VPN 需同时携带 DNS 与子网配置，在第二步不切换生产 `mobile_vpn.ts` | 委托后端全量应用契约测试、会话代际确认与会话重置测试 |
| **No-TUN** | **明确旁路** | `RouteBackend::NoTun` | 停用旧 monitor 虚假事件 | 验证正常计算期望，但完全跳过执行分支，已安装记录严格为空 |

---

## 2. 代码落点与复用清单

### 2.1 源码分工与依赖单向性约束

严格遵守 `easytier → easytier-core` 的单向依赖规则，**Core 绝不引用 Host 类型**：
- **`easytier-core`（纯业务事实与规范化）**：
  - 导出 `CorePacketPlane::list_proxy_cidrs(&self) -> BTreeSet<Ipv4Cidr>`（或其快照），独立于 `proxy-cidr-monitor` feature 开关。
  - 导出配置 `CoreRuntimeConfigStore` 的快照与订阅接口。
  - 导出纯算法函数：
    - `normalize_v4_cidr(addr: Ipv4Addr, prefix: u8) -> Result<Ipv4Cidr, cidr::errors::NetworkParseError>`（CIDR 主机位规范化）。
    - 现有的 `resolve_proxy_cidrs(peer_routes: BTreeSet<Ipv4Cidr>, config: ProxyCidrConfigSnapshot) -> BTreeSet<Ipv4Cidr>`（拥有所有权的手工覆盖计算）。
  - **Core 严禁定义或引用 `RouteSpec`、`InstalledRoute` 或 `UnmigratedRouteTracker`**。
- **`easytier`（宿主策略与系统控制）**：
  - 定义 `RouteSpec`、`InstalledRoute`、`InterfaceBinding` 记录结构与结果枚举。
  - 实现 Host 侧策略函数 `calculate_desired_proxy_routes`：过滤未迁移来源重叠、解析平台默认参数（Linux 65535, Windows 9000）、生成 `RouteSpec`。
  - 实现 `RouteBackend` 及其原生/委托实现（包含长连接 Netlink、Win32 API 等）。
  - 实现 `HostRouteManager` 协调循环、安装记账、重试退避与生命周期停止。
  - 接线宿主生命周期组件：`NativeInstanceRuntimeHost`、`tun_desktop.rs`、`tun_common.rs`。

```text
easytier-core/
  └── src/
        ├── instance/
        │     └── packet_plane.rs           [修改] 独立于 proxy-cidr-monitor feature 导出 list_proxy_cidrs 与通知
        ├── peers/route/
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
              │     ├── model.rs            [新增] RouteSpec, InstalledRoute, InterfaceBinding, 结果枚举
              │     ├── policy.rs           [新增] Host 侧策略计算 (未迁移冲突过滤与参数补全，输出 RouteSpec)
              │     ├── backend.rs          [新增] RouteBackend 抽象与 MockBackend
              │     ├── backend/
              │     │     ├── netlink.rs    [新增] Linux 专属实现 (长连接 netns 绑定、req/ACK 匹配、消除 dump)
              │     │     ├── windows.rs    [新增] Windows 专属实现 (Win32 API、默认 Metric 9000)
              │     │     ├── darwin.rs     [新增] macOS/FreeBSD 专属实现
              │     │     └── delegated.rs  [新增] 移动端委托后端 (真实会话所有者契约)
              │     └── manager.rs          [新增] HostRouteManager 核心闭环与多代际记录
              ├── runtime_host.rs           [修改] 管理器实例生命周期管理 (new/spawn/stop)
              ├── runtime_host/
              │     ├── implementation.rs   [修改] 转发宿主运行时接口
              │     ├── tun_desktop.rs      [修改] 静态 TUN 与 DHCP 换卡就绪时调用 bind，关闭/重置时调用 unbind
              │     └── tun_common.rs       [修改] TunNicState::stop 与 drain 协调解绑与旧网卡销毁确认
              └── virtual_nic.rs            [修改] 停用 run_proxy_cidrs_route_updater
```

### 2.2 `refactor/route-dev` 移植决策

经核对 `refactor/route-dev` (`8abfb51e`) 分支中 `easytier/src/nic/route/manager.rs`：
- **移植并改进**：
  1. `RouteSpec` 概念：移植并精简为包含 `destination: IpCidr` 与 `metric: Option<i32>`，补充基于 `Ipv4Inet::network()` 的安全构造方法。
  2. 单循环顺序处理思路：移植其简洁的循环骨架，但放弃其空白的 `async fn sync()`，填充为真正的比对、执行、记账与退避闭环。
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

/// 安全的纯 IPv4 CIDR 规范化函数：清除主机位，严禁产生 panic
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

### 3.2 操作结果与类型约定

按 master plan 第 2.5 节，后端操作必须返回结构化结果，禁止将所有失败均粗暴归类为重试：

```rust
// easytier/src/instance/route/model.rs

pub enum AddRouteOutcome {
    /// 成功在系统中创建了路由，并返回实际生效的底层安装记录
    Created(InstalledRoute),
    /// 系统中已存在相同条目（非本方创建，不予认领，不入账，记录诊断警告）
    AlreadyPresent,
    /// 确定性的系统调用失败（如权限不足、参数非法），记录错误并按退避重试
    Failed(anyhow::Error),
    /// 结果不明（如超时、Netlink 套接字异常中断），进入阻塞/核对流程，严禁盲目重试
    OutcomeUnknown(anyhow::Error),
}

pub enum RemoveRouteOutcome {
    /// 成功从系统中删除了目标路由
    Removed,
    /// 系统中已经不存在目标路由（已达目标状态，正常销毁账目）
    AlreadyAbsent,
    /// 确定性的删除失败（如正在使用、系统错误），保留账目并按退避重试
    Failed(anyhow::Error),
    /// 结果不明，保留账目并报警阻塞，严禁盲目重试
    OutcomeUnknown(anyhow::Error),
}
```

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
3. **消除 Dump**：直接构造带 `RTA_DST`、`RTA_OIF`、`RTA_PRIORITY`、`rtm_table` 的单发 `RTM_DELROUTE` 报文下发，开销降为 $O(1)$，杜绝全表 dump。
4. **异步安全**：将阻塞底层网络 I/O 放入 `tokio::task::spawn_blocking` 中执行，不阻塞 Tokio 异步调度器线程；NetNS 绑定固定在专用执行环境中，绝不跨越 `await`。

### 3.4 Manager 结构与句柄接口

```rust
// easytier/src/instance/route/manager.rs
pub struct HostRouteManager {
    backend: RouteBackend,
    /// 当前活跃绑定的已安装路由记录 (spec -> InstalledRoute)
    installed_routes: std::collections::BTreeMap<RouteSpec, InstalledRoute>,
    /// 待清理的旧绑定及其专属后端和残留记录 (防止接口重建时丢失旧责任，旧记录绝不交给新后端)
    retired_bindings: Vec<(InterfaceBinding, Box<dyn NativeRouteBackend>, std::collections::BTreeMap<RouteSpec, InstalledRoute>)>,
    /// 失败重试退避追踪表 (限制事件风暴下的反复重试)
    retry_tracker: std::collections::BTreeMap<RouteSpec, RetryState>,
    /// 当前网卡绑定上下文
    current_binding: Option<InterfaceBinding>,
    /// 缓存的上一轮输入指纹与结果 (支持稳态零重算)
    last_eval_cache: Option<EvaluationCache>,
    /// 停机令牌
    cancel_token: tokio_util::sync::CancellationToken,
}

pub struct RouteManagerHandle {
    wake_notify: Arc<tokio::sync::Notify>,
    join_handle: tokio::task::JoinHandle<()>,
    cancel_token: tokio_util::sync::CancellationToken,
}

impl RouteManagerHandle {
    /// 接口创建/重建时更新绑定
    pub fn bind_interface(&self, binding: InterfaceBinding, backend: Box<dyn NativeRouteBackend>) { ... }
    /// 接口注销/失效时解绑
    pub fn unbind_interface(&self) { ... }
    /// 唤醒协调循环
    pub fn notify_change(&self) { ... }
    /// 显式停机并设定等待超时
    pub async fn stop(self, deadline: std::time::Instant) -> Result<(), CleanupIncomplete> { ... }
}
```

---

## 4. 输入接线与无冗余调度

### 4.1 输入接线映射表

Manager 绝不通过虚假消息总线通信，而是直接绑定各组件的权威只读入口：

| 来源分类 | 读取入口 (Read API) | 快照提交点 (Commit Point) | 通知方式 (Wakeup) |
| :--- | :--- | :--- | :--- |
| **Core Peer 路由** | `CorePacketPlane::list_proxy_cidrs()` (独立于旧 monitor 开关) | OSPF 路由表完成重算处 (`rebuild_route_table`) | 触发 `RouteManagerHandle::notify_change()` |
| **手工静态配置** | `CoreRuntimeConfigStore::snapshot().services.manual_routes` | 配置变更原子提交处 | 订阅 `subscribe_service_runtime_changes()` 并通知 |
| **Host 未迁移事实** | `UnmigratedRouteTracker::snapshot()` | DHCP lease 变更、TUN IP 变更、DNS 启停提交处 | 提交处同步更新并通知 Manager |

### 4.2 订阅与初态读取顺序

为杜绝启动初始化期间的事件丢失，严格执行**先订阅、后读初态**（`subscribe -> read_initial`）原则：
1. 先建立 `CoreRuntimeConfigStore` 订阅与路由变更监听。
2. 立即拉取各来源的初始快照，装配初态。
3. 启动协调循环。在订阅与初态读取之间到达的任何并发更新，均会通过已注册的通知机制准确唤醒。

### 4.3 稳态零多余计算与零堆分配

为了将稳态开销降至绝对最低，避免每次迭代重新执行 `collect()` 分配堆内存：
1. **输入快照与指纹比对（Fast-path Check）**：
   协调循环缓存上一轮的不可变快照指针（`Arc::ptr_eq`）或版本号：
   - `last_peer_cidrs: Arc<BTreeSet<Ipv4Cidr>>`（或版本计数）
   - `last_config: Arc<CoreInstanceRuntimeConfig>`
   - `last_unmigrated: UnmigratedRouteSnapshot`
   - `current_binding: Option<InterfaceBinding>`
2. **快速跳过机制**：
   协调循环被唤醒后，首先检查上述输入快照。若事实未变、无待处理失败重试且无待清理旧绑定，**直接跳过计算与拉取**。此时：
   - 0 堆内存分配（无 `collect`，无字符串复制，无树节点创建）。
   - 0 底层系统调用。
3. **输出容量复用**：
   当输入确实变化时，Host 侧策略函数复用排序 `Vec<RouteSpec>` 的预分配容量，避免重复申请堆内存。
4. **低频保底与独立重试**：
   废除原每 1 秒一次的忙碌轮询，将保底一致性检查降低至低频（30 秒）；失败重试由退避计时器在到达最早 `next_retry` 时精准唤醒。

---

## 5. 执行闭环设计与生命周期

### 5.1 协调循环核心算法

```text
       ┌────────────────────────────────────────────────────────┐
       │ 唤醒点: 通知 (notify) OR 退避重试定时器 OR 低频保底定时器 │
       └──────────────────────────┬─────────────────────────────┘
                                  ↓
       ┌────────────────────────────────────────────────────────┐
       │ 1. 检查取消令牌与当前网卡绑定 (无可用绑定则挂起执行)    │
       │ 2. 比对输入快照/指纹: 若未变化且无到期重试项，直接休眠  │
       │ 3. 执行纯策略计算: desired_routes                       │
       └──────────────────────────┬─────────────────────────────┘
                                  ↓
       ┌────────────────────────────────────────────────────────┐
       │ 计算待删除: to_remove = installed.keys - desired        │
       │ 计算待添加: to_add    = desired - installed.keys        │
       └──────────────────────────┬─────────────────────────────┘
                                  ↓
       ┌────────────────────────────────────────────────────────┐
       │ 逐项有界执行 (每步检查 cancel_token 与绑定有效性):      │
       │  a. 执行 to_remove: 成功/已不存在 -> 移除记录          │
       │  b. 执行 to_add:    成功创建     -> 插入 InstalledRoute│
       │                     遇到已存在   -> 不入账，记录警告   │
       │                     遇到失败     -> 启动指数退避       │
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
   当网卡失效或被替换时：
   - 当前网卡记录 `(current_binding, backend, installed_routes)` 整批移入 `retired_bindings`。
   - `current_binding` 更新为新网卡，其 `installed_routes` 初始化为空集合。
2. **旧责任清理闭环**：
   在后台或下一轮协调中，针对 `retired_bindings`：
   - 若宿主明确确认底层设备已被操作系统彻底物理销毁（内核已级联清空其路由），则旧责任安全注销并释放。
   - 若旧网卡仍在（如更名或逻辑重建），调用旧后端的 `remove_route` 进行精确清理；清理成功的项移出旧记录。
   - **绝不把旧接口记录挪用给新接口后端删除**，彻底消除代际混淆。

### 5.4 停机流程与超时保证 (`stop(deadline)`)

```rust
pub struct CleanupIncomplete {
    pub uncleaned_active: Vec<InstalledRoute>,
    pub uncleaned_retired: Vec<InstalledRoute>,
    pub reason: String,
}
```

停机调用 `handle.stop(deadline)` 时严格执行以下步骤：
1. **打断调度**：触发 `cancel_token.cancel()`，拒绝接收新唤醒。
2. **等待在途操作**：平稳等待当前正在执行的底层单项系统调用完成，并如实将结果计入账目（绝不使用粗暴的 task abort 留下脏状态）。
3. **限时精确清理**：
   - 遍历 `installed_routes` 与 `retired_bindings` 中的各项记录，依次调用对应后端的 `remove_route`。
   - 若系统时钟超过 `deadline`，立即终止循环。
4. **失败完全可见**：
   - 若全部记录清理完毕，返回 `Ok(())`。
   - 若超时或存在失败条目，**未清理条目保留在错误结构中返回**：`Err(CleanupIncomplete { .. })`，由宿主决定日志记录或上报。**坚决不返回虚假的 Ok**。宿主保留在途操作跟踪，不启动相竞争的新 writer。

---

## 6. 写入权交接与动态冲突防御

### 6.1 写入权平滑交接时序

在启动 HostRouteManager 时，旧链路与新 Manager 严格遵守以下交接时序：

```text
Host 启动 / 配置同步
   │
   ├─► 1. 禁用 ProxyCidrMonitor 的外部路由派发 (CoreEvent::ProxyCidrsUpdated 不派发系统写)
   ├─► 2. VirtualNic 跳过创建 run_proxy_cidrs_route_updater
   │      (确认代理路由旧 writer 完全停止)
   │
   ├─► 3. 若为旧实例热切换: 等待旧 writer 确认清空所有旧代理路由
   │      (干净实例启动则直接进入下一步)
   │
   └─► 4. 启动 HostRouteManager 协调循环，接管写入权
```

### 6.2 动态全量代理的重叠冲突防御与交接时序

在第二步中，Magic DNS（`fake_ip/32`）与 macOS/FreeBSD 接口前缀依然由旧代码写入。

**未迁移上下文动态追踪 (`UnmigratedRouteTracker`)**：
- 动态事实：`dns_enabled: bool`、`magic_dns_ip: Option<Ipv4Addr>`、`tun_cidr: Option<Ipv4Cidr>`。
- 冲突判定条件：仅当 DNS 启用且 `magic_dns_ip` **处于 TUN 子网网段之外**时，DNS 才实际需要添加主机路由 `/32`（若在子网内，接口直连路由已涵盖，无冲突）。

**生命周期交接顺序（预留冲突范围 $\to$ 等待原 writer 清理确认 $\to$ 启动接手 writer）**：
1. **场景 A：Manager 已安装代理路由 $P$，随后外部事实变化导致未迁移 DNS 也需要 $P$**：
   - **预留范围**：Host 更新 `UnmigratedRouteTracker`，将 $P$ 标记为待接手预留状态。
   - **触发清理**：Manager 协调循环被唤醒，策略函数将 $P$ 从 desired 中剔除，Manager 调用 `remove_route(P)`。
   - **确认后放行**：Manager 确认 $P$ 已成功删除或确认不存在（`Removed` / `AlreadyAbsent`），向 Tracker 发送删除确认。
   - **启动旧 Writer**：DNS 模块收到确认后，方可调用底层系统接口写入 $P$。
   - **失败防御**：若 Manager 删除 $P$ 失败，Tracker 绝不发放确认，DNS 模块中止写入并报错，绝不产生双写踩踏。
2. **场景 B：反向交接（未迁移 DNS 停止，将 $P$ 释放给 Manager）**：
   - DNS 模块退出并调用系统接口删除 $P$。
   - DNS 模块确认删除完成后，更新 `UnmigratedRouteTracker`，释放预留范围并唤醒 Manager。
   - Manager 策略函数解除对 $P$ 的抑制，将 $P$ 纳入 desired 并下发安装。
3. **场景 C：TUN 接口重建**：
   - 旧 TUN 必须先完成停止与 drain，确认旧接口销毁或由旧后端清理完路由后，才允许向新 TUN 下发新路由。

---

## 7. 性能开销分析与测量指标

为落实 master plan 对性能选择的明确要求，说明各项优化的实现机理与测量方法：

### 7.1 稳态零多余操作与零堆分配
- **机理说明**：
  现有 `cidr_monitor.rs:165–192` 虽然已对比 diff，但每 1 秒执行一次忙碌轮询，每次均通过 `list_proxy_cidrs()` 调用 `collect()` 构建新的 `BTreeSet`。
  新 Manager 通过输入版本与快照指针（`Arc::ptr_eq`）在循环入口快速拦截，稳态下完全不拉取路由表、不创建集合、不执行 diff 比对。
- **测量方法**：
  - 测试手段：MockBackend 统计底层调用计数，结合内存分配跟踪器（如全局 allocator 探针）。
  - 验收基准：在 60 秒稳态运行期间，底层路由调用次数严格为 0；协调循环迭代的堆分配次数为 0。

### 7.2 平台连接复用
- **机理说明**：
  现有实现针对每个路由操作临时建立 Netlink socket。新方案在 Linux 原生后端的单次网卡绑定生命周期内持久持有单个 Netlink socket 实例，跨迭代持续复用。
- **测量方法**：
  - 测试手段：使用 `strace -c -e socket,bind,close` 追踪单次网卡生命周期内的路由操作系统调用。
  - 验收基准：在持续增删 100 次路由场景下，Netlink 相关套接字的创建次数严格等于后端单次绑定的 1 次（允许在网卡重绑或致命连接恢复时重新建连）。

### 7.3 消除逐条 Dump
- **机理说明**：
  现有 Linux `remove_ipv4_route` 每次删除均全量调用 `list_routes`（$O(N \times M)$ dump）。新方案改为直接填入网卡、目标、priority 与 table 参数发送单发 `RTM_DELROUTE` 报文（$O(1)$）。
- **测量方法**：
  - 测试手段：编写批量删除 100 条路由的基准测试，统计 Netlink 交互报文类型。
  - 验收基准：删除 100 条路由时，Netlink 请求消息严格为 100 个 `RTM_DELROUTE`，`RTM_GETROUTE` dump 消息数严格为 0。对比记录旧实现与新实现的实际总耗时。

---

## 8. 分批实施顺序与验证矩阵

分批实施划分为 5 个独立可编译、可测试的批次：

```text
Batch 1: 纯计算与轻量模型 (Core 纯算法 + Host 策略与 RouteSpec 安全构造)
   ↓
Batch 2: 精确删除改造与平台后端 (Netlink 消除 dump、长连接、Mock 后端)
   ↓
Batch 3: HostRouteManager 核心闭环 (退避重试、多代际记录、中途失效检查、stop)
   ↓
Batch 4: Host 真实生命周期接线与交接 (runtime_host 挂载、DHCP 绑定、旧 updater 屏蔽)
   ↓
Batch 5: 隔离环境原生测试与基准度量 (netns 真实系统调用、零 dump、零写度量)
```

### 8.1 分批实施详细任务

#### Batch 1：纯计算与轻量模型
- **代码落点**：
  - `easytier-core/src/peers/route/projection.rs`：纯函数 `normalize_v4_cidr`（基于 `Ipv4Inet::network()`）。
  - `easytier-core/src/gateway/proxy/cidr_monitor.rs`：保留 `resolve_proxy_cidrs`。
  - `easytier/src/instance/route/model.rs`：`RouteSpec`、`InstalledRoute`、`InterfaceBinding` 及结果枚举。
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
  - `easytier/src/instance/route/manager.rs`：实现 `HostRouteManager` 协调循环、输入快照比对、失败指数退避、中途失效检查、多代际记录跟踪与 `stop(deadline)`。
- **验证**：
  - 基于 `MockRouteBackend` 的闭环测试：
    - 首启全量添加；
    - 输入未变稳态 0 调用与 0 堆分配；
    - 单项失败指数退避与重试（风暴下不频繁重发）；
    - 接口重建多代际分离与清理；
    - `stop(deadline)` 成功清理与超时/失败返回 `CleanupIncomplete` 错误测试；
    - No-TUN 旁路测试（执行分支跳过，已安装记录保持为空）。

#### Batch 4：Host 真实生命周期接线与交接
- **代码落点**：
  - `easytier/src/instance/runtime_host.rs` & `tun_desktop.rs` / `tun_common.rs` / `implementation.rs`：接入 `RouteManagerHandle`，在网卡就绪时（包括 DHCP 延迟建卡与静态卡）调用 `bind_interface`，在关闭时调用 `stop(deadline)`。
  - `easytier/src/instance/virtual_nic.rs`：停用 `run_proxy_cidrs_route_updater`。
- **验证**：
  - 集成测试：启动集成测试节点，动态推送 `manual_routes`，验证真实 Manager 接管生效且旧 updater 不重复写入；
  - 交接时序测试：
    1. Manager 已装 $P$ $\to$ DNS 需要 $P$ $\to$ DNS 等待 Manager 删除确认 $\to$ Manager 删除成功后 DNS 写入；
    2. 反向交接：DNS 停用并删除 $P$ $\to$ Manager 接手安装 $P$；
    3. 故障注入：Manager 删除 $P$ 注入失败 $\to$ 验证 DNS 模块未被提前放行，杜绝双写。

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
- [ ] **依赖方向合规**：`easytier-core` 绝无引用 `easytier` 类型，所有构建目标独立可编译。
- [ ] **精确删除与身份完整**：已安装记录保存实际创建参数与接口代际；同接口同前缀下不同 metric 的外部路由不被误删。
- [ ] **稳态零多余操作**：在网络拓扑与配置稳定的状态下，输入快照拦截生效，协调循环不产生多余的底层系统调用和堆内存分配。
- [ ] **无全表 Dump**：Linux 下删除路由直接构造 `RTM_DELROUTE`，基准测试验证 0 次 `RTM_GETROUTE` dump。
- [ ] **失败退避与结果明确**：添加/删除失败如实记账并不误报成功；失败项执行指数退避，不被无关事件风暴频繁重发。
- [ ] **停机失败完全可见**：`stop(deadline)` 限时清理；删除失败或超时保留未清理记录并向调用方返回 `CleanupIncomplete` 错误，绝不虚报成功。
- [ ] **重叠交接安全**：自动或手工代理与未迁移 DNS `/32` 或接口前缀重叠时，通过动态交接防御机制排除冲突条目，阶段一不存在同一实际条目的新旧双写；删除失败时不提前放行后续 writer。
- [ ] **接口重建代际清晰**：网卡失效后旧记录与新记录分别由各自代际与专属后端跟踪，旧责任在底层物理销毁或删除确认后注销，新接口正常重新下发。
- [ ] **旧写入权顺利交接**：代理路由的旧 updater 任务已被停写，全仓代理路由仅由单一 `HostRouteManager` 负责；未迁移项（IPv6 地址维护等）照常运行。
