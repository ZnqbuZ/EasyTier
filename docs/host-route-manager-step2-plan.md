# HostRouteManager 第二步实施方案：最小 Manager 闭环

状态：规划中（遵循最新实施总纲 [`docs/host-route-manager-master-plan.md`](host-route-manager-master-plan.md) 与第一步规范 [`docs/host-route-manager-step1-audit-and-contract.md`](host-route-manager-step1-audit-and-contract.md)）。  
基线代码：`refactor/route` 分支；参考分支：`refactor/route-dev` (`8abfb51e`)。

---

## 1. 目标与范围

本阶段的核心目标是**交付一个可工作的最小 HostRouteManager 闭环**：
1. **范围聚焦**：率先接管 **IPv4 自动子网代理路由（Peer Proxy CIDR）** 与 **手工静态代理路由（`manual_routes`）**。
2. **直连事实与闭环操作**：直接从 Core 路由表与配置拉取事实，使用纯函数计算最终期望集合，通过薄后端接口应用变更，在内存中维护已成功安装条目的精确记录（`installed_routes`），支持下一轮重试与显式停止清理。
3. **平滑交接与防双写**：停用旧 `ProxyCidrMonitor` 与 `VirtualNic::run_proxy_cidrs_route_updater` 的系统写权限；尚未迁移的 Public IPv6、Magic DNS 及接口前缀在第二步暂不接入，但在阶段一必须对重叠路由进行动态冲突防御，杜绝新旧双写。
4. **性能与精简约束**：彻底不恢复旧版版本化需求框架（无 Registry / Token / Epoch / 生产影子框架）；遵循稳态零多余系统调用、快照复用、连接复用及消除逐条 dump 等明确性能指标。

---

## 2. 代码落点与复用清单

### 2.1 源码落点总览

```text
easytier-core/
  └── src/peers/route/
        └── projection.rs             [复用/精简] 纯计算函数: normalize_cidr, resolve_proxy_cidrs, 冲突检测
easytier/
  └── src/
        ├── common/ifcfg/
        │     ├── mod.rs              [修改] IfConfiguerTrait 增加按精准参数定位的 remove_route 接口
        │     └── netlink.rs          [修改] 消除遍历 dump，按 table/priority/oif/前缀直接构造 RTM_DELROUTE
        └── instance/
              ├── route/
              │     ├── mod.rs        [新增] 模块声明与导出
              │     ├── model.rs      [新增/移植] RouteSpec (目标网段 + metric)
              │     ├── backend.rs    [新增] NativeRouteBackend / DelegatedRouteBackend / NoTun 抽象
              │     └── manager.rs    [新增/移植] HostRouteManager 协调循环、安装记账、重试与停止
              └── runtime_host/
                    └── implementation.rs [修改] 组装并启动 HostRouteManager，停用旧 updater
```

### 2.2 详细文件增删改映射

| 文件位置 | 变更性质 | 具体入口与内容说明 |
| :--- | :--- | :--- |
| `easytier/src/instance/route/model.rs` | **新增** | 定义 `RouteSpec { destination: IpCidr, metric: Option<i32> }`，提供有序、可哈希、规范化比较能力。移植自 `route-dev` 并精简化。 |
| `easytier/src/instance/route/backend.rs` | **新增** | 定义双分支后端：`NativeRouteBackend`（持有 `IfConfiger`，支持精确增删）、`DelegatedRouteBackend`（移动端整批 `apply_routes` 与 `reset_session`）、`RouteBackend::NoTun`（明确旁路）。 |
| `easytier/src/instance/route/manager.rs` | **新增** | 实现 `HostRouteManager`：持有业务读取句柄、后端接口、内存 `installed_routes: BTreeSet<RouteSpec>`、Tokio 协调循环、失败重试、接口重建与 `stop()`。 |
| `easytier-core/src/peers/route/projection.rs` | **复用/新增** | 复用此前已验证的 `normalize_cidr` 与 `resolve_proxy_cidrs`；新增 `filter_colliding_proxy_routes` 纯函数用于检测和排除与未迁移 DNS/前缀冲突的代理网段。 |
| `easytier/src/common/ifcfg/mod.rs` | **修改** | 在 `IfConfiguerTrait` 中扩展精确删除支持：`remove_ipv4_route_exact(&self, name: &str, dest: Ipv4Addr, prefix: u8, cost: Option<i32>, table: Option<u32>)`。 |
| `easytier/src/common/ifcfg/netlink.rs` | **修改** | 改造 `remove_ipv4_route`：**坚决废除每删一条路由全量 list_routes dump 的低效做法**，直接根据传入的 `oif`、`destination`、`cidr_prefix`、`priority(cost)`、`table` 构造 `RTM_DELROUTE` 请求并下发。 |
| `easytier/src/instance/virtual_nic.rs` | **修改** | 改造 `run_proxy_cidrs_route_updater`：当由 `HostRouteManager` 接管时，该任务不再向系统下发路由增删（或直接跳过创建）。 |
| `easytier/src/instance/runtime_host/` | **修改** | 在 `NativeInstanceRuntimeHost` 中实例化 `HostRouteManager`，于 `prepare_runtime` 传入 TUN 接口与 Core 路由句柄并启动，在 `shutdown_runtime` 异步调用 `stop()`。 |
| 旧 Step 2 框架代码 | **清理** | 确认废除 `easytier-core/src/route_demand/` 下的 `registry.rs`、`token.rs`、`subscription.rs` 及 `easytier/src/instance/route_shadow.rs`。 |

### 2.3 `refactor/route-dev` 移植决策

经核对 `refactor/route-dev` (`8abfb51e`) 分支中 `easytier/src/nic/route/manager.rs`：
- **值得移植并保留**：
  1. `RouteSpec { destination: IpCidr, metric: Option<i32> }`：结构极其精炼，直接表达路由条目的核心身份。
  2. 小型 Manager 骨架与单循环顺序处理模式：结构清晰，易于单线程串行化推理。
- **坚决舍弃与修改**：
  1. **舍弃 `nic.nic_ctx.downcast_ref::<Nic>()`**：该实现通过 `Any` 运行时向下转型强行窃取控制器，脆弱且侵入 NIC 内部结构。改为在构造 `HostRouteManager` 时显式注入薄抽象 `RouteBackend`。
  2. **重写空的 `async fn sync(&self) {}`**：`route-dev` 的同步函数为空。将其填充为实际的期望集合拉取、差集计算、精确增删、记账与重试闭环。
  3. **舍弃 `RouteCommand::SyncSource` 通道机制**：`route-dev` 为每个来源设置消息通道与代际，容易导致局部乱序。改为基于拉取的一致性检查与轻量唤醒通知。

---

## 3. 结构与接口定义

### 3.1 核心数据结构与必要字段

```rust
// easytier/src/instance/route/model.rs
use cidr::IpCidr;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct RouteSpec {
    pub destination: IpCidr,
    pub metric: Option<i32>,
}

impl RouteSpec {
    pub fn new_v4(addr: std::net::Ipv4Addr, prefix: u8, metric: Option<i32>) -> Self {
        // 自动执行 CIDR 主机位清除
        let cidr = cidr::Ipv4Cidr::new(addr, prefix)
            .map(|c| c.first_address())
            .map(|norm| cidr::Ipv4Cidr::new(norm, prefix).unwrap())
            .unwrap_or_else(|_| cidr::Ipv4Cidr::new(addr, prefix).unwrap());
        Self {
            destination: IpCidr::V4(cidr),
            metric,
        }
    }
}
```

```rust
// easytier/src/instance/route/manager.rs
pub struct HostRouteManager {
    /// 平台操作后端
    backend: RouteBackend,
    /// 内存中记录的本次运行已明确安装成功、且尚未删除的路由集合
    installed_routes: BTreeSet<RouteSpec>,
    /// Core OSPF 路由读取接口
    core_route: Arc<dyn Route>,
    /// 运行时配置存储句柄
    runtime_config: Arc<RuntimeConfigStore>,
    /// 未迁移来源查询句柄 (用于重叠冲突防御: DNS fake IP, 接口前缀等)
    unmigrated_context: UnmigratedRouteContext,
    /// 当前 TUN 网卡标识 (代际保护)
    tun_binding: Option<InterfaceBinding>,
    /// 协调循环唤醒信号发送端
    wake_tx: tokio::sync::mpsc::Sender<()>,
    /// 停机取消令牌
    cancel_token: tokio_util::sync::CancellationToken,
}

pub struct UnmigratedRouteContext {
    pub fake_ip: Option<std::net::Ipv4Addr>,
    pub tun_prefix: Option<cidr::Ipv4Cidr>,
}

pub struct InterfaceBinding {
    pub ifname: String,
    pub ifindex: u32,
    pub generation: u64,
}
```

### 3.2 后端接口抽象 (`RouteBackend`)

```rust
// easytier/src/instance/route/backend.rs
#[async_trait::async_trait]
pub trait NativeRouteBackend: Send + Sync + 'static {
    /// 向底层系统路由表添加一条路由
    async fn add_route(&self, route: &RouteSpec) -> Result<(), Error>;
    /// 按各平台精确参数从系统路由表删除一条路由 (无法唯一定位时返回错误)
    async fn remove_route(&self, route: &RouteSpec) -> Result<(), Error>;
}

#[async_trait::async_trait]
pub trait DelegatedRouteBackend: Send + Sync + 'static {
    /// 移动端全量下发完整期望路由集合
    async fn apply_routes(&self, routes: &BTreeSet<RouteSpec>) -> Result<(), Error>;
    /// 重置/清理移动端 VPN 会话
    async fn reset_session(&self) -> Result<(), Error>;
}

pub enum RouteBackend {
    Native(Box<dyn NativeRouteBackend>),
    Delegated(Box<dyn DelegatedRouteBackend>),
    NoTun, // 明确的 No-TUN 旁路，不执行操作且不记安装
}
```

### 3.3 业务规则纯函数

所有业务判定与计算均采用普通无副作用函数，置于 `easytier-core/src/peers/route/projection.rs`：

```rust
/// 计算最终期望的代理路由集合，并排除与未迁移项冲突的网段
pub fn calculate_desired_proxy_routes(
    peer_proxy_cidrs: &BTreeSet<Ipv4Cidr>,
    manual_routes: &Option<BTreeSet<Ipv4Cidr>>,
    unmigrated: &UnmigratedRouteContext,
) -> BTreeSet<RouteSpec> {
    // 1. 纯覆盖解析: None -> peer 广播; Some([]) -> 空集; Some([..]) -> 静态覆盖
    let resolved_cidrs = resolve_proxy_cidrs(manual_routes, peer_proxy_cidrs);

    // 2. 规范化并包装为 RouteSpec (代理路由默认 metric 为 None)
    let mut desired = BTreeSet::new();
    for cidr in resolved_cidrs {
        let norm_cidr = normalize_v4_cidr(cidr);
        
        // 3. 阶段一动态重叠冲突防御: 若与 DNS fake_ip/32 或未迁移接口前缀相同，直接排除
        if is_colliding_with_unmigrated(&norm_cidr, unmigrated) {
            tracing::warn!(?norm_cidr, "proxy CIDR collides with unmigrated source; suppressing in Manager");
            continue;
        }

        desired.insert(RouteSpec {
            destination: IpCidr::V4(norm_cidr),
            metric: None,
        });
    }

    desired
}
```

---

## 4. 执行闭环设计

### 4.1 协调循环核心状态机

`HostRouteManager` 内部运行一个单一的 Tokio 异步循环，由**事件通知**与**保底定时定时器（1 秒）**共同驱动：

```text
       ┌────────────────────────────────────────────────────────┐
       │ 等待事件: 业务唤醒信号 (wake_rx) OR 1s 保底定时器超时   │
       └──────────────────────────┬─────────────────────────────┘
                                  ↓
       ┌────────────────────────────────────────────────────────┐
       │ 1. 检查网卡绑定有效性 (无接口则跳过本轮执行并保留记录)  │
       │ 2. 拉取业务事实: OSPF proxy_cidrs + manual_routes     │
       │ 3. 纯函数计算: desired_routes                          │
       └──────────────────────────┬─────────────────────────────┘
                                  ↓
              ┌───────────────────┴───────────────────┐
              │ 分支 A: Native 后端                   │ 分支 B: Delegated 后端
              ↓                                       ↓
   to_remove = installed - desired         若 desired != applied:
   to_add    = desired - installed           调用 apply_routes(desired)
   执行 remove (成功一项从 installed 减一项) 成功则 applied = desired
   执行 add    (成功一项向 installed 加一项) 失败则保持不变，下轮重试
              └───────────────────┬───────────────────┘
                                  ↓
                        进入下一轮循环等待
```

### 4.2 各种生命周期与异常情况处理细则

1. **首次启动**：
   - `installed_routes` 初始为空集合。
   - 首次执行计算得出 `desired_routes`，`to_add = desired_routes`，依次调用后端的 `add_route`。
   - 只有底层返回成功（`Ok`）的条目才存入 `installed_routes`。若遇 `AlreadyExists`，按第 1 步规范**坚决不认领**，不加入记录。
2. **事件合并与防抖**：
   - 采用容量为 1 的 Tokio `mpsc::channel`（或 `watch` 信号）。当网络拓扑突发变化涌入多个 OSPF 事件时，通道自然合并通知。
   - 唤醒后直接拉取 Core 的最新快照，彻底规避传统基于固定 sleep 引入的延迟累积。
3. **操作失败与保底重试**：
   - **添加失败**：条目不进入 `installed_routes`。在下一轮循环中，由于该条目仍属于 `desired` 且不属于 `installed`，自然再次出现在 `to_add` 中被重试。
   - **删除失败**：条目保留在 `installed_routes`。在下一轮循环中，该条目依然属于 `installed` 且不属于 `desired`，自然再次出现在 `to_remove` 中被重试。
   - **输入读取失败**：若因 Core 繁忙或临时锁竞争导致读取失败，跳过本轮增删，**绝对不把读取失败当成需求为空**。
4. **操作期间输入变化**：
   - 单轮协调工作于一个不可变的局部快照。若在下发第 3 条路由时输入事实又发生了改变，后续事件将挂起唤醒信号，当前轮次执行完毕后立即触发下一轮，重新计算新的差异集，天然收敛。
5. **接口重建（TUN 崩溃 / 重连 / 重新获取 fd）**：
   - 收到接口失效/更名事件时：
     - 若旧接口已确认销毁，操作系统已收回其上的路由，此时**注销旧代际记录**。
     - 获取新接口句柄（生成新代际 `generation + 1`），以全新的上下文开始管理。
     - 立即触发协调：所有 `desired_routes` 将被重新安全下发到新接口上，绝无跨接口代际混淆。
6. **显式停机清理 (`stop`)**：
   - 触发 `cancel_token.cancel()`，中断后台循环的进一步调度。
   - **等待在途操作平稳完成**并如实入账，绝不强行 abort 造成未明系统副作用。
   - 遍历 `installed_routes` 中的条目，依次调用 `remove_route`：
     - 删除成功一项，从 `installed_routes` 移除一项；
     - 若全部成功，返回 `Ok(())`；
     - **若存在删除失败的项**，失败项留在 `installed_routes` 中，`stop()` 向上返回 `Err(CleanupIncomplete { remaining: installed_routes })`，并在日志中明确打印未清理的条目，绝不假报清理干净。

---

## 5. 写入权交接与防双写机制

### 5.1 旧 Writer 停写步骤

在第二步实施中，严格执行“先停旧链路写，再启新 Manager 写”的顺序：

1. **ProxyCidrMonitor 改造**：
   - 在 Core 中，`ProxyCidrMonitor` 原有轮询循环中向 `GlobalCtxEvent::ProxyCidrsUpdated` 派发事件的代码被禁用，或切断其对系统路由的控制意图。
2. **VirtualNic 路由 Updater 停写**：
   - `VirtualNic::run_proxy_cidrs_route_updater` 负责监听代理路由并调用 `IfConfiger`。在启动 HostRouteManager 时，**不创建该任务**（通过配置开关或条件编译分支屏蔽），彻底阻断旧链路对系统路由的写入。
3. **保留未迁移链路正常运行**：
   - `VirtualNic::run_public_ipv6_route_updater`（对端 Public IPv6 路由）保持原样运行；
   - `VirtualNic::run_public_ipv6_addr_updater`（IPv6 地址维护与默认路由）保持原样运行；
   - `MagicDnsServerInstance` 中的 `/32` 写入保持原样运行。

### 5.2 旧条目清理与交接策略

- **干净实例启动（首选标准）**：
  - 测试与部署默认采用干净启动。新实例启动前宿主路由表无残留，Manager 从空的 `installed_routes` 起步。
- **热切换交接防御**：
  - 若在已有旧实例的节点上启用 HostRouteManager，**必须由旧 updater 先行执行反向清空**（或实例重启），确认旧条目全部移除后，新 Manager 方可开始接管。
  - **严禁认领机制**：若系统路由表中恰好存在相同前缀的外部条目，Manager 在调用 `add_route` 遇到 `AlreadyExists` 时，坚决不将其补记为 `installed_routes`，退出时绝不执行误删。

### 5.3 动态代理与未迁移 DNS / 前缀的防双写

在第一阶段，Magic DNS 的 `fake_ip/32` 和 macOS/FreeBSD 接口前缀仍由旧代码写入。动态代理路由可能会在运行时通告与之完全相同的网段。

**双写防御规则实现**：
1. **全量代理输入实时核对**：
   - 无论来源于静态 `manual_routes` 还是动态 OSPF peer 广播，计算所得的每个 `IpCidr` 都要经过 `is_colliding_with_unmigrated` 检查。
2. **冲突判定标准**：
   - 仅当目标网段与当前已分配的 `fake_ip` 形成的 `/32` 完全相等，或者与当前 TUN 虚拟子网网段完全相等时，判定为碰撞冲突（不把合法的子网包含关系视为冲突）。
3. **冲突处置行为**：
   - 检测到冲突时，Manager **主动抑制该条代理路由的安装**，并在日志输出警告，将该条目的写权限留给旧模块，绝不下发。
   - 保证在任何时刻，同一条具体的系统路由在内核中只有一个合法的写入者。

---

## 6. 性能开销分析与测量指标

为满足总纲对性能选择可解释、可测量的硬性要求，针对四项关键性能设计阐明开销削减机理与测量方法：

### 6.1 稳定状态零多余写入 (Zero Redundant Writes in Steady State)

- **削减开销原理**：
  在网络稳定状态下（路由条目未变化），传统的轮询方案往往每次循环都重新构造系统调用或进行繁琐的底层比对。Manager 维护 `installed_routes` 与纯函数产出的 `desired_routes`：
  ```rust
  if self.installed_routes == desired_routes {
      // 快速路径：集合完全相等，0 系统调用，0 内存重分配
      return Ok(());
  }
  ```
  在稳态下，单次迭代开销仅为一次极低开销的内存集合比对，完全杜绝 Netlink 套接字发送或 Win32/CLI 命令调用。
- **测量方法**：
  - **测试手段**：使用装配有计数器的 MockBackend 或 eBPF (`sys_enter_sendmsg` 追踪 Netlink / `tracepoint` 追踪系统调用)。
  - **验收基准**：在组网节点稳定运行 60 秒内，Manager 产生的底层路由系统调用次数**严格为 0**。

### 6.2 快照复用与零深拷贝 (Snapshot & Allocation Reuse)

- **削减开销原理**：
  Core 侧路由表和配置以不可变对象（`Arc`）或借用切片的形式暴露（如 `Route::list_proxy_cidrs()` 产出复用的 `BTreeSet` 或借用迭代器）。计算函数 `calculate_desired_proxy_routes` 接收引用传参，仅在产生实际差异时才构建必要的新增结构，避免每秒轮询复制数百个 CIDR 字符串或重型对象。
- **测量方法**：
  - **测试手段**：使用 `dhat` 或内存分配追踪测试用例，统计在 100 次稳态协调迭代中的堆内存分配总次数（Allocations count）。
  - **验收基准**：稳态下的堆内存分配次数稳定在近乎零增长（仅限 Tokio 计时器事件唤醒自身的轻量封装）。

### 6.3 平台连接复用 (Connection Reuse)

- **削减开销原理**：
  在 Linux 原生平台上，创建 Netlink 套接字（`socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)`）及绑定 netns 属于高开销系统操作。HostRouteManager 的 `NativeRouteBackend` 长期持有一个初始化的 Netlink 套接字实例，跨循环迭代持续复用，杜绝“增删一条路由就建连断开一次”的传统做法。
- **测量方法**：
  - **测试手段**：通过 `strace -c -e socket,bind,close` 观察进程运行期间的网络协议套接字生命周期。
  - **验收基准**：无论路由发生多少次增删变化，Netlink 套接字的创建与绑定调用次数恒定为实例初始化时的单次调用（1 次）。

### 6.4 消除逐条 Dump (Eliminate Per-Route Dump)

- **削减开销原理**：
  **彻底消除历史缺陷**：原 Linux `NetlinkIfConfiger::remove_ipv4_route` 每次删除一条路由，都必须先调用 `list_routes` 进行一次全内核路由表的 `RTM_GETROUTE` dump。若需删除 50 条路由，系统将执行 50 次全表 dump，产生 $O(N \times M)$（$N$ 为删除条数，$M$ 为系统全局路由总数）的巨大 CPU 与 Netlink 流量开销！
  在本次重构中，删除操作改为**直接精确构造 `RTM_DELROUTE` 请求**（填入目标网段、`oif`、`priority` 与 `table`）单发给内核，彻底消除删除前的全量遍历。开销直接降为 $O(1)$。
- **测量方法**：
  - **测试手段**：编写针对 100 条路由批量清理的微基准测试（Benchmark），统计总耗时与 Netlink 交互报文总量。
  - **验收基准**：清理 100 条路由时，Netlink 请求报文数严格等于 100 个 `RTM_DELROUTE`，`RTM_GETROUTE` dump 报文数严格为 0；批量耗时相比原实现下降 90% 以上。

---

## 7. 分批实施顺序与验证矩阵

实施拆分为 5 个保持独立可构建、可测试的代码提交批次：

```text
Batch 1: 纯计算与轻量模型 (Pure Calculation & RouteSpec)
   ↓
Batch 2: 精确删除改造与薄后端 (Exact Deletion & Thin Backend)
   ↓
Batch 3: HostRouteManager 核心闭环 (Manager Core Closed Loop)
   ↓
Batch 4: 实例装配与旧链路交接 (Assembly & Writer Handover)
   ↓
Batch 5: 矩阵验证与基准度量 (Verification & Benchmarking)
```

### 7.1 分批实施详细任务

#### Batch 1：纯计算与轻量模型 (`route/model.rs` & `projection.rs`)
- **任务**：
  1. 定义 `RouteSpec` 结构及其排序、判等与 CIDR 规范化构造方法；
  2. 整合 `projection.rs`，实现 `calculate_desired_proxy_routes` 纯函数；
  3. 实现未迁移来源冲突检测 `is_colliding_with_unmigrated`。
- **验证**：
  - 编写单元测试：CIDR 主机位规范化、`manual_routes` 三态覆盖、与未迁移 DNS `/32` 碰撞排除、IPv4 代理路由计算。

#### Batch 2：精确删除改造与薄后端 (`common/ifcfg/` & `route/backend.rs`)
- **任务**：
  1. 改造 Linux `NetlinkIfConfiger::remove_ipv4_route`：直接构造 `RTM_DELROUTE`，精准匹配 `oif`、`destination`、`priority` 与 `table`，消除全量 dump；
  2. 定义 `NativeRouteBackend`、`DelegatedRouteBackend` 与 `RouteBackend` 枚举；
  3. 实现基于内存的 `MockRouteBackend` 用于测试环境无 root 验证。
- **验证**：
  - 单元测试：同接口、同前缀但不同 metric 的精确删除测试，验证不误删外部条目；Mock 后端操作记录测试。

#### Batch 3：HostRouteManager 核心闭环 (`route/manager.rs`)
- **任务**：
  1. 实现 `HostRouteManager` 核心结构及 Tokio 异步循环；
  2. 实现差异集比对、执行与 `installed_routes` 增删记账；
  3. 实现失败重试、输入变化合并、接口重建生命周期处理；
  4. 实现 `stop()` 流程与失败可见性（返回 `CleanupIncomplete`）。
- **验证**：
  - 基于 `MockRouteBackend` 的全套闭环测试：首启全量安装、无变更稳态跳过、增删失败重试、接口重建代际自愈、正常清理与失败可见性测试、No-TUN 旁路测试。

#### Batch 4：实例装配与旧链路交接 (`runtime_host/` & `virtual_nic.rs`)
- **任务**：
  1. 在 `NativeInstanceRuntimeHost` 中装配 `HostRouteManager`；
  2. 改造 `VirtualNic`，在启用新 Manager 时停写 `run_proxy_cidrs_route_updater`；
  3. 传递真实 TUN 控制器与 Core 路由句柄，完成全链路贯通。
- **验证**：
  - 集成测试：启动完整 `CoreInstance` 与 `TestHost`，动态更新 `manual_routes`，验证真实 Manager 正确接收并下发。

#### Batch 5：矩阵验证与基准度量
- **任务**：
  1. 运行平台兼容性测试矩阵（Linux 原生后端、No-TUN 模式、模拟 Android 委托后端）；
  2. 运行性能测试与系统调用基准度量。
- **验证**：
  - 稳态 60 秒零系统调用验证；
  - 批量删除 100 条路由零 dump 验证。

---

## 8. 进入第三步的验收门槛

在宣布第二步完成并进入第三步前，必须逐项核对满足以下门槛：

- [ ] **计算正确**：自动代理跟随、手工静态覆盖、显式空集禁用均通过测试；CIDR 主机位正确规范化。
- [ ] **稳态零多余写**：在无网络拓扑或配置变动的稳态下，协调循环不产生任何底层增删系统调用。
- [ ] **无全表 Dump**：Linux 下删除路由不再触发全量 Netlink 路由遍历，直接按精确参数下发删除。
- [ ] **失败不记成功**：底层增删失败绝不记入 `installed_routes`，下一轮自动重试；读取失败不被当成空需求。
- [ ] **不误删与精确匹配**：同接口同前缀下不同 metric 的外部路由在删除测试中不受影响；预存外部条目不认领。
- [ ] **停机失败完全可见**：`stop()` 流程按计划等待并清理；删除失败保留在内存并在返回值中报错，不虚报成功。
- [ ] **重叠防御无双写**：动态与静态代理网段若与未迁移 DNS `/32` 或接口前缀重叠，已被 Manager 明确排除，阶段一不存在同一实际条目的新旧双写。
- [ ] **No-TUN 纯净旁路**：在 No-TUN 模式下，业务正常计算但完全跳过执行分支，`installed_routes` 严格为空。
- [ ] **旧写入权顺利交接**：代理路由的旧 updater 任务已被停写，全仓代理路由仅由单一 `HostRouteManager` 负责。
