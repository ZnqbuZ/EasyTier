# HostRouteManager 第二步实施方案：整体架构收缩与闭环（单事实驱动）

状态：已按 [Review 14](host-route-manager-step2-review-14.md) 收缩架构，并落实 [Review 15](host-route-manager-step2-review-15.md) 的接口事实、接管范围、DNS、观察缓存及循环修正。本文为实施方案，尚未代表代码或运行验证完成。

实施核心：**单刷新 Watch + 单协调入口 + 单任务结果 + 全路由合并计算**。不建立任何通知汇聚框架或清理监督框架，摒弃结果锁与队列。

---

## 一、 职责与输入事实

**核心架构**：

```text
Peer / 配置 / Host 接口状态 / DNS 状态
    ├─ 各自保存权威事实快照，Manager 通过自身入口读取
    └─ 提交事实后，触发同一个 watch<()> 唤醒
                            ↓
一个 Manager 任务：读取事实 → 计算差异 → 增删 → 记账
                            ↓
编译期选定的平台后端：独立操作路由，不持有网卡资源

Host：独占网卡生命周期；持有 Manager 任务与 Cancel 令牌，限时等待清理结果
```

**事实接线点**（统一通过克隆的 `watch::Sender<()>` 在更新后 `send_replace(())`）：

1. **Core 路由**：`PeerRouteServiceImpl` 提交代理子网 `Arc<BTreeSet<Ipv4Cidr>>` 快照后通知。
2. **手工路由配置**：`CoreRuntimeConfigStore` 变更提交后通知。
3. **接口事实**：Host 提供当前存在的设备实例、接口定位信息、虚拟地址及就绪状态，变更后通知。存在与就绪分开表达；地址与所属设备一起提交，不能拼接不同设备的地址状态。
4. **DNS 事实**：Host 的 DNS 启停状态提供可选的 `fake_ip` 需求及所属设备实例；Manager 从匹配的接口事实读取 `tun_inet`。完成通知与撤回时序见第五节。

每个实例只有一个刷新 watch；Core 只接收标准 `watch::Sender<()>`，不引用 Host 路由类型。不为已有订阅新增转发任务，不建通知注册中心。`RouteInputs` 只装配固定业务读取入口；读取失败、尚未就绪和明确空结果分别处理，复用已有快照存储。

**本阶段接管边界**：仅在 `all(target_os = "linux", feature = "linux-netlink")` 且实际启用原生 Manager 的装配中，一起接管 IPv4 自动代理、手工代理及 Magic DNS 路由。同一个接管判定停用 `NicCtx::run_proxy_cidrs_route_updater` 和 DNS 原路由增删。其他平台/构建保留原路径；No-TUN 不写原生路由、不产生安装记录。不因模型支持 `IpCidr` 就启用 IPv6 代理。优先干净实例启动，不自动认领旧 writer 遗留条目。

业务规则沿用 [step1 第 3 节](host-route-manager-step1-audit-and-contract.md)：CIDR 规范化、manual 三态覆盖及默认 metric 解析继续有效。迁移顺序调整为 Linux DNS 路由与代理一起接管，替代 step1 中 DNS 留到第三步的安排。

---

## 二、 核心数据模型与最小模块

主体为 `manager.rs`（协调）、`backend.rs`（后端），计算需要独立测试时放 `policy.rs`；短模型放 `mod.rs`，平台实现按需单列。下面是字段职责示意，不要求为了对齐文档新增包装层。

```rust
// 本阶段 Linux 的解析结果；未来平台使用其自身的接口定位值。
// ifname 只留在 Host 的展示/解析信息中，不参与路由等价比较。
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct DeviceId {
    pub ifindex: u32,
    pub host_instance: Option<u64>, // Host 自建设备的实例标识；外部接口为 None
}

// 统一路由实体
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Route {
    pub destination: IpCidr,
    pub interface: DeviceId,
    pub metric: u32,
}

#[derive(thiserror::Error, Debug)]
pub enum RouteError {
    #[error("Failed deterministically: {0}")]
    Failed(anyhow::Error),
    #[error("Unknown outcome: {0}")]
    Unknown(anyhow::Error),
}

pub struct CleanupIncomplete {
    pub uncleaned_routes: Vec<Route>,
    pub unknown_routes: Vec<Route>,
    pub reason: String,
}

// Manager 内部状态 (不包含独立队列或结果锁)
pub struct HostRouteManager<B> {
    inputs: RouteInputs,                     // 固定业务读取入口
    backend: B,

    // 账本状态
    installed_routes: BTreeSet<Route>,        // 本方成功创建的路由
    external_present: BTreeSet<Route>,        // 已存在非本方创建 (防止稳态反复执行与误删)
    unknown_routes: BTreeSet<Route>,          // 结果不明 (隔离，严禁当成普通失败重发)
    retry_tracker: BTreeMap<Route, RetryState>, // 只保存当前仍需执行的失败项

    // 缓存稳态
    current_tun_device: Option<DeviceId>,
    desired_routes_cache: Option<BTreeSet<Route>>, // 连同上轮相关输入快照复用

    // 停机控制与单向唤醒接收端
    cancel_token: tokio_util::sync::CancellationToken,
    wakeup_rx: tokio::sync::watch::Receiver<()>,
}
```

**接口身份与销毁事实**：`host_instance` 复用 Host 已有实例身份；没有时由 Host 在每次成功创建新设备时分配本进程内不重复的值。它只识别自建设备重建，不是需求版本。显式指定当前自建接口的路由也解析成同一个 DeviceId；接口名称变化不造成删增。

本阶段 Host 串行管理一个自建 TUN：只有实际关闭旧设备及持有它的转发任务之后，才提交无设备或替换为新设备的事实。Manager 因而可以从最新事实确认自己记录的旧 Host 实例已经结束，即使中间 None 被 watch 合并、ifindex 被复用也能识别。不就绪不能伪装成“已销毁”。若只是改选默认出口而旧设备仍存活，保留其记录并执行正常撤销；不满足上述 Host 销毁契约的接口，仅在平台确认消失后核销。外部接口不获得 Host 实例标识，也不宣称解决任意外部替换竞态。

确认自建设备销毁后，仅清除属于该实例的 installed、external_present、unknown 和 retry 记录。Manager 不持有设备、fd 或保活资源；后端只持有路由操作所需的 socket 等资源。

Host 接线不能把现有 `TunNicState::stop()` 的 `drop(old)` 当成已经完成销毁：`NicCtx` 的转发任务持有设备两端，Host 应停止并等待这些任务释放资源，再发布销毁事实；仅发出 abort 不够。为 Host 补必要的异步关闭入口即可，不把任务或设备所有权转交给 Manager。[Tokio JoinSet::shutdown](https://docs.rs/tokio/latest/tokio/task/struct.JoinSet.html#method.shutdown)

**集合的失效规则**：每次计算只保留当前仍有需求且设备上下文有效的 external_present；观察到需求撤销或上下文失效就清除，再出现时重新尝试。普通重复刷新不清空它，也不作持续外部漂移检测；被合并的中间需求变化不当作已观察到的撤销。EEXIST 无法确认等价时按冲突失败处理，不能用来宣称需求满足。Unknown 保留到结果核实或确认接口销毁；不能因需求撤销就丢掉未决责任。

---

## 三、 单协调循环与清理 (Single Loop)

彻底删除异步 `handle_device_fact_changed` 和零碎唤醒，设备变化作为普通事实输入，合并退避/定时核对机制。

```rust
pub async fn run(mut self) -> Result<(), CleanupIncomplete> {
    loop {
        if self.cancel_token.is_cancelled() { break; }
        // 每轮读取事实前标记已读并释放借用，第一轮不等通知。
        drop(self.wakeup_rx.borrow_and_update());
        self.reconcile().await;

        if self.cancel_token.is_cancelled() { break; }
        match self.wakeup_rx.has_changed() {
            Ok(true) => {
                // 连续纯计算轮也给其他任务执行机会；不在这里标记新通知已读。
                tokio::task::yield_now().await;
                continue;
            }
            Ok(false) => {}
            Err(_) => { tracing::warn!("route refresh channel closed"); break; }
        }
        let next_wakeup = self.next_wakeup_time(); // 最近重试 / 输入读取重试 / 低频核对

        tokio::select! {
            biased;
            _ = self.cancel_token.cancelled() => break,
            _ = tokio::time::sleep_until(next_wakeup) => {}
            res = self.wakeup_rx.changed() => {
                if res.is_err() { tracing::warn!("route refresh channel closed"); break; }
            }
        }
    }

    // 先读取最新接口事实核销已销毁设备，再清理仍需负责的路由。
    self.perform_shutdown_cleanup().await
}
```

`reconcile` 只有一条处理路径：

1. 短借用读取 Core/Host 最新事实，释放来源锁；必要输入不可用时保留创建记录、暂停依赖该输入的操作并安排退避读取，不把错误解释为空集合。
2. 根据已确认的销毁事实核销对应记录。仅在路由相关输入改变时计算 desired；无关配置变化复用缓存。清理过时 external_present 和不再需要执行的 retry。
3. 计算候选 `to_remove = installed - desired - unknown`、`to_add = desired - installed - external_present - unknown`，再过滤执行依赖。只有到期失败项可重试；同槽替换必须确认旧条目删除后才添加。Unknown 还须阻塞同槽替换：旧 ADD 结果不明时，即使新需求改了 metric、完整 Route 已不相等，也不能绕过阻塞再 ADD。这里槽位按当前业务的替换关系及平台冲突条件判断，不把无关的前缀包含关系或其他作用域一起阻塞。
4. 每个操作完成便记账；每个有界批次前检查取消和未读刷新。需要重读时结束余下旧批次，下轮重新读取；重复通知但相关事实未变时继续推进同一计划，不因通知风暴反复放弃已到期的工作。不能取消正在等待的系统操作来假装它没有副作用。没有变更时直接休眠，不重复写。
5. 对本次 DNS 启动需要的路由，按第五节完成一次性答复。

失败按项指数退避（例如 100ms 起、上限 5s），`RetryState` 仅含尝试次数和下次时间。成功后清除对应 retry；转为 Unknown 后移出普通重试调度。失败删除仍保留 installed，Unknown ADD 不写 installed，Unknown DELETE 保留 installed 并标记未决，不能因它还在 installed 就报告路由就绪。每轮检查到期项，不因通知重置截止时间；被未决依赖阻塞的项不作为已到期可执行重试，否则会形成忙循环。保底核对约 30 秒重新读业务事实，不扫描系统表，也不保证修复外部修改。

停机不再添加路由：先收束在途结果，再读取最新设备事实，随后精确删除仍需负责的 installed；跳过未决操作并汇总 Unknown 和删除失败。设备在清理期间销毁时，在结果核实/最终汇总前再确认相应事实，避免把已随设备消失的记录报告为遗留。输入不可读不视为接口消失；不能准确定位的条目如实报告。external_present 从不进入删除或遗留清理清单。任务正常退出时，对尚待完成的 DNS 启动答复停止错误，不让其误报就绪。

---

## 四、 平台操作 (Platform Operations)

1. **统一后端 Trait**：`add(&Route) -> Result<Option<Route>, RouteError>`、`remove(&Route) -> Result<Option<()>, RouteError>`，声明返回 `impl Future<Output = ...> + Send`，编译期分发。添加 Some 表示本方创建，None 仅表示确认等价外部条目；删除 None 仅表示确认精确目标不存在。确定无副作用的失败与已发送但无法确认结果的 Unknown 分开处理。
2. **Linux Netlink** (`PlatformRouteBackend`)：
   - 在目标网络命名空间创建并复用一个 socket，同一作用域内的 TUN 重建不重建连接。命名空间切换不跨可迁移任务的 await。
   - 优先复用现有 socket 的非阻塞能力接入异步 readiness；若必须保留阻塞 I/O，使用受控执行环境及有界收包等待，避免逐条操作一次线程池往返。仅加 spawn_blocking 不代表完成异步或性能验收。
   - 复用现有 Netlink 编解码，按 sequence 匹配内核 ACK；等待有截止时间，迟到 ACK 不匹配到下一请求。已发送请求超时记为 Unknown，不盲目重发；核实存在也不能反推为本方创建。
   - 在固定 table 与作用域中，用记录的目标、接口索引、metric 等完整匹配参数构造 `RTM_DELROUTE`，正常路径不逐条 dump。EEXIST/Unknown 确需核实时允许异常路径查询，不能把最长前缀查询结果当成精确等价证明。
   - 同一 Manager 是唯一逻辑 writer；批量/流水化只在规模基准证明收益后放入后端，逐项记账并保留替换顺序，不给每条路由 spawn 一个任务。

---

## 五、 Host/DNS 接线与单一所有权 (Wiring)

### 1. 单任务所有权与限时等待

Host 独占一个 `Option<JoinHandle<Result<(), CleanupIncomplete>>>` 任务槽位与取消令牌，来源只克隆刷新 Sender。完成值由任务返回，不保留共享结果锁。现有 Host 使用 `Arc<Self>` 和 `&self` 生命周期入口；实现可沿用其任务槽位 Mutex/串行入口来取得唯一可变访问，不要求重构整个 Host，也不克隆整套控制句柄。

```text
Host 停止流程（唯一任务槽位）：
    触发取消
    限时取得槽位访问；已有生命周期锁的等待也计入同一个 deadline
    从 join.as_mut() 取得 &mut JoinHandle，传给 timeout_at(deadline, handle)
    超时：保留 Option 中的句柄，报告“等待未完成”，以后可继续等待
    完成：从 Option 取出句柄，返回任务的清理结果；任务异常则如实报告
```

超时不是最终失败清单，不以空列表宣称没有遗留。完成后不再轮询已完成句柄；无句柄表示结果已被消费，不编造上次成功。当前无需可重复查询终态的公共 API。Host 退出时若仍有待完成清理，使用 guarden 等现成任务托管机制保存清理任务和后端；不持有 TUN，不新建竞争 writer。

**装配次序**：在 `prepare_runtime` 中先接好来源刷新 Sender 并启动 Manager；静态地址和 DHCP 路径完成 NIC 安装、地址配置并发布接口就绪事实后，才启动依赖该接口的 DNS。不能等 DNS 的路由答复后才发布接口，形成循环等待。等待 Manager 或 DNS 的结果时，不持有它们读取 Host 事实所需的锁；实例停止先禁止新的 NIC/DNS 启动并取消现有等待，再收束任务，不能让销毁任务等待 Manager 的路由清理 ACK。

### 2. DNS 路由合并接管

仅在第一节的接管路径移走 `MagicDnsServerInstance` 的路由增删，DNS 服务、解析器注册和系统 DNS 配置仍由原组件负责。删除临时 Tracker、预留范围和路由清理结果传播链。

**计算**：DNS 未启用或没有就绪设备时不生成 DNS 路由；fake_ip 在当前 TUN 子网内时无需额外 /32，否则产生其主机路由。代理与 DNS 是相同目标和适用出口时按 step1 的用途规则合并，保留 DNS 的既定参数；`0.0.0.0/0` 与 `7.7.7.7/32` 保留两条需求，各自撤销。manual 的空集合只禁用代理，不清空 DNS。DNS 关闭后由剩余需求重算，不直接命令删除某个 CIDR。

**具体启停时序**（只增加 DNS 本次启动的一次性结果，不增加刷新通道）：

1. Host 串行管理该设备上的 DNS 启停，建立本次启动的 `oneshot<Result<(), RouteError>>`。把 fake_ip、所属设备实例和待完成的 Sender 放入现有 Host DNS 状态，提交后通知同一个刷新 watch；即使 `new()` 尚未返回，这份启动中需求也能被 Manager 读取。
2. Manager 计算并处理该 DNS 路由：本方已确认安装或确认等价外部条目，且不存在影响它的未决操作/替换阻塞时，才可答复成功；当前接口子网已覆盖且无需额外路由也是成功。确定失败/冲突/Unknown 答复错误；相关依赖未完成则继续等待。DNS 启动方有有界等待与取消。答复前在 Host 状态短锁内确认所属设备和有效 DNS 需求仍匹配，取出本次待答复 Sender 后释放锁；不持锁跨 I/O。不因其他独立路由失败阻止 DNS 成功。
3. DNS 启动流程等待这个结果，成功后才完成系统 DNS 配置并发布服务可用；发布前仍检查本次启动未取消、所属设备仍有效。先完成服务与解析器所需准备；后续系统配置失败也要回收准备资源。oneshot 完成只消费答复口，成功的 DNS 路由需求保留到服务停止。
4. 启动失败、超时或取消时，撤回本次需求并通知刷新，恢复已改动的 DNS 配置及服务资源；启动中的撤回必须在 `DnsRunner` 取消路径也执行，不能只依赖已构造成功的 `server.clean_env()`。复用现成作用域清理机制，下一次启动不与旧启动清理并发覆盖状态。
5. 正常停止先恢复系统 DNS 配置、结束该 DNS 服务，再撤回需求并通知刷新。设备销毁前结束其 DNS 启停任务；旧设备的异步结果不得发布到新实例。Manager 根据剩余代理/DNS 需求决定路由是否撤销，删除失败留在其记录中，不再交还 DNS writer。

现有 `do_system_config` 使用 spawn_blocking。若取消发生在系统配置操作期间，保留并等待该操作结果后再恢复配置，不能丢掉等待后立即恢复，否则迟到写入可能覆盖恢复结果；这一收束由 DNS 自己负责。准备阶段的解析器注册、失败撤回都要覆盖 `new()` 被取消的路径。[Tokio spawn_blocking 的取消限制](https://docs.rs/tokio/latest/tokio/task/fn.spawn_blocking.html)

DNS 的 oneshot 是本次启动所需的业务结果；所有触发重新计算的请求仍只走同一个 watch，不建立通用提交、版本等待或任意 add/remove API。

---

## 六、 重点验证矩阵

以可控 Mock 验证循环与失败分支，以隔离 netns 验证真实路由操作；不靠增加 sleep 掩盖竞态。

| 场景 | 通过条件 |
| --- | --- |
| 首启、多源通知、I/O 期间更新 | 首次不等通知；最终事实生效，稳定后不重复写；不要求任意调度下恰好一次唤醒。输入失败不清空路由。 |
| 预先取消、刷新与停止并发 | 不启动新的普通批次，在途结果记账后走统一清理；大批次发现新配置及时放弃余下旧计划。 |
| 接口销毁/重建 | 中间 None 被合并、同名同 ifindex 重建仍能识别；改选仍存活的出口不能核销旧记录；延迟转发任务退出时不能提前发布销毁；销毁与停止同时发生先读事实；不影响外部接口。 |
| 外部观察缓存 | 等价 EEXIST 不重复写也不删除；撤销需求后再添加会重新尝试；非等价 EEXIST 报冲突，不虚报 DNS 就绪。 |
| 确定失败、Unknown、替换 | 自主退避不被通知重置；未决不盲重发，变更 metric 不绕过同槽阻塞；Unknown DELETE 不虚报 DNS 就绪；被阻塞重试不忙循环；失败和未决不从清理报告消失。 |
| stop 超时及完成 | 槽位锁被占用也遵守 deadline；超时后句柄仍可等待；完成后消费句柄，不重复 poll；任务异常不报告清理成功。 |
| DNS 合并规则 | 相同 /32 合并、撤销一来源保留另一来源；/0 与 /32 各自存在并独立撤销；子网内无需额外 DNS 路由；manual 空集不禁用 DNS。 |
| DNS 启停 | 接口事实先发布，静态与 DHCP 启动均无循环等待；只发刷新不能完成启动；路由失败/Unknown、初始化失败及 new() 期间取消都撤回需求；系统配置迟到完成不覆盖恢复结果；旧实例结果不污染新实例；没有额外 DNS writer。 |
| 平台与接管 | Linux 接管路径旧代理/DNS writer 均停用；未开启 netlink 及未迁移平台保留原路径；No-TUN 零原生路由操作。 |
| 原生后端与性能 | 同接口同 CIDR 不同 metric/table 的外部条目不误删；ACK 超时/迟到正确分类；正常批量增删复用 socket、零逐条 dump，异常核实单列。 |

纯策略测试复用 step1 规则；性能按 master plan 第 7 节测 100/1,000/10,000 条、单条更新和稳态，记录系统调用、分配及延迟。不以改成静态分发或改文件数代替测量。
