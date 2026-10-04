# HostRouteManager 第二步实施方案：整体架构收缩与闭环（单事实驱动）

状态：已根据最新的整体架构复审（[Review 14](host-route-manager-step2-review-14.md)）彻底重构，方案大幅压平，把通知、协调、任务所有权各收成一条路径，同时补齐全闭环状态缺口。

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
3. **接口事实**：Host 管理 TUN/VPN，提供当前 `Option<DeviceId>`，变更后通知。
4. **DNS 事实**：DNS 启动/配置时提供 `fake_ip` 和 `tun_inet`，加入 Manager 统一读取，**取消原 DNS 侧自带的路由写入**。

---

## 二、 核心数据模型与最小模块

代码划分建议：`model.rs` (模型)、`manager.rs` (协调)、`backend.rs` (后端)、`policy.rs` (计算)。

```rust
// 确切设备身份，不凭 ifname 猜测生命周期
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct DeviceId {
    pub ifname: String,
    pub ifindex: u32,
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
    backend: B,
    
    // 账本状态
    installed_routes: BTreeSet<Route>,        // 本方成功创建的路由
    external_present: BTreeSet<Route>,        // 已存在非本方创建 (防止稳态反复执行与误删)
    unknown_routes: BTreeSet<Route>,          // 结果不明 (隔离，严禁当成普通失败重发)
    retry_tracker: BTreeMap<Route, Instant>,  // 确定性失败重试退避追踪
    
    // 缓存稳态
    current_tun_device: Option<DeviceId>,
    desired_routes_cache: Option<BTreeSet<Route>>,
    
    // 停机控制与单向唤醒接收端
    cancel_token: tokio_util::sync::CancellationToken,
    wakeup_rx: tokio::sync::watch::Receiver<()>,
}
```

---

## 三、 单协调循环与清理 (Single Loop)

彻底删除异步 `handle_device_fact_changed` 和零碎唤醒，设备变化作为普通事实输入，合并退避/定时核对机制。

```rust
pub async fn run(mut self) -> Result<(), CleanupIncomplete> {
    loop {
        // 第一轮立即执行协调，解决首轮漏洞
        self.reconcile().await;
        
        let next_wakeup = self.next_wakeup_time(); // 合并最近重试时间与 30 秒保底核对
        let sleep_fut = async {
            match next_wakeup {
                Some(inst) => tokio::time::sleep_until(inst).await,
                None => std::future::pending().await,
            }
        };

        tokio::select! {
            _ = self.cancel_token.cancelled() => break, // 唯一退出路径
            res = self.wakeup_rx.changed() => {
                if res.is_err() { break; }
                // 标记已读并立即释放锁，允许跨系统 IO 期间产生新通知，不跨域借用
                let _ = self.wakeup_rx.borrow_and_update(); 
            }
            _ = sleep_fut => {}
        }
    }
    
    // 所有退出路径均汇聚至此尾段
    self.perform_shutdown_cleanup().await
}

async fn reconcile(&mut self) {
    // 1. 同步读取各来源最新事实（任何一源不可用均不应视为无路由）
    let device_fact = read_device_fact();
    let dns_fact = read_dns_fact();
    let (peer_routes, manual_routes) = read_core_facts();
    
    // 2. 处理已销毁接口：若旧接口不再生效（ifindex改变或丢失），直接归档
    if device_changed(&self.current_tun_device, &device_fact) {
        self.retire_old_device_routes(); // 依靠内核级联删除，仅做内部账本核销
        self.current_tun_device = device_fact.clone();
    }
    
    // 3. 计算期望（只有在相关输入变更时重算）
    let desired = self.calc_desired(device_fact, peer_routes, manual_routes, dns_fact);
    
    // 4. 差异计算
    // to_remove = installed - desired - unknown
    // to_add = desired - installed - external_present - unknown
    
    // 5. 执行增删
    // 执行期间：分批检查取消信号；精确处理 AlreadyPresent -> 记入 external_present
}
```

---

## 四、 平台操作 (Platform Operations)

1. **统一后端 Trait**：返回 `impl Future<Output = Result<Option<T>, RouteError>> + Send`。
2. **Linux Netlink** (`PlatformRouteBackend`)：
   - 使用 `spawn_blocking` 将 I/O 隔离至后台池，保障 Tokio 调度顺畅。
   - 生命周期内建立长连接并绑定 Namespace，不随每次请求新建套接字。
   - **零 Dump 删除**：直接组装包含 `RTA_OIF`（设为确切 `ifindex`）、目标网段、优先级的 `RTM_DELROUTE`，严格实行 1 发 1 删，抛弃用户态全量表 Dump。

---

## 五、 Host/DNS 接线与单一所有权 (Wiring)

### 1. 单任务所有权与限时等待

彻底抛弃 `RouteManagerHandle` 中的共享任务锁与清理结果存储。Host 独占 Manager 任务的 `&mut JoinHandle`。

```rust
// 在 Host 的停机处理中：
pub async fn stop(&mut self, deadline: tokio::time::Instant) -> Result<(), CleanupIncomplete> {
    self.manager_cancel_token.cancel();
    
    // 借用 `&mut JoinHandle`：超时只丢弃借用，后台任务及句柄不受影响
    match tokio::time::timeout_at(deadline, &mut self.manager_join_handle).await {
        Ok(Ok(result)) => result, // Task 正常返回 Result<(), CleanupIncomplete>
        Ok(Err(e)) => Err(CleanupIncomplete { reason: format!("panic: {e}"), ..Default::default() }),
        Err(_) => Err(CleanupIncomplete { reason: "timeout".into(), ..Default::default() }),
    }
}
```

### 2. DNS 路由合并接管

**一并迁移 DNS (`fake_ip/32`) 路由**：
DNS 初始化过程不再调用 `IfConfiger` 进行路由写或清。
将 `fake_ip` 和 `tun_inet` 提交为 Manager 事实。Manager 的 `calc_desired` 融合该信息自动计算：
- DNS 与代理同路由合并计算（如既配了全量代理又是 DNS fake_ip 时，不会因为 DNS 关闭而误删代理路由）。
- 彻底删除临时 `UnmigratedRouteTracker`、释放预留区间和 `DnsCleanOutcome` 的相关链路。
- 只有成功部署 DNS 配置与路由后，才宣称 DNS 可用。

---

## 六、 重点验证矩阵

为确保没有死锁及虚假保证，强制执行以下用例：

1. **首启与多通知同发**：Manager 初启时没有被 Select 挂起，立刻计算并完成首次写入；并发事实通知抵达，仅作单一唤醒。
2. **接口同名重建与销毁**：依赖 OS `ifindex` 更换识别销毁；销毁与停机同时抵达时，优先使用接口事实核销账本记录，不清空错误接口上的无关路由。
3. **AlreadyPresent (`EEXIST`) 闭环**：添加外部固有路由时记录至 `external_present`。稳态刷新不再高频下发添加，停机退出时也绝不将其作为遗留未清理项报告。
4. **单权安全等待 (`cancel-safety`)**：`stop` 触发超时后检查系统，由于采用 `&mut JoinHandle` 借用，确信 Task 仍在后台工作，句柄仍有效可再次等待。
5. **DNS 路由重叠抗干扰**：在 Manager 接管态，当开启代理包含 `fake_ip`，同时开启 Magic DNS 时，记录为单条安装，撤下任意一个功能，路由不会从系统丢失。
6. **I/O 性能准则**：在连续增加与删除 100 条路由时，`strace` 指标确保无重建 Socket，无 `RTM_GETROUTE` 调用。
