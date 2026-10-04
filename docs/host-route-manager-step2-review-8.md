# HostRouteManager 第二步方案：第八轮复审

审查基线：`6bc9f6d3`；方案为 [`host-route-manager-step2-plan.md`](host-route-manager-step2-plan.md)，Git blob `8cd165d0c0ba265a6a1570c70424683731d84228`。下列行号对应此版本。

**结论：Unknown 处理、结果保存和平台范围已实质改善；仍有三个具体问题需要修正。** 保留当前小型 Manager 方向，修改下面的所有权、命令投递和 future 约束即可，不增加生命周期框架。

上一轮问题的状态：

| 上轮问题 | 本轮结果 |
| --- | --- |
| R1：名称识别换卡、其他接口记录隔离 | 已增加 ifindex、换绑命令和局部清理规则；但换绑命令会丢失，见本轮 R2。 |
| R2：真实设备及在途操作所有权 | 顺序等待当前操作的方案成立；设备保活仍未成立，见本轮 R1。 |
| R3：Unknown 与完整清理结果 | 已补上执行/清理跳过、失败汇总和最终结果保存；正常 stop 超时只取消调用方等待的思路成立。 |
| R4：平台别名和 feature 范围 | 已删除不存在的后端，限定新模块编译范围，可按此实施。 |

## R1 / P1：Arc<Notify> 不持有设备，且示例中的保活变量会提前释放

**位置：第 380–390、398–406、449 行。**

这里有两个独立的所有权问题：

1. `NicCtxContainer` 同时包含 `nic_ctx` 和 `device_keepalive: Arc<Notify>`，并不建立二者的保活关系。Manager 克隆 Notify 只会延长 Notify 自身的生命周期；Host 丢弃容器时仍会释放旁边的 `nic_ctx`。现有 `TunNicState::stop()` 正是在取出容器后 `drop(old)`。Notify 也不会在最后一个 Arc 被释放时自动执行设备释放或唤醒逻辑，因此第 390 行的保证没有实现依据。
2. 即使把 Notify 换成真正拥有设备的类型，当前守卫仍不能保活它：`device_keepalive` 只出现在 guarden 的捕获列表中，没有被内部 `async move` 使用。guarden 0.3.0 的宏将捕获项解构为 action 的参数，再执行给定表达式；未被 future 捕获的变量会在 action 返回 future 时释放，而非等清理结束。第 449 行的注释不会改变 Rust 捕获规则。

此外，Manager 字段及 `BindTunDevice(DeviceId)` 尚未提供实际设备资源的传入/换出位置，需要与修正后的所有权路径一致。

**最小修正：** 明确一个真实资源持有者：可以把实际 `NicCtx` 移入清理任务，也可以让 Host 持有它并在受 guarden 保护的任务中等待 Manager 清理完成。若使用共享所有权，Arc 内部必须直接或间接持有实际资源，不能只放一个通知器。资源必须覆盖正常运行、等待当前在途操作、清理三个阶段；换绑时旧资源清理完再释放，新资源按同一规则接入。

在异步体结束处显式 `drop(device_keepalive)`，或者使用其他清楚表达相同所有权的写法，确保真实资源被移入该 future 并活到最后。无需另做保活凭证协议。

**验证：** 用可观察 Drop 的资源让 backend.remove 暂停，触发 guard 后资源仍未释放；调用方 stop 超时且 Host 退出原持有路径后仍未释放；清理实际结束后才释放。除模拟资源外，集成测试应覆盖真实 NicCtx 接线。

## R2 / P1：BindTunDevice 的 try_send 会静默丢失设备替换

**位置：第 270–273、298–300、320–324 行。**

`bind_tun_device()` 使用 `try_send`，并忽略返回错误。若 Manager 正在等待系统调用，有界队列已被 Refresh 填满，此次 Bind 返回 Full，新 DeviceId 直接丢失，调用方却得到正常返回。Manager 继续使用旧设备身份，换卡后的路由无法正确重装。

Refresh 可以在存在权威最新快照时合并；Bind 当前携带的是设备变更数据，输入表又没有独立、先提交的设备快照入口，不能照搬 Refresh 的丢弃策略。30 秒定时唤醒也无法重新取得已经丢失的命令数据。

**最小修正：** 生命周期命令使用可靠投递，例如 `async fn bind_tun_device(...) -> Result<...>` 内调用 `send().await` 并处理 Closed；不能成功入队时让 Host 得知并保留待处理资源。若改为从 Host 权威设备状态拉取，则先提交包含真实资源关系的状态，再发可合并 Refresh；选择一种即可，不必两套并存。与 R1 一起说明什么时候接收新资源、什么时候允许释放旧资源。

**验证：** 暂停一次 backend 调用并填满命令队列，再发起同名换卡；恢复后 Manager 必须取得新设备，或者调用方明确收到失败，不能静默遗漏。

## R3 / P2：原生 async trait 尚未声明返回 future 的 Send 约束

**位置：第 170–185、237、398–457 行。**

`RouteBackend: Send + 'static` 只约束 backend 自身，不保证 `add`/`remove` 返回的 future 为 Send。按文中的泛型 Manager 实现，清理 future 等待 `B::remove()`，无法满足 guarden 默认 Tokio spawner 所需的 Send；将泛型 Manager 放入 `tokio::spawn` 同样遇到此问题。具体 Netlink 实现恰好是 Send，并不能补足泛型函数中的 trait 契约。

**最小修正：** 继续静态分发，只把 trait 签名写成返回带 Send 的 opaque future，例如：

```rust
fn remove(&mut self, route: &Route)
    -> impl std::future::Future<Output = Result<Option<()>, RouteError>> + Send;
```

add 同理；实现端仍可使用 `async fn`。无需恢复 async_trait、Box 或 trait object。同步 step1 中的同一接口示意。

**验证：** 编译最小的泛型 Manager + guarden 清理路径，并分别用真实后端和 Mock 实例化。本轮使用仓库 Rust 1.95.0 做了独立最小编译验证：原签名出现 `future cannot be sent between threads safely`；增加返回 future 的 Send 约束后通过。

## 文档收尾

master plan 和 step1 已部分同步，但仍有相互矛盾的示意：step1 第 115–122 行继续定义旧 RouteSpec；master plan 第 41 行使用 BTreeSet，而第 81 行仍指定排序 Vec。仅统一这些残留，保留已有业务规则和性能目标即可，不必再次整体重写。

本轮只新增审查文档，未修改方案正文或产品代码。除 Send 编译验证外，还按 guarden 宏实际展开形式验证了未使用的捕获资源会在 future 开始执行前释放；未执行产品测试。
