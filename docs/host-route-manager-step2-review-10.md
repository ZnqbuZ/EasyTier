# HostRouteManager 第二步方案：第十轮复审

审查基线：`6db9e94b`；[`host-route-manager-step2-plan.md`](host-route-manager-step2-plan.md) Git blob 为 `6489d2b85c2473157cb15f0b579e8b2702720cef`。本文行号对应此版本。

**结论：独立设备描述符的持有方式可保留，解绑到空状态及 Debug 修正已补上；关闭顺序和解绑执行路径仍有三处具体问题。** 修正应限于现有 Host 调用顺序、timeout 范围和局部清理分支，不增加新的协调框架。

## R1 / P1：关闭复制出的 fd 不等于设备已销毁，Host 顺序与 ACK 承诺冲突

**位置：第 476–490、546–552、768 行。**

复制底层 TUN fd 可以使设备资源独立于转发任务存活，这个方案方向成立。但 `dup` 得到的是指向同一个 open file description 的另一个描述符；关闭 Manager 的副本不等于关闭 Host 转发任务持有的原始描述符。参见 [Linux dup(2)](https://man7.org/linux/man-pages/man2/dup.2.html)。

第 490、768 行明确规定 **先等待 unbind 成功，再执行 nic.drain()**。按现有 Host 路径，drain 才会停止持有原始设备的 NicCtx。因此，Manager 执行 `drop(device)` 并发 ACK 时，转发任务仍可能持有原始 fd，第 489 行“内核中已绝对销毁”的结论不成立。如果按第 412 行的要求等待实际销毁后才发 ACK，则又会等到 Host 在收到 ACK 后才执行的 drain，形成循环等待。

即使把 `drop(NicCtx)` 提前，也不能把发出任务取消当成任务已退出：现有 NicCtx 使用 JoinSet，Drop 会中止任务，但不等待它们的 future 实际销毁。原始 fd 和 packet receiver 锁的释放需要等任务退出。

**最小修正：** 统一为一条实际可执行的关闭顺序，例如：

1. Manager 已持有独立 fd；Host 停止旧转发任务并等待退出，确认其原始 fd 与 receiver 锁已释放，同时释放 Host 持有的保活副本。
2. Manager 收束在途操作、清理该设备路由，释放最后的保活 fd，再完成解绑。
3. Host 进入 drain/无设备状态或创建新设备。

可以复用 JoinSet 的 shutdown/join 能力，无需新任务框架。也可以保留先清路由再停转发的顺序，但那样 Manager ACK 只能表示“Manager 已解除绑定”；Host 必须在完成自己的任务退出及资源释放之后，才能宣告设备销毁和创建同名设备。两种顺序选择一种并统一全文，不能混用其完成语义。

设备消失的保证限于本实例拥有的非持久 TUN，并以所有相关持有者确实释放为前提；不能由一次 Arc 的 Drop 推导。内核文档也区分普通 TUN 使用与持久设备：[TUN/TAP 文档](https://docs.kernel.org/networking/tuntap.html)。

**验证：** 延迟旧转发任务退出，确认 Host 不会提前报告设备销毁或创建同名设备；任务退出后正常完成解绑和重建。保留 DHCP `Some → None → Some` 测试。

## R2 / P1：解绑 deadline 没有覆盖命令入队等待

**位置：第 339–349 行；与第 564、593 行冲突。**

`unbind_tun_device()` 先无超时地执行 `send(...).await`，之后才对 ack_rx 使用 timeout_at。Manager 正在等待 backend、命令队列已满时，函数会卡在 send，deadline 到达也不能返回。该问题恰好发生在前几轮已经要求覆盖的“系统调用阻塞 + 队列满”场景中。

**最小修正：** 用同一个绝对 deadline 包住发送及 ACK 等待，或分别以同一 deadline 限制这两段等待。发送阶段超时表示请求尚未成功入队，不能声称 Manager 已开始解绑；入队后等待超时才由 Manager 继续持有资源并处理。无需为此增加新命令或状态框架。

**验证：** 保持 backend 调用未返回，填满命令队列，调用 unbind；它必须在 deadline 到达时返回，而不是等队列空出后才返回。另验证已成功入队、仅 ACK 等待超时的后台继续执行路径。

## R3 / P2：清理示例仍是全局停机，不能直接承担局部解绑

**位置：第 498–511、560–566、589–600 行。**

第 5.3 节现在同时描述 stop 和 unbind，但唯一的清理代码会移动整个 backend、全部 installed 和 unknown，遍历所有安装记录；第 562 行还明确写 Manager 等清理完成后退出。这与第 594 行“解绑后继续运行并维护其他接口”冲突。直接复用这个示例会删除外部接口路由并失去后端，无法再次绑定。

**最小修正：** 将当前“接管全部资源并退出”的示例明确限定为 stop。解绑只选择旧默认设备的记录进行处理，保留其他记录及可继续使用的 backend，完成后回到同一个 Manager 循环。补一小段命令分支示意，明确 backend 的持有/返回位置，以及失败和 Unknown 记录在哪里保留；无需复制整套清理实现，也不用增加后端管理器。

**验证：** 同时存在默认 TUN 和其他接口的本方路由时执行 unbind：仅处理前者，Manager 不退出；随后其他接口仍能更新，新 TUN 仍能正常绑定。局部清理失败时，未完成结果不能因回到主循环而丢失。

## 审查范围

上轮的真实资源选择已有实质修正，不再要求更换整体方案；Send、可靠绑定入队、异步体显式持有设备及 Debug 问题保持关闭。本轮只新增本文，未修改方案或产品代码。核对了现有 Host/NicCtx 关闭路径、本地 Tokio JoinSet 实现及 Linux 描述符文档，未运行产品测试。
