# HostRouteManager 第二步方案第四次审查

审查对象：`9bc989bb` 中的 `docs/host-route-manager-step2-plan.md`（724 行，blob `9ef59c2224e8d1d355bfb5fc8057f8d54ab1bd99`）。

**结论：主体设计已经收敛，剩 1 个阻塞点，修正后再通过完整方案。** 不需要重写总纲、增加新状态框架或继续扩大文档；问题是新引入的冻结规则尚未覆盖全部执行入口。

## 上轮问题闭合情况

| 上轮问题 | 本轮判断 |
| --- | --- |
| T1：deadline 未覆盖完整 stop | 已明确外层限时等待、后台继续接收结果及内部清理限时；设计意图关闭。示例的接收句柄传参需按下文校正。 |
| T2：解绑 ACK 后仍发旧 I/O | 普通协调路径已通过 Frozen / CleaningActive 修复；停机和 DNS 交接仍有旁路，见 U1。 |
| T3：换绑定不触发执行 | 已明确区分期望投影缓存和 execution_dirty，新绑定强制协调，并增加同地址换卡、DHCP 延迟建卡验收；关闭。 |
| T4：未决操作放行、Linux DNS 跳过删除 | 已阻止 pending/in-flight/retired 冲突放行，DNS 路由清理已移出 system_config 条件；原问题关闭。 |

## U1 · P1：停机和 DNS 交接仍能绕过 Frozen 的禁止 I/O 规则

**位置：方案第 486、518、595–597 行。**

第 486 行承诺解绑后，在 Host 明确交回控制之前绝不对该 retired 绑定发起系统调用。但另两处仍要求无条件操作 retired：

- 停机第 518 行遍历 `installed_routes` 与 `retired_bindings` 调用 remove_route，未限定 CleaningActive。
- DNS 交接第 596 行发现 P 在未清理 retired 中，就调用 remove_route，也未限定绑定状态。

因此“解绑 ACK → Host 已获准关闭旧设备 → 销毁确认尚未到达 → Stop 或 DNS 交接触发删除”仍是方案允许的执行路径。普通循环跳过 Frozen 并不能保证所有路径都跳过。

**最小修订：** 将 Frozen 的禁止 I/O 定义为所有执行入口共用的约束，包含正常协调、重试、stop、DNS 交接和必要核实。只有匹配绑定的 `CleanupRetiredInterface` 才重新授权 I/O；Stop 和 DNS 请求本身不是这项授权。

- stop 遇到 Frozen 时，保留其 installed/pending 并报告未完成，或在 deadline 内等待对应销毁/授权确认；绝不擅自删除。
- DNS 交接遇到冲突范围内的 Frozen 责任时，保持预留阻塞，等待销毁确认或经授权完成清理。
- 所有路径按同一规则处理即可，不必为每条路径添加一套状态机。

**针对性验收：** 取得 unbind ACK 后，暂不发送销毁确认，分别触发 Stop 和 DNS 冲突请求；两个场景中旧后端调用数均须为零。Stop 返回未完成，DNS 不放行；确认销毁或显式授权清理后再验证后续推进。

## 两处可与上述修订一并处理的局部校正

1. **第 516 行 timeout 接收句柄不能按值移入后丢弃。** `timeout_at(deadline, in_flight_rx).await` 超时时会丢弃其持有的 future；若它是唯一结果接收端，便无法兑现下一行“Manager 继续独占并接收结果”。应由 Manager 保存句柄，用 `&mut in_flight_rx`（或已固定的 future 的可变借用）进行限时等待，超时后继续持有。对清理操作采用相同规则。这个修改落实已有意图，不需要重新设计 stop。
2. **DNS 清理总错误不要等同于路由删除失败。** 第 552–580 行把系统 DNS 恢复失败和路由删除失败合并为 first_error；第 602–604 行却将返回值作为“真实删除结果”。在 system_config.close 失败而路由删除成功时，不能把该路由永远标成 CleaningFailed。保留路由清理结果供交接判断，同时独立报告系统 DNS 恢复错误即可；无须建立通用错误聚合框架。

本轮核对了修订全文、差异、前轮审查及本地 Tokio timeout/oneshot 源码。未修改方案正文或产品代码，未运行系统路由测试。后续实现仍需用实际后端和生命周期测试证明上述承诺；不再将实现细节全部展开成新的规划章节。
