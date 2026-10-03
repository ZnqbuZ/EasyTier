# HostRouteManager 新路线 step1 再审

审查对象：`96f9230c`，设计文档 Git blob 为 `53e003978d2a1c9cd3fae2f4a69d2dda2f0df7c6`。

**结论：上轮主要问题已修正，仍有以下 3 项局部问题需要修改，暂不通过。** 不要求增加框架、日志或新一轮架构设计。

## 上轮意见闭合情况

| 意见 | 本轮判断 |
| --- | --- |
| N1 删除参数不精确 | 已明确补齐匹配参数及测试；正文还需将平台字段表述限定到相应后端，见末尾校正。 |
| N2 清理失败丢记录 | 已修正，保留失败项并返回 CleanupIncomplete，新旧接口安装记录分离。 |
| N3 重叠路由和旧条目交接 | 干净启动/旧 writer 清理后交接已明确；重叠检查仍遗漏自动来源，见 R2。 |
| N4 No-TUN 虚假成功 | 已修正为跳过执行、安装记录保持为空。 |
| N5 委托后端未接入 | 已增加整批应用、确认后记账及会话清理分支。 |
| N6 当前与旧提交混淆 | 已区分当前、旧提交与待新增；尚有具体入口名称错误，见末尾校正。 |

## R1 · P1：不能直接停止整个 Public IPv6 地址 updater

文档第 295–296 行要求停止两个 public_ipv6 updater，但 `run_public_ipv6_addr_updater` 同时负责 IPv6 地址和默认路由：

- `easytier/src/instance/virtual_nic.rs:1173–1185`：初始 link_up、安装 IPv6 地址、安装默认路由。
- 同文件第 1210–1227 行：撤销旧地址、安装新地址，以及对应默认路由更新。

如果直接停止整个任务，Manager 虽能根据租约安装 `::/0`，Host 却不再安装和更新本机公网 IPv6 地址。文档开头仍明确地址由原组件负责，迁移步骤与职责约定冲突。

**最小修改：** 保留地址维护职责，只从该任务移除默认路由增删；peer 路由 updater 在完整接管后可以停止。验收补一条“租约获得、换地址、释放后，地址维护仍运行，路由只有 Manager 写”。这是拆分现有任务中的调用，不需要新组件。

## R2 · P1：重叠防御仅检查 manual_routes，自动 peer 路由仍可双写

文档第 287–288 行及第 304 行只排除手工路由与尚未迁移的 DNS/接口前缀重叠。

在 `manual_routes = None` 时，对端同样可以通告恰好等于 DNS fake IP `/32` 或接口前缀的网段；也可能在 Manager 启动之后才通告。旧 DNS/NIC writer 仍在运行，新 Manager 会写入或撤销同一实际条目。第 303 行的一般原则尚未落实到这个执行路径。

**最小修改：** 检查计算后的有效代理集合，覆盖自动和手工来源，并在来源/配置变化时继续检查。可以整体交接相关 writer，也可以在首期明确阻止冲突范围进入新 writer；禁止直接重新启动一个与新 Manager 同时写的旧链路。判定按同一实际路由或删除匹配范围冲突，不能把所有前缀包含关系都当作双写。

## R3 · P2：新增冲突规则未定义清楚，可能改变 DNS 的既有 metric

文档第 149 行新增“更具体的显式配置优先，否则选较小 metric”，但对同一个 destination，没有定义来源的优先顺序，也没有定义 `None` 如何比较。

反例：Windows 下 manual_routes 包含 DNS fake IP `/32`。代理条目的 metric=None，DNS 条目为 Some(4)。若“显式配置优先”解释为手工代理优先，DNS 的 4 被替换为默认值；当前 Windows 后端的默认值实际为 9000（`easytier/src/common/ifcfg/windows.rs:201`）。这与第 138 行要求保留 DNS metric 的规则不一致。

**最小修改：** 明确同一目标的固定合并规则，保留 DNS/Public IPv6 等用途的既定参数，不能把 manual_routes 的代理覆盖权扩展到其他用途。`None` 表示平台默认，不是数值最小；必要时先解析有效值再比较。尚无合理裁决的冲突可以明确报错，不必建立通用策略框架。补一个 manual 与 DNS 同 `/32` 的规则测试即可。

## 顺手校正，不扩展架构范围

- 第 107、272 行的 `Route::list_proxy_cidrs_excluding` 不存在。公开 trait 是 `Route::list_proxy_cidrs` / `list_proxy_cidrs_v6`（`peers/route/mod.rs:104–107`）；`*_excluding` 是内部路由表方法。该公开实现已负责排除本机，不需要 Host 再调用内部方法。
- 第 198 行把 table/metric 等字段写成所有原生后端共同必需项，应改为“按各平台实际路由身份和创建时有效参数精确定位”。Linux 再具体列 table/priority/oif；Windows 现有接口使用 LUID 和 next-hop；macOS/FreeBSD 按其接口能力定位。无需把 Linux 字段补进公共 RouteSpec。这里是在校正 N1 的适用范围。

## 验证范围

对照上轮差异及现有源码，核对 Public IPv6 updater 的地址职责、公开路由读取方法和 Windows metric 默认值。未修改设计正文或产品实现，未运行平台网络测试。
