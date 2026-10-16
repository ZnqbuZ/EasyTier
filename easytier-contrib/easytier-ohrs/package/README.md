# `easytier-ohrs`

## Install

use `ohpm` to install package.

```shell
ohpm install easytier-ohrs
```

## API

### collectNetworkInfos

```ts
collectNetworkInfos(): Array<KeyValuePair>
````

获取正在运行的网络实例的信息。

---

### collectRunningNetwork

```ts
collectRunningNetwork(): Array<string>
```

获取当前正在运行的网络实例名称列表。

---

### convertTomlToNetworkConfig

```ts
convertTomlToNetworkConfig(cfgStr: string): string
```

将 TOML 配置转换为 NetworkConfig。

* `cfgStr`：TOML 配置内容

---

### defaultNetworkConfig

```ts
defaultNetworkConfig(): string
```

获取默认的网络配置（JSON 字符串），用于转换为object进行赋值。

---

### easytierVersion

```ts
easytierVersion(): string
```

获取 EasyTier 当前版本号。

---

### hilogGlobalOptions

```ts
hilogGlobalOptions(domain: number, tag: string): void
```

设置全局日志选项。

* `domain`：日志域 ID
* `tag`：日志标签

---

### initPanicHook

```ts
initPanicHook(): void
```

初始化 panic 钩子，用于将Rust侧的panic输出到hilog中，请先通过 hilogGlobalOptions 设置hilog的参数。

---

### initTracingSubscriber

```ts
initTracingSubscriber(): void
```

初始化 tracing 日志订阅器，用于将Rust侧日志同步输出到hilog中，请先通过 hilogGlobalOptions 设置hilog的参数。

---

### isRunningNetwork

```ts
isRunningNetwork(instId: string): boolean
```

判断指定网络实例是否正在运行。

* `instId`：网络实例 ID

---

### parseNetworkConfig

```ts
parseNetworkConfig(cfgJson: string): boolean
```

校验网络配置（JSON 格式）是否合法。

* `cfgJson`：网络配置内容

---

### runNetworkInstance

```ts
runNetworkInstance(cfgJson: string): boolean
```

启动网络实例。

* `cfgJson`：网络配置（JSON）

---

### 完整 VPN 配置与本地 TUN

```ts
getMobileTunConfig(instId: string): string | null
setTunFd(instId: string, fd: number, snapshotId?: string): boolean
```

`getMobileTunConfig` 会提交该实例的参与范围并返回 Controller 的完整配置 JSON；调用方必须原样使用其中的 `addresses`、`routes` 和 `dns` 创建系统 VPN，不得再按 proxy CIDR、manual 配置或成员信息筛选。正 fd 的 `setTunFd` 等待本地 attach 完成，并在成功后才更新 attached 展示状态；配置过期时返回失败，调用方应重新获取快照并配置 VPN。

* `instId`：网络实例 ID
* `fd`：TUN 设备文件描述符；小于等于 0 表示解绑
* `snapshotId`：实际安装的配置 JSON 中的 `snapshot_id`；解绑时可省略

运行状态读取与范围提交是两类操作：`collectRuntimeStateJson` / `listInstancesJson` 等状态查询只读取当前完整结果，不改变参与范围；查询失败会抛出 NAPI 错误，不会返回默认状态、空 routes 或 `{}` 冒充成功。状态中的 `aggregatedRoutes`/`dnsServers` 只是完整表的展示映射，不是逐路由 Ready；`attachedInstanceIds` 只表示真实本地接入成功后仍有效的成员。

TUN/VPN/FD 始终由 ArkTS 宿主拥有。`setTunFd` 成功只表示本地接入结果，不代表系统 VPN 已创建或关闭；停止时应先等待本地 detach（`fd <= 0`）完成，再释放或关闭宿主自己的 FD。本绑定没有 request/pending/complete 或 MobileAction 协议。

---

### stopNetworkInstance

```ts
stopNetworkInstance(instNames: Array<string>): void
```

停止指定的网络实例。

* `instNames`：网络实例名称列表


## Usage

```ts
// todo
```
