# 使用说明

1. 需要将 proto 文件放入 app/src/main/proto
2. android/gradle/libs.versions.toml 中加入依赖

```
# Wire 核心运行时
android-wire-runtime = { group = "com.squareup.wire", name = "wire-runtime", version = "5.3.11" }
moshi = { module = "com.squareup.moshi:moshi", version.ref = "moshi" }
android-wire-moshi-adapter = { group = "com.squareup.wire", name = "wire-moshi-adapter", version = "5.3.11" }
kotlinx-serialization-json = { group = "org.jetbrains.kotlinx", name = "kotlinx-serialization-json", version = "1.9.0" }
```

3. build.gradle.kts 中加入

```
plugins {
    ...
    alias(libs.plugins.wire)
}

dependencies {
    ...
    implementation(libs.android.wire.runtime)
    implementation(libs.android.wire.moshi.adapter)
    implementation(libs.moshi)
}

...

wire {
    kotlin {
        rpcRole = "none"
    }
}
```

4. 调用 easytier-contrib/easytier-android-jni/build.sh 生成 jni 和 ffi 的 so 文件。
并将生成的 so 文件放到 android/app/src/main/jniLibs/arm64-v8a 目录下。

5. 使用 EasyTierManager 可以拉起 EasyTier 实例并启动 Android VpnService 组件。

## 完整路由表与后台刷新

`EasyTierManager` 的监控周期只向 `EasyTierVpnService` 的既有后台入口提交刷新意图。
Service 的单一后台执行器负责读取 `getMobileTunConfig(instanceName)` 的完整 JSON，
并原样使用其中的 `addresses`、`routes` 和 `dns` 建立系统 VPN；Manager 不根据
`proxy_cidrs`、manual 配置或成员信息生成最终路由。网络信息只用于状态展示/诊断。

- 完整配置读取失败不会被当成空表，当前 VPN 会保留并在下一次刷新重试。
- `snapshot_id` 和本次实际接入一起保存；相同内容不会循环重建，成员/run 或实际
  接入变化会触发宿主自己的重建策略。
- `vpn_service_start` 仍由宿主创建 FD 并回调；读取完整配置、`setTunFd` 和本地
  detach 都在同一个后台执行器中串行执行，不能在主线程同步调用。
- 连续刷新意图会合并为最新一次，不会每次轮询新起并发安装线程。
- 停止/撤销时先把清理任务排到同一执行器；正在 `setTunFd` 时不会提前关闭仍被
  Native 借用的 FD。`setTunFd` 成功只表示本地接入结果，系统 VPN 仍由宿主管理。
