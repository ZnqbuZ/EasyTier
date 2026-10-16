package com.easytier.jni

import android.app.Activity
import android.content.Intent
import android.os.Handler
import android.os.Looper
import android.util.Log
import com.squareup.moshi.Moshi
import com.squareup.wire.WireJsonAdapterFactory
import common.Ipv4Inet
import web.NetworkInstanceRunningInfoMap

fun parseIpv4InetToString(inet: Ipv4Inet?): String? {
    val addr = inet?.address?.addr ?: return null
    val networkLength = inet.network_length

    // 将 int32 转换为 IPv4 字符串
    val ip =
            String.format(
                    "%d.%d.%d.%d",
                    (addr shr 24) and 0xFF,
                    (addr shr 16) and 0xFF,
                    (addr shr 8) and 0xFF,
                    addr and 0xFF
            )

    return "$ip/$networkLength"
}

/** EasyTier 管理类 负责管理 EasyTier 实例的生命周期、监控网络状态变化、控制 VpnService */
class EasyTierManager(
        private val activity: Activity,
        private val instanceName: String,
        private val networkConfig: String
) {
    companion object {
        private const val TAG = "EasyTierManager"
        private const val MONITOR_INTERVAL = 3000L // 3秒监控间隔
    }

    private val handler = Handler(Looper.getMainLooper())
    private var isRunning = false
    private var currentIpv4: String? = null
    private var currentProxyCidrs: List<String> = emptyList()

    // JSON 解析器，仅用于诊断信息展示，不参与 VPN 配置或路由决策。
    private val moshi = Moshi.Builder().add(WireJsonAdapterFactory()).build()
    private val adapter = moshi.adapter(NetworkInstanceRunningInfoMap::class.java)

    // 监控任务
    private val monitorRunnable =
            object : Runnable {
                override fun run() {
                    if (isRunning) {
                        monitorNetworkStatus()
                        handler.postDelayed(this, MONITOR_INTERVAL)
                    }
                }
            }

    /** 启动 EasyTier 实例和监控 */
    fun start() {
        if (isRunning) {
            Log.w(TAG, "EasyTier 实例已经在运行中")
            return
        }

        try {
            // 启动 EasyTier 实例
            val result = EasyTierJNI.runNetworkInstance(networkConfig)
            if (result == 0) {
                isRunning = true
                Log.i(TAG, "EasyTier 实例启动成功: $instanceName")

                // 立即请求现有 VpnService 后台入口刷新，并开始周期监控。
                requestVpnRefresh()
                handler.post(monitorRunnable)
            } else {
                Log.e(TAG, "EasyTier 实例启动失败: $result")
                val error = EasyTierJNI.getLastError()
                Log.e(TAG, "错误信息: $error")
            }
        } catch (e: Exception) {
            Log.e(TAG, "启动 EasyTier 实例时发生异常", e)
        }
    }

    /** 停止 EasyTier 实例和监控 */
    fun stop() {
        if (!isRunning) {
            Log.w(TAG, "EasyTier 实例未在运行")
            return
        }

        isRunning = false

        // 停止监控任务
        handler.removeCallbacks(monitorRunnable)

        try {
            // 停止 VpnService；其后台入口负责串行释放本地 FD 借用。
            stopVpnService()

            // 停止 EasyTier 实例
            EasyTierJNI.stopAllInstances()
            Log.i(TAG, "EasyTier 实例已停止: $instanceName")

            // 重置诊断状态
            currentIpv4 = null
            currentProxyCidrs = emptyList()
        } catch (e: Exception) {
            Log.e(TAG, "停止 EasyTier 实例时发生异常", e)
        }
    }

    /**
     * 监控网络状态。
     *
     * 网络信息只用于状态展示/诊断。VPN 配置的权威来源是 Service 后台入口读取的完整
     * MobileTunConfig，本类不根据 proxy CIDR 或 virtual IP 自行生成路由。
     */
    private fun monitorNetworkStatus() {
        updateNetworkDiagnostics()
        requestVpnRefresh()
    }

    private fun updateNetworkDiagnostics() {
        try {
            val infosJson = EasyTierJNI.collectNetworkInfos(10)
            if (infosJson.isNullOrEmpty()) {
                Log.d(TAG, "未获取到网络信息")
                return
            }

            val networkInfoMap = parseNetworkInfo(infosJson)
            val networkInfo = networkInfoMap?.map?.get(instanceName)
            if (networkInfo == null) {
                Log.d(TAG, "未找到实例 $instanceName 的网络信息")
                return
            }

            if (!networkInfo.running) {
                Log.w(TAG, "EasyTier 实例未运行: ${networkInfo.error_msg}")
            }

            currentIpv4 =
                    parseIpv4InetToString(networkInfo.my_node_info?.virtual_ipv4)

            val proxyCidrs = mutableListOf<String>()
            networkInfo.routes?.forEach { route ->
                route.proxy_cidrs?.let { cidrs -> proxyCidrs.addAll(cidrs) }
            }
            currentProxyCidrs = proxyCidrs.toList()
        } catch (e: Exception) {
            // 诊断读取失败不影响 VPN 刷新请求；完整配置读取由 Service 处理。
            Log.e(TAG, "监控网络状态时发生异常", e)
        }
    }

    /** 解析网络信息 JSON */
    private fun parseNetworkInfo(jsonString: String): NetworkInstanceRunningInfoMap? {
        return try {
            adapter.fromJson(jsonString)
        } catch (e: Exception) {
            Log.e(TAG, "解析网络信息失败", e)
            null
        }
    }

    /**
     * 向既有 VpnService 后台入口提交一次刷新意图。
     *
     * 连续意图由 Service 合并为最新值；本方法不读取完整配置、不创建安装线程、
     * 不决定路由或 VPN 重建。
     */
    private fun requestVpnRefresh() {
        try {
            val intent =
                    Intent(activity, EasyTierVpnService::class.java).apply {
                        action = EasyTierVpnService.ACTION_REFRESH
                        putExtra(
                                EasyTierVpnService.EXTRA_INSTANCE_NAME,
                                instanceName
                        )
                    }
            activity.startService(intent)
            Log.d(TAG, "已请求 VpnService 刷新: $instanceName")
        } catch (e: Exception) {
            Log.e(TAG, "请求 VpnService 刷新时发生异常", e)
        }
    }

    /** 停止 VpnService；清理由 Service 的后台执行入口完成。 */
    private fun stopVpnService() {
        try {
            activity.stopService(Intent(activity, EasyTierVpnService::class.java))
            Log.i(TAG, "VpnService 停止请求已提交")
        } catch (e: Exception) {
            Log.e(TAG, "停止 VpnService 时发生异常", e)
        }
    }

    /** 获取当前状态信息 */
    fun getStatus(): EasyTierStatus {
        return EasyTierStatus(
                isRunning = isRunning,
                instanceName = instanceName,
                currentIpv4 = currentIpv4,
                currentProxyCidrs = currentProxyCidrs.toList()
        )
    }

    /** 状态数据类 */
    data class EasyTierStatus(
            val isRunning: Boolean,
            val instanceName: String,
            val currentIpv4: String?,
            val currentProxyCidrs: List<String>
    )
}
