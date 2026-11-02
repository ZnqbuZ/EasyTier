package com.easytier.jni

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import org.json.JSONObject
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/**
 * 示例 Android VPN owner。
 *
 * 所有 MobileTunConfig 读取、系统 VPN 建立、setTunFd 和本地 detach 都在同一个后台
 * 执行器中串行完成。onStartCommand/onDestroy 只提交意图，不阻塞主线程，也不会在
 * setTunFd 尚未结束时提前关闭仍被 Native 借用的 FD。
 */
class EasyTierVpnService : VpnService() {

    companion object {
        const val ACTION_REFRESH = "com.easytier.jni.action.REFRESH"
        const val EXTRA_INSTANCE_NAME = "instance_name"
        private const val TAG = "EasyTierVpnService"
    }

    private val worker: ExecutorService = Executors.newSingleThreadExecutor()
    private val stateLock = Any()

    private var vpnInterface: ParcelFileDescriptor? = null
    private var instanceName: String? = null
    private var attachedInstanceName: String? = null
    private var attachedSnapshotId: String? = null
    private var refreshPending = false
    private var refreshWorkerScheduled = false
    private var stopping = false
    private var cleanupScheduled = false

    override fun onCreate() {
        super.onCreate()
        Log.d(TAG, "VPN Service created")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val requestedName = intent?.getStringExtra(EXTRA_INSTANCE_NAME)
        if (!requestedName.isNullOrEmpty()) {
            synchronized(stateLock) { instanceName = requestedName }
        }

        val currentName = synchronized(stateLock) { instanceName }
        if (currentName.isNullOrEmpty()) {
            Log.e(TAG, "Missing EasyTier instance name")
            stopSelf()
            return START_NOT_STICKY
        }
        if (isStopping()) {
            return START_NOT_STICKY
        }

        // Main thread only records the refresh intent. The single worker below
        // reads the complete configuration and performs the local FD work.
        requestRefresh()
        return START_STICKY
    }

    private fun requestRefresh() {
        var scheduleWorker = false
        synchronized(stateLock) {
            if (!stopping) {
                refreshPending = true
                if (!refreshWorkerScheduled) {
                    refreshWorkerScheduled = true
                    scheduleWorker = true
                }
            }
        }
        if (scheduleWorker) {
            submit { drainRefreshRequests() }
        }
    }

    private fun drainRefreshRequests() {
        while (true) {
            val name =
                    synchronized(stateLock) {
                        if (stopping || !refreshPending) {
                            refreshWorkerScheduled = false
                            null
                        } else {
                            refreshPending = false
                            instanceName
                        }
                    }
            if (name.isNullOrEmpty()) {
                return
            }
            refreshVpn(name)
        }
    }

    /**
     * Read the complete MobileTunConfig and apply it to the service-owned VPN.
     * No route selection or member admission happens here.
     */
    private fun refreshVpn(name: String) {
        if (isStopping()) {
            return
        }

        val configJson =
                try {
                    EasyTierJNI.getMobileTunConfig(name)
                } catch (error: Throwable) {
                    // A configuration read failure is not an empty target. Keep
                    // the current VPN and let the next refresh retry.
                    Log.e(TAG, "读取完整 VPN 配置失败", error)
                    return
                }
        if (isStopping()) {
            return
        }

        val config =
                try {
                    JSONObject(configJson)
                } catch (error: Throwable) {
                    Log.e(TAG, "解析完整 VPN 配置失败", error)
                    return
                }

        val snapshotId = config.optString("snapshot_id", "")
        if (snapshotId.isEmpty()) {
            Log.e(TAG, "完整 VPN 配置缺少 snapshot_id")
            return
        }

        val addresses =
                try {
                    readStringArray(config, "addresses")
                } catch (error: Throwable) {
                    Log.e(TAG, "解析 VPN addresses 失败", error)
                    return
                }
        val routes =
                try {
                    readStringArray(config, "routes")
                } catch (error: Throwable) {
                    Log.e(TAG, "解析 VPN routes 失败", error)
                    return
                }
        val dns =
                if (config.isNull("dns")) {
                    null
                } else {
                    config.optString("dns", "").ifEmpty { null }
                }
        logRejectedMembers(config)

        if (addresses.isEmpty()) {
            Log.i(TAG, "完整配置没有可用地址，关闭当前 VPN")
            closeCurrentVpn()
            return
        }

        if (vpnInterface != null &&
                attachedInstanceName == name &&
                attachedSnapshotId == snapshotId) {
            Log.d(TAG, "完整配置未变化，保留当前 VPN: $snapshotId")
            return
        }

        // Rebuild only after the previous local FD borrow has been released.
        if (vpnInterface != null) {
            closeCurrentVpn()
        }
        if (isStopping()) {
            return
        }

        val builder =
                Builder()
                        .setSession("EasyTier VPN")
                        .addDisallowedApplication("com.easytier.easytiervpn")
        try {
            // Apply the Controller's complete table exactly as returned.
            addresses.forEach { address ->
                val (ip, prefix) = parseCidr(address)
                builder.addAddress(ip, prefix)
            }
            routes.forEach { route ->
                val (ip, prefix) = parseCidr(route)
                builder.addRoute(ip, prefix)
            }
            dns?.let { builder.addDnsServer(it) }
        } catch (error: Throwable) {
            Log.e(TAG, "构建系统 VPN 配置失败", error)
            return
        }

        val newInterface =
                try {
                    builder.establish()
                } catch (error: Throwable) {
                    Log.e(TAG, "创建 VPN 接口失败", error)
                    null
                }
        if (newInterface == null) {
            Log.e(TAG, "创建 VPN 接口失败")
            return
        }
        if (isStopping()) {
            newInterface.close()
            return
        }

        val result =
                try {
                    EasyTierJNI.setTunFd(name, newInterface.fd, snapshotId)
                } catch (error: Throwable) {
                    Log.e(TAG, "本地 TUN 接入失败", error)
                    newInterface.close()
                    return
                }
        if (result != 0) {
            Log.e(TAG, "本地 TUN 接入失败: $result")
            newInterface.close()
            return
        }

        if (isStopping()) {
            // setTunFd really succeeded while stop was requested. Release the
            // new borrow before closing the interface; cleanup will run later
            // on this same serial worker.
            releaseTunFd(name)
            newInterface.close()
            return
        }

        vpnInterface = newInterface
        attachedInstanceName = name
        attachedSnapshotId = snapshotId
        Log.i(
                TAG,
                "VPN 已应用完整配置: snapshot=$snapshotId addresses=$addresses routes=$routes dns=$dns"
        )
    }

    private fun releaseTunFd(name: String) {
        try {
            EasyTierJNI.setTunFd(name, 0, null)
        } catch (error: Throwable) {
            Log.w(TAG, "TUN detach failed", error)
        }
    }

    private fun closeCurrentVpn() {
        val name =
                attachedInstanceName
                        ?: synchronized(stateLock) { instanceName }
        if (name != null) {
            releaseTunFd(name)
        }
        vpnInterface?.close()
        vpnInterface = null
        attachedInstanceName = null
        attachedSnapshotId = null
    }

    private fun readStringArray(config: JSONObject, key: String): List<String> {
        val values = config.optJSONArray(key) ?: return emptyList()
        return (0 until values.length()).map { index -> values.getString(index) }
    }

    private fun logRejectedMembers(config: JSONObject) {
        val rejected = config.optJSONArray("rejected") ?: return
        for (index in 0 until rejected.length()) {
            val item = rejected.optJSONObject(index) ?: continue
            Log.w(
                    TAG,
                    "Controller rejected ${item.optString("instance_id")}: ${item.optString("error")}"
            )
        }
    }

    /** 解析 CIDR，返回 IP 和网络长度 */
    private fun parseCidr(cidr: String): Pair<String, Int> {
        val parts = cidr.split("/")
        if (parts.size != 2) {
            throw IllegalArgumentException("无效的 CIDR 格式: $cidr")
        }
        return Pair(parts[0], parts[1].toInt())
    }

    private fun isStopping(): Boolean = synchronized(stateLock) { stopping }

    private fun requestStop() {
        var scheduleCleanup = false
        synchronized(stateLock) {
            stopping = true
            refreshPending = false
            if (!cleanupScheduled) {
                cleanupScheduled = true
                scheduleCleanup = true
            }
        }
        if (scheduleCleanup) {
            submit { closeCurrentVpn() }
        }
    }

    private fun submit(task: () -> Unit) {
        try {
            worker.execute(Runnable { task() })
        } catch (error: RuntimeException) {
            Log.w(TAG, "VPN worker is already closed", error)
        }
    }

    override fun onRevoke() {
        Log.w(TAG, "VPN permission revoked")
        requestStop()
        stopSelf()
        super.onRevoke()
    }

    override fun onDestroy() {
        Log.d(TAG, "VPN Service destroyed")
        // Do not close the borrowed FD on the main thread. The queued cleanup
        // runs after any in-flight setTunFd on the serial worker.
        requestStop()
        worker.shutdown()
        super.onDestroy()
    }
}
