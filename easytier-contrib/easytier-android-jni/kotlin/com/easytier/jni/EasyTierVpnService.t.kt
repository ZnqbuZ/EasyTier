package com.easytier.jni

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import org.json.JSONObject
import kotlin.concurrent.thread

class EasyTierVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private var isRunning = false
    private var instanceName: String? = null

    companion object {
        private const val TAG = "EasyTierVpnService"
    }

    override fun onCreate() {
        super.onCreate()
        Log.d(TAG, "VPN Service created")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        instanceName = intent?.getStringExtra("instance_name")
        if (instanceName.isNullOrEmpty()) {
            Log.e(TAG, "Missing EasyTier instance name")
            stopSelf()
            return START_NOT_STICKY
        }

        thread {
            try {
                setupVpnInterface()
            } catch (t: Throwable) {
                Log.e(TAG, "VPN 设置失败", t)
                stopSelf()
            }
        }

        return START_STICKY
    }

    private fun setupVpnInterface() {
        try {
            val name = requireNotNull(instanceName)
            val config = JSONObject(EasyTierJNI.getMobileTunConfig(name))
            val snapshotId = config.getString("snapshot_id")
            val builder = Builder().setSession("EasyTier VPN")
                    .addDisallowedApplication("com.easytier.easytiervpn")
            val addresses = config.getJSONArray("addresses")
            for (index in 0 until addresses.length()) {
                val (ip, length) = parseCidr(addresses.getString(index))
                builder.addAddress(ip, length)
            }
            val routes = config.getJSONArray("routes")
            for (index in 0 until routes.length()) {
                val (ip, length) = parseCidr(routes.getString(index))
                builder.addRoute(ip, length)
            }
            if (!config.isNull("dns")) builder.addDnsServer(config.getString("dns"))

            // 3. 构建虚拟网络接口
            vpnInterface = builder.establish()

            if (vpnInterface == null) {
                Log.e(TAG, "创建 VPN 接口失败")
                return
            }

            Log.i(TAG, "VPN 接口创建成功")

            // 4. 将 TUN 文件描述符传递给 EasyTier
            instanceName?.let { name ->
                val fd = vpnInterface!!.fd
                val result = EasyTierJNI.setTunFd(name, fd, snapshotId)
                if (result == 0) {
                    Log.i(TAG, "TUN 文件描述符设置成功: $fd")
                } else {
                    Log.e(TAG, "TUN 文件描述符设置失败: $result")
                }
            }

            isRunning = true

            // 5. 保持服务运行
            while (isRunning && vpnInterface != null) {
                Thread.sleep(1000)
            }
        } catch (t: Throwable) {
            Log.e(TAG, "VPN 接口设置过程中发生错误", t)
        } finally {
            cleanup()
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

    private fun cleanup() {
        isRunning = false
        instanceName?.let { name ->
            try { EasyTierJNI.setTunFd(name, 0, "") } catch (error: Exception) { Log.w(TAG, "TUN detach failed", error) }
        }
        vpnInterface?.close()
        vpnInterface = null
        Log.i(TAG, "VPN 接口已清理")
    }

    override fun onDestroy() {
        super.onDestroy()
        Log.d(TAG, "VPN Service destroyed")
        cleanup()
    }
}
