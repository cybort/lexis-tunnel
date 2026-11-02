package lexis

import android.content.Intent
import android.content.pm.PackageManager
import android.net.IpPrefix
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import kotlin.concurrent.thread

/**
 * Source only. This file is not an APK, and Termux cannot pop the system VPN consent.
 * IP packets are framed as uint16be length || packet to 127.0.0.1:17891.
 */
class LexisVpnService : VpnService() {
    private var tun: ParcelFileDescriptor? = null
    @Volatile private var running = false

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (running) return START_STICKY
        val builder = Builder()
            .setSession("词隙")
            .setMtu(intent?.getIntExtra("mtu", 1500) ?: 1500)
            .addAddress(intent?.getStringExtra("address") ?: "10.7.0.2", 32)
            .addDnsServer(intent?.getStringExtra("dns") ?: "1.1.1.1")
            .addRoute("0.0.0.0", 0)
        // Without this the agent's own tunnel connection to the gate is captured by
        // 0.0.0.0/0, comes back through 127.0.0.1:17891 and loops. Keep this app and the
        // app hosting lexis-agent.mjs (Termux by default) outside the VPN.
        val disallowed = (intent?.getStringArrayExtra("disallowedApps") ?: arrayOf("com.termux")) + packageName
        for (pkg in disallowed.distinct()) {
            try {
                builder.addDisallowedApplication(pkg)
            } catch (_: PackageManager.NameNotFoundException) {
                // Not installed on this device; nothing to exclude.
            }
        }
        // Gate endpoints (IPv4 "a.b.c.d" or "a.b.c.d/n") are also routed outside the VPN on API 33+.
        if (Build.VERSION.SDK_INT >= 33) {
            for (item in intent?.getStringArrayExtra("excludeRoutes") ?: emptyArray()) {
                val parts = item.split("/")
                try {
                    builder.excludeRoute(IpPrefix(InetAddress.getByName(parts[0]), parts.getOrNull(1)?.toInt() ?: 32))
                } catch (_: Exception) {
                    // Ignore malformed entries.
                }
            }
        }
        val iface = builder.establish() ?: return START_NOT_STICKY
        tun = iface
        running = true
        thread(name = "lexis-vpn") { pump(iface) }
        return START_STICKY
    }

    override fun onRevoke() {
        running = false
        tun?.close()
        stopSelf()
    }

    private fun pump(iface: ParcelFileDescriptor) {
        val input = ParcelFileDescriptor.AutoCloseInputStream(iface)
        val output = ParcelFileDescriptor.AutoCloseOutputStream(iface)
        val socket = Socket()
        socket.connect(InetSocketAddress("127.0.0.1", 17891), 4000)
        val remoteIn = DataInputStream(socket.getInputStream())
        val remoteOut = DataOutputStream(socket.getOutputStream())
        thread(name = "lexis-vpn-back") {
            val back = ByteArray(65535)
            while (running) {
                val size = remoteIn.readUnsignedShort()
                if (size <= 0 || size > back.size) break
                remoteIn.readFully(back, 0, size)
                output.write(back, 0, size)
            }
        }
        val packet = ByteArray(65535)
        while (running) {
            val n = input.read(packet)
            if (n <= 0) break
            remoteOut.writeShort(n)
            remoteOut.write(packet, 0, n)
            remoteOut.flush()
        }
        running = false
        socket.close()
    }
}
