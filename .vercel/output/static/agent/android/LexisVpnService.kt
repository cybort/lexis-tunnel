package lexis

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import java.io.DataInputStream
import java.io.DataOutputStream
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
