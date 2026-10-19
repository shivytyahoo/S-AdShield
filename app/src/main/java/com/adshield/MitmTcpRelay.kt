package com.adshield

import java.io.ByteArrayOutputStream

/**
 * Userspace TCP for the HTTPS path-filter MITM addresses (v0.8.0).
 *
 * Like [TcpRelay], but full-duplex: after the handshake each connection
 * owns a [MitmSession] (TLS or plaintext HTTP) that consumes client bytes
 * and produces response bytes over the connection's lifetime, instead of
 * the single request->response->close pattern of the surrogate stubs.
 *
 * Only the configured MITM IPs are served (port 443 = TLS MITM, port 80 =
 * plaintext path filter); every other port gets a fast RST.
 *
 * Single-threaded use (called from the TUN reader thread). Session work
 * itself runs on the session's own threads.
 */
class MitmTcpRelay(
    /** MITM IP string ("10.10.10.4") -> domain it stands in for. */
    private val ipToHost: Map<String, String>,
    private val openSession: (
        host: String,
        port: Int,
        onSendToClient: (ByteArray) -> Unit,
        onClose: () -> Unit
    ) -> MitmSession,
    private val onSend: (ByteArray) -> Unit
) {
    private data class Conn(
        var state: Int,
        var cliSeq: Long,
        var srvSeq: Long,
        var session: MitmSession?,
        val dstIpStr: String,
        val localPort: Int
    )

    private val conns = HashMap<String, Conn>()
    private var isnBase = (System.nanoTime() and 0x00FFFFFF).toInt()
    private var ipId = 0

    companion object {
        private const val ST_SYN_RCVD = 1
        private const val ST_EST = 2
        private const val ST_FIN_SENT = 3
        private const val MSS = 1400

        private const val F_FIN = 0x01
        private const val F_SYN = 0x02
        private const val F_RST = 0x04
        private const val F_PSH = 0x08
        private const val F_ACK = 0x10

        /** True if [packet] is IPv4/TCP addressed to one of [mitmIps]. */
        fun isMitmTcp(packet: ByteArray, mitmIps: Set<ByteArray>): Boolean {
            if (packet.size < 40) return false
            if ((packet[0].toInt() shr 4) != 4) return false
            val ihl = (packet[0].toInt() and 0x0F) * 4
            if (ihl < 20 || packet.size < ihl + 20) return false
            if ((packet[9].toInt() and 0xFF) != 6) return false
            for (ip in mitmIps) {
                var match = true
                for (i in 0..3) if (packet[16 + i] != ip[i]) { match = false; break }
                if (match) return true
            }
            return false
        }
    }

    fun handlePacket(packet: ByteArray) {
        val ihl = (packet[0].toInt() and 0x0F) * 4
        val srcIp = packet.copyOfRange(12, 16)
        val dstIp = packet.copyOfRange(16, 20)
        val dstIpStr = ipKey(dstIp)
        val host = ipToHost[dstIpStr] ?: return
        val t = ihl
        val srcPort = u16(packet, t)
        val dstPort = u16(packet, t + 2)
        val seq = u32(packet, t + 4)
        val ack = u32(packet, t + 8)
        val dataOff = ((packet[t + 12].toInt() and 0xFF) shr 4) * 4
        if (dataOff < 20) return
        val flags = packet[t + 13].toInt() and 0xFF
        val payloadStart = t + dataOff
        if (payloadStart > packet.size) return
        val payloadLen = packet.size - payloadStart
        val key = "$dstIpStr:${ipKey(srcIp)}:$srcPort"

        if (dstPort != 443 && dstPort != 80) {
            var ackNum = seq + payloadLen
            if (flags and F_SYN != 0) ackNum += 1
            if (flags and F_FIN != 0) ackNum += 1
            sendRst(srcIp, srcPort, dstIp, dstPort, ackNum)
            return
        }
        if (flags and F_RST != 0) {
            conns.remove(key)?.session?.close()
            return
        }
        if (flags and F_SYN != 0) {
            conns.remove(key)?.session?.close()
            val isn = nextIsn()
            val c = Conn(ST_SYN_RCVD, seq + 1, isn, null, dstIpStr, dstPort)
            conns[key] = c
            MitmDebug.log("MitmTcpRelay: SYN $dstIpStr:$dstPort <- ${ipKey(srcIp)}:$srcPort, sending SYN-ACK")
            sendSynAck(srcIp, srcPort, dstIp, dstPort, isn, seq + 1)
            c.srvSeq += 1
            return
        }
        val c = conns[key] ?: run {
            sendRst(srcIp, srcPort, dstIp, dstPort, seq + payloadLen)
            return
        }
        when (c.state) {
            ST_SYN_RCVD -> {
                if (flags and F_ACK != 0 && ack == c.srvSeq) {
                    c.state = ST_EST
                    MitmDebug.log("MitmTcpRelay: handshake complete for $host:$dstPort, creating session")
                    // Handshake done: spin up the MITM session now.
                    val session = try {
                        openSession(
                            host, dstPort,
                            { bytes -> sendAppData(c, srcIp, srcPort, dstIp, bytes) },
                            { requestFin(c, srcIp, srcPort, dstIp) }
                        )
                    } catch (e: Exception) {
                        MitmDebug.log("MitmTcpRelay: openSession failed: ${e.message}")
                        null
                    }
                    if (session == null) {
                        sendRst(srcIp, srcPort, dstIp, c.localPort, c.cliSeq)
                        conns.remove(key)
                        return
                    }
                    c.session = session
                    session.start()
                } else return
            }
            ST_FIN_SENT -> {
                if (flags and F_ACK != 0 && ack == c.srvSeq) {
                    c.session?.close()
                    conns.remove(key)
                }
                return
            }
        }

        // --- ESTABLISHED ---
        if (seq != c.cliSeq) {
            sendAck(c, srcIp, srcPort, dstIp)
            return
        }
        var advanced = false
        if (payloadLen > 0) {
            c.session?.feedFromClient(packet.copyOfRange(payloadStart, packet.size))
            c.cliSeq += payloadLen
            advanced = true
        }
        if (flags and F_FIN != 0) {
            c.cliSeq += 1
            advanced = true
            // Client half-closed: ACK it, end the session, FIN our side.
            sendAck(c, srcIp, srcPort, dstIp)
            c.session?.close()
            c.session = null
            sendFin(c, srcIp, srcPort, dstIp)
            c.state = ST_FIN_SENT
            return
        }
        if (advanced) sendAck(c, srcIp, srcPort, dstIp)
    }

    /** Session asked to close (upstream EOF / stub done): FIN the client. */
    private fun requestFin(c: Conn, srcIp: ByteArray, srcPort: Int, dstIp: ByteArray) {
        if (c.state != ST_EST) return
        c.session = null
        sendFin(c, srcIp, srcPort, dstIp)
        c.state = ST_FIN_SENT
    }

    private fun sendAppData(c: Conn, srcIp: ByteArray, srcPort: Int, dstIp: ByteArray, data: ByteArray) {
        if (c.state != ST_EST || data.isEmpty()) return
        var off = 0
        while (off < data.size) {
            val n = minOf(MSS, data.size - off)
            sendSegment(dstIp, srcIp, srcPort, c.localPort, c.srvSeq, c.cliSeq,
                F_ACK or F_PSH, data.copyOfRange(off, off + n))
            c.srvSeq += n
            off += n
        }
    }

    private fun sendAck(c: Conn, srcIp: ByteArray, srcPort: Int, dstIp: ByteArray) {
        sendSegment(dstIp, srcIp, srcPort, c.localPort, c.srvSeq, c.cliSeq, F_ACK, ByteArray(0))
    }

    private fun sendFin(c: Conn, srcIp: ByteArray, srcPort: Int, dstIp: ByteArray) {
        sendSegment(dstIp, srcIp, srcPort, c.localPort, c.srvSeq, c.cliSeq, F_ACK or F_FIN, ByteArray(0))
        c.srvSeq += 1
    }

    private fun sendRst(srcIp: ByteArray, srcPort: Int, dstIp: ByteArray, srcPortLocal: Int, ackNum: Long) {
        sendSegment(dstIp, srcIp, srcPort, srcPortLocal, 0, ackNum, F_RST or F_ACK, ByteArray(0))
    }

    private fun sendSynAck(srcIp: ByteArray, srcPort: Int, dstIp: ByteArray, localPort: Int, seq: Long, ackNum: Long) {
        sendSegment(dstIp, srcIp, srcPort, localPort, seq, ackNum, F_SYN or F_ACK, ByteArray(0), withMss = true)
    }

    private fun sendSegment(
        srcIp: ByteArray, dstIp: ByteArray, dstPort: Int, srcPort: Int,
        seq: Long, ackNum: Long, flags: Int, payload: ByteArray,
        withMss: Boolean = false
    ) {
        val tcpLen = 20 + if (withMss) 4 else 0
        val total = 20 + tcpLen + payload.size
        val p = ByteArray(total)
        p[0] = 0x45
        p[1] = 0
        put16(p, 2, total)
        put16(p, 4, nextIpId())
        put16(p, 6, 0x4000)
        p[8] = 64
        p[9] = 6
        System.arraycopy(srcIp, 0, p, 12, 4)
        System.arraycopy(dstIp, 0, p, 16, 4)
        put16(p, 10, ipChecksum(p))
        val t = 20
        put16(p, t, srcPort)
        put16(p, t + 2, dstPort)
        put32(p, t + 4, seq)
        put32(p, t + 8, ackNum)
        p[t + 12] = ((tcpLen / 4) shl 4).toByte()
        p[t + 13] = flags.toByte()
        put16(p, t + 14, 65535)
        put16(p, t + 16, 0)
        put16(p, t + 18, 0)
        if (withMss) {
            p[t + 20] = 2
            p[t + 21] = 4
            put16(p, t + 22, MSS)
        }
        System.arraycopy(payload, 0, p, 20 + tcpLen, payload.size)
        put16(p, t + 16, tcpChecksum(srcIp, dstIp, p.copyOfRange(20, total)))
        onSend(p)
    }

    private fun nextIsn(): Long = ((isnBase++).toLong() and 0xFFFFFFFFL)
    private fun nextIpId(): Int { ipId = (ipId + 1) and 0xFFFF; return ipId }

    private fun ipKey(ip: ByteArray): String =
        "${ip[0].toInt() and 0xFF}.${ip[1].toInt() and 0xFF}." +
            "${ip[2].toInt() and 0xFF}.${ip[3].toInt() and 0xFF}"

    private fun u16(b: ByteArray, o: Int): Int =
        ((b[o].toInt() and 0xFF) shl 8) or (b[o + 1].toInt() and 0xFF)

    private fun u32(b: ByteArray, o: Int): Long =
        ((b[o].toLong() and 0xFF) shl 24) or ((b[o + 1].toLong() and 0xFF) shl 16) or
            ((b[o + 2].toLong() and 0xFF) shl 8) or (b[o + 3].toLong() and 0xFF)

    private fun put16(b: ByteArray, o: Int, v: Int) {
        b[o] = ((v shr 8) and 0xFF).toByte()
        b[o + 1] = (v and 0xFF).toByte()
    }

    private fun put32(b: ByteArray, o: Int, v: Long) {
        b[o] = ((v shr 24) and 0xFF).toByte()
        b[o + 1] = ((v shr 16) and 0xFF).toByte()
        b[o + 2] = ((v shr 8) and 0xFF).toByte()
        b[o + 3] = (v and 0xFF).toByte()
    }

    private fun ipChecksum(header: ByteArray): Int {
        var sum = 0
        var i = 0
        while (i < 20) {
            if (i != 10) sum += u16(header, i)
            i += 2
        }
        while ((sum ushr 16) != 0) sum = (sum and 0xFFFF) + (sum ushr 16)
        return sum.inv() and 0xFFFF
    }

    private fun tcpChecksum(srcIp: ByteArray, dstIp: ByteArray, tcp: ByteArray): Int {
        var sum = 0
        for (i in 0..3 step 2) sum += u16(srcIp, i)
        for (i in 0..3 step 2) sum += u16(dstIp, i)
        sum += 6
        sum += tcp.size
        var i = 0
        while (i + 1 < tcp.size) {
            sum += u16(tcp, i)
            i += 2
        }
        if (i < tcp.size) sum += (tcp[i].toInt() and 0xFF) shl 8
        while ((sum ushr 16) != 0) sum = (sum and 0xFFFF) + (sum ushr 16)
        return sum.inv() and 0xFFFF
    }
}
