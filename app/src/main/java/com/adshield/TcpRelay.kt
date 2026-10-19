package com.adshield

import java.io.ByteArrayOutputStream

/**
 * Minimal userspace TCP stack for AdShield's surrogate stub IP.
 *
 * Part of v0.7.0 "anti-detect" mode. The VpnService routes the stub IP
 * (10.10.10.3) into the TUN; packets arriving there are owned by the app,
 * so a normal ServerSocket can NOT serve them — this relay implements
 * just enough TCP to complete handshakes, receive one HTTP request and
 * answer it with [StubHttpServer], then close:
 *
 *   SYN -> SYN-ACK (MSS 1400) -> ACK -> data -> response segments -> FIN.
 *
 * Deliberately small: single-threaded use (called from the TUN reader
 * thread), no timers — responses are generated locally and immediately,
 * so retransmission handling is limited to re-ACKing duplicates. Port 80
 * is served; every other port gets a fast RST, matching the old NXDOMAIN
 * fail-fast behaviour for traffic we cannot stub (notably 443/TLS, which
 * cannot be answered without a user-installed CA).
 *
 * Pure JVM (no Android APIs) so the state machine is unit-testable.
 */
class TcpRelay(
    private val stubIp: ByteArray,
    private val onSend: (ByteArray) -> Unit
) {
    private data class Conn(
        var state: Int,
        /** Next sequence number we expect from the client. */
        var cliSeq: Long,
        /** Next sequence number we will send. */
        var srvSeq: Long,
        val rx: ByteArrayOutputStream = ByteArrayOutputStream(),
        var responded: Boolean = false
    )

    private val conns = HashMap<String, Conn>()
    private var isnBase = (System.nanoTime() and 0x00FFFFFF).toInt()
    private var ipId = 0

    companion object {
        private const val ST_SYN_RCVD = 1
        private const val ST_EST = 2
        private const val ST_FIN_SENT = 3

        /** We advertise a small MSS so responses never need fragmentation. */
        private const val MSS = 1400

        private const val F_FIN = 0x01
        private const val F_SYN = 0x02
        private const val F_RST = 0x04
        private const val F_PSH = 0x08
        private const val F_ACK = 0x10

        /**
         * True if [packet] is an IPv4/TCP packet addressed to [stubIp].
         * The VpnService uses this to decide whether the packet belongs to
         * this relay (anything else keeps the old drop behaviour).
         */
        fun isStubTcp(packet: ByteArray, stubIp: ByteArray): Boolean {
            if (packet.size < 40) return false
            if ((packet[0].toInt() shr 4) != 4) return false // IPv4
            val ihl = (packet[0].toInt() and 0x0F) * 4
            if (ihl < 20 || packet.size < ihl + 20) return false
            if ((packet[9].toInt() and 0xFF) != 6) return false // TCP
            for (i in 0..3) if (packet[16 + i] != stubIp[i]) return false
            return true
        }
    }

    /** Handles one IPv4/TCP packet already verified by [isStubTcp]. */
    fun handlePacket(packet: ByteArray) {
        val ihl = (packet[0].toInt() and 0x0F) * 4
        val srcIp = packet.copyOfRange(12, 16)
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
        val key = ipKey(srcIp) + ":" + srcPort

        // Only the stub web port is served. Everything else (443/TLS, …)
        // gets a fast RST — same fail-fast outcome NXDOMAIN gave.
        if (dstPort != 80) {
            var ackNum = seq + payloadLen
            if (flags and F_SYN != 0) ackNum += 1
            if (flags and F_FIN != 0) ackNum += 1
            sendRst(srcIp, srcPort, ackNum)
            return
        }

        if (flags and F_RST != 0) {
            conns.remove(key)
            return
        }

        // (Re)transmitted SYN: (re)open the connection and answer SYN-ACK.
        if (flags and F_SYN != 0) {
            val isn = nextIsn()
            val c = Conn(ST_SYN_RCVD, seq + 1, isn)
            conns[key] = c
            sendSynAck(srcIp, srcPort, isn, seq + 1)
            c.srvSeq += 1 // SYN consumes one sequence number
            return
        }

        val c = conns[key] ?: run {
            sendRst(srcIp, srcPort, seq + payloadLen)
            return
        }

        when (c.state) {
            ST_SYN_RCVD -> {
                // Handshake completes on the client's ACK of our SYN; fall
                // through so a piggybacked first data segment is processed.
                if (flags and F_ACK != 0 && ack == c.srvSeq) c.state = ST_EST
                else return
            }
            ST_FIN_SENT -> {
                if (flags and F_ACK != 0 && ack == c.srvSeq) conns.remove(key)
                return
            }
        }

        // --- ESTABLISHED ---
        if (seq != c.cliSeq) {
            // Duplicate / out-of-order: just re-announce what we expect.
            sendAck(srcIp, srcPort, c)
            return
        }
        var advanced = false
        if (payloadLen > 0) {
            c.rx.write(packet, payloadStart, payloadLen)
            c.cliSeq += payloadLen
            advanced = true
        }
        if (flags and F_FIN != 0) {
            c.cliSeq += 1
            advanced = true
        }
        if (!advanced) return
        if (!c.responded) {
            tryRespond(srcIp, srcPort, c)
        } else {
            sendAck(srcIp, srcPort, c)
        }
    }

    private fun tryRespond(srcIp: ByteArray, srcPort: Int, c: Conn) {
        val buffered = c.rx.toByteArray()
        if (!StubHttpServer.hasFullHead(buffered)) {
            // Request head not complete yet — ACK and wait for more.
            sendAck(srcIp, srcPort, c)
            return
        }
        val req = StubHttpServer.parseRequest(buffered)
        val body = if (req != null) StubHttpServer.buildResponse(req.first, req.second)
        else StubHttpServer.badRequest()
        c.responded = true
        var off = 0
        while (off < body.size) {
            val n = minOf(MSS, body.size - off)
            sendSegment(srcIp, srcPort, c.srvSeq, c.cliSeq,
                F_ACK or F_PSH, body.copyOfRange(off, off + n))
            c.srvSeq += n
            off += n
        }
        // Response is complete; half-close our side. The client's final
        // ACK moves the connection to cleanup (ST_FIN_SENT).
        sendSegment(srcIp, srcPort, c.srvSeq, c.cliSeq, F_ACK or F_FIN, ByteArray(0))
        c.srvSeq += 1
        c.state = ST_FIN_SENT
    }

    private fun sendAck(dstIp: ByteArray, dstPort: Int, c: Conn) {
        sendSegment(dstIp, dstPort, c.srvSeq, c.cliSeq, F_ACK, ByteArray(0))
    }

    private fun sendRst(dstIp: ByteArray, dstPort: Int, ackNum: Long) {
        // RST+ACK with seq 0: accepted by peers for an unknown connection.
        sendSegment(dstIp, dstPort, 0, ackNum, F_RST or F_ACK, ByteArray(0))
    }

    private fun sendSynAck(dstIp: ByteArray, dstPort: Int, seq: Long, ackNum: Long) {
        sendSegment(dstIp, dstPort, seq, ackNum, F_SYN or F_ACK, ByteArray(0), withMss = true)
    }

    private fun sendSegment(
        dstIp: ByteArray,
        dstPort: Int,
        seq: Long,
        ackNum: Long,
        flags: Int,
        payload: ByteArray,
        withMss: Boolean = false
    ) {
        val tcpLen = 20 + if (withMss) 4 else 0
        val total = 20 + tcpLen + payload.size
        val p = ByteArray(total)
        // IPv4 header.
        p[0] = 0x45
        p[1] = 0
        put16(p, 2, total)
        put16(p, 4, nextIpId())
        put16(p, 6, 0x4000) // DF — we size segments to avoid fragmentation
        p[8] = 64 // TTL
        p[9] = 6 // TCP
        System.arraycopy(stubIp, 0, p, 12, 4)
        System.arraycopy(dstIp, 0, p, 16, 4)
        put16(p, 10, ipChecksum(p))
        // TCP header.
        val t = 20
        put16(p, t, 80)
        put16(p, t + 2, dstPort)
        put32(p, t + 4, seq)
        put32(p, t + 8, ackNum)
        p[t + 12] = ((tcpLen / 4) shl 4).toByte()
        p[t + 13] = flags.toByte()
        put16(p, t + 14, 65535) // window
        put16(p, t + 16, 0) // checksum filled below
        put16(p, t + 18, 0) // urgent pointer
        if (withMss) {
            p[t + 20] = 2 // MSS option
            p[t + 21] = 4
            put16(p, t + 22, MSS)
        }
        System.arraycopy(payload, 0, p, 20 + tcpLen, payload.size)
        put16(p, t + 16, tcpChecksum(stubIp, dstIp, p.copyOfRange(20, total)))
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
        sum += 6 // protocol: TCP
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
