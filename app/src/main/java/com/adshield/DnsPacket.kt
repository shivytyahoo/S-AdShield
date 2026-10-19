package com.adshield

import java.nio.ByteBuffer
import java.nio.ByteOrder

data class DnsQuestion(val name: String, val qType: Int, val qClass: Int)

object DnsPacket {
    fun parseQuestion(packet: ByteArray, length: Int): DnsQuestion? {
        if (length < 12) return null
        var p = 12
        val labels = ArrayList<String>()
        while (p < length) {
            val n = packet[p].toInt() and 0xff
            p++
            if (n == 0) break
            if (n > 63 || p + n > length) return null
            labels += String(packet, p, n, Charsets.US_ASCII)
            p += n
        }
        if (p + 4 > length) return null
        val type = ((packet[p].toInt() and 0xff) shl 8) or (packet[p+1].toInt() and 0xff)
        val clazz = ((packet[p+2].toInt() and 0xff) shl 8) or (packet[p+3].toInt() and 0xff)
        return DnsQuestion(labels.joinToString("."), type, clazz)
    }

    fun blockedResponse(query: ByteArray, length: Int): ByteArray {
        // DNS response with NXDOMAIN (RCODE=3), preserving transaction ID.
        val out = query.copyOf(length)
        out[2] = ((out[2].toInt() or 0x80) and 0xff).toByte()
        out[3] = ((out[3].toInt() and 0xF0) or 0x03).toByte()
        // Clear answer/authority/additional counts.
        for (i in 6 until 12) out[i] = 0
        return out
    }

    /**
     * Surrogate answer (v0.7.0 "anti-detect" mode): NOERROR with a single A
     * record pointing at AdShield's local stub web server ([stubIp]).
     *
     * Why: most "Ad blocker detected" walls fire because a bait request
     * (ad pixel / ad script / tracking pixel) *fails* — with NXDOMAIN the
     * browser reports a network error and the site's detection script shows
     * the wall. Answering with the stub IP lets the request *succeed*
     * against a local server that returns an empty-but-valid response
     * (1x1 image, empty JS, blank page), exactly like uBlock Origin's
     * `$redirect` / surrogate resources — so the detection never fires,
     * while no real ad is ever fetched or displayed.
     */
    fun surrogateResponse(
        query: ByteArray,
        length: Int,
        stubIp: ByteArray = byteArrayOf(10, 10, 10, 3)
    ): ByteArray {
        require(stubIp.size == 4) { "stub IP must be IPv4" }
        val out = query.copyOf(length)
        out[2] = ((out[2].toInt() or 0x80) and 0xff).toByte() // QR = 1
        out[3] = ((out[3].toInt() and 0xF0) and 0xff).toByte() // RCODE = 0 (NOERROR)
        // ANCOUNT = 1, NSCOUNT = 0, ARCOUNT = 0.
        out[6] = 0; out[7] = 1
        out[8] = 0; out[9] = 0
        out[10] = 0; out[11] = 0
        // Answer: NAME = pointer to the question name, TYPE A, CLASS IN,
        // TTL 60s, RDLENGTH 4, RDATA = stub IP.
        val answer = ByteArray(16)
        answer[0] = 0xC0.toByte(); answer[1] = 0x0C
        answer[2] = 0; answer[3] = 1
        answer[4] = 0; answer[5] = 1
        answer[6] = 0; answer[7] = 0; answer[8] = 0; answer[9] = 60
        answer[10] = 0; answer[11] = 4
        System.arraycopy(stubIp, 0, answer, 12, 4)
        return out + answer
    }

    /**
     * NOERROR with zero answers. Used for AAAA queries on blocked domains
     * while surrogate mode is on: it nudges dual-stack clients onto IPv4,
     * where the stub server can actually answer.
     */
    fun emptyResponse(query: ByteArray, length: Int): ByteArray {
        val out = query.copyOf(length)
        out[2] = ((out[2].toInt() or 0x80) and 0xff).toByte()
        out[3] = ((out[3].toInt() and 0xF0) and 0xff).toByte()
        for (i in 6 until 12) out[i] = 0
        return out
    }
}
