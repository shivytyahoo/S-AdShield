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

    /**
     * Build a minimal DNS query for [host] (type A by default). Used by the
     * MITM upstream resolver (v0.8.0) which must bypass our own filter.
     */
    fun buildQuery(host: String, qType: Int = 1): ByteArray {
        val labels = host.trimEnd('.').split(".")
        val nameBytes = ArrayList<Byte>()
        for (l in labels) {
            val b = l.toByteArray(Charsets.US_ASCII)
            nameBytes.add(b.size.toByte())
            for (x in b) nameBytes.add(x)
        }
        nameBytes.add(0)
        val out = ByteArray(12 + nameBytes.size + 4)
        val id = (System.nanoTime() and 0xFFFF).toInt()
        out[0] = ((id shr 8) and 0xFF).toByte()
        out[1] = (id and 0xFF).toByte()
        out[2] = 0x01 // RD = 1
        out[3] = 0
        out[4] = 0; out[5] = 1 // QDCOUNT = 1
        for (i in nameBytes.indices) out[12 + i] = nameBytes[i]
        val q = 12 + nameBytes.size
        out[q] = ((qType shr 8) and 0xFF).toByte()
        out[q + 1] = (qType and 0xFF).toByte()
        out[q + 2] = 0; out[q + 3] = 1 // CLASS IN
        return out
    }

    /**
     * Parse the first A-record IPv4 address from a DNS [response], or null.
     * Handles name compression pointers in answers.
     */
    fun parseFirstA(response: ByteArray, length: Int): ByteArray? {
        if (length < 12) return null
        val anCount = ((response[6].toInt() and 0xFF) shl 8) or (response[7].toInt() and 0xFF)
        if (anCount == 0) return null
        var pos = 12
        // Skip question section.
        val qdCount = ((response[4].toInt() and 0xFF) shl 8) or (response[5].toInt() and 0xFF)
        repeat(qdCount) {
            pos = skipName(response, length, pos) ?: return null
            pos += 4
            if (pos > length) return null
        }
        repeat(anCount) {
            pos = skipName(response, length, pos) ?: return null
            if (pos + 10 > length) return null
            val type = ((response[pos].toInt() and 0xFF) shl 8) or (response[pos + 1].toInt() and 0xFF)
            val rdLen = ((response[pos + 8].toInt() and 0xFF) shl 8) or (response[pos + 9].toInt() and 0xFF)
            if (type == 1 && rdLen == 4 && pos + 10 + 4 <= length) {
                return response.copyOfRange(pos + 10, pos + 14)
            }
            // CNAME (type 5): the canonical name may have its own A later;
            // keep scanning subsequent answers.
            pos += 10 + rdLen
            if (pos > length) return null
        }
        return null
    }

    private fun skipName(msg: ByteArray, length: Int, start: Int): Int? {
        var p = start
        var jumped = false
        var jumps = 0
        while (p < length) {
            val n = msg[p].toInt() and 0xFF
            if (n == 0) { p++; break }
            if ((n and 0xC0) == 0xC0) {
                if (p + 1 >= length) return null
                if (!jumped) { /* offset for caller not needed here */ }
                p = ((n and 0x3F) shl 8) or (msg[p + 1].toInt() and 0xFF)
                jumped = true
                if (++jumps > 8) return null
                continue
            }
            if (n > 63 || p + 1 + n > length) return null
            p += 1 + n
            if (jumped) break
        }
        // If we followed a pointer, the caller's position is just past it.
        // Simplify: return start+2 when a jump happened at the first byte.
        return if ((msg[start].toInt() and 0xC0) == 0xC0) start + 2 else p
    }
}
