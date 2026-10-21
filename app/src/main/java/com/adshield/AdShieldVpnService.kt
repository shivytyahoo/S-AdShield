package com.adshield

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.IBinder
import android.os.ParcelFileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicLong

/**
 * AdShield local DNS-filtering VPN.
 *
 * Engine added 2026-10-06 (the shipped ZIP only opened the TUN and dropped
 * every packet, which would have black-holed all DNS):
 *  - TUN advertises DNS server 10.10.10.1 and routes only that /32, so only
 *    DNS traffic enters the TUN; all other traffic flows normally.
 *  - IPv4/UDP packets to 10.10.10.1:53 are parsed with DnsPacket.
 *  - Blocked names (AdBlocker list) get an NXDOMAIN reply written back.
 *  - Everything else is forwarded through a protect()-ed DatagramSocket to
 *    8.8.8.8 (fallback 1.1.1.1) and the real reply is written back.
 * IPv6 DNS is out of scope for this MVP (no IPv6 address/route is added).
 *
 * v0.7.0 "anti-detect" mode: blocked domains can instead resolve to the
 * local stub IP 10.10.10.3 (also routed into the TUN). A tiny userspace TCP
 * stack ([TcpRelay]) serves HTTP there with empty-but-valid surrogate
 * resources ([StubHttpServer]: 1x1 image, empty ad-SDK JS, blank page), so
 * sites' "Ad blocker detected" probes see their bait requests *succeed*
 * and never show the wall — while no real ad is ever fetched or shown.
 */
class AdShieldVpnService : VpnService() {

    private var tun: ParcelFileDescriptor? = null
    @Volatile private var running = false
    private var worker: Thread? = null
    private var tunIn: FileInputStream? = null
    private var tunOut: FileOutputStream? = null
    private val writeLock = Any()

    // Battery-friendly engine state: a small fixed worker pool (no thread
    // per query), a TTL-respecting DNS cache (repeat lookups never touch
    // the radio), and in-memory counters that are flushed to disk only
    // in batches instead of on every single DNS query.
    private var dnsExecutor: ExecutorService? = null
    private data class CacheEntry(val response: ByteArray, val expiresAtMs: Long)
    private val dnsCache = ConcurrentHashMap<String, CacheEntry>()
    private val statsQueries = AtomicLong(0)
    private val statsBlocked = AtomicLong(0)

    // Anti-detect surrogate stub server (v0.7.0): answers HTTP for blocked
    // domains from inside the TUN. Single-threaded — only the TUN reader
    // thread calls into it; outgoing packets reuse the service write lock.
    private val tcpRelay = TcpRelay(STUB_IP_BYTES) { packet ->
        synchronized(writeLock) {
            try {
                tunOut?.write(packet)
                tunOut?.flush()
            } catch (_: Exception) {
                // TUN closed while shutting down; nothing useful to do.
            }
        }
    }

    // HTTPS path filter MITM (v0.8.0): per-domain TLS interception scoped to
    // user-listed domains only. Created in startVpn() when enabled.
    private var mitmRelay: MitmTcpRelay? = null
    private var mitmIpSet: Set<ByteArray> = emptySet()
    /** MITM IP string ("10.10.10.4") -> domain it stands in for. */
    private var mitmIpToHost: Map<String, String> = emptyMap()
    private var caManager: CaManager? = null

    private fun mitmEnabled(): Boolean = try {
        getSharedPreferences(PREFS, MODE_PRIVATE).getBoolean(KEY_MITM_ENABLED, false)
    } catch (_: Exception) {
        false
    }

    private fun mitmDomains(): List<String> = try {
        val prefs = getSharedPreferences(PREFS, MODE_PRIVATE)
        // v0.9.0 "Universal": one-time merge of the embedded site list
        // into the user's MITM domains (their own entries keep priority
        // and everything stays editable in the app afterwards).
        if (!prefs.getBoolean(KEY_EMBEDDED_MERGED, false)) {
            val cur = (prefs.getString(KEY_MITM_DOMAINS, DEFAULT_MITM_DOMAINS)
                ?: DEFAULT_MITM_DOMAINS)
                .split(",").map { it.trim().lowercase() }
                .filter { it.isNotEmpty() && it.contains(".") }
            val merged = (cur + EMBEDDED_MITM_DOMAINS).distinct()
            prefs.edit()
                .putString(KEY_MITM_DOMAINS, merged.joinToString(","))
                .putBoolean(KEY_EMBEDDED_MERGED, true)
                .apply()
        }
        val raw = prefs.getString(KEY_MITM_DOMAINS, DEFAULT_MITM_DOMAINS) ?: DEFAULT_MITM_DOMAINS
        raw.split(",").map { it.trim().lowercase() }
            .filter { it.isNotEmpty() && it.contains(".") }
            .distinct().take(MAX_MITM_DOMAINS)
    } catch (_: Exception) {
        listOf("pornhub.org", "pornhub.com")
    }

    private fun mitmBlockPaths(): List<String> = try {
        val raw = getSharedPreferences(PREFS, MODE_PRIVATE)
            .getString(KEY_MITM_RULES, "") ?: ""
        val custom = raw.split(",").map { it.trim().lowercase() }.filter { it.isNotEmpty() }
        if (custom.isEmpty()) PathRules.DEFAULT_BLOCKED_PATHS else custom
    } catch (_: Exception) {
        PathRules.DEFAULT_BLOCKED_PATHS
    }

    /** Build domain -> MITM IP bytes, in pref order. v0.9.0: IPs span
     * 10.10.20.1 upward (250 per third octet) so the universal embedded
     * list fits; 10.10.10.x stays reserved for DNS (.1) and the stub (.3). */
    private fun buildMitmMap(): Map<String, ByteArray> {
        val map = LinkedHashMap<String, ByteArray>()
        for ((i, d) in mitmDomains().withIndex()) {
            val third = MITM_IP_THIRD_BASE + i / 250
            if (third > 240) break
            map[d] = byteArrayOf(10, 10, third.toByte(), (1 + i % 250).toByte())
        }
        return map
    }

    /** True if [name] is a MITM-listed domain or its subdomain. */
    private fun isMitmName(name: String): Boolean {
        val n = name.lowercase().trimEnd('.')
        for (d in mitmDomains()) {
            if (n == d || n.endsWith(".$d")) return true
        }
        return false
    }

    /** MITM IP bytes for [name], or null if not a listed domain. */
    private fun mitmIpFor(name: String): ByteArray? {
        val n = name.lowercase().trimEnd('.')
        val map = buildMitmMap()
        for ((d, ip) in map) {
            if (n == d || n.endsWith(".$d")) return ip
        }
        return null
    }

    private fun getCaManager(): CaManager {
        val cur = caManager
        if (cur != null) return cur
        val created = CaManager(filesDir)
        caManager = created
        return created
    }

    /**
     * Resolve [host] to its real IP via a protect()-ed DNS query to 8.8.8.8,
     * bypassing our own filter (the VPN would otherwise answer the MITM IP).
     */
    private fun resolveUpstreamIp(host: String): ByteArray? {
        return try {
            val query = DnsPacket.buildQuery(host, 1)
            val sock = DatagramSocket()
            try {
                protect(sock)
                sock.soTimeout = 5000
                val req = DatagramPacket(query, query.size, InetAddress.getByName("8.8.8.8"), 53)
                sock.send(req)
                val buf = ByteArray(512)
                val resp = DatagramPacket(buf, buf.size)
                sock.receive(resp)
                DnsPacket.parseFirstA(resp.data, resp.length)
            } finally {
                try { sock.close() } catch (_: Exception) {}
            }
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Open the real upstream connection for a MITM session: protect()-ed
     * socket to the domain's real IP (never the MITM IP), TLS-wrapped for
     * port 443 with standard system trust validation.
     */
    private fun openUpstreamSocket(host: String, port: Int): java.net.Socket {
        val realIp = resolveUpstreamIp(host)
            ?: throw java.io.IOException("upstream DNS failed for $host")
        val addr = InetAddress.getByAddress(realIp)
        val raw = java.net.Socket()
        try {
            protect(raw)
            raw.connect(java.net.InetSocketAddress(addr, port), 10000)
            raw.soTimeout = 30000
        } catch (e: Exception) {
            try { raw.close() } catch (_: Exception) {}
            throw e
        }
        if (port != 443) return raw
        return try {
            val ctx = javax.net.ssl.SSLContext.getInstance("TLS")
            ctx.init(null, null, null) // default system trust managers
            val factory = ctx.socketFactory
            val tls = factory.createSocket(raw, host, port, true) as javax.net.ssl.SSLSocket
            tls.sslParameters = tls.sslParameters.apply {
                endpointIdentificationAlgorithm = "HTTPS"
            }
            tls.startHandshake()
            tls
        } catch (e: Exception) {
            try { raw.close() } catch (_: Exception) {}
            throw e
        }
    }

    /** Anti-detect mode pref (default ON); re-read lazily, toggled from UI. */
    private fun surrogateEnabled(): Boolean = try {
        getSharedPreferences(PREFS, MODE_PRIVATE).getBoolean(KEY_SURROGATE, true)
    } catch (_: Exception) {
        true
    }
    @Volatile private var statsLoaded = false
    @Volatile private var lastStatsFlushMs = 0L

    private fun ensureStatsLoaded() {
        if (statsLoaded) return
        synchronized(this) {
            if (statsLoaded) return
            try {
                val prefs = getSharedPreferences(PREFS, MODE_PRIVATE)
                statsQueries.set(prefs.getLong(KEY_QUERIES, 0))
                statsBlocked.set(prefs.getLong(KEY_BLOCKED, 0))
            } catch (_: Exception) {}
            statsLoaded = true
            lastStatsFlushMs = System.currentTimeMillis()
        }
    }

    private fun flushStats() {
        try {
            getSharedPreferences(PREFS, MODE_PRIVATE).edit()
                .putLong(KEY_QUERIES, statsQueries.get())
                .putLong(KEY_BLOCKED, statsBlocked.get())
                .putLong(KEY_LAST_AT, System.currentTimeMillis())
                .apply()
            lastStatsFlushMs = System.currentTimeMillis()
        } catch (_: Exception) {}
    }

    private fun recordQuery(blockedHit: Boolean) {
        ensureStatsLoaded()
        val q = statsQueries.incrementAndGet()
        if (blockedHit) statsBlocked.incrementAndGet()
        // NOTE: never touches KEY_RUNNING (see git history: setting it here
        // made STOP appear to not work). Flush at most every 5s / 25 queries.
        val now = System.currentTimeMillis()
        if (q % 25L == 0L || now - lastStatsFlushMs >= 5000) flushStats()
    }

    private fun setRunningPref(value: Boolean) {
        try {
            getSharedPreferences(PREFS, MODE_PRIVATE).edit()
                .putBoolean(KEY_RUNNING, value).apply()
        } catch (_: Exception) {}
    }

    /**
     * The user's own on/off wish, kept separate from "is it running right
     * now". Boot restart and sticky restarts honour this; only an explicit
     * STOP (or Android revoking the VPN) clears it.
     */
    private fun setUserEnabledPref(value: Boolean) {
        try {
            getSharedPreferences(PREFS, MODE_PRIVATE).edit()
                .putBoolean(KEY_USER_ENABLED, value).apply()
        } catch (_: Exception) {}
    }

    /**
     * Single teardown path for every stop route (STOP button via
     * [ACTION_STOP], stopService/onDestroy, VPN revoke): stops the reader,
     * closes both TUN streams and the TUN itself, and clears the running
     * flag. Idempotent — safe to call twice.
     */
    private fun shutdownVpn(userInitiated: Boolean = false) {
        running = false
        setRunningPref(false)
        if (userInitiated) setUserEnabledPref(false)
        if (statsLoaded) flushStats()
        try { dnsExecutor?.shutdownNow() } catch (_: Exception) {}
        dnsExecutor = null
        // MITM relay holds live sessions; drop the reference so a fresh
        // startVpn() rebuilds it from current prefs.
        mitmRelay = null
        mitmIpSet = emptySet()
        mitmIpToHost = emptyMap()
        try { tunIn?.close() } catch (_: Exception) {}
        tunIn = null
        try { tunOut?.close() } catch (_: Exception) {}
        tunOut = null
        try { tun?.close() } catch (_: Exception) {}
        tun = null
        worker?.interrupt()
        worker = null
    }

    private fun removeForegroundNotification() {
        if (Build.VERSION.SDK_INT >= 24) {
            stopForeground(Service.STOP_FOREGROUND_REMOVE)
        } else {
            @Suppress("DEPRECATION")
            stopForeground(true)
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            shutdownVpn(userInitiated = true)
            removeForegroundNotification()
            stopSelf()
            return START_NOT_STICKY
        }
        setRunningPref(true)
        setUserEnabledPref(true)
        ensureStatsLoaded()
        createNotificationChannel()
        // Foreground first (Android requires it promptly); the ~250k-entry
        // lists then load on a background thread. The built-in starter set
        // is already active, so no query goes unfiltered while they load.
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(7, notification(), ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            @Suppress("DEPRECATION")
            startForeground(7, notification())
        }
        AdBlocker.initAsync(applicationContext)
        // Always (re)start the VPN to pick up pref changes (e.g. MITM
        // routes). If the service wasn't fully stopped, running may still
        // be true — shut down first so the new config applies.
        if (running) shutdownVpn()
        startVpn()
        return START_STICKY
    }

    private fun startVpn() {
        running = true
        val builder = Builder()
            .setSession("AdShield")
            .setMtu(1500)
            .addAddress(TUN_ADDRESS, 32)
            .addDnsServer(DNS_ADDRESS)
            .addRoute(DNS_ADDRESS, 32)
            // Anti-detect surrogate stubs (v0.7.0): HTTP traffic to the stub
            // IP is pulled into the TUN so TcpRelay can answer it locally.
            .addRoute(STUB_ADDRESS, 32)
        // Bypass hardening (v0.6.0): also pull the well-known public DNS
        // resolver IPs into the TUN. Apps that hardcode 8.8.8.8 / 1.1.1.1
        // (instead of the system resolver) then still land in this engine,
        // and encrypted-DNS (DoH/DoT) attempts to those same IPs have no
        // other traffic to ride on — non-DNS packets to them are dropped,
        // so the app falls back to plain, filterable DNS.
        for (ip in PUBLIC_RESOLVER_IPS) {
            try {
                builder.addRoute(ip, 32)
            } catch (_: Exception) {}
        }
        // HTTPS path filter MITM (v0.8.0): route each per-domain MITM IP
        // into the TUN so MitmTcpRelay can intercept it.
        if (mitmEnabled()) {
            // Setup debug logging (v0.8.6)
            try {
                val logFile = java.io.File(filesDir, "mitm_debug.log")
                MitmDebug.logFile = logFile
                MitmDebug.clear()
                MitmDebug.log("=== MITM session started, domains=${mitmDomains()} ===")
            } catch (_: Exception) {}
            val map = buildMitmMap()
            val ipToHost = LinkedHashMap<String, String>()
            val ipSet = LinkedHashSet<ByteArray>()
            for ((domain, ipBytes) in map) {
                val ipStr = "${ipBytes[0].toInt() and 0xFF}.${ipBytes[1].toInt() and 0xFF}." +
                    "${ipBytes[2].toInt() and 0xFF}.${ipBytes[3].toInt() and 0xFF}"
                try {
                    builder.addRoute(ipStr, 32)
                } catch (_: Exception) {}
                ipToHost[ipStr] = domain
                ipSet.add(ipBytes)
            }
            mitmIpToHost = ipToHost
            mitmIpSet = ipSet
            val blockPaths = mitmBlockPaths()
            mitmRelay = MitmTcpRelay(
                ipToHost = ipToHost,
                openSession = { host, port, onSend, onClose ->
                    MitmSession(
                        host = host,
                        port = port,
                        caManager = getCaManager(),
                        blockPaths = blockPaths,
                        openUpstream = { h, p -> openUpstreamSocket(h, p) },
                        onSendToClient = onSend,
                        onClose = onClose
                    )
                },
                onSend = { packet ->
                    synchronized(writeLock) {
                        try {
                            tunOut?.write(packet)
                            tunOut?.flush()
                        } catch (_: Exception) {}
                    }
                }
            )
        } else {
            mitmRelay = null
            mitmIpSet = emptySet()
            mitmIpToHost = emptyMap()
        }
        val pfd = builder.establish() ?: run {
                running = false
                stopSelf()
                return
            }
        tun = pfd
        worker = Thread { runLoop(pfd) }.also { it.start() }
    }

    private fun dnsExecutor(): ExecutorService {
        val current = dnsExecutor
        if (current != null && !current.isShutdown) return current
        val created = Executors.newFixedThreadPool(4) { r ->
            Thread(r, "adshield-dns").apply { isDaemon = true }
        }
        dnsExecutor = created
        return created
    }

    private fun runLoop(pfd: ParcelFileDescriptor) {
        val input = FileInputStream(pfd.fileDescriptor)
        tunIn = input
        tunOut = FileOutputStream(pfd.fileDescriptor)
        val buffer = ByteArray(32767)
        while (running) {
            try {
                val n = input.read(buffer)
                if (n <= 0) {
                    Thread.sleep(10)
                    continue
                }
                val packet = buffer.copyOf(n)
                val dns = extractDnsQuery(packet)
                if (dns != null) {
                    // Bounded pool: upstream lookups block for a few seconds,
                    // so keep the TUN reader free without spawning a fresh
                    // thread (and radio wakeup pattern) for every query.
                    dnsExecutor().execute { handleDns(dns) }
                } else if (TcpRelay.isStubTcp(packet, STUB_IP_BYTES)) {
                    // Anti-detect surrogate traffic: handled inline on this
                    // single reader thread (TcpRelay is single-threaded).
                    try {
                        tcpRelay.handlePacket(packet)
                    } catch (_: Exception) {
                        // Malformed TCP: drop, the client will retransmit.
                    }
                } else {
                    // HTTPS path filter MITM (v0.8.0): traffic to per-domain
                    // MITM IPs goes to the TLS-intercepting relay.
                    val mr = mitmRelay
                    if (mr != null && mitmIpSet.isNotEmpty()) {
                        try {
                            if (MitmTcpRelay.isMitmTcp(packet, mitmIpSet)) {
                                mr.handlePacket(packet)
                            }
                        } catch (_: Exception) {
                            // Malformed TCP: drop, the client will retransmit.
                        }
                    }
                }
                // Anything else is dropped: only the DNS /32s and the stub
                // /32 are routed into this TUN, so nothing else is expected.
            } catch (_: Exception) {
                break
            }
        }
    }

    private class DnsQuery(
        val sourceIp: ByteArray,
        val sourcePort: Int,
        /** The resolver IP the query was sent to (10.10.10.1 or a hijacked public resolver). */
        val destIp: ByteArray,
        val payload: ByteArray
    )

    /**
     * Returns the DNS payload if [packet] is IPv4/UDP to port 53. Only DNS
     * destinations are routed into this TUN (our own 10.10.10.1 plus the
     * hijacked public resolvers), so any UDP/53 packet arriving here is a
     * DNS query meant for this engine.
     */
    private fun extractDnsQuery(packet: ByteArray): DnsQuery? {
        if (packet.size < 20) return null
        if ((packet[0].toInt() shr 4) != 4) return null // IPv4 only
        val ihl = (packet[0].toInt() and 0x0F) * 4
        if (ihl < 20 || packet.size < ihl + 8) return null
        if ((packet[9].toInt() and 0xFF) != 17) return null // UDP only
        val destPort = u16(packet, ihl + 2)
        if (destPort != 53) return null
        val udpLength = u16(packet, ihl + 4)
        val payloadStart = ihl + 8
        val payloadEnd = minOf(packet.size, ihl + udpLength)
        if (payloadEnd <= payloadStart) return null
        return DnsQuery(
            sourceIp = packet.copyOfRange(12, 16),
            sourcePort = u16(packet, ihl),
            destIp = packet.copyOfRange(16, 20),
            payload = packet.copyOfRange(payloadStart, payloadEnd)
        )
    }

    private fun handleDns(query: DnsQuery) {
        val question = DnsPacket.parseQuestion(query.payload, query.payload.size)
        // HTTPS path filter MITM (v0.8.0): listed domains resolve to their
        // per-domain MITM IP (takes precedence over the blocklist). AAAA
        // gets empty NOERROR to keep clients on IPv4 where we intercept.
        if (question != null && mitmEnabled()) {
            val mitmIp = mitmIpFor(question.name)
            if (mitmIp != null) {
                recordQuery(false)
                val response = when (question.qType) {
                    1 -> DnsPacket.surrogateResponse(query.payload, query.payload.size, mitmIp)
                    28 -> DnsPacket.emptyResponse(query.payload, query.payload.size)
                    else -> DnsPacket.blockedResponse(query.payload, query.payload.size)
                }
                writeDnsResponse(query.sourceIp, query.sourcePort, query.destIp, response)
                return
            }
        }
        val hit = question != null && AdBlocker.isBlocked(question.name)
        recordQuery(hit)
        if (hit) {
            // Anti-detect mode: answer A queries for blocked domains with
            // the local stub IP so bait requests *succeed* (empty surrogate
            // content) instead of failing and tripping "Ad blocker
            // detected" walls. AAAA gets an empty NOERROR to nudge clients
            // onto IPv4; anything else keeps the classic NXDOMAIN.
            val response = when {
                surrogateEnabled() && question?.qType == 1 ->
                    DnsPacket.surrogateResponse(query.payload, query.payload.size, STUB_IP_BYTES)
                question?.qType == 28 ->
                    DnsPacket.emptyResponse(query.payload, query.payload.size)
                else ->
                    DnsPacket.blockedResponse(query.payload, query.payload.size)
            }
            writeDnsResponse(query.sourceIp, query.sourcePort, query.destIp, response)
            return
        }
        // Cache hit: answer locally, no upstream socket, no radio wakeup.
        // The cached message gets this query's transaction ID patched in.
        val key = question?.let { "${it.name.lowercase()}|${it.qType}|${it.qClass}" }
        if (key != null) {
            val entry = dnsCache[key]
            if (entry != null) {
                if (entry.expiresAtMs > System.currentTimeMillis()) {
                    val cached = entry.response.copyOf()
                    if (cached.size >= 2 && query.payload.size >= 2) {
                        cached[0] = query.payload[0]
                        cached[1] = query.payload[1]
                    }
                    writeDnsResponse(query.sourceIp, query.sourcePort, query.destIp, cached)
                    return
                }
                dnsCache.remove(key, entry)
            }
        }
        val upstream = queryUpstream(query.payload) ?: return // no reply -> resolver retries
        if (key != null) {
            if (dnsCache.size > 512) dnsCache.clear()
            val ttlMs = responseTtlSeconds(upstream) * 1000L
            dnsCache[key] = CacheEntry(upstream.copyOf(), System.currentTimeMillis() + ttlMs)
        }
        writeDnsResponse(query.sourceIp, query.sourcePort, query.destIp, upstream)
    }

    /** Smallest TTL among answer records, clamped to 30s..300s (default 60s). */
    private fun responseTtlSeconds(response: ByteArray): Long {
        try {
            if (response.size < 12) return 60
            val qd = u16(response, 4)
            val an = u16(response, 6)
            var pos = 12
            repeat(qd) {
                pos = skipDnsName(response, pos) ?: return 60
                pos += 4
                if (pos > response.size) return 60
            }
            var minTtl = Long.MAX_VALUE
            repeat(an) {
                pos = skipDnsName(response, pos) ?: return 60
                if (pos + 10 > response.size) return 60
                val ttl = ((response[pos + 4].toLong() and 0xFF) shl 24) or
                    ((response[pos + 5].toLong() and 0xFF) shl 16) or
                    ((response[pos + 6].toLong() and 0xFF) shl 8) or
                    (response[pos + 7].toLong() and 0xFF)
                val rdLen = u16(response, pos + 8)
                if (ttl in 1 until minTtl) minTtl = ttl
                pos += 10 + rdLen
                if (pos > response.size) return 60
            }
            if (minTtl == Long.MAX_VALUE) return 60
            return minTtl.coerceIn(30, 300)
        } catch (_: Exception) {
            return 60
        }
    }

    /** Offset just past a (possibly compressed) DNS name, or null if malformed. */
    private fun skipDnsName(message: ByteArray, start: Int): Int? {
        var pos = start
        var guard = 0
        while (pos < message.size && guard++ < 128) {
            val len = message[pos].toInt() and 0xFF
            if (len == 0) return pos + 1
            if ((len and 0xC0) == 0xC0) return pos + 2 // compression pointer ends the name
            if ((len and 0xC0) != 0) return null
            pos += 1 + len
        }
        return null
    }

    private fun queryUpstream(dnsPayload: ByteArray): ByteArray? {
        for (server in UPSTREAM_DNS) {
            var socket: DatagramSocket? = null
            try {
                socket = DatagramSocket()
                protect(socket)
                socket.soTimeout = 4000
                val address = InetAddress.getByAddress(server.second)
                socket.send(DatagramPacket(dnsPayload, dnsPayload.size, address, 53))
                val buffer = ByteArray(4096)
                val reply = DatagramPacket(buffer, buffer.size)
                socket.receive(reply)
                return buffer.copyOf(reply.length)
            } catch (_: Exception) {
                // try next upstream
            } finally {
                try { socket?.close() } catch (_: Exception) {}
            }
        }
        return null
    }

    /**
     * Writes a DNS reply that appears to come from [serverIp] — the very
     * resolver address the app queried (ours or a hijacked public one), so
     * the app's resolver accepts it as the genuine answer.
     */
    private fun writeDnsResponse(destIp: ByteArray, destPort: Int, serverIp: ByteArray, dnsPayload: ByteArray) {
        val totalLength = 20 + 8 + dnsPayload.size
        val packet = ByteArray(totalLength)
        packet[0] = 0x45 // IPv4, IHL 5
        packet[1] = 0
        put16(packet, 2, totalLength)
        put16(packet, 4, 0) // identification
        put16(packet, 6, 0) // flags / fragment offset
        packet[8] = 64 // TTL
        packet[9] = 17 // UDP
        System.arraycopy(serverIp, 0, packet, 12, 4)
        System.arraycopy(destIp, 0, packet, 16, 4)
        put16(packet, 10, ipChecksum(packet))
        put16(packet, 20, 53) // source port
        put16(packet, 22, destPort)
        put16(packet, 24, 8 + dnsPayload.size)
        put16(packet, 26, 0) // UDP checksum 0 = unused (valid for IPv4)
        System.arraycopy(dnsPayload, 0, packet, 28, dnsPayload.size)
        synchronized(writeLock) {
            try {
                tunOut?.write(packet)
                tunOut?.flush()
            } catch (_: Exception) {
                // TUN closed while shutting down; nothing useful to do.
            }
        }
    }

    private fun u16(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 0xFF) shl 8) or (bytes[offset + 1].toInt() and 0xFF)

    private fun put16(bytes: ByteArray, offset: Int, value: Int) {
        bytes[offset] = ((value shr 8) and 0xFF).toByte()
        bytes[offset + 1] = (value and 0xFF).toByte()
    }

    private fun ipChecksum(header: ByteArray): Int {
        var sum = 0
        var i = 0
        while (i < 20) {
            if (i != 10) { // checksum field itself counts as 0
                sum += ((header[i].toInt() and 0xFF) shl 8) or (header[i + 1].toInt() and 0xFF)
            }
            i += 2
        }
        while ((sum shr 16) != 0) sum = (sum and 0xFFFF) + (sum shr 16)
        return sum.inv() and 0xFFFF
    }

    override fun onDestroy() {
        shutdownVpn()
        removeForegroundNotification()
        super.onDestroy()
    }

    override fun onRevoke() {
        shutdownVpn(userInitiated = true)
        removeForegroundNotification()
        stopSelf()
        super.onRevoke()
    }

    override fun onBind(intent: Intent): IBinder? = super.onBind(intent)

    private fun createNotificationChannel() {
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(
            NotificationChannel("adshield", "AdShield protection", NotificationManager.IMPORTANCE_LOW)
        )
    }

    private fun notification(): Notification {
        // Tapping the persistent notification opens the app (it previously
        // had no content intent, so taps did nothing).
        val openApp = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or
                Intent.FLAG_ACTIVITY_CLEAR_TOP or
                Intent.FLAG_ACTIVITY_SINGLE_TOP
        }
        val pendingFlags = if (Build.VERSION.SDK_INT >= 23) {
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        } else {
            PendingIntent.FLAG_UPDATE_CURRENT
        }
        val contentIntent = PendingIntent.getActivity(this, 0, openApp, pendingFlags)
        return Notification.Builder(this, "adshield")
            .setContentTitle("AdShield is active")
            .setContentText("Local ad & tracker protection — tap to open")
            .setSmallIcon(android.R.drawable.ic_secure)
            .setContentIntent(contentIntent)
            .setAutoCancel(false)
            .setOngoing(true)
            .build()
    }

    companion object {
        const val ACTION_STOP = "com.adshield.action.STOP"
        const val PREFS = "adshield_stats"
        const val KEY_QUERIES = "queries"
        const val KEY_BLOCKED = "blocked"
        const val KEY_RUNNING = "running"
        const val KEY_USER_ENABLED = "user_enabled"
        const val KEY_LAST_AT = "last_at"
        private const val TUN_ADDRESS = "10.10.10.2"
        private const val DNS_ADDRESS = "10.10.10.1"
        // Anti-detect surrogate stub IP (v0.7.0): blocked domains resolve
        // here in surrogate mode, and TcpRelay serves empty-but-valid HTTP
        // stubs for it from inside the TUN.
        const val STUB_ADDRESS = "10.10.10.3"
        const val KEY_SURROGATE = "surrogate_stubs"
        private val STUB_IP_BYTES = byteArrayOf(10, 10, 10, 3)
        // HTTPS path filter MITM (v0.8.0): per-domain local MITM IPs starting
        // at 10.10.10.4. Listed domains resolve here (DNS override) and
        // MitmTcpRelay + MitmSession do TLS interception scoped to just
        // those domains, blocking ad URL paths uBlock-style.
        const val KEY_MITM_ENABLED = "mitm_enabled"
        const val KEY_MITM_DOMAINS = "mitm_domains"
        const val KEY_MITM_RULES = "mitm_rules"
        const val KEY_MITM_CA_DONE = "mitm_ca_done"
        const val KEY_EMBEDDED_MERGED = "embedded_v090_merged"
        const val DEFAULT_MITM_DOMAINS = "pornhub.org,pornhub.com"
        private const val MITM_IP_THIRD_BASE = 20
        private const val MAX_MITM_DOMAINS = 1024
        // Well-known public DNS resolver IPs hijacked into the TUN (v0.6.0)
        // so hardcoded-DNS and encrypted-DNS bypass attempts hit this engine.
        private val PUBLIC_RESOLVER_IPS = listOf(
            "8.8.8.8", "8.8.4.4", // Google
            "1.1.1.1", "1.0.0.1", "1.1.1.2", "1.0.0.2", // Cloudflare
            "9.9.9.9", "149.112.112.112", "9.9.9.10", // Quad9
            "208.67.222.222", "208.67.220.220", // OpenDNS
            "94.140.14.14", "94.140.15.15", // AdGuard
            "185.228.168.9", "185.228.169.9", // CleanBrowsing
            "76.76.2.0", "76.76.10.0", // Control D
            "84.200.69.80", "84.200.70.40", // DNS.WATCH
            "4.2.2.1", "4.2.2.2" // Level3
        )
        private val UPSTREAM_DNS = listOf(
            "8.8.8.8" to byteArrayOf(8, 8, 8, 8),
            "1.1.1.1" to byteArrayOf(1, 1, 1, 1)
        )
    }
}
