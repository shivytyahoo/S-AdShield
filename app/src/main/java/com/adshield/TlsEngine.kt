package com.adshield

import java.io.ByteArrayOutputStream
import java.net.Socket
import java.nio.ByteBuffer
import java.util.concurrent.LinkedBlockingQueue
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLEngineResult

/**
 * HTTPS path-filter engine (v0.8.0).
 *
 * For MITM-listed domains, DNS answers the domain's MITM IP and the
 * [MitmTcpRelay] delivers its TCP here. This file owns everything above
 * TCP:
 *
 *  - [TlsServerConn]: an SSLEngine TLS server driven manually over the
 *    userspace TCP byte pump (no sockets on the client side).
 *  - [MitmSession]: per-connection state machine. Port 443: TLS handshake
 *    with a forged cert ([CaManager]), read the plaintext HTTP request,
 *    match its path via [PathRules]; ad paths get a stub response
 *    (empty VAST / 204 — same surrogates as the DNS layer), everything
 *    else is relayed to the real server over a fresh upstream TLS
 *    connection. Port 80: same logic without TLS.
 *
 * Pure JVM (Android socket-protect and DNS resolution are injected), so
 * the handshake, parsing and relay are unit-testable on the JVM.
 */
class TlsServerConn(caManager: CaManager, host: String) {

    private val engine: SSLEngine = run {
        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
        kmf.init(caManager.serverKeyStore(host), CaManager.keyStorePassword())
        val ctx = SSLContext.getInstance("TLS")
        ctx.init(kmf.keyManagers, null, null)
        val e = ctx.createSSLEngine()
        e.useClientMode = false
        e.wantClientAuth = false
        // TLS 1.2 only on the client-facing side: TLS 1.3 sends
        // post-handshake NewSessionTicket messages that complicate the
        // manual SSLEngine pump (app data can be consumed while only
        // handshake bytes are emitted). The upstream connection still
        // negotiates the best version. Browsers all offer 1.2.
        e.enabledProtocols = arrayOf("TLSv1.2")
        val params = e.sslParameters
        // We only speak HTTP/1.1; browsers fall back from h2 cleanly.
        params.applicationProtocols = arrayOf("http/1.1")
        e.sslParameters = params
        e
    }

    private val netIn: ByteBuffer = ByteBuffer.allocate(32768)
    private val appIn: ByteBuffer = ByteBuffer.allocate(32768)
    private val netOut: ByteBuffer = ByteBuffer.allocate(32768)
    private val appOut: ByteBuffer = ByteBuffer.allocate(32768)

    private val pendingNet = LinkedBlockingQueue<ByteArray>()
    private val readyApp = LinkedBlockingQueue<ByteArray>()
    private val readyNet = LinkedBlockingQueue<ByteArray>()

    @Volatile var handshakeDone = false
        private set
    @Volatile var closed = false
        private set

    init {
        netIn.limit(0) // empty-but-readable marker; filled by feedNet
    }

    fun beginHandshake() {
        engine.beginHandshake()
        pumpHandshake()
    }

    /** Encrypted bytes arrived from the client. */
    fun feedNet(data: ByteArray) {
        if (data.isNotEmpty()) pendingNet.offer(data)
        pump()
    }

    /** Decrypted bytes ready for the session, or null. Drains fully. */
    fun pollApp(): ByteArray? = readyApp.poll()

    /** Encrypted bytes to send to the client, or null. Drains fully. */
    fun pollNet(): ByteArray? = readyNet.poll()

    /** Encrypts app bytes for the client. */
    fun sendApp(data: ByteArray) {
        var off = 0
        while (off < data.size && !closed) {
            appOut.clear()
            val n = minOf(data.size - off, appOut.capacity())
            appOut.put(data, off, n)
            appOut.flip()
            netOut.clear()
            val res = try {
                engine.wrap(appOut, netOut)
            } catch (_: Exception) {
                closed = true
                return
            }
            off += n - appOut.remaining()
            if (res.status == SSLEngineResult.Status.CLOSED) {
                closed = true
            }
            netOut.flip()
            if (netOut.hasRemaining()) emitNet(netOut)
            if (res.status != SSLEngineResult.Status.OK &&
                res.status != SSLEngineResult.Status.CLOSED
            ) return
        }
    }

    /** Sends TLS close_notify. */
    fun closeOutbound() {
        try {
            engine.closeOutbound()
            netOut.clear()
            engine.wrap(ByteBuffer.allocate(0), netOut)
            netOut.flip()
            if (netOut.hasRemaining()) emitNet(netOut)
        } catch (_: Exception) {
        }
        closed = true
    }

    private fun emitNet(buf: ByteBuffer) {
        val b = ByteArray(buf.remaining())
        buf.get(b)
        readyNet.offer(b)
    }

    private fun pump() {
        pumpHandshake()
        if (handshakeDone) pumpAppData()
    }

    private fun pumpHandshake() {
        var guard = 0
        while (guard++ < 64 && !closed) {
            when (engine.handshakeStatus) {
                SSLEngineResult.HandshakeStatus.NEED_UNWRAP -> {
                    if (!unwrapOne()) return
                }
                SSLEngineResult.HandshakeStatus.NEED_WRAP -> {
                    netOut.clear()
                    val res = try {
                        engine.wrap(ByteBuffer.allocate(0), netOut)
                    } catch (_: Exception) {
                        closed = true
                        return
                    }
                    netOut.flip()
                    if (netOut.hasRemaining()) emitNet(netOut)
                    if (res.status == SSLEngineResult.Status.CLOSED) {
                        closed = true
                        return
                    }
                }
                SSLEngineResult.HandshakeStatus.NEED_TASK -> {
                    var task = engine.delegatedTask
                    while (task != null) {
                        try {
                            task.run()
                        } catch (_: Exception) {
                            closed = true
                            return
                        }
                        task = engine.delegatedTask
                    }
                }
                else -> {
                    handshakeDone = true
                    return
                }
            }
        }
    }

    /**
     * One unwrap step. Returns false when more network input is needed
     * (or the stream closed); true when progress may continue.
     */
    private fun unwrapOne(): Boolean {
        if (!netIn.hasRemaining()) {
            val chunk = pendingNet.poll() ?: return false
            // Preserve any unprocessed tail (should be none here).
            val tail = ByteArray(netIn.remaining())
            netIn.get(tail)
            netIn.clear()
            val need = tail.size + chunk.size
            if (need > netIn.capacity()) return false // absurd; drop
            netIn.put(tail)
            netIn.put(chunk)
            netIn.flip()
        }
        appIn.clear()
        val res = try {
            engine.unwrap(netIn, appIn)
        } catch (_: Exception) {
            closed = true
            return false
        }
        return when (res.status) {
            SSLEngineResult.Status.OK -> {
                appIn.flip()
                if (appIn.hasRemaining()) {
                    val b = ByteArray(appIn.remaining())
                    appIn.get(b)
                    readyApp.offer(b)
                }
                // Compact any unprocessed network tail for the next round.
                netIn.compact()
                netIn.flip()
                if (engine.handshakeStatus == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING ||
                    engine.handshakeStatus == SSLEngineResult.HandshakeStatus.FINISHED
                ) handshakeDone = true
                true
            }
            SSLEngineResult.Status.BUFFER_UNDERFLOW -> {
                // Need more bytes: compact and wait.
                netIn.compact()
                netIn.flip()
                false
            }
            SSLEngineResult.Status.BUFFER_OVERFLOW -> {
                // appIn too small — cannot happen at 32k for handshakes;
                // treat as fatal to avoid a spin.
                closed = true
                false
            }
            SSLEngineResult.Status.CLOSED -> {
                closed = true
                false
            }
        }
    }

    private fun pumpAppData() {
        var guard = 0
        while (guard++ < 64 && !closed) {
            if (!netIn.hasRemaining()) {
                val chunk = pendingNet.poll() ?: return
                netIn.clear()
                if (chunk.size > netIn.capacity()) return
                netIn.put(chunk)
                netIn.flip()
            }
            if (!unwrapOne()) return
        }
    }
}

/**
 * One MITM'd connection: [host]:[port].
 *
 * @param openUpstream opens an already-connected socket to the real
 *   server (TLS for 443, plain for 80). Injected so JVM tests can fake it;
 *   the Android service injects a protect()ed real connection.
 * @param onSendToClient encrypted (443) or plain (80) bytes for the client.
 * @param onClose invoked once when the session ends (to TCP-FIN the client).
 */
class MitmSession(
    private val host: String,
    private val port: Int,
    private val caManager: CaManager,
    private val blockPaths: List<String>,
    private val openUpstream: (host: String, port: Int) -> Socket,
    private val onSendToClient: (ByteArray) -> Unit,
    private val onClose: () -> Unit
) {
    private val inbound = LinkedBlockingQueue<ByteArray>()
    @Volatile private var closed = false
    private var closeSent = false

    /** Bytes arrived from the client (encrypted for 443). Non-blocking. */
    fun feedFromClient(data: ByteArray) {
        if (!closed && data.isNotEmpty()) inbound.offer(data)
    }

    fun start() {
        Thread({ run() }, "adshield-mitm").apply { isDaemon = true; start() }
    }

    fun close() {
        if (closed) return
        closed = true
        inbound.offer(ByteArray(0)) // unblock take()
    }

    private fun run() {
        try {
            if (port == 443) runTls() else runPlain()
        } catch (_: Exception) {
        } finally {
            finish()
        }
    }

    // ---------------- TLS (443) ----------------

    private fun runTls() {
        val tls = TlsServerConn(caManager, host)
        tls.beginHandshake()
        flushNet(tls)
        while (!tls.handshakeDone && !tls.closed && !closed) {
            val chunk = inbound.take()
            if (closed) return
            tls.feedNet(chunk)
            flushNet(tls)
        }
        if (tls.closed || closed) return

        val head = readHttpHead { tls.pollApp() ?: takeNet(tls) } ?: return
        val req = StubHttpServer.parseRequest(head) ?: run {
            sendTls(tls, StubHttpServer.badRequest())
            return
        }
        handleRequest(
            target = req.first,
            accept = req.second,
            rawHead = head,
            sendToClient = { bytes -> sendTls(tls, bytes) },
            readClient = { tls.pollApp() ?: takeNet(tls) },
            openUp = { openUpstream(host, port) }
        )
        try {
            tls.closeOutbound()
        } catch (_: Exception) {
        }
        flushNet(tls)
    }

    private fun takeNet(tls: TlsServerConn): ByteArray? {
        while (!closed && !tls.closed) {
            val chunk = inbound.take()
            if (closed) return null
            tls.feedNet(chunk)
            flushNet(tls)
            val app = tls.pollApp()
            if (app != null) return app
        }
        return null
    }

    private fun sendTls(tls: TlsServerConn, bytes: ByteArray) {
        tls.sendApp(bytes)
        flushNet(tls)
    }

    private fun flushNet(tls: TlsServerConn) {
        while (true) {
            val b = tls.pollNet() ?: return
            try {
                onSendToClient(b)
            } catch (_: Exception) {
                return
            }
        }
    }

    // ---------------- Plain HTTP (80) ----------------

    private fun runPlain() {
        val head = readHttpHead { takePlain() } ?: return
        val req = StubHttpServer.parseRequest(head) ?: run {
            try {
                onSendToClient(StubHttpServer.badRequest())
            } catch (_: Exception) {
            }
            return
        }
        handleRequest(
            target = req.first,
            accept = req.second,
            rawHead = head,
            sendToClient = { bytes ->
                try {
                    onSendToClient(bytes)
                } catch (_: Exception) {
                }
            },
            readClient = { takePlain() },
            openUp = { openUpstream(host, port) }
        )
    }

    private fun takePlain(): ByteArray? {
        while (!closed) {
            val chunk = inbound.take()
            if (closed) return null
            if (chunk.isNotEmpty()) return chunk
        }
        return null
    }

    // ---------------- Shared ----------------

    /** Reads bytes until a complete HTTP head is buffered. */
    private fun readHttpHead(next: () -> ByteArray?): ByteArray? {
        val buf = ByteArrayOutputStream()
        var guard = 0
        while (guard++ < 64 && !closed) {
            val chunk = next() ?: return null
            buf.write(chunk)
            if (StubHttpServer.hasFullHead(buf.toByteArray())) return buf.toByteArray()
            if (buf.size() > 65536) return null // absurd; bail
        }
        return null
    }

    /**
     * Decides block vs relay for one request, then either stubs it or
     * pumps the connection transparently until either side closes.
     */
    private fun handleRequest(
        target: String,
        accept: String,
        rawHead: ByteArray,
        sendToClient: (ByteArray) -> Unit,
        readClient: () -> ByteArray?,
        openUp: () -> Socket
    ) {
        if (PathRules.isAdPath(target, blockPaths)) {
            // Blocked ad path: video ad tags get the deterministic empty
            // VAST ("no ad"); anything else gets the extension-based stub.
            val stub = if (StubHttpServer.isAdTag(target)) StubHttpServer.emptyVastResponse()
            else StubHttpServer.buildResponse(target, accept)
            sendToClient(stub)
            return
        }
        val upstream: Socket = try {
            openUp()
        } catch (_: Exception) {
            return
        }
        try {
            val out = upstream.getOutputStream()
            out.write(rawHead)
            out.flush()
            val inp = upstream.getInputStream()
            val upToClient = Thread({
                val buf = ByteArray(32768)
                try {
                    while (!closed) {
                        val n = inp.read(buf)
                        if (n <= 0) break
                        sendToClient(buf.copyOf(n))
                    }
                } catch (_: Exception) {
                } finally {
                    close()
                }
            }, "adshield-mitm-up")
            upToClient.isDaemon = true
            upToClient.start()
            // Client -> upstream on this thread (decrypted for 443,
            // plaintext for 80); either side closing ends the session.
            try {
                while (!closed) {
                    val b = readClient() ?: break
                    if (b.isEmpty()) break
                    out.write(b)
                    out.flush()
                }
            } catch (_: Exception) {
            } finally {
                close()
            }
            try {
                upToClient.join(30000)
            } catch (_: Exception) {
            }
        } catch (_: Exception) {
        } finally {
            try {
                upstream.close()
            } catch (_: Exception) {
            }
        }
    }

    private fun finish() {
        if (closeSent) return
        closeSent = true
        try {
            onClose()
        } catch (_: Exception) {
        }
    }
}
