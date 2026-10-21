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
 * uBlock-style in-page bundle (v0.8.20), injected into HTML pages on
 * MITM domains. Three layers adapted from uBlock Origin's techniques:
 * generic cosmetic CSS (hide known ad containers), a no-window-open
 * scriptlet with a decoy window (popunders/popups get a fake 1px iframe
 * window instead of a real tab), and a MutationObserver DOM sweeper
 * (removes ad elements the page inserts dynamically, SPA-style).
 * Plain ES5, no template literals, fully self-defensive.
 */
private val INJECT_BUNDLE: String =
    "<!-- adshield-ubo v1 --><style>" +
    ".adsbygoogle,ins.adsbygoogle,div[id^=\"div-gpt-ad\"],iframe[id^=\"google_ads\"]," +
    "iframe[src*=\"doubleclick\"],iframe[src*=\"googlesyndication\"]," +
    "iframe[src*=\"trafficstars\"],iframe[src*=\"syndicate\"],iframe[src*=\"exoclick\"]," +
    "iframe[src*=\"adsterra\"],iframe[src*=\"trafficjunky\"]," +
    "[class*=\"popunder\"],[id*=\"popunder\"]," +
    ".ad-banner,.ads-banner,.banner-ad" +
    "{display:none!important;visibility:hidden!important}</style>" +
    "<script>(function(){\"use strict\";try{" +
    "var M=[\"syndicate\",\"trafficstars\",\"trafficjunky\",\"exoclick\",\"adsterra\",\"doubleclick\",\"googlesyndication\",\"/v1/direct/\",\"popunder\",\"adserver\",\"adsbygoogle\"];" +
    "function isAd(u){if(!u)return false;u=(\"\"+u).toLowerCase();for(var i=0;i<M.length;i++){if(u.indexOf(M[i])>=0)return true;}return false;}" +
    "var realOpen=window.open;" +
    "function decoy(url){try{var f=document.createElement(\"iframe\");f.src=\"about:blank\";f.style.cssText=\"position:fixed;top:-1px;left:-1px;width:1px;height:1px;border:0\";(document.body||document.documentElement).appendChild(f);var w=f.contentWindow;try{Object.defineProperty(w,\"closed\",{value:false});}catch(e){}setTimeout(function(){try{f.remove();}catch(e){}},4000);return w;}catch(e){return{closed:false,focus:function(){},blur:function(){},close:function(){}};}}" +
    "window.__asNavUrl=\"\";window.__asNavT=0;" +
    "window.open=function(url,name,feats){try{" +
    "var raw=(url==null?\"\":(\"\"+url));if(!raw)return decoy(url);" +
    "if(isAd(raw))return decoy(url);" +
    "var abs=\"\";try{abs=new URL(raw,location.href).href;}catch(e){return decoy(url);}" +
    "if(window.__asNavUrl&&abs===window.__asNavUrl&&(Date.now()-window.__asNavT)<3000)return realOpen?realOpen.apply(window,arguments):null;" +
    "try{if(new URL(abs).hostname===location.hostname)return realOpen?realOpen.apply(window,arguments):null;}catch(e){}" +
    "return decoy(url);}catch(e){return decoy(url);}};" +
    "document.addEventListener(\"click\",function(ev){try{var a=ev.target&&ev.target.closest?ev.target.closest(\"a[href]\"):null;window.__asNavUrl=a?a.href:\"\";window.__asNavT=Date.now();}catch(e){}},true);" +
    "var SEL=\"iframe[src*=trafficstars],iframe[src*=syndicate],iframe[src*=exoclick],iframe[src*=doubleclick],iframe[src*=googlesyndication],iframe[src*=adsterra],iframe[src*=trafficjunky],ins.adsbygoogle,[class*=popunder],[id*=popunder]\";" +
    "function kill(el){try{el.style.setProperty(\"display\",\"none\",\"important\");el.remove();}catch(e){}}" +
    "function sweep(root){try{var list=(root||document).querySelectorAll(SEL);for(var i=0;i<list.length;i++)kill(list[i]);}catch(e){}}" +
    "function start(){sweep(document);try{new MutationObserver(function(ms){for(var i=0;i<ms.length;i++){var an=ms[i].addedNodes;for(var j=0;j<an.length;j++){var n=an[j];if(n.nodeType===1){if(n.matches&&n.matches(SEL))kill(n);else sweep(n);}}}}).observe(document.documentElement,{childList:true,subtree:true});}catch(e){}}" +
    "if(document.readyState===\"loading\")document.addEventListener(\"DOMContentLoaded\",start);else start();" +
    "}catch(e){}})();</script>"

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
        // Drain ALL pending chunks into netIn first (fixes fragmented
        // ClientHello: previously, after BUFFER_UNDERFLOW, the next chunk
        // sat in pendingNet forever while we retried the incomplete data).
        while (true) {
            val chunk = pendingNet.poll() ?: break
            val tail = ByteArray(netIn.remaining())
            netIn.get(tail)
            netIn.clear()
            val need = tail.size + chunk.size
            if (need > netIn.capacity()) return false // absurd; drop
            netIn.put(tail)
            netIn.put(chunk)
            netIn.flip()
        }
        if (!netIn.hasRemaining()) return false
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
 * Simple file logger for MITM debugging (v0.8.6). Set [logFile] from the
 * service; logs are appended with timestamps. User can share the file.
 */
object MitmDebug {
    @Volatile var logFile: java.io.File? = null

    fun log(msg: String) {
        try {
            val f = logFile ?: return
            val ts = java.text.SimpleDateFormat("HH:mm:ss.SSS", java.util.Locale.US)
                .format(java.util.Date())
            f.appendText("[$ts] $msg\n")
        } catch (_: Exception) {}
    }

    fun clear() {
        try { logFile?.writeText("") } catch (_: Exception) {}
    }
}

/**
 * Pull-based buffered source with leftovers preserved (v0.9.1): HTTP
 * heads are consumed exactly, body bytes that arrived in the same chunk
 * stay buffered for the body phase, and the next request head on a
 * keep-alive connection starts exactly where the previous body ended.
 */
private class BufferedSource(private val next: () -> ByteArray?) {
    private var buf = ByteArray(0)
    private var pos = 0
    private var eof = false

    private fun fill(): Boolean {
        if (pos > 0) { buf = buf.copyOfRange(pos, buf.size); pos = 0 }
        if (eof) return buf.isNotEmpty()
        val chunk = try { next() } catch (_: Exception) { null }
        if (chunk == null || chunk.isEmpty()) { eof = true; return buf.isNotEmpty() }
        buf = buf + chunk
        return true
    }

    private fun headEnd(): Int {
        var i = pos
        while (i + 3 < buf.size) {
            if (buf[i] == 13.toByte() && buf[i + 1] == 10.toByte() &&
                buf[i + 2] == 13.toByte() && buf[i + 3] == 10.toByte()) return i + 4
            i++
        }
        return -1
    }

    /** Exactly one HTTP head (through CRLFCRLF), or null on EOF first. */
    fun readHead(): ByteArray? {
        var guard = 0
        while (guard++ < 128) {
            val end = headEnd()
            if (end >= 0) {
                val out = buf.copyOfRange(pos, end)
                pos = end
                return out
            }
            if (buf.size - pos > 65536) return null
            if (!fill()) return null
        }
        return null
    }

    /** Up to [n] bytes; null only when nothing remains. */
    fun readUpTo(n: Int): ByteArray? {
        while (buf.size - pos == 0) { if (!fill()) return null }
        val take = minOf(n, buf.size - pos)
        val out = buf.copyOfRange(pos, pos + take)
        pos += take
        return out
    }

    /** One CRLF-terminated line without the CRLF; null at clean EOF. */
    fun readLine(): String? {
        var guard = 0
        while (guard++ < 128) {
            var i = pos
            while (i + 1 < buf.size) {
                if (buf[i] == 13.toByte() && buf[i + 1] == 10.toByte()) {
                    val s = String(buf, pos, i - pos, Charsets.US_ASCII)
                    pos = i + 2
                    return s
                }
                i++
            }
            if (!fill()) {
                if (buf.size - pos > 0) {
                    val s = String(buf, pos, buf.size - pos, Charsets.US_ASCII)
                    pos = buf.size
                    return s
                }
                return null
            }
        }
        return null
    }

    /** Pushes bytes back to the front (a capped read that overran). */
    fun unread(bytes: ByteArray) {
        if (bytes.isEmpty()) return
        val rest = buf.copyOfRange(pos, buf.size)
        buf = bytes + rest
        pos = 0
        eof = false
    }

    /** InputStream view draining this source in order (body phase). */
    fun asInputStream(): java.io.InputStream = object : java.io.InputStream() {
        override fun read(): Int {
            val b = readUpTo(1) ?: return -1
            return b[0].toInt() and 0xFF
        }

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            if (len == 0) return 0
            val chunk = readUpTo(len) ?: return -1
            System.arraycopy(chunk, 0, b, off, chunk.size)
            return chunk.size
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
        MitmDebug.log("runTls start host=$host port=$port")
        val tls = try {
            TlsServerConn(caManager, host)
        } catch (e: Exception) {
            MitmDebug.log("runTls: TlsServerConn failed: ${e.message}")
            return
        }
        MitmDebug.log("runTls: beginHandshake")
        tls.beginHandshake()
        flushNet(tls)
        while (!tls.handshakeDone && !tls.closed && !closed) {
            val chunk = inbound.take()
            if (closed) return
            MitmDebug.log("runTls: got ${chunk.size}b from client, feeding")
            tls.feedNet(chunk)
            flushNet(tls)
        }
        MitmDebug.log("runTls: handshake done=${tls.handshakeDone} closed=${tls.closed}")
        if (tls.closed || closed) return

        val source = BufferedSource { tls.pollApp() ?: takeNet(tls) }
        sessionLoop(source) { bytes -> sendTls(tls, bytes) }
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
        val source = BufferedSource { takePlain() }
        sessionLoop(source) { bytes ->
            try {
                onSendToClient(bytes)
            } catch (_: Exception) {
            }
        }
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

    /**
     * v0.9.1 keep-alive session loop: serves requests one after another
     * on this connection until the client closes it or asks to close.
     * The pre-0.9.1 design ended the session with the first response,
     * which silently killed every later request the browser sent on the
     * reused connection — the XHR/fetch calls behind site buttons
     * (non-idempotent, never retried) died with it.
     */
    private fun sessionLoop(source: BufferedSource, sendToClient: (ByteArray) -> Unit) {
        while (!closed) {
            val head = source.readHead() ?: break
            val req = StubHttpServer.parseRequest(head) ?: run {
                try { sendToClient(StubHttpServer.badRequest()) } catch (_: Exception) {}
                break
            }
            val keep = try {
                handleRequestLoop(head, req.first, req.second, source, sendToClient)
            } catch (_: Exception) {
                false
            }
            if (!keep) break
        }
        closeUpstream()
    }

    // ---------- upstream connection (reused across requests) ----------

    private var upstreamSocket: Socket? = null
    private var upstreamSource: BufferedSource? = null
    private var upstreamServed = 0

    private fun closeUpstream() {
        try { upstreamSocket?.close() } catch (_: Exception) {}
        upstreamSocket = null
        upstreamSource = null
        upstreamServed = 0
    }

    /** (socket, source, wasReused) for the current upstream connection. */
    private fun ensureUpstream(): Triple<Socket, BufferedSource, Boolean>? {
        val existing = upstreamSocket
        val existingSrc = upstreamSource
        if (existing != null && existingSrc != null && !existing.isClosed) {
            return Triple(existing, existingSrc, upstreamServed > 0)
        }
        closeUpstream()
        val sock = try { openUpstream(host, port) } catch (_: Exception) { return null }
        try { sock.soTimeout = 120_000 } catch (_: Exception) {}
        val inp = try { sock.getInputStream() } catch (_: Exception) {
            try { sock.close() } catch (_: Exception) {}
            return null
        }
        val src = BufferedSource {
            val b = ByteArray(32768)
            val n = try { inp.read(b) } catch (_: Exception) { -1 }
            if (n <= 0) null else b.copyOf(n)
        }
        upstreamSocket = sock
        upstreamSource = src
        return Triple(sock, src, false)
    }

    private enum class UpOutcome { REUSE, REOPEN, STALE, END }

    /**
     * Handles ONE request inside the session loop. Returns true to serve
     * the next request on this client connection.
     */
    private fun handleRequestLoop(
        rawHead: ByteArray,
        target: String,
        accept: String,
        source: BufferedSource,
        sendToClient: (ByteArray) -> Unit
    ): Boolean {
        val headStr = String(rawHead, Charsets.US_ASCII)
        val reqClose = headHasToken(headStr, "connection", "close")
        val blocked = PathRules.isAdPath(target, blockPaths)
        MitmDebug.log("handleRequest host=$host target=${target.take(120)} blocked=$blocked")
        if (blocked) {
            val lower = target.lowercase()
            val stub = when {
                lower.contains("preroll_type=json") || lower.contains("json") ->
                    StubHttpServer.jsonNoAdsResponse()
                StubHttpServer.isAdTag(target) -> StubHttpServer.emptyVastResponse()
                else -> StubHttpServer.buildResponse(target, accept)
            }
            try { sendToClient(stub) } catch (_: Exception) { return false }
            // Swallow any request body so the next head parses cleanly.
            streamRequestBody(source, null, headStr)
            return !reqClose
        }
        // Protocol upgrade (WebSocket etc.): after the handshake this
        // connection is a raw bidirectional tunnel, not request/response.
        if (headStr.contains("upgrade:", ignoreCase = true)) {
            return tunnelUpgrade(rawHead, headStr, source, sendToClient)
        }
        val isHead = headStr.startsWith("HEAD ", ignoreCase = true)
        // Small bodies are buffered so a stale keep-alive upstream can be
        // retried once on a fresh connection (browsers do the same).
        val cappedBody = readBodyCapped(source, headStr, 256 * 1024)
        var attempt = 0
        while (true) {
            attempt++
            val (sock, usrc, wasReused) = ensureUpstream() ?: return false
            val out = try { sock.getOutputStream() } catch (_: Exception) {
                closeUpstream()
                return false
            }
            // Accept-Encoding is stripped ONLY for text-ish requests
            // (v0.9.1): pages/scripts/APIs come uncompressed so the ad
            // filter can read them; images/fonts/media keep their
            // compression, which keeps page loads fast.
            val fwdHead = if (isTextishRequest(target, accept)) {
                stripAcceptEncoding(rawHead)
            } else {
                rawHead
            }
            try {
                out.write(fwdHead)
                if (cappedBody != null) {
                    if (cappedBody.isNotEmpty()) out.write(cappedBody)
                } else {
                    streamRequestBody(source, out, headStr)
                }
                out.flush()
            } catch (_: Exception) {
                closeUpstream()
                // Stale reused socket can also fail at write time.
                if (wasReused && cappedBody != null && attempt == 1) continue
                return false
            }
            when (relayResponse(usrc, sendToClient, target, isHead, wasReused)) {
                UpOutcome.REUSE -> { upstreamServed++; return !reqClose }
                UpOutcome.REOPEN -> { closeUpstream(); return !reqClose }
                UpOutcome.STALE -> {
                    closeUpstream()
                    if (cappedBody != null && attempt == 1) continue
                    return false
                }
                UpOutcome.END -> return false
            }
        }
    }

    /**
     * Reads the request body (Content-Length or chunked framing) fully
     * into memory when it fits [cap]; returns null when it does not (the
     * caller then streams it), pushing back whatever was read.
     */
    private fun readBodyCapped(source: BufferedSource, headStr: String, cap: Int): ByteArray? {
        val chunked = headHasToken(headStr, "transfer-encoding", "chunked")
        val cl = contentLengthOf(headStr)
        val out = java.io.ByteArrayOutputStream()
        if (!chunked) {
            if (cl < 0) return ByteArray(0)
            if (cl > cap) return null
            var remaining = cl
            while (remaining > 0) {
                val chunk = source.readUpTo(minOf(32768, remaining)) ?: break
                out.write(chunk)
                remaining -= chunk.size
            }
            return out.toByteArray()
        }
        while (true) {
            val line = source.readLine() ?: return finishCapped(source, out, cap)
            out.write(line.toByteArray(Charsets.US_ASCII))
            out.write(byteArrayOf(13, 10))
            if (out.size() > cap) return pushBack(source, out)
            val size = line.substringBefore(';').trim().toIntOrNull(16) ?: return pushBack(source, out)
            if (size == 0) {
                while (true) {
                    val t = source.readLine() ?: return out.toByteArray()
                    out.write(t.toByteArray(Charsets.US_ASCII))
                    out.write(byteArrayOf(13, 10))
                    if (out.size() > cap) return pushBack(source, out)
                    if (t.isEmpty()) break
                }
                return out.toByteArray()
            }
            var remaining = size + 2 // chunk data + trailing CRLF
            while (remaining > 0) {
                val chunk = source.readUpTo(minOf(32768, remaining)) ?: return pushBack(source, out)
                out.write(chunk)
                remaining -= chunk.size
                if (out.size() > cap) return pushBack(source, out)
            }
        }
    }

    private fun finishCapped(
        source: BufferedSource,
        out: java.io.ByteArrayOutputStream,
        cap: Int
    ): ByteArray? = if (out.size() <= cap) out.toByteArray() else pushBack(source, out)

    private fun pushBack(source: BufferedSource, out: java.io.ByteArrayOutputStream): ByteArray? {
        source.unread(out.toByteArray())
        return null
    }

    /** Streams the request body from the client to [out] (or discards it
     * when [out] is null). Returns false if the client stream broke. */
    private fun streamRequestBody(
        source: BufferedSource,
        out: java.io.OutputStream?,
        headStr: String
    ): Boolean {
        val chunked = headHasToken(headStr, "transfer-encoding", "chunked")
        val cl = contentLengthOf(headStr)
        try {
            if (!chunked) {
                if (cl <= 0) return true
                var remaining = cl
                while (remaining > 0) {
                    val chunk = source.readUpTo(minOf(32768, remaining)) ?: return false
                    out?.write(chunk)
                    remaining -= chunk.size
                }
                return true
            }
            while (true) {
                val line = source.readLine() ?: return false
                out?.write(line.toByteArray(Charsets.US_ASCII))
                out?.write(byteArrayOf(13, 10))
                val size = line.substringBefore(';').trim().toIntOrNull(16) ?: return false
                if (size == 0) {
                    while (true) {
                        val t = source.readLine() ?: return false
                        out?.write(t.toByteArray(Charsets.US_ASCII))
                        out?.write(byteArrayOf(13, 10))
                        if (t.isEmpty()) break
                    }
                    return true
                }
                var remaining = size + 2
                while (remaining > 0) {
                    val chunk = source.readUpTo(minOf(32768, remaining)) ?: return false
                    out?.write(chunk)
                    remaining -= chunk.size
                }
            }
        } catch (_: Exception) {
            return false
        }
    }

    /** Raw bidirectional tunnel for protocol upgrades (WebSocket). */
    private fun tunnelUpgrade(
        rawHead: ByteArray,
        headStr: String,
        source: BufferedSource,
        sendToClient: (ByteArray) -> Unit
    ): Boolean {
        val (sock, usrc, _) = ensureUpstream() ?: return false
        val out = try { sock.getOutputStream() } catch (_: Exception) {
            closeUpstream()
            return false
        }
        try {
            out.write(rawHead)
            out.flush()
        } catch (_: Exception) {
            closeUpstream()
            return false
        }
        streamRequestBody(source, out, headStr)
        val ain = usrc.asInputStream()
        val t = Thread({
            try {
                val b = ByteArray(32768)
                while (!closed) {
                    val n = ain.read(b)
                    if (n <= 0) break
                    sendToClient(b.copyOf(n))
                }
            } catch (_: Exception) {
            } finally {
                close()
            }
        }, "adshield-mitm-tunnel")
        t.isDaemon = true
        t.start()
        try {
            while (!closed) {
                val chunk = source.readUpTo(32768) ?: break
                out.write(chunk)
                out.flush()
            }
        } catch (_: Exception) {
        }
        closeUpstream()
        return false
    }

    /**
     * Relays ONE response, filtering ad payloads as before, and reports
     * how the upstream connection may be treated afterwards.
     */
    private fun relayResponse(
        usrc: BufferedSource,
        sendToClient: (ByteArray) -> Unit,
        target: String,
        isHeadRequest: Boolean,
        wasReused: Boolean
    ): UpOutcome {
        val headBytes = usrc.readHead() ?: return if (wasReused) UpOutcome.STALE else UpOutcome.END
        val headerStr = String(headBytes, Charsets.US_ASCII)
        val status = statusCodeOf(headerStr)
        if (status in 100..199 && status != 101) {
            // Interim response (e.g. 100 Continue): forward, then the
            // real response head follows on the same connection.
            sendToClient(headBytes)
            return relayResponse(usrc, sendToClient, target, isHeadRequest, wasReused)
        }
        val lowerHeader = headerStr.lowercase()
        val ctLine = lowerHeader.lines().firstOrNull { it.startsWith("content-type:") } ?: ""
        MitmDebug.log("resp ct='${ctLine.trim()}' for ${target.take(70)}")
        val connClose = headHasToken(headerStr, "connection", "close") ||
            (headerStr.startsWith("HTTP/1.0") &&
                !headHasToken(headerStr, "connection", "keep-alive"))
        val chunked = lowerHeader.contains("transfer-encoding:") && lowerHeader.contains("chunked")
        val contentLength = contentLengthOf(headerStr)
        val noBody = isHeadRequest || status == 204 || status == 304 || status in 100..199
        if (noBody) {
            sendToClient(headBytes)
            return if (connClose) UpOutcome.REOPEN else UpOutcome.REUSE
        }
        // Only strict XML counts as potential VAST (NOT xhtml pages).
        val isXml = ctLine.contains("application/xml") || ctLine.contains("text/xml") ||
            ctLine.contains("application/vast") ||
            ctLine.contains("+xml") && !ctLine.contains("xhtml")
        // HTML pages AND JSON/text API responses get the ad-config
        // cleaner (player config and ad spots travel as JSON too).
        // CSS is pass-through now (v0.9.1): it cannot carry ad config
        // and streaming it keeps page loads fast.
        val cleanable = ctLine.contains("text/html") || ctLine.contains("json") ||
            ctLine.contains("javascript") || ctLine.contains("text/plain") ||
            ctLine.isBlank()
        val urlHint = target.lowercase().contains("vast") ||
            target.lowercase().contains("ima3")
        val ain = usrc.asInputStream()
        if (!isXml && !urlHint && !cleanable) {
            sendToClient(headBytes)
            val ok = streamFramed(ain, sendToClient, chunked, contentLength)
            return when {
                !ok -> UpOutcome.END
                connClose || (!chunked && contentLength < 0) -> UpOutcome.REOPEN
                else -> UpOutcome.REUSE
            }
        }
        if (cleanable && !isXml) {
            MitmDebug.log("Content filter: cleaning ad config for ${target.take(80)}")
            filterHtmlResponse(ain, sendToClient, headerStr, headBytes, headBytes.size,
                headBytes.size, ctLine.contains("text/html"))
            return if (!chunked && contentLength >= 0 && !connClose) {
                UpOutcome.REUSE
            } else {
                UpOutcome.REOPEN
            }
        }
        // VAST/XML path: buffer (bounded) and neutralize real ads.
        MitmDebug.log("VAST filter: buffering response for ${target.take(80)}")
        if (contentLength <= 0 || contentLength > 2 * 1024 * 1024) {
            MitmDebug.log("VAST filter: no/invalid Content-Length, passing through")
            sendToClient(headBytes)
            val ok = streamFramed(ain, sendToClient, chunked, contentLength)
            return when {
                !ok -> UpOutcome.END
                connClose || (!chunked && contentLength < 0) -> UpOutcome.REOPEN
                else -> UpOutcome.REUSE
            }
        }
        val bodyOut = java.io.ByteArrayOutputStream()
        var remaining = contentLength
        val buf = ByteArray(32768)
        try {
            while (remaining > 0) {
                val n = ain.read(buf, 0, minOf(buf.size, remaining))
                if (n <= 0) break
                bodyOut.write(buf, 0, n)
                remaining -= n
            }
        } catch (_: Exception) {}
        val body = bodyOut.toByteArray()
        val bodyStr = try { String(body, Charsets.UTF_8) } catch (_: Exception) { "" }
        val isVastAd = bodyStr.contains("<VAST") &&
            (bodyStr.contains("<Ad>") || bodyStr.contains("<Ad ")) &&
            bodyStr.contains("<MediaFile")
        if (isVastAd) {
            MitmDebug.log("VAST filter: AD DETECTED, replacing with empty VAST")
            val emptyVastBytes = StubHttpServer.emptyVastBytes()
            var newHeaders = headerStr
            newHeaders = newHeaders.replace(
                Regex("Content-Length: \\d+", RegexOption.IGNORE_CASE),
                "Content-Length: ${emptyVastBytes.size}"
            )
            newHeaders = newHeaders.replace(
                Regex("Transfer-Encoding: chunked\\r\\n", RegexOption.IGNORE_CASE),
                ""
            )
            sendToClient((newHeaders + String(emptyVastBytes, Charsets.US_ASCII))
                .toByteArray(Charsets.US_ASCII))
        } else {
            MitmDebug.log("VAST filter: no ad, passing through")
            sendToClient(headBytes)
            if (body.isNotEmpty()) sendToClient(body)
        }
        return if (connClose) UpOutcome.REOPEN else UpOutcome.REUSE
    }

    /** Streams exactly one response body per its framing. True when the
     * body was consumed exactly (terminal chunk seen / length met). */
    private fun streamFramed(
        inp: java.io.InputStream,
        sendToClient: (ByteArray) -> Unit,
        chunked: Boolean,
        contentLength: Int
    ): Boolean {
        return if (chunked) {
            streamChunkedRaw(inp, sendToClient)
        } else if (contentLength >= 0) {
            streamExactly(inp, sendToClient, contentLength.toLong())
        } else {
            streamRest(inp, sendToClient)
            true
        }
    }

    private fun streamExactly(
        inp: java.io.InputStream,
        sendToClient: (ByteArray) -> Unit,
        count: Long
    ): Boolean {
        var remaining = count
        val buf = ByteArray(32768)
        try {
            while (remaining > 0) {
                val n = inp.read(buf, 0, minOf(buf.size.toLong(), remaining).toInt())
                if (n <= 0) return false
                sendToClient(buf.copyOf(n))
                remaining -= n
            }
        } catch (_: Exception) {
            return false
        }
        return true
    }

    /** Forwards a chunked body chunk-by-chunk, raw and byte-exact,
     * stopping after the terminal chunk and its trailers. */
    private fun streamChunkedRaw(
        inp: java.io.InputStream,
        sendToClient: (ByteArray) -> Unit
    ): Boolean {
        try {
            while (true) {
                val line = readStreamLine(inp) ?: return false
                sendToClient(line + byteArrayOf(13, 10))
                val size = line.toString(Charsets.US_ASCII)
                    .substringBefore(';').trim().toIntOrNull(16) ?: return false
                if (size == 0) {
                    while (true) {
                        val t = readStreamLine(inp) ?: return false
                        sendToClient(t + byteArrayOf(13, 10))
                        if (t.isEmpty()) return true
                    }
                }
                if (!streamExactly(inp, sendToClient, (size + 2).toLong())) return false
            }
        } catch (_: Exception) {
            return false
        }
    }

    /** Reads one CRLF-terminated line (without the CRLF) off a stream. */
    private fun readStreamLine(inp: java.io.InputStream): ByteArray? {
        val out = java.io.ByteArrayOutputStream()
        var prev = -1
        var guard = 0
        while (guard++ < 8192) {
            val b = inp.read()
            if (b < 0) return if (out.size() == 0) null else out.toByteArray()
            if (prev == 13 && b == 10) {
                val a = out.toByteArray()
                return a.copyOf(a.size - 1) // drop the CR
            }
            out.write(b)
            prev = b
        }
        return null
    }

    private fun statusCodeOf(headerStr: String): Int =
        headerStr.substringBefore("\r\n").split(" ").getOrNull(1)?.toIntOrNull() ?: 0

    private fun contentLengthOf(headStr: String): Int {
        for (line in headStr.split("\r\n")) {
            val idx = line.indexOf(':')
            if (idx <= 0) continue
            if (line.substring(0, idx).trim().equals("content-length", ignoreCase = true)) {
                return line.substring(idx + 1).trim().toIntOrNull() ?: -1
            }
        }
        return -1
    }

    private fun headHasToken(headStr: String, name: String, token: String): Boolean {
        for (line in headStr.split("\r\n")) {
            val idx = line.indexOf(':')
            if (idx <= 0) continue
            if (!line.substring(0, idx).trim().equals(name, ignoreCase = true)) continue
            if (line.substring(idx + 1).split(",").any {
                it.trim().equals(token, ignoreCase = true)
            }) return true
        }
        return false
    }

    /** Text-ish requests get Accept-Encoding stripped for the ad filter;
     * everything else (images, fonts, media, css) keeps compression. */
    private fun isTextishRequest(target: String, accept: String): Boolean {
        if (accept.contains("text/html", ignoreCase = true)) return true
        if (accept.contains("json", ignoreCase = true)) return true
        if (accept.contains("javascript", ignoreCase = true)) return true
        val path = target.lowercase().substringBefore('?').substringBefore('#')
        val last = path.substringAfterLast('/')
        return last.endsWith(".js") || last.endsWith(".json") ||
            last.endsWith(".html") || last.endsWith(".htm") || !last.contains('.')
    }


    private fun streamRest(inp: java.io.InputStream, sendToClient: (ByteArray) -> Unit) {
        val buf = ByteArray(32768)
        try {
            while (!closed) {
                val n = inp.read(buf)
                if (n <= 0) break
                sendToClient(buf.copyOf(n))
            }
        } catch (_: Exception) {}
    }

    /**
     * Normalises the request head (v0.8.13, cache-defeat v0.8.21):
     *  - Accept-Encoding forced to identity so upstream sends uncompressed
     *    responses the ad filter can inspect.
     *  - Conditional headers (If-None-Match / If-Modified-Since / If-Range)
     *    removed so the upstream always returns a fresh 200 body instead
     *    of a 304 that would resurrect a stale, pre-filter cached page
     *    (with live ad config) in the browser.
     */
    private fun stripAcceptEncoding(rawHead: ByteArray): ByteArray {
        try {
            val headStr = String(rawHead, Charsets.US_ASCII)
            val lines = headStr.split("\r\n").toMutableList()
            var changed = false
            val it = lines.listIterator()
            while (it.hasNext()) {
                val lower = it.next().lowercase()
                if (lower.startsWith("accept-encoding:")) {
                    it.set("Accept-Encoding: identity")
                    changed = true
                } else if (lower.startsWith("if-none-match:") ||
                    lower.startsWith("if-modified-since:") ||
                    lower.startsWith("if-unmodified-since:") ||
                    lower.startsWith("if-range:")) {
                    it.remove()
                    changed = true
                } else if (lower.startsWith("expect:")) {
                    // Drop Expect: 100-continue (v0.9.1): the relay sends
                    // the body immediately; a client waiting for a 100
                    // while the server waits for the body would deadlock.
                    it.remove()
                    changed = true
                }
            }
            return if (changed) lines.joinToString("\r\n").toByteArray(Charsets.US_ASCII)
            else rawHead
        } catch (_: Exception) {
            return rawHead
        }
    }

    /**
     * HTML ad filter (v0.8.13, chunked support v0.8.14): buffers HTML pages
     * (Content-Length OR chunked, up to ~1.5MB) and removes embedded ad
     * configuration (ad-server URLs, TJ embed config). Universal — if the
     * full body can't be captured safely, the response passes through
     * untouched (never break a page).
     */
    private fun filterHtmlResponse(
        inp: java.io.InputStream,
        sendToClient: (ByteArray) -> Unit,
        headerStr: String,
        temp: ByteArray,
        foundEnd: Int,
        totalHeader: Int,
        isHtmlPage: Boolean = false
    ) {
        val chunked = headerStr.contains("transfer-encoding:", ignoreCase = true) &&
            headerStr.lowercase().contains("chunked")
        val contentLength = Regex("Content-Length: (\\d+)", RegexOption.IGNORE_CASE)
            .find(headerStr)?.groupValues?.get(1)?.toIntOrNull() ?: -1
        val bodyAlready = if (totalHeader > foundEnd) {
            temp.copyOfRange(foundEnd, totalHeader)
        } else ByteArray(0)
        val limit = 1536 * 1024
        if (!chunked && (contentLength <= 0 || contentLength > limit)) {
            sendToClient(temp.copyOf(totalHeader))
            if (contentLength > limit) {
                // Framing is known: finish exactly this body instead of
                // streaming to EOF (v0.9.1 — the upstream may be reused).
                streamExactly(inp, sendToClient, (contentLength - bodyAlready.size).toLong())
            } else {
                streamRest(inp, sendToClient)
            }
            return
        }
        // Capture the raw body (bounded). If capture is incomplete, fall
        // back to a clean pass-through of everything read so far + rest.
        val raw = java.io.ByteArrayOutputStream()
        raw.write(bodyAlready)
        val buf = ByteArray(32768)
        var complete = false
        try {
            if (chunked) {
                while (raw.size() < limit) {
                    if (dechunk(raw.toByteArray()) != null) { complete = true; break }
                    val n = inp.read(buf)
                    if (n <= 0) { complete = dechunk(raw.toByteArray()) != null; break }
                    raw.write(buf, 0, n)
                }
            } else {
                var remaining = contentLength - bodyAlready.size
                while (remaining > 0) {
                    val n = inp.read(buf, 0, minOf(buf.size, remaining))
                    if (n <= 0) break
                    raw.write(buf, 0, n)
                    remaining -= n
                }
                complete = remaining == 0
            }
        } catch (_: Exception) {}
        if (!complete) {
            MitmDebug.log("Content filter: incomplete capture (chunked=$chunked), passing through")
            sendToClient(temp.copyOf(totalHeader))
            val rest = raw.toByteArray()
            if (rest.size > bodyAlready.size) {
                sendToClient(rest.copyOfRange(bodyAlready.size, rest.size))
            }
            if (!chunked && contentLength > 0) {
                val left = contentLength - raw.size()
                if (left > 0) streamExactly(inp, sendToClient, left.toLong())
            } else {
                streamRest(inp, sendToClient)
            }
            return
        }
        val bodyBytes = if (chunked) dechunk(raw.toByteArray()) ?: raw.toByteArray()
            else raw.toByteArray()
        val html = try { String(bodyBytes, Charsets.UTF_8) } catch (_: Exception) { "" }
        if (html.isEmpty()) {
            sendToClient(temp.copyOf(foundEnd))
            sendToClient(bodyBytes)
            return
        }
        val (cleaned0, adCount) = cleanAdConfig(html)
        MitmDebug.log("Content filter: removed $adCount ad URLs (chunked=$chunked, body=${bodyBytes.size}b)")
        // uBlock-style layer (v0.8.20): on real HTML pages, inject cosmetic
        // CSS + scriptlets (popunder window.open decoy, dynamic DOM
        // sweeper) so ads inserted by page JS after load are hidden too.
        var cleaned = cleaned0
        var injected = false
        if (isHtmlPage) {
            val withBundle = injectBundle(cleaned)
            if (withBundle !== cleaned) { cleaned = withBundle; injected = true }
            if (injected) MitmDebug.log("Injected cosmetic+scriptlet bundle")
        }
        val cleanedBytes = cleaned.toByteArray(Charsets.UTF_8)
        var newHeaders = headerStr.replace(
            Regex("Transfer-Encoding: [^\r\n]*\r\n", RegexOption.IGNORE_CASE), "")
        if (injected) {
            // The page's own CSP would block the injected inline bundle.
            newHeaders = newHeaders.replace(
                Regex("Content-Security-Policy[^:]*: [^\r\n]*\r\n", RegexOption.IGNORE_CASE), "")
        }
        if (isHtmlPage) {
            // Never let the browser store the page: a stored copy can be
            // revalidated/resurrected later, and anything cached before
            // filtering (or with protection off) carries live ad config.
            newHeaders = if (newHeaders.contains("cache-control:", ignoreCase = true)) {
                newHeaders.replace(
                    Regex("Cache-Control: [^\r\n]*", RegexOption.IGNORE_CASE),
                    "Cache-Control: no-store")
            } else {
                newHeaders.trimEnd('\r', '\n') + "\r\nCache-Control: no-store\r\n\r\n"
            }
        }
        newHeaders = if (newHeaders.contains("content-length:", ignoreCase = true)) {
            newHeaders.replace(
                Regex("Content-Length: \\d+", RegexOption.IGNORE_CASE),
                "Content-Length: ${cleanedBytes.size}")
        } else {
            newHeaders.trimEnd('\r', '\n') + "\r\nContent-Length: ${cleanedBytes.size}\r\n\r\n"
        }
        sendToClient(newHeaders.toByteArray(Charsets.US_ASCII))
        sendToClient(cleanedBytes)
    }

    /**
     * Inserts the cosmetic+scriptlet bundle right after <head> (or before
     * <body>). Returns the input unchanged when there is no document
     * structure (API fragments are not pages) or it is already injected.
     */
    private fun injectBundle(html: String): String {
        if (html.contains("adshield-ubo")) return html
        val lower = html.lowercase()
        val headIdx = lower.indexOf("<head")
        if (headIdx >= 0) {
            val gt = html.indexOf('>', headIdx)
            if (gt >= 0) return html.substring(0, gt + 1) + INJECT_BUNDLE +
                html.substring(gt + 1)
        }
        val bodyIdx = lower.indexOf("<body")
        if (bodyIdx >= 0) return html.substring(0, bodyIdx) + INJECT_BUNDLE +
            html.substring(bodyIdx)
        return html
    }

    /**
     * Strips embedded ad configuration from a text body (HTML page or JSON
     * API response): VAST/ad URL fields, the TrafficJunky embed meta,
     * vastUrls arrays, and any quoted URL carrying an ad marker (plain or
     * \/-escaped). Universal — returns the cleaned text and removal count.
     */
    private fun cleanAdConfig(text: String): Pair<String, Int> {
        var cleaned = text
        var adCount = 0
        cleaned = cleaned.replace(
            Regex("\"(vastUrl|adUrl|prerollUrl|adTagUrl|vmapUrl|popunderUrl|popupUrl)\"\\s*:\\s*\"https?://[^\"]+\"", RegexOption.IGNORE_CASE),
            "\"$1\":\"\""
        )
        // Popunder/popup config objects (v0.8.19): {"...popunder...":{"url":
        // "//rotating-domain/..."}} — the URL itself carries no ad marker
        // and is often protocol-relative, so match by the KEY context and
        // empty the url value whatever domain/path it uses.
        val popObj = Regex(
            "(\"(?:[^\"]*(?:popunder|pop_under)[^\"]*)\"\\s*:\\s*\\{[^{}]*?\"url\"\\s*:\\s*\")(?:https?:)?//[^\"]*(\")",
            RegexOption.IGNORE_CASE)
        cleaned = popObj.replace(cleaned) { m ->
            adCount++
            m.groupValues[1] + m.groupValues[2]
        }
        // TrafficJunky embed context meta: carries the display-ad payloads.
        cleaned = cleaned.replace(
            Regex("<meta[^>]*trafficjunky[^>]*>", RegexOption.IGNORE_CASE), "")
        // Rotating ad-delivery domains (v0.8.22): TrafficStars-style spot
        // configs announce TODAY's delivery domain inside the page itself
        // ({"spot":"<hex>", ..., "domain":"rotating-example.com"}) — that is
        // why static blocklists never catch them. Collect any host declared
        // next to a spot id, empty the declared value (runtime-built SDK
        // URLs break), and blank literal URLs on that host below.
        val rotatingHosts = LinkedHashSet<String>()
        for (sm in Regex("\"spot\"\\s*:\\s*\"[0-9a-f]{16,}\"").findAll(cleaned)) {
            val win = cleaned.substring(
                maxOf(0, sm.range.first - 300),
                minOf(cleaned.length, sm.range.last + 900))
            for (dm in Regex("\"domain\"\\s*:\\s*\"([a-z0-9.-]+\\.[a-z]{2,})\"").findAll(win)) {
                rotatingHosts.add(dm.groupValues[1].lowercase())
            }
        }
        for (host in rotatingHosts) {
            val before = cleaned
            cleaned = cleaned
                .replace("\"domain\":\"$host\"", "\"domain\":\"\"")
                .replace("\"domain\": \"$host\"", "\"domain\": \"\"")
                .replace("\\\"domain\\\":\\\"$host\\\"", "\\\"domain\\\":\\\"\\\"")
            if (cleaned !== before) adCount++
        }
        // Spot IDs are the master key (v0.8.23): whatever domain the ad SDK
        // loads from (incl. fallbacks), with an empty spot id it can fetch
        // no creative at all. TS spot ids are 16+ hex chars in a "spot"
        // field; xh_spot_id is the same id echoed inside tracking payloads.
        val spotCount = Regex("\"spot\"\\s*:\\s*\"[0-9a-f]{16,}\"", RegexOption.IGNORE_CASE)
            .findAll(cleaned).count()
        if (spotCount > 0) {
            adCount += spotCount
            cleaned = cleaned.replace(
                Regex("\"spot\"\\s*:\\s*\"[0-9a-f]{16,}\"", RegexOption.IGNORE_CASE),
                "\"spot\":\"\"")
            cleaned = cleaned.replace(
                Regex("\"xh_spot_id\"\\s*:\\s*\"[0-9a-f]{16,}\"", RegexOption.IGNORE_CASE),
                "\"xh_spot_id\":\"\"")
            cleaned = cleaned.replace(
                Regex("""\\"xh_spot_id\\":\\"[0-9a-f]{16,}\\"""", RegexOption.IGNORE_CASE),
                "\\\"xh_spot_id\\\":\\\"\\\"")
        }
        // Empty embedded VAST URL arrays (e.g. xHamster's vastUrls) so the
        // player has no VAST tag to fetch at all (v0.8.16).
        cleaned = emptyJsonArray(cleaned, "vastUrls")
        // Blank out any URL-shaped run carrying an ad marker (v0.8.19).
        // Deliberately independent of quote pairing: naive quote matching
        // desyncs on short/escaped strings in real pages, which silently
        // exempted whole ad configs. A URL run is scheme + "//" (plain or
        // \/-escaped, or protocol-relative) up to the next delimiter.
        val adUrlMarkers = listOf("/_xa/", "vast", "preroll", "trafficjunky",
            "trafficstars", "syndicate", "popunder", "/v1/direct/", ".spot.js",
            "exoclick", "adsterra", "doubleclick",
            "googlesyndication", "adservice.", "adserver")
        val urlRun = Regex("""(?:https?:)?(?:[\\/]{2})[^\s"'`<>()]+""")
        cleaned = urlRun.replace(cleaned) { m ->
            val norm = m.value.replace("\\/", "/").lowercase()
            val onRotating = rotatingHosts.any {
                norm.contains("//$it") || norm.contains(".$it")
            }
            if (onRotating || adUrlMarkers.any { norm.contains(it) }) {
                adCount++
                ""
            } else m.value
        }
        return cleaned to adCount
    }

    /**
     * Empties a JSON array value for the given key (e.g. "vastUrls":[...])
     * wherever it appears — bracket-matched, string-aware (v0.8.16).
     */
    private fun emptyJsonArray(html: String, key: String): String {
        val needle = "\"" + key + "\""
        var result = html
        var idx = result.indexOf(needle)
        while (idx >= 0) {
            var i = result.indexOf(':', idx + needle.length)
            if (i < 0) break
            i++
            while (i < result.length && result[i].isWhitespace()) i++
            if (i >= result.length || result[i] != '[') {
                idx = result.indexOf(needle, idx + 1); continue
            }
            var depth = 0; var j = i; var inStr = false; var esc = false
            while (j < result.length) {
                val c = result[j]
                if (inStr) {
                    if (esc) esc = false
                    else if (c == '\\') esc = true
                    else if (c == '"') inStr = false
                } else {
                    if (c == '"') inStr = true
                    else if (c == '[') depth++
                    else if (c == ']') { depth--; if (depth == 0) break }
                }
                j++
            }
            if (j >= result.length) break
            result = result.substring(0, i) + "[]" + result.substring(j + 1)
            idx = result.indexOf(needle, i + 2)
        }
        return result
    }

    /** Parses an HTTP chunked body; returns the decoded bytes, or null if incomplete. */
    private fun dechunk(data: ByteArray): ByteArray? {        val out = java.io.ByteArrayOutputStream()
        var pos = 0
        while (true) {
            var eol = -1
            var i = pos
            while (i < data.size - 1) {
                if (data[i] == 13.toByte() && data[i + 1] == 10.toByte()) { eol = i; break }
                i++
            }
            if (eol < 0) return null
            val sizeStr = String(data, pos, eol - pos, Charsets.US_ASCII)
                .trim().substringBefore(';')
            val size = sizeStr.toIntOrNull(16) ?: return null
            if (size == 0) return out.toByteArray()
            if (eol + 2 + size > data.size) return null
            out.write(data, eol + 2, size)
            pos = eol + 2 + size + 2 // skip chunk data + trailing CRLF
            if (pos > data.size) return null
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
