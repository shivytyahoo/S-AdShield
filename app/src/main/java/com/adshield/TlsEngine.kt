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
    "window.open=function(url,name,feats){try{" +
    "if(isAd(url))return decoy(url);" +
    "if(url){var a=document.createElement(\"a\");a.href=url;if(a.hostname&&a.hostname!==location.hostname&&!window.__asNav)return decoy(url);}" +
    "}catch(e){}return realOpen?realOpen.apply(window,arguments):null;};" +
    "document.addEventListener(\"click\",function(ev){try{var t=ev.target;var a=t&&t.closest?t.closest(\"a[href],button,[role=button],input,select,textarea,label\"):null;if(a){window.__asNav=true;setTimeout(function(){window.__asNav=false;},1500);}}catch(e){}},true);" +
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
        val blocked = PathRules.isAdPath(target, blockPaths)
        MitmDebug.log("handleRequest host=$host target=${target.take(120)} blocked=$blocked")
        if (blocked) {
            // Blocked ad path: return the right "no ad" stub for the
            // expected content type. JSON ad endpoints (preroll_type=json)
            // get empty JSON; VAST/XML tags get empty VAST; else generic.
            val lower = target.lowercase()
            val stub = when {
                lower.contains("preroll_type=json") || lower.contains("json") ->
                    StubHttpServer.jsonNoAdsResponse()
                StubHttpServer.isAdTag(target) -> StubHttpServer.emptyVastResponse()
                else -> StubHttpServer.buildResponse(target, accept)
            }
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
            // Force plaintext responses (v0.8.13): strip Accept-Encoding so
            // HTML comes uncompressed and we can filter embedded ad config.
            val plainHead = stripAcceptEncoding(rawHead)
            out.write(plainHead)
            out.flush()
            val inp = upstream.getInputStream()
            // Universal VAST detector (v0.8.11): read response headers first.
            // If it looks like VAST/XML, buffer the body and neutralize any
            // ads. Otherwise stream through normally.
            val upToClient = Thread({
                try {
                    relayUpstreamWithVastFilter(inp, sendToClient, target)
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

    /**
     * Universal VAST detector (v0.8.11): relays upstream response to client,
     * but if the response looks like VAST/XML, buffers it and replaces any
     * actual ads with an empty VAST. Works for ANY site, no per-site patterns.
     */
    private fun relayUpstreamWithVastFilter(
        inp: java.io.InputStream,
        sendToClient: (ByteArray) -> Unit,
        target: String
    ) {
        val temp = ByteArray(16384)
        var totalHeader = 0
        var foundEnd = -1
        while (foundEnd == -1 && totalHeader < 16384) {
            val n = inp.read(temp, totalHeader, temp.size - totalHeader)
            if (n <= 0) break
            totalHeader += n
            for (i in 0 until totalHeader - 3) {
                if (temp[i] == 13.toByte() && temp[i+1] == 10.toByte() &&
                    temp[i+2] == 13.toByte() && temp[i+3] == 10.toByte()) {
                    foundEnd = i + 4
                    break
                }
            }
        }
        if (foundEnd == -1) {
            if (totalHeader > 0) sendToClient(temp.copyOf(totalHeader))
            streamRest(inp, sendToClient)
            return
        }
        val headerStr = String(temp, 0, foundEnd, Charsets.US_ASCII)
        val lowerHeader = headerStr.lowercase()
        // Log every response's Content-Type (v0.8.18): makes user-shared
        // logs decisive about which responses carry ad payloads.
        val ctLine = lowerHeader.lines().firstOrNull { it.startsWith("content-type:") } ?: ""
        MitmDebug.log("resp ct='${ctLine.trim()}' for ${target.take(70)}")
        // Only treat as potential VAST if Content-Type is strict XML
        // (NOT xhtml — that's HTML pages! Double-sending those broke sites).
        val isXml = ctLine.contains("application/xml") || ctLine.contains("text/xml") ||
            ctLine.contains("application/vast") || ctLine.contains("+xml") && !ctLine.contains("xhtml")
        // HTML pages AND JSON/text API responses get the ad-config cleaner
        // (v0.8.13/v0.8.17): modern sites deliver player ad config and
        // ad-spot widgets as JSON or plain text, sometimes with no
        // Content-Type at all (v0.8.18) — clean anything text-like.
        val cleanable = ctLine.contains("text/html") || ctLine.contains("json") ||
            ctLine.contains("javascript") || ctLine.contains("text/plain") ||
            ctLine.contains("text/css") || ctLine.isBlank()
        val urlHint = target.lowercase().contains("vast") ||
            target.lowercase().contains("ima3")
        val bodyStart = foundEnd
        val bodyAlready = if (totalHeader > bodyStart) {
            temp.copyOfRange(bodyStart, totalHeader)
        } else ByteArray(0)
        if (!isXml && !urlHint && !cleanable) {
            sendToClient(temp.copyOf(totalHeader))
            streamRest(inp, sendToClient)
            return
        }
        if (cleanable && !isXml) {
            MitmDebug.log("Content filter: cleaning ad config for ${target.take(80)}")
            filterHtmlResponse(inp, sendToClient, headerStr, temp, foundEnd, totalHeader,
                ctLine.contains("text/html"))
            return
        }
        MitmDebug.log("VAST filter: buffering response for ${target.take(80)}")
        // Get Content-Length to know how much to read
        val contentLength = Regex("Content-Length: (\\d+)", RegexOption.IGNORE_CASE)
            .find(headerStr)?.groupValues?.get(1)?.toIntOrNull() ?: -1
        if (contentLength <= 0 || contentLength > 2 * 1024 * 1024) {
            // No Content-Length or too large: pass through without buffering
            // (send everything read so far once, then stream the rest).
            MitmDebug.log("VAST filter: no/invalid Content-Length, passing through")
            sendToClient(temp.copyOf(totalHeader))
            streamRest(inp, sendToClient)
            return
        }
        val bodyOut = java.io.ByteArrayOutputStream()
        bodyOut.write(bodyAlready)
        var remaining = contentLength - bodyAlready.size
        val buf = ByteArray(32768)
        try {
            while (remaining > 0) {
                val toRead = minOf(buf.size, remaining)
                val n = inp.read(buf, 0, toRead)
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
            // Fix Content-Length
            newHeaders = newHeaders.replace(
                Regex("Content-Length: \\d+", RegexOption.IGNORE_CASE),
                "Content-Length: ${emptyVastBytes.size}"
            )
            // Remove Transfer-Encoding: chunked if present (we're sending fixed length)
            newHeaders = newHeaders.replace(
                Regex("Transfer-Encoding: chunked\r\n", RegexOption.IGNORE_CASE),
                ""
            )
            sendToClient((newHeaders + String(emptyVastBytes, Charsets.US_ASCII)).toByteArray(Charsets.US_ASCII))
        } else {
            MitmDebug.log("VAST filter: no ad, passing through")
            // Send ONLY headers (not totalHeader — that included bodyAlready,
            // which is also in `body` → double-send corrupted the response).
            sendToClient(temp.copyOf(foundEnd))
            if (body.isNotEmpty()) sendToClient(body)
            streamRest(inp, sendToClient)
        }
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
            streamRest(inp, sendToClient)
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
            streamRest(inp, sendToClient)
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
            "(\"(?:[^\"]*(?:popunder|popup|pop_under)[^\"]*)\"\\s*:\\s*\\{[^{}]*?\"url\"\\s*:\\s*\")(?:https?:)?//[^\"]*(\")",
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
