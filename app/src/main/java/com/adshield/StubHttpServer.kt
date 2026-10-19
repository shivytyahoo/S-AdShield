package com.adshield

/**
 * Surrogate (stub) HTTP responses for blocked ad/tracker domains.
 *
 * Part of v0.7.0 "anti-detect" mode. When a blocked domain is resolved to
 * AdShield's local stub IP (see [DnsPacket.surrogateResponse]), the app's
 * HTTP requests land here (via [TcpRelay]) instead of failing. Every
 * response is an empty-but-*valid* resource, modelled on uBlock Origin's
 * built-in surrogate resources:
 *
 *  - ad scripts  -> tiny JS that defines the globals pages probe for
 *                   (adsbygoogle, googletag, ga, gtag), so "did the ad
 *                   script run?" checks pass;
 *  - ad images   -> 1x1 transparent GIF, so <img> onload fires;
 *  - ad frames   -> blank HTML page;
 *  - VAST/IMA ad tags -> valid empty VAST 3.0 (deterministic "no ad").
 *  - anything else -> 204 No Content (fetch() resolves = "success").
 *
 * Nothing here fetches, renders or displays a real ad — the stub only
 * satisfies the *detection* probes so sites stop showing
 * "Ad blocker detected" walls. HTTPS bait cannot be stubbed without
 * installing a trusted CA (TLS would fail); those keep the old NXDOMAIN
 * fail-fast behaviour.
 *
 * Pure JVM (no Android APIs) so the logic is unit-testable.
 */
object StubHttpServer {

    /** 1x1 transparent GIF, 43 bytes. */
    private val PIXEL_GIF = byteArrayOf(
        0x47, 0x49, 0x46, 0x38, 0x39, 0x61,
        0x01, 0x00, 0x01, 0x00,
        0x80.toByte(), 0x00, 0x00,
        0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(), 0x00, 0x00, 0x00,
        0x21, 0xF9.toByte(), 0x04, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x2C, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
        0x02, 0x02, 0x44, 0x01, 0x00,
        0x3B
    )

    /**
     * Minimal ad-SDK stub. Pages that probe `window.adsbygoogle`,
     * `googletag`, `ga`/`gtag` see them as "loaded", exactly like uBlock
     * Origin's `googlesyndication_adsbygoogle.js` surrogate. Served ONLY
     * for blocked ad domains, never for first-party content.
     */
    private val JS_SURROGATE =
        "/* AdShield surrogate: empty ad stub, no tracking, no ads */" +
            "(function(){function n(){}" +
            "var g={loaded:true,push:function(){return 0},enable_page_level_ads:n};" +
            "window.adsbygoogle=window.adsbygoogle||g;" +
            "window.googletag=window.googletag||{cmd:[],display:n,enableServices:n," +
            "pubads:function(){return{refresh:n,clear:n,enableSyncRendering:n," +
            "collapseEmptyDivs:n,setTargeting:function(){return this},addEventListener:n}}};" +
            "window.ga=window.ga||n;window.gtag=window.gtag||n;})();"

    private val BLANK_HTML =
        "<!doctype html><html><head><meta charset=\"utf-8\">" +
            "<title></title></head><body></body></html>"

    /**
     * Valid, empty VAST 3.0: the deterministic "no ad" signal for video
     * players. Served for ad-tag-like requests on blocked ad domains —
     * the player finds zero <Ad> elements and plays content instead of
     * erroring, retrying, or falling back to a house ad (which a bare
     * 204 sometimes triggers). The stub only serves blocked ad domains,
     * so any VAST-shaped request here is ad inventory by construction.
     */
    private val EMPTY_VAST =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><VAST version=\"3.0\"></VAST>"

    /** Parses a raw HTTP request head; returns (target, acceptHeader) or null. */
    fun parseRequest(head: ByteArray): Pair<String, String>? {
        val text = head.toString(Charsets.US_ASCII)
        val eol = text.indexOf("\r\n")
        if (eol < 0) return null
        val parts = text.substring(0, eol).split(' ')
        if (parts.size < 2 || parts[1].isEmpty()) return null
        var accept = ""
        for (line in text.substring(eol + 2).split("\r\n")) {
            if (line.isEmpty()) break
            val c = line.indexOf(':')
            if (c > 0 && line.substring(0, c).trim().equals("accept", ignoreCase = true)) {
                accept = line.substring(c + 1).trim()
            }
        }
        return parts[1] to accept
    }

    /** True once the buffered bytes contain a complete HTTP request head. */
    fun hasFullHead(buffered: ByteArray): Boolean {
        if (buffered.size < 4) return false
        for (i in 0..buffered.size - 4) {
            if (buffered[i] == '\r'.code.toByte() && buffered[i + 1] == '\n'.code.toByte() &&
                buffered[i + 2] == '\r'.code.toByte() && buffered[i + 3] == '\n'.code.toByte()
            ) return true
        }
        return false
    }

    /** Builds the complete HTTP response bytes for a request. */
    fun buildResponse(target: String, acceptHeader: String): ByteArray {
        val t = target.lowercase().substringBefore('?').substringBefore('#')
        val a = acceptHeader.lowercase()
        return when {
            t.endsWith(".js") || t.endsWith(".mjs") ||
                a.contains("javascript") || a.contains("ecmascript") ->
                http(200, "OK", "text/javascript", JS_SURROGATE.toByteArray(Charsets.US_ASCII))
            t.endsWith(".css") || a.contains("text/css") ->
                http(200, "OK", "text/css", "/* AdShield surrogate */".toByteArray(Charsets.US_ASCII))
            t.endsWith(".gif") || t.endsWith(".png") || t.endsWith(".jpg") ||
                t.endsWith(".jpeg") || t.endsWith(".webp") || t.endsWith(".ico") ||
                t.endsWith(".bmp") || t.endsWith(".svg") || a.startsWith("image/") ->
                http(200, "OK", "image/gif", PIXEL_GIF)
            t.endsWith(".html") || t.endsWith(".htm") || a.contains("text/html") ->
                http(200, "OK", "text/html", BLANK_HTML.toByteArray(Charsets.US_ASCII))
            // Video ad tags (VAST/IMA): empty VAST is the deterministic
            // "no ad" signal — more robust than 204 for video players.
            t.endsWith(".xml") || t.contains("vast") || t.contains("/ima") ||
                t.contains("ima3") || a.contains("xml") ->
                http(200, "OK", "application/xml", EMPTY_VAST.toByteArray(Charsets.US_ASCII))
            else ->
                // Unknown bait URL: 204 still resolves fetch()/XHR as success,
                // which is all most detection probes check.
                ("HTTP/1.1 204 No Content\r\nConnection: close\r\n" +
                    "Cache-Control: no-store\r\n\r\n")
                    .toByteArray(Charsets.US_ASCII)
        }
    }

    /** Minimal 400 for garbage input (should be rare; keeps the relay honest). */
    fun badRequest(): ByteArray =
        http(400, "Bad Request", "text/plain", ByteArray(0))

    /**
     * True if [target] looks like a video ad-*tag* request (returns VAST)
     * rather than an ad *creative* (image/script). Used by the HTTPS path
     * filter: a blocked ad path with no creative extension (e.g.
     * `/_xa/ads`) is a tag endpoint, so the deterministic "no ad" signal
     * is an empty VAST, not a 204 (which some players retry).
     */
    fun isAdTag(target: String): Boolean {
        val t = target.lowercase().substringBefore('?').substringBefore('#')
        return t.contains("vast") || t.contains("ima3") || t.contains("/ima/") ||
            t.contains("/ads") || t.contains("adserver") || t.contains("adtag") ||
            t.contains("preroll") || t.contains("midroll") || t.contains("postroll")
    }

    /** Valid empty VAST 3.0 response: the deterministic "no ad" signal. */
    fun emptyVastResponse(): ByteArray =
        http(200, "OK", "application/xml", EMPTY_VAST.toByteArray(Charsets.US_ASCII))

    /** Raw empty VAST bytes for the universal filter. */
    fun emptyVastBytes(): ByteArray = EMPTY_VAST.toByteArray(Charsets.US_ASCII)

    /** Empty JSON "no ads" response for JSON ad endpoints (preroll_type=json). */
    fun jsonNoAdsResponse(): ByteArray {
        val json = "{\"ads\":[],\"status\":\"ok\"}"
        return http(200, "OK", "application/json", json.toByteArray(Charsets.US_ASCII))
    }

    private fun http(status: Int, reason: String, contentType: String, body: ByteArray): ByteArray {
        val head = "HTTP/1.1 $status $reason\r\n" +
            "Content-Type: $contentType\r\n" +
            "Content-Length: ${body.size}\r\n" +
            "Connection: close\r\n" +
            "Cache-Control: no-store\r\n" +
            "X-AdShield: surrogate\r\n" +
            "\r\n"
        val hb = head.toByteArray(Charsets.US_ASCII)
        val out = ByteArray(hb.size + body.size)
        System.arraycopy(hb, 0, out, 0, hb.size)
        System.arraycopy(body, 0, out, hb.size, body.size)
        return out
    }
}
