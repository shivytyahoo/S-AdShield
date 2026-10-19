package com.adshield

/**
 * First-party ad-path rules for the HTTPS path filter (v0.8.0).
 *
 * DNS blocking cannot see URL paths, so first-party ad endpoints (e.g.
 * pornhub.com/_xa/ads) sail through. When the HTTPS filter MITMs a listed
 * domain, every plaintext HTTP request's path is matched here:
 *
 *  - a matching path is an ad/tag request -> the caller serves a stub
 *    (empty VAST for vast-like targets, 204 otherwise);
 *  - anything else is proxied untouched to the real server.
 *
 * Rules are plain lowercase substrings matched against the lowercased
 * request path (query string stripped). Users can add their own via
 * the app's domain/rule editor; defaults target known first-party
 * ad-tag endpoints.
 *
 * Pure JVM (no Android APIs) so the matcher is unit-testable.
 */
object PathRules {

    /** Default blocked path substrings (lowercase). */
    val DEFAULT_BLOCKED_PATHS: List<String> = listOf(
        "/_xa/ads",          // Pornhub/Aylo first-party ad-tag endpoint
        "/_xa/ad",
        "vast",              // VAST ad tags served first-party
        "ima3",              // IMA SDK ad requests
        "/ima/",
        "doubleclick.net",   // goog ad hosts sometimes embedded in paths
        "/adserver/",
        "/adsdelivery/",
        "popads",
        "exoclick",
        "adsterra",
        "/bannerads/",
        // Streaming ad platforms (v0.8.1): FreeWheel, SpotX, SpringServe,
        // Anvato, Amazon AAX — first-party ad paths on streaming sites.
        "freewheel",
        "spotxchange",
        "spotx",
        "springserve",
        "anvato",
        "/aax/",             // Amazon Advertising
        "amazon-adsystem",
        "/ads/vast",
        "/ad/vast"
    )

    /**
     * True if [rawTarget] (request-target, may include query) looks like
     * an ad/tag request under [blockedPaths].
     */
    fun isAdPath(rawTarget: String, blockedPaths: Collection<String> = DEFAULT_BLOCKED_PATHS): Boolean {
        val path = rawTarget.lowercase()
            .substringBefore('?')
            .substringBefore('#')
        if (path.isEmpty()) return false
        for (rule in blockedPaths) {
            val r = rule.lowercase().trim()
            if (r.isNotEmpty() && path.contains(r)) return true
        }
        return false
    }

    /** Normalises a user-entered rule line; null = ignore the line. */
    fun normaliseRule(line: String): String? {
        val t = line.trim().lowercase()
        if (t.isEmpty() || t.startsWith("#")) return null
        return t
    }

    /** Parses the stored multiline rule text into a clean list. */
    fun parseRules(text: String?): List<String> {
        if (text.isNullOrBlank()) return DEFAULT_BLOCKED_PATHS
        val out = LinkedHashSet<String>()
        for (line in text.split('\n')) {
            normaliseRule(line)?.let { out.add(it) }
        }
        return if (out.isEmpty()) DEFAULT_BLOCKED_PATHS else out.toList()
    }
}
