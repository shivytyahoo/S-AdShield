package com.adshield

import android.content.Context
import java.util.Locale

object AdBlocker {
    // Built-in fallback list (used until / unless the bundled full list loads).
    private val builtins = setOf(
        "doubleclick.net",
        "googlesyndication.com",
        "googleadservices.com",
        "adservice.google.com",
        "adsafeprotected.com",
        "adnxs.com",
        "adsrvr.org",
        "criteo.com",
        "taboola.com",
        "outbrain.com",
        "scorecardresearch.com",
        "zedo.com",
        "amazon-adsystem.com",
        "adform.net",
        "pubmatic.com",
        "rubiconproject.com",
        "openx.net",
        "unityads.unity3d.com",
        "applovin.com",
        "vungle.com",
        "inmobi.com",
        // Targeted in-app ad-network shield (v0.5.0): the same parents are
        // also shipped in assets/network_blocklist.txt with sources noted.
        "admobclick.com",
        "ironsrc.com",
        "is.com",
        "supersonicads.com",
        "mediation.unity3d.com",
        "iads.unity3d.com",
        "chartboosts.com",
        "startappnetwork.com",
        "startappservice.com",
        "startapp.com",
        "fyber.com",
        "inneractive.com",
        "bidmachine.io",
        "appodeal.com",
        "appodealx.com",
        // Merged from Shiv's v0.4.1 ad-network build: his unique additions.
        "admob.com",
        "ads.google.com",
        "applovinres.com",
        "applovinres.edgekey.net",
        "ironsource.com",
        "startappexchange.com",
        "digitalturbine.com"
    )

    @Volatile
    private var blocked: Set<String> = builtins

    @Volatile
    private var fullListLoaded = false

    // Streaming EXTREME pack (SSAI middlemen: Google DAI/IMA, FreeWheel,
    // SpotX, Innovid, SpringServe, Yospace...). Separate set because these
    // endpoints can stop playback in a few IMA-based players, so the user
    // gets a toggle in the app. Default ON.
    @Volatile
    private var streamingBlocked: Set<String> = emptySet()

    @Volatile
    var streamingEnabled: Boolean = true
        private set

    fun setStreamingEnabled(value: Boolean) {
        streamingEnabled = value
    }

    const val KEY_STREAMING_EXTREME = "streaming_extreme"

    /** Total domains currently active (for diagnostics). */
    fun size(): Int = blocked.size + streamingBlocked.size

    fun isFullListLoaded(): Boolean = fullListLoaded

    /**
     * Loads the bundled blocklists (one domain per line):
     *  - assets/blocklist.txt — StevenBlack unified hosts (72,232 domains)
     *  - assets/network_blocklist.txt — targeted in-app ad-network parents
     *  - assets/ad_networks.txt — Shiv's curated v0.4.1 network list, merged as-is
     *  - assets/ublock_domains.txt — uBlock Origin's uAssets lists converted to
     *    plain DNS domain rules (v0.5.2). Only host-block rules convert; the
     *    extension's cosmetic/scriptlet/redirect rules cannot run at DNS level.
     * Safe to call repeatedly; loads only once. Each file is optional on
     * its own, and the built-ins remain as fallback so protection never
     * silently disappears if an asset cannot be read.
     */
    fun init(context: Context) {
        if (fullListLoaded) return
        synchronized(this) {
            if (fullListLoaded) return
            try {
                streamingEnabled = context
                    .getSharedPreferences(AdShieldVpnService.PREFS, Context.MODE_PRIVATE)
                    .getBoolean(KEY_STREAMING_EXTREME, true)
            } catch (_: Exception) {}
            val lines = ArrayList<String>()
            for (name in listOf(
                "blocklist.txt", "network_blocklist.txt", "ad_networks.txt",
                "ublock_domains.txt", "hagezi_domains.txt", "streaming_safe_rules.txt"
            )) {
                try {
                    lines += context.assets.open(name)
                        .bufferedReader(Charsets.US_ASCII)
                        .readLines()
                } catch (_: Exception) {
                    // Optional asset: keep whatever else loaded.
                }
            }
            if (lines.isNotEmpty()) loadDomains(lines)
            try {
                loadAllowlist(
                    context.assets.open("allowlist.txt")
                        .bufferedReader(Charsets.US_ASCII)
                        .readLines()
                )
            } catch (_: Exception) {
                // Optional asset: no allowlist.
            }
            try {
                loadStreamingDomains(
                    context.assets.open("streaming_blocklist.txt")
                        .bufferedReader(Charsets.US_ASCII)
                        .readLines()
                )
            } catch (_: Exception) {
                // Streaming pack optional; main lists still protect.
            }
        }
    }

    /**
     * Loads the (now ~250k-line) lists off the caller's thread. The built-in
     * starter set is active from the first millisecond, so protection never
     * waits for the big lists, and service/activity startup never stalls.
     */
    fun initAsync(context: Context) {
        if (fullListLoaded) return
        val appContext = context.applicationContext
        Thread {
            try { init(appContext) } catch (_: Exception) {}
        }.apply {
            isDaemon = true
            name = "adshield-list-loader"
            start()
        }
    }

    /** Replaces the active set with builtins + [lines]. Visible for JVM tests. */
    fun loadDomains(lines: Iterable<String>) {
        val parsed = HashSet<String>(280_000)
        parsed.addAll(builtins)
        parsed.addAll(parseDomainSet(lines))
        blocked = parsed
        fullListLoaded = true
    }

    /** Replaces the streaming EXTREME set. Visible for JVM tests. */
    fun loadStreamingDomains(lines: Iterable<String>) {
        streamingBlocked = parseDomainSet(lines)
    }

    /**
     * v0.9.0: functionality allowlist — domains a site's own features are
     * welded to (e.g. AdSpyglass, whose JS drives sextb-style players and
     * lazy thumbnails; blocking it at DNS broke the sites themselves).
     * Allowed domains resolve normally; their ads are fought at the
     * MITM layer instead (config cleaning, popunder trap, path rules).
     */
    @Volatile
    private var allowed: Set<String> = emptySet()

    /** Replaces the allowlist set. Visible for JVM tests. */
    fun loadAllowlist(lines: Iterable<String>) {
        allowed = parseDomainSet(lines)
    }

    private fun parseDomainSet(lines: Iterable<String>): HashSet<String> {
        val parsed = HashSet<String>()
        for (raw in lines) {
            val d = raw.trim().lowercase(Locale.US).trim('.')
            if (d.startsWith("#")) continue
            if (d.isNotEmpty() && d.contains('.') && !d.contains(' ') && !d.contains('/')) {
                parsed.add(d)
            }
        }
        return parsed
    }

    /**
     * Suffix-walk matcher: checks the host itself, then each parent domain.
     * `ads.doubleclick.net` matches an entry for `doubleclick.net`, while an
     * unrelated `notdoubleclick.net` never matches.
     */
    fun isBlocked(host: String): Boolean {
        val h = host.trim().trim('.').lowercase(Locale.US)
        if (matches(allowed, h)) return false
        if (matches(blocked, h)) return true
        if (streamingEnabled && matches(streamingBlocked, h)) return true
        return false
    }

    private fun matches(set: Set<String>, host: String): Boolean {
        var h = host
        while (true) {
            if (set.contains(h)) return true
            val dot = h.indexOf('.')
            if (dot < 0) return false
            h = h.substring(dot + 1)
        }
    }
}
