package com.adshield

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import java.io.File
import java.net.HttpURLConnection
import java.net.URL

/**
 * Blocklist updates (v1.1.0).
 *
 * Downloads the upstream sources behind the two bundled lists and stores
 * them under filesDir/lists/. AdBlocker prefers a downloaded file over its
 * bundled asset when one exists. Only hosts-style sources are used — the
 * uBlock asset list stays bundled because its conversion cannot run
 * on-device.
 */
data class ListSource(
    val name: String,
    val fileName: String,
    val url: String
)

object ListUpdater {
    val SOURCES = listOf(
        ListSource(
            "StevenBlack hosts",
            "blocklist.txt",
            "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
        ),
        ListSource(
            "HaGeZi Multi PRO",
            "hagezi_domains.txt",
            "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro-onlydomains.txt"
        )
    )

    /** "wifi" (default) or "any" (Wi-Fi or mobile data). */
    const val KEY_UPDATE_NETWORK = "list_update_network"
    const val KEY_LAST_UPDATED = "list_last_updated"
    /** "fileName=count;fileName=count" for the downloaded sources. */
    const val KEY_SOURCE_COUNTS = "list_source_counts"

    fun listsDir(context: Context): File =
        File(context.filesDir, "lists").apply { mkdirs() }

    /** True when the current network is allowed by the user's update setting. */
    fun networkAllowed(context: Context): Boolean {
        val prefs = context.getSharedPreferences(
            AdShieldVpnService.PREFS, Context.MODE_PRIVATE
        )
        val setting = prefs.getString(KEY_UPDATE_NETWORK, "wifi") ?: "wifi"
        if (setting == "any") return true
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE)
            as? ConnectivityManager ?: return false
        val caps = cm.getNetworkCapabilities(cm.activeNetwork) ?: return false
        return caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
    }

    /**
     * Downloads every source on the caller's thread. Returns (ok, message).
     * A source is only replaced after a complete, sane download (at least
     * 1000 domains); a failed source aborts the whole update so the active
     * lists are never left half-replaced.
     */
    fun updateAll(context: Context): Pair<Boolean, String> {
        if (!networkAllowed(context)) {
            return false to
                "Wi-Fi required — allow mobile data in the setting below to update on mobile"
        }
        var updated = 0
        var totalDomains = 0
        val counts = StringBuilder()
        for (src in SOURCES) {
            val domains = downloadDomains(src.url)
                ?: return false to "Download failed: ${src.name}"
            if (domains.size < 1000) {
                return false to
                    "Download looks incomplete: ${src.name} (${domains.size} domains)"
            }
            val dir = listsDir(context)
            val tmp = File(dir, src.fileName + ".tmp")
            val out = File(dir, src.fileName)
            tmp.writeText(domains.joinToString("\n"))
            tmp.renameTo(out)
            updated++
            totalDomains += domains.size
            counts.append("${src.fileName}=${domains.size};")
        }
        context.getSharedPreferences(AdShieldVpnService.PREFS, Context.MODE_PRIVATE)
            .edit()
            .putLong(KEY_LAST_UPDATED, System.currentTimeMillis())
            .putString(KEY_SOURCE_COUNTS, counts.toString())
            .apply()
        return true to "Updated $updated lists, $totalDomains domains"
    }

    private fun downloadDomains(url: String): Set<String>? {
        return try {
            val conn = URL(url).openConnection() as HttpURLConnection
            conn.connectTimeout = 15000
            conn.readTimeout = 60000
            conn.setRequestProperty("User-Agent", "S-AdShield/1.2.0")
            if (conn.responseCode != HttpURLConnection.HTTP_OK) return null
            val lines = conn.inputStream.bufferedReader(Charsets.UTF_8).readLines()
            AdBlocker.parseDomains(lines)
        } catch (_: Exception) {
            null
        }
    }
}
