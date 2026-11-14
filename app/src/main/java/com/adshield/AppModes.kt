package com.adshield

import android.content.SharedPreferences

/**
 * Per-app protection modes (v1.1.0).
 *
 * ADS — the app goes through the VPN with normal DNS filtering (default).
 * OFF — the app bypasses the VPN entirely (addDisallowedApplication).
 * NO_INTERNET — every DNS query from the app gets NXDOMAIN, so the app
 * effectively has no internet (apps with hardcoded IPs are the only
 * exception — a DNS-only VPN cannot drop those).
 *
 * Stored as a StringSet of "package|MODE" entries; apps not listed are ADS.
 */
enum class AppMode {
    ADS,
    OFF,
    NO_INTERNET
}

object AppModes {
    const val KEY_APP_MODES = "app_modes"
    private const val SEP = "|"

    fun getMode(prefs: SharedPreferences, pkg: String): AppMode {
        val set = prefs.getStringSet(KEY_APP_MODES, emptySet()) ?: return AppMode.ADS
        for (entry in set) {
            val parts = entry.split(SEP)
            if (parts.size == 2 && parts[0] == pkg) {
                return try {
                    AppMode.valueOf(parts[1])
                } catch (_: Exception) {
                    AppMode.ADS
                }
            }
        }
        return AppMode.ADS
    }

    fun setMode(prefs: SharedPreferences, pkg: String, mode: AppMode) {
        val set = (prefs.getStringSet(KEY_APP_MODES, emptySet()) ?: emptySet()).toMutableSet()
        set.removeAll { it.startsWith("$pkg$SEP") }
        if (mode != AppMode.ADS) set.add("$pkg$SEP${mode.name}")
        prefs.edit().putStringSet(KEY_APP_MODES, set).apply()
    }

    /** Packages currently set to OFF (bypass the VPN). */
    fun offPackages(prefs: SharedPreferences): List<String> {
        val set = prefs.getStringSet(KEY_APP_MODES, emptySet()) ?: return emptyList()
        return set.mapNotNull { entry ->
            val parts = entry.split(SEP)
            if (parts.size == 2 && parts[1] == AppMode.OFF.name) parts[0] else null
        }
    }
}
