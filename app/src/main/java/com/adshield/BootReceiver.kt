package com.adshield

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build

/**
 * Restarts protection after a reboot, but only if the user left it on.
 * The user's own on/off wish (KEY_USER_ENABLED) is the source of truth:
 * an explicit STOP in the app is never overridden by a reboot.
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        if (intent?.action != Intent.ACTION_BOOT_COMPLETED) return
        val prefs = context.getSharedPreferences(AdShieldVpnService.PREFS, Context.MODE_PRIVATE)
        if (!prefs.getBoolean(AdShieldVpnService.KEY_USER_ENABLED, false)) return
        val serviceIntent = Intent(context, AdShieldVpnService::class.java)
        try {
            if (Build.VERSION.SDK_INT >= 26) {
                context.startForegroundService(serviceIntent)
            } else {
                context.startService(serviceIntent)
            }
        } catch (_: Exception) {
            // Some OEM builds restrict background starts even after boot;
            // the user can also enable Android's Always-on VPN for AdShield.
        }
    }
}
