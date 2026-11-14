package com.adshield

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.PowerManager
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import com.adshield.ui.DashboardScreen
import com.adshield.ui.DashboardState
import com.adshield.ui.theme.AdShieldTheme

/**
 * S-AdShield 1.0.0 dashboard (Jetpack Compose + Material 3).
 *
 * DNS-only now: the HTTPS Path Filter MITM and Auto-Skip features were
 * removed in 1.0.0, so this screen is just the protection switch, live
 * stats, the two DNS-layer toggles, and a migration note for users who
 * installed the old HTTPS certificate.
 */
class MainActivity : ComponentActivity() {

    private var uiState by mutableStateOf(DashboardState())
    private val handler = Handler(Looper.getMainLooper())
    private val refresh = object : Runnable {
        override fun run() {
            refreshStats()
            handler.postDelayed(this, 1200)
        }
    }

    private val vpnPermissionLauncher =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            if (result.resultCode == RESULT_OK) startShield()
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // If a previous run crashed, show the captured report instead of
        // the dashboard so the cause can be diagnosed from the device.
        if (ShieldApp.hasCrashReport(application)) {
            startActivity(Intent(this, CrashActivity::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_CLEAR_TASK or Intent.FLAG_ACTIVITY_NEW_TASK)
            })
            finish()
            return
        }
        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(arrayOf(android.Manifest.permission.POST_NOTIFICATIONS), 101)
        }
        enableEdgeToEdge()
        refreshStats()
        setContent {
            AdShieldTheme {
                DashboardScreen(
                    state = uiState,
                    onToggleProtection = {
                        if (uiState.enabled) stopShield() else startShieldWithPermission()
                    },
                    onToggleStreaming = ::toggleStreamingExtreme,
                    onToggleAntiDetect = ::toggleAntiDetect,
                    onOpenBatterySettings = ::openBatterySettings
                )
            }
        }
    }

    override fun onResume() {
        super.onResume()
        handler.post(refresh)
    }

    override fun onPause() {
        handler.removeCallbacks(refresh)
        super.onPause()
    }

    private fun refreshStats() {
        val p = getSharedPreferences(AdShieldVpnService.PREFS, MODE_PRIVATE)
        val q = p.getLong(AdShieldVpnService.KEY_QUERIES, 0)
        val b = p.getLong(AdShieldVpnService.KEY_BLOCKED, 0)
        val pm = getSystemService(Context.POWER_SERVICE) as? PowerManager
        val exempt = Build.VERSION.SDK_INT < 23 ||
            pm?.isIgnoringBatteryOptimizations(packageName) == true
        uiState = DashboardState(
            enabled = p.getBoolean(AdShieldVpnService.KEY_RUNNING, false),
            queries = q,
            blocked = b,
            blockRate = if (q == 0L) 0 else (b * 100 / q).coerceIn(0, 100).toInt(),
            streamingOn = p.getBoolean(AdBlocker.KEY_STREAMING_EXTREME, true),
            antiDetectOn = p.getBoolean(AdShieldVpnService.KEY_SURROGATE, true),
            batteryExempt = exempt,
            // Legacy pre-1.0.0 flag: true when the user installed the old
            // HTTPS MITM certificate. Read-only now; drives the migration note.
            showMigrationNote = p.getBoolean(AdShieldVpnService.KEY_MITM_CA_DONE, false)
        )
    }

    private fun toggleStreamingExtreme() {
        val prefs = getSharedPreferences(AdShieldVpnService.PREFS, MODE_PRIVATE)
        val next = !prefs.getBoolean(AdBlocker.KEY_STREAMING_EXTREME, true)
        prefs.edit().putBoolean(AdBlocker.KEY_STREAMING_EXTREME, next).apply()
        AdBlocker.setStreamingEnabled(next)
        refreshStats()
    }

    private fun toggleAntiDetect() {
        val prefs = getSharedPreferences(AdShieldVpnService.PREFS, MODE_PRIVATE)
        val next = !prefs.getBoolean(AdShieldVpnService.KEY_SURROGATE, true)
        prefs.edit().putBoolean(AdShieldVpnService.KEY_SURROGATE, next).apply()
        refreshStats()
    }

    private fun openBatterySettings() {
        try {
            val intent = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
                data = Uri.parse("package:$packageName")
            }
            startActivity(intent)
        } catch (_: Exception) {
            try {
                startActivity(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS))
            } catch (_: Exception) {
            }
        }
    }

    private fun startShieldWithPermission() {
        val intent = VpnService.prepare(this)
        if (intent != null) vpnPermissionLauncher.launch(intent) else startShield()
    }

    private fun startShield() {
        val intent = Intent(this, AdShieldVpnService::class.java)
        if (Build.VERSION.SDK_INT >= 26) startForegroundService(intent) else startService(intent)
        refreshStats()
    }

    private fun stopShield() {
        try {
            startService(
                Intent(this, AdShieldVpnService::class.java)
                    .setAction(AdShieldVpnService.ACTION_STOP)
            )
        } catch (_: Exception) {
        }
        stopService(Intent(this, AdShieldVpnService::class.java))
        getSharedPreferences(AdShieldVpnService.PREFS, MODE_PRIVATE).edit()
            .putBoolean(AdShieldVpnService.KEY_RUNNING, false).apply()
        refreshStats()
    }
}
