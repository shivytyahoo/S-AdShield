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
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.SystemUpdate
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import com.adshield.ui.DashboardScreen
import com.adshield.ui.DashboardState
import com.adshield.ui.ListSourceState
import com.adshield.ui.ListsScreen
import com.adshield.ui.theme.AdShieldTheme
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import shivyt.android.adshield.R

/**
 * S-AdShield 1.2.0: dashboard with bottom navigation.
 *
 * Tabs: Home (protection + stats) and Lists (blocklist updates).
 * The Request Log and per-app modes from 1.1.0 were removed in 1.2.0.
 */
class MainActivity : ComponentActivity() {

    private var uiState by mutableStateOf(DashboardState())
    private var selectedTab by mutableStateOf(0)
    private var listNetwork by mutableStateOf("wifi")
    private var listLastUpdated by mutableStateOf<Long?>(null)
    private var listSources by mutableStateOf<List<ListSourceState>>(emptyList())
    private var listUpdating by mutableStateOf(false)
    private var listStatus by mutableStateOf<String?>(null)

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
        refreshListsState()
        setContent {
            AdShieldTheme {
                Scaffold(
                    bottomBar = {
                        NavigationBar {
                            NavigationBarItem(
                                selected = selectedTab == 0,
                                onClick = { selectedTab = 0 },
                                icon = {
                                    Icon(Icons.Filled.Home, contentDescription = null)
                                },
                                label = { Text(stringResource(R.string.nav_home)) }
                            )
                            NavigationBarItem(
                                selected = selectedTab == 1,
                                onClick = { selectedTab = 1 },
                                icon = {
                                    Icon(Icons.Filled.SystemUpdate, contentDescription = null)
                                },
                                label = { Text(stringResource(R.string.nav_lists)) }
                            )
                        }
                    }
                ) { padding ->
                    when (selectedTab) {
                        0 -> DashboardScreen(
                            state = uiState,
                            onToggleProtection = {
                                if (uiState.enabled) stopShield() else startShieldWithPermission()
                            },
                            onToggleStreaming = ::toggleStreamingExtreme,
                            onToggleAntiDetect = ::toggleAntiDetect,
                            onOpenBatterySettings = ::openBatterySettings,
                            modifier = Modifier.padding(padding)
                        )
                        else -> ListsScreen(
                            sources = listSources,
                            networkSetting = listNetwork,
                            lastUpdatedText = listLastUpdated?.let {
                                SimpleDateFormat("d MMM yyyy, HH:mm", Locale.getDefault())
                                    .format(Date(it))
                            },
                            updating = listUpdating,
                            statusMessage = listStatus,
                            onSetNetwork = ::setUpdateNetwork,
                            onUpdateNow = ::updateLists,
                            modifier = Modifier.padding(padding)
                        )
                    }
                }
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
            batteryExempt = exempt
        )
    }

    // ---------- List updates ----------

    private fun refreshListsState() {
        val prefs = getSharedPreferences(AdShieldVpnService.PREFS, MODE_PRIVATE)
        listNetwork = prefs.getString(ListUpdater.KEY_UPDATE_NETWORK, "wifi") ?: "wifi"
        val last = prefs.getLong(ListUpdater.KEY_LAST_UPDATED, 0)
        listLastUpdated = if (last > 0) last else null
        val countMap = (prefs.getString(ListUpdater.KEY_SOURCE_COUNTS, "") ?: "")
            .split(";")
            .mapNotNull {
                val parts = it.split("=")
                if (parts.size == 2) parts[0] to (parts[1].toIntOrNull() ?: 0) else null
            }.toMap()
        listSources = ListUpdater.SOURCES.map { src ->
            val file = File(filesDir, "lists/${src.fileName}")
            ListSourceState(
                name = src.name,
                fileName = src.fileName,
                domains = countMap[src.fileName],
                downloaded = file.isFile && file.length() > 0
            )
        }
    }

    private fun setUpdateNetwork(setting: String) {
        getSharedPreferences(AdShieldVpnService.PREFS, MODE_PRIVATE).edit()
            .putString(ListUpdater.KEY_UPDATE_NETWORK, setting).apply()
        refreshListsState()
    }

    private fun updateLists() {
        if (listUpdating) return
        listUpdating = true
        listStatus = null
        Thread {
            val (ok, message) = ListUpdater.updateAll(applicationContext)
            if (ok) AdBlocker.reloadAsync(applicationContext)
            runOnUiThread {
                listUpdating = false
                listStatus = message
                refreshListsState()
            }
        }.apply {
            isDaemon = true
            name = "adshield-list-updater"
            start()
        }
    }

    // ---------- Protection controls (unchanged from 1.0.0) ----------

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
