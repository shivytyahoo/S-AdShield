package com.adshield

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.PowerManager
import android.provider.Settings
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.Window
import android.view.animation.AccelerateDecelerateInterpolator
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.animation.ObjectAnimator
import android.animation.ValueAnimator
import android.app.AlertDialog
import android.security.KeyChain
import android.widget.EditText
import android.widget.Toast

/**
 * Modern AdShield dashboard. Framework-only UI keeps the APK small and works
 * on phones as well as Android TV. No entitlement/license bypass is performed.
 */
class MainActivity : Activity() {
    private lateinit var toggleButton: Button
    private lateinit var batteryButton: Button
    private lateinit var streamingButton: Button
    private lateinit var antiDetectButton: Button
    private lateinit var mitmButton: Button
    private lateinit var caButton: Button
    private lateinit var domainsButton: Button
    private lateinit var logButton: Button
    private lateinit var statusText: TextView
    private lateinit var shieldIcon: TextView
    private lateinit var queryValue: TextView
    private lateinit var blockedValue: TextView
    private lateinit var rateValue: TextView
    private lateinit var protectionCard: LinearLayout
    private var enabled = false
    private var pulse: ObjectAnimator? = null
    private val handler = Handler(Looper.getMainLooper())
    private val refresh = object : Runnable {
        override fun run() { refreshStats(); handler.postDelayed(this, 1200) }
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
        window.statusBarColor = Color.rgb(8, 17, 31)
        window.navigationBarColor = Color.rgb(8, 17, 31)
        if (Build.VERSION.SDK_INT >= 23) window.decorView.systemUiVisibility = 0

        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(arrayOf(android.Manifest.permission.POST_NOTIFICATIONS), 101)
        }

        val scroll = ScrollView(this).apply { setBackgroundColor(color("#08111F")); isFillViewport = true }
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(22), dp(18), dp(22), dp(28))
        }
        // Android 15+ draws apps edge-to-edge: without this, the dashboard
        // slides under the status bar (top) and navigation bar (bottom),
        // exactly the overlap in Shiv's 2026-10-08 screenshot. Push the
        // root's own padding out by the real system-bar insets; the
        // ScrollView keeps the dark background behind the bars themselves.
        val basePadLeft = dp(22)
        val basePadTop = dp(18)
        val basePadRight = dp(22)
        val basePadBottom = dp(28)
        root.setOnApplyWindowInsetsListener { v, insets ->
            @Suppress("DEPRECATION")
            v.setPadding(
                basePadLeft + insets.systemWindowInsetLeft,
                basePadTop + insets.systemWindowInsetTop,
                basePadRight + insets.systemWindowInsetRight,
                basePadBottom + insets.systemWindowInsetBottom
            )
            insets
        }
        scroll.addView(root)

        val top = LinearLayout(this).apply { gravity = Gravity.CENTER_VERTICAL }
        val brand = TextView(this).apply {
            text = "S-ADSHIELD"
            textSize = 24f
            setTextColor(color("#F4F7FB"))
            typeface = Typeface.create("sans", Typeface.BOLD)
            letterSpacing = .08f
        }
        top.addView(brand, LinearLayout.LayoutParams(0, dp(50), 1f))
        val live = pill("LOCAL • PRIVATE")
        top.addView(live)
        root.addView(top)
        root.addView(space(12))

        val hero = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
            setPadding(dp(18), dp(24), dp(18), dp(24))
            background = rounded("#101C2E", 28)
        }
        shieldIcon = TextView(this).apply {
            text = "◈"
            textSize = 54f
            gravity = Gravity.CENTER
            setTextColor(color("#59E1B8"))
            setShadowLayer(24f, 0f, 0f, color("#3359E1B8"))
        }
        hero.addView(shieldIcon, LinearLayout.LayoutParams(dp(92), dp(92)))
        hero.addView(space(6))
        statusText = TextView(this).apply {
            text = "Protection is off"
            textSize = 22f
            gravity = Gravity.CENTER
            setTextColor(color("#F4F7FB"))
            typeface = Typeface.DEFAULT_BOLD
        }
        hero.addView(statusText)
        hero.addView(space(6))
        val desc = TextView(this).apply {
            text = "System-wide DNS protection against ads & trackers"
            textSize = 14f
            gravity = Gravity.CENTER
            setTextColor(color("#93A4BA"))
        }
        hero.addView(desc)
        hero.addView(space(18))
        toggleButton = Button(this).apply {
            text = "START PROTECTION"
            textSize = 14f
            typeface = Typeface.DEFAULT_BOLD
            isAllCaps = false
            isFocusable = true
            isFocusableInTouchMode = true
            setTextColor(color("#08111F"))
            background = rounded("#59E1B8", 18)
            setPadding(dp(18), 0, dp(18), 0)
            setOnClickListener { if (enabled) stopShield() else startShieldWithPermission() }
        }
        hero.addView(toggleButton, LinearLayout.LayoutParams(-1, dp(56)))
        hero.addView(space(10))
        batteryButton = Button(this).apply {
            text = "BATTERY: UNRESTRICTED KARO (24x7 KE LIYE)"
            textSize = 11f
            typeface = Typeface.DEFAULT_BOLD
            isAllCaps = false
            isFocusable = true
            isFocusableInTouchMode = true
            setTextColor(color("#93A4BA"))
            background = rounded("#15243A", 14)
            setPadding(dp(12), 0, dp(12), 0)
            setOnClickListener { openBatterySettings() }
        }
        hero.addView(batteryButton, LinearLayout.LayoutParams(-1, dp(42)))
        hero.addView(space(8))
        streamingButton = Button(this).apply {
            text = "STREAMING EXTREME: ON"
            textSize = 11f
            typeface = Typeface.DEFAULT_BOLD
            isAllCaps = false
            isFocusable = true
            isFocusableInTouchMode = true
            setTextColor(color("#59E1B8"))
            background = rounded("#16352F", 14)
            setPadding(dp(12), 0, dp(12), 0)
            setOnClickListener { toggleStreamingExtreme() }
        }
        hero.addView(streamingButton, LinearLayout.LayoutParams(-1, dp(42)))
        hero.addView(space(8))
        antiDetectButton = Button(this).apply {
            text = "ANTI-DETECT: ON"
            textSize = 11f
            typeface = Typeface.DEFAULT_BOLD
            isAllCaps = false
            isFocusable = true
            isFocusableInTouchMode = true
            setTextColor(color("#59E1B8"))
            background = rounded("#16352F", 14)
            setPadding(dp(12), 0, dp(12), 0)
            setOnClickListener { toggleAntiDetect() }
        }
        hero.addView(antiDetectButton, LinearLayout.LayoutParams(-1, dp(42)))
        hero.addView(space(8))
        mitmButton = Button(this).apply {
            textSize = 11f
            typeface = Typeface.DEFAULT_BOLD
            isAllCaps = false
            isFocusable = true
            isFocusableInTouchMode = true
            setOnClickListener { toggleMitm() }
        }
        hero.addView(mitmButton, LinearLayout.LayoutParams(-1, dp(42)))
        hero.addView(space(8))
        caButton = Button(this).apply {
            text = "INSTALL CA CERTIFICATE"
            textSize = 11f
            typeface = Typeface.DEFAULT_BOLD
            isAllCaps = false
            setTextColor(color("#08111F"))
            background = rounded("#FFB84D", 14)
            setPadding(dp(12), 0, dp(12), 0)
            setOnClickListener { installCaCert() }
        }
        hero.addView(caButton, LinearLayout.LayoutParams(-1, dp(42)))
        hero.addView(space(8))
        domainsButton = Button(this).apply {
            text = "MITM DOMAINS"
            textSize = 11f
            typeface = Typeface.DEFAULT_BOLD
            isAllCaps = false
            setTextColor(color("#93A4BA"))
            background = rounded("#16352F", 14)
            setPadding(dp(12), 0, dp(12), 0)
            setOnClickListener { showDomainEditor() }
        }
        hero.addView(domainsButton, LinearLayout.LayoutParams(-1, dp(42)))
        hero.addView(space(8))
        logButton = Button(this).apply {
            text = "SHARE MITM LOG"
            textSize = 11f
            typeface = Typeface.DEFAULT_BOLD
            isAllCaps = false
            setTextColor(color("#93A4BA"))
            background = rounded("#16352F", 14)
            setPadding(dp(12), 0, dp(12), 0)
            setOnClickListener { shareMitmLog() }
        }
        hero.addView(logButton, LinearLayout.LayoutParams(-1, dp(42)))
        updateMitmButton()
        root.addView(hero)
        protectionCard = hero

        root.addView(space(14))
        val section = TextView(this).apply {
            text = "LIVE OVERVIEW"
            textSize = 12f
            letterSpacing = .12f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(color("#93A4BA"))
        }
        root.addView(section)
        root.addView(space(8))

        val stats = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        queryValue = statCard(stats, "QUERIES", "0")
        blockedValue = statCard(stats, "BLOCKED", "0")
        rateValue = statCard(stats, "BLOCK RATE", "0%")
        root.addView(stats)
        root.addView(space(14))

        val engine = infoCard("PROTECTION ENGINE", "Local VPN DNS filter", "No remote VPN server • traffic stays on device")
        root.addView(engine)
        root.addView(space(10))
        val sources = infoCard("FILTER SOURCES", "250,000+ domains — EXTREME shield", "HaGeZi PRO • uBlock • StevenBlack • 7-network pack • Streaming SSAI pack (Prime / JioHotstar / Netflix)")
        root.addView(sources)
        root.addView(space(18))

        val footer = TextView(this).apply {
            text = "Developed with love by Shiv  •  S-AdShield v0.9.3"
            textSize = 12f
            gravity = Gravity.CENTER
            setTextColor(color("#60738B"))
        }
        root.addView(footer)

        setContentView(scroll)
        root.requestApplyInsets()
        toggleButton.requestFocus()
        refreshStats()
    }

    private fun statCard(parent: ViewGroup, label: String, initial: String): TextView {
        val card = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(14), dp(15), dp(14), dp(14))
            background = rounded("#101C2E", 20)
        }
        val value = TextView(this).apply {
            text = initial
            textSize = 22f
            setTextColor(color("#F4F7FB"))
            typeface = Typeface.DEFAULT_BOLD
        }
        val title = TextView(this).apply {
            text = label
            textSize = 10f
            letterSpacing = .08f
            setTextColor(color("#93A4BA"))
        }
        card.addView(value)
        card.addView(space(4))
        card.addView(title)
        val lp = LinearLayout.LayoutParams(0, dp(82), 1f).apply { marginEnd = dp(6) }
        parent.addView(card, lp)
        return value
    }

    private fun infoCard(title: String, headline: String, detail: String): LinearLayout {
        val card = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(14), dp(16), dp(14))
            background = rounded("#101C2E", 20)
        }
        val t = TextView(this).apply { text = title; textSize = 10f; letterSpacing = .1f; setTextColor(color("#59E1B8")) }
        val h = TextView(this).apply { text = headline; textSize = 16f; typeface = Typeface.DEFAULT_BOLD; setTextColor(color("#F4F7FB")) }
        val d = TextView(this).apply { text = detail; textSize = 12f; setTextColor(color("#93A4BA")) }
        card.addView(t); card.addView(space(5)); card.addView(h); card.addView(space(3)); card.addView(d)
        return card
    }

    private fun pill(text: String): TextView = TextView(this).apply {
        this.text = text; textSize = 10f; letterSpacing = .08f; gravity = Gravity.CENTER
        setTextColor(color("#59E1B8")); setPadding(dp(11), 0, dp(11), 0); background = rounded("#16352F", 50)
        layoutParams = LinearLayout.LayoutParams(-2, dp(30))
    }

    private fun refreshStats() {
        if (!::queryValue.isInitialized) return
        val p = getSharedPreferences(AdShieldVpnService.PREFS, MODE_PRIVATE)
        val q = p.getLong(AdShieldVpnService.KEY_QUERIES, 0)
        val b = p.getLong(AdShieldVpnService.KEY_BLOCKED, 0)
        val running = p.getBoolean(AdShieldVpnService.KEY_RUNNING, false)
        queryValue.text = compact(q); blockedValue.text = compact(b)
        rateValue.text = if (q == 0L) "0%" else "${(b * 100 / q).coerceIn(0, 100)}%"
        if (running != enabled) { enabled = running; updateUi() }
        updateBatteryButton()
        updateStreamingButton()
        updateAntiDetectButton()
    }

    private fun updateBatteryButton() {
        if (!::batteryButton.isInitialized) return
        val pm = getSystemService(Context.POWER_SERVICE) as? PowerManager
        val exempt = Build.VERSION.SDK_INT < 23 ||
            pm?.isIgnoringBatteryOptimizations(packageName) == true
        batteryButton.text = if (exempt) {
            "BATTERY: UNRESTRICTED ✓ — 24x7 READY"
        } else {
            "BATTERY: UNRESTRICTED KARO (24x7 KE LIYE)"
        }
        batteryButton.isEnabled = !exempt
        batteryButton.alpha = if (exempt) 0.65f else 1f
    }

    private fun updateStreamingButton() {
        if (!::streamingButton.isInitialized) return
        val on = getSharedPreferences(AdShieldVpnService.PREFS, MODE_PRIVATE)
            .getBoolean(AdBlocker.KEY_STREAMING_EXTREME, true)
        streamingButton.text = if (on) {
            "STREAMING EXTREME: ON — tap to turn off"
        } else {
            "STREAMING EXTREME: OFF — tap to turn on"
        }
        streamingButton.alpha = if (on) 1f else 0.65f
    }

    private fun toggleStreamingExtreme() {
        val prefs = getSharedPreferences(AdShieldVpnService.PREFS, MODE_PRIVATE)
        val next = !prefs.getBoolean(AdBlocker.KEY_STREAMING_EXTREME, true)
        prefs.edit().putBoolean(AdBlocker.KEY_STREAMING_EXTREME, next).apply()
        AdBlocker.setStreamingEnabled(next)
        updateStreamingButton()
    }

    private fun updateAntiDetectButton() {
        if (!::antiDetectButton.isInitialized) return
        val on = getSharedPreferences(AdShieldVpnService.PREFS, MODE_PRIVATE)
            .getBoolean(AdShieldVpnService.KEY_SURROGATE, true)
        antiDetectButton.text = if (on) {
            "ANTI-DETECT: ON — tap to turn off"
        } else {
            "ANTI-DETECT: OFF — tap to turn on"
        }
        antiDetectButton.alpha = if (on) 1f else 0.65f
    }

    private fun toggleAntiDetect() {
        val prefs = getSharedPreferences(AdShieldVpnService.PREFS, MODE_PRIVATE)
        val next = !prefs.getBoolean(AdShieldVpnService.KEY_SURROGATE, true)
        prefs.edit().putBoolean(AdShieldVpnService.KEY_SURROGATE, next).apply()
        updateAntiDetectButton()
    }

    // ---------- HTTPS Path Filter MITM (v0.8.0) ----------

    private fun toggleMitm() {
        val prefs = getSharedPreferences(AdShieldVpnService.PREFS, MODE_PRIVATE)
        val next = !prefs.getBoolean(AdShieldVpnService.KEY_MITM_ENABLED, false)
        if (next && !prefs.getBoolean(AdShieldVpnService.KEY_MITM_CA_DONE, false)) {
            Toast.makeText(this,
                "Pehle CA certificate install karo (neeche button)",
                Toast.LENGTH_LONG).show()
            return
        }
        prefs.edit().putBoolean(AdShieldVpnService.KEY_MITM_ENABLED, next).apply()
        updateMitmButton()
        if (next) {
            Toast.makeText(this,
                "HTTPS Path Filter ON — VPN restart karo (STOP phir START)",
                Toast.LENGTH_LONG).show()
        }
    }

    private fun updateMitmButton() {
        val prefs = getSharedPreferences(AdShieldVpnService.PREFS, MODE_PRIVATE)
        val on = prefs.getBoolean(AdShieldVpnService.KEY_MITM_ENABLED, false)
        val caDone = prefs.getBoolean(AdShieldVpnService.KEY_MITM_CA_DONE, false)
        mitmButton.text = "HTTPS PATH FILTER: ${if (on) "ON" else "OFF"}"
        mitmButton.setTextColor(color(if (on) "#59E1B8" else "#93A4BA"))
        mitmButton.background = rounded("#16352F", 14)
        mitmButton.setPadding(dp(12), 0, dp(12), 0)
        caButton.visibility = if (on || !caDone) View.VISIBLE else View.GONE
        domainsButton.visibility = if (on) View.VISIBLE else View.GONE
        if (caDone) caButton.text = "CA INSTALLED ✓ (tap to reinstall)"
    }

    private fun installCaCert() {
        try {
            val caMgr = CaManager(filesDir)
            caMgr.getOrCreateCa() // generate on first run
            val pem = caMgr.caCertPem()
            // Save to Downloads for manual install (more reliable than
            // KeyChain intent on Samsung/OneUI devices).
            val fileName = "adshield-ca.crt"
            val saved = saveCertToDownloads(fileName, pem)
            if (saved) {
                showCaInstallGuide(fileName)
            } else {
                // Fallback: try KeyChain intent
                val intent = KeyChain.createInstallIntent()
                intent.putExtra(KeyChain.EXTRA_CERTIFICATE, pem)
                intent.putExtra(KeyChain.EXTRA_NAME, "AdShield MITM CA")
                startActivity(intent)
            }
            getSharedPreferences(AdShieldVpnService.PREFS, MODE_PRIVATE)
                .edit().putBoolean(AdShieldVpnService.KEY_MITM_CA_DONE, true).apply()
            updateMitmButton()
        } catch (e: Exception) {
            Toast.makeText(this, "CA error: ${e.message}", Toast.LENGTH_LONG).show()
        }
    }

    private fun saveCertToDownloads(fileName: String, pem: ByteArray): Boolean {
        return try {
            if (Build.VERSION.SDK_INT >= 29) {
                val values = android.content.ContentValues().apply {
                    put(android.provider.MediaStore.MediaColumns.DISPLAY_NAME, fileName)
                    put(android.provider.MediaStore.MediaColumns.MIME_TYPE, "application/x-x509-ca-cert")
                    put(android.provider.MediaStore.MediaColumns.RELATIVE_PATH, "Download/")
                }
                val uri = contentResolver.insert(
                    android.provider.MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
                if (uri != null) {
                    contentResolver.openOutputStream(uri)?.use { it.write(pem) }
                    true
                } else false
            } else {
                @Suppress("DEPRECATION")
                val dir = android.os.Environment.getExternalStoragePublicDirectory(
                    android.os.Environment.DIRECTORY_DOWNLOADS)
                val file = java.io.File(dir, fileName)
                file.writeBytes(pem)
                true
            }
        } catch (_: Exception) {
            false
        }
    }

    private fun showCaInstallGuide(fileName: String) {
        AlertDialog.Builder(this)
            .setTitle("CA Certificate Saved!")
            .setMessage("File Downloads me save ho gayi: $fileName\n\n" +
                "Ab install karo:\n" +
                "1. Settings kholo\n" +
                "2. Biometrics and security → Other security settings\n" +
                "3. Install from device storage → CA certificate\n" +
                "4. \"$fileName\" select karo → Install dabao\n\n" +
                "Install hone ke baad HTTPS PATH FILTER on kar sakte ho.")
            .setPositiveButton("SETTINGS KHOLO") { _, _ ->
                try {
                    startActivity(Intent(Settings.ACTION_SECURITY_SETTINGS))
                } catch (_: Exception) {
                    try {
                        startActivity(Intent(Settings.ACTION_SETTINGS))
                    } catch (_: Exception) {}
                }
            }
            .setNegativeButton("BAAD ME", null)
            .show()
    }

    private fun showDomainEditor() {
        val prefs = getSharedPreferences(AdShieldVpnService.PREFS, MODE_PRIVATE)
        val current = prefs.getString(AdShieldVpnService.KEY_MITM_DOMAINS,
            AdShieldVpnService.DEFAULT_MITM_DOMAINS) ?: ""
        val input = EditText(this).apply {
            setText(current)
            hint = "pornhub.org,pornhub.com"
            setSingleLine(false)
        }
        AlertDialog.Builder(this)
            .setTitle("MITM Domains (comma-separated)")
            .setMessage("Sirf in domains ka HTTPS decrypt hoga. Baaki sab untouched.")
            .setView(input)
            .setPositiveButton("SAVE") { _, _ ->
                prefs.edit().putString(AdShieldVpnService.KEY_MITM_DOMAINS,
                    input.text.toString()).apply()
                Toast.makeText(this, "Saved — VPN restart karo", Toast.LENGTH_SHORT).show()
            }
            .setNegativeButton("CANCEL", null)
            .show()
    }

    private fun shareMitmLog() {
        try {
            val logFile = java.io.File(filesDir, "mitm_debug.log")
            if (!logFile.exists() || logFile.length() == 0L) {
                Toast.makeText(this, "Log khaali hai — pehle MITM ON karke site kholo", Toast.LENGTH_LONG).show()
                return
            }
            val content = logFile.readText().take(60000)
            val tv = TextView(this).apply {
                text = content
                textSize = 10f
                setPadding(dp(16), dp(16), dp(16), dp(16))
            }
            val scroll = ScrollView(this).apply { addView(tv) }
            AlertDialog.Builder(this)
                .setTitle("MITM Debug Log (copy karke bhejo)")
                .setView(scroll)
                .setPositiveButton("COPY") { _, _ ->
                    val cm = getSystemService(Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
                    cm.setPrimaryClip(android.content.ClipData.newPlainText("mitm", content))
                    Toast.makeText(this, "Copied!", Toast.LENGTH_SHORT).show()
                }
                .setNegativeButton("CLOSE", null)
                .show()
        } catch (e: Exception) {
            Toast.makeText(this, "Log error: ${e.message}", Toast.LENGTH_LONG).show()
        }
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
            } catch (_: Exception) {}
        }
    }

    private fun updateUi() {
        statusText.text = if (enabled) "Protection is active" else "Protection is off"
        toggleButton.text = if (enabled) "STOP PROTECTION" else "START PROTECTION"
        toggleButton.background = rounded(if (enabled) "#FF6B7A" else "#59E1B8", 18)
        toggleButton.setTextColor(color("#08111F"))
        shieldIcon.setTextColor(color(if (enabled) "#59E1B8" else "#4AA3FF"))
        pulse?.cancel()
        if (enabled) {
            pulse = ObjectAnimator.ofFloat(shieldIcon, View.ALPHA, 1f, .55f, 1f).apply {
                duration = 1600; repeatCount = ValueAnimator.INFINITE; interpolator = AccelerateDecelerateInterpolator(); start()
            }
        } else shieldIcon.alpha = 1f
    }

    @Suppress("DEPRECATION")
    private fun startShieldWithPermission() {
        val intent = VpnService.prepare(this)
        if (intent != null) startActivityForResult(intent, 100) else startShield()
    }

    private fun startShield() {
        val intent = Intent(this, AdShieldVpnService::class.java)
        if (Build.VERSION.SDK_INT >= 26) startForegroundService(intent) else startService(intent)
        enabled = true; updateUi()
    }

    private fun stopShield() {
        try { startService(Intent(this, AdShieldVpnService::class.java).setAction(AdShieldVpnService.ACTION_STOP)) } catch (_: Exception) {}
        stopService(Intent(this, AdShieldVpnService::class.java))
        getSharedPreferences(AdShieldVpnService.PREFS, MODE_PRIVATE).edit().putBoolean(AdShieldVpnService.KEY_RUNNING, false).apply()
        enabled = false; updateUi()
    }

    private fun compact(v: Long): String = when {
        v >= 1_000_000 -> "%.1fM".format(v / 1_000_000.0)
        v >= 1_000 -> "%.1fK".format(v / 1_000.0)
        else -> v.toString()
    }

    private fun rounded(hex: String, radius: Int): GradientDrawable = GradientDrawable().apply { setColor(color(hex)); cornerRadius = dp(radius).toFloat() }
    private fun color(hex: String): Int = Color.parseColor(hex)
    private fun space(h: Int): View = View(this).apply { layoutParams = LinearLayout.LayoutParams(1, dp(h)) }
    private fun dp(v: Int): Int = (v * resources.displayMetrics.density).toInt()

    override fun onResume() { super.onResume(); handler.post(refresh) }
    override fun onPause() { handler.removeCallbacks(refresh); pulse?.cancel(); super.onPause() }

    @Suppress("DEPRECATION")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == 100 && resultCode == RESULT_OK) startShield()
    }
}
