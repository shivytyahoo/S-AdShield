package com.adshield

import android.app.Activity
import android.graphics.Color
import android.graphics.Typeface
import android.os.Bundle
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView

/**
 * Minimal crash-report screen. Kept deliberately tiny (framework views
 * only, no shared helpers) so it can load even when the main activity
 * cannot — e.g. a VerifyError in MainActivity.
 */
class CrashActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.rgb(8, 17, 31))
            val d = resources.displayMetrics.density
            setPadding((20 * d).toInt(), (20 * d).toInt(), (20 * d).toInt(), (20 * d).toInt())
        }

        val title = TextView(this).apply {
            text = "S-AdShield crash report"
            textSize = 18f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(Color.rgb(244, 247, 251))
        }
        root.addView(title)

        val hint = TextView(this).apply {
            text = "Iska screenshot lekar bhejo — isse exact bug pata chalega."
            textSize = 13f
            setTextColor(Color.rgb(147, 164, 186))
            val d = resources.displayMetrics.density
            setPadding(0, (8 * d).toInt(), 0, (12 * d).toInt())
        }
        root.addView(hint)

        val report = TextView(this).apply {
            text = ShieldApp.readCrashReport(application as android.app.Application)
            textSize = 11f
            typeface = Typeface.MONOSPACE
            setTextColor(Color.rgb(255, 180, 180))
            setTextIsSelectable(true)
        }
        val scroll = ScrollView(this).apply {
            addView(report)
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f
            )
        }
        root.addView(scroll)

        val clear = Button(this).apply {
            text = "REPORT CLEAR KARO AUR APP KHOLO"
            textSize = 13f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(Color.rgb(8, 17, 31))
            setBackgroundColor(Color.rgb(89, 225, 184))
            val d = resources.displayMetrics.density
            setPadding(0, (14 * d).toInt(), 0, (14 * d).toInt())
            setOnClickListener {
                ShieldApp.clearCrashReport(application as android.app.Application)
                val open = android.content.Intent(
                    this@CrashActivity, MainActivity::class.java
                )
                open.addFlags(android.content.Intent.FLAG_ACTIVITY_CLEAR_TASK or
                    android.content.Intent.FLAG_ACTIVITY_NEW_TASK)
                startActivity(open)
                finish()
            }
        }
        val dBtn = resources.displayMetrics.density
        val btnLp = LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT
        ).apply { topMargin = (12 * dBtn).toInt() }
        root.addView(clear, btnLp)

        setContentView(root)
    }
}
