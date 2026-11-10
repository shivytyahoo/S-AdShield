package com.adshield

/**
 * GKD-style auto-skip: pure text-matching rules for "Skip Ad" style controls.
 *
 * Kept free of android.* imports so the JVM harness can test it directly
 * (see jvm-test/AdSkipTest.kt). The service (AdSkipService) only feeds it
 * node text / content-description and performs the click.
 *
 * Deliberately narrow on purpose:
 *  - Only exact labels match ("Skip Ad", "Skip", "Close", ...). A label that
 *    merely CONTAINS the word skip ("Skip to content") does NOT match, so
 *    onboarding / navigation buttons are never tapped.
 *  - Any label containing a digit never matches: that is a countdown
 *    ("Skip Ad in 5"), not a tappable button yet.
 */
object AdSkipRules {

    private val SKIP_LABELS = setOf(
        "skip ad", "skip ads", "skip", "skip intro", "skip video",
        "close ad", "close", "dismiss", "no thanks",
        "✕", "×", "x"
    )

    /** Normalize a raw label, or null when there is nothing to match. */
    fun normalize(raw: String?): String? {
        if (raw == null) return null
        var s = raw.trim().lowercase()
        if (s.isEmpty()) return null
        // Collapse repeated whitespace ("Skip  Ad" -> "Skip Ad").
        s = s.split("\\s+".toRegex()).joinToString(" ")
        // Strip decorative trailing arrows/chevrons players append ("Skip Ad ▸").
        s = s.trimEnd('▸', '›', '»', '>', '·', '•', ' ')
        return s.ifEmpty { null }
    }

    /** True when this label is a skip/close control worth auto-tapping. */
    fun isSkipLabel(raw: String?): Boolean {
        val s = normalize(raw) ?: return false
        if (s.any { it.isDigit() }) return false // countdown, e.g. "Skip Ad in 5"
        return s in SKIP_LABELS
    }
}
