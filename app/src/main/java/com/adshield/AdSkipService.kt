package com.adshield

import android.accessibilityservice.AccessibilityService
import android.os.SystemClock
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo

/**
 * GKD-style auto-skip (v0.9.7): watches every app's window content and
 * auto-taps "Skip Ad" / "Close" controls the moment they become tappable
 * (e.g. YouTube's Skip Ad button after its countdown ends).
 *
 * Safety rails, by design:
 *  - Only runs when the user turned AUTO-SKIP ADS on in the app AND enabled
 *    this service in Android's Accessibility settings.
 *  - Never touches our own app, Settings, or the package installer.
 *  - Only exact skip/close labels match (AdSkipRules) — countdowns
 *    ("Skip Ad in 5") and look-alikes ("Skip to content") are ignored.
 *  - At most one tap per 800 ms, and the same button is never tapped twice
 *    within 3 s.
 */
class AdSkipService : AccessibilityService() {

    private var lastScanAt = 0L
    private var lastClickAt = 0L
    private var lastClickKey = ""

    override fun onAccessibilityEvent(event: AccessibilityEvent) {
        if (!isAdskipOn()) return
        val pkg = event.packageName?.toString() ?: return
        if (pkg in EXCLUDED_PACKAGES) return
        val now = SystemClock.uptimeMillis()
        if (now - lastScanAt < SCAN_THROTTLE_MS) return
        if (now - lastClickAt < CLICK_THROTTLE_MS) return
        lastScanAt = now
        val root = rootInActiveWindow ?: return
        try {
            val target = findSkipNode(root, 0, intArrayOf(0)) ?: return
            val key = pkg + "|" + (target.text ?: target.contentDescription ?: "")
            if (key == lastClickKey && now - lastClickAt < DEDUP_MS) return
            if (target.performAction(AccessibilityNodeInfo.ACTION_CLICK)) {
                lastClickAt = now
                lastClickKey = key
            }
            target.recycle()
        } finally {
            root.recycle()
        }
    }

    override fun onInterrupt() {
        // Nothing to clean up; the next event re-scans from scratch.
    }

    private fun isAdskipOn(): Boolean =
        getSharedPreferences(AdShieldVpnService.PREFS, MODE_PRIVATE)
            .getBoolean(AdShieldVpnService.KEY_ADSKIP_ENABLED, false)

    /**
     * Depth-first search for the first visible skip/close control.
     * Returns the node itself when clickable, else its nearest clickable
     * ancestor (players often put the label in a non-clickable TextView
     * inside a clickable container). [visited] caps the walk so a huge
     * view tree cannot stall the main thread.
     */
    private fun findSkipNode(
        node: AccessibilityNodeInfo,
        depth: Int,
        visited: IntArray
    ): AccessibilityNodeInfo? {
        if (depth > MAX_DEPTH || visited[0] > MAX_NODES) return null
        visited[0]++
        if (node.isVisibleToUser && matchesSkip(node)) {
            val clickable = clickableAncestor(node)
            if (clickable != null) return clickable
        }
        for (i in 0 until node.childCount) {
            val child = node.getChild(i) ?: continue
            val found = findSkipNode(child, depth + 1, visited)
            if (found != null) return found
            child.recycle()
        }
        return null
    }

    private fun matchesSkip(node: AccessibilityNodeInfo): Boolean =
        AdSkipRules.isSkipLabel(node.text?.toString()) ||
            AdSkipRules.isSkipLabel(node.contentDescription?.toString())

    /**
     * Walks up to the nearest clickable ancestor (at most 3 hops). Nodes
     * fetched with getParent() are recycled here; the input node itself is
     * owned by the caller and is never recycled in this function.
     */
    private fun clickableAncestor(node: AccessibilityNodeInfo): AccessibilityNodeInfo? {
        if (node.isClickable) return node
        var parent = node.parent
        var hops = 0
        while (parent != null && hops < 3) {
            if (parent.isClickable) return parent
            val next = parent.parent
            parent.recycle()
            parent = next
            hops++
        }
        parent?.recycle()
        return null
    }

    companion object {
        private const val SCAN_THROTTLE_MS = 150L
        private const val CLICK_THROTTLE_MS = 800L
        private const val DEDUP_MS = 3000L
        private const val MAX_DEPTH = 12
        private const val MAX_NODES = 800

        private val EXCLUDED_PACKAGES = setOf(
            "shivyt.android.adshield",
            "com.android.settings",
            "com.google.android.packageinstaller",
            "com.android.packageinstaller"
        )
    }
}
