package com.adshield

/**
 * In-memory ring buffer of recent DNS decisions (v1.1.0).
 *
 * The service records every answered query here; the Log tab reads a
 * snapshot of it. Same process, so no IPC is needed. Capped at 200
 * entries — it is a live view, not a history database.
 */
data class QueryEntry(
    val timeMs: Long,
    val domain: String,
    val blocked: Boolean,
    val appLabel: String,
    val packageName: String?
)

object QueryLog {
    private const val MAX_ENTRIES = 200
    private val lock = Any()
    private val entries = ArrayDeque<QueryEntry>()

    fun add(entry: QueryEntry) {
        synchronized(lock) {
            entries.addLast(entry)
            while (entries.size > MAX_ENTRIES) entries.removeFirst()
        }
    }

    fun snapshot(): List<QueryEntry> = synchronized(lock) { entries.toList() }

    fun clear() {
        synchronized(lock) { entries.clear() }
    }
}
