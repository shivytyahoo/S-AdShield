package com.adshield

import android.app.Application
import android.content.Intent
import android.os.Process
import java.io.File
import java.io.PrintWriter
import java.io.StringWriter

/**
 * Installs a global crash reporter as the very first thing in the process.
 *
 * Any uncaught throwable — including VerifyError / NoClassDefFoundError at
 * activity class-load time — is written to filesDir/crash.log and the tiny
 * [CrashActivity] is launched to display it, so the exact cause can be
 * diagnosed from the device without logcat.
 */
class ShieldApp : Application() {

    override fun onCreate() {
        super.onCreate()
        val logFile = File(filesDir, CRASH_LOG)
        val previous = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, error ->
            try {
                val sw = StringWriter()
                error.printStackTrace(PrintWriter(sw))
                val sb = StringBuilder()
                sb.append("time=").append(System.currentTimeMillis()).append('\n')
                sb.append("thread=").append(thread.name).append('\n')
                sb.append("error=").append(error.javaClass.name)
                    .append(": ").append(error.message).append('\n')
                // Walk the cause chain explicitly — printStackTrace already
                // does, but a compact cause list helps on small screens.
                var c = error.cause
                var depth = 0
                while (c != null && depth < 6) {
                    sb.append("caused by: ").append(c.javaClass.name)
                        .append(": ").append(c.message).append('\n')
                    c = c.cause
                    depth++
                }
                sb.append("---- stack ----\n").append(sw.toString())
                logFile.writeText(sb.toString())
            } catch (_: Exception) {
            }
            // Try to show the report immediately in the (dying) process.
            try {
                val intent = Intent(this, CrashActivity::class.java)
                intent.addFlags(
                    Intent.FLAG_ACTIVITY_NEW_TASK or
                        Intent.FLAG_ACTIVITY_CLEAR_TASK
                )
                startActivity(intent)
            } catch (_: Exception) {
            }
            try {
                previous?.uncaughtException(thread, error)
            } catch (_: Exception) {
            }
            Process.killProcess(Process.myPid())
        }
    }

    companion object {
        const val CRASH_LOG = "crash.log"

        /** True if a previous run died with an uncaught throwable. */
        fun hasCrashReport(app: Application): Boolean =
            File(app.filesDir, CRASH_LOG).exists()

        fun readCrashReport(app: Application): String = try {
            File(app.filesDir, CRASH_LOG).readText()
        } catch (_: Exception) {
            "could not read crash log"
        }

        fun clearCrashReport(app: Application) {
            try {
                File(app.filesDir, CRASH_LOG).delete()
            } catch (_: Exception) {
            }
        }
    }
}
