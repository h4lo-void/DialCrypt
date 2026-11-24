package io.github.h4lovoid.dialcrypt.dialer

import java.io.File
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The dialer package runs in `:call` and `:dialer`, which hold no secrets. Its sources must not
 * reach the secure core, the daemon link, the accessibility check or the lockdown controller.
 */
class ProcessIsolationTest {
    private val srcRoot = File(File(System.getProperty("aegis.resDir") ?: "src/main/res").parentFile, "java/io/github/h4lovoid/dialcrypt")
    private val dialerDir = File(srcRoot, "dialer")

    private fun sources(): List<File> = dialerDir.walkTopDown().filter { it.isFile && it.extension == "kt" }.toList()

    // Whole package paths. The word "daemon" alone is not matched: CallWatchdog uses Thread.isDaemon.
    private val forbidden = Regex(
        "io\\.github\\.h4lovoid\\.dialcrypt\\.core\\.(daemon|real|SecureCore|AccessibilityCheck|LockdownController|\\*)(?![A-Za-z0-9_])",
    )

    @Test
    fun theDialerSourcesAreFound() {
        val names = sources().map { it.name }
        assertTrue(names.toString(), names.size >= 15)
        assertTrue(names.contains("DialpadActivity.kt"))
        assertTrue(names.contains("InCallScreens.kt"))
    }

    @Test
    fun noDialerSourceNamesTheSecureCoreDaemonOrLockdownPackages() {
        val hits = sources().flatMap { f ->
            f.readLines().withIndex().filter { forbidden.containsMatchIn(it.value) }.map { "${f.name}:${it.index + 1}: ${it.value.trim()}" }
        }
        assertTrue(hits.joinToString("\n"), hits.isEmpty())
    }

    @Test
    fun theCheckMatchesFullPackagePathsOnly() {
        assertTrue(forbidden.containsMatchIn("import io.github.h4lovoid.dialcrypt.core.daemon.DaemonClient"))
        assertTrue(forbidden.containsMatchIn("import io.github.h4lovoid.dialcrypt.core.real.RealSecureCore"))
        assertTrue(forbidden.containsMatchIn("import io.github.h4lovoid.dialcrypt.core.SecureCore"))
        assertTrue(forbidden.containsMatchIn("import io.github.h4lovoid.dialcrypt.core.AccessibilityCheck"))
        assertTrue(forbidden.containsMatchIn("import io.github.h4lovoid.dialcrypt.core.LockdownController"))
        assertTrue(forbidden.containsMatchIn("import io.github.h4lovoid.dialcrypt.core.*"))
        assertFalse(forbidden.containsMatchIn("import io.github.h4lovoid.dialcrypt.core.NumberPresentation"))
        assertFalse(forbidden.containsMatchIn("import io.github.h4lovoid.dialcrypt.core.PhoneRules"))
        assertFalse(forbidden.containsMatchIn("apply { isDaemon = true }"))
    }

    // The dial pad process never touches a Telecom call, the registry of the secure flow or the call store.
    // Only incoming.screen may be read: plain files (display setting, contact number index) with no call in them.
    @Test
    fun theDialpadProcessFilesDoNotImportTheCallSide() {
        val dialerProcess = listOf(
            "DialpadActivity.kt",
            "MissedCallReceiver.kt",
            "AllowAllScreeningService.kt",
            "CallPlacer.kt",
            "SecureBusyMarker.kt",
            "PendingLogErase.kt",
            "DialerRole.kt",
            "DialerNotifications.kt",
            "RecentCallLog.kt",
            "ui/DialpadScreens.kt",
            "ui/RecentsScreen.kt",
            "model/DialInput.kt",
            "model/RecentCalls.kt",
        )
        val callSide = Regex("^\\s*import\\s+io\\.github\\.h4lovoid\\.dialcrypt\\.(incoming\\.(?!screen\\.)|call\\.)|^\\s*import\\s+io\\.github\\.h4lovoid\\.dialcrypt\\.dialer\\.(InCallStore|TelecomCallCommands|DialerInCallService|InCallActivity)")
        val hits = dialerProcess.flatMap { rel ->
            val f = File(dialerDir, rel)
            assertTrue("missing " + f.path, f.isFile)
            f.readLines().withIndex().filter { callSide.containsMatchIn(it.value) }.map { rel + ":" + (it.index + 1) + ": " + it.value.trim() }
        }
        assertTrue(hits.joinToString("\n"), hits.isEmpty())
    }

    @Test
    fun theDialpadRuleAllowsOnlyTheScreenPackageOfIncoming() {
        val callSide = Regex("^\\s*import\\s+io\\.github\\.h4lovoid\\.dialcrypt\\.(incoming\\.(?!screen\\.)|call\\.)")
        assertFalse(callSide.containsMatchIn("import io.github.h4lovoid.dialcrypt.incoming.screen.ContactNumberIndex"))
        assertTrue(callSide.containsMatchIn("import io.github.h4lovoid.dialcrypt.incoming.CallRegistry"))
        assertTrue(callSide.containsMatchIn("import io.github.h4lovoid.dialcrypt.call.CallLogEraser"))
    }

    // incoming.screen is read by `:call` and `:dialer`: plain files and one Keystore key. It must stay
    // clear of the vault, the daemon, Telecom, the registry of the secure flow and the call store.
    private val screenDir = File(srcRoot, "incoming/screen")
    private val screenForbidden = Regex(
        "io\\.github\\.h4lovoid\\.dialcrypt\\.core\\.(daemon|real|SecureCore|AccessibilityCheck|LockdownController|NativeBridge|\\*)(?![A-Za-z0-9_])" +
            "|android\\.telecom\\." +
            "|io\\.github\\.h4lovoid\\.dialcrypt\\.incoming\\.(?!screen(?![A-Za-z0-9_]))" +
            "|io\\.github\\.h4lovoid\\.dialcrypt\\.(call|dialer|security|ui)\\.",
    )

    @Test
    fun theScreenPackageNamesNoVaultTelecomOrRegistryClass() {
        val files = screenDir.walkTopDown().filter { it.isFile && it.extension == "kt" }.toList()
        assertTrue(files.map { it.name }.toString(), files.any { it.name == "ContactNumberIndex.kt" })
        assertTrue(files.any { it.name == "DisplaySettings.kt" })
        val hits = files.flatMap { f ->
            f.readLines().withIndex().filter { screenForbidden.containsMatchIn(it.value) }.map { f.name + ":" + (it.index + 1) + ": " + it.value.trim() }
        }
        assertTrue(hits.joinToString("\n"), hits.isEmpty())
    }

    @Test
    fun theScreenPackageRuleCatchesTheCallSideAndTheVault() {
        assertTrue(screenForbidden.containsMatchIn("import io.github.h4lovoid.dialcrypt.core.real.NativeSecureCore"))
        assertTrue(screenForbidden.containsMatchIn("import io.github.h4lovoid.dialcrypt.core.SecureCore"))
        assertTrue(screenForbidden.containsMatchIn("import io.github.h4lovoid.dialcrypt.core.NativeBridge"))
        assertTrue(screenForbidden.containsMatchIn("import android.telecom.Call"))
        assertTrue(screenForbidden.containsMatchIn("import io.github.h4lovoid.dialcrypt.incoming.CallRegistry"))
        assertTrue(screenForbidden.containsMatchIn("import io.github.h4lovoid.dialcrypt.call.CallLogEraser"))
        assertTrue(screenForbidden.containsMatchIn("import io.github.h4lovoid.dialcrypt.dialer.InCallStore"))
        assertTrue(screenForbidden.containsMatchIn("val core = io.github.h4lovoid.dialcrypt.core.real.NativeSecureCore.VAULT_FILE"))
        assertFalse(screenForbidden.containsMatchIn("package io.github.h4lovoid.dialcrypt.incoming.screen"))
        assertFalse(screenForbidden.containsMatchIn("import io.github.h4lovoid.dialcrypt.incoming.screen.IncomingMode"))
        assertFalse(screenForbidden.containsMatchIn("import io.github.h4lovoid.dialcrypt.core.PhoneRules"))
        assertFalse(screenForbidden.containsMatchIn("import io.github.h4lovoid.dialcrypt.core.DirectBoot"))
    }
}
