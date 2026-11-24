package io.github.h4lovoid.dialcrypt.dialer

import android.Manifest
import android.annotation.SuppressLint
import android.content.Intent
import android.content.pm.PackageManager
import android.database.ContentObserver
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.CallLog
import android.telecom.PhoneAccount
import android.telecom.TelecomManager
import android.telephony.TelephonyManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.core.content.ContextCompat
import io.github.h4lovoid.dialcrypt.core.ContactMembership
import io.github.h4lovoid.dialcrypt.dialer.model.DialInput
import io.github.h4lovoid.dialcrypt.dialer.model.RecentCallsModel
import io.github.h4lovoid.dialcrypt.dialer.ui.DialNotice
import io.github.h4lovoid.dialcrypt.dialer.ui.DialTab
import io.github.h4lovoid.dialcrypt.dialer.ui.DialerTabs
import io.github.h4lovoid.dialcrypt.dialer.ui.DialpadScreen
import io.github.h4lovoid.dialcrypt.dialer.ui.RecentsScreen
import io.github.h4lovoid.dialcrypt.incoming.screen.ContactNumberIndex
import io.github.h4lovoid.dialcrypt.incoming.screen.DisplaySettings
import io.github.h4lovoid.dialcrypt.ui.SecureWindow
import io.github.h4lovoid.dialcrypt.ui.theme.DialCryptTheme
import io.github.h4lovoid.dialcrypt.ui.theme.Palette
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import kotlinx.coroutines.flow.MutableStateFlow

/**
 * The default dialer's dial pad in `:dialer`: DIAL, VIEW tel: and CALL_BUTTON open it. It never
 * touches a Telecom call, so a crash here leaves calls alone. A number handed in by another app is
 * only filled in; the user still presses call. While the secure flow owns a call, only emergency
 * numbers go out. A second tab lists the recent calls of the system call log; the missed call
 * notification opens that tab ([EXTRA_SHOW_RECENTS]).
 */
class DialpadActivity : ComponentActivity() {
    private val digits = MutableStateFlow("")
    private val notice = MutableStateFlow<DialNotice?>(null)
    private val tab = MutableStateFlow(DialTab.KEYPAD)
    private lateinit var dialer: Dialer
    private lateinit var recents: RecentCallsModel
    private val io: ExecutorService = Executors.newSingleThreadExecutor { r -> Thread(r, "dialer-recents").apply { isDaemon = true } }

    // Deleting has its own thread, so it never waits for a refresh that is reading the call log.
    private val edits: ExecutorService = Executors.newSingleThreadExecutor { r -> Thread(r, "dialer-recents-edit").apply { isDaemon = true } }
    private val main = Handler(Looper.getMainLooper())
    private val refreshRecents = Runnable { io.execute { recents.refresh() } }
    private var observing = false

    // Call log changes come in bursts; the list is loaded once they settle.
    private val callLogObserver = object : ContentObserver(main) {
        override fun onChange(selfChange: Boolean) {
            main.removeCallbacks(refreshRecents)
            main.postDelayed(refreshRecents, RECENTS_SETTLE_MS)
        }
    }

    // While rows are held back for a pending erase, looks once a second whether it finished.
    private val pendingEraseCheck = object : Runnable {
        override fun run() {
            if (recents.state.value.hiddenFromMs != null) io.execute { recents.refreshIfPendingEraseChanged() }
            main.postDelayed(this, PENDING_ERASE_POLL_MS)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        SecureWindow.apply(this)
        dialer = Dialer(
            placer = TelecomCallPlacer(applicationContext),
            isEmergency = ::isEmergency,
            secureBusy = ::secureBusy,
            specialCode = ::sendSpecialCode,
        )
        val index = ContactNumberIndex(applicationContext)
        recents = RecentCallsModel(
            log = RecentCallLog(applicationContext),
            // One reading of the index file serves a whole refresh.
            openIndex = {
                val reader = index.open()
                val lookup: (String) -> ContactMembership = { n -> reader.lookup(n) }
                lookup
            },
            showFull = { DisplaySettings.read(applicationContext) },
            pendingEraseFromMs = { PendingLogErase.hiddenFrom(applicationContext) },
        )
        DialerRole.syncLauncherAlias(applicationContext)
        if (savedInstanceState == null) fillFrom(intent)

        setContent {
            DialCryptTheme {
                val typed by digits.collectAsState()
                val shown by notice.collectAsState()
                val page by tab.collectAsState()
                val list by recents.state.collectAsState()
                Column(Modifier.fillMaxSize().background(Palette.Background).safeDrawingPadding()) {
                    DialerTabs(page, ::selectTab)
                    when (page) {
                        DialTab.KEYPAD -> DialpadScreen(
                            digits = typed,
                            notice = shown,
                            onKey = { c -> edit(DialInput.clean(digits.value + c).orEmpty()) },
                            onDelete = { edit(digits.value.dropLast(1)) },
                            onClear = { edit("") },
                            onCall = ::call,
                            modifier = Modifier.weight(1f),
                        )
                        DialTab.RECENTS -> RecentsScreen(
                            state = list,
                            nowMs = System.currentTimeMillis(),
                            notice = shown,
                            onCall = ::callBack,
                            onDelete = { id -> edits.execute { recents.delete(id) } },
                            onClearAll = { edits.execute { recents.clearAll() } },
                            modifier = Modifier.weight(1f),
                        )
                    }
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        fillFrom(intent)
    }

    override fun onStart() {
        super.onStart()
        if (!observing) {
            observing = runCatching {
                contentResolver.registerContentObserver(CallLog.Calls.CONTENT_URI, true, callLogObserver)
                true
            }.getOrDefault(false)
        }
        main.removeCallbacks(refreshRecents)
        refreshRecents.run()
        main.removeCallbacks(pendingEraseCheck)
        main.postDelayed(pendingEraseCheck, PENDING_ERASE_POLL_MS)
    }

    override fun onStop() {
        if (observing) {
            runCatching { contentResolver.unregisterContentObserver(callLogObserver) }
            observing = false
        }
        main.removeCallbacks(refreshRecents)
        main.removeCallbacks(pendingEraseCheck)
        super.onStop()
    }

    override fun onDestroy() {
        io.shutdown()
        edits.shutdown()
        super.onDestroy()
    }

    // Allowed for the default dialer; any refusal is ignored.
    @SuppressLint("MissingPermission")
    override fun onResume() {
        super.onResume()
        // The phone app was opened: Telecom resets its missed call count and sends a count of zero.
        runCatching { getSystemService(TelecomManager::class.java)?.cancelMissedCallsNotification() }
    }

    private fun edit(value: String) {
        digits.value = value
        notice.value = null
    }

    private fun selectTab(t: DialTab) {
        notice.value = null
        tab.value = t
    }

    private fun call() {
        if (showResult(dialer.dial(digits.value))) edit("")
    }

    /** A row of the recent calls goes out through the same dial path as the keypad. */
    private fun callBack(number: String) {
        notice.value = null
        showResult(dialer.dial(number))
    }

    /** True when the call went out (or the special code was handed over). */
    private fun showResult(result: DialResult): Boolean {
        when (result) {
            DialResult.PLACED, DialResult.SPECIAL_CODE -> return true
            DialResult.BLOCKED -> notice.value = DialNotice.BLOCKED
            DialResult.FAILED -> notice.value = DialNotice.FAILED
            DialResult.EMPTY -> Unit
        }
        return false
    }

    /**
     * DIAL or VIEW with a tel: number fills the pad; DIAL without data and CALL_BUTTON open it as it is.
     * The missed call notification opens the recent calls.
     */
    private fun fillFrom(intent: Intent?) {
        if (intent?.getBooleanExtra(EXTRA_SHOW_RECENTS, false) == true) {
            selectTab(DialTab.RECENTS)
            return
        }
        val data = intent?.data ?: return
        if (data.scheme != PhoneAccount.SCHEME_TEL) return
        if (intent.action != Intent.ACTION_DIAL && intent.action != Intent.ACTION_VIEW) return
        selectTab(DialTab.KEYPAD)
        edit(DialInput.clean(data.schemeSpecificPart.orEmpty()).orEmpty())
    }

    private fun isEmergency(number: String): Boolean {
        val tm = getSystemService(TelephonyManager::class.java) ?: return true
        return tm.isEmergencyNumber(number)
    }

    /** A secure call is under way: the marker written by `:call` exists and a call is up. */
    private fun secureBusy(): Boolean {
        if (!SecureBusyMarker.isSet(this)) return false
        val granted = ContextCompat.checkSelfPermission(this, Manifest.permission.READ_PHONE_STATE) == PackageManager.PERMISSION_GRANTED
        if (!granted) return true
        val tm = getSystemService(TelecomManager::class.java) ?: return true
        return runCatching { tm.isInCall }.getOrDefault(true)
    }

    private fun sendSpecialCode(code: String): Boolean {
        val tm = getSystemService(TelephonyManager::class.java) ?: return false
        return runCatching {
            tm.sendDialerSpecialCode(code)
            true
        }.getOrDefault(false)
    }

    companion object {
        /** Set by the missed call notification: open the recent calls tab. */
        const val EXTRA_SHOW_RECENTS = DialerNotifications.EXTRA_SHOW_RECENTS

        private const val RECENTS_SETTLE_MS = 500L
        private const val PENDING_ERASE_POLL_MS = 1_000L
    }
}

