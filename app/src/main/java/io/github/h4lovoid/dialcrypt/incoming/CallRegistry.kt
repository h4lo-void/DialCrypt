package io.github.h4lovoid.dialcrypt.incoming

import android.Manifest
import android.app.role.RoleManager
import android.content.Context
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.telecom.Call
import android.telecom.CallAudioState
import android.telecom.InCallService
import android.telecom.TelecomManager
import android.util.Log
import androidx.core.content.ContextCompat
import io.github.h4lovoid.dialcrypt.call.CallPhase
import io.github.h4lovoid.dialcrypt.call.CallLogEraser
import io.github.h4lovoid.dialcrypt.call.CallLogMatcher
import io.github.h4lovoid.dialcrypt.call.CallStatus
import io.github.h4lovoid.dialcrypt.call.ClaimResult
import io.github.h4lovoid.dialcrypt.call.IncomingOffer
import io.github.h4lovoid.dialcrypt.core.DirectBoot
import io.github.h4lovoid.dialcrypt.core.NumberPresentation
import io.github.h4lovoid.dialcrypt.dialer.PendingLogErase
import io.github.h4lovoid.dialcrypt.dialer.model.RegistryView
import io.github.h4lovoid.dialcrypt.dialer.model.Screening
import io.github.h4lovoid.dialcrypt.incoming.screen.IncomingMode
import io.github.h4lovoid.dialcrypt.incoming.screen.IncomingSettings
import io.github.h4lovoid.dialcrypt.incoming.screen.ScreeningStore
import java.security.SecureRandom
import java.util.concurrent.CopyOnWriteArraySet
import java.util.concurrent.Executors
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * In-memory call state machine in the isolated `:call` process. Owns the active Telecom [Call],
 * screens incoming ringing calls without touching vault keys, manages prompt offers and
 * single-winner [claim]/[answerPlain] arbitration, and retries [hangUp] until disconnected.
 * When a call the app placed or took over is removed, it starts [CallLogEraser] here: only this
 * process knows the number and the start and end times of every such call, and Telecom keeps it
 * bound until the call is gone, unlike `:secure`, which may already have exited.
 * Calls come from one InCallService only (see [CallSource.accepts]): the non-UI service, or, while
 * the app holds the default dialer role, the service behind the app's own in-call screen.
 * Once accepted, a call is followed through the source it came from until it ends, even if the role
 * is taken or given back meanwhile (see [CallSource.owns]).
 */
internal object CallRegistry {
    interface Listener {
        fun onStatus(status: CallStatus)
        fun onOffer(offer: IncomingOffer?): Boolean
    }

    private const val TAG = "AegisCallRegistry"
    private const val HANGUP_RETRY_MS = 400L
    private const val MAX_HANGUP_RETRIES = 15
    private const val EXPECT_DIAL_WINDOW_MS = 20_000L
    private const val MAX_CREATION_AGE_MS = 10 * 60_000L

    /** Longest wait for the main thread to check an answer request. */
    private const val MAIN_WAIT_MS = 1_500L

    private val main = Handler(Looper.getMainLooper())
    private val random = SecureRandom()
    private val screeningIo = Executors.newSingleThreadExecutor()
    private val listeners = CopyOnWriteArraySet<Listener>()

    private val _status = MutableStateFlow(CallStatus())
    val status: StateFlow<CallStatus> = _status.asStateFlow()

    private val _offers = MutableStateFlow<IncomingOffer?>(null)
    val offers: StateFlow<IncomingOffer?> = _offers.asStateFlow()

    private val _view = MutableStateFlow(RegistryView())

    /** Screening, offer and secure ownership of the tracked call, for the app's in-call screen. */
    val view: StateFlow<RegistryView> = _view.asStateFlow()

    @Volatile
    private var nonUiService: InCallService? = null

    @Volatile
    private var dialerUiService: InCallService? = null

    /** The app holds the default dialer role; refreshed whenever one of its InCallServices is bound. */
    @Volatile
    private var roleHeld: Boolean = false

    /** The source the tracked call was accepted from; null while nothing is tracked. Main thread. */
    private var trackedSource: CallSource? = null

    /** The service instance that delivered the tracked call. */
    @Volatile
    private var trackedService: InCallService? = null

    /** The service of the tracked call, else the one the role selects for the next call. */
    private val service: InCallService?
        get() = trackedService ?: if (roleHeld) dialerUiService else nonUiService

    @Volatile
    private var trackedCall: Call? = null

    @Volatile
    private var trackedIncoming: Boolean = false

    @Volatile
    private var trackedNumber: String? = null
    private var trackedPresentation: NumberPresentation = NumberPresentation.SHOWN

    /** The tracked call was dialed by the app or offered to it; its call log entry is erased at the end. */
    private var trackedByApp: Boolean = false
        set(value) {
            field = value
            // From now until the entry is erased, the recent calls hold back rows dated from this call's start on.
            if (value) service?.applicationContext?.let { PendingLogErase.begin(it, trackedStartMs) }
        }
    private var trackedStartMs: Long = 0L
    private var trackedDialed: String? = null
    private var callLogEraser: CallLogEraser? = null

    private var activeOffer: IncomingOffer? = null
    private var claimedBySecure: Boolean = false
    private var plainAnswered: Boolean = false
    private var promptShownForOffer: Boolean = false
    private var offerDeliveredToSecure: Boolean = false
    private var screening: Screening = Screening.NONE

    /** Claimed or answered by `:secure`, or dialed by it. Never set by a plain answer. */
    @Volatile
    private var secureOwned: Boolean = false

    /** The app's in-call screen service is bound: it presents offers instead of [IncomingPromptActivity]. */
    private var dialerUiBound: Boolean = false

    private var pendingHangUp: Boolean = false
    private var hangUpAttempts: Int = 0
    private var dataRouteActive: Boolean = false

    @Volatile
    private var expectDialAtMs: Long = 0L

    @Volatile
    private var expectDialNumber: String? = null

    private val callCallback = object : Call.Callback() {
        override fun onStateChanged(call: Call, state: Int) {
            main.post { handleStateChanged(call, state) }
        }

        override fun onDetailsChanged(call: Call, details: Call.Details) {
            main.post { handleDetailsChanged(call, details) }
        }
    }

    private val hangUpRetryRunnable = object : Runnable {
        override fun run() {
            if (!pendingHangUp) return
            val call = trackedCall
            if (call == null || callState(call) == Call.STATE_DISCONNECTED) {
                pendingHangUp = false
                return
            }
            if (hangUpAttempts >= MAX_HANGUP_RETRIES) {
                pendingHangUp = false
                Log.w(TAG, "hangUp retry limit reached while call state=${callState(call)}")
                return
            }
            hangUpAttempts += 1
            issueDisconnectOrReject(call)
            main.postDelayed(this, HANGUP_RETRY_MS)
        }
    }

    fun attachService(source: CallSource, inCallService: InCallService) {
        main.post { setService(source, inCallService) }
    }

    fun detachService(source: CallSource, inCallService: InCallService) {
        val ctx = inCallService.applicationContext
        main.post {
            endTrackedFrom(source, inCallService, ctx)
            if (serviceFor(source) === inCallService) setService(source, null)
        }
    }

    /** Called on the main thread when one of the app's InCallServices is bound. */
    fun refreshRoleHeld(context: Context) {
        roleHeld = readRoleHeld(context)
    }

    /**
     * One of the app's InCallServices was unbound, so Telecom no longer updates its Call objects. A
     * call still tracked from it is ended here with the same cleanup as a removed call (call log,
     * secure ownership); only then is the role read again.
     */
    fun onServiceUnbound(source: CallSource, inCallService: InCallService) {
        val ctx = inCallService.applicationContext
        main.post {
            endTrackedFrom(source, inCallService, ctx)
            roleHeld = readRoleHeld(ctx)
        }
    }

    private fun readRoleHeld(context: Context): Boolean = runCatching {
        context.getSystemService(RoleManager::class.java)?.isRoleHeld(RoleManager.ROLE_DIALER) == true
    }.getOrDefault(false)

    /**
     * The app's in-call screen service was bound or unbound. Once it is gone, an offer that nobody
     * has seen yet falls back to [IncomingPromptActivity].
     */
    fun setDialerUiBound(bound: Boolean) {
        main.post {
            dialerUiBound = bound
            if (bound) return@post
            val offer = activeOffer ?: return@post
            val call = trackedCall ?: return@post
            if (callState(call) != Call.STATE_RINGING || claimedBySecure || plainAnswered) return@post
            if (!PromptRouting.showPrompt(false, offerDeliveredToSecure, promptShownForOffer)) return@post
            val ctx = service?.applicationContext ?: return@post
            promptShownForOffer = true
            IncomingCallService.showIncomingPrompt(ctx, offer)
        }
    }

    /** Whether [call] is the call tracked here. Safe from any thread. */
    fun isTracked(call: Call): Boolean = trackedCall === call

    /**
     * Whether [number] belongs to a call the secure flow dialed: announced through [expectDial]
     * within the window, or the tracked outgoing call taken over as the app's. Safe from any thread.
     */
    fun isAppDial(number: String?): Boolean {
        if (number.isNullOrBlank()) return false
        val expected = expectDialNumber
        if (expected != null &&
            System.currentTimeMillis() - expectDialAtMs <= EXPECT_DIAL_WINDOW_MS &&
            CallLogMatcher.sameNumber(number, expected)
        ) {
            return true
        }
        return secureOwned && !trackedIncoming && CallLogMatcher.sameNumber(number, trackedNumber)
    }

    private fun serviceFor(source: CallSource): InCallService? = when (source) {
        CallSource.NON_UI -> nonUiService
        CallSource.DIALER_UI -> dialerUiService
    }

    private fun setService(source: CallSource, inCallService: InCallService?) {
        when (source) {
            CallSource.NON_UI -> nonUiService = inCallService
            CallSource.DIALER_UI -> dialerUiService = inCallService
        }
    }

    fun addListener(listener: Listener) {
        listeners.add(listener)
        listener.onStatus(_status.value)
        listener.onOffer(_offers.value)
    }

    fun removeListener(listener: Listener) {
        listeners.remove(listener)
    }

    fun expectDial(number: String?) {
        main.post {
            expectDialNumber = number
            expectDialAtMs = System.currentTimeMillis()
            pendingHangUp = false
            hangUpAttempts = 0
            plainAnswered = false
            adoptOutgoingCall(number)
        }
    }

    fun onCallAdded(source: CallSource, inCallService: InCallService, call: Call) {
        main.post {
            setService(source, inCallService)
            if (!CallSource.accepts(source, roleHeld)) return@post
            val existing = trackedCall
            if (existing != null && existing !== call && isCallAlive(callState(existing))) {
                Log.i(TAG, "ignoring secondary call while primary call is active")
                return@post
            }
            if (existing != null && existing !== call && trackedByApp) {
                trackedByApp = false
                eraseCallLog(inCallService.applicationContext)
            }
            detachTrackedCallLocked()
            trackedCall = call
            trackedSource = source
            trackedService = inCallService
            call.registerCallback(callCallback, main)

            val now = System.currentTimeMillis()
            val details = call.details
            val incoming = isIncomingCall(call, details)
            val (presentation, number) = extractCaller(details, incoming)
            trackedIncoming = incoming
            trackedNumber = number
            trackedPresentation = presentation
            trackedStartMs = callStartMs(details, now)
            trackedByApp = false
            trackedDialed = null
            if (!incoming) {
                val expected = expectDialNumber?.takeIf { now - expectDialAtMs <= EXPECT_DIAL_WINDOW_MS }
                if (expected != null && number != null && CallLogMatcher.sameNumber(number, expected)) {
                    trackedByApp = true
                    trackedDialed = expected
                }
            }
            claimedBySecure = false
            plainAnswered = false
            promptShownForOffer = false
            pendingHangUp = false
            hangUpAttempts = 0
            offerDeliveredToSecure = false
            secureOwned = trackedByApp && !incoming

            val state = callState(call)
            screening = if (incoming && state == Call.STATE_RINGING) Screening.PENDING else Screening.NONE
            updateStatus(toPhase(state), incoming, number, presentation)

            if (incoming && state == Call.STATE_RINGING) {
                startIncomingScreening(inCallService.applicationContext, call, number, presentation)
            } else if (!incoming) {
                expectDialAtMs = 0L
                expectDialNumber = null
            }
            publishView()
        }
    }

    fun onCallRemoved(source: CallSource, inCallService: InCallService, call: Call) {
        main.post {
            // Matched against the source the call was accepted from: the role may have changed since.
            if (trackedCall !== call || !CallSource.owns(source, trackedSource)) return@post
            endTrackedCall(inCallService.applicationContext)
        }
    }

    /** Ends a call still tracked from [inCallService] of [source], which was unbound or destroyed. Main thread. */
    private fun endTrackedFrom(source: CallSource, inCallService: InCallService, appContext: Context) {
        if (trackedCall == null || !CallSource.owns(source, trackedSource) || trackedService !== inCallService) return
        Log.i(TAG, "service went away while its call was tracked; ending the call here")
        endTrackedCall(appContext)
    }

    /** The tracked call is over: clears the offer, reports the end, erases the call log entry if due. Main thread. */
    private fun endTrackedCall(appContext: Context) {
        detachTrackedCallLocked()
        pendingHangUp = false
        dataRouteActive = false
        clearOfferAndPrompt(appContext)
        updateStatus(CallPhase.ENDED, trackedIncoming, trackedNumber, trackedPresentation)
        if (trackedByApp) {
            trackedByApp = false
            eraseCallLog(appContext)
        }
        screening = Screening.NONE
        secureOwned = false
        publishView()
    }

    fun onCallAudioStateChanged(source: CallSource, audioState: CallAudioState?) {
        if (audioState == null) return
        main.post {
            if (!CallSource.owns(source, trackedSource)) return@post
            if (!dataRouteActive || plainAnswered) return@post
            val s = service ?: return@post
            val call = trackedCall ?: return@post
            if (!isCallAlive(callState(call))) return@post
            if (audioState.route != CallAudioState.ROUTE_SPEAKER &&
                (audioState.supportedRouteMask and CallAudioState.ROUTE_SPEAKER) != 0
            ) {
                runCatching { s.setAudioRoute(CallAudioState.ROUTE_SPEAKER) }
            }
        }
    }

    fun claim(token: ByteArray): ClaimResult {
        var result = ClaimResult.GONE
        runOnMainSync {
            val offer = activeOffer
            val call = trackedCall
            val state = call?.let(::callState) ?: Call.STATE_DISCONNECTED
            result = when {
                offer == null || !offer.token.contentEquals(token) -> {
                    if (plainAnswered) ClaimResult.TAKEN else ClaimResult.GONE
                }
                plainAnswered || state == Call.STATE_ACTIVE -> ClaimResult.TAKEN
                state != Call.STATE_RINGING -> ClaimResult.GONE
                else -> {
                    claimedBySecure = true
                    secureOwned = true
                    service?.applicationContext?.let { IncomingCallService.cancelPromptNotification(it) }
                    publishView()
                    ClaimResult.RINGING
                }
            }
        }
        return result
    }

    fun release(token: ByteArray) {
        main.post {
            val offer = activeOffer ?: return@post
            if (!offer.token.contentEquals(token)) return@post
            claimedBySecure = false
            secureOwned = false
            publishView()
        }
    }

    /**
     * `:secure` received the offer but cannot show it (not in front, lock screen, or ending). If
     * the call still rings for this token, unclaimed and unanswered, the offer counts as not
     * delivered and the prompt opens unless it was already shown for this offer.
     */
    fun returnOfferToPrompt(token: ByteArray) {
        main.post {
            val offer = activeOffer ?: return@post
            val call = trackedCall ?: return@post
            val ringing = callState(call) == Call.STATE_RINGING
            if (!PromptRouting.offerOpen(offer.token.contentEquals(token), ringing, claimedBySecure, plainAnswered)) return@post
            offerDeliveredToSecure = false
            publishView()
            if (!PromptRouting.showPrompt(dialerUiBound, false, promptShownForOffer)) return@post
            val ctx = service?.applicationContext ?: return@post
            promptShownForOffer = true
            IncomingCallService.showIncomingPrompt(ctx, offer)
        }
    }

    /** Decline from the prompt: rejects the call only for this token while it rings, unclaimed and unanswered. */
    fun declineOffered(token: ByteArray): Boolean {
        var declined = false
        runOnMainSync {
            val offer = activeOffer ?: return@runOnMainSync
            val call = trackedCall ?: return@runOnMainSync
            val ringing = callState(call) == Call.STATE_RINGING
            if (!PromptRouting.offerOpen(offer.token.contentEquals(token), ringing, claimedBySecure, plainAnswered)) return@runOnMainSync
            declined = runCatching {
                call.reject(false, null)
                true
            }.getOrDefault(false)
            if (declined) clearOfferAndPrompt(service?.applicationContext)
        }
        return declined
    }

    fun answer(): Boolean {
        var ok = false
        runOnMainSync {
            val call = trackedCall
            if (call == null || plainAnswered) {
                ok = false
                return@runOnMainSync
            }
            val state = callState(call)
            if (state == Call.STATE_RINGING) {
                ok = runCatching {
                    call.answer(android.telecom.VideoProfile.STATE_AUDIO_ONLY)
                    true
                }.getOrDefault(false)
                if (ok) {
                    trackedByApp = true
                    secureOwned = true
                    service?.applicationContext?.let { IncomingCallService.cancelPromptNotification(it) }
                    clearOfferOnly()
                    if (dataRouteActive) applyAudioRouteLocked(true)
                }
            } else {
                ok = state == Call.STATE_ACTIVE
            }
        }
        return ok
    }

    /**
     * Plain answer of the offered call. The main thread checks the token and marks the plain answer;
     * the answer itself is sent from the calling thread (see [requestOnMain]).
     */
    fun answerPlain(token: ByteArray): Boolean {
        val call = requestOnMain<Call> { ticket ->
            val offer = activeOffer
            val tracked = trackedCall
            val state = tracked?.let(::callState) ?: Call.STATE_DISCONNECTED
            if (tracked == null || offer == null || !offer.token.contentEquals(token) || claimedBySecure || state != Call.STATE_RINGING) {
                return@requestOnMain
            }
            if (!ticket.grant(tracked)) return@requestOnMain
            plainAnswered = true
            dataRouteActive = false
            clearOfferOnly()
        } ?: return false
        val ok = answerNow(call)
        if (ok) {
            service?.applicationContext?.let { ctx ->
                IncomingCallService.cancelPromptNotification(ctx)
                val tm = ctx.getSystemService(TelecomManager::class.java)
                if (ContextCompat.checkSelfPermission(ctx, Manifest.permission.READ_PHONE_STATE) == PackageManager.PERMISSION_GRANTED) {
                    runCatching { tm?.showInCallScreen(false) }
                }
            }
        }
        return ok
    }

    /**
     * Plain answer from the app's own in-call screen for a call without an offer (an offer goes
     * through [answerPlain] and its token). Refused while the secure flow holds a call, since
     * answering would hold or end it; for the tracked call also while an offer is open.
     * The main thread only checks and marks; the answer is sent from the calling thread, which is
     * the "dialer-call" thread for the in-call screen.
     */
    fun answerOrdinary(call: Call): Boolean {
        val granted = requestOnMain<Call> { ticket ->
            if (claimedBySecure || secureOwned) return@requestOnMain
            if (call === trackedCall) {
                if (activeOffer != null || plainAnswered || callState(call) != Call.STATE_RINGING) return@requestOnMain
                if (!ticket.grant(call)) return@requestOnMain
                plainAnswered = true
                dataRouteActive = false
                publishView()
            } else {
                ticket.grant(call)
            }
        } ?: return false
        return answerNow(granted)
    }

    fun hangUp() {
        main.post {
            val call = trackedCall ?: return@post
            if (plainAnswered && !claimedBySecure) return@post
            pendingHangUp = true
            hangUpAttempts = 0
            dataRouteActive = false
            clearOfferAndPrompt(service?.applicationContext)
            issueDisconnectOrReject(call)
            main.removeCallbacks(hangUpRetryRunnable)
            main.postDelayed(hangUpRetryRunnable, HANGUP_RETRY_MS)
        }
    }

    fun setDataRoute(dataMode: Boolean) {
        main.post {
            if (plainAnswered) return@post
            dataRouteActive = dataMode
            applyAudioRouteLocked(dataMode)
        }
    }

    fun suppressPromptForApp() {
        main.post {
            service?.applicationContext?.let { IncomingCallService.cancelPromptNotification(it) }
            // An open `:secure` just subscribed and receives the current offer.
            if (activeOffer != null && !offerDeliveredToSecure) {
                offerDeliveredToSecure = true
                publishView()
            }
        }
    }

    private fun handleStateChanged(call: Call, state: Int) {
        if (trackedCall !== call) return
        updateStatus(toPhase(state), trackedIncoming, trackedNumber, trackedPresentation)
        if (pendingHangUp) {
            if (state == Call.STATE_DISCONNECTED) {
                pendingHangUp = false
                main.removeCallbacks(hangUpRetryRunnable)
            } else {
                issueDisconnectOrReject(call)
            }
        }
        if (state == Call.STATE_ACTIVE && dataRouteActive && !plainAnswered) {
            applyAudioRouteLocked(true)
        }
        if (state == Call.STATE_DISCONNECTED || state == Call.STATE_DISCONNECTING) {
            dataRouteActive = false
            clearOfferAndPrompt(service?.applicationContext)
        }
    }

    private fun handleDetailsChanged(call: Call, details: Call.Details) {
        if (trackedCall !== call) return
        val incoming = isIncomingCall(call, details)
        val (presentation, number) = extractCaller(details, incoming)
        val changed = number != trackedNumber || presentation != trackedPresentation || incoming != trackedIncoming
        trackedIncoming = incoming
        trackedNumber = number
        trackedPresentation = presentation
        updateStatus(toPhase(callState(call)), incoming, number, presentation)
        if (changed && incoming && callState(call) == Call.STATE_RINGING && activeOffer == null && !plainAnswered) {
            service?.applicationContext?.let { ctx ->
                screening = Screening.PENDING
                publishView()
                startIncomingScreening(ctx, call, number, presentation)
            }
        }
    }

    private fun startIncomingScreening(
        appContext: Context,
        call: Call,
        number: String?,
        presentation: NumberPresentation,
    ) {
        screeningIo.execute {
            // Before the first unlock the secure flow cannot run and its files cannot be read: no offer.
            val mode = if (DirectBoot.isUserUnlocked(appContext)) IncomingSettings.read(appContext) else IncomingMode.OFF
            // A saved secure contact. Only its calls lose their call log entry without a secure answer;
            // an ordinary caller who is merely offered the prompt keeps the entry.
            val secureContact = mode != IncomingMode.OFF &&
                presentation == NumberPresentation.SHOWN &&
                !number.isNullOrBlank() &&
                ScreeningStore(appContext).matches(number)
            val matched = when (mode) {
                IncomingMode.OFF -> false
                IncomingMode.ALL -> true
                IncomingMode.CONTACTS -> secureContact
            }
            main.post {
                val stillTracked = trackedCall === call
                // Set before any early return: a secure contact's entry is erased even if the call was
                // answered or ended before screening finished.
                if (stillTracked && secureContact) trackedByApp = true
                if (!stillTracked || callState(call) != Call.STATE_RINGING || pendingHangUp || plainAnswered) {
                    if (stillTracked && screening == Screening.PENDING) {
                        screening = Screening.PLAIN
                        publishView()
                    }
                    return@post
                }
                if (!matched) {
                    screening = Screening.PLAIN
                    clearOfferAndPrompt(appContext)
                    return@post
                }
                if (activeOffer != null) return@post
                val token = ByteArray(16).also { random.nextBytes(it) }
                val offer = IncomingOffer(token = token, number = number, presentation = presentation)
                activeOffer = offer
                _offers.value = offer
                var deliveredToSecure = false
                for (listener in listeners) {
                    if (listener.onOffer(offer)) deliveredToSecure = true
                }
                screening = Screening.OFFER
                offerDeliveredToSecure = deliveredToSecure
                publishView()
                if (PromptRouting.showPrompt(dialerUiBound, deliveredToSecure, promptShownForOffer)) {
                    promptShownForOffer = true
                    IncomingCallService.showIncomingPrompt(appContext, offer)
                }
            }
        }
    }

    private fun applyAudioRouteLocked(dataMode: Boolean) {
        val s = service ?: return
        val audioState = s.callAudioState ?: return
        val mask = audioState.supportedRouteMask
        val target = if (dataMode) {
            if ((mask and CallAudioState.ROUTE_SPEAKER) != 0) CallAudioState.ROUTE_SPEAKER else return
        } else {
            when {
                (mask and CallAudioState.ROUTE_WIRED_HEADSET) != 0 -> CallAudioState.ROUTE_WIRED_HEADSET
                (mask and CallAudioState.ROUTE_EARPIECE) != 0 -> CallAudioState.ROUTE_EARPIECE
                else -> CallAudioState.ROUTE_WIRED_OR_EARPIECE
            }
        }
        if (audioState.route != target) {
            runCatching { s.setAudioRoute(target) }
        }
    }

    private fun issueDisconnectOrReject(call: Call) {
        runCatching {
            if (callState(call) == Call.STATE_RINGING) {
                call.reject(false, null)
            } else {
                call.disconnect()
            }
        }
    }

    /** The relay can deliver the dialed number after Telecom already added the outgoing call. */
    private fun adoptOutgoingCall(number: String?) {
        val call = trackedCall ?: return
        if (number == null || trackedIncoming || trackedByApp || !isCallAlive(callState(call))) return
        if (System.currentTimeMillis() - trackedStartMs > EXPECT_DIAL_WINDOW_MS) return
        val handle = trackedNumber ?: return
        if (!CallLogMatcher.sameNumber(handle, number)) return
        trackedByApp = true
        trackedDialed = number
        secureOwned = true
        publishView()
    }

    /** Telecom dates the call log entry with the call's creation time; fall back to [now]. */
    private fun callStartMs(details: Call.Details, now: Long): Long {
        val created = details.creationTimeMillis
        return if (created in (now - MAX_CREATION_AGE_MS)..now) created else now
    }

    /** Starts erasing the call log entry of the tracked call, which just ended. Nothing is logged about the number. */
    private fun eraseCallLog(appContext: Context) {
        val pendingStartMs = trackedStartMs
        val target = CallLogMatcher.target(
            numbers = listOf(trackedNumber, trackedDialed),
            hidden = trackedPresentation != NumberPresentation.SHOWN,
            incoming = trackedIncoming,
            startMs = trackedStartMs,
            endMs = System.currentTimeMillis(),
        )
        trackedDialed = null
        if (target == null) {
            Log.i(TAG, "call log erase skipped: nothing identifies the entry")
            PendingLogErase.end(appContext, pendingStartMs)
            return
        }
        val eraser = callLogEraser ?: CallLogEraser(appContext).also { callLogEraser = it }
        CallRelayService.holdProcess(appContext)
        eraser.erase(target) {
            PendingLogErase.end(appContext, pendingStartMs)
            main.post { CallRelayService.releaseProcess(appContext) }
        }
    }

    private fun detachTrackedCallLocked() {
        main.removeCallbacks(hangUpRetryRunnable)
        trackedCall?.let { prev ->
            runCatching { prev.unregisterCallback(callCallback) }
        }
        trackedCall = null
        trackedSource = null
        trackedService = null
    }

    private fun clearOfferOnly() {
        activeOffer = null
        claimedBySecure = false
        promptShownForOffer = false
        offerDeliveredToSecure = false
        if (screening == Screening.OFFER) screening = Screening.PLAIN
        _offers.value = null
        for (listener in listeners) listener.onOffer(null)
        publishView()
    }

    private fun clearOfferAndPrompt(appContext: Context?) {
        clearOfferOnly()
        appContext?.let { IncomingCallService.cancelPromptNotification(it) }
    }

    private fun publishView() {
        _view.value = RegistryView(
            screening = screening,
            offerToSecure = activeOffer != null && offerDeliveredToSecure,
            secureOwned = secureOwned,
        )
    }

    private fun updateStatus(
        phase: CallPhase,
        incoming: Boolean,
        number: String?,
        presentation: NumberPresentation,
    ) {
        val next = CallStatus(
            phase = phase,
            incoming = incoming,
            number = number,
            presentation = presentation,
        )
        _status.value = next
        for (listener in listeners) listener.onStatus(next)
    }

    private fun isIncomingCall(call: Call, details: Call.Details): Boolean {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            if (details.callDirection == Call.Details.DIRECTION_INCOMING) return true
            if (details.callDirection == Call.Details.DIRECTION_OUTGOING) return false
        }
        return callState(call) == Call.STATE_RINGING
    }

    private fun extractCaller(details: Call.Details, incoming: Boolean): Pair<NumberPresentation, String?> {
        val handle: Uri? = details.handle
        val raw = handle?.schemeSpecificPart?.trim()?.takeIf { it.isNotEmpty() }
        if (!incoming && raw == null) {
            val expected = expectDialNumber?.takeIf {
                System.currentTimeMillis() - expectDialAtMs <= EXPECT_DIAL_WINDOW_MS
            }
            if (expected != null) return NumberPresentation.SHOWN to expected
        }
        return when (details.handlePresentation) {
            TelecomManager.PRESENTATION_RESTRICTED,
            TelecomManager.PRESENTATION_PAYPHONE,
            -> NumberPresentation.WITHHELD to null
            TelecomManager.PRESENTATION_UNKNOWN -> NumberPresentation.UNKNOWN to null
            else -> if (raw != null) NumberPresentation.SHOWN to raw else NumberPresentation.UNKNOWN to null
        }
    }

    private fun toPhase(state: Int): CallPhase = when (state) {
        Call.STATE_RINGING -> CallPhase.RINGING
        Call.STATE_DIALING,
        Call.STATE_CONNECTING,
        Call.STATE_SELECT_PHONE_ACCOUNT,
        Call.STATE_PULLING_CALL,
        -> CallPhase.DIALING
        Call.STATE_ACTIVE,
        Call.STATE_HOLDING,
        -> CallPhase.ACTIVE
        Call.STATE_DISCONNECTED,
        Call.STATE_DISCONNECTING,
        -> CallPhase.ENDED
        else -> CallPhase.IDLE
    }

    private fun isCallAlive(state: Int): Boolean =
        state != Call.STATE_DISCONNECTED && state != Call.STATE_DISCONNECTING

    @Suppress("DEPRECATION")
    private fun callState(call: Call): Int =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) call.details.state else call.state

    private fun runOnMainSync(block: () -> Unit) {
        if (Looper.myLooper() == Looper.getMainLooper()) {
            block()
            return
        }
        val lock = Object()
        var done = false
        main.post {
            try {
                block()
            } finally {
                synchronized(lock) {
                    done = true
                    lock.notifyAll()
                }
            }
        }
        synchronized(lock) {
            val deadline = System.currentTimeMillis() + 1_500L
            while (!done) {
                val rem = deadline - System.currentTimeMillis()
                if (rem <= 0L) break
                runCatching { lock.wait(rem) }
            }
        }
    }

    /**
     * Runs [check] on the main thread and returns what it granted, waiting at most [MAIN_WAIT_MS];
     * on the main thread itself [check] runs at once. [check] may change state only after
     * [AnswerTicket.grant] returned true: when the wait runs out the request is void, and a grant
     * that comes later returns false.
     */
    private fun <T : Any> requestOnMain(check: (AnswerTicket<T>) -> Unit): T? {
        val ticket = AnswerTicket<T>()
        val task = Runnable {
            try {
                check(ticket)
            } finally {
                ticket.refuse()
            }
        }
        if (Looper.myLooper() == Looper.getMainLooper()) task.run() else main.post(task)
        return ticket.await(MAIN_WAIT_MS)
    }

    /** Sends the answer to Telecom from the calling thread. */
    private fun answerNow(call: Call): Boolean = runCatching {
        call.answer(android.telecom.VideoProfile.STATE_AUDIO_ONLY)
        true
    }.getOrDefault(false)
}
