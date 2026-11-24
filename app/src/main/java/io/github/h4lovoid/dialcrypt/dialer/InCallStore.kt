package io.github.h4lovoid.dialcrypt.dialer

import android.content.Context
import android.os.Handler
import android.os.HandlerThread
import android.os.SystemClock
import android.telecom.Call
import android.telecom.CallEndpoint
import android.telecom.InCallService
import android.telecom.PhoneAccountHandle
import android.telecom.TelecomManager
import android.telephony.TelephonyManager
import io.github.h4lovoid.dialcrypt.core.ContactMembership
import io.github.h4lovoid.dialcrypt.core.NumberPresentation
import io.github.h4lovoid.dialcrypt.dialer.model.AudioUi
import io.github.h4lovoid.dialcrypt.dialer.model.CallSnapshot
import io.github.h4lovoid.dialcrypt.dialer.model.Endpoint
import io.github.h4lovoid.dialcrypt.dialer.model.RegistryView
import io.github.h4lovoid.dialcrypt.dialer.model.Screening
import io.github.h4lovoid.dialcrypt.dialer.model.SecondCallPolicy
import io.github.h4lovoid.dialcrypt.dialer.model.TelecomState
import io.github.h4lovoid.dialcrypt.incoming.CallRegistry
import io.github.h4lovoid.dialcrypt.incoming.screen.ContactNumberIndex
import io.github.h4lovoid.dialcrypt.incoming.screen.DisplaySettings
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executor
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/** Call actions of the in-call screen. Each one runs on the "dialer-call" thread. */
internal interface CallCommands {
    fun answer(id: Int)

    /** Ends the current call and answers the waiting call [id]. */
    fun endAndAnswer(id: Int)
    fun reject(id: Int)
    fun end(id: Int)
    fun hold(id: Int, on: Boolean)
    fun swap()

    /** Merges the active and the held call into a conference. */
    fun merge()
    fun setMuted(on: Boolean)
    fun route(e: Endpoint)
    fun dtmf(id: Int, c: Char?)
    fun selectAccount(id: Int, index: Int)
    fun postDial(id: Int, go: Boolean)
}

/**
 * Calls of [DialerInCallService] in `:call`, as plain data for the in-call screen and the
 * notifications. Every Telecom call and callback runs on the "dialer-call" thread, so a busy main
 * thread does not hold up hanging up. Answering asks the main thread of [CallRegistry] only to check
 * and mark the call, waiting at most 1.5 s; the answer itself is sent from the dialer-call thread, and
 * a request the main thread did not grant in time is void. Each call gets an id that only grows
 * within this process and a 16-byte nonce; notification actions must present both.
 */
internal object InCallStore {
    private val TICK_TOKEN = Any()

    private val thread = HandlerThread("dialer-call").apply { start() }
    val handler = Handler(thread.looper)
    val executor = Executor { handler.post(it) }
    private val scope = CoroutineScope(SupervisorJob() + executor.asCoroutineDispatcher())
    private val random = SecureRandom()
    private val nextId = AtomicInteger(0)

    class Entry(val id: Int, val call: Call, val nonce: ByteArray, val addedMs: Long, val emergency: Boolean) {
        var postDial: String? = null
        var accounts: List<PhoneAccountHandle> = emptyList()
        var accountLabels: List<String> = emptyList()
        var callback: Call.Callback? = null

        /** Ended at once because a secure call is under way; never presented. */
        var dropped: Boolean = false

        /** [dropped] and disconnect (not only reject) was sent. */
        var dropDisconnected: Boolean = false
    }

    // Touched on the dialer-call thread only.
    private val entries = LinkedHashMap<Int, Entry>()
    private var endpoints: List<CallEndpoint> = emptyList()
    private var viewJob: Job? = null
    private var lastSecureOwned = false
    private var resumeSecureUntil = 0L
    private var proximity: ProximityLock? = null

    private val nonces = ConcurrentHashMap<Int, ByteArray>()

    private val _snapshots = MutableStateFlow<List<CallSnapshot>>(emptyList())
    val snapshots: StateFlow<List<CallSnapshot>> = _snapshots.asStateFlow()

    private val _audio = MutableStateFlow(AudioUi())
    val audio: StateFlow<AudioUi> = _audio.asStateFlow()

    private val _showFull = MutableStateFlow(false)
    val showFull: StateFlow<Boolean> = _showFull.asStateFlow()

    private val _memberships = MutableStateFlow<Map<String, ContactMembership>>(emptyMap())

    /**
     * Contact index answers for the numbers of the current calls, keyed by the trimmed number. A number
     * without an answer yet counts as unknown and shows masked. Lookups use the Keystore, so they run on
     * their own thread and never hold up the dialer-call thread.
     */
    val memberships: StateFlow<Map<String, ContactMembership>> = _memberships.asStateFlow()
    private val lookupExecutor = Executors.newSingleThreadExecutor { r -> Thread(r, "dialer-number-index").apply { isDaemon = true } }
    private val pendingLookups = HashSet<String>()

    // Grows whenever earlier answers must be forgotten; an answer from before is then dropped.
    private var lookupGeneration = 0

    @Volatile
    private var numberIndex: ContactNumberIndex? = null

    private val _ticks = MutableStateFlow(0L)

    /** Elapsed realtime of the last screening deadline; the in-call screen reduces again when it changes. */
    val ticks: StateFlow<Long> = _ticks.asStateFlow()

    private val _finishRequests = MutableSharedFlow<Unit>(extraBufferCapacity = 1, onBufferOverflow = BufferOverflow.DROP_OLDEST)

    /** The in-call screen must close at once: a secure call took over, or the service was unbound. */
    val finishRequests: SharedFlow<Unit> = _finishRequests.asSharedFlow()

    val commands: CallCommands get() = TelecomCallCommands

    @Volatile
    var service: InCallService? = null
        private set

    @Volatile
    private var appContext: Context? = null

    /** Runs on the dialer-call thread after every change; set by [DialerInCallService]. */
    @Volatile
    var onChanged: (() -> Unit)? = null

    /**
     * Runs on the dialer-call thread before the calls are presented again by [representIncoming];
     * set by [DialerInCallService] to forget what its incoming notification last showed.
     */
    @Volatile
    var onIncomingReset: (() -> Unit)? = null

    private val tick = Runnable {
        _ticks.value = SystemClock.elapsedRealtime()
        publish()
    }

    fun attach(svc: InCallService) {
        service = svc
        val ctx = svc.applicationContext
        appContext = ctx
        handler.post {
            _showFull.value = DisplaySettings.read(ctx)
            if (numberIndex == null) numberIndex = ContactNumberIndex(ctx)
            if (proximity == null) proximity = ProximityLock.create(ctx)
            if (viewJob == null) {
                viewJob = scope.launch { CallRegistry.view.collect { onRegistryView(it) } }
            }
        }
    }

    /**
     * The user is unlocked: the setting and the contact index can be read now, so numbers looked up
     * before the first unlock, which all came back unknown, are asked about again.
     */
    fun onUserUnlocked() {
        handler.post {
            val ctx = appContext ?: return@post
            _showFull.value = DisplaySettings.read(ctx)
            lookupGeneration++
            pendingLookups.clear()
            _memberships.value = emptyMap()
            refreshMemberships()
        }
    }

    /** [svc] was unbound or destroyed: its Call objects are no longer updated. */
    fun detach(svc: InCallService) {
        handler.post {
            if (service !== svc) return@post
            viewJob?.cancel()
            viewJob = null
            service = null
            clearAll()
            _finishRequests.tryEmit(Unit)
        }
    }

    fun add(call: Call) {
        val addedMs = SystemClock.elapsedRealtime()
        handler.post {
            appContext?.let { _showFull.value = DisplaySettings.read(it) }
            val id = nextId.incrementAndGet()
            val nonce = ByteArray(16).also { random.nextBytes(it) }
            val entry = Entry(id, call, nonce, addedMs, isEmergency(call))
            val cb = object : Call.Callback() {
                override fun onStateChanged(c: Call, state: Int) = publish()

                override fun onDetailsChanged(c: Call, details: Call.Details) = publish()

                override fun onParentChanged(c: Call, parent: Call?) = publish()

                override fun onChildrenChanged(c: Call, children: List<Call>) = publish()

                override fun onConferenceableCallsChanged(c: Call, conferenceableCalls: List<Call>) = publish()

                override fun onPostDialWait(c: Call, remainingPostDialSequence: String?) {
                    entry.postDial = remainingPostDialSequence?.takeIf { it.isNotEmpty() }
                    publish()
                }
            }
            entry.callback = cb
            entries[id] = entry
            nonces[id] = nonce
            call.registerCallback(cb, handler)
            dropSecondCallDuringSecure(entry)
            publish()
        }
    }

    fun remove(call: Call) {
        handler.post {
            val entry = entries.values.firstOrNull { it.call === call } ?: return@post
            runCatching { call.unregisterCallback(entry.callback) }
            entries.remove(entry.id)
            nonces.remove(entry.id)
            publish()
        }
    }

    /** Whether [id] and [nonce] name a call of this process. Safe from any thread. */
    fun accepts(id: Int, nonce: ByteArray?): Boolean {
        val expected = nonces[id] ?: return false
        return nonce != null && MessageDigest.isEqual(expected, nonce)
    }

    fun setMuted(muted: Boolean) {
        handler.post { _audio.value = _audio.value.copy(muted = muted) }
    }

    fun setEndpoint(endpoint: CallEndpoint) {
        handler.post {
            _audio.value = _audio.value.copy(endpoint = CallSnapshots.endpoint(endpoint.endpointType))
            updateProximity()
        }
    }

    fun setAvailable(list: List<CallEndpoint>) {
        handler.post {
            endpoints = list.toList()
            _audio.value = _audio.value.copy(available = endpoints.map { CallSnapshots.endpoint(it.endpointType) }.distinct())
        }
    }

    /** A call is ringing, dialing or connected. Safe from any thread. */
    fun hasLiveCall(): Boolean = _snapshots.value.any { !TelecomState.isEnding(it.telecomState) }

    /** Re-publishes at elapsed realtime [atMs], for a screening deadline. Dialer-call thread. */
    fun scheduleTick(atMs: Long) {
        handler.removeCallbacksAndMessages(TICK_TOKEN)
        val delay = (atMs - SystemClock.elapsedRealtime()).coerceAtLeast(0L)
        handler.postAtTime(tick, TICK_TOKEN, SystemClock.uptimeMillis() + delay)
    }

    /**
     * The secure answer was abandoned (the unlock was cancelled), after its notification had been
     * cancelled: post the ringing call's notification again. Nothing is posted once it stopped ringing.
     */
    fun representIncoming() {
        handler.post {
            onIncomingReset?.invoke()
            publish()
        }
    }

    // The following run on the dialer-call thread.

    fun entry(id: Int): Entry? = entries[id]

    fun entries(): List<Entry> = entries.values.toList()

    fun endpointFor(e: Endpoint): CallEndpoint? = endpoints.firstOrNull { CallSnapshots.endpoint(it.endpointType) == e }

    /**
     * Screening that governs answering [e]. A lone ringing call not yet tracked is about to be
     * screened; a call ringing next to another live call is never screened.
     */
    fun screeningFor(e: Entry): Screening {
        if (CallRegistry.isTracked(e.call)) return CallRegistry.view.value.screening
        val othersLive = entries.values.any { other ->
            val s = other.call.details.state
            other !== e && !TelecomState.isRinging(s) && !TelecomState.isEnding(s)
        }
        return if (othersLive) Screening.PLAIN else Screening.PENDING
    }

    private fun onRegistryView(v: RegistryView) {
        if (v.secureOwned != lastSecureOwned) {
            lastSecureOwned = v.secureOwned
            appContext?.let { SecureBusyMarker.set(it, v.secureOwned) }
            if (v.secureOwned) _finishRequests.tryEmit(Unit)
        }
        publish()
    }

    private fun publish() {
        entries.values.forEach(::refreshAccounts)
        disconnectAnsweredDrops()
        _snapshots.value = entries.values.map { e ->
            CallSnapshots.of(
                id = e.id,
                call = e.call,
                addedMs = e.addedMs,
                tracked = CallRegistry.isTracked(e.call),
                emergency = e.emergency,
                postDial = e.postDial,
                accounts = e.accountLabels,
            )
        }
        updateProximity()
        refreshMemberships()
        resumeSecureCallIfHeld()
        onChanged?.invoke()
    }

    /** Dialer-call thread. Forgets answers for numbers no longer on a call and asks about new ones. */
    private fun refreshMemberships() {
        val wanted = _snapshots.value
            .filter { it.presentation == NumberPresentation.SHOWN && !it.payphone }
            .mapNotNull { it.number?.trim()?.takeIf { n -> n.isNotEmpty() } }
            .toSet()
        val known = _memberships.value
        if (!wanted.containsAll(known.keys)) _memberships.value = known.filterKeys { it in wanted }
        pendingLookups.retainAll(wanted)
        val index = numberIndex ?: return
        val generation = lookupGeneration
        for (n in wanted) {
            if (n in known || !pendingLookups.add(n)) continue
            lookupExecutor.execute {
                val m = runCatching { index.lookup(n) }.getOrDefault(ContactMembership.UNKNOWN)
                handler.post {
                    if (generation == lookupGeneration && pendingLookups.remove(n)) _memberships.value = _memberships.value + (n to m)
                }
            }
        }
    }

    private fun updateProximity() {
        proximity?.update(ProximityLock.wanted(_snapshots.value, _audio.value, CallRegistry.view.value.secureOwned))
    }

    private fun clearAll() {
        handler.removeCallbacksAndMessages(TICK_TOKEN)
        for (e in entries.values) runCatching { e.call.unregisterCallback(e.callback) }
        entries.clear()
        nonces.clear()
        endpoints = emptyList()
        resumeSecureUntil = 0L
        lastSecureOwned = false
        // The service is gone, so the view collector no longer clears the marker when the secure call ends.
        appContext?.let { SecureBusyMarker.set(it, false) }
        _snapshots.value = emptyList()
        _memberships.value = emptyMap()
        pendingLookups.clear()
        _audio.value = AudioUi()
        proximity?.update(false)
        onChanged?.invoke()
    }

    private fun refreshAccounts(e: Entry) {
        val d = e.call.details
        if (d.state != Call.STATE_SELECT_PHONE_ACCOUNT) {
            if (e.accounts.isNotEmpty()) {
                e.accounts = emptyList()
                e.accountLabels = emptyList()
            }
            return
        }
        val handles = CallSnapshots.accountHandles(d)
        if (handles == e.accounts) return
        e.accounts = handles
        val tm = appContext?.getSystemService(TelecomManager::class.java)
        e.accountLabels = handles.mapIndexed { i, h ->
            runCatching { tm?.getPhoneAccount(h)?.label?.toString() }.getOrNull()?.takeIf { it.isNotBlank() }
                ?: (i + 1).toString()
        }
    }

    /** Emergency as identified by the network, or an outgoing emergency number. Unknown counts as emergency. */
    private fun isEmergency(call: Call): Boolean {
        val d = call.details
        if (d.hasProperty(Call.Details.PROPERTY_NETWORK_IDENTIFIED_EMERGENCY_CALL)) return true
        if (CallSnapshots.isIncoming(d)) return false
        val number = CallSnapshots.number(d) ?: return false
        val tm = appContext?.getSystemService(TelephonyManager::class.java) ?: return false
        return runCatching { tm.isEmergencyNumber(number) }.getOrDefault(true)
    }

    /**
     * A second call, outgoing or incoming, arrived while the secure flow owns a live call: end it at
     * once unless it is an emergency call (see [SecondCallPolicy]), and resume the secure call if
     * Telecom held it.
     */
    private fun dropSecondCallDuringSecure(e: Entry) {
        val secureOwned = CallRegistry.view.value.secureOwned
        if (!secureOwned) return
        val secureLive = entries.values.any { other ->
            other !== e && CallRegistry.isTracked(other.call) && !TelecomState.isEnding(other.call.details.state)
        }
        // A call while the phone is in emergency callback mode may be the emergency service calling back.
        val emergency = e.emergency || e.call.details.hasProperty(Call.Details.PROPERTY_EMERGENCY_CALLBACK_MODE)
        when (SecondCallPolicy.drop(secureOwned, secureLive, emergency, e.call.details.state)) {
            SecondCallPolicy.Drop.KEEP -> return
            SecondCallPolicy.Drop.REJECT -> runCatching { e.call.reject(false, null) }
            SecondCallPolicy.Drop.DISCONNECT -> {
                runCatching { e.call.disconnect() }
                e.dropDisconnected = true
            }
        }
        e.dropped = true
        resumeSecureUntil = SystemClock.elapsedRealtime() + SecondCallPolicy.RESUME_WINDOW_MS
    }

    /** A rejected second call that was answered anyway is disconnected, and the resume window restarts. */
    private fun disconnectAnsweredDrops() {
        for (e in entries.values) {
            if (!e.dropped || !SecondCallPolicy.disconnectAfterReject(e.call.details.state, e.dropDisconnected)) continue
            runCatching { e.call.disconnect() }
            e.dropDisconnected = true
            resumeSecureUntil = SystemClock.elapsedRealtime() + SecondCallPolicy.RESUME_WINDOW_MS
        }
    }

    private fun resumeSecureCallIfHeld() {
        if (resumeSecureUntil == 0L) return
        val secure = entries.values.firstOrNull { CallRegistry.isTracked(it.call) }
        val othersLive = secure != null && entries.values.any { it !== secure && !TelecomState.isEnding(it.call.details.state) }
        val decision = SecondCallPolicy.resume(
            nowMs = SystemClock.elapsedRealtime(),
            resumeUntilMs = resumeSecureUntil,
            secureOwned = CallRegistry.view.value.secureOwned,
            secureState = secure?.call?.details?.state,
            othersLive = othersLive,
        )
        when (decision) {
            SecondCallPolicy.Resume.IDLE, SecondCallPolicy.Resume.WAIT -> Unit
            SecondCallPolicy.Resume.EXPIRED -> resumeSecureUntil = 0L
            SecondCallPolicy.Resume.UNHOLD -> {
                runCatching { secure?.call?.unhold() }
                resumeSecureUntil = 0L
            }
        }
    }
}
