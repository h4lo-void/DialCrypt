package io.github.h4lovoid.dialcrypt.core.real

import android.content.Context
import android.os.SystemClock
import android.util.Log
import io.github.h4lovoid.dialcrypt.BuildConfig
import io.github.h4lovoid.dialcrypt.call.CallAudio
import io.github.h4lovoid.dialcrypt.call.CallLink
import io.github.h4lovoid.dialcrypt.call.CallPhase
import io.github.h4lovoid.dialcrypt.call.ClaimResult
import io.github.h4lovoid.dialcrypt.call.IncomingOffer
import io.github.h4lovoid.dialcrypt.call.SecureCallService
import io.github.h4lovoid.dialcrypt.core.ChatMessage
import io.github.h4lovoid.dialcrypt.core.Contact
import io.github.h4lovoid.dialcrypt.core.ContactResult
import io.github.h4lovoid.dialcrypt.core.IncomingUi
import io.github.h4lovoid.dialcrypt.core.MessageBody
import io.github.h4lovoid.dialcrypt.core.MessageStatus
import io.github.h4lovoid.dialcrypt.core.NativeBridge
import io.github.h4lovoid.dialcrypt.core.NumberPresentation
import io.github.h4lovoid.dialcrypt.core.PeerInfo
import io.github.h4lovoid.dialcrypt.core.PhoneRules
import io.github.h4lovoid.dialcrypt.core.QuickCommand
import io.github.h4lovoid.dialcrypt.core.SendResult
import io.github.h4lovoid.dialcrypt.core.SessionFailure
import io.github.h4lovoid.dialcrypt.core.SessionPhase
import io.github.h4lovoid.dialcrypt.core.SessionState
import io.github.h4lovoid.dialcrypt.security.HardwareKeyBridge
import java.io.File
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import kotlin.concurrent.thread
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull

/** What a call session needs from [NativeSecureCore]. */
internal interface SessionHost {
    /** Worker thread. Current app handle; 0 while the core is not running. */
    val appHandle: Long

    /** Any thread: the core is running and unlocked. */
    val unlocked: Boolean

    /** Any thread: id of the saved contact holding [pub33]. */
    fun contactIdForKey(pub33: ByteArray): Long?

    /** Worker thread. VAULT_DIRTY(seq): persist the vault, then report it saved to the native library. */
    fun vaultDirty(seq: Long)

    /** Worker thread. Re-reads the contact list after the native library changed it. */
    fun contactsChanged()

    /** Worker thread. Saves the display/dial number in metadata before refreshing contacts. */
    fun saveContactNumber(id: Long, number: String?) {}

    /** Worker thread. A call was established with this contact's pairing: both sides hold it; save and refresh. */
    fun markMutual(contactId: Long) {}

    /** Any thread: unlocked with a fingerprint for one ringing call only. */
    val callScoped: Boolean get() = false

    /** Any thread: the secure screen is in front and the lock screen is not shown, so an incoming offer can be shown. */
    val canPresentIncoming: Boolean get() = true

    /** Any thread: the call a call-scoped unlock was for is over, or never started: lock again. */
    fun lockAfterScopedCall() {}
}

/** Where an incoming offer reaching the secure process goes. */
internal object OfferRouting {
    enum class Action {
        /** A secure call is up: the offer is not ours to show. */
        IGNORE,
        PRESENT,

        /** An ended call's error screen is still up: clear it, then show the offer. */
        RESET_AND_PRESENT,

        /** This process cannot show it: `:call` shows its own prompt. */
        RETURN,
    }

    /**
     * [handoff]: the user already chose a secure answer for this offer in `:call`, which started
     * this screen, so it is shown here even before the screen is in front.
     */
    fun route(callActive: Boolean, phase: SessionPhase, handoff: Boolean, canPresent: Boolean): Action = when {
        callActive -> Action.IGNORE
        !canPresent && !handoff -> Action.RETURN
        // A finished call's end screen is cleared so the new call shows here.
        phase == SessionPhase.ABORTED || phase == SessionPhase.CLEARED -> Action.RESET_AND_PRESENT
        phase == SessionPhase.IDLE -> Action.PRESENT
        else -> Action.RETURN
    }
}

/** A call established with a contact's pairing proves both phones saved each other with it. */
internal object MutualPairing {
    /**
     * Contact a call proves mutual: the one whose pairing PSK it mixed in, or, on a fast resume, the
     * stored contact. Importing a code wipes the resume secrets and a PSK contact's full handshake
     * must use its PSK, so a PSK contact that resumes had a PSK call before. 0 = none. The host
     * still ignores contacts without a PSK.
     */
    fun contactFor(pskContactId: Long, resume: Boolean, storedContactId: Long): Long = when {
        pskContactId > 0L -> pskContactId
        resume && storedContactId > 0L -> storedContactId
        else -> 0L
    }

    /** Worker thread. Marks the contact whose pairing the call used; false when none was used or marking failed. */
    fun record(pskContactId: Long, host: SessionHost): Boolean {
        if (pskContactId <= 0L) return false
        return runCatching { host.markMutual(pskContactId) }.isSuccess
    }
}

/** One cellular call carrying a secure session. */
private class ActiveCall(val dial: Boolean, val number: String?, val contactId: Long?) {
    /** Serializes every native call on [handle]. */
    val nativeLock = Any()
    @Volatile var handle = 0L
    @Volatile var audio: CallAudio? = null
    /** dial() or answer() succeeded: the cellular call is ours to hang up. */
    @Volatile var ownsCall = false
    @Volatile var stopped = false
    /** The user hung up or rejected the words. */
    @Volatile var localEnd = false
    /** Ends without any visible end state (lock, wipe). */
    @Volatile var silent = false
    @Volatile var cause: EndCause? = null
    @Volatile var causeAtMs = 0L
    @Volatile var txEnd: PumpEnd? = null
    @Volatile var rxEnd: PumpEnd? = null
    @Volatile var resumePath = false
    @Volatile var sasWords: List<Int>? = null
    @Volatile var keyChangedFrom: ByteArray? = null
    @Volatile var voiceOpenedAtMs = 0L
    val finishing = AtomicBoolean(false)
    val ended = AtomicBoolean(false)
    val txDone = CompletableDeferred<Unit>()
    /** Native outgoing message id to the local [ChatMessage.id]. */
    val outgoing = ConcurrentHashMap<Int, Long>()
    @Volatile var job: Job? = null
}

/**
 * Call sessions of [NativeSecureCore]: dialing or answering through [CallLink], the native
 * session (nativeSession*), the two audio pumps, the event loop and [state].
 *
 * Threads: the call orchestration and the event loop run as one coroutine on Dispatchers.IO,
 * the transmit and receive pumps each on their own thread, vault work on the core [worker].
 * Every native call on a session holds that session's lock; [state] changes hold [stateLock].
 */
internal class SessionEngine(
    private val call: CallLink,
    private val keys: HardwareKeyBridge,
    private val host: SessionHost,
    private val worker: CoroutineDispatcher,
    private val contacts: StateFlow<List<Contact>>,
    private val context: Context? = null,
) {
    private val sessionState = MutableStateFlow(SessionState())
    val state: StateFlow<SessionState> = sessionState

    private val incomingFlow = MutableStateFlow<IncomingUi?>(null)
    val incoming: StateFlow<IncomingUi?> = incomingFlow.asStateFlow()

    private val callHeldFlow = MutableStateFlow(false)
    val callHeld: StateFlow<Boolean> = callHeldFlow.asStateFlow()

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val stateLock = Any()
    private val engineLock = Any()
    private val offerLock = Any()
    @Volatile private var pendingHandoffToken: ByteArray? = null
    @Volatile private var active: ActiveCall? = null
    private val nextMessageId = AtomicLong(1)

    /** A secure answer chosen in `:call` waits for this screen (unlock, then claim). */
    val handoffPending: Boolean get() = pendingHandoffToken != null

    init {
        scope.launch { watchCalls() }
        scope.launch { watchOffers() }
    }

    private fun now(): Long = SystemClock.elapsedRealtime()

    // ---------------------------------------------------------------- state

    /** Caller holds [stateLock]. */
    private fun put(next: SessionState) {
        val prev = sessionState.value
        sessionState.value = next
        if (prev.phase != next.phase) Log.i(TAG, "phase " + prev.phase + " -> " + next.phase)
    }

    private fun setState(next: SessionState) = synchronized(stateLock) { put(next) }

    /** Applies [f] unless [c] has already ended. */
    private fun update(c: ActiveCall, f: (SessionState) -> SessionState) {
        synchronized(stateLock) {
            if (!c.ended.get()) put(f(sessionState.value))
        }
    }

    private inline fun nativeOn(c: ActiveCall, f: (Long) -> Int): Int = synchronized(c.nativeLock) {
        val h = c.handle
        if (h == 0L) NativeCode.BAD_HANDLE else f(h)
    }

    private fun terminal(c: ActiveCall, cause: EndCause) {
        if (c.cause == null) {
            c.causeAtMs = now()
            c.cause = cause
        }
    }

    // ---------------------------------------------------------------- starting a call

    fun startCallToContact(contactId: Long) {
        val contact = contacts.value.firstOrNull { it.id == contactId }
        val number = contact?.number
        if (contact == null || number == null) {
            // The vault keeps no numbers, so a saved contact cannot be dialed yet.
            Log.w(TAG, "contact call refused code=" + if (contact == null) 1 else 2)
            refuse(PeerInfo(contact?.id, contact?.name, null))
            return
        }
        begin(ActiveCall(dial = true, number = PhoneRules.normalize(number), contactId = contactId), PeerInfo(contact.id, contact.name, number))
    }

    fun startCallToNumber(number: String) {
        val normalized = PhoneRules.normalize(number)
        if (!PhoneRules.isValid(normalized)) {
            Log.w(TAG, "number call refused code=3")
            refuse(PeerInfo(null, null, null))
            return
        }
        val matched = findContactByNumber(normalized)
        val peer = PeerInfo(matched?.id, matched?.name, normalized)
        begin(ActiveCall(dial = true, number = normalized, contactId = matched?.id), peer)
    }

    fun beginHandoff(token: ByteArray) {
        val copy = token.copyOf()
        synchronized(offerLock) { pendingHandoffToken = copy }
        scope.launch {
            val claim = call.claim(copy)
            if (claim != ClaimResult.RINGING) {
                synchronized(offerLock) {
                    if (pendingHandoffToken?.contentEquals(copy) == true) pendingHandoffToken = null
                }
                incomingFlow.value = null
                return@launch
            }
            val currentOffer = call.offers.value
            val offer = if (currentOffer != null && currentOffer.token.contentEquals(copy)) {
                currentOffer
            } else {
                val st = call.status.value
                IncomingOffer(copy, st.number, st.presentation)
            }
            if (host.unlocked) {
                takeIncomingOffer(offer)
            } else {
                incomingFlow.value = IncomingUi(
                    number = offer.number,
                    presentation = offer.presentation,
                    handoff = true,
                    ringingSinceMs = System.currentTimeMillis(),
                )
            }
        }
    }

    fun onUnlocked() {
        val token = synchronized(offerLock) { pendingHandoffToken?.copyOf() } ?: run {
            lockIfScoped()
            return
        }
        scope.launch {
            if (call.claim(token) != ClaimResult.RINGING) {
                synchronized(offerLock) {
                    if (pendingHandoffToken?.contentEquals(token) == true) pendingHandoffToken = null
                }
                incomingFlow.value = null
                lockIfScoped()
                return@launch
            }
            val currentOffer = call.offers.value
            val st = call.status.value
            val offer = if (currentOffer != null && currentOffer.token.contentEquals(token)) {
                currentOffer
            } else {
                IncomingOffer(token, st.number, st.presentation)
            }
            takeIncomingOffer(offer)
        }
    }

    fun decideIncoming(secure: Boolean) {
        val offer = call.offers.value ?: run {
            incomingFlow.value = null
            return
        }
        incomingFlow.value = null
        if (!secure) {
            scope.launch { call.answerPlain(offer.token) }
            return
        }
        if (!host.unlocked) {
            beginHandoff(offer.token)
            return
        }
        scope.launch {
            if (call.claim(offer.token) == ClaimResult.RINGING) {
                takeIncomingOffer(offer)
            }
        }
    }

    private fun takeIncomingOffer(offer: IncomingOffer) {
        synchronized(offerLock) { pendingHandoffToken = null }
        incomingFlow.value = null
        if (active != null || sessionState.value.phase != SessionPhase.IDLE || !host.unlocked) {
            call.release(offer.token)
            if (active == null) lockIfScoped()
            return
        }
        val normalized = offer.number?.let(PhoneRules::normalize)?.takeIf { it.isNotEmpty() }
        val matched = normalized?.let(::findContactByNumber)
        val shownNumber = if (offer.presentation == NumberPresentation.SHOWN) offer.number else null
        val peer = PeerInfo(matched?.id, matched?.name, shownNumber, offer.presentation)
        begin(ActiveCall(dial = false, number = normalized, contactId = matched?.id), peer)
    }

    private fun findContactByNumber(number: String): Contact? {
        val wanted = PhoneRules.matchCandidates(number)
        if (wanted.isEmpty()) return null
        return contacts.value.firstOrNull { c ->
            val cn = c.number ?: return@firstOrNull false
            PhoneRules.matchCandidates(cn).any { it in wanted }
        }
    }

    /** A call that cannot start shows the "call ended" screen instead of doing nothing. */
    private fun refuse(peer: PeerInfo) {
        if (active != null) return
        setState(SessionState(phase = SessionPhase.ABORTED, peer = peer, abort = SessionFailure.UNKNOWN))
    }

    private fun begin(c: ActiveCall, peer: PeerInfo) {
        if (!host.unlocked) {
            Log.w(TAG, "call refused code=4")
            refuse(peer)
            return
        }
        synchronized(engineLock) {
            if (active != null) {
                Log.w(TAG, "call refused code=5")
                return
            }
            active = c
            callHeldFlow.value = true
        }
        incomingFlow.value = null
        context?.let { SecureCallService.start(it) }
        setState(if (c.dial) SessionReducer.dialing(peer) else SessionReducer.incoming(peer))
        c.job = scope.launch { runCall(c) }
    }

    private suspend fun watchCalls() {
        call.status.collect { st ->
            Log.i(TAG, "call phase=" + st.phase + " incoming=" + (if (st.incoming) 1 else 0))
            val c = active
            if (c != null) {
                if (c.audio != null && (st.phase == CallPhase.ENDED || st.phase == CallPhase.IDLE)) {
                    scope.launch { finish(c, EndCause.Dropped) }
                }
            } else if (st.phase == CallPhase.ENDED || st.phase == CallPhase.IDLE) {
                synchronized(offerLock) { pendingHandoffToken = null }
                incomingFlow.value = null
                lockIfScoped()
            }
        }
    }

    private suspend fun watchOffers() {
        call.offers.collect { offer ->
            if (offer == null) {
                synchronized(offerLock) { pendingHandoffToken = null }
                incomingFlow.value = null
                // Answering also clears the offer, but by then the call is active.
                if (active == null) lockIfScoped()
                return@collect
            }
            val isHandoff = synchronized(offerLock) {
                pendingHandoffToken?.contentEquals(offer.token) == true
            }
            when (OfferRouting.route(active != null, sessionState.value.phase, isHandoff, host.canPresentIncoming)) {
                OfferRouting.Action.IGNORE -> return@collect
                OfferRouting.Action.RETURN -> {
                    Log.i(TAG, "offer returned to the prompt")
                    call.returnOffer(offer.token)
                    return@collect
                }
                OfferRouting.Action.RESET_AND_PRESENT -> dismissAbort()
                OfferRouting.Action.PRESENT -> Unit
            }
            if (isHandoff && host.unlocked) {
                scope.launch { takeIncomingOffer(offer) }
            } else {
                incomingFlow.value = IncomingUi(
                    number = offer.number,
                    presentation = offer.presentation,
                    handoff = isHandoff,
                    ringingSinceMs = System.currentTimeMillis(),
                )
            }
        }
    }

    private suspend fun runCall(c: ActiveCall) {
        try {
            val placed = if (c.dial) call.dial(c.number ?: "") else call.answer()
            Log.i(TAG, (if (c.dial) "dial" else "answer") + " ok=" + (if (placed) 1 else 0))
            if (!placed) {
                finish(c, EndCause.Failed(SessionFailure.UNKNOWN))
                return
            }
            c.ownsCall = true
            if (!awaitActive(c)) {
                finish(c, EndCause.Dropped)
                return
            }
            val audio = call.openAudio()
            Log.i(TAG, "openAudio ok=" + if (audio != null) 1 else 0)
            if (audio == null) {
                finish(c, EndCause.Failed(SessionFailure.UNKNOWN))
                return
            }
            c.audio = audio
            if (c.finishing.get()) {
                runCatching { audio.close() }
                return
            }
            if (BuildConfig.FIELD_TEST_LINK_PROBE) {
                val dir = FieldTest.probeDir()
                val tx = dir?.let { d -> FieldTest.loadProbeTx(d) { Log.w(TAG, "probe tx.wav rejected code=1") } }
                if (dir != null && tx != null) {
                    runProbe(c, audio, tx, dir)
                    return
                }
            }
            // Created and attached atomically under NonCancellable so coroutine cancellation
            // cannot abandon an open native session handle.
            val kept = withContext(worker + NonCancellable) {
                val app = host.appHandle
                val h = if (app == 0L || !host.unlocked) {
                    0L
                } else {
                    val gearCode = FieldTest.gearOverride()
                        ?: if (!WIDEBAND) 1 else io.github.h4lovoid.dialcrypt.core.SharedPrefsUiPreferences.readModemMode(context).wireCode
                    Log.i(TAG, "gear=$gearCode")
                    if (gearCode == 1 || gearCode == 2) {
                        NativeBridge.nativeSessionCreate(app, c.dial, nativeContact(c.contactId), e164(c.number), gearCode == 2, now())
                    } else {
                        NativeBridge.nativeSessionCreateGear(app, c.dial, nativeContact(c.contactId), e164(c.number), gearCode, now())
                    }
                }
                Log.i(TAG, "session create ok=" + if (h != 0L) 1 else 0)
                if (h == 0L) {
                    false
                } else {
                    synchronized(c.nativeLock) {
                        if (c.finishing.get()) {
                            NativeBridge.nativeSessionClose(h, false)
                            false
                        } else {
                            c.handle = h
                            true
                        }
                    }
                }
            }
            if (!kept) {
                if (c.handle == 0L && !c.finishing.get()) {
                    finish(c, EndCause.Failed(SessionFailure.UNKNOWN))
                }
                return
            }
            update(c) { SessionReducer.waitingPeer(it) }
            startPumps(c, audio)
            eventLoop(c)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Log.e(TAG, "call failed: " + e.javaClass.simpleName)
            finish(c, EndCause.Failed(SessionFailure.UNKNOWN))
        }
    }

    /**
     * Field-test line probe in place of the native session. Blocks this coroutine's IO thread until
     * the probe ends, then ends the call through [finish]; the screen returns to its pre-call state.
     */
    private fun runProbe(c: ActiveCall, audio: CallAudio, tx: ShortArray, dir: File) {
        val role = if (c.dial) "caller" else "callee"
        c.localEnd = true
        Log.i(TAG, "probe start role=" + role)
        val cause = try {
            val out = LinkProbe.rxFile(dir, role, System.currentTimeMillis())
            LinkProbe(audio, tx, out, { now() }, { Log.i(TAG, it) }).run({ c.stopped }, holdAfterDone = !c.dial)
        } catch (e: Exception) {
            LinkProbe.CAUSE_ERROR
        }
        Log.i(TAG, "probe end cause=" + cause)
        finish(c, EndCause.Local)
    }

    /** True once the call is ACTIVE; false when it ended first or did not connect in time. */
    private suspend fun awaitActive(c: ActiveCall): Boolean {
        var live = false
        val st = withTimeoutOrNull(CONNECT_TIMEOUT_MS) {
            call.status.first { s ->
                if (s.phase == CallPhase.DIALING || s.phase == CallPhase.RINGING || s.phase == CallPhase.ACTIVE) live = true
                s.phase == CallPhase.ACTIVE || (live && (s.phase == CallPhase.ENDED || s.phase == CallPhase.IDLE))
            }
        }
        return st?.phase == CallPhase.ACTIVE && !c.finishing.get()
    }

    private fun startPumps(c: ActiveCall, audio: CallAudio) {
        // To be confirmed on device: CallAudio.write blocks at the uplink rate, so each native slot is produced just
        // in time, and CallAudio.read keeps delivering downlink while the voice window is open.
        val rec = FieldTest.sessionRecorders(c.dial)
        if (rec != null) Log.w(TAG, "field test: recording session audio")
        thread(name = "aegis-tx", isDaemon = true) {
            val end = try {
                PumpLoops.runTx(
                    stopped = { c.stopped },
                    next = {
                        synchronized(c.nativeLock) {
                            val h = c.handle
                            if (h == 0L) null else NativeBridge.nativeSessionTxPcm(h, now())
                        }
                    },
                    write = { pcm ->
                        if (rec != null && pcm.isNotEmpty()) runCatching { rec.first.appendDurable(pcm, 0, pcm.size) }
                        audio.write(pcm, 0, pcm.size)
                    },
                    idle = { Thread.sleep(VOICE_IDLE_MS) },
                )
            } catch (e: Exception) {
                PumpEnd.AUDIO_FAILED
            }
            rec?.let { runCatching { it.first.close() } }
            Log.i(TAG, "tx end=" + end.ordinal)
            c.txEnd = end
            c.txDone.complete(Unit)
        }
        thread(name = "aegis-rx", isDaemon = true) {
            val buf = ShortArray(RX_CHUNK)
            val end = try {
                PumpLoops.runRx(
                    stopped = { c.stopped },
                    buf = buf,
                    read = { b ->
                        audio.read(b, 0, b.size).also { n -> if (rec != null && n > 0) runCatching { rec.second.appendDurable(b, 0, n) } }
                    },
                    feed = { b -> nativeOn(c) { h -> NativeBridge.nativeSessionRxPcm(h, b, now()) } },
                )
            } catch (e: Exception) {
                PumpEnd.AUDIO_FAILED
            }
            buf.fill(0)
            rec?.let { runCatching { it.second.close() } }
            Log.i(TAG, "rx end=" + end.ordinal)
            c.rxEnd = end
        }
    }

    // ---------------------------------------------------------------- events

    private suspend fun eventLoop(c: ActiveCall) {
        while (!c.finishing.get()) {
            if (!pollOnce(c)) {
                finish(c, EndCause.Failed(SessionFailure.UNKNOWN))
                return
            }
            tickVoiceWindow(c)
            val cause = SessionReducer.endCause(c.txEnd, c.rxEnd, c.cause, c.causeAtMs, now(), TERMINAL_GRACE_MS)
            if (cause != null) {
                finish(c, cause)
                return
            }
            delay(POLL_MS)
        }
    }

    /** False when the event buffer could not be read or decoded. */
    private fun pollOnce(c: ActiveCall): Boolean {
        val raw = synchronized(c.nativeLock) {
            val h = c.handle
            if (h == 0L) return true
            NativeBridge.nativeSessionPollEvents(h)
        } ?: return false
        val events = try {
            EventTlv.parse(raw)
        } finally {
            raw.fill(0)
        }
        if (events == null) {
            Log.e(TAG, "event buffer malformed")
            return false
        }
        for (ev in events) onEvent(c, ev)
        return true
    }

    private fun onEvent(c: ActiveCall, ev: NativeEvent) {
        Log.i(TAG, "event t=" + typeOf(ev))
        when (ev) {
            is NativeEvent.NeedSignature -> sign(c, ev)
            is NativeEvent.Sas -> {
                c.sasWords = ev.wordIndices
                update(c) { SessionReducer.sasWords(it, ev.wordIndices) }
            }
            is NativeEvent.PathChosen -> {
                c.resumePath = ev.path.resume
                Log.i(TAG, "path resume=" + (if (ev.path.resume) 1 else 0))
            }
            is NativeEvent.HandshakeProgress -> update(c) { SessionReducer.progress(it, ev.percent, c.resumePath) }
            is NativeEvent.Established -> {
                Log.i(TAG, "established identity=" + ev.identity.ordinal + " resume=" + (if (ev.path.resume) 1 else 0))
                val contact = ev.storedContactId.takeIf { it != 0L }?.let { id -> contacts.value.firstOrNull { it.id == id } }
                update(c) { SessionReducer.established(it, ev, contact) }
                val mutualId = MutualPairing.contactFor(ev.pskContactId, ev.path.resume, ev.storedContactId)
                if (mutualId != 0L) {
                    scope.launch(worker) {
                        if (!MutualPairing.record(mutualId, host)) Log.w(TAG, "mutual pairing not recorded")
                    }
                }
            }
            is NativeEvent.KeyChanged -> {
                c.keyChangedFrom = ev.storedPub33
                ev.peerPub33.fill(0)
                update(c) { SessionReducer.keyChanged(it) }
            }
            NativeEvent.SasConfirmed -> {
                val changedFrom = c.keyChangedFrom
                // Replacing a contact's key changes the vault's identities: a fingerprint unlock may
                // not do it, so the save screen asks for the PIN instead.
                val replace = changedFrom != null && !host.callScoped
                update(c) { SessionReducer.sasConfirmed(it, offerSave = !replace) }
                if (c.voiceOpenedAtMs != 0L) nativeOn(c) { NativeBridge.nativeSessionVoiceWindow(it, false) }
                if (replace && changedFrom != null) replaceChangedKey(c, changedFrom)
            }
            is NativeEvent.VoiceWindow -> {
                c.audio?.setVoiceWindow(ev.open)
                c.voiceOpenedAtMs = if (ev.open) now() else 0L
                update(c) { SessionReducer.voiceWindow(it, ev.open, SessionReducer.VOICE_WINDOW_SECONDS) }
            }
            is NativeEvent.PqProgress -> update(c) { SessionReducer.pqProgress(it, ev.percent) }
            is NativeEvent.PqMixed -> update(c) { SessionReducer.pqMixed(it) }
            is NativeEvent.Epoch -> Log.i(TAG, "epoch=" + ev.epoch)
            is NativeEvent.VaultDirty -> scope.launch(worker) { host.vaultDirty(ev.seq) }
            is NativeEvent.Attestation -> {
                Log.i(TAG, "attestation result=" + ev.result + " boot=" + ev.boot)
                update(c) { SessionReducer.attestation(it, ev) }
            }
            is NativeEvent.MessageReceived -> {
                val text = ev.text.toString(Charsets.UTF_8)
                ev.text.fill(0)
                val id = nextMessageId.getAndIncrement()
                update(c) { SessionReducer.messageAdded(it, ChatMessage(id, false, QuickText.decode(text), MessageStatus.RECEIVED)) }
            }
            is NativeEvent.MessageDelivered -> c.outgoing.remove(ev.msgId)?.let { id ->
                update(c) { SessionReducer.messageStatus(it, id, MessageStatus.DELIVERED) }
            }
            is NativeEvent.MessageFailed -> c.outgoing.remove(ev.msgId)?.let { id ->
                update(c) { SessionReducer.messageStatus(it, id, MessageStatus.FAILED) }
            }
            is NativeEvent.MessageProgress -> c.outgoing[ev.msgId]?.let { id ->
                update(c) { SessionReducer.messageProgress(it, id, ev.acked, ev.total) }
            }
            NativeEvent.RemoteWipe, NativeEvent.WipeSent -> {
                // Session material is already gone in Rust; clear the screen copy now.
                update(c) { it.copy(phase = SessionPhase.CLEARING, sas = null, messages = emptyList()) }
                terminal(c, EndCause.Ended)
            }
            is NativeEvent.Ended -> {
                Log.i(TAG, "ended byPeer=" + if (ev.byPeer) 1 else 0)
                terminal(c, EndCause.Ended)
            }
            is NativeEvent.Aborted -> {
                Log.i(TAG, "abort reason=" + ev.reason)
                terminal(c, EndCause.Aborted(ev.reason))
            }
            is NativeEvent.VaultFailed -> Log.w(TAG, "vault failed code=" + ev.code)
        }
    }

    private fun sign(c: ActiveCall, ev: NativeEvent.NeedSignature) {
        // To be confirmed on device: the identity key requires an unlocked device; a signature asked for while the
        // screen is locked fails and the handshake aborts with SignerFailed (6).
        val der = try {
            keys.signSha256Ecdsa(ev.message)
        } catch (e: Exception) {
            Log.e(TAG, "sign failed: " + e.javaClass.simpleName)
            null
        } finally {
            ev.message.fill(0)
        }
        val rc = nativeOn(c) { NativeBridge.nativeSessionSignResult(it, ev.reqId, der != null, der) }
        der?.fill(0)
        Log.i(TAG, "sign ok=" + (if (der != null) 1 else 0) + " rc=" + rc)
    }

    /** "Compare again and update": after both sides matched, the changed key replaces the stored contact's. */
    private fun replaceChangedKey(c: ActiveCall, storedPub33: ByteArray) {
        scope.launch(worker) {
            val id = host.contactIdForKey(storedPub33)
            val contact = id?.let { i -> contacts.value.firstOrNull { it.id == i } }
            val rc = if (contact == null || contact.id > Int.MAX_VALUE) {
                NativeCode.BAD_ARG
            } else {
                val label = contact.name.toByteArray(Charsets.UTF_8)
                nativeOn(c) { NativeBridge.nativeSessionSaveContact(it, contact.id.toInt(), label, null) }
            }
            Log.i(TAG, "key replace rc=" + (if (rc > 0) 0 else rc))
            if (rc > 0 && contact != null) {
                host.contactsChanged()
                update(c) { SessionReducer.contactSaved(it, contact.id, contact.name, it.peer?.number) }
            } else {
                update(c) { SessionReducer.sasConfirmed(it, offerSave = true) }
            }
        }
    }

    private fun tickVoiceWindow(c: ActiveCall) {
        val opened = c.voiceOpenedAtMs
        if (opened == 0L) return
        val left = SessionReducer.voiceSecondsLeft(opened, now())
        update(c) { s ->
            val sas = s.sas
            if (sas == null || !sas.voiceWindowOpen || sas.voiceSecondsLeft == left) s else SessionReducer.voiceWindow(s, true, left)
        }
    }

    // ---------------------------------------------------------------- ending

    /** Idempotent. Hangs up, closes the audio and the native session, then shows the end state. */
    private fun finish(c: ActiveCall, fallback: EndCause) {
        if (!c.finishing.compareAndSet(false, true)) return
        c.stopped = true
        if (!c.silent) {
            // Last events (ENDED / ABORTED) decide what the screen says.
            runCatching { pollOnce(c) }
        }
        val cause = c.cause ?: fallback
        Log.i(TAG, "end cause=" + cause.logCode + " local=" + if (c.localEnd) 1 else 0)
        synchronized(c.nativeLock) {
            val h = c.handle
            c.handle = 0L
            if (h != 0L) NativeBridge.nativeSessionClose(h, false)
        }
        if (c.ownsCall) runCatching { call.hangUp() }
        c.audio?.let { a -> runCatching { a.close() } }
        c.sasWords = null
        c.keyChangedFrom?.fill(0)
        c.outgoing.clear()
        synchronized(stateLock) {
            c.ended.set(true)
            put(if (c.silent) SessionState() else SessionReducer.finalState(sessionState.value, cause, c.localEnd))
        }
        synchronized(engineLock) {
            if (active === c) {
                active = null
                callHeldFlow.value = false
            }
        }
        context?.let { SecureCallService.stop(it) }
        c.job?.cancel()
        lockIfScoped()
    }

    /**
     * A fingerprint unlock covers one call: once that call is over or never came, lock again. The
     * end screen goes too, so the unlock screen that follows can show the next incoming call.
     */
    private fun lockIfScoped() {
        if (host.callScoped) {
            Log.i(TAG, "call-scoped unlock over: locking")
            if (active == null) setState(SessionState())
            host.lockAfterScopedCall()
        }
    }

    /** Any thread, any state: ends the session (peer notified when possible) and hangs up. */
    suspend fun endAndWipe() {
        val c = active
        if (c == null) {
            runCatching { call.hangUp() }
            synchronized(stateLock) {
                if (sessionState.value.phase != SessionPhase.IDLE) put(SessionState(phase = SessionPhase.CLEARED))
            }
            return
        }
        c.localEnd = true
        update(c) { it.copy(phase = SessionPhase.CLEARING, sas = null) }
        val rc = nativeOn(c) { NativeBridge.nativeSessionClose(it, true) }
        if (rc == NativeCode.OK) withTimeoutOrNull(END_GRACE_MS) { c.txDone.await() }
        withContext(Dispatchers.IO) { finish(c, EndCause.Local) }
        runCatching { call.hangUp() }
    }

    /** Worker thread. Drops the session without a visible end state (lock, duress, wipe). */
    fun wipeAll() {
        active?.let { c ->
            c.silent = true
            c.localEnd = true
            finish(c, EndCause.Local)
        }
        callHeldFlow.value = false
        context?.let { SecureCallService.stop(it) }
        setState(SessionState())
    }

    /** Releases any held incoming offer and ends/wipes the active session prior to process exit. */
    suspend fun prepareExit() {
        val token = synchronized(offerLock) {
            val t = pendingHandoffToken
            pendingHandoffToken = null
            t
        }
        if (token != null) runCatching { call.release(token) }
        incomingFlow.value = null
        if (active != null) {
            endAndWipe()
        } else {
            wipeAll()
        }
        context?.let { SecureCallService.stop(it) }
    }

    // ---------------------------------------------------------------- user actions

    fun sendText(text: String): SendResult = send(MessageBody.Text(text.trim()), text.isBlank())

    fun sendQuick(command: QuickCommand): SendResult = send(MessageBody.Quick(command), false)

    private fun send(body: MessageBody, empty: Boolean): SendResult {
        SessionReducer.sendCheck(sessionState.value, body, empty)?.let { return it }
        val c = active ?: return SendResult.BLOCKED_NOT_ESTABLISHED
        val wire = when (body) {
            is MessageBody.Text -> body.text
            is MessageBody.Quick -> QuickText.encode(body.command)
        }.toByteArray(Charsets.UTF_8)
        val rc = try {
            nativeOn(c) { NativeBridge.nativeSessionSendText(it, wire, 0, now()) }
        } finally {
            wire.fill(0)
        }
        Log.i(TAG, "send rc=" + if (rc >= 0) 0 else rc)
        if (rc < 0) return SessionReducer.sendFailure(rc)
        val id = nextMessageId.getAndIncrement()
        c.outgoing[rc] = id
        update(c) { SessionReducer.messageAdded(it, ChatMessage(id, true, body, MessageStatus.SENDING)) }
        return SendResult.QUEUED
    }

    /** Shows the words and asks the peer to open the voice window. */
    fun beginSas() {
        val c = active ?: return
        val words = c.sasWords
        if (words == null) {
            Log.w(TAG, "sas words not available")
            return
        }
        update(c) { SessionReducer.sasShown(it, words) }
        openVoiceWindow()
    }

    fun openVoiceWindow() {
        val c = active ?: return
        val rc = nativeOn(c) { NativeBridge.nativeSessionVoiceWindow(it, true) }
        Log.i(TAG, "voice request rc=$rc")
    }

    fun decideSas(match: Boolean) {
        val c = active ?: return
        val rc = nativeOn(c) { NativeBridge.nativeSessionSas(it, match) }
        Log.i(TAG, "sas decision=" + (if (match) 1 else 0) + " rc=" + rc)
        if (match) {
            if (rc == NativeCode.OK) update(c) { SessionReducer.localMatch(it) }
            return
        }
        // The native session aborts with SasMismatch and sends its abort frames; then hang up and clear.
        c.localEnd = true
        update(c) { it.copy(phase = SessionPhase.CLEARING, sas = null, messages = emptyList()) }
        scope.launch {
            withTimeoutOrNull(END_GRACE_MS) { c.txDone.await() }
            finish(c, EndCause.Local)
        }
    }

    /** Worker thread. Saves the peer as a new contact after both sides matched the words. */
    fun saveContact(name: String, number: String?): ContactResult {
        // A fingerprint answered this call: saving changes the vault's identities and needs the PIN.
        if (host.callScoped) return ContactResult.FAILED
        val trimmed = name.trim()
        val label = trimmed.toByteArray(Charsets.UTF_8)
        if (label.isEmpty() || label.size > MAX_LABEL_BYTES) return ContactResult.INVALID_NAME
        var phone: ByteArray? = null
        val displayNumber = number?.trim()?.takeIf { it.isNotEmpty() }
        if (displayNumber != null) {
            val e164Str = PhoneRules.toVaultE164(displayNumber) ?: return ContactResult.INVALID_NUMBER
            phone = e164Str.toByteArray(Charsets.US_ASCII)
            if (phone.size > MAX_PHONE_BYTES) return ContactResult.INVALID_NUMBER
        }
        val c = active ?: return ContactResult.FAILED
        val rc = nativeOn(c) { NativeBridge.nativeSessionSaveContact(it, 0, label, phone) }
        Log.i(TAG, "save contact rc=" + if (rc > 0) 0 else rc)
        if (rc <= 0) return ContactResult.FAILED
        host.saveContactNumber(rc.toLong(), displayNumber)
        host.contactsChanged()
        update(c) { SessionReducer.contactSaved(it, rc.toLong(), trimmed, displayNumber) }
        return ContactResult.OK
    }

    fun dismissSaveOffer() {
        synchronized(stateLock) { put(sessionState.value.copy(saveOffer = null)) }
    }

    fun dismissAbort() {
        if (active == null) setState(SessionState())
    }

    private companion object {
        const val TAG = "AegisSession"
    /** To be confirmed on device: the VoLTE call uses AMR-WB or EVS; on AMR-NB the narrowband gear would be needed. */
        const val WIDEBAND = true
        const val POLL_MS = 40L
        const val VOICE_IDLE_MS = 20L
        /** 100 ms of 16 kHz audio per receive call (limit 32000). */
        const val RX_CHUNK = 1600
        const val CONNECT_TIMEOUT_MS = 60_000L
        /** Time for the last native frames (3 END or ABORT superframes) to go out. */
        const val END_GRACE_MS = 1_500L
        const val TERMINAL_GRACE_MS = 3_000L
        const val MAX_LABEL_BYTES = 64
        const val MAX_PHONE_BYTES = 16

        fun nativeContact(id: Long?): Int = if (id != null && id in 1..Int.MAX_VALUE.toLong()) id.toInt() else 0

        fun e164(number: String?): ByteArray? =
            number?.let { PhoneRules.toVaultE164(it) }?.toByteArray(Charsets.US_ASCII)?.takeIf { it.isNotEmpty() && it.size <= MAX_PHONE_BYTES }

        fun typeOf(ev: NativeEvent): Int = when (ev) {
            is NativeEvent.NeedSignature -> EventTlv.NEED_SIGNATURE
            is NativeEvent.Sas -> EventTlv.SAS
            is NativeEvent.PathChosen -> EventTlv.PATH
            is NativeEvent.HandshakeProgress -> EventTlv.HS_PROGRESS
            is NativeEvent.Established -> EventTlv.ESTABLISHED
            is NativeEvent.KeyChanged -> EventTlv.KEY_CHANGED
            NativeEvent.SasConfirmed -> EventTlv.SAS_CONFIRMED
            is NativeEvent.VoiceWindow -> EventTlv.VOICE_WINDOW
            is NativeEvent.PqProgress -> EventTlv.PQ_PROGRESS
            is NativeEvent.PqMixed -> EventTlv.PQ_MIXED
            is NativeEvent.Epoch -> EventTlv.EPOCH
            is NativeEvent.VaultDirty -> EventTlv.VAULT_DIRTY
            is NativeEvent.Attestation -> EventTlv.ATTESTATION
            is NativeEvent.MessageReceived -> EventTlv.MESSAGE_RECEIVED
            is NativeEvent.MessageDelivered -> EventTlv.MESSAGE_DELIVERED
            is NativeEvent.MessageFailed -> EventTlv.MESSAGE_FAILED
            is NativeEvent.MessageProgress -> EventTlv.MESSAGE_PROGRESS
            NativeEvent.RemoteWipe -> EventTlv.REMOTE_WIPE
            NativeEvent.WipeSent -> EventTlv.WIPE_SENT
            is NativeEvent.Ended -> EventTlv.ENDED
            is NativeEvent.Aborted -> EventTlv.ABORTED
            is NativeEvent.VaultFailed -> EventTlv.VAULT_FAILED
        }
    }
}
