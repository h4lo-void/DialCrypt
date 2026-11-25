package io.github.h4lovoid.dialcrypt.core.real

import android.content.Context
import android.app.KeyguardManager
import android.os.SystemClock
import android.provider.Settings
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.util.Log
import io.github.h4lovoid.dialcrypt.call.CallLink
import io.github.h4lovoid.dialcrypt.core.BiometricState
import io.github.h4lovoid.dialcrypt.core.Contact
import io.github.h4lovoid.dialcrypt.core.ContactResult
import io.github.h4lovoid.dialcrypt.core.CoreAvailability
import io.github.h4lovoid.dialcrypt.core.CoreState
import io.github.h4lovoid.dialcrypt.core.IncomingUi
import io.github.h4lovoid.dialcrypt.core.InviteCard
import io.github.h4lovoid.dialcrypt.core.MAX_PIN_ATTEMPTS
import io.github.h4lovoid.dialcrypt.core.NativeBridge
import io.github.h4lovoid.dialcrypt.core.PairingPreview
import io.github.h4lovoid.dialcrypt.core.PairingResult
import io.github.h4lovoid.dialcrypt.core.PhoneRules
import io.github.h4lovoid.dialcrypt.core.PinResult
import io.github.h4lovoid.dialcrypt.core.QuickCommand
import io.github.h4lovoid.dialcrypt.core.SecureCore
import io.github.h4lovoid.dialcrypt.core.SecureForeground
import io.github.h4lovoid.dialcrypt.core.SendResult
import io.github.h4lovoid.dialcrypt.core.SessionPhase
import io.github.h4lovoid.dialcrypt.core.SessionState
import io.github.h4lovoid.dialcrypt.core.UnlockResult
import io.github.h4lovoid.dialcrypt.incoming.screen.ContactNumberIndex
import io.github.h4lovoid.dialcrypt.incoming.screen.ScreeningStore
import io.github.h4lovoid.dialcrypt.security.BioCipher
import io.github.h4lovoid.dialcrypt.security.HardwareKeyBridge
import java.io.File
import java.io.IOException
import java.util.concurrent.Executors
import javax.crypto.Cipher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * The real secure core on top of libaegiscall_jni (secure-session-v2 §2.D, §6.5, §6.6). Used only
 * in the secure process. Every native call and every vault or key-store change runs on one worker
 * thread, so PIN attempts, rotations and contact edits never interleave.
 *
 * Start-up loads the trust files from res/raw, hardens the process, loads the StrongBox identity
 * key and opens the native app object. If any step fails the core stays NOT_CONNECTED.
 */
class NativeSecureCore(
    context: Context,
    call: CallLink,
    private val keys: HardwareKeyBridge,
) : SecureCore {
    private val appContext: Context = context.applicationContext ?: context
    private val worker = Executors.newSingleThreadExecutor { r -> Thread(r, "aegis-core").apply { isDaemon = true } }
        .asCoroutineDispatcher()
    private val scope = CoroutineScope(SupervisorJob() + worker)
    private val vault = VaultFile(File(appContext.noBackupFilesDir, VAULT_FILE))
    // Sealed with the meta key inside the unlocked native vault: unreadable without the app PIN.
    private val metaStore = ContactMetaStore(
        file = File(appContext.noBackupFilesDir, META_FILE),
        seal = { plaintext -> NativeBridge.nativeMetaSeal(app, plaintext) },
        open = { sealed -> NativeBridge.nativeMetaOpen(app, sealed) },
        isUnlocked = { unlocked() },
    )
    private val screeningStore = ScreeningStore(appContext)
    // Truncated tags of the contact numbers, read by the display rule while the vault is locked.
    private val numberIndex = ContactNumberIndex(appContext)
    // Fingerprint answer: the wrapped PIN stretch and the stamp of the last PIN unlock.
    private val bioFiles = BiometricFiles(appContext.noBackupFilesDir)
    private val bioEffects = UnlockBioEffects(bioFiles, ::bootCount) { SystemClock.elapsedRealtime() }

    private val coreState = MutableStateFlow(CoreState())
    private val contactList = MutableStateFlow<List<Contact>>(emptyList())
    private val bioState = MutableStateFlow(BiometricState.OFF)
    private val sessions = SessionEngine(call, keys, Host(), worker, contactList, appContext)

    override val state: StateFlow<CoreState> = coreState
    override val contacts: StateFlow<List<Contact>> = contactList
    override val session: StateFlow<SessionState> = sessions.state
    override val incoming: StateFlow<IncomingUi?> = sessions.incoming
    override val callHeld: StateFlow<Boolean> = sessions.callHeld
    override val biometric: StateFlow<BiometricState> = bioState

    // Written on the worker thread only.
    @Volatile private var app = 0L
    /** Raw records behind [contacts], for key lookups by the session engine. */
    @Volatile private var vaultContacts: List<VaultContact> = emptyList()
    private var trustTlv: ByteArray? = null
    private var spkiDer: ByteArray? = null
    private var chainTlv: ByteArray? = null
    /** The current app object holds the pairing key of the seed saved in contact_meta. */
    private var ownCodeIssued = false
    /** Tickets of an older file, used once and deleted after the next durable write. */
    private val pendingRetire = LinkedHashSet<Int>()
    /** Worker thread. P_normal of the PIN unlock that is turning fingerprint answer on; dropped after HELD_FOR_MS or on lock. */
    private var heldStretch: ByteArray? = null
    private var heldGeneration = 0

    init {
        scope.launch { start() }
    }

    private val ready: Boolean get() = app != 0L && coreState.value.availability == CoreAvailability.READY

    private suspend fun <T> onWorker(fallback: T, block: () -> T): T = withContext(worker) {
        try {
            block()
        } catch (e: Exception) {
            Log.e(TAG, "core operation failed: " + e.javaClass.simpleName)
            fallback
        }
    }

    // ---------------------------------------------------------------- start-up

    private fun start() {
        try {
            startNow()
        } catch (e: Exception) {
            Log.e(TAG, "start failed: " + e.javaClass.simpleName)
        } catch (e: LinkageError) {
            Log.e(TAG, "native library unavailable")
        }
    }

    private fun startNow() {
        trustTlv = TrustResourceLoader.load(appContext) ?: return
        // The daemon raises RLIMIT_MEMLOCK of this process while it answers ATTACH (SessionLease in
        // SecureActivity), which may happen after this point; until then mlockall fails with INTERNAL.
        // The wait blocks the worker thread on purpose: every native call runs on it, so none can
        // run between two attempts.
        // To be confirmed on device: on the Pixel 7 ATTACHED arrives within HardenRetry.LIMIT_MS of this call.
        val hardened = HardenRetry.run({ NativeBridge.nativeHarden() }, { SystemClock.elapsedRealtime() }, { Thread.sleep(it) })
        if (hardened != NativeCode.OK) {
            Log.e(TAG, "process hardening failed: $hardened")
            return
        }
        val identity = keys.ensureIdentity()
        chainTlv = ChainTlv.encode(identity.chainDer) ?: run {
            Log.e(TAG, "identity chain unusable")
            return
        }
        spkiDer = identity.spkiDer
        if (!openApp()) return
        val blob = vault.read()
        // Before any unlock attempt: only the tickets of the file on disk stay.
        val live = if (blob == null) keys.listTickets() else retireOrphans(blob)
        coreState.value = when {
            blob == null -> {
                // Tickets without a vault belong to an interrupted setup.
                live.forEach(keys::retireTicket)
                // So does any contact metadata: no vault will ever open it.
                metaStore.wipe()
                numberIndex.wipe()
                dropBiometric()
                CoreState(CoreAvailability.READY, pinConfigured = false, locked = true)
            }
            live.isEmpty() -> {
                // A dead vault: fingerprint answer can never open it again.
                dropBiometric()
                CoreState(CoreAvailability.READY, pinConfigured = true, locked = true, attemptsLeft = 0, vaultDestroyed = true)
            }
            else -> CoreState(CoreAvailability.READY, pinConfigured = true, locked = true, attemptsLeft = attempts(live))
        }
        refreshBio()
    }

    private fun openApp(): Boolean {
        val trust = trustTlv ?: return false
        val spki = spkiDer ?: return false
        val chain = chainTlv ?: return false
        val h = NativeBridge.nativeAppOpen(trust)
        if (h == 0L) {
            Log.e(TAG, "nativeAppOpen failed")
            return false
        }
        val rc = NativeBridge.nativeSetIdentity(h, spki, chain)
        if (rc != NativeCode.OK) {
            Log.e(TAG, "nativeSetIdentity failed: $rc")
            NativeBridge.nativeAppClose(h)
            return false
        }
        val strict = io.github.h4lovoid.dialcrypt.core.SharedPrefsUiPreferences.readRequireLockedBootloader(appContext)
        NativeBridge.nativeSetStrictAttestation(h, strict)
        app = h
        ownCodeIssued = false
        return true
    }

    /** Closes the app object (wiping the vault, sessions and pairing PSK in Rust) and opens a fresh, locked one. */
    private fun resetApp(): Boolean {
        sessions.wipeAll()
        metaStore.clearMemory()
        if (app != 0L) {
            NativeBridge.nativeAppClose(app)
            app = 0L
        }
        ownCodeIssued = false
        val ok = openApp()
        if (!ok) coreState.update { it.copy(availability = CoreAvailability.NOT_CONNECTED) }
        return ok
    }

    private fun attempts(live: IntArray) = live.size.coerceAtMost(MAX_PIN_ATTEMPTS)

    /**
     * Start-up, worker thread, before any unlock: retires the key-store tickets the vault file on
     * disk ([blob]) does not reference. A file that does not parse retires nothing. Returns the
     * tickets left.
     */
    private fun retireOrphans(blob: ByteArray): IntArray {
        val live = keys.listTickets()
        val orphans = OrphanTickets.toRetire(OrphanTickets.parseIds(NativeBridge.nativeVaultTicketIds(blob)), live)
        if (orphans.isEmpty()) return live
        Log.w(TAG, "retiring " + orphans.size + " tickets the vault file does not reference")
        orphans.forEach(keys::retireTicket)
        return keys.listTickets()
    }

    // ---------------------------------------------------------------- vault persistence

    /**
     * Imports the new tickets of [rot], commits, writes the file and retires the old tickets.
     * Wipes [rot]. Anything but WRITTEN leaves the previous file and its tickets valid. When the
     * file cannot be written, [keepUnwritten] keeps the new tickets of the committed native vault
     * for a later write; false retires them, for a caller that drops the native vault.
     */
    private fun commitRotation(rot: ByteArray, keepUnwritten: Boolean = true): RotationOutcome {
        val layout = try {
            RotationLayout.parse(rot)
        } finally {
            rot.fill(0)
        }
        if (layout == null) {
            Log.e(TAG, "rotation layout malformed")
            NativeBridge.nativeVaultRotateCommit(app, false)
            return RotationOutcome.NOT_COMMITTED
        }
        val imported = try {
            layout.fresh.all { keys.importTicket(it.id, it.material) }
        } finally {
            layout.wipeMaterial()
        }
        val blob = if (imported) NativeBridge.nativeVaultRotateCommit(app, true) else null
        if (blob == null) {
            if (imported) Log.e(TAG, "rotation commit failed") else NativeBridge.nativeVaultRotateCommit(app, false)
            layout.fresh.forEach { keys.retireTicket(it.id) }
            return RotationOutcome.NOT_COMMITTED
        }
        // Committed: the new tickets now belong to the vault in memory, the old ones to the file on disk.
        layout.retire.forEach { pendingRetire += it }
        if (writeAndRetire(blob)) return RotationOutcome.WRITTEN
        if (!keepUnwritten) {
            // The file on disk still needs its tickets; the new ones open no file.
            layout.retire.forEach { pendingRetire -= it }
            layout.fresh.forEach { keys.retireTicket(it.id) }
        }
        return RotationOutcome.UNWRITTEN
    }

    private fun writeAndRetire(blob: ByteArray): Boolean {
        val written = try {
            vault.write(blob)
        } finally {
            blob.fill(0)
        }
        if (!written) {
            Log.e(TAG, "vault write failed")
            return false
        }
        pendingRetire.forEach(keys::retireTicket)
        pendingRetire.clear()
        return true
    }

    private fun commitWrappedRotation(rot: ByteArray, keepUnwritten: Boolean = true): RotationOutcome {
        val layout = try {
            WrappedRotationLayout.parse(rot)
        } finally {
            rot.fill(0)
        }
        if (layout == null) {
            Log.e(TAG, "wrapped rotation layout malformed")
            NativeBridge.nativeVaultRotateCommit(app, false)
            return RotationOutcome.NOT_COMMITTED
        }
        val imported = try {
            layout.fresh.all { keys.importWrappedTicket(it.id, it.wrappedDer) }
        } finally {
            layout.wipe()
        }
        if (!imported) {
            NativeBridge.nativeVaultRotateCommit(app, false)
            layout.fresh.forEach { keys.retireTicket(it.id) }
            return RotationOutcome.NOT_COMMITTED
        }
        val blob = NativeBridge.nativeVaultRotateCommit(app, true)
        if (blob == null) {
            Log.e(TAG, "wrapped rotation commit failed")
            layout.fresh.forEach { keys.retireTicket(it.id) }
            return RotationOutcome.NOT_COMMITTED
        }
        layout.retire.forEach { pendingRetire += it }
        if (writeAndRetire(blob)) return RotationOutcome.WRITTEN
        if (!keepUnwritten) {
            layout.retire.forEach { pendingRetire -= it }
            layout.fresh.forEach { keys.retireTicket(it.id) }
        }
        return RotationOutcome.UNWRITTEN
    }

    /** VAULT_DIRTY and contact edits: export, or rotate when the native vault requires it. */
    private fun persist(): Boolean {
        val blob = NativeBridge.nativeVaultExport(app)
        if (blob != null) return writeAndRetire(blob)
        val wrapSpki = keys.ensureTicketWrappingKey()
        if (wrapSpki != null) {
            val wrappedRot = NativeBridge.nativeVaultRotateBeginWrapped(app, wrapSpki)
            if (wrappedRot != null) {
                val out = commitWrappedRotation(wrappedRot)
                if (out == RotationOutcome.WRITTEN) return true
                if (out == RotationOutcome.UNWRITTEN) return false
            }
        }
        val rot = NativeBridge.nativeVaultRotateBegin(app) ?: return false
        return commitRotation(rot) == RotationOutcome.WRITTEN
    }

    private fun refreshContacts() {
        val raw = NativeBridge.nativeContactList(app)
        var listed = raw != null
        val parsed: List<VaultContact> = if (raw == null) {
            emptyList()
        } else {
            try {
                ContactListCodec.parse(raw) ?: run {
                    Log.e(TAG, "contact list malformed")
                    listed = false
                    emptyList()
                }
            } finally {
                raw.fill(0)
            }
        }
        vaultContacts.forEach { it.wipeSensitive() }
        vaultContacts = parsed
        metaStore.retainContacts(parsed.map { it.id }.toSet())
        contactList.value = parsed.map { vc -> vc.toContact(metaStore.numberFor(vc.id), metaStore.isMutual(vc.id)) }
        screeningStore.reconcile(
            parsed.mapNotNull { vc ->
                vc.phoneTag?.let { pt -> pt to metaStore.numberFor(vc.id) }
            },
        )
        // A failed or locked contact read must not replace the index with an empty one.
        if (listed && unlocked()) {
            if (!numberIndex.rebuild(parsed.mapNotNull { metaStore.numberFor(it.id) })) Log.w(TAG, "number index not written")
        }
    }

    private fun clearContacts() {
        vaultContacts.forEach { it.wipeSensitive() }
        vaultContacts = emptyList()
        contactList.value = emptyList()
    }

    private fun applyPersistentPairingSeed(): Boolean {
        if (app == 0L) return false
        val seed = metaStore.loadOrInitSeed() ?: return false
        return try {
            val rc = NativeBridge.nativeSetPairingSeed(app, seed)
            if (rc == NativeCode.OK) {
                ownCodeIssued = true
                true
            } else {
                false
            }
        } finally {
            seed.fill(0)
        }
    }

    /** Duress PIN: Rust already wiped the vault; destroy every key and cover the file with same-length noise. */
    private fun duress() {
        sessions.wipeAll()
        metaStore.wipe()
        screeningStore.wipe()
        numberIndex.wipe()
        dropBiometric()
        keys.destroyAllKeys()
        pendingRetire.clear()
        val cover = NativeBridge.nativeVaultExport(app)
        val covered = cover != null && vault.overwrite(cover)
        cover?.fill(0)
        if (!covered) vault.overwriteRandom()
        io.github.h4lovoid.dialcrypt.core.daemon.DaemonTrim.requestBestEffort()
        clearContacts()
        coreState.update { it.copy(locked = true) }
    }

    /** No ticket left: the vault can never open again (design 6.5). */
    private fun markDead() {
        sessions.wipeAll()
        metaStore.wipe()
        screeningStore.wipe()
        numberIndex.wipe()
        dropBiometric()
        keys.destroyAllKeys()
        pendingRetire.clear()
        vault.overwriteRandom()
        io.github.h4lovoid.dialcrypt.core.daemon.DaemonTrim.requestBestEffort()
        clearContacts()
        coreState.update { it.copy(locked = true, attemptsLeft = 0, vaultDestroyed = true) }
    }

    // ---------------------------------------------------------------- fingerprint answer

    private fun bootCount(): Int? = try {
        Settings.Global.getInt(appContext.contentResolver, Settings.Global.BOOT_COUNT)
    } catch (e: Exception) {
        null
    }

    private fun freshNow(): Boolean = BiometricStore.isFresh(bioFiles.readStamp(), bootCount(), SystemClock.elapsedRealtime())

    /** Worker thread. State from the files on disk. */
    private fun refreshBio() {
        val wrapped = bioFiles.hasWrapped()
        bioState.value = BiometricStore.state(wrapped, wrapped && freshNow(), bioState.value)
    }

    private fun clearHeld() {
        heldStretch?.let {
            it.fill(0)
            if (app != 0L) NativeBridge.nativeStretchHeld(app, false)
        }
        heldStretch = null
        heldGeneration++
    }

    /** Worker thread. Deletes both files and the key; the PIN stays the only way in. */
    private fun dropBiometric() {
        clearHeld()
        if (!bioFiles.deleteAll()) Log.w(TAG, "fingerprint answer files not deleted")
        try {
            keys.deleteBioKey()
        } catch (e: Exception) {
            Log.w(TAG, "fingerprint key not deleted: " + e.javaClass.simpleName)
        }
        bioState.value = BiometricState.OFF
    }

    /** Worker thread. Binding of the vault file on disk, or null. */
    private fun currentBinding(): ByteArray? {
        val blob = try {
            vault.read()
        } catch (e: IOException) {
            null
        } ?: return null
        return NativeBridge.nativeVaultStretchBinding(blob)?.takeIf { it.size == BiometricStore.BINDING_LEN }
    }

    /**
     * Worker thread. The wrapped stretch a fingerprint may release now: the feature is on, the last
     * PIN unlock is fresh, and the wrap belongs to this vault. Otherwise null, with the state updated.
     */
    private fun usableWrap(): BiometricStore.Wrapped? {
        val w = bioFiles.readWrapped()
        if (w == null) {
            refreshBio()
            return null
        }
        if (!freshNow()) {
            bioState.value = BiometricState.NEEDS_PIN
            return null
        }
        val binding = currentBinding() ?: return null
        if (!BiometricStore.sameVault(w, binding)) {
            // A P of another vault would only spend a ticket.
            Log.w(TAG, "fingerprint answer belongs to another vault: removed")
            dropBiometric()
            return null
        }
        return w
    }

    private fun bioInvalidated() {
        Log.w(TAG, "fingerprint key invalidated: fingerprint answer off")
        dropBiometric()
        bioState.value = BiometricState.INVALIDATED
    }

    /** Worker thread. Keeps P from the PIN unlock that is turning the feature on (see [UnlockBioEffects]). */
    private fun holdStretch(stretch: ByteArray?) {
        clearHeld()
        if (stretch != null) {
            // The native core refuses PIN changes while this stretch of the current PIN is held.
            if (NativeBridge.nativeStretchHeld(app, true) != NativeCode.OK) {
                stretch.fill(0)
                return
            }
            heldStretch = stretch
            val generation = heldGeneration
            scope.launch {
                delay(BiometricStore.HELD_FOR_MS)
                if (heldGeneration == generation) clearHeld()
            }
        }
    }

    override suspend fun beginBiometricEnable(): Boolean = onWorker(false) {
        val st = coreState.value
        if (!unlocked() || st.callScoped || busyWithCall()) return@onWorker false
        coreState.update { it.copy(bioEnrollPending = true) }
        lockNow(keepEnroll = true)
        true
    }

    override suspend fun biometricEnrollCipher(): Cipher? = onWorker(null) {
        val p = heldStretch
        if (!unlocked() || !coreState.value.bioEnrollPending || p == null) {
            cancelEnrollNow()
            return@onWorker null
        }
        val cipher = try {
            if (!keys.createBioKey()) {
                Log.w(TAG, "fingerprint key refused by StrongBox")
                bioState.value = BiometricState.UNAVAILABLE
                null
            } else {
                when (val c = keys.bioCipher(encrypt = true, iv = null)) {
                    is BioCipher.Ready -> c.cipher
                    else -> null
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "fingerprint key failed: " + e.javaClass.simpleName)
            null
        }
        if (cipher == null) {
            val unavailable = bioState.value == BiometricState.UNAVAILABLE
            cancelEnrollNow()
            if (unavailable) bioState.value = BiometricState.UNAVAILABLE
        }
        cipher
    }

    override suspend fun finishBiometricEnable(authed: Cipher): Boolean = onWorker(false) {
        val p = heldStretch
        val binding = if (p != null && unlocked() && coreState.value.bioEnrollPending) currentBinding() else null
        val written = if (p == null || binding == null) {
            false
        } else {
            try {
                authed.updateAAD(BiometricStore.aad(binding))
                val ct = authed.doFinal(p)
                val iv = authed.iv
                val stamp = bootCount()?.let { BiometricStore.Stamp(it, SystemClock.elapsedRealtime()) }
                stamp != null && iv != null &&
                    bioFiles.writeWrapped(BiometricStore.Wrapped(binding, iv, ct)) && bioFiles.writeStamp(stamp)
            } catch (e: Exception) {
                Log.w(TAG, "fingerprint wrap failed: " + e.javaClass.simpleName)
                false
            }
        }
        clearHeld()
        coreState.update { it.copy(bioEnrollPending = false) }
        if (written) {
            refreshBio()
        } else {
            dropBiometric()
        }
        written
    }

    override fun cancelBiometricEnable() {
        scope.launch { cancelEnrollNow() }
    }

    /** Worker thread. */
    private fun cancelEnrollNow() {
        clearHeld()
        coreState.update { it.copy(bioEnrollPending = false) }
        if (!bioFiles.hasWrapped()) {
            try {
                keys.deleteBioKey()
            } catch (e: Exception) {
                Log.w(TAG, "fingerprint key not deleted: " + e.javaClass.simpleName)
            }
        }
        refreshBio()
    }

    override suspend fun disableBiometric() = onWorker(Unit) {
        coreState.update { it.copy(bioEnrollPending = false) }
        dropBiometric()
    }

    override suspend fun biometricUnlockCipher(): Cipher? = onWorker(null) {
        if (!ready || !coreState.value.locked || !sessions.handoffPending) return@onWorker null
        val w = usableWrap() ?: return@onWorker null
        when (val c = keys.bioCipher(encrypt = false, iv = w.iv)) {
            is BioCipher.Ready -> c.cipher
            BioCipher.Invalidated -> {
                bioInvalidated()
                null
            }
            BioCipher.Unavailable -> null
        }
    }

    override suspend fun unlockWithBiometric(authed: Cipher): UnlockResult = onWorker(UnlockResult.UNAVAILABLE) { unlockBioNow(authed) }

    private fun unlockBioNow(authed: Cipher): UnlockResult {
        // Only for the ringing call this screen is answering, and only from a locked vault.
        if (!ready || !coreState.value.locked || !sessions.handoffPending) return UnlockResult.UNAVAILABLE
        val w = usableWrap() ?: return UnlockResult.UNAVAILABLE
        val directBuf = java.nio.ByteBuffer.allocateDirect(BiometricStore.STRETCH_LEN + 32)
        val outLen = try {
            authed.updateAAD(BiometricStore.aad(w.binding))
            authed.doFinal(java.nio.ByteBuffer.wrap(w.ct), directBuf)
        } catch (e: KeyPermanentlyInvalidatedException) {
            bioInvalidated()
            return UnlockResult.UNAVAILABLE
        } catch (e: Exception) {
            Log.w(TAG, "fingerprint unwrap failed: " + e.javaClass.simpleName)
            return UnlockResult.UNAVAILABLE
        }
        try {
            if (outLen != BiometricStore.STRETCH_LEN) return UnlockResult.UNAVAILABLE
            directBuf.flip()
            return withUnlockStart { st, blob, live ->
                finishWithTicket(
                    st,
                    blob,
                    NativeBridge.nativePinBeginStretchDirect(app, blob, directBuf, live),
                    viaPin = false,
                )
            }
        } finally {
            directBuf.clear()
            while (directBuf.hasRemaining()) directBuf.put(0)
            directBuf.clear()
        }
    }

    // ---------------------------------------------------------------- PIN

    override suspend fun setupPins(normal: CharArray, duress: CharArray): PinResult = onWorker(PinResult.FAILED) {
        setupNow(normal, duress)
    }

    private fun setupNow(normal: CharArray, duress: CharArray): PinResult {
        if (!ready) return PinResult.NOT_CONNECTED
        val st = coreState.value
        if (st.pinConfigured || st.vaultDestroyed) return PinResult.FAILED
        PinInput.check(normal, duress)?.let { return it }
        if (!keys.selfTestSingleUseTickets()) return PinResult.DEVICE_UNSUPPORTED
        keys.listTickets().forEach(keys::retireTicket)
        val p = PinInput.utf8(normal)
        val d = PinInput.utf8(duress)
        val wrapSpki = keys.ensureTicketWrappingKey()
        var usedWrapped = false
        val rot = try {
            if (p == null || d == null || p.size > PinInput.NATIVE_MAX_BYTES || d.size > PinInput.NATIVE_MAX_BYTES) {
                return PinResult.FAILED
            }
            val wrapped = wrapSpki?.let { NativeBridge.nativePinSetupWrapped(app, p, d, it) }
            if (wrapped != null) {
                usedWrapped = true
                wrapped
            } else {
                NativeBridge.nativePinSetup(app, p, d)
            }
        } finally {
            p?.fill(0)
            d?.fill(0)
        }
        if (rot == null) {
            Log.e(TAG, "nativePinSetup failed")
            return PinResult.FAILED
        }
        val firstCommit = if (usedWrapped) {
            val out = commitWrappedRotation(rot)
            if (out == RotationOutcome.NOT_COMMITTED) {
                // StrongBox rejected WrappedKeyEntry for HMAC on this firmware; fall back to standard import.
                val plainRot = NativeBridge.nativeVaultRotateBegin(app)
                if (plainRot != null) commitRotation(plainRot) else RotationOutcome.NOT_COMMITTED
            } else {
                out
            }
        } else {
            commitRotation(rot)
        }
        if (firstCommit != RotationOutcome.WRITTEN) {
            // The native vault exists only in memory; start over with an empty app object.
            resetApp()
            keys.listTickets().forEach(keys::retireTicket)
            return PinResult.FAILED
        }
        coreState.value = st.copy(pinConfigured = true, locked = false, attemptsLeft = MAX_PIN_ATTEMPTS, vaultDestroyed = false)
        applyPersistentPairingSeed()
        refreshContacts()
        return PinResult.OK
    }

    override suspend fun unlock(pin: CharArray): UnlockResult = onWorker(UnlockResult.UNAVAILABLE) { unlockNow(pin) }

    private fun unlockNow(pin: CharArray): UnlockResult = withUnlockStart { st, blob, live ->
        val pinBytes = PinInput.utf8(pin) ?: return@withUnlockStart UnlockResult.WRONG
        val begin = try {
            // Rejected before a ticket is spent.
            if (pinBytes.size !in PinInput.NATIVE_MIN_BYTES..PinInput.NATIVE_MAX_BYTES) return@withUnlockStart UnlockResult.WRONG
            NativeBridge.nativePinBegin(app, blob, pinBytes, live)
        } finally {
            pinBytes.fill(0)
        }
        finishWithTicket(st, blob, begin, viaPin = true)
    }

    /** Checks shared by the PIN and the fingerprint unlock, up to phase 1, which [phase1] runs. */
    private inline fun withUnlockStart(phase1: (CoreState, ByteArray, IntArray) -> UnlockResult): UnlockResult {
        if (!ready) return UnlockResult.UNAVAILABLE
        val st = coreState.value
        if (st.vaultDestroyed) return UnlockResult.DEAD
        if (!st.pinConfigured) return UnlockResult.UNAVAILABLE
        if (!st.locked && !resetApp()) return UnlockResult.UNAVAILABLE
        val stored: ByteArray? = try {
            vault.read()
        } catch (e: IOException) {
            null
        }
        val blob = stored ?: return UnlockResult.UNAVAILABLE
        val live = keys.listTickets()
        if (live.isEmpty()) {
            markDead()
            return UnlockResult.DEAD
        }
        return phase1(st, blob, live)
    }

    /**
     * Phase 2 for the phase-1 result [begin] (wiped here): uses the single-use ticket and finishes.
     * A PIN unlock stamps fingerprint freshness and, while the feature is being turned on, keeps
     * P; a fingerprint unlock is call-scoped. Every failure is the PIN path's.
     */
    private fun finishWithTicket(st: CoreState, blob: ByteArray, begin: ByteArray?, viaPin: Boolean): UnlockResult {
        if (begin == null) {
            Log.e(TAG, "unlock phase 1 failed")
            return UnlockResult.UNAVAILABLE
        }
        val parsed: PinBegin? = try {
            PinBegin.parse(begin)
        } finally {
            begin.fill(0)
        }
        val ticket = parsed ?: return UnlockResult.UNAVAILABLE
        val enrolling = st.bioEnrollPending
        var kept: ByteArray? = if (bioEffects.mayKeep(viaPin, enrolling)) ticket.input.copyOf() else null
        val hmac = try {
            keys.useTicket(ticket.ticketId, ticket.input)
        } finally {
            ticket.wipe()
        }
        val after = try {
            keys.listTickets()
        } catch (e: Exception) {
            hmac?.fill(0)
            kept?.fill(0)
            throw e
        }
        val rc = try {
            NativeBridge.nativePinFinish(app, blob, ticket.ticketId, hmac, after)
        } finally {
            hmac?.fill(0)
        }
        // Freshness stamp and the kept P follow the result: only a normal PIN unlock stamps or keeps.
        var held = bioEffects.afterUnlock(rc, viaPin, enrolling, bioFiles.hasWrapped(), kept)
        kept = null
        try {
            return when (rc) {
                NativeCode.UNLOCK_NORMAL -> {
                    coreState.value = st.copy(
                        locked = false,
                        attemptsLeft = MAX_PIN_ATTEMPTS,
                        callScoped = !viaPin,
                        bioEnrollPending = viaPin && enrolling,
                    )
                    holdStretch(held)
                    held = null
                    refreshBio()
                    applyPersistentPairingSeed()
                    // The vault must rotate after every unlock; until that is written the old file
                    // keeps working with its remaining tickets. After a fingerprint unlock the native
                    // vault refills only the ticket it spent, so wrong PINs stay counted.
                    if (!persist()) Log.e(TAG, "rotation after unlock not persisted")
                    runCatching { attempts(keys.listTickets()) }.getOrNull()?.let { n -> coreState.update { it.copy(attemptsLeft = n) } }
                    refreshContacts()
                    sessions.onUnlocked()
                    UnlockResult.SUCCESS
                }
                NativeCode.UNLOCK_DURESS -> {
                    duress()
                    UnlockResult.DURESS
                }
                NativeCode.UNLOCK_WRONG -> {
                    coreState.value = st.copy(locked = true, attemptsLeft = attempts(after), callScoped = false)
                    refreshBio()
                    UnlockResult.WRONG
                }
                NativeCode.LOCKED -> {
                    markDead()
                    UnlockResult.DEAD
                }
                else -> {
                    Log.e(TAG, "nativePinFinish failed: $rc")
                    UnlockResult.UNAVAILABLE
                }
            }
        } finally {
            held?.fill(0)
        }
    }

    /**
     * Verifies [current] against the unlocked vault in Rust, stages new Argon2id stretches for
     * [normal] and [duress], and rotates the five single-use StrongBox tickets atomically.
     * Refused after a fingerprint unlock and while fingerprint answer is being turned on. The third
     * wrong current PIN of one unlock locks the vault. A written change turns fingerprint answer
     * off: the wrapped stretch is the old PIN's. The emergency PIN as the current PIN runs [duress].
     */
    override suspend fun changePins(current: CharArray, normal: CharArray, duress: CharArray): PinResult =
        onWorker(PinResult.FAILED) {
            changeNow(current, normal, duress)
        }

    private fun changeNow(current: CharArray, normal: CharArray, duress: CharArray): PinResult {
        val st = coreState.value
        PinChangeRules.refusal(ready, st)?.let { return it }
        val refused = PinChangeRules.refusedAfterCheck(st, heldStretch != null)
        val cur = PinInput.utf8(current)
        val p = PinInput.utf8(normal)
        val d = PinInput.utf8(duress)
        val problem = PinChangeRules.newPinProblem(PinInput.check(normal, duress), p?.size, d?.size)
        val rc = try {
            when {
                // No stored PIN has this length: nothing to compare, nothing counted.
                cur == null || cur.size !in PinInput.NATIVE_MIN_BYTES..PinInput.NATIVE_MAX_BYTES -> NativeCode.PIN_CHANGE_WRONG_CURRENT
                // The current PIN always goes through the native check (the emergency PIN must work
                // here too); the new PINs only when they may be staged, else empty, which it refuses.
                refused || problem != null || p == null || d == null -> NativeBridge.nativePinChange(app, cur, NO_PIN, NO_PIN)
                else -> NativeBridge.nativePinChange(app, cur, p, d)
            }
        } finally {
            cur?.fill(0)
            p?.fill(0)
            d?.fill(0)
        }
        val outcome = PinChangeRules.afterNative(rc, refused, problem) ?: PinChangeRules.afterRotation(rotatePinChange())
        if (outcome.duress) {
            duress()
            return outcome.result
        }
        if (outcome.dropBiometric) dropBiometric()
        if (outcome.result == PinResult.OK) {
            // The rotation of a PIN change refills every ticket.
            runCatching { attempts(keys.listTickets()) }.getOrNull()?.let { n -> coreState.update { it.copy(attemptsLeft = n) } }
        }
        if (outcome.lock) {
            // Drops the native vault here, before a queued write could store a file with the new PINs.
            resetApp()
            lockNow(keepEnroll = false)
        }
        return outcome.result
    }

    /**
     * Worker thread. The rotation that writes staged PINs. Anything short of a written file keeps the
     * file on disk, with the old PINs, and its tickets: an uncommitted rotation is aborted, which
     * also discards the staged PINs in the native vault; after a commit the new tickets are retired.
     */
    private fun rotatePinChange(): RotationOutcome {
        val wrapSpki = keys.ensureTicketWrappingKey()
        if (wrapSpki != null) {
            val wrapped = NativeBridge.nativeVaultRotateBeginWrapped(app, wrapSpki)
            if (wrapped != null) {
                val out = commitWrappedRotation(wrapped, keepUnwritten = false)
                if (out != RotationOutcome.NOT_COMMITTED) return out
            }
        }
        val rot = NativeBridge.nativeVaultRotateBegin(app)
        val outcome = if (rot == null) RotationOutcome.NOT_COMMITTED else commitRotation(rot, keepUnwritten = false)
        if (outcome == RotationOutcome.NOT_COMMITTED) NativeBridge.nativeVaultRotateCommit(app, false)
        return outcome
    }

    override fun lock() = lockNow(keepEnroll = false)

    /** Any thread. [keepEnroll]: this lock is the PIN step of turning fingerprint answer on. */
    private fun lockNow(keepEnroll: Boolean) {
        coreState.update { it.copy(locked = true, callScoped = false, bioEnrollPending = keepEnroll && it.bioEnrollPending) }
        metaStore.clearMemory()
        clearContacts()
        scope.launch {
            clearHeld()
            try {
                if (app != 0L) resetApp()
            } catch (e: Exception) {
                Log.e(TAG, "lock failed: " + e.javaClass.simpleName)
            }
            // An unlock queued before this lock may have finished in between.
            coreState.update { it.copy(locked = true, callScoped = false) }
            clearContacts()
        }
    }

    // ---------------------------------------------------------------- contacts and pairing

    private fun unlocked() = ready && !coreState.value.locked

    /** Unlocked with the PIN: a fingerprint unlock covers one call and changes no contact, pairing or setting. */
    private fun editable() = unlocked() && !coreState.value.callScoped

    private fun busyWithCall(): Boolean =
        sessions.state.value.phase != SessionPhase.IDLE || sessions.callHeld.value || sessions.incoming.value != null || sessions.handoffPending

    private fun nativeId(id: Long): Int? = if (id in 1..Int.MAX_VALUE.toLong()) id.toInt() else null

    private fun known(id: Long) = contactList.value.any { it.id == id }

    override suspend fun updateContact(id: Long, name: String, number: String?): ContactResult = onWorker(ContactResult.FAILED) {
        val label = name.trim().toByteArray(Charsets.UTF_8)
        val nid = nativeId(id)
        val displayNumber = number?.trim()?.takeIf { it.isNotEmpty() }
        val phoneE164 = if (displayNumber != null) PhoneRules.toVaultE164(displayNumber) else null
        when {
            !editable() -> ContactResult.FAILED
            label.isEmpty() || label.size > MAX_LABEL_BYTES -> ContactResult.INVALID_NAME
            displayNumber != null && phoneE164 == null -> ContactResult.INVALID_NUMBER
            nid == null || !known(id) -> ContactResult.NOT_FOUND
            else -> {
                val renameRc = NativeBridge.nativeContactRename(app, nid, label)
                if (renameRc != NativeCode.OK) {
                    if (renameRc == NativeCode.BAD_ARG) ContactResult.INVALID_NAME else ContactResult.FAILED
                } else {
                    val phoneBytes = phoneE164?.toByteArray(Charsets.US_ASCII)
                    val phoneRc = NativeBridge.nativeContactSetPhone(app, nid, phoneBytes)
                    if (phoneRc != NativeCode.OK) {
                        if (phoneRc == NativeCode.BAD_ARG) ContactResult.INVALID_NUMBER else ContactResult.FAILED
                    } else {
                        metaStore.setNumber(id, displayNumber)
                        val saved = persist()
                        refreshContacts()
                        if (saved) ContactResult.OK else ContactResult.FAILED
                    }
                }
            }
        }
    }

    override suspend fun deleteContact(id: Long): ContactResult = onWorker(ContactResult.FAILED) {
        val nid = nativeId(id)
        when {
            !editable() -> ContactResult.FAILED
            nid == null || !known(id) -> ContactResult.NOT_FOUND
            else -> when (NativeBridge.nativeContactDelete(app, nid)) {
                NativeCode.OK -> {
                    metaStore.setNumber(id, null)
                    val saved = persist()
                    refreshContacts()
                    if (saved) ContactResult.OK else ContactResult.FAILED
                }
                else -> ContactResult.FAILED
            }
        }
    }

    override suspend fun submitPairingCode(id: Long, code: String): PairingResult = onWorker(PairingResult.FAILED) {
        val nid = nativeId(id)
        val parsed = InviteCard.parse(code)?.code ?: code
        val bytes = parsed.filter { !it.isWhitespace() }.toByteArray(Charsets.UTF_8)
        try {
            if (!ownCodeIssued && editable()) applyPersistentPairingSeed()
            when {
                !editable() || nid == null || !known(id) -> PairingResult.FAILED
                !ownCodeIssued -> PairingResult.FAILED
                bytes.isEmpty() || bytes.size > MAX_CODE_BYTES -> PairingResult.BAD_FORMAT
                else -> {
                    val rc = NativeBridge.nativeImportPairing(app, nid, bytes, null)
                    when {
                        rc > 0 -> {
                            val changed = (rc and NativeCode.PAIRING_PSK_CHANGED) != 0
                            // The same pairing again changes nothing: no write, so no write can fail it.
                            val saved = !PairingDecisions.needsWrite(changed, renamed = false, numberSet = false) || savedOrReverted(nid)
                            // A new or changed PSK: whether they hold the same one is unknown until they import our current card.
                            PairingDecisions.mutualAfterImport(answersUs = false, pskChanged = changed, saved = saved)
                                ?.let { metaStore.setMutual(id, it) }
                            refreshContacts()
                            if (saved) PairingResult.OK else PairingResult.FAILED
                        }
                        rc == NativeCode.BAD_ARG -> PairingResult.BAD_FORMAT
                        rc == NativeCode.BAD_STATE -> PairingResult.WRONG_KEY
                        else -> PairingResult.FAILED
                    }
                }
            }
        } finally {
            bytes.fill(0)
        }
    }

    /**
     * Worker thread. Writes the vault after an import; when that fails the import is undone in
     * memory too, so no later write can store a pairing the user was told was not saved.
     */
    private fun savedOrReverted(contactId: Int): Boolean {
        if (persist()) return true
        val rc = NativeBridge.nativeImportRevert(app, contactId)
        if (rc != NativeCode.OK) Log.e(TAG, "unsaved import not undone: $rc")
        return false
    }

    override suspend fun previewPairing(code: String): PairingPreview = onWorker(PairingPreview.Invalid) {
        if (!editable() || (!ownCodeIssued && !applyPersistentPairingSeed())) return@onWorker PairingPreview.Invalid
        val parsed = InviteCard.parse(code)?.code ?: code
        val bytes = parsed.filter { !it.isWhitespace() }.toByteArray(Charsets.UTF_8)
        try {
            if (bytes.isEmpty() || bytes.size > MAX_CODE_BYTES) PairingPreview.Invalid else PairingDecisions.preview(NativeBridge.nativePreviewPairing(app, bytes))
        } finally {
            bytes.fill(0)
        }
    }

    override suspend fun addPairedContact(name: String, number: String?, code: String, mutual: Boolean): PairingResult = onWorker(PairingResult.FAILED) {
        if (!editable()) return@onWorker PairingResult.FAILED
        if (!ownCodeIssued && !applyPersistentPairingSeed()) return@onWorker PairingResult.FAILED
        val card = InviteCard.parse(code) ?: return@onWorker PairingResult.BAD_FORMAT
        // Names come from the user or from someone else's card: strip anything that can fake how it looks.
        val finalName = InviteCard.sanitizeName(name).ifEmpty { InviteCard.sanitizeName(card.name) }
        val label = InviteCard.trimUtf8(finalName, MAX_LABEL_BYTES)
        if (label.isEmpty() || label.size > MAX_LABEL_BYTES) return@onWorker PairingResult.FAILED
        // Only the number on screen is saved; an empty field means no number, never the one on the card.
        val displayNumber = number?.let { PhoneRules.normalize(it) }?.takeIf { it.isNotEmpty() }
        val phoneE164 = if (displayNumber != null) {
            PhoneRules.toVaultE164(displayNumber) ?: return@onWorker PairingResult.FAILED
        } else {
            null
        }
        val codeBytes = card.code.filter { !it.isWhitespace() }.toByteArray(Charsets.UTF_8)
        if (codeBytes.isEmpty() || codeBytes.size > MAX_CODE_BYTES) {
            codeBytes.fill(0)
            return@onWorker PairingResult.BAD_FORMAT
        }
        // A contact that holds this identity key already keeps its name and number unless the user changed them.
        val pub = InviteCard.pub33(card.code)
        val existing = pub?.let { p -> vaultContacts.firstOrNull { it.pub33.contentEquals(p) } }
        pub?.fill(0)
        val existingName = existing?.let { e -> contactList.value.firstOrNull { it.id == e.id }?.name }
        val keepLabel = PairingDecisions.keepsLabel(existingName, finalName)
        val setNumber = PairingDecisions.numberChanged(existing?.let { metaStore.numberFor(it.id) }, displayNumber, existing != null)
        try {
            val result = NativeBridge.nativeImportPairing(app, 0, codeBytes, if (keepLabel) null else label)
            val rc = result and NativeCode.PAIRING_PSK_CHANGED.inv()
            val pskChanged = result > 0 && (result and NativeCode.PAIRING_PSK_CHANGED) != 0
            when {
                result > 0 -> {
                    val phoneSet = setNumber && phoneE164 != null &&
                        NativeBridge.nativeContactSetPhone(app, rc, phoneE164.toByteArray(Charsets.US_ASCII)) == NativeCode.OK
                    // An import that changed nothing in the vault is not written (and cannot fail on the write).
                    val saved = !PairingDecisions.needsWrite(pskChanged, renamed = !keepLabel, numberSet = phoneSet) || savedOrReverted(rc)
                    // Contact metadata follows only a written vault.
                    if (saved && phoneSet) metaStore.setNumber(rc.toLong(), displayNumber)
                    PairingDecisions.mutualAfterImport(answersUs = mutual, pskChanged = pskChanged, saved = saved)
                        ?.let { metaStore.setMutual(rc.toLong(), it) }
                    refreshContacts()
                    if (saved) PairingResult.OK else PairingResult.FAILED
                }
                result == NativeCode.BAD_ARG -> PairingResult.BAD_FORMAT
                result == NativeCode.BAD_STATE -> PairingResult.WRONG_KEY
                else -> PairingResult.FAILED
            }
        } finally {
            codeBytes.fill(0)
        }
    }

    override suspend fun ownPairingCode(): String? = onWorker(null) {
        // No code without a seed saved in contact_meta: its key would be gone after the next unlock.
        if (!editable() || (!ownCodeIssued && !applyPersistentPairingSeed())) null else NativeBridge.nativePairingCode(app)
    }

    override suspend fun rotatePairingCode(): String? = onWorker(null) {
        if (!editable()) return@onWorker null
        // The new seed is written first and handed to the native side; if either fails, the old
        // seed is written back and stays in use, so the cards already shown keep matching.
        val fresh = metaStore.rotateSeed { seed -> NativeBridge.nativeSetPairingSeed(app, seed) == NativeCode.OK }
            ?: return@onWorker null
        try {
            ownCodeIssued = true
            NativeBridge.nativePairingCode(app)
        } finally {
            fresh.fill(0)
        }
    }

    override suspend fun ownInviteCard(name: String, number: String?): InviteCard? {
        val code = ownPairingCode() ?: return null
        return InviteCard(
            name = name.trim(),
            number = number?.trim()?.takeIf { it.isNotEmpty() },
            code = code,
            nonce = InviteCard.newNonce(),
        )
    }

    // ---------------------------------------------------------------- session (see SessionEngine)

    override fun startCallToContact(contactId: Long) = sessions.startCallToContact(contactId)

    override fun startCallToNumber(number: String) = sessions.startCallToNumber(number)

    override fun beginHandoff(token: ByteArray) = sessions.beginHandoff(token)

    override fun decideIncoming(secure: Boolean) = sessions.decideIncoming(secure)

    override fun sendText(text: String): SendResult = sessions.sendText(text)

    override fun sendQuick(command: QuickCommand): SendResult = sessions.sendQuick(command)

    override fun beginSas() = sessions.beginSas()

    override fun openVoiceWindow() = sessions.openVoiceWindow()

    override fun decideSas(match: Boolean) = sessions.decideSas(match)

    override suspend fun saveContact(name: String, number: String?): ContactResult =
        onWorker(ContactResult.FAILED) { sessions.saveContact(name, number) }

    override fun dismissSaveOffer() = sessions.dismissSaveOffer()

    override fun dismissAbort() = sessions.dismissAbort()

    /** Lock, clear active session, and scrub in-memory state cleanly before lease termination. */
    override suspend fun prepareExit() {
        sessions.prepareExit()
        metaStore.clearMemory()
        clearContacts()
        onWorker(Unit) {
            clearHeld()
            if (app != 0L) resetApp()
            coreState.update { it.copy(locked = true, callScoped = false, bioEnrollPending = false) }
        }
    }

    /** Not queued behind the worker: hanging up must not wait for a PIN stretch. */
    override suspend fun endAndWipe() = sessions.endAndWipe()

    // ---------------------------------------------------------------- wipe

    override suspend fun wipeAll() {
        // Before queueing: every native call from now on fails, including one already running.
        try {
            NativeBridge.nativePanicWipe(app)
        } catch (e: LinkageError) {
            Log.e(TAG, "native library unavailable during wipe")
        }
        onWorker(Unit) {
            sessions.wipeAll()
            app = 0L
            ownCodeIssued = false
            pendingRetire.clear()
            metaStore.wipe()
            screeningStore.wipe()
            numberIndex.wipe()
            dropBiometric()
            if (!keys.destroyAllKeys()) Log.e(TAG, "key deletion incomplete")
            if (!vault.destroy()) Log.e(TAG, "vault file destruction incomplete")
            io.github.h4lovoid.dialcrypt.core.daemon.DaemonTrim.requestBestEffort()
            clearContacts()
            coreState.value = CoreState(CoreAvailability.NOT_CONNECTED, pinConfigured = false, locked = true)
        }
    }

    private inner class Host : SessionHost {
        override val appHandle: Long get() = app

        override val unlocked: Boolean get() = ready && !coreState.value.locked

        override fun contactIdForKey(pub33: ByteArray): Long? = vaultContacts.firstOrNull { it.pub33.contentEquals(pub33) }?.id

        override fun vaultDirty(seq: Long) {
            if (persist()) {
                NativeBridge.nativeVaultSaved(app, seq.toInt())
            } else {
                Log.e(TAG, "vault not persisted for a session update")
            }
        }

        override fun contactsChanged() = refreshContacts()

        override fun saveContactNumber(id: Long, number: String?) {
            metaStore.setNumber(id, number)
        }

        override fun markMutual(contactId: Long) {
            if (!unlocked || vaultContacts.none { it.id == contactId && it.hasPsk }) return
            if (metaStore.isMutual(contactId)) return
            if (!metaStore.setMutual(contactId, true)) Log.w(TAG, "mutual pairing not persisted")
            refreshContacts()
        }

        override val callScoped: Boolean get() = coreState.value.callScoped

        override val canPresentIncoming: Boolean
            get() = SecureForeground.started && !keyguardLocked()

        override fun lockAfterScopedCall() {
            if (coreState.value.callScoped) lock()
        }
    }

    private fun keyguardLocked(): Boolean = try {
        appContext.getSystemService(KeyguardManager::class.java)?.isKeyguardLocked ?: true
    } catch (e: Exception) {
        true
    }

    companion object {
        private const val TAG = "AegisCore"

        /** Vault file name in noBackupFilesDir; [ContactNumberIndex] checks whether it exists. */
        internal const val VAULT_FILE = "vault.v2"
        private const val META_FILE = "contact_meta.bin"
        private const val MAX_LABEL_BYTES = 64
        private const val MAX_CODE_BYTES = 256
        /** New PINs sent to nativePinChange when they must not be staged; the native core refuses them after the current-PIN check. */
        private val NO_PIN = ByteArray(0)
    }
}

/**
 * Repeats nativeHarden while it reports INTERNAL (the daemon has not raised the memlock limit yet):
 * one attempt every [INTERVAL_MS], the last one no earlier than [LIMIT_MS] after the first. Any
 * other code, OK included, is returned at once.
 */
internal object HardenRetry {
    const val INTERVAL_MS = 100L
    const val LIMIT_MS = 5_000L

    fun run(harden: () -> Int, nowMs: () -> Long, sleepMs: (Long) -> Unit): Int {
        val start = nowMs()
        while (true) {
            val code = harden()
            if (code != NativeCode.INTERNAL) return code
            val left = LIMIT_MS - (nowMs() - start)
            if (left <= 0) return code
            sleepMs(minOf(INTERVAL_MS, left))
        }
    }
}
