package io.github.h4lovoid.dialcrypt.core

/** Ready-made states shared by the debug demo, unit tests and screenshot tests. */
object FakeScenarios {
    const val FINGERPRINT = "9F3A 51C2 0D7E B84A 66F1 2C09 E3D5 7A18"

    val ana = Contact(1, "Ana Torres", "+34600123456", "A1B2 C3D4 E5F6 0718 293A 4B5C 6D7E 8F90", true, true, QuickConnect.READY, HardwareLevel.STRONGBOX_LOCKED)
    val marc = Contact(2, "Marc Dubois", "+33612345678", "0F1E 2D3C 4B5A 6978 8796 A5B4 C3D2 E1F0", true, false, QuickConnect.REBUILD_PENDING, HardwareLevel.STRONGBOX_SELF_SIGNED)
    val sam = Contact(3, "Sam Carter", "+14155550123", "5566 7788 99AA BBCC DDEE FF00 1122 3344", false, false, QuickConnect.UNAVAILABLE, HardwareLevel.UNATTESTED)
    val hidden = Contact(4, "Courier", null, "C0DE C0DE 1234 5678 9ABC DEF0 1357 9BDF", true, false, QuickConnect.UNAVAILABLE, HardwareLevel.STRONGBOX_UNLOCKED)
    val lucia = Contact(5, "Lucía Peña", "+34911234567", "7B21 09FE 44D0 A6C3 5E18 92BA 0C7D 3F65", true, false, QuickConnect.UNAVAILABLE, HardwareLevel.UNATTESTED, keyChanged = true)

    val contacts = listOf(ana, marc, sam, hidden, lucia)

    val unlocked = CoreState(CoreAvailability.READY, pinConfigured = true, locked = false)

    fun connecting(step: ConnectStep, percent: Int, eta: Int, peer: Contact? = null) = SessionState(
        phase = SessionPhase.CONNECTING,
        peer = if (peer != null) PeerInfo(peer.id, peer.name, peer.number) else PeerInfo(null, null, "+14155550199"),
        connect = ConnectProgress(step, percent, eta),
    )

    private val conversation = listOf(
        ChatMessage(1, false, MessageBody.Text("Are you at the station?"), MessageStatus.RECEIVED),
        ChatMessage(2, true, MessageBody.Quick(QuickCommand.YES), MessageStatus.READ),
        ChatMessage(3, true, MessageBody.Text("Arriving in ten minutes, I will wait at the east exit."), MessageStatus.DELIVERED),
        ChatMessage(4, false, MessageBody.Quick(QuickCommand.UNDERSTOOD), MessageStatus.RECEIVED),
        ChatMessage(5, true, MessageBody.Text("Bring the documents we talked about."), MessageStatus.SENDING, 55),
    )

    fun established(identity: IdentityStatus, peer: Contact?, pq: PqState, messages: List<ChatMessage> = conversation) = SessionState(
        phase = SessionPhase.ESTABLISHED,
        peer = if (peer != null) PeerInfo(peer.id, peer.name, peer.number) else PeerInfo(null, null, "+14155550199"),
        identity = identity,
        paired = peer?.paired == true,
        quickConnect = peer?.quickConnect ?: QuickConnect.UNAVAILABLE,
        pq = pq,
        hardware = peer?.hardware ?: HardwareLevel.UNATTESTED,
        fingerprint = peer?.fingerprint ?: FINGERPRINT,
        messages = messages,
    )

    val chatUnknown get() = established(IdentityStatus.UNKNOWN, null, PqState(mixed = true))
    val chatVerifiedCall get() = established(IdentityStatus.VERIFIED_THIS_CALL, null, PqState(mixed = true))
    val chatContactPairedQuick get() = established(IdentityStatus.VERIFIED_CONTACT, ana, PqState(mixed = false, percent = 42))
    val chatContactPq get() = established(IdentityStatus.VERIFIED_CONTACT, marc, PqState(mixed = true))

    val sasWords = listOf(12, 87, 143, 201, 250)

    fun withSas(base: SessionState, open: Boolean = true, seconds: Int = 24, local: Boolean = false, peer: Boolean = false) =
        base.copy(sas = SasState(sasWords, open, seconds, local, peer))

    val keyChanged get() = established(IdentityStatus.KEY_CHANGED, ana, PqState(mixed = true), emptyList()).copy(phase = SessionPhase.KEY_CHANGED)

    val saveOffer get() = chatVerifiedCall.copy(saveOffer = SaveOffer("+14155550199"))

    fun aborted(code: SessionFailure) = SessionState(phase = SessionPhase.ABORTED, abort = code)
    val endedByPeer get() = SessionState(
        phase = SessionPhase.ABORTED,
        peer = PeerInfo(null, null, "+14155550199"),
        abort = SessionFailure.CALL_DROPPED,
        wasEstablished = true,
    )
    val clearing = SessionState(phase = SessionPhase.CLEARING)
    val cleared = SessionState(phase = SessionPhase.CLEARED)

    fun lockdown(level: HardeningLevel = HardeningLevel.LEVEL_1, done: Int, running: Boolean = true): LockdownState {
        val items = FakeLockdownController.itemsFor(level, ItemStatus.PENDING).mapIndexed { i, it ->
            when {
                i < done -> it.copy(status = ItemStatus.DONE)
                i == done && running -> it.copy(status = ItemStatus.RUNNING)
                else -> it
            }
        }
        return LockdownState(LockdownPhase.PREPARING, items, level)
    }

    fun lockdownFailed(at: PrepItem, code: LockdownFailure): LockdownState {
        val all = FakeLockdownController.itemsFor(HardeningLevel.LEVEL_1, ItemStatus.PENDING)
        val index = all.indexOfFirst { it.item == at }
        val items = all.mapIndexed { i, it ->
            when {
                i < index -> it.copy(status = ItemStatus.DONE)
                i == index -> PrepItemState(it.item, ItemStatus.FAILED, code)
                else -> it
            }
        }
        return LockdownState(LockdownPhase.FAILED, items, HardeningLevel.LEVEL_1)
    }

    fun lockdownReady(level: HardeningLevel = HardeningLevel.LEVEL_1) =
        LockdownState(LockdownPhase.READY, FakeLockdownController.itemsFor(level, ItemStatus.DONE), level)
}
