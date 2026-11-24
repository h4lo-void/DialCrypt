package io.github.h4lovoid.dialcrypt.core.real

/** Path of a handshake: full, or resume with the contact's current (or new) resume secret. */
internal data class SessionPath(val resume: Boolean, val usedNew: Boolean, val contactId: Long)

/** Identity code of the ESTABLISHED event. */
internal enum class NativeIdentity { UNVERIFIED, SAS_VERIFIED, KNOWN_CONTACT, KEY_CHANGED }

/** One record of nativeSessionPollEvents, decoded per the table in NativeBridge.kt. */
internal sealed interface NativeEvent {
    class NeedSignature(val reqId: Int, val message: ByteArray) : NativeEvent
    data class Sas(val wordIndices: List<Int>) : NativeEvent
    data class PathChosen(val path: SessionPath) : NativeEvent
    data class HandshakeProgress(val percent: Int) : NativeEvent
    class Established(
        val responder: Boolean,
        val path: SessionPath,
        val identity: NativeIdentity,
        /** 0 = none. */
        val pskContactId: Long,
        /** 0 = none. */
        val storedContactId: Long,
        val peerPub33: ByteArray,
    ) : NativeEvent
    class KeyChanged(val storedPub33: ByteArray, val peerPub33: ByteArray) : NativeEvent
    data object SasConfirmed : NativeEvent
    data class VoiceWindow(val open: Boolean) : NativeEvent
    data class PqProgress(val percent: Int) : NativeEvent
    data class PqMixed(val epoch: Long) : NativeEvent
    data class Epoch(val epoch: Long) : NativeEvent
    data class VaultDirty(val seq: Long) : NativeEvent
    /** [result] 0 = ok, else a return code; [boot] 0 verified, 1 self-signed, 2 unlocked. */
    data class Attestation(val result: Int, val boot: Int, val osPatch: Long, val stored: Boolean) : NativeEvent
    /** [text] is UTF-8; the receiver wipes it after decoding. */
    class MessageReceived(val msgId: Int, val text: ByteArray) : NativeEvent
    data class MessageDelivered(val msgId: Int) : NativeEvent
    /** [acked] of [total] shards of outgoing message [msgId] were confirmed by the peer. */
    data class MessageProgress(val msgId: Int, val acked: Int, val total: Int) : NativeEvent
    data class MessageFailed(val msgId: Int) : NativeEvent
    data object RemoteWipe : NativeEvent
    data object WipeSent : NativeEvent
    data class Ended(val byPeer: Boolean) : NativeEvent
    data class Aborted(val reason: Int) : NativeEvent
    data class VaultFailed(val code: Int) : NativeEvent
}

/**
 * Decoder for the event TLV: records `type u8 · len u16 BE · value`, back to back. Library and
 * app ship together, so a truncated record, a wrong value length or an unknown type makes the
 * whole buffer malformed (null) and the session fails closed.
 */
internal object EventTlv {
    const val NEED_SIGNATURE = 1
    const val SAS = 2
    const val PATH = 3
    const val HS_PROGRESS = 4
    const val ESTABLISHED = 5
    const val KEY_CHANGED = 6
    const val SAS_CONFIRMED = 7
    const val VOICE_WINDOW = 8
    const val PQ_PROGRESS = 9
    const val PQ_MIXED = 10
    const val EPOCH = 11
    const val VAULT_DIRTY = 12
    const val ATTESTATION = 14
    const val MESSAGE_RECEIVED = 15
    const val MESSAGE_DELIVERED = 16
    const val MESSAGE_FAILED = 17
    const val REMOTE_WIPE = 18
    const val WIPE_SENT = 19
    const val ENDED = 20
    const val ABORTED = 21
    const val MESSAGE_PROGRESS = 22
    const val VAULT_FAILED = 32

    private const val PUB33 = 33
    private const val SAS_BYTES = 5

    fun parse(data: ByteArray): List<NativeEvent>? {
        val r = ByteReader(data)
        val out = ArrayList<NativeEvent>()
        while (!r.atEnd) {
            val type = r.u8() ?: return null
            val len = r.u16() ?: return null
            val value = r.bytes(len) ?: return null
            try {
                out += decode(type, value) ?: return null
            } finally {
                value.fill(0)
            }
        }
        return out
    }

    private fun decode(type: Int, v: ByteArray): NativeEvent? = when (type) {
        NEED_SIGNATURE -> if (v.size > 4) {
            val r = ByteReader(v)
            val id = r.u32()
            val msg = r.bytes(r.remaining)
            if (id != null && msg != null) NativeEvent.NeedSignature(id.toInt(), msg) else null
        } else {
            null
        }
        SAS -> if (v.size == SAS_BYTES) NativeEvent.Sas(v.map { it.toInt() and 0xFF }) else null
        PATH -> if (v.size == 6) path(ByteReader(v))?.let { NativeEvent.PathChosen(it) } else null
        HS_PROGRESS -> percent(v)?.let { NativeEvent.HandshakeProgress(it) }
        ESTABLISHED -> if (v.size == 1 + 6 + 1 + 4 + 4 + PUB33) established(ByteReader(v)) else null
        KEY_CHANGED -> if (v.size == 2 * PUB33) {
            NativeEvent.KeyChanged(v.copyOfRange(0, PUB33), v.copyOfRange(PUB33, 2 * PUB33))
        } else {
            null
        }
        SAS_CONFIRMED -> if (v.isEmpty()) NativeEvent.SasConfirmed else null
        VOICE_WINDOW -> flag(v)?.let { NativeEvent.VoiceWindow(it) }
        PQ_PROGRESS -> percent(v)?.let { NativeEvent.PqProgress(it) }
        PQ_MIXED -> u32Only(v)?.let { NativeEvent.PqMixed(it) }
        EPOCH -> u32Only(v)?.let { NativeEvent.Epoch(it) }
        VAULT_DIRTY -> u32Only(v)?.let { NativeEvent.VaultDirty(it) }
        ATTESTATION -> if (v.size == 7) attestation(ByteReader(v)) else null
        MESSAGE_RECEIVED -> if (v.size >= 2) {
            NativeEvent.MessageReceived(((v[0].toInt() and 0xFF) shl 8) or (v[1].toInt() and 0xFF), v.copyOfRange(2, v.size))
        } else {
            null
        }
        MESSAGE_DELIVERED -> u16Only(v)?.let { NativeEvent.MessageDelivered(it) }
        MESSAGE_FAILED -> u16Only(v)?.let { NativeEvent.MessageFailed(it) }
        MESSAGE_PROGRESS -> if (v.size == 6) {
            val r = ByteReader(v)
            val id = r.u16()
            val acked = r.u16()
            val total = r.u16()
            if (id != null && acked != null && total != null) NativeEvent.MessageProgress(id, acked, total) else null
        } else {
            null
        }
        REMOTE_WIPE -> if (v.isEmpty()) NativeEvent.RemoteWipe else null
        WIPE_SENT -> if (v.isEmpty()) NativeEvent.WipeSent else null
        ENDED -> flag(v)?.let { NativeEvent.Ended(it) }
        ABORTED -> if (v.size == 1) NativeEvent.Aborted(v[0].toInt() and 0xFF) else null
        VAULT_FAILED -> if (v.size == 1) NativeEvent.VaultFailed(v[0].toInt()) else null
        else -> null
    }

    private fun path(r: ByteReader): SessionPath? {
        val kind = r.u8() ?: return null
        val usedNew = bool(r.u8() ?: return null) ?: return null
        val contact = r.u32() ?: return null
        return when (kind) {
            0 -> SessionPath(resume = false, usedNew = usedNew, contactId = contact)
            1 -> SessionPath(resume = true, usedNew = usedNew, contactId = contact)
            else -> null
        }
    }

    private fun established(r: ByteReader): NativeEvent? {
        val responder = bool(r.u8() ?: return null) ?: return null
        val path = path(r) ?: return null
        val identity = NativeIdentity.entries.getOrNull(r.u8() ?: return null) ?: return null
        val psk = r.u32() ?: return null
        val stored = r.u32() ?: return null
        val peer = r.bytes(PUB33) ?: return null
        return NativeEvent.Established(responder, path, identity, psk, stored, peer)
    }

    private fun attestation(r: ByteReader): NativeEvent? {
        val result = (r.u8() ?: return null).toByte().toInt()
        val boot = r.u8() ?: return null
        val patch = r.u32() ?: return null
        val stored = bool(r.u8() ?: return null) ?: return null
        if (boot > 2) return null
        return NativeEvent.Attestation(result, boot, patch, stored)
    }

    private fun bool(b: Int): Boolean? = when (b) {
        0 -> false
        1 -> true
        else -> null
    }

    private fun flag(v: ByteArray): Boolean? = if (v.size == 1) bool(v[0].toInt() and 0xFF) else null

    private fun percent(v: ByteArray): Int? = if (v.size == 1) (v[0].toInt() and 0xFF).coerceAtMost(100) else null

    private fun u16Only(v: ByteArray): Int? = if (v.size == 2) ByteReader(v).u16() else null

    private fun u32Only(v: ByteArray): Long? = if (v.size == 4) ByteReader(v).u32() else null
}
