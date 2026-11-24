package io.github.h4lovoid.dialcrypt.core.real

import io.github.h4lovoid.dialcrypt.core.Contact
import io.github.h4lovoid.dialcrypt.core.HardwareLevel
import io.github.h4lovoid.dialcrypt.core.QuickConnect
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.security.MessageDigest

/** One record of nativeContactList. The vault keeps only a tag of the phone number, never the number. */
internal class VaultContact(
    val id: Long,
    val flags: Int,
    val pub33: ByteArray,
    val label: String,
    /** 0 verified, 1 self-signed, 2 unlocked; null without a stored attestation. */
    val boot: Int?,
    val osPatch: Long?,
    val phoneTag: ByteArray? = null,
) {
    val hasPsk: Boolean get() = flags and ContactListCodec.FLAG_PSK != 0
    val sasVerified: Boolean get() = flags and ContactListCodec.FLAG_SAS != 0
    val resumeCurrent: Boolean get() = flags and ContactListCodec.FLAG_RS_CUR != 0
    val resumeNew: Boolean get() = flags and ContactListCodec.FLAG_RS_NEW != 0
    val hasNumberTag: Boolean get() = flags and ContactListCodec.FLAG_NUMBER != 0

    fun toContact(number: String? = null, mutual: Boolean = false): Contact = Contact(
        id = id,
        name = label,
        number = number,
        fingerprint = Fingerprint.of(pub33),
        verified = sasVerified,
        paired = hasPsk,
        quickConnect = when {
            resumeCurrent -> QuickConnect.READY
            resumeNew || sasVerified -> QuickConnect.REBUILD_PENDING
            else -> QuickConnect.UNAVAILABLE
        },
        hardware = when (boot) {
            null -> HardwareLevel.UNATTESTED
            0 -> HardwareLevel.STRONGBOX_LOCKED
            1 -> HardwareLevel.STRONGBOX_SELF_SIGNED
            else -> HardwareLevel.STRONGBOX_UNLOCKED
        },
        mutual = hasPsk && mutual,
    )

    fun wipeSensitive() {
        phoneTag?.fill(0)
    }
}

/**
 * `count u16 · per contact: id u32 · flags u8 · pub33 · labelLen u8 · label ·
 * [boot u8 · osPatch u32 if flag 0x10] · [phoneTag 16 B if flag 0x20]`.
 */
internal object ContactListCodec {
    const val FLAG_PSK = 0x01
    const val FLAG_SAS = 0x02
    const val FLAG_RS_CUR = 0x04
    const val FLAG_RS_NEW = 0x08
    const val FLAG_ATTESTED = 0x10
    const val FLAG_NUMBER = 0x20
    private const val KNOWN_FLAGS = 0x3F
    private const val PHONE_TAG_LEN = 16

    /** Null when the buffer is malformed (truncated, trailing bytes, unknown flags, bad UTF-8). */
    fun parse(data: ByteArray): List<VaultContact>? {
        val r = ByteReader(data)
        val count = r.u16() ?: return null
        val out = ArrayList<VaultContact>(count)
        repeat(count) {
            val id = r.u32() ?: return null
            val flags = r.u8() ?: return null
            if (flags and KNOWN_FLAGS.inv() != 0 || id == 0L) return null
            val pub = r.bytes(33) ?: return null
            val labelLen = r.u8() ?: return null
            val label = utf8(r.bytes(labelLen) ?: return null) ?: return null
            var boot: Int? = null
            var patch: Long? = null
            if (flags and FLAG_ATTESTED != 0) {
                val b = r.u8() ?: return null
                if (b > 2) return null
                boot = b
                patch = r.u32() ?: return null
            }
            val phoneTag = if (flags and FLAG_NUMBER != 0) r.bytes(PHONE_TAG_LEN) ?: return null else null
            out += VaultContact(id, flags, pub, label, boot, patch, phoneTag)
        }
        return if (r.atEnd) out else null
    }

    private fun utf8(b: ByteArray): String? = try {
        Charsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(b))
            .toString()
    } catch (e: CharacterCodingException) {
        null
    }
}

/** Key fingerprint shown to users: first 16 bytes of SHA-256(pub33), upper-case hex in groups of four. */
internal object Fingerprint {
    fun of(pub33: ByteArray): String {
        val d = MessageDigest.getInstance("SHA-256").digest(pub33)
        val hex = StringBuilder(39)
        for (i in 0 until 16) {
            if (i > 0 && i % 2 == 0) hex.append(' ')
            hex.append(HEX[(d[i].toInt() ushr 4) and 0xF]).append(HEX[d[i].toInt() and 0xF])
        }
        return hex.toString()
    }

    private const val HEX = "0123456789ABCDEF"
}
