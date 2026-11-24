package io.github.h4lovoid.dialcrypt.core

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.SecureRandom
import java.text.Normalizer
import java.util.Base64

/**
 * Contact invite payload shown in person as a QR code or sent remotely, both as `AEGISCARD1:<base64url>`.
 * Wraps the v2 pairing code, an optional display name and number and, for cards made by this
 * version, a random [nonce] that is new for every card made, so every card has its own confirmation code.
 */
data class InviteCard(
    val name: String,
    val number: String?,
    val code: String,
    val nonce: Long? = null,
    /**
     * Hex of the 16-byte tag from [replyTag] for the card this one answers. Only a card shown after
     * saving the other phone's card carries it, so the other phone knows it was saved (version 3).
     */
    val replyTo: String? = null,
) {
    /**
     * Compact binary form (<= 154 bytes) inside the text card: version 2 (with [nonce]) is
     * `2 || raw68 || nonce(8) || len || number || len || name`; version 3 adds the 16-byte [replyTo]
     * tag after the nonce; version 1 has no nonce.
     */
    fun toCompactBytes(): ByteArray? {
        val reply = replyTo?.let { hexToBytes(it) }
        if (replyTo != null && (reply == null || reply.size != TAG_LEN || nonce == null)) return null
        val raw68 = PairingCodeCodec.decode(code) ?: return null
        try {
            val phoneBytes = number?.trim()?.takeIf { it.isNotEmpty() }?.toByteArray(Charsets.UTF_8) ?: ByteArray(0)
            if (phoneBytes.size > MAX_PHONE_BYTES) return null
            val header = 1 + PairingCodeCodec.RAW_LEN + (if (nonce != null) NONCE_LEN else 0) + (reply?.size ?: 0)
            val maxName = (MAX_COMPACT_BYTES - header - 1 - phoneBytes.size - 1).coerceAtLeast(0)
            val nameBytes = trimUtf8(sanitizeName(name), maxName)
            val out = ByteArrayOutputStream(header + 1 + phoneBytes.size + 1 + nameBytes.size)
            out.write(
                when {
                    reply != null -> VERSION_REPLY
                    nonce != null -> VERSION_NONCE
                    else -> VERSION_PLAIN
                },
            )
            out.write(raw68)
            nonce?.let { out.write(longBytes(it)) }
            reply?.let { out.write(it) }
            out.write(phoneBytes.size)
            out.write(phoneBytes)
            out.write(nameBytes.size)
            out.write(nameBytes)
            return out.toByteArray()
        } finally {
            raw68.fill(0)
        }
    }

    /** Copy-pasteable invite card string for remote asynchronous pairing. */
    fun toTextCard(): String? {
        val compact = toCompactBytes() ?: return null
        return try {
            TEXT_PREFIX + Base64.getUrlEncoder().withoutPadding().encodeToString(compact)
        } finally {
            compact.fill(0)
        }
    }

    /**
     * This card exactly as the other phone decodes it (name cleaned and shortened to fit). The
     * sender shows the confirmation code of this copy, so both phones hash the same fields.
     */
    fun wireCopy(): InviteCard? {
        val compact = toCompactBytes() ?: return null
        return try {
            fromCompactBytes(compact)
        } finally {
            compact.fill(0)
        }
    }

    /**
     * Confirmation code both people compare before saving: SHA-256("AegisCard-fp-v2" || raw68 ||
     * nonce || len || number || len || cleaned name), first 5 bytes, shown as 12 decimal digits
     * ("123 456 789 012"). It binds the whole card, so a changed name or number, or a replayed card
     * with another nonce, gives another code; it reveals nothing usable about the PSK. Cards without
     * a nonce (version 1) use "AegisCard-fp-v1" and the same fields minus the nonce. Null when the
     * pairing code is not valid.
     */
    fun fingerprint(): String? {
        val phone = number?.toByteArray(Charsets.UTF_8) ?: ByteArray(0)
        val nameBytes = sanitizeName(name).toByteArray(Charsets.UTF_8)
        if (phone.size > 0xFF || nameBytes.size > 0xFF) return null
        val reply = replyTo?.let { hexToBytes(it) ?: return null }
        val raw68 = PairingCodeCodec.decode(code) ?: return null
        val digest = try {
            val md = MessageDigest.getInstance("SHA-256")
            val domain = when {
                reply != null -> FP_DOMAIN_V3
                nonce != null -> FP_DOMAIN_V2
                else -> FP_DOMAIN_V1
            }
            md.update(domain.toByteArray(Charsets.US_ASCII))
            md.update(raw68)
            nonce?.let { md.update(longBytes(it)) }
            reply?.let { md.update(it) }
            md.update(phone.size.toByte())
            md.update(phone)
            md.update(nameBytes.size.toByte())
            md.update(nameBytes)
            md.digest()
        } finally {
            raw68.fill(0)
        }
        var value = 0L
        for (i in 0 until 5) value = (value shl 8) or (digest[i].toLong() and 0xFF)
        digest.fill(0)
        // 40 bits can exceed 12 digits; keeping the low 12 digits loses well under one bit.
        val digits = (value % FP_MODULUS).toString().padStart(FP_DIGITS, '0')
        return digits.chunked(3).joinToString(" ")
    }

    companion object {
        private const val VERSION_PLAIN = 1
        private const val VERSION_NONCE = 2
        private const val VERSION_REPLY = 3
        private const val NONCE_LEN = 8
        private const val MAX_PHONE_BYTES = 32
        private const val MAX_COMPACT_BYTES = 154
        private const val TEXT_PREFIX = "AEGISCARD1:"
        private const val FP_DOMAIN_V1 = "AegisCard-fp-v1"
        private const val FP_DOMAIN_V2 = "AegisCard-fp-v2"
        private const val FP_DOMAIN_V3 = "AegisCard-fp-v3"
        private const val FP_DIGITS = 12
        private const val FP_MODULUS = 1_000_000_000_000L
        private const val ACK_DOMAIN = "AegisCard-ack-v2"
        private const val TAG_LEN = 16
        private const val MAX_MARKS = 2

        /** Longest display name kept from a card, in UTF-16 units (the name inputs hold 40). */
        const val MAX_NAME_CHARS = 40

        private val random = SecureRandom()

        private val DROPPED_TYPES = setOf(
            Character.CONTROL,
            Character.FORMAT,
            Character.PRIVATE_USE,
            Character.UNASSIGNED,
            Character.SURROGATE,
            Character.ENCLOSING_MARK,
        ).map { it.toInt() }.toSet()

        /** Fresh random nonce for one card of ours. */
        fun newNonce(): Long = random.nextLong()

        /**
         * Tag bytes saying we saved [received]: SHA-256("AegisCard-ack-v2" || raw68 of [received] ||
         * our raw68 || nonce of [received]), first 16 bytes. Both whole pairing codes are covered, so a
         * reply whose pairing key was swapped (a contact's identity key with someone else's key) no
         * longer matches. It holds no secret and only tells the other phone that its card was saved.
         * Null when the card has no nonce or a code is bad.
         */
        private fun tagBytes(received: InviteCard, ownCode: String): ByteArray? {
            val nonce = received.nonce ?: return null
            val peerRaw = PairingCodeCodec.decode(received.code) ?: return null
            val ownRaw = PairingCodeCodec.decode(ownCode) ?: run {
                peerRaw.fill(0)
                return null
            }
            val digest = try {
                val md = MessageDigest.getInstance("SHA-256")
                md.update(ACK_DOMAIN.toByteArray(Charsets.US_ASCII))
                md.update(peerRaw)
                md.update(ownRaw)
                md.update(longBytes(nonce))
                md.digest()
            } finally {
                peerRaw.fill(0)
                ownRaw.fill(0)
            }
            return try {
                digest.copyOf(TAG_LEN)
            } finally {
                digest.fill(0)
            }
        }

        /** [InviteCard.replyTo] tag for the card we show after saving [received], as hex. */
        fun replyTag(received: InviteCard, ownCode: String): String? {
            val tag = tagBytes(received, ownCode) ?: return null
            return try {
                toHex(tag)
            } finally {
                tag.fill(0)
            }
        }

        /** True when [reply] comes from a phone that saved the card we [sent]. */
        fun answers(reply: InviteCard, sent: InviteCard): Boolean {
            val tag = reply.replyTo?.let { hexToBytes(it) } ?: return false
            if (tag.size != TAG_LEN) return false
            val expected = tagBytes(sent, reply.code) ?: return false
            return try {
                MessageDigest.isEqual(expected, tag)
            } finally {
                expected.fill(0)
            }
        }

        private fun toHex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it.toInt() and 0xFF) }

        private fun hexToBytes(hex: String): ByteArray? {
            if (hex.length % 2 != 0) return null
            val out = ByteArray(hex.length / 2)
            for (i in out.indices) {
                val hi = Character.digit(hex[2 * i], 16)
                val lo = Character.digit(hex[2 * i + 1], 16)
                if (hi < 0 || lo < 0) return null
                out[i] = ((hi shl 4) or lo).toByte()
            }
            return out
        }

        /** The identity key in [code] (33 bytes, the caller wipes it), or null for a bad code. */
        fun pub33(code: String): ByteArray? {
            val raw68 = PairingCodeCodec.decode(code) ?: return null
            return try {
                raw68.copyOfRange(1, 34)
            } finally {
                raw68.fill(0)
            }
        }

        private fun longBytes(v: Long): ByteArray = ByteBuffer.allocate(8).putLong(v).array()

        /**
         * Makes a display name received from someone else safe to show: NFKC, then drops control,
         * format (bidi overrides and isolates, zero-width characters), private-use, unassigned,
         * enclosing-mark and lone surrogate code points, keeps at most two non-spacing marks in a row
         * (no "Zalgo" stacks; Vietnamese and Indic scripts keep working), turns line breaks and other
         * spacing into single spaces, trims, and keeps at most [MAX_NAME_CHARS] UTF-16 units without
         * splitting a character.
         */
        fun sanitizeName(raw: String): String {
            val folded = Normalizer.normalize(raw, Normalizer.Form.NFKC)
            val kept = StringBuilder(folded.length)
            var marks = 0
            var i = 0
            while (i < folded.length) {
                val cp = folded.codePointAt(i)
                i += Character.charCount(cp)
                if (isSpacing(cp)) {
                    kept.append(' ')
                    marks = 0
                    continue
                }
                val type = Character.getType(cp)
                if (type in DROPPED_TYPES) continue
                if (type == Character.NON_SPACING_MARK.toInt()) {
                    if (++marks > MAX_MARKS) continue
                } else {
                    marks = 0
                }
                kept.appendCodePoint(cp)
            }
            // A removed character may have kept a letter and its accent apart; join them again.
            val joined = Normalizer.normalize(kept, Normalizer.Form.NFKC)
            val out = StringBuilder(minOf(joined.length, MAX_NAME_CHARS))
            var pendingSpace = false
            var j = 0
            while (j < joined.length) {
                val cp = joined.codePointAt(j)
                j += Character.charCount(cp)
                if (isSpacing(cp)) {
                    if (out.isNotEmpty()) pendingSpace = true
                    continue
                }
                if (Character.getType(cp) in DROPPED_TYPES) continue
                val needed = Character.charCount(cp) + if (pendingSpace) 1 else 0
                if (out.length + needed > MAX_NAME_CHARS) break
                if (pendingSpace) out.append(' ')
                pendingSpace = false
                out.appendCodePoint(cp)
            }
            return out.toString()
        }

        private fun isSpacing(cp: Int): Boolean = when (cp) {
            '\t'.code, '\n'.code, 0x0B, 0x0C, '\r'.code, 0x85 -> true
            else -> when (Character.getType(cp)) {
                Character.SPACE_SEPARATOR.toInt(),
                Character.LINE_SEPARATOR.toInt(),
                Character.PARAGRAPH_SEPARATOR.toInt() -> true
                else -> false
            }
        }

        /** Decodes a version 1, 2 or 3 compact card; the name is cleaned with [sanitizeName]. */
        fun fromCompactBytes(bytes: ByteArray): InviteCard? {
            if (bytes.isEmpty()) return null
            val version = bytes[0].toInt() and 0xFF
            val nonceLen = when (version) {
                VERSION_PLAIN -> 0
                VERSION_NONCE, VERSION_REPLY -> NONCE_LEN
                else -> return null
            }
            val replyLen = if (version == VERSION_REPLY) TAG_LEN else 0
            val header = 1 + PairingCodeCodec.RAW_LEN + nonceLen + replyLen
            if (bytes.size < header + 2) return null
            val raw68 = bytes.copyOfRange(1, 1 + PairingCodeCodec.RAW_LEN)
            val code = PairingCodeCodec.encode(raw68) ?: run {
                raw68.fill(0)
                return null
            }
            raw68.fill(0)
            val nonce = if (nonceLen > 0) ByteBuffer.wrap(bytes, 1 + PairingCodeCodec.RAW_LEN, NONCE_LEN).long else null
            val replyStart = 1 + PairingCodeCodec.RAW_LEN + nonceLen
            val replyTo = if (replyLen > 0) toHex(bytes.copyOfRange(replyStart, replyStart + replyLen)) else null
            val buf = ByteBuffer.wrap(bytes, header, bytes.size - header)
            val phoneLen = buf.get().toInt() and 0xFF
            if (phoneLen > MAX_PHONE_BYTES || buf.remaining() < phoneLen + 1) return null
            val phoneBytes = ByteArray(phoneLen)
            buf.get(phoneBytes)
            val nameLen = buf.get().toInt() and 0xFF
            if (buf.remaining() != nameLen) return null
            val nameBytes = ByteArray(nameLen)
            buf.get(nameBytes)
            val phone = phoneBytes.toString(Charsets.UTF_8).trim().ifEmpty { null }
            val name = sanitizeName(nameBytes.toString(Charsets.UTF_8))
            return InviteCard(name = name, number = phone, code = code, nonce = nonce, replyTo = replyTo)
        }

        /**
         * Parses either an `AEGISCARD1:<base64url>` invite card or a bare `AEGIS2-...` pairing code
         * (with optional whitespace/hyphens).
         */
        fun parse(text: String): InviteCard? {
            val trimmed = text.trim()
            if (trimmed.isEmpty()) return null
            if (trimmed.startsWith(TEXT_PREFIX, ignoreCase = true)) {
                val b64 = trimmed.substring(TEXT_PREFIX.length).filter { !it.isWhitespace() }
                val decoded = runCatching { Base64.getUrlDecoder().decode(b64) }.getOrNull() ?: return null
                return try {
                    fromCompactBytes(decoded)
                } finally {
                    decoded.fill(0)
                }
            }
            val markerIdx = trimmed.indexOf(PairingCodeCodec.PREFIX, ignoreCase = true)
            val candidate = if (markerIdx >= 0) trimmed.substring(markerIdx) else trimmed
            val raw68 = PairingCodeCodec.decode(candidate) ?: return null
            val canonical = PairingCodeCodec.encode(raw68)
            raw68.fill(0)
            return canonical?.let { InviteCard(name = "", number = null, code = it) }
        }

        /** UTF-8 bytes of the longest prefix of [s] that fits [maxBytes], cut on a character boundary. */
        internal fun trimUtf8(s: String, maxBytes: Int): ByteArray {
            if (s.isEmpty() || maxBytes <= 0) return ByteArray(0)
            val full = s.toByteArray(Charsets.UTF_8)
            if (full.size <= maxBytes) return full
            var end = s.length
            while (end > 0) {
                if (Character.isLowSurrogate(s[end - 1]) && end >= 2 && Character.isHighSurrogate(s[end - 2])) {
                    end -= 2
                } else {
                    end--
                }
                val sub = s.substring(0, end).toByteArray(Charsets.UTF_8)
                if (sub.size <= maxBytes) return sub
            }
            return ByteArray(0)
        }
    }
}

/**
 * Pure Kotlin encoder/decoder matching `aegiscall_crypto::PairingCodeV2`
 * (`ver(1)=3 || pub33(33) || X25519 public key(32) || CRC-16/CCITT(2)` = 68 bytes in base32 with
 * `AEGIS2-`). The code holds no secret; the native side also checks the identity point and the
 * X25519 key when it imports a code.
 */
internal object PairingCodeCodec {
    const val PREFIX = "AEGIS2-"
    const val RAW_LEN = 68
    private const val VERSION: Byte = 3
    private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    fun decode(code: String): ByteArray? {
        val trimmed = code.trim()
        if (!trimmed.startsWith(PREFIX, ignoreCase = true)) return null
        val body = trimmed.substring(PREFIX.length)
        val out = ByteArray(RAW_LEN)
        var outLen = 0
        var buffer = 0
        var bits = 0
        for (ch in body) {
            val v = when (ch) {
                in 'A'..'Z' -> ch - 'A'
                in 'a'..'z' -> ch - 'a'
                in '2'..'7' -> 26 + (ch - '2')
                '-', ' ', '\n', '\r', '\t' -> continue
                else -> return null
            }
            buffer = (buffer shl 5) or v
            bits += 5
            if (bits >= 8) {
                bits -= 8
                if (outLen >= RAW_LEN) {
                    out.fill(0)
                    return null
                }
                out[outLen++] = ((buffer ushr bits) and 0xFF).toByte()
                buffer = buffer and ((1 shl bits) - 1)
            }
        }
        if (outLen != RAW_LEN || bits >= 5 || buffer != 0) {
            out.fill(0)
            return null
        }
        if (out[0] != VERSION || !crcValid(out)) {
            out.fill(0)
            return null
        }
        return out
    }

    fun encode(raw68: ByteArray): String? {
        if (raw68.size != RAW_LEN || raw68[0] != VERSION || !crcValid(raw68)) return null
        val b32 = StringBuilder(110)
        var buffer = 0
        var bits = 0
        for (b in raw68) {
            buffer = (buffer shl 8) or (b.toInt() and 0xFF)
            bits += 8
            while (bits >= 5) {
                bits -= 5
                b32.append(ALPHABET[(buffer ushr bits) and 0x1F])
            }
        }
        if (bits > 0) {
            b32.append(ALPHABET[(buffer shl (5 - bits)) and 0x1F])
        }
        val out = StringBuilder(140)
        out.append("AEGIS2")
        for (i in 0 until b32.length) {
            if (i % 5 == 0) out.append('-')
            out.append(b32[i])
        }
        return out.toString()
    }

    private fun crcValid(raw68: ByteArray): Boolean {
        var crc = 0xFFFF
        for (i in 0 until RAW_LEN - 2) {
            crc = crc xor ((raw68[i].toInt() and 0xFF) shl 8)
            repeat(8) {
                crc = if ((crc and 0x8000) != 0) ((crc shl 1) xor 0x1021) and 0xFFFF else (crc shl 1) and 0xFFFF
            }
        }
        val expected = ((raw68[66].toInt() and 0xFF) shl 8) or (raw68[67].toInt() and 0xFF)
        return crc == expected
    }
}
