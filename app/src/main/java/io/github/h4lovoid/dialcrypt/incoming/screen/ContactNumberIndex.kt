package io.github.h4lovoid.dialcrypt.incoming.screen

import android.content.Context
import io.github.h4lovoid.dialcrypt.core.ContactMembership
import io.github.h4lovoid.dialcrypt.core.CoreProvider
import io.github.h4lovoid.dialcrypt.core.DirectBoot
import io.github.h4lovoid.dialcrypt.core.PhoneRules
import java.io.File
import java.io.FileOutputStream
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Arrays

/**
 * The endings of a phone number that the contact number index is keyed by. Every way of writing one
 * number (with its country code, with a trunk 0, or as dialed locally) ends in the same digits, so the
 * main tail needs no country: the last [TAIL_DIGITS] digits after leading zeros are dropped. Only a
 * number whose national part is shorter than [TAIL_DIGITS] needs the SIM country: when it is known,
 * the tail with the country code put in front of a local number, or taken off an international one,
 * is added, so both spellings still share a tail.
 */
internal object NumberTails {
    const val TAIL_DIGITS = 8

    /** Fewer digits than this is never a contact number (PhoneRules.isValid). */
    const val MIN_DIGITS = 5

    fun of(number: String, countryCode: String? = PhoneRules.defaultCountryCode): Set<String> {
        val trimmed = number.trim()
        val digits = trimmed.filter { it in '0'..'9' }
        if (digits.length < MIN_DIGITS) return emptySet()
        val international = trimmed.startsWith("+") || digits.startsWith("00")
        val significant = digits.trimStart('0')
        if (significant.isEmpty()) return emptySet()
        val out = LinkedHashSet<String>(2)
        out += significant.takeLast(TAIL_DIGITS)
        val cc = countryCode?.takeIf { it.isNotEmpty() } ?: return out
        if (!international) {
            out += (cc + significant).takeLast(TAIL_DIGITS)
        } else if (significant.startsWith(cc) && significant.length > cc.length) {
            val national = significant.drop(cc.length).trimStart('0')
            if (national.isNotEmpty()) out += national.takeLast(TAIL_DIGITS)
        }
        return out
    }

    /**
     * A number written without a country code, shorter than [TAIL_DIGITS] once leading zeros are
     * dropped, while the SIM country is unknown: its ending cannot be compared with a contact saved
     * with its country code, so a miss in the index says nothing.
     */
    fun shortLocalWithoutCountry(number: String, countryCode: String? = PhoneRules.defaultCountryCode): Boolean {
        if (!countryCode.isNullOrEmpty()) return false
        val trimmed = number.trim()
        val digits = trimmed.filter { it in '0'..'9' }
        if (trimmed.startsWith("+") || digits.startsWith("00")) return false
        return digits.trimStart('0').length < TAIL_DIGITS
    }
}

/**
 * Contact number index for the number display rule, readable while the vault is locked (`:call`,
 * `:dialer` and the incoming screens of `:secure`). It holds, for every tail of a contact number
 * ([NumberTails]), `HMAC-SHA256(key, "DialCryptNumberIndex-v2" || 0 || tail)` cut to its first
 * [TAG_BITS] bits, and never a number. A number is a contact when any of its tails is in the index, so
 * the answer does not depend on how the number was written or on the SIM country when the index was
 * built. One case stays open: a local number shorter than eight digits that is not found while the SIM
 * country is unknown answers [ContactMembership.UNKNOWN], because the contact may be stored with its
 * country code. About 95 of the 100 million possible 8-digit tails share each 20-bit tag, so even the file
 * together with the key leaves about 95 candidate endings per tag; a stranger whose tail or tag
 * collides only shows masked.
 *
 * Layout: `"DCN2"` || key check (16 B) || N tags of 3 B, sorted, N a positive multiple of [BLOCK].
 * Random filler tags pad the real ones, so the size reveals the contact count only to the next [BLOCK].
 * The key check tells an index written under a lost or replaced key apart from a real miss.
 * `:secure` rebuilds the file whenever the unlocked contacts change and deletes it, with its key, on
 * every vault wipe. The file lives in credential-encrypted storage, so it cannot be read before the
 * first unlock after boot; [userUnlocked] is asked first and every lookup then answers
 * [ContactMembership.UNKNOWN] without touching the file.
 */
class ContactNumberIndex(
    private val file: File,
    private val key: NumberIndexKey,
    private val vaultExists: () -> Boolean,
    private val random: SecureRandom = SecureRandom(),
    private val userUnlocked: () -> Boolean = { true },
) {
    constructor(context: Context) : this(
        file = File(context.applicationContext.noBackupFilesDir, FILE_NAME),
        key = KeystoreNumberIndexKey(context.applicationContext),
        vaultExists = { File(context.applicationContext.noBackupFilesDir, VAULT_FILE_NAME).exists() },
        userUnlocked = { DirectBoot.isUserUnlocked(context.applicationContext) },
    ) {
        CoreProvider.initPhoneRules(context)
    }

    /**
     * One reading of the index file. Many numbers can be looked up against it: the file is read once,
     * the key is checked once and each tail is tagged once.
     */
    inner class Reader internal constructor(
        private val fixed: ContactMembership?,
        private val check: ByteArray?,
        private val tags: IntArray?,
    ) {
        private val tagByTail = HashMap<String, Int?>()
        private var keyMatches: Boolean? = null

        @Synchronized
        fun lookup(number: String?): ContactMembership {
            if (number.isNullOrBlank()) return ContactMembership.NOT_CONTACT
            fixed?.let { return it }
            val known = tags ?: return ContactMembership.UNKNOWN
            val tails = NumberTails.of(number)
            if (tails.isEmpty()) return ContactMembership.NOT_CONTACT
            val matches = keyMatches ?: run {
                val now = key.hmac(CHECK_INPUT)?.copyOf(CHECK_BYTES)
                (now != null && check != null && MessageDigest.isEqual(now, check)).also { keyMatches = it }
            }
            if (!matches) return ContactMembership.UNKNOWN
            var unknown = false
            for (tail in tails) {
                if (!tagByTail.containsKey(tail)) tagByTail[tail] = tagOf(tail)
                val tag = tagByTail[tail]
                if (tag == null) {
                    unknown = true
                } else if (Arrays.binarySearch(known, tag) >= 0) {
                    return ContactMembership.CONTACT
                }
            }
            return if (unknown || NumberTails.shortLocalWithoutCountry(number)) ContactMembership.UNKNOWN else ContactMembership.NOT_CONTACT
        }
    }

    /**
     * Reads the index file once. Without an index every number is [ContactMembership.NOT_CONTACT]
     * only while no vault exists; anything that cannot be read or checked is [ContactMembership.UNKNOWN].
     */
    fun open(): Reader {
        // Before the first unlock neither the index nor the vault can be seen; both would look absent.
        if (!userUnlocked()) return Reader(ContactMembership.UNKNOWN, null, null)
        if (!file.exists()) {
            return Reader(if (vaultExists()) ContactMembership.UNKNOWN else ContactMembership.NOT_CONTACT, null, null)
        }
        val raw = runCatching { file.readBytes() }.getOrNull() ?: return Reader(ContactMembership.UNKNOWN, null, null)
        val tags = parseTags(raw) ?: return Reader(ContactMembership.UNKNOWN, null, null)
        return Reader(null, raw.copyOfRange(MAGIC.size, HEADER_BYTES), tags)
    }

    /** Whether [number] is a contact number, from a fresh reading of the file. */
    fun lookup(number: String?): ContactMembership {
        if (number.isNullOrBlank()) return ContactMembership.NOT_CONTACT
        return open().lookup(number)
    }

    /**
     * Writes a fresh index for [numbers], the numbers of all contacts in the unlocked vault. On failure
     * the old file is removed, so lookups answer unknown (masked) until the next successful rebuild.
     */
    fun rebuild(numbers: Collection<String>): Boolean {
        if (!key.ensure()) return dropFile()
        val check = key.hmac(CHECK_INPUT)?.copyOf(CHECK_BYTES) ?: return dropFile()
        val real = HashSet<Int>()
        val tailsDone = HashSet<String>()
        for (n in numbers) {
            for (tail in NumberTails.of(n)) {
                if (!tailsDone.add(tail)) continue
                real += tagOf(tail) ?: return dropFile()
            }
        }
        val count = ((real.size + BLOCK - 1) / BLOCK).coerceAtLeast(1) * BLOCK
        val tags = IntArray(count)
        var i = 0
        for (t in real) tags[i++] = t
        while (i < count) tags[i++] = random.nextInt(TAG_SPACE)
        tags.sort()
        val body = ByteArray(count * TAG_BYTES)
        tags.forEachIndexed { idx, t ->
            body[idx * TAG_BYTES] = (t ushr 16).toByte()
            body[idx * TAG_BYTES + 1] = (t ushr 8).toByte()
            body[idx * TAG_BYTES + 2] = t.toByte()
        }
        return writeAtomic(check, body) || dropFile()
    }

    /** Vault wipe, duress and reset: cover and delete the file, then delete the key. */
    fun wipe(): Boolean {
        var ok = true
        if (file.exists()) {
            runCatching {
                val len = file.length().coerceIn(0L, MAX_BYTES.toLong()).toInt()
                if (len > 0) file.writeBytes(ByteArray(len).also { random.nextBytes(it) })
            }
            if (!file.delete()) ok = false
        }
        File(file.path + ".tmp").delete()
        return key.delete() && ok
    }

    private fun dropFile(): Boolean {
        file.delete()
        File(file.path + ".tmp").delete()
        return false
    }

    private fun tagOf(tail: String): Int? {
        val h = key.hmac(TAG_PREFIX + byteArrayOf(0) + tail.toByteArray(Charsets.US_ASCII)) ?: return null
        if (h.size < TAG_BYTES) return null
        return ((h[0].toInt() and 0xFF) shl 12) or ((h[1].toInt() and 0xFF) shl 4) or ((h[2].toInt() and 0xFF) ushr 4)
    }

    private fun parseTags(raw: ByteArray): IntArray? {
        if (raw.size < HEADER_BYTES + BLOCK * TAG_BYTES || raw.size > MAX_BYTES) return null
        if (!raw.copyOf(MAGIC.size).contentEquals(MAGIC)) return null
        val bodyBytes = raw.size - HEADER_BYTES
        if (bodyBytes % (BLOCK * TAG_BYTES) != 0) return null
        val tags = IntArray(bodyBytes / TAG_BYTES) { idx ->
            val off = HEADER_BYTES + idx * TAG_BYTES
            ((raw[off].toInt() and 0xFF) shl 16) or ((raw[off + 1].toInt() and 0xFF) shl 8) or (raw[off + 2].toInt() and 0xFF)
        }
        for (idx in tags.indices) {
            if (tags[idx] >= TAG_SPACE) return null
            if (idx > 0 && tags[idx] < tags[idx - 1]) return null
        }
        return tags
    }

    private fun writeAtomic(check: ByteArray, body: ByteArray): Boolean {
        val parent = file.absoluteFile.parentFile ?: return false
        val tmp = File(file.path + ".tmp")
        return try {
            if (!parent.isDirectory && !parent.mkdirs()) return false
            FileOutputStream(tmp).use { out ->
                out.write(MAGIC)
                out.write(check)
                out.write(body)
                out.fd.sync()
            }
            Files.move(tmp.toPath(), file.toPath(), StandardCopyOption.ATOMIC_MOVE)
            true
        } catch (e: Exception) {
            tmp.delete()
            false
        }
    }

    companion object {
        const val FILE_NAME = "number_index.bin"

        /**
         * Name of the vault file in noBackupFilesDir. Only its existence is checked here; the vault
         * class keeps its own copy of the name, and a test holds the two together.
         */
        const val VAULT_FILE_NAME = "vault.v2"
        const val TAG_BITS = 20
        const val TAG_SPACE = 1 shl TAG_BITS
        const val TAG_BYTES = 3
        const val BLOCK = 64
        const val CHECK_BYTES = 16
        private val MAGIC = "DCN2".toByteArray(Charsets.US_ASCII)
        val HEADER_BYTES = MAGIC.size + CHECK_BYTES

        /** Room for 10,000 contacts with two tails each; anything larger is not an index this app wrote. */
        private val MAX_BYTES = HEADER_BYTES + (20_000 / BLOCK + 1) * BLOCK * TAG_BYTES
        private val TAG_PREFIX = "DialCryptNumberIndex-v2".toByteArray(Charsets.US_ASCII)
        private val CHECK_INPUT = "DialCryptNumberIndexCheck-v2".toByteArray(Charsets.US_ASCII)
    }
}
