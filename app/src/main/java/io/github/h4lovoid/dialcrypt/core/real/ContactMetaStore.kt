package io.github.h4lovoid.dialcrypt.core.real

import android.util.Log
import java.io.File
import java.nio.ByteBuffer
import java.security.SecureRandom

/**
 * Sidecar metadata (`noBackupFilesDir/contact_meta.bin`) holding the persistent 32-byte pairing
 * seed, confirmed display/dial phone numbers keyed by contact id and the ids of contacts known to
 * have saved us too (mutual pairing).
 * The native vault stores only `phone_tag` (one-way HMAC) and no plaintext phone numbers.
 * The pairing seed is secret: the native side derives our static X25519 pairing key from it.
 *
 * [seal] and [open] use the meta key inside the unlocked native vault (nativeMetaSeal and
 * nativeMetaOpen), so this data needs the app PIN. While [isUnlocked] is false every read returns
 * null or false, every write returns false and the memory holds no seed, number or mark. The file
 * is loaded once per unlock; a file the unlocked vault cannot open (another key or format) or whose
 * plaintext is malformed is deleted and the store starts empty.
 *
 * Plaintext: `"ACMD" · version u8 · seed 32 B · count u16 · per number: id u64 · len u8 · UTF-8 ·
 * [version 2 and later: mutualCount u16 · per mutual contact: id u64]`. Version 1 files have no
 * mutual section and load with none marked. Version 1 and 2 seeds were printed in every pairing
 * code, so loading such a file keeps its numbers and marks, replaces the seed and rewrites the file
 * at once; every write uses version 3.
 */
internal class ContactMetaStore(
    private val file: File,
    private val seal: (ByteArray) -> ByteArray?,
    private val open: (ByteArray) -> ByteArray?,
    private val isUnlocked: () -> Boolean,
    private val random: SecureRandom = SecureRandom(),
) {
    private val lock = Any()
    private val vaultFile = VaultFile(file)
    /** The file was read since the last unlock. */
    private var loaded = false
    private var pairingSeed: ByteArray? = null
    /** [pairingSeed] is the one in the file (read from it or written since). */
    private var seedSaved = false
    private val numbers = LinkedHashMap<Long, String>()
    private val mutualIds = LinkedHashSet<Long>()

    /**
     * Null while locked, or when no seed could be written: a seed that is not in the file would
     * give a pairing key that is gone after the next unlock.
     */
    fun loadOrInitSeed(): ByteArray? = synchronized(lock) {
        if (!readyLocked()) return null
        val seed = pairingSeed ?: newSeed().also { pairingSeed = it }
        if (!seedSaved && !persistLocked()) {
            runCatching { Log.w(TAG, "pairing seed not persisted") }
            return null
        }
        seed.copyOf()
    }

    /**
     * Writes a new seed, then hands it to [apply] (the native pairing key). Null while locked, when
     * the write fails, or when [apply] refuses it: the old seed is then written back and stays.
     */
    fun rotateSeed(apply: (ByteArray) -> Boolean = { true }): ByteArray? = synchronized(lock) {
        if (!readyLocked()) return null
        val fresh = newSeed()
        if (!writeLocked(fresh)) {
            fresh.fill(0)
            return null
        }
        val applied = try {
            apply(fresh)
        } catch (e: Exception) {
            false
        }
        if (!applied) {
            fresh.fill(0)
            // The file holds the new seed now: put back the one still in use.
            val old = pairingSeed
            seedSaved = old != null && writeLocked(old)
            if (!seedSaved) runCatching { Log.w(TAG, "previous pairing seed not written back") }
            return null
        }
        pairingSeed?.fill(0)
        pairingSeed = fresh
        seedSaved = true
        fresh.copyOf()
    }

    /** Null while locked. */
    fun numberFor(contactId: Long): String? = synchronized(lock) {
        if (readyLocked()) numbers[contactId] else null
    }

    /** False while locked. */
    fun isMutual(contactId: Long): Boolean = synchronized(lock) {
        readyLocked() && contactId in mutualIds
    }

    /** Records whether both sides are known to hold this contact's pairing. False when it could not be saved or the vault is locked. */
    fun setMutual(contactId: Long, mutual: Boolean): Boolean = synchronized(lock) {
        if (!readyLocked()) return false
        if (pairingSeed == null) pairingSeed = newSeed()
        val changed = if (mutual) mutualIds.add(contactId) else mutualIds.remove(contactId)
        if (changed) persistLocked() else true
    }

    /** False when the number could not be saved or the vault is locked. */
    fun setNumber(contactId: Long, number: String?): Boolean = synchronized(lock) {
        if (!readyLocked()) return false
        if (pairingSeed == null) pairingSeed = newSeed()
        if (number.isNullOrBlank()) {
            numbers.remove(contactId)
        } else {
            numbers[contactId] = number.trim()
        }
        persistLocked()
    }

    fun retainContacts(activeIds: Set<Long>) = synchronized(lock) {
        if (!readyLocked() || pairingSeed == null) return@synchronized
        val removedNumbers = numbers.keys.retainAll(activeIds)
        val removedMutual = mutualIds.retainAll(activeIds)
        if (removedNumbers || removedMutual) persistLocked()
    }

    /** Forgets everything in memory; the next use after an unlock reads the file again. */
    fun clearMemory() = synchronized(lock) {
        clearMemoryLocked()
    }

    /** Deletes the file; works while locked. */
    fun wipe(): Boolean = synchronized(lock) {
        clearMemoryLocked()
        vaultFile.destroy()
    }

    private fun newSeed() = ByteArray(SEED_LEN).also { random.nextBytes(it) }

    private fun clearMemoryLocked() {
        pairingSeed?.fill(0)
        pairingSeed = null
        seedSaved = false
        numbers.clear()
        mutualIds.clear()
        loaded = false
    }

    /** True when the vault is unlocked and the file has been read. While locked the memory is cleared. */
    private fun readyLocked(): Boolean {
        if (!isUnlocked()) {
            clearMemoryLocked()
            return false
        }
        if (!loaded) loaded = loadFromDiskLocked()
        return loaded
    }

    /** False only when the vault locked while the file was being opened; nothing is kept then. */
    private fun loadFromDiskLocked(): Boolean {
        val raw = runCatching { vaultFile.read() }.getOrNull() ?: return true
        val pt = try {
            open(raw)
        } finally {
            raw.fill(0)
        }
        if (pt == null) {
            if (!isUnlocked()) return false
            discardUnreadableLocked("metadata file does not open with this vault")
            return true
        }
        val parsed = try {
            parsePlaintext(pt)
        } finally {
            pt.fill(0)
        }
        if (!parsed) {
            discardUnreadableLocked("metadata file malformed")
        } else if (!seedSaved && !persistLocked()) {
            runCatching { Log.w(TAG, "metadata file with a replaced seed not rewritten") }
        }
        return true
    }

    private fun discardUnreadableLocked(reason: String) {
        runCatching { Log.w(TAG, "$reason; starting empty") }
        if (!vaultFile.destroy()) runCatching { Log.w(TAG, "unreadable metadata file not deleted") }
    }

    /** False for a malformed plaintext, which leaves the memory unchanged. A seed older than [VERSION] is replaced. */
    private fun parsePlaintext(pt: ByteArray): Boolean {
        if (pt.size < 4 + 1 + SEED_LEN + 2) return false
        if (pt[0] != MAGIC[0] || pt[1] != MAGIC[1] || pt[2] != MAGIC[2] || pt[3] != MAGIC[3]) return false
        val version = pt[4].toInt() and 0xFF
        if (version < VERSION_NUMBERS_ONLY || version > VERSION) return false
        val buf = ByteBuffer.wrap(pt)
        buf.position(5)
        val seed = ByteArray(SEED_LEN)
        buf.get(seed)
        val count = buf.short.toInt() and 0xFFFF
        val loadedNumbers = LinkedHashMap<Long, String>(count)
        repeat(count) {
            if (buf.remaining() < 9) {
                seed.fill(0)
                return false
            }
            val id = buf.long
            val len = buf.get().toInt() and 0xFF
            if (buf.remaining() < len) {
                seed.fill(0)
                return false
            }
            val numBytes = ByteArray(len)
            buf.get(numBytes)
            val s = numBytes.toString(Charsets.UTF_8)
            numBytes.fill(0)
            if (id > 0 && s.isNotBlank()) loadedNumbers[id] = s
        }
        val loadedMutual = LinkedHashSet<Long>()
        if (version >= VERSION_MUTUAL) {
            if (buf.remaining() < 2) {
                seed.fill(0)
                return false
            }
            val mutualCount = buf.short.toInt() and 0xFFFF
            if (buf.remaining() < mutualCount * 8) {
                seed.fill(0)
                return false
            }
            repeat(mutualCount) {
                val id = buf.long
                if (id > 0) loadedMutual += id
            }
        }
        if (buf.hasRemaining()) {
            seed.fill(0)
            return false
        }
        pairingSeed?.fill(0)
        if (version >= VERSION) {
            pairingSeed = seed
            seedSaved = true
        } else {
            seed.fill(0)
            pairingSeed = newSeed()
            seedSaved = false
        }
        numbers.clear()
        numbers.putAll(loadedNumbers)
        mutualIds.clear()
        mutualIds.addAll(loadedMutual)
        return true
    }

    private fun persistLocked(): Boolean {
        val seed = pairingSeed ?: return false
        val written = writeLocked(seed)
        if (written) seedSaved = true
        return written
    }

    private fun writeLocked(seed: ByteArray): Boolean {
        // One array of the exact size, wiped after sealing: no growing buffer leaves a copy of the seed behind.
        val entries = numbers.entries.mapNotNull { (id, num) ->
            num.toByteArray(Charsets.UTF_8).takeIf { it.size <= 255 }?.let { id to it }
        }
        val mutual = mutualIds.toList()
        val size = MAGIC.size + 1 + SEED_LEN + 2 + entries.sumOf { 8 + 1 + it.second.size } + 2 + 8 * mutual.size
        val pt = ByteArray(size)
        val buf = ByteBuffer.wrap(pt)
        buf.put(MAGIC).put(VERSION.toByte()).put(seed)
        buf.putShort(entries.size.toShort())
        for ((id, nb) in entries) {
            buf.putLong(id).put(nb.size.toByte()).put(nb)
            nb.fill(0)
        }
        buf.putShort(mutual.size.toShort())
        for (id in mutual) buf.putLong(id)
        val ct = try {
            seal(pt)
        } finally {
            pt.fill(0)
        } ?: return false
        return try {
            vaultFile.write(ct)
        } finally {
            ct.fill(0)
        }
    }

    private companion object {
        const val TAG = "AegisMeta"
        const val SEED_LEN = 32
        /** Seed and numbers only; read once and rewritten as [VERSION]. */
        const val VERSION_NUMBERS_ONLY = 1
        /** First version with the mutual section. */
        const val VERSION_MUTUAL = 2
        /** The seed is the pairing key's; older seeds were public and are replaced on load. */
        const val VERSION = 3
        val MAGIC = byteArrayOf('A'.code.toByte(), 'C'.code.toByte(), 'M'.code.toByte(), 'D'.code.toByte())
    }
}
