package io.github.h4lovoid.dialcrypt.incoming.screen

import android.content.Context
import io.github.h4lovoid.dialcrypt.core.CoreProvider
import io.github.h4lovoid.dialcrypt.core.PhoneRules
import java.io.File
import java.io.FileOutputStream
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * Fixed-size (32,004 B) contact screening table (`"ASC1"` + 1000 x `(linkTag 16B || screenTag 16B)`).
 * Unused slots hold random bytes so reading the file reveals neither contact count nor numbers.
 * `:secure` writes on unlock/save/update/delete; `:call` reads while locked.
 */
class ScreeningStore(
    private val file: File,
    private val mac: (ByteArray) -> ByteArray?,
    private val deleteKey: () -> Boolean = { StrongBoxScreeningKey.delete() },
    private val modeFile: File? = null,
    private val random: SecureRandom = SecureRandom(),
) {
    constructor(context: Context) : this(
        file = File(context.applicationContext.noBackupFilesDir, FILE_NAME),
        mac = { input -> StrongBoxScreeningKey.hmac(context.applicationContext, input) },
        deleteKey = { StrongBoxScreeningKey.delete() },
        modeFile = IncomingSettings.file(context.applicationContext),
    ) {
        CoreProvider.initPhoneRules(context)
    }

    fun matches(number: String?): Boolean {
        if (number.isNullOrBlank()) return false
        val candidates = PhoneRules.matchCandidates(number)
        if (candidates.isEmpty()) return false
        val table = readSlotsOrNull() ?: return false
        val wantTags = candidates.mapNotNull { screenTag(it) }
        if (wantTags.isEmpty()) return false
        var matched = false
        for (i in 0 until SLOTS) {
            val slotScreen = table.copyOfRange(i * SLOT_BYTES + TAG_BYTES, (i + 1) * SLOT_BYTES)
            for (want in wantTags) {
                if (MessageDigest.isEqual(slotScreen, want)) matched = true
            }
        }
        return matched
    }

    /** Adds or updates a single `(phoneTag, rawNumber)` entry while keeping all existing entries. */
    fun put(phoneTag: ByteArray, number: String): Boolean {
        if (phoneTag.size != TAG_BYTES) return false
        val e164 = PhoneRules.toVaultE164(number) ?: return false
        val lTag = linkTag(phoneTag) ?: return false
        val sTag = screenTag(e164) ?: return false
        val table = readSlotsOrNull() ?: randomTable()
        var existingSlot = -1
        for (i in 0 until SLOTS) {
            val slotLink = table.copyOfRange(i * SLOT_BYTES, i * SLOT_BYTES + TAG_BYTES)
            if (MessageDigest.isEqual(slotLink, lTag)) {
                existingSlot = i
                break
            }
        }
        val targetSlot = if (existingSlot >= 0) existingSlot else random.nextInt(SLOTS)
        lTag.copyInto(table, targetSlot * SLOT_BYTES)
        sTag.copyInto(table, targetSlot * SLOT_BYTES + TAG_BYTES)
        return writeAtomic(table)
    }

    /**
     * Reconciles the file with the current unlocked contacts (`phoneTag` -> optional confirmed number):
     * removes slots whose `phoneTag` no longer exists (overwriting with random bytes), updates
     * entries with known numbers, and preserves existing `screenTag` when only `phoneTag` is known.
     */
    fun reconcile(entries: List<Pair<ByteArray, String?>>): Boolean {
        val table = readSlotsOrNull() ?: randomTable()
        val wanted = entries.mapNotNull { (pt, num) ->
            if (pt.size != TAG_BYTES) return@mapNotNull null
            val lt = linkTag(pt) ?: return@mapNotNull null
            val st = num?.let { PhoneRules.toVaultE164(it) }?.let { screenTag(it) }
            Triple(lt, st, num != null)
        }
        val matchedWanted = BooleanArray(wanted.size)
        val freeSlots = ArrayList<Int>(SLOTS)
        for (i in 0 until SLOTS) {
            val off = i * SLOT_BYTES
            val slotLink = table.copyOfRange(off, off + TAG_BYTES)
            val idx = wanted.indexOfFirst { (lt, _, _) -> MessageDigest.isEqual(slotLink, lt) }
            if (idx >= 0) {
                matchedWanted[idx] = true
                wanted[idx].second?.copyInto(table, off + TAG_BYTES)
            } else {
                val filler = ByteArray(SLOT_BYTES).also { random.nextBytes(it) }
                filler.copyInto(table, off)
                freeSlots += i
            }
        }
        for (idx in wanted.indices) {
            if (matchedWanted[idx]) continue
            val (_, st, _) = wanted[idx]
            if (st == null || freeSlots.isEmpty()) continue
            val pick = freeSlots.removeAt(random.nextInt(freeSlots.size))
            wanted[idx].first.copyInto(table, pick * SLOT_BYTES)
            st.copyInto(table, pick * SLOT_BYTES + TAG_BYTES)
        }
        return writeAtomic(table)
    }

    fun wipe(): Boolean {
        var ok = true
        if (file.exists()) {
            runCatching {
                val len = file.length().coerceIn(0L, TOTAL_BYTES.toLong()).toInt()
                if (len > 0) file.writeBytes(ByteArray(len).also { random.nextBytes(it) })
            }
            if (!file.delete()) ok = false
        }
        File(file.path + ".tmp").delete()
        modeFile?.let { mf ->
            if (mf.exists()) {
                runCatching { mf.writeBytes(byteArrayOf(0)) }
                if (!mf.delete()) ok = false
            }
        }
        ok = deleteKey() && ok
        return ok
    }

    private fun screenTag(e164: String): ByteArray? =
        mac(SCREEN_PREFIX + byteArrayOf(0) + e164.toByteArray(Charsets.US_ASCII))?.copyOf(TAG_BYTES)

    private fun linkTag(phoneTag: ByteArray): ByteArray? =
        mac(LINK_PREFIX + byteArrayOf(0) + phoneTag)?.copyOf(TAG_BYTES)

    private fun randomTable(): ByteArray = ByteArray(SLOTS * SLOT_BYTES).also { random.nextBytes(it) }

    private fun readSlotsOrNull(): ByteArray? {
        if (!file.exists()) return null
        val raw = runCatching { file.readBytes() }.getOrNull() ?: return null
        if (raw.size != TOTAL_BYTES) return null
        if (!raw.copyOf(4).contentEquals(MAGIC)) return null
        return raw.copyOfRange(4, raw.size)
    }

    private fun writeAtomic(slots: ByteArray): Boolean {
        if (slots.size != SLOTS * SLOT_BYTES) return false
        val parent = file.absoluteFile.parentFile ?: return false
        val tmp = File(file.path + ".tmp")
        return try {
            if (!parent.isDirectory && !parent.mkdirs()) return false
            FileOutputStream(tmp).use { out ->
                out.write(MAGIC)
                out.write(slots)
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
        const val FILE_NAME = "screen.bin"
        const val SLOTS = 1000
        const val TAG_BYTES = 16
        const val SLOT_BYTES = TAG_BYTES * 2
        const val TOTAL_BYTES = 4 + SLOTS * SLOT_BYTES
        private val MAGIC = "ASC1".toByteArray(Charsets.US_ASCII)
        private val SCREEN_PREFIX = "AegisScreen-v1".toByteArray(Charsets.US_ASCII)
        private val LINK_PREFIX = "AegisScreenLink-v1".toByteArray(Charsets.US_ASCII)
    }
}
