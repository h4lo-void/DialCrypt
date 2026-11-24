package io.github.h4lovoid.dialcrypt.core.real

import io.github.h4lovoid.dialcrypt.core.BiometricState
import java.io.File
import java.io.IOException
import java.nio.ByteBuffer
import java.security.MessageDigest

/**
 * Formats and rules of fingerprint answer (pure; the files are handled by [BiometricFiles]).
 *
 * Wrapped stretch `bio_answer.bin` (97 B): `"ABIO" · ver u8 = 1 · binding 32 · iv 12 · ct+tag 48`,
 * AES-256-GCM under the StrongBox key `aegis_bio_v1` with AAD `"AegisBio-v1" · ver · binding`.
 * The plaintext is the 32-byte Argon2id stretch P of the normal PIN; binding is the vault's
 * nativeVaultStretchBinding, so a P of another vault is refused before a ticket is spent.
 *
 * Freshness stamp `bio_fresh.bin` (13 B): `ver u8 = 1 · boot count u32 · elapsedRealtime ms u64`,
 * written only by a PIN unlock. A fingerprint may stand in for the PIN only in the same boot and
 * less than [FRESH_FOR_MS] after it.
 */
internal object BiometricStore {
    const val VERSION = 1
    const val BINDING_LEN = 32
    const val IV_LEN = 12
    const val STRETCH_LEN = 32
    const val CT_LEN = STRETCH_LEN + 16
    const val WRAP_LEN = 4 + 1 + BINDING_LEN + IV_LEN + CT_LEN
    const val STAMP_LEN = 1 + 4 + 8
    const val FRESH_FOR_MS = 12L * 60 * 60 * 1000
    /** The PIN stretch kept to turn the feature on is dropped after this long. */
    const val HELD_FOR_MS = 60_000L

    /** BiometricPrompt error codes after which no "Use fingerprint" retry is offered. */
    const val ERROR_LOCKOUT = 7
    const val ERROR_LOCKOUT_PERMANENT = 9

    private val MAGIC = "ABIO".toByteArray(Charsets.US_ASCII)
    private val AAD_LABEL = "AegisBio-v1".toByteArray(Charsets.US_ASCII)

    class Wrapped(val binding: ByteArray, val iv: ByteArray, val ct: ByteArray)

    data class Stamp(val bootCount: Int, val elapsedMs: Long)

    fun aad(binding: ByteArray): ByteArray = AAD_LABEL + byteArrayOf(VERSION.toByte()) + binding

    /**
     * The wrapped stretch belongs to the vault whose current binding is [binding]. A PIN change
     * draws a new salt and so a new binding: a wrap of the old PIN fails here, before a ticket is spent.
     */
    fun sameVault(w: Wrapped, binding: ByteArray): Boolean =
        binding.size == BINDING_LEN && MessageDigest.isEqual(w.binding, binding)

    fun encodeWrapped(w: Wrapped): ByteArray? {
        if (w.binding.size != BINDING_LEN || w.iv.size != IV_LEN || w.ct.size != CT_LEN) return null
        return MAGIC + byteArrayOf(VERSION.toByte()) + w.binding + w.iv + w.ct
    }

    fun parseWrapped(b: ByteArray?): Wrapped? {
        if (b == null || b.size != WRAP_LEN) return null
        if (!b.copyOfRange(0, 4).contentEquals(MAGIC) || b[4].toInt() != VERSION) return null
        var off = 5
        val binding = b.copyOfRange(off, off + BINDING_LEN).also { off += BINDING_LEN }
        val iv = b.copyOfRange(off, off + IV_LEN).also { off += IV_LEN }
        return Wrapped(binding, iv, b.copyOfRange(off, off + CT_LEN))
    }

    fun encodeStamp(s: Stamp): ByteArray =
        ByteBuffer.allocate(STAMP_LEN).put(VERSION.toByte()).putInt(s.bootCount).putLong(s.elapsedMs).array()

    fun parseStamp(b: ByteArray?): Stamp? {
        if (b == null || b.size != STAMP_LEN || b[0].toInt() != VERSION) return null
        val buf = ByteBuffer.wrap(b, 1, STAMP_LEN - 1)
        val boot = buf.int
        val at = buf.long
        return if (at < 0) null else Stamp(boot, at)
    }

    /** The last PIN unlock was in this boot and less than [FRESH_FOR_MS] ago. Unknown boot count: not fresh. */
    fun isFresh(stamp: Stamp?, bootCount: Int?, nowElapsedMs: Long): Boolean {
        if (stamp == null || bootCount == null || stamp.bootCount != bootCount) return false
        val age = nowElapsedMs - stamp.elapsedMs
        return age in 0 until FRESH_FOR_MS
    }

    /** State shown for the files on disk; INVALIDATED and UNAVAILABLE outlive an empty disk until the next change. */
    fun state(wrapped: Boolean, fresh: Boolean, previous: BiometricState): BiometricState = when {
        wrapped && fresh -> BiometricState.READY
        wrapped -> BiometricState.NEEDS_PIN
        previous == BiometricState.INVALIDATED || previous == BiometricState.UNAVAILABLE -> previous
        else -> BiometricState.OFF
    }

    /** Whether the unlock screen offers "Use fingerprint" again after the prompt ended with [errorCode]. */
    fun retryAllowed(errorCode: Int): Boolean = errorCode != ERROR_LOCKOUT && errorCode != ERROR_LOCKOUT_PERMANENT
}

/** `bio_answer.bin` and `bio_fresh.bin` in noBackupFilesDir. */
internal class BiometricFiles(dir: File) {
    private val wrap = VaultFile(File(dir, WRAP_FILE))
    private val stamp = VaultFile(File(dir, STAMP_FILE))

    fun readWrapped(): BiometricStore.Wrapped? = BiometricStore.parseWrapped(readQuietly(wrap))

    fun hasWrapped(): Boolean = readWrapped() != null

    fun writeWrapped(w: BiometricStore.Wrapped): Boolean = BiometricStore.encodeWrapped(w)?.let(wrap::write) ?: false

    fun readStamp(): BiometricStore.Stamp? = BiometricStore.parseStamp(readQuietly(stamp))

    fun writeStamp(s: BiometricStore.Stamp): Boolean = stamp.write(BiometricStore.encodeStamp(s))

    fun deleteStamp(): Boolean = stamp.destroy()

    /** Both files; true when neither is left. */
    fun deleteAll(): Boolean {
        val a = wrap.destroy()
        val b = stamp.destroy()
        return a && b
    }

    private fun readQuietly(f: VaultFile): ByteArray? = try {
        f.read()
    } catch (e: IOException) {
        null
    }

    companion object {
        const val WRAP_FILE = "bio_answer.bin"
        const val STAMP_FILE = "bio_fresh.bin"
    }
}

/**
 * What one unlock result does to fingerprint answer. Only a normal unlock by PIN (not the
 * emergency PIN, not a fingerprint) stamps freshness, and only while the feature is on or being
 * turned on; only such an unlock while turning it on hands back the stretch to wrap. A wrong PIN
 * or the emergency PIN deletes the stamp, so the next unlock needs the PIN.
 */
internal class UnlockBioEffects(
    private val files: BiometricFiles,
    private val bootCount: () -> Int?,
    private val elapsedMs: () -> Long,
) {
    /** Before the ticket is used: whether a copy of P may be taken at all. */
    fun mayKeep(viaPin: Boolean, enrolling: Boolean): Boolean = viaPin && enrolling

    /**
     * After nativePinFinish returned [rc]. [kept] is the copy of P taken when [mayKeep] allowed
     * it; it comes back only for a normal PIN unlock while enrolling, otherwise it is wiped here.
     */
    fun afterUnlock(rc: Int, viaPin: Boolean, enrolling: Boolean, featureOn: Boolean, kept: ByteArray?): ByteArray? {
        val normalByPin = rc == NativeCode.UNLOCK_NORMAL && viaPin
        if (normalByPin && (enrolling || featureOn)) {
            val stamp = bootCount()?.let { BiometricStore.Stamp(it, elapsedMs()) }
            if (stamp == null || !files.writeStamp(stamp)) runCatching { android.util.Log.w("AegisBio", "freshness not written") }
        } else if (rc == NativeCode.UNLOCK_WRONG || rc == NativeCode.UNLOCK_DURESS) {
            if (!files.deleteStamp()) runCatching { android.util.Log.w("AegisBio", "freshness not deleted") }
        }
        if (normalByPin && enrolling && kept != null) return kept
        kept?.fill(0)
        return null
    }
}
