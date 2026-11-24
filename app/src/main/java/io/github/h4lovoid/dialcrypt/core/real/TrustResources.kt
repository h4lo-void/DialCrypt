package io.github.h4lovoid.dialcrypt.core.real

import android.content.Context
import android.content.res.Resources
import android.util.Log
import java.io.IOException

/**
 * The five res/raw files of design E2. Formats:
 * attestation_roots.der: one or more DER certificates, concatenated.
 * attestation_revoked.txt, avb_keys.txt, app_signers.txt: one hex value per line (serial number,
 * verifiedBootKey, SHA-256 of an app signing certificate); spaces and ':' are ignored, '#' starts
 * a comment. The first two may hold no value; app_signers needs at least one.
 * min_patch.txt: minimum osPatchLevel as decimal YYYYMM.
 */
internal object TrustConfigBuilder {
    fun build(rootsDer: ByteArray, revoked: String, avbKeys: String, appSigners: String, minPatch: String): ByteArray? {
        val roots = DerSplit.certificates(rootsDer) ?: return null
        val serials = HexLines.parse(revoked) ?: return null
        val avb = HexLines.parse(avbKeys) ?: return null
        val signers = HexLines.parse(appSigners) ?: return null
        val patch = minPatch.lineSequence()
            .map { it.substringBefore('#').trim() }
            .filter { it.isNotEmpty() }
            .toList()
            .singleOrNull()
            ?.toLongOrNull() ?: return null
        return TrustTlv.encode(roots, serials, avb, signers, patch)
    }
}

/** Splits concatenated DER SEQUENCEs (definite lengths only). */
internal object DerSplit {
    fun certificates(data: ByteArray): List<ByteArray>? {
        if (data.isEmpty()) return null
        val out = ArrayList<ByteArray>()
        var pos = 0
        while (pos < data.size) {
            if (data[pos].toInt() and 0xFF != 0x30 || pos + 1 >= data.size) return null
            val first = data[pos + 1].toInt() and 0xFF
            var header = 2
            val len: Int
            if (first < 0x80) {
                len = first
            } else {
                val n = first and 0x7F
                if (n == 0 || n > 3 || pos + 2 + n > data.size) return null
                var v = 0
                for (i in 0 until n) v = (v shl 8) or (data[pos + 2 + i].toInt() and 0xFF)
                header += n
                len = v
            }
            val end = pos + header + len
            if (len <= 0 || end > data.size) return null
            out += data.copyOfRange(pos, end)
            pos = end
        }
        return out
    }
}

internal object HexLines {
    fun parse(text: String): List<ByteArray>? {
        val out = ArrayList<ByteArray>()
        for (line in text.lineSequence()) {
            val clean = line.substringBefore('#').filter { !it.isWhitespace() && it != ':' }
            if (clean.isEmpty()) continue
            val hex = if (clean.length % 2 == 1) "0$clean" else clean
            val bytes = ByteArray(hex.length / 2)
            for (i in bytes.indices) {
                val hi = Character.digit(hex[2 * i], 16)
                val lo = Character.digit(hex[2 * i + 1], 16)
                if (hi < 0 || lo < 0) return null
                bytes[i] = ((hi shl 4) or lo).toByte()
            }
            out += bytes
        }
        return out
    }
}

/** Reads the five files from res/raw of the running app. */
internal object TrustResourceLoader {
    private const val TAG = "AegisCore"
    private const val ROOTS = "attestation_roots"
    private const val REVOKED = "attestation_revoked"
    private const val AVB = "avb_keys"
    private const val SIGNERS = "app_signers"
    private const val PATCH = "min_patch"
    private val FILES = listOf(ROOTS, REVOKED, AVB, SIGNERS, PATCH)

    /** Package of the generated R class; the application id may differ from it. To be confirmed on device: which of the two getIdentifier resolves in the APK. */
    private const val NAMESPACE = "io.github.h4lovoid.dialcrypt"

    /** Trust TLV, or null when a file is missing or malformed (the core then refuses to start). */
    fun load(context: Context): ByteArray? {
        val raw = HashMap<String, ByteArray>()
        val missing = ArrayList<String>()
        for (name in FILES) {
            val id = listOf(context.packageName, NAMESPACE)
                .map { context.resources.getIdentifier(name, "raw", it) }
                .firstOrNull { it != 0 }
            if (id == null) {
                missing += name
                continue
            }
            try {
                raw[name] = context.resources.openRawResource(id).use { it.readBytes() }
            } catch (e: IOException) {
                missing += name
            } catch (e: Resources.NotFoundException) {
                missing += name
            }
        }
        if (missing.isNotEmpty()) {
            Log.e(TAG, "trust resources missing in res/raw: " + missing.joinToString())
            return null
        }
        val tlv = TrustConfigBuilder.build(
            rootsDer = raw.getValue(ROOTS),
            revoked = raw.getValue(REVOKED).toString(Charsets.UTF_8),
            avbKeys = raw.getValue(AVB).toString(Charsets.UTF_8),
            appSigners = raw.getValue(SIGNERS).toString(Charsets.UTF_8),
            minPatch = raw.getValue(PATCH).toString(Charsets.UTF_8),
        )
        if (tlv == null) Log.e(TAG, "trust resources malformed")
        return tlv
    }
}
