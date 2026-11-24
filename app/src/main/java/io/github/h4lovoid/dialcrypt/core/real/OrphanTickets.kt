package io.github.h4lovoid.dialcrypt.core.real

import java.nio.ByteBuffer

/**
 * Tickets in the key store that the vault file on disk does not reference. A process killed
 * between importing new tickets and replacing the file, or between replacing the file and
 * retiring the old tickets, leaves them behind; no file can use them, but they would count as
 * attempts and take StrongBox key slots.
 */
internal object OrphanTickets {
    /** The nativeVaultTicketIds layout (big-endian u32 per id); null when the file did not parse. */
    fun parseIds(raw: ByteArray?): IntArray? {
        if (raw == null || raw.isEmpty() || raw.size % 4 != 0) return null
        val buf = ByteBuffer.wrap(raw)
        return IntArray(raw.size / 4) { buf.int }
    }

    /** Key-store tickets ([live]) to retire: those not in [fileIds]. None when the file's ids are unknown. */
    fun toRetire(fileIds: IntArray?, live: IntArray): IntArray {
        if (fileIds == null || fileIds.isEmpty()) return IntArray(0)
        return live.filter { it !in fileIds }.toIntArray()
    }
}
