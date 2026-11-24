package io.github.h4lovoid.dialcrypt.incoming.screen

import android.content.Context
import java.io.File

enum class IncomingMode(val code: Byte) {
    CONTACTS(1),
    ALL(2),
    OFF(3),
    ;

    companion object {
        fun fromCode(b: Byte): IncomingMode = entries.firstOrNull { it.code == b } ?: CONTACTS
    }
}

/**
 * Non-secret incoming-call screening preference stored in `noBackupFilesDir/incoming_mode`
 * so `:call` can read it on every incoming ring without touching `:secure` or the vault.
 */
object IncomingSettings {
    private const val FILE_NAME = "incoming_mode"

    fun file(context: Context): File = File(context.applicationContext.noBackupFilesDir, FILE_NAME)

    fun read(context: Context): IncomingMode = read(file(context))

    fun read(file: File): IncomingMode = runCatching {
        if (!file.exists()) return IncomingMode.CONTACTS
        val bytes = file.readBytes()
        if (bytes.size != 1) IncomingMode.CONTACTS else IncomingMode.fromCode(bytes[0])
    }.getOrDefault(IncomingMode.CONTACTS)

    fun write(context: Context, mode: IncomingMode): Boolean = write(file(context), mode)

    fun write(file: File, mode: IncomingMode): Boolean = runCatching {
        file.parentFile?.mkdirs()
        file.writeBytes(byteArrayOf(mode.code))
        true
    }.getOrDefault(false)
}
