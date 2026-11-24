package io.github.h4lovoid.dialcrypt.incoming.screen

import android.content.Context
import io.github.h4lovoid.dialcrypt.core.DirectBoot
import java.io.File

/**
 * Mirror of the "show full numbers of contacts" preference in `noBackupFilesDir/show_full_numbers`
 * (one byte, 1 = whole numbers), so `:call` and `:dialer` can read it without `:secure`.
 * A missing or damaged file reads as false: contact numbers stay masked. So does the time before the
 * first unlock after boot, when the file cannot be read.
 */
object DisplaySettings {
    private const val FILE_NAME = "show_full_numbers"
    private const val SHOW: Byte = 1
    private const val MASK: Byte = 0

    fun file(context: Context): File = File(context.applicationContext.noBackupFilesDir, FILE_NAME)

    fun read(context: Context): Boolean = DirectBoot.isUserUnlocked(context) && read(file(context))

    fun read(file: File): Boolean = runCatching {
        if (!file.exists()) return false
        val bytes = file.readBytes()
        bytes.size == 1 && bytes[0] == SHOW
    }.getOrDefault(false)

    fun write(context: Context, showFull: Boolean): Boolean = write(file(context), showFull)

    fun write(file: File, showFull: Boolean): Boolean = runCatching {
        file.parentFile?.mkdirs()
        file.writeBytes(byteArrayOf(if (showFull) SHOW else MASK))
        true
    }.getOrDefault(false)
}
