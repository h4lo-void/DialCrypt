package io.github.h4lovoid.dialcrypt.dialer

import android.content.Context
import io.github.h4lovoid.dialcrypt.core.DirectBoot
import java.io.File

/**
 * Empty file `noBackupFilesDir/secure_call_busy`, present while the secure flow owns a call. Other
 * processes read it to refuse a second, non-emergency call that would hold or end the secure call.
 * Before the first unlock after boot no secure call can exist, so the file is neither read nor written.
 */
internal object SecureBusyMarker {
    private const val FILE_NAME = "secure_call_busy"

    fun file(context: Context): File = File(context.applicationContext.noBackupFilesDir, FILE_NAME)

    fun set(context: Context, busy: Boolean) {
        if (!DirectBoot.isUserUnlocked(context)) return
        runCatching {
            val f = file(context)
            if (busy) {
                f.parentFile?.mkdirs()
                if (!f.exists()) f.createNewFile()
            } else if (f.exists()) {
                f.delete()
            }
        }
    }

    fun isSet(context: Context): Boolean =
        DirectBoot.isUserUnlocked(context) && runCatching { file(context).exists() }.getOrDefault(false)
}
