package io.github.h4lovoid.dialcrypt.call

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager

/**
 * Runtime permissions of the call link, granted at every boot by the module's service.sh with pm grant.
 * The privileged ones (READ_PRECISE_PHONE_STATE, MODIFY_PHONE_STATE, CALL_AUDIO_INTERCEPTION,
 * CAPTURE_AUDIO_OUTPUT) come from the privapp allowlist and are granted at install.
 * READ_CALL_LOG and WRITE_CALL_LOG ([CALL_LOG_ERASE]) only let [CallLogEraser] remove the system call
 * log entry of a call the app handled; without them calls work the same and the entry stays.
 */
object CallPermissions {
    val RUNTIME: List<String> = listOf(
        Manifest.permission.CALL_PHONE,
        Manifest.permission.READ_PHONE_STATE,
        Manifest.permission.ANSWER_PHONE_CALLS,
        Manifest.permission.READ_CALL_LOG,
        Manifest.permission.WRITE_CALL_LOG,
        Manifest.permission.RECORD_AUDIO,
    )

    /** Needed together by [CallLogEraser]. */
    val CALL_LOG_ERASE: List<String> = listOf(
        Manifest.permission.READ_CALL_LOG,
        Manifest.permission.WRITE_CALL_LOG,
    )

    fun missing(context: Context): List<String> =
        RUNTIME.filter { context.checkSelfPermission(it) != PackageManager.PERMISSION_GRANTED }
}
