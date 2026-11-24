package io.github.h4lovoid.dialcrypt.call

import android.app.Application
import android.app.ActivityManager
import android.content.Context
import android.media.AudioManager
import android.os.Build
import android.util.Log
import io.github.h4lovoid.dialcrypt.BuildConfig
import io.github.h4lovoid.dialcrypt.core.DirectBoot
import java.io.File

/**
 * Field-test builds only (AEGIS_FIELD_TEST=1): switches read from <filesDir>/fieldtest/<name>,
 * used to measure what each part of the silent data mode does to the call audio. Always false
 * in other builds.
 */
internal object FieldTestAudio {
    fun flag(name: String): Boolean {
        if (!BuildConfig.FIELD_TEST_LINK_PROBE) return false
        return runCatching { File("/data/data/" + BuildConfig.APPLICATION_ID + "/files/fieldtest", name).isFile }.getOrDefault(false)
    }
}

/**
 * Silent data mode of a call: the microphone is muted so it cannot reach the uplink, and the
 * voice call stream is turned down and muted so the modem downlink stays off the earpiece and
 * speaker. The previous microphone mute and call volume are restored on [release].
 * Muting STREAM_VOICE_CALL needs MODIFY_PHONE_STATE.
 *
 * The microphone mute is phone-wide and outlives this process, so [engage] first writes the values
 * to restore into [journal] and [release] deletes it. A journal still there when the process starts
 * again means a call was cut off by a crash or kill; [recoverLeftover] then undoes the mute.
 */
internal class CallAudioMuter(
    private val am: AudioManager,
    private val skipMic: Boolean = false,
    private val skipPlayback: Boolean = false,
    private val journal: File? = null,
) {
    private var engaged = false
    private var savedMicMute = false
    private var savedVolume = -1
    private var lastCheckNs = 0L

    /** False, with nothing changed, when the microphone mute does not take (fail closed). */
    @Synchronized
    fun engage(): Boolean {
        if (engaged) return true
        // A journal left by a killed call holds the real state from before that call; keep it.
        val leftover = journal?.let { readJournal(it) }
        savedMicMute = leftover?.first ?: micMuted()
        savedVolume = leftover?.second ?: runCatching { am.getStreamVolume(AudioManager.STREAM_VOICE_CALL) }.getOrDefault(-1)
        writeJournal()
        engaged = true
        if (skipMic || skipPlayback) Log.w(AUDIO_TAG, "field test: microphone mute skipped=$skipMic call playback mute skipped=$skipPlayback")
        if (!skipMic) runCatching { am.isMicrophoneMute = true }
        val mic = skipMic || micMuted()
        if (!skipPlayback) {
            runCatching {
                am.setStreamVolume(AudioManager.STREAM_VOICE_CALL, am.getStreamMinVolume(AudioManager.STREAM_VOICE_CALL), 0)
            }
            runCatching { am.adjustStreamVolume(AudioManager.STREAM_VOICE_CALL, AudioManager.ADJUST_MUTE, 0) }
        }
        val playback = runCatching { am.isStreamMute(AudioManager.STREAM_VOICE_CALL) }.getOrDefault(false)
        val volume = runCatching { am.getStreamVolume(AudioManager.STREAM_VOICE_CALL) }.getOrDefault(-1)
        Log.i(AUDIO_TAG, "data mode: microphone muted=${micMuted()} call playback muted=$playback call volume=$volume (was $savedVolume)")
        lastCheckNs = System.nanoTime()
        if (!mic) {
            release()
            return false
        }
        return true
    }

    /** Re-mutes the microphone if the system turned it back on; false when that fails. */
    @Synchronized
    fun ensure(): Boolean {
        if (!engaged) return true
        if (skipMic) return true
        val now = System.nanoTime()
        if (now - lastCheckNs < CHECK_INTERVAL_NS) return true
        lastCheckNs = now
        if (micMuted()) return true
        Log.w(AUDIO_TAG, "microphone unmuted externally; muting again")
        runCatching { am.isMicrophoneMute = true }
        return micMuted()
    }

    @Synchronized
    fun release() {
        if (!engaged) return
        engaged = false
        if (!skipPlayback) {
            runCatching { am.adjustStreamVolume(AudioManager.STREAM_VOICE_CALL, AudioManager.ADJUST_UNMUTE, 0) }
            if (savedVolume >= 0) runCatching { am.setStreamVolume(AudioManager.STREAM_VOICE_CALL, savedVolume, 0) }
        }
        if (!skipMic) runCatching { am.isMicrophoneMute = savedMicMute }
        journal?.let { runCatching { it.delete() } }
    }

    private fun micMuted(): Boolean = runCatching { am.isMicrophoneMute }.getOrDefault(false)

    private fun writeJournal() {
        val j = journal ?: return
        runCatching {
            j.parentFile?.mkdirs()
            j.writeText("mic=${if (savedMicMute) 1 else 0}\nvol=$savedVolume\n")
        }.onFailure { Log.w(AUDIO_TAG, "call mute journal not written") }
    }

    companion object {
        const val CHECK_INTERVAL_NS = 250_000_000L

        // Set once this process has looked for a leftover with no call up; a live mute is never older.
        @Volatile
        private var leftoverChecked = false

        internal fun resetLeftoverCheckForTest() {
            leftoverChecked = false
        }

        private fun readJournal(j: File): Pair<Boolean, Int>? {
            if (!j.isFile) return null
            val lines = runCatching { j.readLines() }.getOrNull() ?: return null
            val mic = lines.firstOrNull { it.startsWith("mic=") }?.substringAfter('=') == "1"
            val vol = lines.firstOrNull { it.startsWith("vol=") }?.substringAfter('=')?.toIntOrNull() ?: -1
            return mic to vol
        }

        /** Journal of the calling process, so one process never undoes another one's live mute. */
        fun journalFor(context: Context): File {
            val proc = if (Build.VERSION.SDK_INT >= 28) Application.getProcessName() else null
            val suffix = proc?.substringAfter(':', "main")?.ifEmpty { "main" } ?: "main"
            return File(context.noBackupFilesDir, "call_audio_mute_$suffix.journal")
        }

        /**
         * Restores the microphone mute and call volume left by a call in this process that never
         * reached [release]. Does nothing while any call is up; the journal then waits for later.
         */
        fun recoverLeftover(context: Context) {
            if (leftoverChecked) return
            // The journal cannot be read before the first unlock; look again after it.
            if (!DirectBoot.isUserUnlocked(context)) return
            val j = journalFor(context)
            if (!j.isFile) {
                leftoverChecked = true
                return
            }
            val am = context.getSystemService(AudioManager::class.java) ?: return
            if (callUp(am)) {
                Log.i(AUDIO_TAG, "leftover call mute kept while a call is up")
                return
            }
            leftoverChecked = true
            restore(am, j)
        }

        /**
         * From another process of this app: restores the journal left by process [owner] (for example
         * "secure") only when that process is no longer running, so a mute it still holds is never undone.
         */
        fun recoverOrphan(context: Context, owner: String) {
            if (!DirectBoot.isUserUnlocked(context)) return
            val j = File(context.noBackupFilesDir, "call_audio_mute_$owner.journal")
            if (!j.isFile) return
            val am = context.getSystemService(AudioManager::class.java) ?: return
            if (callUp(am)) return
            val name = context.packageName + ":" + owner
            val alive = runCatching {
                context.getSystemService(ActivityManager::class.java)?.runningAppProcesses?.any { it.processName == name }
            }.getOrNull() ?: true
            if (alive) return
            restore(am, j)
        }

        private fun callUp(am: AudioManager): Boolean {
            val mode = runCatching { am.mode }.getOrDefault(AudioManager.MODE_IN_CALL)
            return mode == AudioManager.MODE_IN_CALL || mode == AudioManager.MODE_IN_COMMUNICATION || mode == AudioManager.MODE_CALL_SCREENING
        }

        private fun restore(am: AudioManager, j: File) {
            val (mic, vol) = readJournal(j) ?: (false to -1)
            runCatching { am.adjustStreamVolume(AudioManager.STREAM_VOICE_CALL, AudioManager.ADJUST_UNMUTE, 0) }
            if (vol >= 0) runCatching { am.setStreamVolume(AudioManager.STREAM_VOICE_CALL, vol, 0) }
            runCatching { am.isMicrophoneMute = mic }
            runCatching { j.delete() }
            Log.w(AUDIO_TAG, "restored the microphone and call volume left muted by an interrupted call")
        }
    }
}
