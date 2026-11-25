package io.github.h4lovoid.dialcrypt.call

import android.content.Context
import android.media.AudioAttributes
import android.media.AudioDeviceInfo
import android.media.AudioFormat
import android.media.AudioManager
import android.media.AudioRecord
import android.media.AudioTrack
import android.media.MediaRecorder
import android.os.Build
import android.util.Log
import java.lang.reflect.InvocationTargetException
import kotlin.math.max

/**
 * Opens the call PCM streams. Tries, in order (unless the `route_a` field-test flag overrides it):
 * (a) AudioRecord on VOICE_DOWNLINK (CAPTURE_AUDIO_OUTPUT) plus an AudioTrack routed to the
 *     TYPE_TELEPHONY output (MODIFY_PHONE_STATE);
 * (b) call audio interception, the @SystemApi AudioManager.getCallUplinkInjectionAudioTrack and
 *     getCallDownlinkExtractionAudioRecord (API 33+, CALL_AUDIO_INTERCEPTION), called by reflection.
 * Both run in silent data mode through [CallAudioMuter]. Logs which one was taken, never content.
 */
internal object CallAudioRoutes {
    /** Preferred first; anything else is resampled to 16 kHz. */
    private val RATES = intArrayOf(PCM_RATE, 48_000, 8_000)
    @Volatile
    private var muteJournal: java.io.File? = null

    fun open(
        context: Context,
        onBeforeReleaseMute: (() -> Boolean)? = null,
        onDataRoute: ((Boolean) -> Unit)? = null,
    ): PcmCallAudio? {
        val am = context.getSystemService(AudioManager::class.java)
        if (am == null) {
            Log.w(AUDIO_TAG, "no audio service")
            return null
        }
        muteJournal = CallAudioMuter.journalFor(context)
        // Order measured on Pixel 7 and 7a (VoLTE, Android 16) with known modem frames sent both
        // ways. Downlink capture carries the modem audio as received: the 150 bps gears decoded
        // 8 of 8 frames, the 2400 bps gear 30 to 41 of 60. The interception API returns audio
        // prepared for listening (it follows the call volume and is filtered): 2 of 8 and
        // 4 to 13 of 60 on the same calls. Interception stays as the fallback; a field test
        // can put it first with the route_a switch.
        val interceptionFirst = FieldTestAudio.flag("route_a")
        if (interceptionFirst) Log.w(AUDIO_TAG, "field test: call audio interception first")
        val capture = { openDownlinkCapture(context, am, onBeforeReleaseMute, onDataRoute)?.also { Log.i(AUDIO_TAG, "route: voice downlink capture + telephony output") } }
        val interception = { openInterception(context, am, onBeforeReleaseMute, onDataRoute)?.also { Log.i(AUDIO_TAG, "route: call audio interception") } }
        val order = if (interceptionFirst) listOf(interception, capture) else listOf(capture, interception)
        for (open in order) open()?.let { return it }
        Log.w(AUDIO_TAG, "route: none available")
        return null
    }

    private fun openInterception(
        context: Context,
        am: AudioManager,
        onBeforeReleaseMute: (() -> Boolean)?,
        onDataRoute: ((Boolean) -> Unit)?,
    ): PcmCallAudio? {
        if (Build.VERSION.SDK_INT < 33) {
            Log.i(AUDIO_TAG, "interception: needs API 33")
            return null
        }
        var record: AudioRecord? = null
        var track: AudioTrack? = null
        try {
            val c = AudioManager::class.java
            if (c.getMethod("isPstnCallAudioInterceptable").invoke(am) != true) {
                Log.i(AUDIO_TAG, "interception: call not interceptable")
                return null
            }
            val getRecord = c.getMethod("getCallDownlinkExtractionAudioRecord", AudioFormat::class.java)
            val getTrack = c.getMethod("getCallUplinkInjectionAudioTrack", AudioFormat::class.java)
            record = firstRate { unlessBadFormat { getRecord.invoke(am, format(it, AudioFormat.CHANNEL_IN_MONO)) as AudioRecord } }
            track = firstRate { unlessBadFormat { getTrack.invoke(am, format(it, AudioFormat.CHANNEL_OUT_MONO)) as AudioTrack } }
            if (record == null || track == null) {
                Log.i(AUDIO_TAG, "interception: no supported format")
                release(record, track)
                return null
            }
            return start(context, am, record, track, requireTelephonyRoute = false, label = "interception", onBeforeReleaseMute = onBeforeReleaseMute, onDataRoute = onDataRoute)
        } catch (e: Exception) {
            Log.i(AUDIO_TAG, "interception: unavailable (${rootName(e)})")
            release(record, track)
            return null
        }
    }

    private fun openDownlinkCapture(
        context: Context,
        am: AudioManager,
        onBeforeReleaseMute: (() -> Boolean)?,
        onDataRoute: ((Boolean) -> Unit)?,
    ): PcmCallAudio? {
        var record: AudioRecord? = null
        var track: AudioTrack? = null
        try {
            val telephonyOut = am.getDevices(AudioManager.GET_DEVICES_OUTPUTS)
                .firstOrNull { it.type == AudioDeviceInfo.TYPE_TELEPHONY }
            if (telephonyOut == null) {
                Log.i(AUDIO_TAG, "downlink capture: no telephony output device")
                return null
            }
            record = firstRate(::downlinkRecord)
            track = firstRate(::uplinkTrack)
            if (record == null || track == null) {
                Log.i(AUDIO_TAG, "downlink capture: stream setup refused")
                release(record, track)
                return null
            }
            if (!track.setPreferredDevice(telephonyOut)) {
                Log.i(AUDIO_TAG, "downlink capture: telephony output refused")
                release(record, track)
                return null
            }
            return start(context, am, record, track, requireTelephonyRoute = true, label = "downlink capture", onBeforeReleaseMute = onBeforeReleaseMute, onDataRoute = onDataRoute)
        } catch (e: Exception) {
            Log.i(AUDIO_TAG, "downlink capture: unavailable (${rootName(e)})")
            release(record, track)
            return null
        }
    }

    /** Mutes first, then starts both streams and verifies uplink write acceptance; any refusal undoes everything. */
    private fun start(
        context: Context,
        am: AudioManager,
        record: AudioRecord,
        track: AudioTrack,
        requireTelephonyRoute: Boolean,
        label: String,
        onBeforeReleaseMute: (() -> Boolean)? = null,
        onDataRoute: ((Boolean) -> Unit)? = null,
    ): PcmCallAudio? {
        val muter = CallAudioMuter(
            am,
            FieldTestAudio.flag("no_mic_mute"),
            FieldTestAudio.flag("no_playback_mute"),
            muteJournal,
            context.applicationContext ?: context,
        )
        if (!muter.engage()) {
            Log.i(AUDIO_TAG, "$label: microphone mute refused")
            release(record, track)
            return null
        }
        val ok = try {
            record.startRecording()
            track.play()
            record.recordingState == AudioRecord.RECORDSTATE_RECORDING &&
                track.playState == AudioTrack.PLAYSTATE_PLAYING &&
                (!requireTelephonyRoute || routedToTelephony(track)) &&
                uplinkAcceptsProbe(track)
        } catch (e: Exception) {
            Log.i(AUDIO_TAG, "$label: start refused (${rootName(e)})")
            false
        }
        if (!ok) {
            Log.i(AUDIO_TAG, "$label: streams did not start on the call path")
            runCatching { record.stop() }
            runCatching { track.stop() }
            release(record, track)
            muter.release()
            return null
        }
        onDataRoute?.invoke(true)
        return PcmCallAudio(record, track, muter, onBeforeReleaseMute = onBeforeReleaseMute, onDataRoute = onDataRoute)
    }

    /** Writes one 20 ms silent frame non-blocking to detect HALs where microphone mute stalls uplink playback. */
    private fun uplinkAcceptsProbe(track: AudioTrack): Boolean {
        val samples = max(1, track.sampleRate / 50)
        val silence = ShortArray(samples)
        val written = track.write(silence, 0, silence.size, AudioTrack.WRITE_NON_BLOCKING)
        return written >= 0 && track.playState == AudioTrack.PLAYSTATE_PLAYING
    }

    /** The track must really land on the uplink; elsewhere the modem tones would be heard locally. */
    private fun routedToTelephony(track: AudioTrack): Boolean {
        repeat(ROUTE_POLLS) {
            if (track.routedDevice?.type == AudioDeviceInfo.TYPE_TELEPHONY) return true
            Thread.sleep(ROUTE_POLL_MS)
        }
        return false
    }

    private fun downlinkRecord(rate: Int): AudioRecord? {
        val min = AudioRecord.getMinBufferSize(rate, AudioFormat.CHANNEL_IN_MONO, AudioFormat.ENCODING_PCM_16BIT)
        if (min <= 0) return null
        return built {
            AudioRecord.Builder()
                .setAudioSource(MediaRecorder.AudioSource.VOICE_DOWNLINK)
                .setAudioFormat(format(rate, AudioFormat.CHANNEL_IN_MONO))
                .setBufferSizeInBytes(max(min * 2, rate / 5 * 2))
                .build()
        }?.takeIf { usable(it) }
    }

    private fun uplinkTrack(rate: Int): AudioTrack? {
        val min = AudioTrack.getMinBufferSize(rate, AudioFormat.CHANNEL_OUT_MONO, AudioFormat.ENCODING_PCM_16BIT)
        if (min <= 0) return null
        return built {
            AudioTrack.Builder()
                .setAudioAttributes(
                    AudioAttributes.Builder()
                        .setUsage(AudioAttributes.USAGE_VOICE_COMMUNICATION)
                        .setContentType(AudioAttributes.CONTENT_TYPE_SPEECH)
                        .build(),
                )
                .setAudioFormat(format(rate, AudioFormat.CHANNEL_OUT_MONO))
                .setTransferMode(AudioTrack.MODE_STREAM)
                .setBufferSizeInBytes(max(min, rate / 10 * 2))
                .build()
        }?.takeIf { usable(it) }
    }

    private fun format(rate: Int, channelMask: Int): AudioFormat =
        AudioFormat.Builder()
            .setEncoding(AudioFormat.ENCODING_PCM_16BIT)
            .setSampleRate(rate)
            .setChannelMask(channelMask)
            .build()

    private inline fun <T> firstRate(make: (Int) -> T?): T? {
        for (rate in RATES) make(rate)?.let { return it }
        return null
    }

    /** Null when the platform rejects the format, so the next rate is tried. */
    private inline fun <T> unlessBadFormat(block: () -> T): T? =
        try {
            block()
        } catch (e: InvocationTargetException) {
            if (e.targetException is IllegalArgumentException) null else throw e
        }

    private inline fun <T> built(block: () -> T): T? =
        try {
            block()
        } catch (e: UnsupportedOperationException) {
            null
        } catch (e: IllegalArgumentException) {
            null
        }

    private fun usable(record: AudioRecord): Boolean {
        if (record.state == AudioRecord.STATE_INITIALIZED) return true
        record.release()
        return false
    }

    private fun usable(track: AudioTrack): Boolean {
        if (track.state == AudioTrack.STATE_INITIALIZED) return true
        track.release()
        return false
    }

    private fun release(record: AudioRecord?, track: AudioTrack?) {
        runCatching { record?.release() }
        runCatching { track?.release() }
    }

    private fun rootName(e: Throwable): String =
        ((e as? InvocationTargetException)?.targetException ?: e).javaClass.simpleName

    private const val ROUTE_POLLS = 15
    private const val ROUTE_POLL_MS = 20L
}
