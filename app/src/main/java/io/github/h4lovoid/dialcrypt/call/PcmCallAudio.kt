package io.github.h4lovoid.dialcrypt.call

import android.media.AudioRecord
import android.media.AudioTrack
import android.util.Log
import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.ReentrantLock
import kotlin.math.max

internal const val PCM_RATE = 16_000
internal const val AUDIO_TAG = "AegisCallAudio"

/**
 * [CallAudio] over a started downlink [record] and uplink [track]. Device rates other than
 * 16 kHz are resampled here. Reads and writes may run on different threads; close and the
 * voice window may be called from any thread.
 */
internal class PcmCallAudio(
    private val record: AudioRecord,
    private val track: AudioTrack,
    private val muter: CallAudioMuter,
    private val onBeforeReleaseMute: (() -> Boolean)? = null,
    private val onDataRoute: ((Boolean) -> Unit)? = null,
) : CallAudio {
    private val down = if (record.sampleRate == PCM_RATE) null else Resampler(record.sampleRate, PCM_RATE)
    private val up = if (track.sampleRate == PCM_RATE) null else Resampler(PCM_RATE, track.sampleRate)
    private val readChunk = ShortArray(max(record.sampleRate / 100, 16))
    private val writeChunk = ShortArray(max(track.sampleRate / 50, 64))
    private val readLock = ReentrantLock()
    private val writeLock = ReentrantLock()
    private val stateLock = Any()
    private val pacer = Pacer()
    private var pacing = false

    @Volatile private var closed = false
    @Volatile private var failed = false
    @Volatile private var voiceWindow = false

    val isClosed: Boolean get() = closed

    override fun read(buf: ShortArray, off: Int, len: Int): Int {
        checkRange(buf.size, off, len)
        readLock.lock()
        try {
            var done = 0
            var idle = 0
            while (done < len) {
                if (closed || failed) return -1
                if (down != null) {
                    val ready = down.pull(buf, off + done, len - done)
                    if (ready > 0) {
                        done += ready
                        continue
                    }
                }
                val n = if (down == null) {
                    record.read(buf, off + done, len - done, AudioRecord.READ_BLOCKING)
                } else {
                    record.read(readChunk, 0, readChunk.size, AudioRecord.READ_BLOCKING)
                }
                when {
                    n > 0 -> {
                        idle = 0
                        if (down == null) done += n else down.push(readChunk, 0, n)
                    }
                    n == 0 -> {
                        if (++idle > MAX_IDLE_ROUNDS) return fail("downlink stalled")
                        nap()
                    }
                    else -> return if (closed) -1 else fail("downlink read error")
                }
            }
            return if (closed || failed) -1 else len
        } finally {
            readLock.unlock()
        }
    }

    override fun write(buf: ShortArray, off: Int, len: Int): Int {
        checkRange(buf.size, off, len)
        writeLock.lock()
        try {
            if (closed || failed) return -1
            if (voiceWindow) {
                // Dropped, at the real-time pace the caller would see from the uplink.
                if (!pacing) {
                    pacer.reset()
                    pacing = true
                }
                pacer.advance(len)
                return if (closed) -1 else len
            }
            if (pacing) {
                pacing = false
                up?.reset()
            }
            if (!muter.ensure()) return fail("microphone mute lost")
            if (up == null) {
                if (!writeFully(buf, off, len)) return -1
            } else {
                up.push(buf, off, len)
                while (true) {
                    val n = up.pull(writeChunk, 0, writeChunk.size)
                    if (n == 0) break
                    if (!writeFully(writeChunk, 0, n)) return -1
                }
            }
            return if (closed || failed) -1 else len
        } finally {
            writeLock.unlock()
        }
    }

    /** False when closed or failed; true when done or the voice window opened midway. */
    private fun writeFully(data: ShortArray, off: Int, len: Int): Boolean {
        var written = 0
        var idle = 0
        while (written < len) {
            if (closed || failed) return false
            if (voiceWindow) return true
            val n = track.write(data, off + written, len - written, AudioTrack.WRITE_BLOCKING)
            when {
                n > 0 -> {
                    written += n
                    idle = 0
                }
                n == 0 -> {
                    if (++idle > MAX_IDLE_ROUNDS) {
                        fail("uplink stalled")
                        return false
                    }
                    nap()
                }
                else -> {
                    if (closed) return false
                    if (voiceWindow) return true
                    fail("uplink write error")
                    return false
                }
            }
        }
        return true
    }

    override fun setVoiceWindow(open: Boolean) {
        synchronized(stateLock) {
            if (closed || failed || open == voiceWindow) return
            if (open) {
                voiceWindow = true
                runCatching {
                    track.pause()
                    track.flush()
                }
                onDataRoute?.invoke(false)
                muter.release()
                Log.i(AUDIO_TAG, "voice window open")
            } else {
                if (!muter.engage()) {
                    fail("data mode mute refused")
                    return
                }
                val playing = runCatching {
                    track.flush()
                    track.play()
                    track.playState == AudioTrack.PLAYSTATE_PLAYING
                }.getOrDefault(false)
                if (!playing) {
                    fail("uplink restart refused")
                    return
                }
                voiceWindow = false
                onDataRoute?.invoke(true)
                Log.i(AUDIO_TAG, "voice window closed")
            }
        }
    }

    override fun close() {
        synchronized(stateLock) {
            if (closed) return
            closed = true
        }
        // stop() and pause() wake up blocked read() and write() calls.
        runCatching { record.stop() }
        runCatching {
            track.pause()
            track.flush()
            track.stop()
        }
        val r = runCatching { readLock.tryLock(LOCK_WAIT_MS, TimeUnit.MILLISECONDS) }.getOrDefault(false)
        val w = runCatching { writeLock.tryLock(LOCK_WAIT_MS, TimeUnit.MILLISECONDS) }.getOrDefault(false)
        try {
            runCatching { record.release() }
            runCatching { track.release() }
        } finally {
            if (w) writeLock.unlock()
            if (r) readLock.unlock()
        }
        val disconnected = onBeforeReleaseMute?.invoke() ?: true
        if (disconnected) {
            muter.release()
        } else {
            Log.w(AUDIO_TAG, "call still active when audio closed; keeping mute")
        }
        Log.i(AUDIO_TAG, "call audio closed")
    }

    /** Marks the streams unusable; the caller sees -1 and hangs up. Mutes stay until close. */
    private fun fail(reason: String): Int {
        if (!failed && !closed) Log.w(AUDIO_TAG, "call audio failed: $reason")
        failed = true
        return -1
    }

    private fun nap() {
        try {
            Thread.sleep(IDLE_NAP_MS)
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            fail("interrupted")
        }
    }

    /** Sleeps so that [advance]d samples leave at 16 kHz. */
    private class Pacer {
        private var startNs = 0L
        private var samples = 0L

        fun reset() {
            startNs = System.nanoTime()
            samples = 0
        }

        fun advance(count: Int) {
            samples += count
            val waitNs = startNs + samples * 1_000_000_000L / PCM_RATE - System.nanoTime()
            if (waitNs <= 0) return
            try {
                Thread.sleep(waitNs / 1_000_000, (waitNs % 1_000_000).toInt())
            } catch (e: InterruptedException) {
                Thread.currentThread().interrupt()
            }
        }
    }

    private companion object {
        const val MAX_IDLE_ROUNDS = 200
        const val IDLE_NAP_MS = 5L
        const val LOCK_WAIT_MS = 1000L

        fun checkRange(size: Int, off: Int, len: Int) {
            if (off < 0 || len < 0 || off > size - len) throw IndexOutOfBoundsException("off=$off len=$len size=$size")
        }
    }
}
