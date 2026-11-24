package io.github.h4lovoid.dialcrypt.core.real

import android.app.Application
import io.github.h4lovoid.dialcrypt.BuildConfig
import io.github.h4lovoid.dialcrypt.call.CallAudio
import java.io.Closeable
import java.io.File
import java.io.IOException
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import kotlin.concurrent.thread

/** 16 kHz, mono, 16-bit PCM WAV files. No Android classes. */
internal object Wav {
    const val RATE = 16_000
    const val HEADER_BYTES = 44

    /** The 44-byte header of a file whose sample data is [dataBytes] long. */
    fun header(dataBytes: Long): ByteArray {
        val b = ByteBuffer.allocate(HEADER_BYTES).order(ByteOrder.LITTLE_ENDIAN)
        b.put("RIFF".toByteArray(Charsets.US_ASCII))
        b.putInt((36L + dataBytes).toInt())
        b.put("WAVE".toByteArray(Charsets.US_ASCII))
        b.put("fmt ".toByteArray(Charsets.US_ASCII))
        b.putInt(16)
        b.putShort(1)
        b.putShort(1)
        b.putInt(RATE)
        b.putInt(RATE * 2)
        b.putShort(2)
        b.putShort(16)
        b.put("data".toByteArray(Charsets.US_ASCII))
        b.putInt(dataBytes.toInt())
        return b.array()
    }

    /** The samples of a 16 kHz mono 16-bit PCM WAV, or null for any other content. */
    fun parse(bytes: ByteArray): ShortArray? {
        if (bytes.size < 12 || tag(bytes, 0) != "RIFF" || tag(bytes, 8) != "WAVE") return null
        var fmtOk = false
        var pos = 12L
        while (pos + 8 <= bytes.size) {
            val p = pos.toInt()
            val id = tag(bytes, p)
            val size = u32(bytes, p + 4)
            val body = p + 8
            if (id == "fmt ") {
                if (size < 16 || body + 16 > bytes.size) return null
                fmtOk = u16(bytes, body) == 1 && u16(bytes, body + 2) == 1 &&
                    u32(bytes, body + 4) == RATE.toLong() && u16(bytes, body + 14) == 16
                if (!fmtOk) return null
            } else if (id == "data") {
                if (!fmtOk) return null
                val n = (minOf(size, (bytes.size - body).toLong()) / 2).toInt()
                return ShortArray(n) { i -> ((bytes[body + 2 * i].toInt() and 0xFF) or (bytes[body + 2 * i + 1].toInt() shl 8)).toShort() }
            }
            pos = body.toLong() + size + (size and 1L)
        }
        return null
    }

    private fun tag(b: ByteArray, off: Int) = String(b, off, 4, Charsets.US_ASCII)
    private fun u16(b: ByteArray, off: Int) = (b[off].toInt() and 0xFF) or ((b[off + 1].toInt() and 0xFF) shl 8)
    private fun u32(b: ByteArray, off: Int) = (u16(b, off).toLong()) or (u16(b, off + 2).toLong() shl 16)
}

/** Appends samples to a WAV file; [flushHeader] makes the file readable at its current length. Single writer thread. */
internal class WavWriter(file: File) : Closeable {
    private var sinceFlush = 0

    /** [append], plus a header update about once a second so a killed process leaves a readable file. */
    fun appendDurable(buf: ShortArray, off: Int, len: Int) {
        append(buf, off, len)
        sinceFlush += len
        if (sinceFlush >= 16_000) {
            sinceFlush = 0
            flushHeader()
        }
    }

    private val raf = RandomAccessFile(file, "rw")

    /** Samples appended so far. */
    var samples = 0L
        private set

    init {
        raf.setLength(0)
        raf.write(Wav.header(0))
    }

    fun append(buf: ShortArray, off: Int, len: Int) {
        val b = ByteBuffer.allocate(len * 2).order(ByteOrder.LITTLE_ENDIAN)
        for (i in off until off + len) b.putShort(buf[i])
        raf.write(b.array())
        samples += len
    }

    /** Writes the real length into the header and forces the file to disk. */
    fun flushHeader() {
        val end = raf.filePointer
        raf.seek(0)
        raf.write(Wav.header(samples * 2))
        raf.seek(end)
        raf.fd.sync()
    }

    override fun close() {
        try {
            flushHeader()
        } finally {
            raf.close()
        }
    }
}

/**
 * Field-test line probe: sends a prepared WAV over the call audio path and records what comes
 * back. Blocking; [run] returns the end cause code. Only used by field-test builds.
 */
internal class LinkProbe(
    private val audio: CallAudio,
    private val tx: ShortArray,
    private val out: File,
    private val clock: () -> Long,
    private val log: (String) -> Unit,
) {
    /**
     * [stop] true: the call is over locally. [holdAfterDone]: after the own part is done keep
     * draining the downlink until the call ends or the time limit.
     */
    fun run(stop: () -> Boolean, holdAfterDone: Boolean): Int {
        val t0 = clock()
        val writer = try {
            WavWriter(out)
        } catch (e: IOException) {
            return CAUSE_ERROR
        }
        val lock = Any()
        var recording = true
        val halt = AtomicBoolean(false)
        val callEnded = AtomicBoolean(false)
        val ioFailed = AtomicBoolean(false)
        val txDoneAt = AtomicLong(-1L)

        thread(name = "aegis-probe-rx", isDaemon = true) {
            val buf = ShortArray(CHUNK)
            var lastSync = clock()
            while (!halt.get()) {
                val n = try {
                    audio.read(buf, 0, CHUNK)
                } catch (e: Exception) {
                    -1
                }
                if (n < 0) {
                    callEnded.set(true)
                    break
                }
                synchronized(lock) {
                    if (recording && n > 0) {
                        try {
                            writer.append(buf, 0, n)
                            val t = clock()
                            if (t - lastSync >= HEADER_SYNC_MS) {
                                lastSync = t
                                writer.flushHeader()
                            }
                        } catch (e: IOException) {
                            recording = false
                            ioFailed.set(true)
                        }
                    }
                }
            }
        }

        thread(name = "aegis-probe-tx", isDaemon = true) {
            try {
                val begin = clock()
                while (clock() - begin < START_DELAY_MS && !halt.get()) Thread.sleep(SLEEP_MS)
                val chunk = ShortArray(CHUNK)
                var pos = 0
                while (pos < tx.size && !halt.get()) {
                    val n = minOf(CHUNK, tx.size - pos)
                    System.arraycopy(tx, pos, chunk, 0, n)
                    if (n < CHUNK) chunk.fill(0, n, CHUNK)
                    if (audio.write(chunk, 0, CHUNK) < 0) {
                        callEnded.set(true)
                        return@thread
                    }
                    pos += n
                }
                if (pos >= tx.size) {
                    txDoneAt.set(clock())
                    log("probe tx done samples=" + tx.size)
                }
            } catch (e: Exception) {
                callEnded.set(true)
            }
        }

        var cause = waitFor(t0, stop, callEnded, ioFailed, txDoneAt, true)
        val saved: Long
        synchronized(lock) {
            recording = false
            saved = writer.samples
            try {
                writer.close()
            } catch (e: IOException) {
                ioFailed.set(true)
            }
        }
        log("probe rx saved samples=$saved")
        if (holdAfterDone && cause == CAUSE_DONE) cause = waitFor(t0, stop, callEnded, ioFailed, txDoneAt, false)
        halt.set(true)
        return cause
    }

    private fun waitFor(
        t0: Long,
        stop: () -> Boolean,
        callEnded: AtomicBoolean,
        ioFailed: AtomicBoolean,
        txDoneAt: AtomicLong,
        ownPart: Boolean,
    ): Int {
        while (true) {
            val now = clock()
            val done = txDoneAt.get()
            val cause = when {
                ownPart && ioFailed.get() -> CAUSE_ERROR
                callEnded.get() -> CAUSE_CALL_ENDED
                stop() -> CAUSE_STOPPED
                now - t0 >= LIMIT_MS -> CAUSE_LIMIT
                ownPart && done >= 0 && now - done >= TAIL_MS -> CAUSE_DONE
                else -> -1
            }
            if (cause >= 0) return cause
            Thread.sleep(SLEEP_MS)
        }
    }

    companion object {
        const val CHUNK = 320
        const val START_DELAY_MS = 2_000L
        const val TAIL_MS = 4_000L
        const val LIMIT_MS = 170_000L
        private const val HEADER_SYNC_MS = 1_000L
        private const val SLEEP_MS = 20L

        const val CAUSE_DONE = 0
        const val CAUSE_CALL_ENDED = 1
        const val CAUSE_LIMIT = 2
        const val CAUSE_STOPPED = 3
        const val CAUSE_ERROR = 4

        fun rxFile(dir: File, role: String, nowMs: Long): File =
            File(dir, "rx-" + role + "-" + SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date(nowMs)) + ".wav")
    }
}

/** Field-test build switches that read files in the app's private directory. */
internal object FieldTest {
    private const val MAX_TX_BYTES = 8L * 1024 * 1024

    /**
     * Recorders for the PCM a real session sends and receives, or null. On only in field-test
     * builds and only while <filesDir>/fieldtest/record exists; the files go next to the probe
     * files as session-<role>-<unix seconds>-tx.wav and -rx.wav. The audio is modem signal, not
     * speech, except during a voice comparison window, when nothing is written.
     */
    fun sessionRecorders(caller: Boolean): Pair<WavWriter, WavWriter>? {
        val dir = probeDir() ?: return null
        val switch = File(dir.parentFile ?: return null, "fieldtest/record")
        if (!switch.isFile) return null
        return runCatching {
            dir.mkdirs()
            val stem = "session-" + (if (caller) "caller" else "callee") + "-" + System.currentTimeMillis() / 1000
            WavWriter(File(dir, "$stem-tx.wav")) to WavWriter(File(dir, "$stem-rx.wav"))
        }.getOrNull()
    }

    /** The app's files directory, or null when it cannot be found. */
    private fun filesDir(): File? {
        val viaApp = runCatching {
            (Class.forName("android.app.ActivityThread").getMethod("currentApplication").invoke(null) as? Application)?.filesDir
        }.getOrNull()
        return viaApp ?: File("/data/data/" + BuildConfig.APPLICATION_ID + "/files").takeIf { it.isDirectory }
    }

    /** <filesDir>/linkprobe, or null when the probe is off. */
    fun probeDir(): File? = if (BuildConfig.FIELD_TEST_LINK_PROBE) filesDir()?.let { File(it, "linkprobe") } else null

    /** The samples of <dir>/tx.wav; null when the file is missing or not 16 kHz mono 16-bit ([onReject] runs in the second case). */
    fun loadProbeTx(dir: File, onReject: () -> Unit): ShortArray? {
        val f = File(dir, "tx.wav")
        if (!f.isFile) return null
        val pcm = if (f.length() in 1..MAX_TX_BYTES) runCatching { Wav.parse(f.readBytes()) }.getOrNull() else null
        if (pcm == null || pcm.isEmpty()) {
            onReject()
            return null
        }
        return pcm
    }

    /** True when the probe build finds <filesDir>/fieldtest/narrowband. */
    fun narrowGear(): Boolean {
        if (!BuildConfig.FIELD_TEST_LINK_PROBE) return false
        val dir = filesDir() ?: return false
        return File(File(dir, "fieldtest"), "narrowband").exists()
    }
}
