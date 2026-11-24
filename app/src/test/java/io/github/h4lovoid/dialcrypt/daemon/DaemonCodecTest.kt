package io.github.h4lovoid.dialcrypt.daemon

import io.github.h4lovoid.dialcrypt.core.daemon.AttachInfo
import io.github.h4lovoid.dialcrypt.core.daemon.ClientMsg
import io.github.h4lovoid.dialcrypt.core.daemon.DaemonCodec
import io.github.h4lovoid.dialcrypt.core.daemon.FrameError
import io.github.h4lovoid.dialcrypt.core.daemon.FrameException
import io.github.h4lovoid.dialcrypt.core.daemon.FrameReader
import io.github.h4lovoid.dialcrypt.core.daemon.ServerMsg
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/** Byte vectors are worked out by hand from the frame rules in daemon/src/ipc.rs. */
class DaemonCodecTest {
    private fun b(vararg v: Int) = ByteArray(v.size) { v[it].toByte() }

    private val lease = ByteArray(16) { (0x10 + it).toByte() }
    private val leaseBytes = intArrayOf(0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f)

    private fun errorOf(block: () -> Unit): FrameError = assertThrows(FrameException::class.java, block).error

    @Test
    fun clientVectorsMatchTheDaemonEncoding() {
        assertArrayEquals(b(0x00, 0x02, 0x01, 0x01), DaemonCodec.encodeClient(ClientMsg.Hello(1)))
        assertArrayEquals(b(0x00, 0x01, 0x02), DaemonCodec.encodeClient(ClientMsg.Prepare))
        assertArrayEquals(b(0x00, 0x11, 0x06, *leaseBytes), DaemonCodec.encodeClient(ClientMsg.Attach(lease)))
        assertArrayEquals(b(0x00, 0x11, 0x08, *leaseBytes), DaemonCodec.encodeClient(ClientMsg.Heartbeat(lease)))
        assertArrayEquals(b(0x00, 0x01, 0x0a), DaemonCodec.encodeClient(ClientMsg.End))
    }

    @Test
    fun serverVectorsMatchTheDaemonEncoding() {
        assertArrayEquals(b(0x00, 0x03, 0x01, 0x01, 0x00), DaemonCodec.encodeServer(ServerMsg.Hello(1, 0)))
        assertArrayEquals(b(0x00, 0x03, 0x01, 0x01, 0x01), DaemonCodec.encodeServer(ServerMsg.Hello(1, 1)))
        assertArrayEquals(b(0x00, 0x02, 0x03, 0x03), DaemonCodec.encodeServer(ServerMsg.Progress(3)))
        assertArrayEquals(
            b(0x00, 0x14, 0x04, *leaseBytes, 0x01, 0x02, 0x07),
            DaemonCodec.encodeServer(ServerMsg.Ready(lease, 1, 2, 7)),
        )
        assertArrayEquals(b(0x00, 0x05, 0x05, 0x00, 0x0a, 0x00, 0x64), DaemonCodec.encodeServer(ServerMsg.Fail(10, 100)))
        // Both bytes of each u16 are used: item 31 = 0x001f, code 410 = 0x019a.
        assertArrayEquals(b(0x00, 0x05, 0x05, 0x00, 0x1f, 0x01, 0x9a), DaemonCodec.encodeServer(ServerMsg.Fail(31, 410)))
        assertArrayEquals(b(0x00, 0x04, 0x07, 0x01, 0x01, 0x01), DaemonCodec.encodeServer(ServerMsg.Attached(1, 1, 1)))
        assertArrayEquals(b(0x00, 0x03, 0x09, 0x01, 0x91), DaemonCodec.encodeServer(ServerMsg.Violation(401)))
        assertArrayEquals(b(0x00, 0x02, 0x0b, 0x01), DaemonCodec.encodeServer(ServerMsg.Ended(1)))
    }

    @Test
    fun everyClientMessageRoundTrips() {
        for (m in listOf(ClientMsg.Hello(1), ClientMsg.Prepare, ClientMsg.Attach(lease), ClientMsg.Heartbeat(lease), ClientMsg.End)) {
            val f = DaemonCodec.encodeClient(m)
            assertEquals(f.size - 2, ((f[0].toInt() and 0xff) shl 8) or (f[1].toInt() and 0xff))
            assertEquals(m, DaemonCodec.decodeClient(f.copyOfRange(2, f.size)))
        }
    }

    @Test
    fun everyServerMessageRoundTrips() {
        for (m in listOf(
            ServerMsg.Hello(1, 0),
            ServerMsg.Progress(5),
            ServerMsg.Ready(lease, 0, 2, 7),
            ServerMsg.Fail(0xffff, 0xffff),
            ServerMsg.Attached(1, 2, 3),
            ServerMsg.Violation(410),
            ServerMsg.Ended(0),
        )) {
            val f = DaemonCodec.encodeServer(m)
            assertEquals(f.size - 2, ((f[0].toInt() and 0xff) shl 8) or (f[1].toInt() and 0xff))
            assertEquals(m, DaemonCodec.decodeServer(f.copyOfRange(2, f.size)))
        }
    }

    @Test
    fun readyKeepsAnIndependentCopyOfTheLease() {
        val source = lease.copyOf()
        val ready = ServerMsg.Ready(source, 1, 1, 1)
        source.fill(0)
        assertArrayEquals(lease, ready.lease)
    }

    @Test
    fun decodeServerRejectsWrongLengthsAndTypes() {
        assertEquals(FrameError.LENGTH, errorOf { DaemonCodec.decodeServer(b()) })
        assertEquals(FrameError.UNKNOWN_TYPE, errorOf { DaemonCodec.decodeServer(b(99)) })
        assertEquals(FrameError.UNKNOWN_TYPE, errorOf { DaemonCodec.decodeServer(b(0)) })
        // Client-only types are unknown to the App-side decoder.
        assertEquals(FrameError.UNKNOWN_TYPE, errorOf { DaemonCodec.decodeServer(b(2)) })
        assertEquals(FrameError.UNKNOWN_TYPE, errorOf { DaemonCodec.decodeServer(b(6, *leaseBytes)) })
        assertEquals(FrameError.BAD_PAYLOAD, errorOf { DaemonCodec.decodeServer(b(5, 0, 1)) })
        assertEquals(FrameError.BAD_PAYLOAD, errorOf { DaemonCodec.decodeServer(b(1, 1)) })
        assertEquals(FrameError.BAD_PAYLOAD, errorOf { DaemonCodec.decodeServer(b(1, 1, 0, 0)) })
        assertEquals(FrameError.BAD_PAYLOAD, errorOf { DaemonCodec.decodeServer(b(3)) })
        assertEquals(FrameError.BAD_PAYLOAD, errorOf { DaemonCodec.decodeServer(b(4, *leaseBytes, 1, 1)) })
        assertEquals(FrameError.BAD_PAYLOAD, errorOf { DaemonCodec.decodeServer(b(4, *leaseBytes, 1, 1, 1, 1)) })
        assertEquals(FrameError.BAD_PAYLOAD, errorOf { DaemonCodec.decodeServer(b(7, 1, 1)) })
        assertEquals(FrameError.BAD_PAYLOAD, errorOf { DaemonCodec.decodeServer(b(9, 1)) })
        assertEquals(FrameError.BAD_PAYLOAD, errorOf { DaemonCodec.decodeServer(b(11)) })
    }

    @Test
    fun decodeClientRejectsWrongLengthsAndTypes() {
        assertEquals(FrameError.LENGTH, errorOf { DaemonCodec.decodeClient(b()) })
        assertEquals(FrameError.UNKNOWN_TYPE, errorOf { DaemonCodec.decodeClient(b(99)) })
        assertEquals(FrameError.BAD_PAYLOAD, errorOf { DaemonCodec.decodeClient(b(2, 0)) })
        assertEquals(FrameError.BAD_PAYLOAD, errorOf { DaemonCodec.decodeClient(b(6, 1, 2, 3)) })
        assertEquals(FrameError.BAD_PAYLOAD, errorOf { DaemonCodec.decodeClient(b(1)) })
        assertEquals(FrameError.UNKNOWN_TYPE, errorOf { DaemonCodec.decodeClient(b(4, *leaseBytes, 1, 1, 1)) })
    }

    @Test
    fun encodeRefusesALeaseOfTheWrongSize() {
        assertThrows(IllegalArgumentException::class.java) { DaemonCodec.encodeClient(ClientMsg.Attach(ByteArray(15))) }
        assertThrows(IllegalArgumentException::class.java) { DaemonCodec.encodeClient(ClientMsg.Heartbeat(ByteArray(17))) }
    }

    @Test
    fun readerRejectsZeroAndOversizedLengths() {
        assertEquals(FrameError.LENGTH, errorOf { FrameReader().push(b(0, 0)) })
        assertEquals(FrameError.LENGTH, errorOf { FrameReader().push(b(0xff, 0xff, 1)) })
        assertEquals(FrameError.LENGTH, errorOf { FrameReader().push(b(0, 65)) })
    }

    @Test
    fun readerAcceptsTheLargestFrame() {
        val body = ByteArray(64) { 7 }
        val frames = FrameReader().push(b(0, 64) + body)
        assertEquals(1, frames.size)
        assertArrayEquals(body, frames[0])
    }

    @Test
    fun readerReassemblesAFrameDeliveredOneByteAtATime() {
        val f = DaemonCodec.encodeServer(ServerMsg.Ready(lease, 1, 2, 3))
        val reader = FrameReader()
        val frames = ArrayList<ByteArray>()
        for (x in f) frames.addAll(reader.push(byteArrayOf(x)))
        assertEquals(1, frames.size)
        assertEquals(ServerMsg.Ready(lease, 1, 2, 3), DaemonCodec.decodeServer(frames[0]))
    }

    @Test
    fun readerSplitsSeveralFramesInOneChunkAndKeepsTheTail() {
        val a = DaemonCodec.encodeServer(ServerMsg.Progress(1))
        val c = DaemonCodec.encodeServer(ServerMsg.Violation(410))
        val d = DaemonCodec.encodeServer(ServerMsg.Ended(0))
        val stream = a + c + d
        val reader = FrameReader()
        // Cut inside the third frame.
        val cut = a.size + c.size + 1
        val first = reader.push(stream, 0, cut)
        assertEquals(listOf<ServerMsg>(ServerMsg.Progress(1), ServerMsg.Violation(410)), first.map { DaemonCodec.decodeServer(it) })
        val second = reader.push(stream, cut, stream.size - cut)
        assertEquals(listOf<ServerMsg>(ServerMsg.Ended(0)), second.map { DaemonCodec.decodeServer(it) })
        assertTrue(reader.push(ByteArray(0)).isEmpty())
    }

    @Test
    fun readerWaitsForALoneLengthByte() {
        val reader = FrameReader()
        assertTrue(reader.push(b(0)).isEmpty())
        assertEquals(1, reader.push(b(2, 3, 5)).size)
    }

    @Test
    fun attachInfoReadsTheClaimBits() {
        val info = AttachInfo(mode = 1, tier = 2, claims = 5)
        assertFalse(info.dryRun)
        assertTrue(info.has(1))
        assertFalse(info.has(2))
        assertTrue(info.has(4))
        assertTrue(AttachInfo(0, 1, 1).dryRun)
    }
}
