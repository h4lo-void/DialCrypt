package io.github.h4lovoid.dialcrypt.review

import io.github.h4lovoid.dialcrypt.core.daemon.ClientMsg
import io.github.h4lovoid.dialcrypt.core.daemon.DaemonCodec
import io.github.h4lovoid.dialcrypt.core.daemon.FrameError
import io.github.h4lovoid.dialcrypt.core.daemon.FrameException
import io.github.h4lovoid.dialcrypt.core.daemon.FrameReader
import io.github.h4lovoid.dialcrypt.core.daemon.ServerMsg
import io.github.h4lovoid.dialcrypt.core.real.ChainTlv
import io.github.h4lovoid.dialcrypt.core.real.ContactListCodec
import io.github.h4lovoid.dialcrypt.core.real.EventTlv
import io.github.h4lovoid.dialcrypt.core.real.NativeEvent
import io.github.h4lovoid.dialcrypt.core.real.NativeIdentity
import io.github.h4lovoid.dialcrypt.core.real.PinBegin
import io.github.h4lovoid.dialcrypt.core.real.RotationLayout
import io.github.h4lovoid.dialcrypt.core.real.TrustTlv
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** Byte layouts built by hand from the Rust encoders (bridge.rs, events.rs, ipc.rs), parsed by the Kotlin decoders. */
class ReviewWireTest {
    private fun u32(v: Long) = byteArrayOf((v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte())

    private fun bytes(vararg v: Int) = ByteArray(v.size) { v[it].toByte() }

    private fun rec(type: Int, v: ByteArray): ByteArray {
        val o = ByteArrayOutputStream()
        o.write(type)
        o.write(v.size ushr 8)
        o.write(v.size and 0xFF)
        o.write(v)
        return o.toByteArray()
    }

    private fun pub(seed: Int) = ByteArray(33) { (seed + it).toByte() }

    private fun parseOne(type: Int, v: ByteArray): NativeEvent {
        val list = EventTlv.parse(rec(type, v))
        assertNotNull("type $type must parse", list)
        assertEquals(1, list!!.size)
        return list[0]
    }

    // ---------------------------------------------------------------- event TLV (criterion 1)

    @Test
    fun establishedResumeKeyChangedWithUnsignedIds() {
        val peer = pub(1)
        // role u8 · path u8 · usedNew u8 · pathContact u32 · identity u8 · psk u32 · stored u32 · peer 33
        val v = bytes(1) + bytes(1, 1) + u32(7) + bytes(3) + u32(9) + u32(0xFFFFFFFFL) + peer
        assertEquals(49, v.size)
        val e = parseOne(EventTlv.ESTABLISHED, v) as NativeEvent.Established
        assertTrue(e.responder)
        assertTrue(e.path.resume)
        assertTrue(e.path.usedNew)
        assertEquals(7L, e.path.contactId)
        assertEquals(NativeIdentity.KEY_CHANGED, e.identity)
        assertEquals(9L, e.pskContactId)
        assertEquals(0xFFFFFFFFL, e.storedContactId)
        assertArrayEquals(peer, e.peerPub33)
    }

    @Test
    fun establishedFullPathAllZeroPathBytes() {
        val v = bytes(0) + ByteArray(6) + bytes(0) + u32(0) + u32(0) + pub(5)
        val e = parseOne(EventTlv.ESTABLISHED, v) as NativeEvent.Established
        assertFalse(e.responder)
        assertFalse(e.path.resume)
        assertEquals(NativeIdentity.UNVERIFIED, e.identity)
        assertEquals(0L, e.storedContactId)
    }

    @Test
    fun establishedWrongLengthOrBadFlagIsMalformed() {
        assertNull(EventTlv.parse(rec(EventTlv.ESTABLISHED, ByteArray(48))))
        assertNull(EventTlv.parse(rec(EventTlv.ESTABLISHED, ByteArray(50))))
        val badRole = bytes(2) + ByteArray(6) + bytes(0) + u32(0) + u32(0) + pub(5)
        assertNull(EventTlv.parse(rec(EventTlv.ESTABLISHED, badRole)))
        val badIdentity = bytes(0) + ByteArray(6) + bytes(4) + u32(0) + u32(0) + pub(5)
        assertNull(EventTlv.parse(rec(EventTlv.ESTABLISHED, badIdentity)))
    }

    @Test
    fun needSignatureKeepsRequestIdBitsAndMessage() {
        val msg = bytes(9, 8, 7)
        val e = parseOne(EventTlv.NEED_SIGNATURE, u32(0x80000001L) + msg) as NativeEvent.NeedSignature
        assertEquals(0x80000001L.toInt(), e.reqId)
        assertArrayEquals(msg, e.message)
        assertNull(EventTlv.parse(rec(EventTlv.NEED_SIGNATURE, u32(1))))
    }

    @Test
    fun attestationSignedResultAndFields() {
        val v = bytes(0xFC, 1) + u32(202411) + bytes(1)
        assertEquals(7, v.size)
        val e = parseOne(EventTlv.ATTESTATION, v) as NativeEvent.Attestation
        assertEquals(-4, e.result)
        assertEquals(1, e.boot)
        assertEquals(202411L, e.osPatch)
        assertTrue(e.stored)
        assertNull(EventTlv.parse(rec(EventTlv.ATTESTATION, bytes(0, 3) + u32(1) + bytes(0))))
    }

    @Test
    fun vaultEventsKeepUnsignedSeqAndSignedCode() {
        val d = parseOne(EventTlv.VAULT_DIRTY, u32(0xFFFFFFFEL)) as NativeEvent.VaultDirty
        assertEquals(0xFFFFFFFEL, d.seq)
        assertEquals(-2, d.seq.toInt())
        val f = parseOne(EventTlv.VAULT_FAILED, bytes(0xFB)) as NativeEvent.VaultFailed
        assertEquals(-5, f.code)
    }

    @Test
    fun sasMessageAndSmallEvents() {
        val s = parseOne(EventTlv.SAS, bytes(0, 1, 127, 128, 255)) as NativeEvent.Sas
        assertEquals(listOf(0, 1, 127, 128, 255), s.wordIndices)
        assertNull(EventTlv.parse(rec(EventTlv.SAS, bytes(1, 2, 3, 4))))
        val text = "€€ hi".toByteArray(Charsets.UTF_8)
        val m = parseOne(EventTlv.MESSAGE_RECEIVED, bytes(0xFF, 0xFF) + text) as NativeEvent.MessageReceived
        assertEquals(65535, m.msgId)
        assertEquals("€€ hi", m.text.toString(Charsets.UTF_8))
        assertEquals(NativeEvent.MessageDelivered(0x0102), parseOne(EventTlv.MESSAGE_DELIVERED, bytes(1, 2)))
        assertEquals(NativeEvent.MessageFailed(3), parseOne(EventTlv.MESSAGE_FAILED, bytes(0, 3)))
        assertEquals(NativeEvent.MessageProgress(0x0102, 3, 0xFFFF), parseOne(EventTlv.MESSAGE_PROGRESS, bytes(1, 2, 0, 3, 0xFF, 0xFF)))
        assertNull(EventTlv.parse(rec(EventTlv.MESSAGE_PROGRESS, bytes(1, 2, 0, 3, 0))))
        assertEquals(NativeEvent.Ended(true), parseOne(EventTlv.ENDED, bytes(1)))
        assertEquals(NativeEvent.Aborted(26), parseOne(EventTlv.ABORTED, bytes(26)))
        assertEquals(NativeEvent.VoiceWindow(true), parseOne(EventTlv.VOICE_WINDOW, bytes(1)))
        assertEquals(NativeEvent.PqMixed(0x01020304L), parseOne(EventTlv.PQ_MIXED, u32(0x01020304L)))
        assertEquals(NativeEvent.Epoch(5L), parseOne(EventTlv.EPOCH, u32(5)))
        assertEquals(NativeEvent.RemoteWipe, parseOne(EventTlv.REMOTE_WIPE, ByteArray(0)))
        assertEquals(NativeEvent.WipeSent, parseOne(EventTlv.WIPE_SENT, ByteArray(0)))
        assertEquals(NativeEvent.SasConfirmed, parseOne(EventTlv.SAS_CONFIRMED, ByteArray(0)))
        assertNull(EventTlv.parse(rec(EventTlv.ENDED, bytes(2))))
        assertNull(EventTlv.parse(rec(EventTlv.REMOTE_WIPE, bytes(0))))
    }

    @Test
    fun keyChangedAndPathAndProgress() {
        val a = pub(10)
        val b = pub(90)
        val k = parseOne(EventTlv.KEY_CHANGED, a + b) as NativeEvent.KeyChanged
        assertArrayEquals(a, k.storedPub33)
        assertArrayEquals(b, k.peerPub33)
        val p = parseOne(EventTlv.PATH, bytes(1, 0) + u32(0x01020304L)) as NativeEvent.PathChosen
        assertTrue(p.path.resume)
        assertEquals(0x01020304L, p.path.contactId)
        assertNull(EventTlv.parse(rec(EventTlv.PATH, bytes(2, 0) + u32(1))))
        assertEquals(NativeEvent.HandshakeProgress(100), parseOne(EventTlv.HS_PROGRESS, bytes(250)))
    }

    @Test
    fun bufferLevelErrorsAreMalformed() {
        assertNotNull(EventTlv.parse(ByteArray(0)))
        assertNull("type 13 is not produced by Rust", EventTlv.parse(rec(13, ByteArray(0))))
        assertNull(EventTlv.parse(rec(EventTlv.ENDED, bytes(0)).copyOf(3)))
        val two = rec(EventTlv.HS_PROGRESS, bytes(10)) + rec(EventTlv.SAS_CONFIRMED, ByteArray(0))
        assertEquals(2, EventTlv.parse(two)!!.size)
        assertNull(EventTlv.parse(two + bytes(1)))
    }

    // ---------------------------------------------------------------- byte layouts (criterion 1)

    @Test
    fun rotationLayoutWithHighBitIds() {
        val m1 = ByteArray(32) { 1 }
        val m2 = ByteArray(32) { 2 }
        val raw = bytes(2) + u32(0xFFFFFFF0L) + m1 + u32(1) + m2 + bytes(1) + u32(0xFFFFFFFFL)
        val l = RotationLayout.parse(raw)!!
        assertEquals(2, l.fresh.size)
        assertEquals(-16, l.fresh[0].id)
        assertArrayEquals(m1, l.fresh[0].material)
        assertEquals(1, l.fresh[1].id)
        assertArrayEquals(intArrayOf(-1), l.retire)
        assertNull(RotationLayout.parse(raw + bytes(0)))
        assertNull(RotationLayout.parse(raw.copyOf(raw.size - 1)))
        val none = RotationLayout.parse(bytes(0, 0))!!
        assertEquals(0, none.fresh.size)
        assertEquals(0, none.retire.size)
    }

    @Test
    fun pinBeginIsTicketIdThen32Bytes() {
        val input = ByteArray(32) { (it + 3).toByte() }
        val b = PinBegin.parse(u32(0x80000005L) + input)!!
        assertEquals(0x80000005L.toInt(), b.ticketId)
        assertArrayEquals(input, b.input)
        assertNull(PinBegin.parse(u32(1) + ByteArray(31)))
        assertNull(PinBegin.parse(u32(1) + ByteArray(33)))
    }

    @Test
    fun contactListAllFlagsAndOptionalParts() {
        val tag = ByteArray(16) { 0x55 }
        val p1 = pub(20)
        val p2 = pub(60)
        val label1 = "Amy".toByteArray()
        val c1 = u32(70000) + bytes(0x01 or 0x02 or 0x10 or 0x20) + p1 + bytes(label1.size) + label1 + bytes(1) + u32(202411) + tag
        val c2 = u32(2) + bytes(0x04 or 0x08) + p2 + bytes(0)
        val raw = bytes(0, 2) + c1 + c2
        val list = ContactListCodec.parse(raw)!!
        assertEquals(2, list.size)
        assertEquals(70000L, list[0].id)
        assertTrue(list[0].hasPsk && list[0].sasVerified && list[0].hasNumberTag)
        assertEquals("Amy", list[0].label)
        assertEquals(1, list[0].boot)
        assertEquals(202411L, list[0].osPatch)
        assertArrayEquals(p1, list[0].pub33)
        assertEquals("", list[1].label)
        assertTrue(list[1].resumeCurrent && list[1].resumeNew)
        assertNull(list[1].boot)
        val c = list[0].toContact()
        assertTrue(c.paired)
        assertTrue(c.verified)
        assertNull("the vault holds only a number tag", c.number)
        assertNull(ContactListCodec.parse(raw + bytes(0)))
        assertNull(ContactListCodec.parse(raw.copyOf(raw.size - 1)))
        assertNull(ContactListCodec.parse(bytes(0, 1) + u32(1) + bytes(0x40) + p1 + bytes(0)))
        assertNull(ContactListCodec.parse(bytes(0, 1) + u32(0) + bytes(0) + p1 + bytes(0)))
        assertNull(ContactListCodec.parse(bytes(0, 1) + u32(1) + bytes(0x10) + p1 + bytes(0) + bytes(3) + u32(1)))
    }

    @Test
    fun trustTlvMatchesRustFromTlv() {
        val root = bytes(0x30, 0x03, 1, 2, 3)
        val serial = bytes(0x12, 0x34)
        val avb = ByteArray(32) { 7 }
        val signer = ByteArray(32) { 9 }
        val out = TrustTlv.encode(listOf(root), listOf(serial), listOf(avb), listOf(signer), 202411)!!
        val expected = bytes(1) +
            bytes(1, 0, root.size) + root +
            bytes(2, 0, serial.size) + serial +
            bytes(3, 0, 32) + avb +
            bytes(4, 0, 32) + signer +
            bytes(5, 0, 4) + ByteBuffer.allocate(4).putInt(202411).array()
        assertArrayEquals(expected, out)
        assertNull(TrustTlv.encode(emptyList(), emptyList(), emptyList(), listOf(signer), 202411))
        assertNull(TrustTlv.encode(listOf(root), emptyList(), emptyList(), emptyList(), 202411))
        assertNull(TrustTlv.encode(listOf(root), emptyList(), emptyList(), listOf(ByteArray(31)), 202411))
        assertNull(TrustTlv.encode(listOf(root), emptyList(), emptyList(), listOf(signer), 0))
    }

    @Test
    fun chainTlvDropsRootAndUsesU16Lengths() {
        val leaf = ByteArray(300) { 1 }
        val mid = bytes(2, 2)
        val root = bytes(3, 3, 3)
        val out = ChainTlv.encode(listOf(leaf, mid, root))!!
        assertArrayEquals(bytes(0x01, 0x2C) + leaf + bytes(0, 2) + mid, out)
        assertNull(ChainTlv.encode(listOf(leaf)))
    }

    // ---------------------------------------------------------------- daemon IPC (criterion 6), bytes from ipc.rs

    private val lease = ByteArray(16) { (it + 1).toByte() }

    @Test
    fun clientFramesAreByteExact() {
        assertArrayEquals(bytes(0, 2, 1, 1), DaemonCodec.encodeClient(ClientMsg.Hello(1)))
        assertArrayEquals(bytes(0, 1, 2), DaemonCodec.encodeClient(ClientMsg.Prepare))
        assertArrayEquals(bytes(0, 17, 6) + lease, DaemonCodec.encodeClient(ClientMsg.Attach(lease)))
        assertArrayEquals(bytes(0, 17, 8) + lease, DaemonCodec.encodeClient(ClientMsg.Heartbeat(lease)))
        assertArrayEquals(bytes(0, 1, 10), DaemonCodec.encodeClient(ClientMsg.End))
    }

    @Test
    fun serverFramesDecodeLikeRust() {
        assertEquals(ServerMsg.Hello(1, 1), DaemonCodec.decodeServer(bytes(1, 1, 1)))
        assertEquals(ServerMsg.Progress(5), DaemonCodec.decodeServer(bytes(3, 5)))
        val ready = DaemonCodec.decodeServer(bytes(4) + lease + bytes(1, 2, 7)) as ServerMsg.Ready
        assertArrayEquals(lease, ready.lease)
        assertEquals(Triple(1, 2, 7), Triple(ready.mode, ready.tier, ready.claims))
        assertEquals(ServerMsg.Fail(30, 300), DaemonCodec.decodeServer(bytes(5, 0, 30, 1, 44)))
        assertEquals(ServerMsg.Attached(1, 1, 3), DaemonCodec.decodeServer(bytes(7, 1, 1, 3)))
        assertEquals(ServerMsg.Violation(410), DaemonCodec.decodeServer(bytes(9, 1, 0x9A)))
        assertEquals(ServerMsg.Ended(1), DaemonCodec.decodeServer(bytes(11, 1)))
    }

    @Test
    fun serverDecoderRejectsWhatRustRejects() {
        fun error(body: ByteArray): FrameError {
            try {
                DaemonCodec.decodeServer(body)
            } catch (e: FrameException) {
                return e.error
            }
            fail("expected FrameException")
            throw IllegalStateException()
        }
        assertEquals(FrameError.LENGTH, error(ByteArray(0)))
        assertEquals(FrameError.BAD_PAYLOAD, error(bytes(5, 0, 1)))
        assertEquals(FrameError.BAD_PAYLOAD, error(bytes(4) + ByteArray(18)))
        assertEquals(FrameError.UNKNOWN_TYPE, error(bytes(6) + lease))
        assertEquals(FrameError.UNKNOWN_TYPE, error(bytes(8) + lease))
        assertEquals(FrameError.UNKNOWN_TYPE, error(bytes(10)))
    }

    @Test
    fun frameReaderSplitsAndLimits() {
        val frame = DaemonCodec.encodeServer(ServerMsg.Ready(lease, 1, 2, 7))
        val r = FrameReader()
        val got = ArrayList<ByteArray>()
        for (b in frame) got += r.push(byteArrayOf(b))
        assertEquals(1, got.size)
        assertEquals(ServerMsg.Ready(lease, 1, 2, 7), DaemonCodec.decodeServer(got[0]))
        val two = DaemonCodec.encodeServer(ServerMsg.Progress(1)) + DaemonCodec.encodeServer(ServerMsg.Ended(0))
        assertEquals(2, FrameReader().push(two).size)
        for (bad in listOf(bytes(0, 0), bytes(0, 65), bytes(0xFF, 0xFF, 1))) {
            try {
                FrameReader().push(bad)
                fail("length " + bad.toList() + " must be fatal")
            } catch (e: FrameException) {
                assertEquals(FrameError.LENGTH, e.error)
            }
        }
        assertEquals(1, FrameReader().push(bytes(0, 64) + ByteArray(64)).size)
    }
}
