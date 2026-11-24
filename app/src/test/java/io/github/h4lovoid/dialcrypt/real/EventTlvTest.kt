package io.github.h4lovoid.dialcrypt.real

import io.github.h4lovoid.dialcrypt.core.real.EventTlv
import io.github.h4lovoid.dialcrypt.core.real.NativeEvent
import io.github.h4lovoid.dialcrypt.core.real.NativeIdentity
import io.github.h4lovoid.dialcrypt.core.real.SessionPath
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class EventTlvTest {
    private val pubA = ByteArray(33) { (it + 1).toByte() }
    private val pubB = ByteArray(33) { (0x80 + it).toByte() }

    @Test
    fun emptyBufferHasNoEvents() {
        assertEquals(emptyList<NativeEvent>(), EventTlv.parse(ByteArray(0)))
    }

    @Test
    fun decodesEveryEventType() {
        val data = bytes {
            tlv(1, bytes { u32(0xFFFF_FFF0L).raw(byteArrayOf(9, 8, 7)) })
            tlv(2, byteArrayOf(0, 1, 127, -128, -1))
            tlv(3, bytes { u8(1).u8(1).u32(42) })
            tlv(4, byteArrayOf(55))
            tlv(5, bytes { u8(1).u8(0).u8(0).u32(0).u8(3).u32(7).u32(9).raw(pubA) })
            tlv(6, bytes { raw(pubA).raw(pubB) })
            tlv(7, ByteArray(0))
            tlv(8, byteArrayOf(1))
            tlv(9, byteArrayOf(250.toByte()))
            tlv(10, bytes { u32(3) })
            tlv(11, bytes { u32(4) })
            tlv(12, bytes { u32(0x8000_0001L) })
            tlv(14, bytes { u8(0xFC).u8(1).u32(202411).u8(1) })
            tlv(15, bytes { u16(513).raw("héllo".toByteArray(Charsets.UTF_8)) })
            tlv(16, bytes { u16(65535) })
            tlv(17, bytes { u16(2) })
            tlv(18, ByteArray(0))
            tlv(19, ByteArray(0))
            tlv(20, byteArrayOf(0))
            tlv(21, byteArrayOf(26))
            tlv(22, bytes { u16(513).u16(7).u16(30) })
            tlv(32, byteArrayOf(-4))
        }
        val ev = EventTlv.parse(data)!!
        assertEquals(22, ev.size)

        val sig = ev[0] as NativeEvent.NeedSignature
        assertEquals(0xFFFF_FFF0L.toInt(), sig.reqId)
        assertArrayEquals(byteArrayOf(9, 8, 7), sig.message)
        assertEquals(NativeEvent.Sas(listOf(0, 1, 127, 128, 255)), ev[1])
        assertEquals(NativeEvent.PathChosen(SessionPath(resume = true, usedNew = true, contactId = 42)), ev[2])
        assertEquals(NativeEvent.HandshakeProgress(55), ev[3])

        val est = ev[4] as NativeEvent.Established
        assertTrue(est.responder)
        assertEquals(SessionPath(resume = false, usedNew = false, contactId = 0), est.path)
        assertEquals(NativeIdentity.KEY_CHANGED, est.identity)
        assertEquals(7L, est.pskContactId)
        assertEquals(9L, est.storedContactId)
        assertArrayEquals(pubA, est.peerPub33)

        val changed = ev[5] as NativeEvent.KeyChanged
        assertArrayEquals(pubA, changed.storedPub33)
        assertArrayEquals(pubB, changed.peerPub33)
        assertEquals(NativeEvent.SasConfirmed, ev[6])
        assertEquals(NativeEvent.VoiceWindow(true), ev[7])
        assertEquals(NativeEvent.PqProgress(100), ev[8])
        assertEquals(NativeEvent.PqMixed(3), ev[9])
        assertEquals(NativeEvent.Epoch(4), ev[10])
        assertEquals(NativeEvent.VaultDirty(0x8000_0001L), ev[11])
        assertEquals(NativeEvent.Attestation(result = -4, boot = 1, osPatch = 202411, stored = true), ev[12])

        val msg = ev[13] as NativeEvent.MessageReceived
        assertEquals(513, msg.msgId)
        assertEquals("héllo", msg.text.toString(Charsets.UTF_8))
        assertEquals(NativeEvent.MessageDelivered(65535), ev[14])
        assertEquals(NativeEvent.MessageFailed(2), ev[15])
        assertEquals(NativeEvent.RemoteWipe, ev[16])
        assertEquals(NativeEvent.WipeSent, ev[17])
        assertEquals(NativeEvent.Ended(false), ev[18])
        assertEquals(NativeEvent.Aborted(26), ev[19])
        assertEquals(NativeEvent.MessageProgress(msgId = 513, acked = 7, total = 30), ev[20])
        assertEquals(NativeEvent.VaultFailed(-4), ev[21])
    }

    @Test
    fun emptyMessageTextIsAllowed() {
        val msg = EventTlv.parse(bytes { tlv(15, bytes { u16(1) }) })!!.single() as NativeEvent.MessageReceived
        assertEquals(0, msg.text.size)
    }

    @Test
    fun truncatedRecordIsMalformed() {
        val good = bytes { tlv(12, bytes { u32(1) }) }
        for (cut in 1 until good.size) assertNull("cut $cut", EventTlv.parse(good.copyOf(cut)))
        assertNull(EventTlv.parse(bytes { u8(12).u16(10).u32(1) }))
    }

    @Test
    fun wrongValueLengthIsMalformed() {
        val bad = listOf(
            bytes { tlv(1, bytes { u32(1) }) },
            bytes { tlv(2, ByteArray(4)) },
            bytes { tlv(3, ByteArray(5)) },
            bytes { tlv(5, ByteArray(48)) },
            bytes { tlv(6, ByteArray(65)) },
            bytes { tlv(7, byteArrayOf(0)) },
            bytes { tlv(8, ByteArray(0)) },
            bytes { tlv(12, ByteArray(3)) },
            bytes { tlv(14, ByteArray(6)) },
            bytes { tlv(15, ByteArray(1)) },
            bytes { tlv(16, ByteArray(3)) },
            bytes { tlv(18, byteArrayOf(1)) },
            bytes { tlv(20, ByteArray(2)) },
            bytes { tlv(21, ByteArray(0)) },
            bytes { tlv(22, ByteArray(5)) },
            bytes { tlv(22, ByteArray(7)) },
        )
        for ((i, b) in bad.withIndex()) assertNull("case $i", EventTlv.parse(b))
    }

    @Test
    fun outOfRangeCodesAreMalformed() {
        assertNull(EventTlv.parse(bytes { tlv(3, bytes { u8(2).u8(0).u32(0) }) }))
        assertNull(EventTlv.parse(bytes { tlv(3, bytes { u8(0).u8(2).u32(0) }) }))
        assertNull(EventTlv.parse(bytes { tlv(5, bytes { u8(0).u8(0).u8(0).u32(0).u8(4).u32(0).u32(0).raw(pubA) }) }))
        assertNull(EventTlv.parse(bytes { tlv(5, bytes { u8(2).u8(0).u8(0).u32(0).u8(0).u32(0).u32(0).raw(pubA) }) }))
        assertNull(EventTlv.parse(bytes { tlv(8, byteArrayOf(2)) }))
        assertNull(EventTlv.parse(bytes { tlv(14, bytes { u8(0).u8(3).u32(1).u8(0) }) }))
    }

    @Test
    fun unknownTypeIsMalformed() {
        assertNull(EventTlv.parse(bytes { tlv(7, ByteArray(0)).tlv(13, ByteArray(0)) }))
        assertNull(EventTlv.parse(bytes { tlv(99, byteArrayOf(1)) }))
    }
}
