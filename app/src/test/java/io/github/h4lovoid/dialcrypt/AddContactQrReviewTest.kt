package io.github.h4lovoid.dialcrypt

import android.content.Context
import android.media.AudioManager
import androidx.activity.ComponentActivity
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.core.app.ApplicationProvider
import com.google.zxing.BinaryBitmap
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.BitMatrix
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import com.google.zxing.qrcode.decoder.Decoder
import io.github.h4lovoid.dialcrypt.call.CallAudioMuter
import io.github.h4lovoid.dialcrypt.core.AppLanguage
import io.github.h4lovoid.dialcrypt.core.InviteCard
import io.github.h4lovoid.dialcrypt.core.PairingCodeCodec
import io.github.h4lovoid.dialcrypt.ui.components.QrCodeEncoder
import io.github.h4lovoid.dialcrypt.ui.components.QrScanner
import io.github.h4lovoid.dialcrypt.ui.keyboard.InputHost
import java.io.File
import java.util.Base64
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

/** QR encoder: every version 1..12 at both ends of its capacity, read back exactly and through the camera path. */
class AddContactQrReviewTest {
    /** ISO 18004 byte-mode capacity at error correction level L, versions 1..12 (independent of the encoder tables). */
    private val capacityL = intArrayOf(17, 32, 53, 78, 106, 134, 154, 192, 230, 271, 321, 367)

    private fun payload(len: Int, seed: Int): String {
        var x = seed * 2654435761L + 12345L
        val sb = StringBuilder(len)
        repeat(len) {
            x = (x * 6364136223846793005L + 1442695040888963407L)
            sb.append((33 + ((x ushr 33) % 94).toInt()).toChar())
        }
        return sb.toString()
    }

    private fun toBits(m: Array<BooleanArray>): BitMatrix {
        val bits = BitMatrix(m.size)
        for (r in m.indices) for (c in m.indices) if (m[r][c]) bits.set(c, r)
        return bits
    }

    /** Decodes the bare module grid with no detector, so every module position and codeword must be exact. */
    private fun assertExact(text: String, version: Int) {
        val m = QrCodeEncoder.encode(text)
        assertNotNull("v$version len=${text.length} must encode", m)
        // The smallest version that fits, or one of the next two when each of its masks holds a finder look-alike.
        val used = (m!!.size - 17) / 4
        assertTrue("v$version size ${m.size}", used in version..minOf(version + 2, 12))
        val res = Decoder().decode(toBits(m))
        assertEquals("v$version text", text, res.text)
        assertEquals("v$version error correction level", "L", res.getECLevel())
        assertTrue("v$version needed error correction: the encoder wrote wrong modules", res.errorsCorrected == 0)
    }

    /** Draws the code like a screen and reads it with the scanner's decoder class and binarizer. */
    private fun assertCameraRead(text: String, version: Int, scale: Int) {
        val m = QrCodeEncoder.encode(text)!!
        val quiet = 4
        val side = (m.size + 2 * quiet) * scale
        val bits = BitMatrix(side)
        for (r in m.indices) for (c in m.indices) if (m[r][c]) bits.setRegion((c + quiet) * scale, (r + quiet) * scale, scale, scale)
        val px = IntArray(side * side) { i -> if (bits.get(i % side, i / side)) -0x1000000 else -1 }
        val got = QRCodeReader().decode(BinaryBitmap(HybridBinarizer(RGBLuminanceSource(side, side, px)))).text
        assertEquals("v$version scale $scale", text, got)
    }

    @Test
    fun everyVersionFromOneToTwelveDecodesExactlyAtItsSmallestAndLargestPayload() {
        for (v in 1..12) {
            val min = if (v == 1) 1 else capacityL[v - 2] + 1
            val max = capacityL[v - 1]
            for (len in listOf(min, (min + max) / 2, max)) {
                for (seed in 1..4) assertExact(payload(len, seed * 31 + v), v)
            }
        }
    }

    @Test
    fun everyVersionIsReadByTheCameraDecoderAtSeveralPixelSizes() {
        for (v in 1..12) {
            val max = capacityL[v - 1]
            for (scale in listOf(3, 4, 6)) assertCameraRead(payload(max, 7 + v), v, scale)
            assertCameraRead(payload(if (v == 1) 1 else capacityL[v - 2] + 1, 90 + v), v, 4)
        }
    }

    @Test
    fun aPayloadOneByteOverVersionTwelveIsRefusedNotCorrupted() {
        assertNotNull(QrCodeEncoder.encode(payload(capacityL[11], 5)))
        assertNull(QrCodeEncoder.encode(payload(capacityL[11] + 1, 5)))
    }

    @Test
    fun multiByteTextAtTheEdgeOfEachVersionStillDecodesExactly() {
        for (v in 4..12) {
            val chars = capacityL[v - 1] / 3
            val text = "€".repeat(chars)
            val m = QrCodeEncoder.encode(text)
            assertNotNull("v$v", m)
            assertEquals("v$v text", text, Decoder().decode(toBits(m!!)).text)
        }
    }

    private fun codeOf(seed: Int): String {
        val raw = ByteArray(PairingCodeCodec.RAW_LEN)
        raw[0] = 3
        for (i in 1 until 66) raw[i] = ((i * 37 + seed * 101 + 5) and 0xFF).toByte()
        var crc = 0xFFFF
        for (i in 0 until 66) {
            crc = crc xor ((raw[i].toInt() and 0xFF) shl 8)
            repeat(8) { crc = if ((crc and 0x8000) != 0) ((crc shl 1) xor 0x1021) and 0xFFFF else (crc shl 1) and 0xFFFF }
        }
        raw[66] = ((crc ushr 8) and 0xFF).toByte()
        raw[67] = (crc and 0xFF).toByte()
        return PairingCodeCodec.encode(raw)!!
    }

    @Test
    fun everyCutOrExtendedVersionThreeCardIsRejectedWithoutACrash() {
        val ours = InviteCard("A", null, codeOf(1), 11L)
        val reply = InviteCard("Bob", "07700900456", codeOf(2), 22L, InviteCard.replyTag(ours, codeOf(2)))
        val text = reply.toTextCard()!!
        val bytes = Base64.getUrlDecoder().decode(text.removePrefix("AEGISCARD1:"))
        assertNotNull(InviteCard.fromCompactBytes(bytes))
        for (n in 0 until bytes.size) assertNull("prefix $n", InviteCard.fromCompactBytes(bytes.copyOf(n)))
        assertNull("one extra byte", InviteCard.fromCompactBytes(bytes + 0))
        assertNull(InviteCard.parse("AEGISCARD1:!!!"))
        assertNotNull("prefix is case-insensitive", InviteCard.parse(text.replaceFirst("AEGISCARD1:", "aegiscard1:")))
    }
}

/** Extra CallAudioMuter edges: volume and the owner's own mute come back, odd journals are tolerated. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class CallAudioMuterReviewTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val am: AudioManager = context.getSystemService(AudioManager::class.java)
    private val journal get() = CallAudioMuter.journalFor(context)

    @Before
    fun reset() {
        journal.delete()
        CallAudioMuter.resetLeftoverCheckForTest()
        am.isMicrophoneMute = false
        am.mode = AudioManager.MODE_NORMAL
    }

    @Test
    fun theJournalHoldsTheStateFromBeforeTheCall() {
        am.isMicrophoneMute = true
        am.setStreamVolume(AudioManager.STREAM_VOICE_CALL, 3, 0)
        val before = am.getStreamVolume(AudioManager.STREAM_VOICE_CALL)
        CallAudioMuter(am, journal = journal).engage()
        val text = journal.readText()
        assertTrue(text, text.contains("mic=1"))
        assertTrue(text, text.contains("vol=$before"))
    }

    @Test
    fun theCallVolumeComesBackAfterAKilledCall() {
        am.setStreamVolume(AudioManager.STREAM_VOICE_CALL, 3, 0)
        val before = am.getStreamVolume(AudioManager.STREAM_VOICE_CALL)
        CallAudioMuter(am, journal = journal).engage()
        CallAudioMuter.recoverLeftover(context)
        assertEquals(before, am.getStreamVolume(AudioManager.STREAM_VOICE_CALL))
        assertFalse(am.isMicrophoneMute)
    }

    @Test
    fun aMuterThatNeverEngagedLeavesAnotherCallsJournalAlone() {
        CallAudioMuter(am, journal = journal).engage()
        CallAudioMuter(am, journal = journal).release()
        assertTrue(journal.isFile)
        assertTrue(am.isMicrophoneMute)
    }

    @Test
    fun releasingTwiceDoesNotUndoALaterMute() {
        val first = CallAudioMuter(am, journal = journal)
        first.engage()
        first.release()
        val second = CallAudioMuter(am, journal = journal)
        second.engage()
        first.release()
        assertTrue(am.isMicrophoneMute)
        assertTrue(journal.isFile)
    }

    @Test
    fun anUnreadableJournalIsStillRemovedAndTheMicrophoneIsRestored() {
        am.isMicrophoneMute = true
        journal.parentFile?.mkdirs()
        journal.writeText("garbage")
        CallAudioMuter.recoverLeftover(context)
        assertFalse(journal.exists())
        assertFalse(am.isMicrophoneMute)
    }

    @Test
    fun characterization_aJournalOfAnotherProcessIsNotRecoveredByThisProcess() {
        // The :call hooks (IncomingCallService, CallRelayService) only ever look at the journal named after their own process.
        val other = File(journal.parentFile, "call_audio_mute_secure.journal")
        if (other == journal) return
        other.parentFile?.mkdirs()
        other.writeText("mic=0\nvol=3\n")
        am.isMicrophoneMute = true
        CallAudioMuter.recoverLeftover(context)
        assertTrue("other process journal untouched", other.isFile)
        assertTrue("microphone stays muted", am.isMicrophoneMute)
        other.delete()
    }
}

/** Camera permission refused: the page says why and offers a way to allow it, and does not open a camera. */
@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [34], qualifiers = "w411dp-h891dp-xxhdpi")
class QrScannerPermissionReviewTest {
    @get:Rule
    val rule = createAndroidComposeRule<ComponentActivity>()

    private val context: Context = ApplicationProvider.getApplicationContext()

    private fun assertAsksForTheCamera(language: AppLanguage) {
        rule.setContent { Harness(language, InputHost()) { QrScanner({ false }) } }
        rule.waitForIdle()
        rule.onNodeWithText(context.getString(R.string.add_camera_needed)).assertExists()
        rule.onNodeWithText(context.getString(R.string.add_camera_allow)).assertExists()
        val asked = shadowOf(rule.activity).nextStartedActivityForResult
        assertNotNull("the camera permission is requested when the scanner opens", asked)
        assertEquals("android.content.pm.action.REQUEST_PERMISSIONS", asked.intent.action)
        rule.onNodeWithText(context.getString(R.string.add_camera_allow)).performClick()
        rule.waitForIdle()
        rule.onNodeWithText(context.getString(R.string.add_camera_needed)).assertExists()
    }

    @Test
    fun withTheSystemLanguageTheReasonAnAllowButtonAndTheRequestAreThere() = assertAsksForTheCamera(AppLanguage.SYSTEM)

    @Test
    fun withAnExplicitlyChosenLanguageTheReasonAnAllowButtonAndTheRequestAreThere() = assertAsksForTheCamera(AppLanguage.EN)
}
