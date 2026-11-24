package io.github.h4lovoid.dialcrypt

import io.github.h4lovoid.dialcrypt.core.InviteCard
import io.github.h4lovoid.dialcrypt.core.PairingCodeCodec
import io.github.h4lovoid.dialcrypt.core.PhoneRules
import io.github.h4lovoid.dialcrypt.core.real.ContactMetaStore
import io.github.h4lovoid.dialcrypt.core.real.VaultFile
import io.github.h4lovoid.dialcrypt.incoming.screen.IncomingMode
import io.github.h4lovoid.dialcrypt.incoming.screen.IncomingSettings
import io.github.h4lovoid.dialcrypt.incoming.screen.ScreeningStore
import io.github.h4lovoid.dialcrypt.ui.components.QrCodeEncoder
import java.io.File
import java.nio.ByteBuffer
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.After
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class IncomingAndPairingTest {
    @Rule
    @JvmField
    val tmp = TemporaryFolder()

    private var savedCountryCode: String? = null

    @Before
    fun useCountryCode44() {
        savedCountryCode = PhoneRules.defaultCountryCode
        PhoneRules.defaultCountryCode = "44"
    }

    @After
    fun restoreCountryCode() {
        PhoneRules.defaultCountryCode = savedCountryCode
    }

    @Test
    fun phoneRulesNormalizeToVaultE164AndMatchCandidates() {
        assertEquals("+447700900101", PhoneRules.toVaultE164("07700-900-101", "44"))
        assertEquals("+447700900202", PhoneRules.toVaultE164("+44 7700 900 202", "44"))
        assertEquals("+14155550199", PhoneRules.toVaultE164("+1 (415) 555-0199", "44"))
        assertEquals("+447700900101", PhoneRules.toVaultE164("00 44 7700 900 101", "44"))
        assertNull(PhoneRules.toVaultE164("123", "44"))
        assertNull(PhoneRules.toVaultE164("000000", "44"))

        val candidatesLocal = PhoneRules.matchCandidates("07700900101", "44")
        assertTrue(candidatesLocal.contains("+447700900101"))
        assertTrue(candidatesLocal.contains("07700900101"))

        val candidatesIntl = PhoneRules.matchCandidates("+447700900101", "44")
        assertTrue(candidatesIntl.contains("+447700900101"))
        assertTrue(candidatesIntl.contains("07700900101"))
    }

    @Test
    fun withoutACountryCodeLocalNumbersAreInvalidAndPlusNumbersStillWork() {
        assertNull(PhoneRules.toVaultE164("07700900101", null))
        assertNull(PhoneRules.toVaultE164("07700-900-101", null))
        assertEquals("+447700900101", PhoneRules.toVaultE164("+44 7700 900 101", null))
        assertEquals("+447700900101", PhoneRules.toVaultE164("00447700900101", null))

        assertEquals(setOf("07700900101"), PhoneRules.matchCandidates("07700900101", null))
        assertEquals(setOf("+447700900101"), PhoneRules.matchCandidates("+447700900101", null))

        PhoneRules.defaultCountryCode = null
        assertNull(PhoneRules.toVaultE164("07700900101"))
        PhoneRules.defaultCountryCode = "44"
        assertEquals("+447700900101", PhoneRules.toVaultE164("07700900101"))
    }

    @Test
    fun inviteCardRoundTripsCompactBinaryTextAndBarePairingCode() {
        val code = samplePairingCode()
        val card = InviteCard(
            name = "€€€_Alice_LongDisplayName_€€€€€€€€€€UTF8€€",
            number = "+447700900101",
            code = code,
        )
        val compact = card.toCompactBytes()
        assertNotNull(compact)
        assertTrue(compact!!.size <= 154)

        val decodedCompact = InviteCard.fromCompactBytes(compact)
        assertNotNull(decodedCompact)
        assertEquals(code, decodedCompact!!.code)
        assertEquals("+447700900101", decodedCompact.number)
        assertTrue(decodedCompact.name.isNotBlank())

        val textCard = card.toTextCard()!!
        assertTrue(textCard.startsWith("AEGISCARD1:"))
        val decodedText = InviteCard.parse("  $textCard\n")
        assertEquals(decodedCompact, decodedText)

        val decodedBare = InviteCard.parse("prefix note:\n$code")
        assertNotNull(decodedBare)
        assertEquals(code, decodedBare!!.code)
        assertEquals("", decodedBare.name)
        assertNull(decodedBare.number)
    }

    @Test
    fun qrCodeEncoderBuildsSquareMatrixForInviteCard() {
        val textCard = InviteCard("Alice", "+447700900101", samplePairingCode()).toTextCard()!!
        val matrix = QrCodeEncoder.encode(textCard)
        assertNotNull(matrix)
        assertTrue(matrix!!.size >= 21)
        assertEquals(matrix.size, matrix[0].size)
        assertTrue(matrix.any { row -> row.any { it } })
    }

    @Test
    fun screeningStoreFixedSizeMatchingReconcileAndWipe() {
        val screenFile = File(tmp.root, "screen.bin")
        val modeFile = File(tmp.root, "incoming_mode")
        val key = ByteArray(32) { (it + 11).toByte() }
        val macFn: (ByteArray) -> ByteArray = { input ->
            Mac.getInstance("HmacSHA256").run {
                init(SecretKeySpec(key, "HmacSHA256"))
                doFinal(input)
            }
        }
        val store = ScreeningStore(screenFile, macFn, deleteKey = { true }, modeFile = modeFile)

        val tagA = ByteArray(16) { 0x11 }
        val tagB = ByteArray(16) { 0x22 }
        assertTrue(store.put(tagA, "07700900101"))
        assertEquals(ScreeningStore.TOTAL_BYTES.toLong(), screenFile.length())
        assertTrue(screenFile.readBytes().copyOf(4).contentEquals("ASC1".toByteArray(Charsets.US_ASCII)))

        // Matches both local national format and canonical E.164 format.
        assertTrue(store.matches("07700900101"))
        assertTrue(store.matches("+447700900101"))
        assertFalse(store.matches("+447700900202"))

        // Reconcile drops tagA when deleted and adds tagB.
        assertTrue(store.reconcile(listOf(tagB to "+447700900202")))
        assertEquals(ScreeningStore.TOTAL_BYTES.toLong(), screenFile.length())
        assertFalse(store.matches("+447700900101"))
        assertTrue(store.matches("07700900202"))

        assertTrue(IncomingSettings.write(modeFile, IncomingMode.ALL))
        assertEquals(IncomingMode.ALL, IncomingSettings.read(modeFile))
        assertTrue(store.wipe())
        assertFalse(screenFile.exists())
        assertFalse(modeFile.exists())
        assertEquals(IncomingMode.CONTACTS, IncomingSettings.read(modeFile))
    }

    @Test
    fun contactMetaStorePersistsSeedAndNumbersAcrossReopen() {
        val metaFile = File(tmp.root, "contact_meta.bin")
        val xorKey = 0x5A.toByte()
        val seal: (ByteArray) -> ByteArray = { pt -> pt.map { (it.toInt() xor xorKey.toInt()).toByte() }.toByteArray() }
        val open: (ByteArray) -> ByteArray = { ct -> ct.map { (it.toInt() xor xorKey.toInt()).toByte() }.toByteArray() }

        var unlocked = true
        val s1 = ContactMetaStore(metaFile, seal, open, { unlocked })
        val seed1 = s1.loadOrInitSeed()!!
        assertEquals(32, seed1.size)
        assertTrue(s1.setNumber(7L, "07700900101"))
        unlocked = false
        assertNull(s1.numberFor(7L))

        val s2 = ContactMetaStore(metaFile, seal, open, alwaysUnlocked)
        val seed2 = s2.loadOrInitSeed()!!
        assertArrayEquals(seed1, seed2)
        assertEquals("07700900101", s2.numberFor(7L))

        val rotated = s2.rotateSeed()!!
        assertFalse(seed2.contentEquals(rotated))
        assertTrue(s2.wipe())
        assertFalse(metaFile.exists())
    }

    @Test
    fun contactMetaStoreKeepsMutualContactsAcrossReopenAndDropsDeletedOnes() {
        val metaFile = File(tmp.root, "contact_meta.bin")
        val s1 = ContactMetaStore(metaFile, xorSeal, xorSeal, alwaysUnlocked)
        val seed = s1.loadOrInitSeed()!!
        assertTrue(s1.setNumber(7L, "07700900101"))
        assertTrue(s1.setMutual(7L, true))
        assertTrue(s1.setMutual(8L, true))
        assertTrue(s1.setMutual(8L, false))
        assertEquals(3, xorSeal(metaFile.readBytes())[4].toInt())

        val s2 = ContactMetaStore(metaFile, xorSeal, xorSeal, alwaysUnlocked)
        assertArrayEquals(seed, s2.loadOrInitSeed()!!)
        assertTrue(s2.isMutual(7L))
        assertFalse(s2.isMutual(8L))
        assertEquals("07700900101", s2.numberFor(7L))

        s2.retainContacts(setOf(9L))
        val s3 = ContactMetaStore(metaFile, xorSeal, xorSeal, alwaysUnlocked)
        s3.loadOrInitSeed()
        assertFalse("a deleted contact loses its mutual mark", s3.isMutual(7L))
        assertNull(s3.numberFor(7L))
        assertTrue(s3.wipe())
        s3.loadOrInitSeed()
        assertFalse(s3.isMutual(7L))
    }

    @Test
    fun contactMetaStoreReadsAVersionOneFileWithNoMutualContacts() {
        val metaFile = File(tmp.root, "contact_meta.bin")
        val seed = ByteArray(32) { (it * 7 + 1).toByte() }
        val number = "07700900123".toByteArray(Charsets.UTF_8)
        val v1 = ByteBuffer.allocate(4 + 1 + 32 + 2 + 8 + 1 + number.size)
            .put("ACMD".toByteArray(Charsets.US_ASCII)).put(1.toByte()).put(seed)
            .putShort(1).putLong(9L).put(number.size.toByte()).put(number)
            .array()
        assertTrue(VaultFile(metaFile).write(xorSeal(v1)))

        val store = ContactMetaStore(metaFile, xorSeal, xorSeal, alwaysUnlocked)
        val fresh = store.loadOrInitSeed()!!
        assertFalse("the old seed was printed in every pairing code, so it is replaced", fresh.contentEquals(seed))
        assertEquals("07700900123", store.numberFor(9L))
        assertFalse(store.isMutual(9L))
        assertEquals("rewritten as version 3 at once", 3, xorSeal(metaFile.readBytes())[4].toInt())

        assertTrue(store.setMutual(9L, true))
        val reopened = ContactMetaStore(metaFile, xorSeal, xorSeal, alwaysUnlocked)
        assertArrayEquals(fresh, reopened.loadOrInitSeed()!!)
        assertEquals("07700900123", reopened.numberFor(9L))
        assertTrue(reopened.isMutual(9L))
    }

    private val xorSeal: (ByteArray) -> ByteArray = { b -> b.map { (it.toInt() xor 0x5A).toByte() }.toByteArray() }
    private val alwaysUnlocked = { true }

    private fun samplePairingCode(): String {
        val raw = ByteArray(PairingCodeCodec.RAW_LEN)
        raw[0] = 3
        for (i in 1 until 66) raw[i] = ((i * 37 + 5) and 0xFF).toByte()
        var crc = 0xFFFF
        for (i in 0 until 66) {
            crc = crc xor ((raw[i].toInt() and 0xFF) shl 8)
            repeat(8) {
                crc = if ((crc and 0x8000) != 0) ((crc shl 1) xor 0x1021) and 0xFFFF else (crc shl 1) and 0xFFFF
            }
        }
        raw[66] = ((crc ushr 8) and 0xFF).toByte()
        raw[67] = (crc and 0xFF).toByte()
        return PairingCodeCodec.encode(raw)!!
    }
}
