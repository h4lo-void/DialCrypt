package io.github.h4lovoid.dialcrypt.incoming

import io.github.h4lovoid.dialcrypt.core.ContactMembership
import io.github.h4lovoid.dialcrypt.core.PhoneRules
import io.github.h4lovoid.dialcrypt.core.real.NativeSecureCore
import io.github.h4lovoid.dialcrypt.incoming.screen.ContactNumberIndex
import io.github.h4lovoid.dialcrypt.incoming.screen.NumberIndexKey
import io.github.h4lovoid.dialcrypt.incoming.screen.NumberTails
import java.io.File
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class ContactNumberIndexTest {
    @Rule
    @JvmField
    val tmp = TemporaryFolder()

    /** Stands in for the Keystore key, which unit tests cannot reach. */
    private class FakeKey : NumberIndexKey {
        var secret: ByteArray? = null
        var creatable = true
        var hmacCalls = 0

        override fun hmac(input: ByteArray): ByteArray? {
            hmacCalls++
            return secret?.let { s ->
                Mac.getInstance("HmacSHA256").run {
                    init(SecretKeySpec(s, "HmacSHA256"))
                    doFinal(input)
                }
            }
        }

        override fun ensure(): Boolean {
            if (secret == null && creatable) secret = ByteArray(32) { (it * 7 + 3).toByte() }
            return secret != null
        }

        override fun delete(): Boolean {
            secret = null
            return true
        }
    }

    /** Filler tags from a fixed sequence: a chance collision with a stranger's tag cannot differ between runs. */
    private class SteppingRandom : SecureRandom() {
        private var state = 7

        override fun nextInt(bound: Int): Int {
            state = (state * 31 + 17) and 0x7FFFFFFF
            return state % bound
        }
    }

    private val key = FakeKey()
    private var vaultExists = true
    private var savedCountryCode: String? = null
    private val file get() = File(tmp.root, ContactNumberIndex.FILE_NAME)
    private val index get() = ContactNumberIndex(file, key, { vaultExists }, random = SteppingRandom())

    @Before
    fun useCountryCode44() {
        savedCountryCode = PhoneRules.defaultCountryCode
        PhoneRules.defaultCountryCode = "44"
    }

    @After
    fun restoreCountryCode() {
        PhoneRules.defaultCountryCode = savedCountryCode
    }

    private fun tagsOf(raw: ByteArray): List<Int> =
        (ContactNumberIndex.HEADER_BYTES until raw.size step ContactNumberIndex.TAG_BYTES).map { off ->
            ((raw[off].toInt() and 0xFF) shl 16) or ((raw[off + 1].toInt() and 0xFF) shl 8) or (raw[off + 2].toInt() and 0xFF)
        }

    @Test
    fun everySpellingOfAContactNumberIsFound() {
        assertTrue(index.rebuild(listOf("+44 7700 900101", "07700900202")))
        for (n in listOf("07700 900 101", "+447700900101", "0044 7700 900101", "+44 7700-900-101")) {
            assertEquals(n, ContactMembership.CONTACT, index.lookup(n))
        }
        assertEquals(ContactMembership.CONTACT, index.lookup("(07700) 900-202"))
        assertEquals(ContactMembership.CONTACT, index.lookup("+447700900202"))
        assertEquals(ContactMembership.NOT_CONTACT, index.lookup("+447700900303"))
        assertEquals(ContactMembership.NOT_CONTACT, index.lookup("+14155550199"))
    }

    @Test
    fun theFileHoldsOnlyPaddedSortedTwentyBitTags() {
        assertTrue(index.rebuild(listOf("+447700900101")))
        val small = file.readBytes()
        assertEquals(ContactNumberIndex.HEADER_BYTES + ContactNumberIndex.BLOCK * ContactNumberIndex.TAG_BYTES, small.size)
        assertTrue(small.copyOf(4).contentEquals("DCN2".toByteArray(Charsets.US_ASCII)))
        assertFalse(String(small, Charsets.ISO_8859_1).contains("7700900101"))
        assertFalse(String(small, Charsets.ISO_8859_1).contains("00900101"))
        val tags = tagsOf(small)
        assertEquals(tags.sorted(), tags)
        assertTrue(tags.all { it in 0 until ContactNumberIndex.TAG_SPACE })

        // Without contacts the file has the same size as with one.
        assertTrue(index.rebuild(emptyList()))
        assertEquals(small.size.toLong(), file.length())

        val many = (1..65).map { "+4477009%05d".format(it) }
        assertTrue(index.rebuild(many))
        assertEquals(
            (ContactNumberIndex.HEADER_BYTES + 2 * ContactNumberIndex.BLOCK * ContactNumberIndex.TAG_BYTES).toLong(),
            file.length(),
        )
        assertTrue(many.all { index.lookup(it) == ContactMembership.CONTACT })
    }

    @Test
    fun noContactsMeansStrangersShowWhole() {
        assertTrue(index.rebuild(emptyList()))
        assertEquals(ContactMembership.NOT_CONTACT, index.lookup("+447700900101"))
    }

    @Test
    fun withoutAnIndexOnlyAMissingVaultMeansNotAContact() {
        vaultExists = false
        assertEquals(ContactMembership.NOT_CONTACT, index.lookup("+447700900101"))
        vaultExists = true
        assertEquals(ContactMembership.UNKNOWN, index.lookup("+447700900101"))
    }

    @Test
    fun aDamagedIndexIsUnknown() {
        assertTrue(index.rebuild(listOf("+447700900101")))
        val good = file.readBytes()

        file.writeBytes(good.copyOf(good.size - 1))
        assertEquals(ContactMembership.UNKNOWN, index.lookup("+447700900303"))

        file.writeBytes(good.copyOf().also { it[0] = 'X'.code.toByte() })
        assertEquals(ContactMembership.UNKNOWN, index.lookup("+447700900303"))

        // Tags out of order.
        val unsorted = good.copyOf()
        val h = ContactNumberIndex.HEADER_BYTES
        unsorted[h] = 0x0F
        unsorted[h + 1] = 0xFF.toByte()
        unsorted[h + 2] = 0xFF.toByte()
        file.writeBytes(unsorted)
        assertEquals(ContactMembership.UNKNOWN, index.lookup("+447700900303"))
    }

    @Test
    fun aMissingOrReplacedKeyIsUnknown() {
        assertTrue(index.rebuild(listOf("+447700900101")))
        key.secret = null
        assertEquals(ContactMembership.UNKNOWN, index.lookup("+447700900303"))
        key.secret = ByteArray(32) { 1 }
        assertEquals(ContactMembership.UNKNOWN, index.lookup("+447700900303"))
        assertEquals(ContactMembership.UNKNOWN, index.lookup("+447700900101"))
    }

    @Test
    fun aContactIsFoundWithoutASimCountryAndAShortCodeIsNeverAContact() {
        assertTrue(index.rebuild(listOf("+447700900101")))
        PhoneRules.defaultCountryCode = null
        assertEquals(ContactMembership.CONTACT, index.lookup("07700900101"))
        assertEquals(ContactMembership.CONTACT, index.lookup("+447700900101"))
        assertEquals(ContactMembership.NOT_CONTACT, index.lookup("07700900303"))
        // A short code can never be a contact number, whatever the key says.
        assertEquals(ContactMembership.NOT_CONTACT, index.lookup("112"))
        key.secret = null
        assertEquals(ContactMembership.NOT_CONTACT, index.lookup("112"))
        assertEquals(ContactMembership.UNKNOWN, index.lookup("+447700900101"))
    }

    @Test
    fun everyWayOfWritingANumberSharesATailWhateverTheSimCountry() {
        for (cc in listOf("44", "49", "1", null)) {
            val tails = listOf("+44 7700 900101", "0044 7700 900101", "07700 900101", "7700900101", "447700900101")
                .map { NumberTails.of(it, cc) }
            assertTrue("cc=$cc", tails.all { "00900101" in it })
        }
        assertEquals(setOf("51234567"), NumberTails.of("+1 (555) 123-4567", "1"))
        assertEquals(setOf("51234567"), NumberTails.of("5551234567", "1"))
        assertTrue(NumberTails.of("112", "44").isEmpty())
        assertTrue(NumberTails.of("00000", "44").isEmpty())
    }

    @Test
    fun aNationalNumberShorterThanTheTailNeedsTheSimCountryOnOneSideOnly() {
        // Iceland: seven-digit national numbers, no trunk prefix.
        PhoneRules.defaultCountryCode = "354"
        assertTrue(index.rebuild(listOf("+354 555 1234")))
        assertEquals(ContactMembership.CONTACT, index.lookup("5551234"))
        assertEquals(ContactMembership.CONTACT, index.lookup("003545551234"))
        assertEquals(ContactMembership.NOT_CONTACT, index.lookup("5551235"))

        // Saved as dialed locally while the SIM country was unknown, called from the full number later.
        PhoneRules.defaultCountryCode = null
        assertTrue(index.rebuild(listOf("555 1234")))
        PhoneRules.defaultCountryCode = "354"
        assertEquals(ContactMembership.CONTACT, index.lookup("+3545551234"))
        assertEquals(ContactMembership.CONTACT, index.lookup("5551234"))
    }

    @Test
    fun aShortLocalNumberThatIsNotFoundIsUnknownWhileTheSimCountryIsUnknown() {
        PhoneRules.defaultCountryCode = null
        assertTrue(index.rebuild(listOf("+354 555 1234", "+49 89 1234")))
        // The contact may be stored with its country code: a miss says nothing.
        assertEquals(ContactMembership.UNKNOWN, index.lookup("5551234"))
        assertEquals(ContactMembership.UNKNOWN, index.lookup("089 1234"))
        assertEquals(ContactMembership.UNKNOWN, index.lookup("7654321"))
        // Long enough, or written with a country code: the ending can be compared.
        assertEquals(ContactMembership.NOT_CONTACT, index.lookup("0170 7654321"))
        assertEquals(ContactMembership.NOT_CONTACT, index.lookup("+354 555 1235"))
        assertEquals(ContactMembership.NOT_CONTACT, index.lookup("00354 555 1235"))
        assertEquals(ContactMembership.NOT_CONTACT, index.lookup("112"))
        // With a SIM country the local number is compared with the country code in front.
        PhoneRules.defaultCountryCode = "354"
        assertEquals(ContactMembership.CONTACT, index.lookup("5551234"))
        assertEquals(ContactMembership.NOT_CONTACT, index.lookup("7654321"))
    }

    @Test
    fun theIndexSurvivesARebuildUnderAnotherOrNoSimCountry() {
        for (cc in listOf("49", null)) {
            PhoneRules.defaultCountryCode = cc
            assertTrue(index.rebuild(listOf("07700 900101", "+1 555 123 4567")))
            PhoneRules.defaultCountryCode = "44"
            assertEquals("built under $cc", ContactMembership.CONTACT, index.lookup("+447700900101"))
            assertEquals(ContactMembership.CONTACT, index.lookup("07700900101"))
            assertEquals(ContactMembership.CONTACT, index.lookup("5551234567"))
            assertEquals(ContactMembership.NOT_CONTACT, index.lookup("+447700900303"))
        }
    }

    @Test
    fun oneReaderChecksTheKeyOnceAndTagsEachTailOnce() {
        assertTrue(index.rebuild(listOf("+447700900101")))
        key.hmacCalls = 0
        val reader = index.open()
        repeat(3) {
            assertEquals(ContactMembership.CONTACT, reader.lookup("+447700900101"))
            assertEquals(ContactMembership.CONTACT, reader.lookup("07700 900101"))
            assertEquals(ContactMembership.NOT_CONTACT, reader.lookup("+447700900303"))
        }
        // One key check and one tag for each of the two tails.
        assertEquals(3, key.hmacCalls)
        // The reader keeps its reading of the file.
        assertTrue(index.rebuild(emptyList()))
        assertEquals(ContactMembership.CONTACT, reader.lookup("+447700900101"))
        assertEquals(ContactMembership.NOT_CONTACT, index.lookup("+447700900101"))
    }

    @Test
    fun theVaultFileNameMatchesTheVault() {
        assertEquals(NativeSecureCore.VAULT_FILE, ContactNumberIndex.VAULT_FILE_NAME)
    }

    @Test
    fun aFailedRebuildRemovesTheOldIndex() {
        assertTrue(index.rebuild(listOf("+447700900101")))
        key.secret = null
        key.creatable = false
        assertFalse(index.rebuild(listOf("+447700900202")))
        assertFalse(file.exists())
        assertEquals(ContactMembership.UNKNOWN, index.lookup("+447700900202"))
    }

    @Test
    fun wipingTheVaultRemovesTheIndexAndItsKey() {
        assertTrue(index.rebuild(listOf("+447700900101")))
        assertTrue(index.wipe())
        assertFalse(file.exists())
        assertFalse(File(file.path + ".tmp").exists())
        assertNull(key.secret)
        vaultExists = false
        assertEquals(ContactMembership.NOT_CONTACT, index.lookup("+447700900101"))
    }
}
