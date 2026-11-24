package io.github.h4lovoid.dialcrypt.review

import io.github.h4lovoid.dialcrypt.core.ContactMembership
import io.github.h4lovoid.dialcrypt.core.PhoneRules
import io.github.h4lovoid.dialcrypt.incoming.screen.ContactNumberIndex
import io.github.h4lovoid.dialcrypt.incoming.screen.NumberIndexKey
import java.io.File
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/** Second review: the index keyed by number endings. */
class ReviewRecheckIndexTest {
    @Rule
    @JvmField
    val tmp = TemporaryFolder()

    private class CountingKey : NumberIndexKey {
        var secret: ByteArray? = null
        var hmacCalls = 0

        override fun hmac(input: ByteArray): ByteArray? = secret?.let { s ->
            hmacCalls++
            Mac.getInstance("HmacSHA256").run {
                init(SecretKeySpec(s, "HmacSHA256"))
                doFinal(input)
            }
        }

        override fun ensure(): Boolean {
            if (secret == null) secret = ByteArray(32) { (it * 11 + 5).toByte() }
            return true
        }

        override fun delete(): Boolean {
            secret = null
            return true
        }
    }

    /** Filler tags in a fixed order, so an answer of "not a contact" never depends on chance. */
    private class FixedRandom : SecureRandom() {
        private var n = 0

        override fun nextInt(bound: Int): Int = (n++ * 7919 + 13) % bound
    }

    private val key = CountingKey()
    private var saved: String? = null
    private val file get() = File(tmp.root, ContactNumberIndex.FILE_NAME)
    private fun index() = ContactNumberIndex(file, key, { true }, FixedRandom())

    @Before
    fun keepCountry() {
        saved = PhoneRules.defaultCountryCode
    }

    @After
    fun restoreCountry() {
        PhoneRules.defaultCountryCode = saved
    }

    @Test
    fun everySpellingIsFoundWhateverTheSimCountryAtBuildOrLookup() {
        for (build in listOf<String?>("44", "1", "49", null)) {
            for (stored in listOf("07700900101", "+447700900101", "00447700900101", "7700900101")) {
                PhoneRules.defaultCountryCode = build
                assertTrue(index().rebuild(listOf(stored)))
                for (look in listOf<String?>("44", "1", null)) {
                    PhoneRules.defaultCountryCode = look
                    for (s in listOf("+44 7700 900101", "07700 900101", "7700900101", "0044 7700 900101")) {
                        assertEquals("$build/$stored/$look/$s", ContactMembership.CONTACT, index().lookup(s))
                    }
                }
            }
        }
    }

    @Test
    fun anIndexInTheOldLayoutIsUnknownUntilItIsRebuilt() {
        PhoneRules.defaultCountryCode = "44"
        assertTrue(index().rebuild(listOf("+447700900101")))
        val raw = file.readBytes()
        assertEquals("DCN2", String(raw.copyOf(4), Charsets.US_ASCII))
        "DCN1".toByteArray(Charsets.US_ASCII).copyInto(raw)
        file.writeBytes(raw)
        assertEquals(ContactMembership.UNKNOWN, index().lookup("+447700900101"))
        assertEquals(ContactMembership.UNKNOWN, index().lookup("+15551234567"))
        assertTrue(index().rebuild(listOf("+447700900101")))
        assertEquals(ContactMembership.CONTACT, index().lookup("+447700900101"))
        assertEquals(ContactMembership.NOT_CONTACT, index().lookup("+15551234567"))
    }

    @Test
    fun aShortNationalNumberIsFoundWhenOneSideKnowsTheCountry() {
        // Iceland: seven digits, no trunk zero.
        PhoneRules.defaultCountryCode = "354"
        assertTrue(index().rebuild(listOf("+3545551234")))
        PhoneRules.defaultCountryCode = null
        assertEquals(ContactMembership.CONTACT, index().lookup("5551234"))

        assertTrue(index().rebuild(listOf("+3545551234")))
        PhoneRules.defaultCountryCode = "354"
        assertEquals(ContactMembership.CONTACT, index().lookup("5551234"))
    }

    @Test
    fun aShortLocalNumberWithoutASimCountryIsUnknownNotAStranger() {
        PhoneRules.defaultCountryCode = null
        assertTrue(index().rebuild(listOf("+3545551234", "+49891234")))
        // The ending cannot be compared without the country code, so a miss shows masked.
        assertEquals(ContactMembership.UNKNOWN, index().lookup("5551234"))
        assertEquals(ContactMembership.UNKNOWN, index().lookup("0891234"))
        // Eight digits or more, or an international spelling, can be compared: a miss is a stranger.
        assertEquals(ContactMembership.NOT_CONTACT, index().lookup("55512345"))
        assertEquals(ContactMembership.NOT_CONTACT, index().lookup("+3545551235"))
    }

    // Known limit, behaviour as shipped: under a SIM of another country a contact's short local number
    // reads as a stranger, so it shows whole. The app cannot tell which country a short local number
    // belongs to; the README lists this next to the index.
    @Test
    fun knownLimit_aShortLocalNumberUnderAForeignSimReadsAsAStranger() {
        // Faroe Islands contact, six digits, seen in its local form while the SIM is British.
        PhoneRules.defaultCountryCode = "44"
        assertTrue(index().rebuild(listOf("+298123456")))
        assertEquals(ContactMembership.CONTACT, index().lookup("+298123456"))
        assertEquals(ContactMembership.NOT_CONTACT, index().lookup("123456"))
    }

    @Test
    fun oneReadingServesManyLookups() {
        PhoneRules.defaultCountryCode = "44"
        assertTrue(index().rebuild(listOf("+447700900101", "+15551234567")))
        val before = key.hmacCalls
        val reader = index().open()
        // The file is not read again.
        assertTrue(file.delete())
        assertEquals(ContactMembership.CONTACT, reader.lookup("+447700900101"))
        assertEquals(ContactMembership.CONTACT, reader.lookup("07700900101"))
        assertEquals(ContactMembership.CONTACT, reader.lookup("+15551234567"))
        assertEquals(ContactMembership.CONTACT, reader.lookup("+15551234567"))
        assertEquals(ContactMembership.NOT_CONTACT, reader.lookup("+33123456789"))
        // One key check and one tag for each of the three endings.
        assertEquals(4, key.hmacCalls - before)
    }
}
