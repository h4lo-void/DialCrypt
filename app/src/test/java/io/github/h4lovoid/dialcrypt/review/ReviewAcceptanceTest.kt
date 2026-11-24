package io.github.h4lovoid.dialcrypt.review

import io.github.h4lovoid.dialcrypt.core.ContactMembership
import io.github.h4lovoid.dialcrypt.core.NumberPresentation
import io.github.h4lovoid.dialcrypt.core.NumberVisibility
import io.github.h4lovoid.dialcrypt.core.PhoneRules
import io.github.h4lovoid.dialcrypt.dialer.model.NumberText
import io.github.h4lovoid.dialcrypt.dialer.model.NumberTexts
import io.github.h4lovoid.dialcrypt.incoming.screen.ContactNumberIndex
import io.github.h4lovoid.dialcrypt.incoming.screen.NumberIndexKey
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

/** Independent acceptance checks for the number display rule, the contact number index and the sources. */
class ReviewAcceptanceTest {
    @Rule
    @JvmField
    val tmp = TemporaryFolder()

    private class CountingKey : NumberIndexKey {
        var secret: ByteArray? = null
        var ensureCalls = 0
        var deleteCalls = 0

        override fun hmac(input: ByteArray): ByteArray? = secret?.let { s ->
            Mac.getInstance("HmacSHA256").run {
                init(SecretKeySpec(s, "HmacSHA256"))
                doFinal(input)
            }
        }

        override fun ensure(): Boolean {
            ensureCalls++
            if (secret == null) secret = ByteArray(32) { (it * 11 + 5).toByte() }
            return true
        }

        override fun delete(): Boolean {
            deleteCalls++
            secret = null
            return true
        }
    }

    private val key = CountingKey()
    private var saved: String? = null
    private val file get() = File(tmp.root, ContactNumberIndex.FILE_NAME)

    /** Filler tags in a fixed order, so an answer of "not a contact" never depends on chance. */
    private class FixedRandom : SecureRandom() {
        private var n = 0

        override fun nextInt(bound: Int): Int = (n++ * 7919 + 13) % bound
    }

    private fun index(vault: Boolean = true) = ContactNumberIndex(file, key, { vault }, FixedRandom())

    @Before
    fun setCountry() {
        saved = PhoneRules.defaultCountryCode
        PhoneRules.defaultCountryCode = "44"
    }

    @After
    fun restoreCountry() {
        PhoneRules.defaultCountryCode = saved
    }

    // ---- criterion 1: the rule table --------------------------------------------------------

    @Test
    fun theRuleTableHoldsForEveryCombination() {
        val n = "+447700900101"
        val masked = PhoneRules.mask(n)
        for (showFull in listOf(false, true)) {
            for (locked in listOf(false, true)) {
                assertEquals(n, NumberVisibility.text(n, ContactMembership.NOT_CONTACT, showFull, locked))
                assertEquals(masked, NumberVisibility.text(n, ContactMembership.UNKNOWN, showFull, locked))
                val contact = NumberVisibility.text(n, ContactMembership.CONTACT, showFull, locked)
                assertEquals(if (showFull && !locked) n else masked, contact)
            }
        }
        assertNull(NumberVisibility.text(null, ContactMembership.NOT_CONTACT, true, false))
        assertNull(NumberVisibility.text("  ", ContactMembership.CONTACT, true, false))
    }

    @Test
    fun theInCallLineFollowsTheSameTable() {
        val n = "+447700900101"
        val masked = NumberText.Digits(PhoneRules.mask(n)!!)
        fun line(m: ContactMembership, full: Boolean, locked: Boolean, p: NumberPresentation = NumberPresentation.SHOWN, payphone: Boolean = false) =
            NumberTexts.of(n, p, m, full, locked, payphone)
        assertEquals(NumberText.Digits(n), line(ContactMembership.NOT_CONTACT, false, true))
        assertEquals(masked, line(ContactMembership.CONTACT, false, false))
        assertEquals(masked, line(ContactMembership.CONTACT, true, true))
        assertEquals(NumberText.Digits(n), line(ContactMembership.CONTACT, true, false))
        assertEquals(masked, line(ContactMembership.UNKNOWN, true, false))
        assertEquals(NumberText.Hidden, line(ContactMembership.NOT_CONTACT, true, false, NumberPresentation.WITHHELD))
        assertEquals(NumberText.Unknown, line(ContactMembership.NOT_CONTACT, true, false, NumberPresentation.UNKNOWN))
        assertEquals(NumberText.Payphone, line(ContactMembership.NOT_CONTACT, true, false, payphone = true))
    }

    // ---- criteria 2 and 3: the index -----------------------------------------------------------

    @Test
    fun theFileNeverHoldsANumberAndIsPaddedToBlocksOf64() {
        val numbers = listOf("+447700900101", "+15551234567")
        assertTrue(index().rebuild(numbers))
        val raw = file.readBytes()
        assertEquals(4 + 16 + 64 * 3, raw.size)
        val text = String(raw, Charsets.ISO_8859_1)
        for (n in numbers) {
            assertFalse(text.contains(n))
            assertFalse(text.contains(n.drop(1)))
            assertFalse(text.contains(n.takeLast(7)))
        }
        val many = (1..65).map { "+4477009" + (10000 + it).toString() }
        assertTrue(index().rebuild(many))
        assertEquals(4 + 16 + 128 * 3, file.readBytes().size)
        assertTrue(many.all { index().lookup(it) == ContactMembership.CONTACT })
    }

    @Test
    fun aLookupNeverCreatesTheKey() {
        assertTrue(index().rebuild(listOf("+447700900101")))
        val ensuresAfterBuild = key.ensureCalls
        key.delete()
        assertEquals(ContactMembership.UNKNOWN, index().lookup("+447700900101"))
        assertEquals(ContactMembership.UNKNOWN, index().lookup("+15551234567"))
        assertEquals(ensuresAfterBuild, key.ensureCalls)
        assertNull(key.secret)
    }

    @Test
    fun wipingRemovesTheFileTheLeftoverTempFileAndTheKey() {
        assertTrue(index().rebuild(listOf("+447700900101")))
        File(file.path + ".tmp").writeBytes(byteArrayOf(1, 2, 3))
        assertTrue(index().wipe())
        assertFalse(file.exists())
        assertFalse(File(file.path + ".tmp").exists())
        assertNull(key.secret)
        assertEquals(ContactMembership.NOT_CONTACT, index(vault = false).lookup("+447700900101"))
    }

    @Test
    fun spellingsWithCountryCodeAndLocalFormShareOneTag() {
        assertTrue(index().rebuild(listOf("07700 900101")))
        for (s in listOf("+44 7700 900101", "0044 7700-900101", "(07700) 900101", "+447700900101")) {
            assertEquals(s, ContactMembership.CONTACT, index().lookup(s))
        }
        assertEquals(ContactMembership.NOT_CONTACT, index().lookup("+447700900102"))
    }

    @Test
    fun aLocalNumberWithoutASimCountryIsStillFoundByItsEnding() {
        assertTrue(index().rebuild(listOf("+447700900101")))
        PhoneRules.defaultCountryCode = null
        assertEquals(ContactMembership.CONTACT, index().lookup("07700900101"))
        assertEquals(ContactMembership.CONTACT, index().lookup("+447700900101"))
    }

    // Each of these once made a contact read as a stranger, so the number showed whole.

    @Test
    fun aNationalNumberWithoutATrunkZeroIsFound() {
        PhoneRules.defaultCountryCode = "1"
        assertTrue(index().rebuild(listOf("+15551234567")))
        assertEquals(ContactMembership.CONTACT, index().lookup("+15551234567"))
        // 10 digits as dialled in the US: the call log keeps them as typed.
        assertEquals(ContactMembership.CONTACT, index().lookup("5551234567"))
    }

    @Test
    fun theIndexDoesNotDependOnTheSimCountryItWasBuiltUnder() {
        assertTrue(index().rebuild(listOf("07700900101")))
        assertEquals(ContactMembership.CONTACT, index().lookup("+447700900101"))
        // The same stored text, rebuilt after the SIM country changed, still stands for the same number.
        PhoneRules.defaultCountryCode = "49"
        assertTrue(index().rebuild(listOf("07700900101")))
        assertEquals(ContactMembership.CONTACT, index().lookup("+447700900101"))
    }

    @Test
    fun aRebuildWhileTheSimCountryIsUnknownKeepsLocalNumbers() {
        PhoneRules.defaultCountryCode = null
        assertTrue(index().rebuild(listOf("07700900101", "+15551234567")))
        PhoneRules.defaultCountryCode = "44"
        assertEquals(ContactMembership.CONTACT, index().lookup("+447700900101"))
        assertEquals(ContactMembership.CONTACT, index().lookup("+15551234567"))
    }

    // ---- criteria 4, 5, 9 and 10: the sources ---------------------------------------------------

    private val resDir = File(System.getProperty("aegis.resDir") ?: "src/main/res")
    private val mainDir = resDir.parentFile
    private val srcRoot = File(mainDir, "java/io/github/h4lovoid/dialcrypt")
    private fun kt(root: File) = root.walkTopDown().filter { it.isFile && it.extension == "kt" }.toList()

    @Test
    fun theDirectBootGuardsAreInPlace() {
        val guarded = listOf(
            "incoming/screen/DisplaySettings.kt",
            "incoming/screen/ContactNumberIndex.kt",
            "dialer/SecureBusyMarker.kt",
            "call/CallAudioMuter.kt",
            "incoming/CallRegistry.kt",
        )
        for (rel in guarded) {
            val f = File(srcRoot, rel)
            assertTrue("missing " + rel, f.isFile)
            assertTrue(rel, f.readText().contains("DirectBoot.isUserUnlocked("))
        }
    }

    @Test
    fun onlyThreeComponentsAreDirectBootAwareAndTheServiceStaysGatedForRelease() {
        val manifest = File(mainDir, "AndroidManifest.xml").readText()
        val element = Regex("<(service|receiver|activity|provider)\\s[^>]*?>", RegexOption.DOT_MATCHES_ALL)
        val tags = element.findAll(manifest).map { it.value }.toList()
        val aware = tags.filter { it.contains("android:directBootAware=\"true\"") }
            .map { Regex("android:name=\"([^\"]+)\"").find(it)!!.groupValues[1] }
            .toSet()
        assertEquals(setOf(".dialer.DialerInCallService", ".dialer.CallActionReceiver", ".dialer.InCallActivity"), aware)
        val service = tags.first { it.contains(".dialer.DialerInCallService") }
        assertTrue(service.contains("android:enabled=\"" + "$" + "{dialerComponentsEnabled}\""))
    }

    @Test
    fun noPhoneNumberReachesALogLine() {
        val logLine = Regex("Log\\.[wiedv]\\(")
        val numberRef = Regex("\\$\\{?(number|digits|e164|dialNumber|raw)\\b|\\+\\s*(number|digits|e164|dialNumber|raw)\\b|\\.number\\b")
        val hits = kt(srcRoot).flatMap { f ->
            f.readLines().withIndex().filter { logLine.containsMatchIn(it.value) && numberRef.containsMatchIn(it.value) }
                .map { f.name + ":" + (it.index + 1) }
        }
        assertTrue(hits.toString(), hits.isEmpty())
    }

    private fun hasHan(s: String) = s.any { it.code in 0x4E00..0x9FFF }

    @Test
    fun noChineseInProductionCodeCommentsOrTheLatinStrings() {
        val files = kt(srcRoot) + listOf("values", "values-es", "values-fr").map { File(resDir, it + "/strings.xml") } +
            listOf(File(mainDir, "AndroidManifest.xml"))
        // The language picker names Simplified Chinese in its own script in every strings file.
        val bad = files.filter { f ->
            f.isFile && f.readLines().any { line -> !line.contains("lang_zh_hans") && hasHan(line) }
        }.map { it.path }
        assertTrue(bad.toString(), bad.isEmpty())
    }

    @Test
    fun theSimplifiedFileHoldsNoTraditionalOnlyCharacters() {
        // Characters whose form differs from the Simplified one, written as escapes.
        val traditional = "\u865f\u78bc\u806f\u7d61\u8a2d\u5099\u96fb\u8a71\u95dc\u958b\u4f86\u9019\u500b\u70ba\u6703\u5f9e\u9ad4\u9304\u9078\u9805\u986f\u96b1\u9396\u756b\u8f38\u61c9\u7576\u5f8c\u6642\u7121\u8207\u6a5f\u7d50\u4e26\u522a\u64c7\u9ede\u64ca\u50c5\u9375\u64a5\u8aaa\u9084"
        val text = File(resDir, "values-b+zh+Hans/strings.xml").readText()
        val hits = text.filter { it in traditional }.toSet()
        assertTrue(hits.joinToString(""), hits.isEmpty())
    }

    @Test
    fun allFourLanguagesHoldTheSameKeys() {
        fun keys(dir: String): Set<String> {
            val text = File(resDir, dir + "/strings.xml").readText()
            return Regex("<(?:string|plurals|string-array)\\s+name=\"([^\"]+)\"").findAll(text).map { it.groupValues[1] }.toSet()
        }
        val base = keys("values")
        assertTrue(base.size > 400)
        for (dir in listOf("values-b+zh+Hans", "values-es", "values-fr")) assertEquals(dir, base, keys(dir))
    }
}
