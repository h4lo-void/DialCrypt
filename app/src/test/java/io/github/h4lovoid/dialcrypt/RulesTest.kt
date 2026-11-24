package io.github.h4lovoid.dialcrypt

import io.github.h4lovoid.dialcrypt.core.FakeScenarios
import io.github.h4lovoid.dialcrypt.core.PhoneRules
import io.github.h4lovoid.dialcrypt.core.PinRules
import io.github.h4lovoid.dialcrypt.ui.keyboard.AccentMap
import io.github.h4lovoid.dialcrypt.ui.keyboard.InputKind
import io.github.h4lovoid.dialcrypt.ui.keyboard.KeyboardController
import io.github.h4lovoid.dialcrypt.ui.keyboard.KeyboardLayouts
import io.github.h4lovoid.dialcrypt.ui.keyboard.KeyboardPage
import io.github.h4lovoid.dialcrypt.ui.keyboard.SecureInputState
import io.github.h4lovoid.dialcrypt.ui.keyboard.ShiftState
import io.github.h4lovoid.dialcrypt.ui.model.ContactUi
import io.github.h4lovoid.dialcrypt.ui.model.Formatters
import io.github.h4lovoid.dialcrypt.ui.theme.Tone
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class RulesTest {

    @Test
    fun pinNeedsTenCharacters() {
        assertEquals(PinRules.Violation.TOO_SHORT, PinRules.violation("abcdefghi"))
        assertNull(PinRules.violation("abcdefghij"))
        assertEquals(PinRules.Violation.TOO_LONG, PinRules.violation("a1".repeat(40)))
    }

    @Test
    fun pinWithFewDistinctCharactersIsTooSimple() {
        assertEquals(PinRules.Violation.TOO_SIMPLE, PinRules.violation("aaaaaaaaaa"))
        assertEquals(PinRules.Violation.TOO_SIMPLE, PinRules.violation("ababababab"))
        assertNull(PinRules.violation("abcdabcdab"))
    }

    @Test
    fun emergencyPinMustDiffer() {
        assertTrue(PinRules.pairViolation("abcdefghij", "abcdefghij"))
        assertFalse(PinRules.pairViolation("abcdefghij", "abcdefghik"))
    }

    @Test
    fun strengthGrowsWithLengthAndVariety() {
        assertEquals(PinRules.Strength.WEAK, PinRules.strength("1234567890"))
        assertEquals(PinRules.Strength.WEAK, PinRules.strength("aaaaaaaaaaaa"))
        assertTrue(PinRules.strength("correct horse battery").ordinal >= PinRules.Strength.GOOD.ordinal)
        assertEquals(PinRules.Strength.STRONG, PinRules.strength("Tr0ub4dor&3-Xylophone!42"))
    }

    @Test
    fun numberIsMaskedExceptLastFourDigits() {
        assertEquals("\u2022\u2022\u2022\u2022 3456", PhoneRules.mask("+34600123456"))
        assertNull(PhoneRules.mask(null))
        assertTrue(PhoneRules.isValid("+34 600 123 456"))
        assertFalse(PhoneRules.isValid("123"))
        assertEquals("+34600123456", PhoneRules.normalize("+34 600-123-456"))
    }

    @Test
    fun pairingCodeIsGroupedInFives() {
        assertEquals("ABCDE FGHJK 23", Formatters.groupCode("ABCDEFGHJK23"))
    }

    @Test
    fun avatarLettersComeFromTheFirstAndLastWord() {
        assertEquals("AT", ContactUi.initials("Ana Torres"))
        assertEquals("AT", ContactUi.initials("  ana mar\u00EDa   torres "))
        assertEquals("C", ContactUi.initials("Courier"))
        assertEquals("\u00C9L", ContactUi.initials("\u00E9mile (l\u00F3uis)"))
        assertEquals("?", ContactUi.initials("   "))
    }

    @Test
    fun aContactShowsOneStatusAndAChangedKeyOutranksVerified() {
        assertEquals(R.string.badge_verified, ContactUi.status(FakeScenarios.ana).textRes)
        assertEquals(Tone.OK, ContactUi.status(FakeScenarios.ana).tone)
        assertEquals(R.string.badge_unverified, ContactUi.status(FakeScenarios.sam).textRes)
        assertEquals(Tone.WARN, ContactUi.status(FakeScenarios.sam).tone)
        val changed = FakeScenarios.ana.copy(keyChanged = true)
        assertEquals(R.string.badge_key_changed, ContactUi.status(changed).textRes)
        assertEquals(Tone.DANGER, ContactUi.status(changed).tone)
        assertTrue(ContactUi.showsQuickConnect(FakeScenarios.ana))
        assertFalse(ContactUi.showsQuickConnect(FakeScenarios.marc))
    }

    @Test
    fun pairedShowsOnlyWhenBothSidesSavedEachOther() {
        val savedByUsOnly = FakeScenarios.sam.copy(paired = true, mutual = false)
        assertEquals(R.string.detail_paired_waiting, ContactUi.status(savedByUsOnly).textRes)
        assertEquals(Tone.WARN, ContactUi.status(savedByUsOnly).tone)
        assertEquals(R.string.detail_paired_waiting, ContactUi.pairing(savedByUsOnly).textRes)

        val mutual = savedByUsOnly.copy(mutual = true)
        assertEquals(R.string.detail_paired_yes, ContactUi.status(mutual).textRes)
        assertEquals(Tone.OK, ContactUi.status(mutual).tone)
        assertEquals(R.string.detail_paired_yes, ContactUi.pairing(mutual).textRes)

        assertEquals(R.string.badge_unverified, ContactUi.status(FakeScenarios.sam).textRes)
        assertEquals(R.string.detail_paired_no, ContactUi.pairing(FakeScenarios.sam).textRes)
        assertEquals(Tone.NEUTRAL, ContactUi.pairing(FakeScenarios.sam).tone)
    }

    @Test
    fun inputBufferRespectsLimitAndPhoneAlphabet() {
        val text = SecureInputState(maxLength = 3)
        assertTrue(text.append("ab"))
        assertFalse(text.append("cd"))
        assertEquals("ab", text.text())
        text.backspace()
        assertEquals("a", text.text())
        text.clear()
        assertTrue(text.isEmpty)

        val phone = SecureInputState(maxLength = 10, kind = InputKind.PHONE)
        assertFalse(phone.append("a"))
        assertTrue(phone.append("+3"))
        assertEquals("+3", phone.text())
    }

    @Test
    fun longPressOffersSpanishAndFrenchLetters() {
        val kb = KeyboardController()
        val input = SecureInputState()
        assertTrue(kb.longPress("e"))
        assertTrue(kb.accents.containsAll(listOf("\u00E9", "\u00E8", "\u00EA", "\u00EB")))
        kb.pickAccent(input, "\u00E9")
        assertEquals("\u00E9", input.text())
        assertTrue(kb.accents.isEmpty())

        assertTrue(kb.longPress("n"))
        assertEquals(listOf("\u00F1"), kb.accents)
        kb.pickAccent(input, "\u00F1")
        assertTrue(kb.longPress("c"))
        kb.pickAccent(input, "\u00E7")
        assertEquals("\u00E9\u00F1\u00E7", input.text())
        assertFalse(kb.longPress("k"))
    }

    @Test
    fun shiftMakesAccentsUpperCaseAndReleasesAfterOneLetter() {
        val kb = KeyboardController()
        val input = SecureInputState()
        kb.tapShift()
        assertTrue(kb.longPress("e"))
        assertTrue(kb.accents.contains("\u00C9"))
        kb.pickAccent(input, "\u00C9")
        assertEquals("\u00C9", input.text())
        assertEquals(ShiftState.OFF, kb.shift)
        kb.type(input, "a")
        assertEquals("\u00C9a", input.text())
    }

    @Test
    fun capsLockStaysOnUntilTapped() {
        val kb = KeyboardController()
        val input = SecureInputState()
        kb.longPressShift()
        kb.type(input, "a")
        kb.type(input, "b")
        assertEquals("AB", input.text())
        kb.tapShift()
        kb.type(input, "c")
        assertEquals("ABc", input.text())
    }

    @Test
    fun everySpanishAndFrenchSpecialLetterIsReachable() {
        val reachable = ('a'..'z').flatMap { AccentMap.options(it.toString()) }.toSet() +
            listOf("?", "!").flatMap { AccentMap.options(it) }
        val needed = "\u00E1\u00E9\u00ED\u00F3\u00FA\u00FC\u00F1\u00BF\u00A1\u00E0\u00E2\u00E6\u00E7\u00E8\u00EA\u00EB\u00EE\u00EF\u00F4\u0153\u00F9\u00FB\u00FF"
        needed.forEach { assertTrue("missing " + it, it.toString() in reachable) }
    }

    @Test
    fun pagesAndLayouts() {
        val kb = KeyboardController()
        assertEquals(KeyboardPage.LETTERS, kb.page)
        kb.togglePage()
        assertEquals(KeyboardPage.SYMBOLS, kb.page)
        kb.togglePage()
        assertEquals(KeyboardPage.LETTERS, kb.page)
        kb.reset(InputKind.PHONE)
        assertEquals(KeyboardPage.PHONE, kb.page)
        assertEquals(26, KeyboardLayouts.letters.sumOf { it.length })
    }
}
