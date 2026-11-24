package io.github.h4lovoid.dialcrypt.real

import io.github.h4lovoid.dialcrypt.core.PairingPreview
import io.github.h4lovoid.dialcrypt.core.PairingResult
import io.github.h4lovoid.dialcrypt.core.real.NativeCode
import io.github.h4lovoid.dialcrypt.core.real.PairingDecisions
import io.github.h4lovoid.dialcrypt.core.real.PairingDecisions.Confirm
import io.github.h4lovoid.dialcrypt.core.real.PairingDecisions.DetailAction
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PairingDecisionsTest {
    @Test
    fun aPreviewTellsANewContactFromAnUnchangedOrAReplacedPairing() {
        assertEquals(PairingPreview.New, PairingDecisions.preview(0))
        assertEquals(PairingPreview.Unchanged(7L), PairingDecisions.preview(7))
        assertEquals(PairingPreview.Replaces(7L), PairingDecisions.preview(7 or NativeCode.PAIRING_PSK_CHANGED))
        for (rc in listOf(NativeCode.BAD_ARG, NativeCode.BAD_STATE, NativeCode.LOCKED, NativeCode.INTERNAL)) {
            assertEquals(PairingPreview.Invalid, PairingDecisions.preview(rc))
        }
    }

    @Test
    fun theMutualMarkFollowsOnlyAWrittenVault() {
        for (answers in listOf(true, false)) for (changed in listOf(true, false)) {
            assertNull("not written: unchanged", PairingDecisions.mutualAfterImport(answers, changed, saved = false))
        }
        assertEquals(true, PairingDecisions.mutualAfterImport(answersUs = true, pskChanged = true, saved = true))
        assertEquals(true, PairingDecisions.mutualAfterImport(answersUs = true, pskChanged = false, saved = true))
        assertEquals(false, PairingDecisions.mutualAfterImport(answersUs = false, pskChanged = true, saved = true))
        assertNull("same pairing again keeps the mark", PairingDecisions.mutualAfterImport(answersUs = false, pskChanged = false, saved = true))
    }

    @Test
    fun aSavedContactKeepsItsNameAndNumberUnlessChangedOnScreen() {
        assertTrue(PairingDecisions.keepsLabel("Bob", "Bob"))
        assertFalse(PairingDecisions.keepsLabel("Bob", "Robert"))
        assertFalse("new contact", PairingDecisions.keepsLabel(null, "Bob"))
        assertFalse(PairingDecisions.numberChanged("07700900123", "07700900123", existing = true))
        assertTrue(PairingDecisions.numberChanged("07700900123", "07700900124", existing = true))
        assertFalse("an empty field keeps it", PairingDecisions.numberChanged("07700900123", null, existing = true))
        assertTrue(PairingDecisions.numberChanged(null, "07700900123", existing = false))
        assertFalse(PairingDecisions.numberChanged(null, null, existing = false))
    }

    @Test
    fun onlyAClearAnswerCanBeSavedAndAReplacementIsNeverTheDefault() {
        assertEquals(Confirm.SAVE, PairingDecisions.confirmFor(PairingPreview.New))
        assertEquals(Confirm.SAVE, PairingDecisions.confirmFor(PairingPreview.Unchanged(3L)))
        assertEquals(Confirm.REPLACE, PairingDecisions.confirmFor(PairingPreview.Replaces(3L)))
        assertEquals("refused or failed check", Confirm.REFUSE, PairingDecisions.confirmFor(PairingPreview.Invalid))
        assertEquals("check still running", Confirm.REFUSE, PairingDecisions.confirmFor(null))
    }

    @Test
    fun theContactPageAsksBeforeReplacingItsPairing() {
        assertEquals(DetailAction.ConfirmReplace, PairingDecisions.detailAction(PairingPreview.Replaces(5L), 5L))
        assertEquals(DetailAction.Submit, PairingDecisions.detailAction(PairingPreview.Unchanged(5L), 5L))
        // A code of nobody saved is refused by the core without a change.
        assertEquals(DetailAction.Submit, PairingDecisions.detailAction(PairingPreview.New, 5L))
        val other = PairingDecisions.detailAction(PairingPreview.Replaces(6L), 5L)
        assertTrue(other is DetailAction.Refuse && other.result == PairingResult.WRONG_KEY)
        val same = PairingDecisions.detailAction(PairingPreview.Unchanged(6L), 5L)
        assertTrue(same is DetailAction.Refuse && same.result == PairingResult.WRONG_KEY)
        val bad = PairingDecisions.detailAction(PairingPreview.Invalid, 5L)
        assertTrue(bad is DetailAction.Refuse && bad.result == PairingResult.BAD_FORMAT)
    }

    @Test
    fun anImportThatChangedNothingIsNotWritten() {
        assertFalse(PairingDecisions.needsWrite(pskChanged = false, renamed = false, numberSet = false))
        assertTrue(PairingDecisions.needsWrite(pskChanged = true, renamed = false, numberSet = false))
        assertTrue(PairingDecisions.needsWrite(pskChanged = false, renamed = true, numberSet = false))
        assertTrue(PairingDecisions.needsWrite(pskChanged = false, renamed = false, numberSet = true))
    }
}
