package io.github.h4lovoid.dialcrypt.core.real

import io.github.h4lovoid.dialcrypt.core.PairingPreview
import io.github.h4lovoid.dialcrypt.core.PairingResult

/** Rules around importing a pairing code, kept apart from the native calls so they can be tested. */
internal object PairingDecisions {
    /** What the add-contact confirmation offers for a received card. */
    enum class Confirm {
        /** A new contact, or the same pairing again: an ordinary save. */
        SAVE,

        /** Replaces a saved contact's pairing: keeping it is the main button. */
        REPLACE,

        /** Unknown or refused (also while the check is still running): nothing can be saved. */
        REFUSE,
    }

    fun confirmFor(preview: PairingPreview?): Confirm = when (preview) {
        PairingPreview.New, is PairingPreview.Unchanged -> Confirm.SAVE
        is PairingPreview.Replaces -> Confirm.REPLACE
        PairingPreview.Invalid, null -> Confirm.REFUSE
    }

    /** What the contact page does with a code typed for [contactId]. */
    sealed interface DetailAction {
        object Submit : DetailAction

        object ConfirmReplace : DetailAction

        class Refuse(val result: PairingResult) : DetailAction
    }

    fun detailAction(preview: PairingPreview, contactId: Long): DetailAction = when (preview) {
        is PairingPreview.Unchanged -> if (preview.contactId == contactId) DetailAction.Submit else DetailAction.Refuse(PairingResult.WRONG_KEY)
        is PairingPreview.Replaces -> if (preview.contactId == contactId) DetailAction.ConfirmReplace else DetailAction.Refuse(PairingResult.WRONG_KEY)
        // No saved contact holds the code's key: the import for this contact is refused by the core
        // itself (wrong key) and changes nothing.
        PairingPreview.New -> DetailAction.Submit
        PairingPreview.Invalid -> DetailAction.Refuse(PairingResult.BAD_FORMAT)
    }

    /** Whether an import changed anything that must be written: a new or changed PSK, a rename, or a new number. */
    fun needsWrite(pskChanged: Boolean, renamed: Boolean, numberSet: Boolean): Boolean = pskChanged || renamed || numberSet

    /** nativePreviewPairing result to what the confirmation screen shows. */
    fun preview(rc: Int): PairingPreview = when {
        rc == 0 -> PairingPreview.New
        rc > 0 && (rc and NativeCode.PAIRING_PSK_CHANGED) != 0 -> PairingPreview.Replaces((rc and NativeCode.PAIRING_PSK_CHANGED.inv()).toLong())
        rc > 0 -> PairingPreview.Unchanged(rc.toLong())
        else -> PairingPreview.Invalid
    }

    /**
     * The mutual mark after an import, written only once the vault was written ([saved]): a card
     * answering ours proves they hold this pairing; a new or changed PSK is not known on their side
     * yet; otherwise (null) the mark stays as it is.
     */
    fun mutualAfterImport(answersUs: Boolean, pskChanged: Boolean, saved: Boolean): Boolean? = when {
        !saved -> null
        answersUs -> true
        pskChanged -> false
        else -> null
    }

    /** A contact already holding the key keeps its name unless the user typed another one on screen. */
    fun keepsLabel(existingName: String?, shownName: String): Boolean = existingName != null && existingName == shownName

    /** Its number is only rewritten when the one on screen differs (an empty field keeps it). */
    fun numberChanged(existingNumber: String?, shownNumber: String?, existing: Boolean): Boolean =
        shownNumber != null && (!existing || existingNumber != shownNumber)
}
