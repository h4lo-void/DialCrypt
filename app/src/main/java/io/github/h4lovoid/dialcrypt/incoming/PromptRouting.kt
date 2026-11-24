package io.github.h4lovoid.dialcrypt.incoming

internal object PromptRouting {
    /**
     * Whether a new offer opens [IncomingPromptActivity]. Not while the app's own in-call screen
     * is bound (it shows the secure answer itself), not when an open `:secure` took the offer, and
     * only once per offer.
     */
    fun showPrompt(dialerUiBound: Boolean, deliveredToSecure: Boolean, promptShown: Boolean): Boolean =
        !dialerUiBound && !deliveredToSecure && !promptShown

    /**
     * Whether the offer named by a token from `:secure` or the prompt is still open to be returned
     * to the prompt or declined: same token, still ringing, not claimed for a secure answer and not
     * answered as a plain call.
     */
    fun offerOpen(tokenMatches: Boolean, ringing: Boolean, claimedBySecure: Boolean, plainAnswered: Boolean): Boolean =
        tokenMatches && ringing && !claimedBySecure && !plainAnswered
}
