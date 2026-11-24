package io.github.h4lovoid.dialcrypt.incoming

/** Which of the app's two InCallServices handed a Telecom call to [CallRegistry]. */
internal enum class CallSource {
    /** IncomingCallService: bound for every call through CONTROL_INCALL_EXPERIENCE. */
    NON_UI,

    /** DialerInCallService: bound only while the app holds the default dialer role. */
    DIALER_UI,
    ;

    companion object {
        /**
         * Each call is tracked through one source only. With the dialer role, calls come from the
         * service that also drives the in-call screen, so both see the same Call objects; without it,
         * from the non-UI service exactly as before the role existed.
         */
        fun accepts(source: CallSource, roleHeld: Boolean): Boolean =
            if (roleHeld) source == DIALER_UI else source == NON_UI

        /**
         * Whether an event from [source] (removal, audio state, unbinding) concerns the tracked call,
         * which was accepted from [trackedSource]. It follows the accepting source, whatever the role
         * is now: the role can be taken or given back while a call is under way.
         */
        fun owns(source: CallSource, trackedSource: CallSource?): Boolean =
            trackedSource != null && source == trackedSource
    }
}
