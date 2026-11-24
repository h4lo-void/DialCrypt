// Compile-time stand-in for the @SystemApi class android.telephony.PreciseCallState, which the
// public SDK jar lacks. The app class loader asks the boot class path first, so at run time the
// framework class is used and this one is never loaded. It only gives TelecomCallLink a type for
// the hidden PhoneStateListener.onPreciseCallStateChanged(PreciseCallState) callback.
package android.telephony

class PreciseCallState private constructor()
