package io.github.h4lovoid.dialcrypt.core

/**
 * Test builds only (AEGIS_TEST_NO_PIN=1, BuildConfig.TEST_NO_PIN): the vault is set up and unlocked
 * with a built-in PIN, so testers never see a PIN screen. The caller tries once per process and falls
 * back to the normal PIN screens on any failure, so a vault made with another PIN loses one attempt at
 * most. Never set it for a build in real use: anyone holding the phone can open the app.
 */
object TestNoPin {
    private const val PIN = "pixeltestkey"
    private const val DURESS = "wipeallkeysnow"

    /** True when the vault needs this to set it up or unlock it now. */
    fun needed(state: CoreState): Boolean =
        state.availability == CoreAvailability.READY && !state.vaultDestroyed && (!state.pinConfigured || state.locked)

    /** Sets up or unlocks the vault with the built-in PIN. False when that failed. */
    suspend fun open(core: SecureCore, state: CoreState): Boolean = when {
        !needed(state) -> true
        !state.pinConfigured -> core.setupPins(PIN.toCharArray(), DURESS.toCharArray()) == PinResult.OK
        else -> core.unlock(PIN.toCharArray()) == UnlockResult.SUCCESS
    }
}
