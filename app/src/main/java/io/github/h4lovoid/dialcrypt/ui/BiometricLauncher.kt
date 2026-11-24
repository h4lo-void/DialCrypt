package io.github.h4lovoid.dialcrypt.ui

import android.content.Context
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.CancellationSignal
import android.util.Log
import javax.crypto.Cipher

/**
 * The platform fingerprint dialog bound to a key-store cipher (CryptoObject), strong biometrics
 * only, no device-credential fallback. Started from the secure process, so the released key never
 * leaves it. Nothing here throws: every failure ends in onError and the PIN stays available.
 */
internal object BiometricLauncher {
    /** onError code for the negative button ("Use PIN" or "Cancel"), or when the dialog could not open. */
    const val ERROR_DISMISSED = -1

    /** A strong fingerprint is enrolled and usable. */
    fun hasStrongFingerprint(context: Context): Boolean = try {
        context.getSystemService(BiometricManager::class.java)
            ?.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS
    } catch (e: Exception) {
        false
    }

    /**
     * Shows the dialog for [cipher]. [onSuccess] gets the cipher the fingerprint released; a
     * fingerprint that does not match lets the system ask again. Callbacks run on the main thread.
     * False when the dialog could not be shown (onError is not called then).
     */
    fun authenticate(
        context: Context,
        title: String,
        negative: String,
        cipher: Cipher,
        cancel: CancellationSignal,
        onSuccess: (Cipher) -> Unit,
        onError: (Int) -> Unit,
    ): Boolean = try {
        val executor = context.mainExecutor
        val prompt = BiometricPrompt.Builder(context)
            .setTitle(title)
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .setNegativeButton(negative, executor) { _, _ -> onError(ERROR_DISMISSED) }
            .build()
        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                val released = result.cryptoObject?.cipher
                if (released != null) onSuccess(released) else onError(ERROR_DISMISSED)
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence?) {
                onError(errorCode)
            }
        }
        prompt.authenticate(BiometricPrompt.CryptoObject(cipher), cancel, executor, callback)
        true
    } catch (e: Exception) {
        Log.w("AegisBio", "fingerprint dialog not shown: " + e.javaClass.simpleName)
        false
    }
}
