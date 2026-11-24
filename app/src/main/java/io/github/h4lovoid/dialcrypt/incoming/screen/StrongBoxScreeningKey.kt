package io.github.h4lovoid.dialcrypt.incoming.screen

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Log
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey

/**
 * Hardware-backed HMAC-SHA256 key (`aegis_screen_v1`) usable while the screen is locked
 * (after first unlock) so `:call` can screen incoming caller IDs without opening the vault.
 */
object StrongBoxScreeningKey {
    const val KEY_ALIAS = "aegis_screen_v1"
    private const val KEY_STORE = "AndroidKeyStore"
    private const val TAG = "AegisScreenKey"

    fun hmac(context: Context, input: ByteArray): ByteArray? = try {
        val ks = KeyStore.getInstance(KEY_STORE).apply { load(null) }
        val key = (ks.getKey(KEY_ALIAS, null) as? SecretKey) ?: generate(context, ks) ?: return null
        Mac.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256).run {
            init(key)
            doFinal(input)
        }
    } catch (e: Exception) {
        Log.w(TAG, "screening hmac failed: " + e.javaClass.simpleName)
        null
    }

    fun delete(): Boolean = try {
        val ks = KeyStore.getInstance(KEY_STORE).apply { load(null) }
        if (ks.containsAlias(KEY_ALIAS)) ks.deleteEntry(KEY_ALIAS)
        true
    } catch (e: Exception) {
        false
    }

    private fun generate(context: Context, ks: KeyStore): SecretKey? {
        val strongBox = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
            context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        fun create(useStrongBox: Boolean): SecretKey {
            val spec = KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_SIGN)
                .apply {
                    if (useStrongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                        setIsStrongBoxBacked(true)
                    }
                }
                .build()
            val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, KEY_STORE)
            kg.init(spec)
            return kg.generateKey()
        }
        return try {
            create(strongBox)
        } catch (e: StrongBoxUnavailableException) {
            create(false)
        } catch (e: Exception) {
            Log.w(TAG, "screening key generate failed: " + e.javaClass.simpleName)
            ks.getKey(KEY_ALIAS, null) as? SecretKey
        }
    }
}
