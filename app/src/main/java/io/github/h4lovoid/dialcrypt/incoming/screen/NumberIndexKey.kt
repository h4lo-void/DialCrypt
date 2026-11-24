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

/** HMAC-SHA256 key of [ContactNumberIndex]. Readers only use it; only `:secure` creates or deletes it. */
interface NumberIndexKey {
    /** HMAC-SHA256 of [input]; null when the key is missing or unusable. Never creates the key. */
    fun hmac(input: ByteArray): ByteArray?

    /** Creates the key when it is missing. False when no key could be made. */
    fun ensure(): Boolean

    fun delete(): Boolean
}

/**
 * Android Keystore key `dialcrypt_number_index_v1`: not exportable, no user authentication (the
 * lock screen must be able to use it), in StrongBox when the device has one.
 */
class KeystoreNumberIndexKey(private val context: Context) : NumberIndexKey {
    override fun hmac(input: ByteArray): ByteArray? = try {
        val key = keyStore().getKey(KEY_ALIAS, null) as? SecretKey ?: return null
        Mac.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256).run {
            init(key)
            doFinal(input)
        }
    } catch (e: Exception) {
        Log.w(TAG, "number index hmac failed: " + e.javaClass.simpleName)
        null
    }

    override fun ensure(): Boolean = try {
        keyStore().containsAlias(KEY_ALIAS) || generate()
    } catch (e: Exception) {
        Log.w(TAG, "number index key unavailable: " + e.javaClass.simpleName)
        false
    }

    override fun delete(): Boolean = try {
        val ks = keyStore()
        if (ks.containsAlias(KEY_ALIAS)) ks.deleteEntry(KEY_ALIAS)
        true
    } catch (e: Exception) {
        false
    }

    private fun keyStore(): KeyStore = KeyStore.getInstance(KEY_STORE).apply { load(null) }

    private fun generate(): Boolean {
        val strongBox = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
            context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        fun create(useStrongBox: Boolean) {
            val spec = KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_SIGN)
                .apply {
                    if (useStrongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) setIsStrongBoxBacked(true)
                }
                .build()
            KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, KEY_STORE).run {
                init(spec)
                generateKey()
            }
        }
        return try {
            create(strongBox)
            true
        } catch (e: StrongBoxUnavailableException) {
            create(false)
            true
        } catch (e: Exception) {
            Log.w(TAG, "number index key generate failed: " + e.javaClass.simpleName)
            false
        }
    }

    private companion object {
        const val KEY_ALIAS = "dialcrypt_number_index_v1"
        const val KEY_STORE = "AndroidKeyStore"
        const val TAG = "DialCryptNumberIndex"
    }
}
