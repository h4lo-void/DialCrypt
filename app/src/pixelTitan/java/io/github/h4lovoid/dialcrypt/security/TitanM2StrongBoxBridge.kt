package io.github.h4lovoid.dialcrypt.security

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.KeyProtection
import android.security.keystore.StrongBoxUnavailableException
import android.security.keystore.WrappedKeyEntry
import android.util.Log
import io.github.h4lovoid.dialcrypt.BuildConfig
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.RSAKeyGenParameterSpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Google Pixel Titan M2 Hardware Security Edition:
 * Enforces `setIsStrongBoxBacked(true)` so identity, ticket, wrapping, and biometric keys never
 * leave the Titan M2 EAL6+ silicon, imports single-use PIN tickets via `WrappedKeyEntry` so raw
 * key bytes stay out of the ART heap, and destroys all keystore aliases on duress or wipe.
 */
class TitanM2StrongBoxBridge(private val context: Context) : HardwareKeyBridge {
    override val editionName: String = "DialCrypt Pixel Titan M2 (StrongBox EAL6+)"

    override val isHardwareStrongBoxBacked: Boolean
        get() = context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)


    // ---- secure-session v2: identity signing key and single-use PIN tickets (design 6.5, 6.6) ----

    private fun keyStore(): KeyStore = KeyStore.getInstance(KEY_STORE).apply { load(null) }

    override fun ensureIdentity(): IdentityMaterial {
        if (!isHardwareStrongBoxBacked) {
            throw StrongBoxUnavailableException("Titan M2 StrongBox is required; this device is not supported.")
        }
        val ks = keyStore()
        if (!ks.containsAlias(ID_ALIAS)) {
            val builder = KeyGenParameterSpec.Builder(ID_ALIAS, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setIsStrongBoxBacked(true)
                .setUnlockedDeviceRequired(true)
                .setAttestationChallenge(ID_CHALLENGE)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                // The native verifier requires attestationIdBrand = "google".
                // To be confirmed on device: Pixel StrongBox accepts device-properties attestation together with setUnlockedDeviceRequired.
                builder.setDevicePropertiesAttestationIncluded(true)
            }
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEY_STORE).run {
                initialize(builder.build())
                generateKeyPair()
            }
        }
        val privateKey = ks.getKey(ID_ALIAS, null) as PrivateKey
        val keyInfo = KeyFactory.getInstance(privateKey.algorithm, KEY_STORE).getKeySpec(privateKey, KeyInfo::class.java)
        val strongBox = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            keyInfo.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX
        } else {
            false
        }
        check(strongBox) { "Identity key is not inside StrongBox." }
        val chain = ks.getCertificateChain(ID_ALIAS)?.map { it.encoded }.orEmpty()
        check(chain.size >= 2) { "Identity key has no attestation chain." }
        return IdentityMaterial(spkiDer = ks.getCertificate(ID_ALIAS).publicKey.encoded, chainDer = chain)
    }

    override fun signSha256Ecdsa(message: ByteArray): ByteArray {
        val key = keyStore().getKey(ID_ALIAS, null) as PrivateKey
        return Signature.getInstance("SHA256withECDSA").run {
            initSign(key)
            update(message)
            sign()
        }
    }

    private fun importSingleUseHmac(alias: String, material: ByteArray): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return false
        return try {
            val protection = KeyProtection.Builder(KeyProperties.PURPOSE_SIGN)
                .setIsStrongBoxBacked(true)
                .setUnlockedDeviceRequired(true)
                .setMaxUsageCount(1)
                .build()
            val entry = KeyStore.SecretKeyEntry(SecretKeySpec(material, KeyProperties.KEY_ALGORITHM_HMAC_SHA256))
            keyStore().setEntry(alias, entry, protection)
            true
        } catch (e: Exception) {
            Log.w(TAG, "single-use key import failed: " + e.javaClass.simpleName)
            false
        }
    }

    private fun hmacOnce(alias: String, input: ByteArray): ByteArray? = try {
        val key = keyStore().getKey(alias, null) as? SecretKey
        key?.let {
            Mac.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256).run {
                init(it)
                doFinal(input)
            }
        }
    } catch (e: Exception) {
        null
    }

    private fun deleteQuietly(alias: String): Boolean = try {
        val ks = keyStore()
        if (ks.containsAlias(alias)) ks.deleteEntry(alias)
        true
    } catch (e: Exception) {
        false
    }

    override fun selfTestSingleUseTickets(): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return false
        val hardwareEnforced = context.packageManager.hasSystemFeature(PackageManager.FEATURE_KEYSTORE_SINGLE_USE_KEY)
        if (!hardwareEnforced) {
            // Without the feature only the key store, not the secure hardware, counts the uses.
            Log.w(TAG, "single-use keys are not hardware enforced; field test build=" + BuildConfig.FIELD_TEST_SOFT_TICKETS)
            if (!BuildConfig.FIELD_TEST_SOFT_TICKETS) return false
        }
        val material = ByteArray(32).also { SecureRandom().nextBytes(it) }
        try {
            if (!importSingleUseHmac(PROBE_ALIAS, material)) return false
            val input = ByteArray(32)
            if (hmacOnce(PROBE_ALIAS, input) == null) {
                Log.w(TAG, "single-use key probe: first use failed")
                return false
            }
            val secondRefused = hmacOnce(PROBE_ALIAS, input) == null
            if (!secondRefused) Log.w(TAG, "single-use key probe: second use was not refused")
            return secondRefused
        } finally {
            material.fill(0)
            deleteQuietly(PROBE_ALIAS)
        }
    }

    override fun ensureTicketWrappingKey(): ByteArray? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S || !isHardwareStrongBoxBacked) return null
        return try {
            val ks = keyStore()
            if (!ks.containsAlias(WRAP_ALIAS)) {
                val spec = KeyGenParameterSpec.Builder(WRAP_ALIAS, KeyProperties.PURPOSE_WRAP_KEY)
                    .setAlgorithmParameterSpec(RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                    .setIsStrongBoxBacked(true)
                    .build()
                KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, KEY_STORE).run {
                    initialize(spec)
                    generateKeyPair()
                }
            }
            val privateKey = ks.getKey(WRAP_ALIAS, null) as? PrivateKey ?: return null
            val info = KeyFactory.getInstance(privateKey.algorithm, KEY_STORE).getKeySpec(privateKey, KeyInfo::class.java)
            if (info.securityLevel != KeyProperties.SECURITY_LEVEL_STRONGBOX) {
                deleteQuietly(WRAP_ALIAS)
                return null
            }
            ks.getCertificate(WRAP_ALIAS)?.publicKey?.encoded
        } catch (e: Exception) {
            Log.w(TAG, "StrongBox ticket wrapping key unavailable: " + e.javaClass.simpleName)
            deleteQuietly(WRAP_ALIAS)
            null
        }
    }

    override fun importWrappedTicket(id: Int, wrappedKeyAsn1: ByteArray): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S || wrappedKeyAsn1.isEmpty()) return false
        return try {
            val spec = KeyGenParameterSpec.Builder(ticketAlias(id), KeyProperties.PURPOSE_SIGN)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setIsStrongBoxBacked(true)
                .setUnlockedDeviceRequired(true)
                .setMaxUsageCount(1)
                .build()
            val entry = WrappedKeyEntry(wrappedKeyAsn1, WRAP_ALIAS, "RSA/ECB/OAEPPadding", spec)
            keyStore().setEntry(ticketAlias(id), entry, null)
            true
        } catch (e: Exception) {
            Log.w(TAG, "wrapped single-use ticket import failed: " + e.javaClass.simpleName)
            false
        }
    }

    override fun importTicket(id: Int, material: ByteArray): Boolean =
        material.size == 32 && importSingleUseHmac(ticketAlias(id), material)

    override fun useTicket(id: Int, input32: ByteArray): ByteArray? {
        val alias = ticketAlias(id)
        try {
            return hmacOnce(alias, input32)
        } finally {
            // Single use: the key must be gone even if the key store kept an exhausted entry.
            // To be confirmed on device: Keystore2 refuses a second HMAC with a setMaxUsageCount(1) key imported into StrongBox.
            deleteQuietly(alias)
        }
    }

    override fun retireTicket(id: Int) {
        val input = ByteArray(32).also { SecureRandom().nextBytes(it) }
        useTicket(id, input)?.fill(0)
    }

    override fun listTickets(): IntArray =
        keyStore().aliases().toList()
            .filter { it.startsWith(TICKET_PREFIX) }
            .mapNotNull { runCatching { Integer.parseUnsignedInt(it.removePrefix(TICKET_PREFIX)) }.getOrNull() }
            .toIntArray()

    override fun destroyAllKeys(): Boolean {
        val fixed = listOf(ID_ALIAS, LEGACY_ID_ALIAS, PROBE_ALIAS, SCREEN_ALIAS, BIO_ALIAS, WRAP_ALIAS, NUMBER_INDEX_ALIAS)
        val aliases = try {
            keyStore().aliases().toList()
        } catch (e: Exception) {
            fixed
        }
        var ok = true
        for (alias in (aliases + fixed).distinct()) {
            if (alias in fixed || alias.startsWith(TICKET_PREFIX)) {
                ok = deleteQuietly(alias) && ok
            }
        }
        return ok
    }

    // ---- fingerprint answer: AES-256-GCM key released by a strong biometric for every use ----

    override fun createBioKey(): Boolean {
        deleteQuietly(BIO_ALIAS)
        return try {
            val spec = KeyGenParameterSpec.Builder(BIO_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(256)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setIsStrongBoxBacked(true)
                .setUserAuthenticationRequired(true)
                // Timeout 0: every use needs its own fingerprint bound to the CryptoObject; no device PIN instead.
                .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                .setInvalidatedByBiometricEnrollment(true)
                .setUnlockedDeviceRequired(true)
                .setRandomizedEncryptionRequired(true)
                .build()
            KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEY_STORE).run {
                init(spec)
                generateKey()
            }
            val key = keyStore().getKey(BIO_ALIAS, null) as SecretKey
            val info = SecretKeyFactory.getInstance(key.algorithm, KEY_STORE).getKeySpec(key, KeyInfo::class.java) as KeyInfo
            // To be confirmed on device: Pixel StrongBox accepts this combination of parameters.
            check(info.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX) { "fingerprint key is not inside StrongBox" }
            true
        } catch (e: Exception) {
            // No fallback to a key outside StrongBox: the feature is reported unavailable.
            Log.w(TAG, "fingerprint key refused: " + e.javaClass.simpleName)
            deleteQuietly(BIO_ALIAS)
            false
        }
    }

    override fun bioCipher(encrypt: Boolean, iv: ByteArray?): BioCipher = try {
        val key = keyStore().getKey(BIO_ALIAS, null) as? SecretKey
        if (key == null || (!encrypt && iv == null)) {
            BioCipher.Unavailable
        } else {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            if (encrypt) cipher.init(Cipher.ENCRYPT_MODE, key) else cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
            BioCipher.Ready(cipher)
        }
    } catch (e: KeyPermanentlyInvalidatedException) {
        BioCipher.Invalidated
    } catch (e: Exception) {
        Log.w(TAG, "fingerprint cipher unavailable: " + e.javaClass.simpleName)
        BioCipher.Unavailable
    }

    override fun deleteBioKey() {
        deleteQuietly(BIO_ALIAS)
    }

    private companion object {
        const val KEY_STORE = "AndroidKeyStore"
        const val TAG = "AegisKeys"
        const val ID_ALIAS = "aegis_id_v2"
        const val LEGACY_ID_ALIAS = "aegischat_titan_m2_strongbox_id"
        const val SCREEN_ALIAS = "aegis_screen_v1"
        const val BIO_ALIAS = "aegis_bio_v1"
        const val WRAP_ALIAS = "aegis_wrap_v1"
        const val NUMBER_INDEX_ALIAS = "dialcrypt_number_index_v1"
        const val TICKET_PREFIX = "aegis_pin_t"
        const val PROBE_ALIAS = "aegis_pin_probe"
        val ID_CHALLENGE = "AegisChat-ID-v2".toByteArray(Charsets.US_ASCII)

        fun ticketAlias(id: Int) = TICKET_PREFIX + Integer.toUnsignedString(id)
    }
}
