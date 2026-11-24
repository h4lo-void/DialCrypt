package io.github.h4lovoid.dialcrypt.security

import javax.crypto.Cipher

/**
 * Hardware Secure Element abstraction. The only supported implementation is
 * `pixelTitan`: mandatory Google Pixel Titan M2 StrongBox chip isolation.
 */
interface HardwareKeyBridge {
    val editionName: String
    val isHardwareStrongBoxBacked: Boolean

    fun ensureIdentityKeyReady(attestationChallenge: ByteArray): HardwareIdentityInfo
    fun computeP256EcdhSecret(peerPublicKeyX509: ByteArray): ByteArray
    fun verifyPeerHardwareChain(peerCertChainDer: List<ByteArray>): PeerHardwareVerdict
    fun duressDestroyMasterKeys(): Boolean

    /**
     * Creates or loads the identity signing key `aegis_id_v2` (P-256, SIGN only, SHA-256,
     * StrongBox, attestation challenge "AegisChat-ID-v2"). Throws when it cannot be provided.
     */
    fun ensureIdentity(): IdentityMaterial

    /** SHA256withECDSA with the identity key; DER signature. Throws on failure. */
    fun signSha256Ecdsa(message: ByteArray): ByteArray

    /**
     * True only when the device has single-use StrongBox keys and a probe key really refuses a
     * second use (design 6.5 self-check before a PIN is set).
     */
    fun selfTestSingleUseTickets(): Boolean

    /** Imports [material] (32 B) as the single-use StrongBox HMAC-SHA256 key `aegis_pin_t<id>`. The caller wipes [material]. */
    fun importTicket(id: Int, material: ByteArray): Boolean

    /** HMAC-SHA256 of [input32] with ticket [id], which is gone afterwards; null when the key gave no result. */
    fun useTicket(id: Int, input32: ByteArray): ByteArray?

    /** Uses ticket [id] once and deletes it. */
    fun retireTicket(id: Int)

    /** Ids of the tickets present in the key store (u32 bit patterns). Throws when the key store cannot be read. */
    fun listTickets(): IntArray

    /** Deletes the identity key and every ticket. */
    fun destroyAllKeys(): Boolean

    /**
     * Creates (replacing any old one) the fingerprint-answer key `aegis_bio_v1`: AES-256-GCM in
     * StrongBox, a strong biometric for every use, invalidated by a new fingerprint, usable only
     * while the device is unlocked. False when the key store refuses any of that; there is no
     * fallback outside StrongBox.
     */
    fun createBioKey(): Boolean = false

    /** A cipher on `aegis_bio_v1` for a BiometricPrompt CryptoObject; [iv] is needed to decrypt. Never throws. */
    fun bioCipher(encrypt: Boolean, iv: ByteArray?): BioCipher = BioCipher.Unavailable

    fun deleteBioKey() {}
}

/** Result of [HardwareKeyBridge.bioCipher]. */
sealed interface BioCipher {
    class Ready(val cipher: Cipher) : BioCipher

    /** The fingerprints or the screen lock changed: the key is gone for good. */
    object Invalidated : BioCipher

    object Unavailable : BioCipher
}

class IdentityMaterial(
    /** SubjectPublicKeyInfo DER of the identity key. */
    val spkiDer: ByteArray,
    /** Key store certificate chain, leaf first, root last. */
    val chainDer: List<ByteArray>,
)

data class HardwareIdentityInfo(
    val publicKeyEncoded: ByteArray,
    val attestationCertChainDer: List<ByteArray>,
    val isStrongBoxTitanM2: Boolean,
)

enum class PeerHardwareVerdict {
    DUAL_TITAN_M2_VERIFIED,
    STANDARD_TEE_OR_MIXED,
    UNTRUSTED_OR_INVALID,
}
