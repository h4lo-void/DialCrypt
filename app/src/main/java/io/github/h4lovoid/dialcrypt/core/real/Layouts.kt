package io.github.h4lovoid.dialcrypt.core.real

import java.io.ByteArrayOutputStream

/** One single-use PIN ticket to import into StrongBox. [material] is wiped by [RotationLayout.wipeMaterial]. */
internal class NewTicket(val id: Int, val material: ByteArray)

/** One StrongBox-wrapped single-use PIN ticket (`SecureKeyWrapper` DER). */
internal class WrappedTicket(val id: Int, val wrappedDer: ByteArray)

/**
 * Wrapped rotation layout from nativePinSetupWrapped / nativeVaultRotateBeginWrapped:
 * `n u8 · n × (ticketId u32 · len u16 BE · SecureKeyWrapper DER) · m u8 · m × retired ticketId u32`.
 */
internal class WrappedRotationLayout(val fresh: List<WrappedTicket>, val retire: IntArray) {
    fun wipe() = fresh.forEach { it.wrappedDer.fill(0) }

    companion object {
        fun parse(data: ByteArray): WrappedRotationLayout? {
            val r = ByteReader(data)
            val n = r.u8() ?: return null
            val fresh = ArrayList<WrappedTicket>(n)
            repeat(n) {
                val id = r.u32() ?: return null
                val len = r.u16() ?: return null
                if (len == 0) return null
                val der = r.bytes(len) ?: return null
                fresh += WrappedTicket(id.toInt(), der)
            }
            val m = r.u8() ?: return null
            val retire = IntArray(m)
            for (i in 0 until m) retire[i] = (r.u32() ?: return null).toInt()
            if (!r.atEnd) return null
            return WrappedRotationLayout(fresh, retire)
        }
    }
}

/**
 * Rotation layout from nativePinSetup / nativeVaultRotateBegin:
 * `n u8 · n × (ticketId u32 · material 32 B) · m u8 · m × retired ticketId u32`.
 * Ticket ids keep their u32 bit pattern in an Int, as the JNI IntArray expects.
 */
internal class RotationLayout(val fresh: List<NewTicket>, val retire: IntArray) {
    fun wipeMaterial() = fresh.forEach { it.material.fill(0) }

    companion object {
        const val MATERIAL_LEN = 32

        fun parse(data: ByteArray): RotationLayout? {
            val r = ByteReader(data)
            val n = r.u8() ?: return null
            val fresh = ArrayList<NewTicket>(n)
            var ok = false
            try {
                repeat(n) {
                    val id = r.u32() ?: return null
                    val material = r.bytes(MATERIAL_LEN) ?: return null
                    fresh += NewTicket(id.toInt(), material)
                }
                val m = r.u8() ?: return null
                val retire = IntArray(m)
                for (i in 0 until m) retire[i] = (r.u32() ?: return null).toInt()
                if (!r.atEnd) return null
                ok = true
                return RotationLayout(fresh, retire)
            } finally {
                if (!ok) fresh.forEach { it.material.fill(0) }
            }
        }
    }
}

/** nativePinBegin result: `ticketId u32 · 32 B HMAC input for useTicket`. */
internal class PinBegin(val ticketId: Int, val input: ByteArray) {
    fun wipe() = input.fill(0)

    companion object {
        const val INPUT_LEN = 32

        fun parse(data: ByteArray): PinBegin? {
            if (data.size != 4 + INPUT_LEN) return null
            val r = ByteReader(data)
            val id = r.u32() ?: return null
            val input = r.bytes(INPUT_LEN) ?: return null
            return PinBegin(id.toInt(), input)
        }
    }
}

/**
 * Trust configuration for nativeAppOpen: `ver u8 = 1 · records type u8 · len u16 · value`
 * (1 root DER, 2 revoked serial, 3 AVB key, 4 app signer SHA-256, 5 min osPatch u32).
 */
internal object TrustTlv {
    private const val VERSION = 1
    private const val MAX_VALUE = 0xFFFF

    fun encode(
        roots: List<ByteArray>,
        revokedSerials: List<ByteArray>,
        avbKeys: List<ByteArray>,
        appSigners: List<ByteArray>,
        minOsPatch: Long,
    ): ByteArray? {
        if (roots.isEmpty() || appSigners.isEmpty() || appSigners.any { it.size != 32 }) return null
        if (minOsPatch !in 1..0xFFFF_FFFFL) return null
        val out = ByteArrayOutputStream()
        out.putU8(VERSION)
        val records = roots.map { 1 to it } + revokedSerials.map { 2 to it } + avbKeys.map { 3 to it } + appSigners.map { 4 to it }
        for ((type, value) in records) {
            if (value.isEmpty() || value.size > MAX_VALUE) return null
            out.putU8(type)
            out.putU16(value.size)
            out.write(value)
        }
        out.putU8(5)
        out.putU16(4)
        out.putU32(minOsPatch)
        return out.toByteArray()
    }
}

/** Identity chain for nativeSetIdentity: repeated `len u16 · DER`, leaf first, root excluded. */
internal object ChainTlv {
    /**
     * [chainWithRoot] is the Android Keystore certificate chain (leaf first, root last); the root
     * is dropped because the trust configuration supplies it. Null when nothing is left.
     * To be confirmed on device: the Pixel StrongBox chain ends with a self-signed root listed in attestation_roots.der
     * and has at most five certificates below it (aegiscall_trust MAX_CHAIN_LEN).
     */
    fun encode(chainWithRoot: List<ByteArray>): ByteArray? {
        if (chainWithRoot.size < 2) return null
        val out = ByteArrayOutputStream()
        for (cert in chainWithRoot.dropLast(1)) {
            if (cert.isEmpty() || cert.size > 0xFFFF) return null
            out.putU16(cert.size)
            out.write(cert)
        }
        return out.toByteArray()
    }
}
