package io.github.h4lovoid.dialcrypt.real

import java.io.ByteArrayOutputStream

/** Builds big-endian byte layouts for the native-format tests. */
internal class Bytes {
    private val out = ByteArrayOutputStream()

    fun u8(v: Int) = apply { out.write(v and 0xFF) }
    fun u16(v: Int) = apply { u8(v ushr 8).u8(v) }
    fun u32(v: Long) = apply { u8((v ushr 24).toInt()).u8((v ushr 16).toInt()).u8((v ushr 8).toInt()).u8(v.toInt()) }
    fun raw(b: ByteArray) = apply { out.write(b) }
    fun fill(n: Int, v: Int) = raw(ByteArray(n) { v.toByte() })
    fun tlv(type: Int, value: ByteArray) = u8(type).u16(value.size).raw(value)
    fun build(): ByteArray = out.toByteArray()
}

internal fun bytes(block: Bytes.() -> Unit): ByteArray = Bytes().apply(block).build()
