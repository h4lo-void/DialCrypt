package io.github.h4lovoid.dialcrypt.core.daemon

/** Constants of the daemon's local protocol (daemon/src/ipc.rs and codes.rs). */
object DaemonProtocol {
    /** Name of the abstract Unix socket, without the leading "@". */
    const val SOCKET_NAME = "io.github.h4lovoid.dialcrypt.d"
    const val VERSION = 1
    const val MAX_FRAME = 64
    const val LEASE_SIZE = 16

    const val MODE_DRY_RUN = 0
    const val MODE_ARMED = 1

    const val CLAIM_OFFLINE = 1
    const val CLAIM_APPS_STOPPED = 2
    const val CLAIM_MEMORY_SCRUBBED = 4

    const val STEP_PRECHECK = 1
    const val STEP_FIREWALL = 2
    const val STEP_RADIOS = 3
    const val STEP_APPS = 4
    const val STEP_MEMORY = 5

    /** First field of FAIL: the checklist item a failure belongs to. */
    const val ITEM_ADB = 3
    const val ITEM_TETHER = 5
    const val ITEM_IMS = 10
    const val ITEM_AUTH = 20
    const val ITEM_APPLY = 30

    /** Second field of FAIL (reason codes) that the App tells apart. */
    const val CODE_APPLY_FAILED = 300
    const val CODE_READBACK_MISMATCH = 301
}

/** Messages the App sends. */
sealed interface ClientMsg {
    data class Hello(val version: Int) : ClientMsg
    object Prepare : ClientMsg
    class Attach(lease: ByteArray) : ClientMsg {
        val lease: ByteArray = lease.copyOf()
        override fun equals(other: Any?) = other is Attach && lease.contentEquals(other.lease)
        override fun hashCode() = lease.contentHashCode()
        override fun toString() = "Attach"
    }
    class Heartbeat(lease: ByteArray) : ClientMsg {
        val lease: ByteArray = lease.copyOf()
        override fun equals(other: Any?) = other is Heartbeat && lease.contentEquals(other.lease)
        override fun hashCode() = lease.contentHashCode()
        override fun toString() = "Heartbeat"
    }
    object End : ClientMsg
    object TrimStorage : ClientMsg
}

/** Messages the daemon sends. */
sealed interface ServerMsg {
    data class Hello(val version: Int, val mode: Int) : ServerMsg
    data class Progress(val step: Int) : ServerMsg
    class Ready(lease: ByteArray, val mode: Int, val tier: Int, val claims: Int) : ServerMsg {
        val lease: ByteArray = lease.copyOf()
        override fun equals(other: Any?) =
            other is Ready && lease.contentEquals(other.lease) && mode == other.mode && tier == other.tier && claims == other.claims
        override fun hashCode() = 31 * lease.contentHashCode() + (mode shl 16 or (tier shl 8) or claims)
        override fun toString() = "Ready(mode=$mode, tier=$tier, claims=$claims)"
    }
    data class Fail(val item: Int, val code: Int) : ServerMsg
    data class Attached(val mode: Int, val tier: Int, val claims: Int) : ServerMsg
    data class Violation(val code: Int) : ServerMsg
    data class Ended(val status: Int) : ServerMsg
}

enum class FrameError { LENGTH, UNKNOWN_TYPE, BAD_PAYLOAD }

class FrameException(val error: FrameError) : Exception(error.name)

/** What the secure process learns when the daemon accepts its ATTACH. */
data class AttachInfo(val mode: Int, val tier: Int, val claims: Int) {
    val dryRun: Boolean get() = mode == DaemonProtocol.MODE_DRY_RUN
    fun has(bit: Int): Boolean = (claims and bit) != 0
}

/** Pure encoder and decoder for the frames `[u16 BE len][u8 type][payload]`; `len` counts the type byte. */
object DaemonCodec {
    private const val T_HELLO = 1
    private const val T_PREPARE = 2
    private const val T_PROGRESS = 3
    private const val T_READY = 4
    private const val T_FAIL = 5
    private const val T_ATTACH = 6
    private const val T_ATTACHED = 7
    private const val T_HEARTBEAT = 8
    private const val T_VIOLATION = 9
    private const val T_END = 10
    private const val T_ENDED = 11
    private const val T_TRIM = 12

    private fun frame(type: Int, payload: ByteArray): ByteArray {
        val len = 1 + payload.size
        val f = ByteArray(2 + len)
        f[0] = (len shr 8).toByte()
        f[1] = len.toByte()
        f[2] = type.toByte()
        payload.copyInto(f, 3)
        return f
    }

    private fun be16(v: Int) = byteArrayOf((v shr 8).toByte(), v.toByte())

    private fun leaseOf(p: ByteArray, from: Int = 0, size: Int = p.size - from): ByteArray {
        if (size != DaemonProtocol.LEASE_SIZE) throw FrameException(FrameError.BAD_PAYLOAD)
        return p.copyOfRange(from, from + size)
    }

    private fun u8(p: ByteArray, i: Int) = p[i].toInt() and 0xff

    private fun u16(p: ByteArray, i: Int) = (u8(p, i) shl 8) or u8(p, i + 1)

    private fun requireLease(lease: ByteArray) =
        require(lease.size == DaemonProtocol.LEASE_SIZE) { "lease must be 16 bytes" }

    fun encodeClient(m: ClientMsg): ByteArray = when (m) {
        is ClientMsg.Hello -> frame(T_HELLO, byteArrayOf(m.version.toByte()))
        ClientMsg.Prepare -> frame(T_PREPARE, ByteArray(0))
        is ClientMsg.Attach -> { requireLease(m.lease); frame(T_ATTACH, m.lease) }
        is ClientMsg.Heartbeat -> { requireLease(m.lease); frame(T_HEARTBEAT, m.lease) }
        ClientMsg.End -> frame(T_END, ByteArray(0))
        ClientMsg.TrimStorage -> frame(T_TRIM, ByteArray(0))
    }

    /** Decodes `type ‖ payload` (a frame without its length prefix). */
    fun decodeClient(body: ByteArray): ClientMsg {
        if (body.isEmpty()) throw FrameException(FrameError.LENGTH)
        val p = body.copyOfRange(1, body.size)
        fun need(n: Int) { if (p.size != n) throw FrameException(FrameError.BAD_PAYLOAD) }
        return when (u8(body, 0)) {
            T_HELLO -> { need(1); ClientMsg.Hello(u8(p, 0)) }
            T_PREPARE -> { need(0); ClientMsg.Prepare }
            T_ATTACH -> ClientMsg.Attach(leaseOf(p))
            T_HEARTBEAT -> ClientMsg.Heartbeat(leaseOf(p))
            T_END -> { need(0); ClientMsg.End }
            T_TRIM -> { need(0); ClientMsg.TrimStorage }
            else -> throw FrameException(FrameError.UNKNOWN_TYPE)
        }
    }

    fun encodeServer(m: ServerMsg): ByteArray = when (m) {
        is ServerMsg.Hello -> frame(T_HELLO, byteArrayOf(m.version.toByte(), m.mode.toByte()))
        is ServerMsg.Progress -> frame(T_PROGRESS, byteArrayOf(m.step.toByte()))
        is ServerMsg.Ready -> {
            requireLease(m.lease)
            frame(T_READY, m.lease + byteArrayOf(m.mode.toByte(), m.tier.toByte(), m.claims.toByte()))
        }
        is ServerMsg.Fail -> frame(T_FAIL, be16(m.item) + be16(m.code))
        is ServerMsg.Attached -> frame(T_ATTACHED, byteArrayOf(m.mode.toByte(), m.tier.toByte(), m.claims.toByte()))
        is ServerMsg.Violation -> frame(T_VIOLATION, be16(m.code))
        is ServerMsg.Ended -> frame(T_ENDED, byteArrayOf(m.status.toByte()))
    }

    /** Decodes `type ‖ payload` of a daemon message. Throws [FrameException] on any malformed input. */
    fun decodeServer(body: ByteArray): ServerMsg {
        if (body.isEmpty()) throw FrameException(FrameError.LENGTH)
        val p = body.copyOfRange(1, body.size)
        fun need(n: Int) { if (p.size != n) throw FrameException(FrameError.BAD_PAYLOAD) }
        return when (u8(body, 0)) {
            T_HELLO -> { need(2); ServerMsg.Hello(u8(p, 0), u8(p, 1)) }
            T_PROGRESS -> { need(1); ServerMsg.Progress(u8(p, 0)) }
            T_READY -> {
                need(19)
                ServerMsg.Ready(leaseOf(p, 0, 16), u8(p, 16), u8(p, 17), u8(p, 18))
            }
            T_FAIL -> { need(4); ServerMsg.Fail(u16(p, 0), u16(p, 2)) }
            T_ATTACHED -> { need(3); ServerMsg.Attached(u8(p, 0), u8(p, 1), u8(p, 2)) }
            T_VIOLATION -> { need(2); ServerMsg.Violation(u16(p, 0)) }
            T_ENDED -> { need(1); ServerMsg.Ended(u8(p, 0)) }
            else -> throw FrameException(FrameError.UNKNOWN_TYPE)
        }
    }
}

/** Reassembles frames from a byte stream. A zero or oversized length is fatal for the connection. */
class FrameReader {
    private var buf = ByteArray(0)

    /** Returns every complete frame body (`type ‖ payload`). */
    fun push(data: ByteArray, offset: Int = 0, length: Int = data.size - offset): List<ByteArray> {
        buf += data.copyOfRange(offset, offset + length)
        val out = ArrayList<ByteArray>()
        var pos = 0
        while (buf.size - pos >= 2) {
            val len = ((buf[pos].toInt() and 0xff) shl 8) or (buf[pos + 1].toInt() and 0xff)
            if (len == 0 || len > DaemonProtocol.MAX_FRAME) {
                buf = ByteArray(0)
                throw FrameException(FrameError.LENGTH)
            }
            if (buf.size - pos < 2 + len) break
            out.add(buf.copyOfRange(pos + 2, pos + 2 + len))
            pos += 2 + len
        }
        buf = buf.copyOfRange(pos, buf.size)
        return out
    }
}
