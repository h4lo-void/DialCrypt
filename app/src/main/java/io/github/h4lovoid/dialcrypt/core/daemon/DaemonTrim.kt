package io.github.h4lovoid.dialcrypt.core.daemon

import android.net.LocalSocket

/**
 * Best-effort asynchronous `sm fstrim` request sent to the root daemon after duress, ticket
 * exhaustion, or panic wipe so flash wear-leveling blocks holding overwritten vault ciphertext
 * are discarded promptly without blocking the caller.
 */
object DaemonTrim {
    fun requestBestEffort() {
        Thread({
            val s = LocalSocket()
            try {
                DaemonSocket.connect(s)
                val out = s.outputStream
                out.write(DaemonCodec.encodeClient(ClientMsg.TrimStorage))
                out.flush()
            } catch (_: Throwable) {
                // Best-effort: daemon may not be running or test JVM may lack LocalSocket implementation.
            } finally {
                DaemonSocket.closeQuietly(s)
            }
        }, "aegis-fstrim").apply {
            isDaemon = true
            start()
        }
    }
}
