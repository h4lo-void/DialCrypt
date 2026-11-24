package io.github.h4lovoid.dialcrypt.core.daemon

import android.net.LocalSocket
import android.net.LocalSocketAddress
import java.io.IOException

internal object DaemonSocket {
    /** The lockdown daemon runs as root. */
    const val DAEMON_UID = 0

    /**
     * Connects to the daemon's abstract socket and checks that root is listening on it. Any app can
     * bind an abstract name first, so the name proves nothing: a peer that is not uid 0 is closed and
     * reported as an IOException, which callers treat as "daemon not reachable".
     */
    fun connect(socket: LocalSocket) {
        socket.connect(LocalSocketAddress(DaemonProtocol.SOCKET_NAME, LocalSocketAddress.Namespace.ABSTRACT))
        verifyPeer(peerUid = { socket.peerCredentials.uid }, close = { closeQuietly(socket) })
    }

    /** Fails closed: throws (after [close]) unless [peerUid] reports root. Also throws when the uid cannot be read. */
    fun verifyPeer(peerUid: () -> Int, close: () -> Unit) {
        val uid = try {
            peerUid()
        } catch (e: Exception) {
            close()
            throw IOException("cannot read the daemon socket peer", e)
        }
        if (uid != DAEMON_UID) {
            close()
            throw IOException("daemon socket peer is uid $uid, not root")
        }
    }

    /** Wakes a thread blocked in read, then releases the socket. Safe to call from any thread, any number of times. */
    fun closeQuietly(socket: LocalSocket?) {
        if (socket == null) return
        try { socket.shutdownInput() } catch (_: Exception) {}
        try { socket.shutdownOutput() } catch (_: Exception) {}
        try { socket.close() } catch (_: Exception) {}
    }
}
