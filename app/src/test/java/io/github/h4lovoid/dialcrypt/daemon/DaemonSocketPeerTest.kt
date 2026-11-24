package io.github.h4lovoid.dialcrypt.daemon

import io.github.h4lovoid.dialcrypt.core.daemon.DaemonSocket
import java.io.IOException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

/** The app talks to the daemon socket only when root is listening on it. */
class DaemonSocketPeerTest {
    private var closed = 0

    private fun verify(uid: () -> Int): IOException? =
        try {
            DaemonSocket.verifyPeer(peerUid = uid, close = { closed++ })
            null
        } catch (e: IOException) {
            e
        }

    @Test
    fun rootPeerIsAccepted() {
        assertNull(verify { 0 })
        assertEquals(0, closed)
    }

    @Test
    fun appPeerIsClosedAndReportedUnreachable() {
        assertNotNull(verify { 10_123 })
        assertEquals(1, closed)
    }

    @Test
    fun unreadableCredentialsFailClosed() {
        assertNotNull(verify { throw IOException("no credentials") })
        assertEquals(1, closed)
    }
}
