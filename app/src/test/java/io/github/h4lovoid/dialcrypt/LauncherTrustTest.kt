package io.github.h4lovoid.dialcrypt

import io.github.h4lovoid.dialcrypt.ui.acceptHandoffToken
import io.github.h4lovoid.dialcrypt.ui.isOwnLaunch
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The exported launcher only accepts a call handoff from this app's own uid, and only on API 34+. */
class LauncherTrustTest {
    private val me = 10123

    @Test
    fun ownUidOnApi34IsTrusted() {
        assertTrue(isOwnLaunch(34, me, me))
        assertTrue(isOwnLaunch(35, me, me))
    }

    @Test
    fun anotherUidIsNotTrusted() {
        assertFalse(isOwnLaunch(34, 10456, me))
        assertFalse(isOwnLaunch(34, 1000, me))
    }

    @Test
    fun anUnreportedCallerIsNotTrusted() {
        assertFalse(isOwnLaunch(34, -1, me))
    }

    @Test
    fun belowApi34NothingIsTrustedEvenWithAMatchingUid() {
        assertFalse(isOwnLaunch(33, me, me))
        assertFalse(isOwnLaunch(30, me, me))
    }

    @Test
    fun aTokenFromAnotherAppIsDropped() {
        assertNull(acceptHandoffToken(false, byteArrayOf(1, 2, 3)))
    }

    @Test
    fun anEmptyTokenIsDroppedEvenFromThisApp() {
        assertNull(acceptHandoffToken(true, ByteArray(0)))
    }

    @Test
    fun aTokenFromThisAppIsKept() {
        assertArrayEquals(byteArrayOf(1, 2, 3), acceptHandoffToken(true, byteArrayOf(1, 2, 3)))
    }
}
