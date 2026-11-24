package io.github.h4lovoid.dialcrypt.dialer

import android.app.Application
import android.telecom.InCallService
import androidx.test.core.app.ApplicationProvider
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

/** An in-call service with no behavior of its own, to attach to [InCallStore]. */
class StubInCallService : InCallService()

/** What [InCallStore] does when the secure answer is abandoned and when its service goes away. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class InCallStoreTest {
    private val app: Application = ApplicationProvider.getApplicationContext()

    private fun idle() = shadowOf(InCallStore.handler.looper).idle()

    @After
    fun tearDown() {
        InCallStore.onIncomingReset = null
        InCallStore.onChanged = null
        SecureBusyMarker.set(app, false)
    }

    @Test
    fun anAbandonedSecureAnswerForgetsTheShownNotificationAndPresentsAgain() {
        val events = ArrayList<String>()
        InCallStore.onIncomingReset = { events += "reset" }
        InCallStore.onChanged = { events += "present" }
        InCallStore.representIncoming()
        idle()
        assertEquals(listOf("reset", "present"), events)
    }

    @Test
    fun unbindingClearsTheSecureBusyMarker() {
        val svc = Robolectric.setupService(StubInCallService::class.java)
        InCallStore.attach(svc)
        idle()
        SecureBusyMarker.set(app, true)
        assertTrue(SecureBusyMarker.isSet(app))
        InCallStore.detach(svc)
        idle()
        assertFalse(SecureBusyMarker.isSet(app))
    }
}
