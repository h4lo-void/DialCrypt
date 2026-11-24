package io.github.h4lovoid.dialcrypt.daemon

import android.accessibilityservice.AccessibilityServiceInfo
import android.app.Application
import android.view.accessibility.AccessibilityManager
import androidx.test.core.app.ApplicationProvider
import io.github.h4lovoid.dialcrypt.core.AccessibilityCheck
import io.github.h4lovoid.dialcrypt.core.AppCheck
import io.github.h4lovoid.dialcrypt.core.HardeningLevel
import io.github.h4lovoid.dialcrypt.core.ItemStatus
import io.github.h4lovoid.dialcrypt.core.LockdownFailure
import io.github.h4lovoid.dialcrypt.core.LockdownPhase
import io.github.h4lovoid.dialcrypt.core.daemon.DaemonLockdownController
import io.github.h4lovoid.dialcrypt.core.daemon.PrepMapping
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

/** Preparation fails closed while any accessibility service is enabled. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class AccessibilityPrepTest {
    private val app: Application = ApplicationProvider.getApplicationContext()

    @Test
    fun checkPassesOnlyWithNoEnabledService() {
        val am = app.getSystemService(AccessibilityManager::class.java)
        assertTrue(AccessibilityCheck.noneEnabled(app))
        shadowOf(am).setEnabledAccessibilityServiceList(listOf(AccessibilityServiceInfo()))
        assertFalse(AccessibilityCheck.noneEnabled(app))
    }

    @Test
    fun enabledServiceFailsPreparationWithoutAskingTheDaemon() {
        val controller = DaemonLockdownController(app, accessibilityOff = { false })
        controller.prepare()
        val state = controller.state.value
        assertEquals(LockdownPhase.FAILED, state.phase)
        val failed = state.failedItem!!
        assertEquals(AppCheck.NO_ACCESSIBILITY_SERVICES, failed.appCheck)
        assertEquals(LockdownFailure.UNKNOWN, failed.failure)
        assertEquals(1, state.items.count { it.status == ItemStatus.FAILED })
        assertNull(controller.lease())
    }

    @Test
    fun appCheckFailureMarksOnlyTheFirstItemAndCarriesItsTexts() {
        val items = PrepMapping.itemsFor(HardeningLevel.LEVEL_1, ItemStatus.PENDING)
        val marked = PrepMapping.appCheckFailed(items, AppCheck.NO_ACCESSIBILITY_SERVICES)
        assertEquals(ItemStatus.FAILED, marked.first().status)
        assertTrue(marked.drop(1).all { it.status == ItemStatus.PENDING && it.appCheck == null })
        val check = AppCheck.NO_ACCESSIBILITY_SERVICES
        assertEquals("Turn off all accessibility services in system settings, then try again.", app.getString(check.fix))
        assertTrue(app.getString(check.reason).isNotBlank())
        assertTrue(app.getString(check.label).isNotBlank())
    }
}
