package io.github.h4lovoid.dialcrypt.daemon

import io.github.h4lovoid.dialcrypt.core.HardeningLevel
import io.github.h4lovoid.dialcrypt.core.ItemStatus
import io.github.h4lovoid.dialcrypt.core.LockdownFailure
import io.github.h4lovoid.dialcrypt.core.PrepItem
import io.github.h4lovoid.dialcrypt.core.PrepItemState
import io.github.h4lovoid.dialcrypt.core.daemon.DaemonProtocol
import io.github.h4lovoid.dialcrypt.core.daemon.PrepMapping
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class PrepMappingTest {
    private fun fresh() = PrepMapping.itemsFor(HardeningLevel.LEVEL_1, ItemStatus.PENDING)

    private fun status(items: List<PrepItemState>, item: PrepItem) = items.first { it.item == item }.status

    @Test
    fun levelOneHasTenItemsAndLevelTwoTwelve() {
        assertEquals(10, fresh().size)
        assertEquals(12, PrepMapping.itemsFor(HardeningLevel.LEVEL_2, ItemStatus.PENDING).size)
    }

    @Test
    fun progressMarksEarlierStepsDoneAndTheCurrentStepRunning() {
        val checks = PrepMapping.applyProgress(fresh(), DaemonProtocol.STEP_PRECHECK)
        assertEquals(ItemStatus.RUNNING, status(checks, PrepItem.VOLTE))
        assertEquals(ItemStatus.PENDING, status(checks, PrepItem.FIREWALL))
        val radios = PrepMapping.applyProgress(PrepMapping.applyProgress(checks, DaemonProtocol.STEP_FIREWALL), DaemonProtocol.STEP_RADIOS)
        assertEquals(ItemStatus.DONE, status(radios, PrepItem.VOLTE))
        assertEquals(ItemStatus.DONE, status(radios, PrepItem.FIREWALL))
        assertEquals(ItemStatus.RUNNING, status(radios, PrepItem.WIFI))
        assertEquals(ItemStatus.RUNNING, status(radios, PrepItem.LTE_NR_ONLY))
    }

    @Test
    fun appsStepAddsTheLevelTwoItems() {
        val apps = PrepMapping.applyProgress(fresh(), DaemonProtocol.STEP_APPS)
        assertEquals(12, apps.size)
        assertEquals(ItemStatus.RUNNING, status(apps, PrepItem.OTHER_APPS_STOPPED))
        assertEquals(ItemStatus.PENDING, status(apps, PrepItem.MEMORY_CLEARED))
        assertEquals(ItemStatus.DONE, status(apps, PrepItem.LTE_NR_ONLY))
    }

    @Test
    fun unknownStepChangesNothing() {
        assertEquals(fresh(), PrepMapping.applyProgress(fresh(), 9))
    }

    @Test
    fun readyMarksEverythingDone() {
        val done = PrepMapping.allDone(fresh(), tier = 1)
        assertEquals(10, done.size)
        assertEquals(true, done.all { it.status == ItemStatus.DONE })
        assertEquals(12, PrepMapping.allDone(fresh(), tier = 2).size)
    }

    @Test
    fun failMapsToTheMatchingItemAndReason() {
        val items = PrepMapping.applyProgress(fresh(), DaemonProtocol.STEP_PRECHECK)
        val volte = PrepMapping.mapFail(DaemonProtocol.ITEM_IMS, 100, items)
        assertEquals(PrepItem.VOLTE, volte.item)
        assertEquals(LockdownFailure.VOLTE_NOT_REGISTERED, volte.failure)
        assertEquals(LockdownFailure.USB_DEBUG_ENABLED, PrepMapping.mapFail(DaemonProtocol.ITEM_ADB, 31, items).failure)
        assertEquals(PrepItem.TETHERING, PrepMapping.mapFail(DaemonProtocol.ITEM_TETHER, 50, items).item)
        assertEquals(LockdownFailure.CALLER_REJECTED, PrepMapping.mapFail(DaemonProtocol.ITEM_AUTH, 205, fresh()).failure)
        assertEquals(LockdownFailure.UNKNOWN, PrepMapping.mapFail(2, 20, items).failure)
    }

    @Test
    fun applyFailuresDependOnTheRunningStep() {
        val radios = PrepMapping.applyProgress(fresh(), DaemonProtocol.STEP_RADIOS)
        assertEquals(LockdownFailure.RADIO_REFUSED, PrepMapping.mapFail(DaemonProtocol.ITEM_APPLY, 300, radios).failure)
        assertEquals(LockdownFailure.READBACK_MISMATCH, PrepMapping.mapFail(DaemonProtocol.ITEM_APPLY, 301, radios).failure)
        val firewall = PrepMapping.applyProgress(fresh(), DaemonProtocol.STEP_FIREWALL)
        val m = PrepMapping.mapFail(DaemonProtocol.ITEM_APPLY, 300, firewall)
        assertEquals(PrepItem.FIREWALL, m.item)
        assertEquals(LockdownFailure.UNKNOWN, m.failure)
    }

    @Test
    fun specificFailuresWinOverGenericOnesAndPassedChecksAreDone() {
        val items = PrepMapping.applyProgress(fresh(), DaemonProtocol.STEP_PRECHECK)
        val failures = listOf(
            PrepMapping.mapFail(2, 20, items),
            PrepMapping.mapFail(DaemonProtocol.ITEM_IMS, 100, items),
        )
        val marked = PrepMapping.markFailed(items, failures)
        assertEquals(ItemStatus.FAILED, status(marked, PrepItem.VOLTE))
        assertEquals(LockdownFailure.VOLTE_NOT_REGISTERED, marked.first { it.item == PrepItem.VOLTE }.failure)
        assertEquals(ItemStatus.DONE, status(marked, PrepItem.STRONGBOX))
        assertEquals(ItemStatus.PENDING, status(marked, PrepItem.FIREWALL))
    }

    @Test
    fun aGenericFailureIsShownWhenItIsTheOnlyOne() {
        val items = PrepMapping.applyProgress(fresh(), DaemonProtocol.STEP_PRECHECK)
        val marked = PrepMapping.markFailed(items, listOf(PrepMapping.mapFail(1, 10, items)))
        assertEquals(ItemStatus.FAILED, status(marked, PrepItem.STRONGBOX))
        assertEquals(LockdownFailure.UNKNOWN, marked.first { it.item == PrepItem.STRONGBOX }.failure)
    }

    @Test
    fun timeoutBlamesTheRunningItemAndLeavesTheRestPending() {
        val items = PrepMapping.applyProgress(PrepMapping.applyProgress(fresh(), 1), DaemonProtocol.STEP_FIREWALL)
        val marked = PrepMapping.failureOnly(items, LockdownFailure.TIMEOUT)
        assertEquals(ItemStatus.FAILED, status(marked, PrepItem.FIREWALL))
        assertEquals(LockdownFailure.TIMEOUT, marked.first { it.item == PrepItem.FIREWALL }.failure)
        assertEquals(ItemStatus.DONE, status(marked, PrepItem.VOLTE))
        assertNull(marked.first { it.item == PrepItem.WIFI }.failure)
    }

    @Test
    fun unreachableDaemonBlamesTheFirstItemBeforeAnyProgress() {
        val marked = PrepMapping.failureOnly(fresh(), LockdownFailure.DAEMON_UNREACHABLE)
        assertEquals(PrepItem.STRONGBOX, marked.first { it.status == ItemStatus.FAILED }.item)
        assertEquals(1, marked.count { it.status == ItemStatus.FAILED })
    }
}
