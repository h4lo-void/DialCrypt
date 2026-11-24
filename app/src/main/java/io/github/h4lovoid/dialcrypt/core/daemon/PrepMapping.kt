package io.github.h4lovoid.dialcrypt.core.daemon

import io.github.h4lovoid.dialcrypt.core.AppCheck
import io.github.h4lovoid.dialcrypt.core.HardeningLevel
import io.github.h4lovoid.dialcrypt.core.ItemStatus
import io.github.h4lovoid.dialcrypt.core.LockdownFailure
import io.github.h4lovoid.dialcrypt.core.PrepItem
import io.github.h4lovoid.dialcrypt.core.PrepItemState

/** Maps the daemon's steps and FAIL fields onto the checklist the preparation screen shows. */
internal object PrepMapping {
    private val stepOrder: Map<Int, List<PrepItem>> = linkedMapOf(
        DaemonProtocol.STEP_PRECHECK to listOf(PrepItem.STRONGBOX, PrepItem.VOLTE, PrepItem.USB_DEBUG, PrepItem.TETHERING),
        DaemonProtocol.STEP_FIREWALL to listOf(PrepItem.FIREWALL),
        DaemonProtocol.STEP_RADIOS to listOf(
            PrepItem.WIFI, PrepItem.MOBILE_DATA, PrepItem.SHORT_RANGE_RADIOS, PrepItem.USB_CHARGE_ONLY, PrepItem.LTE_NR_ONLY,
        ),
        DaemonProtocol.STEP_APPS to listOf(PrepItem.OTHER_APPS_STOPPED),
        DaemonProtocol.STEP_MEMORY to listOf(PrepItem.MEMORY_CLEARED),
    )

    private val tier2Items = listOf(PrepItem.OTHER_APPS_STOPPED, PrepItem.MEMORY_CLEARED)

    fun stepOf(item: PrepItem): Int = stepOrder.entries.first { item in it.value }.key

    fun itemsFor(level: HardeningLevel, status: ItemStatus): List<PrepItemState> {
        val all = stepOrder.values.flatten()
        val shown = if (level == HardeningLevel.LEVEL_2) all else all.filter { it !in tier2Items }
        return shown.map { PrepItemState(it, status) }
    }

    /** The daemon sends PROGRESS when it starts a step: earlier steps are done, this step is running. */
    fun applyProgress(items: List<PrepItemState>, step: Int): List<PrepItemState> {
        if (step !in stepOrder) return items
        val withTier2 = if (step >= DaemonProtocol.STEP_APPS && items.none { it.item == PrepItem.OTHER_APPS_STOPPED }) {
            items + tier2Items.map { PrepItemState(it, ItemStatus.PENDING) }
        } else {
            items
        }
        return withTier2.map {
            val s = stepOf(it.item)
            when {
                it.status == ItemStatus.FAILED -> it
                s < step -> it.copy(status = ItemStatus.DONE)
                s == step -> it.copy(status = ItemStatus.RUNNING)
                else -> it
            }
        }
    }

    fun allDone(items: List<PrepItemState>, tier: Int): List<PrepItemState> {
        val base = if (tier >= 2 && items.none { it.item == PrepItem.OTHER_APPS_STOPPED }) {
            items + tier2Items.map { PrepItemState(it, ItemStatus.PENDING) }
        } else {
            items
        }
        return base.map { it.copy(status = ItemStatus.DONE, failure = null) }
    }

    /** The item the daemon is working on: the first running one, else the first one not started. */
    fun currentItem(items: List<PrepItemState>): PrepItem? =
        (items.firstOrNull { it.status == ItemStatus.RUNNING } ?: items.firstOrNull { it.status == ItemStatus.PENDING }
            ?: items.firstOrNull())?.item

    /** Maps one FAIL to the item and reason to show. [specific] is false when only the generic reason applies. */
    class Mapped(val item: PrepItem, val failure: LockdownFailure, val specific: Boolean)

    fun mapFail(item: Int, code: Int, items: List<PrepItemState>): Mapped {
        val current = currentItem(items) ?: PrepItem.STRONGBOX
        return when (item) {
            DaemonProtocol.ITEM_ADB -> Mapped(PrepItem.USB_DEBUG, LockdownFailure.USB_DEBUG_ENABLED, true)
            DaemonProtocol.ITEM_TETHER -> Mapped(PrepItem.TETHERING, LockdownFailure.TETHERING_ENABLED, true)
            DaemonProtocol.ITEM_IMS -> Mapped(PrepItem.VOLTE, LockdownFailure.VOLTE_NOT_REGISTERED, true)
            DaemonProtocol.ITEM_AUTH -> Mapped(current, LockdownFailure.CALLER_REJECTED, true)
            DaemonProtocol.ITEM_APPLY -> when {
                code == DaemonProtocol.CODE_READBACK_MISMATCH -> Mapped(current, LockdownFailure.READBACK_MISMATCH, true)
                code == DaemonProtocol.CODE_APPLY_FAILED && stepOf(current) == DaemonProtocol.STEP_RADIOS ->
                    Mapped(current, LockdownFailure.RADIO_REFUSED, true)
                else -> Mapped(current, LockdownFailure.UNKNOWN, false)
            }
            else -> Mapped(current, LockdownFailure.UNKNOWN, false)
        }
    }

    /**
     * Marks the failing items. Specific reasons win over generic ones; with none, the first generic one is shown.
     * An item still running when the daemon reported a precheck failure passed that check; any other running item goes back to pending.
     */
    fun markFailed(items: List<PrepItemState>, failures: List<Mapped>, daemonReported: Boolean = true): List<PrepItemState> {
        val chosen = failures.filter { it.specific }.ifEmpty { failures.take(1) }
        val failedFor = LinkedHashMap<PrepItem, LockdownFailure>()
        for (f in chosen) failedFor.putIfAbsent(f.item, f.failure)
        val precheckPassed = daemonReported && currentItem(items)?.let { stepOf(it) } == DaemonProtocol.STEP_PRECHECK
        return items.map {
            val failure = failedFor[it.item]
            when {
                failure != null -> PrepItemState(it.item, ItemStatus.FAILED, failure)
                it.status == ItemStatus.RUNNING -> it.copy(status = if (precheckPassed) ItemStatus.DONE else ItemStatus.PENDING)
                else -> it
            }
        }
    }

    fun failureOnly(items: List<PrepItemState>, failure: LockdownFailure): List<PrepItemState> {
        val current = currentItem(items) ?: PrepItem.STRONGBOX
        return markFailed(items, listOf(Mapped(current, failure, true)), daemonReported = false)
    }

    /** An app-side check failed before the daemon was asked: the current item fails and names the check. */
    fun appCheckFailed(items: List<PrepItemState>, check: AppCheck): List<PrepItemState> =
        failureOnly(items, LockdownFailure.UNKNOWN).map { if (it.status == ItemStatus.FAILED) it.copy(appCheck = check) else it }
}
