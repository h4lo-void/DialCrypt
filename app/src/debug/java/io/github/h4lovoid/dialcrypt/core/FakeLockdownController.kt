package io.github.h4lovoid.dialcrypt.core

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

/** Scripted stand-in for the privileged helper. With a [scope], [prepare] plays the checks out in order. */
class FakeLockdownController(
    initial: LockdownState = LockdownState(LockdownPhase.IDLE, itemsFor(HardeningLevel.LEVEL_1, ItemStatus.PENDING)),
    private val scope: CoroutineScope? = null,
    /** When set, the script stops at this item with the given failure. */
    var failAt: Pair<PrepItem, LockdownFailure>? = null,
) : LockdownController {
    private val flow = MutableStateFlow(initial)
    override val state: StateFlow<LockdownState> = flow

    var prepareCalls = 0
        private set

    fun setState(value: LockdownState) { flow.value = value }

    override fun prepare() {
        prepareCalls++
        val s = scope ?: return
        val level = flow.value.level
        flow.value = LockdownState(LockdownPhase.PREPARING, itemsFor(level, ItemStatus.PENDING), level)
        s.launch {
            val order = flow.value.items.map { it.item }
            for (item in order) {
                setItem(item, ItemStatus.RUNNING, null)
                delay(350)
                val fail = failAt
                if (fail != null && fail.first == item) {
                    setItem(item, ItemStatus.FAILED, fail.second)
                    flow.update { it.copy(phase = LockdownPhase.FAILED) }
                    failAt = null
                    return@launch
                }
                setItem(item, ItemStatus.DONE, null)
            }
            flow.update { it.copy(phase = LockdownPhase.READY) }
        }
    }

    private fun setItem(item: PrepItem, status: ItemStatus, failure: LockdownFailure?) {
        flow.update { st -> st.copy(items = st.items.map { if (it.item == item) PrepItemState(item, status, failure) else it }) }
    }

    companion object {
        fun itemsFor(level: HardeningLevel, status: ItemStatus): List<PrepItemState> {
            val base = listOf(
                PrepItem.STRONGBOX, PrepItem.VOLTE, PrepItem.USB_DEBUG, PrepItem.TETHERING,
                PrepItem.FIREWALL, PrepItem.WIFI, PrepItem.MOBILE_DATA, PrepItem.SHORT_RANGE_RADIOS,
                PrepItem.USB_CHARGE_ONLY, PrepItem.LTE_NR_ONLY,
            )
            val extra = if (level == HardeningLevel.LEVEL_2) listOf(PrepItem.OTHER_APPS_STOPPED, PrepItem.MEMORY_CLEARED) else emptyList()
            return (base + extra).map { PrepItemState(it, status) }
        }
    }
}
