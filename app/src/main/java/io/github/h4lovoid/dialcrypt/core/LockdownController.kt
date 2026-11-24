package io.github.h4lovoid.dialcrypt.core

import androidx.annotation.StringRes
import io.github.h4lovoid.dialcrypt.R
import kotlinx.coroutines.flow.StateFlow

enum class HardeningLevel { LEVEL_1, LEVEL_2 }

enum class PrepItem {
    STRONGBOX, VOLTE, USB_DEBUG, TETHERING,
    FIREWALL, WIFI, MOBILE_DATA, SHORT_RANGE_RADIOS, USB_CHARGE_ONLY, LTE_NR_ONLY,
    OTHER_APPS_STOPPED, MEMORY_CLEARED,
}

enum class ItemStatus { PENDING, RUNNING, DONE, FAILED }

enum class LockdownFailure {
    VOLTE_NOT_REGISTERED, STRONGBOX_UNAVAILABLE, USB_DEBUG_ENABLED, TETHERING_ENABLED,
    DAEMON_UNREACHABLE, CALLER_REJECTED, RADIO_REFUSED, READBACK_MISMATCH, TIMEOUT, UNKNOWN,
}

data class PrepItemState(
    val item: PrepItem,
    val status: ItemStatus,
    val failure: LockdownFailure? = null,
    /** Set when the failure comes from a check the app runs itself rather than from the daemon. */
    val appCheck: AppCheck? = null,
)

/**
 * A check the app runs before it asks the daemon to prepare. A failed check is reported on the first
 * item with [LockdownFailure.UNKNOWN] and this value, which carries the texts naming the real cause.
 */
enum class AppCheck(@StringRes val label: Int, @StringRes val reason: Int, @StringRes val fix: Int) {
    /** Any enabled accessibility service can read messages, numbers and the built-in keypad. */
    NO_ACCESSIBILITY_SERVICES(R.string.prep_accessibility, R.string.fail_accessibility, R.string.fix_accessibility),
}

enum class LockdownPhase { NOT_CONNECTED, IDLE, PREPARING, READY, FAILED }

data class LockdownState(
    val phase: LockdownPhase = LockdownPhase.NOT_CONNECTED,
    val items: List<PrepItemState> = emptyList(),
    val level: HardeningLevel = HardeningLevel.LEVEL_1,
    val dryRun: Boolean = false,
) {
    val failedItem: PrepItemState? get() = items.firstOrNull { it.status == ItemStatus.FAILED }

    /** 0..100 over the listed items. */
    val percent: Int
        get() = if (items.isEmpty()) 0 else items.count { it.status == ItemStatus.DONE } * 100 / items.size
}

/** Pre-launch checks and system hardening, reported by the privileged daemon. */
interface LockdownController {
    val state: StateFlow<LockdownState>
    /** Start (or restart after a failure) the checks and hardening. */
    fun prepare()
}
