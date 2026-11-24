package io.github.h4lovoid.dialcrypt.ui.model

import androidx.annotation.StringRes
import io.github.h4lovoid.dialcrypt.R
import io.github.h4lovoid.dialcrypt.core.HardeningLevel
import io.github.h4lovoid.dialcrypt.core.HardwareLevel
import io.github.h4lovoid.dialcrypt.core.LockdownFailure
import io.github.h4lovoid.dialcrypt.core.PinResult
import io.github.h4lovoid.dialcrypt.core.PairingResult
import io.github.h4lovoid.dialcrypt.core.ContactResult
import io.github.h4lovoid.dialcrypt.core.PinRules
import io.github.h4lovoid.dialcrypt.core.PrepItem
import io.github.h4lovoid.dialcrypt.core.QuickCommand
import io.github.h4lovoid.dialcrypt.core.QuickConnect
import io.github.h4lovoid.dialcrypt.core.SessionFailure

/** Failure codes from the core become sentences here, one per language in the string resources. */
object TextMaps {
    @StringRes
    fun prepItem(item: PrepItem): Int = when (item) {
        PrepItem.STRONGBOX -> R.string.prep_strongbox
        PrepItem.VOLTE -> R.string.prep_volte
        PrepItem.USB_DEBUG -> R.string.prep_usb_debug
        PrepItem.TETHERING -> R.string.prep_tethering
        PrepItem.FIREWALL -> R.string.prep_firewall
        PrepItem.WIFI -> R.string.prep_wifi
        PrepItem.MOBILE_DATA -> R.string.prep_mobile_data
        PrepItem.SHORT_RANGE_RADIOS -> R.string.prep_short_range
        PrepItem.USB_CHARGE_ONLY -> R.string.prep_usb_charge
        PrepItem.LTE_NR_ONLY -> R.string.prep_lte_nr
        PrepItem.OTHER_APPS_STOPPED -> R.string.prep_other_apps
        PrepItem.MEMORY_CLEARED -> R.string.prep_memory
    }

    @StringRes
    fun lockdownReason(code: LockdownFailure): Int = when (code) {
        LockdownFailure.VOLTE_NOT_REGISTERED -> R.string.fail_volte
        LockdownFailure.STRONGBOX_UNAVAILABLE -> R.string.fail_strongbox
        LockdownFailure.USB_DEBUG_ENABLED -> R.string.fail_usb_debug
        LockdownFailure.TETHERING_ENABLED -> R.string.fail_tethering
        LockdownFailure.DAEMON_UNREACHABLE -> R.string.fail_daemon
        LockdownFailure.CALLER_REJECTED -> R.string.fail_caller
        LockdownFailure.RADIO_REFUSED -> R.string.fail_radio
        LockdownFailure.READBACK_MISMATCH -> R.string.fail_readback
        LockdownFailure.TIMEOUT -> R.string.fail_timeout
        LockdownFailure.UNKNOWN -> R.string.fail_unknown
    }

    @StringRes
    fun lockdownFix(code: LockdownFailure): Int = when (code) {
        LockdownFailure.VOLTE_NOT_REGISTERED -> R.string.fix_volte
        LockdownFailure.STRONGBOX_UNAVAILABLE -> R.string.fix_strongbox
        LockdownFailure.USB_DEBUG_ENABLED -> R.string.fix_usb_debug
        LockdownFailure.TETHERING_ENABLED -> R.string.fix_tethering
        LockdownFailure.DAEMON_UNREACHABLE -> R.string.fix_daemon
        LockdownFailure.CALLER_REJECTED -> R.string.fix_caller
        LockdownFailure.RADIO_REFUSED -> R.string.fix_radio
        LockdownFailure.READBACK_MISMATCH -> R.string.fix_readback
        LockdownFailure.TIMEOUT -> R.string.fix_timeout
        LockdownFailure.UNKNOWN -> R.string.fix_unknown
    }

    @StringRes
    fun hardeningLevel(level: HardeningLevel): Int = when (level) {
        HardeningLevel.LEVEL_1 -> R.string.level_1
        HardeningLevel.LEVEL_2 -> R.string.level_2
    }

    @StringRes
    fun sessionFailure(code: SessionFailure): Int = when (code) {
        SessionFailure.NO_PREAMBLE -> R.string.abort_no_preamble
        SessionFailure.HANDSHAKE_FAILED -> R.string.abort_handshake
        SessionFailure.PSK_REQUIRED -> R.string.abort_psk
        SessionFailure.BEARER_VIOLATION -> R.string.abort_bearer
        SessionFailure.PEER_ABORTED -> R.string.abort_peer
        SessionFailure.CALL_DROPPED -> R.string.abort_dropped
        SessionFailure.UNKNOWN -> R.string.abort_unknown
    }

    /** Plain headline for the contact detail screen. */
    @StringRes
    fun hardwareTitle(level: HardwareLevel): Int = when (level) {
        HardwareLevel.UNATTESTED -> R.string.hw_title_none
        HardwareLevel.STRONGBOX_LOCKED -> R.string.hw_title_locked
        HardwareLevel.STRONGBOX_SELF_SIGNED -> R.string.hw_title_self
        HardwareLevel.STRONGBOX_UNLOCKED -> R.string.hw_title_unlocked
    }

    /** One line under the headline; it starts with the technical term from [hardwareDetail]. */
    @StringRes
    fun hardwareExplain(level: HardwareLevel): Int = when (level) {
        HardwareLevel.UNATTESTED -> R.string.hw_explain_none
        HardwareLevel.STRONGBOX_LOCKED -> R.string.hw_explain_locked
        HardwareLevel.STRONGBOX_SELF_SIGNED -> R.string.hw_explain_self
        HardwareLevel.STRONGBOX_UNLOCKED -> R.string.hw_explain_unlocked
    }

    /** Technical wording, only on detail screens. */
    @StringRes
    fun hardwareDetail(level: HardwareLevel): Int = when (level) {
        HardwareLevel.UNATTESTED -> R.string.hw_detail_none
        HardwareLevel.STRONGBOX_LOCKED -> R.string.hw_detail_locked
        HardwareLevel.STRONGBOX_SELF_SIGNED -> R.string.hw_detail_self
        HardwareLevel.STRONGBOX_UNLOCKED -> R.string.hw_detail_unlocked
    }

    @StringRes
    fun quickConnect(q: QuickConnect): Int = when (q) {
        QuickConnect.UNAVAILABLE -> R.string.quick_unavailable
        QuickConnect.READY -> R.string.quick_ready
        QuickConnect.REBUILD_PENDING -> R.string.quick_rebuild
    }

    @StringRes
    fun quickCommand(c: QuickCommand): Int = when (c) {
        QuickCommand.UNDERSTOOD -> R.string.quick_understood
        QuickCommand.YES -> R.string.quick_yes
        QuickCommand.NO -> R.string.quick_no
        QuickCommand.WAIT -> R.string.quick_wait
        QuickCommand.REPEAT -> R.string.quick_repeat
        QuickCommand.CALL_LATER -> R.string.quick_call_later
    }

    @StringRes
    fun strength(s: PinRules.Strength): Int = when (s) {
        PinRules.Strength.WEAK -> R.string.pin_strength_weak
        PinRules.Strength.FAIR -> R.string.pin_strength_fair
        PinRules.Strength.GOOD -> R.string.pin_strength_good
        PinRules.Strength.STRONG -> R.string.pin_strength_strong
    }

    /** Null for OK. */
    @StringRes
    fun pinResult(r: PinResult): Int? = when (r) {
        PinResult.OK -> null
        PinResult.TOO_SHORT -> R.string.pin_error_short
        PinResult.TOO_SIMPLE -> R.string.pin_error_simple
        PinResult.SAME_PINS -> R.string.pin_error_same
        PinResult.WRONG_CURRENT -> R.string.pin_error_wrong_current
        PinResult.DEVICE_UNSUPPORTED -> R.string.pin_error_unsupported
        PinResult.NOT_CONNECTED -> R.string.pin_error_not_connected
        PinResult.FAILED -> R.string.pin_error_failed
        PinResult.DURESS -> null
    }

    @StringRes
    fun pairing(r: PairingResult): Int = when (r) {
        PairingResult.OK -> R.string.pair_ok
        PairingResult.BAD_FORMAT -> R.string.pair_bad_format
        PairingResult.BAD_CHECKSUM -> R.string.pair_bad_checksum
        PairingResult.WRONG_KEY -> R.string.pair_wrong_key
        PairingResult.FAILED -> R.string.pair_failed
    }

    @StringRes
    fun contactError(r: ContactResult): Int? = when (r) {
        ContactResult.OK -> null
        ContactResult.NOT_FOUND -> R.string.contact_error_failed
        ContactResult.INVALID_NAME -> R.string.contact_error_name
        ContactResult.INVALID_NUMBER -> R.string.contact_error_number
        ContactResult.FAILED -> R.string.contact_error_failed
    }
}
