package io.github.h4lovoid.dialcrypt.dialer

import android.telecom.Call
import android.telecom.CallEndpoint
import android.telecom.PhoneAccountHandle
import android.telecom.TelecomManager
import io.github.h4lovoid.dialcrypt.core.NumberPresentation
import io.github.h4lovoid.dialcrypt.dialer.model.CallSnapshot
import io.github.h4lovoid.dialcrypt.dialer.model.Endpoint

/** Copies Telecom calls into plain [CallSnapshot]s. Telecom state values are used as they are. */
internal object CallSnapshots {
    fun of(
        id: Int,
        call: Call,
        addedMs: Long,
        tracked: Boolean,
        emergency: Boolean,
        postDial: String?,
        accounts: List<String>,
    ): CallSnapshot {
        val d = call.details
        val (presentation, payphone) = presentation(d)
        return CallSnapshot(
            id = id,
            telecomState = d.state,
            incoming = isIncoming(d),
            number = if (presentation == NumberPresentation.SHOWN) number(d) else null,
            presentation = presentation,
            connectMs = d.connectTimeMillis,
            canHold = d.can(Call.Details.CAPABILITY_HOLD),
            conferenceChild = call.parent != null,
            emergency = emergency,
            postDial = postDial,
            accounts = accounts,
            payphone = payphone,
            tracked = tracked,
            addedMs = addedMs,
            canMerge = d.can(Call.Details.CAPABILITY_MERGE_CONFERENCE) || runCatching { call.conferenceableCalls.isNotEmpty() }.getOrDefault(false),
            conference = d.hasProperty(Call.Details.PROPERTY_CONFERENCE),
            participants = runCatching { call.children.size }.getOrDefault(0),
        )
    }

    fun number(d: Call.Details): String? = d.handle?.schemeSpecificPart?.trim()?.takeIf { it.isNotEmpty() }

    fun isIncoming(d: Call.Details): Boolean = when (d.callDirection) {
        Call.Details.DIRECTION_INCOMING -> true
        Call.Details.DIRECTION_OUTGOING -> false
        else -> d.state == Call.STATE_RINGING
    }

    /** The presentation and whether the caller is a payphone. */
    fun presentation(d: Call.Details): Pair<NumberPresentation, Boolean> = when (d.handlePresentation) {
        TelecomManager.PRESENTATION_RESTRICTED -> NumberPresentation.WITHHELD to false
        TelecomManager.PRESENTATION_PAYPHONE -> NumberPresentation.WITHHELD to true
        TelecomManager.PRESENTATION_UNKNOWN -> NumberPresentation.UNKNOWN to false
        else -> (if (number(d) != null) NumberPresentation.SHOWN else NumberPresentation.UNKNOWN) to false
    }

    /** SIMs offered while the call waits in SELECT_PHONE_ACCOUNT. */
    fun accountHandles(d: Call.Details): List<PhoneAccountHandle> {
        for (extras in listOf(d.intentExtras, d.extras)) {
            val list = runCatching {
                extras?.getParcelableArrayList(Call.AVAILABLE_PHONE_ACCOUNTS, PhoneAccountHandle::class.java)
            }.getOrNull()
            if (!list.isNullOrEmpty()) return list.toList()
        }
        return emptyList()
    }

    fun endpoint(type: Int): Endpoint = when (type) {
        CallEndpoint.TYPE_EARPIECE -> Endpoint.EARPIECE
        CallEndpoint.TYPE_SPEAKER -> Endpoint.SPEAKER
        CallEndpoint.TYPE_BLUETOOTH -> Endpoint.BLUETOOTH
        CallEndpoint.TYPE_WIRED_HEADSET -> Endpoint.WIRED
        else -> Endpoint.OTHER
    }
}
