package io.github.h4lovoid.dialcrypt.dialer

import android.annotation.SuppressLint
import android.content.Context
import android.net.Uri
import android.os.Bundle
import android.telecom.PhoneAccount
import android.telecom.TelecomManager
import io.github.h4lovoid.dialcrypt.dialer.model.DialInput
import io.github.h4lovoid.dialcrypt.dialer.model.DialPolicy

/** Places an outgoing call to an already cleaned number. */
fun interface CallPlacer {
    fun place(number: String): Boolean
}

/** [CallPlacer] on [TelecomManager.placeCall]. Telecom checks the permission itself; a refusal is false. */
class TelecomCallPlacer(private val context: Context) : CallPlacer {
    @SuppressLint("MissingPermission")
    override fun place(number: String): Boolean {
        val tm = context.getSystemService(TelecomManager::class.java) ?: return false
        return runCatching {
            tm.placeCall(Uri.fromParts(PhoneAccount.SCHEME_TEL, number, null), Bundle())
            true
        }.getOrDefault(false)
    }
}

enum class DialResult { PLACED, SPECIAL_CODE, EMPTY, BLOCKED, FAILED }

/**
 * What the dial pad's call button does. The typed text only goes through [DialInput.clean]; the
 * number is never judged, so emergency numbers and service codes go out unchanged. While a secure
 * call is under way ([secureBusy]) only emergency numbers may be dialed. When the emergency check
 * fails the number counts as an emergency number, so an emergency call is never refused.
 */
class Dialer(
    private val placer: CallPlacer,
    private val isEmergency: (String) -> Boolean,
    private val secureBusy: () -> Boolean,
    private val specialCode: (String) -> Boolean = { false },
) {
    fun dial(raw: String): DialResult {
        val number = DialInput.clean(raw) ?: return DialResult.EMPTY
        SPECIAL.matchEntire(number)?.let { m ->
            return if (specialCode(m.groupValues[1])) DialResult.SPECIAL_CODE else DialResult.FAILED
        }
        val emergency = runCatching { isEmergency(number) }.getOrDefault(true)
        if (!DialPolicy.allow(emergency, secureBusy())) return DialResult.BLOCKED
        return if (placer.place(number)) DialResult.PLACED else DialResult.FAILED
    }

    private companion object {
        /** *#*#code#*#*: handed to the system as a dialer special code, never dialed. */
        val SPECIAL = Regex("\\*#\\*#([0-9]+)#\\*#\\*")
    }
}

