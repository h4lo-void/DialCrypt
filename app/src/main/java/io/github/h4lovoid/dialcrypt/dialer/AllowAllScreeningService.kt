package io.github.h4lovoid.dialcrypt.dialer

import android.telecom.Call
import android.telecom.CallScreeningService
import android.telecom.CallScreeningService.CallResponse

/**
 * Holder of the call screening role in `:dialer`, so the system phone app's caller ID and spam
 * service stop seeing calls. Every call is let through at once; nothing about the call is read or
 * logged.
 */
class AllowAllScreeningService : CallScreeningService() {
    override fun onScreenCall(callDetails: Call.Details) {
        runCatching { respondToCall(callDetails, CallResponse.Builder().build()) }
    }
}

