package io.github.h4lovoid.dialcrypt.dialer

import android.os.OutcomeReceiver
import android.os.SystemClock
import android.telecom.Call
import android.telecom.CallEndpointException
import io.github.h4lovoid.dialcrypt.dialer.model.Endpoint
import io.github.h4lovoid.dialcrypt.dialer.model.IncomingUiPolicy
import io.github.h4lovoid.dialcrypt.dialer.model.WaitingCallPlan
import io.github.h4lovoid.dialcrypt.incoming.CallRegistry

/**
 * [CallCommands] on the Telecom calls of [InCallStore], always on the "dialer-call" thread.
 * Answering goes through [CallRegistry] so the secure answer and the plain answer keep a single
 * winner. While the secure flow owns a call, only ending calls is allowed: holding, swapping,
 * merging, ending and answering, muting, routing or tones would interfere with it.
 */
internal object TelecomCallCommands : CallCommands {
    override fun answer(id: Int) {
        onCall(id) { e -> if (answerAllowed(e)) answerEntry(e) }
    }

    override fun endAndAnswer(id: Int) {
        onCall(id) { e ->
            if (secureBusy() || !answerAllowed(e)) return@onCall
            val steps = WaitingCallPlan.steps(WaitingCallPlan.Choice.END_AND_ANSWER, id, InCallStore.snapshots.value)
            for (step in steps) {
                when (step) {
                    is WaitingCallPlan.Step.Disconnect -> InCallStore.entry(step.id)?.let { runCatching { it.call.disconnect() } }
                    is WaitingCallPlan.Step.Answer -> answerEntry(e)
                    is WaitingCallPlan.Step.Reject -> runCatching { e.call.reject(false, null) }
                }
            }
        }
    }

    override fun merge() {
        InCallStore.handler.post {
            if (secureBusy()) return@post
            val top = InCallStore.entries().filter { it.call.parent == null }
            val active = top.firstOrNull { it.call.details.state == Call.STATE_ACTIVE }?.call ?: return@post
            val held = top.firstOrNull { it.call.details.state == Call.STATE_HOLDING }?.call
            runCatching {
                when {
                    active.details.can(Call.Details.CAPABILITY_MERGE_CONFERENCE) -> active.mergeConference()
                    held != null && held in active.conferenceableCalls -> active.conference(held)
                    held != null && held.details.can(Call.Details.CAPABILITY_MERGE_CONFERENCE) -> held.mergeConference()
                    else -> active.conferenceableCalls.firstOrNull()?.let { active.conference(it) }
                }
            }
        }
    }

    private fun answerAllowed(e: InCallStore.Entry): Boolean =
        IncomingUiPolicy.answerEnabled(InCallStore.screeningFor(e), SystemClock.elapsedRealtime() - e.addedMs)

    private fun answerEntry(e: InCallStore.Entry) {
        val offer = CallRegistry.offers.value
        if (offer != null && CallRegistry.isTracked(e.call)) {
            CallRegistry.answerPlain(offer.token)
        } else {
            CallRegistry.answerOrdinary(e.call)
        }
    }

    override fun reject(id: Int) {
        onCall(id) { e -> runCatching { e.call.reject(false, null) } }
    }

    override fun end(id: Int) {
        onCall(id) { e ->
            runCatching {
                if (e.call.details.state == Call.STATE_RINGING) e.call.reject(false, null) else e.call.disconnect()
            }
        }
    }

    override fun hold(id: Int, on: Boolean) {
        onCall(id) { e ->
            if (secureBusy()) return@onCall
            runCatching {
                if (!on) {
                    e.call.unhold()
                } else if (e.call.details.can(Call.Details.CAPABILITY_HOLD)) {
                    e.call.hold()
                }
            }
        }
    }

    override fun swap() {
        InCallStore.handler.post {
            if (secureBusy()) return@post
            val held = InCallStore.entries().firstOrNull { it.call.details.state == Call.STATE_HOLDING } ?: return@post
            // Telecom holds the active call itself when the held one resumes.
            runCatching { held.call.unhold() }
        }
    }

    override fun setMuted(on: Boolean) {
        InCallStore.handler.post {
            if (secureBusy()) return@post
            runCatching { InCallStore.service?.setMuted(on) }
        }
    }

    override fun route(e: Endpoint) {
        InCallStore.handler.post {
            if (secureBusy()) return@post
            val svc = InCallStore.service ?: return@post
            val target = InCallStore.endpointFor(e) ?: return@post
            runCatching {
                svc.requestCallEndpointChange(
                    target,
                    InCallStore.executor,
                    OutcomeReceiver<Void, CallEndpointException> { },
                )
            }
        }
    }

    override fun dtmf(id: Int, c: Char?) {
        onCall(id) { e ->
            runCatching {
                if (c == null) {
                    e.call.stopDtmfTone()
                } else if (!secureBusy()) {
                    e.call.playDtmfTone(c)
                }
            }
        }
    }

    override fun selectAccount(id: Int, index: Int) {
        onCall(id) { e ->
            if (secureBusy()) return@onCall
            val handle = e.accounts.getOrNull(index) ?: return@onCall
            runCatching { e.call.phoneAccountSelected(handle, false) }
        }
    }

    override fun postDial(id: Int, go: Boolean) {
        onCall(id) { e ->
            if (secureBusy()) return@onCall
            runCatching { e.call.postDialContinue(go) }
        }
    }

    private fun secureBusy(): Boolean = CallRegistry.view.value.secureOwned

    private inline fun onCall(id: Int, crossinline block: (InCallStore.Entry) -> Unit) {
        InCallStore.handler.post {
            val e = InCallStore.entry(id) ?: return@post
            block(e)
        }
    }
}
