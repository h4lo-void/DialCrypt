package io.github.h4lovoid.dialcrypt.dialer

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/**
 * Decline and hang-up buttons of the call notifications. Not exported. The work leaves the main
 * thread at once; an action whose call id and nonce do not match a call of this process (an old
 * notification, or one from before `:call` restarted) is ignored.
 */
class CallActionReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action
        if (action != ACTION_DECLINE && action != ACTION_HANG_UP) return
        val id = intent.getIntExtra(EXTRA_CALL_ID, -1)
        val nonce = intent.getByteArrayExtra(EXTRA_NONCE)
        val pending = goAsync()
        InCallStore.handler.post {
            try {
                if (InCallStore.accepts(id, nonce)) {
                    if (action == ACTION_DECLINE) InCallStore.commands.reject(id) else InCallStore.commands.end(id)
                }
            } finally {
                pending.finish()
            }
        }
    }

    companion object {
        const val ACTION_DECLINE = "io.github.h4lovoid.dialcrypt.dialer.action.DECLINE"
        const val ACTION_HANG_UP = "io.github.h4lovoid.dialcrypt.dialer.action.HANG_UP"

        /** Set on the in-call screen intent of the notification's answer button. */
        const val ACTION_ANSWER = "io.github.h4lovoid.dialcrypt.dialer.action.ANSWER"
        const val EXTRA_CALL_ID = "io.github.h4lovoid.dialcrypt.dialer.extra.CALL_ID"
        const val EXTRA_NONCE = "io.github.h4lovoid.dialcrypt.dialer.extra.NONCE"
    }
}
