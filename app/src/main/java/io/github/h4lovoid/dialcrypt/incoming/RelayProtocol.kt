package io.github.h4lovoid.dialcrypt.incoming

import android.os.Message
import android.os.Process

/**
 * IPC constants and UID verification between `:call` ([CallRelayService]) and `:secure`
 * ([io.github.h4lovoid.dialcrypt.call.RelayCallLink]). Keeps the two processes loosely coupled without
 * sharing vault, daemon, or native symbols with `:call`.
 */
internal object RelayProtocol {
    const val ACTION_BIND = "io.github.h4lovoid.dialcrypt.incoming.RELAY"
    const val EXTRA_HANDOFF_TOKEN = "io.github.h4lovoid.dialcrypt.HANDOFF_TOKEN"

    const val MSG_SUBSCRIBE = 1
    const val MSG_UNSUBSCRIBE = 2
    const val MSG_STATUS = 3
    const val MSG_OFFER = 4
    const val MSG_EXPECT_DIAL = 5
    const val MSG_HANG_UP = 6
    const val MSG_CLAIM = 7
    const val MSG_CLAIM_RESULT = 8
    const val MSG_RELEASE = 9
    const val MSG_ANSWER_PLAIN = 10
    const val MSG_BOOL_RESULT = 11
    const val MSG_SET_DATA_ROUTE = 12
    const val MSG_ANSWER_CALL = 13
    /** `:secure` cannot show this offer (not in front, lock screen, or ending): `:call` shows its prompt. */
    const val MSG_RETURN_OFFER = 14

    const val KEY_NUMBER = "number"
    const val KEY_TOKEN = "token"
    const val KEY_PRESENTATION = "presentation"

    fun isSameUid(msg: Message): Boolean = msg.sendingUid == Process.myUid()
}
