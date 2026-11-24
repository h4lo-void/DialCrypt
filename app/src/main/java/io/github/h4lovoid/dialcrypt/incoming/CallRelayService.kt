package io.github.h4lovoid.dialcrypt.incoming

import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Message
import android.os.Messenger
import android.os.RemoteException
import android.util.Log
import io.github.h4lovoid.dialcrypt.call.CallStatus
import io.github.h4lovoid.dialcrypt.call.IncomingOffer
import java.util.concurrent.CopyOnWriteArraySet
import java.util.concurrent.atomic.AtomicInteger

/**
 * Bound Messenger service in `:call` mediating [io.github.h4lovoid.dialcrypt.call.RelayCallLink] in `:secure`
 * with same-UID verification on every incoming IPC message.
 * It is also started, without a notification, for the few seconds after a call while the call log
 * eraser runs ([holdProcess]), so `:call` is not dropped as a cached process once Telecom unbinds.
 */
class CallRelayService : Service() {
    private val subscribers = CopyOnWriteArraySet<Messenger>()

    private val registryListener = object : CallRegistry.Listener {
        override fun onStatus(status: CallStatus) {
            broadcast(statusMessage(status))
        }

        override fun onOffer(offer: IncomingOffer?): Boolean = broadcast(offerMessage(offer))
    }

    private val incomingHandler = object : Handler(Looper.getMainLooper()) {
        override fun handleMessage(msg: Message) {
            if (!RelayProtocol.isSameUid(msg)) return
            when (msg.what) {
                RelayProtocol.MSG_SUBSCRIBE -> {
                    val reply = msg.replyTo ?: return
                    subscribers.add(reply)
                    CallRegistry.suppressPromptForApp()
                    sendSafe(reply, statusMessage(CallRegistry.status.value))
                    sendSafe(reply, offerMessage(CallRegistry.offers.value))
                }
                RelayProtocol.MSG_UNSUBSCRIBE -> {
                    msg.replyTo?.let { subscribers.remove(it) }
                }
                RelayProtocol.MSG_EXPECT_DIAL -> {
                    val num = msg.data?.getString(RelayProtocol.KEY_NUMBER)
                    CallRegistry.expectDial(num)
                }
                RelayProtocol.MSG_HANG_UP -> {
                    CallRegistry.hangUp()
                }
                RelayProtocol.MSG_CLAIM -> {
                    val token = msg.data?.getByteArray(RelayProtocol.KEY_TOKEN) ?: ByteArray(0)
                    val res = CallRegistry.claim(token)
                    msg.replyTo?.let { reply ->
                        sendSafe(reply, Message.obtain(null, RelayProtocol.MSG_CLAIM_RESULT, res.ordinal, 0))
                    }
                }
                RelayProtocol.MSG_RELEASE -> {
                    val token = msg.data?.getByteArray(RelayProtocol.KEY_TOKEN) ?: ByteArray(0)
                    CallRegistry.release(token)
                }
                RelayProtocol.MSG_RETURN_OFFER -> {
                    val token = msg.data?.getByteArray(RelayProtocol.KEY_TOKEN) ?: ByteArray(0)
                    CallRegistry.returnOfferToPrompt(token)
                }
                RelayProtocol.MSG_ANSWER_CALL -> {
                    val ok = CallRegistry.answer()
                    msg.replyTo?.let { reply ->
                        sendSafe(reply, Message.obtain(null, RelayProtocol.MSG_BOOL_RESULT, if (ok) 1 else 0, 0))
                    }
                }
                RelayProtocol.MSG_ANSWER_PLAIN -> {
                    val token = msg.data?.getByteArray(RelayProtocol.KEY_TOKEN) ?: ByteArray(0)
                    val ok = CallRegistry.answerPlain(token)
                    msg.replyTo?.let { reply ->
                        sendSafe(reply, Message.obtain(null, RelayProtocol.MSG_BOOL_RESULT, if (ok) 1 else 0, 0))
                    }
                }
                RelayProtocol.MSG_SET_DATA_ROUTE -> {
                    CallRegistry.setDataRoute(msg.arg1 != 0)
                }
            }
        }
    }

    private val messenger = Messenger(incomingHandler)

    override fun onCreate() {
        super.onCreate()
        io.github.h4lovoid.dialcrypt.call.CallAudioMuter.recoverLeftover(applicationContext)
        io.github.h4lovoid.dialcrypt.call.CallAudioMuter.recoverOrphan(applicationContext, "secure")
        CallRegistry.addListener(registryListener)
    }

    override fun onDestroy() {
        CallRegistry.removeListener(registryListener)
        subscribers.clear()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? {
        if (intent?.action != RelayProtocol.ACTION_BIND) return null
        return messenger.binder
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action != ACTION_HOLD) stopSelf(startId)
        return START_NOT_STICKY
    }

    private fun broadcast(template: Message): Boolean {
        val dead = ArrayList<Messenger>()
        var delivered = false
        for (sub in subscribers) {
            val copy = Message.obtain().apply { copyFrom(template) }
            if (sendSafe(sub, copy)) delivered = true else dead += sub
        }
        subscribers.removeAll(dead.toSet())
        return delivered
    }

    private fun sendSafe(target: Messenger, msg: Message): Boolean = try {
        target.send(msg)
        true
    } catch (_: RemoteException) {
        false
    }

    private fun statusMessage(status: CallStatus): Message =
        Message.obtain(null, RelayProtocol.MSG_STATUS, status.phase.ordinal, (if (status.incoming) 1 else 0) or (status.presentation.ordinal shl 1)).apply {
            data = Bundle().apply {
                putString(RelayProtocol.KEY_NUMBER, status.number)
            }
        }

    private fun offerMessage(offer: IncomingOffer?): Message =
        Message.obtain(null, RelayProtocol.MSG_OFFER).apply {
            data = Bundle().apply {
                if (offer != null) {
                    putByteArray(RelayProtocol.KEY_TOKEN, offer.token)
                    putString(RelayProtocol.KEY_NUMBER, offer.number)
                    putInt(RelayProtocol.KEY_PRESENTATION, offer.presentation.ordinal)
                }
            }
        }

    companion object {
        private const val TAG = "AegisCallRelay"
        private const val ACTION_HOLD = "io.github.h4lovoid.dialcrypt.incoming.HOLD"
        private val holds = AtomicInteger(0)

        /**
         * Keeps `:call` at started-service priority until the matching [releaseProcess]. Called
         * while Telecom still binds the in-call service, when a start from the app is allowed.
         */
        internal fun holdProcess(context: Context) {
            if (holds.incrementAndGet() != 1) return
            val intent = Intent(context, CallRelayService::class.java).setAction(ACTION_HOLD)
            runCatching { context.startService(intent) }
                .onFailure { Log.i(TAG, "process hold refused: ${it.javaClass.simpleName}") }
        }

        internal fun releaseProcess(context: Context) {
            val left = holds.decrementAndGet()
            if (left > 0) return
            holds.set(0)
            runCatching { context.stopService(Intent(context, CallRelayService::class.java)) }
        }
    }
}
