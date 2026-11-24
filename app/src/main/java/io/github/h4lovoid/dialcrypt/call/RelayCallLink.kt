package io.github.h4lovoid.dialcrypt.call

import android.Manifest
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Bundle
import android.os.Handler
import android.os.HandlerThread
import android.os.IBinder
import android.os.Message
import android.os.Messenger
import android.telecom.TelecomManager
import android.util.Log
import androidx.core.content.ContextCompat
import io.github.h4lovoid.dialcrypt.core.NumberPresentation
import io.github.h4lovoid.dialcrypt.incoming.CallRelayService
import io.github.h4lovoid.dialcrypt.incoming.RelayProtocol
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull

/**
 * Production [CallLink] inside `:secure` backed by IPC to [CallRelayService] in `:call`.
 * Keeps incoming call screening and Telekom `InCallService` active even when `:secure` exits.
 */
class RelayCallLink(context: Context) : CallLink {
    private val appContext = context.applicationContext
    private val tm = appContext.getSystemService(TelecomManager::class.java)

    private val _status = MutableStateFlow(CallStatus())
    override val status: StateFlow<CallStatus> = _status.asStateFlow()

    private val _offers = MutableStateFlow<IncomingOffer?>(null)
    override val offers: StateFlow<IncomingOffer?> = _offers.asStateFlow()

    private val ipcThread = HandlerThread("aegis-relay-ipc").apply { start() }
    private val ipcHandler = object : Handler(ipcThread.looper) {
        override fun handleMessage(msg: Message) {
            if (!RelayProtocol.isSameUid(msg)) return
            when (msg.what) {
                RelayProtocol.MSG_STATUS -> {
                    val phase = CallPhase.entries.getOrElse(msg.arg1) { CallPhase.IDLE }
                    val incoming = (msg.arg2 and 1) != 0
                    val presIdx = (msg.arg2 ushr 1)
                    val presentation = NumberPresentation.entries.getOrElse(presIdx) { NumberPresentation.SHOWN }
                    val number = msg.data?.getString(RelayProtocol.KEY_NUMBER)
                    _status.value = CallStatus(phase = phase, incoming = incoming, number = number, presentation = presentation)
                }
                RelayProtocol.MSG_OFFER -> {
                    val b = msg.data
                    val token = b?.getByteArray(RelayProtocol.KEY_TOKEN)
                    if (token == null || token.isEmpty()) {
                        _offers.value = null
                    } else {
                        val num = b.getString(RelayProtocol.KEY_NUMBER)
                        val pres = NumberPresentation.entries.getOrElse(
                            b.getInt(RelayProtocol.KEY_PRESENTATION),
                        ) { NumberPresentation.SHOWN }
                        _offers.value = IncomingOffer(token = token, number = num, presentation = pres)
                    }
                }
            }
        }
    }
    private val clientMessenger = Messenger(ipcHandler)

    @Volatile
    private var serviceMessenger: Messenger? = null

    @Volatile
    private var pendingHangUp: Boolean = false

    @Volatile
    private var pendingDataRoute: Boolean? = null

    /** Number of a dial made before the relay was bound; sent on connect so `:call` knows the call is ours. */
    @Volatile
    private var pendingExpectDial: String? = null

    private val bindLock = Any()

    private val conn = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
            val m = binder?.let { Messenger(it) } ?: return
            serviceMessenger = m
            pendingExpectDial?.let { number ->
                pendingExpectDial = null
                sendOneWay(m, expectDialMessage(number))
            }
            sendOneWay(m, Message.obtain(null, RelayProtocol.MSG_SUBSCRIBE).apply { replyTo = clientMessenger })
            if (pendingHangUp) {
                pendingHangUp = false
                sendOneWay(m, Message.obtain(null, RelayProtocol.MSG_HANG_UP))
            }
            pendingDataRoute?.let { route ->
                pendingDataRoute = null
                sendOneWay(m, Message.obtain(null, RelayProtocol.MSG_SET_DATA_ROUTE, if (route) 1 else 0, 0))
            }
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            serviceMessenger = null
        }

        override fun onNullBinding(name: ComponentName?) {
            serviceMessenger = null
        }
    }

    init {
        ensureBound()
    }

    override fun dial(number: String): Boolean {
        val m = tm ?: return false
        if (!hasPermission(Manifest.permission.CALL_PHONE)) {
            Log.e(TAG, "CALL_PHONE permission missing")
            return false
        }
        val clean = number.trim()
        if (clean.isEmpty()) return false
        ensureBound()
        pendingHangUp = false
        val relay = serviceMessenger
        if (relay != null && sendOneWay(relay, expectDialMessage(clean))) {
            pendingExpectDial = null
        } else {
            pendingExpectDial = clean
            ensureBound()
        }
        return runCatching {
            m.placeCall(Uri.fromParts("tel", clean, null), Bundle())
            true
        }.getOrElse {
            pendingExpectDial = null
            Log.e(TAG, "placeCall failed: ${it.javaClass.simpleName}")
            false
        }
    }

    override fun answer(): Boolean {
        val target = ensureBoundService(1_500L) ?: return false
        val future = CompletableFuture<Boolean>()
        val reply = oneShotMessenger { msg ->
            if (msg.what == RelayProtocol.MSG_BOOL_RESULT) {
                future.complete(msg.arg1 != 0)
            }
        }
        val sent = sendOneWay(target, Message.obtain(null, RelayProtocol.MSG_ANSWER_CALL).apply { replyTo = reply })
        if (!sent) return false
        return runCatching { future.get(2_000L, TimeUnit.MILLISECONDS) }.getOrDefault(false)
    }

    override fun hangUp() {
        val target = serviceMessenger
        if (target == null || !sendOneWay(target, Message.obtain(null, RelayProtocol.MSG_HANG_UP))) {
            pendingHangUp = true
            ensureBound()
        }
    }

    override fun claim(token: ByteArray): ClaimResult {
        val target = ensureBoundService(1_500L) ?: return ClaimResult.GONE
        val future = CompletableFuture<ClaimResult>()
        val reply = oneShotMessenger { msg ->
            if (msg.what == RelayProtocol.MSG_CLAIM_RESULT) {
                val res = ClaimResult.entries.getOrElse(msg.arg1) { ClaimResult.GONE }
                future.complete(res)
            }
        }
        val msg = Message.obtain(null, RelayProtocol.MSG_CLAIM).apply {
            replyTo = reply
            data = Bundle().apply { putByteArray(RelayProtocol.KEY_TOKEN, token) }
        }
        if (!sendOneWay(target, msg)) return ClaimResult.GONE
        return runCatching { future.get(2_000L, TimeUnit.MILLISECONDS) }.getOrDefault(ClaimResult.GONE)
    }

    override fun release(token: ByteArray) {
        val target = serviceMessenger ?: return
        sendOneWay(
            target,
            Message.obtain(null, RelayProtocol.MSG_RELEASE).apply {
                data = Bundle().apply { putByteArray(RelayProtocol.KEY_TOKEN, token) }
            },
        )
    }

    override fun returnOffer(token: ByteArray) {
        val target = serviceMessenger ?: return
        sendOneWay(
            target,
            Message.obtain(null, RelayProtocol.MSG_RETURN_OFFER).apply {
                data = Bundle().apply { putByteArray(RelayProtocol.KEY_TOKEN, token) }
            },
        )
    }

    override fun answerPlain(token: ByteArray): Boolean {
        val target = ensureBoundService(1_500L) ?: return false
        val future = CompletableFuture<Boolean>()
        val reply = oneShotMessenger { msg ->
            if (msg.what == RelayProtocol.MSG_BOOL_RESULT) {
                future.complete(msg.arg1 != 0)
            }
        }
        val msg = Message.obtain(null, RelayProtocol.MSG_ANSWER_PLAIN).apply {
            replyTo = reply
            data = Bundle().apply { putByteArray(RelayProtocol.KEY_TOKEN, token) }
        }
        if (!sendOneWay(target, msg)) return false
        return runCatching { future.get(2_000L, TimeUnit.MILLISECONDS) }.getOrDefault(false)
    }

    override fun setDataRoute(dataMode: Boolean) {
        val target = serviceMessenger
        if (target == null || !sendOneWay(target, Message.obtain(null, RelayProtocol.MSG_SET_DATA_ROUTE, if (dataMode) 1 else 0, 0))) {
            pendingDataRoute = dataMode
            ensureBound()
        }
    }

    override suspend fun waitUntilDisconnected(timeoutMs: Long): Boolean {
        val current = _status.value.phase
        if (current == CallPhase.IDLE || current == CallPhase.ENDED) return true
        return withTimeoutOrNull(timeoutMs) {
            _status.first { it.phase == CallPhase.IDLE || it.phase == CallPhase.ENDED }
        } != null
    }

    override fun openAudio(): CallAudio? = CallAudioRoutes.open(
        appContext,
        onBeforeReleaseMute = { runBlocking { waitUntilDisconnected(1_500L) } },
        onDataRoute = ::setDataRoute,
    )

    private fun ensureBound() {
        if (serviceMessenger != null) return
        synchronized(bindLock) {
            if (serviceMessenger != null) return
            val intent = Intent(appContext, CallRelayService::class.java).apply {
                action = RelayProtocol.ACTION_BIND
            }
            runCatching { appContext.bindService(intent, conn, Context.BIND_AUTO_CREATE) }
        }
    }

    private fun ensureBoundService(timeoutMs: Long): Messenger? {
        serviceMessenger?.let { return it }
        ensureBound()
        val deadline = System.currentTimeMillis() + timeoutMs
        while (serviceMessenger == null && System.currentTimeMillis() < deadline) {
            runCatching { Thread.sleep(25L) }
        }
        return serviceMessenger
    }

    private fun oneShotMessenger(onReply: (Message) -> Unit): Messenger {
        val h = object : Handler(ipcThread.looper) {
            override fun handleMessage(msg: Message) {
                if (RelayProtocol.isSameUid(msg)) onReply(msg)
            }
        }
        return Messenger(h)
    }

    private fun sendOneWay(target: Messenger, msg: Message): Boolean = try {
        target.send(msg)
        true
    } catch (e: Exception) {
        Log.w(TAG, "relay send failed: ${e.javaClass.simpleName}")
        serviceMessenger = null
        false
    }

    private fun hasPermission(perm: String): Boolean =
        ContextCompat.checkSelfPermission(appContext, perm) == PackageManager.PERMISSION_GRANTED

    private fun expectDialMessage(number: String): Message =
        Message.obtain(null, RelayProtocol.MSG_EXPECT_DIAL).apply {
            data = Bundle().apply { putString(RelayProtocol.KEY_NUMBER, number) }
        }

    private companion object {
        const val TAG = "AegisRelayCallLink"
    }
}
