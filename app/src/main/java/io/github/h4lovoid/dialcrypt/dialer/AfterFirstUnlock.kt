package io.github.h4lovoid.dialcrypt.dialer

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import androidx.core.content.ContextCompat
import io.github.h4lovoid.dialcrypt.core.DirectBoot
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Work of a `directBootAware` component that needs the app's files. It runs at once when the user is
 * unlocked; before the first unlock after boot it runs once, right after ACTION_USER_UNLOCKED. The
 * receiver belongs to the process, not to the component, so the work is not lost when the call that
 * started the component ends before the unlock.
 */
internal object AfterFirstUnlock {
    private val waiting = AtomicBoolean(false)

    fun run(context: Context, work: (Context) -> Unit) {
        val app = context.applicationContext ?: context
        if (DirectBoot.isUserUnlocked(app)) {
            work(app)
            return
        }
        if (!waiting.compareAndSet(false, true)) return
        val done = AtomicBoolean(false)
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(c: Context, intent: Intent) {
                if (!done.compareAndSet(false, true)) return
                runCatching { app.unregisterReceiver(this) }
                waiting.set(false)
                work(app)
            }
        }
        val registered = runCatching {
            ContextCompat.registerReceiver(app, receiver, IntentFilter(Intent.ACTION_USER_UNLOCKED), ContextCompat.RECEIVER_NOT_EXPORTED)
        }.isSuccess
        // Not registered, or unlocked between the check and the registration: the broadcast will not come.
        if (!registered || DirectBoot.isUserUnlocked(app)) receiver.onReceive(app, Intent(Intent.ACTION_USER_UNLOCKED))
    }
}
