package io.github.h4lovoid.dialcrypt.core

/** Whether the secure screen of this process is started (between onStart and onStop). */
object SecureForeground {
    @Volatile
    var started: Boolean = false
}
