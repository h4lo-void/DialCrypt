package io.github.h4lovoid.dialcrypt.core

import android.content.Context
import io.github.h4lovoid.dialcrypt.call.RelayCallLink
import io.github.h4lovoid.dialcrypt.core.daemon.DaemonLockdownController
import io.github.h4lovoid.dialcrypt.core.real.NativeSecureCore
import io.github.h4lovoid.dialcrypt.security.TitanM2StrongBoxBridge

/**
 * Release builds use the real parts: the native secure core over the cellular call link in
 * the secure process, and the root daemon for the preparation steps in the launcher process.
 */
internal object DefaultCores {
    fun secureCore(context: Context): SecureCore =
        NativeSecureCore(context, RelayCallLink(context), TitanM2StrongBoxBridge(context))

    fun lockdown(context: Context): LockdownController = DaemonLockdownController(context)
}
