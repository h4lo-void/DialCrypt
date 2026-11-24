package io.github.h4lovoid.dialcrypt.core

import android.content.Context
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob

/** Debug builds run against scripted fakes so the whole interface can be clicked through. */
internal object DefaultCores {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)

    fun secureCore(@Suppress("UNUSED_PARAMETER") context: Context): SecureCore =
        FakeSecureCore(
            initialState = CoreState(CoreAvailability.READY),
            initialContacts = FakeScenarios.contacts,
            scope = scope,
        )

    fun lockdown(@Suppress("UNUSED_PARAMETER") context: Context): LockdownController =
        FakeLockdownController(scope = scope)
}
