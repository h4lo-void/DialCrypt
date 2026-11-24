package io.github.h4lovoid.dialcrypt.core

import android.content.Context
import android.os.UserManager

/**
 * Before the first unlock after boot only the in-call service, the in-call screen and the call
 * notification actions of `:call` run (they are `directBootAware`). Credential-encrypted storage,
 * where every file of the app lives, cannot be read then. Code those components reach asks
 * [isUserUnlocked] first and uses a default that needs no file.
 */
object DirectBoot {
    /** False before the first unlock after boot, and whenever the answer is not available. */
    fun isUserUnlocked(context: Context): Boolean =
        runCatching { context.getSystemService(UserManager::class.java)?.isUserUnlocked }.getOrNull() ?: false
}
