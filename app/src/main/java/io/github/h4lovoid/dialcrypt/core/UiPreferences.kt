package io.github.h4lovoid.dialcrypt.core

import io.github.h4lovoid.dialcrypt.incoming.screen.IncomingMode
import kotlinx.coroutines.flow.StateFlow

enum class AppLanguage(val tag: String?) {
    SYSTEM(null), EN("en"), ES("es"), FR("fr"), ZH_HANS("zh-Hans"),
}

/** Non-secret display preferences (readable before unlock). */
interface UiPreferences {
    val language: StateFlow<AppLanguage>
    val incomingMode: StateFlow<IncomingMode>
    /**
     * When true, contact numbers show whole instead of only the last four digits while the screen is
     * unlocked. Numbers that are not contacts always show whole. Off by default.
     */
    val showFullNumbers: StateFlow<Boolean>
    fun setLanguage(language: AppLanguage)
    fun setIncomingMode(mode: IncomingMode)
    fun setShowFullNumbers(show: Boolean)
}
