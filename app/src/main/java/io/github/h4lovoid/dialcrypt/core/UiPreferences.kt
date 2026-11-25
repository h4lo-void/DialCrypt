package io.github.h4lovoid.dialcrypt.core

import io.github.h4lovoid.dialcrypt.incoming.screen.IncomingMode
import kotlinx.coroutines.flow.StateFlow

enum class AppLanguage(val tag: String?) {
    SYSTEM(null), EN("en"), ES("es"), FR("fr"), ZH_HANS("zh-Hans"),
}

/** User-selectable voice-band modem gear (`wireCode` matches `ModemGear` 1..4). */
enum class ModemMode(val wireCode: Int) {
    WIDEBAND(2),
    NARROWBAND(1),
    ROBUST_300(3),
    SPEECH_300(4),
    ;

    companion object {
        fun fromName(name: String?): ModemMode = values().firstOrNull { it.name == name } ?: WIDEBAND
    }
}

/** Non-secret display & link preferences (readable before unlock). */
interface UiPreferences {
    val language: StateFlow<AppLanguage>
    val incomingMode: StateFlow<IncomingMode>
    /**
     * When true, contact numbers show whole instead of only the last four digits while the screen is
     * unlocked. Numbers that are not contacts always show whole. Off by default.
     */
    val showFullNumbers: StateFlow<Boolean>
    /** Preferred voice-band modem gear announced during call setup. */
    val modemMode: StateFlow<ModemMode>
        get() = kotlinx.coroutines.flow.MutableStateFlow(ModemMode.WIDEBAND)
    fun setLanguage(language: AppLanguage)
    fun setIncomingMode(mode: IncomingMode)
    fun setShowFullNumbers(show: Boolean)
    fun setModemMode(mode: ModemMode) {}
}
