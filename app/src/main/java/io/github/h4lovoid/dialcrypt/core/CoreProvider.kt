package io.github.h4lovoid.dialcrypt.core

import android.content.Context
import android.content.SharedPreferences
import android.telephony.TelephonyManager
import io.github.h4lovoid.dialcrypt.incoming.screen.DisplaySettings
import io.github.h4lovoid.dialcrypt.incoming.screen.IncomingMode
import io.github.h4lovoid.dialcrypt.incoming.screen.IncomingSettings
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/** Stored in the app's no-backup area; holds only non-secret display & incoming preferences. */
class SharedPrefsUiPreferences(
    private val prefs: SharedPreferences,
    private val appContext: Context? = null,
) : UiPreferences {
    private val flow = MutableStateFlow(
        AppLanguage.values().firstOrNull { it.name == prefs.getString(KEY, null) } ?: AppLanguage.SYSTEM,
    )
    private val incomingFlow = MutableStateFlow(
        appContext?.let { IncomingSettings.read(it) } ?: IncomingMode.CONTACTS,
    )
    override val language: StateFlow<AppLanguage> = flow
    override val incomingMode: StateFlow<IncomingMode> = incomingFlow
    private val fullNumbersFlow = MutableStateFlow(prefs.getBoolean(KEY_FULL_NUMBERS, false))
    override val showFullNumbers: StateFlow<Boolean> = fullNumbersFlow

    init {
        // A preference saved before the mirror existed is copied once, so `:call` sees the same choice.
        appContext?.let { ctx ->
            val show = fullNumbersFlow.value
            if (!DisplaySettings.file(ctx).exists() || DisplaySettings.read(ctx) != show) DisplaySettings.write(ctx, show)
        }
    }

    override fun setShowFullNumbers(show: Boolean) {
        prefs.edit().putBoolean(KEY_FULL_NUMBERS, show).apply()
        appContext?.let { DisplaySettings.write(it, show) }
        fullNumbersFlow.value = show
    }

    override fun setLanguage(language: AppLanguage) {
        prefs.edit().putString(KEY, language.name).apply()
        flow.value = language
    }

    override fun setIncomingMode(mode: IncomingMode) {
        appContext?.let { IncomingSettings.write(it, mode) }
        incomingFlow.value = mode
    }

    private companion object {
        const val KEY = "language"
        const val KEY_FULL_NUMBERS = "show_full_numbers"
    }
}

/**
 * Per-process holder. Each process (launcher, secure) builds its own instances through
 * [DefaultCores], which is provided separately by the debug and release source sets.
 */
object CoreProvider {
    private var core: SecureCore? = null
    private var lockdown: LockdownController? = null
    private var prefs: UiPreferences? = null

    /**
     * Sets [PhoneRules.defaultCountryCode] from the SIM card's country. Needs no permission; it is
     * retried on later calls while the SIM country is still unknown and left alone once it is set.
     */
    @Synchronized
    fun initPhoneRules(context: Context) {
        if (PhoneRules.defaultCountryCode != null) return
        val telephony = context.applicationContext?.getSystemService(TelephonyManager::class.java) ?: return
        PhoneRules.defaultCountryCode = CountryCallingCodes.forIso(telephony.simCountryIso)
    }

    @Synchronized
    fun secureCore(context: Context): SecureCore =
        core ?: run {
            initPhoneRules(context)
            DefaultCores.secureCore(context.applicationContext)
        }.also { core = it }

    @Synchronized
    fun lockdown(context: Context): LockdownController {
        initPhoneRules(context)
        return lockdown ?: DefaultCores.lockdown(context.applicationContext).also { lockdown = it }
    }

    @Synchronized
    fun preferences(context: Context): UiPreferences {
        val app = context.applicationContext ?: context
        initPhoneRules(app)
        return prefs ?: SharedPrefsUiPreferences(
            app.getSharedPreferences("ui_prefs", Context.MODE_PRIVATE),
            app,
        ).also { prefs = it }
    }
}
