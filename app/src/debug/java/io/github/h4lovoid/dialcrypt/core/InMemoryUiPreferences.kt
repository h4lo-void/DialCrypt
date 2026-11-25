package io.github.h4lovoid.dialcrypt.core

import io.github.h4lovoid.dialcrypt.incoming.screen.IncomingMode
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

class InMemoryUiPreferences(
    initial: AppLanguage = AppLanguage.EN,
    initialIncoming: IncomingMode = IncomingMode.CONTACTS,
    initialShowFullNumbers: Boolean = false,
    initialModemMode: ModemMode = ModemMode.WIDEBAND,
) : UiPreferences {
    private val flow = MutableStateFlow(initial)
    private val incomingFlow = MutableStateFlow(initialIncoming)
    private val fullNumbersFlow = MutableStateFlow(initialShowFullNumbers)
    private val modemFlow = MutableStateFlow(initialModemMode)
    override val language: StateFlow<AppLanguage> = flow
    override val incomingMode: StateFlow<IncomingMode> = incomingFlow
    override val showFullNumbers: StateFlow<Boolean> = fullNumbersFlow
    override val modemMode: StateFlow<ModemMode> = modemFlow
    override fun setLanguage(language: AppLanguage) { flow.value = language }
    override fun setIncomingMode(mode: IncomingMode) { incomingFlow.value = mode }
    override fun setShowFullNumbers(show: Boolean) { fullNumbersFlow.value = show }
    override fun setModemMode(mode: ModemMode) { modemFlow.value = mode }
}
