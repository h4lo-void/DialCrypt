package io.github.h4lovoid.dialcrypt.core

import io.github.h4lovoid.dialcrypt.incoming.screen.IncomingMode
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

class InMemoryUiPreferences(
    initial: AppLanguage = AppLanguage.EN,
    initialIncoming: IncomingMode = IncomingMode.CONTACTS,
    initialShowFullNumbers: Boolean = false,
    initialModemMode: ModemMode = ModemMode.WIDEBAND,
    initialRequireLockedBootloader: Boolean = false,
) : UiPreferences {
    private val flow = MutableStateFlow(initial)
    private val incomingFlow = MutableStateFlow(initialIncoming)
    private val fullNumbersFlow = MutableStateFlow(initialShowFullNumbers)
    private val modemFlow = MutableStateFlow(initialModemMode)
    private val lockedBootFlow = MutableStateFlow(initialRequireLockedBootloader)
    override val language: StateFlow<AppLanguage> = flow
    override val incomingMode: StateFlow<IncomingMode> = incomingFlow
    override val showFullNumbers: StateFlow<Boolean> = fullNumbersFlow
    override val modemMode: StateFlow<ModemMode> = modemFlow
    override val requireLockedBootloader: StateFlow<Boolean> = lockedBootFlow
    override fun setLanguage(language: AppLanguage) { flow.value = language }
    override fun setIncomingMode(mode: IncomingMode) { incomingFlow.value = mode }
    override fun setShowFullNumbers(show: Boolean) { fullNumbersFlow.value = show }
    override fun setModemMode(mode: ModemMode) { modemFlow.value = mode }
    override fun setRequireLockedBootloader(require: Boolean) { lockedBootFlow.value = require }
}
