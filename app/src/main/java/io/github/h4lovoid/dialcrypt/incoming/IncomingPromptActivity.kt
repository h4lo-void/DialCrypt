package io.github.h4lovoid.dialcrypt.incoming

import android.app.KeyguardManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.OnBackPressedCallback
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Call
import androidx.compose.material.icons.filled.CallEnd
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Phone
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.produceState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import io.github.h4lovoid.dialcrypt.R
import io.github.h4lovoid.dialcrypt.call.CallPhase
import io.github.h4lovoid.dialcrypt.core.ContactMembership
import io.github.h4lovoid.dialcrypt.core.NumberPresentation
import io.github.h4lovoid.dialcrypt.core.NumberVisibility
import io.github.h4lovoid.dialcrypt.incoming.screen.ContactNumberIndex
import io.github.h4lovoid.dialcrypt.incoming.screen.DisplaySettings
import io.github.h4lovoid.dialcrypt.ui.LauncherActivity
import io.github.h4lovoid.dialcrypt.ui.SecureWindow
import io.github.h4lovoid.dialcrypt.ui.components.Card
import io.github.h4lovoid.dialcrypt.ui.components.PrimaryButton
import io.github.h4lovoid.dialcrypt.ui.components.ScreenPadding
import io.github.h4lovoid.dialcrypt.ui.components.SecondaryButton
import io.github.h4lovoid.dialcrypt.ui.theme.DialCryptTheme
import io.github.h4lovoid.dialcrypt.ui.theme.Palette
import io.github.h4lovoid.dialcrypt.ui.theme.Space
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.withContext

/**
 * Full-screen incoming call prompt running in `:call` when `:secure` is closed or locked.
 * Displays the caller number by [NumberVisibility] (a stranger's number whole, a contact's number
 * masked over the lock screen) or a hidden-number notice, and routes either to
 * secure PIN handoff via [LauncherActivity], plain unencrypted answer in Telecom, or decline
 * (also over the lock screen, as any phone allows).
 */
class IncomingPromptActivity : ComponentActivity() {
    private val gate = PromptGate()
    private lateinit var frontKeeper: FrontKeeper
    private lateinit var handoff: SecureHandoff
    private val locked = MutableStateFlow(true)
    private val numberIndex by lazy { ContactNumberIndex(applicationContext) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        SecureWindow.apply(this)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O_MR1) {
            setShowWhenLocked(true)
            setTurnScreenOn(true)
        }
        frontKeeper = FrontKeeper(
            activity = this,
            shouldHold = { !gate.handoffStarted && CallRegistry.offers.value != null },
        )
        handoff = SecureHandoff(
            activity = this,
            gate = gate,
            cancelNotices = { IncomingCallService.cancelPromptNotification(applicationContext) },
            onAbandoned = ::onUnlockAbandoned,
        )
        // Back must not dismiss a ringing call's prompt: the user has to answer or decline.
        // The prompt closes itself once the call stops ringing.
        onBackPressedDispatcher.addCallback(
            this,
            object : OnBackPressedCallback(true) {
                override fun handleOnBackPressed() = Unit
            },
        )

        setContent {
            DialCryptTheme {
                val view = LocalView.current
                SideEffect { view.filterTouchesWhenObscured = true }

                val offer by CallRegistry.offers.collectAsState()
                val status by CallRegistry.status.collectAsState()
                val isLocked by locked.collectAsState()

                LaunchedEffect(offer, status.phase) {
                    closeIfCallGone()
                }

                val current = offer
                val shownNumber = current?.takeIf { it.presentation == NumberPresentation.SHOWN }?.number?.takeIf { it.isNotBlank() }
                // The index and the setting are files and a Keystore key: read off the main thread, masked until then.
                val numberView by produceState(PromptNumberView(), shownNumber) {
                    value = PromptNumberView()
                    if (shownNumber != null) {
                        value = withContext(Dispatchers.IO) {
                            PromptNumberView(
                                runCatching { numberIndex.lookup(shownNumber) }.getOrDefault(ContactMembership.UNKNOWN),
                                DisplaySettings.read(applicationContext),
                            )
                        }
                    }
                }
                Surface(modifier = Modifier.fillMaxSize(), color = Palette.Background) {
                    if (current != null) {
                        // This screen also shows over the lock screen, where a contact's number never shows whole.
                        val displayNumber = NumberVisibility.text(shownNumber, numberView.membership, numberView.showFullContacts, isLocked)
                            ?: stringResource(R.string.number_hidden)

                        Box(
                            modifier = Modifier
                                .fillMaxSize()
                                .padding(horizontal = ScreenPadding, vertical = Space.xl),
                            contentAlignment = Alignment.Center,
                        ) {
                            Column(
                                modifier = Modifier.fillMaxWidth(),
                                verticalArrangement = Arrangement.spacedBy(Space.xl),
                                horizontalAlignment = Alignment.CenterHorizontally,
                            ) {
                                Icon(
                                    imageVector = Icons.Filled.Call,
                                    contentDescription = null,
                                    tint = Palette.Accent,
                                    modifier = Modifier.size(56.dp),
                                )
                                Column(
                                    verticalArrangement = Arrangement.spacedBy(Space.sm),
                                    horizontalAlignment = Alignment.CenterHorizontally,
                                ) {
                                    Text(
                                        text = stringResource(R.string.incoming_prompt_title),
                                        style = MaterialTheme.typography.titleMedium,
                                        color = Palette.OnSurfaceMuted,
                                    )
                                    Text(
                                        text = displayNumber,
                                        style = MaterialTheme.typography.headlineMedium,
                                        textAlign = TextAlign.Center,
                                    )
                                    Text(
                                        text = stringResource(R.string.incoming_prompt_subtitle),
                                        style = MaterialTheme.typography.bodyMedium,
                                        color = Palette.OnSurfaceMuted,
                                        textAlign = TextAlign.Center,
                                    )
                                }
                                Card {
                                    Column(verticalArrangement = Arrangement.spacedBy(Space.md)) {
                                        PrimaryButton(
                                            text = stringResource(R.string.incoming_answer_secure),
                                            enabled = !gate.busy,
                                            icon = Icons.Filled.Lock,
                                            onClick = {
                                                if (!gate.tryBegin()) return@PrimaryButton
                                                frontKeeper.markUserLeft()
                                                handoff.start(current.token)
                                            },
                                        )
                                        SecondaryButton(
                                            text = stringResource(R.string.incoming_answer_plain),
                                            enabled = !gate.busy,
                                            icon = Icons.Filled.Phone,
                                            onClick = {
                                                if (!gate.tryBegin()) return@SecondaryButton
                                                frontKeeper.markUserLeft()
                                                CallRegistry.answerPlain(current.token)
                                                finishAndRemoveTask()
                                            },
                                        )
                                        SecondaryButton(
                                            text = stringResource(R.string.incoming_decline),
                                            enabled = !gate.busy,
                                            icon = Icons.Filled.CallEnd,
                                            danger = true,
                                            onClick = {
                                                if (!gate.tryBegin()) return@SecondaryButton
                                                frontKeeper.markUserLeft()
                                                CallRegistry.declineOffered(current.token)
                                                IncomingCallService.cancelPromptNotification(applicationContext)
                                                finishAndRemoveTask()
                                            },
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        refreshLocked()
        if (!hasFocus && !gate.handoffStarted) {
            frontKeeper.onCovered()
        }
    }

    override fun onResume() {
        super.onResume()
        refreshLocked()
    }

    private fun refreshLocked() {
        locked.value = getSystemService(KeyguardManager::class.java)?.isKeyguardLocked ?: true
    }

    /** Closes the prompt when the call is no longer ringing, unless an answer is being handed over. */
    private fun closeIfCallGone() {
        val phase = CallRegistry.status.value.phase
        val gone = CallRegistry.offers.value == null || phase == CallPhase.ENDED || phase == CallPhase.IDLE
        if (gone && !gate.handoffStarted) {
            IncomingCallService.cancelPromptNotification(applicationContext)
            finishAndRemoveTask()
        }
    }

    /**
     * The unlock was cancelled or failed ([handoff] already gave both answers back): restore the
     * prompt notification removed when the handoff began, or close if the call ended meanwhile.
     */
    private fun onUnlockAbandoned() {
        frontKeeper.resetUserLeft()
        closeIfCallGone()
        if (!isFinishing) {
            CallRegistry.offers.value?.let { IncomingCallService.postPromptNotification(applicationContext, it) }
        }
    }
}

private data class PromptNumberView(
    val membership: ContactMembership = ContactMembership.UNKNOWN,
    val showFullContacts: Boolean = false,
)
