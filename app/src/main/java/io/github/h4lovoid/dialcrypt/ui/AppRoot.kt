package io.github.h4lovoid.dialcrypt.ui

import android.Manifest
import android.content.pm.PackageManager
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Call
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Phone
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import io.github.h4lovoid.dialcrypt.BuildConfig
import io.github.h4lovoid.dialcrypt.R
import io.github.h4lovoid.dialcrypt.core.Contact
import io.github.h4lovoid.dialcrypt.core.ContactMembership
import io.github.h4lovoid.dialcrypt.core.ContactResult
import io.github.h4lovoid.dialcrypt.core.CoreAvailability
import io.github.h4lovoid.dialcrypt.core.CoreState
import io.github.h4lovoid.dialcrypt.core.IncomingUi
import io.github.h4lovoid.dialcrypt.core.LockdownController
import io.github.h4lovoid.dialcrypt.core.LockdownPhase
import io.github.h4lovoid.dialcrypt.core.NumberPresentation
import io.github.h4lovoid.dialcrypt.core.SecureCore
import io.github.h4lovoid.dialcrypt.core.SessionPhase
import io.github.h4lovoid.dialcrypt.core.SessionState
import io.github.h4lovoid.dialcrypt.core.UiPreferences
import io.github.h4lovoid.dialcrypt.dialer.DialerRole
import io.github.h4lovoid.dialcrypt.ui.components.Card
import io.github.h4lovoid.dialcrypt.ui.components.PrimaryButton
import io.github.h4lovoid.dialcrypt.ui.components.ScreenEnter
import io.github.h4lovoid.dialcrypt.ui.components.ScreenEnterMillis
import io.github.h4lovoid.dialcrypt.ui.components.ScreenExitMillis
import io.github.h4lovoid.dialcrypt.ui.components.ScreenPadding
import io.github.h4lovoid.dialcrypt.ui.components.SecondaryButton
import io.github.h4lovoid.dialcrypt.ui.components.rememberMotionEnabled
import io.github.h4lovoid.dialcrypt.ui.keyboard.InputHost
import io.github.h4lovoid.dialcrypt.ui.keyboard.KeyboardScaffold
import io.github.h4lovoid.dialcrypt.ui.keyboard.LocalInputHost
import io.github.h4lovoid.dialcrypt.ui.model.LocalContactLookup
import io.github.h4lovoid.dialcrypt.ui.model.LocalShowFullNumbers
import io.github.h4lovoid.dialcrypt.ui.model.SessionScreen
import io.github.h4lovoid.dialcrypt.ui.model.SessionUi
import io.github.h4lovoid.dialcrypt.ui.screens.AboutScreen
import io.github.h4lovoid.dialcrypt.ui.screens.AbortedScreen
import io.github.h4lovoid.dialcrypt.ui.screens.AddContactScreen
import io.github.h4lovoid.dialcrypt.ui.screens.BiometricSettings
import io.github.h4lovoid.dialcrypt.ui.screens.ChatScreen
import io.github.h4lovoid.dialcrypt.ui.screens.ConnectingScreen
import io.github.h4lovoid.dialcrypt.ui.screens.ContactDetailScreen
import io.github.h4lovoid.dialcrypt.ui.screens.ContactFormScreen
import io.github.h4lovoid.dialcrypt.ui.screens.DialScreen
import io.github.h4lovoid.dialcrypt.ui.screens.EndingScreen
import io.github.h4lovoid.dialcrypt.ui.screens.HomeScreen
import io.github.h4lovoid.dialcrypt.ui.screens.KeyChangedScreen
import io.github.h4lovoid.dialcrypt.ui.screens.NotConnectedScreen
import io.github.h4lovoid.dialcrypt.ui.screens.PinMode
import io.github.h4lovoid.dialcrypt.ui.screens.PhoneAppSettings
import io.github.h4lovoid.dialcrypt.ui.screens.PinWizardScreen
import io.github.h4lovoid.dialcrypt.ui.screens.PreparationScreen
import io.github.h4lovoid.dialcrypt.ui.screens.SasScreen
import io.github.h4lovoid.dialcrypt.ui.screens.SaveNeedsPinScreen
import io.github.h4lovoid.dialcrypt.ui.screens.SettingsScreen
import io.github.h4lovoid.dialcrypt.ui.screens.StartScreen
import io.github.h4lovoid.dialcrypt.ui.screens.UnlockScreen
import io.github.h4lovoid.dialcrypt.ui.screens.VaultDestroyedScreen
import io.github.h4lovoid.dialcrypt.ui.theme.DialCryptTheme
import io.github.h4lovoid.dialcrypt.ui.theme.Palette
import io.github.h4lovoid.dialcrypt.ui.theme.Space
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

private sealed interface Route {
    data object Home : Route
    data object Dial : Route
    data object AddContact : Route
    data object Settings : Route
    data object ChangePin : Route
    data object About : Route
    data class ContactDetail(val id: Long) : Route
    data class ContactEdit(val id: Long) : Route
}

/** What kind of screen is showing. Only [ScreenKind.ROUTE] screens slide in the direction of travel. */
private enum class ScreenKind { EXITING, ATTACHING, INCOMING, NOT_CONNECTED, DESTROYED, TEST_OPENING, PIN_SETUP, UNLOCK, SESSION, ROUTE }

/**
 * The screen to draw. [key] identifies it; [route] and [depth] (the size of the back stack) matter for
 * route screens only; [session] is the call screen of a session screen.
 */
private data class Destination(
    val key: String,
    val kind: ScreenKind,
    val route: Route = Route.Home,
    val depth: Int = 1,
    val session: SessionScreen? = null,
)

/**
 * First process: a neutral start screen, then the checks and hardening, then the secure process.
 * Only the user's tap on Start asks the helper to prepare; a call handoff that the app started
 * itself ([fastHandoff]) has already done so and skips the start screen.
 */
@Composable
fun LauncherRoot(
    lockdown: LockdownController,
    prefs: UiPreferences,
    onReady: () -> Unit,
    fastHandoff: Boolean = false,
) {
    val language by prefs.language.collectAsState()
    val state by lockdown.state.collectAsState()
    var started by remember { mutableStateOf(fastHandoff) }
    val showStart = !started && state.phase == LockdownPhase.IDLE
    LaunchedEffect(state.phase, fastHandoff) {
        if (state.phase == LockdownPhase.READY) {
            if (!fastHandoff) delay(1200)
            onReady()
        }
    }
    ProvideAppLanguage(language) {
        DialCryptTheme {
            Box(Modifier.fillMaxSize().background(Palette.Background).safeDrawingPadding()) {
                // The system must not end this activity while the checks run; only a dead end may be left with back.
                // On the start screen nothing has been applied yet, so back simply leaves.
                BackHandler(enabled = !showStart && state.phase != LockdownPhase.NOT_CONNECTED) {}
                if (showStart) {
                    ScreenEnter("start") {
                        StartScreen(onStart = {
                            if (!started) {
                                started = true
                                lockdown.prepare()
                            }
                        })
                    }
                } else {
                    ScreenEnter("preparation") {
                        PreparationScreen(state, onRetry = { lockdown.prepare() }, onContinue = onReady)
                    }
                }
            }
        }
    }
}

/**
 * Second process: PIN, contacts, calls, settings. Depends only on the core interfaces.
 * [contactLookup] answers whether a caller's number is a contact; without it every such number shows masked.
 */
@Composable
fun AppRoot(
    core: SecureCore,
    lockdown: LockdownController,
    prefs: UiPreferences,
    onExit: () -> Unit,
    attachReady: Boolean = true,
    exiting: Boolean = false,
    contactLookup: (String) -> ContactMembership = { ContactMembership.UNKNOWN },
) {
    val language by prefs.language.collectAsState()
    val showFullNumbers by prefs.showFullNumbers.collectAsState()
    val coreState by core.state.collectAsState()
    val contacts by core.contacts.collectAsState()
    val session by core.session.collectAsState()
    val incoming by core.incoming.collectAsState()
    val host = remember { InputHost() }
    val red = session.phase == SessionPhase.KEY_CHANGED

    ProvideAppLanguage(language) {
        DialCryptTheme {
            CompositionLocalProvider(
                LocalInputHost provides host,
                LocalShowFullNumbers provides showFullNumbers,
                LocalContactLookup provides contactLookup,
            ) {
                Box(Modifier.fillMaxSize().background(if (red) Palette.DangerBackground else Palette.Background).safeDrawingPadding()) {
                    KeyboardScaffold(host) {
                        AppContent(core, lockdown, prefs, coreState, contacts, session, incoming, host, attachReady, exiting, onExit)
                    }
                }
            }
        }
    }
}

@Composable
private fun AppContent(
    core: SecureCore,
    lockdown: LockdownController,
    prefs: UiPreferences,
    coreState: CoreState,
    contacts: List<Contact>,
    session: SessionState,
    incoming: IncomingUi?,
    host: InputHost,
    attachReady: Boolean,
    exiting: Boolean,
    onExit: () -> Unit,
) {
    val scope = rememberCoroutineScope()
    val stack = remember { mutableStateListOf<Route>(Route.Home) }
    var pinChanged by remember { mutableStateOf(false) }
    // Test builds without a PIN: one automatic setup or unlock per process; a failure shows the normal screens.
    var testOpenFailed by remember { mutableStateOf(false) }
    val testOpening = io.github.h4lovoid.dialcrypt.BuildConfig.TEST_NO_PIN && !testOpenFailed && io.github.h4lovoid.dialcrypt.core.TestNoPin.needed(coreState)
    LaunchedEffect(testOpening, coreState.pinConfigured, coreState.locked) {
        if (testOpening && !io.github.h4lovoid.dialcrypt.core.TestNoPin.open(core, coreState)) testOpenFailed = true
    }
    val route = stack.last()
    val sessionScreen = SessionUi.screenFor(session)
    val inAppIncoming = incoming != null && !incoming.handoff && sessionScreen == null
    val bioState by core.biometric.collectAsState()
    var bioFailed by remember { mutableStateOf(false) }
    val context = LocalContext.current
    val enrollTitle = stringResource(R.string.bio_prompt_enroll_title)
    val enrollCancel = stringResource(R.string.action_cancel)
    // Turning fingerprint answer on: after the PIN unlock, a fingerprint confirms the new key once.
    LaunchedEffect(coreState.locked, coreState.bioEnrollPending) {
        if (coreState.locked || !coreState.bioEnrollPending) return@LaunchedEffect
        val cipher = core.biometricEnrollCipher()
        if (cipher == null) {
            bioFailed = true
            return@LaunchedEffect
        }
        val shown = BiometricLauncher.authenticate(
            context, enrollTitle, enrollCancel, cipher, android.os.CancellationSignal(),
            onSuccess = { authed -> scope.launch { bioFailed = !core.finishBiometricEnable(authed) } },
            onError = { code ->
                core.cancelBiometricEnable()
                bioFailed = code != BiometricLauncher.ERROR_DISMISSED &&
                    code != android.hardware.biometrics.BiometricPrompt.BIOMETRIC_ERROR_USER_CANCELED
            },
        )
        if (!shown) {
            core.cancelBiometricEnable()
            bioFailed = true
        }
    }

    val kind = when {
        exiting -> ScreenKind.EXITING
        !attachReady -> ScreenKind.ATTACHING
        inAppIncoming -> ScreenKind.INCOMING
        coreState.availability == CoreAvailability.NOT_CONNECTED -> ScreenKind.NOT_CONNECTED
        coreState.vaultDestroyed -> ScreenKind.DESTROYED
        testOpening -> ScreenKind.TEST_OPENING
        !coreState.pinConfigured -> ScreenKind.PIN_SETUP
        // A fingerprint unlock covers one call: outside its call screens only the PIN opens the app.
        coreState.locked || (coreState.callScoped && sessionScreen == null) -> ScreenKind.UNLOCK
        sessionScreen != null -> ScreenKind.SESSION
        else -> ScreenKind.ROUTE
    }
    // Whatever owns the keyboard is gone whenever the visible screen changes.
    val screenKey = when (kind) {
        ScreenKind.EXITING -> "exiting"
        ScreenKind.ATTACHING -> "attaching"
        ScreenKind.INCOMING -> "incoming"
        ScreenKind.NOT_CONNECTED -> "not-connected"
        ScreenKind.DESTROYED -> "destroyed"
        ScreenKind.TEST_OPENING -> "test-opening"
        ScreenKind.PIN_SETUP -> "pin-setup"
        ScreenKind.UNLOCK -> "unlock"
        ScreenKind.SESSION -> "session-" + sessionScreen?.name + SessionUi.showSaveOffer(session)
        ScreenKind.ROUTE -> route.toString()
    }
    val dest = Destination(
        key = screenKey,
        kind = kind,
        route = if (kind == ScreenKind.ROUTE) route else Route.Home,
        depth = if (kind == ScreenKind.ROUTE) stack.size else 1,
        session = if (kind == ScreenKind.SESSION) sessionScreen else null,
    )
    DisposableEffect(screenKey) {
        onDispose {
            host.onDone = null
            host.blur()
        }
    }

    LaunchedEffect(sessionScreen == null) {
        if (sessionScreen != null) { stack.clear(); stack.add(Route.Home) }
    }
    fun pop() { if (stack.size > 1) stack.removeAt(stack.lastIndex) }

    // The one handler that is always on, so the system never ends the activity by itself. A screen with a
    // confirmation or a panel of its own registers a handler later, and that one runs first.
    BackHandler(enabled = true) {
        when {
            host.active != null -> host.blur()
            kind == ScreenKind.EXITING || kind == ScreenKind.ATTACHING || kind == ScreenKind.INCOMING ||
                kind == ScreenKind.DESTROYED || kind == ScreenKind.TEST_OPENING || kind == ScreenKind.SESSION -> Unit
            kind == ScreenKind.ROUTE && stack.size > 1 -> pop()
            // Home, unlock, the first step of the PIN setup and the not-connected notice leave through the safe exit.
            else -> onExit()
        }
    }

    val lockdownState by lockdown.state.collectAsState()

    // Route changes slide in the direction of travel; every other change of screen fades in.
    ScreenHost(dest) { d ->
        when (d.kind) {
            ScreenKind.EXITING -> BusyStatusScreen(stringResource(R.string.exiting_securely))
            ScreenKind.ATTACHING, ScreenKind.TEST_OPENING -> BusyStatusScreen(stringResource(R.string.prep_working))
            ScreenKind.INCOMING -> incoming?.let {
                IncomingInAppScreen(
                    incoming = it,
                    onSecure = { core.decideIncoming(true) },
                    onPlain = { core.decideIncoming(false) },
                )
            }
            ScreenKind.NOT_CONNECTED -> NotConnectedScreen()
            ScreenKind.DESTROYED -> VaultDestroyedScreen(onClose = onExit)
            ScreenKind.PIN_SETUP -> PinWizardScreen(PinMode.SETUP, core, onFinished = {}, onBack = null)
            ScreenKind.UNLOCK -> UnlockScreen(core, coreState, onDuress = onExit, handoffActive = incoming?.handoff == true)
            ScreenKind.SESSION -> d.session?.let { SessionHost(session, it, core, onExit, coreState.callScoped) }
            ScreenKind.ROUTE -> when (val r = d.route) {
                Route.Home -> HomeScreen(
                    contacts,
                    onOpenContact = { stack.add(Route.ContactDetail(it)) },
                    onStartCall = { stack.add(Route.Dial) },
                    onSettings = { pinChanged = false; stack.add(Route.Settings) },
                    lockdown = lockdownState,
                    onAddContact = { stack.add(Route.AddContact) },
                    onExit = onExit,
                )
                Route.Dial -> DialScreen(
                    contacts,
                    onCallContact = { core.startCallToContact(it) },
                    onCallNumber = { core.startCallToNumber(it) },
                    onBack = ::pop,
                )
                Route.AddContact -> AddContactScreen(
                    core = core,
                    onBack = ::pop,
                    onAdded = ::pop,
                )
                is Route.ContactDetail -> {
                    val c = contacts.firstOrNull { it.id == r.id }
                    // A screen still fading out after its contact is gone must not pop a second time.
                    LaunchedEffect(c == null) { if (c == null && stack.lastOrNull() == r) pop() }
                    c?.let { contact ->
                        ContactDetailScreen(
                            contact, core, onBack = ::pop,
                            onEdit = { stack.add(Route.ContactEdit(contact.id)) },
                            onCall = { core.startCallToContact(contact.id) },
                            onDeleted = ::pop,
                        )
                    }
                }
                is Route.ContactEdit -> {
                    val c = contacts.firstOrNull { it.id == r.id }
                    LaunchedEffect(c == null) { if (c == null && stack.lastOrNull() == r) pop() }
                    c?.let { contact ->
                        ContactFormScreen(
                            title = stringResource(R.string.edit_title),
                            body = stringResource(R.string.edit_body),
                            initialName = contact.name,
                            initialNumber = contact.number,
                            numberMayBeEmpty = true,
                            confirmLabel = stringResource(R.string.action_save),
                            cancelLabel = stringResource(R.string.action_cancel),
                            onSubmit = { name, number ->
                                val result = core.updateContact(contact.id, name, number)
                                if (result == ContactResult.OK) pop()
                                result
                            },
                            onCancel = ::pop,
                        )
                    }
                }
                Route.Settings -> {
                    val language by prefs.language.collectAsState()
                    val incomingMode by prefs.incomingMode.collectAsState()
                    val showFullNumbers by prefs.showFullNumbers.collectAsState()
                    val modemMode by prefs.modemMode.collectAsState()
                    val phoneApp = if (BuildConfig.DIALER_ROLE_UI) rememberPhoneAppSettings() else null
                    SettingsScreen(
                        language = language,
                        onLanguage = prefs::setLanguage,
                        lockdown = lockdownState,
                        pinChanged = pinChanged,
                        onBack = ::pop,
                        onChangePin = { stack.add(Route.ChangePin) },
                        onAbout = { stack.add(Route.About) },
                        onWipeConfirmed = { scope.launch { core.wipeAll(); onExit() } },
                        incomingMode = incomingMode,
                        onIncomingMode = prefs::setIncomingMode,
                        showFullNumbers = showFullNumbers,
                        onShowFullNumbers = prefs::setShowFullNumbers,
                        modemMode = modemMode,
                        onModemMode = prefs::setModemMode,
                        phoneApp = phoneApp,
                        onExit = onExit,
                        biometric = BiometricSettings(
                            state = bioState,
                            hasFingerprint = remember(bioState) { BiometricLauncher.hasStrongFingerprint(context) },
                            failed = bioFailed,
                            onTurnOn = {
                                bioFailed = false
                                scope.launch { if (!core.beginBiometricEnable()) bioFailed = true }
                            },
                            onTurnOff = {
                                bioFailed = false
                                scope.launch { core.disableBiometric() }
                            },
                        ),
                    )
                }
                Route.ChangePin -> PinWizardScreen(PinMode.CHANGE, core, onFinished = { pinChanged = true; pop() }, onBack = ::pop, onDuress = onExit)
                Route.About -> AboutScreen(onBack = ::pop)
            }
        }
    }
}

@Composable
private fun ScreenHost(dest: Destination, content: @Composable (Destination) -> Unit) {
    if (dest.kind != ScreenKind.ROUTE) {
        ScreenEnter(dest.key) { content(dest) }
    } else {
        // Arriving in the route area (after unlock or a call) fades in once; moves inside it slide.
        ScreenEnter(ScreenKind.ROUTE) {
            if (rememberMotionEnabled()) {
                AnimatedContent(
                    targetState = dest,
                    modifier = Modifier.fillMaxSize(),
                    transitionSpec = {
                        // Forward: the new screen comes in from the right; back: from the left. The old one fades out.
                        val sign = if (targetState.depth >= initialState.depth) 1 else -1
                        val enter = fadeIn(tween(ScreenEnterMillis, easing = FastOutSlowInEasing)) +
                            slideInHorizontally(tween(ScreenEnterMillis, easing = FastOutSlowInEasing)) { full -> sign * full / 10 }
                        enter togetherWith fadeOut(tween(ScreenExitMillis, easing = FastOutSlowInEasing))
                    },
                    label = "screen",
                ) { d -> content(d) }
            } else {
                key(dest.key) { Box(Modifier.fillMaxSize()) { content(dest) } }
            }
        }
    }
}

@Composable
private fun BusyStatusScreen(label: String) {
    // Nothing can be done here, so the back key does nothing either.
    BackHandler {}
    Box(Modifier.fillMaxSize().padding(ScreenPadding), contentAlignment = Alignment.Center) {
        Column(horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(Space.lg)) {
            CircularProgressIndicator(color = Palette.Accent)
            Text(label, style = MaterialTheme.typography.bodyLarge, color = Palette.OnSurfaceMuted, textAlign = TextAlign.Center)
        }
    }
}

@Composable
private fun IncomingInAppScreen(
    incoming: IncomingUi,
    onSecure: () -> Unit,
    onPlain: () -> Unit,
) {
    val view = LocalView.current
    // Answering is always a deliberate tap; the back key does nothing.
    BackHandler {}
    SideEffect { view.filterTouchesWhenObscured = true }
    val shownNumber = if (incoming.presentation == NumberPresentation.SHOWN) {
        io.github.h4lovoid.dialcrypt.ui.model.callerNumber(incoming.number)
    } else {
        null
    }
    val displayNumber = shownNumber ?: stringResource(R.string.number_hidden)
    Box(Modifier.fillMaxSize().padding(horizontal = ScreenPadding, vertical = Space.xl), contentAlignment = Alignment.Center) {
        Column(
            modifier = Modifier.fillMaxWidth(),
            verticalArrangement = Arrangement.spacedBy(Space.xl),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Icon(Icons.Filled.Call, contentDescription = null, tint = Palette.Accent, modifier = Modifier.size(56.dp))
            Column(verticalArrangement = Arrangement.spacedBy(Space.sm), horizontalAlignment = Alignment.CenterHorizontally) {
                Text(stringResource(R.string.incoming_prompt_title), style = MaterialTheme.typography.titleMedium, color = Palette.OnSurfaceMuted)
                Text(displayNumber, style = MaterialTheme.typography.headlineMedium, textAlign = TextAlign.Center)
                Text(
                    stringResource(R.string.incoming_prompt_subtitle),
                    style = MaterialTheme.typography.bodyMedium,
                    color = Palette.OnSurfaceMuted,
                    textAlign = TextAlign.Center,
                )
            }
            Card {
                Column(verticalArrangement = Arrangement.spacedBy(Space.md)) {
                    PrimaryButton(stringResource(R.string.incoming_answer_secure), onClick = onSecure, icon = Icons.Filled.Lock)
                    SecondaryButton(stringResource(R.string.incoming_answer_plain), onClick = onPlain, icon = Icons.Filled.Phone)
                }
            }
        }
    }
}

@Composable
private fun SessionHost(session: SessionState, screen: SessionScreen, core: SecureCore, onExit: () -> Unit, callScoped: Boolean) {
    val scope = rememberCoroutineScope()
    val offer = session.saveOffer
    if (SessionUi.showSaveOffer(session) && offer != null) {
        if (callScoped) {
            SaveNeedsPinScreen(onLater = { core.dismissSaveOffer() })
            return
        }
        ContactFormScreen(
            title = stringResource(R.string.save_title),
            body = stringResource(R.string.save_body),
            initialName = "",
            initialNumber = offer.suggestedNumber,
            numberMayBeEmpty = offer.suggestedNumber == null,
            confirmLabel = stringResource(R.string.save_confirm),
            cancelLabel = stringResource(R.string.save_later),
            onSubmit = { name, number -> core.saveContact(name, number) },
            onCancel = { core.dismissSaveOffer() },
        )
        return
    }
    when (screen) {
        SessionScreen.CONNECTING -> ConnectingScreen(session, onCancel = { scope.launch { core.endAndWipe() } })
        SessionScreen.CHAT -> ChatScreen(session, core)
        SessionScreen.SAS -> SasScreen(
            session, keyChanged = session.phase == SessionPhase.KEY_CHANGED,
            onMatch = { core.decideSas(true) }, onMismatch = { core.decideSas(false) }, onOpenVoice = { core.openVoiceWindow() },
        )
        SessionScreen.KEY_CHANGED -> KeyChangedScreen(
            onRematch = { core.beginSas() }, onHangUp = { scope.launch { core.endAndWipe() } },
        )
        SessionScreen.ABORTED -> AbortedScreen(session.abort, onDone = { core.dismissAbort() }, wasEstablished = session.wasEstablished)
        SessionScreen.ENDING -> EndingScreen(session.phase, onClosed = onExit)
    }
}

/**
 * The "Phone app" section's state, read from the system role manager. It is read again whenever
 * the system's role consent screen or default apps settings return, and the "Phone" launcher entry
 * follows the dialer role. Holding the role also needs notifications, so they are asked for then.
 */
@Composable
private fun rememberPhoneAppSettings(): PhoneAppSettings {
    val context = LocalContext.current
    var version by remember { mutableStateOf(0) }
    val notifications = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) {}
    val roles = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        DialerRole.syncLauncherAlias(context)
        version++
        val canNotify = ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED
        if (DialerRole.isHeld(context) && !canNotify) {
            runCatching { notifications.launch(Manifest.permission.POST_NOTIFICATIONS) }
        }
    }
    LaunchedEffect(Unit) { DialerRole.syncLauncherAlias(context) }
    return remember(version) {
        PhoneAppSettings(
            held = DialerRole.isHeld(context),
            screeningHeld = DialerRole.isScreeningHeld(context),
            onUse = { DialerRole.requestIntent(context)?.let { runCatching { roles.launch(it) } } },
            onRestore = { runCatching { roles.launch(DialerRole.restoreIntent()) } },
            onTakeScreening = { DialerRole.requestScreeningIntent(context)?.let { runCatching { roles.launch(it) } } },
        )
    }
}
