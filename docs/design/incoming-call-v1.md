# Incoming Call Handling, Foreground Retention During a Call, and Secure Exit (v1 Design)

Status: Phase 1 implemented in `io.github.h4lovoid.dialcrypt.incoming.*`; on-device checks in Section 8 remain pending. (`chat/` below refers to `app/src/main/java/io/github/h4lovoid/dialcrypt/`.)

## 0. Approved product behavior and on-device facts

- The app does not need to stay open. The "Incoming call handling" setting has three choices: ask for incoming calls from saved contacts (default), ask for all incoming calls, off. When a matching call rings, a screen appears with two buttons: Secure answer and Plain answer. Secure answer automatically runs preparation, asks for the PIN, then connects after unlock and becomes the responder; Plain answer or ignoring the prompt is an ordinary phone call. If the calling side does not receive the encrypted preamble within 20 seconds, it hangs up, and it never falls back to an unencrypted call.
- Number display: initially shown in full in Phase 1; superseded by `DisplaySettings` ("Show full numbers" off by default, masking numbers to the last four digits on lists and locked screens) alongside `CallLogEraser`.
- During an encrypted call the app must stay in front; the call must not be frozen by the system; the screen must not be turned off by the proximity sensor during data mode.
- There must be an explicit "Secure exit": clear the secrets in memory, tell the daemon to end, and end the process only after the screen is closed.
- On device (Pixel 7 / 7a, Android 16, KernelSU, the app is a /system/priv-app privileged app, the default dialer is Google Phone):
  - On every call, Telecom binds a UI-less InCallService for the system app that holds CONTROL_INCALL_EXPERIENCE.
  - `TelecomManager.acceptRingingCall` is ignored right after an incoming call appears; today a 500 ms retry works around it.
  - On an outgoing call the Google Phone call screen covers the app; about one minute after the secure process goes to the background it is frozen, the heartbeat stops, the daemon ends the session 2 seconds later because the lease expired, and the system also turns the downlink recording into silence.
  - In normal mode Google Phone enables proximity-sensor screen-off; when the sensor is covered, the screen stays off after the call, and the power button must be pressed to recover it.
  - Call audio must use "VOICE_DOWNLINK capture + TELEPHONY output" first (`chat/call/CallAudioRoutes.kt` has been changed to this order); the interception interface receives the audio meant for humans, which the modem cannot decode. Muting the microphone does not affect the injected uplink.
  - Daemon preparation takes about 3-4 seconds; PIN entry takes about 10-20 seconds; carrier-side ringing lasts about 30-40 seconds.

## 1. Components and processes taking over

- Add a UI-less `chat/incoming/IncomingCallService` (InCallService), running in a separate `:call` process that Telecom starts on every call. It screens incoming calls, shows the prompt, holds the `Call` object, and, through a same-uid Messenger relay, hands call state, answer, hang-up, and audio routing to the secure process; this replaces PhoneStateListener and the acceptRingingCall retry.
- It does not go in `:secure` (the daemon requires the secure process to start only after preparation is done); it does not go in the default process (Telecom binds it during a call, so the launcher process could not end).
- Manifest additions: permissions CONTROL_INCALL_EXPERIENCE, START_ACTIVITIES_FROM_BACKGROUND, FOREGROUND_SERVICE_MICROPHONE, MANAGE_OWN_CALLS; `.incoming.IncomingCallService` (`:call`, exported, permission=BIND_INCALL_SERVICE, meta `android.telecom.IN_CALL_SERVICE_UI=false`, action `android.telecom.InCallService`); `.incoming.CallRelayService` (`:call`, not exported); `.incoming.IncomingPromptActivity` (`:call`, not exported, showWhenLocked, turnScreenOn, singleInstance, separate taskAffinity); activity-alias `.ui.IncomingLauncher` (target LauncherActivity, not exported); `.call.SecureCallService` (`:secure`, not exported, foregroundServiceType="phoneCall|microphone"). The privileged permission allowlist gets START_ACTIVITIES_FROM_BACKGROUND added (a missing allowlist entry makes the phone fail to boot; it must be checked item by item against the Manifest).
- `:call` may touch: `Call`, the number (in memory only, never written to a log), the HMAC of the screening key, the settings file. It may not touch: NativeBridge / loadLibrary, `CoreProvider.secureCore`, the vault file, the daemon socket.
- Call log: when a call the app dialed (matched against the number sent with `MSG_EXPECT_DIAL`) or took over (an offer was made, or the relay answered it) is removed, `CallRegistry` in `:call` starts `chat/call/CallLogEraser`. `:call` is the only process that knows the number and the start and end times of every such call, including missed, rejected and failed ones, and Telecom keeps it bound until the call is gone, while `:secure` may already have exited. For up to 30 seconds the eraser watches `CallLog.Calls` and deletes, by `_ID`, only the rows dated from 5 seconds before the call to 60 seconds after it whose direction fits and whose number is the far end's (digits compared, at least the last 7) or, for a withheld caller, that are hidden too. `CallRelayService` is started without a notification for that time so the process is not dropped as cached. Needs READ_CALL_LOG and WRITE_CALL_LOG (granted by `service.sh`); without them it logs one line and does nothing. Logs carry counts only, never the number.

## 2. Deciding "saved contact" while locked

- A StrongBox HMAC-SHA256 key, alias `aegis_screen_v1`, generated on the device, non-exportable, without setUnlockedDeviceRequired (it must be computable while the screen is locked).
- `screenTag = HMAC(K,"AegisScreen-v1"‖0x00‖E.164)[..16]`; `linkTag = HMAC(K,"AegisScreenLink-v1"‖0x00‖phoneTag)[..16]`, where phoneTag is the number tag inside the vault.
- File `noBackupFilesDir/screen.bin`: `"ASC1"` + 1000 slots × (linkTag‖screenTag), a fixed 32 004 bytes, empty slots filled with random values (the number of contacts cannot be seen), written with AtomicFile and fsync. Someone who only reads the stored file has no key and cannot recover the numbers by offline brute force.
- Writes happen only in the secure process after unlock: `saveContact` / `updateContact` writes one slot when it succeeds with a number; on every unlock and contact change it reconciles, refilling with random values any slot that does not match an existing phoneTag.
- wipeAll, the duress PIN, and remote wipe all call `ScreeningStore.wipe()`: overwrite and delete screen.bin, delete the key alias and the settings file.

## 3. Prompt screen and foreground retention

- Only handle: INCOMING and RINGING, the phone has only this one call, not a Wi-Fi call, not an emergency callback.
- App open (the secure process has subscribed to the relay): the relay pushes OFFER and the app shows the same two buttons inside the app, replacing today's automatic answer.
- App not open: OFF does nothing; ALL shows the prompt; CONTACTS shows it only when the lookup hits.
- The prompt screen covers the lock screen or the foreground app, applies `SecureWindow.apply`, and the buttons set filterTouchesWhenObscured; it shows the full number, or "Caller ID withheld" when the number is hidden.
- Plain answer: `call.answer()`, mark as PLAIN, `TelecomManager.showInCallScreen(false)`, close the prompt; afterwards only stay bound passively. The prompt closes automatically when ringing ends.
- Foreground retention `chat/incoming/FrontKeeper` (shared by the prompt screen and SecureActivity): when onStop happens while the foreground must be kept, the screen is on, there was no onUserLeaveHint, and the app is not exiting, it reopens itself with REORDER_TO_FRONT; at most 6 times within 10 seconds per call. If the user presses Home, leaving is allowed, and the foreground service keeps the process running.

## 4. Sequence

Secure answer (phase 1: answer only after unlock):
1. onCallAdded → screening → the prompt appears within about 1 second.
2. Tap "Secure answer": mark as SECURE_PENDING, start `.ui.IncomingLauncher` with a 16-byte token.
3. The default process immediately runs `prepare()`, together with requestDismissKeyguard.
4. READY and keyguard dismissed → start SecureActivity (lease + token); the default process ends itself.
5. The secure process attaches to the daemon → `beginHandoff(token)` → `claim(token)`; if still RINGING it takes ownership, and the PIN screen shows "Encrypted call waiting".
6. PIN unlock succeeds → start the foreground service first (if that fails, do not answer) → `answer()` (`:call` calls `Call.answer()`, succeeding on the first try).
7. ACTIVE → open PCM and mute → switch to the data route → create the native session (responder).

Outgoing: start the foreground service first → tell the relay "the next outgoing call is mine" → placeCall; when the Google Phone screen pops up, FrontKeeper pulls the app back.

Ending: if the other side hangs up first or ringing times out (claim returns GONE / ENDED is received afterwards), show "Call ended" for 3 seconds, then Secure exit; being answered elsewhere (TAKEN) is the same; a wrong PIN keeps the existing retry; the duress PIN does not answer, releases ownership, and clears the screening data; if preparation fails, offer "Retry" and "Use plain answer"; if the secure process dies midway, the relay calls `disconnect()` on a call already in data mode.

"Answer first, unlock later" is not done in phase 1 (it would use up the calling side's 20-second preamble deadline); if more than 20% of 20 measured calls time out while ringing, do it as phase 2 (an unencrypted WAIT beacon, protocol version plus 1).

## 5. Secure exit

`SecureActivity.secureExit(reason)` is the only normal exit path (`ExitReason { USER, LEFT_APP, CALL_ENDED_AWAY, INCOMING_GONE, DURESS, WIPED }`); a daemon violation or disconnect still takes the emergency path `sessionLost()`.
1. Stop accepting input and show "Exiting securely".
2. `core.prepareExit()`: while ringing, release ownership; during a call, `endAndWipe()` (notify the peer and hang up, restore routing and volume, stop the foreground service); `lock()` all state, reset to IDLE, clear the keyboard and PIN buffers.
3. `lease.end(3000)`.
4. finishAndRemoveTask, and killProcess only after onDestroy (fallback timer 1.5 seconds).

When idle it runs directly; during a call it first confirms "End the encrypted call and exit"; on onStop without holding a call it calls `secureExit(LEFT_APP)`; while holding a call, leaving does not exit, and after the call ends in the background it calls `secureExit(CALL_ENDED_AWAY)`. The home, settings, and call menus all have a "Secure exit" button.

## 6. Interfaces

`chat/call/CallLink.kt`:
```kotlin
enum class NumberPresentation { SHOWN, WITHHELD, UNKNOWN }
data class CallStatus(val phase: CallPhase = CallPhase.IDLE, val incoming: Boolean = false,
    val number: String? = null, val presentation: NumberPresentation = NumberPresentation.SHOWN)
class IncomingOffer(val token: ByteArray, val number: String?, val presentation: NumberPresentation)
enum class ClaimResult { RINGING, GONE, TAKEN }
interface CallLink {
    val status: StateFlow<CallStatus>; val offers: StateFlow<IncomingOffer?>
    fun dial(number: String): Boolean
    suspend fun claim(token: ByteArray): ClaimResult; fun release()
    fun answer(): Boolean                 // the call being held, once, blocks at most 1 second, not on the main thread
    fun answerPlain(token: ByteArray): Boolean
    fun hangUp(); fun openAudio(): CallAudio?
}
```
`chat/core/Models.kt`: `PeerInfo` gets `presentation`; `ConnectStep` gets `ANSWERING`; `SessionState` gets `direction: CallDirection { OUTGOING, INCOMING }`. The incoming call screen title is "Encrypted incoming call", with the steps "Answering → Waiting for the peer's encrypted signal → Key exchange → Identity confirmation → Done".

`chat/core/SecureCore.kt`:
```kotlin
val incoming: StateFlow<IncomingUi?>   // IncomingUi(number, presentation, handoff, ringingSinceMs, ended)
val callHeld: StateFlow<Boolean>       // from begin() until the session ends
fun beginHandoff(token: ByteArray); fun decideIncoming(secure: Boolean); suspend fun prepareExit()
```
`chat/core/UiPreferences.kt`: `enum class IncomingMode { CONTACTS, ALL, OFF }`, `val incomingMode: StateFlow<IncomingMode>`, `fun setIncomingMode(mode)`. The setting is stored in `noBackupFilesDir/incoming_mode` (1 byte, a missing file counts as CONTACTS), written only by the secure process, and re-read by `:call` on every incoming call.

New classes:
```kotlin
class ScreeningStore(ctx: Context, mac: (ByteArray) -> ByteArray?) { fun matches(e164: String): Boolean
    fun put(phoneTag: ByteArray, e164: String): Boolean; fun reconcile(tags: List<ByteArray>): BooleanArray; fun wipe() }
object IncomingSettings { fun read(ctx: Context): IncomingMode; fun write(ctx: Context, mode: IncomingMode) }
interface CallKeeper { fun start(): Boolean; fun stop() }
class FrontKeeper(a: Activity, hold: () -> Boolean) { fun onUserLeaveHint(); fun onStop() }
```
Relay protocol `chat/incoming/RelayProtocol.kt` (Messenger; every message checks sendingUid == myUid; only one subscriber at a time): SUBSCRIBE, STATUS, OFFER, CLAIM, RELEASE, ANSWER, ANSWER_PLAIN, HANGUP, EXPECT_DIAL (matched within 5 seconds), DATA_ROUTE. Call state mapping: NEW / CONNECTING / DIALING → DIALING; RINGING → RINGING; ACTIVE → ACTIVE; HOLDING / DISCONNECTING / DISCONNECTED → ENDED.

SessionEngine: `watchCalls` no longer answers automatically (with an OFFER and IDLE, let the app ask; if the handoff has claimed and the vault is unlocked, `begin`; if the held call is ENDED, `finish`); the first step of `begin()` is `keeper.start()`, and the last step of `finish()` is `keeper.stop()`. CoreProvider switches to RelayCallLink; the state listener and retry in TelecomCallLink are disabled.

Proximity sensor: in data mode `:call` calls `InCallService.setAudioRoute()` to switch to the speaker (Google Phone does not enable proximity screen-off on the speaker route; in data mode the earpiece and speaker are silent anyway); DATA_ROUTE(on) is sent only after openAudio succeeds and muting is confirmed; when the voice comparison window opens, restore the original route before unmuting, and do the reverse when it closes.

Background freeze: `chat/call/SecureCallService` (foreground service, phoneCall|microphone) is started by `begin()` while the app is in the foreground, and stopped by `finish`; the notification only says "DialCrypt call in progress".

## 7. Defects raised in review, to be fixed in this round

- Hang up only once: `hangUp()` must record "hang-up pending" and cancel answering, then hang up again whenever the call is observed, until ENDED or timeout.
- Rehearsal mode must not be shown as completed hardening: when the daemon reports mode=0, the preparation screen must state "Rehearsal mode, system not changed"; the two tier 2 items are shown according to the claims bits.
- Unmuting before the call has dropped: wait until the state leaves ACTIVE (with an upper limit) before restoring the microphone and volume; if hanging up fails, stay muted.
- The native session may not be closed: creation and handoff must write the handle into ActiveCall inside a non-cancellable block.
- A vault directory fsync failure is treated as a file write failure: a failure after the rename counts as already written.
- ATTACH has no timeout: set a 5-second deadline for connecting to ATTACHED, and on timeout go to onLost; do not show the PIN screen before ATTACHED.

## 8. Attack surface and items to be confirmed on device

- The only new exported component is the service protected by BIND_INCALL_SERVICE; the relay only gives commands for the call it holds; ANSWER_PLAIN only accepts the token issued by the prompt screen.
- `:call` has no system hardening and stays alive during a secure session: it holds no secrets and does not connect to the daemon; when compromised, the worst case is hanging up the call or aborting the session.
- The screening key amounts to a lookup interface: anyone who can run code under the app uid can try numbers one by one, and StrongBox only slows this down. In CONTACTS mode, as soon as the prompt appears, a bystander knows the caller is a contact.
- To be confirmed on device: Telecom binds our service for both outgoing and incoming calls; `Call.answer()` takes effect once after onCallAdded; FrontKeeper can cover the Google Phone screen and the flicker is acceptable; on the lock screen, keyguard dismissal and preparation can run in parallel; on the lock screen (after the first unlock) the StrongBox HMAC is available; the daemon's attach check passes while `:call` is alive; the screen does not turn off on the speaker route and the modem error rate is unchanged; under the foreground service, the heartbeat and downlink capture are not interrupted when the secure process is in the background or the screen is off for 2 minutes.

## 9. Phase 1 work breakdown (write scopes do not overlap)

- **WP-A (`:call` side)**: `chat/incoming/{IncomingCallService,CallRegistry,CallRelayService,RelayProtocol,IncomingPromptActivity,FrontKeeper}.kt`, `app/src/main/AndroidManifest.xml`, `magisk-module/system/etc/permissions/privapp-permissions-aegiscall.xml`, tests `app/src/test/java/io/github/h4lovoid/dialcrypt/incoming/`.
- **WP-B (screening and settings)**: `chat/incoming/screen/{StrongBoxScreeningKey,ScreeningStore,IncomingSettings}.kt`, tests `app/src/test/java/io/github/h4lovoid/dialcrypt/incoming/screen/`.
- **WP-C (secure process core)**: `chat/call/{CallLink,RelayCallLink,SecureCallService}.kt`, `chat/core/{SecureCore,UiPreferences,CoreProvider,UnavailableCores,Models}.kt`, `chat/core/real/{SessionEngine,SessionModel,NativeSecureCore}.kt`, `chat/ui/{SecureActivity,LauncherActivity}.kt`, fakes implementing the interfaces above, test `app/src/test/java/io/github/h4lovoid/dialcrypt/real/IncomingHandoffTest.kt`.
- **WP-D (screens)**: `chat/ui/AppRoot.kt`, new file `chat/ui/screens/IncomingScreens.kt`, `chat/ui/screens/{SettingsScreens,SessionScreens,PinScreens,PreparationScreens,HomeScreens,ContactScreens}.kt`, `chat/ui/model/`, `strings.xml` for the four locales.
