package io.github.h4lovoid.dialcrypt.dialer

import android.app.Application
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.SemanticsMatcher
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.assertTextEquals
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.core.app.ApplicationProvider
import io.github.h4lovoid.dialcrypt.R
import io.github.h4lovoid.dialcrypt.core.AppLanguage
import io.github.h4lovoid.dialcrypt.core.ContactMembership
import io.github.h4lovoid.dialcrypt.core.NumberPresentation
import io.github.h4lovoid.dialcrypt.dialer.model.AudioUi
import io.github.h4lovoid.dialcrypt.dialer.model.Endpoint
import io.github.h4lovoid.dialcrypt.dialer.model.InCallUiState
import io.github.h4lovoid.dialcrypt.dialer.model.NumberText
import io.github.h4lovoid.dialcrypt.dialer.model.NumberTexts
import io.github.h4lovoid.dialcrypt.dialer.model.Screening
import io.github.h4lovoid.dialcrypt.dialer.model.UiCall
import io.github.h4lovoid.dialcrypt.dialer.model.UiCallState
import io.github.h4lovoid.dialcrypt.dialer.ui.InCallActions
import io.github.h4lovoid.dialcrypt.dialer.ui.InCallScreen
import io.github.h4lovoid.dialcrypt.dialer.ui.InCallTags
import io.github.h4lovoid.dialcrypt.ui.ProvideAppLanguage
import io.github.h4lovoid.dialcrypt.ui.theme.DialCryptTheme
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

/** Which buttons the in-call screen offers in each call state, and what it shows for the caller. */
@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [34], qualifiers = "w411dp-h891dp-xxhdpi")
class InCallScreensTest {
    @get:Rule
    val rule = createComposeRule()

    private val app: Application = ApplicationProvider.getApplicationContext()

    private val fullNumber = "+1 555 123 4567"

    private fun call(
        state: UiCallState,
        id: Int = 1,
        number: NumberText = NumberText.Digits("\u2022\u2022\u2022\u2022 4567"),
        connectMs: Long? = null,
        canHold: Boolean = true,
        emergency: Boolean = false,
        postDial: String? = null,
        accounts: List<String> = emptyList(),
        answerEnabled: Boolean = false,
    ) = UiCall(
        id = id,
        state = state,
        number = number,
        connectMs = connectMs,
        canHold = canHold,
        emergency = emergency,
        postDial = postDial,
        accounts = accounts,
        answerEnabled = answerEnabled,
    )

    private val bothRoutes = AudioUi(endpoint = Endpoint.EARPIECE, available = listOf(Endpoint.EARPIECE, Endpoint.SPEAKER))

    private fun show(
        state: InCallUiState,
        actions: InCallActions = InCallActions(),
        handoffBusy: Boolean = false,
    ) {
        rule.setContent {
            ProvideAppLanguage(AppLanguage.EN) {
                DialCryptTheme { InCallScreen(state, actions, nowMs = 100_000L, handoffBusy = handoffBusy) }
            }
        }
    }

    private fun assertPresent(vararg tags: String) = tags.forEach { rule.onNodeWithTag(it).assertExists() }

    private fun assertAbsent(vararg tags: String) = tags.forEach { rule.onNodeWithTag(it).assertDoesNotExist() }

    private fun assertNoTextInput() {
        val editable = rule.onAllNodes(SemanticsMatcher.keyIsDefined(SemanticsProperties.EditableText)).fetchSemanticsNodes()
        val setText = rule.onAllNodes(SemanticsMatcher.keyIsDefined(SemanticsActions.SetText)).fetchSemanticsNodes()
        assertEquals(0, editable.size)
        assertEquals(0, setText.size)
    }

    // ---- ringing -----------------------------------------------------------------------------

    @Test
    fun aScreenedRingingCallOffersAnswerAndDecline() {
        show(InCallUiState(primary = call(UiCallState.RINGING, answerEnabled = true), screening = Screening.PLAIN))
        assertPresent(InCallTags.ANSWER, InCallTags.DECLINE)
        rule.onNodeWithTag(InCallTags.ANSWER).assertIsEnabled()
        rule.onNodeWithTag(InCallTags.DECLINE).assertIsEnabled()
        assertAbsent(
            InCallTags.ANSWER_SECURE,
            InCallTags.ANSWER_PLAIN,
            InCallTags.HOLD_AND_ANSWER,
            InCallTags.END,
            InCallTags.MUTE,
            InCallTags.CHECKING,
        )
    }

    @Test
    fun whileScreeningTheAnswerButtonIsOffAndTheCheckingTextShows() {
        show(InCallUiState(primary = call(UiCallState.RINGING, answerEnabled = false), screening = Screening.PENDING))
        rule.onNodeWithTag(InCallTags.ANSWER).assertIsNotEnabled()
        rule.onNodeWithTag(InCallTags.DECLINE).assertIsEnabled()
        rule.onNodeWithTag(InCallTags.CHECKING).assertTextEquals(app.getString(R.string.incall_checking))
    }

    @Test
    fun aSecureOfferShowsSecureAnswerPlainAnswerAndDecline() {
        show(InCallUiState(primary = call(UiCallState.RINGING, answerEnabled = true), secureOffer = true, screening = Screening.OFFER))
        assertPresent(InCallTags.ANSWER_SECURE, InCallTags.ANSWER_PLAIN, InCallTags.DECLINE)
        rule.onNodeWithTag(InCallTags.ANSWER_SECURE).assertIsEnabled()
        rule.onNodeWithTag(InCallTags.ANSWER_PLAIN).assertIsEnabled()
        rule.onNodeWithTag(InCallTags.DECLINE).assertIsEnabled()
        // The ordinary answer button is replaced by the two choices.
        assertAbsent(InCallTags.ANSWER, InCallTags.END)
    }

    @Test
    fun withoutAnOfferThereIsNoSecureAnswer() {
        show(InCallUiState(primary = call(UiCallState.RINGING, answerEnabled = true), secureOffer = false, screening = Screening.PLAIN))
        assertAbsent(InCallTags.ANSWER_SECURE, InCallTags.ANSWER_PLAIN)
    }

    @Test
    fun aHandoffInProgressDisablesEveryRingingButton() {
        show(
            InCallUiState(primary = call(UiCallState.RINGING, answerEnabled = true), secureOffer = true, screening = Screening.OFFER),
            handoffBusy = true,
        )
        rule.onNodeWithTag(InCallTags.ANSWER_SECURE).assertIsNotEnabled()
        rule.onNodeWithTag(InCallTags.ANSWER_PLAIN).assertIsNotEnabled()
        rule.onNodeWithTag(InCallTags.DECLINE).assertIsNotEnabled()
    }

    @Test
    fun theRingingButtonsCallTheMatchingActions() {
        val answered = ArrayList<Int>()
        val declined = ArrayList<Int>()
        show(
            InCallUiState(primary = call(UiCallState.RINGING, id = 7, answerEnabled = true), screening = Screening.PLAIN),
            InCallActions(answer = { answered += it }, decline = { declined += it }),
        )
        rule.onNodeWithTag(InCallTags.ANSWER).performClick()
        rule.onNodeWithTag(InCallTags.DECLINE).performClick()
        rule.runOnIdle {
            assertEquals(listOf(7), answered)
            assertEquals(listOf(7), declined)
        }
    }

    @Test
    fun theSecureAnswerButtonOnlyCallsAnswerSecure() {
        var secure = 0
        val answered = ArrayList<Int>()
        show(
            InCallUiState(primary = call(UiCallState.RINGING, answerEnabled = true), secureOffer = true, screening = Screening.OFFER),
            InCallActions(answer = { answered += it }, answerSecure = { secure++ }),
        )
        rule.onNodeWithTag(InCallTags.ANSWER_SECURE).performClick()
        rule.runOnIdle {
            assertEquals(1, secure)
            assertTrue(answered.isEmpty())
        }
    }

    // ---- dialing, active and holding -----------------------------------------------------------

    @Test
    fun aDialingCallCanBeEndedAndHasNoHoldOrKeypad() {
        // The screen also offers mute while dialing (InCallScreens.kt, connectedOrDialing); only the absent controls are pinned here.
        show(InCallUiState(primary = call(UiCallState.DIALING), audio = bothRoutes))
        assertPresent(InCallTags.END)
        rule.onNodeWithTag(InCallTags.END).assertIsEnabled()
        assertAbsent(
            InCallTags.ANSWER,
            InCallTags.DECLINE,
            InCallTags.HOLD,
            InCallTags.RESUME,
            InCallTags.KEYPAD,
            InCallTags.SWAP,
        )
        rule.onNodeWithText(app.getString(R.string.incall_dialing)).assertExists()
    }

    @Test
    fun anActiveCallOffersMuteAudioKeypadHoldAndEnd() {
        show(InCallUiState(primary = call(UiCallState.ACTIVE, connectMs = 40_000L), audio = bothRoutes))
        assertPresent(InCallTags.MUTE, InCallTags.AUDIO, InCallTags.KEYPAD, InCallTags.HOLD, InCallTags.END)
        assertAbsent(InCallTags.RESUME, InCallTags.ANSWER, InCallTags.DECLINE, InCallTags.SWAP, InCallTags.OTHER_CALL)
        // 100 s wall clock minus a connect time of 40 s.
        rule.onNodeWithText("1:00").assertExists()
    }

    @Test
    fun audioNeedsMoreThanOneRouteAndHoldNeedsTheCapability() {
        show(InCallUiState(primary = call(UiCallState.ACTIVE, canHold = false), audio = AudioUi(available = listOf(Endpoint.EARPIECE))))
        assertPresent(InCallTags.MUTE, InCallTags.KEYPAD, InCallTags.END)
        assertAbsent(InCallTags.AUDIO, InCallTags.HOLD)
    }

    @Test
    fun theControlsCallTheMatchingActions() {
        var muted: Boolean? = null
        val held = ArrayList<Pair<Int, Boolean>>()
        val ended = ArrayList<Int>()
        val routes = ArrayList<Endpoint>()
        show(
            InCallUiState(primary = call(UiCallState.ACTIVE, id = 3), audio = bothRoutes),
            InCallActions(
                setMuted = { muted = it },
                hold = { id, on -> held += id to on },
                end = { ended += it },
                route = { routes += it },
            ),
        )
        rule.onNodeWithTag(InCallTags.MUTE).performClick()
        rule.onNodeWithTag(InCallTags.HOLD).performClick()
        rule.onNodeWithTag(InCallTags.AUDIO).performClick()
        rule.onNodeWithTag(InCallTags.route(Endpoint.SPEAKER)).performClick()
        rule.onNodeWithTag(InCallTags.END).performClick()
        rule.runOnIdle {
            assertEquals(true, muted)
            assertEquals(listOf(3 to true), held)
            assertEquals(listOf(Endpoint.SPEAKER), routes)
            assertEquals(listOf(3), ended)
        }
    }

    @Test
    fun aHeldCallOffersResumeAndEnd() {
        val held = ArrayList<Pair<Int, Boolean>>()
        show(
            InCallUiState(primary = call(UiCallState.HOLDING, id = 4, connectMs = 40_000L), audio = bothRoutes),
            InCallActions(hold = { id, on -> held += id to on }),
        )
        assertPresent(InCallTags.RESUME, InCallTags.END)
        assertAbsent(InCallTags.HOLD, InCallTags.MUTE, InCallTags.KEYPAD, InCallTags.AUDIO)
        rule.onNodeWithText(app.getString(R.string.incall_on_hold)).assertExists()
        rule.onNodeWithTag(InCallTags.RESUME).performClick()
        rule.runOnIdle { assertEquals(listOf(4 to false), held) }
    }

    @Test
    fun theKeypadSendsTonesAndReleasesThem() {
        val tones = ArrayList<Pair<Int, Char?>>()
        show(
            InCallUiState(primary = call(UiCallState.ACTIVE, id = 5), audio = bothRoutes),
            InCallActions(dtmf = { id, c -> tones += id to c }),
        )
        assertAbsent(InCallTags.dtmf('5'))
        rule.onNodeWithTag(InCallTags.KEYPAD).performClick()
        assertPresent(InCallTags.dtmf('5'), InCallTags.dtmf('*'), InCallTags.dtmf('#'))
        rule.onNodeWithTag(InCallTags.dtmf('5')).performClick()
        rule.runOnIdle {
            assertTrue(tones.toString(), (5 to '5') in tones)
            // Every press ends with a release (null stops the tone).
            assertEquals(5 to null, tones.last())
        }
    }

    @Test
    fun aPostDialPromptOffersSendAndCancel() {
        val sent = ArrayList<Pair<Int, Boolean>>()
        show(
            InCallUiState(primary = call(UiCallState.ACTIVE, id = 6, postDial = "123"), audio = bothRoutes),
            InCallActions(postDial = { id, go -> sent += id to go }),
        )
        assertPresent(InCallTags.POST_DIAL_SEND, InCallTags.POST_DIAL_CANCEL)
        rule.onNodeWithTag(InCallTags.POST_DIAL_SEND).performClick()
        rule.onNodeWithTag(InCallTags.POST_DIAL_CANCEL).performClick()
        rule.runOnIdle { assertEquals(listOf(6 to true, 6 to false), sent) }
    }

    // ---- second call ----------------------------------------------------------------------------

    @Test
    fun aWaitingCallOffersHoldAndAnswerAndDecline() {
        val answered = ArrayList<Int>()
        show(
            InCallUiState(
                primary = call(UiCallState.WAITING, id = 2, answerEnabled = true),
                secondary = call(UiCallState.ACTIVE, id = 1, connectMs = 40_000L),
                audio = bothRoutes,
                screening = Screening.PLAIN,
            ),
            InCallActions(answer = { answered += it }),
        )
        assertPresent(InCallTags.HOLD_AND_ANSWER, InCallTags.DECLINE, InCallTags.OTHER_CALL)
        rule.onNodeWithTag(InCallTags.HOLD_AND_ANSWER).assertIsEnabled()
        assertAbsent(InCallTags.ANSWER, InCallTags.ANSWER_SECURE, InCallTags.END, InCallTags.SWAP)
        rule.onNodeWithTag(InCallTags.HOLD_AND_ANSWER).performClick()
        rule.runOnIdle { assertEquals(listOf(2), answered) }
    }

    @Test
    fun twoCallsOfferSwapOnlyForTheActiveOneNextToAHeldOne() {
        var swaps = 0
        show(
            InCallUiState(
                primary = call(UiCallState.ACTIVE, id = 2, connectMs = 40_000L),
                secondary = call(UiCallState.HOLDING, id = 1, connectMs = 10_000L),
                audio = bothRoutes,
            ),
            InCallActions(swap = { swaps++ }),
        )
        assertPresent(InCallTags.OTHER_CALL, InCallTags.SWAP)
        rule.onNodeWithTag(InCallTags.SWAP).performClick()
        rule.runOnIdle { assertEquals(1, swaps) }
    }

    @Test
    fun noSwapWhenTheOtherCallIsNotHeld() {
        show(
            InCallUiState(
                primary = call(UiCallState.ACTIVE, id = 2, connectMs = 40_000L),
                secondary = call(UiCallState.DIALING, id = 1),
                audio = bothRoutes,
            ),
        )
        assertPresent(InCallTags.OTHER_CALL)
        assertAbsent(InCallTags.SWAP)
    }

    @Test
    fun aSecureCallOnlyOffersEndAndNoSwapOrPostDial() {
        show(
            InCallUiState(
                primary = call(UiCallState.ACTIVE, id = 2, connectMs = 40_000L, postDial = "123"),
                secondary = call(UiCallState.HOLDING, id = 1),
                audio = bothRoutes,
                secureOwned = true,
            ),
        )
        assertPresent(InCallTags.END)
        assertAbsent(
            InCallTags.MUTE,
            InCallTags.AUDIO,
            InCallTags.KEYPAD,
            InCallTags.HOLD,
            InCallTags.RESUME,
            InCallTags.SWAP,
            InCallTags.POST_DIAL_SEND,
        )
    }

    // ---- SIM choice and the end -----------------------------------------------------------------

    @Test
    fun theSimChoiceListsEveryAccount() {
        val picked = ArrayList<Pair<Int, Int>>()
        show(
            InCallUiState(primary = call(UiCallState.SELECT_ACCOUNT, id = 8, accounts = listOf("Work SIM", "Home SIM"))),
            InCallActions(selectAccount = { id, index -> picked += id to index }),
        )
        assertPresent(InCallTags.sim(0), InCallTags.sim(1), InCallTags.END)
        assertAbsent(InCallTags.sim(2))
        rule.onNodeWithText(app.getString(R.string.incall_select_sim)).assertExists()
        rule.onNodeWithText("Work SIM").assertExists()
        rule.onNodeWithText("Home SIM").assertExists()
        rule.onNodeWithTag(InCallTags.sim(1)).performClick()
        rule.runOnIdle { assertEquals(listOf(8 to 1), picked) }
    }

    @Test
    fun anEndedCallShowsOnlyTheEndedText() {
        show(InCallUiState(primary = call(UiCallState.ENDED)))
        rule.onNodeWithText(app.getString(R.string.incall_ended)).assertExists()
        assertAbsent(InCallTags.ANSWER, InCallTags.DECLINE, InCallTags.END, InCallTags.MUTE, InCallTags.HOLD)
    }

    @Test
    fun noCallAtAllAlsoShowsTheEndedText() {
        show(InCallUiState(primary = null))
        rule.onNodeWithText(app.getString(R.string.incall_ended)).assertExists()
        assertAbsent(InCallTags.NUMBER, InCallTags.END)
    }

    @Test
    fun aDisconnectingCallHasADisabledEndButtonAndNoControls() {
        show(InCallUiState(primary = call(UiCallState.DISCONNECTING), audio = bothRoutes))
        rule.onNodeWithTag(InCallTags.END).assertIsNotEnabled()
        assertAbsent(InCallTags.MUTE, InCallTags.KEYPAD, InCallTags.HOLD)
    }

    @Test
    fun anEmergencyCallCarriesAMarker() {
        show(InCallUiState(primary = call(UiCallState.DIALING, emergency = true)))
        assertPresent(InCallTags.EMERGENCY)
        rule.onNodeWithText(app.getString(R.string.incall_emergency)).assertExists()
    }

    // ---- the caller line ------------------------------------------------------------------------

    @Test
    fun aMaskedNumberShowsOnlyTheLastFourDigits() {
        val masked = NumberTexts.of(fullNumber, NumberPresentation.SHOWN, ContactMembership.CONTACT, showFull = false, locked = true)
        show(InCallUiState(primary = call(UiCallState.ACTIVE, number = masked)))
        rule.onNodeWithTag(InCallTags.NUMBER).assertTextEquals("\u2022\u2022\u2022\u2022 4567")
        // Nothing else on the screen may carry the digits that were hidden.
        assertEquals(0, rule.onAllNodesWithText("555", substring = true).fetchSemanticsNodes().size)
        assertEquals(0, rule.onAllNodesWithText("1234", substring = true).fetchSemanticsNodes().size)
    }

    @Test
    fun aNumberOverTheLockScreenIsMaskedEvenWhenFullNumbersAreOn() {
        val masked = NumberTexts.of(fullNumber, NumberPresentation.SHOWN, ContactMembership.CONTACT, showFull = true, locked = true)
        show(InCallUiState(primary = call(UiCallState.RINGING, number = masked, answerEnabled = true)))
        rule.onNodeWithTag(InCallTags.NUMBER).assertTextEquals("\u2022\u2022\u2022\u2022 4567")
    }

    @Test
    fun theWholeNumberShowsOnlyWhenUnlockedAndChosen() {
        val full = NumberTexts.of(fullNumber, NumberPresentation.SHOWN, ContactMembership.CONTACT, showFull = true, locked = false)
        show(InCallUiState(primary = call(UiCallState.ACTIVE, number = full)))
        rule.onNodeWithTag(InCallTags.NUMBER).assertTextEquals(fullNumber)
    }

    @Test
    fun aStrangerShowsWholeOverTheLockScreen() {
        val full = NumberTexts.of(fullNumber, NumberPresentation.SHOWN, ContactMembership.NOT_CONTACT, showFull = false, locked = true)
        show(InCallUiState(primary = call(UiCallState.RINGING, number = full, answerEnabled = true)))
        rule.onNodeWithTag(InCallTags.NUMBER).assertTextEquals(fullNumber)
    }

    @Test
    fun hiddenUnknownAndPayphoneCallersShowTheirOwnWords() {
        val cases = listOf(
            NumberText.Hidden to R.string.incall_number_hidden,
            NumberText.Unknown to R.string.incall_number_unknown,
            NumberText.Payphone to R.string.incall_payphone,
        )
        val shown = mutableStateOf<NumberText>(NumberText.Hidden)
        rule.setContent {
            ProvideAppLanguage(AppLanguage.EN) {
                DialCryptTheme {
                    InCallScreen(InCallUiState(primary = call(UiCallState.ACTIVE, number = shown.value)), InCallActions(), nowMs = 100_000L)
                }
            }
        }
        for ((text, res) in cases) {
            rule.runOnIdle { shown.value = text }
            rule.onNodeWithTag(InCallTags.NUMBER).assertTextEquals(app.getString(res))
        }
    }

    // ---- no text input --------------------------------------------------------------------------

    @Test
    fun theRingingScreenHasNoTextInput() {
        show(InCallUiState(primary = call(UiCallState.RINGING, answerEnabled = true), secureOffer = true, screening = Screening.OFFER))
        assertNoTextInput()
    }

    @Test
    fun theCallScreenWithTheKeypadOpenHasNoTextInput() {
        show(InCallUiState(primary = call(UiCallState.ACTIVE, postDial = "123"), audio = bothRoutes))
        rule.onNodeWithTag(InCallTags.KEYPAD).performClick()
        assertPresent(InCallTags.dtmf('1'))
        assertNoTextInput()
    }

    @Test
    fun theSimChoiceHasNoTextInput() {
        show(InCallUiState(primary = call(UiCallState.SELECT_ACCOUNT, accounts = listOf("A", "B"))))
        assertNoTextInput()
    }

    // ---- end and answer, merge, conference -------------------------------------------------------

    @Test
    fun aWaitingCallNextToAnActiveOneOffersEndAndAnswer() {
        val ended = ArrayList<Int>()
        show(
            InCallUiState(
                primary = call(UiCallState.WAITING, id = 2, answerEnabled = true),
                secondary = call(UiCallState.ACTIVE, id = 1, connectMs = 40_000L),
                screening = Screening.PLAIN,
            ),
            InCallActions(endAndAnswer = { ended += it }),
        )
        assertPresent(InCallTags.HOLD_AND_ANSWER, InCallTags.END_AND_ANSWER, InCallTags.DECLINE)
        rule.onNodeWithTag(InCallTags.END_AND_ANSWER).assertIsEnabled().performClick()
        rule.runOnIdle { assertEquals(listOf(2), ended) }
    }

    @Test
    fun endAndAnswerWaitsForScreeningLikeTheOtherAnswer() {
        show(
            InCallUiState(
                primary = call(UiCallState.WAITING, id = 2, answerEnabled = false),
                secondary = call(UiCallState.ACTIVE, id = 1, connectMs = 40_000L),
                screening = Screening.PENDING,
            ),
        )
        rule.onNodeWithTag(InCallTags.END_AND_ANSWER).assertIsNotEnabled()
        rule.onNodeWithTag(InCallTags.HOLD_AND_ANSWER).assertIsNotEnabled()
    }

    @Test
    fun aWaitingCallNextToAHeldOneHasNoEndAndAnswer() {
        show(
            InCallUiState(
                primary = call(UiCallState.WAITING, id = 2, answerEnabled = true),
                secondary = call(UiCallState.HOLDING, id = 1, connectMs = 40_000L),
            ),
        )
        assertPresent(InCallTags.HOLD_AND_ANSWER, InCallTags.DECLINE)
        assertAbsent(InCallTags.END_AND_ANSWER)
    }

    @Test
    fun whileTheSecureFlowOwnsACallAWaitingCallCanOnlyBeDeclined() {
        show(
            InCallUiState(
                primary = call(UiCallState.WAITING, id = 2, answerEnabled = true),
                secondary = call(UiCallState.ACTIVE, id = 1, connectMs = 40_000L),
                secureOwned = true,
            ),
        )
        assertPresent(InCallTags.DECLINE)
        assertAbsent(InCallTags.HOLD_AND_ANSWER, InCallTags.END_AND_ANSWER)
    }

    @Test
    fun mergeShowsOnlyWhenAllowedAndCallsMerge() {
        var merges = 0
        show(
            InCallUiState(
                primary = call(UiCallState.ACTIVE, id = 2, connectMs = 40_000L),
                secondary = call(UiCallState.HOLDING, id = 1, connectMs = 10_000L),
                canMerge = true,
            ),
            InCallActions(merge = { merges++ }),
        )
        rule.onNodeWithTag(InCallTags.MERGE).performClick()
        rule.runOnIdle { assertEquals(1, merges) }
    }

    @Test
    fun noMergeWithoutTheCapability() {
        show(
            InCallUiState(
                primary = call(UiCallState.ACTIVE, id = 2, connectMs = 40_000L),
                secondary = call(UiCallState.HOLDING, id = 1, connectMs = 10_000L),
            ),
        )
        assertAbsent(InCallTags.MERGE)
    }

    @Test
    fun aConferenceShowsItsNameAndSizeAndEndsAsOneCall() {
        val ended = ArrayList<Int>()
        show(
            InCallUiState(primary = call(UiCallState.ACTIVE, id = 7, number = NumberText.Conference(3), connectMs = 40_000L)),
            InCallActions(end = { ended += it }),
        )
        rule.onNodeWithTag(InCallTags.NUMBER).assertTextEquals("Conference call")
        rule.onNodeWithTag(InCallTags.CONFERENCE_SIZE).assertTextEquals("3 people")
        rule.onNodeWithTag(InCallTags.END).performClick()
        rule.runOnIdle { assertEquals(listOf(7), ended) }
    }

    @Test
    fun aConferenceWithoutAListOfParticipantsShowsNoCount() {
        show(InCallUiState(primary = call(UiCallState.ACTIVE, id = 7, number = NumberText.Conference(0), connectMs = 40_000L)))
        rule.onNodeWithTag(InCallTags.NUMBER).assertTextEquals("Conference call")
        assertAbsent(InCallTags.CONFERENCE_SIZE)
    }
}
