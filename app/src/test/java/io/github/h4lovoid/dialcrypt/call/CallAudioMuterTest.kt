package io.github.h4lovoid.dialcrypt.call

import android.content.Context
import android.media.AudioManager
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.Shadows.shadowOf
import android.app.ActivityManager
import java.io.File

/** The phone-wide microphone mute of a secure call must not outlive a crashed or killed call. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class CallAudioMuterTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val am: AudioManager = context.getSystemService(AudioManager::class.java)
    private val journal get() = CallAudioMuter.journalFor(context)

    @Before
    fun reset() {
        journal.delete()
        CallAudioMuter.resetLeftoverCheckForTest()
        am.isMicrophoneMute = false
        am.mode = AudioManager.MODE_NORMAL
    }

    @Test
    fun aNormalCallWritesTheJournalAndRemovesItWhenReleased() {
        val muter = CallAudioMuter(am, journal = journal)
        assertTrue(muter.engage())
        assertTrue(am.isMicrophoneMute)
        assertTrue("written before muting", journal.isFile)
        muter.release()
        assertFalse(am.isMicrophoneMute)
        assertFalse(journal.exists())
    }

    @Test
    fun aKilledCallLeavesAJournalThatTheNextProcessStartUndoes() {
        CallAudioMuter(am, journal = journal).engage() // never released: the process "dies" here
        assertTrue(am.isMicrophoneMute)

        CallAudioMuter.recoverLeftover(context)
        assertFalse("microphone back on", am.isMicrophoneMute)
        assertFalse(journal.exists())
    }

    @Test
    fun aLeftoverIsKeptWhileACallIsUp() {
        CallAudioMuter(am, journal = journal).engage()
        am.mode = AudioManager.MODE_IN_CALL

        CallAudioMuter.recoverLeftover(context)
        assertTrue("never unmute during a call", am.isMicrophoneMute)
        assertTrue(journal.isFile)

        am.mode = AudioManager.MODE_NORMAL
        CallAudioMuter.recoverLeftover(context)
        assertFalse(am.isMicrophoneMute)
    }

    @Test
    fun aMicrophoneTheOwnerHadMutedStaysMuted() {
        am.isMicrophoneMute = true
        CallAudioMuter(am, journal = journal).engage()
        CallAudioMuter.recoverLeftover(context)
        assertTrue(am.isMicrophoneMute)
    }

    @Test
    fun aNewCallOverALeftoverKeepsTheStateFromBeforeTheKilledCall() {
        CallAudioMuter(am, journal = journal).engage() // killed call; the microphone was on before it
        val next = CallAudioMuter(am, journal = journal)
        assertTrue(next.engage())
        next.release()
        assertFalse("restored to the state before the killed call", am.isMicrophoneMute)
        assertEquals(false, journal.exists())
    }

    @Test
    fun onlyTheFirstCheckOfAProcessActs() {
        CallAudioMuter.recoverLeftover(context) // fresh process, nothing left over
        CallAudioMuter(am, journal = journal).engage() // a live call of this same process
        CallAudioMuter.recoverLeftover(context) // e.g. the activity is recreated mid-process
        assertTrue("a live mute of this process is not undone", am.isMicrophoneMute)
    }

    private fun plantSecureJournal(): File =
        File(context.noBackupFilesDir, "call_audio_mute_secure.journal").apply {
            parentFile?.mkdirs()
            writeText("mic=0\nvol=7\n")
        }

    private fun runningProcesses(vararg names: String) {
        val am = context.getSystemService(ActivityManager::class.java)
        shadowOf(am).setProcesses(names.map { ActivityManager.RunningAppProcessInfo(it, 1, null) })
    }

    @Test
    fun anOrphanOfADeadProcessIsRestoredFromAnotherProcess() {
        val j = plantSecureJournal()
        am.isMicrophoneMute = true
        runningProcesses(context.packageName + ":call")

        CallAudioMuter.recoverOrphan(context, "secure")
        assertFalse(am.isMicrophoneMute)
        assertFalse(j.exists())
    }

    @Test
    fun aJournalOfAProcessThatIsStillRunningIsLeftAlone() {
        val j = plantSecureJournal()
        am.isMicrophoneMute = true
        runningProcesses(context.packageName + ":secure")

        CallAudioMuter.recoverOrphan(context, "secure")
        assertTrue(am.isMicrophoneMute)
        assertTrue(j.isFile)
    }

    @Test
    fun anOrphanIsLeftAloneDuringACall() {
        val j = plantSecureJournal()
        am.isMicrophoneMute = true
        am.mode = AudioManager.MODE_IN_CALL
        runningProcesses()

        CallAudioMuter.recoverOrphan(context, "secure")
        assertTrue(am.isMicrophoneMute)
        assertTrue(j.isFile)
    }
}

