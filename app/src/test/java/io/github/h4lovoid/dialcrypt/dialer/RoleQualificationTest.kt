package io.github.h4lovoid.dialcrypt.dialer

import android.Manifest
import android.app.Application
import android.content.ComponentName
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.telecom.CallScreeningService
import android.telecom.InCallService
import android.telecom.TelecomManager
import androidx.test.core.app.ApplicationProvider
import java.io.File
import javax.xml.parsers.DocumentBuilderFactory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.w3c.dom.Element

/** What the system's default phone app role needs from the manifest, resolved the way the system resolves it. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class RoleQualificationTest {
    private val app: Application = ApplicationProvider.getApplicationContext()
    private val pm: PackageManager get() = app.packageManager

    private val pkg = "io.github.h4lovoid.dialcrypt"
    private val dialpad = "$pkg.dialer.DialpadActivity"
    private val inCallService = "$pkg.dialer.DialerInCallService"
    private val inCallActivity = "$pkg.dialer.InCallActivity"
    private val screening = "$pkg.dialer.AllowAllScreeningService"
    private val launcherAlias = "$pkg.dialer.PhoneLauncher"

    private fun activitiesFor(intent: Intent): List<String> =
        pm.queryIntentActivities(intent, PackageManager.MATCH_DEFAULT_ONLY).map { it.activityInfo.name }

    private fun service(name: String) = pm.getServiceInfo(ComponentName(app.packageName, name), PackageManager.GET_META_DATA)

    // ---- dial pad: the three intents the role requires --------------------------------------------

    @Test
    fun dialWithoutDataOpensTheDialpad() {
        assertTrue(activitiesFor(Intent(Intent.ACTION_DIAL)).toString(), dialpad in activitiesFor(Intent(Intent.ACTION_DIAL)))
    }

    @Test
    fun dialWithATelNumberOpensTheDialpad() {
        val intent = Intent(Intent.ACTION_DIAL, Uri.parse("tel:5551234"))
        assertTrue(activitiesFor(intent).toString(), dialpad in activitiesFor(intent))
    }

    @Test
    fun viewWithATelNumberOpensTheDialpad() {
        val intent = Intent(Intent.ACTION_VIEW, Uri.parse("tel:5551234"))
        assertTrue(activitiesFor(intent).toString(), dialpad in activitiesFor(intent))
    }

    @Test
    fun theCallButtonOpensTheDialpad() {
        val intent = Intent(Intent.ACTION_CALL_BUTTON)
        assertTrue(activitiesFor(intent).toString(), dialpad in activitiesFor(intent))
    }

    @Test
    fun theDialpadIsExportedForOtherApps() {
        val info = pm.getActivityInfo(ComponentName(app.packageName, dialpad), 0)
        assertTrue(info.exported)
    }

    // ---- in-call service ----------------------------------------------------------------------------

    @Test
    fun theUiInCallServiceIsProtectedAndDeclaresItsUi() {
        val info = service(inCallService)
        assertEquals(Manifest.permission.BIND_INCALL_SERVICE, info.permission)
        assertTrue(info.exported)
        assertEquals("true", info.metaData.get(TelecomManager.METADATA_IN_CALL_SERVICE_UI).toString())
        val bound = pm.queryIntentServices(Intent(InCallService.SERVICE_INTERFACE).setPackage(app.packageName), PackageManager.GET_META_DATA)
            .map { it.serviceInfo.name }
        assertTrue(bound.toString(), inCallService in bound)
    }

    @Test
    fun theInCallScreenCannotBeStartedByOtherApps() {
        val info = pm.getActivityInfo(ComponentName(app.packageName, inCallActivity), 0)
        assertFalse(info.exported)
    }

    // ---- call screening role ------------------------------------------------------------------------

    @Test
    fun theScreeningServiceIsProtectedByTheScreeningPermission() {
        val info = service(screening)
        assertEquals(Manifest.permission.BIND_SCREENING_SERVICE, info.permission)
        val found = pm.queryIntentServices(Intent(CallScreeningService.SERVICE_INTERFACE).setPackage(app.packageName), 0)
            .map { it.serviceInfo.name }
        assertTrue(found.toString(), screening in found)
    }

    // ---- launcher entry -----------------------------------------------------------------------------

    @Test
    fun thePhoneLauncherEntryIsDisabledUntilTheRoleIsHeld() {
        // Read from the manifest file: PackageManager reports a manifest-disabled component as DEFAULT, which would hide the attribute.
        val ns = "http://schemas.android.com/apk/res/android"
        val manifest = File(File(System.getProperty("aegis.resDir") ?: "src/main/res").parentFile, "AndroidManifest.xml")
        val doc = DocumentBuilderFactory.newInstance().apply { isNamespaceAware = true }.newDocumentBuilder().parse(manifest)
        val aliases = doc.getElementsByTagName("activity-alias")
        val alias = (0 until aliases.length).map { aliases.item(it) as Element }
            .single { it.getAttributeNS(ns, "name") == ".dialer.PhoneLauncher" }
        assertEquals("false", alias.getAttributeNS(ns, "enabled"))
        assertEquals(".dialer.DialpadActivity", alias.getAttributeNS(ns, "targetActivity"))
        assertEquals(launcherAlias, DialerRole.PHONE_LAUNCHER)
    }
}
