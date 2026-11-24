package io.github.h4lovoid.dialcrypt.dialer

import java.io.File
import javax.xml.parsers.DocumentBuilderFactory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.w3c.dom.Element

/**
 * A release build cannot be chosen as the phone app: the default dialer components are disabled in
 * its manifest through the dialerComponentsEnabled placeholder, which only debug and field-test builds turn on.
 */
class DialerComponentsBuildTest {
    private val ns = "http://schemas.android.com/apk/res/android"
    private val mainDir = File(System.getProperty("aegis.resDir") ?: "src/main/res").parentFile
    private val appDir = mainDir.parentFile.parentFile
    private val placeholder = "\${dialerComponentsEnabled}"

    private fun buildTypeBlock(text: String, start: String, end: String?): String {
        val from = text.indexOf(start)
        val to = if (end == null) text.indexOf("sourceSets", from) else text.indexOf(end, from)
        assertTrue("block $start not found", from >= 0 && to > from)
        return text.substring(from, to)
    }

    private fun placeholderValue(block: String): String? =
        Regex("manifestPlaceholders\\[\"dialerComponentsEnabled\"]\\s*=\\s*\"(true|false)\"").find(block)?.groupValues?.get(1)

    @Test
    fun onlyDebugAndFieldTestEnableTheDialerComponents() {
        val text = File(appDir, "build.gradle.kts").readText()
        assertEquals("true", placeholderValue(buildTypeBlock(text, "getByName(\"debug\")", "getByName(\"release\")")))
        assertEquals("false", placeholderValue(buildTypeBlock(text, "getByName(\"release\")", "create(\"fieldTest\")")))
        assertEquals("true", placeholderValue(buildTypeBlock(text, "create(\"fieldTest\")", null)))
    }

    @Test
    fun theDialerComponentsFollowThePlaceholder() {
        val doc = DocumentBuilderFactory.newInstance().apply { isNamespaceAware = true }.newDocumentBuilder()
            .parse(File(mainDir, "AndroidManifest.xml"))
        fun component(tag: String, name: String): Element {
            val list = doc.getElementsByTagName(tag)
            return (0 until list.length).map { list.item(it) as Element }.single { it.getAttributeNS(ns, "name") == name }
        }
        val gated = listOf(
            "activity" to ".dialer.DialpadActivity",
            "service" to ".dialer.DialerInCallService",
            "service" to ".dialer.AllowAllScreeningService",
            "receiver" to ".dialer.MissedCallReceiver",
        )
        for ((tag, name) in gated) {
            assertEquals(name, placeholder, component(tag, name).getAttributeNS(ns, "enabled"))
        }
        // The launcher alias stays off until DialerRole turns it on while the role is held.
        assertEquals("false", component("activity-alias", ".dialer.PhoneLauncher").getAttributeNS(ns, "enabled"))
        // No other component answers DIAL.
        val actions = doc.getElementsByTagName("action")
        val dialOwners = (0 until actions.length).map { actions.item(it) as Element }
            .filter { it.getAttributeNS(ns, "name") == "android.intent.action.DIAL" }
            .map { (it.parentNode.parentNode as Element).getAttributeNS(ns, "name") }
            .toSet()
        assertEquals(setOf(".dialer.DialpadActivity"), dialOwners)
    }
}
