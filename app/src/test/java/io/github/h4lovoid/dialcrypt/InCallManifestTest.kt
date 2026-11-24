package io.github.h4lovoid.dialcrypt

import java.io.File
import javax.xml.parsers.DocumentBuilderFactory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.w3c.dom.Element

/** Telecom tells the two InCallServices apart by their meta-data; both live in `:call`. */
class InCallManifestTest {
    private val ns = "http://schemas.android.com/apk/res/android"
    private val manifest = File(File(System.getProperty("aegis.resDir") ?: "src/main/res").parentFile, "AndroidManifest.xml")
    private val doc = DocumentBuilderFactory.newInstance().apply { isNamespaceAware = true }.newDocumentBuilder().parse(manifest)

    private fun elements(tag: String): List<Element> {
        val list = doc.getElementsByTagName(tag)
        return (0 until list.length).map { list.item(it) as Element }
    }

    private fun component(tag: String, name: String): Element = elements(tag).single { it.getAttributeNS(ns, "name") == name }

    private fun meta(e: Element): Map<String, String> {
        val list = e.getElementsByTagName("meta-data")
        return (0 until list.length).map { list.item(it) as Element }.associate { it.getAttributeNS(ns, "name") to it.getAttributeNS(ns, "value") }
    }

    private fun actions(e: Element): List<String> {
        val list = e.getElementsByTagName("action")
        return (0 until list.length).map { (list.item(it) as Element).getAttributeNS(ns, "name") }
    }

    private fun assertInCallService(e: Element) {
        assertEquals(":call", e.getAttributeNS(ns, "process"))
        assertEquals("android.permission.BIND_INCALL_SERVICE", e.getAttributeNS(ns, "permission"))
        assertEquals("true", e.getAttributeNS(ns, "exported"))
        assertTrue(actions(e).contains("android.telecom.InCallService"))
    }

    @Test
    fun theNonUiServiceKeepsScreening() {
        val s = component("service", ".incoming.IncomingCallService")
        assertInCallService(s)
        assertEquals("false", meta(s)["android.telecom.IN_CALL_SERVICE_UI"])
        assertEquals("true", meta(s)["android.telecom.IN_CALL_SERVICE_RINGING"])
    }

    @Test
    fun theDialerServiceIsTheUiAndLeavesRingingToTelecom() {
        val s = component("service", ".dialer.DialerInCallService")
        assertInCallService(s)
        assertEquals("true", meta(s)["android.telecom.IN_CALL_SERVICE_UI"])
        assertEquals("false", meta(s)["android.telecom.IN_CALL_SERVICE_RINGING"])
    }

    @Test
    fun theCallActionReceiverIsPrivate() {
        val r = component("receiver", ".dialer.CallActionReceiver")
        assertEquals("false", r.getAttributeNS(ns, "exported"))
        assertEquals(":call", r.getAttributeNS(ns, "process"))
    }

    @Test
    fun wakeLockIsDeclared() {
        assertTrue(elements("uses-permission").any { it.getAttributeNS(ns, "name") == "android.permission.WAKE_LOCK" })
    }
}
