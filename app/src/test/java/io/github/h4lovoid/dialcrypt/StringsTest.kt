package io.github.h4lovoid.dialcrypt

import java.io.File
import javax.xml.parsers.DocumentBuilderFactory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class StringsTest {
    private val resDir = File(System.getProperty("aegis.resDir") ?: "src/main/res")

    private fun load(dir: String): Map<String, String> {
        val doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(File(resDir, "$dir/strings.xml"))
        val nodes = doc.getElementsByTagName("string")
        return (0 until nodes.length).associate { i ->
            val n = nodes.item(i)
            n.attributes.getNamedItem("name").nodeValue to n.textContent
        }
    }

    private val en get() = load("values")
    private val es get() = load("values-es")
    private val fr get() = load("values-fr")
    private val zh get() = load("values-b+zh+Hans")
    private val all get() = mapOf("en" to en, "es" to es, "fr" to fr, "zh-Hans" to zh)

    @Test
    fun fourLanguagesDefineTheSameNames() {
        assertTrue(en.isNotEmpty())
        assertEquals(en.keys, es.keys)
        assertEquals(en.keys, fr.keys)
        assertEquals(en.keys, zh.keys)
    }

    @Test
    fun placeholdersMatchAcrossLanguages() {
        val pattern = Regex("%(\\d+\\$)?[sd]")
        for ((name, text) in en) {
            val expected = pattern.findAll(text).map { it.value }.sorted().toList()
            for ((lang, map) in all) {
                assertEquals(lang + ":" + name, expected, pattern.findAll(map.getValue(name)).map { it.value }.sorted().toList())
            }
            // A literal percent sign must be written as %% in every language.
            val literal = Regex("%%")
            for ((lang, map) in all) {
                assertEquals(lang + ":" + name, literal.findAll(text).count(), literal.findAll(map.getValue(name)).count())
            }
        }
    }

    private fun hasHan(text: String) = text.any { Character.UnicodeScript.of(it.code) == Character.UnicodeScript.HAN }

    @Test
    fun noValueIsEmptyAndChineseOnlyWhereItBelongs() {
        all.values.forEach { map -> map.forEach { (name, text) -> assertFalse("empty " + name, text.isBlank()) } }
        listOf(en, es, fr).forEach { map ->
            map.forEach { (name, text) ->
                // The language picker names Simplified Chinese in its own script in every language.
                if (name == "lang_zh_hans") assertEquals("简体中文", text) else assertFalse("han in " + name, hasHan(text))
            }
        }
        // Only identifiers and the other languages' own names may lack Chinese characters.
        val withoutHan = zh.filter { !hasHan(it.value) }.keys
        assertEquals(setOf("kb_numbers", "kb_letters", "connect_percent", "lang_en", "lang_es", "lang_fr"), withoutHan)
    }

    @Test
    fun launcherLabelLooksLikeAPlainNotesApp() {
        assertEquals("Notes", en.getValue("launcher_label"))
        assertEquals("Notas", es.getValue("launcher_label"))
        assertEquals("Notes", fr.getValue("launcher_label"))
        assertEquals("备忘录", zh.getValue("launcher_label"))
    }

    @Test
    fun chineseDoesNotKeepEnglishSentences() {
        // Catches an entry that was copied over without being translated.
        zh.forEach { (name, text) ->
            if (name != "lang_en" && name != "lang_es" && name != "lang_fr" && text.length > 20) {
                assertTrue("not translated: " + name, hasHan(text))
            }
        }
    }

    @Test
    fun verificationWordListIsNotDefinedHere() {
        // sas_words.xml is supplied separately; strings.xml must not carry a copy.
        all.values.forEach { assertFalse(it.containsKey("sas_words")) }
        assertFalse(File(resDir, "values/sas_words.xml").exists() && File(resDir, "values/strings.xml").readText().contains("sas_words"))
    }

    @Test
    fun pinScreensNameNeitherTheVaultNorTheProduct() {
        val banned = Regex("vault|almac\u00E9n|coffre|\u4FDD\u9669\u5E93|aegis|dialcrypt|shield|escudo|bouclier|\u76FE", RegexOption.IGNORE_CASE)
        val keys = listOf("unlock_title", "unlock_caption", "unlock_hint", "unlock_action", "destroyed_title", "destroyed_body")
        for ((lang, map) in all) {
            for (key in keys) assertFalse(lang + ":" + key, banned.containsMatchIn(map.getValue(key)))
        }
        assertEquals("Enter PIN", en.getValue("unlock_title"))
        assertEquals("Enter your PIN to continue.", en.getValue("unlock_caption"))
    }

    @Test
    fun mainActionsUsePlainWords() {
        assertEquals("Call", en.getValue("home_start_call"))
        assertEquals("Reset", en.getValue("danger_zone"))
        assertEquals("Erase all data", en.getValue("settings_wipe"))
        assertEquals("Erase all data", en.getValue("wipe_action"))
        // The short protection words and the progress-free sending label exist in every language.
        val shortKeys = listOf("protect_short_ready", "protect_short_working", "protect_short_failed", "protect_short_idle", "protect_short_unavailable")
        for ((lang, map) in all) {
            for (key in shortKeys + listOf("msg_sending_unknown", "add_camera_settings", "back_hangup_title", "back_end_title")) {
                assertTrue(lang + ":" + key, map.getValue(key).isNotBlank())
            }
            assertFalse(lang + ":msg_sending_unknown", map.getValue("msg_sending_unknown").contains("%"))
        }
        assertEquals("Ready", en.getValue("protect_short_ready"))
    }

    @Test
    fun theEndingScreenSaysTheAppWillClose() {
        assertEquals("Cleared. The app will now close.", en.getValue("ending_closing"))
    }
}
