package io.github.h4lovoid.dialcrypt

import io.github.h4lovoid.dialcrypt.core.InviteCard
import io.github.h4lovoid.dialcrypt.core.PairingCodeCodec
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.Base64
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class InviteCardTest {
    // ---- confirmation code ---------------------------------------------------------------------

    @Test
    fun fingerprintIsTwelveDigitsInGroupsOfThree() {
        val fp = InviteCard("Alice", null, code(1), 42L).fingerprint()
        assertNotNull(fp)
        assertTrue(fp!!, Regex("^\\d{3} \\d{3} \\d{3} \\d{3}$").matches(fp))
    }

    @Test
    fun fingerprintFollowsTheDocumentedV2Hash() {
        val raw = raw(7)
        val nonce = 0x0102030405060708L
        val expected = digits(
            sha256(
                "AegisCard-fp-v2".toByteArray(Charsets.US_ASCII),
                raw,
                ByteBuffer.allocate(8).putLong(nonce).array(),
                byteArrayOf(10),
                "5551234567".toByteArray(),
                byteArrayOf(6),
                "\u20AC\u20AC".toByteArray(Charsets.UTF_8),
            ),
        )
        assertEquals(expected, InviteCard("\u20AC\u20AC", "5551234567", PairingCodeCodec.encode(raw)!!, nonce).fingerprint())
    }

    @Test
    fun aCardWithoutNonceUsesTheV1HashOverTheSameFields() {
        val raw = raw(8)
        val expected = digits(
            sha256("AegisCard-fp-v1".toByteArray(Charsets.US_ASCII), raw, byteArrayOf(0), byteArrayOf(3), "Bob".toByteArray()),
        )
        assertEquals(expected, InviteCard("Bob", null, PairingCodeCodec.encode(raw)!!).fingerprint())
        assertNotEquals(expected, InviteCard("Bob", null, PairingCodeCodec.encode(raw)!!, 0L).fingerprint())
    }

    @Test
    fun fingerprintBindsCodeNonceNameAndNumber() {
        val base = InviteCard("Alice", "5551234567", code(1), 9L)
        assertEquals(base.fingerprint(), base.copy().fingerprint())
        assertNotEquals(base.fingerprint(), base.copy(nonce = 10L).fingerprint())
        assertNotEquals(base.fingerprint(), base.copy(name = "Alicia").fingerprint())
        assertNotEquals(base.fingerprint(), base.copy(number = "5551234568").fingerprint())
        assertNotEquals(base.fingerprint(), base.copy(number = null).fingerprint())
        assertNotEquals(base.fingerprint(), base.copy(code = code(2)).fingerprint())
        // A hidden direction override does not change the code: the name is cleaned first.
        assertEquals(base.fingerprint(), base.copy(name = "\u202EAlice\u200B").fingerprint())
    }

    @Test
    fun thePhoneShowingTheCardAndThePhoneScanningItSeeTheSameCode() {
        val sent = InviteCard("  " + "\u20AC".repeat(30) + " ", "+447700900101", code(3), InviteCard.newNonce())
        val wire = sent.wireCopy()!!
        val heard = InviteCard.fromCompactBytes(sent.toCompactBytes()!!)!!
        assertEquals(wire, heard)
        assertEquals(wire.fingerprint(), heard.fingerprint())
        assertEquals(wire.fingerprint(), InviteCard.parse(sent.toTextCard()!!)!!.fingerprint())
    }

    @Test
    fun everyCardGetsItsOwnNonceAndCode() {
        val nonces = (1..20).map { InviteCard.newNonce() }.toSet()
        assertEquals(20, nonces.size)
        val a = InviteCard("Alice", null, code(1), InviteCard.newNonce()).fingerprint()
        val b = InviteCard("Alice", null, code(1), InviteCard.newNonce()).fingerprint()
        assertNotEquals(a, b)
    }

    @Test
    fun fingerprintRejectsInvalidCodes() {
        assertNull(InviteCard("A", null, "", 1L).fingerprint())
        assertNull(InviteCard("A", null, "AEGIS2-AAAAA", 1L).fingerprint())
        val good = code(3)
        // One changed character breaks the checksum.
        val broken = good.substring(0, 10) + (if (good[10] == 'A') 'B' else 'A') + good.substring(11)
        assertNull(InviteCard("A", null, broken, 1L).fingerprint())
    }

    // ---- compact format ------------------------------------------------------------------------

    @Test
    fun versionTwoCarriesTheNonceAndVersionOneStillParses() {
        val v2 = InviteCard("Alice", "5551234567", code(4), -7L)
        val bytes = v2.toCompactBytes()!!
        assertEquals(2, bytes[0].toInt())
        assertTrue(bytes.size <= 154)
        assertEquals(v2, InviteCard.fromCompactBytes(bytes))
        assertEquals(v2, InviteCard.parse(v2.toTextCard()!!))

        val v1 = InviteCard("Alice", "5551234567", code(4))
        val old = v1.toCompactBytes()!!
        assertEquals(1, old[0].toInt())
        val parsed = InviteCard.fromCompactBytes(old)!!
        assertNull(parsed.nonce)
        assertEquals(v1, parsed)
    }

    @Test
    fun aLongNameIsShortenedSoTheVersionTwoCardStillFits() {
        val card = InviteCard("\uD83D\uDE00".repeat(20), "+12345678901234", code(5), 1L)
        val bytes = card.toCompactBytes()!!
        assertTrue(bytes.size <= 154)
        val heard = InviteCard.fromCompactBytes(bytes)!!
        assertTrue(heard.name.isNotEmpty())
        assertEquals(1L, heard.nonce)
    }

    // ---- pairing receipt -----------------------------------------------------------------------

    @Test
    fun aReplyTagCountsOnlyForTheCardThatWasShown() {
        val aCode = code(10)
        val bCode = code(11)
        val bSent = InviteCard("Bob", null, bCode, 1234L)
        // A saved Bob's card and shows its own card tagged for it.
        val tag = InviteCard.replyTag(bSent, aCode)!!
        val reply = InviteCard("Ann", null, aCode, 5L, tag)

        assertTrue(InviteCard.answers(reply, bSent))
        assertFalse("other nonce", InviteCard.answers(reply, bSent.copy(nonce = 1235L)))
        assertFalse("other sender", InviteCard.answers(reply.copy(code = code(12)), bSent))
        assertFalse("other own key", InviteCard.answers(reply, bSent.copy(code = code(13))))
        val flipped = (if (tag[0] == '0') "1" else "0") + tag.substring(1)
        assertFalse("tampered tag", InviteCard.answers(reply.copy(replyTo = flipped), bSent))
        assertFalse("short tag", InviteCard.answers(reply.copy(replyTo = tag.substring(0, 30)), bSent))
    }

    @Test
    fun theReplyTagFollowsTheDocumentedHashAndHoldsNoSecret() {
        val aRaw = raw(20)
        val bRaw = raw(21)
        val nonce = 77L
        val tag = InviteCard.replyTag(InviteCard("", null, PairingCodeCodec.encode(bRaw)!!, nonce), PairingCodeCodec.encode(aRaw)!!)!!
        val hash = sha256(
            "AegisCard-ack-v2".toByteArray(Charsets.US_ASCII),
            bRaw,
            aRaw,
            ByteBuffer.allocate(8).putLong(nonce).array(),
        )
        val tagBytes = hash.copyOf(16)
        assertEquals(tagBytes.joinToString("") { "%02x".format(it.toInt() and 0xFF) }, tag)
    }

    @Test
    fun aReplyWithAContactsKeyAndAnotherPairingKeyIsNotAnAnswer() {
        val aliceCode = code(30)
        val bobCode = code(31)
        val ours = InviteCard("Alice", null, aliceCode, 4321L)
        // Bob saved our card and shows his own, tagged for it.
        val genuine = InviteCard("Bob", null, bobCode, 9L, InviteCard.replyTag(ours, bobCode))
        assertTrue(InviteCard.answers(genuine, ours))
        // Someone keeps Bob's identity key and tag but puts their own pairing key in the code.
        val raw = PairingCodeCodec.decode(bobCode)!!
        for (i in 34 until 66) raw[i] = (raw[i].toInt() xor 0x5A).toByte()
        raw[65] = (raw[65].toInt() and 0x7F).toByte()
        val fakeCode = PairingCodeCodec.encode(withCrc(raw))!!
        val fake = genuine.copy(code = fakeCode)
        assertTrue("same identity key", PairingCodeCodec.decode(fakeCode)!!.copyOfRange(1, 34).contentEquals(raw.copyOfRange(1, 34)))
        assertFalse(InviteCard.answers(fake, ours))
    }

    private fun withCrc(raw: ByteArray): ByteArray {
        var crc = 0xFFFF
        for (i in 0 until 66) {
            crc = crc xor ((raw[i].toInt() and 0xFF) shl 8)
            repeat(8) {
                crc = if ((crc and 0x8000) != 0) ((crc shl 1) xor 0x1021) and 0xFFFF else (crc shl 1) and 0xFFFF
            }
        }
        raw[66] = ((crc ushr 8) and 0xFF).toByte()
        raw[67] = (crc and 0xFF).toByte()
        return raw
    }

    @Test
    fun aCardWithoutNonceCannotBeAnswered() {
        assertNull(InviteCard.replyTag(InviteCard("Old", null, code(14)), code(15)))
    }

    // ---- name cleaning -------------------------------------------------------------------------

    @Test
    fun sanitizeNameRemovesDirectionOverridesAndZeroWidthCharacters() {
        assertEquals("evil.exe", InviteCard.sanitizeName("\u202Eevil.exe"))
        assertEquals("Mama", InviteCard.sanitizeName("\u2066Ma\u200Bm\u200Da\u2069\uFEFF"))
        assertEquals("ab", InviteCard.sanitizeName("a\u202A\u202B\u202C\u202D\u2067\u2068\u200E\u200Fb"))
    }

    @Test
    fun sanitizeNameRemovesControlPrivateUnassignedAndEnclosingMarks() {
        assertEquals("abc", InviteCard.sanitizeName("a\u0000b\u0007\u001Bc\u007F"))
        assertEquals("ab", InviteCard.sanitizeName("a\uE000\u0378b"))
        assertEquals("ab", InviteCard.sanitizeName("a\uD800b")) // lone surrogate
        assertEquals("A1", InviteCard.sanitizeName("A\u20DD1\u20E3"))
    }

    @Test
    fun sanitizeNameAppliesNfkc() {
        assertEquals("ABC file 1", InviteCard.sanitizeName("\uFF21\uFF22\uFF23 \uFB01le \u2460"))
        // A decomposed Vietnamese name ends up composed.
        assertEquals("Nguy\u1EC5n", InviteCard.sanitizeName("Nguye\u0302\u0303n"))
        // Removing a zero-width space lets the letter and its accent join.
        assertEquals("\u00E9", InviteCard.sanitizeName("e\u200B\u0301"))
    }

    @Test
    fun sanitizeNameCutsStackedMarksButKeepsRealScripts() {
        assertEquals("x\u0300\u0301y", InviteCard.sanitizeName("x\u0300\u0301\u0302\u0303\u0304\u0305y"))
        assertEquals("x\u0300\u0301", InviteCard.sanitizeName("x\u0300\u200B\u0301\u0302"))
        val vietnamese = "Nguy\u1EC5n Th\u1ECB Minh Khai"
        assertEquals(vietnamese, InviteCard.sanitizeName(vietnamese))
        val hindi = "\u0939\u093F\u0928\u094D\u0926\u0940 \u0915\u094D\u0937\u093F\u0924\u093F\u091C"
        assertEquals(hindi, InviteCard.sanitizeName(hindi))
    }

    @Test
    fun sanitizeNameTurnsLineBreaksIntoSingleSpacesAndTrims() {
        assertEquals("Line one Line two x y", InviteCard.sanitizeName("  Line one\nLine two\r\n \t x\u2028\u00A0y \n"))
        assertEquals("", InviteCard.sanitizeName(" \n\u200B\t "))
        assertEquals("\u20AC\u20AC\u20AC Alice", InviteCard.sanitizeName("\u20AC\u20AC\u20AC\u3000Alice"))
    }

    @Test
    fun sanitizeNameKeepsAtMostFortyCharactersWithoutSplittingOne() {
        assertEquals("a".repeat(40), InviteCard.sanitizeName("a".repeat(50)))
        val emoji = "\uD83D\uDE00"
        assertEquals("a".repeat(39), InviteCard.sanitizeName("a".repeat(39) + emoji))
        assertEquals("a".repeat(38) + emoji, InviteCard.sanitizeName("a".repeat(38) + emoji + "b"))
        // Removed characters do not count toward the limit.
        assertEquals("b".repeat(40), InviteCard.sanitizeName("\u202E".repeat(30) + "b".repeat(45)))
    }

    @Test
    fun fromCompactBytesAndParseCleanTheReceivedName() {
        val code = code(5)
        for (version in listOf(1, 2)) {
            val compact = compact(version, code, "\u202Emom\u200B\nhome\u0007", "+447700900101")
            val card = InviteCard.fromCompactBytes(compact)
            assertNotNull(card)
            assertEquals("mom home", card!!.name)
            assertEquals("+447700900101", card.number)
            assertEquals(code, card.code)
            assertEquals(if (version == 2) 99L else null, card.nonce)

            val text = "AEGISCARD1:" + Base64.getUrlEncoder().withoutPadding().encodeToString(compact)
            assertEquals(card, InviteCard.parse(text))

            val long = InviteCard.fromCompactBytes(compact(version, code, "x".repeat(60), null))
            assertEquals("x".repeat(40), long!!.name)
        }
        assertNull(InviteCard.fromCompactBytes(compact(3, code, "x", null)))
    }

    @Test
    fun aTaggedReplyRoundTripsAsVersionThreeAndProvesTheSenderSavedOurCard() {
        val sent = InviteCard("ann", null, code(1), 11L)
        val tag = InviteCard.replyTag(sent, code(2))!!
        assertEquals(32, tag.length)
        val reply = InviteCard("bob", "5551234567", code(2), 22L, tag)
        val bytes = reply.toCompactBytes()!!
        assertEquals(3, bytes[0].toInt())
        val decoded = InviteCard.fromCompactBytes(bytes)!!
        assertEquals(tag, decoded.replyTo)
        assertEquals(22L, decoded.nonce)
        assertTrue(InviteCard.answers(decoded, sent))
        assertEquals(decoded, InviteCard.parse(reply.toTextCard()!!))
    }

    @Test
    fun aTagForAnotherCardOrAnotherSenderDoesNotCount() {
        val sent = InviteCard("ann", null, code(1), 11L)
        val other = InviteCard("ann", null, code(1), 12L)
        assertFalse(InviteCard.answers(InviteCard("bob", null, code(2), 22L, InviteCard.replyTag(other, code(2))), sent))
        assertFalse(InviteCard.answers(InviteCard("bob", null, code(2), 22L, InviteCard.replyTag(sent, code(3))), sent))
        assertFalse(InviteCard.answers(InviteCard("bob", null, code(2), 22L), sent))
        assertNull("a tag needs a nonce", InviteCard("bob", null, code(2), null, InviteCard.replyTag(sent, code(2))).toCompactBytes())
        assertNull("a malformed tag is rejected", InviteCard("bob", null, code(2), 22L, "zz").toCompactBytes())
    }

    @Test
    fun theConfirmationCodeCoversTheReplyTag() {
        val sent = InviteCard("ann", null, code(1), 11L)
        val plain = InviteCard("bob", null, code(2), 22L)
        val tagged = plain.copy(replyTo = InviteCard.replyTag(sent, code(2)))
        assertNotEquals(plain.fingerprint(), tagged.fingerprint())
        assertEquals(tagged.fingerprint(), tagged.wireCopy()!!.fingerprint())
    }

    /** Builds the compact form by hand so the name reaches the decoder unchanged. */
    private fun compact(version: Int, code: String, name: String, number: String?): ByteArray {
        val raw = PairingCodeCodec.decode(code)!!
        val phone = number?.toByteArray(Charsets.UTF_8) ?: ByteArray(0)
        val nameBytes = name.toByteArray(Charsets.UTF_8)
        val out = ByteArrayOutputStream()
        out.write(version)
        out.write(raw)
        if (version != 1) out.write(ByteBuffer.allocate(8).putLong(99L).array())
        out.write(phone.size)
        out.write(phone)
        out.write(nameBytes.size)
        out.write(nameBytes)
        return out.toByteArray()
    }

    private fun sha256(vararg parts: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").run {
            parts.forEach { update(it) }
            digest()
        }

    private fun digits(digest: ByteArray): String {
        var value = 0L
        for (i in 0 until 5) value = (value shl 8) or (digest[i].toLong() and 0xFF)
        return (value % 1_000_000_000_000L).toString().padStart(12, '0').chunked(3).joinToString(" ")
    }

    private fun code(seed: Int): String = PairingCodeCodec.encode(raw(seed))!!

    private fun raw(seed: Int): ByteArray {
        val raw = ByteArray(PairingCodeCodec.RAW_LEN)
        raw[0] = 3
        for (i in 1 until 66) raw[i] = ((i * 37 + seed * 101 + 5) and 0xFF).toByte()
        var crc = 0xFFFF
        for (i in 0 until 66) {
            crc = crc xor ((raw[i].toInt() and 0xFF) shl 8)
            repeat(8) {
                crc = if ((crc and 0x8000) != 0) ((crc shl 1) xor 0x1021) and 0xFFFF else (crc shl 1) and 0xFFFF
            }
        }
        raw[66] = ((crc ushr 8) and 0xFF).toByte()
        raw[67] = (crc and 0xFF).toByte()
        return raw
    }
}
