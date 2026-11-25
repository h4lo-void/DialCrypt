package io.github.h4lovoid.dialcrypt.core

/**
 * JNI bridge to libaegiscall_jni.so (secure-session-v2 §2.D and §6.6), loaded only in the
 * secure process. App objects and call sessions are opaque Long handles (0 = creation failed).
 * Rust never calls back into Kotlin: poll [nativeSessionPollEvents] and answer each event with
 * the matching call. Arrays passed in (PIN, text, labels, numbers, vault file) belong to the
 * caller, who zeroes them after the call returns; Rust zeroes its own copies. Length limits,
 * checked before Rust copies anything (-2 when exceeded): PIN 128 B, pairing code 256 B,
 * label 64 B, phone number 16 B, message text 4096 B.
 *
 * Return codes of the Int functions (values >= 0 are results):
 *    0 OK
 *   -1 invalid, closed or wrong-type handle, or a panic wipe is in progress
 *   -2 bad argument        -3 wrong state          -4 cryptographic failure
 *   -5 vault locked, dead (no ticket left) or wiped by the duress PIN
 *   -6 session aborted or ended                    -7 busy (queue full, capacity)
 *   -8 internal error
 *
 * Event TLV from nativeSessionPollEvents: records of type u8 · len u16 BE · value, back to back;
 * integers are big-endian.
 *    1 NEED_SIGNATURE    reqId u32 · message: sign with SHA256withECDSA, then nativeSessionSignResult
 *    2 SAS               5 raw bytes to show as words; then nativeSessionSas
 *    3 PATH              path u8 (0 full, 1 resume) · usedNew u8 · contact u32
 *    4 HS_PROGRESS       percent u8
 *    5 ESTABLISHED       role u8 (0 initiator, 1 responder) · path u8 · usedNew u8 · pathContact u32 ·
 *                        identity u8 (0 unverified, 1 SAS verified, 2 known contact, 3 key changed) ·
 *                        pskContact u32 · storedContact u32 (0 none) · peer pub33 (33 B)
 *    6 KEY_CHANGED       stored pub33 · peer pub33; sending stays locked until both SAS match. The
 *                        stored key came from the dialed contact or the caller ID and is a hint for
 *                        the screen: to update a contact the user picks it, see nativeSessionSaveContact
 *    7 SAS_CONFIRMED     empty; the contact may now be saved
 *    8 VOICE_WINDOW      open u8
 *    9 PQ_PROGRESS       percent u8
 *   10 PQ_MIXED          epoch u32
 *   11 EPOCH             epoch u32
 *   12 VAULT_DIRTY       seq u32: write nativeVaultExport() atomically (if it returns null, rotate:
 *                        nativeVaultRotateBegin, import, nativeVaultRotateCommit), fsync, then
 *                        nativeVaultSaved(app, seq)
 *   14 ATTESTATION       result i8 (0 ok, else a return code; -4 also when the chain does not hash
 *                        to the evidence id signed in the handshake) · boot u8 (0 verified,
 *                        1 self-signed, 2 unlocked) · osPatch u32 · stored u8. Full path only.
 *   15 MESSAGE_RECEIVED  msgId u16 · UTF-8 text
 *   16 MESSAGE_DELIVERED msgId u16
 *   17 MESSAGE_FAILED    msgId u16
 *   22 MESSAGE_PROGRESS  msgId u16 · acked u16 · total u16 (shards of an outgoing message the peer confirmed)
 *   18 REMOTE_WIPE       empty
 *   19 WIPE_SENT         empty
 *   20 ENDED            byPeer u8
 *   21 ABORTED           reason u8 (1 local user, 2 preamble timeout, 3 handshake timeout, 4 stall,
 *                        5 signer timeout, 6 signer failed, 7 incompatible version, 8 link protocol,
 *                        9 peer abort, 10-18 handshake checks, 19 SAS mismatch, 20 peer SAS mismatch,
 *                        21 ratchet, 22 cipher, 23 bulk, 24 bearer violation, 25 internal,
 *                        26 both sides dialed)
 *   32 VAULT_FAILED      code i8 (resume secret not stored)
 *
 * Byte layouts:
 *   trustTlv     ver u8 = 1 · records type u8 · len u16 · value (1 root DER, 2 revoked serial,
 *                3 AVB key, 4 app signer SHA-256, 5 min osPatch u32)
 *   chainTlv     repeated len u16 · DER, leaf first, root excluded
 *   rotation     n u8 · n × (ticketId u32 · material 32 B) · m u8 · m × retired ticketId u32
 *                (import each material as a single-use StrongBox HMAC key, commit, write the file,
 *                then use each retired ticket once and delete it)
 *   pinBegin     ticketId u32 · 32 B HMAC input for useTicket
 *   contactList  count u16 · per contact: id u32 · flags u8 · pub33 · labelLen u8 · label ·
 *                [boot u8 · osPatch u32 if flag 0x10] · [phoneTag 16 B if flag 0x20];
 *                flags 0x01 PSK, 0x02 SAS verified, 0x04 rsCur, 0x08 rsNew, 0x10 attested, 0x20 number
 *   quickCode    1 safe arrival, 2 surveillance, 3 hold silent, 4 rekey now, 5 GPS pin (lat/lon 1e-6 deg)
 */
object NativeBridge {
    init {
        System.loadLibrary("aegiscall_jni")
    }

    /** mlockall, not dumpable, no core files: 0 or -8. */
    external fun nativeHarden(): Int

    external fun nativeAppOpen(trustTlv: ByteArray): Long

    external fun nativeSetIdentity(app: Long, spkiDer: ByteArray, chainTlv: ByteArray): Int

    /** Creates the vault; returns the rotation layout (five tickets to import), then call nativeVaultRotateCommit. */
    external fun nativePinSetup(app: Long, pinUtf8: ByteArray, duressUtf8: ByteArray): ByteArray?

    external fun nativePinBegin(app: Long, vaultBlob: ByteArray, pinUtf8: ByteArray, liveTickets: IntArray): ByteArray?

    /** Phase 1 with the PIN stretch kept for fingerprint answer (32 bytes); same output and phase 2 as [nativePinBegin]. */
    external fun nativePinBeginStretch(app: Long, vaultBlob: ByteArray, stretch32: ByteArray, liveTickets: IntArray): ByteArray?

    /** 32-byte id of the vault's PIN stretch; the same for every file of one vault. Null for a malformed file. */
    external fun nativeVaultStretchBinding(vaultBlob: ByteArray): ByteArray?

    /** Ticket ids in the vault file's header (big-endian u32 each), read without unlocking. Null for a file that does not parse. */
    external fun nativeVaultTicketIds(vaultBlob: ByteArray): ByteArray?

    /** 1 normal, 2 duress, 0 wrong PIN, -5 no ticket left, -3 ticket not consumed. */
    external fun nativePinFinish(
        app: Long,
        vaultBlob: ByteArray,
        ticketId: Int,
        hmacOut: ByteArray?,
        liveTickets: IntArray,
    ): Int

    /**
     * 1 staged (rotate and write next), 0 wrong current PIN, 2 wrong current PIN and the vault is
     * locked now (third wrong one in this unlock), 3 the current PIN is the emergency PIN (wiped as
     * by nativePinFinish returning 2: run the duress path), < 0 error; -3 after a fingerprint unlock
     * or while the stretch is held (nativeStretchHeld).
     */
    external fun nativePinChange(
        app: Long,
        currentUtf8: ByteArray,
        pinUtf8: ByteArray,
        duressUtf8: ByteArray,
    ): Int

    /** The app keeps (true) or dropped (false) the PIN stretch of this unlock to turn fingerprint answer on; PIN changes are refused while held. */
    external fun nativeStretchHeld(app: Long, held: Boolean): Int

    external fun nativeVaultRotateBegin(app: Long): ByteArray?

    external fun nativeVaultRotateCommit(app: Long, imported: Boolean): ByteArray?

    /** Current vault file; null when locked or a rotation is required. Random bytes after the duress PIN. */
    external fun nativeVaultExport(app: Long): ByteArray?

    external fun nativeVaultSaved(app: Long, seq: Int): Int

    /** Our pairing code; null while locked or until [nativeSetPairingSeed] gave this app object the persisted seed. */
    external fun nativePairingCode(app: Long): String?

    /** Sets the persisted 32-byte pairing seed; the static X25519 pairing key is derived from it. */
    external fun nativeSetPairingSeed(app: Long, seed32: ByteArray): Int

    /** Seals contact metadata under the vault's meta key; null while the vault is locked. */
    external fun nativeMetaSeal(app: Long, plaintext: ByteArray): ByteArray?

    /** Opens a blob of [nativeMetaSeal]; null while the vault is locked, or for a blob of another key or a modified one. */
    external fun nativeMetaOpen(app: Long, sealed: ByteArray): ByteArray?

    /**
     * contactId 0 = the contact holding the code's key, or a new one named label. Otherwise that
     * contact must already hold the code's key (-3 if not). The PSK comes from an X25519 exchange
     * between our pairing key and the code's. Returns the contact id, plus
     * NativeCode.PAIRING_PSK_CHANGED when the stored PSK is new or different; -3 without a seed.
     */
    external fun nativeImportPairing(app: Long, contactId: Int, codeUtf8: ByteArray, labelUtf8: ByteArray?): Int

    /**
     * What nativeImportPairing with contactId 0 would do, changing nothing: 0 new contact, the id
     * of the contact holding the code's key, plus NativeCode.PAIRING_PSK_CHANGED when its PSK would change.
     */
    external fun nativePreviewPairing(app: Long, codeUtf8: ByteArray): Int

    /** Undoes the last nativeImportPairing of contactId after the vault could not be written. */
    external fun nativeImportRevert(app: Long, contactId: Int): Int

    external fun nativeContactList(app: Long): ByteArray?

    external fun nativeContactRename(app: Long, contactId: Int, labelUtf8: ByteArray): Int

    external fun nativeContactSetPhone(app: Long, contactId: Int, phoneE164Utf8: ByteArray?): Int

    external fun nativeContactDelete(app: Long, contactId: Int): Int

    /** dial = we placed the call (contactId 0 = typed number). peerE164Utf8 only feeds the KEY_CHANGED hint. */
    external fun nativeSessionCreate(
        app: Long,
        dial: Boolean,
        contactId: Int,
        peerE164Utf8: ByteArray?,
        wideband: Boolean,
        nowMs: Long,
    ): Long

    /** Like [nativeSessionCreate], selecting wire gear `1` (NB1200), `2` (WB2400), `3` (Robust300), or `4` (Speech300). */
    external fun nativeSessionCreateGear(
        app: Long,
        dial: Boolean,
        contactId: Int,
        peerE164Utf8: ByteArray?,
        gearCode: Int,
        nowMs: Long,
    ): Long

    /** PCM for the next slot; empty = voice window (send the microphone), null = session over. */
    external fun nativeSessionTxPcm(session: Long, nowMs: Long): ShortArray?

    external fun nativeSessionRxPcm(session: Long, pcm: ShortArray, nowMs: Long): Int

    external fun nativeSessionPollEvents(session: Long): ByteArray?

    external fun nativeSessionSignResult(session: Long, reqId: Int, ok: Boolean, derSig: ByteArray?): Int

    external fun nativeSessionSas(session: Long, ok: Boolean): Int

    external fun nativeSessionVoiceWindow(session: Long, open: Boolean): Int

    /**
     * After SAS_CONFIRMED. contactId 0 adds a new contact (number optional). contactId != 0 replaces
     * the key of the contact the user picked: allowed only when it holds the stored key reported by
     * KEY_CHANGED in this call and has no PSK (-3 otherwise); phoneE164Utf8 must then be null.
     * Returns the contact id; then persist the vault (rotation required).
     */
    external fun nativeSessionSaveContact(
        session: Long,
        contactId: Int,
        labelUtf8: ByteArray,
        phoneE164Utf8: ByteArray?,
    ): Int

    external fun nativeSessionBearerViolation(session: Long, code: Int): Int

    /** Returns the message id. */
    external fun nativeSessionSendText(session: Long, textUtf8: ByteArray, burnTtlSecs: Int, nowMs: Long): Int

    external fun nativeSessionSendQuick(session: Long, quickCode: Int, latE6: Int, lonE6: Int, nowMs: Long): Int

    external fun nativeSessionRequestRatchet(session: Long): Int

    /** notifyPeer = hang up (handle stays until called again with false); false = wipe and release. */
    external fun nativeSessionClose(session: Long, notifyPeer: Boolean): Int

    external fun nativePanicWipe(app: Long): Int

    external fun nativeAppClose(app: Long): Int
}
