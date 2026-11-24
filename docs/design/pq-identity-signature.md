<!-- This file is an addendum (6.12) to section 6 of secure-session-v2.md. -->

# 6.12 Hardware Post-Quantum Identity Signature

## Final revisions (after review; where they conflict with the text below, this section prevails)

Status: design is final, not yet implemented. All Android 17 Keystore details are to be confirmed on a Pixel 11 device (see item 7).

**R1 First pinning accepts only the verification words.** The first pin is written only after both sides' SAS match on this call. Neither quick connect (resume) nor a PSK can serve alone as a condition, because rs and the PSK both live in the vault: if vault secrets leak and an attacker can also forge ECDSA with a quantum computer, the attacker could pin their own public key onto the real peer and lock that peer out permanently. The term "post-quantum secure" below is used only to decide whether to lock sending; it is no longer a pinning condition, and "pin immediately on the next resume after an upgrade" is void.
- The contact page gains "Enable post-quantum identity with verification words": on the next call the caller fills rid0/rid1 with random values, which forces the full path to run to completion and compare the SAS; the wire format does not change.
- The way to recover from a wrong pin is to delete the contact, compare again, and save; there is no separate update path.
- `pin_pq` must set `rotation_required` (rotate per 6.5); it must not follow `set_attestation`, which does not rotate.

**R2 Strict mode.** For a pinned contact on resume, sending is not locked by default, and the hard timeout of R3 limits the impersonation window. The settings page gains "Strict post-quantum mode" (off by default): when on, resume is also locked until the signature has verified or both sides' SAS match. This setting is stored in the vault and follows rotation rollback protection; it protects only the local side.
- `PQ_REQ` body[0] gains bit2 "urgent": the receiver schedules the signature ahead of EK/CT. Strict-mode resume and a locked full path both set this bit.

**R3 The timeout uses a local send-slot count.** It no longer counts frames sent by the peer (a man in the middle that lets one frame through every 15 seconds could nearly stall the count). It counts the local send slots after establishment, pausing only while both sides agree to open a voice window. Expiry slot count = 2 × (301 + 178 if the public key is requested + 143 if resume and not urgent) + 100. Waiting only for the signature is 702 slots (wideband 112 seconds, narrowband 225 seconds); resume, not urgent, is 988 slots (wideband 158 seconds, narrowband 316 seconds). The 1500/2100 frames below are void.

**R4 Messages received while locked are only buffered, not displayed.** The trigger is the same as the send lock (the full path is pinned, or resume under strict mode). The session ACKs as usual and the decrypted messages stay inside the session without emitting MessageReceived; once the lock is released they are delivered in order, and on abort they are zeroed and discarded, and the screen shows "N messages with unconfirmed identity discarded". The "mark received messages as 'identity being confirmed'" entry in the table of item 4 below, and "receive first, verify later" in item 8, are void.

**R5 A local PQ key fault never deletes any key automatically.** `nativeSetPqIdentity` returning -8 means a temporary error (a Keystore or StrongBox exception): retry with backoff, do not start new calls in the meantime, and the screen shows "Secure hardware temporarily unavailable". Returning -7 means the alias definitely does not exist or the hash does not match: enter "PQ identity invalid", keep the P-256 key, set cap to 0, and do not regenerate the PQ key alone; the screen explains that contacts who have pinned you will hang up, and only after the user taps "Reset identity" and confirms are both keys deleted and rebuilt. The "delete both keys and rebuild the identity" below is void.

**R6 Transmission time correction.** Each superframe takes 160 ms in wideband and 320 ms in narrowband, that is 6.25 / 3.125 frames per second. The signature takes 48 / 96 seconds, the public key 28.5 / 57 seconds, the first time totals 77 / 153 seconds, resume is about 71 / 142 seconds; an ML-DSA-87 signature takes 67 / 135 seconds. The seconds in the tables below follow this; the frame counts are unchanged.

**Residual risk addendum.** In non-strict mode, when vault secrets have leaked and the attacker can forge ECDSA with a quantum computer, impersonation of a pinned contact can last up to the R3 timeout (wideband about 112 to 158 seconds), and messages sent in that period fall into the attacker's hands. Strict mode removes this window, at the cost of waiting about 48 to 96 seconds on every call, or comparing the verification words, before sending.

---

**Summary**

- After each call is established, each side sends one ML-DSA-65 signature, over the BULK background, without blocking text. The public key is sent only when the peer has not pinned it.
- The handshake uses only bit2 of the HS1 caps to say "I have a hardware PQ identity". HS1 is still 77 B, the protocol version is still 2, the suite is still 0x01.
- After pinning, every call must verify or it is hung up; the full path locks sending until the signature verifies or the verification words are compared.
- Only phones whose StrongBox supports ML-DSA create a PQ identity. Older Pixels use no software key, but can still verify and pin the peer's PQ identity.

**Where the gap is**

There are three situations that already withstand an active quantum attacker; together they are called "post-quantum secure" below:

- resume: the AEAD of RS3 uses rs, rs derives from a handshake that includes ML-KEM, and it is written only after the SAS matched or a PSK was used (6.3).
- This call mixed in that contact's PSK.
- Both sides pressed "SAS matches" on this call. The commitment-based SAS relies on a hash, which quantum computers cannot break.

The case that relies only on ECDSA is: full path, no PSK, and no SAS comparison on this call, for example after rs went out of sync, or a contact saved before the upgrade. ML-DSA mainly fills this gap; on the other paths it is a second line of defense that still holds when rs leaks.

**Transmission time**

Each BULK frame carries only 11 B and a superframe 23 B, so the net rate is half of the raw rate (modulator.rs:60). So wideband is about 6.5 frames per second and narrowband about 3.3.

| Content | Frames | Wideband 2400 | Narrowband 1200 |
|---|---|---|---|
| Signature alg(1)+3309 B | 301 | 46 s | 92 s |
| Public key alg(1)+1952 B | 178 | 27 s | 55 s |
| First time: public key + signature | 479 | 73 s | 147 s |
| resume: ML-KEM runs first, signature interleaved | — | about 70 s | about 140 s |

The above assumes an idle channel with no loss; ACKs and retransmission at 5% loss add about 15%. For comparison: an ML-DSA-87 signature takes 421 frames, 65 seconds wideband and 129 seconds narrowband.

**1. What is signed**

`pq_msg_X = L_X ‖ th_end ‖ pub33_X ‖ pub33_Y ‖ alg ‖ SHA-384(pk_X)`, all fields fixed length, 182 B in total.

- `L_X`: ASCII `"AegisChat-v2 pqid I"` or `"AegisChat-v2 pqid R"`, 19 B. X is the signer's role on this call (Initiator/Responder).
- `th_end`: the final transcript passed to `finish()`, 48 B (th5 on the full path, th_f on resume). It covers both sides' HS1 (including caps and nonce), the ephemeral keys, and the ID block or RS3 signed with ECDSA.
- `pub33_X` is the signer itself and `pub33_Y` is the peer, both taken from the values authenticated by this call's handshake. `alg` = 0x01 (ML-DSA-65).
- The algorithm is pure ML-DSA from FIPS 204, with an empty-string context; all domain separation is placed in the message. The verifier builds the message from its own state and takes only the signature (and, when needed, the public key) from the wire.

This definition stops the following attacks:

- Cross-call replay: th_end contains both sides' fresh nonces and ephemeral keys, so a signature from another call does not verify.
- Binding the PQ key to a classical identity: the message contains the signer's pub33 and the transcript already signed with ECDSA.
- Binding the classical identity to the PQ key: caps bit2 is inside th0; the full path is covered by ECDSA, and resume is covered by ECDSA plus the AEAD of rs. The PQ objects are sent inside this call's AEAD.
- Mix and match: the verifier verifies with the public key pinned for "the contact that owns this pub33"; the message contains the peer's pub33, which prevents unknown-key share; the role label prevents reflection.

**2. Capability bit**

- `CAP_PQ_ID = 1 << 2` means "I have a hardware ML-DSA-65 identity and will answer PQ_REQ", and is set only when `LocalIdentity.pq` has a value.
- The current implementation rejects only bit1 (handshake_v2.rs:525), and older versions ignore bit2, so the protocol version and the suite are not changed, and PROTOCOL_LABEL does not change either.
- The purpose is that a pinned contact that loses this bit aborts at the handshake stage, before any user data has started to flow. A quantum attacker on the full path can forge ECDSA and strip the bit, but the pin still stops it; stripping it on resume would also require rs.
- The ability to verify needs no separate bit: every version with this feature verifies.

**3. How it is transmitted**

- Add `PQ_REQ`, an encrypted control frame subtype 21, using the same control-frame mechanism as EVIDENCE_REQ. Bit0 of body[0] asks for the public key, bit1 asks for the PQ attestation chain, and the rest are filled with 0. The verifier sends it after establishment, when it sees the peer set CAP_PQ_ID; when a duplicate PQ_REQ arrives, the flags are merged and the signature is not redone.
- When the signer receives the first PQ_REQ it emits `NeedPqSignature`. If the peer wants the public key, obj 4 is queued first; after the signature comes back, obj 5 is queued; if the peer wants the attestation chain and the app has provided it, obj 6 is queued.
- BULK object format:
  - obj 4 = public key, alg(1)·pk(1952), 178 pieces.
  - obj 5 = signature, alg(1)·sig(3309), 301 pieces.
  - obj 6 = PQ attestation chain, length(2)·DER chain (root excluded, ≤ 8192 B).
  - The last piece is padded with 0, and the padding check is the same as obj 1/2. The current receiver drops an object nobody asked for and does not send an ACK (call_session.rs:1492), so these objects are sent only when the peer requests them.
- The priority stays "control > chat > BULK > filler". Inside BULK it becomes: EK/CT > public key > signature > attestation chain > PQ attestation chain. This is done by adding `prio` to `BulkTx`, and `next_frame` picks the first object that has a piece to send by prio (today it is by order of addition, call_session.rs:420). On resume, while R waits for ek it sends its own signature in the gap, and as soon as ct appears it cuts in, so the "with post-quantum" time is the same as in 6.3.
- The public key is not sent on every call, and no hash is sent either. If the peer has pinned it, only the signature is sent, and it is verified with the pinned public key.
- The timeout is counted in "valid encrypted frames received from the peer after establishment", which adapts automatically to the gear and the voice window: waiting only for the signature is 1500 frames, and when the public key is also needed, 2100 frames. That is about 230 / 320 seconds wideband and about 455 / 640 seconds narrowband, about 3 times the expected time. If the local signature has not returned within 15 seconds or fails, abort with `PqSignFailed`. If the call ends before the timeout, nothing is recorded and no penalty applies.

**4. Pinning and fail-closed**

`Contact` gains `pq: Option<PqPin>`, containing `{ alg, pk 1952 B, attestation: Option<AttestationVerdict> }`. A value means "verified, required from now on"; there is no separate "seen" flag.

There are two write conditions, and both must hold: the signature on this call verified, and this call is post-quantum secure. A SAS that arrives later than the signature also counts. A full path with only ECDSA verifies but does not store. Pinning counts as an identity change and rotates the credential per 6.5, so restoring an old vault file cannot remove the pin either.

| Situation | Handling | Screen |
|---|---|---|
| Pinned, the peer did not set CAP_PQ_ID | Both the full path and resume abort at the handshake with `PqDowngrade`, send ABORT, then hang up | Red: "The other side did not present its earlier post-quantum identity this time, and the call was hung up. Someone may be impersonating them; confirm with them another way." |
| Pinned, post-quantum secure | Receive and send as usual, verify the signature in the background | Yellow "Confirming post-quantum identity NN%" → green "Includes post-quantum identity" |
| Pinned, full path with only ECDSA | Lock sending until the signature verifies or both sides' SAS match; received messages are marked "identity being confirmed" | Yellow: "Confirming post-quantum identity NN% (about N seconds); compare the verification words to start sending right away" |
| Signature does not verify (any case) | Abort with `PqBadSignature`; messages received on this call are re-marked "identity unconfirmed" | Red: "Post-quantum identity verification failed, and the call was hung up." |
| The peer set the bit but timed out | Abort with `PqTimeout` | Red: "The other side did not present its post-quantum identity in time, and the call was hung up." |
| Not pinned, the peer has the bit | Request the public key and the signature; pin if the conditions are met | Green "Includes post-quantum identity (remembered)"; when the conditions are not met, gray "Post-quantum signature valid; compare the verification words for it to be remembered" |
| Not pinned, the peer does not have the bit | No handling | Gray: "The other side's phone does not support post-quantum identity" |

Handling device changes and upgrades:

- **Old phone to new phone**: pub33 changed, which triggers KeyChanged, and sending is allowed only after the SAS is compared (6.2). A SAS match is post-quantum secure, so as soon as the signature arrives, the new public key is written together with the key change.
- **New phone back to old phone**: also KeyChanged. `replace_contact_key` clears the old pin, because it belongs to the old pub33. The KeyChanged event gains `stored_had_pq` / `peer_has_pq`, and the screen gets one more line: "The other side's earlier phone had a post-quantum identity; this one does not. After you compare the verification words, it will be stored as a classical identity." This is a downgrade confirmed by a human, and is accepted.
- **The same pub33 but a changed PQ public key**: not allowed. The two keys live and die together; the vault content gains `local_pq_hash`, recording the hash of the local PQ public key. If the vault has a record but Keystore cannot find this PQ key or the hash does not match, both keys are deleted and the identity is rebuilt. The peer sees the signature fail to verify and aborts, and the next call goes through KeyChanged.
- **An existing user upgrading for the first time**: only when `local_pq_hash` is empty is a PQ key generated, reusing the existing P-256 identity. The peer's next call is mostly a resume, which pins immediately.

**resume**: resume is already post-quantum secure and does not lock sending, but still sends PQ_REQ. If already pinned, it must verify, and failing to verify or timing out aborts the same way; if not yet pinned, it pins on this call. The RS2/RS3 format does not change.

**5. Keys and hardware**

- **Choosing ML-DSA-65**: an identity signature only needs to be unforgeable during the key's period of use and needs no protection against "record now, decrypt later", so NIST security level 3 is enough. An ML-DSA-87 signature takes 40% more transmission time. Confidentiality still uses ML-KEM-1024; the different levels on the two sides are deliberate. ML-DSA-44 saves only about 27%, and its margin is thin for a multi-year identity key.
- **Generation parameters** (in TitanM2StrongBoxBridge.kt):
  - Alias `aegis_pqid_v1`, with only PURPOSE_SIGN.
  - `setIsStrongBoxBacked(true)`; on failure, no PQ identity is created, cap is set to 0, and there is no fallback to TEE (6.1).
  - `setAttestationChallenge("AegisChat-PQID-v1" ‖ pub33)`, 50 B in total.
  - `setDevicePropertiesAttestationIncluded(true)`.
  - `setUnlockedDeviceRequired` follows the identity key (:50).
  - User authentication is not required, the same as the current P-256 identity key: the signature is made in the background during a call, and the precondition for opening a session is that the vault has already been unlocked with the PIN (6.5).
- **Deletion**: on duress, when the 5 credentials are used up, and on `destroyAll`, `aegis_pqid_v1` is deleted together with the rest.
- **The attestation chain is verified, but it only affects the "hardware attested / not attested" label**; it takes no part in the pin or abort decisions. `verify_pq_attestation` checks the following items, and rejects if any one does not match:
  - E2 rules: StrongBox, brand field is google, package name.
  - challenge = label ‖ the peer's pub33. This binds the PQ key to the P-256 identity.
  - Purpose is signing only, and algorithm is KeyMint's ML-DSA value.
  - The OID of the leaf certificate SPKI is id-ml-dsa-65 (2.16.840.1.101.3.4.3.18), and the public key bytes equal the pinned value.
  - As far as is known, this chain is issued with classical ECDSA/RSA, which a quantum attacker can forge, so it can only prove today's hardware properties.
- **Software ML-DSA is not allowed** except in tests, for three reasons:
  - It violates the StrongBox-only rule of 6.1.
  - These phones have Magisk root (6.10), and a software private key can be read by any root program. After the private key is stolen, a future quantum forger faces no further obstacle, while the screen still shows the same "includes post-quantum" label.
  - Old phones are not left unprotected: resume, PSK, and SAS are already post-quantum secure, and an old phone can also verify and pin the peer's PQ identity. The old phone's screen says "This device has no post-quantum identity hardware".

**6. Rust and JNI changes**

```rust
// aegiscall-crypto: new file src/pq_identity.rs, modify handshake_v2.rs
pub const CAP_PQ_ID: u16 = 1 << 2; pub const PQ_ALG_MLDSA65: u8 = 1;
pub const MLDSA65_PK_LEN: usize = 1952; pub const MLDSA65_SIG_LEN: usize = 3309; pub const PQ_SIG_MSG_LEN: usize = 182;
pub struct PqPublicKey { pub alg: u8, pub bytes: Box<[u8; MLDSA65_PK_LEN]> }   // fn hash(&self) -> [u8; 48]
pub fn pq_sig_message(role: Role, th_end: &[u8; 48], self_pub33: &[u8; 33], peer_pub33: &[u8; 33], self_pk: &PqPublicKey) -> [u8; PQ_SIG_MSG_LEN];
pub fn pq_verify(pk: &PqPublicKey, msg: &[u8; PQ_SIG_MSG_LEN], sig: &[u8]) -> Result<(), CryptoError>;
#[cfg(any(test, feature = "test-pq-signer"))] pub struct SoftPqSigner;   // from_seed(&[u8; 32]), public_key(), sign(msg)
pub struct LocalIdentity { pub pub33: [u8; 33], pub evidence_id: [u8; 16], pub pq: Option<PqPublicKey> }
// PeerExpectation gains pub pq_pins: Vec<(u32, [u8; 33], PqPublicKey)>
// Established gains pub th_end: [u8; 48], pub peer_pq_cap: bool, pub peer_pq_pin: Option<(u32, PqPublicKey)>
// HsError gains PqDowngrade (checked in verify_peer_id and in RS3 verification)
// aegiscall-mux: ctrl::PQ_REQ = 21
// aegiscall-chat (call_session.rs)
SessionEvent::NeedPqSignature { req_id: u32, message: Vec<u8> }
SessionEvent::PqIdentity(PqIdStatus)   // NotOffered | Pending(u8) | Verified { pinned: bool } | ValidUnpinned
SessionEvent::PqPinReady { contact: u32 }; SessionEvent::PqEvidenceChain(Vec<u8>)
SessionEvent::KeyChanged { stored_pub33, peer_pub33, stored_had_pq: bool, peer_has_pq: bool }
impl SecureCallSession {
  pub fn on_pq_signature(&mut self, req_id: u32, sig: Option<&[u8]>);
  pub fn pinnable_pq(&self) -> Option<&PqPublicKey>;   // returns Some only if verified and post-quantum secure
  pub fn provide_pq_evidence_chain(&mut self, chain: &[u8]) -> Result<(), ChatError>;
  pub fn request_pq_evidence(&mut self) -> Result<(), ChatError>; }
// AbortReason gains PqDowngrade = 27, PqBadSignature = 28, PqTimeout = 29, PqSignFailed = 30
// The send lock becomes reason bits (KEY_CHANGED | PQ_PENDING); set_tx_locked(false) is called only when all are cleared
// aegiscall-trust: does not depend on crypto, public keys are stored as bytes
impl Vault {
  pub fn pin_pq(&mut self, id: u32, alg: u8, pk: &[u8; 1952]) -> Result<(), TrustError>;
  pub fn set_pq_attestation(&mut self, id: u32, v: AttestationVerdict) -> Result<(), TrustError>;
  pub fn local_pq(&self) -> Option<[u8; 48]>; pub fn set_local_pq(&mut self, h: Option<[u8; 48]>); }
pub fn verify_pq_attestation(chain_no_root: &[Vec<u8>], cfg: &TrustConfig, expected_pub33: &[u8; 33],
                             expected_pk: &[u8; 1952]) -> Result<AttestationVerdict, TrustError>;
```

- **Vault format**:
  - The contact flags gain `F_PQ = 1 << 6`, merged into `F_ALL`. The content follows the attestation: alg(1)·pk(1952)·sub(1, bit0 means attested)·[same encoding as attestation].
  - The inner `CONTENT_VERSION` goes to 2, adding has_local_pq(1)·local_pq_hash(48) after next_contact_id. v1 files are still read, treated as having no PQ fields.
  - `CONTACT_MAX_LEN` includes the PQ block. `MAX_VAULT_LEN` goes from 1 MiB to 4 MiB, because 1000 contacts all pinned is about 2 MB.
  - `replace_contact_key` clears pq; `ContactView` gains `pq_pinned` and `pq_hw_attested`.
- **JNI**:
  - `nativeSetPqIdentity(app, pkRaw: ByteArray?, chainTlv: ByteArray?): Int`, called after the vault is unlocked. Returning 0 means normal; returning -7 means the vault record and Keystore do not match, and Kotlin must rebuild the identity.
  - `nativeSessionOnPqSignature(session, reqId, sig: ByteArray?)`, `nativeSessionProvidePqEvidence`, `nativeSessionRequestPqEvidence`.
  - `nativeContactPinPq(app, session, contactId): Int`: Rust takes the public key from `pinnable_pq`, and Kotlin never handles it; after that it goes through `nativeVaultRotateBegin` / `Commit` as usual.
  - `nativeSessionSaveContact` (NativeBridge.kt:147) also brings in `pinnable_pq` on the Rust side.
  - New events `NEED_PQ_SIGNATURE`, `PQ_ID`, `PQ_PIN_READY`, `PQ_EVIDENCE`.
- **Kotlin bridge**: add `ensurePqIdentity(pub33): ByteArray?` (returns null when unsupported), `signMlDsa65(msg): ByteArray`, `pqAttestationChain()`; `destroyAll` also deletes `aegis_pqid_v1`.
- **Verification crate**: use RustCrypto `ml-dsa`. It is pure Rust, no_std, MIT/Apache-2.0, in the same family as the existing `ml-kem 0.2.3` (Cargo.toml:28), sharing sha3 and hybrid-array.
  - As far as I know there is no public third-party audit, and it is still pre-1.0, so check this before implementing.
  - Pin the version with `=`, turn off default features, and enable only the verification feature; test with the NIST ACVP ML-DSA-65 sigVer vectors as a fixed file. Verification handles only public data, so there is no need to worry about timing side channels.
  - deny.toml does not need to change: the license is in the allowlist and the source is crates.io. If the sha3 version differs from ml-kem's, a multiple-versions warning appears, so choose an ml-dsa that shares the version.

**7. To be confirmed on device (Pixel 11, Android 17)**

I cannot verify any detail of Android 17 Keystore's ML-DSA support, so all of the following are unconfirmed:

- Whether support is in StrongBox (Titan M3) or only in the TEE. If only in the TEE, this design is not enabled and a separate decision is needed.
- The algorithm name and the ML-DSA-65 parameter spelling for KeyPairGenerator; whether `setDigests` and `setUnlockedDeviceRequired` are required or compatible.
- Signing mode: pure ML-DSA, or HashML-DSA / external μ; whether a context can be passed; whether the output is 3309 B of raw bytes; whether it is randomized or deterministic. If only another mode is supported, switch to a new alg number; the message definition stays the same.
- The time one StrongBox signature takes, which decides whether the 15-second timeout is reasonable.
- Attestation format: the ML-DSA value of the KeyMint algorithm field, the encoding of the leaf certificate SPKI, whether the chain is issued classically or with PQ, whether the brand field and device property attestation can be used, and whether a 50 B challenge is accepted.
- How to detect support: first assume "key generation succeeding counts as supported".
- Record a real attestation chain, and the signature of one known message, and save them as fixture files for use in tests.

**8. Residual risks and what is not done**

- The full path receives first and verifies later: although sending is locked, received messages are still displayed. In the roughly 1 to 2.5 minutes before the abort, an impersonated message may be read, and after the abort those messages are re-marked "identity unconfirmed".
- The first call still relies on the SAS. For a full-path call without a SAS comparison, the PQ identity is verified but not stored.
- The attestation chain is a classical signature, and a quantum attacker can forge "hardware attested".
- If the peer phone's signing function fails (for example a bug in a system update), the two cannot call each other until it is fixed or the identity is reset. This is the cost of fail-closed.
- The Titan M3's ML-DSA implementation must be trusted; the `ml-dsa` crate has no audit record. Impersonating the SAS with a voice deepfake is outside the scope of this section.
- Not done: putting ML-DSA in the foreground handshake, bumping the protocol version, software ML-DSA, a PQ attestation root, moving ML-KEM into hardware.

**Rejected approaches**

- ML-DSA in the foreground handshake: every call would wait 46 to 92 seconds longer before typing is possible.
- Sending the public key on every call: 27 / 55 seconds more per call, with no security gain once pinned.
- ML-DSA-87: 40% more signature transmission, and level 3 is already enough for identity verification.
- Bumping to protocol v3 or a new suite 0x02: bit2 is already signed into the transcript and older versions ignore it, so it is unnecessary.
- Having ECDSA sign the PQ public key inside the ID block: HS3/HS4 would grow longer, and a quantum attacker can still forge it.
- Pinning as soon as there is only ECDSA (TOFU): if the very first call meets a man in the middle, the attacker's key is pinned and the real peer is locked out. Most contacts go through resume on the next call, so pinning one call later loses nothing.
- Software ML-DSA on old phones: see item 5 for the reasons.

**9. Implementation breakdown**

Verification: run `cargo test -p <crate>` for each crate. PQ1 and PQ2 can run in parallel; PQ3 waits for PQ1; PQ4 waits for the first three packages.

| Package | Write scope (repo-relative paths) | Required test scenarios |
|---|---|---|
| PQ1 Protocol (host-side) | `core/aegiscall-crypto/src/pq_identity.rs` (new), `core/aegiscall-crypto/src/handshake_v2.rs`, `core/aegiscall-crypto/src/lib.rs`, `core/aegiscall-crypto/Cargo.toml`, `core/aegiscall-crypto/tests/data/mldsa65_sigver.json` (new); `Cargo.toml` at the repo root gets ml-dsa added (shared file, modified only by this package) | Message is 182 B with correct field offsets; ACVP vectors; verification fails if any field or th_end changes; bit2 is set only when a PQ identity exists; an older version without bit2 handshakes as usual; when pinned but bit2 is absent, both the full path and resume abort with `PqDowngrade` |
| PQ2 Vault and attestation (host-side) | `core/aegiscall-trust/src/vault.rs`, `core/aegiscall-trust/src/attest.rs`, `core/aegiscall-trust/src/keydesc.rs`, `core/aegiscall-trust/src/tests/` | v1 vault is still read; v2 write/read round trip is identical; 1000 contacts all pinned is under 4 MiB; a key change clears the pin; local_pq access; a synthetic ML-DSA leaf certificate is rejected when the challenge lacks pub33, the public key differs, or it is not StrongBox |
| PQ3 Session (host-side) | `core/aegiscall-chat/src/call_session.rs`, `core/aegiscall-mux/src/lib.rs` | Tested with SoftPqSigner: first pin on resume; when the full path is pinned, sending is locked until verified, and the SAS can unlock it early; with a bad signature, both sides abort with `PqBadSignature`; if the peer does not send, abort with `PqTimeout` at 1500 / 2100 frames; under 5% loss the frame count does not exceed the estimate × 1.15; chat latency unchanged; mixing in ML-KEM is no later than today; when the peer has no bit2, no PQ_REQ and no PQ objects are sent; a duplicate PQ_REQ does not re-sign |
| PQ4 JNI (host-side) | `core/aegiscall-jni/`, `app/src/main/java/io/github/h4lovoid/dialcrypt/core/NativeBridge.kt` | Run both the full-path and resume PQ flows without the JVM; the pin can take the public key only from the session; exported symbols match the `external fun` declarations one by one |
| PQ5 Keystore (on device) | `app/src/main/java/io/github/h4lovoid/dialcrypt/security/HardwareKeyBridge.kt`, `app/src/pixelTitan/java/io/github/h4lovoid/dialcrypt/security/TitanM2StrongBoxBridge.kt`, screen string resources | Every item in item 7; real calls between two Pixel 11 phones testing first pin, resume, and an injected bad signature; one-way pinning from a Pixel 11 to a Pixel 9; device changes in both directions |
