# DialCrypt Secure Session Design v2 (Handshake, Trust Model, Lifecycle)
- **Status**: Sections 2–5 have been through a second-opinion review; the review conclusions and the project owner's later decisions are recorded in Section 6. Where they conflict, Section 6 prevails.

- **Two additions made during implementation (adopted)**: th0 is now taken after PATH has been absorbed, so the keys of both paths are bound to PATH. When dialing a contact that has a PSK, if PATH says the full path was taken and no PSK was mixed in, the caller aborts directly with PskRequired and does not establish a connection with an unverified identity.
- **6.12 Hardware post-quantum identity signature** (ML-DSA-65, background transfer; decided, not yet implemented) is written up in pq-identity-signature.md in the same directory.

### 6.11 Protocol revisions after handshake implementation acceptance

Acceptance testing and the security review pointed out that if the choice of path and PSK depends on caller ID, a hidden number or a forged caller ID can make the two sides take different paths and abort. The revisions below replace the approach in 6.3 where "each side decides the path from rid on its own"; everything else stays the same.

- **Caller marker**: HS1 caps uses a previously reserved bit to mean "I am the caller". If both sides have the same value, abort.
- **Who announces, who matches**: the caller fills psk_tag, rid0 and rid1 according to the contact it dialed; the callee always fills these three fields with random bytes and makes no cryptographic decision from caller ID.
- **PATH message**: once the callee has received the peer's HS1, it matches the PSKs and quick connect secrets of all contacts in the vault against it and sends PATH (link type 7, 2 bytes: byte 1 is the path, 0 full, 1 quick connect (resume); byte 2 is flags, bit0 = PSK mixed in, bit1 = the match was rs_new). PATH is absorbed into the transcript, positioned after both HS1 messages and before every other message. The caller decides the rest of the flow from PATH; a PATH that contradicts what the caller itself announced (for example, being told there was a match when nothing was announced) causes an abort.
- The PskRequired check after identity reveal is unchanged; a quick connect whose RS3 verification fails still aborts directly and does not fall back to the full path.
- **Handshake frames after establishment**: after establishment, any handshake type or ABORT received is discarded, and the state of the handshake object must not change.
- **DH ratchet**: before committing TX, the responder must not change the epoch, root or frame counter; a new ratchet is refused until the one in progress completes; the quick connect secret derived from the new root may be used only after both sides have entered the new epoch.
- **When the responder counts as established**: it reports established to the upper layer only after receiving the peer's first valid encrypted frame, and must not send or receive user data before that.
- **Link-layer checksum**: the implementation uses CRC-16/IBM-SDLC (X.25), which differs from the name written in Section B; both ends use the same implementation, and the implementation prevails.
## 6. Final revisions

This section lists only the differences from Sections 2–5; where they conflict, this section prevails. All five review findings and the four additional points were adopted, with two of them handled differently: Android Keystore has no monotonic counter an app can use, so attempt count and generation use one-time key binding instead (6.5); the input method is no longer disabled across the board, so the lock screen is unaffected (6.7). All three leanings were adopted, each with the missing piece added.

### 6.1 Scope reduction

- **Pixel only**: removed are `HardwareEdition`, `edition_claim`, `PeerTrustLevel`, the preamble's `CAP_EDITION_*` (bits 0–1 reserved as 0), the daemon's edition parameter, and the `standardRoot` source set. The only package is `io.github.h4lovoid.dialcrypt`. The pairing code stays at 68 B: ver(1)=3 · pub33 · X(32) · crc16, where X is the X25519 public pairing key; the code holds no secret. Each side derives its pairing key x = BLAKE3-derive_key("DialCrypt pairing v3 x25519", seed) from the 32-byte seed in `contact_meta.bin` (a version 1 or 2 file is given a new seed on load, because older seeds were printed in the codes). Importing a code gives psk = BLAKE3-derive_key("DialCrypt pairing v3 psk", X25519(x_own, X_peer) ‖ pub33_lo ‖ X_lo ‖ pub33_hi ‖ X_hi), the two sides ordered by pub33, so both compute the same psk whichever code is imported first. A code is refused when X has its top bit set, when it carries our own pub33 or X, or when the exchange is all zero (low-order point). Without a seed saved in `contact_meta.bin` no code is shown.
- The identity key and the PIN tickets always live in StrongBox; if it is unavailable, startup is refused, with no TEE fallback. Item 5 of E2 becomes: both security levels must be StrongBox; one item is added: the key is generated with `setDevicePropertiesAttestationIncluded(true)` and the brand field of the leaf certificate must be `google`. The only hardware labels left are "StrongBox・locked / self-signed locked / unlocked" and "hardware not attested".
- **Messages are text and quick commands only**: the entry points for micro images, micro video and sketches are all removed. The attestation chain and the background ML-KEM move to the BULK channel of 6.3.
- **Always fail-closed**: on a handshake abort, no peer preamble within 20 seconds (previously 60 seconds), or any failed check, 3 ABORT frames are sent and then the app calls `endCall()` to hang up. A call is not retried; retrying means redialing. Except for the SAS voice comparison window, the uplink microphone is muted the whole time, and the screen has no "switch to a normal call" entry.

### 6.2 Handshake revisions (full path)

- **HS1 becomes 77 B (5 frames)**: ver(1)=2 · suite(1) · caps(2) · gear(1) · nonce(16) · psk_tag(8) · rid0(8) · rid1(8) · commit(32). commit = SHA-384("AegisCommit-v2" ‖ HS1[0..45] ‖ x25519_pub)[..32].
- **The ID block becomes 113 B**: pub33 · evidence_id(16) · sig(64), plus a 16 B tag. HS3 = 1729 B (97 frames), HS4 = 129 B (8 frames), and a full handshake still takes about 38 seconds.
- **th0** = SHA-384(protocol label ‖ pre_I ‖ pre_R ‖ gear ‖ HS1_I ‖ HS1_R), that is, the transcript value at the moment both sides' HS1 have been absorbed.
- **The signature covers evidence_id**: sig_I = ECDSA("AegisChat-v2 auth I" ‖ th3 ‖ pub33_I ‖ evidence_id_I); sig_R is the same using th4.
- **Key output**: the handshake outputs only `root_0 = Expand(ck2, "root" ‖ th5)`, `chaff_seed`, `rs_next` and `transcript_tag`; the per-direction keys and nonce salts are derived from the epoch derivation in 6.4.
- **PSK enforced by identity**: after identity reveal, if the peer's `pub33` belongs to a contact that has a PSK and the PSK mixed into this handshake is not that one, abort with `PskRequired`. `phone_tag` no longer decides whether a PSK is required.
- **Contacts are recognized by `pub33`**; `phone_tag` is only used to hint that "this number used to have a different key". When saving, the number field is prefilled with the caller ID and the user must confirm or correct it; a hidden number may be saved without a number.
- **Key changed**: sending is prohibited until both sides press "SAS matches" in this call; the option "continue this time as unverified" is removed.
- **Handshake frames after establishment**: a session runs the handshake only once and never restarts it after establishment. After establishment it does only two things: resend our own last message according to the peer's ACK bitmap (on the full path that is HS4 for R and nothing for I; for resume it is RS3 on both sides), and discard duplicate fragments of the peer's last message. Any other type, a different tag, or ABORT is discarded without changing state. It closes permanently on receipt of the peer's first valid encrypted frame, after at most 32 frames. After establishment, an abort is accepted only as an encrypted control frame.

### 6.3 Faster repeat calls (resume)

Each verified contact stores two extra values in the vault, `rs_cur` and `rs_new` (32 B each, either may be empty). After a full handshake, the first secret `Expand(ck2, "resume next" ‖ th5, 32)` is written only once "both sides' SAS match and the contact is saved" or "that contact's PSK was used".

**Path decision costs no extra round trip**: every call sends the same kind of HS1. rid = HMAC-SHA384(rs, "AegisRID-v2" ‖ own nonce ‖ own pub33)[..8]; rid0 corresponds to `rs_cur` and rid1 to `rs_new`, filled with random bytes if absent. Each side matches all secrets in its vault against the peer's two rids and obtains the set of secrets held in common: if it is non-empty, resume is used with the newer one; if it is empty, the full path is used. Both sides compute the same result; if tampering makes them disagree, a message of an unexpected type arrives and the handshake aborts.

| Message (sent by both sides at the same time) | Layout | Length / frames |
|---|---|---|
| RS2 (type 5) | x25519_pub(32), must match the side's own commit in HS1 | 32 B / 2 |
| RS3 (type 6) | AEAD_k(sig(64)), nonce all zeros, AAD = th_r | 80 B / 5 |
| Finished | first encrypted frame `HS_FINISHED` | 1 frame |

- **Key schedule**: `ck0 = Extract(th0, rs)`; `th_r = SHA-384(th0 ‖ 0x52 ‖ x25519_I ‖ x25519_R)`; `ck1 = Extract(ck0, X25519(e_I, e_R))`; `k_i2r / k_r2i = Expand(ck1, "rs i2r" / "rs r2i" ‖ th_r)`.
- `sig_X = ECDSA_X("AegisChat-v2 resume X" ‖ th_r ‖ pub33_X)`, which the peer verifies with the `pub33` pinned in the vault. `th_f = SHA-384(th_r ‖ RS3_I ‖ RS3_R)`; `root_0 = Expand(ck1, "root" ‖ th_f)`; `rs_next = Expand(ck1, "resume next" ‖ th_f, 32)`.
- The AEAD tag of RS3 proves the peer holds rs, and the signature proves the peer holds the StrongBox identity key; the session counts as established only when both pass. If either one fails after the rid match, the handshake aborts directly and does not fall back to the full path.
- **Per-call update (two phases)**:
  1. After establishment, each side writes `rs_next` into `rs_new` (keeping `rs_cur`); the vault file is written atomically and fsynced.
  2. Only after the write does it send the encrypted control frame `RESUME_SAVED` (subtype 17: k(1) · Expand(rs_next, "saved")[..8]), resent every 8 frames until the peer's same k is received.
  3. Only on receiving the peer's `RESUME_SAVED(k)` does it promote `rs_new` to `rs_cur` and clear the old value; receiving k also means the peer has confirmed all updates smaller than k.
  4. After the background post-quantum exchange is mixed in, it does one more round with `Expand(root_e, "resume next pq" ‖ e, 32)` and k=2 (e is the epoch in which the mix-in happened). If the previous round has not finished promoting, it waits; if the call ends first, it is skipped.
  5. If the next resume uses `rs_new`, it first promotes it to `rs_cur`.
- This order guarantees that whenever either side clears an old value, the peer already holds the new one, so the two sides' sets always intersect. Normally the vault keeps only the newest one, so a seized device cannot be used to derive the keys of earlier calls.
- **Out of sync** (vault restored, lost, or one side reinstalled): the common set is empty and the full handshake runs automatically; release waits until the post-quantum exchange completes, the identity is checked by signature against the pinned `pub33`, and a PSK is enforced where present, so the level is the same as without resume. The screen adds the note "quick connect to be rebuilt" and the old rs is kept for now; the new secret is written only when SAS matches again in this call (or a PSK was used), so someone forging a signature cannot use this to plant a secret.
- **Replay protection**: each time, both sides provide a fresh nonce and a fresh X25519 ephemeral key, both of which enter th0 and ck1, so a replayed old HS1 / RS2 / RS3 cannot produce this call's RS3 tag. There is no 0-RTT, and user data is sent and received only after both sides' RS3 have been verified. rid includes the sender's `pub33`, so reflecting one's own HS1 back does not match.
- **Background post-quantum exchange**: after establishment, I generates an ML-KEM-1024 key pair. `BULK_DATA` (subtype 18): (obj:4 | idx high 4 bits) · idx low 8 bits · data(11); `BULK_ACK` (19): (obj:4 | base high 4 bits) · base low 8 bits · 88-bit bitmap. obj 1 = ek (I→R, 143 fragments), obj 2 = ct (R→I, 143 fragments), obj 3 = attestation chain (the first 2 B are the length). Priority: control > chat > BULK > chaff frames. As soon as I decapsulates, it starts one DH ratchet with the pq flag (6.4).
- **Elapsed time (broadband)**: preamble 0.6 s + HS1 0.8 s + RS2 0.3 s + signature 0.3 s + RS3 0.8 s + Finished 0.2 s + about 1 s for three transmission delays + 0.5 s retransmission, so about 5 seconds until sending is possible; about 9 seconds on narrowband. The background post-quantum exchange takes about 305 frames, about 50 seconds when the channel is idle.
- **Screen**: after establishment it shows a green "Verified contact・Quick connect" with the note "post-quantum hardening NN%"; after the mix-in it changes to "Verified contact・Includes post-quantum". "Includes post-quantum" must not be shown before the hardening completes.

### 6.4 Rekeying: DH ratchet only

Adopted. The symmetric rekey with a random salt, `LIVE_REKEY` / `LIVE_REKEY_ACK` (subtypes 4 and 5 are disabled) and `ratchet_mix` are all removed.

- **Single epoch**: e starts at 0 and is shared by both directions. For each epoch, the key, the 16 B nonce salt and the msg base (each split into i2r / r2i) are all derived by `Expand(root_e, "ep" ‖ BE32(e) ‖ label)`. The frame counter resets to zero when the epoch changes.
- **Flow** (only I can initiate; if R wants to rekey it sends 1 `DH_RATCHET_REQ` frame):
  1. Every 375 frames, I generates a new X25519 key and sends `DH_RATCHET` (3 frames) in epoch e.
  2. After receiving all of it, R computes `root_{e+1} = Extract(root_e, dh ‖ [ss ‖ SHA-384(ek ‖ ct)])`, first stages RX (both e and e+1 can be received), and then replies with `DH_RATCHET_ACK` (3 frames) in epoch e. R's TX stays at e.
  3. After receiving all of it, I stages RX and commits TX to e+1 at the same time.
  4. R commits TX only after receiving the first valid e+1 frame. After both sides have received a valid e+1 frame from the peer, the old RX keys are kept for another 16 frames and then cleared.
- Fragment layout: epoch_lsb(1) · (flags:4 | fragment number:4) · data(11); flags bit0 means this round mixes in the post-quantum secret.
- Only one ratchet runs at a time; anything whose target is not e+1 is ignored, and a duplicate `DH_RATCHET` is answered with the same ACK. If it is still unfinished 1500 frames after it fell due, the session is aborted, which puts an upper bound on key lifetime.
- **Message keys** become `Expand(msg_base_{e,direction}, msg_id)`, where e is taken from the 6-bit epoch field already present in the fragment frame ([chat lib.rs](../../core/aegiscall-chat/src/lib.rs#L532)). The receiver keeps the current and the previous epoch; a message that has not finished sending after more than one epoch has passed is aborted by the sender and resent. The message chain, the fence and the skipped key table are removed. The cost is 6 frames every 60 seconds, about 1.6% of channel time.

### 6.5 PIN and vault

One-time keys are workable, but "refill after success" needs one added condition: root can also generate new keys itself, so the tickets are only useful if they are bound to the vault root key.

- **Tickets**: 5 HMAC-SHA256 keys. The app generates 32 B of random bytes and imports them into StrongBox with `KeyProtection` (`setIsStrongBoxBacked(true)`, `setMaxUsageCount(1)`), under the alias `aegis_pin_t<id>`, and the material is zeroed immediately after import. The original `aegis_pin_v2` is removed.
- **Wrapping**: the vault root key K_root is 32 B of random bytes, and P = Argon2id(PIN, salt). For each ticket t two equal-length wraps are stored: AEAD(HKDF(HMAC_t(P_normal)), 0x01 ‖ K_root) and AEAD(HKDF(HMAC_t(P_duress)), 0x02 ‖ random bytes), sorted by byte value, so the file does not reveal which one is the duress value.
- **Attempt**: take an unused ticket and have StrongBox compute HMAC_t(P); the hardware invalidates that key immediately; use the result to try to open the two wraps. Opening 0x01 is a normal unlock, 0x02 is duress, and opening neither is an error. When all 5 are used up the vault can never be opened again, and the identity key is deleted at the same time. Someone who obtains the vault file and root gets only 5 attempts in total; without K_root they cannot create usable new tickets either.
- **Rotation**: after every successful unlock, and whenever a contact identity changes (add, rekey, delete, import pairing), import 5 new tickets → atomically write the new file → use each old ticket once and then delete it. The tickets referenced by any earlier vault file are all invalidated, so restoring an old file cannot open it, and key continuity cannot be rolled back. `P_duress` is stored inside the vault contents so rotation can recompute it. The contents also hold a random 32 B meta key, created with the vault and unchanged by rotation, that seals `contact_meta.bin` (contact phone numbers, mutual-add marks, pairing seed) with XChaCha20-Poly1305 through `nativeMetaSeal` / `nativeMetaOpen`; the key never leaves Rust and both calls fail while the vault is locked. Rotation does not happen when only rs is updated; the consequence of rolling rs back is only a fallback to the full handshake. At start-up, before any unlock, the app retires every key-store ticket that the vault file on disk does not list (left by a process killed between importing new tickets and replacing the file, or between replacing it and retiring the old ones); a file that does not parse retires nothing.
- **Self-check and duress**: if the device lacks `FEATURE_KEYSTORE_SINGLE_USE_KEY`, or a test one-time key can be used a second time, PIN setup is refused. On duress, all tickets are used up, the identity key is deleted, and the vault file is overwritten with random bytes of the same length.
- **PIN change**: only while the vault is unlocked with the PIN. The current PIN is checked first, against both P_normal and P_duress in constant time, and spends no ticket, so the vault allows 3 wrong current PINs per unlock; the third locks it, and trying again needs an unlock, which spends a ticket. The duress PIN entered as the current PIN works as on the unlock screen, whatever the new PINs and the count: the vault wipes itself and the app runs the same duress path (every key destroyed, the vault file overwritten with same-length noise, fingerprint answer, contact metadata and the number index deleted, the app closed); until that wipe it takes the same steps and time as a wrong PIN. The new normal and duress PINs are stretched under a new salt and take effect with a rotation that hands out all 5 tickets; until that file is written the old file, its tickets and the old PINs stay valid. The new salt changes the stretch binding, and a written change turns fingerprint answer off. Refused after a fingerprint unlock and while fingerprint answer is being turned on, but only after the same current-PIN check, so the duress PIN still wipes there; such a refusal is the same for a right and a wrong PIN and is not counted. New PINs that are invalid (too short, too simple, equal, or over the byte limit) are reported only after that check, which they never skip; a right current PIN with invalid new PINs is not counted.
- **Fingerprint answer (optional, off by default)**: a strong fingerprint may stand in for the PIN only to answer a ringing secure call. Turning it on needs one real PIN attempt; that unlock keeps P_normal for at most 60 s, a StrongBox key `aegis_bio_v1` (AES-256-GCM, biometric for every use, invalidated by a new fingerprint, unlocked device required) wraps it into `bio_answer.bin` together with a binding to the vault's salt and KDF parameters. A fingerprint only releases P; the unlock still spends one single-use ticket and rotates. That rotation (and every later one until the vault locks) hands out only as many tickets as were live after the unlock plus one, so a fingerprint never gives back attempts spent on wrong PINs; the file keeps five records, and the ones above the cap have wraps whose key never exists. Only a PIN unlock refills all five. It is allowed only in the same boot and within 12 hours of the last PIN unlock (`bio_fresh.bin`, deleted by any wrong PIN), and the unlock is call-scoped: identity-changing operations are refused and the vault locks when that call ends or stops ringing. Duress, a dead vault and a wipe delete the key and both files. Details: `docs/design/fingerprint-answer.md`.

### 6.6 API and JNI changes

```rust
// aegiscall-crypto
pub const HS1_LEN: usize = 77; pub const HS3_LEN: usize = 1729; pub const HS4_LEN: usize = 129; pub const RS2_LEN: usize = 32; pub const RS3_LEN: usize = 80;
pub struct LocalIdentity { pub pub33: [u8; 33], pub evidence_id: [u8; 16] }   // PeerIdentity likewise drops edition_claim
pub struct ResumeCandidate { pub contact: u32, pub pub33: [u8; 33], pub secret: SecretKey32, pub is_new: bool }
pub struct PeerExpectation { pub psk: Vec<(u32, [u8; 33], SecretKey32)>, pub resume: Vec<ResumeCandidate> }
pub enum Path { Full, Resume { contact: u32, used_new: bool } }
pub struct Established { pub root0: SecretKey32, pub chaff_seed: SecretKey32, pub rs_next: SecretKey32, pub transcript_tag: [u8; 4],
                         pub role: Role, pub peer: PeerIdentity, pub path: Path, pub psk_contact: Option<u32> }   // HsError gains PskRequired, ResumeAuthFailed, PathMismatch
impl SessionCipher { pub fn from_root(root0: &SecretKey32, role: Role, tag: [u8; 4]) -> Self;
  pub fn stage_rx_epoch(&mut self, root: &SecretKey32, e: u32); pub fn commit_tx_epoch(&mut self, e: u32); }
// aegiscall-trust
impl Vault { pub fn create(pin: &[u8], duress: &[u8], rng) -> Result<(Self, Rotation), TrustError>;   // Rotation { new: Vec<(u32, SecretKey32)>, retire: Vec<u32> }
  pub fn begin_unlock(blob: &[u8], pin: &[u8]) -> Result<TicketUse, TrustError>;                        // TicketUse { ticket_id: u32, hmac_input: SecretKey32 }
  pub fn finish_unlock(blob: &[u8], ticket_id: u32, hmac_out: Option<&[u8; 32]>) -> UnlockOutcome;     // Normal(Vault)|Duress|Invalid{left}|Dead
  pub fn begin_rotation(&mut self, rng) -> Rotation; pub fn commit_rotation(&mut self) -> Vec<u8>; pub fn export(&self) -> Vec<u8>;
  pub fn resume_stage(&mut self, contact: u32, rs: SecretKey32, k: u8); pub fn resume_promote(&mut self, contact: u32, k: u8); }
```

- The JNI PIN flow becomes: `nativePinBegin(app, vaultBlob, pinUtf8) → ByteArray?` (ticket_id ‖ 32 B HMAC input) → Kotlin calls `useTicket` → `nativePinFinish(app, vaultBlob, ticketId, hmacOut?) → Int` (1 normal, 2 duress, 0 error, -5 no tickets left) → `nativeVaultRotateBegin(app) → ByteArray` (new ticket ids and material, ids to invalidate) → `nativeVaultRotateCommit(app, imported) → ByteArray?` (the new vault file).
- `nativeSetIdentity` drops the edition parameter; the media-type send functions are removed; `nativeTriggerLiveRekey` is renamed `nativeSessionRequestRatchet`. The events gain `PATH`, `PQ_PROGRESS`, `PQ_MIXED` and `VAULT_DIRTY(seq)`; after Kotlin has written the file it calls `nativeVaultSaved(app, seq)`, and only then does Rust send `RESUME_SAVED`.
- The Kotlin bridge becomes a single implementation with the methods `ensureIdentity`, `signSha256Ecdsa`, `importTicket(id, material)`, `useTicket(id, input32)`, `retireTicket(id)`, `listTickets` and `destroyAll`.
- **handle**: a registry entry is an `Arc<Mutex<Slot>>` with `enum Slot { Live(T), Closed }`, and every call holds this lock for the whole operation. After close acquires the lock it zeroes the contents, changes the slot to `Closed`, and then removes it from the registry; a call that already obtained the Arc earlier sees `Closed` when it gets the lock and returns -1. `nativePanicWipe` first sets the global `WIPING` flag so that all new calls return -1, and then closes all sessions and app entries in turn.

### 6.7 System hardening in two levels

| Level | Contents | Switch |
|---|---|---|
| Level 1 (on by default) | firewall, turning off Wi-Fi / mobile data / Bluetooth / NFC / UWB and auto scanning, USB charge-only, baseband restricted to LTE / NR, restore journal, monitoring and fail-closed | runs every time |
| Level 2 (dedicated-device mode, off by default) | suspend and terminate other apps, new-process monitoring, third-party input methods and accessibility services, memory scrubbing | `dedicated_mode=1` in `/data/adb/aegischat/policy.conf` |

- The switch lives in a file only root can change, and the app can learn the current level only from the READY reply. For every change made by Level 1, the user can change it back manually in system settings, and the firewall rules disappear on reboot; every change that only root can undo is in Level 2.
- **Disabling 2G / 3G**: when a session is opened (not during a call), the daemon runs `cmd phone set-allowed-network-types-for-users` for each SIM, leaving only LTE and NR, writes the original value into the restore journal (kind `NETTYPE`), and reads it back every 2 seconds. The app-side check in E3 stays as a second line.
- **Firewall** (adopted): the own chains stay inserted in first position, and `iptables-restore -w -n` is now used, declaring only the own chains and applying them atomically in one step. `aegis_out`: lo is allowed; `-o <ims_if> -m owner --uid-owner <ims_uid> -d <P-CSCF>` is allowed; the same condition with `-p udp -d <media address>` is allowed; ICMPv6 types 133–136 on the IMS interface are allowed; everything else is DROP. `aegis_in` correspondingly allows lo, a source that is the P-CSCF or a media address, and ICMPv6 133–136. There is no allow rule that looks only at the interface.
- **Address sources**: `ims_if` and the P-CSCF are taken from the data connection in `dumpsys telephony.registry` whose APN type includes IMS (the InterfaceName and PcscfServers of its LinkProperties), and that connection must not carry the INTERNET capability. `ims_uid` is the UID of the package reported by `cmd phone ims get-ims-service`, plus the `ims_uids` in `policy.conf`. If any item cannot be resolved, the pre-check fails.
- **Media addresses are learned from the first packet**: UDP sent by the IMS UID on the IMS interface to an unknown address is first handed to the daemon through `NFLOG` and then dropped; only if the daemon confirms a call is being dialed or in progress, and fewer than 4 addresses have been learned in this call, does it add that address to the rules, and they are cleared when the call ends. If the baseband handles the voice, no media packets appear on the AP side, and this step naturally stays inactive.
- **Address changes**: netlink address or link events trigger re-resolution immediately, and a comparison is also made every 2 seconds; on any change the whole rule set is regenerated and replaced atomically. Disappearance of the IMS registration is treated as a violation per E3.
- **Level 2 exemptions**: only packages on the read-only system partition (SystemUI, Telecom, the IMS service, carrier config, telephony providers, the permission controller, the installer), this app, and the Magisk manager app are exempt. The default dialer app and the default launcher must be built into the system image, otherwise the pre-check fails; anything the user installed is always suspended. The phone app built into the system image (`cmd telecom get-system-dialer`) is always exempt as well, even when this app is the default dialer, because Telecom shows emergency calls with it (see `default-dialer-v1.md`).
- **Input methods**: `ime disable` is no longer run. Third-party input methods are suspended along with the other apps; during the session the default input method is switched to the one built into the system image and the original value is recorded; the secure window has no component that can obtain input method focus. The lock screen works as usual, and pre-check item 6 (screen lock type) is removed.
- **Restore order**: stop monitoring (state becomes RESTORING, and later changes no longer count as violations) → confirm the secure process has ended → [Level 2] clear memory and logs → [Level 2] unsuspend → [Level 2] default input method and accessibility settings → USB function → allowed network types → each radio and setting → remove the firewall chains.
- A single item that fails after 3 retries is recorded and the process continues, and the firewall chains are always removed; failed items stay in the journal, the daemon retries them at its next start and at the next boot, and a system notification is issued. The pre-check requires only that USB debugging be off; the daemon does not change it.
- **Boot restore** does not depend on the daemon, the module's enabled state, or the Magisk app: when the module is installed it places the pure-shell `aegis-restore.sh` in `/data/adb/service.d/`, and on every boot it reads the restore journal and restores. The handling of the three kinds of crash is unchanged, and each stops monitoring first and then follows the order above.
- **Screen**: Level 1 can show only "Network cut off・Radios off・LTE / NR only"; "Other apps stopped" and "Memory cleared" are shown only when Level 2 is on and ran successfully.

### 6.8 Responses to review findings

| Finding | Conclusion | Change |
|---|---|---|
| 1 Restore, monitoring, lock screen | Adopted | 6.7: stop monitoring first, continue even on failure, the firewall is always removed, unsuspend before handling the input method, USB is ordered before the firewall, `service.d` boot restore, Magisk app exempt; the input method is no longer disabled across the board, so there is no need to restrict the lock screen type |
| 2 Firewall and exemptions | Adopted | 6.7: UID plus destination address; the dialer app and launcher are limited to those built into the system. SAS is not a secret, and being overheard does not affect security; the voice window screen adds "This is normal voice now; read out only the verification words" |
| 3 Attempt count and rollback | Adopted, handled differently | 6.5: one-time tickets are counted by hardware, and rotation invalidates old files |
| 4 Rekey collision | Adopted | 6.4: only the DH ratchet remains, single epoch, I initiates, stage first and then commit, salt changes with the epoch |
| 5 PSK and key change | Adopted | 6.2: PSK enforced by `pub33`, saving the number requires confirmation, sending is not allowed after a change until SAS has been compared |
| Handshake frames after establishment | Adopted | the last item of 6.2 |
| JNI close and in-flight calls | Adopted | `Slot` and `WIPING` in 6.6 |
| Signature covers evidence_id | Adopted | 6.2 |
| th0 definition | Adopted | 6.2 |

### 6.9 Implementation breakdown for this round

Verification: run `cargo test -p <crate>` for each crate. Each package declares dependencies only in its own crate's `Cargo.toml` (RustCrypto-family packages under MIT / Apache-2.0 only).

| Package | Write scope | Depends on | Required test scenarios |
|---|---|---|---|
| WP1 Handshake v2 and resume | `core/aegiscall-crypto/` | none | Full handshake with field-by-field tampering; a modified evidence_id fails signature verification; `PskRequired`; resume succeeds; all four holding combinations of `rs_cur` / `rs_new` select the newer common secret; no intersection takes the full path; rid reflection does not match; replaying an old RS2 / RS3 aborts; a signature or pinned key mismatch aborts; 10 consecutive ratchets leave both sides' keys identical; ACK loss is resent; R does not commit when it has not seen a frame of the new epoch; pq flag mix-in; abort after 1500 frames; a message that spans one epoch can be decrypted, spanning two is refused |
| WP2 Vault and attestation chain | `core/aegiscall-trust/` | the types of WP1 (settled in this section, so work can run in parallel) | Every item of E2, including StrongBox and brand; simulate tickets with a software HMAC: one each for normal, duress and wrong; 5 wrong attempts gives Dead; after rotation the old file returns Dead; the two wraps have equal length and their order leaks nothing; rotation recovers when interrupted either before or after the file write; resume stage / promote, including "receiving k confirms the smaller ones" |
| WP3 Link layer and session | `core/aegiscall-chat/`, `core/aegiscall-mux/src/lib.rs`, `core/aegiscall-modem/src/preamble.rs` | WP1; the change that removes the media features is merged first | With 5% loss, the full handshake takes ≤ 216 frames and resume takes ≤ 20 frames per side; injecting HS1 and ABORT after establishment does not change state, and the handshake closes after the first encrypted frame is received; BULK completes under loss and chat interleaving and triggers a ratchet; `RESUME_SAVED` loss at every point in time; abort on no preamble for 20 seconds; sending is refused when SAS has not been compared after a key change; a path decision mismatch aborts |
| WP4 JNI | `core/aegiscall-jni/`, `app/src/main/java/io/github/h4lovoid/dialcrypt/core/NativeBridge.kt` | WP1–3 | Stale and wrong-type handles, repeated close; when close runs concurrently with an in-flight call it returns -1 and the vault cannot be exported; new calls return -1 during `WIPING`; complete a full session and a resume session without the JVM; exported symbols match the `external fun` names one by one |
| WP6 Daemon two-level hardening | `daemon/`, `magisk-module/` | none | The rule text declares only the own chains, and every allow rule (except lo and ICMPv6) carries a UID and a destination address; a P-CSCF change produces new rules; media learning's cap of 4, in-call only, UDP only; no violation is reported during RESTORING; the firewall is still removed after some item fails; restore order; the journal can still be restored when truncated at any byte; when Level 2 is off, a fake system interface receives no suspend, input method, accessibility or memory-clear operation; the shell restore script and Rust produce the same commands from the same journal |

### 6.10 Residual risks and To be confirmed on device

- The Android behaviors below are written from recollection of the platform documentation and could not be verified on the development machine; they must be tested on the target Pixel and recorded as test fixtures (To be confirmed on device): whether StrongBox declares `FEATURE_KEYSTORE_SINGLE_USE_KEY`, and whether an imported one-time key is still unusable after the Keystore database is restored; the argument formats of the two `cmd phone` commands; whether `dumpsys telephony.registry` prints PcscfServers; the IMS package UID on the Pixel and whether voice media is on the AP or the baseband; whether the kernel has `NFLOG`; whether brand-field attestation works on an unlocked device.
- A root program can use up all 5 tickets and render the vault useless; this is a loss of availability and does not leak contents. The ticket material appears briefly in app memory before import.
- Before the background hardening completes, the post-quantum confidentiality of resume comes from the rs chain (the initial full handshake); if rs has leaked, only X25519 protects the call during this time. There is no limit on the number of calls that are too short to complete the hardening.
- The IMS UID can still send data to the P-CSCF and to learned media addresses; first-packet learning drops about 0.2 seconds of voice packets at the start of each call.
- While only LTE / NR is allowed, emergency calls may fail to connect on networks without VoLTE emergency calling.
- Level 1 does not stop other apps; they keep running without network access, and on a Magisk device a root program may still read this process; Level 2 must not be enabled before it has been verified on device.
- Approaches not adopted: limiting PIN attempts with a TEE counter or a file counter (can be rolled back); automatically falling back to the full handshake after a resume failure (lets a tamperer probe repeatedly); allowing the whole IMS interface by interface.
- The attestation chain is released only to a verified peer: `EVIDENCE_REQ` is answered when the SAS of this call has been confirmed or the peer is a pinned contact (matching stored key, PSK or resume secret). A request from an unverified peer is held without a reply and answered only if the SAS is confirmed later in the same call, so the hardware badge of a new contact appears only after the SAS comparison.
- Level 1 does not switch accessibility services off. The app fails preparation while `AccessibilityManager` reports any enabled service (`FEEDBACK_ALL_MASK`); the check runs once when preparation starts, so a service turned on later in the session is not detected, and root software can still read the screen.
- Contact phone numbers, mutual-add marks and the pairing seed in `contact_meta.bin` are sealed with the meta key inside the PIN vault, so they can be read only after the app PIN unlocks the vault, and locking clears them from memory. While the app is unlocked they are in app memory, where root software can read them like the rest of the vault contents.
- The pairing code holds no secret: the `psk` comes from an X25519 exchange between both people's pairing keys, so holding both codes is not enough to recognize their calls. Someone with a quantum computer who holds both codes can compute the `psk`, and a pairing seed leaked from a seized phone gives the `psk` with anyone whose code the attacker holds, deleted contacts included. After a new code (rotate), each pair must import each other's current code again: a re-import on one side alone makes the two stored `psk`s differ, and calls between them abort with PskRequired until the other side imports too. A card with a saved contact's pub33 and another X is only a replacement of that contact's PSK: the app shows which contact it would change and writes nothing until the user confirms; label, SAS verification, attestation and resume secrets stay, because they belong to the identity key. Someone who tricks the user into confirming such a card breaks the pairing (calls stop until both scan each other's current cards) but cannot impersonate the contact, whose identity signature the handshake still needs. The reply tag covers both whole 68-byte codes, so a reply whose X was swapped does not count as an answer. Replacing a pairing deliberately keeps SAS verification, attestation and resume secrets: they belong to the identity key, which did not change, and clearing them would only cut off the real contact after someone tricked the user into confirming a fake card. The consequence is that replacing a pairing cannot revoke the contact's old device: a phone that still holds the resume secret keeps resuming. To revoke a device, delete the contact, add it again and compare the words again.

## 1. Overview

The handshake uses one fixed suite: ZRTP-style commitment, SIGMA-I signatures, and a hybrid X25519 plus ML-KEM-1024 key exchange. Messages travel over a selective-repeat link on 23 B audio frames, and complete in about 38 seconds on broadband. No user data is released before the post-quantum part is done. The SAS becomes 5 words (40 bit) and cannot be ground down offline.
Trust rests on three things: the hardware signing key, a contact vault protected by a PIN, and key continuity that is remembered only after both sides have compared the SAS and it matched. The hardware attestation chain is sent once in the background over the encrypted channel after the connection is established and then cached; the hardware badge is shown only according to the verification result.
The secure session is run by the root daemon according to a write-ahead restore journal: cut the network, stop other apps, clear memory, and produce a brand-new clean process; at the end everything is restored in reverse order, with continuous monitoring throughout, and any deviation fails closed. All testable logic lives in Rust. JNI uses registry handles and a pull-based event queue.

## 2. Design details

### A. Trust model

The items that are stored are listed in the table below; anything not in the table is kept only in Rust locked memory:

| Item | Location and protection | Duress PIN / 5 wrong attempts |
|---|---|---|
| Identity signing key `aegis_id_v2` (P-256, SIGN only, SHA-256) | AndroidKeyStore. pixelTitan must use StrongBox; standardRoot tries StrongBox first and falls back to TEE only if that fails; if `KeyInfo` shows SOFTWARE, the key is refused. `setUnlockedDeviceRequired(true)`, and the attestation challenge is fixed to `"AegisChat-ID-v2"` | `deleteEntry` |
| PIN key `aegis_pin_v2` (HMAC-SHA256) | Same as above | `deleteEntry` |
| Vault `noBackupFilesDir/vault.v2` | Root key = HMAC_SE(Argon2id(PIN, salt, 64 MiB, t=3, p=1)), then HKDF splits out a verification value and a content key. The content is encrypted with XChaCha20-Poly1305 and padded to a multiple of 4 KiB | Overwritten with random bytes of the same length, then deleted |
| Contact records (stored inside the vault) | `pub33`, edition claim, optional PSK, `phone_tag = HMAC(content key, E.164)[..16]`, label, SAS-verified flag, attestation verdict (level, boot state, patch level, evidence_id). No timestamps are stored | Disappear with the vault |
| Messages, session keys, SAS, the peer's raw attestation chain | Kept only in the Rust `LockedBuffer` and zeroized after use | Cleared immediately, and a panic is sent to the peer |

- The vault header stores two verification values (normal and duress), sorted by byte value so that it is not visible which one is the duress value. The attempt count is recorded in the header, and 5 consecutive wrong attempts count as duress. The PIN logic moves from [memsec lib.rs](../../core/aegiscall-memsec/src/lib.rs#L488) into the vault, and the old in-RAM BLAKE3 approach is removed.
- Key continuity is implemented, but a key seen for the first time is not trusted blindly. A new peer may be "saved as a contact" only after both sides have pressed "SAS matches" in this call. After that, if a different `pub33` appears for the same `phone_tag`, it is judged "key changed": a red full-screen warning is shown and sending is paused until the user chooses "re-compare and update" or "continue this time as unverified". A contact with a PSK always requires the PSK, and a mismatch aborts directly, with no fallback.
- Hardware attestation evidence: each side places `evidence_id = SHA-384(attestation chain without the root certificate)[..16]` in the identity block, and this value is covered by the signature. When the peer's cache does not contain this id, the encrypted control frame `EVIDENCE_REQ` is sent after the connection is established. The holder sends the chain without its root (about 2–3 KB) as a low-priority internal transfer over the existing fragment ARQ (10 B per frame, about 30–50 seconds, chat has priority). The binding requires the leaf certificate's public key to equal the `pub33` already signed in the handshake. The verification verdict is stored in the contact record, and afterwards only the id is compared.
- Screen claims: identity and hardware are two independent labels. The edition claim flag is not used in any badge, and the current `PeerTrustLevel` is removed.

| Stage | What may be shown |
|---|---|
| Preamble and during handshake | "Establishing encryption NN%, about MM seconds left"; the words "encrypted" and "secure" must not appear |
| Established, unknown peer | Orange "Encrypted (includes post-quantum)・identity not verified" |
| Both sides' SAS match in this call | Green "Verified in this call" |
| Saved contact and key matches | Green "Verified contact"; with a PSK it adds "Paired" |
| Key changed | Red full-screen "The peer's key has changed" |
| Hardware label | Only when verification passes: "StrongBox / TEE・locked / self-signed locked / unlocked"; otherwise "hardware not attested" |
| Abort | "Not established; nothing was sent" |

### B. Handshake wire specification (protocol v2, single suite 0x01)

Suite contents: X25519 + ML-KEM-1024, HKDF-SHA-384, XChaCha20-Poly1305, and ECDSA-P256-SHA256 identity signatures. 1024 was chosen to align with CNSA 2.0 and Signal PQXDH, at a cost of about 8 seconds more than 768. Static-to-static ECDH is removed, and identity is proved only by signing the whole transcript.

**Roles**: both sides send HS1 at the same time, and the side with the larger `commit` value acts as Initiator (I); if equal, both draw new random values and start over. This does not depend on the dialing direction, so an interceptor tampering with the roles gains nothing.

**Link layer (before keys are established, `hs_link`)**, layout of each 23 B superframe:

| Byte | Contents |
|---|---|
| 0 | The high 4 bits are fixed at `0xA`; the low 4 bits are the type: 1–4 = HS1–HS4, `0xE` = ACK, `0xF` = ABORT |
| 1 | DATA frames carry the fragment sequence number; ACK frames carry the message type being acknowledged |
| 2 | The sender's random tag for this attempt. The receiver locks onto the first value received and discards frames with any other value |
| 3–20 | 18 B of data (the last fragment is padded with 0, and the message length is fixed); ACK frames carry a 144-bit received bitmap |
| 21–22 | CRC-16/CCITT, covering 0–20 |

- Each side must send one frame every 160 ms. If there are unacknowledged fragments it alternates among them; if not, it sends the ACK bitmap. While sending data and receiving at the same time, one ACK frame is inserted for every 4 fragments received. It uses selective repeat, and retransmission is driven by the ACK bitmap.
- If AEAD decryption of a frame fails after the keys are established, it then tries parsing it as a handshake frame, to handle the case where the peer is still resending its last message.
- The preamble is sent at the start and then resent every 2 seconds until the peer's first valid handshake frame is received. Within one session the preamble content is fixed.

**Messages** (fixed length; if any of length, type or order does not match, abort):

| Message | Direction | Layout | Length / frames |
|---|---|---|---|
| HS1 | both | ver(1)=2 · suite(1) · caps(2) · gear(1) · nonce(16) · psk_tag(8) · commit(32). commit = SHA-384("AegisCommit-v2" ‖ HS1[0..29] ‖ x25519_pub)[..32]; psk_tag = HMAC-SHA384(psk, "AegisPSK-v2" ‖ nonce)[..8], filled with random bytes when there is no PSK | 61 B / 4 |
| HS2 | R→I | x25519_R(32, must match R's own commit) · ek_R(1568) | 1600 B / 89 |
| HS3 | I→R | x25519_I(32, must match commit) · ct(1568) · AEAD_{k_i2r}(ID_I) | 1730 B / 97 |
| HS4 | R→I | AEAD_{k_r2i}(ID_R) | 130 B / 8 |
| Finished | I→R | The first encrypted superframe, control subtype `HS_FINISHED`. R counts as complete when it receives the first valid encrypted frame, and until then keeps resending HS4 | 1 frame |

The ID block (114 B) = pub33(33) · edition_claim(1) · evidence_id(16) · sig(64, raw r‖s format), plus a 16 B tag.
How the PSK is chosen: each side tries the PSKs of all its contacts against the peer's HS1 psk_tag. If the contact that `phone_tag` maps to requires a PSK but there is no match, abort. The `pub33` of the contact that owns the matching PSK must equal the identity the peer reveals.

**Transcript (SHA-384 running hash)**, absorbed in this order:
protocol label "AegisChat-v2|X25519|MLKEM1024|P256|SHA384|XCHACHA" → pre_I(5) → pre_R(5) → gear → HS1_I → HS1_R → HS2 → x25519_I. A snapshot `th_sas` is taken here; then ct is absorbed to give `th3`, the HS3 ciphertext part is absorbed to give `th4`, and HS4 is absorbed to give `th5`.
pre_X is the raw 5 bytes of the preamble that X sent (each side uses the one it sent and the one it received). The gear takes the smaller of the two sides' preferences. So the preamble capabilities, gear, version, ek and ct are all bound into the transcript.

**Key schedule (HKDF-SHA-384)**:

- `ck0 = Extract(th0, psk or 0^32)`; `ck1 = Extract(ck0, X25519(e_I, e_R))`
- `sas = Expand(ck1, "sas" ‖ th_sas, 5)`, mapped onto the existing 256-word list, 5 words in all
- `ck2 = Extract(ck1, ML-KEM shared secret)`
- `k_i2r = Expand(ck2, "hs i2r" ‖ th3)`, `k_r2i = Expand(ck2, "hs r2i" ‖ th4)`. The AEAD nonce is all zeros (each key is used only once), and the AAD is th3 and th4 respectively
- `sig_I = ECDSA_I("AegisChat-v2 auth I" ‖ th3 ‖ pub33_I)`; `sig_R = ECDSA_R("AegisChat-v2 auth R" ‖ th4 ‖ pub33_R)`. The signature covers the whole transcript and the signer's own identity
- Application-layer keys are derived from `Expand(ck2, label ‖ th5)`: key i2r / r2i (32 each), salt i2r / r2i (16 each), inner (32), chaff (32), ratchet root (32). `transcript_tag = th5[..4]`. All ck values, DH results and KEM secrets are zeroized immediately after use

**Security of the SAS commitment**: I commits to its own value in HS1 and only afterwards sees R's value. R must receive I's HS1 before it reveals x25519_R, and I reveals last. ct is generated freely by I after it has seen ek, so it is not put into the SAS but only into key derivation, and tampering with it only makes the handshake fail. The result is that a man in the middle has just one 2^-40 chance of guessing right per handshake.

**How the SAS is compared**: when either side presses "voice comparison" it sends the `VOICE_WINDOW` control frame. Both sides stop modulating and switch to voice for at most 60 seconds. When it ends, the preamble is resent and the counters continue. The comparison result is exchanged with the `SAS_RESULT` control frame; if either side presses "mismatch", both sides abort and clear.

**PQ policy and downgrade protection**: the suite has no non-PQ version, and no user data is sent or received before Finished. If the peer's preamble version is not 2, or caps lacks `CAP_SUITE_V2` (1<<5), abort and show "Version incompatible".

**Timeouts and abort** (broadband values; double on narrowband): waiting for the preamble 60 seconds; the whole handshake 90 seconds; no new fragment for 15 seconds aborts; local signing 5 seconds. On any failed check: send 3 ABORT frames, zeroize the ephemeral keys, the KEM decapsulation key and all ck values, and change the state to Aborted. Retry happens only when the user presses the button manually, at most 3 times per call, each time with fresh ephemeral keys, and there is no automatic fallback.

**Time estimate** (broadband 160 ms / frame, 5% loss, round trip 0.6 seconds, StrongBox signing 0.3 seconds):

| Step | Frames | Estimated time |
|---|---|---|
| Preamble exchange | — | 0.6 s |
| HS1 sent by both at once, plus round trip | 4 | 1.3 s |
| HS2 (includes ek) | 89 | 14.2 s |
| I encapsulates and signs, plus round trip | — | 0.9 s |
| HS3 | 97 | 15.5 s |
| R decapsulates, verifies the signature, signs, plus round trip | — | 0.9 s |
| HS4 | 8 | 1.3 s |
| Finished plus round trip | 1 | 0.8 s |
| Retransmission of lost frames | about 10 | 2.5 s |
| **Total** | **about 209** | **about 38 s on broadband; about 72 s on narrowband** |

### C. Periodic rekeying

- Symmetric ratchet: every 375 frames (about 60 seconds on broadband) the existing staged rekey runs automatically, putting the currently unused `REKEY_INTERVAL_FRAMES` into effect. The manual button is changed to trigger the DH ratchet.
- Add a DH ratchet: every 1875 frames (about 5 minutes on broadband) or on a manual trigger, always initiated by I.
  - I sends a new X25519 public key, control subtype `DH_RATCHET`, in 3 frames of 13 B each (epoch_lsb · fragment number · 11 B of data). R returns its own new public key with `DH_RATCHET_ACK`, also in 3 frames.
  - `root' = Extract(root, dh ‖ epoch)`, and from root' a 32 B mix value for each direction is derived and applied to the existing "stage RX first, commit TX after confirmation" fence mechanism.
  - The cost is 6 frames every 5 minutes, about 1 second of channel time; in return the call can recover after a mid-call key leak.
- ML-KEM is not redone periodically: doing it once takes about 285 frames (46 seconds). The root chain already contains the ML-KEM secret from the handshake, so every later epoch still has PQ confidentiality.
- The uncalled `ratchet_mix` is removed.

### D. Rust API

```rust
// aegiscall-crypto/src/handshake_v2.rs (replaces handshake.rs)
pub const PROTO_V2: u8 = 2; pub const SUITE_V2: u8 = 1; pub const SAS_WORDS: usize = 5;
pub const HS1_LEN: usize = 61; pub const HS2_LEN: usize = 1600; pub const HS3_LEN: usize = 1730; pub const HS4_LEN: usize = 130;
pub enum Role { Initiator, Responder }
pub struct LocalIdentity { pub pub33: [u8; 33], pub edition_claim: u8, pub evidence_id: [u8; 16] }
pub struct LinkContext { pub local_preamble: [u8; 5], pub peer_preamble: [u8; 5], pub gear: u8 }
pub struct PeerExpectation { pub psk_candidates: Vec<(u32, SecretKey32)>, pub required_psk_contact: Option<u32> }
pub enum HsOut { Send { msg_type: u8, body: Vec<u8> }, NeedSignature { req_id: u32, to_sign: Vec<u8> },
                 Sas([&'static str; 5]), Established(Box<Established>) }
pub struct Established { pub cipher: SessionCipher, pub chaff_seed: SecretKey32, pub ratchet_root: SecretKey32,
                         pub role: Role, pub peer: PeerIdentity, pub psk_contact: Option<u32>, pub th5: [u8; 48] }
pub struct PeerIdentity { pub pub33: [u8; 33], pub edition_claim: u8, pub evidence_id: [u8; 16] }
pub enum HsError { Malformed, VersionMismatch, RoleTie, CommitMismatch, AeadFail, BadSignature, PskMismatch, Timeout, PeerAbort, SignerFailed }
impl HandshakeV2 {
  pub fn start(l: LocalIdentity, k: LinkContext, e: PeerExpectation, rng: &mut impl CryptoRngCore) -> Result<(Self, Vec<HsOut>), HsError>;
  pub fn on_message(&mut self, msg_type: u8, body: &[u8]) -> Result<Vec<HsOut>, HsError>;
  pub fn on_signature(&mut self, req_id: u32, sig_der: &[u8]) -> Result<Vec<HsOut>, HsError>; }
// identity.rs
pub fn spki_der_to_pub33(spki: &[u8]) -> Result<[u8; 33], CryptoError>;
pub fn ecdsa_der_to_raw(der: &[u8]) -> Result<[u8; 64], CryptoError>;
pub fn verify_identity_sig(pub33: &[u8; 33], msg: &[u8], sig: &[u8; 64]) -> Result<(), CryptoError>;
pub fn classify_peer(peer: &PeerIdentity, stored: Option<&[u8; 33]>, sas_ok: bool) -> IdentityStatus; // Unverified|SasVerified|KnownContact|KeyChanged
// dh_ratchet.rs
impl DhRatchet { pub fn new(root: SecretKey32, role: Role) -> Self; pub fn begin(&mut self, rng) -> [u8; 32];
  pub fn on_peer_pub(&mut self, p: &[u8; 32], rng) -> Result<(Option<[u8; 32]>, RatchetMix), CryptoError>; }
// aead.rs: the salt parameter of stage_rx_ratchet / commit_tx_ratchet becomes a &[u8; 32] mix; sas_words.rs: format_sas_words(&[u8; 5])
```

The following are removed: `TripleHybridHandshake`, `FastHandshakeInit`, `HardwareSeProvider`, `PeerTrustLevel`, `attestation_message`. `InProcessP256Provider` becomes `#[cfg(any(test, feature="test-signer"))] SoftwareSigner`. The pairing code keeps the 68 B layout with the version changed to 3 and the X25519 pairing public key in place of the psk, and the identity inside it becomes the signing public key.

```rust
// new crate aegiscall-trust
pub fn verify_attestation(chain_no_root: &[Vec<u8>], cfg: &TrustConfig, expected_pub33: &[u8; 33]) -> Result<AttestationVerdict, TrustError>;
pub struct AttestationVerdict { pub level: SecLevel /*StrongBox|Tee*/, pub boot: BootState /*Verified|SelfSigned{key}|Unlocked*/, pub os_patch: u32, pub evidence_id: [u8; 16] }
impl TrustConfig { pub fn from_tlv(b: &[u8]) -> Result<Self, TrustError>; }
impl Vault { pub fn stretch_pin(blob: Option<&[u8]>, pin: &[u8]) -> Result<(SecretKey32, VaultHeader), TrustError>;
  pub fn create(h: VaultHeader, se_normal: &[u8; 32], se_duress: &[u8; 32]) -> Result<Self, TrustError>;
  pub fn unlock(blob: &[u8], se_out: &[u8; 32]) -> (UnlockOutcome /*Normal(Vault)|Duress|Invalid{left}|LockedOut*/, Vec<u8> /*file to write back*/);
  pub fn export(&self) -> Vec<u8>; pub fn expectation_for(&self, e164: Option<&[u8]>) -> (PeerExpectation, Option<[u8; 33]>);
  pub fn upsert_contact(&mut self, c: ContactRecord); pub fn wipe(&mut self); }
// new crate aegiscall-ime: ZhuyinEngine::load(lexicon) / candidates(syllables, max) -> Vec<String> (no learning, nothing persisted)
// aegiscall-chat: hs_link.rs, call_session.rs
impl HsLink { pub fn new(tag: u8) -> Self; pub fn send(&mut self, t: u8, body: Vec<u8>); pub fn next_frame(&mut self) -> [u8; 23];
  pub fn on_frame(&mut self, f: &[u8; 23]) -> Result<Option<(u8, Vec<u8>)>, HsLinkError>; pub fn all_acked(&self) -> bool; }
pub enum TxUnit { Preamble([u8; 5]), Superframe([u8; 23]) }
impl SecureCallSession { pub fn new(l: LocalIdentity, e: PeerExpectation, stored: Option<[u8; 33]>, gear: ModemGear, now: u64) -> Result<Self, ChatError>;
  pub fn next_tx(&mut self, now: u64) -> TxUnit; pub fn on_rx_preamble(&mut self, raw: [u8; 5], now: u64);
  pub fn on_rx_superframe(&mut self, w: &[u8; 23], now: u64); pub fn on_signature(&mut self, id: u32, der: &[u8]);
  pub fn poll_events(&mut self) -> Vec<SessionEvent>; pub fn sas_decision(&mut self, ok: bool); pub fn accept_key_change(&mut self);
  pub fn voice_window(&mut self, open: bool); pub fn chat(&mut self) -> Result<&mut ChatSessionEngine, ChatError>; pub fn abort(&mut self, r: AbortReason); }
```

New control subtypes: 9 `HS_FINISHED`, 10 `DH_RATCHET`, 11 `DH_RATCHET_ACK`, 12 `SAS_RESULT`, 13 `VOICE_WINDOW`, 14 `EVIDENCE_REQ`, 15 `SESSION_END`, 16 `GEAR_SWITCH`.
`preamble.rs`: `PROTOCOL_VERSION` becomes 2, `CAP_SUITE_V2` is added, and the detection result must carry the raw 5 bytes of the preamble.

**JNI handle**:

- Managed with `static REG: OnceLock<Mutex<Registry>>`, with app and session as two separate `HashMap<u64, Arc<Mutex<..>>>` tables.
- A handle is a 63-bit non-zero random number produced by OsRng and is never reused. A lookup only clones the Arc and then releases the registry lock. Closing removes the registry entry and triggers zeroize through Drop.
- A stale or wrong-type handle always returns `-1`. Pointers are no longer cast at all, replacing the raw pointer in the current [jni lib.rs](../../core/aegiscall-jni/src/lib.rs#L200).
- `panic=abort` is kept, so that process death is itself fail-closed.
- Return codes: 0 = OK; -1 invalid handle, -2 bad argument, -3 wrong state, -4 cryptographic failure, -5 locked, -6 aborted, -7 busy, -8 internal error.

| Kotlin `NativeBridge` (loaded only in the secure process) | Parameters → return |
|---|---|
| `nativeHarden` | () → Int; returns -8 if any of mlockall, dumpable or core fails |
| `nativeAppOpen` | (trustTlv, lexicon?) → Long; 0 = failure |
| `nativeSetIdentity` | (app, spkiDer, chainTlv, editionClaim) → Int |
| `nativePinStretch` | (app, vaultBlob?, pinUtf8) → ByteArray? (32 B, handed to `hmacPin`) |
| `nativePinSetup` | (app, seNormal, seDuress) → ByteArray? (the new vault file) |
| `nativePinVerify` | (app, vaultBlob, seOut) → Int; 1 normal, 2 duress, 0 error, -5 locked |
| `nativeVaultExport` | (app) → ByteArray. After every verify or contact save the file must be written atomically; after duress it returns random bytes of the same length |
| `nativePairingCode` / `nativeImportPairing` | (app) → String? / (app, code) → Int |
| `nativeImeCandidates` | (app, zhuyin, max) → String (separated by `\u0000`) |
| `nativeSessionCreate` | (app, peerE164?, wideband) → Long |
| `nativeSessionTxPcm` / `nativeSessionRxPcm` | (s) → ShortArray? / (s, pcm: ShortArray, nowMs) → Int |
| `nativeSessionPollEvents` | (s) → ByteArray; the TLV format is type u8 · len u16 BE · value |
| `nativeSessionSignResult` | (s, reqId, ok, derSig?) → Int |
| `nativeSessionSas` / `AcceptKeyChange` / `VoiceWindow` / `SaveContact` | (s, ok) / (s) / (s, open) / (s, label) → Int |
| `nativeSessionBearerViolation` | (s, code) → Int; aborts and clears immediately |
| The existing send functions | The first parameter becomes the session handle; returns -3 when not yet established |
| `nativeSessionClose` / `nativePanicWipe` / `nativeAppClose` | (s, notifyPeer) / (app) / (app) → Int |

**The uplink interface is pull-based**: Rust never calls Java. When a signature is needed, Rust emits the event `NEED_SIGNATURE(req_id u32, msg)`; Kotlin signs with `SHA256withECDSA` on a dedicated thread and then calls `nativeSessionSignResult` to return the DER. Rust converts the DER to 64 B and verifies it once with its own public key before using it. The PIN goes through an explicit three steps: stretch → `hmacPin` → verify. The reasons for this are to avoid JNI callbacks while holding a lock, to avoid thread attach, and so that the state machine can be driven directly in Rust tests with SoftwareSigner.

### E. Kotlin side and secure session lifecycle

**E1 Key bridge**

```kotlin
interface HardwareKeyBridge {
    val editionClaim: Int                              // 1 standardRoot, 2 pixelTitan (self-declared only)
    fun ensureKeys(): IdentityMaterial                 // create or load aegis_id_v2, aegis_pin_v2
    fun signSha256Ecdsa(message: ByteArray): ByteArray // returns DER
    fun hmacPin(input32: ByteArray): ByteArray          // returns 32 B
    fun destroyAllKeys(): Boolean
}
data class IdentityMaterial(val spkiDer: ByteArray, val chainDer: List<ByteArray>, val securityLevel: Int)
```

`computeP256EcdhSecret` and `verifyPeerHardwareChain` are removed; the TitanM2 approach of judging by the issuer string is not valid. ByteArrays handed out are zeroed on the Kotlin side immediately after use.

**E2 Attestation chain verification checklist**

Verification lives in the Rust trust crate. Kotlin only loads `attestation_roots.der`, `attestation_revoked.txt`, `avb_keys.txt`, `app_signers.txt` and `min_patch.txt` under `res/raw`; if any one is missing, startup is refused.

1. The chain is 2–6 certificates long, issuer/subject link up certificate by certificate, each signature is verified, and the last certificate must be verifiable by a root certificate in the resource file (compared by SPKI SHA-256). ECDSA P-256 / P-384 and RSA PKCS#1 are supported.
2. A serial number that appears in the revocation snapshot is refused.
3. The SPKI of the leaf certificate equals the `pub33` in the handshake.
4. The leaf certificate's KeyDescription (OID 1.3.6.1.4.1.11129.2.1.17) appears exactly once, with attestationVersion ≥ 4.
5. Both the attestation and keyMint security levels must be TEE or StrongBox; Software is refused.
6. The challenge equals `"AegisChat-ID-v2"`.
7. Hardware-enforced list: the only purpose is SIGN, EC, P-256, and the origin is GENERATED.
8. rootOfTrust: Verified is labeled "locked"; SelfSigned with the boot key in `avb_keys` is labeled "self-signed locked"; anything else is labeled "unlocked", accepted but explicitly labeled.
9. The package name in attestationApplicationId belongs to one of this app's two packages, and the signature hash is in `app_signers`.
10. osPatchLevel ≥ the minimum value.

When verification fails, only the hardware label changes to a red "evidence invalid"; the call is not aborted, since identity trust is judged independently.

**E3 Bearer restriction (`BearerGuard.kt`)**

- Permissions: READ_PHONE_STATE (runtime permission), plus READ_PRECISE_PHONE_STATE (privileged, to be added to the privapp list), and ANSWER_PHONE_CALLS. No network permission is added.
- Use `ImsMmTelManager.registerImsRegistrationCallback`: require `transportType == WWAN` and `registrationTechnology ∈ {LTE, NR}`. IWLAN, CROSS_SIM or not registered counts as a violation.
- During a call: on API 31–32 use `CallAttributesListener`, on API 33 and above use `onCallStatesChanged`. `CallState.networkType` must be LTE or NR, and is cross-checked with `getVoiceNetworkType()`.
- Handover: LTE↔NR (including EPS fallback) is allowed and continues. If SRVCC moves to 2G / 3G or to IWLAN, `nativeSessionBearerViolation` is called immediately, followed by hanging up with `TelecomManager.endCall()`; the daemon mutes the uplink at the same time.
- When the codec becomes AMR-NB, an encrypted `GEAR_SWITCH` is sent to switch to the narrowband gear.
- Every 2 seconds the daemon cross-checks with `dumpsys telephony.registry`, to guard against an app process that has been hooked and lies.

**E4 Lifecycle: how the three components divide the work**

| Component | Responsibility |
|---|---|
| Magisk module | Installs the daemon, sepolicy and the privapp list. `service.sh` guards the daemon in a loop (restarted within 1 second if it dies) and runs `aegiscalld --recover-boot` after boot completes. `action.sh` provides a manual "restore now" |
| daemon (root) | The only component that changes the system: checks, network cut-off, stopping apps, clearing memory, writing the restore journal, monitoring, fail-closed, restore |
| Launcher process (default process) | Loads no native library and touches no secret. It only shows the preparation screen, asks the daemon to prepare, starts the secure process on success, and then ends itself |
| Secure process (`android:process=":secure"`) | Native hardening, PIN, handshake, chat; sends a lease heartbeat to the daemon every 500 ms |

**IPC**: abstract Unix socket `@io.github.h4lovoid.dialcrypt.d`. The daemon obtains the uid with SO_PEERCRED, looks up the package name in packages.list, then parses the v2/v3 signature block of that APK and compares it with the pinned signature hash. The frame format is `[u16 len][u8 type][payload]`, and the message types are: HELLO, PREPARE, PROGRESS, READY(lease 16 B), FAIL(item, reason), ATTACH, ATTACHED, HEARTBEAT, VIOLATION, END, ENDED. If the lease has no heartbeat for 2 seconds, the app is considered dead.

**1. Network cut-off**

The daemon first builds the firewall, then turns off the various radios, and finally turns off the system's auto-restart options; every item must be read back to confirm.

| Layer | Method |
|---|---|
| Firewall (IPv4/IPv6) | Creates its own chains `aegis_in`, `aegis_out`, `aegis_fwd` and inserts them in first position with `iptables -w -I <chain> 1`. Only lo and the IMS / EIMS interface are allowed; everything else is DROP. It never uses `-F` or `-P`, and does not touch the built-in chains or netd's chains. The table-flushing approach in the former `daemon/src/root_fortress.rs` (line 161) must be removed |
| IMS interface | Find the InterfaceName that carries both the CELLULAR and the IMS / EIMS capability from `dumpsys connectivity`; re-resolve when a netlink link or address event arrives. On platforms where IMS is on the AP side (Tensor, MediaTek), the traffic through this interface is allowed; on platforms where IMS is on the baseband side it does not pass through the AP and is unaffected to begin with |
| Wi-Fi | Turn off Wi-Fi, and set `wifi_scan_always_enabled` and `wifi_wakeup_enabled` to 0 (which also rules out VoWiFi) |
| Mobile data | Turn off internet data for every SIM. The IMS PDN is not affected by this switch |
| Bluetooth, NFC, UWB | All turned off; `ble_scan_always_enabled` and Bluetooth auto-enable are turned off as well |
| Hotspot, USB / Bluetooth tethering | The pre-check requires them to be off already. The daemon does not toggle them for the user and only monitors during the session |
| USB function | Changed to charge-only, with the original function string recorded |

Monitoring is of two kinds: netlink events trigger a check immediately; in addition, every 1 second it checks whether the jump rules are still in first position, the content hash of the chains, the read-back values of each setting, and whether any interface other than lo and IMS is UP. If any item has been turned back on, it is handled by the fail-closed flow below.

**Fail-closed flow**:

1. The daemon sends VIOLATION to the app, and the app clears and kills itself within 200 ms.
2. The daemon mutes the uplink and turns the item that was turned on back off.
3. After confirming the process is gone, it runs the normal end flow.

**2. Stopping other applications**

- The targets are all packages with uid ≥ 10000 that are not on the exemption list. The method is to `pm suspend` first (recording whether it was already suspended), and then send SIGKILL to all of its processes.
- During the session, new processes are watched with the netlink proc connector (when it is not supported, /proc is scanned every 250 ms instead), and any non-exempt process is killed as soon as it appears.
- force-stop is not used: it keeps clearing the other app's alarms and schedules until that app is next opened.
- The exemption list lives inside the module and the project owner can modify it: SystemUI, Telecom, the platform's IMS service, carrier config, telephony providers, the default dialer app, the system phone app, the launcher, the permission controller and the installer, and this app. GMS, browsers, input methods, accessibility apps and the clock are all stopped.
- Input methods: use the app's built-in keyboard (Zhuyin, digits, English), with candidates provided by the Rust ime crate, and the secure process never lets a system text field take focus. The daemon records `enabled_input_methods` and the default, and then runs `ime disable` on each one.
- Accessibility services: after the daemon records the original value, it empties `enabled_accessibility_services` and sets `accessibility_enabled` to 0.
- The app side additionally sets `FLAG_SECURE`, `setHideOverlayWindows(true)`, `setAccessibilityDataSensitive(true)` and `setRecentsScreenshotEnabled(false)`.
- On restore, only the packages we suspended ourselves are unsuspended, and the input method and accessibility settings are restored. Killed apps restart on their own.

**3. How far memory clearing can honestly go**

| Time | What a Magisk unlocked device can do | What only a self-signed relocked device (custom-built kernel) can do |
|---|---|---|
| Before start | Kill all non-exempt processes → `drop_caches=3`, `compact_memory` → swapoff, reset, swapon for zram → start a child process (oom_score_adj 1000) that keeps allocating free memory with `MAP_POPULATE` until 256 MiB remain or 8 seconds have passed, then frees it, so the kernel overwrites the freed physical pages with zeros | Kernel parameters `init_on_free=1 init_on_alloc=1` (zeroed on free), and the system has no swap |
| During | The daemon raises the secure process's memlock limit with prlimit; the process calls `mlockall(CURRENT\|FUTURE\|ONFAULT)` so its pages never go to zram; `PR_SET_DUMPABLE=0`, `RLIMIT_CORE=0` | No other root can read `/proc/pid/mem` |
| After end | Rust zeroes keys, messages, the vault and the SAS; Kotlin empties the UI lists; the process kills itself; the daemon redoes drop_caches, the zram reset and the free-page overwrite, and clears logcat and dmesg (writing the files directly, not through `sh -c`) | The process's pages are zeroed the moment they are freed |
| Cannot be done | Kernel slab and socket buffers, GPU and display buffers, audio DSP and baseband memory, copies of Kotlin Strings before the process ends, DRAM remanence | The baseband and DSP still cannot be controlled |

**4. Two-stage clean start**

Stage one (launcher process): the daemon runs the pre-check first, and if any item fails it replies FAIL and the system is left completely unchanged.

1. Boot verification: `ro.boot.vbmeta.device_state`, `verifiedbootstate`, `flash.locked`. locked + yellow with the AVB key on the allowlist → self-signed locked; unlocked + orange → Magisk mode (allowed but labeled); red or inconsistent state → failure.
2. SELinux is enforcing.
3. `adb_enabled`, `adb_wifi_enabled` and `development_settings_enabled` are all 0, and adbd is not running.
4. There is no device owner or profile owner.
5. Hotspot and all kinds of tethering are off.
6. The screen lock is a PIN or pattern (the system input method will be disabled, and an alphanumeric password could not be entered).
7. There is no screen recording or casting, and no other process is capturing audio.
8. `/proc/swaps` contains only zram.
9. In Magisk mode, this app is on the DenyList and the DenyList is enforced; there are no injection framework processes such as frida or LSPosed.
10. IMS is registered on WWAN over LTE / NR, and the IMS interface can be resolved.
11. The system commands required by this device's version all exist and can be read back.

Only after all pre-checks pass are the following run in order: write the restore journal (marked ACTIVE) → cut the network → stop apps → clear memory → return READY(lease).

Stage two: after the launcher starts the secure process, it kills itself. The secure process sends ATTACH, and the daemon checks item by item:

- the process start time is later than READY;
- the cmdline is `:secure`;
- TracerPid is 0;
- maps contains none of frida, xposed, zygisk, riru, substrate;
- the launcher process is gone;
- the input method, accessibility and overlay windows have all been cleared.

Only when the checks pass does it reply ATTACHED. The secure process then calls `nativeHarden` and exits if it fails.

**5. Restore journal and crash handling**

The journal lives at `/data/adb/aegischat/journal.v1`, the directory has permission 0700 root, and the app cannot read it.

- It is write-ahead: before each change, a line INTENT (including the original value) is appended and the file and directory are fsynced; after the change completes, a line DONE is appended.
- Each line has the format `seq⇥INTENT|DONE⇥kind⇥target⇥prior⇥crc32`, and field values are restricted to `[A-Za-z0-9._:/,=-]`. The header is `ACTIVE⇥boot_id⇥lease_hash⇥pid:starttime`.
- The kinds include: FW, RADIO, SETTING, USB, PKG_SUSPEND, IME, A11Y, ZRAM. The journal contains no message content, number or key.
- On restore, all INTENT entries are processed in reverse order (those without a DONE are also restored, because restore is idempotent), and the journal is deleted only after each item has been read back and confirmed. If an item still fails after 3 retries, the journal is kept and a system notification is issued.

| Situation | Detection | Handling |
|---|---|---|
| The app's secure process crashes | Socket EOF or no heartbeat for 2 seconds | The uplink stays muted → confirm the process is dead (SIGKILL if necessary) → clear memory → restore in reverse order |
| The daemon crashes | The app sees socket EOF; the guard loop restarts the daemon within 1 second | The app clears immediately and kills itself. The firewall chains are still in the kernel, so the network stays blocked. The new daemon reads ACTIVE with the same boot_id → confirms the secure process is gone → clears memory → restores |
| Reboot during a call | `--recover-boot` finds a different boot_id | iptables is gone with the reboot. Persisted settings stay off until restored, and then it restores according to the journal |

**Normal end flow**

Triggers: pressing "End", the call hanging up, the app leaving the foreground for more than 60 seconds (the screen is hidden the moment it leaves, and the PIN must be entered again on return), entering the duress PIN, or a violation occurring.

1. The app sends `SESSION_END` → calls `nativeAppClose` → empties the UI → sends END to the daemon → `finishAndRemoveTask` → `killProcess`.
2. The daemon confirms with pidfd that the process has ended (SIGKILL if it has not ended within 3 seconds) → clears memory and logs.
3. Restore in reverse order: input method and accessibility → unsuspend the packages → USB → each radio and setting → only last remove the firewall chains → delete the restore journal.

### F. Implementation breakdown

Verification: run `cargo test -p <crate>` for each crate. `Cargo.lock` does not belong to any work package and is regenerated once at integration. Until WP4 is done, `--workspace` fails because the old APIs have been removed, so each package runs only its own crate.

| Package | Contents and write scope | Depends on | Verification |
|---|---|---|---|
| WP1 | Handshake v2, identity format conversion, DH ratchet, 5-word SAS, pairing code v2. Scope: `core/aegiscall-crypto/` | none | Full handshake; field-by-field tampering of HS1–HS4 and the preamble always aborts; commit mismatch; gear and version downgrade; PSK required; the SAS and identity differ on the two legs of a relay; message length equals the constant; DER / SPKI conversion; the DH ratchet gives identical results on both sides |
| WP2 | The trust crate, the ime crate, removal of the old PIN, workspace dependencies. Scope: `core/aegiscall-trust/`, `core/aegiscall-ime/`, `core/aegiscall-memsec/src/lib.rs`, `Cargo.toml`, `deny.toml` | none | Inside the tests, build synthetic attestation chains with the x509-cert builder and trigger every check of E2 one by one; vault creation, unlock, duress, 5-attempt lockout, file tampering; `cargo deny check licenses` |
| WP3 | hs_link, SecureCallSession, the new control subtypes, automatic rekeying, preamble v2. Scope: `core/aegiscall-chat/`, `core/aegiscall-mux/src/lib.rs`, `core/aegiscall-modem/src/preamble.rs` | WP1 | Both ends complete under 5% random loss and burst loss, with frames ≤ 215; the whole flow runs through modulation via channel_sim; timeout, ABORT, role tie; the DH ratchet completes within 2000 frames; recovery after the voice window |
| WP4 | JNI registry, function list, event TLV. Scope: `core/aegiscall-jni/`, `app/src/main/java/io/github/h4lovoid/dialcrypt/core/NativeBridge.kt` | WP1–3, WP2 | Stale and wrong-type handles, repeated close, concurrent calls; TLV encode and decode; run a complete session with SoftwareSigner without the JVM |
| WP5 | Key bridge, BearerGuard, DaemonClient, launcher and secure process, the in-app keyboard, UI claims, manifest. Scope: all files under `app/` other than NativeBridge.kt | The interface of WP4 (settled in this specification, so work can run in parallel) | Cannot be compiled at present: the diff is reviewed item by item against Section E; confirm with `rg` that the manifest has no network permission at all |
| WP6 | The daemon lifecycle and the Magisk module: `ipc.rs`, `journal.rs`, `lockdown.rs`, `monitor.rs`, `precheck.rs`, `memscrub.rs`, `sysops.rs` (a trait with a fake implementation added). Rewrite sepolicy (allow `priv_app` to connect to the socket of the magisk domain), the privapp list and `service.sh`, and add `action.sh`. Scope: `daemon/`, `magisk-module/` | none (IPC per this specification) | The restore journal restores correctly when truncated at any byte; reverse order; the firewall plan contains no `-F`, `-P` or `-X` on any built-in chain; the pre-check and IMS interface resolution use recorded dumpsys fixtures; violation detection is tested with a fake SysOps; IPC encode and decode; on-device testing is scheduled separately |

### G. Residual risks

- **Magisk unlocked device**: this only guarantees effectiveness against non-root malicious programs and operator mistakes. Other root programs (modules, su apps, Zygisk injection) can change the settings back, modify the daemon's files, read this process's memory, or inject only after the check. Monitoring can only detect and fail closed within 1 second after the fact; it cannot prevent anything, and it cannot stop a root that forges the read-back values. The boot chain is not verified, so someone with physical access can swap the kernel; the hardware label the peer sees will be "unlocked".
- **Self-signed relocked device** (relocked with avb_custom_key, no su, the daemon built as an init service inside the system image with its own dedicated SELinux domain, kernel with init_on_free): the boot chain and the daemon are protected by dm-verity, only system components can change settings, and they are detected and fail closed. Zero-on-free holds, and the peer can verify "self-signed locked". The baseband, the DSP and vulnerabilities in system_server itself still cannot be constrained.
- Identity authentication is classical cryptography (ECDSA, SAS). A quantum attacker who attacks in real time can impersonate on the first call; "record now, decrypt later" is already covered by PQ protection. Contacts with a PSK are not subject to this limit.
- The SAS comparison relies on recognizing a voice. An interceptor who can forge a voice in real time can read out a fake SAS; for high-risk peers it is recommended to compare once more over another channel before saving.
- The attestation chain has no trusted time and no online revocation, only the revocation snapshot. On models whose TEE key box has leaked, attestation can be forged. Attestation reflects only the boot state at the time the key was generated.
- A root attacker on the device can reset the attempt counter and then brute-force the PIN with the SE; a 6-digit PIN can be exhausted within a few hours, so 10 or more digits are recommended. Deleting a key in Keystore is not guaranteed to resist rollback.
- The handshake takes about 38 seconds on broadband and about 72 seconds on narrowband; under strong interference it cannot be established. The superframe has only a 48-bit tag. The carrier can see the call records and can tell that this is data tones.
- Alarms that fall due during a session are missed; killed system packages may be pulled up repeatedly by the system, causing CPU load; the exempt dialer app and launcher keep running (without network).
- Some carriers put IMS on the internet APN, so turning off data breaks VoLTE; in that case the system refuses to start. If the daemon executable is corrupted, the settings stay in the blocked state and need manual recovery.
- During the voice comparison window, plaintext voice is transmitted. The CNSA requirements of P-384 and AES-256-GCM are not met, because StrongBox supports only P-256.

## 3. Trade-offs

- Advantages: the handshake, attestation, vault, restore journal and violation decisions all live in Rust that can be tested off-device; every kind of failure ends in the state "blocked, nothing sent".
- Costs and risks: each call has to wait about 38 more seconds before the first message can be sent; the lifecycle changes a lot of system state, and command differences between device models must be tested one device at a time; other root programs cannot be stopped on a Magisk device.
- Approaches considered and abandoned: ML-KEM-768 (saves 8 seconds but does not meet CNSA 2.0), sending data with classical encryption first and adding PQ later, JNI callbacks, a firewall that flushes the table and changes the default policy, cgroup-freezing other apps (memory remains), and force-stop (it clears other apps' alarms).

## 4. Assumptions and uncertain items

- Rust verification runs `cargo test -p <crate>` for each crate. The host for Android cross-compilation and on-device testing has not been specified yet.
- The premises of the time estimate: 5% loss, round trip 0.6 seconds, StrongBox signing 0.3 seconds.
- It is assumed that MlKem1024 from ml-kem 0.2.3, and the SPKI and DER parsing in p256, can be used directly; if extra features are needed, only RustCrypto's own are enabled. If RSA signature verification is blocked by a cargo-deny advisory, it is allowed through with the reason noted in deny.toml (signature verification only, no private key operations).
- The commands and output formats of `cmd wifi`, `bluetooth_manager`, `phone data`, `svc nfc`, `ime`, `pm suspend` and `dumpsys` (connectivity, telephony.registry, lock_settings) must be tested on one Tensor device and one Qualcomm device and recorded as test fixtures; whether `TelecomManager.endCall()` is available on the target version must also be confirmed. To be confirmed on device.
- It is assumed that when the Magisk DenyList is enforced, Zygisk modules do not load into the processes on the list.
- The trust roots, the revocation snapshot, the AVB key allowlist, the release signature hashes, and the Zhuyin lexicon under an MIT / BSD-style license are all supplied by the project owner; if any one is missing, the app refuses to start. The audio routing needed for the voice comparison window reuses the daemon's existing mute-patch interface.

## 5. Final additions (per the project owner's later instructions)

- **Product language**: English is the default, and Simplified Chinese, Spanish and French are also supported. All screen text moves into Android string resources (`values`, `values-zh-rCN`, `values-es`, `values-fr`). Rust and the daemon return only codes, never sentences meant to be shown to the user. The existing Traditional Chinese interface text is replaced when WP5 redoes the interface.
- **SAS display**: the 5 bytes of the SAS are unchanged. Each of the four languages has its own 256-word list, in which the same index stands for the same byte value; next to each word the screen shows the corresponding three-digit number (000–255). When the two sides use different languages, compare the numbers. This item replaces "mapped onto the existing 256-word list" in Section B and affects `sas_words.rs` in WP1.
- **In-app keyboard**: becomes Latin letters (English, Spanish, French, with long-press entry of accented characters and characters such as ñ and ç), digits, and Simplified Chinese pinyin, replacing the Zhuyin in Sections A, D and E. `aegiscall-ime` becomes `PinyinEngine`, and the lexicon must be under an MIT / BSD / Apache-style license. This affects WP2 and WP5.
- **Call bearer**: only VoLTE and VoNR are allowed; VoWiFi, 2G and 3G are always refused (already covered by E3).
- **Status**: proposal, under review. This document is a design proposal; it has not yet had a second-opinion review and has not been implemented.
