//! App objects, call sessions and the operations behind every exported function.
//!
//! Lock order: a session operation holds its session lock and may then take its app lock
//! (vault updates driven by session events). App operations never take a session lock while
//! holding the app lock; operations that touch both (vault saved, duress, close) release the
//! app lock first.

use crate::audio::{render_tx, RxModem, MAX_RX_CHUNK};
use crate::code::{ABORTED, BAD_ARG, BAD_HANDLE, BAD_STATE, BUSY, CRYPTO, INTERNAL, LOCKED, OK};
use crate::events::*;
use crate::registry::{close_entry, with_live, Entry, Handles, Table};
use aegiscall_chat::call_session::MAX_EVIDENCE_LEN;
use aegiscall_chat::{AbortReason, ChatError, SecureCallSession, SessionEvent, TacticalQuickCode};
use aegiscall_crypto::{
    spki_der_to_pub33, CallSide, IdentityStatus, LocalIdentity, PairingCodeV2, PairingSecret, Path,
    PeerExpectation, ResumeCandidate, Role,
};
use aegiscall_memsec::{MessageDirection, SecretKey32};
use aegiscall_modem::{FormantModulator, ModemGear};
use aegiscall_trust::{
    duress_overwrite, evidence_id, verify_attestation, AttestationVerdict, BootState, ContactProof, ContactSnapshot,
    ContactView, NewContact, PhoneChoice, Rotation, TicketUse, TrustConfig, TrustError, UnlockOutcome, Vault,
    MAX_CHAIN_LEN, MAX_LABEL_LEN,
};
use rand_core::OsRng;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use zeroize::{Zeroize, Zeroizing};

const EVENT_QUEUE_CAP: usize = 4096;
const PENDING_SAVES_CAP: usize = 256;
/// Longest outgoing text accepted from Java (UTF-8 bytes).
pub const MAX_TEXT_LEN: usize = 4096;
/// Longest pairing code accepted from Java (UTF-8 bytes).
pub const MAX_CODE_LEN: usize = 256;
/// Longest phone number accepted from Java (E.164: '+' and at most 15 digits).
pub const MAX_PHONE_LEN: usize = 16;
/// Longest contact label accepted from Java (UTF-8 bytes).
pub const MAX_LABEL_BYTES: usize = MAX_LABEL_LEN;
const MAX_BOOT_KEY_BYTES: usize = 64;
/// Quick command codes of nativeSessionSendQuick.
pub const QUICK_SAFE_ARRIVAL: i32 = 1;
pub const QUICK_SURVEILLANCE: i32 = 2;
pub const QUICK_HOLD_SILENT: i32 = 3;
pub const QUICK_REKEY: i32 = 4;
pub const QUICK_GPS_PIN: i32 = 5;

/// [Bridge::pin_change] results.
pub const PIN_CHANGE_WRONG: i32 = 0;
pub const PIN_CHANGE_STAGED: i32 = 1;
pub const PIN_CHANGE_WRONG_LOCKED: i32 = 2;
pub const PIN_CHANGE_DURESS: i32 = 3;

fn trust_code(e: TrustError) -> i32 {
    match e {
        TrustError::Attestation(_) | TrustError::Crypto => CRYPTO,
        TrustError::VaultDead | TrustError::VaultLocked => LOCKED,
        TrustError::RotationRequired
        | TrustError::NoPendingRotation
        | TrustError::DuplicateContact
        | TrustError::PhoneInUse
        | TrustError::PskRequiredForKeyChange
        | TrustError::ResumeBusy
        | TrustError::ResumeStale
        | TrustError::StretchUnlock => BAD_STATE,
        TrustError::CapacityExceeded => BUSY,
        _ => BAD_ARG,
    }
}

fn chat_code(e: ChatError) -> i32 {
    match e {
        ChatError::SessionClosed => ABORTED,
        ChatError::NotEstablished | ChatError::InvalidState | ChatError::SendLocked => BAD_STATE,
        ChatError::MessageTooLarge => BAD_ARG,
        ChatError::QueueFull => BUSY,
        _ => INTERNAL,
    }
}

fn handle(x: i64) -> Result<u64, i32> {
    u64::try_from(x).ok().filter(|h| *h != 0).ok_or(BAD_HANDLE)
}

fn jlong(h: u64) -> Result<i64, i32> {
    i64::try_from(h).map_err(|_| INTERNAL)
}

fn now_ms(x: i64) -> Result<u64, i32> {
    u64::try_from(x).map_err(|_| BAD_ARG)
}

fn contact_id(x: i32) -> Result<u32, i32> {
    u32::try_from(x).ok().filter(|c| *c != 0).ok_or(BAD_ARG)
}

/// 0 means "no contact named"; anything else must be a valid id.
fn opt_contact(x: i32) -> Result<Option<u32>, i32> {
    match x {
        0 => Ok(None),
        c => contact_id(c).map(Some),
    }
}

fn label_arg(b: &[u8]) -> Result<String, i32> {
    if b.len() > MAX_LABEL_BYTES {
        return Err(BAD_ARG);
    }
    std::str::from_utf8(b).map(str::to_owned).map_err(|_| BAD_ARG)
}

fn phone_arg(b: &[u8]) -> Result<Vec<u8>, i32> {
    if b.is_empty() || b.len() > MAX_PHONE_LEN {
        return Err(BAD_ARG);
    }
    Ok(b.to_vec())
}

/// Mirrors the vault's rule for a stored verdict, so storing it later cannot fail.
fn storable(v: &AttestationVerdict) -> bool {
    match &v.boot {
        BootState::SelfSigned { key } => !key.is_empty() && key.len() <= MAX_BOOT_KEY_BYTES,
        _ => true,
    }
}

fn flatten(r: Result<i32, i32>) -> i32 {
    match r {
        Ok(v) => v,
        Err(c) => c,
    }
}

/// Chain TLV from the app: repeated `len u16 BE · DER`, leaf first, root excluded.
fn parse_chain(mut b: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    while !b.is_empty() {
        let n = usize::from(u16::from_be_bytes([*b.first()?, *b.get(1)?]));
        let cert = b.get(2..2 + n)?;
        if cert.is_empty() || out.len() >= MAX_CHAIN_LEN {
            return None;
        }
        out.push(cert.to_vec());
        b = b.get(2 + n..)?;
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// `n u8 · n × (ticket id u32 · material 32 B) · m u8 · m × retired id u32`.
fn encode_rotation(r: &Rotation) -> Result<Zeroizing<Vec<u8>>, i32> {
    let n = u8::try_from(r.new.len()).map_err(|_| INTERNAL)?;
    let m = u8::try_from(r.retire.len()).map_err(|_| INTERNAL)?;
    let mut out = Zeroizing::new(Vec::with_capacity(2 + 36 * r.new.len() + 4 * r.retire.len()));
    out.push(n);
    for (id, material) in &r.new {
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(material.as_bytes());
    }
    out.push(m);
    for id in &r.retire {
        out.extend_from_slice(&id.to_be_bytes());
    }
    Ok(out)
}

fn boot_code(b: &BootState) -> u8 {
    match b {
        BootState::Verified => 0,
        BootState::SelfSigned { .. } => 1,
        BootState::Unlocked => 2,
    }
}

/// `count u16 · per contact: id u32 · flags u8 · pub33 · label_len u8 · label ·
/// [boot u8 · os_patch u32 if flag 0x10] · [phone_tag 16 B if flag 0x20]`. Flags: 0x01 PSK,
/// 0x02 SAS verified, 0x04 rs_cur, 0x08 rs_new, 0x10 attestation, 0x20 phone number.
fn encode_contacts(list: &[ContactView]) -> Result<Zeroizing<Vec<u8>>, i32> {
    let count = u16::try_from(list.len()).map_err(|_| INTERNAL)?;
    let mut out = Zeroizing::new(Vec::with_capacity(2 + list.len() * 160));
    out.extend_from_slice(&count.to_be_bytes());
    for c in list {
        let label = c.label.as_bytes();
        let label_len = u8::try_from(label.len()).map_err(|_| INTERNAL)?;
        let flags = u8::from(c.has_psk)
            | u8::from(c.sas_verified) << 1
            | u8::from(c.resume.0) << 2
            | u8::from(c.resume.1) << 3
            | u8::from(c.attestation.is_some()) << 4
            | u8::from(c.phone_tag.is_some()) << 5;
        out.extend_from_slice(&c.id.to_be_bytes());
        out.push(flags);
        out.extend_from_slice(&c.pub33);
        out.push(label_len);
        out.extend_from_slice(label);
        if let Some(a) = &c.attestation {
            out.push(boot_code(&a.boot));
            out.extend_from_slice(&a.os_patch.to_be_bytes());
        }
        if let Some(t) = &c.phone_tag {
            out.extend_from_slice(t);
        }
    }
    Ok(out)
}

/// Added to the contact id returned by [Bridge::import_pairing] when the import stored a PSK
/// the contact did not hold before (new contact, first pairing, or a changed pairing key).
pub(crate) const PAIRING_PSK_CHANGED: i32 = 0x4000_0000;

fn tagged_id(id: u32, changed: bool) -> Result<i32, i32> {
    let id = i32::try_from(id).ok().filter(|v| v & PAIRING_PSK_CHANGED == 0).ok_or(INTERNAL)?;
    Ok(if changed { id | PAIRING_PSK_CHANGED } else { id })
}

fn code_arg(code: &[u8]) -> Result<&str, i32> {
    if code.len() > MAX_CODE_LEN {
        return Err(BAD_ARG);
    }
    std::str::from_utf8(code).map_err(|_| BAD_ARG)
}

/// The code's identity key and the PSK we share with it.
fn pair_with(a: &App, code: &str) -> Result<([u8; 33], SecretKey32), i32> {
    let own_pub = a.identity.as_ref().ok_or(BAD_STATE)?.pub33;
    let peer = PairingCodeV2::from_code(code).map_err(|_| BAD_ARG)?;
    if peer.pub33 == own_pub {
        return Err(BAD_ARG);
    }
    let secret = a.pairing_secret.as_ref().ok_or(BAD_STATE)?;
    let psk = secret.pair_psk(&own_pub, &peer).map_err(|_| BAD_ARG)?;
    Ok((peer.pub33, psk))
}

/// What [Bridge::import_revert] puts back: the contact before the import, or None for a new one.
struct ImportUndo {
    id: u32,
    before: Option<ContactSnapshot>,
}

fn path_bytes(p: Path) -> [u8; 6] {
    match p {
        Path::Full => [0; 6],
        Path::Resume { contact, used_new } => {
            let c = contact.to_be_bytes();
            [1, u8::from(used_new), c[0], c[1], c[2], c[3]]
        }
    }
}

fn identity_code(i: IdentityStatus) -> u8 {
    match i {
        IdentityStatus::Unverified => 0,
        IdentityStatus::SasVerified => 1,
        IdentityStatus::KnownContact => 2,
        IdentityStatus::KeyChanged => 3,
    }
}

/// Process hardening (§2.D nativeHarden): memory-lock limit lifted, not dumpable, no core
/// files. Any failure, or a platform without these calls, returns INTERNAL.
///
/// Secrets live in buffers that lock their own pages (aegiscall-memsec LockedBuffer), so they
/// never reach zram. That needs an unlimited RLIMIT_MEMLOCK, which the daemon grants at
/// ATTACH; before that this returns INTERNAL and the caller may simply call again.
///
/// The whole process is deliberately not locked with mlockall. Verified on a Pixel 7
/// (Android 16): the Android runtime releases arena and heap pages with madvise and relies on
/// getting zeroed pages back, which locked mappings do not give, and its JIT compiler thread
/// then crashes (SIGSEGV in libart) within seconds of start.
pub fn harden() -> i32 {
    #[cfg(any(target_os = "android", target_os = "linux"))]
    {
        let rl = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        let mut memlock = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        // SAFETY: plain system calls with constant arguments and a valid rlimit reference.
        let ok = unsafe {
            let lockable = libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut memlock) == 0 && memlock.rlim_cur == libc::RLIM_INFINITY;
            let undumpable = libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) == 0;
            let no_core = libc::setrlimit(libc::RLIMIT_CORE, &rl) == 0;
            lockable && undumpable && no_core
        };
        if ok {
            OK
        } else {
            INTERNAL
        }
    }
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    {
        INTERNAL
    }
}

// ---------------------------------------------------------------- app object

struct Identity {
    pub33: [u8; 33],
    evidence_id: [u8; 16],
    chain_tlv: Vec<u8>,
}

struct PendingSave {
    app_seq: u32,
    session: u64,
    session_seq: u32,
}

pub(crate) struct App {
    trust: TrustConfig,
    identity: Option<Identity>,
    vault: Option<Box<Vault>>,
    pending_unlock: Option<TicketUse>,
    /// The pending unlock started from a kept stretch ([Bridge::pin_begin_stretch]).
    pending_from_stretch: bool,
    /// The app holds the stretch of this unlock to turn fingerprint answer on
    /// ([Bridge::stretch_held]); PIN changes are refused until it lets go.
    stretch_held: bool,
    /// Set by the duress PIN: the vault is gone and exports return random bytes of this length.
    duress_len: Option<usize>,
    /// Static pairing key from the persisted seed ([Bridge::set_pairing_seed]).
    pairing_secret: Option<PairingSecret>,
    import_undo: Option<ImportUndo>,
    dirty_seq: u32,
    pending_saves: VecDeque<PendingSave>,
}

impl App {
    fn new(trust: TrustConfig) -> Self {
        Self {
            trust,
            identity: None,
            vault: None,
            pending_unlock: None,
            pending_from_stretch: false,
            stretch_held: false,
            duress_len: None,
            pairing_secret: None,
            import_undo: None,
            dirty_seq: 0,
            pending_saves: VecDeque::new(),
        }
    }

    fn next_dirty(&mut self) -> u32 {
        self.dirty_seq = self.dirty_seq.checked_add(1).unwrap_or(1);
        self.dirty_seq
    }

    fn vault_mut(&mut self) -> Result<&mut Vault, i32> {
        if self.duress_len.is_some() {
            return Err(LOCKED);
        }
        self.vault.as_deref_mut().ok_or(LOCKED)
    }

    fn vault_ref(&self) -> Result<&Vault, i32> {
        if self.duress_len.is_some() {
            return Err(LOCKED);
        }
        self.vault.as_deref().ok_or(LOCKED)
    }

    /// Back to the locked state of a fresh app object: the vault (wiped on drop) and everything
    /// that came from it go; the identity stays for the next unlock.
    fn lock_vault(&mut self) {
        self.vault = None;
        self.pending_unlock = None;
        self.pending_from_stretch = false;
        self.stretch_held = false;
        self.pairing_secret = None;
        self.import_undo = None;
    }

    /// Drops every secret (the vault zeroizes itself on drop).
    fn wipe(&mut self) {
        self.vault = None;
        self.pending_unlock = None;
        self.pending_from_stretch = false;
        self.stretch_held = false;
        self.pairing_secret = None;
        self.import_undo = None;
        self.identity = None;
        self.pending_saves.clear();
    }
}

// ---------------------------------------------------------------- call session

pub(crate) struct Session {
    handle: u64,
    app: Entry<App>,
    call: SecureCallSession,
    gear: ModemGear,
    tx: FormantModulator,
    rx: RxModem,
    events: VecDeque<Zeroizing<Vec<u8>>>,
    now: u64,
    peer: Option<[u8; 33]>,
    key_changed_from: Option<[u8; 33]>,
    sas_confirmed: bool,
    contact: Option<u32>,
    verdict: Option<AttestationVerdict>,
}

impl Session {
    fn new(handle: u64, app: Entry<App>, call: SecureCallSession, gear: ModemGear, now: u64) -> Self {
        Self {
            handle,
            app,
            call,
            gear,
            tx: FormantModulator::new(gear),
            rx: RxModem::new(),
            events: VecDeque::new(),
            now,
            peer: None,
            key_changed_from: None,
            sas_confirmed: false,
            contact: None,
            verdict: None,
        }
    }

    fn emit(&mut self, t: u8, v: &[u8]) {
        let mut rec = Zeroizing::new(Vec::with_capacity(3 + v.len()));
        if !encode_tlv(&mut rec, t, v) {
            return;
        }
        if self.events.len() >= EVENT_QUEUE_CAP {
            self.events.pop_front();
        }
        self.events.push_back(rec);
    }

    fn take_events(&mut self) -> Zeroizing<Vec<u8>> {
        self.pump();
        let total = self.events.iter().map(|e| e.len()).sum();
        let mut out = Zeroizing::new(Vec::with_capacity(total));
        for e in self.events.drain(..) {
            out.extend_from_slice(&e);
        }
        out
    }

    /// Moves the call's events into the TLV queue, applying vault updates on the way.
    fn pump(&mut self) {
        for _ in 0..8 {
            let evs = self.call.poll_events();
            if evs.is_empty() {
                break;
            }
            for ev in evs {
                self.on_event(ev);
            }
        }
    }

    fn on_event(&mut self, ev: SessionEvent) {
        #[allow(unreachable_patterns)]
        match ev {
            SessionEvent::NeedSignature { req_id, message } => {
                let mut v = Vec::with_capacity(4 + message.len());
                v.extend_from_slice(&req_id.to_be_bytes());
                v.extend_from_slice(&message);
                self.emit(EV_NEED_SIGNATURE, &v);
            }
            SessionEvent::Sas(b) => self.emit(EV_SAS, &b),
            SessionEvent::Path(p) => self.emit(EV_PATH, &path_bytes(p)),
            SessionEvent::HandshakeProgress(p) => self.emit(EV_HS_PROGRESS, &[p]),
            SessionEvent::Established { role, path, peer_pub33, identity, psk_contact } => {
                self.on_established(role, path, peer_pub33, identity, psk_contact)
            }
            SessionEvent::KeyChanged { stored_pub33, peer_pub33 } => {
                self.key_changed_from = Some(stored_pub33);
                let mut v = [0u8; 66];
                v[..33].copy_from_slice(&stored_pub33);
                v[33..].copy_from_slice(&peer_pub33);
                self.emit(EV_KEY_CHANGED, &v);
            }
            SessionEvent::SasConfirmed => {
                self.sas_confirmed = true;
                self.emit(EV_SAS_CONFIRMED, &[]);
            }
            SessionEvent::VoiceWindow { open } => {
                self.emit(EV_VOICE_WINDOW, &[u8::from(open)]);
            }
            SessionEvent::PqProgress(p) => self.emit(EV_PQ_PROGRESS, &[p]),
            SessionEvent::PqMixed { epoch } => self.emit(EV_PQ_MIXED, &epoch.to_be_bytes()),
            SessionEvent::EpochAdvanced(e) => self.emit(EV_EPOCH, &e.to_be_bytes()),
            SessionEvent::VaultDirty { seq, contact, k, secret, promote_used_new_first } => {
                self.on_vault_dirty(seq, contact, k, secret, promote_used_new_first)
            }
            SessionEvent::ResumePromote { contact, k } => self.on_promote(contact, k),
            SessionEvent::EvidenceChain(chain) => self.on_evidence(&chain),
            SessionEvent::MessageReceived(id) => {
                let mut v = Zeroizing::new(Vec::new());
                let text = self.call.vault().and_then(|vault| {
                    vault
                        .messages()
                        .iter()
                        .find(|m| m.msg_id == u32::from(id) && m.direction == MessageDirection::Incoming)
                        .map(|m| m.raw_bytes())
                });
                v.reserve_exact(2 + text.map_or(0, |t| t.len()));
                v.extend_from_slice(&id.to_be_bytes());
                if let Some(t) = text {
                    v.extend_from_slice(t);
                }
                self.emit(EV_MESSAGE_RECEIVED, &v);
            }
            SessionEvent::MessageDelivered(id) => self.emit(EV_MESSAGE_DELIVERED, &id.to_be_bytes()),
            SessionEvent::MessageProgress { msg_id, acked, total } => {
                let mut v = [0u8; 6];
                v[0..2].copy_from_slice(&msg_id.to_be_bytes());
                v[2..4].copy_from_slice(&acked.to_be_bytes());
                v[4..6].copy_from_slice(&total.to_be_bytes());
                self.emit(EV_MESSAGE_PROGRESS, &v);
            }
            SessionEvent::MessageFailed(id) => self.emit(EV_MESSAGE_FAILED, &id.to_be_bytes()),
            SessionEvent::RemoteWipe => self.emit(EV_REMOTE_WIPE, &[]),
            SessionEvent::WipeSent => self.emit(EV_WIPE_SENT, &[]),
            SessionEvent::Ended { by_peer } => self.emit(EV_ENDED, &[u8::from(by_peer)]),
            SessionEvent::Aborted(r) => self.emit(EV_ABORTED, &[r.code()]),
            _ => {}
        }
    }

    fn on_established(&mut self, role: Role, path: Path, peer: [u8; 33], identity: IdentityStatus, psk: Option<u32>) {
        self.peer = Some(peer);
        let known = with_live(&self.app, |a| {
            Ok(a.vault_ref().ok().and_then(|v| v.contact_by_pub33(&peer)).map(|c| (c.id, c.attestation.is_some())))
        })
        .ok()
        .flatten();
        self.contact = known.map(|k| k.0);
        if matches!(path, Path::Full) && !known.is_some_and(|k| k.1) {
            // Full path only: the chain must hash to the evidence_id signed in this handshake.
            // On the resume path the verdict already stored in the vault stands.
            let _ = self.call.request_evidence();
        }
        let mut v = Vec::with_capacity(49);
        v.push(u8::from(role == Role::Responder));
        v.extend_from_slice(&path_bytes(path));
        v.push(identity_code(identity));
        v.extend_from_slice(&psk.unwrap_or(0).to_be_bytes());
        v.extend_from_slice(&self.contact.unwrap_or(0).to_be_bytes());
        v.extend_from_slice(&peer);
        self.emit(EV_ESTABLISHED, &v);
    }

    /// §6.3 step 1: stage the new resume secret, then ask the app to persist the vault.
    fn on_vault_dirty(&mut self, seq: u32, contact: u32, k: u8, secret: SecretKey32, promote_first: bool) {
        let me = self.handle;
        let r = with_live(&self.app, |a| {
            if k == 0 {
                return Err(BAD_ARG);
            }
            let vault = a.vault_mut()?;
            if promote_first {
                vault.resume_mark_used(contact, true).map_err(trust_code)?;
            } else if k == 1 {
                // A leftover rs_new from an earlier call that this call did not use.
                vault.resume_discard_staged(contact).map_err(trust_code)?;
            }
            vault.resume_stage(contact, secret, k).map_err(trust_code)?;
            let app_seq = a.next_dirty();
            if a.pending_saves.len() >= PENDING_SAVES_CAP {
                a.pending_saves.pop_front();
            }
            a.pending_saves.push_back(PendingSave { app_seq, session: me, session_seq: seq });
            Ok(app_seq)
        });
        match r {
            Ok(s) => self.emit(EV_VAULT_DIRTY, &s.to_be_bytes()),
            Err(c) => self.emit(EV_VAULT_FAILED, &c.to_be_bytes()[3..]),
        }
    }

    /// §6.3 step 3: the peer confirmed update k.
    fn on_promote(&mut self, contact: u32, k: u8) {
        let r = with_live(&self.app, |a| {
            let promoted = a.vault_mut()?.resume_promote(contact, k).map_err(trust_code)?;
            Ok(if promoted { Some(a.next_dirty()) } else { None })
        });
        match r {
            Ok(Some(s)) => self.emit(EV_VAULT_DIRTY, &s.to_be_bytes()),
            Ok(None) => {}
            Err(c) => self.emit(EV_VAULT_FAILED, &c.to_be_bytes()[3..]),
        }
    }

    fn emit_attestation(&mut self, result: i32, v: Option<&AttestationVerdict>, stored: bool) {
        let mut b = [0u8; 7];
        b[0] = result.to_be_bytes()[3];
        if let Some(v) = v {
            b[1] = boot_code(&v.boot);
            b[2..6].copy_from_slice(&v.os_patch.to_be_bytes());
        }
        b[6] = u8::from(stored);
        self.emit(EV_ATTESTATION, &b);
    }

    /// The peer's attestation chain. It must hash to the evidence_id the peer signed in this
    /// handshake and verify against the trust config and the handshake key; only then is the
    /// verdict stored in the contact (or kept until the contact is saved). The resume path has
    /// no signed evidence_id, so a chain received there is refused.
    fn on_evidence(&mut self, chain: &[u8]) {
        let (Some(peer), Some(signed)) = (self.peer, self.call.peer_evidence_id()) else {
            self.emit_attestation(BAD_STATE, None, false);
            return;
        };
        let r = with_live(&self.app, |a| {
            let chain = parse_chain(chain).ok_or(BAD_ARG)?;
            if evidence_id(&chain) != signed {
                return Err(CRYPTO);
            }
            let verdict = verify_attestation(&chain, &a.trust, &peer).map_err(|_| CRYPTO)?;
            if !storable(&verdict) {
                return Err(CRYPTO);
            }
            let mut seq = None;
            if let Ok(vault) = a.vault_mut() {
                if let Some(c) = vault.contact_by_pub33(&peer) {
                    vault.set_attestation(c.id, verdict.clone()).map_err(trust_code)?;
                    seq = Some(a.next_dirty());
                }
            }
            Ok((verdict, seq))
        });
        match r {
            Ok((verdict, seq)) => {
                self.emit_attestation(OK, Some(&verdict), seq.is_some());
                self.verdict = Some(verdict);
                if let Some(s) = seq {
                    self.emit(EV_VAULT_DIRTY, &s.to_be_bytes());
                }
            }
            Err(c) => self.emit_attestation(c, None, false),
        }
    }

    /// Saves the peer after both sides confirmed the SAS (§6.2).
    ///
    /// target None adds a new contact. target Some(id) replaces that contact's key, and only
    /// when the key it holds is exactly the old key this call reported as changed; the caller
    /// ID never selects a contact. A PSK contact refuses (it needs a new pairing). Every check
    /// runs before the vault is touched.
    fn save_contact(&mut self, target: Option<u32>, label: String, phone: Option<Vec<u8>>) -> Result<i32, i32> {
        let peer = self.peer.ok_or(BAD_STATE)?;
        if !self.sas_confirmed {
            return Err(BAD_STATE);
        }
        if target.is_some() && phone.is_some() {
            return Err(BAD_ARG);
        }
        let changed_from = self.key_changed_from;
        let verdict = self.verdict.clone().filter(storable);
        let (id, seq) = with_live(&self.app, |a| {
            let vault = a.vault_mut()?;
            if vault.contact_by_pub33(&peer).is_some() {
                return Err(BAD_STATE);
            }
            let id = match target {
                Some(t) => {
                    let old = vault.contacts().into_iter().find(|c| c.id == t).ok_or(BAD_ARG)?;
                    if changed_from != Some(old.pub33) || old.has_psk {
                        return Err(BAD_STATE);
                    }
                    // The contact exists without a PSK, the new key is unused and the label
                    // length was checked, so neither call can fail half way.
                    vault.replace_contact_key(t, peer, ContactProof::SasMatchedThisCall).map_err(trust_code)?;
                    vault.set_label(t, label).map_err(trust_code)?;
                    t
                }
                None => {
                    // add_contact validates label, number and uniqueness before it changes anything.
                    let phone = match phone {
                        Some(n) => PhoneChoice::UserConfirmed(n),
                        None => PhoneChoice::NoNumber,
                    };
                    vault
                        .add_contact(NewContact { pub33: peer, label, phone, proof: ContactProof::SasMatchedThisCall })
                        .map_err(trust_code)?
                }
            };
            if let Some(v) = verdict {
                vault.set_attestation(id, v).map_err(trust_code)?;
            }
            Ok((id, a.next_dirty()))
        })?;
        self.contact = Some(id);
        // The contact is saved either way; a call that is already ending just seeds no resume secret.
        let _ = self.call.contact_saved(id);
        self.emit(EV_VAULT_DIRTY, &seq.to_be_bytes());
        i32::try_from(id).map_err(|_| INTERNAL)
    }
}

// ---------------------------------------------------------------- bridge

/// Both handle tables plus the WIPING flag. The JNI exports use [Bridge::global]; tests build
/// their own instances.
pub struct Bridge {
    wiping: AtomicBool,
    handles: Handles,
    apps: Table<App>,
    sessions: Table<Session>,
}

static GLOBAL: OnceLock<Bridge> = OnceLock::new();

impl Default for Bridge {
    fn default() -> Self {
        Self::new()
    }
}

impl Bridge {
    pub fn new() -> Self {
        Self { wiping: AtomicBool::new(false), handles: Handles::new(), apps: Table::new(), sessions: Table::new() }
    }

    pub fn global() -> &'static Bridge {
        GLOBAL.get_or_init(Bridge::new)
    }

    pub fn is_wiping(&self) -> bool {
        self.wiping.load(Ordering::SeqCst)
    }

    fn guard(&self) -> Result<(), i32> {
        if self.is_wiping() {
            Err(BAD_HANDLE)
        } else {
            Ok(())
        }
    }

    fn app_entry(&self, app: i64) -> Result<Entry<App>, i32> {
        self.guard()?;
        self.apps.get(handle(app)?)
    }

    fn session_entry(&self, s: i64) -> Result<Entry<Session>, i32> {
        self.guard()?;
        self.sessions.get(handle(s)?)
    }

    fn on_app<R>(&self, app: i64, f: impl FnOnce(&mut App) -> Result<R, i32>) -> Result<R, i32> {
        let e = self.app_entry(app)?;
        with_live(&e, |a| {
            // Checked again under the lock and once more before the result leaves it: a wipe
            // that started meanwhile gets BAD_HANDLE and the result is dropped (zeroized).
            self.guard()?;
            let r = f(a)?;
            self.guard()?;
            Ok(r)
        })
    }

    fn on_session<R>(&self, s: i64, f: impl FnOnce(&mut Session) -> Result<R, i32>) -> Result<R, i32> {
        let e = self.session_entry(s)?;
        with_live(&e, |sess| {
            self.guard()?;
            let r = f(sess);
            sess.pump();
            self.guard()?;
            r
        })
    }

    fn close_session_handle(&self, h: u64) -> i32 {
        let Ok(e) = self.sessions.get(h) else { return BAD_HANDLE };
        let c = close_entry(&e, |s| s.call.abort(AbortReason::LocalUser));
        self.sessions.remove(h);
        c
    }

    fn close_app_handle(&self, h: u64) -> i32 {
        let Ok(e) = self.apps.get(h) else { return BAD_HANDLE };
        let c = close_entry(&e, App::wipe);
        self.apps.remove(h);
        for s in self.sessions.owned_by(h) {
            self.close_session_handle(s);
        }
        c
    }

    // ------------------------------------------------------------ app object

    /// trust_tlv: TrustConfig::from_tlv format. Returns the app handle.
    pub fn app_open(&self, trust_tlv: &[u8]) -> Result<i64, i32> {
        self.guard()?;
        let trust = TrustConfig::from_tlv(trust_tlv).map_err(|_| BAD_ARG)?;
        let h = self.handles.fresh()?;
        self.apps.insert(h, 0, App::new(trust))?;
        jlong(h)
    }

    /// Our StrongBox identity: SPKI DER and chain TLV (verified like a peer's chain).
    pub fn set_identity(&self, app: i64, spki: &[u8], chain_tlv: &[u8]) -> i32 {
        flatten(self.on_app(app, |a| {
            if a.duress_len.is_some() {
                return Err(LOCKED);
            }
            if chain_tlv.len() > MAX_EVIDENCE_LEN {
                return Err(BAD_ARG);
            }
            let pub33 = spki_der_to_pub33(spki).map_err(|_| BAD_ARG)?;
            let chain = parse_chain(chain_tlv).ok_or(BAD_ARG)?;
            verify_attestation(&chain, &a.trust, &pub33).map_err(|_| CRYPTO)?;
            a.identity = Some(Identity { pub33, evidence_id: evidence_id(&chain), chain_tlv: chain_tlv.to_vec() });
            Ok(OK)
        }))
    }

    /// Creates the vault; returns the five tickets to import (rotation format). The first
    /// file comes from vault_rotate_commit.
    pub fn pin_setup(&self, app: i64, pin: &[u8], duress: &[u8]) -> Result<Zeroizing<Vec<u8>>, i32> {
        self.on_app(app, |a| {
            if a.duress_len.is_some() {
                return Err(LOCKED);
            }
            if a.vault.is_some() {
                return Err(BAD_STATE);
            }
            let (vault, rot) = Vault::create(pin, duress, &mut OsRng).map_err(trust_code)?;
            let out = encode_rotation(&rot)?;
            a.vault = Some(Box::new(vault));
            Ok(out)
        })
    }

    /// Unlock phase 1: `ticket id u32 · 32-byte HMAC input`.
    pub fn pin_begin(&self, app: i64, blob: &[u8], pin: &[u8], live: &[i32]) -> Result<Zeroizing<Vec<u8>>, i32> {
        let live: Vec<u32> = live.iter().map(|t| *t as u32).collect();
        self.on_app(app, |a| {
            if a.duress_len.is_some() {
                return Err(LOCKED);
            }
            let t = Vault::begin_unlock(blob, pin, &live).map_err(trust_code)?;
            Ok(Self::pending(a, t, false))
        })
    }

    /// Unlock phase 1 with the PIN stretch the app kept for fingerprint answer (32 bytes); same
    /// output and phase 2 as [Bridge::pin_begin].
    pub fn pin_begin_stretch(&self, app: i64, blob: &[u8], stretch: &[u8], live: &[i32]) -> Result<Zeroizing<Vec<u8>>, i32> {
        let p = Zeroizing::new(<[u8; 32]>::try_from(stretch).map_err(|_| BAD_ARG)?);
        let p = SecretKey32::from_bytes(*p);
        let live: Vec<u32> = live.iter().map(|t| *t as u32).collect();
        self.on_app(app, |a| {
            if a.duress_len.is_some() {
                return Err(LOCKED);
            }
            let t = Vault::begin_unlock_stretch(blob, &p, &live).map_err(trust_code)?;
            Ok(Self::pending(a, t, true))
        })
    }

    /// Binds a kept PIN stretch to its vault ([Vault::stretch_binding]); needs no app object.
    pub fn vault_stretch_binding(&self, blob: &[u8]) -> Result<[u8; 32], i32> {
        Vault::stretch_binding(blob).map_err(trust_code)
    }

    /// Ticket ids in the header of a vault file, big-endian u32 each, read without unlocking;
    /// an error for a file that does not parse. Needs no app object.
    pub fn vault_ticket_ids(&self, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, i32> {
        let ids = Vault::ticket_ids(blob).map_err(trust_code)?;
        Ok(Zeroizing::new(ids.iter().flat_map(|id| id.to_be_bytes()).collect()))
    }

    fn pending(a: &mut App, t: TicketUse, kept_stretch: bool) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(36));
        out.extend_from_slice(&t.ticket_id.to_be_bytes());
        out.extend_from_slice(t.hmac_input.as_bytes());
        a.pending_unlock = Some(t);
        a.pending_from_stretch = kept_stretch;
        out
    }

    /// Unlock phase 2: 1 normal, 2 duress, 0 wrong PIN, LOCKED when no ticket is left,
    /// BAD_STATE when the ticket was not consumed (or no phase 1 is pending).
    pub fn pin_finish(&self, app: i64, blob: &[u8], ticket_id: i32, hmac: Option<&[u8]>, live: &[i32]) -> i32 {
        let hmac = match hmac.map(<[u8; 32]>::try_from) {
            None => None,
            Some(Ok(h)) => Some(Zeroizing::new(h)),
            Some(Err(_)) => return BAD_ARG,
        };
        let live: Vec<u32> = live.iter().map(|t| *t as u32).collect();
        let r = self.on_app(app, |a| {
            let t = a.pending_unlock.take().ok_or(BAD_STATE)?;
            let from_stretch = core::mem::take(&mut a.pending_from_stretch);
            if t.ticket_id != ticket_id as u32 {
                return Err(BAD_ARG);
            }
            match Vault::finish_unlock(blob, t, hmac.as_deref(), &live) {
                UnlockOutcome::Normal(mut v) => {
                    // A fingerprint unlock refills only the ticket it spent (wrong PINs stay counted).
                    if from_stretch {
                        v.cap_refill(&live);
                    }
                    a.vault = Some(v);
                    a.stretch_held = false;
                    Ok(1)
                }
                UnlockOutcome::Duress => {
                    a.wipe();
                    a.duress_len = Some(blob.len());
                    Ok(2)
                }
                UnlockOutcome::Invalid { .. } => Ok(0),
                UnlockOutcome::Dead => Err(LOCKED),
                UnlockOutcome::Malformed => Err(BAD_ARG),
                UnlockOutcome::TicketNotConsumed => Err(BAD_STATE),
            }
        });
        if r == Ok(2) {
            self.close_sessions_of(app);
        }
        flatten(r)
    }

    /// Duress: the sessions of this app object end with its vault.
    fn close_sessions_of(&self, app: i64) {
        if let Ok(h) = handle(app) {
            for s in self.sessions.owned_by(h) {
                self.close_session_handle(s);
            }
        }
    }

    /// Verifies `current` and stages new normal + duress PINs: 1 staged (rotate and write next),
    /// 0 wrong current PIN, 2 wrong current PIN and the vault is locked now (third wrong one in
    /// this unlock), 3 the current PIN is the duress PIN (wiped as by [Bridge::pin_finish] returning
    /// 2; the app runs its duress path), < 0 error (`LOCKED`, `BAD_ARG`, `BAD_HANDLE`; `BAD_STATE`
    /// after a fingerprint unlock or while the app holds the stretch to turn fingerprint answer on).
    /// The current PIN is always compared first, so the duress PIN takes the duress path also when
    /// the change is refused or the new PINs are invalid (`BAD_ARG` only after that comparison).
    pub fn pin_change(&self, app: i64, current: &[u8], pin: &[u8], duress: &[u8]) -> i32 {
        let r = self.on_app(app, |a| {
            let held = a.stretch_held;
            let v = a.vault_mut()?;
            // Taken for every request, so the duress PIN costs no extra step before the wipe.
            let file_len = v.file_len().unwrap_or(aegiscall_trust::VAULT_PAD_BLOCK);
            let result = if held {
                // Refused, but only after the same current-PIN check.
                match v.refuse_pin_change(current) {
                    Err(TrustError::DuressPin) => Err(TrustError::DuressPin),
                    _ => return Err(BAD_STATE),
                }
            } else {
                v.change_pins(current, pin, duress, &mut OsRng)
            };
            match result {
                Ok(()) => Ok(PIN_CHANGE_STAGED),
                Err(TrustError::WrongCurrentPin) => Ok(PIN_CHANGE_WRONG),
                Err(TrustError::WrongCurrentPinLocked) => {
                    a.lock_vault();
                    Ok(PIN_CHANGE_WRONG_LOCKED)
                }
                Err(TrustError::DuressPin) => {
                    a.wipe();
                    a.duress_len = Some(file_len);
                    Ok(PIN_CHANGE_DURESS)
                }
                Err(e) => Err(trust_code(e)),
            }
        });
        if r == Ok(PIN_CHANGE_DURESS) {
            self.close_sessions_of(app);
        }
        flatten(r)
    }

    /// The app keeps (true) or dropped (false) the stretch of the current PIN unlock to turn
    /// fingerprint answer on. That stretch belongs to the current PIN, so [Bridge::pin_change] is
    /// refused while it is held. Holding needs an unlocked vault (LOCKED otherwise).
    pub fn stretch_held(&self, app: i64, held: bool) -> i32 {
        flatten(self.on_app(app, |a| {
            if held {
                a.vault_ref()?;
            }
            a.stretch_held = held;
            Ok(OK)
        }))
    }

    pub fn vault_rotate_begin(&self, app: i64) -> Result<Zeroizing<Vec<u8>>, i32> {
        self.on_app(app, |a| {
            let rot = a.vault_mut()?.begin_rotation(&mut OsRng).map_err(trust_code)?;
            encode_rotation(&rot)
        })
    }

    /// imported = every new ticket is in StrongBox. Returns the new vault file.
    pub fn vault_rotate_commit(&self, app: i64, imported: bool) -> Result<Zeroizing<Vec<u8>>, i32> {
        self.on_app(app, |a| {
            let v = a.vault_mut()?;
            if !imported {
                v.abort_rotation();
                return Err(BAD_STATE);
            }
            v.commit_rotation().map(Zeroizing::new).map_err(trust_code)
        })
    }

    /// Current vault file; BAD_STATE when a rotation is required first. After the duress PIN
    /// it returns random bytes of the old file's length.
    pub fn vault_export(&self, app: i64) -> Result<Zeroizing<Vec<u8>>, i32> {
        self.on_app(app, |a| {
            if let Some(n) = a.duress_len {
                return Ok(Zeroizing::new(duress_overwrite(n, &mut OsRng)));
            }
            a.vault_mut()?.export().map(Zeroizing::new).map_err(trust_code)
        })
    }

    /// The file announced by VAULT_DIRTY(seq) (and every earlier one) is durable.
    pub fn vault_saved(&self, app: i64, seq: i32) -> i32 {
        let Some(seq) = u32::try_from(seq).ok().filter(|s| *s != 0) else { return BAD_ARG };
        let due = match self.on_app(app, |a| {
            if seq > a.dirty_seq {
                return Err(BAD_ARG);
            }
            let mut due = Vec::new();
            a.pending_saves.retain(|p| {
                if p.app_seq <= seq {
                    due.push((p.session, p.session_seq));
                    false
                } else {
                    true
                }
            });
            Ok(due)
        }) {
            Ok(d) => d,
            Err(c) => return c,
        };
        for (s, sseq) in due {
            if let Ok(e) = self.sessions.get(s) {
                let _ = with_live(&e, |sess| {
                    self.guard()?;
                    let _ = sess.call.vault_saved(sseq);
                    sess.pump();
                    Ok(())
                });
            }
        }
        OK
    }

    /// Our pairing code. BAD_STATE until [Bridge::set_pairing_seed] gave this app object the
    /// persisted seed: a key made up here would not survive the next unlock.
    pub fn pairing_code(&self, app: i64) -> Result<Zeroizing<String>, i32> {
        self.on_app(app, |a| {
            a.vault_ref()?;
            let pub33 = a.identity.as_ref().ok_or(BAD_STATE)?.pub33;
            let xpub = a.pairing_secret.as_ref().ok_or(BAD_STATE)?.public();
            let code = PairingCodeV2::new(pub33, xpub).map_err(|_| INTERNAL)?;
            Ok(code.to_code())
        })
    }

    /// Restores or rotates the 32-byte pairing seed; the static X25519 pairing key behind
    /// [Bridge::pairing_code] and [Bridge::import_pairing] is derived from it.
    pub fn set_pairing_seed(&self, app: i64, seed: &[u8]) -> i32 {
        if seed.len() != 32 {
            return BAD_ARG;
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(seed);
        let rc = flatten(self.on_app(app, |a| {
            a.vault_ref()?;
            a.pairing_secret = Some(PairingSecret::from_seed(&arr));
            Ok(OK)
        }));
        arr.zeroize();
        rc
    }

    /// Seals contact metadata (`contact_meta.bin`) under the vault's meta key. LOCKED while
    /// the vault is locked or after the duress PIN.
    pub fn meta_seal(&self, app: i64, plaintext: &[u8]) -> Result<Zeroizing<Vec<u8>>, i32> {
        self.on_app(app, |a| a.vault_ref()?.meta_seal(plaintext, &mut OsRng).map(Zeroizing::new).map_err(trust_code))
    }

    /// Opens a blob of [Bridge::meta_seal]. LOCKED while the vault is locked, CRYPTO when the
    /// blob was sealed under another key or modified.
    pub fn meta_open(&self, app: i64, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, i32> {
        self.on_app(app, |a| a.vault_ref()?.meta_open(sealed).map_err(trust_code))
    }

    /// What [Bridge::import_pairing] with contact 0 would do, without changing anything: 0 when
    /// no contact holds the code's key, the id of the contact that does, plus
    /// [PAIRING_PSK_CHANGED] when importing would replace its PSK. Same errors as the import.
    pub fn preview_pairing(&self, app: i64, code: &[u8]) -> i32 {
        let code = match code_arg(code) {
            Ok(c) => c,
            Err(c) => return c,
        };
        flatten(self.on_app(app, |a| {
            let (peer_pub, psk) = pair_with(a, code)?;
            let vault = a.vault_ref()?;
            let Some(id) = vault.contact_by_pub33(&peer_pub).map(|c| c.id) else { return Ok(0) };
            tagged_id(id, !vault.holds_pairing_psk(id, &psk))
        }))
    }

    /// Imports the peer's code. contact 0: the contact holding the code's key, or a new one
    /// named label. contact != 0: that contact must already hold the code's key, otherwise the
    /// import is refused and the vault is unchanged. The PSK is derived from our pairing key
    /// and the code's. For a contact that holds the key already only the PSK changes, and only
    /// when it differs (its label, verification, attestation and resume secrets stay); label
    /// renames it when given. Returns the contact id, plus [PAIRING_PSK_CHANGED] when the stored
    /// PSK is new or different. The change can be undone once with [Bridge::import_revert]
    /// until the next import. Needs the pairing seed in this app object (BAD_STATE otherwise).
    pub fn import_pairing(&self, app: i64, contact: i32, code: &[u8], label: Option<&[u8]>) -> i32 {
        let code = match code_arg(code) {
            Ok(c) => c,
            Err(c) => return c,
        };
        let parsed: Result<_, i32> = (|| Ok((opt_contact(contact)?, label.map(label_arg).transpose()?)))();
        let (target, label) = match parsed {
            Ok(v) => v,
            Err(c) => return c,
        };
        flatten(self.on_app(app, |a| {
            let (peer_pub, psk) = pair_with(a, code)?;
            let vault = a.vault_mut()?;
            let holder = vault.contact_by_pub33(&peer_pub).map(|c| c.id);
            let existing = match target {
                Some(t) => {
                    if !vault.contacts().iter().any(|c| c.id == t) {
                        return Err(BAD_ARG);
                    }
                    if holder != Some(t) {
                        return Err(BAD_STATE);
                    }
                    Some(t)
                }
                None => holder,
            };
            let (id, changed, before) = match existing {
                Some(id) => {
                    let changed = !vault.holds_pairing_psk(id, &psk);
                    let before = vault.contact_snapshot(id).ok_or(INTERNAL)?;
                    // Same key: only the PSK changes, and an equal PSK changes nothing.
                    if changed {
                        vault.set_pairing_psk(id, psk).map_err(trust_code)?;
                    }
                    if let Some(l) = label {
                        if let Err(e) = vault.set_label(id, l) {
                            vault.restore_contact(before).map_err(trust_code)?;
                            return Err(trust_code(e));
                        }
                    }
                    (id, changed, Some(before))
                }
                None => {
                    let label = label.ok_or(BAD_ARG)?;
                    let c = NewContact {
                        pub33: peer_pub,
                        label,
                        phone: PhoneChoice::NoNumber,
                        proof: ContactProof::Paired(psk),
                    };
                    (vault.add_contact(c).map_err(trust_code)?, true, None)
                }
            };
            a.import_undo = Some(ImportUndo { id, before });
            tagged_id(id, changed)
        }))
    }

    /// Undoes the last [Bridge::import_pairing] of contact (and any phone change made to it
    /// since) when the app could not write the vault: a new contact is removed, an existing one
    /// gets back its PSK and the rest. BAD_STATE when that import is not the last one.
    pub fn import_revert(&self, app: i64, contact: i32) -> i32 {
        let id = match contact_id(contact) {
            Ok(v) => v,
            Err(c) => return c,
        };
        flatten(self.on_app(app, |a| {
            let undo = a.import_undo.take().ok_or(BAD_STATE)?;
            if undo.id != id {
                a.import_undo = Some(undo);
                return Err(BAD_STATE);
            }
            let vault = a.vault_mut()?;
            match undo.before {
                Some(snap) => vault.restore_contact(snap),
                None => vault.remove_contact(id),
            }
            .map_err(trust_code)?;
            Ok(OK)
        }))
    }

    pub fn contact_list(&self, app: i64) -> Result<Zeroizing<Vec<u8>>, i32> {
        self.on_app(app, |a| encode_contacts(&a.vault_ref()?.contacts()))
    }

    pub fn contact_rename(&self, app: i64, contact: i32, label: &[u8]) -> i32 {
        let label = match label_arg(label) {
            Ok(l) => l,
            Err(c) => return c,
        };
        flatten(self.on_app(app, |a| {
            let id = contact_id(contact)?;
            a.vault_mut()?.set_label(id, label).map_err(trust_code)?;
            Ok(OK)
        }))
    }

    pub fn contact_set_phone(&self, app: i64, contact: i32, phone_e164: Option<&[u8]>) -> i32 {
        let parsed: Result<_, i32> = (|| Ok((contact_id(contact)?, phone_e164.map(phone_arg).transpose()?)))();
        let (id, phone) = match parsed {
            Ok(v) => v,
            Err(c) => return c,
        };
        flatten(self.on_app(app, |a| {
            let choice = match phone {
                Some(n) => PhoneChoice::UserConfirmed(n),
                None => PhoneChoice::NoNumber,
            };
            a.vault_mut()?.set_phone(id, choice).map_err(trust_code)?;
            Ok(OK)
        }))
    }

    pub fn contact_delete(&self, app: i64, contact: i32) -> i32 {
        flatten(self.on_app(app, |a| {
            let id = contact_id(contact)?;
            a.vault_mut()?.remove_contact(id).map_err(trust_code)?;
            Ok(OK)
        }))
    }

    // ------------------------------------------------------------ call session

    /// dial: we placed the call to contact (0 = a typed number). Every PSK and resume secret
    /// in the vault goes to the handshake; peer_e164 only feeds the "number had another key" hint.
    pub fn session_create(
        &self,
        app: i64,
        dial: bool,
        contact: i32,
        peer_e164: Option<&[u8]>,
        wideband: bool,
        now: i64,
    ) -> Result<i64, i32> {
        let gear_code = if wideband { ModemGear::Wideband2400 as i32 } else { ModemGear::Narrowband1200 as i32 };
        self.session_create_gear(app, dial, contact, peer_e164, gear_code, now)
    }

    /// Like [Bridge::session_create], selecting any wire [ModemGear] (`1` Narrowband1200,
    /// `2` Wideband2400, `3` Robust300, `4` Speech300).
    pub fn session_create_gear(
        &self,
        app: i64,
        dial: bool,
        contact: i32,
        peer_e164: Option<&[u8]>,
        gear_code: i32,
        now: i64,
    ) -> Result<i64, i32> {
        let gear = u8::try_from(gear_code).ok().and_then(ModemGear::from_wire).ok_or(BAD_ARG)?;
        let now = now_ms(now)?;
        if peer_e164.is_some_and(|n| n.len() > MAX_PHONE_LEN) {
            return Err(BAD_ARG);
        }
        let app_h = handle(app)?;
        let e = self.app_entry(app)?;
        let h = self.handles.fresh()?;
        let entry = e.clone();
        with_live(&e, |a| {
            self.guard()?;
            let id = a.identity.as_ref().ok_or(BAD_STATE)?;
            let local = LocalIdentity { pub33: id.pub33, evidence_id: id.evidence_id };
            let chain = id.chain_tlv.clone();
            let vault = a.vault_ref()?;
            let side = match (dial, contact) {
                (true, 0) => CallSide::Dialer { contact: None },
                (true, c) => CallSide::Dialer { contact: Some(contact_id(c)?) },
                (false, _) => CallSide::Answerer,
            };
            // The caller ID only produces the "this number had another key" hint.
            let (exp, hint) = vault.expectation_for(peer_e164);
            let stored = match side {
                CallSide::Dialer { contact: Some(c) } => {
                    Some(vault.contacts().into_iter().find(|v| v.id == c).ok_or(BAD_ARG)?.pub33)
                }
                _ => hint,
            };
            let expect = PeerExpectation {
                psk: exp.psk,
                resume: exp
                    .resume
                    .into_iter()
                    .map(|r| ResumeCandidate { contact: r.contact, pub33: r.pub33, secret: r.secret, is_new: r.is_new })
                    .collect(),
            };
            let mut call = SecureCallSession::new(local, expect, side, stored, gear, now).map_err(|_| BAD_STATE)?;
            call.provide_evidence_chain(&chain).map_err(|_| BAD_STATE)?;
            self.sessions.insert(h, app_h, Session::new(h, entry, call, gear, now))?;
            jlong(h)
        })
    }

    /// PCM for the next slot: Some(empty) = voice window (send the microphone), None = done.
    pub fn session_tx_pcm(&self, s: i64, now: i64) -> Result<Option<Vec<i16>>, i32> {
        let now = now_ms(now)?;
        self.on_session(s, |x| {
            x.now = now;
            let unit = x.call.next_tx(now);
            Ok(render_tx(unit, x.gear, &mut x.tx))
        })
    }

    pub fn session_rx_pcm(&self, s: i64, pcm: &[i16], now: i64) -> i32 {
        if pcm.len() > MAX_RX_CHUNK {
            return BAD_ARG;
        }
        let Ok(now) = now_ms(now) else { return BAD_ARG };
        flatten(self.on_session(s, |x| {
            x.now = now;
            // The receiver checks every unit boundary for the peer's preamble on its own.
            x.rx.feed(pcm, &mut x.call, now);
            Ok(OK)
        }))
    }

    pub fn session_poll(&self, s: i64) -> Result<Zeroizing<Vec<u8>>, i32> {
        self.on_session(s, |x| Ok(x.take_events()))
    }

    /// DER signature for NEED_SIGNATURE(req_id); ok = false (or no DER) fails the handshake.
    pub fn session_sign_result(&self, s: i64, req_id: i32, ok: bool, der: Option<&[u8]>) -> i32 {
        flatten(self.on_session(s, |x| {
            let req = req_id as u32;
            match (ok, der) {
                (true, Some(d)) => x.call.on_signature(req, d),
                _ => x.call.on_signature(req, &[]),
            }
            Ok(OK)
        }))
    }

    pub fn session_sas(&self, s: i64, ok: bool) -> i32 {
        flatten(self.on_session(s, |x| x.call.sas_decision(ok).map(|_| OK).map_err(chat_code)))
    }

    pub fn session_voice_window(&self, s: i64, open: bool) -> i32 {
        flatten(self.on_session(s, |x| x.call.voice_window(open).map(|_| OK).map_err(chat_code)))
    }

    /// contact 0 adds the peer as a new contact (phone optional). contact != 0 replaces the
    /// key of that contact after a key change (no phone argument). Returns the contact id.
    pub fn session_save_contact(&self, s: i64, contact: i32, label: &[u8], phone_e164: Option<&[u8]>) -> i32 {
        let parsed: Result<_, i32> =
            (|| Ok((opt_contact(contact)?, label_arg(label)?, phone_e164.map(phone_arg).transpose()?)))();
        let (target, label, phone) = match parsed {
            Ok(v) => v,
            Err(c) => return c,
        };
        flatten(self.on_session(s, |x| x.save_contact(target, label, phone)))
    }

    /// The bearer left LTE/NR (code is the app's reason, 0-255): abort and wipe now.
    pub fn session_bearer_violation(&self, s: i64, code: i32) -> i32 {
        if !(0..=255).contains(&code) {
            return BAD_ARG;
        }
        flatten(self.on_session(s, |x| {
            x.call.abort(AbortReason::BearerViolation);
            Ok(OK)
        }))
    }

    /// Returns the message id (0-65535).
    pub fn session_send_text(&self, s: i64, text: &[u8], burn_ttl_secs: i32, now: i64) -> i32 {
        let (Ok(ttl), Ok(now)) = (u16::try_from(burn_ttl_secs), now_ms(now)) else { return BAD_ARG };
        if text.is_empty() || text.len() > MAX_TEXT_LEN {
            return BAD_ARG;
        }
        let Ok(t) = std::str::from_utf8(text) else { return BAD_ARG };
        flatten(self.on_session(s, |x| {
            x.now = now;
            let id = x.call.chat().map_err(chat_code)?.send_text_message(now, ttl, t).map_err(chat_code)?;
            Ok(i32::from(id))
        }))
    }

    /// quick_code: 1 safe arrival, 2 surveillance/switch plan, 3 hold silent, 4 rekey now,
    /// 5 GPS pin (lat/lon in 1e-6 degrees). Returns the message id.
    pub fn session_send_quick(&self, s: i64, quick_code: i32, lat_e6: i32, lon_e6: i32, now: i64) -> i32 {
        let q = match quick_code {
            QUICK_SAFE_ARRIVAL => TacticalQuickCode::SafeArrival,
            QUICK_SURVEILLANCE => TacticalQuickCode::UnderSurveillanceSwitchPlan,
            QUICK_HOLD_SILENT => TacticalQuickCode::BusyHoldSilent,
            QUICK_REKEY => TacticalQuickCode::RequestImmediateRekey,
            QUICK_GPS_PIN if (-90_000_000..=90_000_000).contains(&lat_e6) && (-180_000_000..=180_000_000).contains(&lon_e6) => {
                TacticalQuickCode::OfflineGpsPin { lat_e6, lon_e6 }
            }
            _ => return BAD_ARG,
        };
        let Ok(now) = now_ms(now) else { return BAD_ARG };
        flatten(self.on_session(s, |x| {
            x.now = now;
            let id = x.call.chat().map_err(chat_code)?.send_tactical_quick_code(now, q).map_err(chat_code)?;
            Ok(i32::from(id))
        }))
    }

    pub fn session_request_ratchet(&self, s: i64) -> i32 {
        flatten(self.on_session(s, |x| x.call.request_ratchet().map(|_| OK).map_err(chat_code)))
    }

    /// notify_peer: hang up (SESSION_END or ABORT frames go out; the handle stays until the
    /// app calls again with false). Otherwise wipe and release the handle now.
    pub fn session_close(&self, s: i64, notify_peer: bool) -> i32 {
        if notify_peer {
            return flatten(self.on_session(s, |x| {
                x.call.end();
                Ok(OK)
            }));
        }
        if let Err(c) = self.guard() {
            return c;
        }
        match handle(s) {
            Ok(h) => self.close_session_handle(h),
            Err(c) => c,
        }
    }

    /// Sets WIPING (every later call returns BAD_HANDLE), then closes every session and app.
    pub fn panic_wipe(&self, _app: i64) -> i32 {
        self.wiping.store(true, Ordering::SeqCst);
        for s in self.sessions.handles() {
            self.close_session_handle(s);
        }
        for a in self.apps.handles() {
            self.close_app_handle(a);
        }
        for s in self.sessions.handles() {
            self.close_session_handle(s);
        }
        OK
    }

    pub fn app_close(&self, app: i64) -> i32 {
        if let Err(c) = self.guard() {
            return c;
        }
        match handle(app) {
            Ok(h) => self.close_app_handle(h),
            Err(c) => c,
        }
    }
}

#[cfg(test)]
impl Bridge {
    pub(crate) fn app_slot(&self, app: i64) -> Result<Entry<App>, i32> {
        self.app_entry(app)
    }

    pub(crate) fn export_via(e: &Entry<App>) -> Result<Zeroizing<Vec<u8>>, i32> {
        with_live(e, |a| a.vault_mut()?.export().map(Zeroizing::new).map_err(trust_code))
    }

    pub(crate) fn live_handles(&self) -> usize {
        self.apps.handles().len() + self.sessions.handles().len()
    }

    /// Replaces the chain we hand to peers without touching the evidence_id we sign.
    pub(crate) fn swap_chain(&self, app: i64, chain_tlv: &[u8]) -> Result<(), i32> {
        self.on_app(app, |a| {
            a.identity.as_mut().ok_or(BAD_STATE)?.chain_tlv = chain_tlv.to_vec();
            Ok(())
        })
    }

    pub(crate) fn session_next_unit(&self, s: i64, now: i64) -> Result<aegiscall_chat::TxUnit, i32> {
        let now = now_ms(now)?;
        self.on_session(s, |x| {
            x.now = now;
            Ok(x.call.next_tx(now))
        })
    }

    pub(crate) fn session_deliver(&self, s: i64, u: aegiscall_chat::TxUnit, now: i64) -> Result<(), i32> {
        let now = now_ms(now)?;
        self.on_session(s, |x| {
            x.now = now;
            match u {
                aegiscall_chat::TxUnit::Preamble(raw) => {
                    x.call.on_rx_preamble(raw, now);
                }
                aegiscall_chat::TxUnit::Superframe(w) => x.call.on_rx_superframe(&w, now),
                _ => {}
            }
            Ok(())
        })
    }

    /// (contact, secret, is_new) of every resume secret in the vault.
    pub(crate) fn resume_secrets(&self, app: i64) -> Result<Vec<(u32, [u8; 32], bool)>, i32> {
        self.on_app(app, |a| {
            let (exp, _) = a.vault_ref()?.expectation_for(None);
            Ok(exp.resume.iter().map(|r| (r.contact, *r.secret.as_bytes(), r.is_new)).collect())
        })
    }
}
