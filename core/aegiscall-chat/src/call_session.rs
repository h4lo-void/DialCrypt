//! Secure call session (secure-session-v2 §2.B, §2.D, amended by §6).
//!
//! Drives one call: preamble exchange, handshake v2 over [HsLink], key installation, SAS
//! decision and voice comparison window, encrypted chat ([ChatSessionEngine]), BULK transfer of
//! the background ML-KEM exchange (resume path) and attestation chain, the two-phase update of
//! the resume secret, and hang-up. The app drives it by polling: [SecureCallSession::next_tx]
//! once per slot, the two receive calls, and [SecureCallSession::poll_events]. Failures are
//! reported as codes ([AbortReason], [ChatError::code]); nothing here produces user-facing text.
//!
//! Fail-closed (§6.1): any check failure, no peer preamble within 20 s, or a stalled handshake
//! sends 3 abort frames and ends the session; there is no retry inside one call. After the keys
//! exist, link-layer ABORT and stray handshake frames are ignored (§6.2): only encrypted
//! SESSION_END / SAS_RESULT end the session.
//!
//! Time: every `now` argument is milliseconds from a monotonic clock (for example Android
//! SystemClock.elapsedRealtime), never wall-clock time. Calls without a `now` argument use the
//! time of the most recent call that had one.

use crate::hs_link::{HsLink, HsLinkError, HS_FRAME_LEN};
use crate::{ChatError, ChatSessionEngine, EngineEvent, RxOutcome, SUPERFRAME_LEN};
use aegiscall_crypto::handshake_v2::{MSG_HS1, MSG_HS2, MSG_HS3, MSG_HS4, MSG_PATH, MSG_RS2, MSG_RS3};
use aegiscall_crypto::identity::validate_pub33;
use aegiscall_crypto::{
    classify_peer, pq_encapsulate, resume_saved_tag, CallSide, Established, HandshakeV2, HsError, HsOut, IdentityStatus,
    LinkContext, LocalIdentity, Path, PeerExpectation, PeerIdentity, PqKeyPair, Role,
};
use aegiscall_memsec::{EphemeralChatVault, SecretKey32};
use aegiscall_modem::{ModemGear, PreambleCapabilities};
use aegiscall_mux::{ctrl, FrameKind, MuxFrame, MUX_BODY_LEN};
use rand_core::{OsRng, RngCore};
use std::collections::VecDeque;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Abort when no valid peer preamble arrives within this time (§6.1; not doubled on narrowband).
pub const PREAMBLE_WAIT_MS: u64 = 20_000;
pub const PREAMBLE_REPEAT_MS: u64 = 2_000;
/// Once the peer's handshake frames are seen, and for the rest of the call, our preamble is
/// re-sent after this many superframes so the peer's receiver re-anchors its timing: the two
/// phones' sample clocks differ (-116 ppm measured between two Pixels, +-200 ppm designed for)
/// and the VoLTE jitter buffer inserts or drops samples. 24 wideband (or 12 narrowband)
/// superframes are 3.84 s; with the 0.4 s preamble that is 9.4 % of the channel time. At
/// 200 ppm the timing slides 13.6 samples per cycle before the receiver's clock compensation,
/// inside the 32-sample guard of a frame; a jump is repaired at most one cycle later.
/// To be confirmed on device: how often the jitter buffer jumps on a real call (each jump costs up to one
/// cycle of frames until the next preamble).
pub const RESYNC_PREAMBLE_SLOTS_WIDE: u32 = 24;
pub const RESYNC_PREAMBLE_SLOTS_NARROW: u32 = 12;
/// Whole handshake limit (doubled on narrowband).
pub const HANDSHAKE_LIMIT_MS: u64 = 90_000;
/// No new handshake fragment for this long aborts (doubled on narrowband). Also bounds the time
/// between our keys and the peer's first valid encrypted frame.
///
/// A received preamble is not progress and never resets this timer: it is unauthenticated, can
/// be replayed from a recording, and a healthy line always carries link frames (new fragments
/// or acknowledgements) next to the preambles. The periodic preambles keep the receiver
/// aligned so that those frames decode; a peer that sends nothing else still stalls out.
pub const STALL_LIMIT_MS: u64 = 15_000;
/// Local StrongBox signature limit.
pub const SIGN_LIMIT_MS: u64 = 5_000;
pub const VOICE_WINDOW_MAX_MS: u64 = 60_000;
/// After a voice window closes, the peer's preamble is accepted for re-synchronisation this long.
pub const RESYNC_ACCEPT_MS: u64 = 10_000;
pub const ABORT_FRAMES: u8 = 3;
pub const END_FRAMES: u8 = 3;
/// SAS_RESULT and RESUME_SAVED are repeated every this many slots until the peer's arrives.
pub const CTRL_RESEND_FRAMES: u64 = 8;
pub const VOICE_ANNOUNCE_FRAMES: u8 = 3;
/// A request to open the voice window lives this long. The peer's request counts only this long
/// after it was last heard (it is repeated every CTRL_RESEND_FRAMES slots); the local request
/// is withdrawn automatically when the peer has not asked too within this time.
pub const VOICE_REQUEST_TTL_MS: u64 = 30_000;
pub const MAX_EVIDENCE_LEN: usize = 8192;
const FULL_PATH_FRAGS: u64 = 205;
const RESUME_PATH_FRAGS: u64 = 25;
const EVENT_CAP: usize = 4096;
const BULK_DATA_LEN: usize = 11;
const BULK_ACK_SPAN: usize = 88;
const BULK_RETX_FRAMES: u64 = 24;
const BULK_ACK_EVERY: u32 = 8;
const OBJ_EK: u8 = 1;
const OBJ_CT: u8 = 2;
const OBJ_EVIDENCE: u8 = 3;
const PQ_OBJ_LEN: usize = 1568;
const PQ_OBJ_FRAGS: usize = PQ_OBJ_LEN.div_ceil(BULK_DATA_LEN);
const MAX_EVIDENCE_FRAGS: usize = (MAX_EVIDENCE_LEN + 2).div_ceil(BULK_DATA_LEN);

/// What the modem should transmit in the next slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxUnit {
    /// Synthesize and send this 5-byte capability preamble.
    Preamble([u8; 5]),
    Superframe([u8; SUPERFRAME_LEN]),
    /// SAS voice comparison window: stop modulating and pass the microphone through.
    Voice,
    /// Nothing more to send; the app hangs up.
    End,
}

/// Why a session ended abnormally. [AbortReason::code] is what crosses the JNI boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AbortReason {
    LocalUser = 1,
    PreambleTimeout = 2,
    HandshakeTimeout = 3,
    StallTimeout = 4,
    SignerTimeout = 5,
    SignerFailed = 6,
    IncompatibleVersion = 7,
    LinkProtocol = 8,
    PeerAbort = 9,
    HsMalformed = 10,
    HsRoleTie = 11,
    HsCommitMismatch = 12,
    HsAeadFail = 13,
    HsBadSignature = 14,
    HsPskMismatch = 15,
    HsPskRequired = 16,
    HsResumeAuthFailed = 17,
    HsPathMismatch = 18,
    SasMismatch = 19,
    PeerSasMismatch = 20,
    RatchetFailed = 21,
    CipherFailure = 22,
    BulkFailed = 23,
    BearerViolation = 24,
    Internal = 25,
    /// Both ends claimed to be the dialer (or both the answerer).
    HsSideConflict = 26,
}

impl AbortReason {
    pub fn code(self) -> u8 {
        self as u8
    }

    pub fn from_code(c: u8) -> Option<Self> {
        use AbortReason::*;
        let all = [
            LocalUser, PreambleTimeout, HandshakeTimeout, StallTimeout, SignerTimeout, SignerFailed,
            IncompatibleVersion, LinkProtocol, PeerAbort, HsMalformed, HsRoleTie, HsCommitMismatch, HsAeadFail,
            HsBadSignature, HsPskMismatch, HsPskRequired, HsResumeAuthFailed, HsPathMismatch, SasMismatch,
            PeerSasMismatch, RatchetFailed, CipherFailure, BulkFailed, BearerViolation, Internal, HsSideConflict,
        ];
        all.into_iter().find(|r| r.code() == c)
    }
}

fn hs_reason(e: HsError) -> AbortReason {
    match e {
        HsError::Malformed => AbortReason::HsMalformed,
        HsError::VersionMismatch => AbortReason::IncompatibleVersion,
        HsError::RoleTie => AbortReason::HsRoleTie,
        HsError::CommitMismatch => AbortReason::HsCommitMismatch,
        HsError::AeadFail => AbortReason::HsAeadFail,
        HsError::BadSignature => AbortReason::HsBadSignature,
        HsError::PskMismatch => AbortReason::HsPskMismatch,
        HsError::Timeout => AbortReason::HandshakeTimeout,
        HsError::PeerAbort => AbortReason::PeerAbort,
        HsError::SignerFailed => AbortReason::SignerFailed,
        HsError::PskRequired => AbortReason::HsPskRequired,
        HsError::ResumeAuthFailed => AbortReason::HsResumeAuthFailed,
        HsError::PathMismatch => AbortReason::HsPathMismatch,
        HsError::SideConflict => AbortReason::HsSideConflict,
        HsError::Aborted => AbortReason::Internal,
    }
}

fn engine_reason(e: ChatError) -> AbortReason {
    match e {
        ChatError::Ratchet(_) => AbortReason::RatchetFailed,
        ChatError::Epoch(_) => AbortReason::CipherFailure,
        _ => AbortReason::Internal,
    }
}

/// Session notifications, drained with [SecureCallSession::poll_events].
pub enum SessionEvent {
    /// Sign message with SHA256withECDSA on the StrongBox identity key; return the DER via on_signature.
    NeedSignature { req_id: u32, message: Vec<u8> },
    /// Five raw SAS bytes (full path); the app maps them to words.
    Sas([u8; 5]),
    Path(Path),
    HandshakeProgress(u8),
    /// Both sides hold the keys and the peer's first encrypted frame arrived: user data may flow.
    Established {
        role: Role,
        path: Path,
        peer_pub33: [u8; 33],
        identity: IdentityStatus,
        psk_contact: Option<u32>,
    },
    /// The peer's key differs from the stored contact; sending stays locked until both SAS match.
    KeyChanged { stored_pub33: [u8; 33], peer_pub33: [u8; 33] },
    SasConfirmed,
    VoiceWindow { open: bool },
    PqProgress(u8),
    PqMixed { epoch: u32 },
    EpochAdvanced(u32),
    /// Write secret into rs_new of contact (after promoting rs_new to rs_cur first when
    /// promote_used_new_first), fsync, then call vault_saved(seq).
    VaultDirty { seq: u32, contact: u32, k: u8, secret: SecretKey32, promote_used_new_first: bool },
    /// The peer confirmed update k: promote rs_new to rs_cur and clear the old value.
    ResumePromote { contact: u32, k: u8 },
    EvidenceChain(Vec<u8>),
    MessageReceived(u16),
    MessageDelivered(u16),
    /// Outgoing message progress: `acked` of `total` shards confirmed by the peer.
    MessageProgress { msg_id: u16, acked: u16, total: u16 },
    MessageFailed(u16),
    RemoteWipe,
    /// All PANIC_WIPE frames were sent; the session is closed.
    WipeSent,
    Ended { by_peer: bool },
    Aborted(AbortReason),
}

impl SessionEvent {
    /// Stable event type code for the JNI TLV encoding.
    pub fn code(&self) -> u8 {
        match self {
            SessionEvent::NeedSignature { .. } => 1,
            SessionEvent::Sas(_) => 2,
            SessionEvent::Path(_) => 3,
            SessionEvent::HandshakeProgress(_) => 4,
            SessionEvent::Established { .. } => 5,
            SessionEvent::KeyChanged { .. } => 6,
            SessionEvent::SasConfirmed => 7,
            SessionEvent::VoiceWindow { .. } => 8,
            SessionEvent::PqProgress(_) => 9,
            SessionEvent::PqMixed { .. } => 10,
            SessionEvent::EpochAdvanced(_) => 11,
            SessionEvent::VaultDirty { .. } => 12,
            SessionEvent::ResumePromote { .. } => 13,
            SessionEvent::EvidenceChain(_) => 14,
            SessionEvent::MessageReceived(_) => 15,
            SessionEvent::MessageDelivered(_) => 16,
            SessionEvent::MessageFailed(_) => 17,
            SessionEvent::RemoteWipe => 18,
            SessionEvent::WipeSent => 19,
            SessionEvent::Ended { .. } => 20,
            SessionEvent::Aborted(_) => 21,
            SessionEvent::MessageProgress { .. } => 22,
        }
    }
}

impl core::fmt::Debug for SessionEvent {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SessionEvent::NeedSignature { req_id, message } => {
                write!(f, "NeedSignature({req_id}, {} B)", message.len())
            }
            SessionEvent::Sas(_) => write!(f, "Sas"),
            SessionEvent::Path(p) => write!(f, "Path({p:?})"),
            SessionEvent::HandshakeProgress(p) => write!(f, "HandshakeProgress({p})"),
            SessionEvent::Established { role, path, identity, psk_contact, .. } => {
                write!(f, "Established({role:?}, {path:?}, {identity:?}, {psk_contact:?})")
            }
            SessionEvent::KeyChanged { .. } => write!(f, "KeyChanged"),
            SessionEvent::SasConfirmed => write!(f, "SasConfirmed"),
            SessionEvent::VoiceWindow { open } => write!(f, "VoiceWindow({open})"),
            SessionEvent::PqProgress(p) => write!(f, "PqProgress({p})"),
            SessionEvent::PqMixed { epoch } => write!(f, "PqMixed({epoch})"),
            SessionEvent::EpochAdvanced(e) => write!(f, "EpochAdvanced({e})"),
            SessionEvent::VaultDirty { seq, contact, k, promote_used_new_first, .. } => {
                write!(f, "VaultDirty(seq {seq}, contact {contact}, k {k}, promote_first {promote_used_new_first})")
            }
            SessionEvent::ResumePromote { contact, k } => write!(f, "ResumePromote({contact}, {k})"),
            SessionEvent::EvidenceChain(c) => write!(f, "EvidenceChain({} B)", c.len()),
            SessionEvent::MessageReceived(id) => write!(f, "MessageReceived({id})"),
            SessionEvent::MessageDelivered(id) => write!(f, "MessageDelivered({id})"),
            SessionEvent::MessageProgress { msg_id, acked, total } => {
                write!(f, "MessageProgress({msg_id}, {acked}/{total})")
            }
            SessionEvent::MessageFailed(id) => write!(f, "MessageFailed({id})"),
            SessionEvent::RemoteWipe => write!(f, "RemoteWipe"),
            SessionEvent::WipeSent => write!(f, "WipeSent"),
            SessionEvent::Ended { by_peer } => write!(f, "Ended(by_peer {by_peer})"),
            SessionEvent::Aborted(r) => write!(f, "Aborted({r:?})"),
        }
    }
}

struct KeyInfo {
    role: Role,
    path: Path,
    peer: PeerIdentity,
    psk_contact: Option<u32>,
    identity: IdentityStatus,
    key_changed: bool,
    rs_next: Option<SecretKey32>,
    keyed_ms: u64,
}

struct VoiceState {
    since: u64,
    announce_left: u8,
}

struct ResumeSlot {
    k: u8,
    contact: u32,
    tag: [u8; 8],
    seq: u32,
    saved: bool,
    peer_confirmed: bool,
    promoted: bool,
    last_tx: Option<u64>,
}

#[derive(Default)]
struct ResumeState {
    contact: Option<u32>,
    k1_started: bool,
    slot: Option<ResumeSlot>,
    next_k2: Option<SecretKey32>,
    last_done: Option<(u8, [u8; 8])>,
    peer_ahead: Option<(u8, [u8; 8])>,
    next_seq: u32,
}

struct BulkTx {
    obj: u8,
    frags: Vec<[u8; BULK_DATA_LEN]>,
    acked: Vec<bool>,
    last_tx: Vec<Option<u64>>,
}

impl BulkTx {
    fn new(obj: u8, data: &[u8]) -> Self {
        let frags: Vec<[u8; BULK_DATA_LEN]> = data
            .chunks(BULK_DATA_LEN)
            .map(|c| {
                let mut f = [0u8; BULK_DATA_LEN];
                f[..c.len()].copy_from_slice(c);
                f
            })
            .collect();
        let n = frags.len();
        Self { obj, frags, acked: vec![false; n], last_tx: vec![None; n] }
    }

    fn done(&self) -> bool {
        self.acked.iter().all(|a| *a)
    }

    fn acked_count(&self) -> usize {
        self.acked.iter().filter(|a| **a).count()
    }
}

struct BulkRx {
    obj: u8,
    frags: Vec<Option<[u8; BULK_DATA_LEN]>>,
    have: usize,
    total: Option<usize>,
    done: bool,
    since_ack: u32,
}

enum BulkStep {
    Nothing,
    AckWindow(usize),
    Complete,
    Corrupt,
}

impl BulkRx {
    fn push(&mut self, idx: usize, data: [u8; BULK_DATA_LEN]) -> BulkStep {
        if self.done {
            return BulkStep::AckWindow(idx);
        }
        match self.frags.get(idx) {
            None => return BulkStep::Nothing,
            Some(Some(prev)) => {
                return if *prev == data { BulkStep::AckWindow(idx) } else { BulkStep::Nothing };
            }
            Some(None) => {}
        }
        if let Some(slot) = self.frags.get_mut(idx) {
            *slot = Some(data);
        }
        self.have += 1;
        self.since_ack += 1;
        if self.obj == OBJ_EVIDENCE && idx == 0 {
            let len = usize::from(u16::from_be_bytes([data[0], data[1]]));
            if len > MAX_EVIDENCE_LEN {
                return BulkStep::Corrupt;
            }
            let total = (len + 2).div_ceil(BULK_DATA_LEN);
            if self.frags.iter().skip(total).any(Option::is_some) {
                return BulkStep::Corrupt;
            }
            self.total = Some(total);
        } else if self.total.is_some_and(|t| idx >= t) {
            return BulkStep::Corrupt;
        }
        if self.total.is_some_and(|t| self.have == t) {
            self.done = true;
            return BulkStep::Complete;
        }
        if self.since_ack >= BULK_ACK_EVERY {
            self.since_ack = 0;
            return BulkStep::AckWindow(idx);
        }
        BulkStep::Nothing
    }

    fn assemble(&self) -> Zeroizing<Vec<u8>> {
        let total = self.total.unwrap_or(0);
        let mut out = Zeroizing::new(Vec::with_capacity(total * BULK_DATA_LEN));
        for f in self.frags.iter().take(total).flatten() {
            out.extend_from_slice(f);
        }
        out
    }

    fn bitmap(&self, base: usize) -> [u8; BULK_DATA_LEN] {
        let mut bm = [0u8; BULK_DATA_LEN];
        for bit in 0..BULK_ACK_SPAN {
            if self.frags.get(base + bit).is_some_and(|f| f.is_some()) {
                if let Some(b) = bm.get_mut(bit / 8) {
                    *b |= 1 << (bit % 8);
                }
            }
        }
        bm
    }
}

#[derive(Default)]
struct BulkState {
    tx: Vec<BulkTx>,
    rx: Vec<BulkRx>,
    pq_kp: Option<PqKeyPair>,
    last_pq: Option<u8>,
}

impl BulkState {
    fn next_frame(&mut self, tick: u64) -> Option<MuxFrame> {
        for tx in self.tx.iter_mut() {
            if tx.done() {
                continue;
            }
            let n = tx.frags.len();
            let unacked = |i: usize| !tx.acked.get(i).copied().unwrap_or(true);
            let fresh = (0..n).find(|&i| unacked(i) && tx.last_tx.get(i).is_some_and(|l| l.is_none()));
            let pick = fresh.or_else(|| {
                (0..n).find(|&i| {
                    unacked(i)
                        && tx.last_tx.get(i).copied().flatten().is_some_and(|t| tick.saturating_sub(t) >= BULK_RETX_FRAMES)
                })
            });
            let Some(i) = pick else { continue };
            if let Some(l) = tx.last_tx.get_mut(i) {
                *l = Some(tick);
            }
            let mut body = [0u8; MUX_BODY_LEN];
            body[0] = (tx.obj << 4) | (((i >> 8) as u8) & 0x0F);
            body[1] = (i & 0xFF) as u8;
            if let Some(d) = tx.frags.get(i) {
                body[2..].copy_from_slice(d);
            }
            return Some(MuxFrame::new(FrameKind::CtrlAck, ctrl::BULK_DATA, body));
        }
        None
    }

    fn rx_get(&self, obj: u8) -> Option<&BulkRx> {
        self.rx.iter().find(|r| r.obj == obj)
    }

    fn rx_entry(&mut self, obj: u8, cap: usize) -> Option<&mut BulkRx> {
        if !self.rx.iter().any(|r| r.obj == obj) {
            let total = if obj == OBJ_EVIDENCE { None } else { Some(cap) };
            self.rx.push(BulkRx { obj, frags: vec![None; cap], have: 0, total, done: false, since_ack: 0 });
        }
        self.rx.iter_mut().find(|r| r.obj == obj)
    }
}

/// Byte 1 of SAS_RESULT / byte 9 of RESUME_SAVED: 1 marks a reply. Periodic copies are
/// answered with a reply; replies are never answered, so the exchange always ends.
const CTRL_REPLY: u8 = 1;

/// VOICE_WINDOW body: byte 0 = 1 "I want the window open" / 0 "not (any more)"; byte 1 = 1 on a
/// close that follows a window this side actually opened (0 = a request was only withdrawn).
fn voice_body(open: bool, was_open: bool) -> [u8; MUX_BODY_LEN] {
    let mut b = [0u8; MUX_BODY_LEN];
    b[0] = u8::from(open);
    b[1] = u8::from(was_open);
    b
}

fn flag_body(v: u8) -> [u8; MUX_BODY_LEN] {
    let mut b = [0u8; MUX_BODY_LEN];
    b[0] = v;
    b
}

fn sas_body(ok: bool, reply: bool) -> [u8; MUX_BODY_LEN] {
    let mut b = [0u8; MUX_BODY_LEN];
    b[0] = u8::from(ok);
    b[1] = if reply { CTRL_REPLY } else { 0 };
    b
}

fn resume_body(k: u8, tag: &[u8; 8], reply: bool) -> [u8; MUX_BODY_LEN] {
    let mut b = [0u8; MUX_BODY_LEN];
    b[0] = k;
    b[1..9].copy_from_slice(tag);
    b[9] = if reply { CTRL_REPLY } else { 0 };
    b
}

fn ctrl_frame(subtype: u8, body: [u8; MUX_BODY_LEN]) -> MuxFrame {
    MuxFrame::new(FrameKind::CtrlAck, subtype, body)
}

pub struct SecureCallSession {
    local: LocalIdentity,
    expect: Option<PeerExpectation>,
    side: CallSide,
    stored: Option<[u8; 33]>,
    gear: ModemGear,
    peer_gear: Option<ModemGear>,
    local_preamble: [u8; 5],
    peer_preamble: Option<[u8; 5]>,
    started_ms: u64,
    last_now: u64,
    last_preamble_ms: Option<u64>,
    /// Superframes sent since our last preamble (voice slots do not count).
    slots_since_preamble: u32,
    peer_hs_seen: bool,
    link: HsLink,
    hs: Option<HandshakeV2>,
    hs_pending: Vec<(u8, Vec<u8>)>,
    hs_fed: u8,
    path_reported: bool,
    sign_deadline: Option<u64>,
    last_progress_ms: u64,
    seen_frags: u64,
    hs_progress: Option<u8>,
    sas: Option<[u8; 5]>,
    local_sas: Option<bool>,
    peer_sas: Option<bool>,
    peer_has_our_sas: bool,
    sas_last_tx: Option<u64>,
    sas_confirmed: bool,
    saved_contact: Option<u32>,
    engine: Option<ChatSessionEngine>,
    keys: Option<KeyInfo>,
    peer_confirmed: bool,
    finished_sent: bool,
    voice: Option<VoiceState>,
    voice_close_announce: u8,
    /// The local user asked for the window and is waiting for the peer to ask too.
    voice_local_req: bool,
    voice_local_req_ms: Option<u64>,
    /// When the peer last asked for the window (not open yet: both sides must ask).
    voice_peer_req_ms: Option<u64>,
    voice_req_last_tx: Option<u64>,
    /// One window per call: set when it opens (or when the peer reports it opened and closed).
    voice_used: bool,
    resync_preamble_due: bool,
    resync_until: u64,
    resume: ResumeState,
    bulk: BulkState,
    pq_mixed: bool,
    local_evidence: Option<Vec<u8>>,
    evidence_sent: bool,
    /// The peer asked for our chain before it was verified; answered once the SAS is confirmed.
    evidence_req_deferred: bool,
    events: VecDeque<SessionEvent>,
    aborting: Option<AbortReason>,
    abort_left: u8,
    ending: bool,
    end_left: u8,
    wiping: bool,
    closed: bool,
}

impl SecureCallSession {
    /// local: our StrongBox identity; expect: every PSK and resume secret in the vault;
    /// side: Dialer with the contact that was dialed, or Answerer (the caller ID is never used
    /// for a cryptographic decision, §6.11); stored_pub33: the key pinned for the dialed contact
    /// or for the number shown by the caller ID, only used to flag "this number had another key".
    pub fn new(
        local: LocalIdentity,
        expect: PeerExpectation,
        side: CallSide,
        stored_pub33: Option<[u8; 33]>,
        gear: ModemGear,
        now: u64,
    ) -> Result<Self, ChatError> {
        validate_pub33(&local.pub33).map_err(|_| ChatError::InvalidState)?;
        let mut tag = [0u8; 1];
        OsRng.fill_bytes(&mut tag);
        Ok(Self {
            local,
            expect: Some(expect),
            side,
            stored: stored_pub33,
            gear,
            peer_gear: None,
            local_preamble: PreambleCapabilities::v2(gear).encode_bytes(),
            peer_preamble: None,
            started_ms: now,
            last_now: now,
            last_preamble_ms: None,
            slots_since_preamble: 0,
            peer_hs_seen: false,
            link: HsLink::new(tag[0]),
            hs: None,
            hs_pending: Vec::new(),
            hs_fed: 0,
            path_reported: false,
            sign_deadline: None,
            last_progress_ms: now,
            seen_frags: 0,
            hs_progress: None,
            sas: None,
            local_sas: None,
            peer_sas: None,
            peer_has_our_sas: false,
            sas_last_tx: None,
            sas_confirmed: false,
            saved_contact: None,
            engine: None,
            keys: None,
            peer_confirmed: false,
            finished_sent: false,
            voice: None,
            voice_close_announce: 0,
            voice_local_req: false,
            voice_local_req_ms: None,
            voice_peer_req_ms: None,
            voice_req_last_tx: None,
            voice_used: false,
            resync_preamble_due: false,
            resync_until: 0,
            resume: ResumeState::default(),
            bulk: BulkState::default(),
            pq_mixed: false,
            local_evidence: None,
            evidence_sent: false,
            evidence_req_deferred: false,
            events: VecDeque::new(),
            aborting: None,
            abort_left: 0,
            ending: false,
            end_left: 0,
            wiping: false,
            closed: false,
        })
    }

    // ----- accessors -----

    pub fn local_preamble(&self) -> [u8; 5] {
        self.local_preamble
    }

    /// User data may flow (keys on both sides, peer's first encrypted frame received).
    pub fn is_established(&self) -> bool {
        self.peer_confirmed && !self.closed && self.aborting.is_none()
    }

    /// Our handshake finished and the session keys are installed.
    pub fn is_keyed(&self) -> bool {
        self.engine.is_some() && !self.closed && self.aborting.is_none()
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    pub fn abort_reason(&self) -> Option<AbortReason> {
        self.aborting
    }

    pub fn role(&self) -> Option<Role> {
        self.keys.as_ref().map(|k| k.role).or_else(|| self.hs.as_ref().and_then(|h| h.role()))
    }

    pub fn path(&self) -> Option<Path> {
        self.keys.as_ref().map(|k| k.path).or_else(|| self.hs.as_ref().and_then(|h| h.path()))
    }

    pub fn hs_link_closed(&self) -> bool {
        self.link.is_closed()
    }

    pub fn sas_bytes(&self) -> Option<[u8; 5]> {
        self.sas
    }

    /// The evidence_id the peer signed in its handshake ID block. Only the full path carries
    /// one; on the resume path this is None.
    pub fn peer_evidence_id(&self) -> Option<[u8; 16]> {
        self.keys.as_ref().filter(|k| matches!(k.path, Path::Full)).map(|k| k.peer.evidence_id)
    }

    pub fn tx_epoch(&self) -> Option<u32> {
        self.engine.as_ref().map(|e| e.tx_epoch())
    }

    pub fn vault(&self) -> Option<&EphemeralChatVault> {
        self.engine.as_ref().map(|e| &e.vault)
    }

    pub fn poll_events(&mut self) -> Vec<SessionEvent> {
        self.events.drain(..).collect()
    }

    fn push(&mut self, ev: SessionEvent) {
        if self.events.len() >= EVENT_CAP {
            self.events.pop_front();
        }
        self.events.push_back(ev);
    }

    fn ensure_open(&self) -> Result<(), ChatError> {
        if self.closed || self.aborting.is_some() || self.ending || self.wiping {
            Err(ChatError::SessionClosed)
        } else {
            Ok(())
        }
    }

    // ----- app commands -----

    /// The chat engine, once user data may flow.
    pub fn chat(&mut self) -> Result<&mut ChatSessionEngine, ChatError> {
        self.ensure_open()?;
        if !self.peer_confirmed {
            return Err(ChatError::NotEstablished);
        }
        self.engine.as_mut().ok_or(ChatError::NotEstablished)
    }

    /// Ends the session: 3 abort frames, then [TxUnit::End].
    pub fn abort(&mut self, reason: AbortReason) {
        self.abort_at(reason);
    }

    /// Normal hang-up: 3 SESSION_END frames, then [TxUnit::End]. Before establishment this aborts.
    pub fn end(&mut self) {
        if self.ensure_open().is_err() {
            return;
        }
        if self.peer_confirmed && self.engine.is_some() {
            self.ending = true;
            self.end_left = END_FRAMES;
            // Hanging up wipes message plaintext and pending secrets right away; the engine only
            // stays until the SESSION_END frames are sealed.
            self.drop_secrets();
            if let Some(e) = self.engine.as_mut() {
                e.wipe_local();
            }
            self.push(SessionEvent::Ended { by_peer: false });
        } else {
            self.abort_at(AbortReason::LocalUser);
        }
    }

    /// Dual-end panic wipe: local state is wiped now, PANIC_WIPE goes out in the next 3 slots,
    /// then [SessionEvent::WipeSent] and [TxUnit::End]. Before establishment this aborts.
    pub fn panic_wipe(&mut self) {
        if self.ensure_open().is_err() {
            return;
        }
        if self.peer_confirmed {
            if let Some(e) = self.engine.as_mut() {
                e.trigger_dual_end_panic_wipe();
                self.wiping = true;
                self.bulk = BulkState::default();
                self.resume.slot = None;
                self.resume.next_k2 = None;
                self.voice = None;
                self.voice_local_req = false;
                self.voice_peer_req_ms = None;
                self.purge_secret_events();
                return;
            }
        }
        self.abort_at(AbortReason::LocalUser);
    }

    /// DER signature for a NeedSignature request (verified against our key before use).
    pub fn on_signature(&mut self, req_id: u32, sig_der: &[u8]) {
        if self.closed || self.aborting.is_some() {
            return;
        }
        let now = self.last_now;
        let Some(hs) = self.hs.as_mut() else { return };
        let res = hs.on_signature(req_id, sig_der);
        self.sign_deadline = None;
        self.last_progress_ms = now;
        match res {
            Ok(outs) => {
                self.handle_hs_outs(outs, now);
                self.pump_handshake(now);
            }
            Err(e) => self.abort_at(hs_reason(e)),
        }
    }

    /// The local user's SAS comparison result. A mismatch aborts both sides.
    pub fn sas_decision(&mut self, ok: bool) -> Result<(), ChatError> {
        self.ensure_open()?;
        if self.sas.is_none() || self.local_sas.is_some() {
            return Err(ChatError::InvalidState);
        }
        self.local_sas = Some(ok);
        if !ok {
            self.abort_at(AbortReason::SasMismatch);
            return Ok(());
        }
        if self.peer_confirmed {
            self.send_sas_result(false);
        }
        self.check_sas();
        Ok(())
    }

    /// The user saved (or confirmed) the peer as this contact (full path).
    pub fn contact_saved(&mut self, contact: u32) -> Result<(), ChatError> {
        self.ensure_open()?;
        if self.keys.is_none() {
            return Err(ChatError::NotEstablished);
        }
        self.saved_contact = Some(contact);
        self.maybe_start_k1();
        Ok(())
    }

    /// The vault write announced by VaultDirty(seq) is durable; RESUME_SAVED may be sent.
    pub fn vault_saved(&mut self, seq: u32) -> Result<(), ChatError> {
        self.ensure_open()?;
        let tick = self.engine.as_ref().map(|e| e.frames_sent()).unwrap_or(0);
        let Some(slot) = self.resume.slot.as_mut() else { return Err(ChatError::InvalidState) };
        if slot.seq != seq || slot.saved {
            return Err(ChatError::InvalidState);
        }
        slot.saved = true;
        slot.last_tx = Some(tick);
        let (k, tag, confirmed) = (slot.k, slot.tag, slot.peer_confirmed);
        if let Some(e) = self.engine.as_mut() {
            e.enqueue_ctrl(ctrl::RESUME_SAVED, resume_body(k, &tag, false));
        }
        if confirmed {
            self.promote_slot();
        }
        Ok(())
    }

    /// Asks for (true) or closes / withdraws (false) the SAS voice comparison window.
    ///
    /// The window (microphone passed through, at most VOICE_WINDOW_MAX_MS) opens only when both
    /// users asked for it; [SessionEvent::VoiceWindow] reports the actual opening and closing on
    /// both sides. It opens at most once per call and only while this call's SAS is still to be
    /// compared: on the resume path (no SAS), after both sides confirmed the SAS, or after the
    /// one window was used, asking returns [ChatError::InvalidState].
    /// A request the peer does not match within VOICE_REQUEST_TTL_MS is withdrawn automatically
    /// and reported as VoiceWindow { open: false }; that does not spend the call's one window.
    pub fn voice_window(&mut self, open: bool) -> Result<(), ChatError> {
        self.ensure_open()?;
        if !self.peer_confirmed {
            return Err(ChatError::NotEstablished);
        }
        let now = self.last_now;
        if open {
            self.expire_voice_request(now);
            if self.voice.is_some() || self.voice_local_req {
                return Ok(());
            }
            if !self.voice_allowed() {
                return Err(ChatError::InvalidState);
            }
            let peer_asked = self
                .voice_peer_req_ms
                .is_some_and(|t| now.saturating_sub(t) <= VOICE_REQUEST_TTL_MS);
            if peer_asked {
                self.open_voice(now);
            } else {
                self.voice_local_req = true;
                self.voice_local_req_ms = Some(now);
                self.voice_peer_req_ms = None;
                if let Some(e) = self.engine.as_mut() {
                    e.enqueue_ctrl(ctrl::VOICE_WINDOW, voice_body(true, false));
                    self.voice_req_last_tx = Some(e.frames_sent());
                }
            }
        } else if self.voice.is_some() {
            self.close_voice(now, true);
        } else if self.voice_local_req {
            self.voice_local_req = false;
            if let Some(e) = self.engine.as_mut() {
                e.enqueue_ctrl(ctrl::VOICE_WINDOW, voice_body(false, false));
            }
        }
        Ok(())
    }

    /// Our attestation chain, sent when the peer asks with EVIDENCE_REQ.
    pub fn provide_evidence_chain(&mut self, chain: &[u8]) -> Result<(), ChatError> {
        if chain.len() > MAX_EVIDENCE_LEN {
            return Err(ChatError::MessageTooLarge);
        }
        self.local_evidence = Some(chain.to_vec());
        Ok(())
    }

    /// Asks the peer for its attestation chain (arrives as EvidenceChain).
    pub fn request_evidence(&mut self) -> Result<(), ChatError> {
        let e = self.chat()?;
        e.enqueue_ctrl(ctrl::EVIDENCE_REQ, [0u8; MUX_BODY_LEN]);
        Ok(())
    }

    /// Manual DH ratchet (the responder asks the initiator).
    pub fn request_ratchet(&mut self) -> Result<(), ChatError> {
        self.chat()?.request_ratchet();
        Ok(())
    }

    // ----- receive -----

    /// A decoded peer preamble. Returns true when the modem should (re)synchronise on it:
    /// the first valid one, repeats of it before the keys exist, and the re-synchronisation after
    /// a voice window. Every other preamble after establishment is ignored here; the modem still
    /// re-anchors its timing on any repeat identical to the first one (the peer repeats it every
    /// RESYNC_PREAMBLE_SLOTS_* superframes). A preamble never counts as handshake progress.
    pub fn on_rx_preamble(&mut self, raw: [u8; 5], now: u64) -> bool {
        self.last_now = now;
        if self.closed || self.aborting.is_some() {
            return false;
        }
        if let Some(p) = self.peer_preamble {
            if !bool::from(p.ct_eq(&raw)) {
                return false;
            }
            if self.engine.is_none() {
                return true;
            }
            return self.voice.is_some() || now < self.resync_until;
        }
        let Some(caps) = PreambleCapabilities::decode_bytes(&raw) else { return false };
        if !caps.is_v2_compatible() {
            self.abort_at(AbortReason::IncompatibleVersion);
            return false;
        }
        self.peer_preamble = Some(raw);
        self.peer_gear = Some(caps.preferred_gear);
        self.last_progress_ms = now;
        let Some(expect) = self.expect.take() else {
            self.abort_at(AbortReason::Internal);
            return false;
        };
        let link = LinkContext { local_preamble: self.local_preamble, peer_preamble: raw, gear: self.gear as u8 };
        match HandshakeV2::start(self.local.clone(), link, expect, self.side, &mut OsRng) {
            Ok((hs, outs)) => {
                self.hs = Some(hs);
                self.handle_hs_outs(outs, now);
                true
            }
            Err(e) => {
                self.abort_at(hs_reason(e));
                false
            }
        }
    }

    /// A decoded 23-byte superframe from the peer.
    pub fn on_rx_superframe(&mut self, w: &[u8; SUPERFRAME_LEN], now: u64) {
        self.last_now = now;
        if self.closed || self.aborting.is_some() {
            return;
        }
        if self.ending || self.wiping {
            self.rx_while_closing(w, now);
            return;
        }
        if self.engine.is_some() {
            self.rx_established(w, now);
        } else {
            self.rx_handshake(w, now);
        }
    }

    /// Hanging up or wiping: the only thing still honoured from the peer is its PANIC_WIPE.
    fn rx_while_closing(&mut self, w: &[u8; SUPERFRAME_LEN], now: u64) {
        let Some(e) = self.engine.as_mut() else { return };
        let _ = e.process_rx_wire_superframe(w, now);
        let wiped = e.take_events().iter().any(|ev| matches!(ev, EngineEvent::RemoteWipe));
        if !wiped {
            return;
        }
        self.push(SessionEvent::RemoteWipe);
        if self.ending {
            // Local state is already wiped; stop here instead of finishing the hang-up frames.
            self.close_now();
        }
    }

    fn rx_handshake(&mut self, w: &[u8; SUPERFRAME_LEN], now: u64) {
        if self.peer_preamble.is_none() || self.hs.is_none() {
            return;
        }
        match self.link.on_frame(w) {
            Ok(msg) => {
                self.peer_hs_seen = true;
                if let Some((t, body)) = msg {
                    let bit = 1u8 << (t & 7);
                    if self.hs_fed & bit == 0 && !self.hs_pending.iter().any(|(p, _)| *p == t) && self.hs_pending.len() < 6 {
                        self.hs_pending.push((t, body));
                    }
                    self.last_progress_ms = now;
                    self.pump_handshake(now);
                }
            }
            Err(HsLinkError::PeerAbort(_)) => self.abort_at(AbortReason::PeerAbort),
            Err(e) if e.is_fatal() => self.abort_at(AbortReason::LinkProtocol),
            Err(_) => {}
        }
        // Progress = new fragments from the peer or new acknowledgements of ours.
        let frags = self.link.received_fragments() + self.link.acked_fragments();
        if frags != self.seen_frags {
            self.seen_frags = frags;
            self.last_progress_ms = now;
        }
        self.update_hs_progress();
    }

    /// Feeds completed link messages to the handshake in protocol order. A message that the
    /// decided path never carries is fed immediately so the handshake rejects it.
    fn pump_handshake(&mut self, now: u64) {
        loop {
            if self.aborting.is_some() || self.closed {
                return;
            }
            let Some(hs) = self.hs.as_ref() else { return };
            // Only the dialer receives PATH, right after HS1 and before anything else.
            let dialer = matches!(self.side, CallSide::Dialer { .. });
            let seq: &[u8] = match (hs.path(), hs.role(), dialer) {
                (Some(Path::Resume { .. }), _, true) => &[MSG_HS1, MSG_PATH, MSG_RS2, MSG_RS3],
                (Some(Path::Resume { .. }), _, false) => &[MSG_HS1, MSG_RS2, MSG_RS3],
                (Some(Path::Full), Some(Role::Initiator), true) => &[MSG_HS1, MSG_PATH, MSG_HS2, MSG_HS4],
                (Some(Path::Full), Some(Role::Initiator), false) => &[MSG_HS1, MSG_HS2, MSG_HS4],
                (Some(Path::Full), Some(Role::Responder), true) => &[MSG_HS1, MSG_PATH, MSG_HS3],
                (Some(Path::Full), Some(Role::Responder), false) => &[MSG_HS1, MSG_HS3],
                (_, _, true) => &[MSG_HS1, MSG_PATH],
                (_, _, false) => &[MSG_HS1],
            };
            let path_known = hs.path().is_some();
            let fed = self.hs_fed;
            let next = seq.iter().copied().find(|t| fed & (1u8 << (t & 7)) == 0);
            let pos = self.hs_pending.iter().position(|(t, _)| Some(*t) == next).or_else(|| {
                if path_known {
                    self.hs_pending.iter().position(|(t, _)| !seq.contains(t))
                } else {
                    None
                }
            });
            let Some(pos) = pos else { return };
            let (t, body) = self.hs_pending.remove(pos);
            self.hs_fed |= 1u8 << (t & 7);
            let res = match self.hs.as_mut() {
                Some(hs) => hs.on_message(t, &body),
                None => return,
            };
            match res {
                Ok(outs) => self.handle_hs_outs(outs, now),
                Err(e) => {
                    self.abort_at(hs_reason(e));
                    return;
                }
            }
        }
    }

    fn handle_hs_outs(&mut self, outs: Vec<HsOut>, now: u64) {
        for out in outs {
            if self.aborting.is_some() || self.closed {
                return;
            }
            match out {
                HsOut::Send { msg_type, body } => {
                    if self.link.send(msg_type, body).is_err() {
                        self.abort_at(AbortReason::LinkProtocol);
                    }
                }
                HsOut::NeedSignature { req_id, to_sign } => {
                    self.sign_deadline = Some(now.saturating_add(SIGN_LIMIT_MS));
                    self.push(SessionEvent::NeedSignature { req_id, message: to_sign });
                }
                HsOut::Sas(b) => {
                    self.sas = Some(b);
                    self.push(SessionEvent::Sas(b));
                }
                HsOut::Established(est) => self.install_keys(*est, now),
            }
        }
        if !self.path_reported {
            if let Some(p) = self.hs.as_ref().and_then(|h| h.path()) {
                self.path_reported = true;
                self.push(SessionEvent::Path(p));
            }
        }
    }

    fn install_keys(&mut self, est: Established, now: u64) {
        let Established { root0, chaff_seed, rs_next, transcript_tag, role, peer, path, psk_contact } = est;
        let mut engine = ChatSessionEngine::new(role, &root0, transcript_tag, chaff_seed);
        drop(root0);
        // A peer authenticated through a contact's resume secret or PSK is that contact, whatever
        // number the caller ID showed; the pinned key of the shown number only matters otherwise.
        let identity = if matches!(path, Path::Resume { .. }) || psk_contact.is_some() {
            IdentityStatus::KnownContact
        } else {
            classify_peer(&peer, self.stored.as_ref(), false)
        };
        let key_changed = identity == IdentityStatus::KeyChanged;
        if key_changed {
            engine.set_tx_locked(true);
        }
        // §6.2: R (full path) resends HS4, both sides resend RS3 on resume; I resends nothing.
        self.link.set_established(matches!(path, Path::Resume { .. }) || role == Role::Responder);
        self.engine = Some(engine);
        self.keys = Some(KeyInfo {
            role,
            path,
            peer,
            psk_contact,
            identity,
            key_changed,
            rs_next: Some(rs_next),
            keyed_ms: now,
        });
        self.sign_deadline = None;
        if !self.path_reported {
            self.path_reported = true;
            self.push(SessionEvent::Path(path));
        }
        self.hs = None;
        self.hs_pending.clear();
    }

    fn update_hs_progress(&mut self) {
        if self.keys.is_some() {
            return;
        }
        let total = match self.hs.as_ref().and_then(|h| h.path()) {
            Some(Path::Resume { .. }) => RESUME_PATH_FRAGS,
            _ => FULL_PATH_FRAGS,
        };
        let done = self.link.received_fragments() + self.link.acked_fragments();
        let pct = ((done * 100) / total).min(99) as u8;
        if self.hs_progress != Some(pct) {
            self.hs_progress = Some(pct);
            self.push(SessionEvent::HandshakeProgress(pct));
        }
    }

    fn rx_established(&mut self, w: &[u8; SUPERFRAME_LEN], now: u64) {
        let res = match self.engine.as_mut() {
            Some(e) => e.process_rx_wire_superframe(w, now),
            None => return,
        };
        match res {
            Ok(outcome) => {
                if !self.peer_confirmed {
                    self.peer_confirmed = true;
                    self.on_confirmed();
                }
                if let RxOutcome::Session { subtype, body } = outcome {
                    self.on_session_ctrl(subtype, &body, now);
                }
                self.drain_engine();
                self.update_pq_progress();
            }
            Err(ChatError::FrameRejected) => {
                if !self.link.is_closed() {
                    // Post-establishment link frames never change the session state (§6.2).
                    let _ = self.link.on_frame(w);
                }
            }
            Err(e) => {
                self.drain_engine();
                self.abort_at(engine_reason(e));
            }
        }
    }

    fn on_confirmed(&mut self) {
        self.link.close();
        let Some(k) = self.keys.as_ref() else { return };
        let (role, path, peer_pub33, identity, psk_contact, key_changed) =
            (k.role, k.path, k.peer.pub33, k.identity, k.psk_contact, k.key_changed);
        if self.hs_progress != Some(100) {
            self.hs_progress = Some(100);
            self.push(SessionEvent::HandshakeProgress(100));
        }
        self.push(SessionEvent::Established { role, path, peer_pub33, identity, psk_contact });
        if key_changed {
            if let Some(stored_pub33) = self.stored {
                self.push(SessionEvent::KeyChanged { stored_pub33, peer_pub33 });
            }
        }
        if self.local_sas == Some(true) {
            self.send_sas_result(false);
        }
        self.maybe_start_k1();
        if matches!(path, Path::Resume { .. }) {
            if role == Role::Initiator {
                let kp = PqKeyPair::generate(&mut OsRng);
                self.bulk.tx.push(BulkTx::new(OBJ_EK, kp.encapsulation_key()));
                self.bulk.pq_kp = Some(kp);
            }
            self.update_pq_progress();
        }
    }

    fn on_session_ctrl(&mut self, subtype: u8, body: &[u8; MUX_BODY_LEN], now: u64) {
        match subtype {
            ctrl::HS_FINISHED => {}
            ctrl::SAS_RESULT => self.on_peer_sas(body[0] == 1, body[1] == CTRL_REPLY),
            ctrl::VOICE_WINDOW => self.on_peer_voice(body[0] == 1, body[1] == 1, now),
            ctrl::EVIDENCE_REQ => self.on_evidence_req(),
            ctrl::SESSION_END => self.on_peer_end(body[0]),
            ctrl::RESUME_SAVED => self.on_resume_saved(body),
            ctrl::BULK_DATA => self.on_bulk_data(body),
            ctrl::BULK_ACK => self.on_bulk_ack(body),
            // GEAR_SWITCH and unknown subtypes: no state change.
            _ => {}
        }
    }

    fn drain_engine(&mut self) {
        let evs = match self.engine.as_mut() {
            Some(e) => e.take_events(),
            None => return,
        };
        for ev in evs {
            match ev {
                EngineEvent::EpochAdvanced(e) => self.push(SessionEvent::EpochAdvanced(e)),
                EngineEvent::PqMixed { epoch, resume_next } => {
                    self.pq_mixed = true;
                    self.push(SessionEvent::PqMixed { epoch });
                    self.on_pq_mixed(resume_next);
                }
                EngineEvent::MessageReceived(id) => self.push(SessionEvent::MessageReceived(id)),
                EngineEvent::MessageDelivered(id) => self.push(SessionEvent::MessageDelivered(id)),
                EngineEvent::MessageProgress { msg_id, acked, total } => {
                    self.push(SessionEvent::MessageProgress { msg_id, acked, total })
                }
                EngineEvent::MessageFailed(id) => self.push(SessionEvent::MessageFailed(id)),
                EngineEvent::RemoteWipe => {
                    self.push(SessionEvent::RemoteWipe);
                    self.close_now();
                    return;
                }
            }
        }
    }

    // ----- SAS -----

    fn send_sas_result(&mut self, reply: bool) {
        if let Some(e) = self.engine.as_mut() {
            e.enqueue_ctrl(ctrl::SAS_RESULT, sas_body(true, reply));
            if !reply {
                self.sas_last_tx = Some(e.frames_sent());
            }
        }
    }

    fn on_peer_sas(&mut self, ok: bool, is_reply: bool) {
        if self.sas.is_none() {
            return;
        }
        if !ok {
            self.abort_at(AbortReason::PeerSasMismatch);
            return;
        }
        self.peer_sas = Some(true);
        if is_reply {
            self.peer_has_our_sas = true;
        } else if self.local_sas == Some(true) {
            self.send_sas_result(true);
        }
        self.check_sas();
    }

    fn check_sas(&mut self) {
        if self.sas_confirmed || self.local_sas != Some(true) || self.peer_sas != Some(true) {
            return;
        }
        self.sas_confirmed = true;
        self.push(SessionEvent::SasConfirmed);
        if self.evidence_req_deferred {
            self.evidence_req_deferred = false;
            self.send_evidence();
        }
        // Nothing left to compare: pending voice window requests lapse (an open window runs on).
        self.voice_peer_req_ms = None;
        if self.voice_local_req {
            self.voice_local_req = false;
            self.push(SessionEvent::VoiceWindow { open: false });
        }
        if self.keys.as_ref().is_some_and(|k| k.key_changed) {
            if let Some(e) = self.engine.as_mut() {
                e.set_tx_locked(false);
            }
        }
        self.maybe_start_k1();
    }

    // ----- voice window -----

    /// Once per call, and only while this call's SAS is still to be compared.
    fn voice_allowed(&self) -> bool {
        !self.voice_used && self.sas.is_some() && !self.sas_confirmed
    }

    /// Withdraws a local request the peer did not match in time; the window stays unused.
    fn expire_voice_request(&mut self, now: u64) {
        let expired = self.voice_local_req
            && self.voice_local_req_ms.is_none_or(|t| now.saturating_sub(t) >= VOICE_REQUEST_TTL_MS);
        if !expired {
            return;
        }
        self.voice_local_req = false;
        self.voice_local_req_ms = None;
        self.push(SessionEvent::VoiceWindow { open: false });
        if let Some(e) = self.engine.as_mut() {
            // Sent twice so the peer stops counting our request even if one copy is lost.
            e.enqueue_ctrl(ctrl::VOICE_WINDOW, voice_body(false, false));
            e.enqueue_ctrl(ctrl::VOICE_WINDOW, voice_body(false, false));
        }
    }

    fn open_voice(&mut self, now: u64) {
        self.voice = Some(VoiceState { since: now, announce_left: VOICE_ANNOUNCE_FRAMES });
        self.voice_used = true;
        self.voice_local_req = false;
        self.voice_peer_req_ms = None;
        self.push(SessionEvent::VoiceWindow { open: true });
    }

    fn close_voice(&mut self, now: u64, announce: bool) {
        self.voice = None;
        self.resync_preamble_due = true;
        self.voice_close_announce = if announce { VOICE_ANNOUNCE_FRAMES } else { 0 };
        self.resync_until = now.saturating_add(RESYNC_ACCEPT_MS);
        self.push(SessionEvent::VoiceWindow { open: false });
    }

    fn on_peer_voice(&mut self, open: bool, was_open: bool, now: u64) {
        self.expire_voice_request(now);
        if open {
            // Never opens on the peer's word alone, never reopens, never restarts the timer.
            if self.voice.is_some() || !self.voice_allowed() {
                return;
            }
            if self.voice_local_req {
                self.open_voice(now);
            } else {
                self.voice_peer_req_ms = Some(now);
            }
        } else if self.voice.is_some() {
            self.close_voice(now, false);
        } else {
            self.voice_peer_req_ms = None;
            if was_open {
                // The peer's window opened and closed without ours (its announcements were lost):
                // the call's one window is spent.
                self.voice_used = true;
                if self.voice_local_req {
                    self.voice_local_req = false;
                    self.push(SessionEvent::VoiceWindow { open: false });
                }
            }
        }
    }

    fn on_peer_end(&mut self, code: u8) {
        if code == 0 {
            self.close_now();
            self.push(SessionEvent::Ended { by_peer: true });
            return;
        }
        let r = if code == AbortReason::SasMismatch.code() {
            AbortReason::PeerSasMismatch
        } else {
            AbortReason::PeerAbort
        };
        self.aborting = Some(r);
        self.push(SessionEvent::Aborted(r));
        self.close_now();
    }

    // ----- resume secret update (§6.3, two phases) -----

    fn maybe_start_k1(&mut self) {
        if self.resume.k1_started || !self.peer_confirmed {
            return;
        }
        let Some(k) = self.keys.as_ref() else { return };
        let (contact, promote_first) = match k.path {
            Path::Resume { contact, used_new } => (contact, used_new),
            Path::Full => match (k.psk_contact, self.sas_confirmed, self.saved_contact) {
                (Some(c), _, _) => (c, false),
                (None, true, Some(c)) => (c, false),
                _ => return,
            },
        };
        let Some(secret) = k.rs_next.clone() else { return };
        self.resume.k1_started = true;
        self.resume.contact = Some(contact);
        self.start_slot(1, contact, secret, promote_first);
    }

    fn start_slot(&mut self, k: u8, contact: u32, secret: SecretKey32, promote_used_new_first: bool) {
        let tag = resume_saved_tag(&secret);
        self.resume.next_seq = self.resume.next_seq.wrapping_add(1);
        let seq = self.resume.next_seq;
        let peer_confirmed = self
            .resume
            .peer_ahead
            .is_some_and(|(pk, ptag)| pk == k && bool::from(ptag.ct_eq(&tag)));
        self.resume.slot = Some(ResumeSlot {
            k,
            contact,
            tag,
            seq,
            saved: false,
            peer_confirmed,
            promoted: false,
            last_tx: None,
        });
        self.push(SessionEvent::VaultDirty { seq, contact, k, secret, promote_used_new_first });
    }

    fn promote_slot(&mut self) {
        let Some(slot) = self.resume.slot.as_mut() else { return };
        if slot.promoted || !slot.saved {
            return;
        }
        slot.promoted = true;
        let (k, contact, tag) = (slot.k, slot.contact, slot.tag);
        self.resume.last_done = Some((k, tag));
        self.push(SessionEvent::ResumePromote { contact, k });
        self.try_start_k2();
    }

    fn try_start_k2(&mut self) {
        let ready = self.resume.slot.as_ref().is_some_and(|s| s.k == 1 && s.promoted);
        if !ready {
            return;
        }
        let Some(contact) = self.resume.contact else { return };
        let Some(secret) = self.resume.next_k2.take() else { return };
        self.start_slot(2, contact, secret, false);
    }

    fn on_pq_mixed(&mut self, secret: SecretKey32) {
        let resume = self.keys.as_ref().is_some_and(|k| matches!(k.path, Path::Resume { .. }));
        if !resume || self.resume.contact.is_none() {
            return;
        }
        self.resume.next_k2 = Some(secret);
        self.try_start_k2();
    }

    fn on_resume_saved(&mut self, body: &[u8; MUX_BODY_LEN]) {
        let k = body[0];
        let mut tag = [0u8; 8];
        tag.copy_from_slice(&body[1..9]);
        let is_reply = body[9] == CTRL_REPLY;
        let mut reply = None;
        let mut promote = false;
        if let Some(slot) = self.resume.slot.as_mut() {
            if k == slot.k {
                if !bool::from(slot.tag.ct_eq(&tag)) {
                    return;
                }
                slot.peer_confirmed = true;
                if slot.saved && !is_reply {
                    reply = Some((slot.k, slot.tag));
                }
                promote = slot.saved && !slot.promoted;
            } else if k > slot.k {
                // Receiving k also confirms every smaller update.
                if slot.saved {
                    slot.peer_confirmed = true;
                    promote = !slot.promoted;
                }
                self.resume.peer_ahead = Some((k, tag));
            } else if let Some((dk, dtag)) = self.resume.last_done {
                if dk == k && bool::from(dtag.ct_eq(&tag)) && !is_reply {
                    reply = Some((dk, dtag));
                }
            }
        }
        if let Some((rk, rtag)) = reply {
            if let Some(e) = self.engine.as_mut() {
                e.enqueue_ctrl(ctrl::RESUME_SAVED, resume_body(rk, &rtag, true));
            }
        }
        if promote {
            self.promote_slot();
        }
    }

    // ----- BULK -----

    fn bulk_role(&self) -> Option<(Role, bool)> {
        self.keys.as_ref().map(|k| (k.role, matches!(k.path, Path::Resume { .. })))
    }

    fn on_bulk_data(&mut self, body: &[u8; MUX_BODY_LEN]) {
        let Some((role, resume)) = self.bulk_role() else { return };
        let obj = body[0] >> 4;
        let idx = (usize::from(body[0] & 0x0F) << 8) | usize::from(body[1]);
        let cap = match obj {
            OBJ_EK if role == Role::Responder && resume => PQ_OBJ_FRAGS,
            OBJ_CT if role == Role::Initiator && resume && self.bulk.pq_kp.is_some() => PQ_OBJ_FRAGS,
            OBJ_EVIDENCE => MAX_EVIDENCE_FRAGS,
            _ => return,
        };
        let mut data = [0u8; BULK_DATA_LEN];
        data.copy_from_slice(&body[2..13]);
        let step = match self.bulk.rx_entry(obj, cap) {
            Some(rx) => rx.push(idx, data),
            None => return,
        };
        match step {
            BulkStep::Nothing => {}
            BulkStep::AckWindow(i) => self.send_bulk_ack(obj, (i / BULK_ACK_SPAN) * BULK_ACK_SPAN),
            BulkStep::Corrupt => self.abort_at(AbortReason::BulkFailed),
            BulkStep::Complete => {
                let total = self.bulk.rx_get(obj).and_then(|r| r.total).unwrap_or(0);
                let mut base = 0;
                while base < total {
                    self.send_bulk_ack(obj, base);
                    base += BULK_ACK_SPAN;
                }
                self.on_bulk_complete(obj);
            }
        }
    }

    fn send_bulk_ack(&mut self, obj: u8, base: usize) {
        let Some(bm) = self.bulk.rx_get(obj).map(|r| r.bitmap(base)) else { return };
        let b0 = (obj << 4) | (((base >> 8) as u8) & 0x0F);
        let b1 = (base & 0xFF) as u8;
        let mut body = [0u8; MUX_BODY_LEN];
        body[0] = b0;
        body[1] = b1;
        body[2..].copy_from_slice(&bm);
        if let Some(e) = self.engine.as_mut() {
            e.mux
                .remove_ctrl_where(|f| f.is_ctrl(ctrl::BULK_ACK) && f.body[0] == b0 && f.body[1] == b1);
            e.enqueue_ctrl(ctrl::BULK_ACK, body);
        }
    }

    fn on_bulk_ack(&mut self, body: &[u8; MUX_BODY_LEN]) {
        let obj = body[0] >> 4;
        let base = (usize::from(body[0] & 0x0F) << 8) | usize::from(body[1]);
        for tx in self.bulk.tx.iter_mut().filter(|t| t.obj == obj) {
            for bit in 0..BULK_ACK_SPAN {
                let set = body.get(2 + bit / 8).is_some_and(|b| (b >> (bit % 8)) & 1 == 1);
                if set {
                    if let Some(a) = tx.acked.get_mut(base + bit) {
                        *a = true;
                    }
                }
            }
        }
        self.update_pq_progress();
    }

    fn on_bulk_complete(&mut self, obj: u8) {
        let Some(data) = self.bulk.rx_get(obj).map(|r| r.assemble()) else { return };
        match obj {
            OBJ_EK | OBJ_CT => {
                let pad_ok = data.get(PQ_OBJ_LEN..).is_some_and(|p| p.iter().all(|b| *b == 0));
                let Some(material) = data.get(..PQ_OBJ_LEN) else {
                    self.abort_at(AbortReason::BulkFailed);
                    return;
                };
                if !pad_ok {
                    self.abort_at(AbortReason::BulkFailed);
                    return;
                }
                if obj == OBJ_EK {
                    match pq_encapsulate(material, &mut OsRng) {
                        Ok((ct, ss)) => {
                            if let Some(e) = self.engine.as_mut() {
                                e.set_pq_secret(ss);
                            }
                            self.bulk.tx.push(BulkTx::new(OBJ_CT, &ct));
                        }
                        Err(_) => self.abort_at(AbortReason::BulkFailed),
                    }
                } else {
                    let Some(kp) = self.bulk.pq_kp.take() else { return };
                    match kp.decapsulate(material) {
                        Ok(ss) => {
                            if let Some(e) = self.engine.as_mut() {
                                e.set_pq_secret(ss);
                            }
                        }
                        Err(_) => self.abort_at(AbortReason::BulkFailed),
                    }
                }
            }
            OBJ_EVIDENCE => {
                let len = data.get(..2).map(|b| usize::from(u16::from_be_bytes([b[0], b[1]]))).unwrap_or(0);
                match data.get(2..2 + len) {
                    Some(chain) => {
                        let chain = chain.to_vec();
                        self.push(SessionEvent::EvidenceChain(chain));
                    }
                    None => self.abort_at(AbortReason::BulkFailed),
                }
            }
            _ => {}
        }
    }

    fn on_evidence_req(&mut self) {
        if self.evidence_sent {
            return;
        }
        if !self.evidence_peer_trusted() {
            // The chain names the boot state, patch level and model of this phone: an unverified
            // peer gets nothing. The request is kept and answered if the SAS is confirmed later.
            self.evidence_req_deferred = true;
            return;
        }
        self.send_evidence();
    }

    /// Only a peer whose SAS was confirmed in this call, or a pinned contact (matching stored key,
    /// PSK or resume secret), may receive our attestation chain.
    fn evidence_peer_trusted(&self) -> bool {
        self.sas_confirmed || self.keys.as_ref().is_some_and(|k| k.identity == IdentityStatus::KnownContact)
    }

    fn send_evidence(&mut self) {
        if self.evidence_sent {
            return;
        }
        let Some(chain) = self.local_evidence.as_ref() else { return };
        let mut data = Vec::with_capacity(chain.len() + 2);
        data.extend_from_slice(&(chain.len() as u16).to_be_bytes());
        data.extend_from_slice(chain);
        self.bulk.tx.push(BulkTx::new(OBJ_EVIDENCE, &data));
        self.evidence_sent = true;
    }

    fn update_pq_progress(&mut self) {
        if self.pq_mixed {
            return;
        }
        let Some((role, resume)) = self.bulk_role() else { return };
        if !resume {
            return;
        }
        let (tx_obj, rx_obj) = match role {
            Role::Initiator => (OBJ_EK, OBJ_CT),
            Role::Responder => (OBJ_CT, OBJ_EK),
        };
        let a = self.bulk.tx.iter().find(|t| t.obj == tx_obj).map(|t| t.acked_count()).unwrap_or(0);
        let b = self.bulk.rx_get(rx_obj).map(|r| r.have).unwrap_or(0);
        let pct = (((a + b) * 100) / (2 * PQ_OBJ_FRAGS)).min(99) as u8;
        if self.bulk.last_pq != Some(pct) {
            self.bulk.last_pq = Some(pct);
            self.push(SessionEvent::PqProgress(pct));
        }
    }

    // ----- transmit -----

    /// The unit for the next slot (wideband 160 ms, narrowband 320 ms). now: monotonic ms.
    pub fn next_tx(&mut self, now: u64) -> TxUnit {
        let unit = self.next_unit(now);
        match unit {
            TxUnit::Preamble(_) => self.slots_since_preamble = 0,
            TxUnit::Superframe(_) => self.slots_since_preamble = self.slots_since_preamble.saturating_add(1),
            TxUnit::Voice | TxUnit::End => {}
        }
        unit
    }

    fn next_unit(&mut self, now: u64) -> TxUnit {
        self.last_now = now;
        if self.closed {
            return TxUnit::End;
        }
        self.check_timers(now);
        if self.aborting.is_some() {
            return self.tx_abort();
        }
        if self.ending {
            return self.tx_end();
        }
        if self.wiping {
            return self.tx_wipe(now);
        }
        if self.engine.is_some() {
            return self.tx_established(now);
        }
        self.tx_handshake(now)
    }

    fn slow(&self) -> u64 {
        if self.gear == ModemGear::Narrowband1200 || self.peer_gear == Some(ModemGear::Narrowband1200) {
            2
        } else {
            1
        }
    }

    /// Time for the periodic re-synchronisation preamble.
    fn resync_preamble_slot(&self) -> bool {
        let every = if self.gear == ModemGear::Narrowband1200 {
            RESYNC_PREAMBLE_SLOTS_NARROW
        } else {
            RESYNC_PREAMBLE_SLOTS_WIDE
        };
        self.slots_since_preamble >= every
    }

    fn check_timers(&mut self, now: u64) {
        if self.closed || self.aborting.is_some() || self.ending || self.wiping {
            return;
        }
        let f = self.slow();
        if self.peer_preamble.is_none() {
            if now.saturating_sub(self.started_ms) >= PREAMBLE_WAIT_MS {
                self.abort_at(AbortReason::PreambleTimeout);
            }
            return;
        }
        match self.keys.as_ref() {
            None => {
                if now.saturating_sub(self.started_ms) >= HANDSHAKE_LIMIT_MS * f {
                    self.abort_at(AbortReason::HandshakeTimeout);
                } else if let Some(d) = self.sign_deadline {
                    if now >= d {
                        self.abort_at(AbortReason::SignerTimeout);
                    }
                } else if now.saturating_sub(self.last_progress_ms) >= STALL_LIMIT_MS * f {
                    self.abort_at(AbortReason::StallTimeout);
                }
            }
            Some(k) => {
                if !self.peer_confirmed && now.saturating_sub(k.keyed_ms) >= STALL_LIMIT_MS * f {
                    self.abort_at(AbortReason::StallTimeout);
                }
            }
        }
    }

    fn tx_handshake(&mut self, now: u64) -> TxUnit {
        let due = self.last_preamble_ms.is_none_or(|t| now.saturating_sub(t) >= PREAMBLE_REPEAT_MS);
        if self.peer_preamble.is_none() {
            if due {
                self.last_preamble_ms = Some(now);
                return TxUnit::Preamble(self.local_preamble);
            }
            return TxUnit::Superframe([0u8; HS_FRAME_LEN]);
        }
        // Until the peer's handshake frames arrive every 2 s; afterwards on the slot schedule.
        if (!self.peer_hs_seen && due) || self.resync_preamble_slot() {
            self.last_preamble_ms = Some(now);
            self.link.skip_slot();
            return TxUnit::Preamble(self.local_preamble);
        }
        let f = self.link.next_frame();
        self.update_hs_progress();
        TxUnit::Superframe(f)
    }

    fn tx_established(&mut self, now: u64) -> TxUnit {
        self.expire_voice_request(now);
        if let Some(since) = self.voice.as_ref().map(|v| v.since) {
            if now.saturating_sub(since) >= VOICE_WINDOW_MAX_MS {
                self.close_voice(now, true);
            }
        }
        if let Some(v) = self.voice.as_mut() {
            if v.announce_left > 0 {
                v.announce_left -= 1;
                return self.seal_ctrl_now(ctrl::VOICE_WINDOW, voice_body(true, false));
            }
            return TxUnit::Voice;
        }
        // First unit after a voice window, then on the slot schedule. The preamble slot carries
        // no link or engine frame: the link counts it as a skipped slot, the engine (multiplexer,
        // ratchet, message numbers, retransmission ticks) simply is not asked for a frame.
        if self.resync_preamble_due || self.resync_preamble_slot() {
            self.resync_preamble_due = false;
            if !self.link.is_closed() {
                self.link.skip_slot();
            }
            return TxUnit::Preamble(self.local_preamble);
        }
        if self.voice_close_announce > 0 {
            self.voice_close_announce -= 1;
            return self.seal_ctrl_now(ctrl::VOICE_WINDOW, voice_body(false, true));
        }
        if !self.finished_sent && self.link.all_acked() {
            self.finished_sent = true;
            self.link.skip_slot();
            let mut b = [0u8; MUX_BODY_LEN];
            b[..8].copy_from_slice(b"FINISHED");
            return self.seal_ctrl_now(ctrl::HS_FINISHED, b);
        }
        if self.link.post_wants_tx() {
            return TxUnit::Superframe(self.link.next_frame());
        }
        if !self.link.is_closed() {
            self.link.skip_slot();
        }
        if !self.finished_sent {
            self.finished_sent = true;
            let mut b = [0u8; MUX_BODY_LEN];
            b[..8].copy_from_slice(b"FINISHED");
            return self.seal_ctrl_now(ctrl::HS_FINISHED, b);
        }
        self.periodic_ctrl();
        let res = {
            let Some(engine) = self.engine.as_mut() else { return TxUnit::End };
            let tick = engine.frames_sent();
            let bulk = &mut self.bulk;
            engine.next_tx_with_filler(now, &mut || bulk.next_frame(tick))
        };
        match res {
            Ok(w) => {
                self.drain_engine();
                self.update_pq_progress();
                if self.closed {
                    return TxUnit::End;
                }
                TxUnit::Superframe(w)
            }
            Err(e) => {
                self.drain_engine();
                self.abort_at(engine_reason(e));
                self.tx_abort()
            }
        }
    }

    fn periodic_ctrl(&mut self) {
        let Some(engine) = self.engine.as_mut() else { return };
        let tick = engine.frames_sent();
        let due = |last: Option<u64>| last.is_none_or(|t| tick.saturating_sub(t) >= CTRL_RESEND_FRAMES);
        if self.local_sas == Some(true) && !self.peer_has_our_sas && due(self.sas_last_tx) {
            self.sas_last_tx = Some(tick);
            engine.enqueue_ctrl(ctrl::SAS_RESULT, sas_body(true, false));
        }
        if self.voice_local_req && due(self.voice_req_last_tx) {
            self.voice_req_last_tx = Some(tick);
            engine.enqueue_ctrl(ctrl::VOICE_WINDOW, voice_body(true, false));
        }
        if let Some(slot) = self.resume.slot.as_mut() {
            if slot.saved && !slot.peer_confirmed && due(slot.last_tx) {
                slot.last_tx = Some(tick);
                engine.enqueue_ctrl(ctrl::RESUME_SAVED, resume_body(slot.k, &slot.tag, false));
            }
        }
    }

    fn seal_ctrl_now(&mut self, subtype: u8, body: [u8; MUX_BODY_LEN]) -> TxUnit {
        let res = match self.engine.as_mut() {
            Some(e) => e.seal_frame(&ctrl_frame(subtype, body)),
            None => return TxUnit::End,
        };
        match res {
            Ok(w) => TxUnit::Superframe(w),
            Err(e) => {
                self.abort_at(engine_reason(e));
                self.tx_abort()
            }
        }
    }

    fn tx_abort(&mut self) -> TxUnit {
        let Some(r) = self.aborting else { return TxUnit::End };
        if self.abort_left == 0 {
            self.close_now();
            return TxUnit::End;
        }
        let n = self.abort_left;
        self.abort_left -= 1;
        // With keys but no confirmation the peer may still be in its handshake: mix both kinds.
        let encrypted = self.engine.is_some() && (self.peer_confirmed || n == 2);
        if encrypted {
            let frame = if r == AbortReason::SasMismatch {
                ctrl_frame(ctrl::SAS_RESULT, sas_body(false, false))
            } else {
                ctrl_frame(ctrl::SESSION_END, flag_body(r.code()))
            };
            if let Some(Ok(w)) = self.engine.as_mut().map(|e| e.seal_frame(&frame)) {
                return TxUnit::Superframe(w);
            }
        }
        TxUnit::Superframe(self.link.abort_frame(r.code()))
    }

    fn tx_end(&mut self) -> TxUnit {
        if self.end_left == 0 {
            self.close_now();
            return TxUnit::End;
        }
        self.end_left -= 1;
        let frame = ctrl_frame(ctrl::SESSION_END, flag_body(0));
        match self.engine.as_mut().map(|e| e.seal_frame(&frame)) {
            Some(Ok(w)) => TxUnit::Superframe(w),
            _ => {
                self.close_now();
                TxUnit::End
            }
        }
    }

    fn tx_wipe(&mut self, now: u64) -> TxUnit {
        let flushed = self.engine.as_ref().is_none_or(|e| e.wipe_flushed());
        if flushed {
            self.push(SessionEvent::WipeSent);
            self.close_now();
            return TxUnit::End;
        }
        match self.engine.as_mut().map(|e| e.next_tx_wire_superframe(now)) {
            Some(Ok(w)) => TxUnit::Superframe(w),
            _ => {
                self.close_now();
                TxUnit::End
            }
        }
    }

    // ----- teardown -----

    fn drop_secrets(&mut self) {
        if let Some(hs) = self.hs.as_mut() {
            hs.abort();
        }
        self.hs = None;
        self.hs_pending.clear();
        self.expect = None;
        self.bulk = BulkState::default();
        self.resume.slot = None;
        self.resume.next_k2 = None;
        if let Some(k) = self.keys.as_mut() {
            k.rs_next = None;
        }
        self.voice = None;
        self.voice_local_req = false;
        self.voice_peer_req_ms = None;
        self.sign_deadline = None;
        self.purge_secret_events();
    }

    /// Queued events that carry key material (the resume secret to store) are dropped; their
    /// SecretKey32 zeroizes on drop. A call that ends first skips the update (§6.3).
    fn purge_secret_events(&mut self) {
        self.events.retain(|e| !matches!(e, SessionEvent::VaultDirty { .. }));
    }

    fn abort_at(&mut self, r: AbortReason) {
        if self.closed || self.aborting.is_some() {
            return;
        }
        self.aborting = Some(r);
        self.abort_left = ABORT_FRAMES;
        self.push(SessionEvent::Aborted(r));
        self.drop_secrets();
        if let Some(e) = self.engine.as_mut() {
            e.wipe_local();
        }
    }

    /// Every way out ends here: plaintext, engine (ciphers, ratchet, message keys) and pending
    /// secrets are wiped and dropped, not only on a panic wipe.
    fn close_now(&mut self) {
        self.closed = true;
        self.link.close();
        self.drop_secrets();
        if let Some(e) = self.engine.as_mut() {
            e.wipe_local();
        }
        self.engine = None;
    }
}

impl Drop for SecureCallSession {
    fn drop(&mut self) {
        self.close_now();
        self.events.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegiscall_crypto::SoftwareSigner;

    struct Side {
        s: SecureCallSession,
        signer: SoftwareSigner,
        answer_sas: bool,
    }

    impl Side {
        fn new(side: CallSide, answer_sas: bool) -> Self {
            let signer = SoftwareSigner::generate();
            let expect = PeerExpectation { psk: Vec::new(), resume: Vec::new() };
            let s = SecureCallSession::new(signer.local_identity([7; 16]), expect, side, None, ModemGear::Wideband2400, 0)
                .unwrap();
            Self { s, signer, answer_sas }
        }

        /// Answers signature requests (and the SAS prompt) like the app; other events are dropped.
        fn pump(&mut self) {
            loop {
                let evs = self.s.poll_events();
                if evs.is_empty() {
                    return;
                }
                for ev in evs {
                    match ev {
                        SessionEvent::NeedSignature { req_id, message } => {
                            let der = self.signer.sign_der(&message);
                            self.s.on_signature(req_id, &der);
                        }
                        SessionEvent::Sas(_) if self.answer_sas => self.s.sas_decision(true).unwrap(),
                        _ => {}
                    }
                }
            }
        }
    }

    fn give(u: TxUnit, to: &mut SecureCallSession, now: u64) {
        match u {
            TxUnit::Preamble(raw) => {
                to.on_rx_preamble(raw, now);
            }
            TxUnit::Superframe(w) => to.on_rx_superframe(&w, now),
            TxUnit::Voice | TxUnit::End => {}
        }
    }

    /// One slot without pumping events; returns what each side sent.
    fn slot(a: &mut Side, b: &mut Side, now: &mut u64) -> (TxUnit, TxUnit) {
        *now += 160;
        let ua = a.s.next_tx(*now);
        let ub = b.s.next_tx(*now);
        give(ua, &mut b.s, *now);
        give(ub, &mut a.s, *now);
        (ua, ub)
    }

    fn established(answer_sas: bool) -> (Side, Side, u64) {
        let mut a = Side::new(CallSide::Dialer { contact: None }, answer_sas);
        let mut b = Side::new(CallSide::Answerer, answer_sas);
        let mut now = 0;
        for _ in 0..600 {
            if a.s.is_established() && b.s.is_established() {
                break;
            }
            slot(&mut a, &mut b, &mut now);
            a.pump();
            b.pump();
        }
        assert!(a.s.is_established() && b.s.is_established());
        (a, b, now)
    }

    fn holds_nothing(s: &SecureCallSession) -> bool {
        s.engine.is_none()
            && s.hs.is_none()
            && s.expect.is_none()
            && s.hs_pending.is_empty()
            && s.resume.slot.is_none()
            && s.resume.next_k2.is_none()
            && s.bulk.tx.is_empty()
            && s.bulk.rx.is_empty()
            && s.bulk.pq_kp.is_none()
            && s.keys.as_ref().is_none_or(|k| k.rs_next.is_none())
            && !s.events.iter().any(|e| matches!(e, SessionEvent::VaultDirty { .. }))
    }

    #[test]
    fn normal_end_leaves_no_keys_plaintext_or_secret_events_on_either_side() {
        let (mut a, mut b, mut now) = established(true);
        let id = a.s.chat().unwrap().send_text_message(now, 0, "plaintext to forget").unwrap();
        for _ in 0..60 {
            slot(&mut a, &mut b, &mut now);
            a.pump();
            b.pump();
        }
        assert!(a.s.chat().unwrap().is_outgoing_delivered(id));
        assert!(b.s.vault().unwrap().total_live_secret_bytes() > 0);
        // The resume secret is queued for the app on both sides and not polled before the hang-up.
        a.s.contact_saved(1).unwrap();
        b.s.contact_saved(2).unwrap();
        assert!(a.s.events.iter().any(|e| matches!(e, SessionEvent::VaultDirty { .. })));
        assert!(b.s.events.iter().any(|e| matches!(e, SessionEvent::VaultDirty { .. })));

        a.s.end();
        // Plaintext and pending secrets go at once; only the cipher stays for the END frames.
        assert_eq!(a.s.engine.as_ref().map(|e| e.vault.total_live_secret_bytes()), Some(0));
        assert!(a.s.resume.slot.is_none());
        assert!(!a.s.events.iter().any(|e| matches!(e, SessionEvent::VaultDirty { .. })));
        for _ in 0..6 {
            slot(&mut a, &mut b, &mut now);
        }
        assert!(a.s.is_closed() && b.s.is_closed());
        assert!(holds_nothing(&a.s), "the side that hung up still holds secrets");
        assert!(holds_nothing(&b.s), "the side that was hung up on still holds secrets");
        assert!(b.s.events.iter().any(|e| matches!(e, SessionEvent::Ended { by_peer: true })));
        assert!(a.s.vault().is_none() && b.s.vault().is_none());
        assert!(a.s.tx_epoch().is_none() && b.s.tx_epoch().is_none());
        assert_eq!(a.s.chat().err(), Some(ChatError::SessionClosed));
    }

    #[test]
    fn abort_and_timeout_also_leave_nothing_behind() {
        let (mut a, mut b, mut now) = established(true);
        a.s.chat().unwrap().send_text_message(now, 0, "to forget").unwrap();
        a.s.contact_saved(1).unwrap();
        a.s.abort(AbortReason::BearerViolation);
        for _ in 0..6 {
            slot(&mut a, &mut b, &mut now);
        }
        assert!(a.s.is_closed() && b.s.is_closed());
        assert!(holds_nothing(&a.s) && holds_nothing(&b.s));
        assert_eq!(b.s.abort_reason(), Some(AbortReason::PeerAbort));

        // A handshake that stalls half way: the timeout path drops the handshake secrets too.
        let mut c = Side::new(CallSide::Dialer { contact: None }, true);
        let mut d = Side::new(CallSide::Answerer, true);
        let mut now = 0;
        for _ in 0..30 {
            slot(&mut c, &mut d, &mut now);
            c.pump();
            d.pump();
        }
        assert!(c.s.hs.is_some());
        for _ in 0..200 {
            now += 160;
            let _ = c.s.next_tx(now);
        }
        assert_eq!(c.s.abort_reason(), Some(AbortReason::StallTimeout));
        assert!(c.s.is_closed() && holds_nothing(&c.s));
    }

    #[test]
    fn repeated_peer_open_requests_never_open_reopen_or_extend_the_voice_window() {
        let (mut a, mut b, mut now) = established(false);
        // Peer asks on its own, many times: nothing opens and no Voice unit is ever produced.
        for k in 0..20 {
            a.s.on_peer_voice(true, false, now + k);
        }
        assert!(a.s.voice.is_none() && !a.s.voice_used);
        assert!(!matches!(a.s.next_tx(now + 160), TxUnit::Voice));
        // A stale peer request does not count when the local user asks much later.
        a.s.last_now = now + VOICE_REQUEST_TTL_MS + 1_000;
        a.s.voice_window(true).unwrap();
        assert!(a.s.voice.is_none() && a.s.voice_local_req);
        // Both asked: open, once.
        a.s.on_peer_voice(true, false, a.s.last_now);
        let since = a.s.voice.as_ref().map(|v| v.since);
        assert!(since.is_some() && a.s.voice_used);
        // More open requests while open do not restart the 60 s timer.
        a.s.on_peer_voice(true, false, a.s.last_now + 30_000);
        assert_eq!(a.s.voice.as_ref().map(|v| v.since), since);
        // The window times out on its own ...
        now = a.s.last_now + VOICE_WINDOW_MAX_MS;
        assert!(!matches!(a.s.next_tx(now), TxUnit::Voice));
        assert!(a.s.voice.is_none());
        // ... and neither the peer nor the local user can open a second one.
        for k in 0..20 {
            a.s.on_peer_voice(true, false, now + k);
        }
        assert!(a.s.voice.is_none() && a.s.voice_peer_req_ms.is_none());
        assert_eq!(a.s.voice_window(true), Err(ChatError::InvalidState));
        for k in 1..40 {
            assert!(!matches!(a.s.next_tx(now + k * 160), TxUnit::Voice));
        }
        // A peer that reports "opened and closed" spends the window for a side that only asked.
        b.s.voice_window(true).unwrap();
        b.s.on_peer_voice(false, true, now);
        assert!(b.s.voice.is_none() && b.s.voice_used && !b.s.voice_local_req);
        assert_eq!(b.s.voice_window(true), Err(ChatError::InvalidState));
        assert!(a.s.abort_reason().is_none() && b.s.abort_reason().is_none());
    }

    #[test]
    fn unmatched_local_voice_request_expires_without_spending_the_window() {
        let (mut a, _b, now) = established(false);
        a.s.poll_events();
        a.s.last_now = now;
        a.s.voice_window(true).unwrap();
        // Just before the limit the request still stands.
        assert!(!matches!(a.s.next_tx(now + VOICE_REQUEST_TTL_MS - 160), TxUnit::Voice));
        assert!(a.s.voice_local_req);
        // At the limit it is withdrawn and reported; the peer agreeing afterwards opens nothing.
        let late = now + VOICE_REQUEST_TTL_MS;
        assert!(!matches!(a.s.next_tx(late), TxUnit::Voice));
        assert!(!a.s.voice_local_req && !a.s.voice_used);
        let evs = a.s.poll_events();
        assert_eq!(evs.iter().filter(|e| matches!(e, SessionEvent::VoiceWindow { open: false })).count(), 1);
        a.s.on_peer_voice(true, false, late + 160);
        assert!(a.s.voice.is_none());
        assert!(!matches!(a.s.next_tx(late + 320), TxUnit::Voice));
        assert!(!a.s.poll_events().iter().any(|e| matches!(e, SessionEvent::VoiceWindow { open: true })));
        // Expiry is also applied when the late agreement is the first thing to arrive.
        let (mut c, _d, now) = established(false);
        c.s.last_now = now;
        c.s.voice_window(true).unwrap();
        c.s.on_peer_voice(true, false, now + VOICE_REQUEST_TTL_MS + 1);
        assert!(c.s.voice.is_none() && !c.s.voice_used && !c.s.voice_local_req);
        // The one window is still available: with the peer's request fresh, asking again opens it.
        c.s.last_now = now + VOICE_REQUEST_TTL_MS + 2_000;
        c.s.voice_window(true).unwrap();
        assert!(c.s.voice.is_some() && c.s.voice_used);
    }
}
