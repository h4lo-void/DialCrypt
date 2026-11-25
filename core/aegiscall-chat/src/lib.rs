//! DialCrypt text engine for the secure call session (secure-session-v2 §6.3, §6.4).
//!
//! - Superframes are sealed by [EpochCipher]; one epoch e is shared by both directions.
//! - Message keys are Expand(msg_base_{e,dir}, msg_id); the 6-bit epoch travels in every shard.
//!   The receiver keeps the current and previous epoch; the sender aborts a message that is
//!   still unfinished when its epoch falls more than one behind.
//! - Only the initiator starts a DH ratchet step (every RATCHET_INTERVAL_FRAMES slots, on
//!   request, or flagged with the background ML-KEM secret); the responder may ask with
//!   DH_RATCHET_REQ.
//! - Selective-repeat ARQ with bounded outgoing queue, reassembly table, completed / aborted id
//!   sets and per-shard retransmission budget. Plaintext buffers are zeroized on every path.
//! - Presence, viewed receipts, transfer abort and dual-end panic wipe (the wipe is sent at
//!   least [WIPE_FRAMES] times before the engine reports it flushed).
//!
//! Every `now_ms` argument must be milliseconds from a monotonic clock (never wall-clock time).

#![forbid(unsafe_code)]

pub mod call_session;
pub mod hs_link;

pub use aegiscall_mux::ctrl;
pub use aegiscall_crypto::CallSide;
pub use call_session::{AbortReason, SecureCallSession, SessionEvent, TxUnit};
pub use hs_link::{HsLink, HsLinkError};

use aegiscall_crypto::epoch_cipher::{EPOCH_PAYLOAD_LEN, EPOCH_SUPERFRAME_LEN, MSG_EPOCH_MASK};
use aegiscall_crypto::{
    DhRatchet, EpochCipher, EpochError, PqSecret, RatchetAction, RatchetAssembler, RatchetError, Role,
    MUX_PAYLOAD_LEN, RATCHET_FLAG_PQ,
};
use aegiscall_memsec::{
    DeliveryReceiptState, EphemeralChatVault, EphemeralMediaKind, MessageDirection, SecretKey32,
};
use aegiscall_mux::{FrameKind, MuxFrame, MuxScheduler, MUX_BODY_LEN};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand_core::{OsRng, RngCore};
use std::collections::{HashMap, VecDeque};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const _: () = assert!(MUX_PAYLOAD_LEN == EPOCH_PAYLOAD_LEN);

pub const SUPERFRAME_LEN: usize = EPOCH_SUPERFRAME_LEN;
pub const CHAT_SHARD_DATA_LEN: usize = 10; // 13B mux body = 2B msg_id + 1B shard_idx + 10B data
pub const PAD_BUCKET: usize = 32; // Pad inner envelopes to multiples of 32 bytes
pub const MAX_SHARDS: usize = 250;
/// Messages waiting for delivery; further sends fail with [ChatError::QueueFull].
pub const MAX_OUTGOING_MESSAGES: usize = 16;
/// Concurrent incomplete incoming messages; shards of further messages are dropped.
pub const MAX_INCOMING_REASSEMBLY: usize = 16;
/// Transmissions per shard before the whole message is aborted.
pub const MAX_SHARD_TRANSMISSIONS: u8 = 16;
pub const DEFAULT_RETRANSMIT_TICKS: u64 = 12;
/// An outgoing message not delivered within this time is aborted.
pub const OUTGOING_TIMEOUT_MS: u64 = 180_000;
/// An incomplete incoming message without a new shard for this long is discarded.
pub const INCOMING_TIMEOUT_MS: u64 = 120_000;
pub const ID_SET_CAP: usize = 256;
pub const ID_SET_TTL_MS: u64 = 600_000;
/// The initiator resends an unanswered DH_RATCHET after this many slots.
pub const RATCHET_RESEND_FRAMES: u64 = 32;
pub const WIPE_FRAMES: u8 = 3;
const ACK_EVERY_SHARDS: usize = 4;
const FRAME_HDR_LEN: usize = 3;
const NONCE_TAIL_LEN: usize = 21;
const AEAD_TAG_LEN: usize = 16;
const MIN_BLOB_LEN: usize = NONCE_TAIL_LEN + PAD_BUCKET + AEAD_TAG_LEN;
const EVENT_CAP: usize = 1024;
const CONTENT_TEXT: u8 = 0x00;
const DIR_I2R: u8 = 0xA1;
const DIR_R2I: u8 = 0xB2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PeerPresenceState {
    Idle = 0,
    TypingText = 1,
}

impl PeerPresenceState {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => PeerPresenceState::TypingText,
            _ => PeerPresenceState::Idle,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TacticalQuickCode {
    SafeArrival,
    UnderSurveillanceSwitchPlan,
    BusyHoldSilent,
    RequestImmediateRekey,
    OfflineGpsPin { lat_e6: i32, lon_e6: i32 },
}

impl TacticalQuickCode {
    pub fn to_tactical_text(self) -> String {
        match self {
            TacticalQuickCode::SafeArrival => "[Quick code] Arrived safely at the planned point".to_string(),
            TacticalQuickCode::UnderSurveillanceSwitchPlan => {
                "[Quick code] Suspected surveillance, switch to the backup plan now".to_string()
            }
            TacticalQuickCode::BusyHoldSilent => "[Quick code] Cannot reply now, staying silent on standby".to_string(),
            TacticalQuickCode::RequestImmediateRekey => {
                "[Quick code] Both sides rotate the session key now".to_string()
            }
            TacticalQuickCode::OfflineGpsPin { lat_e6, lon_e6 } => {
                let lat = lat_e6 as f64 / 1_000_000.0;
                let lon = lon_e6 as f64 / 1_000_000.0;
                format!("[Offline location] {:.6}, {:.6}", lat, lon)
            }
        }
    }
}

/// Failures are codes ([ChatError::code]); the Display strings are for developers only.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ChatError {
    #[error("message too large")]
    MessageTooLarge,
    #[error("inner message authentication failed")]
    InnerAuthFailed,
    #[error("corrupt envelope")]
    CorruptEnvelope,
    #[error("outgoing queue full")]
    QueueFull,
    #[error("sending locked until both sides confirm the SAS")]
    SendLocked,
    #[error("session not established")]
    NotEstablished,
    #[error("session closed")]
    SessionClosed,
    #[error("call not valid in the current state")]
    InvalidState,
    #[error("superframe rejected")]
    FrameRejected,
    #[error("epoch cipher failure")]
    Epoch(EpochError),
    #[error("ratchet failure")]
    Ratchet(RatchetError),
    #[error("vault failure")]
    Vault,
}

impl ChatError {
    pub fn code(&self) -> u8 {
        match self {
            ChatError::MessageTooLarge => 1,
            ChatError::InnerAuthFailed => 2,
            ChatError::CorruptEnvelope => 3,
            ChatError::QueueFull => 4,
            ChatError::SendLocked => 5,
            ChatError::NotEstablished => 6,
            ChatError::SessionClosed => 7,
            ChatError::InvalidState => 8,
            ChatError::FrameRejected => 9,
            ChatError::Epoch(_) => 10,
            ChatError::Ratchet(_) => 11,
            ChatError::Vault => 12,
        }
    }
}

/// Engine notifications, drained with [ChatSessionEngine::take_events].
pub enum EngineEvent {
    /// TX switched to this epoch.
    EpochAdvanced(u32),
    /// A PQ-flagged ratchet step produced epoch; resume_next = Expand(root_e, "resume next pq" || e).
    PqMixed { epoch: u32, resume_next: SecretKey32 },
    MessageReceived(u16),
    MessageDelivered(u16),
    /// Partial delivery progress of an outgoing message: `acked` of `total` shards confirmed by
    /// the peer. Emitted only when `acked` grows; the final shard is reported as MessageDelivered.
    MessageProgress { msg_id: u16, acked: u16, total: u16 },
    /// An outgoing message was aborted (retransmission budget, timeout or stale epoch).
    MessageFailed(u16),
    RemoteWipe,
}

impl core::fmt::Debug for EngineEvent {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            EngineEvent::EpochAdvanced(e) => write!(f, "EpochAdvanced({e})"),
            EngineEvent::PqMixed { epoch, .. } => write!(f, "PqMixed({epoch})"),
            EngineEvent::MessageReceived(id) => write!(f, "MessageReceived({id})"),
            EngineEvent::MessageDelivered(id) => write!(f, "MessageDelivered({id})"),
            EngineEvent::MessageProgress { msg_id, acked, total } => {
                write!(f, "MessageProgress({msg_id}, {acked}/{total})")
            }
            EngineEvent::MessageFailed(id) => write!(f, "MessageFailed({id})"),
            EngineEvent::RemoteWipe => write!(f, "RemoteWipe"),
        }
    }
}

/// Result of a successfully opened superframe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RxOutcome {
    Consumed,
    /// A session-level control frame (handled by [SecureCallSession]).
    Session { subtype: u8, body: [u8; MUX_BODY_LEN] },
}

struct OutgoingPending {
    msg_id: u16,
    epoch: u32,
    shards: Vec<[u8; CHAT_SHARD_DATA_LEN]>,
    acked: Vec<bool>,
    tx_count: Vec<u8>,
    last_tx: Vec<Option<u64>>,
    created_ms: u64,
    /// Acked shard count last reported through MessageProgress (0 = nothing reported yet).
    last_progress_acked: usize,
}

struct IncomingReassembly {
    epoch6: u8,
    total: Option<usize>,
    blob_len: usize,
    shards: Vec<Option<[u8; CHAT_SHARD_DATA_LEN]>>,
    have: usize,
    since_ack: usize,
    last_ms: u64,
}

impl IncomingReassembly {
    fn bitmap(&self, base: usize) -> u64 {
        let mut bm = 0u64;
        for bit in 0..64 {
            if self.shards.get(base + bit).is_some_and(|s| s.is_some()) {
                bm |= 1u64 << bit;
            }
        }
        bm
    }
}

/// Insertion-ordered id set with a size cap and a time-to-live (monotonic ms).
struct BoundedIdSet {
    entries: VecDeque<(u16, u64)>,
    cap: usize,
    ttl_ms: u64,
}

impl BoundedIdSet {
    fn new(cap: usize, ttl_ms: u64) -> Self {
        Self { entries: VecDeque::new(), cap, ttl_ms }
    }

    fn prune(&mut self, now_ms: u64) {
        while let Some(&(_, t)) = self.entries.front() {
            if now_ms.saturating_sub(t) > self.ttl_ms {
                self.entries.pop_front();
            } else {
                break;
            }
        }
    }

    fn contains(&mut self, id: u16, now_ms: u64) -> bool {
        self.prune(now_ms);
        self.entries.iter().any(|(i, _)| *i == id)
    }

    fn insert(&mut self, id: u16, now_ms: u64) {
        self.prune(now_ms);
        self.entries.retain(|(i, _)| *i != id);
        self.entries.push_back((id, now_ms));
        while self.entries.len() > self.cap {
            self.entries.pop_front();
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }
}

enum ShardStep {
    Drop,
    Reject,
    Ack(usize),
    Complete,
}

fn id_range(role: Role) -> (u16, u16) {
    match role {
        Role::Initiator => (1, 0x7FFF),
        Role::Responder => (0x8000, 0xFFFF),
    }
}

fn dir_byte(role: Role) -> u8 {
    match role {
        Role::Initiator => DIR_I2R,
        Role::Responder => DIR_R2I,
    }
}

fn msg_aad(dir: u8, epoch: u32, msg_id: u16) -> [u8; 16] {
    let mut aad = [0u8; 16];
    aad[..9].copy_from_slice(b"AegisMsg2");
    aad[9] = dir;
    aad[10..14].copy_from_slice(&epoch.to_be_bytes());
    aad[14..16].copy_from_slice(&msg_id.to_be_bytes());
    aad
}

fn epoch6(e: u32) -> u8 {
    (e as u8) & MSG_EPOCH_MASK
}

fn ctrl_frame(subtype: u8, body: [u8; MUX_BODY_LEN]) -> MuxFrame {
    MuxFrame::new(FrameKind::CtrlAck, subtype, body)
}

pub struct ChatSessionEngine {
    role: Role,
    id_lo: u16,
    id_hi: u16,
    peer_lo: u16,
    peer_hi: u16,
    next_msg_id: u16,
    tick_counter: u64,
    retransmit_ticks: u64,
    outgoing: VecDeque<OutgoingPending>,
    incoming: HashMap<u16, IncomingReassembly>,
    completed_rx_ids: BoundedIdSet,
    aborted_rx_ids: BoundedIdSet,
    peer_presence: PeerPresenceState,
    ratchet: DhRatchet,
    ratchet_asm: RatchetAssembler,
    ratchet_ack_asm: RatchetAssembler,
    ratchet_last_tx: Option<u64>,
    ratchet_flags: u8,
    /// Epoch of a PQ-flagged step whose PqMixed event waits until both sides are in it.
    pq_mixed_epoch: Option<u32>,
    tx_locked: bool,
    wipe_left: u8,
    wipe_requested: bool,
    wipe_body: [u8; MUX_BODY_LEN],
    events: VecDeque<EngineEvent>,
    cipher: EpochCipher,
    pub vault: EphemeralChatVault,
    pub mux: MuxScheduler,
    pub remote_wipe_triggered: bool,
}

impl ChatSessionEngine {
    /// Builds the engine from the handshake output (root_0, role, transcript tag, chaff seed).
    pub fn new(role: Role, root0: &SecretKey32, transcript_tag: [u8; 4], chaff_seed: SecretKey32) -> Self {
        let peer_role = match role {
            Role::Initiator => Role::Responder,
            Role::Responder => Role::Initiator,
        };
        let (id_lo, id_hi) = id_range(role);
        let (peer_lo, peer_hi) = id_range(peer_role);
        Self {
            role,
            id_lo,
            id_hi,
            peer_lo,
            peer_hi,
            next_msg_id: id_lo,
            tick_counter: 0,
            retransmit_ticks: DEFAULT_RETRANSMIT_TICKS,
            outgoing: VecDeque::new(),
            incoming: HashMap::new(),
            completed_rx_ids: BoundedIdSet::new(ID_SET_CAP, ID_SET_TTL_MS),
            aborted_rx_ids: BoundedIdSet::new(ID_SET_CAP, ID_SET_TTL_MS),
            peer_presence: PeerPresenceState::Idle,
            ratchet: DhRatchet::new(root0.clone(), role),
            ratchet_asm: RatchetAssembler::default(),
            ratchet_ack_asm: RatchetAssembler::default(),
            ratchet_last_tx: None,
            ratchet_flags: 0,
            pq_mixed_epoch: None,
            tx_locked: false,
            wipe_left: 0,
            wipe_requested: false,
            wipe_body: [0u8; MUX_BODY_LEN],
            events: VecDeque::new(),
            cipher: EpochCipher::from_root(root0, role, transcript_tag),
            vault: EphemeralChatVault::new(),
            mux: MuxScheduler::new(chaff_seed),
            remote_wipe_triggered: false,
        }
    }

    pub fn role(&self) -> Role {
        self.role
    }

    pub fn tx_epoch(&self) -> u32 {
        self.cipher.tx_epoch()
    }

    pub fn rx_epoch(&self) -> u32 {
        self.cipher.rx_epoch()
    }

    /// Superframe slots produced so far.
    pub fn frames_sent(&self) -> u64 {
        self.tick_counter
    }

    pub fn set_retransmit_ticks(&mut self, ticks: u64) {
        self.retransmit_ticks = ticks.max(1);
    }

    /// While locked, sending user messages fails with [ChatError::SendLocked].
    pub fn set_tx_locked(&mut self, locked: bool) {
        // Also gates reception: while locked, incoming chat shards are dropped unacknowledged.
        self.tx_locked = locked;
    }

    pub fn is_tx_locked(&self) -> bool {
        self.tx_locked
    }

    pub fn outgoing_len(&self) -> usize {
        self.outgoing.len()
    }

    pub fn incoming_len(&self) -> usize {
        self.incoming.len()
    }

    pub fn take_events(&mut self) -> Vec<EngineEvent> {
        self.events.drain(..).collect()
    }

    fn push_event(&mut self, ev: EngineEvent) {
        if self.events.len() >= EVENT_CAP {
            self.events.pop_front();
        }
        self.events.push_back(ev);
    }

    pub fn peer_presence(&self) -> PeerPresenceState {
        self.peer_presence
    }

    /// Queues a control frame (false when the control queue is full).
    pub fn enqueue_ctrl(&mut self, subtype: u8, body: [u8; MUX_BODY_LEN]) -> bool {
        self.mux.enqueue_ctrl(ctrl_frame(subtype, body))
    }

    /// Hands the background ML-KEM secret to the ratchet; the initiator starts a PQ-flagged step.
    pub fn set_pq_secret(&mut self, pq: PqSecret) {
        self.ratchet.set_pq_secret(pq);
        if self.role == Role::Initiator {
            self.ratchet.request();
        }
    }

    /// Initiator: ratchet now. Responder: ask the initiator with DH_RATCHET_REQ.
    pub fn request_ratchet(&mut self) {
        match self.role {
            Role::Initiator => self.ratchet.request(),
            Role::Responder => {
                self.mux.enqueue_ctrl(ctrl_frame(ctrl::DH_RATCHET_REQ, [0u8; MUX_BODY_LEN]));
            }
        }
    }

    /// Not sent while sending is locked (changed key, SAS not yet re-confirmed) or during a wipe.
    pub fn send_presence_state(&mut self, state: PeerPresenceState) {
        if self.tx_locked || self.wipe_requested {
            return;
        }
        let mut body = [0u8; MUX_BODY_LEN];
        body[0] = state as u8;
        body[1..9].copy_from_slice(b"PRESENCE");
        self.mux.enqueue_ctrl(ctrl_frame(ctrl::PRESENCE, body));
    }

    /// Sends a "Viewed by Peer" receipt once the user unblurs a message. Not sent while sending
    /// is locked (changed key, SAS not yet re-confirmed) or during a wipe.
    pub fn send_viewed_receipt(&mut self, msg_id: u16) {
        if self.tx_locked || self.wipe_requested {
            return;
        }
        let mut body = [0u8; MUX_BODY_LEN];
        body[0..2].copy_from_slice(&msg_id.to_be_bytes());
        body[2..10].copy_from_slice(b"VIEWED!!");
        let frame = ctrl_frame(ctrl::VIEWED_RECEIPT, body);
        self.mux.enqueue_ctrl(frame.clone());
        self.mux.enqueue_ctrl(frame);
    }

    fn send_abort_transfer(&mut self, msg_id: u16) {
        let mut body = [0u8; MUX_BODY_LEN];
        body[0..2].copy_from_slice(&msg_id.to_be_bytes());
        body[2..9].copy_from_slice(b"ABORT!!");
        let frame = ctrl_frame(ctrl::ABORT_TRANSFER, body);
        self.mux.enqueue_ctrl_urgent(frame.clone());
        self.mux.enqueue_ctrl_urgent(frame);
    }

    /// Cancels an outgoing transfer so urgent texts never stall behind it.
    pub fn abort_outgoing_transfer(&mut self, msg_id: u16) -> bool {
        let Some(pos) = self.outgoing.iter().position(|o| o.msg_id == msg_id) else {
            return false;
        };
        self.outgoing.remove(pos);
        self.mux.remove_chat_shards_for_msg(msg_id);
        self.vault.mark_aborted(u32::from(msg_id));
        self.send_abort_transfer(msg_id);
        true
    }

    fn fail_outgoing(&mut self, msg_id: u16) {
        if self.abort_outgoing_transfer(msg_id) {
            self.push_event(EngineEvent::MessageFailed(msg_id));
        }
    }

    pub fn incoming_transfer_progress(&self, msg_id: u16) -> Option<(usize, usize)> {
        let entry = self.incoming.get(&msg_id)?;
        Some((entry.have, entry.total?))
    }

    pub fn send_tactical_quick_code(&mut self, now_ms: u64, code: TacticalQuickCode) -> Result<u16, ChatError> {
        if code == TacticalQuickCode::RequestImmediateRekey {
            self.request_ratchet();
        }
        let text = code.to_tactical_text();
        self.send_text_message(now_ms, 0, &text)
    }

    pub fn send_text_message(&mut self, now_ms: u64, burn_ttl_secs: u16, plaintext: &str) -> Result<u16, ChatError> {
        self.send_typed_payload(now_ms, burn_ttl_secs, CONTENT_TEXT, EphemeralMediaKind::Text, plaintext.as_bytes())
    }

    fn alloc_msg_id(&mut self) -> u16 {
        for _ in 0..=MAX_OUTGOING_MESSAGES {
            let id = self.next_msg_id;
            self.next_msg_id = if id >= self.id_hi { self.id_lo } else { id + 1 };
            if !self.outgoing.iter().any(|o| o.msg_id == id) {
                return id;
            }
        }
        self.next_msg_id
    }

    fn send_typed_payload(
        &mut self,
        now_ms: u64,
        burn_ttl_secs: u16,
        content_tag: u8,
        media_kind: EphemeralMediaKind,
        raw_bytes: &[u8],
    ) -> Result<u16, ChatError> {
        if self.wipe_requested {
            return Err(ChatError::SessionClosed);
        }
        if self.tx_locked {
            return Err(ChatError::SendLocked);
        }
        self.expire_outgoing(now_ms);
        if self.outgoing.len() >= MAX_OUTGOING_MESSAGES {
            return Err(ChatError::QueueFull);
        }
        let body_len = u16::try_from(raw_bytes.len()).map_err(|_| ChatError::MessageTooLarge)?;
        let padded_len = (6 + raw_bytes.len()).div_ceil(PAD_BUCKET) * PAD_BUCKET;
        let blob_len = NONCE_TAIL_LEN + padded_len + AEAD_TAG_LEN;
        let total_shards = (FRAME_HDR_LEN + blob_len).div_ceil(CHAT_SHARD_DATA_LEN);
        if total_shards > MAX_SHARDS {
            return Err(ChatError::MessageTooLarge);
        }

        let mut inner = Zeroizing::new(vec![0u8; padded_len]);
        inner[0..2].copy_from_slice(&burn_ttl_secs.to_be_bytes());
        inner[2] = content_tag;
        // Byte 3 is reserved: always 0 on send, any other value is rejected on receive.
        inner[3] = 0;
        inner[4..6].copy_from_slice(&body_len.to_be_bytes());
        inner[6..6 + raw_bytes.len()].copy_from_slice(raw_bytes);

        let msg_id = self.alloc_msg_id();
        let epoch = self.cipher.tx_epoch();
        let msg_key = self.cipher.tx_message_key(epoch, u32::from(msg_id)).map_err(ChatError::Epoch)?;
        let dir = dir_byte(self.role);
        let mut nonce = [0u8; 24];
        nonce[0] = dir;
        nonce[1..3].copy_from_slice(&msg_id.to_be_bytes());
        OsRng.fill_bytes(&mut nonce[3..]);
        let aad = msg_aad(dir, epoch, msg_id);
        let aead = XChaCha20Poly1305::new(msg_key.as_bytes().into());
        drop(msg_key);
        self.cipher.retire_tx_message_key(epoch, u32::from(msg_id));
        let ct = aead
            .encrypt(XNonce::from_slice(&nonce), Payload { msg: inner.as_slice(), aad: &aad })
            .map_err(|_| ChatError::InnerAuthFailed)?;
        drop(inner);

        let mut framed = Vec::with_capacity(total_shards * CHAT_SHARD_DATA_LEN);
        framed.push(total_shards as u8);
        framed.extend_from_slice(&(blob_len as u16).to_be_bytes());
        framed.extend_from_slice(&nonce[3..]);
        framed.extend_from_slice(&ct);
        framed.resize(total_shards * CHAT_SHARD_DATA_LEN, 0);

        self.vault
            .push_binary_payload(
                u32::from(msg_id),
                MessageDirection::Outgoing,
                now_ms,
                burn_ttl_secs,
                media_kind,
                raw_bytes,
            )
            .map_err(|_| ChatError::Vault)?;

        let shards: Vec<[u8; CHAT_SHARD_DATA_LEN]> = framed
            .chunks_exact(CHAT_SHARD_DATA_LEN)
            .map(|c| {
                let mut a = [0u8; CHAT_SHARD_DATA_LEN];
                a.copy_from_slice(c);
                a
            })
            .collect();
        let n = shards.len();
        self.outgoing.push_back(OutgoingPending {
            msg_id,
            epoch,
            shards,
            acked: vec![false; n],
            tx_count: vec![0; n],
            last_tx: vec![None; n],
            created_ms: now_ms,
            last_progress_acked: 0,
        });
        self.vault.update_progress(u32::from(msg_id), 0, n as u16);
        Ok(msg_id)
    }

    fn encode_chat_shard_frame(epoch6: u8, msg_id: u16, shard_idx: u8, chunk: &[u8; CHAT_SHARD_DATA_LEN]) -> MuxFrame {
        let mut body = [0u8; MUX_BODY_LEN];
        body[0..2].copy_from_slice(&msg_id.to_be_bytes());
        body[2] = shard_idx;
        body[3..13].copy_from_slice(chunk);
        MuxFrame::new(FrameKind::ChatData, epoch6 & MSG_EPOCH_MASK, body)
    }

    fn queue_arq_ack(&mut self, msg_id: u16, base: u8, bitmap: u64, complete: bool) {
        let id = msg_id.to_be_bytes();
        self.mux
            .remove_ctrl_where(|f| f.is_ctrl(ctrl::ARQ_BITMAP) && f.body[0] == id[0] && f.body[1] == id[1]);
        let mut body = [0u8; MUX_BODY_LEN];
        body[0..2].copy_from_slice(&id);
        body[2] = base;
        body[3..11].copy_from_slice(&bitmap.to_be_bytes());
        body[11] = u8::from(complete);
        self.mux.enqueue_ctrl(ctrl_frame(ctrl::ARQ_BITMAP, body));
    }

    /// Wipes local chat state (vault, queues, transfers) without notifying the peer.
    pub fn wipe_local(&mut self) {
        self.mux.clear_queues();
        self.outgoing.clear();
        self.incoming.clear();
        self.vault.panic_wipe();
    }

    /// Wipes locally, then sends PANIC_WIPE in the next [WIPE_FRAMES] slots.
    pub fn trigger_dual_end_panic_wipe(&mut self) {
        self.wipe_local();
        let mut body = [0u8; MUX_BODY_LEN];
        OsRng.fill_bytes(&mut body[..8]);
        body[8..13].copy_from_slice(b"WIPE!");
        self.wipe_body = body;
        self.wipe_left = WIPE_FRAMES;
        self.wipe_requested = true;
    }

    /// True once every PANIC_WIPE frame has been handed to the modem.
    pub fn wipe_flushed(&self) -> bool {
        self.wipe_requested && self.wipe_left == 0
    }

    /// Seals one mux frame immediately (bypassing the queues).
    pub fn seal_frame(&mut self, frame: &MuxFrame) -> Result<[u8; SUPERFRAME_LEN], ChatError> {
        let mut pt = frame.encode();
        let r = self.cipher.seal_superframe(&pt).map_err(ChatError::Epoch);
        pt.zeroize();
        r
    }

    pub fn next_tx_wire_superframe(&mut self, now_ms: u64) -> Result<[u8; SUPERFRAME_LEN], ChatError> {
        self.next_tx_with_filler(now_ms, &mut || None)
    }

    /// Produces the next superframe. filler supplies a BULK frame for slots that would
    /// otherwise carry chaff (priority control > chat > BULK > chaff).
    pub fn next_tx_with_filler(
        &mut self,
        now_ms: u64,
        filler: &mut dyn FnMut() -> Option<MuxFrame>,
    ) -> Result<[u8; SUPERFRAME_LEN], ChatError> {
        self.tick_counter += 1;
        if self.wipe_left > 0 {
            self.wipe_left -= 1;
            let frame = ctrl_frame(ctrl::PANIC_WIPE, self.wipe_body);
            return self.seal_frame(&frame);
        }
        self.ratchet_tick()?;
        self.schedule_chat(now_ms);
        if !self.mux.has_pending_ctrl_or_chat() {
            if let Some(f) = filler() {
                self.mux.enqueue_bulk(f);
            }
        }
        let frame = self.mux.pop_next_frame();
        self.seal_frame(&frame)
    }

    fn ratchet_tick(&mut self) -> Result<(), ChatError> {
        let due = self.ratchet.tick().map_err(ChatError::Ratchet)?;
        if !due || self.role != Role::Initiator {
            return Ok(());
        }
        let fresh = !self.ratchet.is_pending();
        let resend = self
            .ratchet_last_tx
            .is_none_or(|t| self.tick_counter.saturating_sub(t) >= RATCHET_RESEND_FRAMES);
        if fresh || resend {
            let msg = self.ratchet.begin(&mut OsRng).map_err(ChatError::Ratchet)?;
            self.ratchet_flags = msg.flags;
            self.ratchet_last_tx = Some(self.tick_counter);
            for frag in msg.to_fragments() {
                self.mux.enqueue_ctrl(ctrl_frame(ctrl::DH_RATCHET, frag));
            }
        }
        Ok(())
    }

    fn expire_outgoing(&mut self, now_ms: u64) {
        let tx_e = self.cipher.tx_epoch();
        let stale: Vec<u16> = self
            .outgoing
            .iter()
            .filter(|o| now_ms.saturating_sub(o.created_ms) > OUTGOING_TIMEOUT_MS || tx_e > o.epoch.saturating_add(1))
            .map(|o| o.msg_id)
            .collect();
        for id in stale {
            self.fail_outgoing(id);
        }
    }

    fn schedule_chat(&mut self, now_ms: u64) {
        self.expire_outgoing(now_ms);
        if self.mux.has_pending_ctrl_or_chat() {
            return;
        }
        let tick = self.tick_counter;
        let gap = self.retransmit_ticks;
        let mut exhausted = None;
        let mut frame = None;
        for o in self.outgoing.iter_mut() {
            let n = o.shards.len();
            let unacked = |i: usize| !o.acked.get(i).copied().unwrap_or(true);
            let fresh = (0..n).find(|&i| unacked(i) && o.last_tx.get(i).is_some_and(|l| l.is_none()));
            let pick = fresh.or_else(|| {
                (0..n).find(|&i| unacked(i) && o.last_tx.get(i).copied().flatten().is_some_and(|t| tick.saturating_sub(t) >= gap))
            });
            let Some(i) = pick else { continue };
            let count = o.tx_count.get(i).copied().unwrap_or(MAX_SHARD_TRANSMISSIONS);
            if count >= MAX_SHARD_TRANSMISSIONS {
                exhausted = Some(o.msg_id);
                break;
            }
            if let Some(c) = o.tx_count.get_mut(i) {
                *c += 1;
            }
            if let Some(l) = o.last_tx.get_mut(i) {
                *l = Some(tick);
            }
            if let Some(chunk) = o.shards.get(i) {
                frame = Some(Self::encode_chat_shard_frame(epoch6(o.epoch), o.msg_id, i as u8, chunk));
            }
            break;
        }
        if let Some(id) = exhausted {
            self.fail_outgoing(id);
        }
        if let Some(f) = frame {
            self.mux.enqueue_chat(f);
        }
    }

    /// Opens a superframe. AEAD failures and replays return [ChatError::FrameRejected]
    /// (the caller may then try it as a handshake frame); other errors are fatal.
    pub fn process_rx_wire_superframe(&mut self, wire: &[u8; SUPERFRAME_LEN], now_ms: u64) -> Result<RxOutcome, ChatError> {
        let before = self.cipher.tx_epoch();
        let opened = match self.cipher.open_superframe(wire) {
            Ok(o) => o,
            Err(EpochError::AuthenticationFailed) => {
                if self.cipher.take_rekey_signal() {
                    match self.role {
                        Role::Initiator => self.ratchet.request(),
                        Role::Responder => {
                            let mut body = [0u8; MUX_BODY_LEN];
                            body[0] = 1;
                            body[1..5].copy_from_slice(&self.cipher.rx_epoch().to_be_bytes());
                            self.mux.enqueue_ctrl(ctrl_frame(ctrl::DH_RATCHET_REQ, body));
                        }
                    }
                }
                return Err(ChatError::FrameRejected);
            }
            Err(EpochError::ReplayDetected) => return Err(ChatError::FrameRejected),
            Err(other) => return Err(ChatError::Epoch(other)),
        };
        let after = self.cipher.tx_epoch();
        if after != before {
            self.push_event(EngineEvent::EpochAdvanced(after));
        }
        // The ratchet learns about the peer's epoch before any control frame in this superframe
        // is handled: the responder commits here, the initiator sees the responder arrive.
        if self.ratchet.note_valid_frame(opened.epoch) && self.pq_mixed_epoch == Some(opened.epoch) {
            self.pq_mixed_epoch = None;
            let resume_next = self.ratchet.resume_next_pq().map_err(ChatError::Ratchet)?;
            self.push_event(EngineEvent::PqMixed { epoch: opened.epoch, resume_next });
        }
        let mut pt = opened.plaintext;
        let frame = MuxFrame::decode(&pt);
        pt.zeroize();
        match frame.kind {
            FrameKind::Chaff | FrameKind::VoiceReserved => Ok(RxOutcome::Consumed),
            FrameKind::ChatData => {
                self.handle_incoming_chat_shard(frame.subflags, &frame.body, now_ms);
                Ok(RxOutcome::Consumed)
            }
            FrameKind::CtrlAck => self.handle_incoming_ctrl(frame.subflags, &frame.body, now_ms),
        }
    }

    fn handle_incoming_ctrl(&mut self, subtype: u8, body: &[u8; MUX_BODY_LEN], now_ms: u64) -> Result<RxOutcome, ChatError> {
        match subtype {
            ctrl::PANIC_WIPE => {
                if &body[8..13] == b"WIPE!" && !self.remote_wipe_triggered {
                    self.wipe_local();
                    self.remote_wipe_triggered = true;
                    self.push_event(EngineEvent::RemoteWipe);
                }
            }
            ctrl::PRESENCE => {
                if &body[1..9] == b"PRESENCE" {
                    self.peer_presence = PeerPresenceState::from_u8(body[0]);
                }
            }
            ctrl::VIEWED_RECEIPT => {
                if &body[2..10] == b"VIEWED!!" {
                    let msg_id = u16::from_be_bytes([body[0], body[1]]);
                    self.vault.mark_viewed(u32::from(msg_id));
                }
            }
            ctrl::ABORT_TRANSFER => {
                if &body[2..9] == b"ABORT!!" {
                    let msg_id = u16::from_be_bytes([body[0], body[1]]);
                    self.incoming.remove(&msg_id);
                    self.aborted_rx_ids.insert(msg_id, now_ms);
                }
            }
            ctrl::ARQ_BITMAP => self.handle_arq(body),
            ctrl::DH_RATCHET => self.on_ratchet_fragment(body)?,
            ctrl::DH_RATCHET_ACK => self.on_ratchet_ack_fragment(body)?,
            ctrl::DH_RATCHET_REQ => {
                if self.role == Role::Initiator {
                    if body[0] == 1 {
                        let req_epoch = u32::from_be_bytes([body[1], body[2], body[3], body[4]]);
                        if self.cipher.tx_epoch() <= req_epoch && !self.ratchet.is_pending() {
                            self.ratchet.request();
                        }
                    } else {
                        self.ratchet.request();
                    }
                }
            }
            ctrl::PING_KEEPALIVE => {}
            other => return Ok(RxOutcome::Session { subtype: other, body: *body }),
        }
        Ok(RxOutcome::Consumed)
    }

    fn on_ratchet_fragment(&mut self, body: &[u8; MUX_BODY_LEN]) -> Result<(), ChatError> {
        if self.role != Role::Responder {
            return Err(ChatError::Ratchet(RatchetError::WrongRole));
        }
        let Some(msg) = self.ratchet_asm.push(body).map_err(ChatError::Ratchet)? else {
            return Ok(());
        };
        match self.ratchet.on_ratchet(&msg, &mut OsRng).map_err(ChatError::Ratchet)? {
            RatchetAction::Ignore => {}
            RatchetAction::ResendAck(ack) => {
                for frag in ack.to_fragments() {
                    self.mux.enqueue_ctrl(ctrl_frame(ctrl::DH_RATCHET_ACK, frag));
                }
            }
            RatchetAction::Staged { ack, root, epoch } => {
                self.cipher.stage_rx_epoch(&root, epoch).map_err(ChatError::Epoch)?;
                drop(root);
                for frag in ack.to_fragments() {
                    self.mux.enqueue_ctrl(ctrl_frame(ctrl::DH_RATCHET_ACK, frag));
                }
                if msg.flags & RATCHET_FLAG_PQ != 0 {
                    self.pq_mixed_epoch = Some(epoch);
                }
            }
        }
        Ok(())
    }

    fn on_ratchet_ack_fragment(&mut self, body: &[u8; MUX_BODY_LEN]) -> Result<(), ChatError> {
        if self.role != Role::Initiator {
            return Err(ChatError::Ratchet(RatchetError::WrongRole));
        }
        let Some(msg) = self.ratchet_ack_asm.push(body).map_err(ChatError::Ratchet)? else {
            return Ok(());
        };
        let flags = self.ratchet_flags;
        let Some((root, epoch)) = self.ratchet.on_ack(&msg).map_err(ChatError::Ratchet)? else {
            return Ok(());
        };
        self.cipher.stage_rx_epoch(&root, epoch).map_err(ChatError::Epoch)?;
        self.cipher.commit_tx_epoch(epoch).map_err(ChatError::Epoch)?;
        drop(root);
        self.ratchet_last_tx = None;
        self.push_event(EngineEvent::EpochAdvanced(epoch));
        if flags & RATCHET_FLAG_PQ != 0 {
            self.pq_mixed_epoch = Some(epoch);
        }
        Ok(())
    }

    fn handle_arq(&mut self, body: &[u8; MUX_BODY_LEN]) {
        let msg_id = u16::from_be_bytes([body[0], body[1]]);
        let base = usize::from(body[2]);
        let mut bm = [0u8; 8];
        bm.copy_from_slice(&body[3..11]);
        let bitmap = u64::from_be_bytes(bm);
        let complete = body[11] == 1;
        let Some(pos) = self.outgoing.iter().position(|o| o.msg_id == msg_id) else {
            return;
        };
        let Some(o) = self.outgoing.get_mut(pos) else { return };
        if complete {
            o.acked.iter_mut().for_each(|a| *a = true);
        } else {
            for bit in 0..64 {
                if (bitmap >> bit) & 1 == 1 {
                    if let Some(a) = o.acked.get_mut(base + bit) {
                        *a = true;
                    }
                }
            }
        }
        let acked = o.acked.iter().filter(|a| **a).count();
        let total = o.acked.len();
        if acked == total {
            self.outgoing.remove(pos);
            self.mux.remove_chat_shards_for_msg(msg_id);
            self.vault.mark_delivered(u32::from(msg_id));
            self.push_event(EngineEvent::MessageDelivered(msg_id));
        } else {
            let changed = acked != o.last_progress_acked;
            o.last_progress_acked = acked;
            self.vault.update_progress(u32::from(msg_id), acked as u16, total as u16);
            if changed {
                self.push_event(EngineEvent::MessageProgress {
                    msg_id,
                    acked: acked as u16,
                    total: total as u16,
                });
            }
        }
    }

    fn expire_incoming(&mut self, now_ms: u64) {
        self.incoming
            .retain(|_, e| now_ms.saturating_sub(e.last_ms) <= INCOMING_TIMEOUT_MS);
    }

    fn handle_incoming_chat_shard(&mut self, epoch6: u8, body: &[u8; MUX_BODY_LEN], now_ms: u64) {
        let msg_id = u16::from_be_bytes([body[0], body[1]]);
        let idx = usize::from(body[2]);
        let mut chunk = [0u8; CHAT_SHARD_DATA_LEN];
        chunk.copy_from_slice(&body[3..13]);

        // Changed key, SAS not yet re-confirmed: nothing from this peer is reassembled, stored
        // or acknowledged. The sender keeps retransmitting, so reception resumes after unlock.
        if self.tx_locked {
            return;
        }
        if msg_id < self.peer_lo || msg_id > self.peer_hi || idx >= MAX_SHARDS {
            return;
        }
        if self.aborted_rx_ids.contains(msg_id, now_ms) {
            return;
        }
        if self.completed_rx_ids.contains(msg_id, now_ms) {
            self.queue_arq_ack(msg_id, 0, u64::MAX, true);
            return;
        }
        self.expire_incoming(now_ms);
        if !self.incoming.contains_key(&msg_id) && self.incoming.len() >= MAX_INCOMING_REASSEMBLY {
            return;
        }
        let entry = self.incoming.entry(msg_id).or_insert_with(|| IncomingReassembly {
            epoch6,
            total: None,
            blob_len: 0,
            shards: Vec::new(),
            have: 0,
            since_ack: 0,
            last_ms: now_ms,
        });
        let step = Self::store_shard(entry, epoch6, idx, chunk, now_ms);
        match step {
            ShardStep::Drop => {}
            ShardStep::Reject => self.reject_incoming(msg_id, now_ms),
            ShardStep::Ack(b) => {
                let bitmap = self.incoming.get(&msg_id).map(|e| e.bitmap(b)).unwrap_or(0);
                self.queue_arq_ack(msg_id, b as u8, bitmap, false);
            }
            ShardStep::Complete => {
                if !self.finalize_incoming(msg_id, now_ms) {
                    self.reject_incoming(msg_id, now_ms);
                }
            }
        }
    }

    fn store_shard(
        entry: &mut IncomingReassembly,
        epoch6: u8,
        idx: usize,
        chunk: [u8; CHAT_SHARD_DATA_LEN],
        now_ms: u64,
    ) -> ShardStep {
        if entry.epoch6 != epoch6 {
            return ShardStep::Drop;
        }
        entry.last_ms = now_ms;
        let base = (idx / 64) * 64;
        if entry.shards.len() <= idx {
            entry.shards.resize(idx + 1, None);
        }
        match entry.shards.get(idx).copied().flatten() {
            Some(prev) if prev == chunk => return ShardStep::Ack(base),
            Some(_) => return ShardStep::Drop,
            None => {}
        }
        if let Some(slot) = entry.shards.get_mut(idx) {
            *slot = Some(chunk);
        }
        entry.have += 1;
        entry.since_ack += 1;
        if idx == 0 {
            let total = usize::from(chunk[0]);
            let blob_len = usize::from(u16::from_be_bytes([chunk[1], chunk[2]]));
            let valid = (1..=MAX_SHARDS).contains(&total)
                && blob_len >= MIN_BLOB_LEN
                && FRAME_HDR_LEN + blob_len <= total * CHAT_SHARD_DATA_LEN
                && FRAME_HDR_LEN + blob_len > (total - 1) * CHAT_SHARD_DATA_LEN
                && !entry.shards.iter().skip(total).any(|s| s.is_some());
            if !valid {
                return ShardStep::Reject;
            }
            entry.total = Some(total);
            entry.blob_len = blob_len;
        } else if entry.total.is_some_and(|t| idx >= t) {
            return ShardStep::Reject;
        }
        if entry.total.is_some_and(|t| entry.have == t) {
            return ShardStep::Complete;
        }
        if entry.since_ack >= ACK_EVERY_SHARDS {
            entry.since_ack = 0;
            return ShardStep::Ack(base);
        }
        ShardStep::Drop
    }

    fn reject_incoming(&mut self, msg_id: u16, now_ms: u64) {
        self.incoming.remove(&msg_id);
        self.aborted_rx_ids.insert(msg_id, now_ms);
    }

    /// Decrypts a complete message into the vault. Returns false when it must be rejected.
    fn finalize_incoming(&mut self, msg_id: u16, now_ms: u64) -> bool {
        let Some(entry) = self.incoming.remove(&msg_id) else { return false };
        let Some(total) = entry.total else { return false };
        let mut stream = Zeroizing::new(Vec::with_capacity(total * CHAT_SHARD_DATA_LEN));
        for s in entry.shards.iter().take(total) {
            match s {
                Some(c) => stream.extend_from_slice(c),
                None => return false,
            }
        }
        let Some(blob) = stream.get(FRAME_HDR_LEN..FRAME_HDR_LEN + entry.blob_len) else { return false };
        let (Some(tail), Some(ct)) = (blob.get(..NONCE_TAIL_LEN), blob.get(NONCE_TAIL_LEN..)) else {
            return false;
        };
        let Ok((epoch, msg_key)) = self.cipher.rx_message_key(entry.epoch6, u32::from(msg_id)) else {
            return false;
        };
        let peer_dir = match self.role {
            Role::Initiator => DIR_R2I,
            Role::Responder => DIR_I2R,
        };
        let mut nonce = [0u8; 24];
        nonce[0] = peer_dir;
        nonce[1..3].copy_from_slice(&msg_id.to_be_bytes());
        nonce[3..].copy_from_slice(tail);
        let aad = msg_aad(peer_dir, epoch, msg_id);
        let aead = XChaCha20Poly1305::new(msg_key.as_bytes().into());
        drop(msg_key);
        let Ok(plain) = aead.decrypt(XNonce::from_slice(&nonce), Payload { msg: ct, aad: &aad }) else {
            return false;
        };
        self.cipher.retire_rx_message_key(epoch, u32::from(msg_id));
        let inner = Zeroizing::new(plain);
        if inner.len() < 6 || inner[3] != 0 || inner[2] != CONTENT_TEXT {
            return false;
        }
        let burn_ttl_secs = u16::from_be_bytes([inner[0], inner[1]]);
        let body_len = usize::from(u16::from_be_bytes([inner[4], inner[5]]));
        let Some(payload) = inner.get(6..6 + body_len) else { return false };
        if core::str::from_utf8(payload).is_err() {
            return false;
        }
        if self
            .vault
            .push_binary_payload(
                u32::from(msg_id),
                MessageDirection::Incoming,
                now_ms,
                burn_ttl_secs,
                EphemeralMediaKind::Text,
                payload,
            )
            .is_err()
        {
            return false;
        }
        drop(inner);
        self.completed_rx_ids.insert(msg_id, now_ms);
        self.queue_arq_ack(msg_id, 0, u64::MAX, true);
        self.push_event(EngineEvent::MessageReceived(msg_id));
        true
    }

    pub fn is_outgoing_delivered(&self, msg_id: u16) -> bool {
        self.vault.messages().iter().any(|m| {
            m.msg_id == u32::from(msg_id)
                && m.direction == MessageDirection::Outgoing
                && matches!(
                    m.delivery_state,
                    DeliveryReceiptState::DeliveredToPeerRam | DeliveryReceiptState::ViewedByPeer
                )
        })
    }

    pub fn is_outgoing_viewed(&self, msg_id: u16) -> bool {
        self.vault.messages().iter().any(|m| {
            m.msg_id == u32::from(msg_id)
                && m.direction == MessageDirection::Outgoing
                && m.delivery_state == DeliveryReceiptState::ViewedByPeer
        })
    }

    pub fn is_outgoing_failed(&self, msg_id: u16) -> bool {
        self.vault.messages().iter().any(|m| {
            m.msg_id == u32::from(msg_id)
                && m.direction == MessageDirection::Outgoing
                && m.delivery_state == DeliveryReceiptState::FailedOrAborted
        })
    }
}

impl Drop for ChatSessionEngine {
    /// Message plaintext, queued frames and pending events are wiped; the cipher and the
    /// ratchet zeroize their own keys when dropped right after.
    fn drop(&mut self) {
        self.wipe_local();
        self.events.clear();
        self.wipe_body.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (ChatSessionEngine, ChatSessionEngine) {
        let root = SecretKey32::from_bytes([0x5A; 32]);
        let tag = [1, 2, 3, 4];
        (
            ChatSessionEngine::new(Role::Initiator, &root, tag, SecretKey32::from_bytes([1; 32])),
            ChatSessionEngine::new(Role::Responder, &root, tag, SecretKey32::from_bytes([2; 32])),
        )
    }

    fn shard_body(msg_id: u16, idx: u8) -> [u8; MUX_BODY_LEN] {
        let mut b = [0u8; MUX_BODY_LEN];
        b[0..2].copy_from_slice(&msg_id.to_be_bytes());
        b[2] = idx;
        b
    }

    #[test]
    fn locked_engine_drops_incoming_shards_until_unlocked() {
        let (mut i, mut r) = pair();
        r.set_tx_locked(true);
        let id = i.send_text_message(0, 0, "held back").unwrap();
        let mut now = 0;
        let mut exchange = |i: &mut ChatSessionEngine, r: &mut ChatSessionEngine, slots: u32| {
            for _ in 0..slots {
                now += 160;
                let w = i.next_tx_wire_superframe(now).unwrap();
                r.process_rx_wire_superframe(&w, now).unwrap();
                let w = r.next_tx_wire_superframe(now).unwrap();
                i.process_rx_wire_superframe(&w, now).unwrap();
            }
        };
        exchange(&mut i, &mut r, 40);
        assert_eq!(r.incoming_len(), 0, "nothing is reassembled while locked");
        assert!(r.vault.messages().is_empty());
        assert!(r.take_events().is_empty(), "no MessageReceived while locked");
        assert!(!i.is_outgoing_delivered(id), "no delivery acknowledgement while locked");
        r.set_tx_locked(false);
        exchange(&mut i, &mut r, 80);
        assert!(i.is_outgoing_delivered(id));
        assert!(r.vault.messages().iter().any(|m| m.text() == "held back"));
    }

    #[test]
    fn presence_and_viewed_receipt_are_held_back_while_locked_or_wiping() {
        let (mut i, _) = pair();
        i.set_tx_locked(true);
        i.send_presence_state(PeerPresenceState::TypingText);
        i.send_viewed_receipt(7);
        assert_eq!(i.mux.ctrl_len(), 0);
        i.set_tx_locked(false);
        i.send_presence_state(PeerPresenceState::TypingText);
        i.send_viewed_receipt(7);
        assert_eq!(i.mux.ctrl_len(), 3);
        i.trigger_dual_end_panic_wipe();
        i.send_presence_state(PeerPresenceState::Idle);
        i.send_viewed_receipt(8);
        assert_eq!(i.mux.ctrl_len(), 0);
    }

    #[test]
    fn reassembly_table_is_capped_and_expires() {
        let (_, mut r) = pair();
        for k in 0..(MAX_INCOMING_REASSEMBLY as u16 + 8) {
            r.handle_incoming_chat_shard(0, &shard_body(10 + k, 1), 1_000);
        }
        assert_eq!(r.incoming_len(), MAX_INCOMING_REASSEMBLY);
        assert!(!r.incoming.contains_key(&(10 + MAX_INCOMING_REASSEMBLY as u16)));
        // After the timeout the stale entries go and a new message is accepted again.
        let later = 1_000 + INCOMING_TIMEOUT_MS + 1;
        r.handle_incoming_chat_shard(0, &shard_body(500, 1), later);
        assert_eq!(r.incoming_len(), 1);
        // Shards outside the peer's id range or beyond MAX_SHARDS never allocate.
        r.handle_incoming_chat_shard(0, &shard_body(0x8001, 1), later);
        r.handle_incoming_chat_shard(0, &shard_body(600, 251), later);
        assert_eq!(r.incoming_len(), 1);
    }

    #[test]
    fn completed_and_aborted_id_sets_are_bounded_with_ttl() {
        let mut s = BoundedIdSet::new(ID_SET_CAP, ID_SET_TTL_MS);
        for id in 0..(ID_SET_CAP as u16 * 2) {
            s.insert(id, 5);
        }
        assert_eq!(s.len(), ID_SET_CAP);
        assert!(!s.contains(0, 5));
        assert!(s.contains(ID_SET_CAP as u16 * 2 - 1, 5));
        assert!(!s.contains(ID_SET_CAP as u16 * 2 - 1, 5 + ID_SET_TTL_MS + 1));
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn outgoing_queue_is_capped() {
        let (mut i, _) = pair();
        for n in 0..MAX_OUTGOING_MESSAGES {
            i.send_text_message(n as u64, 0, "queued").unwrap();
        }
        assert_eq!(i.send_text_message(99, 0, "one too many"), Err(ChatError::QueueFull));
        assert_eq!(i.outgoing_len(), MAX_OUTGOING_MESSAGES);
        let big = "x".repeat(3000);
        assert_eq!(i.abort_outgoing_transfer(1), true);
        assert_eq!(i.send_text_message(100, 0, &big), Err(ChatError::MessageTooLarge));
    }

    #[test]
    fn retransmission_budget_exhaustion_aborts_the_message() {
        let (mut i, _) = pair();
        i.set_retransmit_ticks(2);
        let id = i.send_text_message(0, 0, "nobody hears this").unwrap();
        let mut failed = false;
        for n in 0..2_000u64 {
            i.next_tx_wire_superframe(n * 160).unwrap();
            if i.take_events().iter().any(|e| matches!(e, EngineEvent::MessageFailed(m) if *m == id)) {
                failed = true;
                break;
            }
        }
        assert!(failed);
        assert!(i.is_outgoing_failed(id));
        assert_eq!(i.outgoing_len(), 0);
    }

    #[test]
    fn lossless_pair_delivers_text_and_rejects_tampered_frames() {
        let (mut i, mut r) = pair();
        let id = i.send_text_message(0, 0, "First message 1").unwrap();
        let mut now = 0;
        for _ in 0..40 {
            now += 160;
            let w = i.next_tx_wire_superframe(now).unwrap();
            let mut bad = w;
            bad[5] ^= 0x40;
            assert_eq!(r.process_rx_wire_superframe(&bad, now), Err(ChatError::FrameRejected));
            r.process_rx_wire_superframe(&w, now).unwrap();
            assert_eq!(r.process_rx_wire_superframe(&w, now), Err(ChatError::FrameRejected));
            let w = r.next_tx_wire_superframe(now).unwrap();
            i.process_rx_wire_superframe(&w, now).unwrap();
        }
        assert!(i.is_outgoing_delivered(id));
        assert!(r.vault.messages().iter().any(|m| m.text() == "First message 1"));
    }
}
