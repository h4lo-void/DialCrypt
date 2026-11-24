//! AegisMux: Encrypted Superframe Multiplexer & Constant-Rate Chaff Cover Generator.
//!
//! Ensures the cellular voice channel carries a uniform continuous stream of encrypted
//! pseudo-speech frames whether users are typing or silent, defeating carrier timing/length
//! traffic analysis and preventing VoLTE VAD/DTX silence suppression from breaking modem sync.
//!
//! Priority: control > chat > BULK > chaff (secure-session-v2 §6.3). Every queue is bounded.

use aegiscall_crypto::MUX_PAYLOAD_LEN;
use aegiscall_memsec::SecretKey32;
use std::collections::VecDeque;

pub const MUX_BODY_LEN: usize = 13;
/// Maximum queued control frames; urgent frames evict the newest queued one when full.
pub const CTRL_QUEUE_CAP: usize = 64;
/// Maximum queued chat shards.
pub const CHAT_QUEUE_CAP: usize = 64;
/// Maximum queued BULK fragments.
pub const BULK_QUEUE_CAP: usize = 8;

/// Control subtypes carried in the 6-bit subflags of [FrameKind::CtrlAck] frames
/// (secure-session-v2 §2.D, §6.3, §6.4). Subtypes 4 and 5 belonged to the retired symmetric
/// rekey and must never be reused.
pub mod ctrl {
    pub const ARQ_BITMAP: u8 = 1;
    pub const PANIC_WIPE: u8 = 2;
    pub const PING_KEEPALIVE: u8 = 3;
    pub const PRESENCE: u8 = 6;
    pub const VIEWED_RECEIPT: u8 = 7;
    pub const ABORT_TRANSFER: u8 = 8;
    /// First encrypted frame of each side after the handshake.
    pub const HS_FINISHED: u8 = 9;
    /// I -> R, 3 fragments: epoch_lsb(1) | (flags:4 | index:4) | data(11).
    pub const DH_RATCHET: u8 = 10;
    /// R -> I, same layout as DH_RATCHET.
    pub const DH_RATCHET_ACK: u8 = 11;
    /// body[0] = 1 (SAS matched) or 0 (mismatch).
    pub const SAS_RESULT: u8 = 12;
    /// body[0] = 1 (voice comparison window opens) or 0 (closes).
    pub const VOICE_WINDOW: u8 = 13;
    /// Ask the peer to send its attestation chain over BULK object 3.
    pub const EVIDENCE_REQ: u8 = 14;
    /// body[0] = 0 normal hang-up, otherwise an abort reason code.
    pub const SESSION_END: u8 = 15;
    pub const GEAR_SWITCH: u8 = 16;
    /// k(1) | Expand(rs_next, "saved")[..8].
    pub const RESUME_SAVED: u8 = 17;
    /// (obj:4 | idx high 4) | idx low 8 | data(11).
    pub const BULK_DATA: u8 = 18;
    /// (obj:4 | base high 4) | base low 8 | 88-bit bitmap.
    pub const BULK_ACK: u8 = 19;
    /// R -> I: request a DH ratchet step as soon as possible (one frame).
    pub const DH_RATCHET_REQ: u8 = 20;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameKind {
    /// Statistically indistinguishable encrypted cover traffic emitted when idle.
    Chaff = 0b00,
    /// Reserved for V2 1.6kbps neural vocoder speech frames.
    VoiceReserved = 0b01,
    /// Compressed + inner-AEAD-protected chat shard.
    ChatData = 0b10,
    /// Control frames (see [ctrl]), including BULK data and acknowledgements.
    CtrlAck = 0b11,
}

impl FrameKind {
    pub fn from_bits(v: u8) -> Self {
        match v & 0b11 {
            0b00 => FrameKind::Chaff,
            0b01 => FrameKind::VoiceReserved,
            0b10 => FrameKind::ChatData,
            _ => FrameKind::CtrlAck,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MuxFrame {
    pub kind: FrameKind,
    pub subflags: u8, // 6 bits (0..63)
    pub body: [u8; MUX_BODY_LEN],
}

impl MuxFrame {
    pub fn new(kind: FrameKind, subflags: u8, body: [u8; MUX_BODY_LEN]) -> Self {
        Self {
            kind,
            subflags: subflags & 0x3F,
            body,
        }
    }

    pub fn encode(&self) -> [u8; MUX_PAYLOAD_LEN] {
        let mut out = [0u8; MUX_PAYLOAD_LEN];
        out[0] = ((self.kind as u8) << 6) | (self.subflags & 0x3F);
        out[1..MUX_PAYLOAD_LEN].copy_from_slice(&self.body);
        out
    }

    pub fn decode(raw: &[u8; MUX_PAYLOAD_LEN]) -> Self {
        let kind = FrameKind::from_bits(raw[0] >> 6);
        let subflags = raw[0] & 0x3F;
        let mut body = [0u8; MUX_BODY_LEN];
        body.copy_from_slice(&raw[1..MUX_PAYLOAD_LEN]);
        Self {
            kind,
            subflags,
            body,
        }
    }

    pub fn is_ctrl(&self, subtype: u8) -> bool {
        self.kind == FrameKind::CtrlAck && self.subflags == (subtype & 0x3F)
    }
}

/// Deterministic cryptographic Chaff PRNG derived from the session `chaff_seed`.
pub struct ChaffGenerator {
    seed: SecretKey32,
    counter: u64,
}

impl ChaffGenerator {
    pub fn new(seed: SecretKey32) -> Self {
        Self { seed, counter: 0 }
    }

    pub fn next_chaff_frame(&mut self) -> MuxFrame {
        let mut h = blake3::Hasher::new_keyed(self.seed.as_bytes());
        h.update(&self.counter.to_le_bytes());
        self.counter = self.counter.wrapping_add(1);
        let digest = h.finalize();
        let bytes = digest.as_bytes();
        let subflags = bytes[0] & 0x3F;
        let mut body = [0u8; MUX_BODY_LEN];
        body.copy_from_slice(&bytes[1..14]);
        MuxFrame::new(FrameKind::Chaff, subflags, body)
    }
}

/// Priority scheduler: control (highest) > chat > BULK > chaff (always available).
pub struct MuxScheduler {
    ctrl_queue: VecDeque<MuxFrame>,
    chat_queue: VecDeque<MuxFrame>,
    bulk_queue: VecDeque<MuxFrame>,
    chaff: ChaffGenerator,
    pub total_emitted_frames: u64,
    pub total_chaff_frames: u64,
    /// Frames refused or evicted because a queue was full.
    pub dropped_frames: u64,
}

impl MuxScheduler {
    pub fn new(chaff_seed: SecretKey32) -> Self {
        Self {
            ctrl_queue: VecDeque::with_capacity(CTRL_QUEUE_CAP),
            chat_queue: VecDeque::with_capacity(CHAT_QUEUE_CAP),
            bulk_queue: VecDeque::with_capacity(BULK_QUEUE_CAP),
            chaff: ChaffGenerator::new(chaff_seed),
            total_emitted_frames: 0,
            total_chaff_frames: 0,
            dropped_frames: 0,
        }
    }

    fn push_bounded(q: &mut VecDeque<MuxFrame>, cap: usize, frame: MuxFrame, dropped: &mut u64) -> bool {
        if q.len() >= cap {
            *dropped += 1;
            return false;
        }
        q.push_back(frame);
        true
    }

    /// Returns false (frame dropped) when the control queue is full.
    pub fn enqueue_ctrl(&mut self, frame: MuxFrame) -> bool {
        Self::push_bounded(&mut self.ctrl_queue, CTRL_QUEUE_CAP, frame, &mut self.dropped_frames)
    }

    /// Puts the frame first; when full the newest queued control frame is evicted.
    pub fn enqueue_ctrl_urgent(&mut self, frame: MuxFrame) -> bool {
        if self.ctrl_queue.len() >= CTRL_QUEUE_CAP {
            self.ctrl_queue.pop_back();
            self.dropped_frames += 1;
        }
        self.ctrl_queue.push_front(frame);
        true
    }

    /// Returns false (frame dropped) when the chat queue is full.
    pub fn enqueue_chat(&mut self, frame: MuxFrame) -> bool {
        Self::push_bounded(&mut self.chat_queue, CHAT_QUEUE_CAP, frame, &mut self.dropped_frames)
    }

    /// Returns false (frame dropped) when the BULK queue is full.
    pub fn enqueue_bulk(&mut self, frame: MuxFrame) -> bool {
        Self::push_bounded(&mut self.bulk_queue, BULK_QUEUE_CAP, frame, &mut self.dropped_frames)
    }

    pub fn has_pending_non_chaff(&self) -> bool {
        !self.ctrl_queue.is_empty() || !self.chat_queue.is_empty() || !self.bulk_queue.is_empty()
    }

    /// True when control or chat frames are waiting (BULK only fills otherwise idle slots).
    pub fn has_pending_ctrl_or_chat(&self) -> bool {
        !self.ctrl_queue.is_empty() || !self.chat_queue.is_empty()
    }

    pub fn ctrl_len(&self) -> usize {
        self.ctrl_queue.len()
    }

    pub fn chat_len(&self) -> usize {
        self.chat_queue.len()
    }

    pub fn bulk_len(&self) -> usize {
        self.bulk_queue.len()
    }

    /// Always returns an encrypted-ready frame (emits chaff cover traffic when idle).
    pub fn pop_next_frame(&mut self) -> MuxFrame {
        self.total_emitted_frames += 1;
        if let Some(ctrl) = self.ctrl_queue.pop_front() {
            return ctrl;
        }
        if let Some(chat) = self.chat_queue.pop_front() {
            return chat;
        }
        if let Some(bulk) = self.bulk_queue.pop_front() {
            return bulk;
        }
        self.total_chaff_frames += 1;
        self.chaff.next_chaff_frame()
    }

    pub fn clear_queues(&mut self) {
        self.ctrl_queue.clear();
        self.chat_queue.clear();
        self.bulk_queue.clear();
    }

    /// Drops queued control frames matching the predicate (used to coalesce acknowledgements).
    pub fn remove_ctrl_where<F: Fn(&MuxFrame) -> bool>(&mut self, pred: F) {
        self.ctrl_queue.retain(|f| !pred(f));
    }

    pub fn remove_chat_shards_for_msg(&mut self, msg_id: u16) {
        self.chat_queue.retain(|f| {
            !(f.kind == FrameKind::ChatData
                && u16::from_be_bytes([f.body[0], f.body[1]]) == msg_id)
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mux_prioritizes_ctrl_over_chat_and_emits_continuous_chaff() {
        let mut sched = MuxScheduler::new(SecretKey32::from_bytes([7u8; 32]));
        sched.enqueue_chat(MuxFrame::new(FrameKind::ChatData, 1, [0xAA; 13]));
        sched.enqueue_ctrl(MuxFrame::new(FrameKind::CtrlAck, 2, [0xBB; 13]));

        assert_eq!(sched.pop_next_frame().kind, FrameKind::CtrlAck);
        assert_eq!(sched.pop_next_frame().kind, FrameKind::ChatData);
        let c1 = sched.pop_next_frame();
        let c2 = sched.pop_next_frame();
        assert_eq!(c1.kind, FrameKind::Chaff);
        assert_eq!(c2.kind, FrameKind::Chaff);
        assert_ne!(c1.body, c2.body);
        assert_eq!(sched.total_chaff_frames, 2);
    }

    #[test]
    fn bulk_sits_between_chat_and_chaff() {
        let mut sched = MuxScheduler::new(SecretKey32::from_bytes([3u8; 32]));
        assert!(sched.enqueue_bulk(MuxFrame::new(FrameKind::CtrlAck, ctrl::BULK_DATA, [1; 13])));
        assert!(sched.enqueue_chat(MuxFrame::new(FrameKind::ChatData, 0, [2; 13])));
        assert!(sched.enqueue_ctrl(MuxFrame::new(FrameKind::CtrlAck, ctrl::SAS_RESULT, [3; 13])));
        assert!(sched.has_pending_ctrl_or_chat());
        assert!(sched.pop_next_frame().is_ctrl(ctrl::SAS_RESULT));
        assert_eq!(sched.pop_next_frame().kind, FrameKind::ChatData);
        assert!(!sched.has_pending_ctrl_or_chat());
        assert!(sched.has_pending_non_chaff());
        assert!(sched.pop_next_frame().is_ctrl(ctrl::BULK_DATA));
        assert_eq!(sched.pop_next_frame().kind, FrameKind::Chaff);
    }

    #[test]
    fn queues_are_bounded_and_urgent_frames_evict_the_newest() {
        let mut sched = MuxScheduler::new(SecretKey32::from_bytes([5u8; 32]));
        for i in 0..CTRL_QUEUE_CAP {
            assert!(sched.enqueue_ctrl(MuxFrame::new(FrameKind::CtrlAck, ctrl::PRESENCE, [i as u8; 13])));
        }
        assert!(!sched.enqueue_ctrl(MuxFrame::new(FrameKind::CtrlAck, ctrl::PRESENCE, [0xFF; 13])));
        assert!(sched.enqueue_ctrl_urgent(MuxFrame::new(FrameKind::CtrlAck, ctrl::PANIC_WIPE, [0xEE; 13])));
        assert_eq!(sched.ctrl_len(), CTRL_QUEUE_CAP);
        assert_eq!(sched.dropped_frames, 2);
        assert!(sched.pop_next_frame().is_ctrl(ctrl::PANIC_WIPE));

        for _ in 0..CHAT_QUEUE_CAP {
            assert!(sched.enqueue_chat(MuxFrame::new(FrameKind::ChatData, 0, [0; 13])));
        }
        assert!(!sched.enqueue_chat(MuxFrame::new(FrameKind::ChatData, 0, [0; 13])));
        for _ in 0..BULK_QUEUE_CAP {
            assert!(sched.enqueue_bulk(MuxFrame::new(FrameKind::CtrlAck, ctrl::BULK_DATA, [0; 13])));
        }
        assert!(!sched.enqueue_bulk(MuxFrame::new(FrameKind::CtrlAck, ctrl::BULK_DATA, [0; 13])));

        sched.remove_ctrl_where(|f| f.is_ctrl(ctrl::PRESENCE));
        assert_eq!(sched.ctrl_len(), 0);
        sched.clear_queues();
        assert!(!sched.has_pending_non_chaff());
    }

    #[test]
    fn new_control_subtypes_fit_six_bits_and_are_distinct() {
        let all = [
            ctrl::ARQ_BITMAP,
            ctrl::PANIC_WIPE,
            ctrl::PING_KEEPALIVE,
            ctrl::PRESENCE,
            ctrl::VIEWED_RECEIPT,
            ctrl::ABORT_TRANSFER,
            ctrl::HS_FINISHED,
            ctrl::DH_RATCHET,
            ctrl::DH_RATCHET_ACK,
            ctrl::SAS_RESULT,
            ctrl::VOICE_WINDOW,
            ctrl::EVIDENCE_REQ,
            ctrl::SESSION_END,
            ctrl::GEAR_SWITCH,
            ctrl::RESUME_SAVED,
            ctrl::BULK_DATA,
            ctrl::BULK_ACK,
            ctrl::DH_RATCHET_REQ,
        ];
        for (i, a) in all.iter().enumerate() {
            assert!(*a < 64 && *a != 4 && *a != 5);
            for b in &all[i + 1..] {
                assert_ne!(a, b);
            }
        }
        let f = MuxFrame::new(FrameKind::CtrlAck, ctrl::BULK_ACK, [9; 13]);
        assert_eq!(MuxFrame::decode(&f.encode()), f);
    }
}
