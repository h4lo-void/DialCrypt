//! Pre-key link layer for handshake v2 (secure-session-v2 §2.B, amended by §6.2).
//!
//! Every 23-byte superframe sent before the keys exist has this layout:
//!
//! | byte  | content |
//! |-------|---------|
//! | 0     | high nibble 0xA; low nibble = type: 1-4 HS1-HS4, 5 RS2, 6 RS3, 7 PATH, 0xE ACK, 0xF ABORT |
//! | 1     | DATA: fragment index; ACK: acknowledged message type; ABORT: reason code |
//! | 2     | sender's random attempt tag (the receiver locks the first value it sees) |
//! | 3-20  | 18 data bytes (last fragment zero padded); ACK: 144-bit received bitmap |
//! | 21-22 | CRC-16 over bytes 0-20, big endian |
//!
//! One frame per slot. Fragments the peer's ACK bitmap reports missing go first, then fresh
//! fragments, then timed resends round-robin (selective repeat). While receiving, an ACK is
//! inserted after every 4 received fragments and whenever a message completes (deferred while
//! fresh fragments are waiting, until 4 more fragments have arrived); with nothing fresh to send
//! and a peer message incomplete, every slot carries an ACK.
//!
//! On the real modem path a frame needs several slots to reach the peer and its ACK as many
//! to come back, so an ACK does not yet cover the fragments sent during the last round trip.
//! The link measures the round trip in slots (the shortest delay from sending a fragment once
//! to the first ACK covering it, smoothed) and treats a fragment as reported missing only by an
//! ACK that arrived at least one round trip after the fragment was last sent; timed resends
//! also wait at least one round trip. Without this every ACK re-queued all fragments still in
//! flight ahead of fresh ones.
//!
//! Before the keys exist an ACK is accepted only when it matches what we actually sent: an empty
//! idle ACK (type 0), or a bitmap for a message type we queued whose set bits all name fragments
//! inside that message that we have already transmitted. Any other ACK is dropped
//! ([HsLinkError::UnexpectedAck]) without touching the ARQ state or locking the peer's tag.
//!
//! After the keys exist ([HsLink::set_established]) the link only resends our last message, at
//! most [POST_ESTABLISH_MAX_FRAMES] frames, and sends no ACKs; every other frame type, foreign
//! tags and ABORT are dropped without any state change. No link frame is authenticated, so from
//! then on the peer's ACK bitmap is only a resend hint: fragments it reports missing are resent
//! at once, but it never marks a fragment acknowledged, and every fragment not acknowledged
//! before the keys keeps its timer resend. A forged ACK can therefore neither cancel nor
//! indefinitely delay a fragment the peer still needs.
//! [HsLink::close] shuts it permanently once the peer's first valid encrypted frame arrives.

use aegiscall_crypto::{HS1_LEN, HS2_LEN, HS3_LEN, HS4_LEN, PATH_LEN, RS2_LEN, RS3_LEN};
use aegiscall_modem::crc16_ccitt;
use thiserror::Error;
use zeroize::Zeroize;

pub const HS_FRAME_LEN: usize = 23;
pub const HS_DATA_LEN: usize = 18;
pub const HS_ACK_BITS: usize = HS_DATA_LEN * 8;
pub const HS_MAGIC: u8 = 0xA0;
pub const FRAME_ACK: u8 = 0x0E;
pub const FRAME_ABORT: u8 = 0x0F;
/// Insert an ACK after this many received data fragments.
pub const ACK_EVERY_RX: u32 = 4;
/// Upper bound on link frames sent after the keys exist (§6.2).
pub const POST_ESTABLISH_MAX_FRAMES: u32 = 32;
/// A fragment is not resent sooner than this many slots after its previous transmission.
/// Timed resends only use slots that would otherwise carry an idle ACK, so a short gap is cheap.
pub const DEFAULT_RESEND_GAP: u32 = 2;
/// After establishment an unacknowledged fragment is resent this many slots (or one round trip,
/// if longer) after its previous transmission.
pub const POST_RESEND_TIMEOUT: u32 = 8;
const DUP_ACK_GAP: u32 = 2;
const MAX_MSG_TYPE: u8 = 7;
/// Upper bound of the round-trip estimate (slots).
/// To be confirmed on device: the real round trip (modem latency, VoLTE network, audio buffers) stays below it.
const MAX_ROUND_TRIP: u32 = 32;

/// Fixed body length of each link message type (HS1-HS4, RS2, RS3, PATH).
pub fn message_len(t: u8) -> Option<usize> {
    match t {
        1 => Some(HS1_LEN),
        2 => Some(HS2_LEN),
        3 => Some(HS3_LEN),
        4 => Some(HS4_LEN),
        5 => Some(RS2_LEN),
        6 => Some(RS3_LEN),
        7 => Some(PATH_LEN),
        _ => None,
    }
}

/// Number of 18-byte fragments of a message type.
pub fn fragment_count(t: u8) -> Option<usize> {
    message_len(t).map(|l| l.div_ceil(HS_DATA_LEN))
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum HsLinkError {
    #[error("frame CRC mismatch")]
    BadCrc,
    #[error("not a handshake frame")]
    NotHandshake,
    #[error("frame carries a different attempt tag")]
    ForeignTag,
    #[error("unknown frame type")]
    UnknownType,
    #[error("fragment index out of range")]
    BadIndex,
    #[error("fragment differs from an earlier copy")]
    Conflict,
    #[error("message length or padding does not match its type")]
    BadLength,
    #[error("message type already queued")]
    DuplicateSend,
    #[error("peer aborted")]
    PeerAbort(u8),
    #[error("acknowledgement does not match any fragment sent")]
    UnexpectedAck,
}

impl HsLinkError {
    /// Fatal errors end the handshake (fail-closed); the others mean "not for us, drop it".
    pub fn is_fatal(&self) -> bool {
        !matches!(
            self,
            HsLinkError::BadCrc | HsLinkError::NotHandshake | HsLinkError::ForeignTag | HsLinkError::UnexpectedAck
        )
    }
}

struct TxMsg {
    t: u8,
    frags: Vec<[u8; HS_DATA_LEN]>,
    acked: Vec<bool>,
    last_tx: Vec<Option<u32>>,
    /// Sent more than once: its ACK delay is ambiguous and not used as a round-trip sample.
    resent: Vec<bool>,
    last_ack: Option<u32>,
    /// After establishment: the fragments the latest ACK reported received. A hint that only
    /// postpones the prompt resend; it is never taken as an acknowledgement.
    peer_has: Vec<bool>,
}

struct RxMsg {
    data: Vec<u8>,
    have: Vec<bool>,
    count: usize,
    done: bool,
    /// Changed since the last ACK that reported this message.
    dirty: bool,
}

impl RxMsg {
    fn new(frags: usize) -> Self {
        Self {
            data: vec![0u8; frags * HS_DATA_LEN],
            have: vec![false; frags],
            count: 0,
            done: false,
            dirty: false,
        }
    }
}

impl Drop for RxMsg {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

enum DataStep {
    Duplicate,
    Conflict,
    Stored { remaining: usize },
    Complete,
}

pub struct HsLink {
    tag: u8,
    peer_tag: Option<u8>,
    tx: Vec<TxMsg>,
    rx: [Option<RxMsg>; 8],
    tick: u32,
    rr_cursor: usize,
    ack_pending: bool,
    ack_type: u8,
    rx_since_ack: u32,
    last_ack_tick: Option<u32>,
    resend_gap: u32,
    /// Measured round trip in slots (1 until the first sample: frames delivered within the slot).
    round_trip: u32,
    round_trip_known: bool,
    established: bool,
    post_frames: u32,
    closed: bool,
    received: u64,
}

impl HsLink {
    pub fn new(tag: u8) -> Self {
        Self {
            tag,
            peer_tag: None,
            tx: Vec::new(),
            rx: std::array::from_fn(|_| None),
            tick: 0,
            rr_cursor: 0,
            ack_pending: false,
            ack_type: 0,
            rx_since_ack: 0,
            last_ack_tick: None,
            resend_gap: DEFAULT_RESEND_GAP,
            round_trip: 1,
            round_trip_known: false,
            established: false,
            post_frames: 0,
            closed: false,
            received: 0,
        }
    }

    pub fn tag(&self) -> u8 {
        self.tag
    }

    pub fn peer_tag(&self) -> Option<u8> {
        self.peer_tag
    }

    /// Minimum slots between two transmissions of the same fragment (at least 1).
    pub fn set_resend_gap(&mut self, slots: u32) {
        self.resend_gap = slots.max(1);
    }

    /// Queues a message of type t (1-7); its length must match the type.
    pub fn send(&mut self, t: u8, mut body: Vec<u8>) -> Result<(), HsLinkError> {
        let len = message_len(t).ok_or(HsLinkError::UnknownType)?;
        if body.len() != len {
            return Err(HsLinkError::BadLength);
        }
        if self.closed || self.established || self.tx.iter().any(|m| m.t == t) {
            return Err(HsLinkError::DuplicateSend);
        }
        let frags: Vec<[u8; HS_DATA_LEN]> = body
            .chunks(HS_DATA_LEN)
            .map(|c| {
                let mut f = [0u8; HS_DATA_LEN];
                f[..c.len()].copy_from_slice(c);
                f
            })
            .collect();
        body.zeroize();
        let n = frags.len();
        self.tx.push(TxMsg {
            t,
            frags,
            acked: vec![false; n],
            last_tx: vec![None; n],
            resent: vec![false; n],
            last_ack: None,
            peer_has: vec![false; n],
        });
        Ok(())
    }

    /// True when every fragment of every queued message has been acknowledged.
    pub fn all_acked(&self) -> bool {
        self.tx.iter().all(|m| m.acked.iter().all(|a| *a))
    }

    pub fn received_fragments(&self) -> u64 {
        self.received
    }

    pub fn acked_fragments(&self) -> u64 {
        self.tx
            .iter()
            .map(|m| m.acked.iter().filter(|a| **a).count() as u64)
            .sum()
    }

    pub fn is_established(&self) -> bool {
        self.established
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Keys exist: keep only our last message for ACK-driven resends (resend_last) or nothing.
    pub fn set_established(&mut self, resend_last: bool) {
        if self.established {
            return;
        }
        self.established = true;
        self.post_frames = 0;
        let last = if resend_last { self.tx.pop() } else { None };
        self.tx.clear();
        if let Some(m) = last {
            self.tx.push(m);
        }
        self.rr_cursor = 0;
    }

    /// The peer's first valid encrypted frame arrived: the link is shut for good.
    pub fn close(&mut self) {
        self.closed = true;
        self.ack_pending = false;
        self.tx.clear();
        self.rx = std::array::from_fn(|_| None);
    }

    /// After establishment: does the link still have something useful to send?
    pub fn post_wants_tx(&self) -> bool {
        self.established
            && !self.closed
            && self.post_frames < POST_ESTABLISH_MAX_FRAMES
            && self.pick_fragment().is_some()
    }

    /// Builds the frame for the next slot.
    pub fn next_frame(&mut self) -> [u8; HS_FRAME_LEN] {
        self.tick = self.tick.wrapping_add(1);
        if self.established {
            self.post_frames = self.post_frames.saturating_add(1);
            return match self.pick_fragment() {
                Some((mi, fi, pos)) => self.make_data(mi, fi, pos),
                None => self.make_ack(),
            };
        }
        let fresh_waiting = self.has_fresh();
        if self.ack_pending && (!fresh_waiting || self.rx_since_ack >= ACK_EVERY_RX) {
            return self.make_ack();
        }
        // Nothing fresh to send while a peer message is still incomplete: report what we have.
        if !fresh_waiting && self.rx_since_ack > 0 && self.has_incomplete_rx() {
            return self.make_ack();
        }
        if let Some((mi, fi, pos)) = self.pick_fragment() {
            return self.make_data(mi, fi, pos);
        }
        self.make_ack()
    }

    /// A slot went by without a link frame (preamble or encrypted frame sent instead):
    /// keeps the resend gap measured in slots.
    pub fn skip_slot(&mut self) {
        self.tick = self.tick.wrapping_add(1);
    }

    /// An ABORT frame carrying a reason code.
    pub fn abort_frame(&self, reason: u8) -> [u8; HS_FRAME_LEN] {
        self.build(FRAME_ABORT, reason, &[0u8; HS_DATA_LEN])
    }

    /// Parses a received frame; returns a completed message when its last fragment arrives.
    pub fn on_frame(&mut self, f: &[u8; HS_FRAME_LEN]) -> Result<Option<(u8, Vec<u8>)>, HsLinkError> {
        if self.closed {
            return Ok(None);
        }
        let crc = u16::from_be_bytes([f[21], f[22]]);
        if crc16_ccitt(&f[..21]) != crc {
            return Err(HsLinkError::BadCrc);
        }
        if f[0] & 0xF0 != HS_MAGIC {
            return Err(HsLinkError::NotHandshake);
        }
        match self.peer_tag {
            Some(t) if t != f[2] => return Err(HsLinkError::ForeignTag),
            None if self.established => return Err(HsLinkError::ForeignTag),
            _ => {}
        }
        let kind = f[0] & 0x0F;
        let mut data = [0u8; HS_DATA_LEN];
        data.copy_from_slice(&f[3..21]);
        // Link frames carry no authentication: once the keys exist none of them may advance any
        // state (§6.2, §6.11); an ACK of our last message only steers its resends.
        if self.established {
            if kind == FRAME_ACK && self.ack_matches_sent(f[1], &data) {
                self.note_post_ack(f[1], &data);
            }
            return Ok(None);
        }
        if kind == FRAME_ACK && !self.ack_matches_sent(f[1], &data) {
            return Err(HsLinkError::UnexpectedAck);
        }
        self.peer_tag.get_or_insert(f[2]);
        match kind {
            FRAME_ABORT => Err(HsLinkError::PeerAbort(f[1])),
            FRAME_ACK => {
                self.apply_ack(f[1], &data);
                Ok(None)
            }
            1..=MAX_MSG_TYPE => self.on_data(kind, usize::from(f[1]), &data),
            _ => Err(HsLinkError::UnknownType),
        }
    }

    fn on_data(&mut self, t: u8, idx: usize, data: &[u8; HS_DATA_LEN]) -> Result<Option<(u8, Vec<u8>)>, HsLinkError> {
        let len = message_len(t).ok_or(HsLinkError::UnknownType)?;
        let n = len.div_ceil(HS_DATA_LEN);
        if idx >= n {
            return Err(HsLinkError::BadIndex);
        }
        self.ack_type = t;
        self.rx_since_ack = self.rx_since_ack.saturating_add(1);
        let slot = self.rx.get_mut(usize::from(t)).ok_or(HsLinkError::UnknownType)?;
        let msg = slot.get_or_insert_with(|| RxMsg::new(n));
        msg.dirty = true;
        let off = idx * HS_DATA_LEN;
        let step = if msg.done {
            DataStep::Duplicate
        } else if msg.have.get(idx).copied().unwrap_or(true) {
            match msg.data.get(off..off + HS_DATA_LEN) {
                Some(d) if d == data => DataStep::Duplicate,
                _ => DataStep::Conflict,
            }
        } else {
            if let Some(d) = msg.data.get_mut(off..off + HS_DATA_LEN) {
                d.copy_from_slice(data);
            }
            if let Some(h) = msg.have.get_mut(idx) {
                *h = true;
            }
            msg.count += 1;
            if msg.count == n {
                msg.done = true;
                DataStep::Complete
            } else {
                DataStep::Stored { remaining: n - msg.count }
            }
        };
        match step {
            DataStep::Conflict => Err(HsLinkError::Conflict),
            DataStep::Duplicate => {
                let quiet = self
                    .last_ack_tick
                    .is_some_and(|t| self.tick.wrapping_sub(t) < DUP_ACK_GAP);
                if !quiet || self.rx_since_ack >= ACK_EVERY_RX {
                    self.ack_pending = true;
                }
                Ok(None)
            }
            DataStep::Stored { remaining } => {
                self.received += 1;
                // The completion ACK follows right away when only one fragment is missing.
                if self.rx_since_ack >= ACK_EVERY_RX && remaining > 1 {
                    self.ack_pending = true;
                }
                Ok(None)
            }
            DataStep::Complete => {
                self.received += 1;
                self.ack_pending = true;
                let Some(Some(msg)) = self.rx.get_mut(usize::from(t)) else {
                    return Err(HsLinkError::UnknownType);
                };
                let pad_ok = msg.data.get(len..).is_some_and(|p| p.iter().all(|b| *b == 0));
                let body = msg.data.get(..len).map(<[u8]>::to_vec);
                msg.data.zeroize();
                match (pad_ok, body) {
                    (true, Some(b)) => Ok(Some((t, b))),
                    _ => Err(HsLinkError::BadLength),
                }
            }
        }
    }

    /// Could the peer's link have built this ACK? It reports what the peer received from us, so
    /// type 0 (nothing received yet) carries an empty bitmap and any other type names a message
    /// we queued, with at least one bit set and only bits of fragments we have transmitted.
    fn ack_matches_sent(&self, t: u8, bm: &[u8; HS_DATA_LEN]) -> bool {
        let set = |i: usize| bm.get(i / 8).is_some_and(|b| (b >> (i % 8)) & 1 == 1);
        if t == 0 {
            return bm.iter().all(|b| *b == 0);
        }
        let Some(n) = fragment_count(t) else { return false };
        if !(0..n).any(set) || (n..HS_ACK_BITS).any(set) {
            return false;
        }
        let Some(m) = self.tx.iter().find(|m| m.t == t) else { return false };
        (0..n)
            .filter(|i| set(*i))
            .all(|i| m.last_tx.get(i).is_some_and(Option::is_some))
    }

    /// After establishment the peer's ACK is a resend hint only: fragments it reports missing
    /// become due one round trip after their last transmission, the others keep the timer
    /// resend. Each ACK replaces the previous hint; nothing is marked acknowledged.
    fn note_post_ack(&mut self, t: u8, bm: &[u8; HS_DATA_LEN]) {
        let tick = self.tick;
        for m in self.tx.iter_mut().filter(|m| m.t == t) {
            m.last_ack = Some(tick);
            for (i, h) in m.peer_has.iter_mut().enumerate() {
                *h = bm.get(i / 8).is_some_and(|b| (b >> (i % 8)) & 1 == 1);
            }
        }
    }

    fn apply_ack(&mut self, t: u8, bm: &[u8; HS_DATA_LEN]) {
        let tick = self.tick;
        let mut sample: Option<u32> = None;
        for m in self.tx.iter_mut().filter(|m| m.t == t) {
            m.last_ack = Some(tick);
            for (i, a) in m.acked.iter_mut().enumerate() {
                if bm.get(i / 8).is_some_and(|b| (b >> (i % 8)) & 1 == 1) {
                    if !*a && !m.resent.get(i).copied().unwrap_or(true) {
                        if let Some(Some(sent)) = m.last_tx.get(i) {
                            let d = tick.wrapping_sub(*sent).clamp(1, MAX_ROUND_TRIP);
                            sample = Some(sample.map_or(d, |s| s.min(d)));
                        }
                    }
                    *a = true;
                }
            }
        }
        if let Some(s) = sample {
            // The most recently sent fragment this ACK newly covers bounds the round trip best.
            self.round_trip = if self.round_trip_known { (3 * self.round_trip + s + 3) / 4 } else { s };
            self.round_trip_known = true;
        }
    }

    /// An ACK received at tick a reports a fragment last sent at tick t: it is evidence of loss
    /// only when the fragment had a full round trip to arrive before the peer built that ACK.
    fn ack_covers(&self, a: u32, t: u32) -> bool {
        a > t && a - t >= self.round_trip
    }

    fn has_incomplete_rx(&self) -> bool {
        self.rx.iter().flatten().any(|m| !m.done && m.count > 0)
    }

    fn has_fresh(&self) -> bool {
        self.tx
            .iter()
            .any(|m| m.acked.iter().zip(&m.last_tx).any(|(a, l)| !*a && l.is_none()))
    }

    /// Fragments the peer reported missing, then fresh fragments, in message order.
    fn pick_reported_or_fresh(&self) -> Option<(usize, usize, usize)> {
        let mut pos = 0usize;
        // 1. Fragments an ACK newer than their last transmission reports missing: the peer
        //    consumes messages in order, so these go before fresh fragments of later messages.
        for (mi, m) in self.tx.iter().enumerate() {
            for fi in 0..m.frags.len() {
                let unacked = !m.acked.get(fi).copied().unwrap_or(true)
                    && !m.peer_has.get(fi).copied().unwrap_or(true);
                let reported = match (m.last_tx.get(fi).copied().flatten(), m.last_ack) {
                    (Some(t), Some(a)) => self.ack_covers(a, t),
                    _ => false,
                };
                if unacked && reported {
                    return Some((mi, fi, pos));
                }
                pos += 1;
            }
        }
        // 2. Fresh fragments in message order.
        pos = 0;
        for (mi, m) in self.tx.iter().enumerate() {
            for fi in 0..m.frags.len() {
                if !m.acked.get(fi).copied().unwrap_or(true) && m.last_tx.get(fi).is_some_and(|l| l.is_none()) {
                    return Some((mi, fi, pos));
                }
                pos += 1;
            }
        }
        None
    }

    /// (message index, fragment index, flat position) of the next fragment to send.
    fn pick_fragment(&self) -> Option<(usize, usize, usize)> {
        if let Some(p) = self.pick_reported_or_fresh() {
            return Some(p);
        }
        let total: usize = self.tx.iter().map(|m| m.frags.len()).sum();
        if total == 0 {
            return None;
        }
        for step in 0..total {
            let target = (self.rr_cursor + step) % total;
            let mut flat = 0usize;
            for (mi, m) in self.tx.iter().enumerate() {
                let n = m.frags.len();
                if target < flat + n {
                    let fi = target - flat;
                    let unacked = !m.acked.get(fi).copied().unwrap_or(true);
                    let due = match m.last_tx.get(fi).copied().flatten() {
                        Some(t) if self.established => {
                            (m.last_ack.is_some_and(|a| self.ack_covers(a, t))
                                && !m.peer_has.get(fi).copied().unwrap_or(true))
                                || self.tick.wrapping_sub(t) >= POST_RESEND_TIMEOUT.max(self.round_trip)
                        }
                        Some(t) => self.tick.wrapping_sub(t) >= self.resend_gap.max(self.round_trip),
                        None => true,
                    };
                    if unacked && due {
                        return Some((mi, fi, target));
                    }
                    break;
                }
                flat += n;
            }
        }
        None
    }

    fn make_data(&mut self, mi: usize, fi: usize, pos: usize) -> [u8; HS_FRAME_LEN] {
        let tick = self.tick;
        let (t, data) = match self.tx.get_mut(mi) {
            Some(m) => {
                if let Some(l) = m.last_tx.get_mut(fi) {
                    if l.is_some() {
                        if let Some(r) = m.resent.get_mut(fi) {
                            *r = true;
                        }
                    }
                    *l = Some(tick);
                }
                (m.t, m.frags.get(fi).copied().unwrap_or([0u8; HS_DATA_LEN]))
            }
            None => return self.make_ack(),
        };
        self.rr_cursor = pos + 1;
        self.build(t, fi as u8, &data)
    }

    fn make_ack(&mut self) -> [u8; HS_FRAME_LEN] {
        // Report the oldest message with unreported changes first, so a completed message is
        // acknowledged even when fragments of the next one are already arriving.
        let t = (1..=MAX_MSG_TYPE)
            .find(|t| matches!(self.rx.get(usize::from(*t)), Some(Some(m)) if m.dirty))
            .unwrap_or(self.ack_type);
        let mut bm = [0u8; HS_DATA_LEN];
        if let Some(Some(m)) = self.rx.get_mut(usize::from(t)) {
            m.dirty = false;
            for (i, h) in m.have.iter().enumerate() {
                if *h {
                    if let Some(b) = bm.get_mut(i / 8) {
                        *b |= 1 << (i % 8);
                    }
                }
            }
        }
        self.ack_pending = self.rx.iter().flatten().any(|m| m.dirty && m.done);
        self.rx_since_ack = 0;
        self.last_ack_tick = Some(self.tick);
        self.build(FRAME_ACK, t, &bm)
    }

    fn build(&self, kind: u8, b1: u8, data: &[u8; HS_DATA_LEN]) -> [u8; HS_FRAME_LEN] {
        let mut f = [0u8; HS_FRAME_LEN];
        f[0] = HS_MAGIC | (kind & 0x0F);
        f[1] = b1;
        f[2] = self.tag;
        f[3..21].copy_from_slice(data);
        let crc = crc16_ccitt(&f[..21]);
        f[21..23].copy_from_slice(&crc.to_be_bytes());
        f
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(t: u8, seed: u8) -> Vec<u8> {
        let len = message_len(t).unwrap();
        (0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect()
    }

    /// Lockstep exchange; drop(n, a_to_b) decides losses. Returns delivered messages per side.
    fn run(
        a: &mut HsLink,
        b: &mut HsLink,
        slots: usize,
        mut drop: impl FnMut(usize, bool) -> bool,
    ) -> (Vec<(u8, Vec<u8>)>, Vec<(u8, Vec<u8>)>) {
        let (mut got_a, mut got_b) = (Vec::new(), Vec::new());
        for n in 0..slots {
            let fa = a.next_frame();
            let fb = b.next_frame();
            if !drop(n, true) {
                if let Some(m) = b.on_frame(&fa).unwrap() {
                    got_b.push(m);
                }
            }
            if !drop(n, false) {
                if let Some(m) = a.on_frame(&fb).unwrap() {
                    got_a.push(m);
                }
            }
        }
        (got_a, got_b)
    }

    #[test]
    fn messages_survive_loss_and_are_fully_acknowledged() {
        let mut a = HsLink::new(0x11);
        let mut b = HsLink::new(0x22);
        a.send(1, body(1, 1)).unwrap();
        b.send(1, body(1, 2)).unwrap();
        a.send(3, body(3, 3)).unwrap();
        let mut x = 0x9E37_79B9_7F4A_7C15u64;
        let (got_a, mut got_b) = run(&mut a, &mut b, 400, |_, _| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x % 100 < 10
        });
        got_b.sort();
        assert_eq!(got_a, vec![(1, body(1, 2))]);
        assert_eq!(got_b, vec![(1, body(1, 1)), (3, body(3, 3))]);
        assert!(a.all_acked() && b.all_acked());
        assert_eq!(a.peer_tag(), Some(0x22));
    }

    #[test]
    fn foreign_tag_crc_and_magic_are_dropped_and_abort_is_reported() {
        let mut a = HsLink::new(0x11);
        let mut b = HsLink::new(0x22);
        a.send(5, body(5, 9)).unwrap();
        let f = a.next_frame();
        assert_eq!(b.on_frame(&f), Ok(None));
        let other = HsLink::new(0x33).abort_frame(1);
        assert_eq!(b.on_frame(&other), Err(HsLinkError::ForeignTag));
        let mut bad = f;
        bad[5] ^= 1;
        assert_eq!(b.on_frame(&bad), Err(HsLinkError::BadCrc));
        assert_eq!(b.on_frame(&[0u8; HS_FRAME_LEN]).map_err(|e| e.is_fatal()), Err(false));
        assert_eq!(b.on_frame(&a.abort_frame(7)), Err(HsLinkError::PeerAbort(7)));
    }

    #[test]
    fn malformed_frames_with_a_valid_crc_are_fatal() {
        let a = HsLink::new(0x11);
        let mut b = HsLink::new(0x22);
        let bad_index = a.build(1, 5, &[0u8; HS_DATA_LEN]);
        assert_eq!(b.on_frame(&bad_index), Err(HsLinkError::BadIndex));
        let unknown = a.build(9, 0, &[0u8; HS_DATA_LEN]);
        assert_eq!(b.on_frame(&unknown), Err(HsLinkError::UnknownType));
        let first = a.build(5, 0, &[1u8; HS_DATA_LEN]);
        let conflict = a.build(5, 0, &[2u8; HS_DATA_LEN]);
        assert_eq!(b.on_frame(&first), Ok(None));
        assert_eq!(b.on_frame(&conflict), Err(HsLinkError::Conflict));
        let pad = a.build(5, 1, &[3u8; HS_DATA_LEN]);
        assert_eq!(b.on_frame(&pad), Err(HsLinkError::BadLength));
        assert!(HsLinkError::BadLength.is_fatal());
        let mut c = HsLink::new(1);
        assert_eq!(c.send(5, vec![0u8; 31]), Err(HsLinkError::BadLength));
        assert_eq!(c.send(8, vec![0u8; 32]), Err(HsLinkError::UnknownType));
        assert_eq!(c.send(7, vec![0u8; 3]), Err(HsLinkError::BadLength));
        c.send(7, vec![1, 0]).unwrap();
        c.send(5, vec![0u8; 32]).unwrap();
        assert_eq!(c.send(5, vec![0u8; 32]), Err(HsLinkError::DuplicateSend));
    }

    #[test]
    fn established_link_resends_only_the_last_message_and_ignores_everything_else() {
        let mut a = HsLink::new(0x11);
        let mut b = HsLink::new(0x22);
        a.send(1, body(1, 1)).unwrap();
        b.send(1, body(1, 2)).unwrap();
        run(&mut a, &mut b, 20, |_, _| false);
        a.send(6, body(6, 4)).unwrap();
        a.set_established(true);
        // HS1 of b re-sent after establishment, a foreign-tag frame and an ABORT change nothing.
        let peer_hs1 = b.build(1, 0, &[0u8; HS_DATA_LEN]);
        assert_eq!(a.on_frame(&peer_hs1), Ok(None));
        assert_eq!(a.on_frame(&b.abort_frame(3)), Ok(None));
        assert_eq!(a.on_frame(&HsLink::new(0x44).abort_frame(3)), Err(HsLinkError::ForeignTag));
        let mut sent = 0;
        while a.post_wants_tx() {
            let f = a.next_frame();
            assert!(f[0] == HS_MAGIC | 6 || f[0] == HS_MAGIC | FRAME_ACK);
            sent += 1;
        }
        assert!(sent <= POST_ESTABLISH_MAX_FRAMES as usize);
        // An ACK after establishment is not authenticated: even one covering every RS3 fragment
        // acknowledges nothing, and the fragments are still resent on the timer.
        let mut bm = [0u8; HS_DATA_LEN];
        bm[0] = 0x1F;
        let ack = b.build(FRAME_ACK, 6, &bm);
        assert_eq!(a.on_frame(&ack), Ok(None));
        assert!(!a.all_acked());
        assert_eq!(a.acked_fragments(), 0);
        let mut resent = 0;
        for _ in 0..POST_RESEND_TIMEOUT {
            if a.post_wants_tx() {
                assert_eq!(a.next_frame()[0], HS_MAGIC | 6);
                resent += 1;
            } else {
                a.skip_slot();
            }
        }
        assert!(resent > 0, "the timer resend stopped after a post-establishment ACK");
        a.close();
        assert!(a.is_closed() && !a.post_wants_tx());
        assert_eq!(a.on_frame(&b.abort_frame(1)), Ok(None));
    }

    #[test]
    fn acks_that_do_not_match_sent_fragments_are_dropped_before_the_keys() {
        let mut a = HsLink::new(0x11);
        let b = HsLink::new(0x22);
        a.send(4, body(4, 1)).unwrap();
        let ack = |t: u8, bm: [u8; HS_DATA_LEN]| b.build(FRAME_ACK, t, &bm);
        let mut first = [0u8; HS_DATA_LEN];
        first[0] = 0x01;
        // Nothing sent yet: an ACK of HS4 cannot be genuine and must not cancel any fragment.
        let mut all = [0u8; HS_DATA_LEN];
        all[0] = 0xFF;
        assert_eq!(a.on_frame(&ack(4, all)), Err(HsLinkError::UnexpectedAck));
        assert!(!HsLinkError::UnexpectedAck.is_fatal());
        assert_eq!(a.peer_tag(), None, "a dropped ACK locked the peer tag");
        assert_eq!(a.next_frame(), a.build(4, 0, &body(4, 1)[..HS_DATA_LEN].try_into().unwrap()));
        // Fragment 0 is out now; bits of unsent fragments, of fragments past the message, of a
        // type never queued, an empty bitmap for a real type or an unknown type are all dropped.
        let mut past = first;
        past[1] = 0x01;
        let mut unsent = first;
        unsent[0] = 0x03;
        for f in [ack(4, unsent), ack(4, past), ack(3, first), ack(4, [0u8; HS_DATA_LEN]), ack(9, first), ack(0, first)] {
            assert_eq!(a.on_frame(&f), Err(HsLinkError::UnexpectedAck));
        }
        assert_eq!(a.acked_fragments(), 0);
        assert_eq!(a.peer_tag(), None);
        // The idle ACK and an ACK of the fragment actually sent are accepted.
        assert_eq!(a.on_frame(&ack(0, [0u8; HS_DATA_LEN])), Ok(None));
        assert_eq!(a.peer_tag(), Some(0x22));
        assert_eq!(a.on_frame(&ack(4, first)), Ok(None));
        assert_eq!(a.acked_fragments(), 1);
    }

    #[test]
    fn post_establish_link_frames_are_capped() {
        let mut a = HsLink::new(0x11);
        a.set_resend_gap(1);
        a.send(4, body(4, 1)).unwrap();
        a.set_established(true);
        let mut sent = 0;
        for _ in 0..400 {
            if a.post_wants_tx() {
                let f = a.next_frame();
                assert_eq!(f[0], HS_MAGIC | 4, "no ACKs after establishment");
                sent += 1;
            } else {
                a.skip_slot();
            }
        }
        assert_eq!(sent, POST_ESTABLISH_MAX_FRAMES as usize);
    }
}
