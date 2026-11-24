//! Single-epoch superframe cipher (secure-session-v2 §6.4).
//!
//! Each epoch e has, per direction, a 32 B key, a 16 B nonce salt and a 32 B message base, all
//! from Expand(root_e, "ep" || BE32(e) || label). Wire format is unchanged from aead.rs:
//! counter(3) || ciphertext(14) || Poly1305 tag truncated to 6 bytes. The frame counter restarts
//! at 0 in every epoch. The receiver keeps the current epoch, the staged next epoch and (for 16
//! frames after a switch) the previous epoch's frame key, each with its own replay window.
//! Message keys are Expand(msg_base_{e,dir}, BE32(msg_id)) for the current and previous epoch.

use crate::handshake_v2::Role;
use crate::primitives::{expand, expand32};
use aegiscall_memsec::SecretKey32;
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::XChaCha20;
use poly1305::universal_hash::KeyInit;
use poly1305::Poly1305;
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

pub const EPOCH_SUPERFRAME_LEN: usize = 23;
pub const EPOCH_PAYLOAD_LEN: usize = 14;
const TAG_LEN: usize = 6;
/// Largest counter that fits the 3-byte wire field; sealing beyond it is refused.
pub const EPOCH_FRAME_COUNTER_MAX: u32 = 0x00FF_FFFF;
/// Frames accepted under the previous epoch's key after the first frame of the new epoch.
pub const OLD_RX_GRACE_FRAMES: u32 = 16;
/// Width of the epoch field carried in message fragments.
pub const MSG_EPOCH_MASK: u8 = 0x3F;
const REPLAY_WINDOW: u32 = 64;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum EpochError {
    #[error("superframe authentication failed")]
    AuthenticationFailed,
    #[error("superframe replay detected")]
    ReplayDetected,
    #[error("epoch was not staged")]
    NotStaged,
    #[error("epoch outside the kept window")]
    OutOfWindow,
    #[error("frame counter exhausted for this epoch")]
    CounterExhausted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenedFrame {
    pub epoch: u32,
    pub counter: u32,
    pub plaintext: [u8; EPOCH_PAYLOAD_LEN],
}

struct DirKeys {
    epoch: u32,
    key: SecretKey32,
    salt: Zeroizing<[u8; 16]>,
    msg_base: SecretKey32,
}

fn derive_dir(root: &SecretKey32, e: u32, i2r: bool) -> DirKeys {
    let ep = e.to_be_bytes();
    let (lk, ls, lm): (&[u8], &[u8], &[u8]) = if i2r {
        (b"key i2r", b"salt i2r", b"msg i2r")
    } else {
        (b"key r2i", b"salt r2i", b"msg r2i")
    };
    let key = expand32(root.as_bytes(), &[b"ep", &ep, lk]);
    let mut salt = Zeroizing::new([0u8; 16]);
    expand(root.as_bytes(), &[b"ep", &ep, ls], salt.as_mut_slice());
    let msg_base = expand32(root.as_bytes(), &[b"ep", &ep, lm]);
    DirKeys { epoch: e, key, salt, msg_base }
}

struct RxSlot {
    epoch: u32,
    frame_key: Option<(SecretKey32, Zeroizing<[u8; 16]>)>,
    msg_base: SecretKey32,
    max_counter: Option<u32>,
    bitmap: u64,
}

impl RxSlot {
    fn new(d: DirKeys) -> Self {
        Self {
            epoch: d.epoch,
            frame_key: Some((d.key, d.salt)),
            msg_base: d.msg_base,
            max_counter: None,
            bitmap: 0,
        }
    }

    fn check_replay(&self, counter: u32) -> Result<(), EpochError> {
        if let Some(max_c) = self.max_counter {
            if counter <= max_c {
                let diff = max_c - counter;
                if diff >= REPLAY_WINDOW || (self.bitmap >> diff) & 1 == 1 {
                    return Err(EpochError::ReplayDetected);
                }
            }
        }
        Ok(())
    }

    fn record(&mut self, counter: u32) {
        match self.max_counter {
            None => {
                self.max_counter = Some(counter);
                self.bitmap = 1;
            }
            Some(max_c) if counter > max_c => {
                let shift = counter - max_c;
                self.bitmap = if shift >= REPLAY_WINDOW { 1 } else { (self.bitmap << shift) | 1 };
                self.max_counter = Some(counter);
            }
            Some(max_c) => {
                let diff = max_c - counter;
                if diff < REPLAY_WINDOW {
                    self.bitmap |= 1u64 << diff;
                }
            }
        }
    }

    /// Returns the nonce if the wire tag verifies under this slot's frame key.
    fn verify(&self, aad_tag: &[u8; 4], c3: &[u8; 3], counter: u32, ct: &[u8; 14], wtag: &[u8]) -> Option<[u8; 24]> {
        let (key, salt) = self.frame_key.as_ref()?;
        let nonce = build_nonce(salt, self.epoch, counter);
        let aad = build_aad(self.epoch, c3, aad_tag);
        let full = sf_tag(key.as_bytes(), &nonce, &aad, ct);
        let ok = full.get(..TAG_LEN).map(|t| t.ct_eq(wtag).unwrap_u8() == 1).unwrap_or(false);
        if ok {
            Some(nonce)
        } else {
            None
        }
    }
}

fn build_nonce(salt: &[u8; 16], epoch: u32, counter: u32) -> [u8; 24] {
    let mut nonce = [0u8; 24];
    nonce[..16].copy_from_slice(salt);
    nonce[16..20].copy_from_slice(&epoch.to_be_bytes());
    let c = counter.to_be_bytes();
    nonce[21..24].copy_from_slice(&c[1..4]);
    nonce
}

fn build_aad(epoch: u32, c3: &[u8; 3], tag: &[u8; 4]) -> [u8; 11] {
    let mut aad = [0u8; 11];
    aad[..4].copy_from_slice(&epoch.to_be_bytes());
    aad[4..7].copy_from_slice(c3);
    aad[7..11].copy_from_slice(tag);
    aad
}

fn sf_tag(key: &[u8; 32], nonce: &[u8; 24], aad: &[u8; 11], ct: &[u8; 14]) -> [u8; 16] {
    let mut cipher = XChaCha20::new(key.into(), nonce.into());
    let mut otk = Zeroizing::new([0u8; 32]);
    cipher.apply_keystream(otk.as_mut_slice());
    let mut mac_input = [0u8; 48];
    mac_input[..11].copy_from_slice(aad);
    mac_input[16..30].copy_from_slice(ct);
    mac_input[32..40].copy_from_slice(&(aad.len() as u64).to_le_bytes());
    mac_input[40..48].copy_from_slice(&(ct.len() as u64).to_le_bytes());
    let poly = Poly1305::new((&*otk).into());
    let tag = poly.compute_unpadded(&mac_input);
    let mut out = [0u8; 16];
    out.copy_from_slice(tag.as_slice());
    out
}

fn keystream(key: &[u8; 32], nonce: &[u8; 24], buf: &mut [u8; 14]) {
    let mut cipher = XChaCha20::new(key.into(), nonce.into());
    cipher.seek(64);
    cipher.apply_keystream(buf);
}

fn msg_key(base: &SecretKey32, msg_id: u32) -> SecretKey32 {
    expand32(base.as_bytes(), &[&msg_id.to_be_bytes()])
}

pub struct EpochCipher {
    role: Role,
    tag: [u8; 4],
    tx: DirKeys,
    tx_counter: u32,
    tx_prev_msg: Option<(u32, SecretKey32)>,
    tx_staged: Option<DirKeys>,
    rx_cur: RxSlot,
    rx_prev: Option<RxSlot>,
    rx_staged: Option<RxSlot>,
    grace_left: u32,
}

impl EpochCipher {
    /// Epoch 0 keys from the handshake's root_0; tag is the 4-byte transcript tag (bound in AAD).
    pub fn from_root(root0: &SecretKey32, role: Role, tag: [u8; 4]) -> Self {
        let own_i2r = role == Role::Initiator;
        Self {
            role,
            tag,
            tx: derive_dir(root0, 0, own_i2r),
            tx_counter: 0,
            tx_prev_msg: None,
            tx_staged: None,
            rx_cur: RxSlot::new(derive_dir(root0, 0, !own_i2r)),
            rx_prev: None,
            rx_staged: None,
            grace_left: 0,
        }
    }

    pub fn tx_epoch(&self) -> u32 {
        self.tx.epoch
    }

    pub fn rx_epoch(&self) -> u32 {
        self.rx_cur.epoch
    }

    pub fn staged_epoch(&self) -> Option<u32> {
        self.rx_staged.as_ref().map(|s| s.epoch)
    }

    /// Derives epoch e from root_e: RX for e becomes receivable alongside the current epoch,
    /// TX for e is prepared for commit_tx_epoch. e must be exactly current + 1 and no other
    /// epoch may be staged.
    pub fn stage_rx_epoch(&mut self, root: &SecretKey32, e: u32) -> Result<(), EpochError> {
        let expected = self.rx_cur.epoch.checked_add(1).ok_or(EpochError::OutOfWindow)?;
        if e != expected || self.rx_staged.is_some() || self.tx_staged.is_some() || self.tx.epoch != self.rx_cur.epoch {
            return Err(EpochError::OutOfWindow);
        }
        let own_i2r = self.role == Role::Initiator;
        self.rx_staged = Some(RxSlot::new(derive_dir(root, e, !own_i2r)));
        self.tx_staged = Some(derive_dir(root, e, own_i2r));
        Ok(())
    }

    /// Switches TX to the staged epoch e and restarts the frame counter. The responder does this
    /// automatically on the first valid frame of e; calling it again for the active epoch is a no-op.
    pub fn commit_tx_epoch(&mut self, e: u32) -> Result<(), EpochError> {
        if self.tx.epoch == e && self.tx_staged.is_none() {
            return Ok(());
        }
        match self.tx_staged.take() {
            Some(d) if d.epoch == e => {
                let old = core::mem::replace(&mut self.tx, d);
                self.tx_prev_msg = Some((old.epoch, old.msg_base));
                self.tx_counter = 0;
                Ok(())
            }
            other => {
                self.tx_staged = other;
                Err(EpochError::NotStaged)
            }
        }
    }

    pub fn seal_superframe(&mut self, pt: &[u8; EPOCH_PAYLOAD_LEN]) -> Result<[u8; EPOCH_SUPERFRAME_LEN], EpochError> {
        if self.tx_counter > EPOCH_FRAME_COUNTER_MAX {
            return Err(EpochError::CounterExhausted);
        }
        let counter = self.tx_counter;
        self.tx_counter += 1;
        let cb = counter.to_be_bytes();
        let c3 = [cb[1], cb[2], cb[3]];
        let nonce = build_nonce(&self.tx.salt, self.tx.epoch, counter);
        let aad = build_aad(self.tx.epoch, &c3, &self.tag);
        let mut ct = *pt;
        keystream(self.tx.key.as_bytes(), &nonce, &mut ct);
        let tag = sf_tag(self.tx.key.as_bytes(), &nonce, &aad, &ct);
        let mut wire = [0u8; EPOCH_SUPERFRAME_LEN];
        wire[0..3].copy_from_slice(&c3);
        wire[3..17].copy_from_slice(&ct);
        wire[17..23].copy_from_slice(&tag[..TAG_LEN]);
        Ok(wire)
    }

    pub fn open_superframe(&mut self, wire: &[u8; EPOCH_SUPERFRAME_LEN]) -> Result<OpenedFrame, EpochError> {
        let c3 = [wire[0], wire[1], wire[2]];
        let counter = u32::from_be_bytes([0, c3[0], c3[1], c3[2]]);
        let mut ct = [0u8; EPOCH_PAYLOAD_LEN];
        ct.copy_from_slice(&wire[3..17]);
        let wtag = &wire[17..23];

        if let Some(nonce) = self.rx_cur.verify(&self.tag, &c3, counter, &ct, wtag) {
            self.rx_cur.check_replay(counter)?;
            self.rx_cur.record(counter);
            let out = Self::decrypt(&self.rx_cur, &nonce, counter, ct);
            self.count_grace();
            return out;
        }
        let staged_nonce = self
            .rx_staged
            .as_ref()
            .and_then(|s| s.verify(&self.tag, &c3, counter, &ct, wtag));
        if let Some(nonce) = staged_nonce {
            let mut staged = self.rx_staged.take().ok_or(EpochError::NotStaged)?;
            staged.record(counter);
            let out = Self::decrypt(&staged, &nonce, counter, ct);
            let old = core::mem::replace(&mut self.rx_cur, staged);
            self.rx_prev = Some(old);
            self.grace_left = OLD_RX_GRACE_FRAMES;
            if self.role == Role::Responder {
                let e = self.rx_cur.epoch;
                if self.tx_staged.as_ref().is_some_and(|d| d.epoch == e) {
                    self.commit_tx_epoch(e)?;
                }
            }
            return out;
        }
        let prev_nonce = self
            .rx_prev
            .as_ref()
            .and_then(|s| s.verify(&self.tag, &c3, counter, &ct, wtag));
        if let Some(nonce) = prev_nonce {
            let prev = self.rx_prev.as_mut().ok_or(EpochError::AuthenticationFailed)?;
            prev.check_replay(counter)?;
            prev.record(counter);
            let out = match self.rx_prev.as_ref() {
                Some(p) => Self::decrypt(p, &nonce, counter, ct),
                None => Err(EpochError::AuthenticationFailed),
            };
            self.count_grace();
            return out;
        }
        Err(EpochError::AuthenticationFailed)
    }

    fn decrypt(slot: &RxSlot, nonce: &[u8; 24], counter: u32, mut ct: [u8; 14]) -> Result<OpenedFrame, EpochError> {
        let (key, _) = slot.frame_key.as_ref().ok_or(EpochError::AuthenticationFailed)?;
        keystream(key.as_bytes(), nonce, &mut ct);
        Ok(OpenedFrame { epoch: slot.epoch, counter, plaintext: ct })
    }

    fn count_grace(&mut self) {
        if let Some(prev) = self.rx_prev.as_mut() {
            if prev.frame_key.is_some() {
                self.grace_left = self.grace_left.saturating_sub(1);
                if self.grace_left == 0 {
                    prev.frame_key = None;
                }
            }
        }
    }

    /// Message key for an outgoing message labelled with epoch (current or previous TX epoch).
    pub fn tx_message_key(&self, epoch: u32, msg_id: u32) -> Result<SecretKey32, EpochError> {
        if epoch == self.tx.epoch {
            return Ok(msg_key(&self.tx.msg_base, msg_id));
        }
        match &self.tx_prev_msg {
            Some((e, base)) if *e == epoch => Ok(msg_key(base, msg_id)),
            _ => Err(EpochError::OutOfWindow),
        }
    }

    /// Message key for an incoming message whose fragment carries the 6-bit epoch field.
    /// Only the current and previous RX epochs are accepted.
    pub fn rx_message_key(&self, epoch6: u8, msg_id: u32) -> Result<(u32, SecretKey32), EpochError> {
        if epoch6 & !MSG_EPOCH_MASK != 0 {
            return Err(EpochError::OutOfWindow);
        }
        if (self.rx_cur.epoch as u8) & MSG_EPOCH_MASK == epoch6 {
            return Ok((self.rx_cur.epoch, msg_key(&self.rx_cur.msg_base, msg_id)));
        }
        match &self.rx_prev {
            Some(p) if (p.epoch as u8) & MSG_EPOCH_MASK == epoch6 => Ok((p.epoch, msg_key(&p.msg_base, msg_id))),
            _ => Err(EpochError::OutOfWindow),
        }
    }
}

impl Drop for EpochCipher {
    fn drop(&mut self) {
        self.tag.zeroize();
        self.tx.key.zeroize();
        self.tx.salt.zeroize();
        self.tx.msg_base.zeroize();
        self.rx_cur.msg_base.zeroize();
        // Each of these zeroizes its keys when dropped.
        self.rx_cur.frame_key = None;
        self.tx_prev_msg = None;
        self.tx_staged = None;
        self.rx_prev = None;
        self.rx_staged = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (EpochCipher, EpochCipher) {
        let root = SecretKey32::from_bytes([0x42; 32]);
        (
            EpochCipher::from_root(&root, Role::Initiator, [1, 2, 3, 4]),
            EpochCipher::from_root(&root, Role::Responder, [1, 2, 3, 4]),
        )
    }

    #[test]
    fn seal_open_both_directions_replay_and_tamper() {
        let (mut i, mut r) = pair();
        let _lost = i.seal_superframe(&[5u8; 14]).unwrap();
        let f1 = i.seal_superframe(&[7u8; 14]).unwrap();
        let o = r.open_superframe(&f1).unwrap();
        assert_eq!((o.epoch, o.counter, o.plaintext), (0, 1, [7u8; 14]));
        assert_eq!(r.open_superframe(&f1), Err(EpochError::ReplayDetected));
        let g = r.seal_superframe(&[9u8; 14]).unwrap();
        assert_eq!(i.open_superframe(&g).unwrap().plaintext, [9u8; 14]);
        // A frame sealed in one direction never opens in the same direction.
        let mut r2 = pair().1;
        assert_eq!(r2.open_superframe(&g), Err(EpochError::AuthenticationFailed));
        for pos in [0usize, 3, 16, 17, 22] {
            let mut t = i.seal_superframe(&[1u8; 14]).unwrap();
            t[pos] ^= 0x01;
            assert_eq!(r.open_superframe(&t), Err(EpochError::AuthenticationFailed));
        }
        // Different transcript tag => different AAD.
        let root = SecretKey32::from_bytes([0x42; 32]);
        let mut other = EpochCipher::from_root(&root, Role::Responder, [9, 9, 9, 9]);
        let f = i.seal_superframe(&[2u8; 14]).unwrap();
        assert_eq!(other.open_superframe(&f), Err(EpochError::AuthenticationFailed));
    }

    #[test]
    fn counter_exhaustion_refuses_to_reuse_nonces() {
        let (mut i, _) = pair();
        i.tx_counter = EPOCH_FRAME_COUNTER_MAX;
        assert!(i.seal_superframe(&[0; 14]).is_ok());
        assert_eq!(i.seal_superframe(&[0; 14]), Err(EpochError::CounterExhausted));
    }

    #[test]
    fn staging_rules_and_counter_reset() {
        let (mut i, mut r) = pair();
        let root1 = SecretKey32::from_bytes([0x11; 32]);
        assert_eq!(i.stage_rx_epoch(&root1, 2), Err(EpochError::OutOfWindow));
        assert_eq!(i.commit_tx_epoch(1), Err(EpochError::NotStaged));
        for _ in 0..5 {
            i.seal_superframe(&[0; 14]).unwrap();
        }
        i.stage_rx_epoch(&root1, 1).unwrap();
        assert_eq!(i.stage_rx_epoch(&root1, 1), Err(EpochError::OutOfWindow));
        i.commit_tx_epoch(1).unwrap();
        r.stage_rx_epoch(&root1, 1).unwrap();
        let f = i.seal_superframe(&[3; 14]).unwrap();
        let o = r.open_superframe(&f).unwrap();
        assert_eq!((o.epoch, o.counter), (1, 0));
        assert_eq!(r.tx_epoch(), 1);
        assert_eq!(r.rx_epoch(), 1);
    }

    #[test]
    fn old_epoch_frame_key_is_purged_after_16_frames() {
        let (mut i, mut r) = pair();
        let held_a = i.seal_superframe(&[0xA; 14]).unwrap();
        let held_b = i.seal_superframe(&[0xB; 14]).unwrap();
        let root1 = SecretKey32::from_bytes([0x22; 32]);
        i.stage_rx_epoch(&root1, 1).unwrap();
        i.commit_tx_epoch(1).unwrap();
        r.stage_rx_epoch(&root1, 1).unwrap();
        r.open_superframe(&i.seal_superframe(&[0; 14]).unwrap()).unwrap();
        // Late frame from epoch 0 still opens inside the grace window.
        assert_eq!(r.open_superframe(&held_a).unwrap().epoch, 0);
        for _ in 0..15 {
            r.open_superframe(&i.seal_superframe(&[0; 14]).unwrap()).unwrap();
        }
        assert_eq!(r.open_superframe(&held_b), Err(EpochError::AuthenticationFailed));
        // Message keys of the previous epoch remain available.
        assert!(r.rx_message_key(0, 1).is_ok());
    }
}
