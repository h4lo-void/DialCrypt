//! Single-epoch superframe cipher with intra-epoch symmetric KDF chain ratcheting (secure-session-v2 §6.4).
//!
//! Each epoch e derives per-direction initial chain keys (`chain_key`, `msg_chain_key`) and a 16 B
//! nonce salt from `Expand(root_e, "ep" || BE32(e) || label)`. Every superframe steps the symmetric
//! frame chain `(frame_key_c, chain_key_{c+1}) = Step(chain_key_c, c)` and wipes `frame_key_c` as
//! soon as the frame is sealed or opened, providing immediate per-superframe forward secrecy within
//! an epoch. Out-of-order frames within the 64-frame replay window retain only skipped keys (capped
//! at 64 entries). Message keys likewise advance a one-way message chain and are retired right after
//! single use. Because wire tags are truncated to 48 bits, authentication failures are counted per
//! RX epoch: reaching [`REKEY_AUTH_FAILURES`] requests an early DH ratchet, and exceeding
//! [`MAX_EPOCH_AUTH_FAILURES`] aborts the epoch with [`EpochError::ForgeryLimitExceeded`].

use crate::handshake_v2::Role;
use crate::primitives::{expand, expand32};
use aegiscall_memsec::SecretKey32;
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::XChaCha20;
use poly1305::universal_hash::KeyInit;
use poly1305::Poly1305;
use std::collections::{BTreeMap, VecDeque};
use std::sync::Mutex;
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
/// Maximum forward counter jump accepted in one step (prevents CPU DoS on forged headers).
pub const MAX_COUNTER_SKIP: u32 = 1_024;
/// Per-epoch authentication failures before requesting an early DH ratchet step.
pub const REKEY_AUTH_FAILURES: u32 = 64;
/// Hard ceiling on failed tag verifications in a single epoch (bounds 48-bit tag forgery < 2^-36).
pub const MAX_EPOCH_AUTH_FAILURES: u32 = 4_096;

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
    #[error("epoch forgery attempt limit exceeded")]
    ForgeryLimitExceeded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenedFrame {
    pub epoch: u32,
    pub counter: u32,
    pub plaintext: [u8; EPOCH_PAYLOAD_LEN],
}

fn step_frame_chain(chain_key: &SecretKey32, counter: u32) -> (SecretKey32, SecretKey32) {
    let cb = counter.to_be_bytes();
    let frame_key = expand32(chain_key.as_bytes(), &[b"sf-key", &cb]);
    let next_chain = expand32(chain_key.as_bytes(), &[b"sf-next", &cb]);
    (frame_key, next_chain)
}

struct MsgChain {
    chain_key: SecretKey32,
    next_seq: u32,
    window: BTreeMap<u32, (u32, SecretKey32)>,
}

impl MsgChain {
    fn new(base: SecretKey32) -> Self {
        Self { chain_key: base, next_seq: 0, window: BTreeMap::new() }
    }

    fn seq_of(msg_id: u32) -> u32 {
        msg_id & 0x7FFF
    }

    fn derive_or_get(&mut self, msg_id: u32) -> Result<SecretKey32, EpochError> {
        let seq = Self::seq_of(msg_id);
        if seq < self.next_seq {
            return match self.window.get(&seq) {
                Some((stored_id, key)) if *stored_id == msg_id => Ok(key.clone()),
                _ => Err(EpochError::OutOfWindow),
            };
        }
        if seq.saturating_sub(self.next_seq) > MAX_COUNTER_SKIP {
            return Err(EpochError::OutOfWindow);
        }
        while self.next_seq <= seq {
            let s = self.next_seq;
            let sb = s.to_be_bytes();
            let item_seed = expand32(self.chain_key.as_bytes(), &[b"msg-step", &sb]);
            let next_ck = expand32(self.chain_key.as_bytes(), &[b"msg-next", &sb]);
            self.chain_key = next_ck;
            let id_for_slot = if s == seq { msg_id } else { s };
            let mk = expand32(item_seed.as_bytes(), &[b"msg-id", &id_for_slot.to_be_bytes()]);
            self.window.insert(s, (id_for_slot, mk));
            self.next_seq += 1;
        }
        while self.window.len() > REPLAY_WINDOW as usize {
            if let Some((&oldest, _)) = self.window.iter().next() {
                self.window.remove(&oldest);
            } else {
                break;
            }
        }
        self.window
            .get(&seq)
            .and_then(|(id, k)| {
                if *id == msg_id {
                    Some(k.clone())
                } else {
                    None
                }
            })
            .ok_or(EpochError::OutOfWindow)
    }

    fn retire(&mut self, msg_id: u32) {
        let seq = Self::seq_of(msg_id);
        if self.window.get(&seq).is_some_and(|(id, _)| *id == msg_id) {
            self.window.remove(&seq);
        }
    }

    fn wipe(&mut self) {
        self.chain_key.zeroize();
        self.window.clear();
    }
}

struct DirKeys {
    epoch: u32,
    chain_key: SecretKey32,
    salt: Zeroizing<[u8; 16]>,
    msg_chain: Mutex<MsgChain>,
}

fn derive_dir(root: &SecretKey32, e: u32, i2r: bool) -> DirKeys {
    let ep = e.to_be_bytes();
    let (lk, ls, lm): (&[u8], &[u8], &[u8]) = if i2r {
        (b"key i2r", b"salt i2r", b"msg i2r")
    } else {
        (b"key r2i", b"salt r2i", b"msg r2i")
    };
    let chain_key = expand32(root.as_bytes(), &[b"ep", &ep, lk]);
    let mut salt = Zeroizing::new([0u8; 16]);
    expand(root.as_bytes(), &[b"ep", &ep, ls], salt.as_mut_slice());
    let msg_base = expand32(root.as_bytes(), &[b"ep", &ep, lm]);
    DirKeys {
        epoch: e,
        chain_key,
        salt,
        msg_chain: Mutex::new(MsgChain::new(msg_base)),
    }
}

struct RxFrameChain {
    chain_key: SecretKey32,
    salt: Zeroizing<[u8; 16]>,
    next_counter: u32,
    skipped: BTreeMap<u32, SecretKey32>,
}

impl Drop for RxFrameChain {
    fn drop(&mut self) {
        self.chain_key.zeroize();
        self.salt.zeroize();
        self.skipped.clear();
    }
}

struct RxSlot {
    epoch: u32,
    frame_chain: Option<RxFrameChain>,
    msg_chain: Mutex<MsgChain>,
    max_counter: Option<u32>,
    bitmap: u64,
    seen_tags: VecDeque<(u32, [u8; TAG_LEN])>,
}

impl RxSlot {
    fn new(d: DirKeys) -> Self {
        Self {
            epoch: d.epoch,
            frame_chain: Some(RxFrameChain {
                chain_key: d.chain_key,
                salt: d.salt,
                next_counter: 0,
                skipped: BTreeMap::new(),
            }),
            msg_chain: d.msg_chain,
            max_counter: None,
            bitmap: 0,
            seen_tags: VecDeque::with_capacity(REPLAY_WINDOW as usize),
        }
    }

    fn is_exact_replay(&self, counter: u32, wtag: &[u8]) -> bool {
        let Ok(t6) = <[u8; TAG_LEN]>::try_from(wtag) else { return false };
        self.seen_tags
            .iter()
            .any(|(c, saved)| *c == counter && saved.ct_eq(&t6).unwrap_u8() == 1)
    }

    fn is_older_than_window(&self, counter: u32) -> bool {
        matches!(self.max_counter, Some(max_c) if counter <= max_c && max_c - counter >= REPLAY_WINDOW)
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

    fn record(&mut self, counter: u32, wtag: &[u8]) {
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
        if let Ok(t6) = <[u8; TAG_LEN]>::try_from(wtag) {
            if self.seen_tags.len() >= REPLAY_WINDOW as usize {
                self.seen_tags.pop_front();
            }
            self.seen_tags.push_back((counter, t6));
        }
        if let (Some(fc), Some(max_c)) = (self.frame_chain.as_mut(), self.max_counter) {
            let min_keep = max_c.saturating_sub(REPLAY_WINDOW - 1);
            fc.skipped.retain(|&c, _| c >= min_keep);
            while fc.skipped.len() > REPLAY_WINDOW as usize {
                if let Some(&oldest) = fc.skipped.keys().next() {
                    fc.skipped.remove(&oldest);
                } else {
                    break;
                }
            }
        }
    }

    /// Verifies `wtag` without mutating chain state on failure; on success commits the chain step,
    /// consumes and returns the single-use `(frame_key, nonce)` for decryption.
    fn verify_and_consume(
        &mut self,
        aad_tag: &[u8; 4],
        c3: &[u8; 3],
        counter: u32,
        ct: &[u8; 14],
        wtag: &[u8],
    ) -> Result<Option<(SecretKey32, [u8; 24])>, EpochError> {
        let (salt, next_counter) = match self.frame_chain.as_ref() {
            Some(fc) => (fc.salt.clone(), fc.next_counter),
            None => return Ok(None),
        };
        let nonce = build_nonce(&salt, self.epoch, counter);
        let aad = build_aad(self.epoch, c3, aad_tag);

        if counter < next_counter {
            if self.is_exact_replay(counter, wtag) {
                return Err(EpochError::ReplayDetected);
            }
            let ok = {
                let Some(sk) = self.frame_chain.as_ref().and_then(|fc| fc.skipped.get(&counter)) else {
                    return Ok(None);
                };
                let full = sf_tag(sk.as_bytes(), &nonce, &aad, ct);
                full.get(..TAG_LEN).map(|t| t.ct_eq(wtag).unwrap_u8() == 1).unwrap_or(false)
            };
            if !ok {
                return Ok(None);
            }
            self.check_replay(counter)?;
            let used_key = self
                .frame_chain
                .as_mut()
                .and_then(|fc| fc.skipped.remove(&counter))
                .ok_or(EpochError::AuthenticationFailed)?;
            self.record(counter, wtag);
            return Ok(Some((used_key, nonce)));
        }

        if counter.saturating_sub(next_counter) > MAX_COUNTER_SKIP {
            return Ok(None);
        }

        // Speculatively step a temporary copy so invalid tags never advance RxFrameChain
        let mut tmp_ck = match self.frame_chain.as_ref() {
            Some(fc) => fc.chain_key.clone(),
            None => return Ok(None),
        };
        let mut pending_skipped: Vec<(u32, SecretKey32)> =
            Vec::with_capacity((counter - next_counter) as usize);
        let mut c = next_counter;
        while c < counter {
            let (fk, nck) = step_frame_chain(&tmp_ck, c);
            tmp_ck = nck;
            pending_skipped.push((c, fk));
            c += 1;
        }
        let (target_fk, final_ck) = step_frame_chain(&tmp_ck, counter);
        drop(tmp_ck);

        let full = sf_tag(target_fk.as_bytes(), &nonce, &aad, ct);
        let ok = full.get(..TAG_LEN).map(|t| t.ct_eq(wtag).unwrap_u8() == 1).unwrap_or(false);
        if !ok {
            return Ok(None);
        }

        self.check_replay(counter)?;
        if let Some(fc) = self.frame_chain.as_mut() {
            fc.chain_key = final_ck;
            fc.next_counter = counter.saturating_add(1);
            for (sc, sfk) in pending_skipped {
                fc.skipped.insert(sc, sfk);
            }
        }
        self.record(counter, wtag);
        Ok(Some((target_fk, nonce)))
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

pub struct EpochCipher {
    role: Role,
    tag: [u8; 4],
    tx: DirKeys,
    tx_counter: u32,
    tx_prev_msg: Option<(u32, Mutex<MsgChain>)>,
    tx_staged: Option<DirKeys>,
    rx_cur: RxSlot,
    rx_prev: Option<RxSlot>,
    rx_staged: Option<RxSlot>,
    grace_left: u32,
    auth_failures: u32,
    rekey_signaled: bool,
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
            auth_failures: 0,
            rekey_signaled: false,
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

    /// Failed tag checks accumulated in the active RX epoch.
    pub fn auth_failures(&self) -> u32 {
        self.auth_failures
    }

    /// True once failed superframe verifications in the active epoch reach [`REKEY_AUTH_FAILURES`].
    pub fn needs_rekey(&self) -> bool {
        self.auth_failures >= REKEY_AUTH_FAILURES
    }

    /// Latches and returns `true` at most once per RX epoch when [`REKEY_AUTH_FAILURES`] is reached.
    pub fn take_rekey_signal(&mut self) -> bool {
        if self.auth_failures >= REKEY_AUTH_FAILURES && !self.rekey_signaled {
            self.rekey_signaled = true;
            true
        } else {
            false
        }
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
                let mut old = core::mem::replace(&mut self.tx, d);
                old.chain_key.zeroize();
                old.salt.zeroize();
                self.tx_prev_msg = Some((old.epoch, old.msg_chain));
                self.tx_counter = 0;
                self.auth_failures = 0;
                self.rekey_signaled = false;
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
        let (frame_key, next_ck) = step_frame_chain(&self.tx.chain_key, counter);
        self.tx.chain_key = next_ck;

        let cb = counter.to_be_bytes();
        let c3 = [cb[1], cb[2], cb[3]];
        let nonce = build_nonce(&self.tx.salt, self.tx.epoch, counter);
        let aad = build_aad(self.tx.epoch, &c3, &self.tag);
        let mut ct = *pt;
        keystream(frame_key.as_bytes(), &nonce, &mut ct);
        let tag = sf_tag(frame_key.as_bytes(), &nonce, &aad, &ct);
        drop(frame_key);
        let mut wire = [0u8; EPOCH_SUPERFRAME_LEN];
        wire[0..3].copy_from_slice(&c3);
        wire[3..17].copy_from_slice(&ct);
        wire[17..23].copy_from_slice(&tag[..TAG_LEN]);
        Ok(wire)
    }

    pub fn open_superframe(&mut self, wire: &[u8; EPOCH_SUPERFRAME_LEN]) -> Result<OpenedFrame, EpochError> {
        if self.auth_failures >= MAX_EPOCH_AUTH_FAILURES {
            return Err(EpochError::ForgeryLimitExceeded);
        }
        let c3 = [wire[0], wire[1], wire[2]];
        let counter = u32::from_be_bytes([0, c3[0], c3[1], c3[2]]);
        let mut ct = [0u8; EPOCH_PAYLOAD_LEN];
        ct.copy_from_slice(&wire[3..17]);
        let wtag = &wire[17..23];

        // 1. Staged next epoch first if it matches, so counter=0 of epoch e+1 never collides with
        //    epoch e's replay table.
        if let Some(staged) = self.rx_staged.as_mut() {
            if let Some((fk, nonce)) = staged.verify_and_consume(&self.tag, &c3, counter, &ct, wtag)? {
                let Some(promoted) = self.rx_staged.take() else {
                    return Err(EpochError::NotStaged);
                };
                let epoch = promoted.epoch;
                let out = Self::decrypt_with_key(epoch, &fk, &nonce, counter, ct);
                drop(fk);
                let old = core::mem::replace(&mut self.rx_cur, promoted);
                self.rx_prev = Some(old);
                self.grace_left = OLD_RX_GRACE_FRAMES;
                self.auth_failures = 0;
                self.rekey_signaled = false;
                if self.role == Role::Responder && self.tx_staged.as_ref().is_some_and(|d| d.epoch == epoch) {
                    self.commit_tx_epoch(epoch)?;
                }
                return out;
            }
        }

        // 2. Current RX epoch
        match self.rx_cur.verify_and_consume(&self.tag, &c3, counter, &ct, wtag) {
            Ok(Some((fk, nonce))) => {
                let out = Self::decrypt_with_key(self.rx_cur.epoch, &fk, &nonce, counter, ct);
                drop(fk);
                self.count_grace();
                return out;
            }
            Err(EpochError::ReplayDetected) => return Err(EpochError::ReplayDetected),
            Err(e) => return Err(e),
            Ok(None) => {}
        }

        // 3. Previous RX epoch inside the 16-frame grace window
        if let Some(prev) = self.rx_prev.as_mut() {
            match prev.verify_and_consume(&self.tag, &c3, counter, &ct, wtag) {
                Ok(Some((fk, nonce))) => {
                    let out = Self::decrypt_with_key(prev.epoch, &fk, &nonce, counter, ct);
                    drop(fk);
                    self.count_grace();
                    return out;
                }
                Err(EpochError::ReplayDetected) => return Err(EpochError::ReplayDetected),
                Err(e) => return Err(e),
                Ok(None) => {}
            }
        }

        if self.rx_cur.is_older_than_window(counter) {
            return Err(EpochError::ReplayDetected);
        }

        self.auth_failures = self.auth_failures.saturating_add(1);
        if self.auth_failures >= MAX_EPOCH_AUTH_FAILURES {
            return Err(EpochError::ForgeryLimitExceeded);
        }
        Err(EpochError::AuthenticationFailed)
    }

    fn decrypt_with_key(
        epoch: u32,
        frame_key: &SecretKey32,
        nonce: &[u8; 24],
        counter: u32,
        mut ct: [u8; 14],
    ) -> Result<OpenedFrame, EpochError> {
        keystream(frame_key.as_bytes(), nonce, &mut ct);
        Ok(OpenedFrame { epoch, counter, plaintext: ct })
    }

    fn count_grace(&mut self) {
        if let Some(prev) = self.rx_prev.as_mut() {
            if prev.frame_chain.is_some() {
                self.grace_left = self.grace_left.saturating_sub(1);
                if self.grace_left == 0 {
                    prev.frame_chain = None;
                }
            }
        }
    }

    /// Message key for an outgoing message labelled with epoch (current or previous TX epoch).
    pub fn tx_message_key(&self, epoch: u32, msg_id: u32) -> Result<SecretKey32, EpochError> {
        if epoch == self.tx.epoch {
            return self
                .tx
                .msg_chain
                .lock()
                .map_err(|_| EpochError::OutOfWindow)?
                .derive_or_get(msg_id);
        }
        match &self.tx_prev_msg {
            Some((e, chain)) if *e == epoch => {
                chain.lock().map_err(|_| EpochError::OutOfWindow)?.derive_or_get(msg_id)
            }
            _ => Err(EpochError::OutOfWindow),
        }
    }

    /// Wipes an outgoing message key from the forward chain window right after single use.
    pub fn retire_tx_message_key(&mut self, epoch: u32, msg_id: u32) {
        if epoch == self.tx.epoch {
            if let Ok(mut g) = self.tx.msg_chain.lock() {
                g.retire(msg_id);
            }
        } else if let Some((e, chain)) = &self.tx_prev_msg {
            if *e == epoch {
                if let Ok(mut g) = chain.lock() {
                    g.retire(msg_id);
                }
            }
        }
    }

    /// Message key for an incoming message whose fragment carries the 6-bit epoch field.
    /// Only the current and previous RX epochs are accepted.
    pub fn rx_message_key(&self, epoch6: u8, msg_id: u32) -> Result<(u32, SecretKey32), EpochError> {
        if epoch6 & !MSG_EPOCH_MASK != 0 {
            return Err(EpochError::OutOfWindow);
        }
        if (self.rx_cur.epoch as u8) & MSG_EPOCH_MASK == epoch6 {
            let k = self
                .rx_cur
                .msg_chain
                .lock()
                .map_err(|_| EpochError::OutOfWindow)?
                .derive_or_get(msg_id)?;
            return Ok((self.rx_cur.epoch, k));
        }
        match &self.rx_prev {
            Some(p) if (p.epoch as u8) & MSG_EPOCH_MASK == epoch6 => {
                let k = p.msg_chain.lock().map_err(|_| EpochError::OutOfWindow)?.derive_or_get(msg_id)?;
                Ok((p.epoch, k))
            }
            _ => Err(EpochError::OutOfWindow),
        }
    }

    /// Wipes an incoming message key from the forward chain window right after single use.
    pub fn retire_rx_message_key(&mut self, epoch: u32, msg_id: u32) {
        if self.rx_cur.epoch == epoch {
            if let Ok(mut g) = self.rx_cur.msg_chain.lock() {
                g.retire(msg_id);
            }
        } else if let Some(p) = &self.rx_prev {
            if p.epoch == epoch {
                if let Ok(mut g) = p.msg_chain.lock() {
                    g.retire(msg_id);
                }
            }
        }
    }
}

impl Drop for EpochCipher {
    fn drop(&mut self) {
        self.tag.zeroize();
        self.tx.chain_key.zeroize();
        self.tx.salt.zeroize();
        if let Ok(mut g) = self.tx.msg_chain.lock() {
            g.wipe();
        }
        if let Ok(mut g) = self.rx_cur.msg_chain.lock() {
            g.wipe();
        }
        self.rx_cur.frame_chain = None;
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

    #[test]
    fn intra_epoch_chain_ratchet_and_message_key_retirement_enforce_forward_secrecy() {
        let (mut i, mut r) = pair();
        let f0 = i.seal_superframe(&[0x10; 14]).unwrap();
        let f1 = i.seal_superframe(&[0x20; 14]).unwrap();
        let f2 = i.seal_superframe(&[0x30; 14]).unwrap();

        // Out-of-order delivery: f2 first, then f0, then f1
        assert_eq!(r.open_superframe(&f2).unwrap().plaintext, [0x30; 14]);
        assert_eq!(r.open_superframe(&f0).unwrap().plaintext, [0x10; 14]);
        assert_eq!(r.open_superframe(&f1).unwrap().plaintext, [0x20; 14]);
        // Consumed keys are gone from skipped map
        assert!(r.rx_cur.frame_chain.as_ref().unwrap().skipped.is_empty());

        // Message key retirement wipes single-use message keys immediately
        let mk = i.tx_message_key(0, 5).unwrap();
        let (_, rk) = r.rx_message_key(0, 5).unwrap();
        assert_eq!(mk.as_bytes(), rk.as_bytes());
        i.retire_tx_message_key(0, 5);
        r.retire_rx_message_key(0, 5);
        assert_eq!(i.tx_message_key(0, 5).err(), Some(EpochError::OutOfWindow));
        assert_eq!(r.rx_message_key(0, 5).err(), Some(EpochError::OutOfWindow));
    }

    #[test]
    fn forgery_counter_requests_rekey_and_caps_48bit_tag_attempts() {
        let (mut i, mut r) = pair();
        let mut bad = i.seal_superframe(&[0x55; 14]).unwrap();
        bad[22] ^= 0x80;
        for _ in 0..REKEY_AUTH_FAILURES {
            assert!(!r.needs_rekey());
            assert_eq!(r.open_superframe(&bad), Err(EpochError::AuthenticationFailed));
        }
        assert!(r.needs_rekey());
        for _ in REKEY_AUTH_FAILURES..(MAX_EPOCH_AUTH_FAILURES - 1) {
            assert_eq!(r.open_superframe(&bad), Err(EpochError::AuthenticationFailed));
        }
        assert_eq!(r.open_superframe(&bad), Err(EpochError::ForgeryLimitExceeded));
        assert_eq!(r.open_superframe(&bad), Err(EpochError::ForgeryLimitExceeded));
    }
}
