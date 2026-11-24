//! DH ratchet (secure-session-v2 §6.4): only the initiator starts a step; one step at a time.
//!
//! I sends DH_RATCHET (fresh X25519 public key) in epoch e, R answers DH_RATCHET_ACK with its
//! own fresh key. Both compute root_{e+1} = Extract(root_e, dh || [ss || SHA-384(ek || ct)])[..32]
//! (the bracket only when the PQ flag is set). R stages RX on receipt and commits TX on the first
//! valid e+1 frame (EpochCipher does that); I stages and commits when the ACK arrives.
//!
//! §6.11: until R commits, its epoch, root and frame count stay untouched and any DH_RATCHET
//! for another step is refused. Feed the epoch of every valid frame to
//! [DhRatchet::note_valid_frame]; a step counts as complete once both sides are in the new
//! epoch, and only then is [DhRatchet::resume_next_pq] available.
//! Each message is 3 fragments of 13 B: epoch_lsb(1) || (flags:4 | index:4) || data(11);
//! the 33 data bytes are the 32 B public key followed by one zero byte.

use crate::handshake_v2::Role;
use crate::primitives::{expand32, extract, kem_decapsulate, kem_encapsulate, kem_generate, sha384, DecapKey};
use aegiscall_memsec::SecretKey32;
use rand_core::CryptoRngCore;
use subtle::ConstantTimeEq;
use thiserror::Error;
use x25519_dalek::{PublicKey as XPublic, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

pub const RATCHET_INTERVAL_FRAMES: u32 = 375;
/// After the interval expires, the step must finish within this many frames or the session ends.
pub const RATCHET_DEADLINE_FRAMES: u32 = 1500;
pub const RATCHET_FRAGMENT_COUNT: usize = 3;
pub const RATCHET_FRAGMENT_LEN: usize = 13;
pub const RATCHET_FRAGMENT_DATA_LEN: usize = 11;
pub const RATCHET_FLAG_PQ: u8 = 0x01;
pub const PQ_EK_LEN: usize = 1568;
pub const PQ_CT_LEN: usize = 1568;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum RatchetError {
    #[error("malformed ratchet fragment")]
    Malformed,
    #[error("operation not allowed for this role")]
    WrongRole,
    #[error("ratchet protocol violation")]
    Protocol,
    #[error("PQ flag set but no PQ secret is available")]
    PqMissing,
    #[error("invalid or low-order X25519 public key")]
    InvalidPublicKey,
    #[error("ratchet deadline exceeded")]
    Timeout,
    #[error("epoch counter exhausted")]
    EpochExhausted,
    #[error("a ratchet step is still waiting for its commit")]
    Busy,
    #[error("the peer has not entered the current epoch yet")]
    NotSynced,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RatchetMsg {
    pub target_lsb: u8,
    pub flags: u8,
    pub public: [u8; 32],
}

impl RatchetMsg {
    pub fn to_fragments(&self) -> [[u8; RATCHET_FRAGMENT_LEN]; RATCHET_FRAGMENT_COUNT] {
        let mut data = [0u8; RATCHET_FRAGMENT_COUNT * RATCHET_FRAGMENT_DATA_LEN];
        data[..32].copy_from_slice(&self.public);
        let mut out = [[0u8; RATCHET_FRAGMENT_LEN]; RATCHET_FRAGMENT_COUNT];
        for ((frag, chunk), idx) in out.iter_mut().zip(data.chunks(RATCHET_FRAGMENT_DATA_LEN)).zip(0u8..) {
            frag[0] = self.target_lsb;
            frag[1] = ((self.flags & 0x0F) << 4) | idx;
            frag[2..].copy_from_slice(chunk);
        }
        out
    }
}

/// Reassembles the three fragments of one DH_RATCHET / DH_RATCHET_ACK.
#[derive(Default)]
pub struct RatchetAssembler {
    head: Option<(u8, u8)>,
    parts: [Option<[u8; RATCHET_FRAGMENT_DATA_LEN]>; RATCHET_FRAGMENT_COUNT],
}

impl RatchetAssembler {
    pub fn push(&mut self, frag: &[u8]) -> Result<Option<RatchetMsg>, RatchetError> {
        let f = <&[u8; RATCHET_FRAGMENT_LEN]>::try_from(frag).map_err(|_| RatchetError::Malformed)?;
        let target = f[0];
        let flags = f[1] >> 4;
        let idx = usize::from(f[1] & 0x0F);
        if flags & !RATCHET_FLAG_PQ != 0 {
            return Err(RatchetError::Malformed);
        }
        let mut data = [0u8; RATCHET_FRAGMENT_DATA_LEN];
        data.copy_from_slice(&f[2..]);
        if self.head != Some((target, flags)) {
            *self = Self::default();
            self.head = Some((target, flags));
        }
        let slot = self.parts.get_mut(idx).ok_or(RatchetError::Malformed)?;
        match slot {
            Some(prev) if *prev != data => return Err(RatchetError::Malformed),
            _ => *slot = Some(data),
        }
        let [Some(a), Some(b), Some(c)] = self.parts else { return Ok(None) };
        *self = Self::default();
        if c[RATCHET_FRAGMENT_DATA_LEN - 1] != 0 {
            return Err(RatchetError::Malformed);
        }
        let mut public = [0u8; 32];
        public[..11].copy_from_slice(&a);
        public[11..22].copy_from_slice(&b);
        public[22..].copy_from_slice(&c[..10]);
        Ok(Some(RatchetMsg { target_lsb: target, flags, public }))
    }
}

/// Post-quantum contribution: ss || SHA-384(ek || ct).
pub struct PqSecret(Zeroizing<Vec<u8>>);

impl PqSecret {
    fn new(ss: &[u8; 32], ek: &[u8], ct: &[u8]) -> Self {
        let mut v = Zeroizing::new(Vec::with_capacity(80));
        v.extend_from_slice(ss);
        v.extend_from_slice(&sha384(&[ek, ct]));
        Self(v)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// ML-KEM-1024 key pair generated by I after establishment (ek travels over BULK).
pub struct PqKeyPair {
    dk: DecapKey,
    ek: Vec<u8>,
}

impl PqKeyPair {
    pub fn generate<R: CryptoRngCore>(rng: &mut R) -> Self {
        let (dk, ek) = kem_generate(rng);
        Self { dk, ek }
    }

    pub fn encapsulation_key(&self) -> &[u8] {
        &self.ek
    }

    pub fn decapsulate(&self, ct: &[u8]) -> Result<PqSecret, RatchetError> {
        let ss = kem_decapsulate(&self.dk, ct).ok_or(RatchetError::Malformed)?;
        Ok(PqSecret::new(&ss, &self.ek, ct))
    }
}

/// R side: encapsulates against I's ek; returns (ct, secret).
pub fn pq_encapsulate<R: CryptoRngCore>(ek: &[u8], rng: &mut R) -> Result<(Vec<u8>, PqSecret), RatchetError> {
    let (ct, ss) = kem_encapsulate(ek, rng).ok_or(RatchetError::Malformed)?;
    let secret = PqSecret::new(&ss, ek, &ct);
    Ok((ct, secret))
}

fn next_root(root: &SecretKey32, dh: &[u8; 32], pq: Option<&PqSecret>) -> SecretKey32 {
    let prk = match pq {
        Some(p) => extract(root.as_bytes(), &[dh, p.as_bytes()]),
        None => extract(root.as_bytes(), &[dh]),
    };
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&prk[..32]);
    SecretKey32::from_bytes(*out)
}

fn dh(secret: &StaticSecret, peer: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, RatchetError> {
    let ss = secret.diffie_hellman(&XPublic::from(*peer));
    if !ss.was_contributory() {
        return Err(RatchetError::InvalidPublicKey);
    }
    Ok(Zeroizing::new(*ss.as_bytes()))
}

pub enum RatchetAction {
    /// Not for the next epoch: drop without state change.
    Ignore,
    /// Duplicate DH_RATCHET: resend the same ACK, nothing to stage.
    ResendAck(RatchetMsg),
    /// Stage RX for epoch with root (EpochCipher::stage_rx_epoch), then send ack in the current epoch.
    Staged { ack: RatchetMsg, root: SecretKey32, epoch: u32 },
}

/// R: a step that is staged for RX but not yet committed for TX.
struct StagedStep {
    i_pub: [u8; 32],
    ack: RatchetMsg,
    root: SecretKey32,
    epoch: u32,
}

pub struct DhRatchet {
    role: Role,
    epoch: u32,
    root: SecretKey32,
    frames: u32,
    forced: bool,
    failed: bool,
    pending: Option<(StaticSecret, RatchetMsg)>,
    staged: Option<StagedStep>,
    last_ack: Option<([u8; 32], RatchetMsg)>,
    synced: bool,
    pq: Option<PqSecret>,
}

impl DhRatchet {
    pub fn new(root: SecretKey32, role: Role) -> Self {
        Self {
            role,
            epoch: 0,
            root,
            frames: 0,
            forced: false,
            failed: false,
            pending: None,
            staged: None,
            last_ack: None,
            synced: true,
            pq: None,
        }
    }

    /// The epoch both TX and the ratchet state are in (R: unchanged until its TX commit).
    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    pub fn is_pending(&self) -> bool {
        self.pending.is_some()
    }

    /// R: a step is staged and waits for the first valid frame of the new epoch.
    pub fn is_staged(&self) -> bool {
        self.staged.is_some()
    }

    /// True once both sides are known to be in [DhRatchet::epoch].
    pub fn is_synced(&self) -> bool {
        self.synced
    }

    /// Call once per superframe slot. Returns Ok(true) when I should (re)send DH_RATCHET.
    /// Both roles fail once an epoch outlives RATCHET_INTERVAL_FRAMES + RATCHET_DEADLINE_FRAMES;
    /// the count restarts only when this side has committed TX to the next epoch.
    pub fn tick(&mut self) -> Result<bool, RatchetError> {
        if self.failed {
            return Err(RatchetError::Timeout);
        }
        self.frames = self.frames.saturating_add(1);
        if self.frames > RATCHET_INTERVAL_FRAMES + RATCHET_DEADLINE_FRAMES {
            self.failed = true;
            return Err(RatchetError::Timeout);
        }
        Ok(self.role == Role::Initiator
            && (self.frames >= RATCHET_INTERVAL_FRAMES || self.forced || self.pending.is_some()))
    }

    /// I: ratchet as soon as possible (peer sent DH_RATCHET_REQ, or a PQ secret arrived). A request
    /// made while a step is in flight stays pending and starts another step right after it.
    pub fn request(&mut self) {
        self.forced = true;
    }

    /// Supplies the PQ secret; the next step started (I) or the next PQ-flagged step received (R) mixes it.
    pub fn set_pq_secret(&mut self, pq: PqSecret) {
        self.pq = Some(pq);
    }

    /// I: returns DH_RATCHET for epoch + 1; while unanswered the same message is returned again.
    pub fn begin<R: CryptoRngCore>(&mut self, rng: &mut R) -> Result<RatchetMsg, RatchetError> {
        if self.role != Role::Initiator {
            return Err(RatchetError::WrongRole);
        }
        if let Some((_, msg)) = &self.pending {
            return Ok(*msg);
        }
        let target = self.epoch.checked_add(1).ok_or(RatchetError::EpochExhausted)?;
        let secret = StaticSecret::random_from_rng(&mut *rng);
        let msg = RatchetMsg {
            target_lsb: target as u8,
            flags: if self.pq.is_some() { RATCHET_FLAG_PQ } else { 0 },
            public: XPublic::from(&secret).to_bytes(),
        };
        self.pending = Some((secret, msg));
        self.forced = false;
        Ok(msg)
    }

    /// R: handles a reassembled DH_RATCHET. The new root is only staged; epoch, root and the
    /// frame count change in [DhRatchet::note_valid_frame]. While a step is staged, a DH_RATCHET
    /// for any other step is refused with [RatchetError::Busy].
    pub fn on_ratchet<R: CryptoRngCore>(&mut self, msg: &RatchetMsg, rng: &mut R) -> Result<RatchetAction, RatchetError> {
        if self.role != Role::Responder {
            return Err(RatchetError::WrongRole);
        }
        if let Some(st) = &self.staged {
            if st.ack.target_lsb != msg.target_lsb {
                return Err(RatchetError::Busy);
            }
            if bool::from(st.i_pub.ct_eq(&msg.public)) && st.ack.flags == msg.flags {
                return Ok(RatchetAction::ResendAck(st.ack));
            }
            return Err(RatchetError::Protocol);
        }
        if let Some((i_pub, ack)) = &self.last_ack {
            if ack.target_lsb == msg.target_lsb {
                if bool::from(i_pub.ct_eq(&msg.public)) && ack.flags == msg.flags {
                    return Ok(RatchetAction::ResendAck(*ack));
                }
                return Err(RatchetError::Protocol);
            }
        }
        let target = self.epoch.checked_add(1).ok_or(RatchetError::EpochExhausted)?;
        if msg.target_lsb != target as u8 {
            return Ok(RatchetAction::Ignore);
        }
        let use_pq = msg.flags & RATCHET_FLAG_PQ != 0;
        if use_pq && self.pq.is_none() {
            return Err(RatchetError::PqMissing);
        }
        let secret = StaticSecret::random_from_rng(&mut *rng);
        let shared = dh(&secret, &msg.public)?;
        let pq = if use_pq { self.pq.take() } else { None };
        let root = next_root(&self.root, &shared, pq.as_ref());
        let ack = RatchetMsg {
            target_lsb: msg.target_lsb,
            flags: msg.flags,
            public: XPublic::from(&secret).to_bytes(),
        };
        self.staged = Some(StagedStep { i_pub: msg.public, ack, root: root.clone(), epoch: target });
        Ok(RatchetAction::Staged { ack, root, epoch: target })
    }

    /// Call with the epoch of every frame that opened successfully. R commits its staged step on
    /// the first frame of the new epoch (the cipher switches TX at the same moment); I learns
    /// that R has entered the epoch. Returns true when this frame completed the step.
    pub fn note_valid_frame(&mut self, epoch: u32) -> bool {
        match self.role {
            Role::Responder => match self.staged.take() {
                Some(st) if st.epoch == epoch => {
                    self.epoch = st.epoch;
                    self.root = st.root.clone();
                    self.frames = 0;
                    self.last_ack = Some((st.i_pub, st.ack));
                    self.synced = true;
                    true
                }
                other => {
                    self.staged = other;
                    false
                }
            },
            Role::Initiator => {
                if !self.synced && epoch == self.epoch {
                    self.synced = true;
                    return true;
                }
                false
            }
        }
    }

    /// I: handles a reassembled DH_RATCHET_ACK. Returns (root, epoch) to stage and commit,
    /// or None for a stale or duplicate ACK.
    pub fn on_ack(&mut self, msg: &RatchetMsg) -> Result<Option<(SecretKey32, u32)>, RatchetError> {
        if self.role != Role::Initiator {
            return Err(RatchetError::WrongRole);
        }
        let Some((_, sent)) = &self.pending else { return Ok(None) };
        if sent.target_lsb != msg.target_lsb {
            return Ok(None);
        }
        if sent.flags != msg.flags {
            return Err(RatchetError::Protocol);
        }
        let use_pq = sent.flags & RATCHET_FLAG_PQ != 0;
        if use_pq && self.pq.is_none() {
            return Err(RatchetError::PqMissing);
        }
        let target = self.epoch.checked_add(1).ok_or(RatchetError::EpochExhausted)?;
        let shared = match &self.pending {
            Some((secret, _)) => dh(secret, &msg.public)?,
            None => return Ok(None),
        };
        let pq = if use_pq { self.pq.take() } else { None };
        let root = next_root(&self.root, &shared, pq.as_ref());
        self.pending = None;
        self.epoch = target;
        self.root = root.clone();
        self.frames = 0;
        self.synced = false;
        Ok(Some((root, target)))
    }

    /// §6.3 step 4: Expand(root_e, "resume next pq" || BE32(e), 32) for the current epoch e.
    /// Only available once both sides are in epoch e.
    pub fn resume_next_pq(&self) -> Result<SecretKey32, RatchetError> {
        if !self.synced {
            return Err(RatchetError::NotSynced);
        }
        Ok(expand32(self.root.as_bytes(), &[b"resume next pq", &self.epoch.to_be_bytes()]))
    }
}

impl Drop for DhRatchet {
    fn drop(&mut self) {
        self.root.zeroize();
        // Each of these zeroizes its secret when dropped.
        self.pending = None;
        self.staged = None;
        self.pq = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::epoch_cipher::{EpochCipher, EpochError};
    use rand_core::OsRng;

    struct Side {
        c: EpochCipher,
        r: DhRatchet,
    }

    fn sides() -> (Side, Side) {
        let root = SecretKey32::from_bytes([0x5A; 32]);
        let tag = [0xA, 0xB, 0xC, 0xD];
        (
            Side { c: EpochCipher::from_root(&root, Role::Initiator, tag), r: DhRatchet::new(root.clone(), Role::Initiator) },
            Side { c: EpochCipher::from_root(&root, Role::Responder, tag), r: DhRatchet::new(root, Role::Responder) },
        )
    }

    fn ship(msg: &RatchetMsg) -> RatchetMsg {
        let mut asm = RatchetAssembler::default();
        let mut out = None;
        for f in msg.to_fragments() {
            out = asm.push(&f).unwrap();
        }
        out.unwrap()
    }

    fn one_step(i: &mut Side, r: &mut Side) -> u32 {
        let m = i.r.begin(&mut OsRng).unwrap();
        let RatchetAction::Staged { ack, root, epoch } = r.r.on_ratchet(&ship(&m), &mut OsRng).unwrap() else {
            panic!("expected staged")
        };
        r.c.stage_rx_epoch(&root, epoch).unwrap();
        let (iroot, ie) = i.r.on_ack(&ship(&ack)).unwrap().unwrap();
        assert_eq!(ie, epoch);
        assert_eq!(iroot.as_bytes(), root.as_bytes());
        i.c.stage_rx_epoch(&iroot, ie).unwrap();
        i.c.commit_tx_epoch(ie).unwrap();
        assert_eq!(r.c.tx_epoch(), epoch - 1, "R must not commit before seeing an e+1 frame");
        let f = i.c.seal_superframe(&[ie as u8; 14]).unwrap();
        let o = r.c.open_superframe(&f).unwrap();
        assert_eq!((o.epoch, o.counter, o.plaintext), (ie, 0, [ie as u8; 14]));
        assert_eq!(r.r.epoch(), epoch - 1);
        assert!(r.r.note_valid_frame(o.epoch));
        assert_eq!(r.r.epoch(), epoch);
        assert_eq!(r.c.tx_epoch(), epoch);
        let g = r.c.seal_superframe(&[0x77; 14]).unwrap();
        let o2 = i.c.open_superframe(&g).unwrap();
        assert_eq!((o2.epoch, o2.counter), (ie, 0));
        assert!(i.r.resume_next_pq().is_err());
        assert!(i.r.note_valid_frame(o2.epoch));
        assert!(!i.r.note_valid_frame(o2.epoch));
        let k_tx = i.c.tx_message_key(ie, 77).unwrap();
        let (e_rx, k_rx) = r.c.rx_message_key((ie as u8) & 0x3F, 77).unwrap();
        assert_eq!(e_rx, ie);
        assert_eq!(k_tx.as_bytes(), k_rx.as_bytes());
        ie
    }

    #[test]
    fn ten_consecutive_ratchets_keep_both_sides_in_sync() {
        let (mut i, mut r) = sides();
        let mut roots = Vec::new();
        for n in 1..=10u32 {
            assert_eq!(one_step(&mut i, &mut r), n);
            roots.push(i.r.resume_next_pq().unwrap().as_bytes().to_vec());
            assert_eq!(i.r.resume_next_pq().unwrap().as_bytes(), r.r.resume_next_pq().unwrap().as_bytes());
        }
        roots.dedup();
        assert_eq!(roots.len(), 10);
        assert_eq!((i.c.tx_epoch(), i.c.rx_epoch(), r.c.tx_epoch(), r.c.rx_epoch()), (10, 10, 10, 10));
    }

    #[test]
    fn lost_ack_is_recovered_by_resending_the_same_messages() {
        let (mut i, mut r) = sides();
        let m1 = i.r.begin(&mut OsRng).unwrap();
        let RatchetAction::Staged { ack, root, epoch } = r.r.on_ratchet(&ship(&m1), &mut OsRng).unwrap() else {
            panic!("expected staged")
        };
        r.c.stage_rx_epoch(&root, epoch).unwrap();
        // ACK lost: I keeps sending epoch-0 frames and resends DH_RATCHET unchanged.
        let f = i.c.seal_superframe(&[1; 14]).unwrap();
        assert_eq!(r.c.open_superframe(&f).unwrap().epoch, 0);
        assert!(!r.r.note_valid_frame(0));
        assert_eq!(r.c.tx_epoch(), 0);
        let m2 = i.r.begin(&mut OsRng).unwrap();
        assert_eq!(m1, m2);
        let RatchetAction::ResendAck(ack2) = r.r.on_ratchet(&ship(&m2), &mut OsRng).unwrap() else {
            panic!("expected resend")
        };
        assert_eq!(ack, ack2);
        let (iroot, ie) = i.r.on_ack(&ship(&ack2)).unwrap().unwrap();
        assert!(i.r.on_ack(&ack2).unwrap().is_none(), "duplicate ACK is ignored");
        i.c.stage_rx_epoch(&iroot, ie).unwrap();
        i.c.commit_tx_epoch(ie).unwrap();
        let f = i.c.seal_superframe(&[2; 14]).unwrap();
        assert_eq!(r.c.open_superframe(&f).unwrap().epoch, 1);
        assert!(r.r.note_valid_frame(1));
        assert_eq!(r.c.tx_epoch(), 1);
        // A DH_RATCHET for a different target or a conflicting key is not accepted.
        let mut stale = m1;
        stale.target_lsb = 5;
        assert!(matches!(r.r.on_ratchet(&stale, &mut OsRng), Ok(RatchetAction::Ignore)));
        let mut conflicting = m1;
        conflicting.public[0] ^= 1;
        assert!(matches!(r.r.on_ratchet(&conflicting, &mut OsRng), Err(RatchetError::Protocol)));
    }

    #[test]
    fn responder_keeps_epoch_root_and_frame_count_until_commit_and_refuses_a_second_step() {
        let (mut i, mut r) = sides();
        let before = r.r.resume_next_pq().unwrap();
        // R is one frame short of its deadline when the step is staged.
        for _ in 0..RATCHET_INTERVAL_FRAMES + RATCHET_DEADLINE_FRAMES - 1 {
            r.r.tick().unwrap();
        }
        let m = i.r.begin(&mut OsRng).unwrap();
        let RatchetAction::Staged { ack, root, epoch } = r.r.on_ratchet(&ship(&m), &mut OsRng).unwrap() else {
            panic!("expected staged")
        };
        r.c.stage_rx_epoch(&root, epoch).unwrap();
        assert!(r.r.is_staged());
        assert_eq!(r.r.epoch(), 0);
        assert_eq!(r.r.resume_next_pq().unwrap().as_bytes(), before.as_bytes());

        // A DH_RATCHET for a further step is refused while this one is uncommitted.
        let second = RatchetMsg { target_lsb: 2, flags: 0, public: [9; 32] };
        assert_eq!(r.r.on_ratchet(&second, &mut OsRng).err(), Some(RatchetError::Busy));
        let mut other_key = m;
        other_key.public[0] ^= 1;
        assert_eq!(r.r.on_ratchet(&other_key, &mut OsRng).err(), Some(RatchetError::Protocol));
        assert!(r.r.is_staged());
        assert_eq!(r.r.epoch(), 0);

        // I has the new root but may not derive the resume secret before R is seen in epoch 1.
        let (iroot, ie) = i.r.on_ack(&ship(&ack)).unwrap().unwrap();
        i.c.stage_rx_epoch(&iroot, ie).unwrap();
        i.c.commit_tx_epoch(ie).unwrap();
        assert_eq!(i.r.resume_next_pq().err(), Some(RatchetError::NotSynced));
        let late = r.c.seal_superframe(&[1; 14]).unwrap();
        assert!(!i.r.note_valid_frame(i.c.open_superframe(&late).unwrap().epoch));
        assert_eq!(i.r.resume_next_pq().err(), Some(RatchetError::NotSynced));

        // Staging did not restart R's frame count: the deadline still fires without a commit.
        assert!(r.r.tick().is_ok());
        assert_eq!(r.r.tick(), Err(RatchetError::Timeout));

        // With a commit in time the count restarts and both sides derive the same secret.
        let (mut i, mut r) = sides();
        for _ in 0..RATCHET_INTERVAL_FRAMES + RATCHET_DEADLINE_FRAMES - 1 {
            r.r.tick().unwrap();
        }
        one_step(&mut i, &mut r);
        for _ in 0..RATCHET_INTERVAL_FRAMES {
            r.r.tick().unwrap();
        }
        assert_eq!(i.r.resume_next_pq().unwrap().as_bytes(), r.r.resume_next_pq().unwrap().as_bytes());
    }

    #[test]
    fn request_made_while_a_plain_step_is_in_flight_survives_and_starts_the_pq_step() {
        let (mut i, mut r) = sides();
        let kp = PqKeyPair::generate(&mut OsRng);
        let (ct, pq_r) = pq_encapsulate(kp.encapsulation_key(), &mut OsRng).unwrap();
        i.r.request();
        assert!(i.r.tick().unwrap());
        let m = i.r.begin(&mut OsRng).unwrap();
        assert_eq!(m.flags, 0);
        // The PQ secret arrives while the unflagged step is still unanswered.
        i.r.set_pq_secret(kp.decapsulate(&ct).unwrap());
        i.r.request();
        r.r.set_pq_secret(pq_r);
        assert_eq!(i.r.begin(&mut OsRng).unwrap(), m, "the step in flight is resent unchanged");
        let RatchetAction::Staged { ack, root, epoch } = r.r.on_ratchet(&ship(&m), &mut OsRng).unwrap() else {
            panic!("expected staged")
        };
        r.c.stage_rx_epoch(&root, epoch).unwrap();
        let (iroot, ie) = i.r.on_ack(&ship(&ack)).unwrap().unwrap();
        i.c.stage_rx_epoch(&iroot, ie).unwrap();
        i.c.commit_tx_epoch(ie).unwrap();
        assert!(i.r.pq.is_some() && r.r.pq.is_some(), "the unflagged step leaves the PQ secret alone");
        // The request is still pending: the very next slot starts the flagged step.
        assert!(i.r.tick().unwrap());
        let f = i.c.seal_superframe(&[0; 14]).unwrap();
        assert!(r.r.note_valid_frame(r.c.open_superframe(&f).unwrap().epoch));
        let m2 = i.r.begin(&mut OsRng).unwrap();
        assert_eq!((m2.flags, m2.target_lsb), (RATCHET_FLAG_PQ, 2));
        assert!(matches!(r.r.on_ratchet(&ship(&m2), &mut OsRng), Ok(RatchetAction::Staged { epoch: 2, .. })));
    }

    #[test]
    fn pq_flag_mixes_the_kem_secret() {
        let (mut i, mut r) = sides();
        let kp = PqKeyPair::generate(&mut OsRng);
        let (ct, pq_r) = pq_encapsulate(kp.encapsulation_key(), &mut OsRng).unwrap();
        assert_eq!((kp.encapsulation_key().len(), ct.len()), (PQ_EK_LEN, PQ_CT_LEN));
        let pq_i = kp.decapsulate(&ct).unwrap();
        assert_eq!(pq_i.as_bytes(), pq_r.as_bytes());

        // R without the PQ secret refuses a PQ-flagged step.
        i.r.set_pq_secret(pq_i);
        let m = i.r.begin(&mut OsRng).unwrap();
        assert_eq!(m.flags, RATCHET_FLAG_PQ);
        assert!(matches!(r.r.on_ratchet(&ship(&m), &mut OsRng), Err(RatchetError::PqMissing)));
        r.r.set_pq_secret(pq_r);
        let RatchetAction::Staged { ack, root, .. } = r.r.on_ratchet(&ship(&m), &mut OsRng).unwrap() else {
            panic!("expected staged")
        };
        let mut wrong_flags = ack;
        wrong_flags.flags = 0;
        assert_eq!(i.r.on_ack(&wrong_flags).err(), Some(RatchetError::Protocol));
        let (iroot, _) = i.r.on_ack(&ack).unwrap().unwrap();
        assert_eq!(iroot.as_bytes(), root.as_bytes());
        assert!(i.r.pq.is_none() && r.r.pq.is_none(), "PQ secret consumed by the step");

        // The PQ contribution changes the derived root for the same DH value.
        let base = SecretKey32::from_bytes([1; 32]);
        let kp2 = PqKeyPair::generate(&mut OsRng);
        let (_, s2) = pq_encapsulate(kp2.encapsulation_key(), &mut OsRng).unwrap();
        let dhv = [9u8; 32];
        assert_ne!(next_root(&base, &dhv, None).as_bytes(), next_root(&base, &dhv, Some(&s2)).as_bytes());
    }

    #[test]
    fn ratchet_deadline_aborts_after_1500_frames_past_due() {
        let (mut i, mut r) = sides();
        for n in 1..=RATCHET_INTERVAL_FRAMES + RATCHET_DEADLINE_FRAMES {
            let due = i.r.tick().unwrap();
            assert_eq!(due, n >= RATCHET_INTERVAL_FRAMES);
            assert!(!r.r.tick().unwrap());
        }
        assert_eq!(i.r.tick(), Err(RatchetError::Timeout));
        assert_eq!(r.r.tick(), Err(RatchetError::Timeout));
        assert_eq!(i.r.tick(), Err(RatchetError::Timeout));
        // A completed step resets the clock.
        let (mut i2, mut r2) = sides();
        for _ in 0..RATCHET_INTERVAL_FRAMES + 100 {
            i2.r.tick().unwrap();
            r2.r.tick().unwrap();
        }
        one_step(&mut i2, &mut r2);
        assert!(!i2.r.tick().unwrap());
        // R may request an early step.
        i2.r.request();
        assert!(i2.r.tick().unwrap());
    }

    #[test]
    fn message_keys_survive_one_epoch_and_are_refused_after_two() {
        let (mut i, mut r) = sides();
        let k0 = i.c.tx_message_key(0, 9).unwrap();
        one_step(&mut i, &mut r);
        let (e, k) = r.c.rx_message_key(0, 9).unwrap();
        assert_eq!(e, 0);
        assert_eq!(k.as_bytes(), k0.as_bytes());
        assert_eq!(i.c.tx_message_key(0, 9).unwrap().as_bytes(), k0.as_bytes());
        one_step(&mut i, &mut r);
        assert!(matches!(r.c.rx_message_key(0, 9), Err(EpochError::OutOfWindow)));
        assert!(matches!(i.c.tx_message_key(0, 9), Err(EpochError::OutOfWindow)));
        assert!(matches!(r.c.rx_message_key(0x40, 9), Err(EpochError::OutOfWindow)));
    }

    #[test]
    fn assembler_rejects_malformed_fragments() {
        let msg = RatchetMsg { target_lsb: 3, flags: 0, public: [7; 32] };
        let frags = msg.to_fragments();
        let mut asm = RatchetAssembler::default();
        assert_eq!(asm.push(&frags[0][..12]), Err(RatchetError::Malformed));
        let mut bad_idx = frags[0];
        bad_idx[1] = 0x03;
        assert_eq!(asm.push(&bad_idx), Err(RatchetError::Malformed));
        let mut bad_flags = frags[0];
        bad_flags[1] |= 0x20;
        assert_eq!(asm.push(&bad_flags), Err(RatchetError::Malformed));
        let mut bad_pad = frags[2];
        bad_pad[12] = 1;
        let mut asm2 = RatchetAssembler::default();
        asm2.push(&frags[0]).unwrap();
        asm2.push(&frags[1]).unwrap();
        assert_eq!(asm2.push(&bad_pad), Err(RatchetError::Malformed));
        // Out-of-order arrival still reassembles.
        let mut asm3 = RatchetAssembler::default();
        assert_eq!(asm3.push(&frags[2]).unwrap(), None);
        assert_eq!(asm3.push(&frags[0]).unwrap(), None);
        assert_eq!(asm3.push(&frags[1]).unwrap(), Some(msg));
    }
}
