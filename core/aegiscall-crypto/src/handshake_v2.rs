//! Handshake v2 (secure-session-v2 §2.B as amended by §6.2 / §6.3).
//!
//! Pure state machine: feed peer messages with [HandshakeV2::on_message], forward
//! [HsOut::NeedSignature] to the StrongBox signer and return its DER result through
//! [HandshakeV2::on_signature]. Any failure aborts permanently (fail-closed) and wipes secrets.
//!
//! Full path:  HS1 <-> HS1, PATH, R->I HS2 (x25519_R || ek_R), I->R HS3 (x25519_I || ct || AEAD(ID_I)),
//!             R->I HS4 (AEAD(ID_R)).  Resume path: HS1 <-> HS1, PATH, RS2 <-> RS2, RS3 <-> RS3.
//!
//! §6.11: the caller ID never drives a cryptographic decision. The dialer marks its HS1 with
//! CAP_DIALER and advertises psk_tag / rid0 / rid1 for the contact it dialed; the answerer fills
//! those fields with random bytes, matches the dialer's fields against every secret in its vault
//! and announces the result in PATH (2 bytes), which both sides absorb into the transcript right
//! after the two HS1 messages. th0 is taken after PATH, so both key schedules bind it.

use crate::identity::{
    ecdsa_der_to_raw, validate_pub33, verify_identity_sig, LocalIdentity, PeerIdentity, EVIDENCE_ID_LEN,
    PUB33_LEN, RAW_SIG_LEN,
};
use crate::primitives::{
    aead_open_once, aead_seal_once, expand, expand32, extract, hmac_sha384, kem_decapsulate,
    kem_encapsulate, kem_generate, sha384, DecapKey, Prk, MLKEM1024_CT_LEN, MLKEM1024_EK_LEN, PRK_LEN,
};
use aegiscall_memsec::SecretKey32;
use rand_core::{CryptoRngCore, OsRng};
use sha2::{Digest, Sha384};
use subtle::ConstantTimeEq;
use thiserror::Error;
use x25519_dalek::{PublicKey as XPublic, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

pub const PROTO_V2: u8 = 2;
pub const SUITE_V2: u8 = 1;
pub const CAP_SUITE_V2: u16 = 1 << 5;
/// HS1 only: set by the side that placed the call (§6.11). Both sides equal aborts.
pub const CAP_DIALER: u16 = 1 << 0;
/// Remaining former CAP_EDITION_* bit; must be zero (§6.1).
pub const CAP_RESERVED_MASK: u16 = 0b10;
pub const SAS_LEN: usize = 5;

pub const HS1_LEN: usize = 77;
pub const HS2_LEN: usize = 32 + MLKEM1024_EK_LEN; // 1600
pub const ID_BLOCK_LEN: usize = PUB33_LEN + EVIDENCE_ID_LEN + RAW_SIG_LEN; // 113
pub const ID_SEALED_LEN: usize = ID_BLOCK_LEN + 16; // 129
pub const HS3_LEN: usize = 32 + MLKEM1024_CT_LEN + ID_SEALED_LEN; // 1729
pub const HS4_LEN: usize = ID_SEALED_LEN; // 129
pub const RS2_LEN: usize = 32;
pub const RS3_LEN: usize = RAW_SIG_LEN + 16; // 80
pub const PATH_LEN: usize = 2;

pub const MSG_HS1: u8 = 1;
pub const MSG_HS2: u8 = 2;
pub const MSG_HS3: u8 = 3;
pub const MSG_HS4: u8 = 4;
pub const MSG_RS2: u8 = 5;
pub const MSG_RS3: u8 = 6;
pub const MSG_PATH: u8 = 7;

pub const PATH_FULL: u8 = 0;
pub const PATH_RESUME: u8 = 1;
pub const PATH_FLAG_PSK: u8 = 0x01;
pub const PATH_FLAG_RS_NEW: u8 = 0x02;

const PROTOCOL_LABEL: &[u8] = b"AegisChat-v2|X25519|MLKEM1024|P256|SHA384|XCHACHA";
const OFF_GEAR: usize = 4;
const OFF_NONCE: usize = 5;
const OFF_PSK: usize = 21;
const OFF_RID0: usize = 29;
const OFF_RID1: usize = 37;
const OFF_COMMIT: usize = 45;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Initiator,
    Responder,
}

/// Which end of the phone call we are. Only the dialer names a contact; the answerer finds the
/// contact by matching the dialer's HS1 against its whole vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallSide {
    Dialer { contact: Option<u32> },
    Answerer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkContext {
    pub local_preamble: [u8; 5],
    pub peer_preamble: [u8; 5],
    /// Our preferred gear; the negotiated gear is the smaller of both HS1 values.
    pub gear: u8,
}

pub struct ResumeCandidate {
    pub contact: u32,
    pub pub33: [u8; 33],
    pub secret: SecretKey32,
    pub is_new: bool,
}

/// psk: every contact holding a PSK (contact id, pinned pub33, PSK).
/// resume: rs_cur / rs_new secrets of verified contacts.
pub struct PeerExpectation {
    pub psk: Vec<(u32, [u8; 33], SecretKey32)>,
    pub resume: Vec<ResumeCandidate>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Path {
    Full,
    Resume { contact: u32, used_new: bool },
}

pub struct Established {
    pub root0: SecretKey32,
    pub chaff_seed: SecretKey32,
    pub rs_next: SecretKey32,
    pub transcript_tag: [u8; 4],
    pub role: Role,
    pub peer: PeerIdentity,
    pub path: Path,
    pub psk_contact: Option<u32>,
}

impl core::fmt::Debug for Established {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Established")
            .field("role", &self.role)
            .field("path", &self.path)
            .field("psk_contact", &self.psk_contact)
            .field("peer", &self.peer)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub enum HsOut {
    Send { msg_type: u8, body: Vec<u8> },
    /// Sign to_sign with SHA256withECDSA on the identity key and return the DER signature.
    NeedSignature { req_id: u32, to_sign: Vec<u8> },
    /// Five raw SAS bytes (full path only); word mapping lives in the app resources.
    Sas([u8; SAS_LEN]),
    Established(Box<Established>),
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum HsError {
    #[error("malformed, unexpected or out-of-order handshake message")]
    Malformed,
    #[error("peer protocol version, suite or capabilities incompatible")]
    VersionMismatch,
    #[error("role tie: identical commits")]
    RoleTie,
    #[error("revealed X25519 key does not match the HS1 commitment")]
    CommitMismatch,
    #[error("handshake AEAD authentication failed")]
    AeadFail,
    #[error("peer identity signature invalid")]
    BadSignature,
    #[error("PSK selection inconsistent with the revealed identity")]
    PskMismatch,
    #[error("handshake timed out")]
    Timeout,
    #[error("peer aborted the handshake")]
    PeerAbort,
    #[error("local signer failed or returned an invalid signature")]
    SignerFailed,
    #[error("peer is a PSK contact but its PSK was not mixed in")]
    PskRequired,
    #[error("resume authentication (RS3) failed")]
    ResumeAuthFailed,
    #[error("peer is on the other handshake path")]
    PathMismatch,
    #[error("both sides claim the same call side (dialer / answerer)")]
    SideConflict,
    #[error("handshake already aborted")]
    Aborted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    AwaitHs1,
    AwaitPath,
    IAwaitHs2,
    ISigning,
    IAwaitHs4,
    RAwaitHs3,
    RSigning,
    ResAwaitRs2,
    ResSigning,
    ResAwaitRs3,
    Done,
    Aborted,
}

enum Choice {
    Full(Option<u32>),
    Resume(usize),
}

pub struct HandshakeV2 {
    local: LocalIdentity,
    link: LinkContext,
    expect: PeerExpectation,
    side: CallSide,
    phase: Phase,
    x_secret: Option<StaticSecret>,
    x_pub: [u8; 32],
    kem: Option<(DecapKey, Vec<u8>)>,
    hs1_local: [u8; HS1_LEN],
    peer_hs1: Option<[u8; HS1_LEN]>,
    role: Option<Role>,
    gear: Option<u8>,
    transcript: Sha384,
    th0: [u8; 48],
    path: Option<Path>,
    resume_pin: Option<[u8; 33]>,
    psk_contact: Option<u32>,
    ck: Prk,
    th_mark: [u8; 48],
    th4: [u8; 48],
    k_i2r: Option<SecretKey32>,
    k_r2i: Option<SecretKey32>,
    pending_ct: Option<Vec<u8>>,
    sign_req: Option<(u32, Vec<u8>)>,
    next_req: u32,
    peer: Option<PeerIdentity>,
    own_rs3: Option<[u8; RS3_LEN]>,
    peer_rs3: Option<[u8; RS3_LEN]>,
}

fn arr<const N: usize>(s: &[u8]) -> Result<[u8; N], HsError> {
    <[u8; N]>::try_from(s).map_err(|_| HsError::Malformed)
}

fn field<const N: usize>(s: &[u8], off: usize) -> Result<[u8; N], HsError> {
    let end = off.checked_add(N).ok_or(HsError::Malformed)?;
    arr::<N>(s.get(off..end).ok_or(HsError::Malformed)?)
}

fn compute_commit(prefix: &[u8], x_pub: &[u8; 32]) -> [u8; 32] {
    let h = sha384(&[b"AegisCommit-v2", prefix, x_pub]);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h[..32]);
    out
}

fn psk_tag(psk: &SecretKey32, nonce: &[u8; 16]) -> [u8; 8] {
    let t = hmac_sha384(psk.as_bytes(), &[b"AegisPSK-v2", nonce]);
    let mut out = [0u8; 8];
    out.copy_from_slice(&t[..8]);
    out
}

/// rid = HMAC-SHA384(rs, "AegisRID-v2" || sender nonce || sender pub33)[..8]
pub(crate) fn resume_rid(rs: &SecretKey32, nonce: &[u8; 16], pub33: &[u8; 33]) -> [u8; 8] {
    let t = hmac_sha384(rs.as_bytes(), &[b"AegisRID-v2", nonce, pub33]);
    let mut out = [0u8; 8];
    out.copy_from_slice(&t[..8]);
    out
}

/// Tag carried in the RESUME_SAVED control frame: Expand(rs_next, "saved")[..8].
pub fn resume_saved_tag(rs_next: &SecretKey32) -> [u8; 8] {
    let mut out = [0u8; 8];
    expand(rs_next.as_bytes(), &[b"saved"], &mut out);
    out
}

fn concat(parts: &[&[u8]]) -> Vec<u8> {
    let mut v = Vec::with_capacity(parts.iter().map(|p| p.len()).sum());
    for p in parts {
        v.extend_from_slice(p);
    }
    v
}

fn hint_resume(expect: &PeerExpectation, hint: Option<u32>) -> (Option<usize>, Option<usize>) {
    let Some(h) = hint else { return (None, None) };
    let cur = expect.resume.iter().position(|c| c.contact == h && !c.is_new);
    let new = expect.resume.iter().position(|c| c.contact == h && c.is_new);
    (cur, new)
}

impl HandshakeV2 {
    /// Starts a handshake and returns HS1. A dialer advertises the PSK tag and resume ids of the
    /// contact it dialed (random when it dialed a bare number); an answerer always sends random
    /// fields and later decides the path from the dialer's HS1.
    pub fn start<R: CryptoRngCore>(
        local: LocalIdentity,
        link: LinkContext,
        expect: PeerExpectation,
        side: CallSide,
        rng: &mut R,
    ) -> Result<(Self, Vec<HsOut>), HsError> {
        validate_pub33(&local.pub33).map_err(|_| HsError::SignerFailed)?;
        let x_secret = StaticSecret::random_from_rng(&mut *rng);
        let x_pub = XPublic::from(&x_secret).to_bytes();
        let peer_hint = match side {
            CallSide::Dialer { contact } => contact,
            CallSide::Answerer => None,
        };
        let caps = match side {
            CallSide::Dialer { .. } => CAP_SUITE_V2 | CAP_DIALER,
            CallSide::Answerer => CAP_SUITE_V2,
        };

        let mut hs1 = [0u8; HS1_LEN];
        hs1[0] = PROTO_V2;
        hs1[1] = SUITE_V2;
        hs1[2..4].copy_from_slice(&caps.to_be_bytes());
        hs1[OFF_GEAR] = link.gear;
        rng.fill_bytes(&mut hs1[OFF_NONCE..OFF_PSK]);
        let nonce: [u8; 16] = field(&hs1, OFF_NONCE)?;

        let hinted_psk = peer_hint.and_then(|h| expect.psk.iter().find(|(c, _, _)| *c == h));
        match hinted_psk {
            Some((_, _, psk)) => hs1[OFF_PSK..OFF_RID0].copy_from_slice(&psk_tag(psk, &nonce)),
            None => rng.fill_bytes(&mut hs1[OFF_PSK..OFF_RID0]),
        }
        let (cur, new) = hint_resume(&expect, peer_hint);
        match cur.and_then(|i| expect.resume.get(i)) {
            Some(c) => hs1[OFF_RID0..OFF_RID1].copy_from_slice(&resume_rid(&c.secret, &nonce, &local.pub33)),
            None => rng.fill_bytes(&mut hs1[OFF_RID0..OFF_RID1]),
        }
        match new.and_then(|i| expect.resume.get(i)) {
            Some(c) => hs1[OFF_RID1..OFF_COMMIT].copy_from_slice(&resume_rid(&c.secret, &nonce, &local.pub33)),
            None => rng.fill_bytes(&mut hs1[OFF_RID1..OFF_COMMIT]),
        }
        let commit = compute_commit(&hs1[..OFF_COMMIT], &x_pub);
        hs1[OFF_COMMIT..].copy_from_slice(&commit);

        let kem = kem_generate(rng);
        let hs = Self {
            local,
            link,
            expect,
            side,
            phase: Phase::AwaitHs1,
            x_secret: Some(x_secret),
            x_pub,
            kem: Some(kem),
            hs1_local: hs1,
            peer_hs1: None,
            role: None,
            gear: None,
            transcript: Sha384::new(),
            th0: [0u8; 48],
            path: None,
            resume_pin: None,
            psk_contact: None,
            ck: Zeroizing::new([0u8; PRK_LEN]),
            th_mark: [0u8; 48],
            th4: [0u8; 48],
            k_i2r: None,
            k_r2i: None,
            pending_ct: None,
            sign_req: None,
            next_req: 1,
            peer: None,
            own_rs3: None,
            peer_rs3: None,
        };
        Ok((hs, vec![HsOut::Send { msg_type: MSG_HS1, body: hs1.to_vec() }]))
    }

    pub fn role(&self) -> Option<Role> {
        self.role
    }

    /// Gear negotiated from both HS1 messages (smaller value).
    pub fn negotiated_gear(&self) -> Option<u8> {
        self.gear
    }

    pub fn path(&self) -> Option<Path> {
        self.path
    }

    pub fn is_established(&self) -> bool {
        self.phase == Phase::Done
    }

    pub fn is_aborted(&self) -> bool {
        self.phase == Phase::Aborted
    }

    /// Local abort (timeout, user, peer ABORT): wipes all secrets. No effect once established.
    pub fn abort(&mut self) {
        self.fail();
    }

    pub fn on_timeout(&mut self) -> HsError {
        self.fail();
        HsError::Timeout
    }

    /// After establishment every input is dropped and the object never changes state (§6.11).
    pub fn on_message(&mut self, msg_type: u8, body: &[u8]) -> Result<Vec<HsOut>, HsError> {
        if self.phase == Phase::Done {
            return Ok(Vec::new());
        }
        let r = self.step(msg_type, body);
        if r.is_err() {
            self.fail();
        }
        r
    }

    pub fn on_signature(&mut self, req_id: u32, sig_der: &[u8]) -> Result<Vec<HsOut>, HsError> {
        if self.phase == Phase::Done {
            return Ok(Vec::new());
        }
        let r = self.sig_step(req_id, sig_der);
        if r.is_err() {
            self.fail();
        }
        r
    }

    fn fail(&mut self) {
        if self.phase == Phase::Done {
            return;
        }
        self.phase = Phase::Aborted;
        self.wipe();
    }

    fn wipe(&mut self) {
        self.x_secret = None;
        self.kem = None;
        self.ck.zeroize();
        self.k_i2r = None;
        self.k_r2i = None;
        self.pending_ct = None;
        self.sign_req = None;
        self.own_rs3 = None;
        self.peer_rs3 = None;
        self.expect.psk.clear();
        self.expect.resume.clear();
    }

    fn snap(&self) -> [u8; 48] {
        let d = self.transcript.clone().finalize();
        let mut out = [0u8; 48];
        out.copy_from_slice(d.as_slice());
        out
    }

    fn role_or_err(&self) -> Result<Role, HsError> {
        self.role.ok_or(HsError::Malformed)
    }

    fn new_sign_req(&mut self, to_sign: Vec<u8>) -> HsOut {
        let id = self.next_req;
        self.next_req = self.next_req.wrapping_add(1);
        self.sign_req = Some((id, to_sign.clone()));
        HsOut::NeedSignature { req_id: id, to_sign }
    }

    fn check_peer_commit(&self, x: &[u8; 32]) -> Result<(), HsError> {
        let p = self.peer_hs1.as_ref().ok_or(HsError::Malformed)?;
        let c = compute_commit(&p[..OFF_COMMIT], x);
        if c.ct_eq(&p[OFF_COMMIT..]).unwrap_u8() != 1 {
            return Err(HsError::CommitMismatch);
        }
        Ok(())
    }

    fn dh(&mut self, peer_x: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, HsError> {
        let sk = self.x_secret.take().ok_or(HsError::Malformed)?;
        let ss = sk.diffie_hellman(&XPublic::from(*peer_x));
        if !ss.was_contributory() {
            return Err(HsError::Malformed);
        }
        Ok(Zeroizing::new(*ss.as_bytes()))
    }

    fn step(&mut self, t: u8, body: &[u8]) -> Result<Vec<HsOut>, HsError> {
        if !(MSG_HS1..=MSG_PATH).contains(&t) {
            return match self.phase {
                Phase::Aborted => Err(HsError::Aborted),
                _ => Err(HsError::Malformed),
            };
        }
        let resume_type = t == MSG_RS2 || t == MSG_RS3;
        let full_type = (MSG_HS2..=MSG_HS4).contains(&t);
        match self.phase {
            Phase::Aborted => Err(HsError::Aborted),
            // After establishment the link layer owns retransmission handling (§6.2);
            // stray handshake messages never change state here.
            Phase::Done => Ok(Vec::new()),
            Phase::AwaitHs1 if t == MSG_HS1 => self.on_hs1(body),
            Phase::AwaitPath if t == MSG_PATH => self.on_path(body),
            Phase::IAwaitHs2 if t == MSG_HS2 => self.on_hs2(body),
            Phase::IAwaitHs4 if t == MSG_HS4 => self.on_hs4(body),
            Phase::RAwaitHs3 if t == MSG_HS3 => self.on_hs3(body),
            Phase::ResAwaitRs2 if t == MSG_RS2 => self.on_rs2(body),
            Phase::ResSigning if t == MSG_RS3 && self.peer_rs3.is_none() => {
                self.peer_rs3 = Some(arr::<RS3_LEN>(body)?);
                Ok(Vec::new())
            }
            Phase::ResAwaitRs3 if t == MSG_RS3 => {
                let rs3 = arr::<RS3_LEN>(body)?;
                self.res_finish(rs3)
            }
            Phase::IAwaitHs2 | Phase::ISigning | Phase::IAwaitHs4 | Phase::RAwaitHs3 | Phase::RSigning
                if resume_type =>
            {
                Err(HsError::PathMismatch)
            }
            Phase::ResAwaitRs2 | Phase::ResSigning | Phase::ResAwaitRs3 if full_type => {
                Err(HsError::PathMismatch)
            }
            _ => Err(HsError::Malformed),
        }
    }

    fn on_hs1(&mut self, body: &[u8]) -> Result<Vec<HsOut>, HsError> {
        let peer = arr::<HS1_LEN>(body)?;
        if peer[0] != PROTO_V2 || peer[1] != SUITE_V2 {
            return Err(HsError::VersionMismatch);
        }
        let caps = u16::from_be_bytes([peer[2], peer[3]]);
        if caps & CAP_SUITE_V2 == 0 || caps & CAP_RESERVED_MASK != 0 {
            return Err(HsError::VersionMismatch);
        }
        let peer_nonce: [u8; 16] = field(&peer, OFF_NONCE)?;
        let local_nonce: [u8; 16] = field(&self.hs1_local, OFF_NONCE)?;
        if bool::from(peer_nonce.ct_eq(&local_nonce)) {
            return Err(HsError::Malformed); // reflected HS1
        }
        let we_dial = matches!(self.side, CallSide::Dialer { .. });
        if (caps & CAP_DIALER != 0) == we_dial {
            return Err(HsError::SideConflict);
        }
        let role = match self.hs1_local[OFF_COMMIT..].cmp(&peer[OFF_COMMIT..]) {
            core::cmp::Ordering::Greater => Role::Initiator,
            core::cmp::Ordering::Less => Role::Responder,
            core::cmp::Ordering::Equal => return Err(HsError::RoleTie),
        };
        let gear = self.hs1_local[OFF_GEAR].min(peer[OFF_GEAR]);
        self.role = Some(role);
        self.gear = Some(gear);
        self.peer_hs1 = Some(peer);

        let (hs1_i, hs1_r, pre_i, pre_r) = match role {
            Role::Initiator => (self.hs1_local, peer, self.link.local_preamble, self.link.peer_preamble),
            Role::Responder => (peer, self.hs1_local, self.link.peer_preamble, self.link.local_preamble),
        };
        self.transcript.update(PROTOCOL_LABEL);
        self.transcript.update(pre_i);
        self.transcript.update(pre_r);
        self.transcript.update([gear]);
        self.transcript.update(hs1_i);
        self.transcript.update(hs1_r);
        if we_dial {
            // The answerer decides; nothing is sent until its PATH arrives.
            self.phase = Phase::AwaitPath;
            return Ok(Vec::new());
        }

        // Answerer: the dialer's tag against every PSK contact.
        let peer_tag: [u8; 8] = field(&peer, OFF_PSK)?;
        let mut peer_match: Option<u32> = None;
        for (c, _, psk) in &self.expect.psk {
            let hit = bool::from(psk_tag(psk, &peer_nonce).ct_eq(&peer_tag));
            if hit && peer_match.is_none() {
                peer_match = Some(*c);
            }
        }

        // The dialer's rid0 (its rs_cur) and rid1 (its rs_new) against every resume secret.
        // The newest common secret wins: a hit on the dialer's rs_new or on our rs_new ranks higher.
        let peer_rid0: [u8; 8] = field(&peer, OFF_RID0)?;
        let peer_rid1: [u8; 8] = field(&peer, OFF_RID1)?;
        let mut chosen: Option<(usize, bool, u8)> = None;
        for (idx, c) in self.expect.resume.iter().enumerate() {
            let rid = resume_rid(&c.secret, &peer_nonce, &c.pub33);
            let hit0 = bool::from(rid.ct_eq(&peer_rid0));
            let hit1 = bool::from(rid.ct_eq(&peer_rid1));
            if !(hit0 || hit1) {
                continue;
            }
            let score = u8::from(hit1) * 2 + u8::from(c.is_new);
            if chosen.is_none_or(|(_, _, s)| score > s) {
                chosen = Some((idx, hit1, score));
            }
        }

        let (path_msg, choice) = match chosen {
            Some((idx, dialer_new, _)) => (
                [PATH_RESUME, if dialer_new { PATH_FLAG_RS_NEW } else { 0 }],
                Choice::Resume(idx),
            ),
            None => (
                [PATH_FULL, if peer_match.is_some() { PATH_FLAG_PSK } else { 0 }],
                Choice::Full(peer_match),
            ),
        };
        let mut outs = vec![HsOut::Send { msg_type: MSG_PATH, body: path_msg.to_vec() }];
        outs.extend(self.enter_path(&path_msg, choice)?);
        Ok(outs)
    }

    /// Dialer: the answerer's decision. Anything that contradicts what we advertised aborts.
    fn on_path(&mut self, body: &[u8]) -> Result<Vec<HsOut>, HsError> {
        let msg = arr::<PATH_LEN>(body)?;
        let [path, flags] = msg;
        if flags & !(PATH_FLAG_PSK | PATH_FLAG_RS_NEW) != 0 {
            return Err(HsError::Malformed);
        }
        let CallSide::Dialer { contact } = self.side else { return Err(HsError::Malformed) };
        let choice = match path {
            PATH_FULL => {
                if flags & PATH_FLAG_RS_NEW != 0 {
                    return Err(HsError::Malformed);
                }
                if flags & PATH_FLAG_PSK != 0 {
                    let own = contact.filter(|h| self.expect.psk.iter().any(|(c, _, _)| c == h));
                    Choice::Full(Some(own.ok_or(HsError::PathMismatch)?))
                } else {
                    // We dialed a PSK contact: whoever answered must hold that PSK (or the
                    // contact's resume secret). No unauthenticated fallback for such a contact.
                    if contact.is_some_and(|h| self.expect.psk.iter().any(|(c, _, _)| *c == h)) {
                        return Err(HsError::PskRequired);
                    }
                    Choice::Full(None)
                }
            }
            PATH_RESUME => {
                if flags & PATH_FLAG_PSK != 0 {
                    return Err(HsError::Malformed);
                }
                let (cur, new) = hint_resume(&self.expect, contact);
                let idx = if flags & PATH_FLAG_RS_NEW != 0 { new } else { cur };
                Choice::Resume(idx.ok_or(HsError::PathMismatch)?)
            }
            _ => return Err(HsError::Malformed),
        };
        self.enter_path(&msg, choice)
    }

    /// Absorbs PATH, fixes th0 and starts the chosen path.
    fn enter_path(&mut self, path_msg: &[u8; PATH_LEN], choice: Choice) -> Result<Vec<HsOut>, HsError> {
        let role = self.role_or_err()?;
        self.transcript.update(path_msg);
        self.th0 = self.snap();
        let psk_contact = match choice {
            Choice::Resume(idx) => {
                let c = self.expect.resume.get(idx).ok_or(HsError::Malformed)?;
                self.ck = extract(&self.th0, &[c.secret.as_bytes()]);
                self.path = Some(Path::Resume { contact: c.contact, used_new: c.is_new });
                self.resume_pin = Some(c.pub33);
                self.psk_contact = None;
                self.kem = None;
                self.phase = Phase::ResAwaitRs2;
                return Ok(vec![HsOut::Send { msg_type: MSG_RS2, body: self.x_pub.to_vec() }]);
            }
            Choice::Full(p) => p,
        };
        self.path = Some(Path::Full);
        self.psk_contact = psk_contact;
        let zero = [0u8; 32];
        let psk_bytes = psk_contact
            .and_then(|pc| self.expect.psk.iter().find(|(c, _, _)| *c == pc))
            .map(|(_, _, k)| k.as_bytes())
            .unwrap_or(&zero);
        self.ck = extract(&self.th0, &[psk_bytes]);
        match role {
            Role::Responder => {
                let ek = self.kem.as_ref().map(|(_, ek)| ek.clone()).ok_or(HsError::Malformed)?;
                let hs2 = concat(&[&self.x_pub, &ek]);
                if hs2.len() != HS2_LEN {
                    return Err(HsError::Malformed);
                }
                self.transcript.update(&hs2);
                self.phase = Phase::RAwaitHs3;
                Ok(vec![HsOut::Send { msg_type: MSG_HS2, body: hs2 }])
            }
            Role::Initiator => {
                self.kem = None;
                self.phase = Phase::IAwaitHs2;
                Ok(Vec::new())
            }
        }
    }

    fn on_hs2(&mut self, body: &[u8]) -> Result<Vec<HsOut>, HsError> {
        if body.len() != HS2_LEN {
            return Err(HsError::Malformed);
        }
        let x_r: [u8; 32] = field(body, 0)?;
        self.check_peer_commit(&x_r)?;
        let ek = body.get(32..).ok_or(HsError::Malformed)?;
        self.transcript.update(body);
        self.transcript.update(self.x_pub);
        let th_sas = self.snap();
        let dh = self.dh(&x_r)?;
        let ck1 = extract(self.ck.as_slice(), &[dh.as_slice()]);
        let mut sas = [0u8; SAS_LEN];
        expand(ck1.as_slice(), &[b"sas", &th_sas], &mut sas);
        let (ct, ss) = kem_encapsulate(ek, &mut OsRng).ok_or(HsError::Malformed)?;
        self.transcript.update(&ct);
        let th3 = self.snap();
        let ck2 = extract(ck1.as_slice(), &[ss.as_slice()]);
        self.k_i2r = Some(expand32(ck2.as_slice(), &[b"hs i2r", &th3]));
        self.ck = ck2;
        self.th_mark = th3;
        self.pending_ct = Some(ct);
        let to_sign = concat(&[
            b"AegisChat-v2 auth I",
            &th3,
            &self.local.pub33,
            &self.local.evidence_id,
        ]);
        let req = self.new_sign_req(to_sign);
        self.phase = Phase::ISigning;
        Ok(vec![HsOut::Sas(sas), req])
    }

    fn on_hs3(&mut self, body: &[u8]) -> Result<Vec<HsOut>, HsError> {
        if body.len() != HS3_LEN {
            return Err(HsError::Malformed);
        }
        let x_i: [u8; 32] = field(body, 0)?;
        self.check_peer_commit(&x_i)?;
        self.transcript.update(x_i);
        let th_sas = self.snap();
        let dh = self.dh(&x_i)?;
        let ck1 = extract(self.ck.as_slice(), &[dh.as_slice()]);
        let mut sas = [0u8; SAS_LEN];
        expand(ck1.as_slice(), &[b"sas", &th_sas], &mut sas);

        let ct_end = 32 + MLKEM1024_CT_LEN;
        let ct = body.get(32..ct_end).ok_or(HsError::Malformed)?;
        self.transcript.update(ct);
        let th3 = self.snap();
        let (dk, _) = self.kem.take().ok_or(HsError::Malformed)?;
        let ss = kem_decapsulate(&dk, ct).ok_or(HsError::Malformed)?;
        drop(dk);
        let ck2 = extract(ck1.as_slice(), &[ss.as_slice()]);
        let k_i2r = expand32(ck2.as_slice(), &[b"hs i2r", &th3]);
        let sealed = body.get(ct_end..).ok_or(HsError::Malformed)?;
        let id = aead_open_once(&k_i2r, &th3, sealed).ok_or(HsError::AeadFail)?;
        let peer = self.verify_peer_id(&id, b"AegisChat-v2 auth I", &th3)?;

        self.transcript.update(sealed);
        let th4 = self.snap();
        self.k_r2i = Some(expand32(ck2.as_slice(), &[b"hs r2i", &th4]));
        self.ck = ck2;
        self.th4 = th4;
        self.peer = Some(peer);
        let to_sign = concat(&[
            b"AegisChat-v2 auth R",
            &th4,
            &self.local.pub33,
            &self.local.evidence_id,
        ]);
        let req = self.new_sign_req(to_sign);
        self.phase = Phase::RSigning;
        Ok(vec![HsOut::Sas(sas), req])
    }

    fn on_hs4(&mut self, body: &[u8]) -> Result<Vec<HsOut>, HsError> {
        let sealed = arr::<HS4_LEN>(body)?;
        let k = self.k_r2i.as_ref().ok_or(HsError::Malformed)?;
        let th4 = self.th4;
        let id = aead_open_once(k, &th4, &sealed).ok_or(HsError::AeadFail)?;
        let peer = self.verify_peer_id(&id, b"AegisChat-v2 auth R", &th4)?;
        self.transcript.update(sealed);
        let th5 = self.snap();
        let est = self.finish(&th5, peer)?;
        Ok(vec![HsOut::Established(Box::new(est))])
    }

    fn verify_peer_id(&self, id: &[u8], label: &[u8], th: &[u8; 48]) -> Result<PeerIdentity, HsError> {
        if id.len() != ID_BLOCK_LEN {
            return Err(HsError::Malformed);
        }
        let pub33: [u8; PUB33_LEN] = field(id, 0)?;
        let evidence_id: [u8; EVIDENCE_ID_LEN] = field(id, PUB33_LEN)?;
        let sig: [u8; RAW_SIG_LEN] = field(id, PUB33_LEN + EVIDENCE_ID_LEN)?;
        validate_pub33(&pub33).map_err(|_| HsError::BadSignature)?;
        let msg = concat(&[label, th, &pub33, &evidence_id]);
        verify_identity_sig(&pub33, &msg, &sig).map_err(|_| HsError::BadSignature)?;
        self.enforce_psk(&pub33)?;
        Ok(PeerIdentity { pub33, evidence_id })
    }

    /// §6.2: a peer whose pub33 belongs to a PSK contact must have had that PSK mixed in,
    /// and a mixed PSK must belong to the revealed identity.
    fn enforce_psk(&self, pub33: &[u8; 33]) -> Result<(), HsError> {
        let is_psk_contact = self.expect.psk.iter().any(|(_, pk, _)| bool::from(pk.ct_eq(pub33)));
        let mixed_matches = self.psk_contact.is_some_and(|pc| {
            self.expect
                .psk
                .iter()
                .any(|(c, pk, _)| *c == pc && bool::from(pk.ct_eq(pub33)))
        });
        if is_psk_contact && !mixed_matches {
            return Err(HsError::PskRequired);
        }
        if self.psk_contact.is_some() && !mixed_matches {
            return Err(HsError::PskMismatch);
        }
        Ok(())
    }

    fn finish(&mut self, th: &[u8; 48], peer: PeerIdentity) -> Result<Established, HsError> {
        let role = self.role_or_err()?;
        let path = self.path.ok_or(HsError::Malformed)?;
        let mut transcript_tag = [0u8; 4];
        transcript_tag.copy_from_slice(&th[..4]);
        let est = Established {
            root0: expand32(self.ck.as_slice(), &[b"root", th]),
            chaff_seed: expand32(self.ck.as_slice(), &[b"chaff", th]),
            rs_next: expand32(self.ck.as_slice(), &[b"resume next", th]),
            transcript_tag,
            role,
            peer,
            path,
            psk_contact: self.psk_contact,
        };
        self.phase = Phase::Done;
        self.wipe();
        Ok(est)
    }

    fn on_rs2(&mut self, body: &[u8]) -> Result<Vec<HsOut>, HsError> {
        let x_peer = arr::<RS2_LEN>(body)?;
        self.check_peer_commit(&x_peer)?;
        let role = self.role_or_err()?;
        let (x_i, x_r) = match role {
            Role::Initiator => (self.x_pub, x_peer),
            Role::Responder => (x_peer, self.x_pub),
        };
        let th_r = sha384(&[&self.th0, &[0x52], &x_i, &x_r]);
        let dh = self.dh(&x_peer)?;
        let ck1 = extract(self.ck.as_slice(), &[dh.as_slice()]);
        self.k_i2r = Some(expand32(ck1.as_slice(), &[b"rs i2r", &th_r]));
        self.k_r2i = Some(expand32(ck1.as_slice(), &[b"rs r2i", &th_r]));
        self.ck = ck1;
        self.th_mark = th_r;
        let label: &[u8] = match role {
            Role::Initiator => b"AegisChat-v2 resume I",
            Role::Responder => b"AegisChat-v2 resume R",
        };
        let to_sign = concat(&[label, &th_r, &self.local.pub33]);
        let req = self.new_sign_req(to_sign);
        self.phase = Phase::ResSigning;
        Ok(vec![req])
    }

    fn sig_step(&mut self, req_id: u32, sig_der: &[u8]) -> Result<Vec<HsOut>, HsError> {
        match self.phase {
            Phase::ISigning | Phase::RSigning | Phase::ResSigning => {}
            Phase::Aborted => return Err(HsError::Aborted),
            _ => return Err(HsError::SignerFailed),
        }
        let (id, msg) = self.sign_req.take().ok_or(HsError::SignerFailed)?;
        if id != req_id {
            return Err(HsError::SignerFailed);
        }
        let sig = ecdsa_der_to_raw(sig_der).map_err(|_| HsError::SignerFailed)?;
        verify_identity_sig(&self.local.pub33, &msg, &sig).map_err(|_| HsError::SignerFailed)?;
        self.send_signed(sig)
    }

    fn send_signed(&mut self, sig: [u8; RAW_SIG_LEN]) -> Result<Vec<HsOut>, HsError> {
        match self.phase {
            Phase::ISigning => {
                let id = concat(&[&self.local.pub33, &self.local.evidence_id, &sig]);
                let k = self.k_i2r.take().ok_or(HsError::Malformed)?;
                let sealed = aead_seal_once(&k, &self.th_mark, &id).ok_or(HsError::Malformed)?;
                drop(k);
                if sealed.len() != ID_SEALED_LEN {
                    return Err(HsError::Malformed);
                }
                let ct = self.pending_ct.take().ok_or(HsError::Malformed)?;
                let hs3 = concat(&[&self.x_pub, &ct, &sealed]);
                if hs3.len() != HS3_LEN {
                    return Err(HsError::Malformed);
                }
                self.transcript.update(&sealed);
                let th4 = self.snap();
                self.k_r2i = Some(expand32(self.ck.as_slice(), &[b"hs r2i", &th4]));
                self.th4 = th4;
                self.phase = Phase::IAwaitHs4;
                Ok(vec![HsOut::Send { msg_type: MSG_HS3, body: hs3 }])
            }
            Phase::RSigning => {
                let id = concat(&[&self.local.pub33, &self.local.evidence_id, &sig]);
                let k = self.k_r2i.take().ok_or(HsError::Malformed)?;
                let sealed = aead_seal_once(&k, &self.th4, &id).ok_or(HsError::Malformed)?;
                drop(k);
                if sealed.len() != HS4_LEN {
                    return Err(HsError::Malformed);
                }
                self.transcript.update(&sealed);
                let th5 = self.snap();
                let peer = self.peer.clone().ok_or(HsError::Malformed)?;
                let est = self.finish(&th5, peer)?;
                Ok(vec![
                    HsOut::Send { msg_type: MSG_HS4, body: sealed },
                    HsOut::Established(Box::new(est)),
                ])
            }
            Phase::ResSigning => {
                let role = self.role_or_err()?;
                let k = match role {
                    Role::Initiator => self.k_i2r.as_ref(),
                    Role::Responder => self.k_r2i.as_ref(),
                }
                .ok_or(HsError::Malformed)?;
                let sealed = aead_seal_once(k, &self.th_mark, &sig).ok_or(HsError::Malformed)?;
                let rs3 = arr::<RS3_LEN>(&sealed)?;
                self.own_rs3 = Some(rs3);
                self.phase = Phase::ResAwaitRs3;
                let mut out = vec![HsOut::Send { msg_type: MSG_RS3, body: sealed }];
                if let Some(p) = self.peer_rs3.take() {
                    out.extend(self.res_finish(p)?);
                }
                Ok(out)
            }
            _ => Err(HsError::SignerFailed),
        }
    }

    fn res_finish(&mut self, peer_rs3: [u8; RS3_LEN]) -> Result<Vec<HsOut>, HsError> {
        let role = self.role_or_err()?;
        let th_r = self.th_mark;
        let (k_peer, label): (Option<&SecretKey32>, &[u8]) = match role {
            Role::Initiator => (self.k_r2i.as_ref(), b"AegisChat-v2 resume R"),
            Role::Responder => (self.k_i2r.as_ref(), b"AegisChat-v2 resume I"),
        };
        let k_peer = k_peer.ok_or(HsError::Malformed)?;
        let sig = aead_open_once(k_peer, &th_r, &peer_rs3).ok_or(HsError::ResumeAuthFailed)?;
        let sig: [u8; RAW_SIG_LEN] = arr(&sig)?;
        let pin = self.resume_pin.ok_or(HsError::Malformed)?;
        let msg = concat(&[label, &th_r, &pin]);
        verify_identity_sig(&pin, &msg, &sig).map_err(|_| HsError::BadSignature)?;
        let own = self.own_rs3.ok_or(HsError::Malformed)?;
        let (rs3_i, rs3_r) = match role {
            Role::Initiator => (own, peer_rs3),
            Role::Responder => (peer_rs3, own),
        };
        let th_f = sha384(&[&th_r, &rs3_i, &rs3_r]);
        let peer = PeerIdentity { pub33: pin, evidence_id: [0u8; EVIDENCE_ID_LEN] };
        let est = self.finish(&th_f, peer)?;
        Ok(vec![HsOut::Established(Box::new(est))])
    }
}

impl Drop for HandshakeV2 {
    fn drop(&mut self) {
        self.wipe();
    }
}

#[cfg(test)]
#[path = "handshake_v2_tests.rs"]
mod tests;
