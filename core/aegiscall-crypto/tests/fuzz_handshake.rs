//! Mutation fuzzing of handshake v2 (full path, full path with pairing PSK, resume path).
//!
//! Every iteration is derived from a fixed base seed, so a failure is reproduced by the numbers the
//! failure banner prints (AEGIS_FUZZ_SEED, AEGIS_FUZZ_START, AEGIS_FUZZ_ITERS=1). The only input the
//! seed does not control is the ML-KEM encapsulation randomness the library draws from the OS RNG
//! inside on_message; control flow and every mutation choice are seed-driven.
//!
//! Invariants asserted:
//!  1. no input ever panics;
//!  2. when both sides are established, root0 / chaff seed / rs_next / transcript tag / SAS / path
//!     are identical and the roles are opposite;
//!  3. a message whose content was altered in transit never ends with both sides established, and
//!     an established side always holds the true counterpart identity, path and PSK contact;
//!  4. after a HsError the object stays aborted (every later input is Err(Aborted)) and never
//!     becomes established; after establishment every input is Ok(empty).
//!
//! Knobs: AEGIS_FUZZ_ITERS (iterations per path), AEGIS_FUZZ_SEED, AEGIS_FUZZ_START.

use aegiscall_crypto::handshake_v2::{CAP_DIALER, CAP_SUITE_V2, MSG_HS1, MSG_PATH};
use aegiscall_crypto::{
    CallSide, Established, HandshakeV2, HsError, HsOut, LinkContext, Path, PeerExpectation, ResumeCandidate,
    Role, SoftwareSigner, HS1_LEN, HS2_LEN, HS3_LEN, HS4_LEN, PATH_LEN, RS2_LEN, RS3_LEN,
};
use aegiscall_memsec::SecretKey32;
use rand_core::{CryptoRng, RngCore};
use std::collections::VecDeque;
use std::panic::{catch_unwind, resume_unwind, AssertUnwindSafe};
use std::time::Instant;

const DEFAULT_ITERS_RELEASE: u64 = 10_000;
const DEFAULT_ITERS_DEBUG: u64 = 20;
const DEFAULT_SEED: u64 = 0x0AE6_15C4_A720_2611;

// ---------------------------------------------------------------------------------------------
// Deterministic RNG (splitmix64) usable as the handshake's CryptoRngCore.
// ---------------------------------------------------------------------------------------------

struct Rng(u64);

impl Rng {
    fn step(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        assert!(n > 0);
        (self.step() % n as u64) as usize
    }
    fn range(&mut self, lo: usize, hi_incl: usize) -> usize {
        lo + self.below(hi_incl - lo + 1)
    }
    fn chance(&mut self, pct: u64) -> bool {
        self.step() % 100 < pct
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        let mut v = vec![0u8; n];
        self.fill_bytes(&mut v);
        v
    }
    fn bytes_below(&mut self, n: usize) -> Vec<u8> {
        let l = self.below(n);
        self.bytes(l)
    }
}

impl RngCore for Rng {
    fn next_u32(&mut self) -> u32 {
        (self.step() >> 32) as u32
    }
    fn next_u64(&mut self) -> u64 {
        self.step()
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for c in dest.chunks_mut(8) {
            let b = self.step().to_le_bytes();
            c.copy_from_slice(&b[..c.len()]);
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for Rng {}

fn env_u64(name: &str) -> Option<u64> {
    let v = std::env::var(name).ok()?;
    let v = v.trim();
    match v.strip_prefix("0x") {
        Some(h) => u64::from_str_radix(h, 16).ok(),
        None => v.parse().ok(),
    }
}

fn iters() -> u64 {
    env_u64("AEGIS_FUZZ_ITERS").unwrap_or(if cfg!(debug_assertions) { DEFAULT_ITERS_DEBUG } else { DEFAULT_ITERS_RELEASE })
}

fn mix(base: u64, kind: PathKind, iter: u64) -> u64 {
    let mut r = Rng(base ^ ((kind as u64 + 1) << 56) ^ iter.wrapping_mul(0xD6E8_FEB8_6659_FD93));
    r.step()
}

// ---------------------------------------------------------------------------------------------
// Parties and the scenario set-up.
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PathKind {
    Full = 0,
    Psk = 1,
    Resume = 2,
}

type Rec = (usize, u8, Vec<u8>);

struct P {
    name: &'static str,
    hs: HandshakeV2,
    signer: SoftwareSigner,
    out: VecDeque<(u8, Vec<u8>)>,
    sigs: VecDeque<(u32, Vec<u8>)>,
    est: Option<Box<Established>>,
    sas: Option<[u8; 5]>,
    dead: bool,
}

impl P {
    fn new(
        name: &'static str,
        signer: SoftwareSigner,
        link: LinkContext,
        e: PeerExpectation,
        side: CallSide,
        rng: &mut Rng,
    ) -> Self {
        let id = signer.local_identity([signer.pub33()[1]; 16]);
        let (hs, outs) = HandshakeV2::start(id, link, e, side, rng).expect("start");
        let mut p = P {
            name,
            hs,
            signer,
            out: VecDeque::new(),
            sigs: VecDeque::new(),
            est: None,
            sas: None,
            dead: false,
        };
        p.absorb("start", Ok(outs)).expect("start outputs");
        p
    }

    /// Applies one library result and checks the per-object invariants (4).
    fn absorb(&mut self, what: &str, r: Result<Vec<HsOut>, HsError>) -> Result<(), HsError> {
        let (was_dead, was_est) = (self.dead, self.est.is_some());
        match r {
            Ok(v) => {
                assert!(!was_dead, "{}: aborted object answered {} with Ok", self.name, what);
                if was_est {
                    assert!(v.is_empty(), "{}: established object produced output on {}", self.name, what);
                }
                for o in v {
                    match o {
                        HsOut::Send { msg_type, body } => self.out.push_back((msg_type, body)),
                        HsOut::NeedSignature { req_id, to_sign } => self.sigs.push_back((req_id, to_sign)),
                        HsOut::Sas(s) => self.sas = Some(s),
                        HsOut::Established(e) => {
                            assert!(self.est.is_none(), "{}: established twice", self.name);
                            self.est = Some(e);
                        }
                    }
                }
                assert!(!self.hs.is_aborted(), "{}: Ok result but object is aborted ({})", self.name, what);
                assert_eq!(
                    self.hs.is_established(),
                    self.est.is_some(),
                    "{}: is_established disagrees with the Established output ({})",
                    self.name,
                    what
                );
                Ok(())
            }
            Err(e) => {
                assert!(!was_est, "{}: established object returned {:?} on {}", self.name, e, what);
                if was_dead {
                    assert_eq!(e, HsError::Aborted, "{}: aborted object answered {} with {:?}", self.name, what, e);
                }
                self.dead = true;
                assert!(
                    self.hs.is_aborted() && !self.hs.is_established(),
                    "{}: {:?} on {} did not leave the object aborted",
                    self.name,
                    e,
                    what
                );
                Err(e)
            }
        }
    }

    fn on_msg(&mut self, t: u8, body: &[u8]) -> Result<(), HsError> {
        let r = self.hs.on_message(t, body);
        self.absorb("on_message", r)
    }

    fn on_sig(&mut self, id: u32, der: &[u8]) -> Result<(), HsError> {
        let r = self.hs.on_signature(id, der);
        self.absorb("on_signature", r)
    }

    fn on_timeout(&mut self) {
        let was_est = self.est.is_some();
        assert_eq!(self.hs.on_timeout(), HsError::Timeout);
        if was_est {
            assert!(self.hs.is_established() && !self.hs.is_aborted(), "{}: timeout changed an established object", self.name);
        } else {
            self.dead = true;
            assert!(self.hs.is_aborted() && !self.hs.is_established(), "{}: timeout did not abort", self.name);
        }
    }

    fn abort(&mut self) {
        let was_est = self.est.is_some();
        self.hs.abort();
        if was_est {
            assert!(self.hs.is_established() && !self.hs.is_aborted(), "{}: abort() changed an established object", self.name);
        } else {
            self.dead = true;
            assert!(self.hs.is_aborted() && !self.hs.is_established(), "{}: abort() did not abort", self.name);
        }
    }
}

struct Ctx {
    kind: PathKind,
    pub_a: [u8; 33],
    pub_b: [u8; 33],
    evid_a: [u8; 16],
    evid_b: [u8; 16],
    psk_a: Option<u32>,
    psk_b: Option<u32>,
    contact_a: u32,
    contact_b: u32,
}

fn key(b: [u8; 32]) -> SecretKey32 {
    SecretKey32::from_bytes(b)
}

fn rnd32(rng: &mut Rng) -> [u8; 32] {
    let mut k = [0u8; 32];
    rng.fill_bytes(&mut k);
    k
}

fn cands(contact: u32, pk: [u8; 33], cur: [u8; 32], new: Option<[u8; 32]>) -> Vec<ResumeCandidate> {
    let mut v = vec![ResumeCandidate { contact, pub33: pk, secret: key(cur), is_new: false }];
    if let Some(n) = new {
        v.push(ResumeCandidate { contact, pub33: pk, secret: key(n), is_new: true });
    }
    v
}

fn build(kind: PathKind, rng: &mut Rng) -> (P, P, Ctx) {
    let sa = SoftwareSigner::from_seed([0xA1; 32]);
    let sb = SoftwareSigner::from_seed([0xB2; 32]);
    let (pa, pb) = (sa.pub33(), sb.pub33());
    let decoy = SoftwareSigner::from_seed([0xC3; 32]).pub33();
    let none = || PeerExpectation { psk: vec![], resume: vec![] };
    let (ea, eb, side_a, psk_a, psk_b, contact_a, contact_b) = match kind {
        PathKind::Full => (none(), none(), CallSide::Dialer { contact: None }, None, None, 0, 0),
        PathKind::Psk => {
            let (k, k2, k3) = (rnd32(rng), rnd32(rng), rnd32(rng));
            (
                PeerExpectation { psk: vec![(3, decoy, key(k2)), (7, pb, key(k))], resume: vec![] },
                PeerExpectation { psk: vec![(5, decoy, key(k3)), (9, pa, key(k))], resume: vec![] },
                CallSide::Dialer { contact: Some(7) },
                Some(7),
                Some(9),
                0,
                0,
            )
        }
        PathKind::Resume => {
            let cur = rnd32(rng);
            let shared_new = rng.chance(40);
            let a_extra = !shared_new && rng.chance(20);
            let n = rnd32(rng);
            let n2 = rnd32(rng);
            (
                PeerExpectation { psk: vec![], resume: cands(1, pb, cur, if shared_new { Some(n) } else if a_extra { Some(n2) } else { None }) },
                PeerExpectation { psk: vec![], resume: cands(2, pa, cur, if shared_new { Some(n) } else { None }) },
                CallSide::Dialer { contact: Some(1) },
                None,
                None,
                1,
                2,
            )
        }
    };
    let (x, y) = ([1, 2, 3, 4, 5], [6, 7, 8, 9, 10]);
    let la = LinkContext { local_preamble: x, peer_preamble: y, gear: 2 };
    let lb = LinkContext { local_preamble: y, peer_preamble: x, gear: 3 };
    let ctx = Ctx {
        kind,
        pub_a: pa,
        pub_b: pb,
        evid_a: [pa[1]; 16],
        evid_b: [pb[1]; 16],
        psk_a,
        psk_b,
        contact_a,
        contact_b,
    };
    let a = P::new("A(dialer)", sa, la, ea, side_a, rng);
    let b = P::new("B(answerer)", sb, lb, eb, CallSide::Answerer, rng);
    (a, b, ctx)
}

// ---------------------------------------------------------------------------------------------
// Mutation plan and the message pump.
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mut {
    Flip,
    Trunc,
    Extend,
    Retype,
    Random,
    Foreign,
    Replay,
    Dup,
    Swap,
    Drop,
}

const ALL_MUTS: [Mut; 10] = [
    Mut::Flip,
    Mut::Trunc,
    Mut::Extend,
    Mut::Retype,
    Mut::Random,
    Mut::Foreign,
    Mut::Replay,
    Mut::Dup,
    Mut::Swap,
    Mut::Drop,
];

struct Plan {
    at: usize,
    kind: Mut,
    held: Option<(usize, u8, Vec<u8>)>,
    modified: bool,
    applied: bool,
}

impl Plan {
    fn apply(&mut self, idx: usize, src: usize, t: u8, body: Vec<u8>, rec: &[Rec], prev: &[Rec], rng: &mut Rng) -> Vec<(u8, Vec<u8>)> {
        let mut out = Vec::new();
        if idx != self.at {
            out.push((t, body));
            if self.held.as_ref().is_some_and(|h| h.0 == src) {
                if let Some(h) = self.held.take() {
                    out.push((h.1, h.2));
                }
            }
            return out;
        }
        self.applied = true;
        let orig = (t, body.clone());
        let (mut nt, mut nb) = (t, body);
        match self.kind {
            Mut::Flip => {
                let bit = rng.below(nb.len() * 8);
                nb[bit / 8] ^= 1 << (bit % 8);
            }
            Mut::Trunc => {
                let l = rng.below(nb.len());
                nb.truncate(l);
            }
            Mut::Extend => {
                let n = rng.range(1, 40);
                nb.extend(rng.bytes(n));
            }
            Mut::Retype => {
                nt = loop {
                    let c = if rng.chance(70) { rng.range(1, 7) as u8 } else { rng.below(256) as u8 };
                    if c != t {
                        break c;
                    }
                };
            }
            Mut::Random => {
                let l = if rng.chance(50) { nb.len() } else { rng.below(2000) };
                nb = rng.bytes(l);
                if rng.chance(20) {
                    nt = rng.below(256) as u8;
                }
            }
            Mut::Foreign => {
                let c: Vec<&Rec> = prev.iter().filter(|r| r.1 == t).collect();
                if c.is_empty() {
                    nb = rng.bytes(nb.len());
                } else {
                    nb = c[rng.below(c.len())].2.clone();
                }
            }
            Mut::Replay => {
                let earlier: Vec<&Rec> = rec.iter().take(idx).filter(|r| r.0 == src).collect();
                out.push(orig.clone());
                if earlier.is_empty() {
                    out.push(orig.clone());
                } else {
                    let e = earlier[rng.below(earlier.len())];
                    out.push((e.1, e.2.clone()));
                }
                return out;
            }
            Mut::Dup => {
                out.push(orig.clone());
                out.push(orig);
                return out;
            }
            Mut::Swap => {
                self.held = Some((src, t, nb));
                return out;
            }
            Mut::Drop => return out,
        }
        self.modified = (nt, &nb) != (orig.0, &orig.1);
        out.push((nt, nb));
        out
    }
}

fn drive(a: &mut P, b: &mut P, mut plan: Option<&mut Plan>, limit: usize, rec: &mut Vec<Rec>, prev: &[Rec], rng: &mut Rng) {
    let mut events = 0usize;
    let mut idx = 0usize;
    loop {
        let mut progressed = false;
        for s in 0..2 {
            if events >= limit {
                return;
            }
            let (src, dst) = if s == 0 { (&mut *a, &mut *b) } else { (&mut *b, &mut *a) };
            if let Some((t, body)) = src.out.pop_front() {
                progressed = true;
                events += 1;
                rec.push((s, t, body.clone()));
                let deliveries = match plan.as_deref_mut() {
                    Some(p) => p.apply(idx, s, t, body, rec, prev, rng),
                    None => vec![(t, body)],
                };
                idx += 1;
                for (dt, db) in deliveries {
                    let _ = dst.on_msg(dt, &db);
                }
            }
        }
        if progressed {
            continue;
        }
        if let Some(p) = plan.as_deref_mut() {
            if let Some((s, t, body)) = p.held.take() {
                let dst = if s == 0 { &mut *b } else { &mut *a };
                let _ = dst.on_msg(t, &body);
                continue;
            }
        }
        for p in [&mut *a, &mut *b] {
            if events >= limit {
                return;
            }
            if let Some((id, msg)) = p.sigs.pop_front() {
                progressed = true;
                events += 1;
                let der = p.signer.sign_der(&msg);
                let _ = p.on_sig(id, &der);
            }
        }
        if !progressed {
            break;
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Outcome checks.
// ---------------------------------------------------------------------------------------------

fn check_single(ctx: &Ctx, is_a: bool, e: &Established) {
    let who = if is_a { "A" } else { "B" };
    let (peer_pub, peer_evid, psk, contact) =
        if is_a { (ctx.pub_b, ctx.evid_b, ctx.psk_a, ctx.contact_a) } else { (ctx.pub_a, ctx.evid_a, ctx.psk_b, ctx.contact_b) };
    assert_eq!(e.peer.pub33, peer_pub, "{who} established with a foreign identity");
    assert_eq!(e.psk_contact, psk, "{who} established with the wrong PSK contact");
    match ctx.kind {
        PathKind::Full | PathKind::Psk => {
            assert_eq!(e.path, Path::Full, "{who}: wrong path");
            assert_eq!(e.peer.evidence_id, peer_evid, "{who}: evidence id differs from the peer's");
        }
        PathKind::Resume => match e.path {
            Path::Resume { contact: c, .. } => assert_eq!(c, contact, "{who}: resumed the wrong contact"),
            Path::Full => panic!("{who}: resume scenario ended on the full path"),
        },
    }
}

fn check_pair(ctx: &Ctx, a: &P, b: &P) {
    let (Some(ea), Some(eb)) = (&a.est, &b.est) else { return };
    assert_eq!(ea.root0.as_bytes(), eb.root0.as_bytes(), "root0 differs");
    assert_eq!(ea.chaff_seed.as_bytes(), eb.chaff_seed.as_bytes(), "chaff_seed differs");
    assert_eq!(ea.rs_next.as_bytes(), eb.rs_next.as_bytes(), "rs_next differs");
    assert_eq!(ea.transcript_tag, eb.transcript_tag, "transcript tag differs");
    assert_ne!(ea.role, eb.role, "both sides took the same role");
    assert!(matches!((ea.role, eb.role), (Role::Initiator, Role::Responder) | (Role::Responder, Role::Initiator)));
    assert_eq!(a.sas, b.sas, "SAS differs");
    assert_eq!(a.sas.is_some(), ctx.kind != PathKind::Resume, "SAS presence does not match the path");
    check_single(ctx, true, ea);
    check_single(ctx, false, eb);
    if let (Path::Resume { used_new: x, .. }, Path::Resume { used_new: y, .. }) = (ea.path, eb.path) {
        assert_eq!(x, y, "sides resumed with different secret generations");
    }
}

/// Feeds a dead or established object a battery of inputs; it must keep refusing / ignoring them.
fn battery(p: &mut P, rec: &[Rec], rng: &mut Rng) {
    let (was_dead, was_est) = (p.dead, p.est.is_some());
    if !was_dead && !was_est {
        return;
    }
    let check = |r: Result<(), HsError>, what: &str| {
        if was_dead {
            assert_eq!(r, Err(HsError::Aborted), "aborted object answered {what} with {r:?}");
        } else {
            assert_eq!(r, Ok(()), "established object answered {what} with {r:?}");
        }
    };
    for (_, t, body) in rec.iter().take(16) {
        let r = p.on_msg(*t, body);
        check(r, "a recorded handshake message");
    }
    for _ in 0..6 {
        let (t, body) = gen_msg(rng, rec);
        let r = p.on_msg(t, &body);
        check(r, "random garbage");
    }
    for id in [0u32, 1, 2, u32::MAX] {
        let der = rng.bytes_below(80);
        let r = p.on_sig(id, &der);
        check(r, "a random signature");
    }
    p.abort();
    p.on_timeout();
    assert_eq!(p.hs.is_established(), was_est);
    assert_eq!(p.hs.is_aborted(), was_dead);
}

fn finish(ctx: &Ctx, a: &mut P, b: &mut P, plan: Option<&Plan>, rec: &[Rec], rng: &mut Rng) {
    for (is_a, p) in [(true, &*a), (false, &*b)] {
        if let Some(e) = &p.est {
            check_single(ctx, is_a, e);
        }
    }
    check_pair(ctx, a, b);
    if let Some(pl) = plan {
        assert!(
            !(pl.modified && a.est.is_some() && b.est.is_some()),
            "an altered message ({:?} at message {}) did not stop the handshake: both sides established",
            pl.kind,
            pl.at
        );
    }
    battery(a, rec, rng);
    battery(b, rec, rng);
}

// ---------------------------------------------------------------------------------------------
// Garbage generators.
// ---------------------------------------------------------------------------------------------

fn msg_len_for(t: u8) -> Option<usize> {
    Some(match t {
        1 => HS1_LEN,
        2 => HS2_LEN,
        3 => HS3_LEN,
        4 => HS4_LEN,
        5 => RS2_LEN,
        6 => RS3_LEN,
        7 => PATH_LEN,
        _ => return None,
    })
}

fn gen_msg(rng: &mut Rng, rec: &[Rec]) -> (u8, Vec<u8>) {
    let mut t = if rng.chance(25) { rng.below(256) as u8 } else { rng.range(1, 7) as u8 };
    let body = match rng.below(8) {
        0 => Vec::new(),
        1 => rng.bytes_below(65),
        2 => {
            let l = msg_len_for(t).unwrap_or_else(|| rng.below(101));
            rng.bytes(l)
        }
        3 => {
            // Well-formed HS1 header, random remainder: reaches the commit / role logic.
            t = MSG_HS1;
            let mut b = rng.bytes(HS1_LEN);
            let caps = CAP_SUITE_V2 | if rng.chance(50) { CAP_DIALER } else { 0 };
            b[0] = 2;
            b[1] = 1;
            b[2..4].copy_from_slice(&caps.to_be_bytes());
            b
        }
        4 if !rec.is_empty() => {
            let r = &rec[rng.below(rec.len())];
            t = r.1;
            let mut b = r.2.clone();
            for _ in 0..rng.range(1, 3) {
                let bit = rng.below(b.len() * 8);
                b[bit / 8] ^= 1 << (bit % 8);
            }
            b
        }
        5 => rng.bytes_below(4001),
        6 => {
            t = MSG_PATH;
            vec![rng.below(3) as u8, rng.below(4) as u8]
        }
        _ => rng.bytes(msg_len_for(t).unwrap_or(32)),
    };
    (t, body)
}

enum Input {
    Msg(u8, Vec<u8>),
    Sig(u32, Vec<u8>),
    Timeout,
    Abort,
}

fn der_of(r: &[u8], s: &[u8]) -> Vec<u8> {
    let mut v = vec![0x30, (4 + r.len() + s.len()) as u8, 0x02, r.len() as u8];
    v.extend_from_slice(r);
    v.push(0x02);
    v.push(s.len() as u8);
    v.extend_from_slice(s);
    v
}

fn gen_input(rng: &mut Rng, x: &P, rec: &[Rec], stranger: &SoftwareSigner) -> Input {
    match rng.below(10) {
        0 => Input::Timeout,
        1 => Input::Abort,
        2..=6 => {
            let (t, b) = gen_msg(rng, rec);
            Input::Msg(t, b)
        }
        _ => {
            let pending = x.sigs.front();
            let id = match pending {
                Some((id, _)) if rng.chance(60) => *id,
                _ => [0u32, 1, 2, 3, u32::MAX][rng.below(5)],
            };
            let der = match rng.below(5) {
                0 => rng.bytes_below(81),
                1 => der_of(&rng.bytes(32), &rng.bytes(32)),
                2 => x.signer.sign_der(&rng.bytes(40)),
                3 => {
                    let mut m = pending.map(|p| p.1.clone()).unwrap_or_else(|| rng.bytes(40));
                    let bit = rng.below(m.len() * 8);
                    m[bit / 8] ^= 1 << (bit % 8);
                    x.signer.sign_der(&m)
                }
                _ => {
                    let m = pending.map(|p| p.1.clone()).unwrap_or_else(|| rng.bytes(40));
                    stranger.sign_der(&m)
                }
            };
            Input::Sig(id, der)
        }
    }
}

// ---------------------------------------------------------------------------------------------
// One iteration = one mutated run + one random-input-in-every-state run.
// ---------------------------------------------------------------------------------------------

fn honest_trace(kind: PathKind, seed: u64) -> Vec<Rec> {
    let mut rng = Rng(seed);
    let (mut a, mut b, ctx) = build(kind, &mut rng);
    let mut rec = Vec::new();
    drive(&mut a, &mut b, None, usize::MAX, &mut rec, &[], &mut rng);
    assert!(a.est.is_some() && b.est.is_some(), "honest run did not establish");
    finish(&ctx, &mut a, &mut b, None, &rec, &mut rng);
    let expected = if kind == PathKind::Resume { 7 } else { 6 };
    assert_eq!(rec.len(), expected, "honest run has an unexpected message count");
    rec
}

fn mutated_run(kind: PathKind, rng: &mut Rng) {
    let (mut a, mut b, ctx) = build(kind, rng);
    let n_msgs = if kind == PathKind::Resume { 7 } else { 6 };
    let mk = ALL_MUTS[rng.below(ALL_MUTS.len())];
    let mut plan = Plan { at: rng.below(n_msgs), kind: mk, held: None, modified: false, applied: false };
    let prev = if mk == Mut::Foreign { honest_trace(kind, rng.next_u64()) } else { Vec::new() };
    let mut rec = Vec::new();
    drive(&mut a, &mut b, Some(&mut plan), usize::MAX, &mut rec, &prev, rng);
    assert!(plan.applied, "mutation point {} was never reached", plan.at);
    finish(&ctx, &mut a, &mut b, Some(&plan), &rec, rng);
}

fn state_fuzz(kind: PathKind, rng: &mut Rng) {
    let stranger = SoftwareSigner::from_seed([0xD4; 32]);
    let (mut a, mut b, ctx) = build(kind, rng);
    let mut rec = Vec::new();
    let limit = rng.below(11);
    drive(&mut a, &mut b, None, limit, &mut rec, &[], rng);
    let x_is_a = rng.chance(50);
    for _ in 0..rng.range(1, 4) {
        let x = if x_is_a { &mut a } else { &mut b };
        match gen_input(rng, x, &rec, &stranger) {
            Input::Msg(t, body) => {
                let _ = x.on_msg(t, &body);
            }
            Input::Sig(id, der) => {
                let was_est = x.est.is_some();
                let r = x.on_sig(id, &der);
                assert!(was_est || r.is_err(), "{}: a signature that is not the signer's was accepted", x.name);
            }
            Input::Timeout => x.on_timeout(),
            Input::Abort => x.abort(),
        }
    }
    drive(&mut a, &mut b, None, usize::MAX, &mut rec, &[], rng);
    finish(&ctx, &mut a, &mut b, None, &rec, rng);
}

fn one_iteration(kind: PathKind, seed: u64) {
    let mut rng = Rng(seed);
    mutated_run(kind, &mut rng);
    state_fuzz(kind, &mut rng);
}

fn run_fuzz(kind: PathKind) {
    let base = env_u64("AEGIS_FUZZ_SEED").unwrap_or(DEFAULT_SEED);
    let start = env_u64("AEGIS_FUZZ_START").unwrap_or(0);
    let n = iters();
    let t0 = Instant::now();
    for it in start..start + n {
        let seed = mix(base, kind, it);
        if let Err(e) = catch_unwind(AssertUnwindSafe(|| one_iteration(kind, seed))) {
            eprintln!(
                "FUZZ FAILURE path={kind:?} base_seed=0x{base:x} iter={it} iter_seed=0x{seed:x}\n  reproduce: AEGIS_FUZZ_SEED=0x{base:x} AEGIS_FUZZ_START={it} AEGIS_FUZZ_ITERS=1 cargo test -p aegiscall-crypto --release --test fuzz_handshake"
            );
            resume_unwind(e);
        }
    }
    eprintln!("fuzz_handshake {kind:?}: {n} iterations from {start}, seed 0x{base:x}, {:.1}s", t0.elapsed().as_secs_f64());
}

#[test]
fn honest_runs_establish_identically_on_every_path() {
    for kind in [PathKind::Full, PathKind::Psk, PathKind::Resume] {
        for i in 0..5 {
            honest_trace(kind, 0x1000 + i);
        }
    }
}

#[test]
fn fuzz_full_path_without_psk() {
    run_fuzz(PathKind::Full);
}

#[test]
fn fuzz_full_path_with_pairing_psk() {
    run_fuzz(PathKind::Psk);
}

#[test]
fn fuzz_resume_path() {
    run_fuzz(PathKind::Resume);
}
