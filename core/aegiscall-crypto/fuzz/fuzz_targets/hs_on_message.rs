#![no_main]
//! Script-driven handshake fuzzing: byte 0 selects the path, the rest is a list of operations applied
//! to two live handshake objects (A dials, B answers). Invariants: no panic; an object that returned
//! an error stays aborted; established sides agree on every secret and hold the true peer identity;
//! a message altered in transit never ends with both sides established.

use aegiscall_crypto::{
    CallSide, Established, HandshakeV2, HsError, HsOut, LinkContext, PeerExpectation, ResumeCandidate,
    SoftwareSigner,
};
use aegiscall_memsec::SecretKey32;
use libfuzzer_sys::fuzz_target;
use rand_core::{CryptoRng, RngCore};
use std::collections::VecDeque;

struct Det(u64);

impl Det {
    fn step(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

impl RngCore for Det {
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

impl CryptoRng for Det {}

struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn u8(&mut self) -> Option<u8> {
        let (h, t) = self.0.split_first()?;
        self.0 = t;
        Some(*h)
    }
    fn take(&mut self, n: usize) -> &'a [u8] {
        let (h, t) = self.0.split_at(n.min(self.0.len()));
        self.0 = t;
        h
    }
}

struct Side {
    name: &'static str,
    hs: HandshakeV2,
    signer: SoftwareSigner,
    out: VecDeque<(u8, Vec<u8>)>,
    sigs: VecDeque<(u32, Vec<u8>)>,
    est: Option<Box<Established>>,
    dead: bool,
}

impl Side {
    fn new(name: &'static str, signer: SoftwareSigner, link: LinkContext, e: PeerExpectation, side: CallSide, rng: &mut Det) -> Self {
        let id = signer.local_identity([signer.pub33()[1]; 16]);
        let (hs, outs) = HandshakeV2::start(id, link, e, side, rng).expect("start");
        let mut s = Side { name, hs, signer, out: VecDeque::new(), sigs: VecDeque::new(), est: None, dead: false };
        let _ = s.absorb(Ok(outs));
        s
    }

    fn absorb(&mut self, r: Result<Vec<HsOut>, HsError>) -> Result<(), HsError> {
        let (was_dead, was_est) = (self.dead, self.est.is_some());
        match r {
            Ok(v) => {
                assert!(!was_dead, "{}: aborted object returned Ok", self.name);
                assert!(!was_est || v.is_empty(), "{}: established object produced output", self.name);
                for o in v {
                    match o {
                        HsOut::Send { msg_type, body } => self.out.push_back((msg_type, body)),
                        HsOut::NeedSignature { req_id, to_sign } => self.sigs.push_back((req_id, to_sign)),
                        HsOut::Sas(_) => {}
                        HsOut::Established(e) => {
                            assert!(self.est.is_none(), "{}: established twice", self.name);
                            self.est = Some(e);
                        }
                    }
                }
                assert!(!self.hs.is_aborted(), "{}: Ok but aborted", self.name);
                assert_eq!(self.hs.is_established(), self.est.is_some(), "{}: established flag mismatch", self.name);
                Ok(())
            }
            Err(e) => {
                assert!(!was_est, "{}: established object returned an error", self.name);
                if was_dead {
                    assert_eq!(e, HsError::Aborted, "{}: aborted object answered {:?}", self.name, e);
                }
                self.dead = true;
                assert!(self.hs.is_aborted() && !self.hs.is_established(), "{}: error did not abort", self.name);
                Err(e)
            }
        }
    }

    fn on_msg(&mut self, t: u8, body: &[u8]) -> Result<(), HsError> {
        let r = self.hs.on_message(t, body);
        self.absorb(r)
    }

    fn on_sig(&mut self, id: u32, der: &[u8]) -> Result<(), HsError> {
        let r = self.hs.on_signature(id, der);
        self.absorb(r)
    }
}

fn cand(contact: u32, pk: [u8; 33]) -> Vec<ResumeCandidate> {
    vec![ResumeCandidate { contact, pub33: pk, secret: SecretKey32::from_bytes([0x77; 32]), is_new: false }]
}

fn setup(kind: u8, rng: &mut Det) -> (Side, Side, [u8; 33], [u8; 33]) {
    let sa = SoftwareSigner::from_seed([0xA1; 32]);
    let sb = SoftwareSigner::from_seed([0xB2; 32]);
    let (pa, pb) = (sa.pub33(), sb.pub33());
    let none = || PeerExpectation { psk: vec![], resume: vec![] };
    let (ea, eb, side_a) = match kind {
        0 => (none(), none(), CallSide::Dialer { contact: None }),
        1 => (
            PeerExpectation { psk: vec![(7, pb, SecretKey32::from_bytes([0x42; 32]))], resume: vec![] },
            PeerExpectation { psk: vec![(9, pa, SecretKey32::from_bytes([0x42; 32]))], resume: vec![] },
            CallSide::Dialer { contact: Some(7) },
        ),
        _ => (
            PeerExpectation { psk: vec![], resume: cand(1, pb) },
            PeerExpectation { psk: vec![], resume: cand(2, pa) },
            CallSide::Dialer { contact: Some(1) },
        ),
    };
    let (x, y) = ([1, 2, 3, 4, 5], [6, 7, 8, 9, 10]);
    let la = LinkContext { local_preamble: x, peer_preamble: y, gear: 2 };
    let lb = LinkContext { local_preamble: y, peer_preamble: x, gear: 3 };
    let a = Side::new("A", sa, la, ea, side_a, rng);
    let b = Side::new("B", sb, lb, eb, CallSide::Answerer, rng);
    (a, b, pa, pb)
}

fn drain(a: &mut Side, b: &mut Side) {
    for _ in 0..64 {
        let mut progressed = false;
        for s in 0..2 {
            let (src, dst) = if s == 0 { (&mut *a, &mut *b) } else { (&mut *b, &mut *a) };
            if let Some((t, body)) = src.out.pop_front() {
                progressed = true;
                let _ = dst.on_msg(t, &body);
            }
        }
        if progressed {
            continue;
        }
        for p in [&mut *a, &mut *b] {
            if let Some((id, msg)) = p.sigs.pop_front() {
                progressed = true;
                let der = p.signer.sign_der(&msg);
                let _ = p.on_sig(id, &der);
            }
        }
        if !progressed {
            break;
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut c = Cursor(data);
    let Some(kind) = c.u8() else { return };
    let seed = data.iter().take(8).fold(0x5EED_u64, |s, b| s.rotate_left(8) ^ u64::from(*b));
    let mut rng = Det(seed);
    let (mut a, mut b, pa, pb) = setup(kind % 3, &mut rng);
    let mut modified = false;
    for _ in 0..64 {
        let Some(op) = c.u8() else { break };
        let (dst, src) = if op & 0x80 != 0 { (&mut b, &mut a) } else { (&mut a, &mut b) };
        match (op & 0x7F) % 8 {
            0 => {
                if let Some((t, body)) = src.out.pop_front() {
                    let _ = dst.on_msg(t, &body);
                }
            }
            1 => {
                if let Some((t, mut body)) = src.out.pop_front() {
                    let pos = usize::from(c.u8().unwrap_or(0)) << 8 | usize::from(c.u8().unwrap_or(0));
                    let bit = pos % (body.len() * 8);
                    body[bit / 8] ^= 1 << (bit % 8);
                    modified = true;
                    let _ = dst.on_msg(t, &body);
                }
            }
            2 => {
                if let Some((t, mut body)) = src.out.pop_front() {
                    let keep = usize::from(c.u8().unwrap_or(0)) % body.len();
                    body.truncate(keep);
                    modified = true;
                    let _ = dst.on_msg(t, &body);
                }
            }
            3 => {
                let t = c.u8().unwrap_or(0);
                let n = usize::from(c.u8().unwrap_or(0)) * 16;
                let body = c.take(n).to_vec();
                let _ = dst.on_msg(t, &body);
            }
            4 => {
                if let Some((id, msg)) = dst.sigs.pop_front() {
                    let der = dst.signer.sign_der(&msg);
                    let _ = dst.on_sig(id, &der);
                }
            }
            5 => {
                let idb = c.u8().unwrap_or(0);
                let len = usize::from(c.u8().unwrap_or(0)) % 96;
                let der = c.take(len).to_vec();
                let id = if idb == 0 { dst.sigs.front().map(|s| s.0).unwrap_or(0) } else { u32::from(idb) };
                let was_est = dst.est.is_some();
                let r = dst.on_sig(id, &der);
                assert!(was_est || r.is_err(), "{}: a signature the signer never made was accepted", dst.name);
            }
            6 => {
                let was_est = dst.est.is_some();
                assert_eq!(dst.hs.on_timeout(), HsError::Timeout);
                if !was_est {
                    dst.dead = true;
                }
                assert_eq!(dst.hs.is_aborted(), !was_est);
            }
            _ => {
                if let Some((t, body)) = src.out.pop_front() {
                    let nt = c.u8().unwrap_or(0);
                    modified |= nt != t;
                    let _ = dst.on_msg(nt, &body);
                }
            }
        }
    }
    drain(&mut a, &mut b);
    if let Some(e) = &a.est {
        assert_eq!(e.peer.pub33, pb, "A established with a foreign identity");
    }
    if let Some(e) = &b.est {
        assert_eq!(e.peer.pub33, pa, "B established with a foreign identity");
    }
    if let (Some(ea), Some(eb)) = (&a.est, &b.est) {
        assert_eq!(ea.root0.as_bytes(), eb.root0.as_bytes(), "root0 differs");
        assert_eq!(ea.chaff_seed.as_bytes(), eb.chaff_seed.as_bytes(), "chaff_seed differs");
        assert_eq!(ea.rs_next.as_bytes(), eb.rs_next.as_bytes(), "rs_next differs");
        assert_eq!(ea.transcript_tag, eb.transcript_tag, "transcript tag differs");
        assert_eq!(std::mem::discriminant(&ea.path), std::mem::discriminant(&eb.path), "paths differ");
        assert!(!modified, "an altered message did not stop the handshake");
    }
});
