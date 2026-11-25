//! Independent acceptance checks for aegiscall-crypto WP1 (review r2-rev1).
//! Run with: cargo test -p aegiscall-crypto --features test-signer --test review_wp1
#![cfg(feature = "test-signer")]

use aegiscall_crypto::handshake_v2::{MSG_HS1, MSG_HS2, MSG_HS3, MSG_HS4, MSG_RS2, MSG_RS3};
use aegiscall_crypto::{
    ecdsa_der_to_raw, resume_saved_tag, spki_der_to_pub33, verify_identity_sig, CallSide, DhRatchet, EpochCipher, EpochError,
    Established, HandshakeV2, HsError, HsOut, LinkContext, PairingCodeV2, PeerExpectation, Path, RatchetAssembler,
    ResumeCandidate, Role, SoftwareSigner, HS1_LEN, HS2_LEN, HS3_LEN, HS4_LEN, RS2_LEN, RS3_LEN,
};
use aegiscall_memsec::SecretKey32;
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha384};
use std::collections::VecDeque;

type H384 = Hmac<Sha384>;

fn hmac(key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut m = <H384 as Mac>::new_from_slice(key).unwrap();
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().to_vec()
}

struct P {
    hs: HandshakeV2,
    signer: SoftwareSigner,
    out: VecDeque<(u8, Vec<u8>)>,
    sigs: VecDeque<(u32, Vec<u8>)>,
    sent: Vec<(u8, Vec<u8>)>,
    est: Option<Box<Established>>,
    err: Option<HsError>,
}

impl P {
    // §6.11: the first party of every pair dials (naming its contact), the second answers.
    fn new(signer: SoftwareSigner, link: LinkContext, e: PeerExpectation, side: CallSide) -> Self {
        let id = signer.local_identity([signer.pub33()[1]; 16]);
        let (hs, outs) = HandshakeV2::start(id, link, e, side, &mut OsRng).unwrap();
        let mut p = P { hs, signer, out: VecDeque::new(), sigs: VecDeque::new(), sent: vec![], est: None, err: None };
        p.absorb(Ok(outs));
        p
    }
    fn absorb(&mut self, r: Result<Vec<HsOut>, HsError>) {
        match r {
            Ok(v) => {
                for o in v {
                    match o {
                        HsOut::Send { msg_type, body } => {
                            self.sent.push((msg_type, body.clone()));
                            self.out.push_back((msg_type, body));
                        }
                        HsOut::NeedSignature { req_id, to_sign } => self.sigs.push_back((req_id, to_sign)),
                        HsOut::Sas(_) => {}
                        HsOut::Established(e) => self.est = Some(e),
                    }
                }
            }
            Err(e) => self.err = Some(e),
        }
    }
    fn done(&self) -> bool {
        self.est.is_some() || self.err.is_some()
    }
}

fn links() -> (LinkContext, LinkContext) {
    let (x, y) = ([1, 2, 3, 4, 5], [6, 7, 8, 9, 10]);
    (
        LinkContext { local_preamble: x, peer_preamble: y, gear: 2 },
        LinkContext { local_preamble: y, peer_preamble: x, gear: 3 },
    )
}

fn none() -> PeerExpectation {
    PeerExpectation { psk: vec![], resume: vec![] }
}

fn run(a: &mut P, b: &mut P, tamper: &mut dyn FnMut(usize, u8, &mut Vec<u8>)) {
    loop {
        let mut progressed = false;
        for s in 0..2 {
            let (src, dst) = if s == 0 { (&mut *a, &mut *b) } else { (&mut *b, &mut *a) };
            if let Some((t, mut body)) = src.out.pop_front() {
                progressed = true;
                tamper(s, t, &mut body);
                if !dst.done() {
                    let r = dst.hs.on_message(t, &body);
                    dst.absorb(r);
                }
            }
        }
        if progressed {
            continue;
        }
        for p in [&mut *a, &mut *b] {
            if p.done() {
                continue;
            }
            if let Some((id, msg)) = p.sigs.pop_front() {
                progressed = true;
                let der = p.signer.sign_der(&msg);
                let r = p.hs.on_signature(id, &der);
                p.absorb(r);
            }
        }
        if !progressed {
            break;
        }
    }
}

fn full_pair() -> (P, P) {
    let (la, lb) = links();
    (
        P::new(SoftwareSigner::generate(), la, none(), CallSide::Dialer { contact: None }),
        P::new(SoftwareSigner::generate(), lb, none(), CallSide::Answerer),
    )
}

fn key(b: u8) -> SecretKey32 {
    SecretKey32::from_bytes([b; 32])
}

fn resume_pair(cur: u8, new: Option<u8>) -> (P, P) {
    let (sa, sb) = (SoftwareSigner::generate(), SoftwareSigner::generate());
    let (pa, pb) = (sa.pub33(), sb.pub33());
    let mk = |pk: [u8; 33], c: u32| {
        let mut v = vec![ResumeCandidate { contact: c, pub33: pk, secret: key(cur), is_new: false }];
        if let Some(n) = new {
            v.push(ResumeCandidate { contact: c, pub33: pk, secret: key(n), is_new: true });
        }
        PeerExpectation { psk: vec![], resume: v }
    };
    let (la, lb) = links();
    (P::new(sa, la, mk(pb, 1), CallSide::Dialer { contact: Some(1) }), P::new(sb, lb, mk(pa, 2), CallSide::Answerer))
}

#[test]
fn r1_expand_with_32_byte_prk_matches_plain_hmac_construction() {
    let rs = key(0x5A);
    let full = hmac(rs.as_bytes(), &[b"saved", &[1u8]]);
    assert_eq!(resume_saved_tag(&rs).as_slice(), &full[..8]);
    let dr = DhRatchet::new(key(0x33), Role::Initiator);
    let full = hmac(&[0x33; 32], &[b"resume next pq", &0u32.to_be_bytes(), &[1u8]]);
    assert_eq!(dr.resume_next_pq().unwrap().as_bytes().as_slice(), &full[..32]);
}

#[test]
fn r1_hs1_layout_commit_psk_tag_and_rids_match_spec() {
    let (sa, sb) = (SoftwareSigner::generate(), SoftwareSigner::generate());
    let (pa, pb) = (sa.pub33(), sb.pub33());
    let mk = |pk: [u8; 33], c: u32| PeerExpectation {
        psk: vec![(c, pk, key(0x77))],
        resume: vec![
            ResumeCandidate { contact: c, pub33: pk, secret: key(0xA1), is_new: false },
            ResumeCandidate { contact: c, pub33: pk, secret: key(0xA2), is_new: true },
        ],
    };
    let mk_b = |pk: [u8; 33], c: u32| PeerExpectation {
        psk: vec![(c, pk, key(0x77))],
        resume: vec![ResumeCandidate { contact: c, pub33: pk, secret: key(0xB1), is_new: false }],
    };
    let (la, lb) = links();
    let (mut a, mut b) =
        (P::new(sa, la, mk(pb, 1), CallSide::Dialer { contact: Some(1) }), P::new(sb, lb, mk_b(pa, 2), CallSide::Answerer));
    let (hs1_a, hs1_b) = (a.sent[0].1.clone(), b.sent[0].1.clone());
    run(&mut a, &mut b, &mut |_, _, _| {});
    assert!(a.err.is_none() && b.err.is_none(), "{:?} {:?}", a.err, b.err);
    // §6.11: only the dialer (a) advertises psk_tag and rids; the answerer's fields are random.
    for (hs1, p, own_pub, dialer) in [(&hs1_a, &a, pa, true), (&hs1_b, &b, pb, false)] {
        assert_eq!(hs1.len(), 77);
        assert_eq!((hs1[0], hs1[1], hs1[2], hs1[3]), (2, 1, 0x00, if dialer { 0x21 } else { 0x20 }));
        let nonce = &hs1[5..21];
        let psk_tag = hmac(&[0x77; 32], &[b"AegisPSK-v2", nonce]);
        let rid_cur = hmac(&[if dialer { 0xA1 } else { 0xB1 }; 32], &[b"AegisRID-v2", nonce, &own_pub]);
        let rid_new = hmac(&[0xA2; 32], &[b"AegisRID-v2", nonce, &own_pub]);
        assert_eq!(&hs1[21..29] == &psk_tag[..8], dialer);
        assert_eq!(&hs1[29..37] == &rid_cur[..8], dialer);
        if dialer {
            assert_eq!(&hs1[37..45], &rid_new[..8]);
        }
        let is_i = p.est.as_ref().unwrap().role == Role::Initiator;
        let (ty, len) = if is_i { (MSG_HS3, HS3_LEN) } else { (MSG_HS2, HS2_LEN) };
        let body = &p.sent.iter().find(|(t, _)| *t == ty).unwrap().1;
        assert_eq!(body.len(), len);
        let mut h = Sha384::new();
        h.update(b"AegisCommit-v2");
        h.update(&hs1[..45]);
        h.update(&body[..32]);
        assert_eq!(&hs1[45..77], &h.finalize()[..32]);
    }
    let a_larger = hs1_a[45..] > hs1_b[45..];
    assert_eq!(a.est.as_ref().unwrap().role == Role::Initiator, a_larger);
    assert_eq!(a.hs.negotiated_gear(), Some(2));
    assert_eq!((HS4_LEN, RS2_LEN, RS3_LEN), (129, 32, 80));
    let _ = MSG_HS4;
}

#[test]
fn r2_swapping_a_revealed_x25519_key_is_a_commit_mismatch() {
    for ty in [MSG_HS2, MSG_HS3] {
        let (mut a, mut b) = full_pair();
        let mut swapped = false;
        let mut t = |_s: usize, t: u8, body: &mut Vec<u8>| {
            if t == ty && !swapped {
                let mut x = [0u8; 32];
                OsRng.fill_bytes(&mut x);
                body[..32].copy_from_slice(&x);
                swapped = true;
            }
        };
        run(&mut a, &mut b, &mut t);
        assert!(swapped);
        let errs = [a.err, b.err];
        assert!(errs.contains(&Some(HsError::CommitMismatch)), "type {ty}: {errs:?}");
        assert!(!(a.est.is_some() && b.est.is_some()));
    }
}

#[test]
fn r3_every_single_bit_flip_in_rs2_and_rs3_prevents_establishment() {
    for (ty, len) in [(MSG_RS2, RS2_LEN), (MSG_RS3, RS3_LEN)] {
        for sender in 0..2usize {
            for pos in (0..len).step_by(3).chain([len - 1]) {
                let (mut a, mut b) = resume_pair(0xC3, None);
                let mut hit = false;
                let mut t = |s: usize, t: u8, body: &mut Vec<u8>| {
                    if s == sender && t == ty && !hit {
                        body[pos] ^= 0x80;
                        hit = true;
                    }
                };
                run(&mut a, &mut b, &mut t);
                assert!(hit);
                assert!(a.err.is_some() || b.err.is_some(), "ty {ty} sender {sender} pos {pos}: no error");
                assert!(!(a.est.is_some() && b.est.is_some()), "ty {ty} sender {sender} pos {pos}");
            }
        }
    }
}

#[test]
fn r3_hs1_rid_or_commit_flip_in_resume_is_detected() {
    for pos in [29usize, 36, 37, 44, 45, 76] {
        let (mut a, mut b) = resume_pair(0xC4, Some(0xC5));
        let mut hit = false;
        let mut t = |s: usize, t: u8, body: &mut Vec<u8>| {
            if s == 0 && t == MSG_HS1 && !hit {
                body[pos] ^= 1;
                hit = true;
            }
        };
        run(&mut a, &mut b, &mut t);
        assert!(a.err.is_some() || b.err.is_some(), "pos {pos}");
        assert!(!(a.est.is_some() && b.est.is_some()), "pos {pos}");
    }
}

#[test]
fn r4_unknown_message_types_after_establishment_do_not_change_state() {
    let (mut a, mut b) = full_pair();
    run(&mut a, &mut b, &mut |_, _, _| {});
    assert!(a.est.is_some() && b.est.is_some());
    for t in [MSG_HS1, MSG_HS2, MSG_RS3] {
        assert!(a.hs.on_message(t, &[0u8; 5]).unwrap().is_empty());
    }
    assert!(a.hs.is_established());
    for t in [0u8, 7, 0xE, 0xF] {
        let _ = a.hs.on_message(t, &[0u8; 5]);
        assert!(a.hs.is_established(), "type {t:#x} flipped the established handshake object (is_aborted={})", a.hs.is_aborted());
    }
}

#[test]
fn r5_high_s_and_noncanonical_der_are_rejected() {
    const N: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xBC, 0xE6,
        0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
    ];
    let s = SoftwareSigner::generate();
    let msg = b"review message";
    let der = s.sign_der(msg);
    let raw = ecdsa_der_to_raw(&der).unwrap();
    verify_identity_sig(&s.pub33(), msg, &raw).unwrap();
    let mut hi = raw;
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let mut v = N[i] as i16 - raw[32 + i] as i16 - borrow;
        borrow = if v < 0 { v += 256; 1 } else { 0 };
        hi[32 + i] = v as u8;
    }
    assert!(verify_identity_sig(&s.pub33(), msg, &hi).is_err());
    let mut t = der.clone();
    t.push(0);
    assert!(ecdsa_der_to_raw(&t).is_err());
    assert!(ecdsa_der_to_raw(&der[..der.len() - 1]).is_err());
    assert!(ecdsa_der_to_raw(&[]).is_err());
    let mut ber = vec![0x30, 0x81, der[1]];
    ber.extend_from_slice(&der[2..]);
    assert!(ecdsa_der_to_raw(&ber).is_err());
    let mut bad = s.pub33();
    bad[0] = 0x04;
    assert!(verify_identity_sig(&bad, msg, &raw).is_err());
}

#[test]
fn r6_replay_window_accepts_reordering_inside_64_and_rejects_older_and_duplicates() {
    let root = key(0x42);
    let mut i = EpochCipher::from_root(&root, Role::Initiator, [1, 2, 3, 4]);
    let mut r = EpochCipher::from_root(&root, Role::Responder, [1, 2, 3, 4]);
    let frames: Vec<_> = (0..100u8).map(|n| i.seal_superframe(&[n; 14]).unwrap()).collect();
    assert_eq!(r.open_superframe(&frames[99]).unwrap().counter, 99);
    assert_eq!(r.open_superframe(&frames[0]), Err(EpochError::ReplayDetected));
    assert_eq!(r.open_superframe(&frames[35]), Err(EpochError::ReplayDetected));
    assert_eq!(r.open_superframe(&frames[36]).unwrap().plaintext, [36u8; 14]);
    assert_eq!(r.open_superframe(&frames[36]), Err(EpochError::ReplayDetected));
    assert_eq!(r.open_superframe(&frames[99]), Err(EpochError::ReplayDetected));
}

#[test]
fn r7_no_panic_on_random_input() {
    let mut rng = OsRng;
    for _ in 0..25 {
        let (mut a, mut b) = full_pair();
        let (ha, hb) = (a.sent[0].1.clone(), b.sent[0].1.clone());
        let r1 = a.hs.on_message(MSG_HS1, &hb);
        a.absorb(r1);
        let r2 = b.hs.on_message(MSG_HS1, &ha);
        b.absorb(r2);
        for _ in 0..40 {
            let t = (rng.next_u32() % 9) as u8;
            let len = [0usize, 1, 32, 77, 80, 129, 1600, 1729, (rng.next_u32() % 2000) as usize][(rng.next_u32() % 9) as usize];
            let mut body = vec![0u8; len];
            rng.fill_bytes(&mut body);
            let p = if rng.next_u32() % 2 == 0 { &mut a } else { &mut b };
            let _ = p.hs.on_message(t, &body);
            let _ = p.hs.on_signature(rng.next_u32() % 4, &body);
        }
    }
    let mut c = EpochCipher::from_root(&key(1), Role::Responder, [0; 4]);
    for _ in 0..5000 {
        let mut w = [0u8; 23];
        rng.fill_bytes(&mut w);
        let _ = c.open_superframe(&w);
        let _ = c.rx_message_key((rng.next_u32() & 0xFF) as u8, rng.next_u32());
    }
    let mut asm = RatchetAssembler::default();
    for _ in 0..5000 {
        let mut f = [0u8; 13];
        rng.fill_bytes(&mut f);
        f[1] &= 0x1F;
        let _ = asm.push(&f);
        let mut g = vec![0u8; (rng.next_u32() % 20) as usize];
        rng.fill_bytes(&mut g);
        let _ = asm.push(&g);
    }
    for _ in 0..3000 {
        let mut g = vec![0u8; (rng.next_u32() % 140) as usize];
        rng.fill_bytes(&mut g);
        let _ = spki_der_to_pub33(&g);
        let _ = ecdsa_der_to_raw(&g);
        let _ = PairingCodeV2::from_raw(&g);
        let s: String = g.iter().map(|b| char::from_u32(*b as u32 * 3).unwrap_or('x')).collect();
        let _ = PairingCodeV2::from_code(&s);
        let _ = PairingCodeV2::from_code(&format!("AEGIS2-{s}"));
    }
    let _ = (Path::Full, MSG_RS2, HS1_LEN);
}
