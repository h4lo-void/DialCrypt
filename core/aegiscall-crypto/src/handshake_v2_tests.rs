//! Handshake v2 tests (driven with the software signer). Party a is the dialer, b the answerer.

use super::*;
use crate::identity::SoftwareSigner;
use rand_core::OsRng;
use std::collections::VecDeque;

type Tamper<'a> = &'a mut dyn FnMut(usize, u8, &mut Vec<u8>);
type Hook = fn(&mut HandshakeV2);

struct Party {
    hs: HandshakeV2,
    signer: SoftwareSigner,
    forge: Option<SoftwareSigner>,
    pre_sign: Option<Hook>,
    defer_sign: bool,
    pending_sig: VecDeque<(u32, Vec<u8>)>,
    outbox: VecDeque<(u8, Vec<u8>)>,
    sent: Vec<(u8, Vec<u8>)>,
    sas: Option<[u8; 5]>,
    est: Option<Established>,
    err: Option<HsError>,
}

impl Party {
    fn new(signer: SoftwareSigner, link: LinkContext, expect: PeerExpectation, side: CallSide) -> Self {
        let local = signer.local_identity([signer.pub33()[1]; 16]);
        let (hs, outs) = HandshakeV2::start(local, link, expect, side, &mut OsRng).unwrap();
        let mut p = Party {
            hs,
            signer,
            forge: None,
            pre_sign: None,
            defer_sign: false,
            pending_sig: VecDeque::new(),
            outbox: VecDeque::new(),
            sent: Vec::new(),
            sas: None,
            est: None,
            err: None,
        };
        p.absorb(Ok(outs));
        p
    }

    fn sign(&mut self, req_id: u32, to_sign: &[u8]) -> Result<Vec<HsOut>, HsError> {
        if let Some(h) = self.pre_sign {
            h(&mut self.hs);
        }
        if let Some(f) = &self.forge {
            // Bypass the local self-check to emulate a peer with a forged signature.
            self.hs.sign_req = None;
            let raw = ecdsa_der_to_raw(&f.sign_der(to_sign)).unwrap();
            return self.hs.send_signed(raw);
        }
        let der = self.signer.sign_der(to_sign);
        self.hs.on_signature(req_id, &der)
    }

    fn absorb(&mut self, r: Result<Vec<HsOut>, HsError>) {
        let mut q: VecDeque<HsOut> = match r {
            Ok(v) => v.into(),
            Err(e) => {
                self.err.get_or_insert(e);
                return;
            }
        };
        while let Some(o) = q.pop_front() {
            match o {
                HsOut::Send { msg_type, body } => {
                    self.sent.push((msg_type, body.clone()));
                    self.outbox.push_back((msg_type, body));
                }
                HsOut::NeedSignature { req_id, to_sign } => {
                    if self.defer_sign {
                        self.pending_sig.push_back((req_id, to_sign));
                    } else {
                        match self.sign(req_id, &to_sign) {
                            Ok(v) => q.extend(v),
                            Err(e) => {
                                self.err.get_or_insert(e);
                                return;
                            }
                        }
                    }
                }
                HsOut::Sas(s) => self.sas = Some(s),
                HsOut::Established(e) => self.est = Some(*e),
            }
        }
    }

    fn done(&self) -> bool {
        self.est.is_some() || self.err.is_some()
    }
}

fn links() -> (LinkContext, LinkContext) {
    let pa = [0x51, 0x02, 0x20, 0x00, 0x11];
    let pb = [0x52, 0x02, 0x20, 0x00, 0x22];
    (
        LinkContext { local_preamble: pa, peer_preamble: pb, gear: 3 },
        LinkContext { local_preamble: pb, peer_preamble: pa, gear: 2 },
    )
}

fn empty() -> PeerExpectation {
    PeerExpectation { psk: Vec::new(), resume: Vec::new() }
}

/// Delivers queued messages in both directions until nothing moves.
fn deliver(a: &mut Party, b: &mut Party, tamper: Tamper<'_>) {
    loop {
        let mut progressed = false;
        for s in 0..2 {
            let (src, dst) = if s == 0 { (&mut *a, &mut *b) } else { (&mut *b, &mut *a) };
            if let Some((t, mut body)) = src.outbox.pop_front() {
                progressed = true;
                tamper(s, t, &mut body);
                if !dst.done() {
                    let r = dst.hs.on_message(t, &body);
                    dst.absorb(r);
                }
            }
        }
        if !progressed {
            return;
        }
    }
}

fn run(a: &mut Party, b: &mut Party, tamper: Tamper<'_>) {
    loop {
        deliver(a, b, tamper);
        let mut progressed = false;
        for p in [&mut *a, &mut *b] {
            if p.done() {
                continue;
            }
            if let Some((id, msg)) = p.pending_sig.pop_front() {
                progressed = true;
                let r = p.sign(id, &msg);
                p.absorb(r);
            }
        }
        if progressed {
            continue;
        }
        for p in [&mut *a, &mut *b] {
            if !p.done() {
                p.err = Some(p.hs.on_timeout());
            }
        }
        return;
    }
}

fn no_tamper() -> impl FnMut(usize, u8, &mut Vec<u8>) {
    |_, _, _| {}
}

fn pair_with(sa: SoftwareSigner, ea: PeerExpectation, dialed: Option<u32>, sb: SoftwareSigner, eb: PeerExpectation) -> (Party, Party) {
    let (la, lb) = links();
    (
        Party::new(sa, la, ea, CallSide::Dialer { contact: dialed }),
        Party::new(sb, lb, eb, CallSide::Answerer),
    )
}

fn pair(ea: PeerExpectation, dialed: Option<u32>, eb: PeerExpectation) -> (Party, Party) {
    pair_with(SoftwareSigner::generate(), ea, dialed, SoftwareSigner::generate(), eb)
}

fn plain_pair() -> (Party, Party) {
    pair(empty(), None, empty())
}

fn assert_matching(a: &Party, b: &Party) {
    let (ea, eb) = (a.est.as_ref().unwrap(), b.est.as_ref().unwrap());
    assert_ne!(ea.role, eb.role);
    assert_eq!(ea.root0.as_bytes(), eb.root0.as_bytes());
    assert_eq!(ea.chaff_seed.as_bytes(), eb.chaff_seed.as_bytes());
    assert_eq!(ea.rs_next.as_bytes(), eb.rs_next.as_bytes());
    assert_eq!(ea.transcript_tag, eb.transcript_tag);
    assert_ne!(ea.root0.as_bytes(), ea.rs_next.as_bytes());
    assert_eq!(ea.peer.pub33, b.signer.pub33());
    assert_eq!(eb.peer.pub33, a.signer.pub33());
}

fn sent_lens(p: &Party) -> Vec<(u8, usize)> {
    p.sent.iter().map(|(t, m)| (*t, m.len())).collect()
}

#[test]
fn full_handshake_establishes_with_spec_message_lengths() {
    let (mut a, mut b) = plain_pair();
    run(&mut a, &mut b, &mut no_tamper());
    assert!(a.err.is_none() && b.err.is_none(), "{:?} {:?}", a.err, b.err);
    assert_matching(&a, &b);
    let ea = a.est.as_ref().unwrap();
    assert_eq!(ea.path, Path::Full);
    assert_eq!(ea.peer.evidence_id, [b.signer.pub33()[1]; 16]);
    assert_eq!(a.sas.unwrap(), b.sas.unwrap());
    assert_eq!(a.hs.negotiated_gear(), Some(2));
    assert_eq!(b.hs.negotiated_gear(), Some(2));
    // The dialer bit is the only difference in caps; PATH comes from the answerer only.
    assert_eq!((a.sent[0].1[2], a.sent[0].1[3]), (0x00, 0x21));
    assert_eq!((b.sent[0].1[2], b.sent[0].1[3]), (0x00, 0x20));
    assert_eq!(b.sent[1], (MSG_PATH, vec![PATH_FULL, 0]));
    let i_is_a = ea.role == Role::Initiator;
    let i_msgs = vec![(MSG_HS1, HS1_LEN), (MSG_HS3, HS3_LEN)];
    let r_msgs = vec![(MSG_HS1, HS1_LEN), (MSG_HS2, HS2_LEN), (MSG_HS4, HS4_LEN)];
    let without_path = |p: &Party| sent_lens(p).into_iter().filter(|(t, _)| *t != MSG_PATH).collect::<Vec<_>>();
    assert_eq!(without_path(&a), if i_is_a { i_msgs.clone() } else { r_msgs.clone() });
    assert_eq!(without_path(&b), if i_is_a { r_msgs } else { i_msgs });
    assert!(!a.sent.iter().any(|(t, _)| *t == MSG_PATH));
    assert_eq!(
        (HS1_LEN, HS2_LEN, HS3_LEN, HS4_LEN, RS2_LEN, RS3_LEN, PATH_LEN),
        (77, 1600, 1729, 129, 32, 80, 2)
    );
}

#[test]
fn nothing_received_after_establishment_changes_the_handshake_object() {
    let (mut a, mut b) = plain_pair();
    run(&mut a, &mut b, &mut no_tamper());
    for p in [&mut a, &mut b] {
        assert!(p.hs.is_established());
        for t in 0..=255u8 {
            for len in [0usize, 2, 5, HS1_LEN, RS3_LEN, HS4_LEN] {
                assert!(p.hs.on_message(t, &vec![0xA5; len]).unwrap().is_empty(), "type {t} len {len}");
            }
        }
        // Late or bogus signature results.
        let late = p.signer.sign_der(b"late");
        for req in [0u32, 1, 2, 99] {
            assert!(p.hs.on_signature(req, &late).unwrap().is_empty());
            assert!(p.hs.on_signature(req, &[0x30, 0x00]).unwrap().is_empty());
        }
        // A link-level ABORT or timeout reaching the object after establishment.
        p.hs.abort();
        let _ = p.hs.on_timeout();
        assert!(p.hs.is_established() && !p.hs.is_aborted());
        assert_eq!(p.hs.path(), Some(Path::Full));
    }
}

#[test]
fn wrong_lengths_unknown_types_and_reflection_are_rejected() {
    for len in [0usize, HS1_LEN - 1, HS1_LEN + 1] {
        let (mut a, _) = plain_pair();
        assert_eq!(a.hs.on_message(MSG_HS1, &vec![0u8; len]).unwrap_err(), HsError::Malformed);
        assert_eq!(a.hs.on_message(MSG_HS1, &[0u8; HS1_LEN]).unwrap_err(), HsError::Aborted);
    }
    let (mut a, mut b) = plain_pair();
    assert_eq!(a.hs.on_message(9, &[0u8; 4]).unwrap_err(), HsError::Malformed);
    assert_eq!(b.hs.on_message(MSG_HS2, &[0u8; HS2_LEN]).unwrap_err(), HsError::Malformed);

    // Version / suite / capability checks.
    for (pos, val) in [(0usize, 1u8), (1, 2), (3, 0x20 | 0x02), (3, 0x00)] {
        let (mut a, b) = plain_pair();
        let mut hs1 = b.sent[0].1.clone();
        hs1[pos] = val;
        assert_eq!(a.hs.on_message(MSG_HS1, &hs1).unwrap_err(), HsError::VersionMismatch);
    }

    // Our own HS1 reflected back.
    let (mut a, _) = plain_pair();
    let own = a.sent[0].1.clone();
    assert!(a.hs.on_message(MSG_HS1, &own).is_err());

    // PATH: wrong length, undefined values, sent to the answerer, or sent twice.
    for bad in [vec![0u8], vec![0, 0, 0], vec![2, 0], vec![0, 4], vec![0, 2], vec![1, 1]] {
        let (mut a, b) = plain_pair();
        let r = a.hs.on_message(MSG_HS1, &b.sent[0].1);
        a.absorb(r);
        assert_eq!(a.hs.on_message(MSG_PATH, &bad).unwrap_err(), HsError::Malformed, "{bad:?}");
    }
    let (a, mut b) = plain_pair();
    let r = b.hs.on_message(MSG_HS1, &a.sent[0].1);
    b.absorb(r);
    assert_eq!(b.hs.on_message(MSG_PATH, &[0, 0]).unwrap_err(), HsError::Malformed);
    let (mut a, b) = plain_pair();
    let r = a.hs.on_message(MSG_HS1, &b.sent[0].1);
    a.absorb(r);
    assert!(a.hs.on_message(MSG_PATH, &[0, 0]).is_ok());
    assert!(a.hs.on_message(MSG_PATH, &[0, 0]).is_err());
    // The dialer accepts nothing else before PATH.
    let (mut a, b) = plain_pair();
    let r = a.hs.on_message(MSG_HS1, &b.sent[0].1);
    a.absorb(r);
    assert_eq!(a.hs.on_message(MSG_RS2, &[0u8; RS2_LEN]).unwrap_err(), HsError::Malformed);
}

#[test]
fn both_sides_claiming_the_same_call_side_abort() {
    for side in [CallSide::Dialer { contact: None }, CallSide::Answerer] {
        let (la, lb) = links();
        let mut a = Party::new(SoftwareSigner::generate(), la, empty(), side);
        let mut b = Party::new(SoftwareSigner::generate(), lb, empty(), side);
        run(&mut a, &mut b, &mut no_tamper());
        assert_eq!((a.err, b.err), (Some(HsError::SideConflict), Some(HsError::SideConflict)));
        assert!(a.est.is_none() && b.est.is_none());
        assert!(a.hs.is_aborted() && b.hs.is_aborted());
    }
}

#[test]
fn single_bit_tampering_of_any_full_path_message_ends_in_error() {
    let mut cases: Vec<(Option<usize>, u8, usize)> = Vec::new();
    for pos in [0usize, 1, 2, 3, 4, 5, 20, 21, 28, 29, 36, 37, 44, 45, 60, 76] {
        cases.push((Some(0), MSG_HS1, pos));
        cases.push((Some(1), MSG_HS1, pos));
    }
    for pos in [0usize, 1] {
        cases.push((None, MSG_PATH, pos));
    }
    for pos in [0usize, 31, 32, 800, 1599] {
        cases.push((None, MSG_HS2, pos));
    }
    for pos in [0usize, 31, 32, 900, 1599, 1600, 1632, 1648, 1712, 1728] {
        cases.push((None, MSG_HS3, pos));
    }
    for pos in [0usize, 32, 48, 112, 128] {
        cases.push((None, MSG_HS4, pos));
    }
    for (sender, ty, pos) in cases {
        let (mut a, mut b) = plain_pair();
        let mut hit = false;
        let mut tamper = |s: usize, t: u8, body: &mut Vec<u8>| {
            if t == ty && sender.is_none_or(|x| x == s) && !hit {
                body[pos] ^= 0x01;
                hit = true;
            }
        };
        run(&mut a, &mut b, &mut tamper);
        assert!(hit, "case {ty}/{pos} never sent");
        assert!(a.err.is_some() || b.err.is_some(), "case {ty}/{pos}: no error");
        assert!(!(a.est.is_some() && b.est.is_some()), "case {ty}/{pos}: both established");
    }
}

#[test]
fn evidence_id_is_covered_by_the_signature() {
    let (mut a, mut b) = plain_pair();
    // b changes the evidence_id it sends after the signature over the original was requested.
    b.pre_sign = Some(|hs: &mut HandshakeV2| hs.local.evidence_id[0] ^= 0x01);
    run(&mut a, &mut b, &mut no_tamper());
    assert_eq!(a.err, Some(HsError::BadSignature));
    assert!(a.est.is_none());
}

#[test]
fn forged_identity_signature_aborts_full_path() {
    let (mut a, mut b) = plain_pair();
    b.forge = Some(SoftwareSigner::generate());
    run(&mut a, &mut b, &mut no_tamper());
    assert_eq!(a.err, Some(HsError::BadSignature));
    assert!(a.est.is_none());
}

#[test]
fn local_signer_output_is_checked_before_use() {
    // Deliver messages without signing: the initiator is then waiting for its signature.
    for wrong_key in [false, true] {
        let (mut a, mut b) = plain_pair();
        a.defer_sign = true;
        b.defer_sign = true;
        deliver(&mut a, &mut b, &mut no_tamper());
        let i = if a.hs.role() == Some(Role::Initiator) { &mut a } else { &mut b };
        let (req, msg) = i.pending_sig.pop_front().unwrap();
        let der = if wrong_key { SoftwareSigner::generate().sign_der(&msg) } else { i.signer.sign_der(&msg) };
        let res = i.hs.on_signature(if wrong_key { req } else { req + 1 }, &der);
        assert_eq!(res.unwrap_err(), HsError::SignerFailed);
        assert!(i.hs.is_aborted());
    }
}

#[test]
fn mitm_with_separate_handshakes_sees_different_sas_on_each_end() {
    let (mut alice, mut m1) = plain_pair();
    run(&mut alice, &mut m1, &mut no_tamper());
    let (mut m2, mut bob) = plain_pair();
    run(&mut m2, &mut bob, &mut no_tamper());
    assert!(alice.est.is_some() && bob.est.is_some());
    assert_eq!(alice.sas, m1.sas);
    assert_eq!(bob.sas, m2.sas);
    assert_ne!(alice.sas.unwrap(), bob.sas.unwrap());
    assert_ne!(alice.est.as_ref().unwrap().peer.pub33, bob.signer.pub33());
}

fn psk_entry(contact: u32, pk: [u8; 33], k: u8) -> (u32, [u8; 33], SecretKey32) {
    (contact, pk, SecretKey32::from_bytes([k; 32]))
}

fn psk_only(v: Vec<(u32, [u8; 33], SecretKey32)>) -> PeerExpectation {
    PeerExpectation { psk: v, resume: vec![] }
}

#[test]
fn psk_is_selected_by_the_dialer_tag_and_enforced_by_identity() {
    // The answerer has no caller ID: the dialer's tag selects the PSK among several contacts.
    let (sa, sb) = (SoftwareSigner::generate(), SoftwareSigner::generate());
    let (pa, pb) = (sa.pub33(), sb.pub33());
    let other = SoftwareSigner::generate().pub33();
    let (mut a, mut b) = pair_with(
        sa,
        psk_only(vec![psk_entry(7, pb, 0x44)]),
        Some(7),
        sb,
        psk_only(vec![psk_entry(1, other, 0x01), psk_entry(9, pa, 0x44)]),
    );
    run(&mut a, &mut b, &mut no_tamper());
    assert_matching(&a, &b);
    assert_eq!(a.est.as_ref().unwrap().psk_contact, Some(7));
    assert_eq!(b.est.as_ref().unwrap().psk_contact, Some(9));
    assert_eq!(b.sent[1], (MSG_PATH, vec![PATH_FULL, PATH_FLAG_PSK]));

    // The dialer dialed a bare number although the peer is a PSK contact: PskRequired.
    let (sa, sb) = (SoftwareSigner::generate(), SoftwareSigner::generate());
    let (pa, pb) = (sa.pub33(), sb.pub33());
    let (mut a, mut b) = pair_with(sa, psk_only(vec![psk_entry(7, pb, 0x55)]), None, sb, psk_only(vec![psk_entry(9, pa, 0x55)]));
    run(&mut a, &mut b, &mut no_tamper());
    assert!(a.err == Some(HsError::PskRequired) || b.err == Some(HsError::PskRequired), "{:?} {:?}", a.err, b.err);
    assert!(!(a.est.is_some() && b.est.is_some()));

    // Different PSKs on both sides: no tag match, and the identity check then demands the PSK.
    let (sa, sb) = (SoftwareSigner::generate(), SoftwareSigner::generate());
    let (pa, pb) = (sa.pub33(), sb.pub33());
    let (mut a, mut b) = pair_with(sa, psk_only(vec![psk_entry(7, pb, 0x66)]), Some(7), sb, psk_only(vec![psk_entry(9, pa, 0x67)]));
    run(&mut a, &mut b, &mut no_tamper());
    assert!(a.err == Some(HsError::PskRequired) || b.err == Some(HsError::PskRequired), "{:?} {:?}", a.err, b.err);
    assert!(!(a.est.is_some() && b.est.is_some()));

    // The PSK matches, but the answerer reveals a different key than the dialer pinned for it.
    let (sa, sb) = (SoftwareSigner::generate(), SoftwareSigner::generate());
    let pa = sa.pub33();
    let (mut a, mut b) = pair_with(
        sa,
        psk_only(vec![psk_entry(7, SoftwareSigner::generate().pub33(), 0x68)]),
        Some(7),
        sb,
        psk_only(vec![psk_entry(9, pa, 0x68)]),
    );
    run(&mut a, &mut b, &mut no_tamper());
    assert_eq!(a.err, Some(HsError::PskMismatch), "{:?} {:?}", a.err, b.err);
    assert!(a.est.is_none());

    // PATH claims a PSK hit although the dialer advertised none.
    let (mut a, mut b) = plain_pair();
    let mut tamper = |_s: usize, t: u8, body: &mut Vec<u8>| {
        if t == MSG_PATH {
            body[1] |= PATH_FLAG_PSK;
        }
    };
    run(&mut a, &mut b, &mut tamper);
    assert_eq!(a.err, Some(HsError::PathMismatch));
    assert!(a.est.is_none() && b.est.is_none());
}

struct Holding {
    cur: Option<u8>,
    new: Option<u8>,
}

fn cands(contact: u32, pk: [u8; 33], h: &Holding) -> Vec<ResumeCandidate> {
    let mut v = Vec::new();
    if let Some(c) = h.cur {
        v.push(ResumeCandidate { contact, pub33: pk, secret: SecretKey32::from_bytes([c; 32]), is_new: false });
    }
    if let Some(n) = h.new {
        v.push(ResumeCandidate { contact, pub33: pk, secret: SecretKey32::from_bytes([n; 32]), is_new: true });
    }
    v
}

fn resume_pair_with(sa: SoftwareSigner, ha: Holding, sb: SoftwareSigner, hb: Holding) -> (Party, Party) {
    let (pa, pb) = (sa.pub33(), sb.pub33());
    pair_with(
        sa,
        PeerExpectation { psk: vec![], resume: cands(1, pb, &ha) },
        Some(1),
        sb,
        PeerExpectation { psk: vec![], resume: cands(2, pa, &hb) },
    )
}

fn resume_pair(ha: Holding, hb: Holding) -> (Party, Party) {
    resume_pair_with(SoftwareSigner::generate(), ha, SoftwareSigner::generate(), hb)
}

fn one(c: u8) -> Holding {
    Holding { cur: Some(c), new: None }
}

fn nothing() -> Holding {
    Holding { cur: None, new: None }
}

#[test]
fn resume_succeeds_with_spec_message_lengths_and_no_sas() {
    let (mut a, mut b) = resume_pair(one(0xA1), one(0xA1));
    run(&mut a, &mut b, &mut no_tamper());
    assert!(a.err.is_none() && b.err.is_none(), "{:?} {:?}", a.err, b.err);
    assert_matching(&a, &b);
    assert_eq!(a.est.as_ref().unwrap().path, Path::Resume { contact: 1, used_new: false });
    assert_eq!(b.est.as_ref().unwrap().path, Path::Resume { contact: 2, used_new: false });
    assert!(a.sas.is_none() && b.sas.is_none());
    assert_eq!(sent_lens(&a), vec![(MSG_HS1, HS1_LEN), (MSG_RS2, RS2_LEN), (MSG_RS3, RS3_LEN)]);
    assert_eq!(sent_lens(&b), vec![(MSG_HS1, HS1_LEN), (MSG_PATH, PATH_LEN), (MSG_RS2, RS2_LEN), (MSG_RS3, RS3_LEN)]);
    assert_eq!(b.sent[1].1, vec![PATH_RESUME, 0]);
    // RESUME_SAVED tag is the same on both sides.
    let ea = a.est.as_ref().unwrap();
    assert_eq!(resume_saved_tag(&ea.rs_next), resume_saved_tag(&b.est.as_ref().unwrap().rs_next));
}

#[test]
fn answerer_without_caller_id_resumes_when_the_dialer_is_in_its_vault() {
    // The answerer holds secrets for several contacts and is told nothing about who is calling.
    let (sa, sb) = (SoftwareSigner::generate(), SoftwareSigner::generate());
    let (pa, pb) = (sa.pub33(), sb.pub33());
    let mut vault = Vec::new();
    for (contact, seed) in [(10u32, 0x10u8), (11, 0x11), (12, 0x12)] {
        vault.extend(cands(contact, SoftwareSigner::generate().pub33(), &Holding { cur: Some(seed), new: Some(seed + 0x40) }));
    }
    vault.extend(cands(2, pa, &one(0xE1)));
    let (mut a, mut b) = pair_with(
        sa,
        PeerExpectation { psk: vec![], resume: cands(1, pb, &one(0xE1)) },
        Some(1),
        sb,
        PeerExpectation { psk: vec![psk_entry(10, [2; 33], 0x77)], resume: vault },
    );
    // The answerer's own HS1 carries random fields only: nothing in it depends on its vault.
    let nonce: [u8; 16] = b.sent[0].1[OFF_NONCE..OFF_PSK].try_into().unwrap();
    let own_rid = resume_rid(&SecretKey32::from_bytes([0xE1; 32]), &nonce, &pb);
    assert_ne!(&b.sent[0].1[OFF_RID0..OFF_RID1], &own_rid);
    assert_ne!(&b.sent[0].1[OFF_RID1..OFF_COMMIT], &own_rid);
    run(&mut a, &mut b, &mut no_tamper());
    assert!(a.err.is_none() && b.err.is_none(), "{:?} {:?}", a.err, b.err);
    assert_matching(&a, &b);
    assert_eq!(b.est.as_ref().unwrap().path, Path::Resume { contact: 2, used_new: false });
    assert_eq!(a.est.as_ref().unwrap().path, Path::Resume { contact: 1, used_new: false });
}

#[test]
fn resume_with_deferred_signatures_buffers_early_rs3() {
    let (mut a, mut b) = resume_pair(one(0xB1), one(0xB1));
    a.defer_sign = true;
    b.defer_sign = true;
    run(&mut a, &mut b, &mut no_tamper());
    assert!(a.err.is_none() && b.err.is_none(), "{:?} {:?}", a.err, b.err);
    assert_matching(&a, &b);
}

#[test]
fn resume_picks_the_newer_common_secret_for_every_holding_combination() {
    let combos = [
        // (dialer cur, dialer new, answerer cur, answerer new, dialer used_new, answerer used_new)
        (Some(1u8), None, Some(1u8), None, false, false),
        (Some(1), Some(2), Some(1), None, false, false),
        (Some(1), None, Some(1), Some(2), false, false),
        (Some(1), Some(2), Some(1), Some(2), true, true),
        (Some(2), None, Some(1), Some(2), false, true),
        (None, Some(2), Some(2), None, true, false),
    ];
    for (n, (ac, an, bc, bn, ua, ub)) in combos.into_iter().enumerate() {
        let (mut a, mut b) = resume_pair(Holding { cur: ac, new: an }, Holding { cur: bc, new: bn });
        run(&mut a, &mut b, &mut no_tamper());
        assert!(a.err.is_none() && b.err.is_none(), "combo {n}: {:?} {:?}", a.err, b.err);
        assert_matching(&a, &b);
        assert_eq!(a.est.as_ref().unwrap().path, Path::Resume { contact: 1, used_new: ua }, "combo {n}");
        assert_eq!(b.est.as_ref().unwrap().path, Path::Resume { contact: 2, used_new: ub }, "combo {n}");
        assert_eq!(b.sent[1].1, vec![PATH_RESUME, if ua { PATH_FLAG_RS_NEW } else { 0 }], "combo {n}");
    }
}

#[test]
fn answerer_without_a_matching_secret_takes_the_full_path() {
    for (ha, hb) in [
        (one(1), nothing()),
        (Holding { cur: Some(1), new: Some(2) }, one(3)),
        (nothing(), Holding { cur: Some(3), new: Some(4) }),
    ] {
        let (mut a, mut b) = resume_pair(ha, hb);
        run(&mut a, &mut b, &mut no_tamper());
        assert!(a.err.is_none() && b.err.is_none(), "{:?} {:?}", a.err, b.err);
        assert_matching(&a, &b);
        assert_eq!(a.est.as_ref().unwrap().path, Path::Full);
        assert_eq!(b.est.as_ref().unwrap().path, Path::Full);
        assert_eq!(b.sent[1], (MSG_PATH, vec![PATH_FULL, 0]));
        assert!(a.sas.is_some());
    }
    // A dialer that names no contact never resumes, even though the answerer knows it.
    let (sa, sb) = (SoftwareSigner::generate(), SoftwareSigner::generate());
    let (pa, pb) = (sa.pub33(), sb.pub33());
    let (mut a, mut b) = pair_with(
        sa,
        PeerExpectation { psk: vec![], resume: cands(1, pb, &one(5)) },
        None,
        sb,
        PeerExpectation { psk: vec![], resume: cands(2, pa, &one(5)) },
    );
    run(&mut a, &mut b, &mut no_tamper());
    assert_matching(&a, &b);
    assert_eq!(b.est.as_ref().unwrap().path, Path::Full);
}

#[test]
fn tampered_path_message_aborts_both_sides() {
    type Mk = fn() -> (Party, Party);
    let both: Mk = || resume_pair(Holding { cur: Some(1), new: Some(2) }, one(1));
    let single: Mk = || resume_pair(one(1), one(1));
    let none: Mk = || resume_pair(one(1), one(9));
    // (setup, byte, xor mask): every change to PATH must end with nobody established.
    let cases: [(Mk, usize, u8); 6] = [
        (single, 0, 0x01), // resume announced, dialer told "full"
        (single, 1, 0x02), // hit on rs_cur turned into rs_new, which the dialer does not hold
        (both, 1, 0x02),   // hit on rs_cur turned into rs_new, which the dialer holds
        (both, 0, 0x01),
        (none, 0, 0x01), // full announced, dialer told "resume" with a secret the answerer lacks
        (none, 1, 0x01), // PSK hit claimed without an advertised PSK
    ];
    for (n, (mk, pos, mask)) in cases.into_iter().enumerate() {
        let (mut a, mut b) = mk();
        let mut hit = false;
        let mut tamper = |_s: usize, t: u8, body: &mut Vec<u8>| {
            if t == MSG_PATH {
                body[pos] ^= mask;
                hit = true;
            }
        };
        run(&mut a, &mut b, &mut tamper);
        assert!(hit);
        assert!(a.err.is_some() && b.err.is_some(), "case {n}: {:?} {:?}", a.err, b.err);
        assert!(a.est.is_none() && b.est.is_none(), "case {n}");
        assert!(a.hs.is_aborted() && b.hs.is_aborted(), "case {n}");
    }
    // A contradiction is reported as such by the dialer.
    let (mut a, mut b) = resume_pair(nothing(), one(9));
    run(&mut a, &mut b, &mut |_, t, body: &mut Vec<u8>| {
        if t == MSG_PATH {
            body[0] = PATH_RESUME;
        }
    });
    assert_eq!(a.err, Some(HsError::PathMismatch));
}

#[test]
fn reflected_or_foreign_rids_never_match() {
    let me = SoftwareSigner::generate();
    let peer = SoftwareSigner::generate();
    let rs = SecretKey32::from_bytes([0x5C; 32]);
    let nonce = [9u8; 16];
    let my_rid = resume_rid(&rs, &nonce, &me.pub33());
    // Matching is done against the sender's pinned key, so a rid bound to another key never fits.
    assert_ne!(my_rid, resume_rid(&rs, &nonce, &peer.pub33()));
    assert_eq!(my_rid, resume_rid(&rs, &nonce, &me.pub33()));

    // The dialer's HS1 with rids computed over the answerer's key (what a reflection would carry)
    // does not select resume at the answerer.
    let (a, mut b) = resume_pair(one(7), one(7));
    let mut forged = a.sent[0].1.clone();
    let a_nonce: [u8; 16] = forged[OFF_NONCE..OFF_PSK].try_into().unwrap();
    let bound_to_b = resume_rid(&SecretKey32::from_bytes([7; 32]), &a_nonce, &b.signer.pub33());
    forged[OFF_RID0..OFF_RID1].copy_from_slice(&bound_to_b);
    forged[OFF_RID1..OFF_COMMIT].copy_from_slice(&bound_to_b);
    let r = b.hs.on_message(MSG_HS1, &forged);
    b.absorb(r);
    assert_eq!(b.hs.path(), Some(Path::Full));

    // Rids replayed from an earlier call of the same dialer (other nonce) do not match either.
    let (sa, sb) = (SoftwareSigner::generate(), SoftwareSigner::generate());
    let (old, _) = resume_pair_with(sa.clone(), one(7), sb.clone(), one(7));
    let (a, mut b) = resume_pair_with(sa, one(7), sb, one(7));
    let mut forged = a.sent[0].1.clone();
    forged[OFF_RID0..OFF_COMMIT].copy_from_slice(&old.sent[0].1[OFF_RID0..OFF_COMMIT]);
    let r = b.hs.on_message(MSG_HS1, &forged);
    b.absorb(r);
    assert_eq!(b.hs.path(), Some(Path::Full));

    // Our whole HS1 reflected back (commit altered to avoid a role tie) is rejected outright.
    let (_, mut b) = resume_pair(one(7), one(7));
    let mut own = b.sent[0].1.clone();
    own[HS1_LEN - 1] ^= 0x01;
    assert_eq!(b.hs.on_message(MSG_HS1, &own).unwrap_err(), HsError::Malformed);
    assert!(b.hs.path().is_none());
}

#[test]
fn replayed_rs2_or_rs3_from_an_earlier_session_aborts() {
    let (sa, sb) = (SoftwareSigner::generate(), SoftwareSigner::generate());
    let (mut a, mut b) = resume_pair_with(sa.clone(), one(0xC1), sb.clone(), one(0xC1));
    run(&mut a, &mut b, &mut no_tamper());
    assert!(a.est.is_some() && b.est.is_some());
    let old_rs2 = b.sent.iter().find(|(t, _)| *t == MSG_RS2).unwrap().1.clone();
    let old_rs3 = b.sent.iter().find(|(t, _)| *t == MSG_RS3).unwrap().1.clone();

    for (ty, old, expect) in [(MSG_RS2, old_rs2, HsError::CommitMismatch), (MSG_RS3, old_rs3, HsError::ResumeAuthFailed)] {
        let (mut a, mut b) = resume_pair_with(sa.clone(), one(0xC1), sb.clone(), one(0xC1));
        let mut tamper = |s: usize, t: u8, body: &mut Vec<u8>| {
            if s == 1 && t == ty {
                *body = old.clone();
            }
        };
        run(&mut a, &mut b, &mut tamper);
        assert_eq!(a.err, Some(expect));
        assert!(a.est.is_none());
    }
}

#[test]
fn resume_with_wrong_signature_or_wrong_pinned_key_aborts() {
    // Forged RS3 signature (correct rs, wrong key).
    let (mut a, mut b) = resume_pair(one(0xD1), one(0xD1));
    b.forge = Some(SoftwareSigner::generate());
    run(&mut a, &mut b, &mut no_tamper());
    assert_eq!(a.err, Some(HsError::BadSignature));
    assert!(a.est.is_none());

    // The dialer pinned another key for this contact: the peer's RS3 signature does not verify.
    let (sa, sb) = (SoftwareSigner::generate(), SoftwareSigner::generate());
    let pa = sa.pub33();
    let wrong = SoftwareSigner::generate().pub33();
    let (mut a, mut b) = pair_with(
        sa,
        PeerExpectation { psk: vec![], resume: cands(1, wrong, &one(0xD2)) },
        Some(1),
        sb,
        PeerExpectation { psk: vec![], resume: cands(2, pa, &one(0xD2)) },
    );
    run(&mut a, &mut b, &mut no_tamper());
    assert_eq!(a.err, Some(HsError::BadSignature));
    assert!(a.est.is_none());
}

#[test]
fn established_secrets_differ_between_sessions() {
    let (mut a, mut b) = plain_pair();
    run(&mut a, &mut b, &mut no_tamper());
    let (mut c, mut d) = plain_pair();
    run(&mut c, &mut d, &mut no_tamper());
    assert_ne!(a.est.as_ref().unwrap().root0.as_bytes(), c.est.as_ref().unwrap().root0.as_bytes());
}
