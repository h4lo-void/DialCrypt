//! SecureCallSession scenarios (secure-session-v2 §6.9, WP3 row, plus robustness cases).

mod common;

use aegiscall_chat::{AbortReason, HsLink, SecureCallSession, SessionEvent, TxUnit};
use aegiscall_crypto::{CallSide, IdentityStatus, Path, PeerExpectation, ResumeCandidate, Role, SoftwareSigner};
use aegiscall_memsec::SecretKey32;
use aegiscall_modem::{ModemGear, PreambleCapabilities};
use common::*;

fn is_abort_frame(u: &TxUnit) -> bool {
    matches!(u, TxUnit::Superframe(w) if w[0] == 0xAF)
}

/// Budget model: lockstep slots (one frame per side per 160 ms slot, delivered within the slot),
/// signatures returned immediately, 5% independent superframe loss per direction, preamble not
/// lost. Frames are superframes sent by one side until both report Established. The §6.9 budget
/// is checked against the mean over the seeds; the worst seed is reported and bounded loosely.
#[test]
fn full_handshake_under_5pct_loss_fits_216_frames_on_average() {
    let mut worst = 0;
    let mut total = 0;
    let seeds = 16u64;
    for seed in 1..=seeds {
        let mut p = full_pair(seed * 7919, 0.05);
        p.lossy_preamble = false;
        let ok = p.run_until(500, both_established);
        assert!(ok, "seed {seed} did not establish: a {:?} b {:?} / {:?} / {:?}", p.a.aborted(), p.b.aborted(), p.a.log, p.b.log);
        assert!(p.a.aborted().is_none() && p.b.aborted().is_none());
        let frames = p.a.superframes.max(p.b.superframes);
        worst = worst.max(frames);
        total += frames;
        assert!(p.a.has(|e| matches!(e, SessionEvent::Path(Path::Full))));
        assert_eq!(p.a.s.sas_bytes(), p.b.s.sas_bytes());
    }
    eprintln!("full handshake, 5% loss: worst {worst} frames, mean {} frames", total / seeds);
    assert!(total / seeds <= 216, "mean {} frames", total / seeds);
    assert!(worst <= 230, "worst case {worst} frames");
}

#[test]
fn resume_handshake_under_5pct_loss_fits_20_frames_per_side_on_average() {
    let mut worst = 0;
    let mut total = 0;
    let seeds = 16u64;
    for seed in 1..=seeds {
        let mut p = resume_pair(seed * 104_729, 0.05, [0x42; 32]);
        p.lossy_preamble = false;
        let ok = p.run_until(200, both_established);
        assert!(ok, "seed {seed} did not establish: a {:?} b {:?} / {:?} / {:?}", p.a.aborted(), p.b.aborted(), p.a.log, p.b.log);
        let frames = p.a.superframes.max(p.b.superframes);
        worst = worst.max(frames);
        total += frames;
        assert!(p.a.has(|e| matches!(e, SessionEvent::Path(Path::Resume { contact: B_AT_A, used_new: false }))));
        assert!(p.b.has(|e| matches!(e, SessionEvent::Path(Path::Resume { contact: A_AT_B, used_new: false }))));
        assert!(!p.a.has(|e| matches!(e, SessionEvent::Sas(_))));
    }
    eprintln!("resume handshake, 5% loss: worst {worst} frames per side, mean {}", total / seeds);
    assert!(total / seeds <= 20, "mean {} frames", total / seeds);
    assert!(worst <= 26, "worst case {worst} frames");
}

#[test]
fn after_keys_injected_hs1_and_abort_change_nothing_and_link_closes_on_first_encrypted_frame() {
    let mut p = full_pair(11, 0.0);
    p.record = true;
    assert!(p.run_until(400, |p| p.a.s.is_keyed() || p.b.s.is_keyed()));
    // The responder holds the keys first; the initiator is still waiting for HS4.
    let a_is_r = p.a.s.is_keyed();
    let hs1_of_i = p
        .tape
        .iter()
        .find_map(|(_, from_a, u)| match u {
            TxUnit::Superframe(w) if *from_a != a_is_r && w[0] == 0xA1 => Some(*w),
            _ => None,
        })
        .unwrap();
    let i_tag = hs1_of_i[2];
    let abort_of_i = HsLink::new(i_tag).abort_frame(AbortReason::PeerAbort.code());
    let foreign_abort = HsLink::new(i_tag.wrapping_add(1)).abort_frame(1);
    let now = p.now;
    {
        let r = if a_is_r { &mut p.a } else { &mut p.b };
        assert!(!r.s.is_established());
        for f in [hs1_of_i, abort_of_i, foreign_abort] {
            r.s.on_rx_superframe(&f, now);
        }
        r.react(p.tick);
        assert!(r.s.is_keyed());
        assert!(r.aborted().is_none());
        assert!(!r.s.hs_link_closed());
    }
    assert!(p.run_until(100, both_established));
    assert!(p.a.s.hs_link_closed() && p.b.s.hs_link_closed());
    let now = p.now;
    for party in [&mut p.a, &mut p.b] {
        for f in [hs1_of_i, abort_of_i] {
            party.s.on_rx_superframe(&f, now);
        }
        party.react(0);
        assert!(party.s.is_established() && party.aborted().is_none());
    }
    let id = p.a.s.chat().unwrap().send_text_message(now, 0, "still fine").unwrap();
    assert!(p.run_until(100, |p| p.a.has(|e| matches!(e, SessionEvent::MessageDelivered(m) if *m == id))));
    assert!(text_of(&p.b).iter().any(|t| t == "still fine"));
}

#[test]
fn bulk_pq_exchange_finishes_under_loss_with_chat_cutting_in_and_triggers_flagged_ratchet() {
    let mut sent = Vec::new();
    let mut n = 0u32;
    let mut q = resume_pair(78, 0.05, [0x25; 32]);
    assert!(q.run_until(200, both_established));
    for _ in 0..4000 {
        if q.a.has(|e| matches!(e, SessionEvent::PqMixed { .. })) && q.b.has(|e| matches!(e, SessionEvent::PqMixed { .. })) {
            break;
        }
        if q.tick % 12 == 0 {
            n += 1;
            let now = q.now;
            let (who, party) = if n % 2 == 0 { ('a', &mut q.a) } else { ('b', &mut q.b) };
            if let Ok(id) = party.s.chat().unwrap().send_text_message(now, 0, &format!("Intruder msg {n}")) {
                sent.push((who, id));
            }
        }
        q.step();
    }
    for party in [&q.a, &q.b] {
        let pcts: Vec<u8> = party
            .log
            .iter()
            .filter_map(|e| match e {
                SessionEvent::PqProgress(v) => Some(*v),
                _ => None,
            })
            .collect();
        assert!(pcts.windows(2).all(|w| w[0] <= w[1]), "progress must not go backwards");
        assert!(pcts.last().copied().unwrap_or(0) >= 90);
        let mixed = party.log.iter().find_map(|e| match e {
            SessionEvent::PqMixed { epoch } => Some(*epoch),
            _ => None,
        });
        assert!(mixed.is_some_and(|e| e >= 1));
        assert!(party.has(|e| matches!(e, SessionEvent::EpochAdvanced(_))));
    }
    assert!(sent.len() >= 10, "chat must have cut in ({} messages)", sent.len());
    // Every chat message sent during the transfer is delivered, and the PQ resume update (k=2) completes.
    assert!(q.run_until(1500, |q| {
        sent.iter().all(|(who, id)| {
            let party = if *who == 'a' { &q.a } else { &q.b };
            party.has(|e| matches!(e, SessionEvent::MessageDelivered(m) if m == id))
        }) && q.a.has(|e| matches!(e, SessionEvent::ResumePromote { k: 2, .. }))
            && q.b.has(|e| matches!(e, SessionEvent::ResumePromote { k: 2, .. }))
    }));
    assert!(!q.a.has(|e| matches!(e, SessionEvent::MessageFailed(_))));
    assert!(!q.b.has(|e| matches!(e, SessionEvent::MessageFailed(_))));
}

fn promoted(p: &Party, k: u8) -> bool {
    p.has(|e| matches!(e, SessionEvent::ResumePromote { k: kk, .. } if *kk == k))
}

#[test]
fn resume_saved_survives_loss_and_late_saves_at_various_points() {
    // 1. Peer writes its vault 40 slots later than we do.
    let mut p = resume_pair(5, 0.0, [0x31; 32]);
    p.b.vault_delay_ticks = 40;
    assert!(p.run_until(200, both_established));
    assert!(p.a.has(|e| matches!(e, SessionEvent::VaultDirty { k: 1, contact: B_AT_A, promote_used_new_first: false, .. })));
    assert!(p.run_until(300, |p| promoted(&p.a, 1) && promoted(&p.b, 1)));

    // 2./3. Every frame in one direction is lost for 60 slots right after establishment.
    for a_to_b in [true, false] {
        let mut p = resume_pair(6, 0.0, [0x32; 32]);
        assert!(p.run_until(200, both_established));
        let start = p.tick;
        p.drop = Some(Box::new(move |tick, dir, _| dir == a_to_b && tick > start && tick <= start + 60));
        p.run_until(60, |_| false);
        assert!(!(promoted(&p.a, 1) && promoted(&p.b, 1)), "the loss window must have mattered");
        assert!(p.run_until(300, |p| promoted(&p.a, 1) && promoted(&p.b, 1)), "direction a_to_b={a_to_b}");
    }

    // 4. Random 30% loss over the whole exchange.
    let mut p = resume_pair(8, 0.30, [0x33; 32]);
    assert!(p.run_until(1500, both_established));
    assert!(p.run_until(1500, |p| promoted(&p.a, 1) && promoted(&p.b, 1)));

    // 5. The peer never writes its vault: nobody may promote.
    let mut p = resume_pair(9, 0.0, [0x34; 32]);
    p.b.auto_vault = false;
    assert!(p.run_until(200, both_established));
    p.run_until(300, |_| false);
    assert!(!promoted(&p.a, 1) && !promoted(&p.b, 1));
}

#[test]
fn no_peer_preamble_for_20_seconds_aborts_with_three_abort_frames() {
    let signer = SoftwareSigner::generate();
    let mut s =
        SecureCallSession::new(signer.local_identity([0; 16]), empty(), CallSide::Answerer, None, ModemGear::Wideband2400, 0).unwrap();
    let mut units = Vec::new();
    let mut now = 0;
    while now <= 25_000 {
        units.push((now, s.next_tx(now)));
        now += 160;
    }
    let events = s.poll_events();
    assert!(events.iter().any(|e| matches!(e, SessionEvent::Aborted(AbortReason::PreambleTimeout))));
    let first_abort = units.iter().position(|(_, u)| is_abort_frame(u)).unwrap();
    assert!(units[first_abort].0 >= 20_000 && units[first_abort].0 < 20_200);
    assert!(units[first_abort..first_abort + 3].iter().all(|(_, u)| is_abort_frame(u)));
    assert!(units[first_abort + 3..].iter().all(|(_, u)| *u == TxUnit::End));
    assert!(units[..first_abort].iter().any(|(_, u)| matches!(u, TxUnit::Preamble(_))));
    assert!(s.is_closed());
}

#[test]
fn incompatible_peer_preamble_aborts() {
    let signer = SoftwareSigner::generate();
    let mut s =
        SecureCallSession::new(signer.local_identity([0; 16]), empty(), CallSide::Answerer, None, ModemGear::Wideband2400, 0).unwrap();
    let old = PreambleCapabilities { version: 1, ..PreambleCapabilities::v2(ModemGear::Wideband2400) };
    assert!(!s.on_rx_preamble(old.encode_bytes(), 100));
    assert_eq!(s.abort_reason(), Some(AbortReason::IncompatibleVersion));
    assert!((0..3).all(|i| is_abort_frame(&s.next_tx(200 + i * 160))));
    assert_eq!(s.next_tx(1000), TxUnit::End);
}

#[test]
fn changed_key_blocks_sending_until_both_sides_confirm_the_sas() {
    let mut p = full_pair(21, 0.0);
    let stale = SoftwareSigner::generate().pub33();
    let sa = SoftwareSigner::generate();
    p.a = Party::new(sa, empty(), dialing(B_AT_A), Some(stale), ModemGear::Wideband2400);
    p.a.sas_choice = None;
    p.b.sas_choice = None;
    assert!(p.run_until(400, both_established));
    assert!(p.a.has(|e| matches!(e, SessionEvent::KeyChanged { .. })));
    let now = p.now;
    assert_eq!(
        p.a.s.chat().unwrap().send_text_message(now, 0, "blocked"),
        Err(aegiscall_chat::ChatError::SendLocked)
    );
    assert!(p.b.s.chat().unwrap().send_text_message(now, 0, "peer may talk").is_ok());
    p.a.s.sas_decision(true).unwrap();
    p.run_until(30, |_| false);
    assert!(!p.a.has(|e| matches!(e, SessionEvent::SasConfirmed)));
    assert_eq!(
        p.a.s.chat().unwrap().send_text_message(p.now, 0, "still blocked"),
        Err(aegiscall_chat::ChatError::SendLocked)
    );
    p.b.s.sas_decision(true).unwrap();
    assert!(p.run_until(60, |p| p.a.has(|e| matches!(e, SessionEvent::SasConfirmed))
        && p.b.has(|e| matches!(e, SessionEvent::SasConfirmed))));
    let id = p.a.s.chat().unwrap().send_text_message(p.now, 0, "verified now").unwrap();
    assert!(p.run_until(100, |p| p.a.has(|e| matches!(e, SessionEvent::MessageDelivered(m) if *m == id))));
}

/// The answerer's vault: a few unrelated contacts plus (optionally) the dialer.
fn answerer_vault(dialer: Option<([u8; 33], [u8; 32])>) -> PeerExpectation {
    let mut resume = Vec::new();
    for n in 0..3u8 {
        resume.push(ResumeCandidate {
            contact: 100 + u32::from(n),
            pub33: SoftwareSigner::from_seed([n; 32]).pub33(),
            secret: SecretKey32::from_bytes([0x80 + n; 32]),
            is_new: n == 1,
        });
    }
    if let Some((pub33, rs)) = dialer {
        resume.push(ResumeCandidate { contact: A_AT_B, pub33, secret: SecretKey32::from_bytes(rs), is_new: false });
    }
    PeerExpectation { psk: Vec::new(), resume }
}

#[test]
fn hidden_or_wrong_caller_id_still_resumes_when_the_dialer_is_in_the_answerers_vault() {
    let rs = [0x55; 32];
    let stranger = SoftwareSigner::from_seed([0xEE; 32]).pub33();
    // What the caller ID gives the answerer: nothing (hidden number) or another contact's key.
    for (n, shown) in [None, Some(stranger)].into_iter().enumerate() {
        let sa = SoftwareSigner::from_seed([0xA0 + n as u8; 32]);
        let sb = SoftwareSigner::from_seed([0xB0 + n as u8; 32]);
        let (pa, pb) = (sa.pub33(), sb.pub33());
        let a = Party::new(sa, resume_expectation(B_AT_A, pb, rs, false), dialing(B_AT_A), Some(pb), ModemGear::Wideband2400);
        let b = Party::new(sb, answerer_vault(Some((pa, rs))), CallSide::Answerer, shown, ModemGear::Wideband2400);
        let mut p = Pair::new(a, b, 5 + n as u64, 0.0);
        assert!(p.run_until(200, both_established), "case {n}: {:?} {:?}", p.a.aborted(), p.b.aborted());
        assert!(p.a.has(|e| matches!(e, SessionEvent::Path(Path::Resume { contact: B_AT_A, used_new: false }))));
        assert!(p.b.has(|e| matches!(e, SessionEvent::Path(Path::Resume { contact: A_AT_B, used_new: false }))));
        // The answerer identified the dialer by its secret: a known contact, nothing locked.
        assert!(p.b.has(|e| matches!(
            e,
            SessionEvent::Established { identity: IdentityStatus::KnownContact, peer_pub33, .. } if *peer_pub33 == pa
        )));
        assert!(!p.b.has(|e| matches!(e, SessionEvent::KeyChanged { .. } | SessionEvent::Sas(_))));
        let now = p.now;
        let id = p.b.s.chat().unwrap().send_text_message(now, 0, "resumed").unwrap();
        assert!(p.run_until(100, |p| p.b.has(|e| matches!(e, SessionEvent::MessageDelivered(m) if *m == id))));
    }
}

#[test]
fn answerer_without_the_dialers_secret_takes_the_full_path() {
    let sa = SoftwareSigner::from_seed([0xA5; 32]);
    let sb = SoftwareSigner::from_seed([0xB5; 32]);
    let (pa, pb) = (sa.pub33(), sb.pub33());
    // The dialer still holds a resume secret for B; B's vault no longer has A (reinstalled).
    let a = Party::new(sa, resume_expectation(B_AT_A, pb, [0x56; 32], false), dialing(B_AT_A), Some(pb), ModemGear::Wideband2400);
    let b = Party::new(sb, answerer_vault(None), CallSide::Answerer, None, ModemGear::Wideband2400);
    let mut p = Pair::new(a, b, 6, 0.0);
    assert!(p.run_until(500, both_established), "{:?} {:?}", p.a.aborted(), p.b.aborted());
    for party in [&p.a, &p.b] {
        assert!(party.has(|e| matches!(e, SessionEvent::Path(Path::Full))));
        assert!(party.has(|e| matches!(e, SessionEvent::Sas(_))));
        assert!(!party.has(|e| matches!(e, SessionEvent::Path(Path::Resume { .. }))));
    }
    assert!(p.a.has(|e| matches!(e, SessionEvent::Established { peer_pub33, .. } if *peer_pub33 == pb)));
    assert!(p.b.has(|e| matches!(e, SessionEvent::Established { peer_pub33, .. } if *peer_pub33 == pa)));
}

#[test]
fn tampered_path_message_aborts_both_sides() {
    use std::cell::RefCell;
    use std::rc::Rc;
    // (resume possible?, byte of the PATH body, xor mask)
    for (n, (resume, pos, mask)) in [(true, 0usize, 0x01u8), (true, 1, 0x02), (false, 0, 0x01), (false, 1, 0x01)].into_iter().enumerate() {
        let mut p = if resume { resume_pair(40 + n as u64, 0.0, [0x57; 32]) } else { full_pair(40 + n as u64, 0.0) };
        // The answerer's PATH frames are taken off the line and a modified copy is delivered.
        let taken: Rc<RefCell<Vec<[u8; 23]>>> = Rc::new(RefCell::new(Vec::new()));
        let sink = taken.clone();
        p.drop = Some(Box::new(move |_, a_to_b, u| match u {
            TxUnit::Superframe(w) if !a_to_b && w[0] == 0xA7 => {
                sink.borrow_mut().push(*w);
                true
            }
            _ => false,
        }));
        let mut forged_any = false;
        for _ in 0..600 {
            if p.a.s.is_closed() && p.b.s.is_closed() {
                break;
            }
            p.step();
            let frames: Vec<[u8; 23]> = taken.borrow_mut().drain(..).collect();
            for mut w in frames {
                w[3 + pos] ^= mask;
                let crc = aegiscall_modem::crc16_ccitt(&w[..21]);
                w[21..].copy_from_slice(&crc.to_be_bytes());
                forged_any = true;
                let (now, tick) = (p.now, p.tick);
                p.a.s.on_rx_superframe(&w, now);
                p.a.react(tick);
            }
        }
        assert!(forged_any, "case {n}: no PATH frame seen");
        let (ra, rb) = (p.a.aborted(), p.b.aborted());
        assert!(ra.is_some() && rb.is_some(), "case {n}: {ra:?} {rb:?}");
        // The dialer is the one that received the forged PATH: it must stop because the path
        // decision no longer fits (not by a timeout or a generic error); the answerer then
        // learns of it through the dialer's ABORT.
        assert_eq!(ra, Some(AbortReason::HsPathMismatch), "case {n}: dialer reason");
        assert_eq!(rb, Some(AbortReason::PeerAbort), "case {n}: answerer reason");
        assert!(p.a.s.is_closed() && p.b.s.is_closed(), "case {n}");
        for party in [&p.a, &p.b] {
            assert!(!party.has(|e| matches!(e, SessionEvent::Established { .. })), "case {n}");
            assert!(!party.s.is_established(), "case {n}");
        }
    }
}

#[test]
fn both_sides_claiming_to_be_the_dialer_abort() {
    for side in [DIAL_NUMBER, CallSide::Answerer] {
        let a = Party::new(SoftwareSigner::generate(), empty(), side, None, ModemGear::Wideband2400);
        let b = Party::new(SoftwareSigner::generate(), empty(), side, None, ModemGear::Wideband2400);
        let mut p = Pair::new(a, b, 8, 0.0);
        assert!(p.run_until(100, |p| p.a.s.is_closed() && p.b.s.is_closed()));
        let (ra, rb) = (p.a.aborted(), p.b.aborted());
        assert!(ra == Some(AbortReason::HsSideConflict) || rb == Some(AbortReason::HsSideConflict), "{ra:?} {rb:?}");
        assert!(ra.is_some() && rb.is_some());
        assert!(!p.a.s.is_keyed() && !p.b.s.is_keyed());
    }
}

#[test]
fn responder_reports_established_only_after_the_peers_first_encrypted_frame() {
    let mut p = full_pair(12, 0.0);
    // The responder installs its keys when it sends HS4; the initiator is not keyed yet.
    assert!(p.run_until(400, |p| p.a.s.is_keyed() || p.b.s.is_keyed()));
    let a_is_r = p.a.s.is_keyed();
    assert!(a_is_r != p.b.s.is_keyed());
    // HS4 is held back: the responder stays keyed without any encrypted frame from the peer.
    p.drop = Some(Box::new(move |_, a_to_b, u| matches!(u, TxUnit::Superframe(w) if a_to_b == a_is_r && w[0] == 0xA4)));
    p.run_until(5, |_| false);
    let now = p.now;
    {
        let r = if a_is_r { &mut p.a } else { &mut p.b };
        assert!(r.s.is_keyed() && !r.s.is_established());
        assert!(!r.has(|e| matches!(e, SessionEvent::Established { .. })));
        assert!(!r.has(|e| matches!(e, SessionEvent::HandshakeProgress(100))));
        assert!(matches!(r.s.chat(), Err(aegiscall_chat::ChatError::NotEstablished)));
        // Handshake-layer frames (even well-formed ones) are not the confirmation.
        let stray = HsLink::new(0x5A).abort_frame(1);
        r.s.on_rx_superframe(&stray, now);
        r.react(0);
        assert!(!r.s.is_established() && r.aborted().is_none());
    }
    {
        let i = if a_is_r { &p.b } else { &p.a };
        assert!(!i.s.is_keyed() && !i.s.is_established());
    }
    // Once HS4 gets through, the initiator's first encrypted frame confirms the responder.
    p.drop = None;
    assert!(p.run_until(100, both_established));
    let r = if a_is_r { &p.a } else { &p.b };
    assert!(r.has(|e| matches!(e, SessionEvent::Established { role: Role::Responder, .. })));
    let now = p.now;
    let r = if a_is_r { &mut p.a } else { &mut p.b };
    assert!(r.s.chat().unwrap().send_text_message(now, 0, "after confirmation").is_ok());
}

#[test]
fn full_path_writes_the_resume_secret_only_after_sas_and_contact_save() {
    let mut p = full_pair(31, 0.0);
    assert!(p.run_until(400, both_established));
    p.run_until(20, |_| false);
    assert!(p.a.has(|e| matches!(e, SessionEvent::SasConfirmed)));
    assert!(!p.a.has(|e| matches!(e, SessionEvent::VaultDirty { .. })));
    p.a.s.contact_saved(B_AT_A).unwrap();
    p.b.s.contact_saved(A_AT_B).unwrap();
    assert!(p.run_until(100, |p| promoted(&p.a, 1) && promoted(&p.b, 1)));
    assert!(p.a.has(|e| matches!(e, SessionEvent::VaultDirty { k: 1, contact: B_AT_A, .. })));
    assert!(!p.a.has(|e| matches!(e, SessionEvent::PqProgress(_))));
}

#[test]
fn psk_contact_on_full_path_writes_the_resume_secret_without_sas() {
    let sa = SoftwareSigner::generate();
    let sb = SoftwareSigner::generate();
    let (pa, pb) = (sa.pub33(), sb.pub33());
    let psk = [0xC3u8; 32];
    let ea = PeerExpectation { psk: vec![(B_AT_A, pb, SecretKey32::from_bytes(psk))], resume: Vec::new() };
    let eb = PeerExpectation { psk: vec![(A_AT_B, pa, SecretKey32::from_bytes(psk))], resume: Vec::new() };
    let mut a = Party::new(sa, ea, dialing(B_AT_A), Some(pb), ModemGear::Wideband2400);
    let mut b = Party::new(sb, eb, CallSide::Answerer, Some(pa), ModemGear::Wideband2400);
    a.sas_choice = None;
    b.sas_choice = None;
    let mut p = Pair::new(a, b, 4, 0.0);
    assert!(p.run_until(400, both_established));
    assert!(p.a.has(|e| matches!(e, SessionEvent::Established { psk_contact: Some(B_AT_A), .. })));
    assert!(p.run_until(100, |p| promoted(&p.a, 1) && promoted(&p.b, 1)));
}

#[test]
fn sas_mismatch_after_establishment_aborts_both_sides() {
    let mut p = full_pair(41, 0.0);
    p.a.sas_choice = None;
    assert!(p.run_until(400, both_established));
    p.a.s.sas_decision(false).unwrap();
    assert!(p.run_until(50, |p| p.a.s.is_closed() && p.b.s.is_closed()));
    assert_eq!(p.a.aborted(), Some(AbortReason::SasMismatch));
    assert_eq!(p.b.aborted(), Some(AbortReason::PeerSasMismatch));
    assert!(p.b.s.vault().is_none());
}

#[test]
fn messages_cross_ratchet_steps_under_loss_without_being_lost() {
    let mut p = full_pair(51, 0.05);
    assert!(p.run_until(500, both_established));
    let mut sent = Vec::new();
    for k in 0..1300u64 {
        if k % 25 == 0 {
            let now = p.now;
            let (who, party) = if k % 50 == 0 { ('a', &mut p.a) } else { ('b', &mut p.b) };
            let id = party.s.chat().unwrap().send_text_message(now, 0, &format!("Ratchet: msg {k} ok.")).unwrap();
            sent.push((who, id));
        }
        p.step();
    }
    assert!(p.run_until(800, |p| sent.iter().all(|(who, id)| {
        let party = if *who == 'a' { &p.a } else { &p.b };
        party.has(|e| matches!(e, SessionEvent::MessageDelivered(m) if m == id))
    })));
    assert!(p.a.s.tx_epoch().unwrap() >= 3 && p.b.s.tx_epoch().unwrap() >= 3);
    assert!(!p.a.has(|e| matches!(e, SessionEvent::MessageFailed(_))));
    assert!(!p.b.has(|e| matches!(e, SessionEvent::MessageFailed(_))));
    assert_eq!(text_of(&p.b).iter().filter(|t| t.starts_with("Ratchet: ")).count(), sent.len());
}

#[test]
fn remote_wipe_is_sent_three_times_and_reaches_the_peer() {
    let mut p = full_pair(61, 0.0);
    assert!(p.run_until(400, both_established));
    let now = p.now;
    p.a.s.chat().unwrap().send_text_message(now, 0, "to be wiped").unwrap();
    p.run_until(40, |_| false);
    assert!(!text_of(&p.b).is_empty());
    p.a.s.panic_wipe();
    assert_eq!(p.a.s.vault().map(|v| v.total_live_secret_bytes()), Some(0));
    // The first two PANIC_WIPE frames are lost; the third must still get through.
    let start = p.tick;
    p.drop = Some(Box::new(move |tick, a_to_b, _| a_to_b && tick <= start + 2));
    p.record = true;
    assert!(p.run_until(10, |p| p.a.s.is_closed() && p.b.s.is_closed()));
    let wipe_frames = p.tape.iter().filter(|(_, from_a, u)| *from_a && matches!(u, TxUnit::Superframe(_))).count();
    assert_eq!(wipe_frames, 3);
    assert!(p.a.has(|e| matches!(e, SessionEvent::WipeSent)));
    assert!(p.b.has(|e| matches!(e, SessionEvent::RemoteWipe)));
    assert!(p.b.s.vault().is_none());
}

/// Full-path pair whose users have not answered the SAS prompt yet.
fn pair_with_sas_pending(seed: u64) -> Pair {
    let mut p = full_pair(seed, 0.0);
    p.a.sas_choice = None;
    p.b.sas_choice = None;
    assert!(p.run_until(400, both_established));
    p
}

fn voice_opened(p: &Party) -> usize {
    p.count(|e| matches!(e, SessionEvent::VoiceWindow { open: true }))
}

fn voice_units(p: &Pair) -> usize {
    p.tape.iter().filter(|(_, _, u)| *u == TxUnit::Voice).count()
}

#[test]
fn peer_alone_cannot_open_the_voice_window() {
    let mut p = pair_with_sas_pending(71);
    p.record = true;
    let pre_a = p.a.s.local_preamble();
    p.a.s.voice_window(true).unwrap();
    // A keeps repeating its request; B's user never agrees.
    p.run_until(120, |_| false);
    assert_eq!(voice_units(&p), 0, "nobody may stop modulating");
    assert_eq!(voice_opened(&p.a) + voice_opened(&p.b), 0);
    assert!(!p.b.s.on_rx_preamble(pre_a, p.now), "no resync is accepted without an open window");
    // The session is not stuck: A withdraws, and chat still works in both directions.
    p.a.s.voice_window(false).unwrap();
    let now = p.now;
    let ia = p.a.s.chat().unwrap().send_text_message(now, 0, "a to b").unwrap();
    let ib = p.b.s.chat().unwrap().send_text_message(now, 0, "b to a").unwrap();
    assert!(p.run_until(100, |p| p.a.has(|e| matches!(e, SessionEvent::MessageDelivered(m) if *m == ia))
        && p.b.has(|e| matches!(e, SessionEvent::MessageDelivered(m) if *m == ib))));
    assert_eq!(voice_units(&p), 0);
}

#[test]
fn voice_window_opens_only_when_both_sides_ask_and_only_once_per_call() {
    let mut p = pair_with_sas_pending(72);
    p.record = true;
    let pre_a = p.a.s.local_preamble();
    assert!(!p.b.s.on_rx_preamble(pre_a, p.now), "preambles after establishment are ignored");
    p.a.s.voice_window(true).unwrap();
    p.run_until(30, |_| false);
    assert_eq!(voice_units(&p), 0);
    p.b.s.voice_window(true).unwrap();
    assert!(p.run_until(30, |p| voice_opened(&p.a) == 1 && voice_opened(&p.b) == 1));
    p.run_until(5, |_| false);
    let last = &p.tape[p.tape.len() - 2..];
    assert!(last.iter().all(|(_, _, u)| *u == TxUnit::Voice), "both sides pass the microphone through");
    assert!(p.b.s.on_rx_preamble(pre_a, p.now), "resync accepted while the window is open");

    p.a.s.voice_window(false).unwrap();
    assert!(p.run_until(20, |p| p.a.has(|e| matches!(e, SessionEvent::VoiceWindow { open: false }))
        && p.b.has(|e| matches!(e, SessionEvent::VoiceWindow { open: false }))));
    assert!(p.tape.iter().any(|(_, from_a, u)| *from_a && matches!(u, TxUnit::Preamble(_))));
    p.run_until(5, |_| false);
    assert!(p.b.s.on_rx_preamble(pre_a, p.now), "resync accepted right after the window");

    // Second window in the same call: refused locally on both sides, and no Voice unit follows.
    let before = voice_units(&p);
    assert_eq!(p.a.s.voice_window(true), Err(aegiscall_chat::ChatError::InvalidState));
    assert_eq!(p.b.s.voice_window(true), Err(aegiscall_chat::ChatError::InvalidState));
    let id = p.a.s.chat().unwrap().send_text_message(p.now, 0, "after voice").unwrap();
    assert!(p.run_until(100, |p| p.a.has(|e| matches!(e, SessionEvent::MessageDelivered(m) if *m == id))));
    p.run_until(80, |_| false);
    assert_eq!(voice_units(&p), before);
    assert_eq!(voice_opened(&p.a), 1);
    assert_eq!(voice_opened(&p.b), 1);
    assert!(!p.b.s.on_rx_preamble(pre_a, p.now), "outside the resync window preambles are ignored again");

    // The SAS can still be confirmed after the window.
    p.a.s.sas_decision(true).unwrap();
    p.b.s.sas_decision(true).unwrap();
    assert!(p.run_until(60, |p| p.a.has(|e| matches!(e, SessionEvent::SasConfirmed))
        && p.b.has(|e| matches!(e, SessionEvent::SasConfirmed))));
}

#[test]
fn voice_window_is_refused_without_a_pending_sas() {
    use aegiscall_chat::ChatError;
    // Resume path: verified contact, no SAS in this call.
    let mut p = resume_pair(73, 0.0, [0x61; 32]);
    p.record = true;
    assert!(p.run_until(200, both_established));
    assert!(p.a.s.sas_bytes().is_none());
    assert_eq!(p.a.s.voice_window(true), Err(ChatError::InvalidState));
    assert_eq!(p.b.s.voice_window(true), Err(ChatError::InvalidState));
    p.run_until(60, |_| false);
    assert_eq!(voice_units(&p), 0);
    assert_eq!(voice_opened(&p.a) + voice_opened(&p.b), 0);

    // Full path after both sides confirmed the SAS: nothing left to compare.
    let mut p = full_pair(74, 0.0);
    p.record = true;
    assert!(p.run_until(400, both_established));
    assert!(p.run_until(60, |p| p.a.has(|e| matches!(e, SessionEvent::SasConfirmed))
        && p.b.has(|e| matches!(e, SessionEvent::SasConfirmed))));
    assert_eq!(p.a.s.voice_window(true), Err(ChatError::InvalidState));
    assert_eq!(p.b.s.voice_window(true), Err(ChatError::InvalidState));
    p.run_until(40, |_| false);
    assert_eq!(voice_units(&p), 0);
}

#[test]
fn remote_wipe_is_still_executed_while_hanging_up_or_wiping() {
    // A hangs up in the same slot in which B wipes.
    let mut p = full_pair(75, 0.0);
    assert!(p.run_until(400, both_established));
    let now = p.now;
    p.b.s.chat().unwrap().send_text_message(now, 0, "secret").unwrap();
    p.run_until(40, |_| false);
    assert!(!text_of(&p.a).is_empty());
    p.a.s.end();
    p.b.s.panic_wipe();
    assert!(p.run_until(10, |p| p.a.s.is_closed() && p.b.s.is_closed()));
    assert!(p.a.has(|e| matches!(e, SessionEvent::RemoteWipe)));
    assert!(p.b.has(|e| matches!(e, SessionEvent::WipeSent)));
    assert!(p.a.s.vault().is_none() && p.b.s.vault().is_none());

    // Both wipe at once: each still reports the other's wipe and finishes its own.
    let mut p = full_pair(76, 0.0);
    assert!(p.run_until(400, both_established));
    p.a.s.panic_wipe();
    p.b.s.panic_wipe();
    assert!(p.run_until(10, |p| p.a.s.is_closed() && p.b.s.is_closed()));
    for party in [&p.a, &p.b] {
        assert_eq!(party.count(|e| matches!(e, SessionEvent::RemoteWipe)), 1);
        assert!(party.has(|e| matches!(e, SessionEvent::WipeSent)));
    }
}

#[test]
fn normal_hang_up_notifies_the_peer() {
    let mut p = full_pair(81, 0.0);
    assert!(p.run_until(400, both_established));
    let now = p.now;
    p.a.s.chat().unwrap().send_text_message(now, 0, "kept only for the call").unwrap();
    p.run_until(40, |_| false);
    assert!(!text_of(&p.b).is_empty());
    p.a.s.end();
    assert!(p.run_until(10, |p| p.a.s.is_closed() && p.b.s.is_closed()));
    assert!(p.b.has(|e| matches!(e, SessionEvent::Ended { by_peer: true })));
    assert!(p.a.aborted().is_none() && p.b.aborted().is_none());
    // After a normal hang-up neither side keeps the engine, its keys or any message plaintext.
    for party in [&mut p.a, &mut p.b] {
        assert!(party.s.vault().is_none());
        assert!(party.s.tx_epoch().is_none());
        assert!(!party.s.is_keyed());
        assert_eq!(party.s.chat().err(), Some(aegiscall_chat::ChatError::SessionClosed));
    }
}

#[test]
fn signer_that_never_answers_times_out() {
    let mut p = full_pair(91, 0.0);
    // A drops every signature request on the floor.
    let mut ticks = 0;
    while ticks < 600 && !p.a.s.is_closed() {
        ticks += 1;
        p.tick += 1;
        p.now += p.step_ms;
        let now = p.now;
        let ua = p.a.s.next_tx(now);
        let ub = p.b.s.next_tx(now);
        deliver(ua, &mut p.b.s, now);
        deliver(ub, &mut p.a.s, now);
        let evs = p.a.s.poll_events();
        p.a.log.extend(evs);
        p.b.react(p.tick);
    }
    assert_eq!(p.a.aborted(), Some(AbortReason::SignerTimeout));
}

#[test]
fn evidence_chain_travels_over_bulk_on_request() {
    let mut p = full_pair(101, 0.05);
    let chain: Vec<u8> = (0..3000u32).map(|i| (i * 7) as u8).collect();
    p.b.s.provide_evidence_chain(&chain).unwrap();
    assert!(p.run_until(500, both_established));
    // The chain is only given to a verified peer: let both users confirm the SAS first.
    assert!(p.run_until(200, |p| p.a.has(|e| matches!(e, SessionEvent::SasConfirmed))
        && p.b.has(|e| matches!(e, SessionEvent::SasConfirmed))));
    p.a.s.request_evidence().unwrap();
    // EVIDENCE_REQ is a single control frame without retransmission. The periodic
    // re-synchronisation preambles shift which slot the seeded 5 % loss hits, so the request
    // itself may be lost: ask again every 100 slots (same 2000-slot budget) like a retrying app.
    let mut arrived = false;
    for _ in 0..20 {
        if p.run_until(100, |p| p.a.has(|e| matches!(e, SessionEvent::EvidenceChain(_)))) {
            arrived = true;
            break;
        }
        p.a.s.request_evidence().unwrap();
    }
    assert!(arrived);
    let got = p.a.log.iter().find_map(|e| match e {
        SessionEvent::EvidenceChain(c) => Some(c.clone()),
        _ => None,
    });
    assert_eq!(got, Some(chain));
}

fn evidence_arrived(p: &Party) -> bool {
    p.has(|e| matches!(e, SessionEvent::EvidenceChain(_)))
}

#[test]
fn unverified_peer_does_not_receive_the_evidence_chain() {
    let mut p = pair_with_sas_pending(102);
    p.b.s.provide_evidence_chain(&[0x5Au8; 1500]).unwrap();
    for _ in 0..10 {
        p.a.s.request_evidence().unwrap();
        p.run_until(100, |_| false);
    }
    assert!(!evidence_arrived(&p.a), "no attestation chain before the SAS is confirmed");
    assert_eq!(p.a.aborted(), None, "the request is ignored, the call goes on");
    assert_eq!(p.b.aborted(), None);
    assert!(both_established(&p));
}

#[test]
fn evidence_chain_is_sent_once_the_sas_is_confirmed() {
    let mut p = pair_with_sas_pending(103);
    let chain: Vec<u8> = (0..2000u32).map(|i| (i * 13) as u8).collect();
    p.b.s.provide_evidence_chain(&chain).unwrap();
    // Asked while unverified (as the app does right after establishment): held back.
    p.a.s.request_evidence().unwrap();
    p.run_until(300, |_| false);
    assert!(!evidence_arrived(&p.a));
    p.a.s.sas_decision(true).unwrap();
    p.b.s.sas_decision(true).unwrap();
    assert!(p.run_until(60, |p| p.a.has(|e| matches!(e, SessionEvent::SasConfirmed))
        && p.b.has(|e| matches!(e, SessionEvent::SasConfirmed))));
    // The held request is answered without being asked again.
    assert!(p.run_until(2000, |p| evidence_arrived(&p.a)));
    let got = p.a.log.iter().find_map(|e| match e {
        SessionEvent::EvidenceChain(c) => Some(c.clone()),
        _ => None,
    });
    assert_eq!(got, Some(chain));
}

#[test]
fn pinned_psk_contact_receives_the_evidence_chain_without_sas() {
    let sa = SoftwareSigner::generate();
    let sb = SoftwareSigner::generate();
    let (pa, pb) = (sa.pub33(), sb.pub33());
    let psk = [0xC4u8; 32];
    let ea = PeerExpectation { psk: vec![(B_AT_A, pb, SecretKey32::from_bytes(psk))], resume: Vec::new() };
    let eb = PeerExpectation { psk: vec![(A_AT_B, pa, SecretKey32::from_bytes(psk))], resume: Vec::new() };
    let mut a = Party::new(sa, ea, dialing(B_AT_A), Some(pb), ModemGear::Wideband2400);
    let mut b = Party::new(sb, eb, CallSide::Answerer, Some(pa), ModemGear::Wideband2400);
    a.sas_choice = None;
    b.sas_choice = None;
    let mut p = Pair::new(a, b, 104, 0.0);
    let chain = vec![0xA5u8; 1200];
    p.b.s.provide_evidence_chain(&chain).unwrap();
    assert!(p.run_until(400, both_established));
    assert!(p.b.has(|e| matches!(e, SessionEvent::Established { identity: IdentityStatus::KnownContact, .. })));
    p.a.s.request_evidence().unwrap();
    assert!(p.run_until(2000, |p| evidence_arrived(&p.a)));
    assert!(!p.a.has(|e| matches!(e, SessionEvent::SasConfirmed)));
}

#[test]
fn multi_shard_message_reports_increasing_progress_and_ends_with_delivered() {
    let mut p = full_pair(31, 0.0);
    assert!(p.run_until(400, both_established));
    let now = p.now;
    let text = "Progress check: ".repeat(16);
    let id = p.a.s.chat().unwrap().send_text_message(now, 0, &text).unwrap();
    assert!(p.run_until(400, |p| p.a.has(|e| matches!(e, SessionEvent::MessageDelivered(m) if *m == id))));

    let mut progress = Vec::new();
    let mut delivered_at = None;
    for (i, e) in p.a.log.iter().enumerate() {
        match e {
            SessionEvent::MessageProgress { msg_id, acked, total } if *msg_id == id => progress.push((*acked, *total)),
            SessionEvent::MessageDelivered(m) if *m == id => delivered_at = Some(i),
            _ => {}
        }
    }
    let delivered_at = delivered_at.unwrap();
    assert_eq!(p.a.count(|e| matches!(e, SessionEvent::MessageDelivered(m) if *m == id)), 1);
    assert!(progress.len() >= 2, "progress events: {progress:?}");
    // The 0-progress state at send time is not reported, and nothing follows Delivered.
    assert!(p.a.log.iter().skip(delivered_at).all(|e| !matches!(e, SessionEvent::MessageProgress { .. })));
    let total = progress[0].1;
    assert!(total >= 8);
    assert!(progress.iter().all(|(acked, t)| *t == total && *acked > 0 && *acked < total));
    // Strictly increasing: the same (acked, total) pair is never reported twice.
    assert!(progress.windows(2).all(|w| w[0].0 < w[1].0), "progress events: {progress:?}");
    assert_eq!(p.a.log.iter().filter(|e| matches!(e, SessionEvent::MessageProgress { .. })).count(), progress.len());
    // The receiver never reports progress for messages it only receives.
    assert!(!p.b.has(|e| matches!(e, SessionEvent::MessageProgress { .. })));
}
