//! Reviewer tests for WP3 (hs_link, call_session, mux, preamble). Evidence for the acceptance report.

mod common;

use aegiscall_chat::{AbortReason, HsLink, PeerPresenceState, SecureCallSession, SessionEvent, TxUnit};
use aegiscall_crypto::{CallSide, SoftwareSigner};
use aegiscall_modem::{crc16_ccitt, ModemGear, PreambleCapabilities};
use common::*;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

fn describe(name: &str, mut v: Vec<u64>, limit: u64) {
    v.sort();
    let n = v.len();
    let mean = v.iter().sum::<u64>() as f64 / n as f64;
    let over = v.iter().filter(|x| **x > limit).count();
    eprintln!(
        "{name}: n={n} min={} mean={mean:.1} p50={} p95={} p99={} max={} over{limit}={over}",
        v[0],
        v[n / 2],
        v[n * 95 / 100],
        v[n * 99 / 100],
        v[n - 1]
    );
}

#[test]
fn crc_is_x25_check_value() {
    assert_eq!(crc16_ccitt(b"123456789"), 0x906E);
}

#[test]
fn budget_distribution_wideband_and_narrowband() {
    let mut frames = Vec::new();
    let mut ticks = Vec::new();
    for seed in 1..=400u64 {
        let mut p = full_pair(seed * 7919, 0.05);
        p.lossy_preamble = false;
        assert!(p.run_until(1000, both_established), "full seed {seed}: {:?} {:?}", p.a.aborted(), p.b.aborted());
        frames.push(p.a.superframes.max(p.b.superframes));
        ticks.push(p.tick);
    }
    describe("FULL 5% wide frames(max of sides)", frames, 216);
    describe("FULL 5% wide ticks(160ms)", ticks, 562);
    let mut frames = Vec::new();
    for seed in 1..=400u64 {
        let mut p = resume_pair(seed * 104_729, 0.05, [0x42; 32]);
        p.lossy_preamble = false;
        assert!(p.run_until(400, both_established), "resume seed {seed}: {:?} {:?}", p.a.aborted(), p.b.aborted());
        frames.push(p.a.superframes.max(p.b.superframes));
    }
    describe("RESUME 5% wide frames per side", frames, 20);
    for (gear, step, label) in [(ModemGear::Wideband2400, 160u64, "wide"), (ModemGear::Narrowband1200, 320u64, "narrow")] {
        for loss in [0.05f64, 0.10, 0.20, 0.30] {
            let mut tally: BTreeMap<String, u32> = BTreeMap::new();
            let mut ticks = Vec::new();
            for seed in 1..=100u64 {
                let mut p = full_pair_gear(seed * 31 + 5, loss, gear);
                p.step_ms = step;
                p.lossy_preamble = false;
                let ok = p.run_until(1500, both_established);
                if ok {
                    ticks.push(p.tick * step / 1000);
                    *tally.entry("ok".into()).or_default() += 1;
                } else {
                    *tally.entry(format!("{:?}/{:?}", p.a.aborted(), p.b.aborted())).or_default() += 1;
                }
            }
            if !ticks.is_empty() {
                describe(&format!("FULL {label} loss {loss} seconds-to-established"), ticks, 90);
            }
            eprintln!("FULL {label} loss {loss}: {tally:?}");
        }
    }
    for loss in [0.20f64, 0.30] {
        let mut tally: BTreeMap<String, u32> = BTreeMap::new();
        for seed in 1..=100u64 {
            let mut p = resume_pair(seed * 17 + 3, loss, [0x43; 32]);
            p.lossy_preamble = false;
            let ok = p.run_until(1500, both_established);
            let k = if ok { "ok".to_string() } else { format!("{:?}/{:?}", p.a.aborted(), p.b.aborted()) };
            *tally.entry(k).or_default() += 1;
        }
        eprintln!("RESUME wide loss {loss}: {tally:?}");
    }
    let mut tally: BTreeMap<String, u32> = BTreeMap::new();
    for seed in 1..=100u64 {
        let mut p = full_pair(seed * 13 + 1, 0.05);
        let ok = p.run_until(1500, both_established);
        let k = if ok { "ok".to_string() } else { format!("{:?}/{:?}", p.a.aborted(), p.b.aborted()) };
        *tally.entry(k).or_default() += 1;
    }
    eprintln!("FULL wide 5% incl. lossy preamble: {tally:?}");
}

#[test]
fn presence_and_viewed_receipt_are_not_queued_while_key_changed_and_sas_unconfirmed() {
    let mut p = full_pair(21, 0.0);
    let stale = SoftwareSigner::generate().pub33();
    let sa = SoftwareSigner::generate();
    p.a = Party::new(sa, empty(), dialing(B_AT_A), Some(stale), ModemGear::Wideband2400);
    p.a.sas_choice = None;
    p.b.sas_choice = None;
    assert!(p.run_until(400, both_established));
    let eng = p.a.s.chat().unwrap();
    assert!(eng.is_tx_locked());
    let before = eng.mux.ctrl_len();
    eng.send_presence_state(PeerPresenceState::TypingText);
    let after_presence = eng.mux.ctrl_len();
    eng.send_viewed_receipt(0x1234);
    let after_viewed = eng.mux.ctrl_len();
    eprintln!("ctrl queue while locked: before {before}, after presence {after_presence}, after viewed {after_viewed}");
    assert_eq!(after_presence, before, "send_presence_state queued a frame while sending is locked");
    assert_eq!(after_viewed, before, "send_viewed_receipt queued a frame while sending is locked");
}

#[test]
fn path_tamper_is_detected_promptly_with_a_path_related_reason() {
    for (n, (resume, pos, mask)) in [(true, 0usize, 0x01u8), (true, 1, 0x02), (false, 0, 0x01), (false, 1, 0x01)].into_iter().enumerate() {
        let mut p = if resume { resume_pair(40 + n as u64, 0.0, [0x57; 32]) } else { full_pair(40 + n as u64, 0.0) };
        let taken: Rc<RefCell<Vec<[u8; 23]>>> = Rc::new(RefCell::new(Vec::new()));
        let sink = taken.clone();
        p.drop = Some(Box::new(move |_, a_to_b, u| match u {
            TxUnit::Superframe(w) if !a_to_b && w[0] == 0xA7 => {
                sink.borrow_mut().push(*w);
                true
            }
            _ => false,
        }));
        let mut forged_tick = None;
        let mut a_abort_tick = None;
        for _ in 0..700 {
            if p.a.s.is_closed() && p.b.s.is_closed() {
                break;
            }
            p.step();
            if a_abort_tick.is_none() && p.a.aborted().is_some() {
                a_abort_tick = Some(p.tick);
            }
            let frames: Vec<[u8; 23]> = taken.borrow_mut().drain(..).collect();
            for mut w in frames {
                w[3 + pos] ^= mask;
                let crc = crc16_ccitt(&w[..21]);
                w[21..].copy_from_slice(&crc.to_be_bytes());
                forged_tick.get_or_insert(p.tick);
                let (now, tick) = (p.now, p.tick);
                p.a.s.on_rx_superframe(&w, now);
                p.a.react(tick);
            }
        }
        let (ra, rb) = (p.a.aborted(), p.b.aborted());
        eprintln!("case {n} resume={resume}: forged at tick {forged_tick:?}, a aborted {ra:?} at {a_abort_tick:?}, b {rb:?}");
        assert!(forged_tick.is_some());
        let timeouts = [AbortReason::HandshakeTimeout, AbortReason::StallTimeout, AbortReason::PreambleTimeout];
        assert!(ra.is_some_and(|r| !timeouts.contains(&r)), "case {n}: dialer reason {ra:?}");
        assert!(a_abort_tick.unwrap() <= forged_tick.unwrap() + 30, "case {n}: detection too late");
    }
}

fn rand_frame(r: &mut XorShift) -> [u8; 23] {
    let mut f = [0u8; 23];
    for b in f.iter_mut() {
        *b = (r.next_u64() >> 24) as u8;
    }
    if r.chance(0.75) {
        f[0] = 0xA0 | ((r.next_u64() % 16) as u8);
        if r.chance(0.7) {
            f[1] = (r.next_u64() % 120) as u8;
        }
        if r.chance(0.5) {
            f[2] = 0x77;
        }
        let crc = crc16_ccitt(&f[..21]);
        f[21..].copy_from_slice(&crc.to_be_bytes());
    }
    f
}

#[test]
fn random_input_never_panics_and_garbage_cannot_abort_a_keyed_session() {
    let mut r = XorShift(0x1234_5678_9ABC_DEF1);
    for round in 0..120u64 {
        let mut s = SecureCallSession::new(
            SoftwareSigner::generate().local_identity([0; 16]),
            empty(),
            CallSide::Answerer,
            None,
            ModemGear::Wideband2400,
            0,
        )
        .unwrap();
        for i in 0..200u64 {
            s.on_rx_superframe(&rand_frame(&mut r), i * 160);
            let mut raw = [0u8; 5];
            for b in raw.iter_mut() {
                *b = (r.next_u64() >> 20) as u8;
            }
            let _ = s.on_rx_preamble(raw, i * 160);
            let _ = s.next_tx(i * 160);
            let _ = s.poll_events();
        }
        let mut p = full_pair(round + 100, 0.0);
        p.run_until(5 + round % 40, |_| false);
        for _ in 0..300 {
            let f = rand_frame(&mut r);
            let now = p.now;
            p.a.s.on_rx_superframe(&f, now);
            let _ = p.a.s.next_tx(now);
        }
        let mut p = full_pair(round + 1000, 0.0);
        assert!(p.run_until(400, |p| p.a.s.is_keyed() || p.b.s.is_keyed()));
        let keyed_a = p.a.s.is_keyed();
        for _ in 0..300 {
            let f = rand_frame(&mut r);
            let now = p.now;
            let party = if keyed_a { &mut p.a } else { &mut p.b };
            party.s.on_rx_superframe(&f, now);
        }
        {
            let party = if keyed_a { &mut p.a } else { &mut p.b };
            party.react(0);
            assert!(party.aborted().is_none(), "round {round}: garbage aborted a keyed session: {:?}", party.aborted());
        }
        assert!(p.run_until(200, both_established), "round {round}: {:?} {:?}", p.a.aborted(), p.b.aborted());
        for _ in 0..300 {
            let f = rand_frame(&mut r);
            let now = p.now;
            p.a.s.on_rx_superframe(&f, now);
            p.b.s.on_rx_superframe(&f, now);
            let other = PreambleCapabilities::v2(ModemGear::Narrowband1200).encode_bytes();
            assert!(!p.a.s.on_rx_preamble(other, now));
        }
        p.a.react(0);
        p.b.react(0);
        assert!(p.a.aborted().is_none() && p.b.aborted().is_none(), "round {round}: established session aborted by garbage");
        let now = p.now;
        let id = p.a.s.chat().unwrap().send_text_message(now, 0, "alive").unwrap();
        assert!(p.run_until(100, |p| p.a.has(|e| matches!(e, SessionEvent::MessageDelivered(m) if *m == id))));
    }
}

/// Deterministic form of the rare failure of the test above: right after one side installs the
/// keys, CRC-valid ACKs carrying the peer's attempt tag claim every fragment of every message. They
/// are not authenticated, so they must not stop the keyed side from delivering its last handshake
/// message (HS4); before the fix the keyed side never sent HS4 and the call stalled.
#[test]
fn forged_acks_cannot_suppress_the_last_handshake_message_of_a_keyed_side() {
    for seed in 0..8u64 {
        let tags: Rc<RefCell<[Option<u8>; 2]>> = Rc::new(RefCell::new([None; 2]));
        let sink = tags.clone();
        let mut p = full_pair(seed + 500, 0.0);
        p.drop = Some(Box::new(move |_, a_to_b, u| {
            if let TxUnit::Superframe(w) = u {
                if w[0] & 0xF0 == 0xA0 {
                    sink.borrow_mut()[usize::from(!a_to_b)].get_or_insert(w[2]);
                }
            }
            false
        }));
        assert!(p.run_until(400, |p| p.a.s.is_keyed() || p.b.s.is_keyed()), "seed {seed}: no side keyed");
        assert!(!(p.a.s.is_keyed() && p.b.s.is_keyed()), "seed {seed}: both sides keyed in the same slot");
        let keyed_a = p.a.s.is_keyed();
        // Index 0 holds a's tag and index 1 b's: the keyed side's peer is the other one.
        let peer_tag = tags.borrow()[usize::from(keyed_a)].expect("peer sent link frames");
        let now = p.now;
        let party = if keyed_a { &mut p.a } else { &mut p.b };
        for t in 0..=7u8 {
            let n = aegiscall_chat::hs_link::fragment_count(t).unwrap_or(0);
            for bm in [[0xFFu8; 18], std::array::from_fn(|i| if i * 8 + 8 <= n { 0xFF } else if i * 8 < n { (1u8 << (n - i * 8)) - 1 } else { 0 })] {
                let mut f = [0u8; 23];
                f[0] = 0xA0 | 0x0E;
                f[1] = t;
                f[2] = peer_tag;
                f[3..21].copy_from_slice(&bm);
                let crc = crc16_ccitt(&f[..21]);
                f[21..].copy_from_slice(&crc.to_be_bytes());
                party.s.on_rx_superframe(&f, now);
            }
        }
        party.react(p.tick);
        assert!(party.aborted().is_none(), "seed {seed}: forged ACKs aborted the keyed side");
        assert!(p.run_until(200, both_established), "seed {seed}: {:?} {:?}", p.a.aborted(), p.b.aborted());
    }
}

#[test]
fn hs_link_fuzz_keeps_reassembly_bounded() {
    let mut r = XorShift(0xDEAD_BEEF_0000_0001);
    let mut link = HsLink::new(0x10);
    let mut fed = 0u64;
    for _ in 0..50_000 {
        let mut f = rand_frame(&mut r);
        f[2] = 0x77;
        let crc = crc16_ccitt(&f[..21]);
        f[21..].copy_from_slice(&crc.to_be_bytes());
        fed += 1;
        let _ = link.on_frame(&f);
        let _ = link.next_frame();
        if link.is_closed() {
            break;
        }
    }
    eprintln!("fed {fed} frames, stored fragments {}", link.received_fragments());
    assert!(link.received_fragments() <= 5 + 89 + 97 + 8 + 2 + 5 + 1);
}

#[test]
fn no_retry_after_abort_in_the_same_call() {
    let mut s = SecureCallSession::new(
        SoftwareSigner::generate().local_identity([0; 16]),
        empty(),
        CallSide::Answerer,
        None,
        ModemGear::Wideband2400,
        0,
    )
    .unwrap();
    let old = PreambleCapabilities { version: 1, ..PreambleCapabilities::v2(ModemGear::Wideband2400) };
    s.on_rx_preamble(old.encode_bytes(), 100);
    assert_eq!(s.abort_reason(), Some(AbortReason::IncompatibleVersion));
    for i in 0..4 {
        let _ = s.next_tx(200 + i * 160);
    }
    assert!(!s.on_rx_preamble(PreambleCapabilities::v2(ModemGear::Wideband2400).encode_bytes(), 2000));
    assert_eq!(s.next_tx(2200), TxUnit::End);
    let evs = s.poll_events();
    assert!(!evs.iter().any(|e| matches!(e, SessionEvent::NeedSignature { .. } | SessionEvent::Sas(_) | SessionEvent::Path(_))));
}

#[test]
fn timeouts_stall_total_and_narrowband_preamble() {
    for (gear, step) in [(ModemGear::Wideband2400, 160u64), (ModemGear::Narrowband1200, 320)] {
        let mut p = full_pair_gear(3, 0.0, gear);
        p.step_ms = step;
        p.drop = Some(Box::new(|_, _, u| matches!(u, TxUnit::Superframe(_))));
        p.run_until(2000, |p| p.a.s.is_closed() && p.b.s.is_closed());
        eprintln!("stall {gear:?}: a {:?} b {:?} at {} s", p.a.aborted(), p.b.aborted(), p.tick * step / 1000);
        assert_eq!(p.a.aborted(), Some(AbortReason::StallTimeout));
    }
    for (gear, step) in [(ModemGear::Wideband2400, 160u64), (ModemGear::Narrowband1200, 320)] {
        let mut hits = 0;
        for seed in 1..=6u64 {
            let mut p = full_pair_gear(seed * 977, 0.85, gear);
            p.step_ms = step;
            p.lossy_preamble = false;
            p.run_until(3000, |p| p.a.s.is_closed() && p.b.s.is_closed());
            let (ra, rb, at) = (p.a.aborted(), p.b.aborted(), p.tick * step / 1000);
            eprintln!("drip {gear:?} seed {seed}: a {ra:?} b {rb:?} at {at} s");
            if ra == Some(AbortReason::HandshakeTimeout) || rb == Some(AbortReason::HandshakeTimeout) {
                let limit = if step == 160 { 90 } else { 180 };
                assert!(at >= limit && at <= limit + 2, "total limit fired at {at} s");
                hits += 1;
            }
        }
        assert!(hits >= 1, "no run ended by the total handshake limit for {gear:?}");
    }
    let mut s = SecureCallSession::new(
        SoftwareSigner::generate().local_identity([0; 16]),
        empty(),
        CallSide::Answerer,
        None,
        ModemGear::Narrowband1200,
        0,
    )
    .unwrap();
    let mut now = 0;
    while now < 21_000 {
        let _ = s.next_tx(now);
        now += 320;
    }
    assert_eq!(s.abort_reason(), Some(AbortReason::PreambleTimeout));
}
#[test]
fn remote_wipe_is_not_lost_when_the_receiver_hangs_up_at_the_same_moment() {
    let mut p = full_pair(61, 0.0);
    assert!(p.run_until(400, both_established));
    let now = p.now;
    p.a.s.chat().unwrap().send_text_message(now, 0, "secret").unwrap();
    p.run_until(40, |_| false);
    assert!(!text_of(&p.a).is_empty());
    p.a.s.end();
    p.b.s.panic_wipe();
    p.run_until(10, |p| p.a.s.is_closed() && p.b.s.is_closed());
    eprintln!(
        "a closed={} remote_wipe_seen={} vault_present={} live_secret_bytes={:?}",
        p.a.s.is_closed(),
        p.a.has(|e| matches!(e, SessionEvent::RemoteWipe)),
        p.a.s.vault().is_some(),
        p.a.s.vault().map(|v| v.total_live_secret_bytes())
    );
    assert!(p.a.has(|e| matches!(e, SessionEvent::RemoteWipe)), "peer's PANIC_WIPE was ignored while hanging up");
}

// ----- re-review (C3, C4, C5) -----

fn voice_units(p: &Pair, from: usize, a: bool) -> usize {
    p.tape[from..].iter().filter(|(_, from_a, u)| *from_a == a && *u == TxUnit::Voice).count()
}

fn opened(p: &Party) -> usize {
    p.count(|e| matches!(e, SessionEvent::VoiceWindow { open: true }))
}

#[test]
fn c3_voice_window_needs_both_users_and_opens_once_per_call() {
    let mut p = full_pair(81, 0.0);
    p.a.sas_choice = None;
    p.b.sas_choice = None;
    assert!(p.run_until(400, both_established));
    p.record = true;
    // The peer alone asks and keeps asking for 24 s (inside the 30 s request lifetime): nothing
    // opens on either side.
    p.b.s.voice_window(true).unwrap();
    p.run_until(150, |_| false);
    assert_eq!((voice_units(&p, 0, true), voice_units(&p, 0, false)), (0, 0));
    assert_eq!((opened(&p.a), opened(&p.b)), (0, 0));
    // The local user asks too: both open.
    p.a.s.voice_window(true).unwrap();
    assert!(p.run_until(20, |p| opened(&p.a) == 1 && opened(&p.b) == 1));
    p.run_until(20, |_| false);
    assert!(voice_units(&p, 0, true) > 0 && voice_units(&p, 0, false) > 0);
    // Repeated requests while open do not extend it past 60 s.
    let opened_at = p.now;
    for _ in 0..500 {
        let _ = p.b.s.voice_window(true);
        p.step();
    }
    let last_voice = p.tape.iter().filter(|(_, _, u)| *u == TxUnit::Voice).map(|(t, _, _)| *t).max().unwrap();
    eprintln!("voice window ran {} ms after both sides opened", last_voice * 160 - opened_at);
    assert!(last_voice * 160 <= opened_at + 61_000);
    assert!(p.a.has(|e| matches!(e, SessionEvent::VoiceWindow { open: false })));
    assert!(p.b.has(|e| matches!(e, SessionEvent::VoiceWindow { open: false })));
    // After the one window: asking again is refused and nothing reopens.
    let mark = p.tape.len();
    assert_eq!(p.a.s.voice_window(true), Err(aegiscall_chat::ChatError::InvalidState));
    assert_eq!(p.b.s.voice_window(true), Err(aegiscall_chat::ChatError::InvalidState));
    p.run_until(450, |_| false);
    assert_eq!((voice_units(&p, mark, true), voice_units(&p, mark, false)), (0, 0));
    assert_eq!((opened(&p.a), opened(&p.b)), (1, 1));
    // The state machine is not stuck: chat still works.
    assert!(p.a.aborted().is_none() && p.b.aborted().is_none());
    let now = p.now;
    let id = p.a.s.chat().unwrap().send_text_message(now, 0, "after voice").unwrap();
    assert!(p.run_until(200, |p| p.a.has(|e| matches!(e, SessionEvent::MessageDelivered(m) if *m == id))));
}

#[test]
fn c3_voice_window_refused_without_a_pending_sas() {
    // Resume path: no SAS at all.
    let mut p = resume_pair(82, 0.0, [0x61; 32]);
    assert!(p.run_until(200, both_established));
    assert_eq!(p.a.s.voice_window(true), Err(aegiscall_chat::ChatError::InvalidState));
    assert_eq!(p.b.s.voice_window(true), Err(aegiscall_chat::ChatError::InvalidState));
    // Full path after both confirmed the SAS.
    let mut p = full_pair(83, 0.0);
    assert!(p.run_until(400, both_established));
    assert!(p.run_until(100, |p| p.a.has(|e| matches!(e, SessionEvent::SasConfirmed)) && p.b.has(|e| matches!(e, SessionEvent::SasConfirmed))));
    assert_eq!(p.a.s.voice_window(true), Err(aegiscall_chat::ChatError::InvalidState));
    p.record = true;
    p.run_until(100, |_| false);
    assert_eq!(voice_units(&p, 0, true) + voice_units(&p, 0, false), 0);
}

#[test]
fn c3_withdrawn_request_and_stale_request_observation() {
    // Withdrawn: A asks, withdraws, then B asks. A must not open.
    let mut p = full_pair(84, 0.0);
    p.a.sas_choice = None;
    p.b.sas_choice = None;
    assert!(p.run_until(400, both_established));
    p.record = true;
    p.a.s.voice_window(true).unwrap();
    p.run_until(20, |_| false);
    p.a.s.voice_window(false).unwrap();
    p.run_until(250, |_| false);
    p.b.s.voice_window(true).unwrap();
    p.run_until(60, |_| false);
    assert_eq!(opened(&p.a), 0, "A opened after withdrawing its request");
    assert_eq!(voice_units(&p, 0, true), 0);
    // Stale: A asks once and never withdraws; B agrees 5 minutes later.
    let mut p = full_pair(85, 0.0);
    p.a.sas_choice = None;
    p.b.sas_choice = None;
    assert!(p.run_until(400, both_established));
    p.a.s.voice_window(true).unwrap();
    p.run_until(1875, |_| false);
    // A's unmatched request lapsed after 30 s and was reported as "not opened".
    assert_eq!(p.a.count(|e| matches!(e, SessionEvent::VoiceWindow { open: false })), 1);
    p.record = true;
    p.b.s.voice_window(true).unwrap();
    p.run_until(60, |_| false);
    assert_eq!(opened(&p.a), 0, "A opened on an agreement that came after its request expired");
    assert_eq!(opened(&p.b), 0, "B opened alone");
    assert_eq!(voice_units(&p, 0, true) + voice_units(&p, 0, false), 0);
    assert!(p.a.aborted().is_none() && p.b.aborted().is_none());
    // The expiry did not spend the call's one window: A asks again while B's request is fresh.
    p.a.s.voice_window(true).unwrap();
    assert!(p.run_until(30, |p| opened(&p.a) == 1 && opened(&p.b) == 1));
    // B's own request, left unmatched, lapses the same way.
    let mut p = full_pair(86, 0.0);
    p.a.sas_choice = None;
    p.b.sas_choice = None;
    assert!(p.run_until(400, both_established));
    p.b.s.voice_window(true).unwrap();
    p.run_until(200, |_| false);
    assert_eq!(p.b.count(|e| matches!(e, SessionEvent::VoiceWindow { open: false })), 1);
    assert_eq!(opened(&p.a) + opened(&p.b), 0);
}

#[test]
fn c4_every_way_out_drops_engine_keys_and_plaintext() {
    for way in 0..6 {
        let mut p = full_pair(90 + way, 0.0);
        if way == 3 {
            p.a.sas_choice = None;
        }
        assert!(p.run_until(400, both_established));
        let now = p.now;
        p.a.s.chat().unwrap().send_text_message(now, 0, "plaintext").unwrap();
        p.run_until(40, |_| false);
        assert!(!text_of(&p.a).is_empty() && !text_of(&p.b).is_empty());
        match way {
            0 => {
                p.a.s.end();
                assert_eq!(p.a.s.vault().map(|v| v.total_live_secret_bytes()), Some(0), "plaintext must go at once");
            }
            1 => p.b.s.end(),
            2 => p.a.s.abort(AbortReason::BearerViolation),
            3 => p.a.s.sas_decision(false).unwrap(),
            4 => p.a.s.panic_wipe(),
            _ => p.b.s.panic_wipe(),
        }
        assert!(p.run_until(20, |p| p.a.s.is_closed() && p.b.s.is_closed()), "way {way}");
        for party in [&mut p.a, &mut p.b] {
            assert!(party.s.vault().is_none() && party.s.tx_epoch().is_none(), "way {way}: engine kept");
            assert!(party.s.chat().is_err());
            assert!(!party.s.poll_events().iter().any(|e| matches!(e, SessionEvent::VaultDirty { .. })));
        }
    }
}

#[test]
fn c5_key_changed_side_before_sas_send_and_receive() {
    let mut p = full_pair(21, 0.0);
    let stale = SoftwareSigner::generate().pub33();
    p.a = Party::new(SoftwareSigner::generate(), empty(), dialing(B_AT_A), Some(stale), ModemGear::Wideband2400);
    p.a.sas_choice = None;
    p.b.sas_choice = None;
    assert!(p.run_until(400, both_established));
    let now = p.now;
    assert_eq!(p.a.s.chat().unwrap().send_text_message(now, 0, "x"), Err(aegiscall_chat::ChatError::SendLocked));
    let sent = p.b.s.chat().unwrap().send_text_message(now, 0, "from unverified peer");
    p.run_until(60, |_| false);
    // While A is locked nothing from the peer is reassembled, stored, acknowledged or reported.
    let id = sent.unwrap();
    assert!(text_of(&p.a).is_empty(), "A stored a message from a peer whose changed key is unverified");
    assert_eq!(p.a.s.chat().unwrap().incoming_len(), 0);
    assert!(!p.a.has(|e| matches!(e, SessionEvent::MessageReceived(_))));
    assert!(!p.b.has(|e| matches!(e, SessionEvent::MessageDelivered(_))));
    // After both sides confirm the SAS the lock lifts and reception resumes.
    p.a.s.sas_decision(true).unwrap();
    p.b.s.sas_decision(true).unwrap();
    assert!(p.run_until(200, |p| p.b.has(|e| matches!(e, SessionEvent::MessageDelivered(m) if *m == id))));
    assert!(text_of(&p.a).iter().any(|t| t == "from unverified peer"));
    assert!(p.a.has(|e| matches!(e, SessionEvent::MessageReceived(m) if *m == id)));
    let now = p.now;
    let id2 = p.a.s.chat().unwrap().send_text_message(now, 0, "verified reply").unwrap();
    assert!(p.run_until(100, |p| p.a.has(|e| matches!(e, SessionEvent::MessageDelivered(m) if *m == id2))));
}
