//! Call sessions end to end through the Bridge (no JVM).

use super::*;
use aegiscall_chat::AbortReason;

const NUMBER: &str = "+447700900123";
const QUICK_SAFE: i32 = crate::bridge::QUICK_SAFE_ARRIVAL;

fn confirmed(a: &Party, b: &Party) -> bool {
    a.has(EV_SAS_CONFIRMED) && b.has(EV_SAS_CONFIRMED)
}

fn hang_up(a: &Party, b: &Party) {
    assert_eq!(a.b.session_close(a.s, false), OK);
    assert_eq!(b.b.session_close(b.s, false), OK);
}

/// A dials the number, both confirm the SAS and A saves B as "Bob" with that number.
fn first_call(a: &mut Party, b: &mut Party, now: &mut i64) -> i32 {
    a.call(true, 0, Some(NUMBER), *now);
    b.call(false, 0, None, *now);
    assert!(run_until(a, b, now, 4000, confirmed));
    let bob = a.save(0, "Bob", Some(NUMBER));
    assert!(bob > 0);
    a.react();
    hang_up(a, b);
    bob
}

/// A stranger (new key) calls A showing Bob's number; A's user has not compared the SAS yet.
fn stranger_calls_as_bob(a: &mut Party, x: &mut Party, now: &mut i64) {
    a.auto_sas = false;
    x.call(true, 0, None, *now);
    a.call(false, 0, Some(NUMBER), *now);
    assert!(run_until(a, x, now, 4000, |a, x| a.has(EV_SAS) && a.has(EV_KEY_CHANGED) && x.has(EV_ESTABLISHED)));
}

#[test]
fn full_call_then_resume_call_upgrades_the_secret() {
    let mut a = Party::new();
    let mut b = Party::new();
    let mut now = 0i64;

    // Call 1: A dials a bare number; full handshake, both compare the SAS and save each other.
    a.call(true, 0, Some(NUMBER), now);
    b.call(false, 0, None, now);
    assert_eq!(a.save(0, "Bob", None), BAD_STATE);
    assert!(run_until(&mut a, &mut b, &mut now, 4000, confirmed));
    let sas = a.find(EV_SAS).unwrap().clone();
    assert_eq!(sas.len(), 5);
    assert_eq!(Some(&sas), b.find(EV_SAS));
    let est_a = a.find(EV_ESTABLISHED).unwrap().clone();
    let est_b = b.find(EV_ESTABLISHED).unwrap().clone();
    assert_eq!((est_a.len(), est_a[1], est_b[1]), (49, 0, 0));
    assert_ne!(est_a[0], est_b[0]);
    assert_eq!(&est_a[16..], &b.d.pub33()[..]);
    assert_eq!(&est_b[16..], &a.d.pub33()[..]);
    assert_eq!(be32(&a.find(EV_PATH).unwrap()[2..]), 0);

    let id_b = a.save(0, "Bob", Some(NUMBER));
    let id_a = b.save(0, "Alice", None);
    assert!(id_b > 0 && id_a > 0);
    assert_eq!(a.save(0, "Bob", None), BAD_STATE);
    let (cb, ca) = (id_b as u32, id_a as u32);
    // rs_cur present, rs_new gone (k=1 promoted on both sides), attestation stored.
    assert!(run_until(&mut a, &mut b, &mut now, 4000, |a, b| a.flags(cb) & 0x1c == 0x14 && b.flags(ca) & 0x1c == 0x14));
    for p in [&a, &b] {
        let att = p.find(EV_ATTESTATION).unwrap();
        assert_eq!((att[0], att[1], be32(&att[2..])), (0, 0, 202409));
    }
    assert_eq!(contacts(&a.b, a.app)[0].3, "Bob");
    let rs1 = a.rs_cur(cb).unwrap();
    assert_eq!(b.rs_cur(ca), Some(rs1));

    let text = "Café at B, 11pm tonight!".as_bytes();
    assert!(a.b.session_send_text(a.s, text, 0, now) >= 0);
    assert_eq!(a.b.session_send_text(a.s, &vec![b'a'; 5000], 0, now), BAD_ARG);
    assert!(run_until(&mut a, &mut b, &mut now, 600, |_, b| b
        .log
        .iter()
        .any(|(t, v)| *t == EV_MESSAGE_RECEIVED && &v[2..] == text)));
    assert!(a.b.session_send_quick(a.s, QUICK_SAFE, 0, 0, now) >= 0);
    assert_eq!(a.b.session_send_quick(a.s, 9, 0, 0, now), BAD_ARG);

    // Hang up: A sends SESSION_END, B sees ENDED(by peer).
    assert_eq!(a.b.session_close(a.s, true), OK);
    assert!(run_until(&mut a, &mut b, &mut now, 200, |_, b| b.find(EV_ENDED).is_some_and(|v| v[0] == 1)));
    hang_up(&a, &b);

    // Call 2: A dials the saved contact; both hold the same rs_cur, so the resume path runs and
    // the secret is replaced by a new one on both sides.
    a.call(true, id_b, None, now);
    b.call(false, 0, Some(NUMBER), now);
    let resumed = run_until(&mut a, &mut b, &mut now, 2000, |a, b| {
        a.has(EV_ESTABLISHED)
            && b.has(EV_ESTABLISHED)
            && a.rs_cur(cb).is_some_and(|s| s != rs1)
            && b.rs_cur(ca).is_some_and(|s| s != rs1)
            && a.flags(cb) & 0x08 == 0
            && b.flags(ca) & 0x08 == 0
    });
    assert!(resumed, "flags {:#x} {:#x}", a.flags(cb), b.flags(ca));
    for (p, c) in [(&a, cb), (&b, ca)] {
        let path = p.find(EV_PATH).unwrap();
        assert_eq!((path[0], be32(&path[2..])), (1, c));
        let est = p.find(EV_ESTABLISHED).unwrap();
        assert_eq!((est[1], est[7], be32(&est[12..])), (1, 2, c));
        // No SAS and no new chain on the resume path; the stored verdict stands.
        assert!(!p.has(EV_SAS) && !p.has(EV_ATTESTATION));
        assert_eq!(p.flags(c) & 0x10, 0x10);
    }
    assert_eq!(a.rs_cur(cb), b.rs_cur(ca));
    hang_up(&a, &b);
}

#[test]
fn paired_contacts_mix_the_shared_psk() {
    let mut a = Party::new();
    let mut b = Party::new();
    let code_a = a.b.pairing_code(a.app).unwrap();
    let code_b = b.b.pairing_code(b.app).unwrap();
    assert!(code_a.starts_with("AEGIS2-"));
    assert_eq!(a.import(0, &code_a, Some("me")), BAD_ARG);
    assert_eq!(a.import(0, "AEGIS2-AAAAA", Some("x")), BAD_ARG);
    let (id_b, new_b) = imported(a.import(0, &code_b, Some("Bob")));
    let (id_a, new_a) = imported(b.import(0, &code_a, Some("Alice")));
    assert!(new_b && new_a);
    a.persist();
    b.persist();
    assert_eq!(a.flags(id_b as u32) & 0x01, 0x01);

    let mut now = 0i64;
    a.call(true, id_b, None, now);
    b.call(false, 0, None, now);
    assert!(run_until(&mut a, &mut b, &mut now, 4000, |a, b| a.has(EV_ESTABLISHED) && b.has(EV_ESTABLISHED)));
    assert_eq!(be32(&a.find(EV_ESTABLISHED).unwrap()[8..]), id_b as u32);
    assert_eq!(be32(&b.find(EV_ESTABLISHED).unwrap()[8..]), id_a as u32);
    assert!(a.find(EV_ABORTED).is_none() && b.find(EV_ABORTED).is_none());
}

#[test]
fn key_change_updates_only_the_contact_the_user_names() {
    let mut a = Party::new();
    let mut b = Party::new();
    let mut now = 0i64;
    let bob = first_call(&mut a, &mut b, &mut now);
    a.b.pairing_code(a.app).unwrap();
    let (carol_code, _) = synthetic_code();
    let (carol, _) = imported(a.import(0, &carol_code, Some("Carol")));
    assert!(carol != bob);
    a.persist();

    // Bob's number shows up with a new key.
    let mut b2 = Party::new();
    stranger_calls_as_bob(&mut a, &mut b2, &mut now);
    let kc = a.find(EV_KEY_CHANGED).unwrap().clone();
    assert_eq!((&kc[..33], &kc[33..]), (&b.d.pub33()[..], &b2.d.pub33()[..]));
    let before = a.b.contact_list(a.app).unwrap().to_vec();
    // Before the SAS is confirmed: no save, no sending.
    assert_eq!(a.save(bob, "Bob2", None), BAD_STATE);
    assert_eq!(a.save(0, "New", None), BAD_STATE);
    assert_eq!(a.b.session_send_text(a.s, b"hi", 0, now), BAD_STATE);
    assert_eq!(a.b.session_sas(a.s, true), OK);
    assert!(run_until(&mut a, &mut b2, &mut now, 600, confirmed));

    // Refused, vault untouched: another contact, the number alone, bad arguments.
    assert_eq!(a.save(carol, "Bob2", None), BAD_STATE);
    assert_eq!(a.save(0, "Bob2", Some(NUMBER)), BAD_STATE);
    assert_eq!(a.save(999, "Bob2", None), BAD_ARG);
    assert_eq!(a.save(-1, "Bob2", None), BAD_ARG);
    assert_eq!(a.save(bob, &"x".repeat(65), None), BAD_ARG);
    assert_eq!(a.save(bob, "Bob2", Some(NUMBER)), BAD_ARG);
    assert_eq!(a.save(0, "Bob2", Some("12345")), BAD_ARG);
    assert_eq!(a.save(0, "Bob2", Some("+4477009001234567890")), BAD_ARG);
    assert_eq!(a.b.contact_list(a.app).unwrap().to_vec(), before);

    // Allowed: the user names Bob, who holds exactly the old key of this call.
    assert_eq!(a.save(bob, "Bob2", None), bob);
    let c = contacts(&a.b, a.app).into_iter().find(|c| c.0 == bob as u32).unwrap();
    assert_eq!((c.2, c.3.as_str(), c.1 & 0x23), (b2.d.pub33(), "Bob2", 0x22));
    assert!(a.b.session_send_text(a.s, b"hi", 0, now) >= 0);
    a.react();
    hang_up(&a, &b2);

    // A dials Bob and someone else answers. Saving without naming Bob adds a new contact.
    let mut m = Party::new();
    a.auto_sas = true;
    a.call(true, bob, None, now);
    m.call(false, 0, None, now);
    assert!(run_until(&mut a, &mut m, &mut now, 4000, |a, m| confirmed(a, m) && a.has(EV_KEY_CHANGED)));
    let mallory = a.save(0, "Mallory", None);
    assert!(mallory > 0 && mallory != bob && mallory != carol);
    let list = contacts(&a.b, a.app);
    assert_eq!(list.len(), 3);
    assert_eq!(list.iter().find(|c| c.0 == bob as u32).unwrap().2, b2.d.pub33());
    assert_eq!(list.iter().find(|c| c.0 == mallory as u32).unwrap().2, m.d.pub33());
}

#[test]
fn pairing_import_checks_the_key_and_psk_contacts_refuse_a_key_change() {
    let mut a = Party::new();
    let mut b = Party::new();
    let mut now = 0i64;
    let bob = first_call(&mut a, &mut b, &mut now);
    a.b.pairing_code(a.app).unwrap();
    let code_b = b.b.pairing_code(b.app).unwrap();
    let (carol_code, _) = synthetic_code();
    let (new_code, _) = synthetic_code();
    let (carol, _) = imported(a.import(0, &carol_code, Some("Carol")));
    a.persist();

    // A code may not be pushed onto a contact that holds another key.
    let before = a.b.contact_list(a.app).unwrap().to_vec();
    assert_eq!(a.import(bob, &carol_code, None), BAD_STATE);
    assert_eq!(a.import(bob, &new_code, Some("Bob")), BAD_STATE);
    assert_eq!(a.import(carol, &code_b, None), BAD_STATE);
    assert_eq!(a.import(999, &code_b, None), BAD_ARG);
    assert_eq!(a.import(0, &new_code, None), BAD_ARG);
    assert_eq!(a.import(0, &new_code, Some(&"x".repeat(65))), BAD_ARG);
    assert_eq!(a.import(bob, &code_b, Some(&"x".repeat(65))), BAD_ARG);
    assert_eq!(a.import(0, &"A".repeat(300), Some("x")), BAD_ARG);
    assert_eq!(a.b.contact_rename(a.app, bob, &[b'x'; 65]), BAD_ARG);
    assert_eq!(a.b.contact_list(a.app).unwrap().to_vec(), before);

    // Same key: the PSK is attached, by id or by key; importing the same code again keeps it.
    assert_eq!(imported(a.import(bob, &code_b, None)), (bob, true));
    assert_eq!(imported(a.import(0, &code_b, Some("Bobby"))), (bob, false));
    let c = contacts(&a.b, a.app).into_iter().find(|c| c.0 == bob as u32).unwrap();
    assert_eq!((c.2, c.3.as_str(), c.1 & 0x21), (b.d.pub33(), "Bobby", 0x21));
    a.persist();

    // Bob's number calls with a new key: a PSK contact only changes key through a new pairing.
    let mut b2 = Party::new();
    stranger_calls_as_bob(&mut a, &mut b2, &mut now);
    assert_eq!(a.b.session_sas(a.s, true), OK);
    assert!(run_until(&mut a, &mut b2, &mut now, 600, confirmed));
    let before = a.b.contact_list(a.app).unwrap().to_vec();
    assert_eq!(a.save(bob, "Bob2", None), BAD_STATE);
    assert_eq!(a.b.contact_list(a.app).unwrap().to_vec(), before);
}

#[test]
fn attestation_chain_must_match_the_signed_evidence_id() {
    let mut a = Party::new();
    let mut b = Party::new();
    // B hands out another valid chain for its key than the one whose id it signs.
    let other = chain_for(&b.d.sk, 98);
    assert_ne!(other, b.d.chain_tlv);
    b.b.swap_chain(b.app, &other).unwrap();
    let mut now = 0i64;
    a.call(true, 0, None, now);
    b.call(false, 0, None, now);
    assert!(run_until(&mut a, &mut b, &mut now, 4000, |a, b| confirmed(a, b) && a.has(EV_ATTESTATION)));
    let att = a.find(EV_ATTESTATION).unwrap().clone();
    assert_eq!((att[0] as i8 as i32, att[6]), (CRYPTO, 0));
    let id = a.save(0, "Bob", None);
    assert!(id > 0);
    assert_eq!(a.flags(id as u32) & 0x10, 0);
}

#[test]
fn pcm_path_syncs_on_the_preamble_and_carries_handshake_frames() {
    let mut a = Party::new();
    let mut b = Party::new();
    a.call(true, 0, None, 0);
    b.call(false, 0, None, 0);
    let progress = |p: &Party| p.log.iter().filter(|(t, _)| *t == EV_HS_PROGRESS).map(|(_, v)| v[0]).max().unwrap_or(0);
    let mut now = 0i64;
    for _ in 0..400 {
        if progress(&a) >= 10 && progress(&b) >= 10 {
            break;
        }
        now += 160;
        let pa = a.b.session_tx_pcm(a.s, now).unwrap().expect("pcm");
        let pb = b.b.session_tx_pcm(b.s, now).unwrap().expect("pcm");
        assert!(!pa.is_empty() && !pb.is_empty());
        assert_eq!(b.b.session_rx_pcm(b.s, &pa, now), OK);
        assert_eq!(a.b.session_rx_pcm(a.s, &pb, now), OK);
        a.react();
        b.react();
    }
    assert!(progress(&a) >= 10 && progress(&b) >= 10, "progress {} / {}", progress(&a), progress(&b));
    assert_eq!(a.b.session_rx_pcm(a.s, &vec![0i16; 40_000], now), BAD_ARG);
    assert_eq!(a.b.session_close(a.s, false), OK);
    assert!(a.b.session_tx_pcm(a.s, now).is_err());
}

#[test]
fn persistent_pairing_seed_and_phone_update_work_end_to_end() {
    let mut a = Party::new();
    let mut b = Party::new();

    // Both parties persist a pairing seed; restarting (reopening on a new Bridge) still produces the same code and PSK.
    let seed_a = [0x11u8; 32];
    let seed_b = [0x22u8; 32];
    assert_eq!(a.b.set_pairing_seed(a.app, &seed_a[..31]), BAD_ARG);
    assert_eq!(a.b.set_pairing_seed(a.app, &seed_a), OK);
    assert_eq!(b.b.set_pairing_seed(b.app, &seed_b), OK);
    let code_a = a.b.pairing_code(a.app).unwrap().to_string();
    let code_b = b.b.pairing_code(b.app).unwrap().to_string();

    // B imports A's code while A restarts and reloads seed_a before importing B's code.
    let (id_a_on_b, _) = imported(b.import(0, &code_a, Some("Alice")));
    assert_eq!(b.b.contact_set_phone(b.app, id_a_on_b, Some(b"+447700900101")), OK);
    b.persist();
    assert_ne!(b.flags(id_a_on_b as u32) & 0x21, 0);

    let b_restarted = Bridge::new();
    let app_a2 = a.d.open(&b_restarted);
    assert_eq!(a.d.unlock(&b_restarted, app_a2, PIN), 1);
    a.d.rotate(&b_restarted, app_a2);
    assert_eq!(b_restarted.set_pairing_seed(app_a2, &seed_a), OK);
    assert_eq!(b_restarted.pairing_code(app_a2).unwrap().as_str(), code_a);
    let (id_b_on_a, _) = imported(b_restarted.import_pairing(app_a2, 0, code_b.as_bytes(), Some(b"Bob")));
    assert_eq!(b_restarted.contact_set_phone(app_a2, id_b_on_a, Some(b"+447700900202")), OK);
    assert_ne!(b_restarted.contact_list(app_a2).unwrap().len(), 0);
    assert_eq!(b_restarted.contact_set_phone(app_a2, id_b_on_a, None), OK);
}

/// A dials contact without a number. Some((path, PSK contact on A, PSK contact on B)) when both
/// sides establish; None when the call ends on the PSK-required check (any other end fails the test).
fn paired_call(a: &mut Party, b: &mut Party, contact: i32, now: &mut i64) -> Option<(u8, u32, u32)> {
    a.call(true, contact, None, *now);
    b.call(false, 0, None, *now);
    let est = |p: &Party| p.has(EV_ESTABLISHED);
    let gone = |p: &Party| p.has(EV_ABORTED);
    assert!(run_until(a, b, now, 4000, |a, b| (est(a) && est(b)) || gone(a) || gone(b)));
    let out = if est(a) && est(b) && !gone(a) && !gone(b) {
        let ea = a.find(EV_ESTABLISHED).unwrap();
        let eb = b.find(EV_ESTABLISHED).unwrap();
        Some((ea[1], be32(&ea[8..]), be32(&eb[8..])))
    } else {
        let psk_abort = |p: &Party| p.find(EV_ABORTED).is_some_and(|v| v[0] == AbortReason::HsPskRequired.code());
        assert!(psk_abort(a) || psk_abort(b), "not a PSK abort: {:?} / {:?}", a.find(EV_ABORTED), b.find(EV_ABORTED));
        None
    };
    let _ = a.b.session_close(a.s, false);
    let _ = b.b.session_close(b.s, false);
    out
}

#[test]
fn pairing_code_and_import_need_the_persisted_seed() {
    let b = Bridge::new();
    let mut d = Device::new();
    let app = d.setup(&b);
    let (code, _) = synthetic_code();
    assert_eq!(b.pairing_code(app).err(), Some(BAD_STATE));
    assert_eq!(b.import_pairing(app, 0, code.as_bytes(), Some(b"Carol")), BAD_STATE);
    assert!(contacts(&b, app).is_empty());
    assert_eq!(b.set_pairing_seed(app, &[0x33; 32]), OK);
    assert_eq!(b.pairing_code(app).unwrap().as_str(), b.pairing_code(app).unwrap().as_str());
    assert!(imported(b.import_pairing(app, 0, code.as_bytes(), Some(b"Carol"))).1);
}

#[test]
fn either_import_order_and_either_caller_mix_the_pairing_psk() {
    let mut a = Party::new();
    let mut b = Party::new();
    let mut now = 0i64;
    let code_a = a.b.pairing_code(a.app).unwrap().to_string();
    let code_b = b.b.pairing_code(b.app).unwrap().to_string();
    // B imports first and B dials (the opposite of paired_contacts_mix_the_shared_psk).
    let (id_a, _) = imported(b.import(0, &code_a, Some("Alice")));
    let (id_b, _) = imported(a.import(0, &code_b, Some("Bob")));
    a.persist();
    b.persist();
    assert_eq!(paired_call(&mut b, &mut a, id_a, &mut now), Some((0, id_a as u32, id_b as u32)));
}

#[test]
fn a_new_code_keeps_the_stored_pairings_working() {
    let mut a = Party::new();
    let mut b = Party::new();
    let mut now = 0i64;
    let code_b = b.b.pairing_code(b.app).unwrap().to_string();
    let code_a_old = a.b.pairing_code(a.app).unwrap().to_string();
    let (id_b, _) = imported(a.import(0, &code_b, Some("Bob")));
    let (id_a, _) = imported(b.import(0, &code_a_old, Some("Alice")));
    a.persist();
    b.persist();
    assert_eq!(a.b.set_pairing_seed(a.app, &[0x44; 32]), OK);
    assert_ne!(a.b.pairing_code(a.app).unwrap().to_string(), code_a_old);
    assert_eq!(paired_call(&mut a, &mut b, id_b, &mut now), Some((0, id_b as u32, id_a as u32)));
}

#[test]
fn after_a_new_code_both_sides_must_import_again() {
    let mut a = Party::new();
    let mut b = Party::new();
    let mut now = 0i64;
    let code_b = b.b.pairing_code(b.app).unwrap().to_string();
    let code_a_old = a.b.pairing_code(a.app).unwrap().to_string();
    let (id_b, _) = imported(a.import(0, &code_b, Some("Bob")));
    let (id_a, _) = imported(b.import(0, &code_a_old, Some("Alice")));
    a.persist();
    b.persist();
    assert_eq!(a.b.set_pairing_seed(a.app, &[0x44; 32]), OK);
    let code_a_new = a.b.pairing_code(a.app).unwrap().to_string();

    // Only B imports the new code: the PSKs differ and full handshakes stop on the PSK check either way.
    assert_eq!(imported(b.import(0, &code_a_new, None)), (id_a, true));
    b.persist();
    assert_eq!(paired_call(&mut a, &mut b, id_b, &mut now), None);
    assert_eq!(paired_call(&mut b, &mut a, id_a, &mut now), None);

    // A imports B's code again under its new key: both hold the same PSK again.
    assert_eq!(imported(a.import(id_b, &code_b, None)), (id_b, true));
    a.persist();
    assert_eq!(paired_call(&mut a, &mut b, id_b, &mut now), Some((0, id_b as u32, id_a as u32)));
    // Once both agree, importing the same codes again changes nothing.
    assert_eq!(imported(a.import(0, &code_b, None)), (id_b, false));
    assert_eq!(imported(b.import(0, &code_a_new, None)), (id_a, false));
}

/// A and B after one confirmed call (SAS verified, number saved, resume secret staged) and a pairing.
fn verified_and_paired(a: &mut Party, b: &mut Party, now: &mut i64) -> (i32, String) {
    let bob = first_call(a, b, now);
    let code_b = b.b.pairing_code(b.app).unwrap().to_string();
    assert_eq!(imported(a.import(bob, &code_b, None)), (bob, true));
    a.persist();
    (bob, code_b)
}

fn entry(p: &Party, id: i32) -> (u32, u8, [u8; 33], String) {
    contacts(&p.b, p.app).into_iter().find(|c| c.0 == id as u32).unwrap()
}

#[test]
fn importing_the_same_pairing_again_changes_nothing() {
    let mut a = Party::new();
    let mut b = Party::new();
    let mut now = 0i64;
    let (bob, code_b) = verified_and_paired(&mut a, &mut b, &mut now);
    let list = a.b.contact_list(a.app).unwrap().to_vec();
    let rs = a.b.resume_secrets(a.app).unwrap();
    assert_ne!(entry(&a, bob).1 & 0x02, 0);
    assert_eq!(a.b.preview_pairing(a.app, code_b.as_bytes()), bob);
    assert_eq!(imported(a.import(0, &code_b, None)), (bob, false));
    assert_eq!(imported(a.import(bob, &code_b, None)), (bob, false));
    assert_eq!(a.b.contact_list(a.app).unwrap().to_vec(), list);
    assert_eq!(a.b.resume_secrets(a.app).unwrap(), rs);
    // Nothing changed, so no rotation is needed before the file can be written.
    assert!(a.b.vault_export(a.app).is_ok());
}

#[test]
fn a_card_with_a_contacts_key_and_another_pairing_key_is_only_a_replacement() {
    let mut a = Party::new();
    let mut b = Party::new();
    let mut now = 0i64;
    let (bob, code_b) = verified_and_paired(&mut a, &mut b, &mut now);
    let before = entry(&a, bob);
    let rs = a.b.resume_secrets(a.app).unwrap();
    assert!(!rs.is_empty());
    // Bob's identity key, from any of his cards, with the attacker's pairing key.
    let eve_x = aegiscall_crypto::PairingSecret::from_seed(&[0xEE; 32]).public();
    let fake = aegiscall_crypto::PairingCodeV2::new(b.d.pub33(), eve_x).unwrap().to_code().as_str().to_owned();

    // Unconfirmed: the preview names Bob as the contact whose pairing would change, and changes nothing.
    let list = a.b.contact_list(a.app).unwrap().to_vec();
    assert_eq!(a.b.preview_pairing(a.app, fake.as_bytes()), bob | PAIRING_PSK_CHANGED);
    assert_eq!(a.b.contact_list(a.app).unwrap().to_vec(), list);
    assert_eq!(a.b.preview_pairing(a.app, code_b.as_bytes()), bob);
    assert!(a.b.vault_export(a.app).is_ok());

    // Confirmed: only the PSK changes; name, key, SAS verification, number and resume stay.
    assert_eq!(imported(a.import(0, &fake, None)), (bob, true));
    let after = entry(&a, bob);
    assert_eq!((after.1, &after.2, &after.3), (before.1, &before.2, &before.3));
    assert_eq!(after.1 & 0x22, 0x22);
    assert_eq!(a.b.resume_secrets(a.app).unwrap(), rs);
    assert_eq!(a.b.preview_pairing(a.app, code_b.as_bytes()), bob | PAIRING_PSK_CHANGED);
    // A name typed on the confirmation screen is the only rename.
    assert_eq!(imported(a.import(0, &code_b, Some("Robert"))), (bob, true));
    assert_eq!(entry(&a, bob).3, "Robert");
}

#[test]
fn an_import_the_app_could_not_save_is_undone() {
    let mut a = Party::new();
    let mut b = Party::new();
    let mut now = 0i64;
    let (bob, code_b) = verified_and_paired(&mut a, &mut b, &mut now);
    let list = a.b.contact_list(a.app).unwrap().to_vec();
    let rs = a.b.resume_secrets(a.app).unwrap();

    let eve_x = aegiscall_crypto::PairingSecret::from_seed(&[0xEF; 32]).public();
    let fake = aegiscall_crypto::PairingCodeV2::new(b.d.pub33(), eve_x).unwrap().to_code().as_str().to_owned();
    assert_eq!(imported(a.import(0, &fake, Some("Eve"))), (bob, true));
    assert_eq!(a.b.contact_set_phone(a.app, bob, Some(b"+447700900999")), OK);
    assert_eq!(a.b.import_revert(a.app, bob + 1), BAD_STATE);
    assert_eq!(a.b.import_revert(a.app, bob), OK);
    assert_eq!(a.b.contact_list(a.app).unwrap().to_vec(), list);
    assert_eq!(a.b.resume_secrets(a.app).unwrap(), rs);
    assert_eq!(a.b.preview_pairing(a.app, code_b.as_bytes()), bob);
    assert_eq!(a.b.import_revert(a.app, bob), BAD_STATE);

    // A new contact the app could not save is removed again.
    let (carol_code, _) = synthetic_code();
    let (carol, _) = imported(a.import(0, &carol_code, Some("Carol")));
    assert_eq!(a.b.import_revert(a.app, carol), OK);
    assert_eq!(a.b.contact_list(a.app).unwrap().to_vec(), list);
    // The undone state is what the next written file holds.
    a.persist();
    assert_eq!(a.b.preview_pairing(a.app, code_b.as_bytes()), bob);
}

#[test]
fn message_progress_events_carry_msg_id_acked_and_total_as_big_endian_u16() {
    assert_eq!(EV_MESSAGE_PROGRESS, 22);
    let mut rec = Vec::new();
    assert!(encode_tlv(&mut rec, EV_MESSAGE_PROGRESS, &[0x01, 0x02, 0x00, 0x05, 0x00, 0x1e]));
    assert_eq!(decode_tlv(&rec).unwrap(), vec![(22u8, &[0x01u8, 0x02, 0x00, 0x05, 0x00, 0x1e][..])]);

    let mut a = Party::new();
    let mut b = Party::new();
    let mut now = 0i64;
    a.call(true, 0, Some(NUMBER), now);
    b.call(false, 0, None, now);
    assert!(run_until(&mut a, &mut b, &mut now, 4000, |a, b| {
        confirmed(a, b) && a.has(EV_ESTABLISHED) && b.has(EV_ESTABLISHED)
    }));

    let text = "Progress check: ".repeat(16);
    let id = a.b.session_send_text(a.s, text.as_bytes(), 0, now);
    assert!(id >= 0);
    assert!(run_until(&mut a, &mut b, &mut now, 600, |a, _| a.has(EV_MESSAGE_DELIVERED)));

    let mut progress = Vec::new();
    let mut delivered_at = None;
    for (i, (t, v)) in a.log.iter().enumerate() {
        if *t == EV_MESSAGE_PROGRESS {
            assert_eq!(v.len(), 6);
            let id16 = u16::from_be_bytes([v[0], v[1]]);
            assert_eq!(i32::from(id16), id);
            progress.push((u16::from_be_bytes([v[2], v[3]]), u16::from_be_bytes([v[4], v[5]])));
        } else if *t == EV_MESSAGE_DELIVERED {
            delivered_at = Some(i);
        }
    }
    let delivered_at = delivered_at.unwrap();
    assert!(progress.len() >= 2, "progress events: {progress:?}");
    assert!(a.log.iter().skip(delivered_at).all(|(t, _)| *t != EV_MESSAGE_PROGRESS));
    let total = progress[0].1;
    assert!(progress.iter().all(|(acked, t)| *t == total && *acked > 0 && *acked < total));
    assert!(progress.windows(2).all(|w| w[0].0 < w[1].0), "progress events: {progress:?}");
}
