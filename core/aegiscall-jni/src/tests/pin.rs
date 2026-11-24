//! PIN vault through the Bridge: setup, two-phase unlock, rotation, duress, dead vault.

use super::*;

#[test]
fn unlock_needs_a_consumed_ticket_then_a_rotation() {
    let b = Bridge::new();
    let mut d = Device::new();
    let app = d.setup(&b);
    assert!(b.vault_export(app).is_ok());
    assert_eq!(b.pin_setup(app, PIN, DURESS).err(), Some(BAD_STATE));

    // Finish while the ticket is still live (StrongBox did not consume it): refused.
    let begin = b.pin_begin(app, &d.blob, PIN, &d.live()).unwrap();
    let id = be32(&begin);
    let out = hmac(&d.tickets[&id], &begin[4..]);
    assert_eq!(b.pin_finish(app, &d.blob, id as i32, Some(&out), &d.live()), BAD_STATE);
    // The pending attempt is gone; a finish without a begin is a state error.
    assert_eq!(b.pin_finish(app, &d.blob, id as i32, Some(&out), &[]), BAD_STATE);
    assert_eq!(b.pin_finish(app, &d.blob, id as i32, Some(&out[..31]), &[]), BAD_ARG);

    // A fresh process unlocks with the normal PIN, must rotate before it can export.
    let b2 = Bridge::new();
    let app2 = d.open(&b2);
    assert_eq!(b2.vault_export(app2).err(), Some(LOCKED));
    assert_eq!(d.unlock(&b2, app2, PIN), 1);
    assert_eq!(d.tickets.len(), 4);
    assert_eq!(b2.vault_export(app2).err(), Some(BAD_STATE));
    assert_eq!(b2.vault_rotate_commit(app2, true).err(), Some(BAD_STATE));
    let rot = b2.vault_rotate_begin(app2).unwrap();
    assert_eq!(rot[0], 5);
    assert_eq!(b2.vault_rotate_commit(app2, false).err(), Some(BAD_STATE));
    d.rotate(&b2, app2);
    assert_eq!(d.tickets.len(), 5);
    assert!(b2.vault_export(app2).is_ok());
}

#[test]
fn five_wrong_pins_kill_the_vault() {
    let b = Bridge::new();
    let mut d = Device::new();
    let app = d.setup(&b);
    for left in (1..=4).rev() {
        assert_eq!(d.unlock(&b, app, b"0000"), 0);
        assert_eq!(d.tickets.len(), left);
    }
    assert_eq!(d.unlock(&b, app, b"0000"), LOCKED);
    assert!(d.tickets.is_empty());
    assert_eq!(b.pin_begin(app, &d.blob, PIN, &d.live()).err(), Some(LOCKED));
    assert_eq!(b.pin_begin(app, &d.blob, b"12", &[1]).err(), Some(BAD_ARG));
}

#[test]
fn a_kept_stretch_unlocks_through_the_ticket_like_the_pin() {
    let b = Bridge::new();
    let mut d = Device::new();
    d.setup(&b);
    let binding = b.vault_stretch_binding(&d.blob).unwrap();
    assert_eq!(b.vault_stretch_binding(&d.blob[..100]).err(), Some(BAD_ARG));

    // A PIN unlock hands the stretch to the app, which keeps it for fingerprint answer.
    let b2 = Bridge::new();
    let app2 = d.open(&b2);
    let begin = b2.pin_begin(app2, &d.blob, PIN, &d.live()).unwrap();
    let p = begin[4..].to_vec();
    assert_eq!(d.finish(&b2, app2, &begin), 1);
    d.rotate(&b2, app2);
    assert_eq!(b2.vault_stretch_binding(&d.blob).unwrap(), binding);

    // A later app object unlocks with it; the ticket choice and phase 2 are the PIN path's.
    let b3 = Bridge::new();
    let app3 = d.open(&b3);
    assert_eq!(b3.pin_begin_stretch(app3, &d.blob, &p[..31], &d.live()).err(), Some(BAD_ARG));
    assert_eq!(b3.pin_begin_stretch(app3, &d.blob, &[p.clone(), vec![0]].concat(), &d.live()).err(), Some(BAD_ARG));
    let begin = b3.pin_begin_stretch(app3, &d.blob, &p, &d.live()).unwrap();
    assert_eq!(&begin[4..], &p[..]);
    assert_eq!(be32(&begin), *d.tickets.keys().next().unwrap());
    let left = d.tickets.len();
    assert_eq!(d.finish(&b3, app3, &begin), 1);
    assert_eq!(d.tickets.len(), left - 1);
    assert!(b3.meta_seal(app3, b"x").is_ok());

    // A wrong stretch spends a ticket like a wrong PIN.
    let b4 = Bridge::new();
    let app4 = d.open(&b4);
    let begin = b4.pin_begin_stretch(app4, &d.blob, &[9u8; 32], &d.live()).unwrap();
    assert_eq!(d.finish(&b4, app4, &begin), 0);
    assert_eq!(d.tickets.len(), left - 2);
}

#[test]
fn a_kept_stretch_is_refused_after_the_duress_pin() {
    let b = Bridge::new();
    let mut d = Device::new();
    let app = d.setup(&b);
    let p = b.pin_begin(app, &d.blob, PIN, &d.live()).unwrap()[4..].to_vec();
    let blob = d.blob.clone();
    assert_eq!(d.unlock(&b, app, DURESS), 2);
    assert_eq!(b.pin_begin_stretch(app, &blob, &p, &d.live()).err(), Some(LOCKED));
    let b2 = Bridge::new();
    let app2 = b2.app_open(trust_tlv()).unwrap();
    d.tickets.clear();
    assert_eq!(b2.pin_begin_stretch(app2, &blob, &p, &d.live()).err(), Some(LOCKED));
}

#[test]
fn a_fingerprint_unlock_does_not_give_back_attempts_spent_on_wrong_pins() {
    let b = Bridge::new();
    let mut d = Device::new();
    let app = d.setup(&b);
    let p = b.pin_begin(app, &d.blob, PIN, &d.live()).unwrap()[4..].to_vec();
    assert_eq!(d.unlock(&b, app, b"0000"), 0);
    assert_eq!(d.unlock(&b, app, b"1111"), 0);
    assert_eq!(d.tickets.len(), 3);

    // Fingerprint answer: the unlock spends one ticket and its rotation gives back only that one.
    let b2 = Bridge::new();
    let app2 = d.open(&b2);
    let begin = b2.pin_begin_stretch(app2, &d.blob, &p, &d.live()).unwrap();
    assert_eq!(d.finish(&b2, app2, &begin), 1);
    assert_eq!(d.tickets.len(), 2);
    d.rotate(&b2, app2);
    assert_eq!(d.tickets.len(), 3);

    // A PIN unlock fills all five again.
    let b3 = Bridge::new();
    let app3 = d.open(&b3);
    assert_eq!(d.unlock(&b3, app3, PIN), 1);
    d.rotate(&b3, app3);
    assert_eq!(d.tickets.len(), 5);
}

#[test]
fn duress_pin_wipes_sessions_and_the_vault_never_opens_again() {
    let b = Bridge::new();
    let mut d = Device::new();
    let app = d.setup(&b);
    let s = b.session_create(app, true, 0, None, true, 0).unwrap();
    assert!(b.session_poll(s).is_ok());
    let blob = d.blob.clone();

    assert_eq!(d.unlock(&b, app, DURESS), 2);
    assert_eq!(b.session_poll(s).err(), Some(BAD_HANDLE));
    assert!(b.session_create(app, true, 0, None, true, 0).is_err());
    let over = b.vault_export(app).unwrap();
    assert_eq!(over.len(), blob.len());
    assert_ne!(&over[..], &blob[..]);
    assert_eq!(b.pin_begin(app, &blob, PIN, &d.live()).err(), Some(LOCKED));
    assert_eq!(b.vault_rotate_begin(app).err(), Some(LOCKED));
    assert_eq!(b.pairing_code(app).err(), Some(LOCKED));

    // The app destroys every ticket and writes the overwrite: neither file opens again.
    d.tickets.clear();
    let b2 = Bridge::new();
    let app2 = b2.app_open(trust_tlv()).unwrap();
    assert_eq!(b2.pin_begin(app2, &blob, PIN, &d.live()).err(), Some(LOCKED));
    assert_eq!(b2.pin_begin(app2, &over, PIN, &[]).err(), Some(BAD_ARG));
}

#[test]
fn contact_metadata_seals_and_opens_only_while_the_vault_is_unlocked() {
    let b = Bridge::new();
    let mut d = Device::new();
    let app = d.setup(&b);
    let sealed = b.meta_seal(app, b"numbers").unwrap().to_vec();
    assert_eq!(&b.meta_open(app, &sealed).unwrap()[..], b"numbers");
    let mut bad = sealed.clone();
    bad[30] ^= 1;
    assert_eq!(b.meta_open(app, &bad).err(), Some(CRYPTO));
    // Locking closes the app object.
    assert_eq!(b.app_close(app), OK);
    assert_eq!(b.meta_open(app, &sealed).err(), Some(BAD_HANDLE));

    // A fresh app object is locked: nothing seals or opens before the normal PIN.
    let b2 = Bridge::new();
    let app2 = d.open(&b2);
    assert_eq!(b2.meta_seal(app2, b"x").err(), Some(LOCKED));
    assert_eq!(b2.meta_open(app2, &sealed).err(), Some(LOCKED));
    assert_eq!(d.unlock(&b2, app2, b"0000"), 0);
    assert_eq!(b2.meta_open(app2, &sealed).err(), Some(LOCKED));
    assert_eq!(d.unlock(&b2, app2, PIN), 1);
    assert_eq!(&b2.meta_open(app2, &sealed).unwrap()[..], b"numbers");
    d.rotate(&b2, app2);
    assert_eq!(&b2.meta_open(app2, &sealed).unwrap()[..], b"numbers");

    // The duress PIN leaves no key behind.
    let b3 = Bridge::new();
    let app3 = d.open(&b3);
    assert_eq!(d.unlock(&b3, app3, DURESS), 2);
    assert_eq!(b3.meta_open(app3, &sealed).err(), Some(LOCKED));
    assert_eq!(b3.meta_seal(app3, b"x").err(), Some(LOCKED));
}

#[test]
fn pin_change_verifies_current_rolls_back_on_failed_import_and_rotates_both_pins() {
    const NEW_PIN: &[u8] = b"86420975";
    const NEW_DURESS: &[u8] = b"97531864";

    let b = Bridge::new();
    let mut d = Device::new();
    let app = d.setup(&b);
    let sealed = b.meta_seal(app, b"contacts-meta").unwrap().to_vec();

    // Wrong current PIN returns 0; invalid arguments return BAD_ARG; locked app returns LOCKED.
    assert_eq!(b.pin_change(app, b"0000", NEW_PIN, NEW_DURESS), 0);
    assert_eq!(b.pin_change(app, PIN, b"12", NEW_DURESS), BAD_ARG);
    assert_eq!(b.pin_change(app, PIN, NEW_PIN, NEW_PIN), BAD_ARG);
    assert!(b.vault_export(app).is_ok());

    // Simulate failed StrongBox ticket import (imported = false): rolls back cleanly.
    assert_eq!(b.pin_change(app, PIN, NEW_PIN, NEW_DURESS), 1);
    assert_eq!(b.vault_export(app).err(), Some(BAD_STATE));
    let _ = b.vault_rotate_begin(app).unwrap();
    assert_eq!(b.vault_rotate_commit(app, false).err(), Some(BAD_STATE));
    assert!(b.vault_export(app).is_ok());
    assert_eq!(b.pin_change(app, NEW_PIN, PIN, DURESS), 0);

    // Stage and commit for real.
    assert_eq!(b.pin_change(app, PIN, NEW_PIN, NEW_DURESS), 1);
    d.rotate(&b, app);
    assert_eq!(d.tickets.len(), 5);

    // Fresh process: old PIN fails, new PIN unlocks and opens metadata, new duress wipes.
    let b2 = Bridge::new();
    let app2 = d.open(&b2);
    assert_eq!(b2.pin_change(app2, NEW_PIN, PIN, DURESS), LOCKED);
    assert_eq!(d.unlock(&b2, app2, PIN), 0);
    assert_eq!(d.unlock(&b2, app2, NEW_PIN), 1);
    assert_eq!(&b2.meta_open(app2, &sealed).unwrap()[..], b"contacts-meta");
    d.rotate(&b2, app2);

    let b3 = Bridge::new();
    let app3 = d.open(&b3);
    assert_eq!(d.unlock(&b3, app3, NEW_DURESS), 2);
}

const NEXT_PIN: &[u8] = b"86420975";
const NEXT_DURESS: &[u8] = b"97531864";

#[test]
fn pin_change_is_refused_after_a_fingerprint_unlock_and_while_the_stretch_is_held() {
    let b = Bridge::new();
    let mut d = Device::new();
    let app = d.setup(&b);
    let p = b.pin_begin(app, &d.blob, PIN, &d.live()).unwrap()[4..].to_vec();

    // Call-scoped (fingerprint) unlock: refused before and after its rotation, nothing staged.
    let b2 = Bridge::new();
    let app2 = d.open(&b2);
    let begin = b2.pin_begin_stretch(app2, &d.blob, &p, &d.live()).unwrap();
    assert_eq!(d.finish(&b2, app2, &begin), 1);
    assert_eq!(b2.pin_change(app2, PIN, NEXT_PIN, NEXT_DURESS), BAD_STATE);
    d.rotate(&b2, app2);
    assert_eq!(b2.pin_change(app2, PIN, NEXT_PIN, NEXT_DURESS), BAD_STATE);
    assert!(b2.vault_export(app2).is_ok());

    // PIN unlock that keeps the stretch to turn fingerprint answer on.
    let b3 = Bridge::new();
    let app3 = d.open(&b3);
    assert_eq!(b3.stretch_held(app3, true), LOCKED);
    assert_eq!(d.unlock(&b3, app3, PIN), 1);
    d.rotate(&b3, app3);
    let binding = b3.vault_stretch_binding(&d.blob).unwrap();
    assert_eq!(b3.stretch_held(app3, true), OK);
    assert_eq!(b3.pin_change(app3, PIN, NEXT_PIN, NEXT_DURESS), BAD_STATE);
    assert!(b3.vault_export(app3).is_ok());
    // Let go: the same request goes through and its rotation refills all five tickets.
    assert_eq!(b3.stretch_held(app3, false), OK);
    assert_eq!(b3.pin_change(app3, PIN, NEXT_PIN, NEXT_DURESS), 1);
    d.rotate(&b3, app3);
    assert_eq!(d.tickets.len(), 5);

    // A stretch kept for the old PIN no longer matches the file's binding.
    assert_ne!(b3.vault_stretch_binding(&d.blob).unwrap(), binding);
    let b4 = Bridge::new();
    let app4 = d.open(&b4);
    assert_eq!(d.unlock(&b4, app4, NEXT_PIN), 1);
}

#[test]
fn the_third_wrong_current_pin_locks_the_app_object_until_an_unlock() {
    let b = Bridge::new();
    let mut d = Device::new();
    let app = d.setup(&b);
    let sealed = b.meta_seal(app, b"contacts-meta").unwrap().to_vec();
    let left = d.tickets.len();

    assert_eq!(b.pin_change(app, b"0000", NEXT_PIN, NEXT_DURESS), 0);
    assert_eq!(b.pin_change(app, b"3333", NEXT_PIN, NEXT_DURESS), 0);
    assert_eq!(b.pin_change(app, b"1111", NEXT_PIN, NEXT_DURESS), 2);
    assert_eq!(d.tickets.len(), left, "guesses of the current PIN spend no ticket");

    // Locked like a fresh app object: the right PIN is refused and nothing of the vault is left.
    assert_eq!(b.pin_change(app, PIN, NEXT_PIN, NEXT_DURESS), LOCKED);
    assert_eq!(b.vault_export(app).err(), Some(LOCKED));
    assert_eq!(b.meta_open(app, &sealed).err(), Some(LOCKED));
    assert_eq!(b.contact_list(app).err(), Some(LOCKED));
    assert_eq!(b.pairing_code(app).err(), Some(LOCKED));

    // An unlock spends a ticket, opens the same app object again and starts a new count.
    assert_eq!(d.unlock(&b, app, PIN), 1);
    assert_eq!(d.tickets.len(), left - 1);
    assert_eq!(&b.meta_open(app, &sealed).unwrap()[..], b"contacts-meta");
    d.rotate(&b, app);
    assert_eq!(b.pin_change(app, b"0000", NEXT_PIN, NEXT_DURESS), 0);
    assert_eq!(b.pin_change(app, b"1111", NEXT_PIN, NEXT_DURESS), 0);
    assert_eq!(b.pin_change(app, PIN, NEXT_PIN, NEXT_DURESS), 1);
    d.rotate(&b, app);
    let b2 = Bridge::new();
    let app2 = d.open(&b2);
    assert_eq!(d.unlock(&b2, app2, NEXT_PIN), 1);
}

#[test]
fn a_pin_change_that_was_not_written_leaves_the_old_pin_working() {
    let b = Bridge::new();
    let mut d = Device::new();
    let app = d.setup(&b);

    // Ticket import failed: aborted; the unlocked vault keeps the old PINs and can be written.
    assert_eq!(b.pin_change(app, PIN, NEXT_PIN, NEXT_DURESS), 1);
    let _ = b.vault_rotate_begin(app).unwrap();
    assert_eq!(b.vault_rotate_commit(app, false).err(), Some(BAD_STATE));
    d.blob = b.vault_export(app).unwrap().to_vec();

    // Begin failed: the app aborts the same way, which also drops the staged PINs.
    assert_eq!(b.pin_change(app, PIN, NEXT_PIN, NEXT_DURESS), 1);
    assert_eq!(b.vault_rotate_commit(app, false).err(), Some(BAD_STATE));
    assert!(b.vault_export(app).is_ok());

    // Committed, but the file was not written: the app retires the new tickets and drops this
    // app object. The file on disk and its tickets are untouched.
    let before: std::collections::BTreeSet<u32> = d.tickets.keys().copied().collect();
    assert_eq!(b.pin_change(app, PIN, NEXT_PIN, NEXT_DURESS), 1);
    let rot = b.vault_rotate_begin(app).unwrap();
    let _ = d.import(&rot);
    let unwritten = b.vault_rotate_commit(app, true).unwrap().to_vec();
    d.tickets.retain(|id, _| before.contains(id));
    assert_eq!(b.app_close(app), OK);

    let b2 = Bridge::new();
    let app2 = d.open(&b2);
    assert_eq!(b2.pin_begin(app2, &unwritten, NEXT_PIN, &d.live()).err(), Some(LOCKED));
    assert_eq!(d.unlock(&b2, app2, NEXT_PIN), 0);
    assert_eq!(d.unlock(&b2, app2, PIN), 1);
    d.rotate(&b2, app2);
    assert_eq!(d.tickets.len(), 5);
}

#[test]
fn the_duress_pin_as_the_current_pin_takes_the_duress_path() {
    let b = Bridge::new();
    let mut d = Device::new();
    let app = d.setup(&b);
    let s = b.session_create(app, true, 0, None, true, 0).unwrap();
    let blob = d.blob.clone();

    assert_eq!(b.pin_change(app, b"0000", NEXT_PIN, NEXT_DURESS), 0);
    assert_eq!(b.pin_change(app, DURESS, NEXT_PIN, NEXT_DURESS), 3);
    // Exactly what a duress unlock leaves: sessions gone, same-length noise, everything locked.
    assert_eq!(b.session_poll(s).err(), Some(BAD_HANDLE));
    assert!(b.session_create(app, true, 0, None, true, 0).is_err());
    let over = b.vault_export(app).unwrap();
    assert_eq!(over.len(), blob.len());
    assert_ne!(&over[..], &blob[..]);
    assert_eq!(b.pin_begin(app, &blob, PIN, &d.live()).err(), Some(LOCKED));
    assert_eq!(b.pin_change(app, PIN, NEXT_PIN, NEXT_DURESS), LOCKED);
    assert_eq!(b.meta_seal(app, b"x").err(), Some(LOCKED));
    assert_eq!(b.pairing_code(app).err(), Some(LOCKED));
    assert_eq!(b.stretch_held(app, true), LOCKED);
}

#[test]
fn the_duress_pin_wins_over_invalid_new_pins_and_a_refused_change() {
    let long = vec![b'7'; 200];

    // Over-long new PINs: a right current PIN gets BAD_ARG without counting, the duress PIN wipes.
    let b = Bridge::new();
    let mut d = Device::new();
    let app = d.setup(&b);
    for _ in 0..3 {
        assert_eq!(b.pin_change(app, PIN, &long, NEXT_DURESS), BAD_ARG);
        assert_eq!(b.pin_change(app, PIN, NEXT_PIN, b""), BAD_ARG);
    }
    assert_eq!(b.pin_change(app, b"0000", &long, &long), 0);
    assert_eq!(b.pin_change(app, b"1111", b"", b""), 0);
    assert!(b.vault_export(app).is_ok());
    assert_eq!(b.pin_change(app, DURESS, &long, &long), 3);
    assert_eq!(b.vault_export(app).unwrap().len(), d.blob.len());

    // While the stretch is held: refused (BAD_STATE) for a right or wrong PIN, never counted.
    let b2 = Bridge::new();
    let mut d2 = Device::new();
    let app2 = d2.setup(&b2);
    assert_eq!(b2.stretch_held(app2, true), OK);
    for _ in 0..4 {
        assert_eq!(b2.pin_change(app2, b"0000", NEXT_PIN, NEXT_DURESS), BAD_STATE);
    }
    assert_eq!(b2.pin_change(app2, PIN, NEXT_PIN, NEXT_DURESS), BAD_STATE);
    assert_eq!(b2.pin_change(app2, DURESS, NEXT_PIN, NEXT_DURESS), 3);
    assert_eq!(b2.vault_export(app2).unwrap().len(), d2.blob.len());
    assert_eq!(b2.pin_change(app2, PIN, NEXT_PIN, NEXT_DURESS), LOCKED);

    // Fingerprint (stretch) unlock: BAD_STATE, but the duress PIN still wipes.
    let b3 = Bridge::new();
    let mut d3 = Device::new();
    let app3 = d3.setup(&b3);
    let p = b3.pin_begin(app3, &d3.blob, PIN, &d3.live()).unwrap()[4..].to_vec();
    let b4 = Bridge::new();
    let app4 = d3.open(&b4);
    let begin = b4.pin_begin_stretch(app4, &d3.blob, &p, &d3.live()).unwrap();
    assert_eq!(d3.finish(&b4, app4, &begin), 1);
    assert_eq!(b4.pin_change(app4, b"0000", NEXT_PIN, NEXT_DURESS), BAD_STATE);
    assert_eq!(b4.pin_change(app4, DURESS, NEXT_PIN, NEXT_DURESS), 3);
    assert_eq!(b4.meta_seal(app4, b"x").err(), Some(LOCKED));
}

#[test]
fn vault_ticket_ids_reads_the_header_without_unlocking_and_refuses_a_broken_file() {
    let b = Bridge::new();
    let mut d = Device::new();
    let app = d.setup(&b);
    let ids = |raw: &[u8]| -> Vec<u32> { raw.chunks(4).map(be32).collect() };
    let raw = b.vault_ticket_ids(&d.blob).unwrap();
    assert_eq!(raw.len(), 20);
    assert_eq!(ids(&raw[..]), d.tickets.keys().copied().collect::<Vec<_>>());
    assert_eq!(d.unlock(&b, app, PIN), 1);
    d.rotate(&b, app);
    assert_eq!(ids(&b.vault_ticket_ids(&d.blob).unwrap()[..]), d.tickets.keys().copied().collect::<Vec<_>>());
    assert_eq!(b.vault_ticket_ids(&d.blob[..d.blob.len() - 1]).err(), Some(BAD_ARG));
    assert!(b.vault_ticket_ids(&vec![0x5a; d.blob.len()]).is_err());
    assert!(b.vault_ticket_ids(&[]).is_err());
}
