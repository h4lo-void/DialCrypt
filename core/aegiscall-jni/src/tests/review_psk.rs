//! Review tests for pairing at the Bridge level: refused codes leave the vault unchanged,
//! and the abort reason after a one-sided re-import is the PSK-required one.

use super::*;
use aegiscall_chat::AbortReason;

fn code_with(pub33: [u8; 33], xpub: [u8; 32]) -> String {
    aegiscall_crypto::PairingCodeV2::new(pub33, xpub).unwrap().to_code().as_str().to_owned()
}

#[test]
fn low_order_and_own_key_codes_are_refused_and_leave_the_vault_unchanged() {
    let p = Party::new();
    let own_code = p.b.pairing_code(p.app).unwrap().to_string();
    let own_x = aegiscall_crypto::PairingCodeV2::from_code(&own_code).unwrap().xpub;
    let (_, other_pub) = synthetic_code();
    let before = contacts(&p.b, p.app);
    assert!(before.is_empty());
    for x in [[0u8; 32], { let mut o = [0u8; 32]; o[0] = 1; o }, own_x] {
        let rc = p.import(0, &code_with(other_pub, x), Some("Eve"));
        assert!(rc < 0, "refused code returned {rc}");
        assert_eq!(rc, BAD_ARG);
    }
    assert!(contacts(&p.b, p.app).is_empty());
}

fn abort_code(p: &Party) -> Option<u8> {
    p.find(EV_ABORTED).map(|v| v[0])
}

/// A dials the contact; returns (A abort, B abort) when no call is established.
fn dial_expect_abort(a: &mut Party, b: &mut Party, contact: i32, now: &mut i64) -> (Option<u8>, Option<u8>) {
    a.call(true, contact, None, *now);
    b.call(false, 0, None, *now);
    let est = |p: &Party| p.has(EV_ESTABLISHED);
    let gone = |p: &Party| p.has(EV_ABORTED);
    assert!(run_until(a, b, now, 4000, |a, b| (est(a) && est(b)) || gone(a) || gone(b)));
    assert!(!(est(a) && est(b)), "call established with differing PSKs");
    let out = (abort_code(a), abort_code(b));
    let _ = a.b.session_close(a.s, false);
    let _ = b.b.session_close(b.s, false);
    out
}

#[test]
fn one_sided_reimport_aborts_with_psk_required_not_mismatch() {
    let mut a = Party::new();
    let mut b = Party::new();
    let mut now = 0i64;
    let code_b = b.b.pairing_code(b.app).unwrap().to_string();
    let code_a_old = a.b.pairing_code(a.app).unwrap().to_string();
    let (id_b, _) = imported(a.import(0, &code_b, Some("Bob")));
    let (id_a, _) = imported(b.import(0, &code_a_old, Some("Alice")));
    a.persist();
    b.persist();
    assert_eq!(a.b.set_pairing_seed(a.app, &[0x77; 32]), OK);
    let code_a_new = a.b.pairing_code(a.app).unwrap().to_string();
    assert_eq!(imported(b.import(0, &code_a_new, None)), (id_a, true));
    b.persist();
    let (aa, ab) = dial_expect_abort(&mut a, &mut b, id_b, &mut now);
    let (ba, bb) = dial_expect_abort(&mut b, &mut a, id_a, &mut now);
    let req = AbortReason::HsPskRequired.code();
    let mis = AbortReason::HsPskMismatch.code();
    eprintln!("A dials: A={aa:?} B={ab:?}; B dials: B={ba:?} A={bb:?}");
    for c in [aa, ab, ba, bb].into_iter().flatten() {
        assert_ne!(c, mis, "unexpected PskMismatch");
    }
    assert!(aa == Some(req) || ab == Some(req));
    assert!(ba == Some(req) || bb == Some(req));
}
