//! Handle registry, WIPING, concurrency, TLV and the Kotlin declarations.

use super::*;
use crate::bridge::App;
use crate::registry::Entry;
use std::sync::{Arc, TryLockError};
use std::thread;
use std::time::Instant;

#[test]
fn stale_and_wrong_type_handles_return_bad_handle() {
    let b = Bridge::new();
    let mut d = Device::new();
    let app = d.setup(&b);
    let s = b.session_create(app, true, 0, None, true, 0).unwrap();
    assert!(app > 0 && s > 0 && app != s);
    for h in [0i64, -1, i64::MIN, 12345] {
        assert_eq!(b.vault_export(h).err(), Some(BAD_HANDLE));
        assert_eq!(b.session_sas(h, true), BAD_HANDLE);
        assert_eq!(b.app_close(h), BAD_HANDLE);
    }
    // Wrong table.
    assert_eq!(b.vault_export(s).err(), Some(BAD_HANDLE));
    assert_eq!(b.contact_delete(s, 1), BAD_HANDLE);
    assert_eq!(b.session_poll(app).err(), Some(BAD_HANDLE));
    assert_eq!(b.session_close(app, false), BAD_HANDLE);
    assert!(b.session_create(s, true, 0, None, true, 0).is_err());
    // Operations before the session exists on the wire.
    assert_eq!(b.session_send_text(s, b"hi", 0, 0), BAD_STATE);
    assert_eq!(b.session_save_contact(s, 0, b"x", None), BAD_STATE);
    assert_eq!(b.session_send_text(s, &[0xff, 0xfe], 0, 0), BAD_ARG);
    assert_eq!(b.session_bearer_violation(s, 300), BAD_ARG);
    // Double close.
    assert_eq!(b.session_close(s, false), OK);
    assert_eq!(b.session_close(s, false), BAD_HANDLE);
    assert_eq!(b.session_poll(s).err(), Some(BAD_HANDLE));
    let s2 = b.session_create(app, false, 0, None, false, 0).unwrap();
    assert_ne!(s2, s);
    assert_eq!(b.app_close(app), OK);
    assert_eq!(b.app_close(app), BAD_HANDLE);
    assert_eq!(b.session_poll(s2).err(), Some(BAD_HANDLE));
    assert_eq!(b.live_handles(), 0);
}

/// Returns once another thread holds the app lock (its bridge operation is running).
fn wait_until_locked(e: &Entry<App>) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !matches!(e.try_lock(), Err(TryLockError::WouldBlock)) {
        assert!(Instant::now() < deadline, "the operation never took the lock");
        std::hint::spin_loop();
    }
}

/// Starts pin_begin (Argon2 under the app lock) on another thread and waits until it runs.
fn slow_operation(b: &Arc<Bridge>, d: &Device, app: i64, slot: &Entry<App>) -> thread::JoinHandle<Result<usize, i32>> {
    let (b1, blob, live) = (b.clone(), d.blob.clone(), d.live());
    let t = thread::spawn(move || b1.pin_begin(app, &blob, PIN, &live).map(|v| v.len()));
    wait_until_locked(slot);
    t
}

#[test]
fn close_waits_for_the_running_call_and_later_calls_get_bad_handle() {
    let b = Arc::new(Bridge::new());
    let mut d = Device::new();
    let app = d.setup(&b);
    // An Arc looked up before the close, as a call that is about to take the lock holds it.
    let slot = b.app_slot(app).unwrap();
    let running = slow_operation(&b, &d, app, &slot);
    // The close starts while pin_begin holds the lock, so it can only finish afterwards.
    let b2 = b.clone();
    let closer = thread::spawn(move || {
        let c = b2.app_close(app);
        (c, Instant::now())
    });
    let begun = running.join().unwrap();
    let ran_until = Instant::now();
    let (closed, closed_at) = closer.join().unwrap();
    // The running call saw a live object and completed; had the close gone first it would be -1.
    assert_eq!(begun, Ok(36));
    assert_eq!(closed, OK);
    assert!(closed_at + Duration::from_millis(50) > ran_until);
    // Everything after the close: -1, and no vault leaves through the old Arc either.
    assert_eq!(Bridge::export_via(&slot).err(), Some(BAD_HANDLE));
    assert_eq!(b.vault_export(app).err(), Some(BAD_HANDLE));
    assert_eq!(b.pairing_code(app).err(), Some(BAD_HANDLE));
    assert_eq!(b.pin_finish(app, &d.blob, 1, Some(&[0u8; 32]), &[]), BAD_HANDLE);
    assert_eq!(b.app_close(app), BAD_HANDLE);
}

#[test]
fn wipe_during_a_running_call_returns_bad_handle_without_data() {
    let b = Arc::new(Bridge::new());
    let mut d = Device::new();
    let app = d.setup(&b);
    let slot = b.app_slot(app).unwrap();
    let running = slow_operation(&b, &d, app, &slot);
    // Sets WIPING at once, then waits for the lock to close the app.
    assert_eq!(b.panic_wipe(app), OK);
    // The call that was already inside finds the flag before it hands anything out.
    assert_eq!(running.join().unwrap(), Err(BAD_HANDLE));
    assert_eq!(Bridge::export_via(&slot).err(), Some(BAD_HANDLE));
    assert_eq!(b.live_handles(), 0);
}

#[test]
fn wiping_flag_turns_every_new_call_into_bad_handle() {
    let b = Bridge::new();
    let mut d = Device::new();
    let app = d.setup(&b);
    let s = b.session_create(app, true, 0, None, true, 0).unwrap();
    assert_eq!(b.panic_wipe(app), OK);
    assert!(b.is_wiping());
    assert_eq!(b.live_handles(), 0);
    assert_eq!(b.app_open(trust_tlv()).err(), Some(BAD_HANDLE));
    assert_eq!(b.vault_export(app).err(), Some(BAD_HANDLE));
    assert_eq!(b.pin_begin(app, &d.blob, PIN, &d.live()).err(), Some(BAD_HANDLE));
    assert_eq!(b.session_poll(s).err(), Some(BAD_HANDLE));
    assert_eq!(b.session_sas(s, true), BAD_HANDLE);
    assert_eq!(b.session_close(s, false), BAD_HANDLE);
    assert_eq!(b.app_close(app), BAD_HANDLE);
}

#[test]
fn event_tlv_round_trip_and_truncation() {
    let mut buf = Vec::new();
    assert!(encode_tlv(&mut buf, EV_SAS, &[1, 2, 3, 4, 5]));
    assert!(encode_tlv(&mut buf, EV_SAS_CONFIRMED, &[]));
    let long = vec![0xab; 3000];
    assert!(encode_tlv(&mut buf, EV_MESSAGE_RECEIVED, &long));
    assert!(!encode_tlv(&mut Vec::new(), EV_MESSAGE_RECEIVED, &vec![0; 70_000]));
    assert_eq!(&buf[..3], &[EV_SAS, 0, 5]);
    let recs = decode_tlv(&buf).unwrap();
    assert_eq!(recs.len(), 3);
    assert_eq!(recs[0], (EV_SAS, &[1u8, 2, 3, 4, 5][..]));
    assert_eq!(recs[1], (EV_SAS_CONFIRMED, &[][..]));
    assert_eq!(recs[2].1.len(), 3000);
    for cut in 1..buf.len() {
        let r = decode_tlv(&buf[..cut]);
        assert!(r.is_none() || cut == 8 || cut == 11, "cut {cut}");
    }
    assert_eq!(decode_tlv(&[]).unwrap().len(), 0);
}

#[test]
fn setup_rejects_bad_identity_and_config() {
    let b = Bridge::new();
    assert_eq!(b.app_open(&[1, 9, 0, 1, 0]).err(), Some(BAD_ARG));
    let d = Device::new();
    let other = Device::new();
    let app = b.app_open(trust_tlv()).unwrap();
    // Chain of another key, truncated chain, bad SPKI.
    assert_eq!(b.set_identity(app, &d.spki, &other.chain_tlv), CRYPTO);
    assert_eq!(b.set_identity(app, &d.spki, &d.chain_tlv[..40]), BAD_ARG);
    assert_eq!(b.set_identity(app, &d.spki[..20], &d.chain_tlv), BAD_ARG);
    assert!(b.session_create(app, true, 0, None, true, 0).is_err());
    assert_eq!(b.pairing_code(app).err(), Some(LOCKED));
    assert_eq!(b.set_identity(app, &d.spki, &d.chain_tlv), OK);
}

// ------------------------------------------------------------ Kotlin declarations

fn camel(snake: &str) -> String {
    let mut out = String::new();
    for (i, part) in snake.split('_').enumerate() {
        let mut cs = part.chars();
        match cs.next() {
            Some(c) if i > 0 => out.push(c.to_ascii_uppercase()),
            Some(c) => out.push(c),
            None => {}
        }
        out.push_str(cs.as_str());
    }
    out
}

fn kotlin_type(rust: &str) -> &'static str {
    match rust.trim_end_matches("<'l>") {
        "jlong" => "Long",
        "jint" => "Int",
        "jboolean" => "Boolean",
        "JByteArray" => "ByteArray",
        "NullableByteArray" => "ByteArray?",
        "JIntArray" => "IntArray",
        "JShortArray" => "ShortArray",
        "JByteBuffer" => "java.nio.ByteBuffer",
        "jbyteArray" => "ByteArray?",
        "jstring" => "String?",
        "jshortArray" => "ShortArray?",
        other => panic!("unmapped JNI type {other}"),
    }
}

fn split_params(list: &str) -> Vec<(String, String)> {
    list.split(',')
        .filter(|p| !p.trim().is_empty())
        .map(|p| {
            let (n, t) = p.split_once(':').unwrap();
            (n.trim().trim_start_matches("mut ").to_string(), t.trim().to_string())
        })
        .collect()
}

type Decl = (String, Vec<(String, String)>, String);

/// Every export as Kotlin would declare it: name, (parameter name, type) without env/this, return type.
fn rust_exports() -> Vec<Decl> {
    let src = include_str!("../exports.rs");
    let marker = "fn Java_io_github_h4lovoid_dialcrypt_core_NativeBridge_";
    let mut out = Vec::new();
    for part in src.split(marker).skip(1) {
        let name: String = part.chars().take_while(|c| c.is_ascii_alphanumeric()).collect();
        let open = part.find('(').unwrap();
        let close = part.find(')').unwrap();
        let params = split_params(&part[open + 1..close])
            .into_iter()
            .skip(2)
            .map(|(n, t)| (camel(&n), kotlin_type(&t).to_string()))
            .collect();
        let ret = part[close + 1..].split('{').next().unwrap().trim().trim_start_matches("->").trim();
        let ret = kotlin_type(ret).to_string();
        out.push((name, params, ret));
    }
    out
}

fn kotlin_externals() -> Vec<Decl> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../app/src/main/java/io/github/h4lovoid/dialcrypt/core/NativeBridge.kt");
    let src = std::fs::read_to_string(path).unwrap();
    let mut out = Vec::new();
    for part in src.split("external fun ").skip(1) {
        let name: String = part.chars().take_while(|c| c.is_ascii_alphanumeric()).collect();
        let open = part.find('(').unwrap();
        let close = part.find(')').unwrap();
        let params = split_params(&part[open + 1..close]);
        let ret = part[close + 1..].lines().next().unwrap().trim().trim_start_matches(':').trim().to_string();
        out.push((name, params, ret));
    }
    out
}

/// Names, parameter names, parameter types with their null marks, and return types.
#[test]
fn exports_match_kotlin_external_funs() {
    let mut rust = rust_exports();
    let mut kotlin = kotlin_externals();
    assert_eq!(rust.len(), 46);
    rust.sort();
    kotlin.sort();
    assert_eq!(rust.len(), kotlin.len());
    for (r, k) in rust.iter().zip(&kotlin) {
        assert_eq!(r, k);
    }
    // The nullable parameters are exactly these.
    let nullable: Vec<String> = kotlin
        .iter()
        .flat_map(|(f, ps, _)| ps.iter().filter(|p| p.1.ends_with('?')).map(move |p| format!("{f}.{}", p.0)))
        .collect();
    assert_eq!(
        nullable,
        [
            "nativeContactSetPhone.phoneE164Utf8",
            "nativeImportPairing.labelUtf8",
            "nativePinFinish.hmacOut",
            "nativeSessionCreate.peerE164Utf8",
            "nativeSessionCreateGear.peerE164Utf8",
            "nativeSessionSaveContact.phoneE164Utf8",
            "nativeSessionSignResult.derSig",
        ]
    );
}
