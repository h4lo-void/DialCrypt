//! extern "system" functions for io.github.h4lovoid.dialcrypt.core.NativeBridge. Each converts the Java
//! arguments, calls the global Bridge and converts the result; none calls back into Java.
//! Byte arrays copied from Java (PIN, text, vault file, signatures) are zeroized after use.

use crate::bridge::{harden, Bridge};
use crate::bridge::{MAX_CODE_LEN, MAX_LABEL_BYTES, MAX_PHONE_LEN, MAX_TEXT_LEN};
use crate::code::BAD_ARG;
use aegiscall_trust::MAX_PIN_LEN;
use jni::objects::{JByteArray, JIntArray, JObject, JShortArray};
use jni::sys::{jboolean, jbyteArray, jint, jlong, jshortArray, jstring, JNI_TRUE};
use jni::JNIEnv;
use zeroize::Zeroizing;

/// Largest byte array accepted from Java.
const MAX_IN_LEN: usize = 2 * 1024 * 1024;
const MAX_TICKETS_IN: usize = 64;
/// New PINs given to nativePinChange: long enough that an over-long one still reaches the
/// current-PIN comparison, which runs first; the vault refuses it after that.
const MAX_NEW_PIN_IN: usize = 4 * MAX_PIN_LEN;

/// A byte array parameter that Kotlin declares as ByteArray? (null allowed).
type NullableByteArray<'l> = JByteArray<'l>;

fn bridge() -> &'static Bridge {
    Bridge::global()
}

fn flag(v: jboolean) -> bool {
    v == JNI_TRUE
}

fn res(r: Result<i32, i32>) -> jint {
    match r {
        Ok(v) => v,
        Err(c) => c,
    }
}

fn array_len(env: &JNIEnv, n: jni::errors::Result<i32>, max: usize) -> Result<usize, i32> {
    let _ = env;
    let n = usize::try_from(n.map_err(|_| BAD_ARG)?).map_err(|_| BAD_ARG)?;
    if n > max {
        return Err(BAD_ARG);
    }
    Ok(n)
}

/// Copies a Java byte array; the length is checked against max before anything is allocated.
fn bytes_max(env: &JNIEnv, a: &JByteArray, max: usize) -> Result<Zeroizing<Vec<u8>>, i32> {
    if a.is_null() {
        return Err(BAD_ARG);
    }
    array_len(env, env.get_array_length(a), max)?;
    env.convert_byte_array(a).map(Zeroizing::new).map_err(|_| BAD_ARG)
}

fn bytes(env: &JNIEnv, a: &JByteArray) -> Result<Zeroizing<Vec<u8>>, i32> {
    bytes_max(env, a, MAX_IN_LEN)
}

fn opt_bytes(env: &JNIEnv, a: &JByteArray, max: usize) -> Result<Option<Zeroizing<Vec<u8>>>, i32> {
    if a.is_null() {
        Ok(None)
    } else {
        bytes_max(env, a, max).map(Some)
    }
}

fn ints(env: &JNIEnv, a: &JIntArray) -> Result<Vec<i32>, i32> {
    if a.is_null() {
        return Err(BAD_ARG);
    }
    let n = array_len(env, env.get_array_length(a), MAX_TICKETS_IN)?;
    let mut v = vec![0i32; n];
    env.get_int_array_region(a, 0, &mut v).map_err(|_| BAD_ARG)?;
    Ok(v)
}

fn shorts_max(env: &JNIEnv, a: &JShortArray, max: usize) -> Result<Vec<i16>, i32> {
    if a.is_null() {
        return Err(BAD_ARG);
    }
    let n = array_len(env, env.get_array_length(a), max)?;
    let mut v = vec![0i16; n];
    env.get_short_array_region(a, 0, &mut v).map_err(|_| BAD_ARG)?;
    Ok(v)
}

fn shorts(env: &JNIEnv, a: &JShortArray) -> Result<Vec<i16>, i32> {
    shorts_max(env, a, crate::audio::MAX_RX_CHUNK)
}

fn slice(v: &Option<Zeroizing<Vec<u8>>>) -> Option<&[u8]> {
    v.as_deref().map(Vec::as_slice)
}

/// Nothing is copied to Java once a panic wipe has started.
fn released<T>(r: Result<T, i32>) -> Option<T> {
    if bridge().is_wiping() {
        return None;
    }
    r.ok()
}

fn out_bytes(env: &JNIEnv, r: Result<Zeroizing<Vec<u8>>, i32>) -> jbyteArray {
    match released(r).and_then(|v| env.byte_array_from_slice(&v).ok()) {
        Some(a) => a.into_raw(),
        None => std::ptr::null_mut(),
    }
}

fn out_string(env: &mut JNIEnv, r: Result<Zeroizing<String>, i32>) -> jstring {
    match released(r).and_then(|s| env.new_string(s.as_str()).ok()) {
        Some(j) => j.into_raw(),
        None => std::ptr::null_mut(),
    }
}

fn out_shorts(env: &JNIEnv, r: Result<Option<Vec<i16>>, i32>) -> jshortArray {
    let Some(Some(pcm)) = released(r) else { return std::ptr::null_mut() };
    let Ok(len) = i32::try_from(pcm.len()) else { return std::ptr::null_mut() };
    let Ok(arr) = env.new_short_array(len) else { return std::ptr::null_mut() };
    if env.set_short_array_region(&arr, 0, &pcm).is_err() {
        return std::ptr::null_mut();
    }
    arr.into_raw()
}

// ---------------------------------------------------------------- process and app object

#[no_mangle]
pub extern "system" fn Java_io_github_h4lovoid_dialcrypt_core_NativeBridge_nativeHarden<'l>(_env: JNIEnv<'l>, _this: JObject<'l>) -> jint {
    harden()
}

#[no_mangle]
pub extern "system" fn Java_io_github_h4lovoid_dialcrypt_core_NativeBridge_nativeAppOpen<'l>(env: JNIEnv<'l>, _this: JObject<'l>, trust_tlv: JByteArray<'l>) -> jlong {
    bytes(&env, &trust_tlv).and_then(|t| bridge().app_open(&t)).unwrap_or(0)
}

#[no_mangle]
pub extern "system" fn Java_io_github_h4lovoid_dialcrypt_core_NativeBridge_nativeSetIdentity<'l>(
    env: JNIEnv<'l>,
    _this: JObject<'l>,
    app: jlong,
    spki_der: JByteArray<'l>,
    chain_tlv: JByteArray<'l>,
) -> jint {
    res((|| {
        let spki = bytes(&env, &spki_der)?;
        let chain = bytes(&env, &chain_tlv)?;
        Ok(bridge().set_identity(app, &spki, &chain))
    })())
}

#[no_mangle]
pub extern "system" fn Java_io_github_h4lovoid_dialcrypt_core_NativeBridge_nativePinSetup<'l>(
    env: JNIEnv<'l>,
    _this: JObject<'l>,
    app: jlong,
    pin_utf8: JByteArray<'l>,
    duress_utf8: JByteArray<'l>,
) -> jbyteArray {
    let r = (|| {
        let pin = bytes_max(&env, &pin_utf8, MAX_PIN_LEN)?;
        let duress = bytes_max(&env, &duress_utf8, MAX_PIN_LEN)?;
        bridge().pin_setup(app, &pin, &duress)
    })();
    out_bytes(&env, r)
}

#[no_mangle]
pub extern "system" fn Java_io_github_h4lovoid_dialcrypt_core_NativeBridge_nativePinBegin<'l>(
    env: JNIEnv<'l>,
    _this: JObject<'l>,
    app: jlong,
    vault_blob: JByteArray<'l>,
    pin_utf8: JByteArray<'l>,
    live_tickets: JIntArray<'l>,
) -> jbyteArray {
    let r = (|| {
        let blob = bytes(&env, &vault_blob)?;
        let pin = bytes_max(&env, &pin_utf8, MAX_PIN_LEN)?;
        let live = ints(&env, &live_tickets)?;
        bridge().pin_begin(app, &blob, &pin, &live)
    })();
    out_bytes(&env, r)
}

#[no_mangle]
pub extern "system" fn Java_io_github_h4lovoid_dialcrypt_core_NativeBridge_nativePinBeginStretch<'l>(
    env: JNIEnv<'l>,
    _this: JObject<'l>,
    app: jlong,
    vault_blob: JByteArray<'l>,
    stretch32: JByteArray<'l>,
    live_tickets: JIntArray<'l>,
) -> jbyteArray {
    let r = (|| {
        let blob = bytes(&env, &vault_blob)?;
        let stretch = bytes_max(&env, &stretch32, 32)?;
        let live = ints(&env, &live_tickets)?;
        bridge().pin_begin_stretch(app, &blob, &stretch, &live)
    })();
    out_bytes(&env, r)
}

#[no_mangle]
pub extern "system" fn Java_io_github_h4lovoid_dialcrypt_core_NativeBridge_nativeVaultStretchBinding<'l>(
    env: JNIEnv<'l>,
    _this: JObject<'l>,
    vault_blob: JByteArray<'l>,
) -> jbyteArray {
    let r = bytes(&env, &vault_blob).and_then(|blob| bridge().vault_stretch_binding(&blob)).map(|b| Zeroizing::new(b.to_vec()));
    out_bytes(&env, r)
}

#[no_mangle]
pub extern "system" fn Java_io_github_h4lovoid_dialcrypt_core_NativeBridge_nativePinFinish<'l>(
    env: JNIEnv<'l>,
    _this: JObject<'l>,
    app: jlong,
    vault_blob: JByteArray<'l>,
    ticket_id: jint,
    hmac_out: NullableByteArray<'l>,
    live_tickets: JIntArray<'l>,
) -> jint {
    res((|| {
        let blob = bytes(&env, &vault_blob)?;
        let hmac = opt_bytes(&env, &hmac_out, 32)?;
        let live = ints(&env, &live_tickets)?;
        Ok(bridge().pin_finish(app, &blob, ticket_id, slice(&hmac), &live))
    })())
}

#[no_mangle]
pub extern "system" fn Java_io_github_h4lovoid_dialcrypt_core_NativeBridge_nativePinChange<'l>(
    env: JNIEnv<'l>,
    _this: JObject<'l>,
    app: jlong,
    current_utf8: JByteArray<'l>,
    pin_utf8: JByteArray<'l>,
    duress_utf8: JByteArray<'l>,
) -> jint {
    res((|| {
        let current = bytes_max(&env, &current_utf8, MAX_PIN_LEN)?;
        let pin = bytes_max(&env, &pin_utf8, MAX_NEW_PIN_IN)?;
        let duress = bytes_max(&env, &duress_utf8, MAX_NEW_PIN_IN)?;
        Ok(bridge().pin_change(app, &current, &pin, &duress))
    })())
}

#[no_mangle]
pub extern "system" fn Java_io_github_h4lovoid_dialcrypt_core_NativeBridge_nativeVaultTicketIds<'l>(
    env: JNIEnv<'l>,
    _this: JObject<'l>,
    vault_blob: JByteArray<'l>,
) -> jbyteArray {
    let r = bytes(&env, &vault_blob).and_then(|blob| bridge().vault_ticket_ids(&blob));
    out_bytes(&env, r)
}

#[no_mangle]
pub extern "system" fn Java_io_github_h4lovoid_dialcrypt_core_NativeBridge_nativeStretchHeld<'l>(
    _env: JNIEnv<'l>,
    _this: JObject<'l>,
    app: jlong,
    held: jboolean,
) -> jint {
    bridge().stretch_held(app, flag(held))
}

#[no_mangle]
pub extern "system" fn Java_io_github_h4lovoid_dialcrypt_core_NativeBridge_nativeVaultRotateBegin<'l>(env: JNIEnv<'l>, _this: JObject<'l>, app: jlong) -> jbyteArray {
    out_bytes(&env, bridge().vault_rotate_begin(app))
}

#[no_mangle]
pub extern "system" fn Java_io_github_h4lovoid_dialcrypt_core_NativeBridge_nativeVaultRotateCommit<'l>(
    env: JNIEnv<'l>,
    _this: JObject<'l>,
    app: jlong,
    imported: jboolean,
) -> jbyteArray {
    out_bytes(&env, bridge().vault_rotate_commit(app, flag(imported)))
}

#[no_mangle]
pub extern "system" fn Java_io_github_h4lovoid_dialcrypt_core_NativeBridge_nativeVaultExport<'l>(env: JNIEnv<'l>, _this: JObject<'l>, app: jlong) -> jbyteArray {
    out_bytes(&env, bridge().vault_export(app))
}

#[no_mangle]
pub extern "system" fn Java_io_github_h4lovoid_dialcrypt_core_NativeBridge_nativeVaultSaved<'l>(_env: JNIEnv<'l>, _this: JObject<'l>, app: jlong, seq: jint) -> jint {
    bridge().vault_saved(app, seq)
}

#[no_mangle]
pub extern "system" fn Java_io_github_h4lovoid_dialcrypt_core_NativeBridge_nativePairingCode<'l>(mut env: JNIEnv<'l>, _this: JObject<'l>, app: jlong) -> jstring {
    let r = bridge().pairing_code(app);
    out_string(&mut env, r)
}

#[no_mangle]
pub extern "system" fn Java_io_github_h4lovoid_dialcrypt_core_NativeBridge_nativeSetPairingSeed<'l>(
    env: JNIEnv<'l>,
    _this: JObject<'l>,
    app: jlong,
    seed32: JByteArray<'l>,
) -> jint {
    res(bytes_max(&env, &seed32, 32).map(|s| bridge().set_pairing_seed(app, &s)))
}

#[no_mangle]
pub extern "system" fn Java_io_github_h4lovoid_dialcrypt_core_NativeBridge_nativeMetaSeal<'l>(
    env: JNIEnv<'l>,
    _this: JObject<'l>,
    app: jlong,
    plaintext: JByteArray<'l>,
) -> jbyteArray {
    let r = bytes(&env, &plaintext).and_then(|pt| bridge().meta_seal(app, &pt));
    out_bytes(&env, r)
}

#[no_mangle]
pub extern "system" fn Java_io_github_h4lovoid_dialcrypt_core_NativeBridge_nativeMetaOpen<'l>(
    env: JNIEnv<'l>,
    _this: JObject<'l>,
    app: jlong,
    sealed: JByteArray<'l>,
) -> jbyteArray {
    let r = bytes(&env, &sealed).and_then(|ct| bridge().meta_open(app, &ct));
    out_bytes(&env, r)
}

#[no_mangle]
pub extern "system" fn Java_io_github_h4lovoid_dialcrypt_core_NativeBridge_nativeImportPairing<'l>(
    env: JNIEnv<'l>,
    _this: JObject<'l>,
    app: jlong,
    contact_id: jint,
    code_utf8: JByteArray<'l>,
    label_utf8: NullableByteArray<'l>,
) -> jint {
    res((|| {
        let code = bytes_max(&env, &code_utf8, MAX_CODE_LEN)?;
        let label = opt_bytes(&env, &label_utf8, MAX_LABEL_BYTES)?;
        Ok(bridge().import_pairing(app, contact_id, &code, slice(&label)))
    })())
}

#[no_mangle]
pub extern "system" fn Java_io_github_h4lovoid_dialcrypt_core_NativeBridge_nativePreviewPairing<'l>(
    env: JNIEnv<'l>,
    _this: JObject<'l>,
    app: jlong,
    code_utf8: JByteArray<'l>,
) -> jint {
    res(bytes_max(&env, &code_utf8, MAX_CODE_LEN).map(|code| bridge().preview_pairing(app, &code)))
}

#[no_mangle]
pub extern "system" fn Java_io_github_h4lovoid_dialcrypt_core_NativeBridge_nativeImportRevert<'l>(
    _env: JNIEnv<'l>,
    _this: JObject<'l>,
    app: jlong,
    contact_id: jint,
) -> jint {
    bridge().import_revert(app, contact_id)
}

#[no_mangle]
pub extern "system" fn Java_io_github_h4lovoid_dialcrypt_core_NativeBridge_nativeContactList<'l>(env: JNIEnv<'l>, _this: JObject<'l>, app: jlong) -> jbyteArray {
    out_bytes(&env, bridge().contact_list(app))
}

#[no_mangle]
pub extern "system" fn Java_io_github_h4lovoid_dialcrypt_core_NativeBridge_nativeContactRename<'l>(
    env: JNIEnv<'l>,
    _this: JObject<'l>,
    app: jlong,
    contact_id: jint,
    label_utf8: JByteArray<'l>,
) -> jint {
    res(bytes_max(&env, &label_utf8, MAX_LABEL_BYTES).map(|l| bridge().contact_rename(app, contact_id, &l)))
}

#[no_mangle]
pub extern "system" fn Java_io_github_h4lovoid_dialcrypt_core_NativeBridge_nativeContactSetPhone<'l>(
    env: JNIEnv<'l>,
    _this: JObject<'l>,
    app: jlong,
    contact_id: jint,
    phone_e164_utf8: NullableByteArray<'l>,
) -> jint {
    res(opt_bytes(&env, &phone_e164_utf8, MAX_PHONE_LEN).map(|p| bridge().contact_set_phone(app, contact_id, slice(&p))))
}

#[no_mangle]
pub extern "system" fn Java_io_github_h4lovoid_dialcrypt_core_NativeBridge_nativeContactDelete<'l>(
    _env: JNIEnv<'l>,
    _this: JObject<'l>,
    app: jlong,
    contact_id: jint,
) -> jint {
    bridge().contact_delete(app, contact_id)
}

// ---------------------------------------------------------------- call session

#[no_mangle]
pub extern "system" fn Java_io_github_h4lovoid_dialcrypt_core_NativeBridge_nativeSessionCreate<'l>(
    env: JNIEnv<'l>,
    _this: JObject<'l>,
    app: jlong,
    dial: jboolean,
    contact_id: jint,
    peer_e164_utf8: NullableByteArray<'l>,
    wideband: jboolean,
    now_ms: jlong,
) -> jlong {
    (|| {
        let e164 = opt_bytes(&env, &peer_e164_utf8, MAX_PHONE_LEN)?;
        bridge().session_create(app, flag(dial), contact_id, slice(&e164), flag(wideband), now_ms)
    })()
    .unwrap_or(0)
}

#[no_mangle]
pub extern "system" fn Java_io_github_h4lovoid_dialcrypt_core_NativeBridge_nativeSessionCreateGear<'l>(
    env: JNIEnv<'l>,
    _this: JObject<'l>,
    app: jlong,
    dial: jboolean,
    contact_id: jint,
    peer_e164_utf8: NullableByteArray<'l>,
    gear_code: jint,
    now_ms: jlong,
) -> jlong {
    (|| {
        let e164 = opt_bytes(&env, &peer_e164_utf8, MAX_PHONE_LEN)?;
        bridge().session_create_gear(app, flag(dial), contact_id, slice(&e164), gear_code, now_ms)
    })()
    .unwrap_or(0)
}

#[no_mangle]
pub extern "system" fn Java_io_github_h4lovoid_dialcrypt_core_NativeBridge_nativeSessionTxPcm<'l>(
    env: JNIEnv<'l>,
    _this: JObject<'l>,
    session: jlong,
    now_ms: jlong,
) -> jshortArray {
    out_shorts(&env, bridge().session_tx_pcm(session, now_ms))
}

#[no_mangle]
pub extern "system" fn Java_io_github_h4lovoid_dialcrypt_core_NativeBridge_nativeSessionRxPcm<'l>(
    env: JNIEnv<'l>,
    _this: JObject<'l>,
    session: jlong,
    pcm: JShortArray<'l>,
    now_ms: jlong,
) -> jint {
    res(shorts(&env, &pcm).map(|p| bridge().session_rx_pcm(session, &p, now_ms)))
}

#[no_mangle]
pub extern "system" fn Java_io_github_h4lovoid_dialcrypt_core_NativeBridge_nativeSessionPollEvents<'l>(env: JNIEnv<'l>, _this: JObject<'l>, session: jlong) -> jbyteArray {
    out_bytes(&env, bridge().session_poll(session))
}

#[no_mangle]
pub extern "system" fn Java_io_github_h4lovoid_dialcrypt_core_NativeBridge_nativeSessionSignResult<'l>(
    env: JNIEnv<'l>,
    _this: JObject<'l>,
    session: jlong,
    req_id: jint,
    ok: jboolean,
    der_sig: NullableByteArray<'l>,
) -> jint {
    res(opt_bytes(&env, &der_sig, 128).map(|d| bridge().session_sign_result(session, req_id, flag(ok), slice(&d))))
}

#[no_mangle]
pub extern "system" fn Java_io_github_h4lovoid_dialcrypt_core_NativeBridge_nativeSessionSas<'l>(_env: JNIEnv<'l>, _this: JObject<'l>, session: jlong, ok: jboolean) -> jint {
    bridge().session_sas(session, flag(ok))
}

#[no_mangle]
pub extern "system" fn Java_io_github_h4lovoid_dialcrypt_core_NativeBridge_nativeSessionVoiceWindow<'l>(
    _env: JNIEnv<'l>,
    _this: JObject<'l>,
    session: jlong,
    open: jboolean,
) -> jint {
    bridge().session_voice_window(session, flag(open))
}

#[no_mangle]
pub extern "system" fn Java_io_github_h4lovoid_dialcrypt_core_NativeBridge_nativeSessionSaveContact<'l>(
    env: JNIEnv<'l>,
    _this: JObject<'l>,
    session: jlong,
    contact_id: jint,
    label_utf8: JByteArray<'l>,
    phone_e164_utf8: NullableByteArray<'l>,
) -> jint {
    res((|| {
        let label = bytes_max(&env, &label_utf8, MAX_LABEL_BYTES)?;
        let phone = opt_bytes(&env, &phone_e164_utf8, MAX_PHONE_LEN)?;
        Ok(bridge().session_save_contact(session, contact_id, &label, slice(&phone)))
    })())
}

#[no_mangle]
pub extern "system" fn Java_io_github_h4lovoid_dialcrypt_core_NativeBridge_nativeSessionBearerViolation<'l>(
    _env: JNIEnv<'l>,
    _this: JObject<'l>,
    session: jlong,
    code: jint,
) -> jint {
    bridge().session_bearer_violation(session, code)
}

#[no_mangle]
pub extern "system" fn Java_io_github_h4lovoid_dialcrypt_core_NativeBridge_nativeSessionSendText<'l>(
    env: JNIEnv<'l>,
    _this: JObject<'l>,
    session: jlong,
    text_utf8: JByteArray<'l>,
    burn_ttl_secs: jint,
    now_ms: jlong,
) -> jint {
    res(bytes_max(&env, &text_utf8, MAX_TEXT_LEN)
        .map(|t| bridge().session_send_text(session, &t, burn_ttl_secs, now_ms)))
}

#[no_mangle]
pub extern "system" fn Java_io_github_h4lovoid_dialcrypt_core_NativeBridge_nativeSessionSendQuick<'l>(
    _env: JNIEnv<'l>,
    _this: JObject<'l>,
    session: jlong,
    quick_code: jint,
    lat_e6: jint,
    lon_e6: jint,
    now_ms: jlong,
) -> jint {
    bridge().session_send_quick(session, quick_code, lat_e6, lon_e6, now_ms)
}

#[no_mangle]
pub extern "system" fn Java_io_github_h4lovoid_dialcrypt_core_NativeBridge_nativeSessionRequestRatchet<'l>(_env: JNIEnv<'l>, _this: JObject<'l>, session: jlong) -> jint {
    bridge().session_request_ratchet(session)
}

#[no_mangle]
pub extern "system" fn Java_io_github_h4lovoid_dialcrypt_core_NativeBridge_nativeSessionClose<'l>(
    _env: JNIEnv<'l>,
    _this: JObject<'l>,
    session: jlong,
    notify_peer: jboolean,
) -> jint {
    bridge().session_close(session, flag(notify_peer))
}

#[no_mangle]
pub extern "system" fn Java_io_github_h4lovoid_dialcrypt_core_NativeBridge_nativePanicWipe<'l>(_env: JNIEnv<'l>, _this: JObject<'l>, app: jlong) -> jint {
    bridge().panic_wipe(app)
}

#[no_mangle]
pub extern "system" fn Java_io_github_h4lovoid_dialcrypt_core_NativeBridge_nativeAppClose<'l>(_env: JNIEnv<'l>, _this: JObject<'l>, app: jlong) -> jint {
    bridge().app_close(app)
}
