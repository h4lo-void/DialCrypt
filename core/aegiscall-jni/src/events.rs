//! Event TLV returned by `nativeSessionPollEvents`: records `type u8 · len u16 BE · value`
//! back to back (§2.D). Integers are big-endian. The type numbers are mirrored in the comment
//! block of NativeBridge.kt.

/// req_id u32 · message to sign with SHA256withECDSA on the identity key.
pub const EV_NEED_SIGNATURE: u8 = 1;
/// Five raw SAS bytes (full path); the app maps them to words.
pub const EV_SAS: u8 = 2;
/// path u8 (0 full, 1 resume) · used_new u8 · contact u32 (0 on the full path).
pub const EV_PATH: u8 = 3;
/// Percent u8.
pub const EV_HS_PROGRESS: u8 = 4;
/// role u8 (0 initiator, 1 responder) · path u8 · used_new u8 · path contact u32 ·
/// identity u8 (0 unverified, 1 SAS verified, 2 known contact, 3 key changed) ·
/// psk contact u32 · stored contact u32 (0 none) · peer pub33.
pub const EV_ESTABLISHED: u8 = 5;
/// stored pub33 · peer pub33. Sending stays locked until both sides confirm the SAS.
pub const EV_KEY_CHANGED: u8 = 6;
/// Both sides confirmed the SAS (empty).
pub const EV_SAS_CONFIRMED: u8 = 7;
/// open u8.
pub const EV_VOICE_WINDOW: u8 = 8;
/// Percent u8.
pub const EV_PQ_PROGRESS: u8 = 9;
/// epoch u32.
pub const EV_PQ_MIXED: u8 = 10;
/// epoch u32.
pub const EV_EPOCH: u8 = 11;
/// seq u32: write nativeVaultExport() atomically (rotate first if it returns null), fsync,
/// then call nativeVaultSaved(app, seq).
pub const EV_VAULT_DIRTY: u8 = 12;
/// result i8 (0 ok, else a return code) · boot u8 (0 verified, 1 self-signed, 2 unlocked) ·
/// os_patch u32 · stored u8 (1 when written to the contact).
pub const EV_ATTESTATION: u8 = 14;
/// msg_id u16 · UTF-8 text.
pub const EV_MESSAGE_RECEIVED: u8 = 15;
/// msg_id u16.
pub const EV_MESSAGE_DELIVERED: u8 = 16;
/// msg_id u16.
pub const EV_MESSAGE_FAILED: u8 = 17;
/// The peer wiped both ends (empty).
pub const EV_REMOTE_WIPE: u8 = 18;
/// Our panic wipe frames went out (empty).
pub const EV_WIPE_SENT: u8 = 19;
/// by_peer u8.
pub const EV_ENDED: u8 = 20;
/// Abort reason u8 (aegiscall_chat::AbortReason codes 1-26).
pub const EV_ABORTED: u8 = 21;
/// msg_id u16 · acked u16 · total u16 (shards of an outgoing message confirmed by the peer).
pub const EV_MESSAGE_PROGRESS: u8 = 22;
/// Vault update for the resume secret failed: code i8.
pub const EV_VAULT_FAILED: u8 = 32;

/// Appends one record; false when the value does not fit a u16 length.
pub fn encode_tlv(out: &mut Vec<u8>, t: u8, v: &[u8]) -> bool {
    let Ok(n) = u16::try_from(v.len()) else { return false };
    out.push(t);
    out.extend_from_slice(&n.to_be_bytes());
    out.extend_from_slice(v);
    true
}

/// Splits a TLV buffer; None when a record is truncated.
pub fn decode_tlv(mut b: &[u8]) -> Option<Vec<(u8, &[u8])>> {
    let mut out = Vec::new();
    while !b.is_empty() {
        let t = *b.first()?;
        let n = usize::from(u16::from_be_bytes([*b.get(1)?, *b.get(2)?]));
        out.push((t, b.get(3..3 + n)?));
        b = b.get(3 + n..)?;
    }
    Some(out)
}
