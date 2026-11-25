//! PIN vault (design 6.5 / 6.6).
//!
//! File layout (big-endian, every byte authenticated):
//!
//! ```text
//! 0   magic "AGVT"(4) · format(1)=1 · kdf(1)=1 Argon2id v1.3 · m_kib(4) · t(4) · p(4)
//! 18  salt(16) · file_id(16) · ticket_count(1)=5
//! 51  5 × [ticket_id(4) · wrap_lo(49) · wrap_hi(49)]      wraps sorted by bytes
//! 561 body_seq(8) · body_len(4)
//! 573 body = ChaCha20-Poly1305(body_key, 0^4‖seq, aad = bytes[0..573],
//!            content_len(4) ‖ content ‖ zero padding)
//! total length = 573 + body_len, a multiple of 4096
//! ```
//!
//! wrap = ChaCha20-Poly1305(HKDF(salt=file_id, HMAC_t(P)‖P, "AegisVault-v2 wrap"‖id), 0^12,
//! aad = bytes[0..51] ‖ all ticket ids ‖ id, 0x01‖K_root  or  0x02‖random).
//! Each wrap key encrypts exactly one message, so the fixed nonce is never reused.
//!
//! The content stores the duress stretch only (design 6.5). The normal stretch `P` is never
//! written to the file: it lives in the unlocked [`Vault`] so rotation can re-wrap, and is
//! wiped by [`Vault::wipe`] and on drop.
//!
//! The content also holds the random meta key that seals the app's contact metadata file
//! (`contact_meta.bin`, see [`Vault::meta_seal`]); it never leaves this crate and survives
//! every rotation.

use crate::attest::{AttestationVerdict, BootState, SecLevel};
use crate::error::TrustError;
use aegiscall_memsec::SecretKey32;
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, XChaCha20Poly1305, XNonce};
use core::fmt;
use hmac::{Hmac, Mac};
use rand_core::CryptoRngCore;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

type HmacSha256 = Hmac<Sha256>;

const MAGIC: [u8; 4] = *b"AGVT";
const FORMAT_VERSION: u8 = 1;
const KDF_ARGON2ID_V13: u8 = 1;
/// Content with a meta key (written).
const CONTENT_VERSION: u8 = 2;
/// Content without a meta key (read only; the key is derived on load).
const CONTENT_VERSION_NO_META: u8 = 1;
/// One-time tickets referenced by every vault file.
pub const TICKETS_PER_VAULT: usize = 5;
/// Wrong current PINs accepted by [`Vault::change_pins`] in one unlock; the last one locks the vault.
pub(crate) const MAX_WRONG_CURRENT_PINS: u8 = 3;
const TAG_LEN: usize = 16;
const WRAP_PT_LEN: usize = 33;
const WRAP_LEN: usize = WRAP_PT_LEN + TAG_LEN;
const TICKET_REC_LEN: usize = 4 + 2 * WRAP_LEN;
const FIXED_HDR_LEN: usize = 51;
const TICKETS_END: usize = FIXED_HDR_LEN + TICKETS_PER_VAULT * TICKET_REC_LEN;
const BODY_HDR_END: usize = TICKETS_END + 12;
/// Vault files are padded to a multiple of this many bytes.
pub const VAULT_PAD_BLOCK: usize = 4096;
/// Largest accepted vault file.
pub const MAX_VAULT_LEN: usize = 1 << 20;
/// Shortest accepted PIN (bytes).
pub const MIN_PIN_LEN: usize = 4;
/// Longest accepted PIN (bytes).
pub const MAX_PIN_LEN: usize = 128;
/// Maximum number of contacts.
pub const MAX_CONTACTS: usize = 1000;
/// Maximum label length (UTF-8 bytes).
pub const MAX_LABEL_LEN: usize = 64;
const MAX_BOOT_KEY_LEN: usize = 64;
const WRAP_NORMAL: u8 = 0x01;
const WRAP_DURESS: u8 = 0x02;
const ZERO_NONCE: [u8; 12] = [0; 12];
const CONTENT_FIXED_LEN: usize = 1 + 3 * 32 + 4 + 4 + 2;
/// Format byte of a sealed contact metadata blob.
const META_FORMAT: u8 = 1;
const META_NONCE_LEN: usize = 24;
const META_AAD: &[u8] = b"AegisMeta-v1 contact metadata";
/// [`Vault::stretch_binding`]: label, and the header bytes it covers (magic through salt).
const STRETCH_ID_LABEL: &[u8] = b"AegisVault-v2 stretch id";
const STRETCH_ID_LEN: usize = 34;
/// Maximum consecutive fast-resume calls permitted without completing a fresh ML-KEM-1024
/// exchange (`k = 2` background refresh or a full handshake). Once reached, `expectation_for`
/// withholds resume secrets for that contact so the next call runs a full PQC handshake.
pub const MAX_UNREFRESHED_RESUMES: u8 = 3;
const CONTACT_MAX_LEN: usize =
    4 + 33 + 1 + 1 + MAX_LABEL_LEN + 32 + 16 + 32 + 33 + 1 + (1 + 1 + 1 + MAX_BOOT_KEY_LEN + 4 + 16);
const F_PSK: u8 = 1 << 0;
const F_SAS: u8 = 1 << 1;
const F_PHONE: u8 = 1 << 2;
const F_RS_CUR: u8 = 1 << 3;
const F_RS_NEW: u8 = 1 << 4;
const F_ATTEST: u8 = 1 << 5;
const F_RESUME_AGE: u8 = 1 << 6;
const F_ALL: u8 = F_PSK | F_SAS | F_PHONE | F_RS_CUR | F_RS_NEW | F_ATTEST | F_RESUME_AGE;

/// Argon2id cost parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory in KiB.
    pub m_kib: u32,
    /// Iterations.
    pub t_cost: u32,
    /// Lanes.
    pub p_lanes: u32,
}

/// Production parameters (design A): 64 MiB, t=3, p=1, 32-byte output.
pub const ARGON2ID_PARAMS: KdfParams = KdfParams { m_kib: 64 * 1024, t_cost: 3, p_lanes: 1 };

#[cfg(test)]
pub(crate) const TEST_KDF_PARAMS: KdfParams = KdfParams { m_kib: 8, t_cost: 1, p_lanes: 1 };

#[cfg(not(test))]
const fn active_kdf() -> KdfParams {
    ARGON2ID_PARAMS
}

#[cfg(test)]
const fn active_kdf() -> KdfParams {
    TEST_KDF_PARAMS
}

pub(crate) fn stretch(params: KdfParams, pin: &[u8], salt: &[u8; 16]) -> Result<SecretKey32, TrustError> {
    let p = Params::new(params.m_kib, params.t_cost, params.p_lanes, Some(32)).map_err(|_| TrustError::Crypto)?;
    let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    let mut out = SecretKey32::from_bytes([0u8; 32]);
    a.hash_password_into(pin, salt, &mut out.0).map_err(|_| TrustError::Crypto)?;
    Ok(out)
}

fn check_pin(pin: &[u8]) -> Result<(), TrustError> {
    if (MIN_PIN_LEN..=MAX_PIN_LEN).contains(&pin.len()) {
        Ok(())
    } else {
        Err(TrustError::InvalidPin)
    }
}

/// Lowest ticket of the file that is still in the key store.
fn first_live_ticket(parsed: &Parsed<'_>, live: &[u32]) -> Result<u32, TrustError> {
    parsed.tickets.iter().map(|t| t.id).find(|id| live.contains(id)).ok_or(TrustError::VaultDead)
}

fn random_key(rng: &mut impl CryptoRngCore) -> SecretKey32 {
    let mut k = SecretKey32::from_bytes([0u8; 32]);
    rng.fill_bytes(&mut k.0);
    k
}

/// HMAC-SHA256. The tag temporary is wiped once it is copied into the zeroizing wrapper.
fn hmac32(key: &[u8], parts: &[&[u8]]) -> Result<SecretKey32, TrustError> {
    let mut mac = <HmacSha256 as hmac::KeyInit>::new_from_slice(key).map_err(|_| TrustError::Crypto)?;
    for p in parts {
        mac.update(p);
    }
    let mut tag = mac.finalize().into_bytes();
    let mut out = SecretKey32::from_bytes([0u8; 32]);
    out.0.copy_from_slice(tag.as_slice());
    tag.as_mut_slice().zeroize();
    Ok(out)
}

/// HKDF-SHA256 (RFC 5869) with a 32-byte output: `T(1) = HMAC(PRK, info ‖ 0x01)`. Built on
/// [`hmac32`] so the PRK and the output block only ever sit in zeroizing wrappers.
fn hkdf32(salt: &[u8], ikm: &[u8], info: &[&[u8]]) -> Result<SecretKey32, TrustError> {
    let prk = hmac32(salt, &[ikm])?;
    let mut parts: Vec<&[u8]> = Vec::with_capacity(info.len() + 1);
    parts.extend_from_slice(info);
    parts.push(&[0x01]);
    hmac32(prk.as_bytes(), &parts)
}

/// Wrap key of ticket `ticket_id`. The stretch `p` is mixed in next to `HMAC_t(p)`, so a
/// wrap only opens when the stretch handed to `finish_unlock` is the one the HMAC was
/// computed over; a mismatched stretch can therefore never be kept for a later rotation.
fn wrap_key(hmac_out: &[u8; 32], p: &SecretKey32, file_id: &[u8; 16], ticket_id: u32) -> Result<SecretKey32, TrustError> {
    let mut ikm = Zeroizing::new([0u8; 64]);
    let (head, tail) = ikm.split_at_mut(32);
    head.copy_from_slice(hmac_out);
    tail.copy_from_slice(p.as_bytes());
    hkdf32(file_id, &ikm[..], &[b"AegisVault-v2 wrap", &ticket_id.to_be_bytes()])
}

fn body_key(k_root: &SecretKey32, file_id: &[u8; 16]) -> Result<SecretKey32, TrustError> {
    hkdf32(file_id, k_root.as_bytes(), &[b"AegisVault-v2 body"])
}

fn body_nonce(seq: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&seq.to_be_bytes());
    n
}

fn aead_seal(key: &SecretKey32, nonce: &[u8; 12], aad: &[u8], pt: &[u8]) -> Result<Vec<u8>, TrustError> {
    let c = ChaCha20Poly1305::new(Key::from_slice(key.as_bytes()));
    c.encrypt(Nonce::from_slice(nonce), Payload { msg: pt, aad }).map_err(|_| TrustError::Crypto)
}

fn aead_open(key: &SecretKey32, nonce: &[u8; 12], aad: &[u8], ct: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let c = ChaCha20Poly1305::new(Key::from_slice(key.as_bytes()));
    c.decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad }).ok().map(Zeroizing::new)
}

fn round_up_block(n: usize) -> Option<usize> {
    n.checked_add(VAULT_PAD_BLOCK - 1).map(|x| x / VAULT_PAD_BLOCK * VAULT_PAD_BLOCK)
}

fn valid_e164(n: &[u8]) -> bool {
    match n.split_first() {
        Some((b'+', digits)) => {
            (2..=15).contains(&digits.len())
                && digits.first().is_some_and(|d| (b'1'..=b'9').contains(d))
                && digits.iter().all(u8::is_ascii_digit)
        }
        _ => false,
    }
}

fn validate_pub33(p: &[u8; 33]) -> Result<(), TrustError> {
    if !matches!(p.first(), Some(0x02 | 0x03)) {
        return Err(TrustError::InvalidPub33);
    }
    p256::PublicKey::from_sec1_bytes(p).map(|_| ()).map_err(|_| TrustError::InvalidPub33)
}

fn validate_label(l: &str) -> Result<(), TrustError> {
    if l.len() <= MAX_LABEL_LEN {
        Ok(())
    } else {
        Err(TrustError::InvalidLabel)
    }
}

fn validate_attestation(a: &AttestationVerdict) -> Result<(), TrustError> {
    match &a.boot {
        BootState::SelfSigned { key } if key.is_empty() || key.len() > MAX_BOOT_KEY_LEN => {
            Err(TrustError::InvalidAttestation)
        }
        _ => Ok(()),
    }
}

fn ct_eq_bool(a: &[u8], b: &[u8]) -> bool {
    bool::from(a.ct_eq(b))
}

// ---------------------------------------------------------------- file parsing

struct TicketRec<'a> {
    id: u32,
    wraps: [&'a [u8]; 2],
}

pub(crate) struct Parsed<'a> {
    kdf: KdfParams,
    salt: [u8; 16],
    file_id: [u8; 16],
    tickets: Vec<TicketRec<'a>>,
    seq: u64,
    blob: &'a [u8],
}

fn slice(b: &[u8], start: usize, len: usize) -> Result<&[u8], TrustError> {
    let end = start.checked_add(len).ok_or(TrustError::VaultMalformed)?;
    b.get(start..end).ok_or(TrustError::VaultMalformed)
}

fn arr<const N: usize>(b: &[u8], start: usize) -> Result<[u8; N], TrustError> {
    <[u8; N]>::try_from(slice(b, start, N)?).map_err(|_| TrustError::VaultMalformed)
}

fn be32(b: &[u8], start: usize) -> Result<u32, TrustError> {
    Ok(u32::from_be_bytes(arr::<4>(b, start)?))
}

pub(crate) fn parse(blob: &[u8]) -> Result<Parsed<'_>, TrustError> {
    let mal = TrustError::VaultMalformed;
    if blob.len() < VAULT_PAD_BLOCK || blob.len() > MAX_VAULT_LEN || blob.len() % VAULT_PAD_BLOCK != 0 {
        return Err(mal);
    }
    if arr::<4>(blob, 0)? != MAGIC {
        return Err(mal);
    }
    if arr::<1>(blob, 4)? != [FORMAT_VERSION] || arr::<1>(blob, 5)? != [KDF_ARGON2ID_V13] {
        return Err(TrustError::UnsupportedVersion);
    }
    let kdf = KdfParams { m_kib: be32(blob, 6)?, t_cost: be32(blob, 10)?, p_lanes: be32(blob, 14)? };
    if kdf != active_kdf() {
        return Err(mal);
    }
    let salt = arr::<16>(blob, 18)?;
    let file_id = arr::<16>(blob, 34)?;
    if arr::<1>(blob, 50)? != [TICKETS_PER_VAULT as u8] {
        return Err(mal);
    }
    let mut tickets = Vec::with_capacity(TICKETS_PER_VAULT);
    let mut prev = 0u32;
    for i in 0..TICKETS_PER_VAULT {
        let off = FIXED_HDR_LEN + i * TICKET_REC_LEN;
        let id = be32(blob, off)?;
        let a = slice(blob, off + 4, WRAP_LEN)?;
        let b = slice(blob, off + 4 + WRAP_LEN, WRAP_LEN)?;
        if id <= prev || id == u32::MAX || a >= b {
            return Err(mal);
        }
        prev = id;
        tickets.push(TicketRec { id, wraps: [a, b] });
    }
    let seq = u64::from_be_bytes(arr::<8>(blob, TICKETS_END)?);
    let body_len = usize::try_from(be32(blob, TICKETS_END + 8)?).map_err(|_| mal)?;
    if body_len != blob.len() - BODY_HDR_END {
        return Err(mal);
    }
    Ok(Parsed { kdf, salt, file_id, tickets, seq, blob })
}

impl Parsed<'_> {
    fn ids(&self) -> Vec<u32> {
        self.tickets.iter().map(|t| t.id).collect()
    }

    fn wrap_aad(&self, ticket_id: u32) -> Vec<u8> {
        let mut aad = Vec::with_capacity(FIXED_HDR_LEN + 4 * (TICKETS_PER_VAULT + 1));
        aad.extend_from_slice(self.blob.get(..FIXED_HDR_LEN).unwrap_or(&[]));
        for t in &self.tickets {
            aad.extend_from_slice(&t.id.to_be_bytes());
        }
        aad.extend_from_slice(&ticket_id.to_be_bytes());
        aad
    }
}

// ---------------------------------------------------------------- content

struct Contact {
    id: u32,
    pub33: [u8; 33],
    label: Zeroizing<String>,
    phone_tag: Option<[u8; 16]>,
    psk: Option<SecretKey32>,
    sas_verified: bool,
    attestation: Option<AttestationVerdict>,
    rs_cur: Option<SecretKey32>,
    rs_new: Option<(SecretKey32, u8)>,
    unrefreshed_resumes: u8,
}

impl Drop for Contact {
    fn drop(&mut self) {
        self.pub33.zeroize();
        if let Some(t) = self.phone_tag.as_mut() {
            t.zeroize();
        }
    }
}

impl Contact {
    fn duplicate(&self) -> Contact {
        Contact {
            id: self.id,
            pub33: self.pub33,
            label: self.label.clone(),
            phone_tag: self.phone_tag,
            psk: self.psk.clone(),
            sas_verified: self.sas_verified,
            attestation: self.attestation.clone(),
            rs_cur: self.rs_cur.clone(),
            rs_new: self.rs_new.as_ref().map(|(k, n)| (k.clone(), *n)),
            unrefreshed_resumes: self.unrefreshed_resumes,
        }
    }
}

/// Opaque copy of one contact, secrets included, wiped like the contact when dropped.
pub struct ContactSnapshot(Contact);

/// Encrypted vault content. Of the two PIN stretches only the duress one is stored.
struct Content {
    p_duress: SecretKey32,
    phone_key: SecretKey32,
    /// Seals `contact_meta.bin`. Random at creation; unchanged by rotations.
    meta_key: SecretKey32,
    next_ticket_id: u32,
    next_contact_id: u32,
    contacts: Vec<Contact>,
}

struct Cur<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Cur<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], TrustError> {
        let s = slice(self.b, self.pos, n)?;
        self.pos += n;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, TrustError> {
        Ok(arr::<1>(self.take(1)?, 0)?[0])
    }
    fn u16(&mut self) -> Result<u16, TrustError> {
        Ok(u16::from_be_bytes(arr::<2>(self.take(2)?, 0)?))
    }
    fn u32(&mut self) -> Result<u32, TrustError> {
        be32(self.take(4)?, 0)
    }
    fn key(&mut self) -> Result<SecretKey32, TrustError> {
        let mut k = SecretKey32::from_bytes([0u8; 32]);
        k.0.copy_from_slice(self.take(32)?);
        Ok(k)
    }
}

fn boot_code(b: &BootState) -> u8 {
    match b {
        BootState::Verified => 0,
        BootState::SelfSigned { .. } => 1,
        BootState::Unlocked => 2,
    }
}

impl Contact {
    fn encode(&self, o: &mut Vec<u8>) -> Result<(), TrustError> {
        o.extend_from_slice(&self.id.to_be_bytes());
        o.extend_from_slice(&self.pub33);
        let mut flags = 0u8;
        if self.psk.is_some() {
            flags |= F_PSK;
        }
        if self.sas_verified {
            flags |= F_SAS;
        }
        if self.phone_tag.is_some() {
            flags |= F_PHONE;
        }
        if self.rs_cur.is_some() {
            flags |= F_RS_CUR;
        }
        if self.rs_new.is_some() {
            flags |= F_RS_NEW;
        }
        if self.attestation.is_some() {
            flags |= F_ATTEST;
        }
        if self.unrefreshed_resumes > 0 {
            flags |= F_RESUME_AGE;
        }
        o.push(flags);
        o.push(u8::try_from(self.label.len()).map_err(|_| TrustError::InvalidLabel)?);
        o.extend_from_slice(self.label.as_bytes());
        if let Some(p) = &self.psk {
            o.extend_from_slice(p.as_bytes());
        }
        if let Some(t) = &self.phone_tag {
            o.extend_from_slice(t);
        }
        if let Some(r) = &self.rs_cur {
            o.extend_from_slice(r.as_bytes());
        }
        if let Some((r, k)) = &self.rs_new {
            o.extend_from_slice(r.as_bytes());
            o.push(*k);
        }
        if self.unrefreshed_resumes > 0 {
            o.push(self.unrefreshed_resumes);
        }
        if let Some(a) = &self.attestation {
            o.push(1);
            o.push(boot_code(&a.boot));
            match &a.boot {
                BootState::SelfSigned { key } => {
                    o.push(u8::try_from(key.len()).map_err(|_| TrustError::InvalidAttestation)?);
                    o.extend_from_slice(key);
                }
                _ => o.push(0),
            }
            o.extend_from_slice(&a.os_patch.to_be_bytes());
            o.extend_from_slice(&a.evidence_id);
        }
        Ok(())
    }

    fn decode(c: &mut Cur<'_>) -> Result<Contact, TrustError> {
        let mal = TrustError::VaultMalformed;
        let id = c.u32()?;
        let pub33 = arr::<33>(c.take(33)?, 0)?;
        validate_pub33(&pub33).map_err(|_| mal)?;
        let flags = c.u8()?;
        if flags & !F_ALL != 0 {
            return Err(mal);
        }
        let ll = usize::from(c.u8()?);
        if ll > MAX_LABEL_LEN {
            return Err(mal);
        }
        let label = core::str::from_utf8(c.take(ll)?).map_err(|_| mal)?;
        let label = Zeroizing::new(label.to_owned());
        let psk = if flags & F_PSK != 0 { Some(c.key()?) } else { None };
        let phone_tag = if flags & F_PHONE != 0 { Some(arr::<16>(c.take(16)?, 0)?) } else { None };
        let rs_cur = if flags & F_RS_CUR != 0 { Some(c.key()?) } else { None };
        let rs_new = if flags & F_RS_NEW != 0 {
            let r = c.key()?;
            let k = c.u8()?;
            if k == 0 {
                return Err(mal);
            }
            Some((r, k))
        } else {
            None
        };
        let unrefreshed_resumes = if flags & F_RESUME_AGE != 0 {
            let age = c.u8()?;
            if age == 0 {
                return Err(mal);
            }
            age
        } else {
            0
        };
        let attestation = if flags & F_ATTEST != 0 {
            if c.u8()? != 1 {
                return Err(mal);
            }
            let code = c.u8()?;
            let klen = usize::from(c.u8()?);
            let boot = match (code, klen) {
                (0, 0) => BootState::Verified,
                (2, 0) => BootState::Unlocked,
                (1, 1..=MAX_BOOT_KEY_LEN) => BootState::SelfSigned { key: c.take(klen)?.to_vec() },
                _ => return Err(mal),
            };
            let os_patch = c.u32()?;
            let evidence_id = arr::<16>(c.take(16)?, 0)?;
            Some(AttestationVerdict { level: SecLevel::StrongBox, boot, os_patch, evidence_id })
        } else {
            None
        };
        Ok(Contact {
            id,
            pub33,
            label,
            phone_tag,
            psk,
            sas_verified: flags & F_SAS != 0,
            attestation,
            rs_cur,
            rs_new,
            unrefreshed_resumes,
        })
    }
}

impl Content {
    fn encode(&self) -> Result<Zeroizing<Vec<u8>>, TrustError> {
        let cap = CONTENT_FIXED_LEN + self.contacts.len() * CONTACT_MAX_LEN;
        let mut o = Zeroizing::new(Vec::with_capacity(cap));
        o.push(CONTENT_VERSION);
        o.extend_from_slice(self.p_duress.as_bytes());
        o.extend_from_slice(self.phone_key.as_bytes());
        o.extend_from_slice(self.meta_key.as_bytes());
        o.extend_from_slice(&self.next_ticket_id.to_be_bytes());
        o.extend_from_slice(&self.next_contact_id.to_be_bytes());
        let n = u16::try_from(self.contacts.len()).map_err(|_| TrustError::CapacityExceeded)?;
        o.extend_from_slice(&n.to_be_bytes());
        for c in &self.contacts {
            c.encode(&mut o)?;
        }
        Ok(o)
    }

    fn decode_padded(pt: &[u8]) -> Result<Content, TrustError> {
        let mal = TrustError::VaultMalformed;
        let len = usize::try_from(be32(pt, 0)?).map_err(|_| mal)?;
        let body = slice(pt, 4, len)?;
        let pad = pt.get(4 + len..).ok_or(mal)?;
        if pad.iter().any(|b| *b != 0) {
            return Err(mal);
        }
        let mut c = Cur { b: body, pos: 0 };
        let version = c.u8()?;
        if version != CONTENT_VERSION && version != CONTENT_VERSION_NO_META {
            return Err(TrustError::UnsupportedVersion);
        }
        let p_duress = c.key()?;
        let phone_key = c.key()?;
        let meta_key = if version == CONTENT_VERSION {
            c.key()?
        } else {
            // Older content has no meta key. Derive one from the random phone key so every
            // unlock of that content yields the same key; the next write stores it.
            hkdf32(b"AegisVault-v2 meta upgrade", phone_key.as_bytes(), &[b"AegisMeta-v1 key"])?
        };
        let next_ticket_id = c.u32()?;
        let next_contact_id = c.u32()?;
        let n = usize::from(c.u16()?);
        if n > MAX_CONTACTS {
            return Err(mal);
        }
        let mut contacts: Vec<Contact> = Vec::with_capacity(n);
        for _ in 0..n {
            let ct = Contact::decode(&mut c)?;
            let dup = contacts.iter().any(|x| {
                x.id == ct.id
                    || ct_eq_bool(&x.pub33, &ct.pub33)
                    || matches!((&x.phone_tag, &ct.phone_tag), (Some(a), Some(b)) if ct_eq_bool(a, b))
            });
            if dup || ct.id == 0 || ct.id >= next_contact_id {
                return Err(mal);
            }
            contacts.push(ct);
        }
        if c.pos != body.len() {
            return Err(mal);
        }
        Ok(Content { p_duress, phone_key, meta_key, next_ticket_id, next_contact_id, contacts })
    }
}

// ---------------------------------------------------------------- public types

/// New ticket material for the app to import into StrongBox (`aegis_pin_t<id>`,
/// single use), and old ticket ids to use once and delete after the new file is durable.
///
/// This value owns the only copy of the material: the vault computed the wraps inside
/// `begin_rotation` and kept none of it. Drop it as soon as the import data has been handed
/// over; dropping wipes every key.
pub struct Rotation {
    /// (ticket id, 32-byte HMAC key material). Zeroized on drop.
    pub new: Vec<(u32, SecretKey32)>,
    /// Tickets of the previous file.
    pub retire: Vec<u32>,
}

/// Ticket to consume: the app computes `HMAC_t(hmac_input)` with StrongBox key `ticket_id`
/// and then passes this value on to [`Vault::finish_unlock`].
pub struct TicketUse {
    /// Ticket id.
    pub ticket_id: u32,
    /// Argon2id(PIN, salt).
    pub hmac_input: SecretKey32,
}

/// Result of [`Vault::finish_unlock`].
#[derive(Debug)]
pub enum UnlockOutcome {
    /// Normal PIN. The vault must be rotated before it can be exported.
    Normal(Box<Vault>),
    /// Duress PIN. Carries nothing: the app destroys all tickets and the identity key,
    /// overwrites the file with [`duress_overwrite`] and exits.
    Duress,
    /// Wrong PIN or unusable ticket; `left` unused tickets remain.
    Invalid {
        /// Unused tickets left.
        left: usize,
    },
    /// No unused ticket left: the vault is permanently unopenable.
    Dead,
    /// The file failed structural parsing.
    Malformed,
    /// `live` still lists the ticket of this attempt: StrongBox has not consumed it.
    /// Nothing was decrypted.
    TicketNotConsumed,
}

/// Phone number decision made by the user when saving a contact (design 6.2).
pub enum PhoneChoice {
    /// Caller ID confirmed or corrected by the user (E.164).
    UserConfirmed(Vec<u8>),
    /// Store no number (hidden caller ID or user choice).
    NoNumber,
}

/// Why a contact identity may be saved or changed (design A / 6.2).
pub enum ContactProof {
    /// Both sides pressed "SAS matches" in this call.
    SasMatchedThisCall,
    /// Imported pairing code carrying this PSK.
    Paired(SecretKey32),
}

/// Input to [`Vault::add_contact`].
pub struct NewContact {
    /// Peer identity key (compressed P-256).
    pub pub33: [u8; 33],
    /// Display label.
    pub label: String,
    /// Phone number decision.
    pub phone: PhoneChoice,
    /// Proof.
    pub proof: ContactProof,
}

/// Read-only contact view without secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactView {
    /// Contact id.
    pub id: u32,
    /// Identity key.
    pub pub33: [u8; 33],
    /// Label.
    pub label: String,
    /// Phone tag if a number is stored.
    pub phone_tag: Option<[u8; 16]>,
    /// Contact has a PSK.
    pub has_psk: bool,
    /// SAS verified flag.
    pub sas_verified: bool,
    /// Stored attestation verdict.
    pub attestation: Option<AttestationVerdict>,
    /// Resume secrets present (cur, new).
    pub resume: (bool, bool),
}

/// Resume secret handed to the handshake.
pub struct ResumeCandidate {
    /// Contact id.
    pub contact: u32,
    /// Pinned identity key.
    pub pub33: [u8; 33],
    /// Secret.
    pub secret: SecretKey32,
    /// True for `rs_new`.
    pub is_new: bool,
}

/// Everything the handshake needs from the vault (adapter to aegiscall-crypto lives elsewhere).
pub struct PeerExpectation {
    /// (contact, pub33, psk) for every PSK contact.
    pub psk: Vec<(u32, [u8; 33], SecretKey32)>,
    /// Resume candidates.
    pub resume: Vec<ResumeCandidate>,
}

/// Equal-length random bytes for overwriting the vault file on duress.
pub fn duress_overwrite(len: usize, rng: &mut impl CryptoRngCore) -> Vec<u8> {
    let mut v = vec![0u8; len];
    rng.fill_bytes(&mut v);
    v
}

// ---------------------------------------------------------------- vault

/// A prepared rotation: new root key plus the finished file header with all wraps.
/// Holds no ticket material.
struct Pending {
    k_root: SecretKey32,
    file_id: [u8; 16],
    hdr: Vec<u8>,
    ids: Vec<u32>,
}

/// Staged PIN stretches from [`Vault::change_pins`], promoted atomically by [`Vault::commit_rotation`]
/// or discarded by [`Vault::abort_rotation`].
struct StagedPins {
    salt: [u8; 16],
    p_normal: SecretKey32,
    p_duress: SecretKey32,
    prev_rotation_required: bool,
}

impl Drop for StagedPins {
    fn drop(&mut self) {
        self.salt.zeroize();
    }
}

struct Committed {
    file_id: [u8; 16],
    hdr: Vec<u8>,
}

/// Unlocked vault.
///
/// # Call order contract
///
/// Unlock: [`Vault::begin_unlock`] → the app has StrongBox compute `HMAC_t(hmac_input)` with
/// ticket `ticket_id`, which consumes that key → [`Vault::finish_unlock`] with the same
/// [`TicketUse`] and the ticket ids still alive *after* that use. `finish_unlock` opens
/// nothing while that list still contains the ticket.
///
/// Rotation: [`Vault::begin_rotation`] → import every [`Rotation::new`] entry as a single-use
/// StrongBox key → drop the [`Rotation`] (wipes the material; the vault keeps none) →
/// [`Vault::commit_rotation`] → write the returned file atomically and fsync → use each
/// [`Rotation::retire`] ticket once and delete it.
pub struct Vault {
    k_root: SecretKey32,
    /// Argon2id(normal PIN, salt). Memory only; `None` once wiped.
    p_normal: Option<SecretKey32>,
    kdf: KdfParams,
    salt: [u8; 16],
    content: Content,
    tickets: Vec<u32>,
    committed: Option<Committed>,
    pending: Option<Pending>,
    staged_pins: Option<StagedPins>,
    rotation_required: bool,
    pad_to: usize,
    seq: u64,
    /// Set by [`Vault::cap_refill`] after an unlock with a kept stretch: how many tickets of
    /// every rotation of this unlocked vault are handed out for import. None: all of them.
    live_cap: Option<usize>,
    /// Wrong current PINs given to [`Vault::change_pins`] since this vault was unlocked.
    wrong_current: u8,
}

impl Drop for Vault {
    fn drop(&mut self) {
        self.wipe();
    }
}

impl fmt::Debug for Vault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Vault { .. }")
    }
}

impl Vault {
    /// Creates a vault. Returns the vault in "rotation pending" state and five tickets to
    /// import; call [`Vault::commit_rotation`] after the import to obtain the first file.
    pub fn create(pin: &[u8], duress: &[u8], rng: &mut impl CryptoRngCore) -> Result<(Self, Rotation), TrustError> {
        check_pin(pin)?;
        check_pin(duress)?;
        if ct_eq_bool(pin, duress) {
            return Err(TrustError::DuressEqualsPin);
        }
        let mut salt = [0u8; 16];
        rng.fill_bytes(&mut salt);
        let kdf = active_kdf();
        let content = Content {
            p_duress: stretch(kdf, duress, &salt)?,
            phone_key: random_key(rng),
            meta_key: random_key(rng),
            next_ticket_id: 1,
            next_contact_id: 1,
            contacts: Vec::new(),
        };
        let mut vault = Vault {
            k_root: random_key(rng),
            p_normal: Some(stretch(kdf, pin, &salt)?),
            kdf,
            salt,
            content,
            tickets: Vec::new(),
            committed: None,
            pending: None,
            staged_pins: None,
            rotation_required: true,
            pad_to: VAULT_PAD_BLOCK,
            seq: 0,
            live_cap: None,
            wrong_current: 0,
        };
        let rotation = vault.begin_rotation(rng)?;
        Ok((vault, rotation))
    }

    /// Ticket ids referenced by a vault file (to find orphans after an interrupted rotation).
    pub fn ticket_ids(blob: &[u8]) -> Result<Vec<u32>, TrustError> {
        Ok(parse(blob)?.ids())
    }

    /// Phase 1 of an unlock attempt. `live` lists ticket ids still present in StrongBox.
    /// Picks the lowest live ticket of this file.
    pub fn begin_unlock(blob: &[u8], pin: &[u8], live: &[u32]) -> Result<TicketUse, TrustError> {
        let parsed = parse(blob)?;
        check_pin(pin)?;
        let ticket_id = first_live_ticket(&parsed, live)?;
        let hmac_input = stretch(parsed.kdf, pin, &parsed.salt)?;
        Ok(TicketUse { ticket_id, hmac_input })
    }

    /// Phase 1 with the PIN stretch `p` already known (the app kept it under a fingerprint-bound
    /// key). Picks the same ticket as [`Vault::begin_unlock`]; phase 2 and every check after it
    /// are unchanged, so a stale or wrong `p` spends the ticket like a wrong PIN.
    pub fn begin_unlock_stretch(blob: &[u8], p: &SecretKey32, live: &[u32]) -> Result<TicketUse, TrustError> {
        let parsed = parse(blob)?;
        let ticket_id = first_live_ticket(&parsed, live)?;
        Ok(TicketUse { ticket_id, hmac_input: p.clone() })
    }

    /// Identifies the PIN stretch of a vault: SHA-256("AegisVault-v2 stretch id" ‖ bytes[0..34]),
    /// which covers the magic, format, KDF parameters and salt. Rotation keeps the salt, so every
    /// file of one vault gives the same value and a new vault another. A PIN change
    /// ([`Vault::change_pins`]) draws a new salt, so the files written after it give another value
    /// and a stretch kept for the old PIN no longer matches.
    pub fn stretch_binding(blob: &[u8]) -> Result<[u8; 32], TrustError> {
        parse(blob)?;
        let mut m = Vec::with_capacity(STRETCH_ID_LABEL.len() + STRETCH_ID_LEN);
        m.extend_from_slice(STRETCH_ID_LABEL);
        m.extend_from_slice(slice(blob, 0, STRETCH_ID_LEN)?);
        Ok(<Sha256 as sha2::Digest>::digest(&m).into())
    }

    /// Phase 2: `ticket` is the value returned by `begin_unlock`, `hmac_out` the StrongBox
    /// result (None if the key was consumed without producing one) and `live` the ticket ids
    /// still present *after* the use. If `live` still contains the ticket the call returns
    /// `TicketNotConsumed` without opening anything. The stretch is kept (in memory) only
    /// by a `Normal` vault; in every other case it is wiped before returning.
    pub fn finish_unlock(blob: &[u8], ticket: TicketUse, hmac_out: Option<&[u8; 32]>, live: &[u32]) -> UnlockOutcome {
        let Ok(parsed) = parse(blob) else {
            return UnlockOutcome::Malformed;
        };
        let TicketUse { ticket_id, hmac_input } = ticket;
        if live.contains(&ticket_id) {
            return UnlockOutcome::TicketNotConsumed;
        }
        let left = parsed.tickets.iter().filter(|t| live.contains(&t.id)).count();
        let failed = || if left == 0 { UnlockOutcome::Dead } else { UnlockOutcome::Invalid { left } };
        let (Some(out), Some(rec)) = (hmac_out, parsed.tickets.iter().find(|t| t.id == ticket_id)) else {
            return failed();
        };
        let Ok(key) = wrap_key(out, &hmac_input, &parsed.file_id, ticket_id) else {
            return failed();
        };
        let aad = parsed.wrap_aad(ticket_id);
        let first = aead_open(&key, &ZERO_NONCE, &aad, rec.wraps[0]);
        let second = aead_open(&key, &ZERO_NONCE, &aad, rec.wraps[1]);
        let Some(pt) = first.or(second) else {
            return failed();
        };
        if pt.len() != WRAP_PT_LEN {
            return failed();
        }
        match pt.first() {
            Some(&WRAP_NORMAL) => match Self::open_normal(&parsed, pt.get(1..).unwrap_or(&[]), hmac_input) {
                Ok(v) => UnlockOutcome::Normal(Box::new(v)),
                Err(_) => failed(),
            },
            Some(&WRAP_DURESS) => UnlockOutcome::Duress,
            _ => failed(),
        }
    }

    fn open_normal(parsed: &Parsed<'_>, k_bytes: &[u8], p_normal: SecretKey32) -> Result<Vault, TrustError> {
        let mal = TrustError::VaultMalformed;
        let mut k_root = SecretKey32::from_bytes([0u8; 32]);
        if k_bytes.len() != 32 {
            return Err(mal);
        }
        k_root.0.copy_from_slice(k_bytes);
        let key = body_key(&k_root, &parsed.file_id)?;
        let aad = parsed.blob.get(..BODY_HDR_END).ok_or(mal)?;
        let body = parsed.blob.get(BODY_HDR_END..).ok_or(mal)?;
        let pt = aead_open(&key, &body_nonce(parsed.seq), aad, body).ok_or(mal)?;
        let content = Content::decode_padded(&pt)?;
        let ids = parsed.ids();
        if ids.last().is_some_and(|m| content.next_ticket_id <= *m) {
            return Err(mal);
        }
        Ok(Vault {
            k_root,
            p_normal: Some(p_normal),
            kdf: parsed.kdf,
            salt: parsed.salt,
            content,
            tickets: ids,
            committed: None,
            pending: None,
            staged_pins: None,
            rotation_required: true,
            pad_to: parsed.blob.len(),
            seq: parsed.seq.saturating_add(1),
            live_cap: None,
            wrong_current: 0,
        })
    }

    /// After an unlock with a kept stretch (fingerprint answer): every rotation of this unlocked
    /// vault refills only the ticket that unlock spent. `live_after` lists the key-store tickets
    /// after that use; the cap is this file's live tickets among them plus one, so attempts
    /// spent on wrong PINs stay spent. The count comes from the single-use StrongBox keys, which
    /// nothing outside the vault can recreate. A PIN unlock opens the vault without the cap.
    pub fn cap_refill(&mut self, live_after: &[u32]) {
        let left = self.tickets.iter().filter(|t| live_after.contains(t)).count();
        self.live_cap = Some((left + 1).min(TICKETS_PER_VAULT));
    }

    /// Verifies `current` against the unlocked vault's normal PIN in constant time and stages
    /// fresh Argon2id stretches for `pin` and `duress` under a new random salt. Takes effect on
    /// the next [`Vault::begin_rotation`] + [`Vault::commit_rotation`]; rolled back cleanly by
    /// [`Vault::abort_rotation`] if StrongBox ticket import fails.
    ///
    /// Refused with `StretchUnlock` on a vault opened with a kept stretch ([`Vault::cap_refill`]):
    /// only a PIN unlock may change the PINs, so the rotation of a PIN change always hands out all
    /// TICKETS_PER_VAULT tickets. The current PIN spends no ticket, so it is limited here instead:
    /// the [`MAX_WRONG_CURRENT_PINS`]th wrong one in this unlock wipes (locks) the vault and returns
    /// `WrongCurrentPinLocked`; trying again needs a real unlock, which spends a ticket.
    ///
    /// `current` is checked first ([`Vault::refuse_pin_change`] runs the same check), before the
    /// stretch-unlock refusal and the new PINs, and compared with both stored stretches in constant
    /// time. The duress PIN acts as in a duress unlock: the vault wipes itself and returns
    /// `DuressPin`, whatever the new PINs, the refusal and the wrong-PIN count; up to that wipe it
    /// costs the same as a wrong PIN. A right current PIN with invalid new PINs is not counted.
    pub fn change_pins(
        &mut self,
        current: &[u8],
        pin: &[u8],
        duress: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<(), TrustError> {
        let is_normal = self.check_current(current)?;
        if self.live_cap.is_some() {
            return Err(TrustError::StretchUnlock);
        }
        if !is_normal {
            self.wrong_current = self.wrong_current.saturating_add(1);
            if self.wrong_current >= MAX_WRONG_CURRENT_PINS {
                self.wipe();
                return Err(TrustError::WrongCurrentPinLocked);
            }
            return Err(TrustError::WrongCurrentPin);
        }
        check_pin(pin)?;
        check_pin(duress)?;
        if ct_eq_bool(pin, duress) {
            return Err(TrustError::DuressEqualsPin);
        }
        let mut new_salt = [0u8; 16];
        rng.fill_bytes(&mut new_salt);
        let new_p_normal = stretch(self.kdf, pin, &new_salt)?;
        let new_p_duress = stretch(self.kdf, duress, &new_salt)?;
        let prev_rotation_required = self
            .staged_pins
            .as_ref()
            .map_or(self.rotation_required, |s| s.prev_rotation_required);
        self.pending = None;
        self.staged_pins = Some(StagedPins {
            salt: new_salt,
            p_normal: new_p_normal,
            p_duress: new_p_duress,
            prev_rotation_required,
        });
        self.rotation_required = true;
        Ok(())
    }

    /// A PIN change the app must refuse (fingerprint answer is being turned on): runs the
    /// current-PIN check of [`Vault::change_pins`], so the duress PIN still wipes and returns
    /// `DuressPin`. Otherwise nothing changes and nothing is counted: the refusal is the same for a
    /// right and a wrong PIN, so it tells nothing about it.
    pub fn refuse_pin_change(&mut self, current: &[u8]) -> Result<(), TrustError> {
        self.check_current(current).map(|_| ())
    }

    /// Stretches `current` and compares it with both stored stretches; both comparisons always
    /// run, so only the result tells the duress PIN from a wrong one. The duress PIN wipes the
    /// vault (`DuressPin`); otherwise true for the normal PIN.
    fn check_current(&mut self, current: &[u8]) -> Result<bool, TrustError> {
        let cur_normal = self.p_normal.as_ref().ok_or(TrustError::VaultLocked)?;
        check_pin(current)?;
        let cur_stretch = stretch(self.kdf, current, &self.salt)?;
        let is_normal = ct_eq_bool(cur_stretch.as_bytes(), cur_normal.as_bytes());
        let is_duress = ct_eq_bool(cur_stretch.as_bytes(), self.content.p_duress.as_bytes());
        if is_duress {
            self.wipe();
            return Err(TrustError::DuressPin);
        }
        Ok(is_normal)
    }

    /// Discards any pending rotation and staged PIN stretches, restoring the pre-staging state.
    pub fn abort_rotation(&mut self) {
        self.pending = None;
        if let Some(s) = self.staged_pins.take() {
            self.rotation_required = s.prev_rotation_required;
        }
    }

    /// Starts a rotation: five fresh tickets and a fresh root key. Every wrap is computed
    /// here from the fresh material, which then leaves in the returned [`Rotation`]; the
    /// vault keeps only the finished wraps. Calling it again before commit replaces the
    /// pending set (same ids, so re-import overwrites the aliases).
    /// The file always holds TICKETS_PER_VAULT records; with a cap ([`Vault::cap_refill`]) only the
    /// lowest ids get their material handed out, and the rest are wraps whose key never exists.
    pub fn begin_rotation(&mut self, rng: &mut impl CryptoRngCore) -> Result<Rotation, TrustError> {
        let usable = self.live_cap.unwrap_or(TICKETS_PER_VAULT).clamp(1, TICKETS_PER_VAULT);
        let cur_normal = self.p_normal.as_ref().ok_or(TrustError::VaultLocked)?;
        let (salt, p_normal, p_duress) = match &self.staged_pins {
            Some(s) => (&s.salt, &s.p_normal, &s.p_duress),
            None => (&self.salt, cur_normal, &self.content.p_duress),
        };
        let first = self.content.next_ticket_id;
        let last = first.checked_add(TICKETS_PER_VAULT as u32).ok_or(TrustError::CapacityExceeded)?;
        if first == 0 || last == u32::MAX {
            return Err(TrustError::CapacityExceeded);
        }
        let ids: Vec<u32> = (first..last).collect();
        let k_root = random_key(rng);
        let mut file_id = [0u8; 16];
        rng.fill_bytes(&mut file_id);
        let mut hdr = Vec::with_capacity(TICKETS_END);
        hdr.extend_from_slice(&MAGIC);
        hdr.push(FORMAT_VERSION);
        hdr.push(KDF_ARGON2ID_V13);
        hdr.extend_from_slice(&self.kdf.m_kib.to_be_bytes());
        hdr.extend_from_slice(&self.kdf.t_cost.to_be_bytes());
        hdr.extend_from_slice(&self.kdf.p_lanes.to_be_bytes());
        hdr.extend_from_slice(salt);
        hdr.extend_from_slice(&file_id);
        hdr.push(TICKETS_PER_VAULT as u8);
        let mut aad_base = hdr.clone();
        for id in &ids {
            aad_base.extend_from_slice(&id.to_be_bytes());
        }
        let mut new = Vec::with_capacity(TICKETS_PER_VAULT);
        for &id in &ids {
            let material = random_key(rng);
            let filler = random_key(rng);
            let hn = hmac32(material.as_bytes(), &[p_normal.as_bytes()])?;
            let hd = hmac32(material.as_bytes(), &[p_duress.as_bytes()])?;
            let kn = wrap_key(hn.as_bytes(), p_normal, &file_id, id)?;
            let kd = wrap_key(hd.as_bytes(), p_duress, &file_id, id)?;
            let mut aad = aad_base.clone();
            aad.extend_from_slice(&id.to_be_bytes());
            let mut pn = Zeroizing::new([0u8; WRAP_PT_LEN]);
            pn[0] = WRAP_NORMAL;
            pn[1..].copy_from_slice(k_root.as_bytes());
            let mut pd = Zeroizing::new([0u8; WRAP_PT_LEN]);
            pd[0] = WRAP_DURESS;
            pd[1..].copy_from_slice(filler.as_bytes());
            let wn = aead_seal(&kn, &ZERO_NONCE, &aad, &pn[..])?;
            let wd = aead_seal(&kd, &ZERO_NONCE, &aad, &pd[..])?;
            let (lo, hi) = if wn < wd { (wn, wd) } else { (wd, wn) };
            hdr.extend_from_slice(&id.to_be_bytes());
            hdr.extend_from_slice(&lo);
            hdr.extend_from_slice(&hi);
            // The only copy of the material leaves with the returned `Rotation`; beyond the cap it
            // is dropped (and wiped) here, so that ticket can never be used.
            if new.len() < usable {
                new.push((id, material));
            }
        }
        let retire = self.tickets.clone();
        self.pending = Some(Pending { k_root, file_id, hdr, ids });
        Ok(Rotation { new, retire })
    }

    /// Finishes a rotation after the app imported the new tickets; returns the new file to
    /// write atomically (fsync) before retiring the old tickets. Needs no ticket material.
    pub fn commit_rotation(&mut self) -> Result<Vec<u8>, TrustError> {
        let pending = self.pending.take().ok_or(TrustError::NoPendingRotation)?;
        let Some(next) = pending.ids.last().and_then(|l| l.checked_add(1)) else {
            self.pending = Some(pending);
            return Err(TrustError::CapacityExceeded);
        };
        let staged = self.staged_pins.take();
        let prev_pins = staged.as_ref().map(|s| {
            let old_salt = core::mem::replace(&mut self.salt, s.salt);
            let old_normal = self.p_normal.replace(s.p_normal.clone());
            let old_duress = core::mem::replace(&mut self.content.p_duress, s.p_duress.clone());
            (old_salt, old_normal, old_duress)
        });
        let prev_next = core::mem::replace(&mut self.content.next_ticket_id, next);
        let prev_root = core::mem::replace(&mut self.k_root, pending.k_root.clone());
        let prev_committed = self.committed.replace(Committed { file_id: pending.file_id, hdr: pending.hdr.clone() });
        let (prev_seq, prev_required) = (self.seq, self.rotation_required);
        self.seq = 0;
        self.rotation_required = false;
        match self.seal_blob() {
            Ok(blob) => {
                if let Some((mut old_salt, _, _)) = prev_pins {
                    old_salt.zeroize();
                }
                self.tickets = pending.ids;
                Ok(blob)
            }
            Err(e) => {
                if let Some((old_salt, old_normal, old_duress)) = prev_pins {
                    self.salt = old_salt;
                    self.p_normal = old_normal;
                    self.content.p_duress = old_duress;
                }
                self.staged_pins = staged;
                self.content.next_ticket_id = prev_next;
                self.k_root = prev_root;
                self.committed = prev_committed;
                self.seq = prev_seq;
                self.rotation_required = prev_required;
                self.pending = Some(pending);
                Err(e)
            }
        }
    }

    /// Re-encrypts the current content under the committed tickets (resume secret updates,
    /// labels, attestation verdicts). Fails with `RotationRequired` after an unlock or an
    /// identity change until a rotation is committed.
    pub fn export(&mut self) -> Result<Vec<u8>, TrustError> {
        if self.rotation_required {
            return Err(TrustError::RotationRequired);
        }
        self.seal_blob()
    }

    /// True when the vault must be rotated before it can be persisted.
    pub fn rotation_required(&self) -> bool {
        self.rotation_required
    }

    /// Length of the file [`Vault::export`] would write now; what the file is replaced with on
    /// duress ([`duress_overwrite`]).
    pub fn file_len(&self) -> Result<usize, TrustError> {
        let needed = BODY_HDR_END + 4 + self.content.encode()?.len() + TAG_LEN;
        round_up_block(needed.max(self.pad_to)).ok_or(TrustError::CapacityExceeded)
    }

    fn seal_blob(&mut self) -> Result<Vec<u8>, TrustError> {
        let cap = TrustError::CapacityExceeded;
        let committed = self.committed.as_ref().ok_or(TrustError::RotationRequired)?;
        let content = self.content.encode()?;
        let needed = BODY_HDR_END + 4 + content.len() + TAG_LEN;
        let total = round_up_block(needed.max(self.pad_to)).ok_or(cap)?;
        if total > MAX_VAULT_LEN {
            return Err(cap);
        }
        let body_len = total - BODY_HDR_END;
        let seq = self.seq;
        let next_seq = seq.checked_add(1).ok_or(cap)?;
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&committed.hdr);
        out.extend_from_slice(&seq.to_be_bytes());
        out.extend_from_slice(&u32::try_from(body_len).map_err(|_| cap)?.to_be_bytes());
        let mut pt = Zeroizing::new(vec![0u8; body_len - TAG_LEN]);
        let clen = u32::try_from(content.len()).map_err(|_| cap)?;
        pt.get_mut(..4).ok_or(cap)?.copy_from_slice(&clen.to_be_bytes());
        pt.get_mut(4..4 + content.len()).ok_or(cap)?.copy_from_slice(&content);
        let key = body_key(&self.k_root, &committed.file_id)?;
        let ct = aead_seal(&key, &body_nonce(seq), &out, &pt)?;
        out.extend_from_slice(&ct);
        self.seq = next_seq;
        Ok(out)
    }

    /// Locks the vault: zeroizes the root key, both PIN stretches, the phone and meta keys and
    /// every contact. Also runs on drop.
    pub fn wipe(&mut self) {
        self.k_root.zeroize();
        if let Some(p) = self.p_normal.as_mut() {
            p.zeroize();
        }
        self.p_normal = None;
        self.content.p_duress.zeroize();
        self.content.phone_key.zeroize();
        self.content.meta_key.zeroize();
        self.content.contacts.clear();
        self.pending = None;
        self.staged_pins = None;
        self.committed = None;
        self.rotation_required = true;
    }

    fn mark_rotation_required(&mut self) {
        self.rotation_required = true;
        if let Some(s) = self.staged_pins.as_mut() {
            s.prev_rotation_required = true;
        }
    }

    // ------------------------------------------------------------ contact metadata

    fn meta_cipher(&self) -> Result<XChaCha20Poly1305, TrustError> {
        if self.p_normal.is_none() {
            return Err(TrustError::VaultLocked);
        }
        Ok(XChaCha20Poly1305::new(Key::from_slice(self.content.meta_key.as_bytes())))
    }

    /// Seals the app's contact metadata (phone numbers, mutual marks, pairing seed):
    /// `format(1)=1 ‖ nonce(24) ‖ XChaCha20-Poly1305(meta_key, nonce, aad = fixed label)`.
    /// Fails with `VaultLocked` once the vault is wiped.
    pub fn meta_seal(&self, plaintext: &[u8], rng: &mut impl CryptoRngCore) -> Result<Vec<u8>, TrustError> {
        let cipher = self.meta_cipher()?;
        let mut nonce = [0u8; META_NONCE_LEN];
        rng.fill_bytes(&mut nonce);
        let ct = cipher
            .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad: META_AAD })
            .map_err(|_| TrustError::Crypto)?;
        let mut out = Vec::with_capacity(1 + META_NONCE_LEN + ct.len());
        out.push(META_FORMAT);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Opens a blob of [`Vault::meta_seal`]. `VaultLocked` once wiped, `Crypto` for a blob
    /// of another format or key, or any modified byte.
    pub fn meta_open(&self, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, TrustError> {
        let cipher = self.meta_cipher()?;
        let (format, rest) = sealed.split_first().ok_or(TrustError::Crypto)?;
        if *format != META_FORMAT || rest.len() < META_NONCE_LEN + TAG_LEN {
            return Err(TrustError::Crypto);
        }
        let (nonce, ct) = rest.split_at(META_NONCE_LEN);
        cipher
            .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad: META_AAD })
            .map(Zeroizing::new)
            .map_err(|_| TrustError::Crypto)
    }

    // ------------------------------------------------------------ contacts

    /// `HMAC(phone_key, "AegisPhone-v2" ‖ E.164)[..16]`.
    pub fn phone_tag(&self, e164: &[u8]) -> Result<[u8; 16], TrustError> {
        if !valid_e164(e164) {
            return Err(TrustError::InvalidPhone);
        }
        let h = hmac32(self.content.phone_key.as_bytes(), &[b"AegisPhone-v2", e164])?;
        let mut t = [0u8; 16];
        t.copy_from_slice(h.as_bytes().get(..16).unwrap_or(&[0u8; 16]));
        Ok(t)
    }

    fn index_of(&self, id: u32) -> Result<usize, TrustError> {
        self.content.contacts.iter().position(|c| c.id == id).ok_or(TrustError::UnknownContact)
    }

    fn find_mut(&mut self, id: u32) -> Result<&mut Contact, TrustError> {
        self.content.contacts.iter_mut().find(|c| c.id == id).ok_or(TrustError::UnknownContact)
    }

    fn pub33_owner(&self, pub33: &[u8; 33]) -> Option<u32> {
        self.content.contacts.iter().find(|c| ct_eq_bool(&c.pub33, pub33)).map(|c| c.id)
    }

    /// Saves a new contact (identity change: rotation required before export).
    pub fn add_contact(&mut self, c: NewContact) -> Result<u32, TrustError> {
        validate_pub33(&c.pub33)?;
        validate_label(&c.label)?;
        if self.content.contacts.len() >= MAX_CONTACTS {
            return Err(TrustError::CapacityExceeded);
        }
        if self.pub33_owner(&c.pub33).is_some() {
            return Err(TrustError::DuplicateContact);
        }
        let phone_tag = match &c.phone {
            PhoneChoice::UserConfirmed(n) => {
                let t = self.phone_tag(n)?;
                if self.content.contacts.iter().any(|x| x.phone_tag.as_ref().is_some_and(|p| ct_eq_bool(p, &t))) {
                    return Err(TrustError::PhoneInUse);
                }
                Some(t)
            }
            PhoneChoice::NoNumber => None,
        };
        let id = self.content.next_contact_id;
        let next = id.checked_add(1).ok_or(TrustError::CapacityExceeded)?;
        let (psk, sas_verified) = match c.proof {
            ContactProof::SasMatchedThisCall => (None, true),
            ContactProof::Paired(psk) => (Some(psk), false),
        };
        self.content.contacts.push(Contact {
            id,
            pub33: c.pub33,
            label: Zeroizing::new(c.label),
            phone_tag,
            psk,
            sas_verified,
            attestation: None,
            rs_cur: None,
            rs_new: None,
            unrefreshed_resumes: 0,
        });
        self.content.next_contact_id = next;
        self.mark_rotation_required();
        Ok(id)
    }

    /// "Re-verify and update" after a key change. A PSK contact can only change key through
    /// a new pairing. Clears resume secrets and the attestation verdict.
    pub fn replace_contact_key(&mut self, id: u32, pub33: [u8; 33], proof: ContactProof) -> Result<(), TrustError> {
        validate_pub33(&pub33)?;
        if self.pub33_owner(&pub33).is_some_and(|o| o != id) {
            return Err(TrustError::DuplicateContact);
        }
        let c = self.find_mut(id)?;
        match proof {
            ContactProof::SasMatchedThisCall => {
                if c.psk.is_some() {
                    return Err(TrustError::PskRequiredForKeyChange);
                }
                c.sas_verified = true;
            }
            ContactProof::Paired(psk) => {
                c.psk = Some(psk);
                c.sas_verified = false;
            }
        }
        c.pub33 = pub33;
        c.rs_cur = None;
        c.rs_new = None;
        c.unrefreshed_resumes = 0;
        c.attestation = None;
        self.mark_rotation_required();
        Ok(())
    }

    /// Deletes a contact (identity change).
    pub fn remove_contact(&mut self, id: u32) -> Result<(), TrustError> {
        let i = self.index_of(id)?;
        drop(self.content.contacts.remove(i));
        self.mark_rotation_required();
        Ok(())
    }

    /// Changes a label (no rotation).
    pub fn set_label(&mut self, id: u32, label: String) -> Result<(), TrustError> {
        validate_label(&label)?;
        self.find_mut(id)?.label = Zeroizing::new(label);
        Ok(())
    }

    /// Sets or clears a contact's phone tag (no rotation).
    pub fn set_phone(&mut self, id: u32, phone: PhoneChoice) -> Result<(), TrustError> {
        self.index_of(id)?;
        let new_tag = match &phone {
            PhoneChoice::UserConfirmed(n) => {
                let t = self.phone_tag(n)?;
                if self
                    .content
                    .contacts
                    .iter()
                    .any(|x| x.id != id && x.phone_tag.as_ref().is_some_and(|p| ct_eq_bool(p, &t)))
                {
                    return Err(TrustError::PhoneInUse);
                }
                Some(t)
            }
            PhoneChoice::NoNumber => None,
        };
        self.find_mut(id)?.phone_tag = new_tag;
        Ok(())
    }

    /// Stores an attestation verdict (no rotation).
    pub fn set_attestation(&mut self, id: u32, verdict: AttestationVerdict) -> Result<(), TrustError> {
        validate_attestation(&verdict)?;
        self.find_mut(id)?.attestation = Some(verdict);
        Ok(())
    }

    fn view(c: &Contact) -> ContactView {
        let usable = c.unrefreshed_resumes < MAX_UNREFRESHED_RESUMES;
        ContactView {
            id: c.id,
            pub33: c.pub33,
            label: c.label.as_str().to_owned(),
            phone_tag: c.phone_tag,
            has_psk: c.psk.is_some(),
            sas_verified: c.sas_verified,
            attestation: c.attestation.clone(),
            resume: (usable && c.rs_cur.is_some(), usable && c.rs_new.is_some()),
        }
    }

    /// All contacts.
    pub fn contacts(&self) -> Vec<ContactView> {
        self.content.contacts.iter().map(Self::view).collect()
    }

    /// Contact identified by its key (design 6.2: identity is `pub33`).
    pub fn contact_by_pub33(&self, pub33: &[u8; 33]) -> Option<ContactView> {
        self.content.contacts.iter().find(|c| ct_eq_bool(&c.pub33, pub33)).map(Self::view)
    }

    /// True when contact id holds exactly this pairing PSK (constant-time comparison).
    pub fn holds_pairing_psk(&self, id: u32, psk: &SecretKey32) -> bool {
        self.content
            .contacts
            .iter()
            .find(|c| c.id == id)
            .and_then(|c| c.psk.as_ref())
            .is_some_and(|p| ct_eq_bool(p.as_bytes(), psk.as_bytes()))
    }

    /// Replaces only the pairing PSK of a contact whose key stays the same (a new pairing with
    /// the same identity). Label, phone, SAS verification, attestation and resume secrets are kept:
    /// they belong to the identity key, which did not change. Rotation required.
    pub fn set_pairing_psk(&mut self, id: u32, psk: SecretKey32) -> Result<(), TrustError> {
        self.find_mut(id)?.psk = Some(psk);
        self.mark_rotation_required();
        Ok(())
    }

    /// Copy of one contact, to undo a change the app could not persist ([`Vault::restore_contact`]).
    pub fn contact_snapshot(&self, id: u32) -> Option<ContactSnapshot> {
        self.content.contacts.iter().find(|c| c.id == id).map(|c| ContactSnapshot(c.duplicate()))
    }

    /// Puts a contact back as it was in `snap`. Rotation required, so a file written before
    /// the undo cannot be exported as the current one.
    pub fn restore_contact(&mut self, snap: ContactSnapshot) -> Result<(), TrustError> {
        let i = self.index_of(snap.0.id)?;
        self.content.contacts[i] = snap.0;
        self.mark_rotation_required();
        Ok(())
    }

    /// Handshake expectation plus, if `e164` matches a stored number, the `pub33` stored
    /// for it (only a "this number used another key" hint).
    pub fn expectation_for(&self, e164: Option<&[u8]>) -> (PeerExpectation, Option<[u8; 33]>) {
        fn resume_usable(c: &Contact) -> bool {
            c.unrefreshed_resumes < MAX_UNREFRESHED_RESUMES
        }
        let mut psk = Vec::new();
        let mut resume = Vec::new();
        for c in &self.content.contacts {
            if let Some(p) = &c.psk {
                psk.push((c.id, c.pub33, p.clone()));
            }
            if resume_usable(c) {
                if let Some(r) = &c.rs_cur {
                    resume.push(ResumeCandidate { contact: c.id, pub33: c.pub33, secret: r.clone(), is_new: false });
                }
                if let Some((r, _)) = &c.rs_new {
                    resume.push(ResumeCandidate { contact: c.id, pub33: c.pub33, secret: r.clone(), is_new: true });
                }
            }
        }
        let hint = e164.and_then(|n| self.phone_tag(n).ok()).and_then(|t| {
            self.content
                .contacts
                .iter()
                .find(|c| c.phone_tag.as_ref().is_some_and(|p| ct_eq_bool(p, &t)))
                .map(|c| c.pub33)
        });
        (PeerExpectation { psk, resume }, hint)
    }

    // ------------------------------------------------------------ resume (design 6.3)

    /// Step 1: store `rs` as `rs_new` for update `k`, keeping `rs_cur`. Persist with
    /// [`Vault::export`] before sending RESUME_SAVED(k). Fails with `ResumeBusy` while a
    /// lower-numbered update is still unpromoted and with `ResumeStale` when a
    /// higher-numbered one is already staged (an older update never replaces a newer one).
    pub fn resume_stage(&mut self, contact: u32, rs: SecretKey32, k: u8) -> Result<(), TrustError> {
        if k == 0 {
            return Err(TrustError::InvalidResumeK);
        }
        let c = self.find_mut(contact)?;
        match c.rs_new.as_ref().map(|(_, staged)| *staged) {
            Some(staged) if staged < k => return Err(TrustError::ResumeBusy),
            Some(staged) if staged > k => return Err(TrustError::ResumeStale),
            _ => {}
        }
        c.rs_new = Some((rs, k));
        Ok(())
    }

    /// Drops a leftover `rs_new` at the start of a session that did not use it (resume
    /// through `rs_cur`, or a full handshake). The peer does not hold that secret, and a
    /// leftover with a higher update number would make this session's `resume_stage(.., 1)`
    /// fail with `ResumeStale`. Do not call it after the session has staged an update.
    pub fn resume_discard_staged(&mut self, contact: u32) -> Result<(), TrustError> {
        self.find_mut(contact)?.rs_new = None;
        Ok(())
    }

    /// Resets the unrefreshed fast-resume counter after a full ML-KEM-1024 handshake.
    pub fn resume_reset_pqc_age(&mut self, contact: u32) -> Result<(), TrustError> {
        self.find_mut(contact)?.unrefreshed_resumes = 0;
        Ok(())
    }

    /// Step 3: peer's RESUME_SAVED(k) confirms every update <= k. Promotes `rs_new` to
    /// `rs_cur` (old value zeroized) if its update number is <= k. Returns whether it did.
    pub fn resume_promote(&mut self, contact: u32, k: u8) -> Result<bool, TrustError> {
        if k == 0 {
            return Err(TrustError::InvalidResumeK);
        }
        let c = self.find_mut(contact)?;
        match c.rs_new.take() {
            Some((rs, staged)) if staged <= k => {
                if k >= 2 || c.rs_cur.is_none() || c.unrefreshed_resumes >= MAX_UNREFRESHED_RESUMES {
                    c.unrefreshed_resumes = 0;
                } else {
                    c.unrefreshed_resumes = c.unrefreshed_resumes.saturating_add(1);
                }
                c.rs_cur = Some(rs);
                Ok(true)
            }
            other => {
                c.rs_new = other;
                Ok(false)
            }
        }
    }

    /// Step 5: a resume that used `rs_new` promotes it first.
    pub fn resume_mark_used(&mut self, contact: u32, used_new: bool) -> Result<(), TrustError> {
        let c = self.find_mut(contact)?;
        if used_new {
            if let Some((rs, staged)) = c.rs_new.take() {
                if staged >= 2 {
                    c.unrefreshed_resumes = 0;
                } else {
                    c.unrefreshed_resumes = c.unrefreshed_resumes.saturating_add(1);
                }
                c.rs_cur = Some(rs);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "tests/vault.rs"]
mod tests;
