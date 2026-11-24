//! Internal primitives shared by the v2 modules: HMAC/HKDF-SHA-384 (RFC 2104 / RFC 5869),
//! SHA-384, single-use XChaCha20-Poly1305 (all-zero nonce) and ML-KEM-1024 helpers.
//! Every function here is infallible for well-formed local input and never panics on peer data.

use aegiscall_memsec::SecretKey32;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hmac::digest::Key;
use hmac::{Hmac, Mac};
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{Ciphertext, Encoded, EncodedSizeUser, KemCore, MlKem1024};
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha384};
use zeroize::{Zeroize, Zeroizing};

type HmacSha384 = Hmac<Sha384>;

pub(crate) const PRK_LEN: usize = 48;
pub(crate) type Prk = Zeroizing<[u8; PRK_LEN]>;
pub(crate) type DecapKey = <MlKem1024 as KemCore>::DecapsulationKey;
type EncapKey = <MlKem1024 as KemCore>::EncapsulationKey;

/// HMAC-SHA-384 over the concatenation of `parts`. Keys longer than the block are hashed first.
pub(crate) fn hmac_sha384(key: &[u8], parts: &[&[u8]]) -> Prk {
    let mut block = Key::<HmacSha384>::default();
    if key.len() <= block.len() {
        if let Some(dst) = block.get_mut(..key.len()) {
            dst.copy_from_slice(key);
        }
    } else {
        let mut h = Sha384::digest(key);
        if let Some(dst) = block.get_mut(..h.len()) {
            dst.copy_from_slice(&h);
        }
        h.as_mut_slice().zeroize();
    }
    let mut mac = <HmacSha384 as hmac::digest::KeyInit>::new(&block);
    block.as_mut_slice().zeroize();
    for p in parts {
        Mac::update(&mut mac, p);
    }
    let mut tag = Mac::finalize(mac).into_bytes();
    let mut out = Zeroizing::new([0u8; PRK_LEN]);
    out.copy_from_slice(tag.as_slice());
    tag.as_mut_slice().zeroize();
    out
}

/// HKDF-Extract(salt, ikm) with SHA-384; ikm is the concatenation of ikm_parts.
pub(crate) fn extract(salt: &[u8], ikm_parts: &[&[u8]]) -> Prk {
    hmac_sha384(salt, ikm_parts)
}

/// HKDF-Expand(prk, info, out.len()) with SHA-384; info is the concatenation of the parts.
/// Output lengths used in this crate are compile-time constants far below 255 * 48.
pub(crate) fn expand(prk: &[u8], info: &[&[u8]], out: &mut [u8]) {
    let mut t = Zeroizing::new([0u8; PRK_LEN]);
    let mut have_prev = false;
    let mut counter: u8 = 1;
    for chunk in out.chunks_mut(PRK_LEN) {
        let next = {
            let ctr = [counter];
            let mut parts: Vec<&[u8]> = Vec::with_capacity(info.len() + 2);
            if have_prev {
                parts.push(t.as_slice());
            }
            parts.extend_from_slice(info);
            parts.push(&ctr);
            hmac_sha384(prk, &parts)
        };
        t.copy_from_slice(next.as_slice());
        if let Some(src) = t.get(..chunk.len()) {
            chunk.copy_from_slice(src);
        }
        have_prev = true;
        counter = counter.wrapping_add(1);
    }
}

pub(crate) fn expand32(prk: &[u8], info: &[&[u8]]) -> SecretKey32 {
    let mut b = Zeroizing::new([0u8; 32]);
    expand(prk, info, b.as_mut_slice());
    SecretKey32::from_bytes(*b)
}

pub(crate) fn sha384(parts: &[&[u8]]) -> [u8; 48] {
    let mut h = Sha384::new();
    for p in parts {
        h.update(p);
    }
    let d = h.finalize();
    let mut out = [0u8; 48];
    out.copy_from_slice(d.as_slice());
    out
}

/// XChaCha20-Poly1305 with an all-zero nonce. Only for keys that are used exactly once.
pub(crate) fn aead_seal_once(key: &SecretKey32, aad: &[u8], pt: &[u8]) -> Option<Vec<u8>> {
    let cipher = <XChaCha20Poly1305 as chacha20poly1305::KeyInit>::new(key.as_bytes().into());
    let nonce = XNonce::default();
    cipher.encrypt(&nonce, Payload { msg: pt, aad }).ok()
}

pub(crate) fn aead_open_once(key: &SecretKey32, aad: &[u8], ct: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let cipher = <XChaCha20Poly1305 as chacha20poly1305::KeyInit>::new(key.as_bytes().into());
    let nonce = XNonce::default();
    cipher
        .decrypt(&nonce, Payload { msg: ct, aad })
        .ok()
        .map(Zeroizing::new)
}

pub(crate) const MLKEM1024_EK_LEN: usize = 1568;
pub(crate) const MLKEM1024_CT_LEN: usize = 1568;

pub(crate) fn kem_generate<R: CryptoRngCore>(rng: &mut R) -> (DecapKey, Vec<u8>) {
    let (dk, ek) = MlKem1024::generate(rng);
    (dk, ek.as_bytes().as_slice().to_vec())
}

/// Encapsulates against a peer key. Rejects wrong lengths and keys that fail the FIPS 203
/// modulus check (decode then re-encode must reproduce the input).
pub(crate) fn kem_encapsulate<R: CryptoRngCore>(
    ek_bytes: &[u8],
    rng: &mut R,
) -> Option<(Vec<u8>, Zeroizing<[u8; 32]>)> {
    let mut enc = Encoded::<EncapKey>::default();
    if ek_bytes.len() != enc.len() {
        return None;
    }
    enc.as_mut_slice().copy_from_slice(ek_bytes);
    let ek = EncapKey::from_bytes(&enc);
    if ek.as_bytes().as_slice() != ek_bytes {
        return None;
    }
    let (ct, mut ss) = ek.encapsulate(rng).ok()?;
    let mut out = Zeroizing::new([0u8; 32]);
    if ss.len() != out.len() {
        ss.as_mut_slice().zeroize();
        return None;
    }
    out.copy_from_slice(ss.as_slice());
    ss.as_mut_slice().zeroize();
    Some((ct.as_slice().to_vec(), out))
}

pub(crate) fn kem_decapsulate(dk: &DecapKey, ct_bytes: &[u8]) -> Option<Zeroizing<[u8; 32]>> {
    let mut ct = Ciphertext::<MlKem1024>::default();
    if ct_bytes.len() != ct.len() {
        return None;
    }
    ct.as_mut_slice().copy_from_slice(ct_bytes);
    let mut ss = dk.decapsulate(&ct).ok()?;
    let mut out = Zeroizing::new([0u8; 32]);
    if ss.len() != out.len() {
        ss.as_mut_slice().zeroize();
        return None;
    }
    out.copy_from_slice(ss.as_slice());
    ss.as_mut_slice().zeroize();
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_and_hkdf_match_rfc_vectors() {
        // RFC 4231 test case 2 (HMAC-SHA-384, key "Jefe").
        let tag = hmac_sha384(b"Jefe", &[b"what do ya want ", b"for nothing?"]);
        let expected = "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649";
        let hex: String = tag.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, expected);

        // Cross-check against the hkdf crate for a 48-byte PRK and multi-block output.
        let prk = extract(b"salt", &[b"input key ", b"material"]);
        let mut ours = [0u8; 80];
        expand(prk.as_slice(), &[b"info"], &mut ours);
        let hk = hkdf::Hkdf::<Sha384>::from_prk(prk.as_slice()).unwrap();
        let mut theirs = [0u8; 80];
        hk.expand(b"info", &mut theirs).unwrap();
        assert_eq!(ours, theirs);
        let (prk2, _) = hkdf::Hkdf::<Sha384>::extract(Some(b"salt"), b"input key material");
        assert_eq!(prk.as_slice(), prk2.as_slice());
    }

    #[test]
    fn kem_rejects_bad_lengths_and_roundtrips() {
        let (dk, ek) = kem_generate(&mut rand_core::OsRng);
        assert_eq!(ek.len(), MLKEM1024_EK_LEN);
        assert!(kem_encapsulate(&ek[1..], &mut rand_core::OsRng).is_none());
        let (ct, ss) = kem_encapsulate(&ek, &mut rand_core::OsRng).unwrap();
        assert_eq!(ct.len(), MLKEM1024_CT_LEN);
        assert!(kem_decapsulate(&dk, &ct[1..]).is_none());
        assert_eq!(kem_decapsulate(&dk, &ct).unwrap().as_slice(), ss.as_slice());
        // A coefficient >= q in the first slot fails the modulus check.
        let mut bad = ek.clone();
        bad[0] = 0xFF;
        bad[1] |= 0x0F;
        assert!(kem_encapsulate(&bad, &mut rand_core::OsRng).is_none());
    }
}
