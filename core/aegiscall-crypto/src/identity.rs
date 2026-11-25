//! Identity helpers for handshake v2: Android Keystore SPKI -> compressed SEC1 (pub33),
//! DER ECDSA -> raw r||s (low-S), raw signature verification and peer classification.

use crate::CryptoError;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::pkcs8::DecodePublicKey;
use p256::PublicKey;
use subtle::ConstantTimeEq;

pub const PUB33_LEN: usize = 33;
pub const EVIDENCE_ID_LEN: usize = 16;
pub const RAW_SIG_LEN: usize = 64;

/// Our own identity as announced in the handshake ID block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalIdentity {
    pub pub33: [u8; PUB33_LEN],
    pub evidence_id: [u8; EVIDENCE_ID_LEN],
}

/// The peer identity revealed (full path) or pinned (resume path, evidence_id all zero).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerIdentity {
    pub pub33: [u8; PUB33_LEN],
    pub evidence_id: [u8; EVIDENCE_ID_LEN],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityStatus {
    Unverified,
    SasVerified,
    KnownContact,
    KeyChanged,
}

/// Checks that pub33 is a compressed SEC1 encoding of a valid P-256 point.
pub fn validate_pub33(pub33: &[u8; PUB33_LEN]) -> Result<(), CryptoError> {
    if pub33[0] != 0x02 && pub33[0] != 0x03 {
        return Err(CryptoError::InvalidPeerPublicKey);
    }
    PublicKey::from_sec1_bytes(pub33)
        .map(|_| ())
        .map_err(|_| CryptoError::InvalidPeerPublicKey)
}

/// Converts a DER SubjectPublicKeyInfo (id-ecPublicKey, prime256v1) into a compressed point.
pub fn spki_der_to_pub33(spki: &[u8]) -> Result<[u8; PUB33_LEN], CryptoError> {
    let pk = PublicKey::from_public_key_der(spki).map_err(|_| CryptoError::InvalidPeerPublicKey)?;
    let ep = pk.to_sec1_point(true);
    <[u8; PUB33_LEN]>::try_from(ep.as_bytes()).map_err(|_| CryptoError::InvalidPeerPublicKey)
}

/// Converts a strict (canonical) DER ECDSA-P256 signature into raw r||s with low S.
pub fn ecdsa_der_to_raw(der: &[u8]) -> Result<[u8; RAW_SIG_LEN], CryptoError> {
    let sig = Signature::from_der(der).map_err(|_| CryptoError::InvalidKeyMaterial)?;
    if sig.to_der().as_bytes() != der {
        return Err(CryptoError::InvalidKeyMaterial);
    }
    let sig = sig.normalize_s();
    let bytes = sig.to_bytes();
    <[u8; RAW_SIG_LEN]>::try_from(bytes.as_slice()).map_err(|_| CryptoError::InvalidKeyMaterial)
}

/// Verifies ECDSA-P256-SHA256 over msg. High-S signatures are rejected.
pub fn verify_identity_sig(
    pub33: &[u8; PUB33_LEN],
    msg: &[u8],
    sig: &[u8; RAW_SIG_LEN],
) -> Result<(), CryptoError> {
    validate_pub33(pub33)?;
    let vk = VerifyingKey::from_sec1_bytes(pub33).map_err(|_| CryptoError::InvalidPeerPublicKey)?;
    let s = Signature::from_slice(sig).map_err(|_| CryptoError::AuthenticationFailed)?;
    if s.normalize_s() != s {
        return Err(CryptoError::AuthenticationFailed);
    }
    vk.verify(msg, &s).map_err(|_| CryptoError::AuthenticationFailed)
}

/// Classifies the peer against the stored contact key (if any) and this call's SAS result.
pub fn classify_peer(peer: &PeerIdentity, stored: Option<&[u8; PUB33_LEN]>, sas_ok: bool) -> IdentityStatus {
    match stored {
        Some(s) if bool::from(s.ct_eq(&peer.pub33)) => IdentityStatus::KnownContact,
        Some(_) => IdentityStatus::KeyChanged,
        None if sas_ok => IdentityStatus::SasVerified,
        None => IdentityStatus::Unverified,
    }
}

/// Software P-256 signer standing in for the StrongBox key in tests.
#[cfg(any(test, feature = "test-signer"))]
#[derive(Clone)]
pub struct SoftwareSigner {
    sk: p256::ecdsa::SigningKey,
}

#[cfg(any(test, feature = "test-signer"))]
impl SoftwareSigner {
    pub fn generate() -> Self {
        Self {
            sk: <p256::ecdsa::SigningKey as p256::elliptic_curve::Generate>::generate(),
        }
    }

    /// Deterministic key from a seed, for reproducible tests. Signatures are RFC 6979, so the
    /// same seed and message always give the same bytes.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        use sha2::{Digest, Sha256};
        let mut counter = 0u32;
        loop {
            let mut h = Sha256::new();
            h.update(b"DialCrypt test signer");
            h.update(seed);
            h.update(counter.to_be_bytes());
            if let Ok(sk) = p256::ecdsa::SigningKey::from_slice(h.finalize().as_slice()) {
                return Self { sk };
            }
            counter = counter.wrapping_add(1);
        }
    }

    pub fn pub33(&self) -> [u8; PUB33_LEN] {
        let ep = self.sk.verifying_key().to_sec1_point(true);
        let mut out = [0u8; PUB33_LEN];
        out.copy_from_slice(ep.as_bytes());
        out
    }

    /// DER SPKI with an uncompressed point, as Android Keystore exports it.
    pub fn spki_der(&self) -> Vec<u8> {
        let mut out = vec![
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
            0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
        ];
        out.extend_from_slice(self.sk.verifying_key().to_sec1_point(false).as_bytes());
        out
    }

    /// SHA256withECDSA, DER encoded (what Android's Signature API returns).
    pub fn sign_der(&self, msg: &[u8]) -> Vec<u8> {
        use p256::ecdsa::signature::Signer;
        let sig: Signature = self.sk.sign(msg);
        sig.to_der().as_bytes().to_vec()
    }

    pub fn local_identity(&self, evidence_id: [u8; EVIDENCE_ID_LEN]) -> LocalIdentity {
        LocalIdentity {
            pub33: self.pub33(),
            evidence_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const N: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
    ];

    fn n_minus(s: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let mut v = N[i] as i16 - s[i] as i16 - borrow;
            borrow = if v < 0 { v += 256; 1 } else { 0 };
            out[i] = v as u8;
        }
        out
    }

    #[test]
    fn spki_conversion_accepts_keystore_format_and_rejects_malformed() {
        let s = SoftwareSigner::generate();
        let spki = s.spki_der();
        assert_eq!(spki_der_to_pub33(&spki).unwrap(), s.pub33());

        assert!(spki_der_to_pub33(&[]).is_err());
        assert!(spki_der_to_pub33(&spki[..spki.len() - 1]).is_err());
        let mut trailing = spki.clone();
        trailing.push(0);
        assert!(spki_der_to_pub33(&trailing).is_err());
        let mut wrong_curve = spki.clone();
        wrong_curve[22] = 0x08; // prime256v1 OID last arc 7 -> 8
        assert!(spki_der_to_pub33(&wrong_curve).is_err());
        let mut wrong_alg = spki.clone();
        wrong_alg[12] = 0x02; // id-ecPublicKey -> other OID
        assert!(spki_der_to_pub33(&wrong_alg).is_err());
        let mut off_curve = spki.clone();
        let last = off_curve.len() - 1;
        off_curve[last] ^= 0x01; // y no longer matches x
        assert!(spki_der_to_pub33(&off_curve).is_err());
    }

    #[test]
    fn der_signature_conversion_normalizes_and_rejects_malformed() {
        let s = SoftwareSigner::generate();
        let msg = b"AegisChat-v2 auth I test";
        let der = s.sign_der(msg);
        let raw = ecdsa_der_to_raw(&der).unwrap();
        verify_identity_sig(&s.pub33(), msg, &raw).unwrap();
        assert!(verify_identity_sig(&s.pub33(), b"other message", &raw).is_err());

        // High-S DER converts to the low-S raw form; the raw high-S form is rejected by verify.
        let high_s = n_minus(&raw[32..]);
        let mut high_raw = [0u8; 64];
        high_raw[..32].copy_from_slice(&raw[..32]);
        high_raw[32..].copy_from_slice(&high_s);
        let high_der = Signature::from_slice(&high_raw).unwrap().to_der();
        assert_eq!(ecdsa_der_to_raw(high_der.as_bytes()).unwrap(), raw);
        assert!(verify_identity_sig(&s.pub33(), msg, &high_raw).is_err());

        assert!(ecdsa_der_to_raw(&[]).is_err());
        assert!(ecdsa_der_to_raw(&der[..der.len() - 1]).is_err());
        let mut trailing = der.clone();
        trailing.push(0);
        assert!(ecdsa_der_to_raw(&trailing).is_err());
        let mut bad_tag = der.clone();
        bad_tag[0] = 0x31;
        assert!(ecdsa_der_to_raw(&bad_tag).is_err());
        // r = 0
        assert!(ecdsa_der_to_raw(&[0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01]).is_err());
        // Non-minimal integer encoding (leading zero) is not canonical DER.
        assert!(ecdsa_der_to_raw(&[0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01]).is_err());
        assert!(ecdsa_der_to_raw(&raw).is_err());
    }

    #[test]
    fn pub33_validation_and_classification() {
        let s = SoftwareSigner::generate();
        let other = SoftwareSigner::generate();
        validate_pub33(&s.pub33()).unwrap();
        // Seeded signers are reproducible: same key and (RFC 6979) same signature bytes.
        let (s1, s2) = (SoftwareSigner::from_seed([7; 32]), SoftwareSigner::from_seed([7; 32]));
        assert_eq!(s1.pub33(), s2.pub33());
        assert_eq!(s1.sign_der(b"m"), s2.sign_der(b"m"));
        assert_ne!(s1.pub33(), SoftwareSigner::from_seed([8; 32]).pub33());
        let mut bad = s.pub33();
        bad[0] = 0x04;
        assert!(validate_pub33(&bad).is_err());
        let mut not_x = [0u8; 33];
        not_x[0] = 0x02;
        not_x[1..].copy_from_slice(&[0xFF; 32]); // x >= p
        assert!(validate_pub33(&not_x).is_err());

        let peer = PeerIdentity { pub33: s.pub33(), evidence_id: [1; 16] };
        assert_eq!(classify_peer(&peer, None, false), IdentityStatus::Unverified);
        assert_eq!(classify_peer(&peer, None, true), IdentityStatus::SasVerified);
        assert_eq!(classify_peer(&peer, Some(&s.pub33()), false), IdentityStatus::KnownContact);
        assert_eq!(classify_peer(&peer, Some(&other.pub33()), true), IdentityStatus::KeyChanged);
    }
}
