//! Pairing code (secure-session-v2 §6.1): 68 B = ver(1)=3 || pub33 || X25519 public key(32) ||
//! CRC-16/CCITT, shown as base32 grouped in fives behind the "AEGIS2-" prefix. The identity is the
//! StrongBox signing key (compressed P-256); the CRC only catches typing errors.
//!
//! The code carries no secret. Each side holds a static X25519 pairing key derived from its
//! persistent seed ([PairingSecret]); the PSK of a pair of contacts is derived from the X25519
//! exchange between the two keys and both codes' public fields ([PairingSecret::pair_psk]), so
//! whoever sees both codes still cannot compute it.

use crate::identity::validate_pub33;
use crate::CryptoError;
use aegiscall_memsec::SecretKey32;
use x25519_dalek::{PublicKey as XPublic, StaticSecret};
use zeroize::Zeroizing;

pub const PAIRING_V2_VERSION: u8 = 3;
pub const PAIRING_V2_RAW_LEN: usize = 68;
pub const PAIRING_V2_PREFIX: &str = "AEGIS2-";
const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const SECRET_CONTEXT: &str = "DialCrypt pairing v3 x25519";
const PSK_CONTEXT: &str = "DialCrypt pairing v3 psk";

fn crc16_ccitt(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &b in data {
        crc ^= u16::from(b) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 { (crc << 1) ^ 0x1021 } else { crc << 1 };
        }
    }
    crc
}

pub struct PairingCodeV2 {
    pub pub33: [u8; 33],
    /// X25519 public pairing key; the top bit of the last byte must be clear.
    pub xpub: [u8; 32],
}

impl PairingCodeV2 {
    pub fn new(pub33: [u8; 33], xpub: [u8; 32]) -> Result<Self, CryptoError> {
        validate_pub33(&pub33).map_err(|_| CryptoError::InvalidPairingCode)?;
        // X25519 ignores this bit, but the PSK derivation hashes the bytes as written: reject
        // it so that one key has exactly one code.
        if xpub[31] & 0x80 != 0 {
            return Err(CryptoError::InvalidPairingCode);
        }
        Ok(Self { pub33, xpub })
    }

    pub fn to_raw(&self) -> Zeroizing<[u8; PAIRING_V2_RAW_LEN]> {
        let mut raw = Zeroizing::new([0u8; PAIRING_V2_RAW_LEN]);
        raw[0] = PAIRING_V2_VERSION;
        raw[1..34].copy_from_slice(&self.pub33);
        raw[34..66].copy_from_slice(&self.xpub);
        let crc = crc16_ccitt(&raw[..66]);
        raw[66..68].copy_from_slice(&crc.to_be_bytes());
        raw
    }

    pub fn from_raw(raw: &[u8]) -> Result<Self, CryptoError> {
        let raw = <&[u8; PAIRING_V2_RAW_LEN]>::try_from(raw).map_err(|_| CryptoError::InvalidPairingCode)?;
        if crc16_ccitt(&raw[..66]) != u16::from_be_bytes([raw[66], raw[67]]) {
            return Err(CryptoError::InvalidPairingCode);
        }
        if raw[0] != PAIRING_V2_VERSION {
            return Err(CryptoError::InvalidPairingCode);
        }
        let mut pub33 = [0u8; 33];
        pub33.copy_from_slice(&raw[1..34]);
        let mut xpub = [0u8; 32];
        xpub.copy_from_slice(&raw[34..66]);
        Self::new(pub33, xpub)
    }

    pub fn to_code(&self) -> Zeroizing<String> {
        let raw = self.to_raw();
        let mut b32 = Zeroizing::new(String::with_capacity(110));
        let mut buffer: u32 = 0;
        let mut bits: u32 = 0;
        for &b in raw.iter() {
            buffer = (buffer << 8) | u32::from(b);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                b32.push(char::from(ALPHABET[((buffer >> bits) & 0x1F) as usize]));
            }
        }
        if bits > 0 {
            b32.push(char::from(ALPHABET[((buffer << (5 - bits)) & 0x1F) as usize]));
        }
        let mut out = Zeroizing::new(String::with_capacity(140));
        out.push_str(PAIRING_V2_PREFIX.trim_end_matches('-'));
        for (n, ch) in b32.chars().enumerate() {
            if n % 5 == 0 {
                out.push('-');
            }
            out.push(ch);
        }
        out
    }

    /// Strict parser: prefix, base32 alphabet (case-insensitive), '-' or space separators,
    /// exactly 68 bytes with zero padding bits, valid CRC, version and point.
    pub fn from_code(code: &str) -> Result<Self, CryptoError> {
        let trimmed = code.trim();
        let body = trimmed
            .get(..PAIRING_V2_PREFIX.len())
            .filter(|p| p.eq_ignore_ascii_case(PAIRING_V2_PREFIX))
            .and_then(|_| trimmed.get(PAIRING_V2_PREFIX.len()..))
            .ok_or(CryptoError::InvalidPairingCode)?;
        let mut out = Zeroizing::new(Vec::with_capacity(PAIRING_V2_RAW_LEN));
        let mut buffer: u32 = 0;
        let mut bits: u32 = 0;
        for ch in body.bytes() {
            let v = match ch {
                b'A'..=b'Z' => ch - b'A',
                b'a'..=b'z' => ch - b'a',
                b'2'..=b'7' => 26 + (ch - b'2'),
                b'-' | b' ' => continue,
                _ => return Err(CryptoError::InvalidPairingCode),
            };
            buffer = (buffer << 5) | u32::from(v);
            bits += 5;
            if bits >= 8 {
                bits -= 8;
                // Checked before the push so the buffer never grows (a reallocation would leave
                // an unwiped copy of the decoded bytes behind).
                if out.len() >= PAIRING_V2_RAW_LEN {
                    return Err(CryptoError::InvalidPairingCode);
                }
                out.push(((buffer >> bits) & 0xFF) as u8);
                buffer &= (1u32 << bits) - 1;
            }
        }
        if bits >= 5 || buffer != 0 {
            return Err(CryptoError::InvalidPairingCode);
        }
        Self::from_raw(&out)
    }
}

/// Static X25519 pairing key, derived from the 32-byte seed persisted in the app's contact
/// metadata. Not Clone or Debug; the key is zeroized on drop.
pub struct PairingSecret(StaticSecret);

impl PairingSecret {
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let k = Zeroizing::new(blake3::derive_key(SECRET_CONTEXT, seed));
        Self(StaticSecret::from(*k))
    }

    /// Public key shown in our pairing code.
    pub fn public(&self) -> [u8; 32] {
        XPublic::from(&self.0).to_bytes()
    }

    /// PSK shared with the owner of peer: BLAKE3 derive_key over the X25519 output and both
    /// sides' (pub33, X), ordered by pub33, so both sides compute the same key whichever code
    /// was imported first. Refuses our own identity or pairing key and keys that give a
    /// non-contributory (all-zero) exchange.
    pub fn pair_psk(&self, own_pub33: &[u8; 33], peer: &PairingCodeV2) -> Result<SecretKey32, CryptoError> {
        let own_x = self.public();
        if &peer.pub33 == own_pub33 || peer.xpub == own_x || peer.xpub[31] & 0x80 != 0 {
            return Err(CryptoError::InvalidPairingCode);
        }
        let shared = self.0.diffie_hellman(&XPublic::from(peer.xpub));
        if !shared.was_contributory() {
            return Err(CryptoError::InvalidPairingCode);
        }
        let ((p_lo, x_lo), (p_hi, x_hi)) =
            if own_pub33 <= &peer.pub33 { ((own_pub33, &own_x), (&peer.pub33, &peer.xpub)) } else { ((&peer.pub33, &peer.xpub), (own_pub33, &own_x)) };
        let mut m = Zeroizing::new([0u8; 162]);
        m[..32].copy_from_slice(shared.as_bytes());
        m[32..65].copy_from_slice(p_lo);
        m[65..97].copy_from_slice(x_lo);
        m[97..130].copy_from_slice(p_hi);
        m[130..].copy_from_slice(x_hi);
        Ok(SecretKey32::from_bytes(blake3::derive_key(PSK_CONTEXT, &m[..])))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::SoftwareSigner;

    fn with_crc(mut raw: [u8; PAIRING_V2_RAW_LEN]) -> [u8; PAIRING_V2_RAW_LEN] {
        let crc = crc16_ccitt(&raw[..66]);
        raw[66..].copy_from_slice(&crc.to_be_bytes());
        raw
    }

    struct Side {
        pub33: [u8; 33],
        secret: PairingSecret,
    }

    impl Side {
        fn new(n: u8) -> Self {
            Self { pub33: SoftwareSigner::from_seed([n; 32]).pub33(), secret: PairingSecret::from_seed(&[n.wrapping_add(100); 32]) }
        }
        fn code(&self) -> PairingCodeV2 {
            PairingCodeV2::new(self.pub33, self.secret.public()).unwrap()
        }
        fn psk(&self, peer: &PairingCodeV2) -> [u8; 32] {
            *self.secret.pair_psk(&self.pub33, peer).unwrap().as_bytes()
        }
    }

    #[test]
    fn pairing_v2_roundtrip_and_rejections() {
        let s = SoftwareSigner::generate();
        let xpub = PairingSecret::from_seed(&[0x3C; 32]).public();
        let p = PairingCodeV2::new(s.pub33(), xpub).unwrap();
        let raw = p.to_raw();
        assert_eq!(raw.len(), PAIRING_V2_RAW_LEN);
        assert_eq!(raw[0], 3);
        let code = p.to_code();
        assert!(code.starts_with("AEGIS2-"));
        let back = PairingCodeV2::from_code(&code).unwrap();
        assert_eq!(back.pub33, s.pub33());
        assert_eq!(back.xpub, xpub);
        assert!(PairingCodeV2::from_code(&code.to_lowercase()).is_ok());

        let mut bad_crc = *raw;
        bad_crc[40] ^= 1;
        assert!(PairingCodeV2::from_raw(&bad_crc).is_err());
        for ver in [0x12u8, 2, 4] {
            let mut other = *raw;
            other[0] = ver;
            assert!(PairingCodeV2::from_raw(&with_crc(other)).is_err(), "version {ver} accepted");
        }
        let mut bad_point = *raw;
        bad_point[1] = 0x04;
        assert!(PairingCodeV2::from_raw(&with_crc(bad_point)).is_err());
        let mut high_bit = *raw;
        high_bit[65] |= 0x80;
        assert!(PairingCodeV2::from_raw(&with_crc(high_bit)).is_err());
        let mut top = xpub;
        top[31] |= 0x80;
        assert!(PairingCodeV2::new(s.pub33(), top).is_err());
        assert!(PairingCodeV2::from_raw(&raw[..67]).is_err());
        assert!(PairingCodeV2::from_code(&code.replace("AEGIS2-", "AEGIS1-")).is_err());
        assert!(PairingCodeV2::from_code(&format!("{}A", &*code)).is_err());
        assert!(PairingCodeV2::from_code(&code[..code.len() - 1]).is_err());
        assert!(PairingCodeV2::from_code(&format!("AEGIS2-1{}", &code[8..])).is_err());
        assert!(PairingCodeV2::from_code(&format!("AEGIS2-!{}", &code[7..])).is_err());
        assert!(PairingCodeV2::from_code("").is_err());
        assert!(PairingCodeV2::from_code("AEGIS2").is_err());
    }

    #[test]
    fn pairing_secret_is_deterministic_per_seed() {
        let a = PairingSecret::from_seed(&[7; 32]).public();
        assert_eq!(a, PairingSecret::from_seed(&[7; 32]).public());
        assert_ne!(a, PairingSecret::from_seed(&[8; 32]).public());
        // The seed itself is never the X25519 scalar: its plain base-point product differs.
        assert_ne!(a, XPublic::from(&StaticSecret::from([7u8; 32])).to_bytes());
    }

    #[test]
    fn both_sides_derive_the_same_psk_and_other_pairs_differ() {
        let (a, b, c) = (Side::new(1), Side::new(2), Side::new(3));
        let ab = a.psk(&b.code());
        assert_eq!(ab, b.psk(&a.code()));
        let ac = a.psk(&c.code());
        assert_eq!(ac, c.psk(&a.code()));
        assert_ne!(ab, ac);
        assert_ne!(ab, b.psk(&c.code()));
        // Re-importing the same code gives the same key.
        assert_eq!(ab, a.psk(&PairingCodeV2::from_code(&b.code().to_code()).unwrap()));
    }

    #[test]
    fn psk_binds_every_bit_of_x_and_the_identity_key() {
        let (a, b, c) = (Side::new(1), Side::new(2), Side::new(3));
        let base = a.psk(&b.code());
        for bit in 0..255 {
            let mut x = b.secret.public();
            x[bit / 8] ^= 1 << (bit % 8);
            let peer = PairingCodeV2 { pub33: b.pub33, xpub: x };
            if let Ok(k) = a.secret.pair_psk(&a.pub33, &peer) {
                assert_ne!(*k.as_bytes(), base, "bit {bit} of X is not bound");
            }
        }
        // Same X under another identity key: another PSK.
        let swapped = PairingCodeV2::new(c.pub33, b.secret.public()).unwrap();
        assert_ne!(a.psk(&swapped), base);
    }

    #[test]
    fn own_keys_low_order_points_and_the_top_bit_are_refused() {
        let (a, b) = (Side::new(1), Side::new(2));
        let own_x = PairingCodeV2 { pub33: b.pub33, xpub: a.secret.public() };
        assert!(a.secret.pair_psk(&a.pub33, &own_x).is_err());
        let own_id = PairingCodeV2 { pub33: a.pub33, xpub: b.secret.public() };
        assert!(a.secret.pair_psk(&a.pub33, &own_id).is_err());
        let mut top = b.secret.public();
        top[31] |= 0x80;
        assert!(a.secret.pair_psk(&a.pub33, &PairingCodeV2 { pub33: b.pub33, xpub: top }).is_err());

        let mut p_minus_1 = [0xFFu8; 32];
        p_minus_1[0] = 0xEC;
        p_minus_1[31] = 0x7F;
        let mut p = p_minus_1;
        p[0] = 0xED;
        let mut one = [0u8; 32];
        one[0] = 1;
        let order8 = [
            0xE0, 0xEB, 0x7A, 0x7C, 0x3B, 0x41, 0xB8, 0xAE, 0x16, 0x56, 0xE3, 0xFA, 0xF1, 0x9F, 0xC4, 0x6A, 0xDA, 0x09, 0x8D,
            0xEB, 0x9C, 0x32, 0xB1, 0xFD, 0x86, 0x62, 0x05, 0x16, 0x5F, 0x49, 0xB8, 0x00,
        ];
        for x in [[0u8; 32], one, order8, p_minus_1, p] {
            let peer = PairingCodeV2::new(b.pub33, x).unwrap();
            assert!(a.secret.pair_psk(&a.pub33, &peer).is_err(), "low-order point {x:02x?} accepted");
        }
    }
}
