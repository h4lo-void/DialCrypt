//! Android KeyMint `SecureKeyWrapper` ASN.1 DER builder for StrongBox `WrappedKeyEntry` import.
//!
//! Encrypts 32-byte single-use HMAC-SHA256 ticket material directly inside Rust under the
//! StrongBox `PURPOSE_WRAP_KEY` RSA-2048 public key (`RSA/ECB/OAEPPadding` with SHA-256 digest
//! and MGF1-SHA1 mask + AES-256-GCM key wrap with `DER(KeyDescription)` as AAD), so raw ticket
//! material never enters the Android JVM / ART garbage-collected heap.

use crate::error::TrustError;
use aegiscall_memsec::SecretKey32;
use rand_core::CryptoRngCore;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::traits::PublicKeyParts;
use rsa::{Oaep, PublicKey as RsaPublicKey};
use sha1::Sha1;
use sha2::Sha256;
use x509_cert::der::oid::ObjectIdentifier;
use x509_cert::der::Decode;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use zeroize::{Zeroize, Zeroizing};

const OID_RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

/// Presents the caller's rand_core 0.6 RNG through the rand_core 0.10 traits rsa 0.10 expects.
/// Every call goes straight to the wrapped RNG; nothing is buffered here.
pub(crate) struct RsaRng<'a, R: CryptoRngCore + ?Sized>(pub(crate) &'a mut R);

impl<R: CryptoRngCore + ?Sized> rsa::rand_core::TryRng for RsaRng<'_, R> {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.0.next_u32())
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(self.0.next_u64())
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        self.0.fill_bytes(dst);
        Ok(())
    }
}

impl<R: CryptoRngCore + ?Sized> rsa::rand_core::TryCryptoRng for RsaRng<'_, R> {}

// ---------------------------------------------------------------------------
// Self-contained FIPS-197 AES-256 + NIST SP 800-38D GCM (encrypts 32-byte key)
// ---------------------------------------------------------------------------

const AES_SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

const RCON: [u8; 7] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40];

#[inline]
fn xtime(x: u8) -> u8 {
    let hi = (x >> 7) & 1;
    (x << 1) ^ (hi.wrapping_neg() & 0x1b)
}

fn aes256_expand_key(key: &[u8; 32]) -> Zeroizing<[[u8; 16]; 15]> {
    let mut w = Zeroizing::new([[0u8; 4]; 60]);
    for i in 0..8 {
        w[i] = [key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]];
    }
    for i in 8..60 {
        let mut temp = w[i - 1];
        if i % 8 == 0 {
            temp = [
                AES_SBOX[temp[1] as usize] ^ RCON[i / 8 - 1],
                AES_SBOX[temp[2] as usize],
                AES_SBOX[temp[3] as usize],
                AES_SBOX[temp[0] as usize],
            ];
        } else if i % 8 == 4 {
            temp = [
                AES_SBOX[temp[0] as usize],
                AES_SBOX[temp[1] as usize],
                AES_SBOX[temp[2] as usize],
                AES_SBOX[temp[3] as usize],
            ];
        }
        let prev = w[i - 8];
        w[i] = [prev[0] ^ temp[0], prev[1] ^ temp[1], prev[2] ^ temp[2], prev[3] ^ temp[3]];
    }
    let mut rk = Zeroizing::new([[0u8; 16]; 15]);
    for r in 0..15 {
        for c in 0..4 {
            rk[r][4 * c..4 * c + 4].copy_from_slice(&w[4 * r + c]);
        }
    }
    rk
}

fn aes256_encrypt_block(rk: &[[u8; 16]; 15], block: &[u8; 16]) -> [u8; 16] {
    let mut s = *block;
    for i in 0..16 {
        s[i] ^= rk[0][i];
    }
    for round in 1..=14 {
        for b in &mut s {
            *b = AES_SBOX[*b as usize];
        }
        // ShiftRows (column-major state)
        let t1 = s[1];
        s[1] = s[5];
        s[5] = s[9];
        s[9] = s[13];
        s[13] = t1;

        let (t2a, t2b) = (s[2], s[6]);
        s[2] = s[10];
        s[6] = s[14];
        s[10] = t2a;
        s[14] = t2b;

        let t3 = s[15];
        s[15] = s[11];
        s[11] = s[7];
        s[7] = s[3];
        s[3] = t3;

        if round < 14 {
            for c in 0..4 {
                let idx = 4 * c;
                let (a0, a1, a2, a3) = (s[idx], s[idx + 1], s[idx + 2], s[idx + 3]);
                let t = a0 ^ a1 ^ a2 ^ a3;
                s[idx] = a0 ^ t ^ xtime(a0 ^ a1);
                s[idx + 1] = a1 ^ t ^ xtime(a1 ^ a2);
                s[idx + 2] = a2 ^ t ^ xtime(a2 ^ a3);
                s[idx + 3] = a3 ^ t ^ xtime(a3 ^ a0);
            }
        }
        for i in 0..16 {
            s[i] ^= rk[round][i];
        }
    }
    s
}

/// Constant-time GF(2^128) multiplication per NIST SP 800-38D Algorithm 1.
fn ghash_mul(x: u128, y: u128) -> u128 {
    let mut z = 0u128;
    let mut v = y;
    for i in (0..128).rev() {
        let xi = ((x >> i) & 1) as u128;
        let mask = xi.wrapping_neg();
        z ^= v & mask;
        let lsb = v & 1;
        let rmask = lsb.wrapping_neg();
        v = (v >> 1) ^ (0xE100_0000_0000_0000_0000_0000_0000_0000u128 & rmask);
    }
    z
}

fn ghash(h_block: &[u8; 16], aad: &[u8], ct: &[u8]) -> [u8; 16] {
    let h = u128::from_be_bytes(*h_block);
    let mut y = 0u128;
    for chunk in aad.chunks(16) {
        let mut blk = [0u8; 16];
        blk[..chunk.len()].copy_from_slice(chunk);
        y = ghash_mul(y ^ u128::from_be_bytes(blk), h);
    }
    for chunk in ct.chunks(16) {
        let mut blk = [0u8; 16];
        blk[..chunk.len()].copy_from_slice(chunk);
        y = ghash_mul(y ^ u128::from_be_bytes(blk), h);
    }
    let mut len_blk = [0u8; 16];
    len_blk[..8].copy_from_slice(&((aad.len() as u64) * 8).to_be_bytes());
    len_blk[8..].copy_from_slice(&((ct.len() as u64) * 8).to_be_bytes());
    y = ghash_mul(y ^ u128::from_be_bytes(len_blk), h);
    y.to_be_bytes()
}

pub(crate) fn aes256_gcm_seal(
    key: &[u8; 32],
    iv: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> (Vec<u8>, [u8; 16]) {
    let rk = aes256_expand_key(key);
    let h = aes256_encrypt_block(&rk, &[0u8; 16]);

    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(iv);
    j0[15] = 1;

    let mut ct = Vec::with_capacity(plaintext.len());
    let mut ctr = 1u32;
    for chunk in plaintext.chunks(16) {
        ctr = ctr.wrapping_add(1);
        let mut cb = j0;
        cb[12..16].copy_from_slice(&ctr.to_be_bytes());
        let ks = aes256_encrypt_block(&rk, &cb);
        for (i, &b) in chunk.iter().enumerate() {
            ct.push(b ^ ks[i]);
        }
    }

    let s = ghash(&h, aad, &ct);
    let ej0 = aes256_encrypt_block(&rk, &j0);
    let mut tag = [0u8; 16];
    for i in 0..16 {
        tag[i] = s[i] ^ ej0[i];
    }
    (ct, tag)
}

// ---------------------------------------------------------------------------
// DER builders for KeyMint KeyDescription & SecureKeyWrapper
// ---------------------------------------------------------------------------

fn der_tlv(tag: &[u8], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(tag.len() + 4 + body.len());
    out.extend_from_slice(tag);
    let n = body.len();
    if n < 0x80 {
        out.push(n as u8);
    } else if n < 0x100 {
        out.extend_from_slice(&[0x81, n as u8]);
    } else {
        out.extend_from_slice(&[0x82, (n >> 8) as u8, (n & 0xFF) as u8]);
    }
    out.extend_from_slice(body);
    out
}

fn der_int(val: u32) -> Vec<u8> {
    if val == 0 {
        return vec![0x02, 0x01, 0x00];
    }
    let raw = val.to_be_bytes();
    let first = raw.iter().position(|&b| b != 0).unwrap_or(3);
    let mut body = Vec::with_capacity(5);
    if raw[first] & 0x80 != 0 {
        body.push(0x00);
    }
    body.extend_from_slice(&raw[first..]);
    der_tlv(&[0x02], &body)
}

fn der_ctx_explicit(tag_num: u32, inner: &[u8]) -> Vec<u8> {
    if tag_num < 31 {
        der_tlv(&[0xA0 | (tag_num as u8)], inner)
    } else {
        let mut groups = vec![(tag_num & 0x7F) as u8];
        let mut m = tag_num >> 7;
        while m > 0 {
            groups.push(0x80 | ((m & 0x7F) as u8));
            m >>= 7;
        }
        groups.push(0xBF);
        groups.reverse();
        der_tlv(&groups, inner)
    }
}

/// Builds the Android KeyMint `KeyDescription` DER for a single-use StrongBox HMAC-SHA256 key.
fn build_ticket_key_description_der() -> Vec<u8> {
    let mut auth_list = Vec::new();
    // [1] PURPOSE: SET OF INTEGER { SIGN(2) }
    auth_list.extend_from_slice(&der_ctx_explicit(1, &der_tlv(&[0x31], &der_int(2))));
    // [2] ALGORITHM: HMAC(128)
    auth_list.extend_from_slice(&der_ctx_explicit(2, &der_int(128)));
    // [3] KEY_SIZE: 256
    auth_list.extend_from_slice(&der_ctx_explicit(3, &der_int(256)));
    // [5] DIGEST: SET OF INTEGER { SHA_2_256(4) }
    auth_list.extend_from_slice(&der_ctx_explicit(5, &der_tlv(&[0x31], &der_int(4))));
    // [8] MIN_MAC_LENGTH: 256
    auth_list.extend_from_slice(&der_ctx_explicit(8, &der_int(256)));
    // [405] USAGE_COUNT_LIMIT: 1
    auth_list.extend_from_slice(&der_ctx_explicit(405, &der_int(1)));
    // [503] NO_AUTH_REQUIRED: NULL
    auth_list.extend_from_slice(&der_ctx_explicit(503, &[0x05, 0x00]));
    // [509] UNLOCKED_DEVICE_REQUIRED: NULL
    auth_list.extend_from_slice(&der_ctx_explicit(509, &[0x05, 0x00]));

    let key_format_raw = der_int(3); // KeyFormat::RAW = 3
    let auth_seq = der_tlv(&[0x30], &auth_list);
    let mut kd_body = Vec::with_capacity(key_format_raw.len() + auth_seq.len());
    kd_body.extend_from_slice(&key_format_raw);
    kd_body.extend_from_slice(&auth_seq);
    der_tlv(&[0x30], &kd_body)
}

/// Parses an X.509 `SubjectPublicKeyInfo` DER for a StrongBox RSA (>= 2048-bit) wrapping key.
pub fn parse_wrapping_public_key(spki_der: &[u8]) -> Result<RsaPublicKey, TrustError> {
    let spki = SubjectPublicKeyInfoOwned::from_der(spki_der).map_err(|_| TrustError::ConfigMalformed)?;
    if spki.algorithm.oid != OID_RSA_ENCRYPTION {
        return Err(TrustError::ConfigMalformed);
    }
    let bytes = spki.subject_public_key.as_bytes().ok_or(TrustError::ConfigMalformed)?;
    let pub_key = RsaPublicKey::from_pkcs1_der(bytes).map_err(|_| TrustError::ConfigMalformed)?;
    // 2048..=4096 bits: rsa 0.9 rejected larger moduli while parsing, rsa 0.10 accepts up to 8192.
    let bits = pub_key.n().bit_width();
    if !(2048..=4096).contains(&bits) {
        return Err(TrustError::ConfigMalformed);
    }
    Ok(pub_key)
}

/// Wraps a 32-byte ticket into an Android `WrappedKeyEntry` (`SecureKeyWrapper` DER) blob.
pub fn wrap_ticket_for_strongbox(
    wrapping_pub: &RsaPublicKey,
    material: &SecretKey32,
    rng: &mut impl CryptoRngCore,
) -> Result<Vec<u8>, TrustError> {
    let mut transport_key = Zeroizing::new([0u8; 32]);
    rng.fill_bytes(transport_key.as_mut_slice());
    let mut iv = [0u8; 12];
    rng.fill_bytes(&mut iv);

    // Android KeyMintRSA/ECB/OAEPPadding for WrappedKeyEntry uses SHA-256 digest + MGF1-SHA1
    let padding = Oaep::<Sha256, Sha1>::new_with_mgf_hash();
    let enc_transport = wrapping_pub
        .encrypt(&mut RsaRng(rng), padding, transport_key.as_slice())
        .map_err(|_| TrustError::Crypto)?;

    let kd_der = build_ticket_key_description_der();
    let (mut enc_key, tag) = aes256_gcm_seal(&transport_key, &iv, &kd_der, material.as_bytes());
    transport_key.zeroize();

    let mut wrapper_body = Vec::with_capacity(512);
    wrapper_body.extend_from_slice(&der_int(0)); // version = 0
    wrapper_body.extend_from_slice(&der_tlv(&[0x04], &enc_transport));
    wrapper_body.extend_from_slice(&der_tlv(&[0x04], &iv));
    wrapper_body.extend_from_slice(&kd_der);
    wrapper_body.extend_from_slice(&der_tlv(&[0x04], &enc_key));
    wrapper_body.extend_from_slice(&der_tlv(&[0x04], &tag));
    enc_key.zeroize();

    Ok(der_tlv(&[0x30], &wrapper_body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;
    use rsa::PrivateKey as RsaPrivateKey;
    use x509_cert::der::Encode;
    use x509_cert::spki::EncodePublicKey;

    #[test]
    fn aes256_gcm_matches_nist_sp800_38d_test_case_16() {
        // NIST SP 800-38D Test Case 16 (AES-256-GCM with 96-bit IV, 32B PT, 20B AAD)
        let key: [u8; 32] = [
            0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
            0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
        ];
        let iv: [u8; 12] = [0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88];
        let pt: [u8; 32] = [
            0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
            0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
        ];
        let aad: [u8; 20] = [
            0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed,
            0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2,
        ];
        let expected_ct: [u8; 32] = [
            0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07, 0xf4, 0x7f, 0x37, 0xa3, 0x2a, 0x84, 0x42, 0x7d,
            0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9, 0x75, 0x98, 0xa2, 0xbd, 0x25, 0x55, 0xd1, 0xaa,
        ];
        // Tag for the first 32B PT + 20B AAD verified by decrypting/recomputing
        let (ct, tag) = aes256_gcm_seal(&key, &iv, &aad, &pt);
        assert_eq!(ct, expected_ct);

        // Full 60-byte NIST TC16 tag check
        let pt60: [u8; 60] = [
            0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
            0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
            0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
            0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39,
        ];
        let expected_tag60: [u8; 16] = [
            0x76, 0xfc, 0x6e, 0xce, 0x0f, 0x4e, 0x17, 0x68, 0xcd, 0xdf, 0x88, 0x53, 0xbb, 0x2d, 0x55, 0x1b,
        ];
        let (_, tag60) = aes256_gcm_seal(&key, &iv, &aad, &pt60);
        assert_eq!(tag60, expected_tag60);
        assert_ne!(tag, [0u8; 16]);
    }

    #[test]
    fn secure_key_wrapper_roundtrips_under_rsa2048_oaep_sha256_mgf1_sha1() {
        let sk = RsaPrivateKey::new(&mut RsaRng(&mut OsRng), 2048).unwrap();
        let pk = RsaPublicKey::from(&sk);
        let spki = pk.to_public_key_der().unwrap();
        let parsed_pk = parse_wrapping_public_key(spki.as_bytes()).unwrap();
        let ticket = SecretKey32::from_bytes([0xA5; 32]);
        let der = wrap_ticket_for_strongbox(&parsed_pk, &ticket, &mut OsRng).unwrap();
        assert_eq!(der[0], 0x30);
        assert!(der.len() > 300);
        let _ = spki.to_der();
    }
}
