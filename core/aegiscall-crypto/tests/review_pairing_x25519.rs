//! Review tests for the X25519 pairing code. Independent reference
//! implementation of the documented derivation, so a wrong KDF, a missing pub33 or a missing
//! contributory check fails here.

use aegiscall_crypto::{PairingCodeV2, PairingSecret, SoftwareSigner};
use x25519_dalek::{PublicKey, StaticSecret};

fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &b in data {
        crc ^= u16::from(b) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 { (crc << 1) ^ 0x1021 } else { crc << 1 };
        }
    }
    crc
}

fn raw_with_crc(ver: u8, pub33: &[u8; 33], x: &[u8; 32]) -> [u8; 68] {
    let mut raw = [0u8; 68];
    raw[0] = ver;
    raw[1..34].copy_from_slice(pub33);
    raw[34..66].copy_from_slice(x);
    let c = crc16(&raw[..66]);
    raw[66..].copy_from_slice(&c.to_be_bytes());
    raw
}

fn pub33_of(n: u8) -> [u8; 33] {
    SoftwareSigner::from_seed([n; 32]).pub33()
}

/// Reference: x from the seed, psk from DH and both (pub33, X) pairs ordered by pub33.
fn ref_x(seed: &[u8; 32]) -> StaticSecret {
    StaticSecret::from(blake3::derive_key("DialCrypt pairing v3 x25519", seed))
}

fn ref_psk(own_seed: &[u8; 32], own_p: &[u8; 33], peer_p: &[u8; 33], peer_x: &[u8; 32]) -> [u8; 32] {
    let x = ref_x(own_seed);
    let own_x = PublicKey::from(&x).to_bytes();
    let dh = x.diffie_hellman(&PublicKey::from(*peer_x));
    let ((pl, xl), (ph, xh)) = if own_p <= peer_p { ((own_p, &own_x), (peer_p, peer_x)) } else { ((peer_p, peer_x), (own_p, &own_x)) };
    let mut m = Vec::new();
    m.extend_from_slice(dh.as_bytes());
    m.extend_from_slice(pl);
    m.extend_from_slice(xl);
    m.extend_from_slice(ph);
    m.extend_from_slice(xh);
    blake3::derive_key("DialCrypt pairing v3 psk", &m)
}

#[test]
fn public_key_and_psk_match_the_documented_derivation_for_both_orderings() {
    let (sa, sb) = ([0x11u8; 32], [0x22u8; 32]);
    let (pa, pb) = (pub33_of(1), pub33_of(2));
    let (a, b) = (PairingSecret::from_seed(&sa), PairingSecret::from_seed(&sb));
    assert_eq!(a.public(), PublicKey::from(&ref_x(&sa)).to_bytes());
    let (ca, cb) = (PairingCodeV2::new(pa, a.public()).unwrap(), PairingCodeV2::new(pb, b.public()).unwrap());
    let k_ab = *a.pair_psk(&pa, &cb).unwrap().as_bytes();
    let k_ba = *b.pair_psk(&pb, &ca).unwrap().as_bytes();
    assert_eq!(k_ab, ref_psk(&sa, &pa, &pb, &cb.xpub));
    assert_eq!(k_ba, ref_psk(&sb, &pb, &pa, &ca.xpub));
    assert_eq!(k_ab, k_ba);
    // a and b take opposite branches of the pub33 ordering, so both branches ran above.
    assert!(pa != pb);
}

#[test]
fn psk_depends_on_the_peer_pub33_even_with_the_same_x() {
    let a = PairingSecret::from_seed(&[5; 32]);
    let pa = pub33_of(5);
    let x = PairingSecret::from_seed(&[6; 32]).public();
    let k1 = *a.pair_psk(&pa, &PairingCodeV2::new(pub33_of(6), x).unwrap()).unwrap().as_bytes();
    let k2 = *a.pair_psk(&pa, &PairingCodeV2::new(pub33_of(7), x).unwrap()).unwrap().as_bytes();
    assert_ne!(k1, k2);
    // Our own identity key is part of the input too.
    let k3 = *a.pair_psk(&pub33_of(8), &PairingCodeV2::new(pub33_of(6), x).unwrap()).unwrap().as_bytes();
    assert_ne!(k1, k3);
}

#[test]
fn every_low_order_point_and_noncanonical_alias_is_refused() {
    let a = PairingSecret::from_seed(&[9; 32]);
    let pa = pub33_of(9);
    let hex = |s: &str| -> [u8; 32] {
        let mut o = [0u8; 32];
        for i in 0..32 {
            o[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        o
    };
    let mut p = [0xFFu8; 32];
    p[0] = 0xED;
    p[31] = 0x7F;
    let mut p_plus_1 = p;
    p_plus_1[0] = 0xEE;
    let mut p_minus_1 = p;
    p_minus_1[0] = 0xEC;
    let mut one = [0u8; 32];
    one[0] = 1;
    let points = [
        [0u8; 32],
        one,
        hex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
        hex("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
        p_minus_1,
        p,
        p_plus_1,
    ];
    for x in points {
        let code = PairingCodeV2::new(pub33_of(10), x).unwrap();
        assert!(a.pair_psk(&pa, &code).is_err(), "low-order point {x:02x?} accepted");
    }
}

#[test]
fn raw_parser_accepts_only_version_3_and_a_clear_top_bit() {
    let (p, x) = (pub33_of(3), PairingSecret::from_seed(&[3; 32]).public());
    assert!(PairingCodeV2::from_raw(&raw_with_crc(3, &p, &x)).is_ok());
    for ver in (0u8..=255).filter(|v| *v != 3) {
        assert!(PairingCodeV2::from_raw(&raw_with_crc(ver, &p, &x)).is_err(), "version {ver} accepted");
    }
    let mut hi = x;
    hi[31] |= 0x80;
    assert!(PairingCodeV2::from_raw(&raw_with_crc(3, &p, &hi)).is_err());
    let mut bad_pub = p;
    bad_pub[0] = 0x04;
    assert!(PairingCodeV2::from_raw(&raw_with_crc(3, &bad_pub, &x)).is_err());
    // A wrong CRC is refused even with everything else valid.
    let mut raw = raw_with_crc(3, &p, &x);
    raw[67] ^= 1;
    assert!(PairingCodeV2::from_raw(&raw).is_err());
    assert!(PairingCodeV2::from_raw(&[0u8; 67]).is_err());
    assert!(PairingCodeV2::from_raw(&[0u8; 69]).is_err());
}

#[test]
fn own_identity_or_own_pairing_key_in_a_peer_code_is_refused() {
    let a = PairingSecret::from_seed(&[12; 32]);
    let pa = pub33_of(12);
    let other_x = PairingSecret::from_seed(&[13; 32]).public();
    assert!(a.pair_psk(&pa, &PairingCodeV2::new(pa, other_x).unwrap()).is_err());
    assert!(a.pair_psk(&pa, &PairingCodeV2::new(pub33_of(13), a.public()).unwrap()).is_err());
    assert!(a.pair_psk(&pa, &PairingCodeV2::new(pub33_of(13), other_x).unwrap()).is_ok());
}
