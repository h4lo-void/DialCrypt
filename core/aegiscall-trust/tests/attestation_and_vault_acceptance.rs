//! Reviewer acceptance tests for WP2 (aegiscall-trust). Public API only, production KDF.
use aegiscall_trust::keydesc::parse_key_description;
use aegiscall_trust::*;
use hmac::{Hmac, Mac};
use p256::ecdsa::signature::{Keypair, Signer};
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use std::collections::BTreeMap;
use std::str::FromStr;
use std::time::Duration;
use x509_cert::builder::{Builder, CertificateBuilder};
use x509_cert::certificate::Version;
use x509_cert::der::asn1::{Any, BitString};
use x509_cert::der::{Decode, Encode, Tag};
use x509_cert::ext::pkix::BasicConstraints;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{DynSignatureAlgorithmIdentifier, EncodePublicKey, SignatureBitStringEncoding, SubjectPublicKeyInfoOwned};
use x509_cert::time::Validity;
use x509_cert::Certificate;

const PIN: &[u8] = b"246810";
const DURESS: &[u8] = b"135790";
const WRONG: &[u8] = b"000000";
const SIGNER: [u8; 32] = [0x5a; 32];

// ---------------------------------------------------------------- vault helpers

#[derive(Clone, Default)]
struct Ks(BTreeMap<u32, [u8; 32]>);

impl Ks {
    fn import(&mut self, r: &Rotation) {
        for (id, m) in &r.new {
            self.0.insert(*id, *m.as_bytes());
        }
    }
    fn use_t(&mut self, id: u32, input: &[u8; 32]) -> Option<[u8; 32]> {
        let k = self.0.remove(&id)?;
        let mut m = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(&k).unwrap();
        m.update(input);
        let tag = m.finalize().into_bytes();
        let mut out = [0u8; 32];
        out.copy_from_slice(&tag);
        Some(out)
    }
    fn live(&self) -> Vec<u32> {
        self.0.keys().copied().collect()
    }
}

fn attempt(ks: &mut Ks, blob: &[u8], pin: &[u8]) -> UnlockOutcome {
    let tu = match Vault::begin_unlock(blob, pin, &ks.live()) {
        Ok(t) => t,
        Err(TrustError::VaultDead) => return UnlockOutcome::Dead,
        Err(_) => return UnlockOutcome::Malformed,
    };
    let out = ks.use_t(tu.ticket_id, tu.hmac_input.as_bytes());
    Vault::finish_unlock(blob, tu, out.as_ref(), &ks.live())
}

fn fresh() -> (Vault, Vec<u8>, Ks) {
    let (mut v, rot) = Vault::create(PIN, DURESS, &mut OsRng).unwrap();
    assert_eq!(rot.new.len(), TICKETS_PER_VAULT);
    assert!(rot.retire.is_empty());
    let mut ks = Ks::default();
    ks.import(&rot);
    let blob = v.commit_rotation().unwrap();
    (v, blob, ks)
}

#[test]
fn vault_flow_with_production_kdf() {
    let (_v, blob, ks) = fresh();
    assert_eq!(blob.len(), VAULT_PAD_BLOCK);
    assert_eq!(Vault::ticket_ids(&blob).unwrap(), vec![1, 2, 3, 4, 5]);

    let mut ksn = ks.clone();
    let mut n = match attempt(&mut ksn, &blob, PIN) {
        UnlockOutcome::Normal(n) => *n,
        o => panic!("expected Normal, got {o:?}"),
    };
    assert!(n.rotation_required());
    assert_eq!(n.export().err(), Some(TrustError::RotationRequired));

    match attempt(&mut ks.clone(), &blob, DURESS) {
        UnlockOutcome::Duress => {}
        o => panic!("expected Duress, got {o:?}"),
    }
    assert!(matches!(attempt(&mut ks.clone(), &blob, WRONG), UnlockOutcome::Invalid { left: 4 }));

    // Rotation: new root key and file, old file dead once the old tickets are retired.
    let rot2 = n.begin_rotation(&mut OsRng).unwrap();
    ksn.import(&rot2);
    let blob2 = n.commit_rotation().unwrap();
    assert_eq!(rot2.retire, vec![1, 2, 3, 4, 5]);
    assert_eq!(Vault::ticket_ids(&blob2).unwrap(), vec![6, 7, 8, 9, 10]);
    assert_ne!(blob[34..50], blob2[34..50]);
    for id in &rot2.retire {
        let _ = ksn.use_t(*id, &[0u8; 32]);
    }
    assert!(matches!(attempt(&mut ksn.clone(), &blob, PIN), UnlockOutcome::Dead));
    assert!(matches!(attempt(&mut ksn.clone(), &blob2, PIN), UnlockOutcome::Normal(_)));
}

#[test]
fn vault_file_parsers_survive_garbage_and_mutation() {
    let (_v, blob, ks) = fresh();
    let live = ks.live();
    let mut rnd = [0u8; 32];
    for it in 0..4000u32 {
        let mut m = blob.clone();
        OsRng.fill_bytes(&mut rnd);
        let edits = 1 + (rnd[0] as usize % 8);
        for e in 0..edits {
            let pos = (u16::from_le_bytes([rnd[1 + e * 3], rnd[2 + e * 3]]) as usize) % m.len();
            m[pos] ^= rnd[3 + e * 3] | 1;
        }
        match it % 4 {
            1 => m.truncate(m.len() - 1 - (rnd[30] as usize % 4000)),
            2 => m.extend_from_slice(&rnd),
            _ => {}
        }
        let _ = Vault::ticket_ids(&m);
        let mut out = [0u8; 32];
        OsRng.fill_bytes(&mut out);
        let id = live[it as usize % live.len()];
        let consumed: Vec<u32> = live.iter().copied().filter(|l| *l != id).collect();
        let tu = TicketUse { ticket_id: id, hmac_input: SecretKey32::from_bytes(rnd) };
        let r = Vault::finish_unlock(&m, tu, Some(&out), &consumed);
        assert!(!matches!(r, UnlockOutcome::Normal(_) | UnlockOutcome::Duress));
    }
    for len in [0usize, 1, 4, 51, 573, 574, 4095, 4096, 8192, 1 << 20, (1 << 20) + 4096, 3 << 20] {
        let mut g = vec![0u8; len];
        OsRng.fill_bytes(&mut g);
        if len >= 4 {
            g[..4].copy_from_slice(b"AGVT");
        }
        let _ = Vault::ticket_ids(&g);
        let tu = TicketUse { ticket_id: 1, hmac_input: SecretKey32::from_bytes([7u8; 32]) };
        assert!(matches!(Vault::finish_unlock(&g, tu, Some(&[7u8; 32]), &[1]), UnlockOutcome::Malformed | UnlockOutcome::Dead | UnlockOutcome::Invalid { .. }));
    }
}

// ---------------------------------------------------------------- attestation helpers

fn cfg(root: &[u8]) -> TrustConfig {
    TrustConfig::new(&[root], &[], &[], &[SIGNER], 202401).unwrap()
}

fn spki_of<K: EncodePublicKey>(k: &K) -> SubjectPublicKeyInfoOwned {
    SubjectPublicKeyInfoOwned::from_der(k.to_public_key_der().unwrap().as_bytes()).unwrap()
}

fn nm(s: &str) -> Name {
    Name::from_str(s).unwrap()
}

fn issue<S, Sig>(signer: &S, profile: Profile, serial: u8, subject: &str, spki: SubjectPublicKeyInfoOwned, leaf: bool) -> Vec<u8>
where
    S: Keypair + DynSignatureAlgorithmIdentifier + Signer<Sig>,
    S::VerifyingKey: EncodePublicKey,
    Sig: SignatureBitStringEncoding,
{
    let mut b = CertificateBuilder::new(
        FixtureProfile { kind: profile, subject: nm(subject) },
        SerialNumber::new(&[0x01, serial]).unwrap(),
        Validity::from_now(Duration::from_secs(3600)).unwrap(),
        spki,
    )
    .unwrap();
    if leaf {
        b.add_extension(&BasicConstraints { ca: false, path_len_constraint: None }).unwrap();
    }
    b.build::<_, Sig>(signer).unwrap().to_der().unwrap()
}

fn key_missing() -> Option<TrustError> {
    Some(TrustError::Attestation(AttestError::KeyDescriptionMissing))
}

fn rsa_inter_chain(bits: usize) -> (Vec<u8>, Vec<Vec<u8>>, [u8; 33]) {
    let root_k = <p256::ecdsa::SigningKey as p256::elliptic_curve::Generate>::generate();
    let root = issue::<_, p256::ecdsa::DerSignature>(&root_k, Profile::Root, 1, "CN=R Root", spki_of(root_k.verifying_key()), false);
    let rsa_k = rsa::pkcs1v15::SigningKey::<Sha256>::new(rsa::PrivateKey::new(&mut p256::elliptic_curve::common::getrandom::SysRng, bits).unwrap());
    let inter = issue::<_, p256::ecdsa::DerSignature>(
        &root_k,
        Profile::SubCA { issuer: nm("CN=R Root"), path_len_constraint: None },
        2,
        "CN=R Inter",
        spki_of(&rsa_k.verifying_key()),
        false,
    );
    let leaf_k = <p256::ecdsa::SigningKey as p256::elliptic_curve::Generate>::generate();
    let leaf = issue::<_, rsa::pkcs1v15::Signature>(
        &rsa_k,
        Profile::Manual { issuer: Some(nm("CN=R Inter")) },
        3,
        "CN=R Leaf",
        spki_of(leaf_k.verifying_key()),
        true,
    );
    let p33 = <[u8; 33]>::try_from(leaf_k.verifying_key().to_sec1_point(true).as_bytes()).unwrap();
    (root, vec![leaf, inter], p33)
}

#[test]
fn rsa_issuer_below_2048_bits_is_rejected() {
    let (root, chain, p33) = rsa_inter_chain(1536);
    assert_eq!(
        verify_attestation(&chain, &cfg(&root), &p33).err(),
        Some(TrustError::Attestation(AttestError::UnsupportedAlgorithm { index: 0 }))
    );
    // Control: identical structure with a 2048-bit issuer passes the chain stage.
    let (root, chain, p33) = rsa_inter_chain(2048);
    assert_eq!(verify_attestation(&chain, &cfg(&root), &p33).err(), key_missing());
}

/// root(P-256) -> inter(P-256) -> leaf(with the given SPKI); returns (root, inter, leaf, inter key).
fn p256_chain(leaf_spki: SubjectPublicKeyInfoOwned) -> (Vec<u8>, Vec<u8>, Vec<u8>, p256::ecdsa::SigningKey) {
    let root_k = <p256::ecdsa::SigningKey as p256::elliptic_curve::Generate>::generate();
    let root = issue::<_, p256::ecdsa::DerSignature>(&root_k, Profile::Root, 1, "CN=P Root", spki_of(root_k.verifying_key()), false);
    let inter_k = <p256::ecdsa::SigningKey as p256::elliptic_curve::Generate>::generate();
    let inter = issue::<_, p256::ecdsa::DerSignature>(
        &root_k,
        Profile::SubCA { issuer: nm("CN=P Root"), path_len_constraint: None },
        2,
        "CN=P Inter",
        spki_of(inter_k.verifying_key()),
        false,
    );
    let leaf = issue::<_, p256::ecdsa::DerSignature>(&inter_k, Profile::Manual { issuer: Some(nm("CN=P Inter")) }, 3, "CN=P Leaf", leaf_spki, true);
    (root, inter, leaf, inter_k)
}

#[test]
fn certificate_version_must_be_v3() {
    let leaf_k = <p256::ecdsa::SigningKey as p256::elliptic_curve::Generate>::generate();
    let p33 = <[u8; 33]>::try_from(leaf_k.verifying_key().to_sec1_point(true).as_bytes()).unwrap();
    let (root, inter, leaf, inter_k) = p256_chain(spki_of(leaf_k.verifying_key()));
    let resign = |version: Version| -> Vec<u8> {
        // x509-cert 0.3 has no field setters: patch the version INTEGER inside the DER TBS
        // ([0] EXPLICIT INTEGER, same length for v2 and v3) and reassemble the certificate.
        let c = Certificate::from_der(&leaf).unwrap();
        let mut tbs = c.tbs_certificate().to_der().unwrap();
        let at = tbs.windows(5).position(|w| w == [0xa0, 0x03, 0x02, 0x01, Version::V3 as u8]).unwrap();
        tbs[at + 4] = version as u8;
        let sig: p256::ecdsa::DerSignature = inter_k.sign(&tbs);
        let mut body = tbs;
        body.extend_from_slice(&c.signature_algorithm().to_der().unwrap());
        body.extend_from_slice(&BitString::from_bytes(sig.as_bytes()).unwrap().to_der().unwrap());
        Any::new(Tag::Sequence, body).unwrap().to_der().unwrap()
    };
    let ok = vec![resign(Version::V3), inter.clone()];
    assert_eq!(verify_attestation(&ok, &cfg(&root), &p33).err(), key_missing());
    let v2 = vec![resign(Version::V2), inter];
    assert_eq!(
        verify_attestation(&v2, &cfg(&root), &p33).err(),
        Some(TrustError::Attestation(AttestError::CertMalformed { index: 0 }))
    );
}

#[test]
fn leaf_key_must_be_p256() {
    let k384 = <p384::ecdsa::SigningKey as p256::elliptic_curve::Generate>::generate();
    let (root, inter, leaf, _) = p256_chain(spki_of(k384.verifying_key()));
    assert_eq!(
        verify_attestation(&[leaf, inter], &cfg(&root), &[2u8; 33]).err(),
        Some(TrustError::Attestation(AttestError::LeafKeyNotP256))
    );
}

#[test]
fn trust_config_has_no_builtin_defaults() {
    let bad = Some(TrustError::ConfigMalformed);
    assert_eq!(TrustConfig::from_tlv(&[]).err(), bad);
    assert_eq!(TrustConfig::from_tlv(&[1]).err(), bad);
    assert_eq!(TrustConfig::new(&[], &[], &[], &[SIGNER], 202401).err(), bad);
    let k = <p256::ecdsa::SigningKey as p256::elliptic_curve::Generate>::generate();
    let root = issue::<_, p256::ecdsa::DerSignature>(&k, Profile::Root, 1, "CN=X", spki_of(k.verifying_key()), false);
    assert_eq!(TrustConfig::new(&[&root], &[], &[], &[], 202401).err(), bad);
    assert_eq!(TrustConfig::new(&[&root], &[], &[], &[SIGNER], 0).err(), bad);
}

#[test]
fn attestation_parsers_survive_garbage() {
    let k = <p256::ecdsa::SigningKey as p256::elliptic_curve::Generate>::generate();
    let root = issue::<_, p256::ecdsa::DerSignature>(&k, Profile::Root, 1, "CN=X", spki_of(k.verifying_key()), false);
    let c = cfg(&root);
    let p33 = [2u8; 33];
    let mut rnd = [0u8; 64];
    for _ in 0..3000 {
        OsRng.fill_bytes(&mut rnd);
        let n = 2 + (rnd[0] as usize % 4);
        let chain: Vec<Vec<u8>> = (0..n)
            .map(|i| {
                let len = (u16::from_le_bytes([rnd[1 + i], rnd[10 + i]]) as usize) % 1500;
                let mut v = vec![0u8; len];
                OsRng.fill_bytes(&mut v);
                if len > 4 && rnd[20 + i] % 2 == 0 {
                    v[0] = 0x30;
                    v[1] = 0x82;
                }
                v
            })
            .collect();
        assert!(verify_attestation(&chain, &c, &p33).is_err());
        let mut kd = vec![0u8; (rnd[40] as usize) % 300];
        OsRng.fill_bytes(&mut kd);
        if kd.len() > 4 {
            kd[0] = 0x30;
        }
        let _ = parse_key_description(&kd);
    }
    assert_eq!(
        verify_attestation(&vec![vec![1u8]; 1000], &c, &p33).err(),
        Some(TrustError::Attestation(AttestError::ChainLength))
    );
    assert_eq!(
        verify_attestation(&[vec![0u8; 17 * 1024], vec![0u8; 3]], &c, &p33).err(),
        Some(TrustError::Attestation(AttestError::CertMalformed { index: 0 }))
    );
    for kd in [
        vec![0x30, 0x84, 0xff, 0xff, 0xff, 0xff],
        vec![0x30, 0x80],
        vec![0x30, 0x88, 1, 0, 0, 0, 0, 0, 0, 0, 0],
        vec![0xbf, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f, 0x00],
        vec![0x30, 0x03, 0x02, 0x01],
        vec![],
    ] {
        assert!(parse_key_description(&kd).is_err());
    }
}

// x509-cert 0.3 replaced the builder's `Profile` enum with the `BuilderProfile` trait. This keeps
// the 0.2 Root / SubCA / Manual variants these fixtures use and emits the same extensions, in the
// same order, as x509-cert 0.2 did.
mod fixture_profile {
    use x509_cert::builder::profile::BuilderProfile;
    use x509_cert::certificate::TbsCertificate;
    use x509_cert::ext::pkix::{AuthorityKeyIdentifier, BasicConstraints, KeyUsage, KeyUsages, SubjectKeyIdentifier};
    use x509_cert::ext::{Extension, ToExtension};
    use x509_cert::name::Name;
    use x509_cert::spki::SubjectPublicKeyInfoRef;

    pub(super) enum Profile {
        Root,
        SubCA { issuer: Name, path_len_constraint: Option<u8> },
        Manual { issuer: Option<Name> },
    }

    pub(super) struct FixtureProfile {
        pub(super) kind: Profile,
        pub(super) subject: Name,
    }

    impl BuilderProfile for FixtureProfile {
        fn get_issuer(&self, subject: &Name) -> Name {
            match &self.kind {
                Profile::Root => subject.clone(),
                Profile::SubCA { issuer, .. } => issuer.clone(),
                Profile::Manual { issuer } => issuer.as_ref().unwrap_or(subject).clone(),
            }
        }

        fn get_subject(&self) -> Name {
            self.subject.clone()
        }

        fn build_extensions(
            &self,
            spk: SubjectPublicKeyInfoRef<'_>,
            issuer_spk: SubjectPublicKeyInfoRef<'_>,
            tbs: &TbsCertificate,
        ) -> x509_cert::builder::Result<Vec<Extension>> {
            let path_len_constraint = match &self.kind {
                Profile::Manual { .. } => return Ok(Vec::new()),
                Profile::Root => None,
                Profile::SubCA { path_len_constraint, .. } => *path_len_constraint,
            };
            let subject = tbs.subject();
            let mut exts = Vec::new();
            exts.push(SubjectKeyIdentifier::try_from(spk)?.to_extension(subject, &exts)?);
            if !matches!(self.kind, Profile::Root) {
                exts.push(AuthorityKeyIdentifier::try_from(issuer_spk)?.to_extension(subject, &exts)?);
            }
            exts.push(BasicConstraints { ca: true, path_len_constraint }.to_extension(subject, &exts)?);
            exts.push(KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign).to_extension(subject, &exts)?);
            Ok(exts)
        }
    }
}
use fixture_profile::{FixtureProfile, Profile};
