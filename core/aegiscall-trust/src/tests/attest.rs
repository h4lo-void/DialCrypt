use super::*;
use crate::keydesc::parse_key_description;
use p256::ecdsa::signature::{Keypair, Signer};
use rand_core::OsRng;
use std::str::FromStr;
use std::sync::OnceLock;
use std::time::Duration;
use x509_cert::builder::{Builder, CertificateBuilder};
use x509_cert::der::oid::AssociatedOid;
use x509_cert::der::{Length, Writer};
use x509_cert::ext::{Criticality, Extension};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{DynSignatureAlgorithmIdentifier, EncodePublicKey, SignatureBitStringEncoding};
use x509_cert::time::Validity;

const SIGNER: [u8; 32] = [0x5a; 32];
const AVB_KEY: [u8; 32] = [0x33; 32];
const MIN_PATCH: u32 = 202401;
const ROOT_CN: &str = "CN=Test Attestation Root";

// ------------------------------------------------------------ DER writer for KeyDescription

fn tlv(tag: &[u8], content: &[u8]) -> Vec<u8> {
    let mut o = tag.to_vec();
    let n = content.len();
    if n < 0x80 {
        o.push(n as u8);
    } else if n < 0x100 {
        o.extend_from_slice(&[0x81, n as u8]);
    } else {
        o.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]);
    }
    o.extend_from_slice(content);
    o
}
fn uint_bytes(v: u64) -> Vec<u8> {
    let mut b: Vec<u8> = v.to_be_bytes().iter().copied().skip_while(|x| *x == 0).collect();
    if b.first().map_or(true, |x| x & 0x80 != 0) {
        b.insert(0, 0);
    }
    b
}
fn int(v: u64) -> Vec<u8> {
    tlv(&[0x02], &uint_bytes(v))
}
fn enm(v: u64) -> Vec<u8> {
    tlv(&[0x0a], &uint_bytes(v))
}
fn oct(b: &[u8]) -> Vec<u8> {
    tlv(&[0x04], b)
}
fn boolean(b: bool) -> Vec<u8> {
    vec![0x01, 0x01, if b { 0xff } else { 0x00 }]
}
fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(&[0x30], &parts.concat())
}
fn set(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(&[0x31], &parts.concat())
}
fn ctx(n: u32, inner: &[u8]) -> Vec<u8> {
    if n < 31 {
        tlv(&[0xa0 | n as u8], inner)
    } else {
        let mut groups = vec![(n & 0x7f) as u8];
        let mut m = n >> 7;
        while m > 0 {
            groups.push(0x80 | (m & 0x7f) as u8);
            m >>= 7;
        }
        groups.push(0xbf);
        groups.reverse();
        tlv(&groups, inner)
    }
}

#[derive(Clone)]
struct KdSpec {
    att_ver: u64,
    att_level: u64,
    km_level: u64,
    challenge: Vec<u8>,
    purpose: Option<Vec<u64>>,
    algorithm: Option<u64>,
    digest: Option<Vec<u64>>,
    curve: Option<u64>,
    origin: Option<u64>,
    rot: Option<(Vec<u8>, bool, u64)>,
    patch: Option<u64>,
    brand: Option<Vec<u8>>,
    app_id: Option<(Vec<Vec<u8>>, Vec<Vec<u8>>)>,
}

impl Default for KdSpec {
    fn default() -> Self {
        KdSpec {
            att_ver: 300,
            att_level: 2,
            km_level: 2,
            challenge: ATTESTATION_CHALLENGE.to_vec(),
            purpose: Some(vec![2]),
            algorithm: Some(3),
            digest: Some(vec![4]),
            curve: Some(1),
            origin: Some(0),
            rot: Some((vec![0x44; 32], true, 0)),
            patch: Some(202409),
            brand: Some(b"google".to_vec()),
            app_id: Some((vec![APP_PACKAGE.to_vec()], vec![SIGNER.to_vec()])),
        }
    }
}

fn encode_kd(s: &KdSpec) -> Vec<u8> {
    let mut hw = Vec::new();
    if let Some(p) = &s.purpose {
        hw.extend(ctx(1, &set(&p.iter().map(|v| int(*v)).collect::<Vec<_>>())));
    }
    if let Some(a) = s.algorithm {
        hw.extend(ctx(2, &int(a)));
    }
    hw.extend(ctx(3, &int(256)));
    if let Some(d) = &s.digest {
        hw.extend(ctx(5, &set(&d.iter().map(|v| int(*v)).collect::<Vec<_>>())));
    }
    if let Some(c) = s.curve {
        hw.extend(ctx(10, &int(c)));
    }
    hw.extend(ctx(503, &[0x05, 0x00]));
    if let Some(o) = s.origin {
        hw.extend(ctx(702, &int(o)));
    }
    if let Some((key, locked, state)) = &s.rot {
        hw.extend(ctx(704, &seq(&[oct(key), boolean(*locked), enm(*state), oct(&[0x55; 32])])));
    }
    hw.extend(ctx(705, &int(150000)));
    if let Some(p) = s.patch {
        hw.extend(ctx(706, &int(p)));
    }
    if let Some(b) = &s.brand {
        hw.extend(ctx(710, &oct(b)));
    }
    hw.extend(ctx(718, &int(20240905)));
    let mut sw = Vec::new();
    sw.extend(ctx(701, &int(1_700_000_000_000)));
    if let Some((pkgs, sigs)) = &s.app_id {
        let p: Vec<Vec<u8>> = pkgs.iter().map(|n| seq(&[oct(n), int(1)])).collect();
        let d: Vec<Vec<u8>> = sigs.iter().map(|x| oct(x)).collect();
        sw.extend(ctx(709, &oct(&seq(&[set(&p), set(&d)]))));
    }
    seq(&[
        int(s.att_ver),
        enm(s.att_level),
        int(300),
        enm(s.km_level),
        oct(&s.challenge),
        oct(&[]),
        tlv(&[0x30], &sw),
        tlv(&[0x30], &hw),
    ])
}

// ------------------------------------------------------------ certificate builder helpers

struct KdExt(Vec<u8>);
impl AssociatedOid for KdExt {
    const OID: ObjectIdentifier = OID_KEY_DESCRIPTION;
}
impl Encode for KdExt {
    fn encoded_len(&self) -> x509_cert::der::Result<Length> {
        Length::try_from(self.0.len())
    }
    fn encode(&self, w: &mut impl Writer) -> x509_cert::der::Result<()> {
        w.write(&self.0)
    }
}
impl Criticality for KdExt {
    fn criticality(&self, _: &Name, _: &[Extension]) -> bool {
        false
    }
}

fn build_cert<S, Sig>(signer: &S, profile: Profile, serial: u8, subject: &str, spki: SubjectPublicKeyInfoOwned, exts: &[KdExt], dup_bc: bool) -> Vec<u8>
where
    S: Keypair + DynSignatureAlgorithmIdentifier + Signer<Sig>,
    S::VerifyingKey: EncodePublicKey,
    Sig: SignatureBitStringEncoding,
{
    // The builder emits X.509 v1 when no extension is present; give manual-profile
    // certificates a non-CA BasicConstraints so every fixture stays v3 like real chains.
    let manual = matches!(profile, Profile::Manual { .. });
    let mut b = CertificateBuilder::new(
        FixtureProfile { kind: profile, subject: Name::from_str(subject).unwrap() },
        SerialNumber::new(&[0x01, serial]).unwrap(),
        Validity::from_now(Duration::from_secs(3600)).unwrap(),
        spki,
    )
    .unwrap();
    if manual {
        b.add_extension(&BasicConstraints { ca: false, path_len_constraint: None }).unwrap();
    }
    if dup_bc {
        // Second BasicConstraints next to the one the CA profile already added.
        b.add_extension(&BasicConstraints { ca: true, path_len_constraint: None }).unwrap();
    }
    for e in exts {
        b.add_extension(e).unwrap();
    }
    b.build::<_, Sig>(signer).unwrap().to_der().unwrap()
}

enum TestKey {
    P256(p256::ecdsa::SigningKey),
    P384(p384::ecdsa::SigningKey),
    Rsa(Box<rsa::pkcs1v15::SigningKey<Sha256>>),
}

fn rsa_key() -> rsa::PrivateKey {
    static KEY: OnceLock<rsa::PrivateKey> = OnceLock::new();
    KEY.get_or_init(|| rsa::PrivateKey::new(&mut crate::wrap::RsaRng(&mut OsRng), 2048).unwrap()).clone()
}

impl TestKey {
    fn p256() -> Self {
        TestKey::P256(<p256::ecdsa::SigningKey as p256::elliptic_curve::Generate>::generate())
    }
    fn spki(&self) -> SubjectPublicKeyInfoOwned {
        let der = match self {
            TestKey::P256(k) => k.verifying_key().to_public_key_der().unwrap(),
            TestKey::P384(k) => k.verifying_key().to_public_key_der().unwrap(),
            TestKey::Rsa(k) => k.verifying_key().to_public_key_der().unwrap(),
        };
        SubjectPublicKeyInfoOwned::from_der(der.as_bytes()).unwrap()
    }
    fn issue(&self, profile: Profile, serial: u8, subject: &str, spki: SubjectPublicKeyInfoOwned, exts: &[KdExt]) -> Vec<u8> {
        self.issue_opt(profile, serial, subject, spki, exts, false)
    }
    fn issue_opt(&self, profile: Profile, serial: u8, subject: &str, spki: SubjectPublicKeyInfoOwned, exts: &[KdExt], dup_bc: bool) -> Vec<u8> {
        match self {
            TestKey::P256(k) => build_cert::<_, p256::ecdsa::DerSignature>(k, profile, serial, subject, spki, exts, dup_bc),
            TestKey::P384(k) => build_cert::<_, p384::ecdsa::DerSignature>(k, profile, serial, subject, spki, exts, dup_bc),
            TestKey::Rsa(k) => build_cert::<_, rsa::pkcs1v15::Signature>(k.as_ref(), profile, serial, subject, spki, exts, dup_bc),
        }
    }
}

fn name(s: &str) -> Name {
    Name::from_str(s).unwrap()
}

struct Opts {
    kd: Vec<KdExt>,
    intermediates: usize,
    inter_ca: bool,
    inter_dup_bc: bool,
    leaf_issuer: Option<String>,
}

impl Default for Opts {
    fn default() -> Self {
        Opts { kd: vec![KdExt(encode_kd(&KdSpec::default()))], intermediates: 1, inter_ca: true, inter_dup_bc: false, leaf_issuer: None }
    }
}

fn with_kd(s: KdSpec) -> Opts {
    Opts { kd: vec![KdExt(encode_kd(&s))], ..Opts::default() }
}

struct Built {
    root: Vec<u8>,
    chain: Vec<Vec<u8>>,
    pub33: [u8; 33],
}

fn leaf_parts() -> (SubjectPublicKeyInfoOwned, [u8; 33]) {
    let k = TestKey::p256();
    let pub33 = match &k {
        TestKey::P256(sk) => <[u8; 33]>::try_from(sk.verifying_key().to_sec1_point(true).as_bytes()).unwrap(),
        _ => unreachable!(),
    };
    (k.spki(), pub33)
}

fn build(o: Opts) -> Built {
    let root_key = TestKey::p256();
    let root = root_key.issue(Profile::Root, 1, ROOT_CN, root_key.spki(), &[]);
    let mut issuer_key = root_key;
    let mut issuer_name = ROOT_CN.to_string();
    let mut upper = Vec::new();
    for i in 0..o.intermediates {
        let k = TestKey::p256();
        let subject = format!("CN=Test Intermediate {i}");
        let profile = if o.inter_ca {
            Profile::SubCA { issuer: name(&issuer_name), path_len_constraint: None }
        } else {
            Profile::Manual { issuer: Some(name(&issuer_name)) }
        };
        upper.push(issuer_key.issue_opt(profile, 10 + i as u8, &subject, k.spki(), &[], o.inter_dup_bc));
        issuer_key = k;
        issuer_name = subject;
    }
    let (spki, pub33) = leaf_parts();
    let li = o.leaf_issuer.unwrap_or(issuer_name);
    let leaf = issuer_key.issue(Profile::Manual { issuer: Some(name(&li)) }, 99, "CN=Android Keystore Key", spki, &o.kd);
    let mut chain = vec![leaf];
    chain.extend(upper.into_iter().rev());
    Built { root, chain, pub33 }
}

fn cfg_with(root: &[u8], revoked: &[&[u8]]) -> TrustConfig {
    TrustConfig::new(&[root], revoked, &[&AVB_KEY], &[SIGNER], MIN_PATCH).unwrap()
}

fn run(b: &Built) -> Result<AttestationVerdict, TrustError> {
    verify_attestation(&b.chain, &cfg_with(&b.root, &[]), &b.pub33)
}

fn expect(b: &Built, e: AttestError) {
    assert_eq!(run(b).err(), Some(TrustError::Attestation(e)));
}

fn kd_case(f: impl FnOnce(&mut KdSpec), e: AttestError) {
    let mut s = KdSpec::default();
    f(&mut s);
    expect(&build(with_kd(s)), e);
}

// ------------------------------------------------------------ positive paths

#[test]
fn valid_chain_is_accepted() {
    let b = build(Opts::default());
    let v = run(&b).unwrap();
    assert_eq!(v.level, SecLevel::StrongBox);
    assert_eq!(v.boot, BootState::Verified);
    assert_eq!(v.os_patch, 202409);
    let mut h = Sha384::new();
    for c in &b.chain {
        h.update(c);
    }
    assert_eq!(&v.evidence_id[..], &h.finalize()[..16]);
}

#[test]
fn rsa_and_p384_issuers_are_accepted() {
    let root_key = TestKey::Rsa(Box::new(rsa::pkcs1v15::SigningKey::<Sha256>::new(rsa_key())));
    let root = root_key.issue(Profile::Root, 1, ROOT_CN, root_key.spki(), &[]);
    let k384 = TestKey::P384(<p384::ecdsa::SigningKey as p256::elliptic_curve::Generate>::generate());
    let i1 = root_key.issue(Profile::SubCA { issuer: name(ROOT_CN), path_len_constraint: None }, 2, "CN=P384 CA", k384.spki(), &[]);
    let k256 = TestKey::p256();
    let i2 = k384.issue(Profile::SubCA { issuer: name("CN=P384 CA"), path_len_constraint: None }, 3, "CN=P256 CA", k256.spki(), &[]);
    let (spki, pub33) = leaf_parts();
    let leaf = k256.issue(
        Profile::Manual { issuer: Some(name("CN=P256 CA")) },
        4,
        "CN=Android Keystore Key",
        spki,
        &[KdExt(encode_kd(&KdSpec::default()))],
    );
    let b = Built { root, chain: vec![leaf, i2, i1], pub33 };
    assert!(run(&b).is_ok());
}

// ------------------------------------------------------------ E2-1 chain

#[test]
fn e2_1_chain_too_short() {
    expect(&build(Opts { intermediates: 0, ..Opts::default() }), AttestError::ChainLength);
}

#[test]
fn e2_1_chain_too_long() {
    expect(&build(Opts { intermediates: 5, ..Opts::default() }), AttestError::ChainLength);
}

#[test]
fn e2_1_name_chain_broken() {
    expect(
        &build(Opts { leaf_issuer: Some("CN=Somebody Else".into()), ..Opts::default() }),
        AttestError::NameChainBroken { index: 0 },
    );
}

#[test]
fn e2_1_issuer_not_ca() {
    expect(&build(Opts { inter_ca: false, ..Opts::default() }), AttestError::IssuerNotCa { index: 1 });
}

#[test]
fn e2_1_duplicate_basic_constraints() {
    // Both copies say cA=TRUE; the issuer is still rejected because the extension repeats.
    expect(&build(Opts { inter_dup_bc: true, ..Opts::default() }), AttestError::IssuerNotCa { index: 1 });
}

#[test]
fn e2_1_bad_signature() {
    let mut b = build(Opts::default());
    let leaf = &mut b.chain[0];
    let last = leaf.len() - 1;
    leaf[last] ^= 0x01;
    expect(&b, AttestError::BadSignature { index: 0 });
}

#[test]
fn e2_1_unsupported_signature_algorithm() {
    let mut b = build(Opts::default());
    let ecdsa_sha256 = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
    let leaf = &mut b.chain[0];
    let mut hits = 0;
    for i in 0..leaf.len() - ecdsa_sha256.len() {
        if leaf[i..i + ecdsa_sha256.len()] == ecdsa_sha256 {
            leaf[i + 7] = 0x01; // ecdsa-with-SHA224
            hits += 1;
        }
    }
    assert_eq!(hits, 2);
    expect(&b, AttestError::UnsupportedAlgorithm { index: 0 });
}

#[test]
fn e2_1_untrusted_root() {
    let b = build(Opts::default());
    let other = TestKey::p256();
    let fake_root = other.issue(Profile::Root, 1, ROOT_CN, other.spki(), &[]);
    let r = verify_attestation(&b.chain, &cfg_with(&fake_root, &[]), &b.pub33);
    assert_eq!(r.err(), Some(TrustError::Attestation(AttestError::UntrustedRoot)));
}

#[test]
fn e2_1_root_in_chain() {
    let mut b = build(Opts::default());
    b.chain.push(b.root.clone());
    expect(&b, AttestError::RootInChain { index: 2 });
}

#[test]
fn e2_1_malformed_certificate() {
    let mut b = build(Opts::default());
    b.chain[1] = vec![0x30, 0x03, 0x02, 0x01, 0x01];
    expect(&b, AttestError::CertMalformed { index: 1 });
}

#[test]
fn mutated_chains_never_panic_or_pass() {
    let b = build(Opts::default());
    let cfg = cfg_with(&b.root, &[]);
    for idx in 0..b.chain.len() {
        for i in 0..b.chain[idx].len() {
            let mut c = b.chain.clone();
            c[idx][i] ^= 0x01;
            assert!(verify_attestation(&c, &cfg, &b.pub33).is_err(), "cert {idx} byte {i}");
        }
        for cut in 0..b.chain[idx].len() {
            let mut c = b.chain.clone();
            c[idx].truncate(cut);
            assert!(verify_attestation(&c, &cfg, &b.pub33).is_err());
        }
    }
}

// ------------------------------------------------------------ E2-2 .. E2-3

#[test]
fn e2_2_revoked_leaf() {
    let b = build(Opts::default());
    let r = verify_attestation(&b.chain, &cfg_with(&b.root, &[&[0x00, 0x01, 99]]), &b.pub33);
    assert_eq!(r.err(), Some(TrustError::Attestation(AttestError::Revoked { index: 0 })));
}

#[test]
fn e2_2_revoked_intermediate() {
    let b = build(Opts::default());
    let r = verify_attestation(&b.chain, &cfg_with(&b.root, &[&[0x01, 10]]), &b.pub33);
    assert_eq!(r.err(), Some(TrustError::Attestation(AttestError::Revoked { index: 1 })));
}

#[test]
fn e2_3_leaf_key_mismatch() {
    let b = build(Opts::default());
    let (_, other) = leaf_parts();
    let r = verify_attestation(&b.chain, &cfg_with(&b.root, &[]), &other);
    assert_eq!(r.err(), Some(TrustError::Attestation(AttestError::LeafKeyMismatch)));
}

// ------------------------------------------------------------ E2-4 .. E2-10, 6.1 brand

#[test]
fn e2_4_key_description_missing() {
    expect(&build(Opts { kd: vec![], ..Opts::default() }), AttestError::KeyDescriptionMissing);
}

#[test]
fn e2_4_key_description_duplicated() {
    let kd = encode_kd(&KdSpec::default());
    expect(&build(Opts { kd: vec![KdExt(kd.clone()), KdExt(kd)], ..Opts::default() }), AttestError::KeyDescriptionDuplicated);
}

#[test]
fn e2_4_key_description_malformed() {
    // Valid DER, wrong schema: KeyDescription with only two of its eight fields.
    let kd = seq(&[int(300), enm(2)]);
    expect(&build(Opts { kd: vec![KdExt(kd)], ..Opts::default() }), AttestError::KeyDescriptionMalformed);
}

#[test]
fn e2_4_attestation_version_too_low() {
    kd_case(|s| s.att_ver = 3, AttestError::AttestationVersionTooLow);
}

#[test]
fn e2_5_attestation_level_tee_rejected() {
    kd_case(|s| s.att_level = 1, AttestError::AttestationLevelNotStrongBox);
}

#[test]
fn e2_5_keymint_level_tee_rejected() {
    kd_case(|s| s.km_level = 1, AttestError::KeyMintLevelNotStrongBox);
}

#[test]
fn e2_6_challenge_mismatch() {
    kd_case(|s| s.challenge = b"AegisChat-ID-v1".to_vec(), AttestError::ChallengeMismatch);
}

#[test]
fn e2_7_purpose_not_sign_only() {
    kd_case(|s| s.purpose = Some(vec![2, 3]), AttestError::PurposeNotSignOnly);
    kd_case(|s| s.purpose = None, AttestError::PurposeNotSignOnly);
}

#[test]
fn e2_7_algorithm_not_ec() {
    kd_case(|s| s.algorithm = Some(1), AttestError::AlgorithmNotEc);
}

#[test]
fn e2_7_curve_not_p256() {
    kd_case(|s| s.curve = Some(2), AttestError::CurveNotP256);
}

#[test]
fn e2_7_digest_not_sha256() {
    kd_case(|s| s.digest = Some(vec![4, 6]), AttestError::DigestNotSha256);
}

#[test]
fn e2_7_origin_not_generated() {
    kd_case(|s| s.origin = Some(2), AttestError::OriginNotGenerated);
}

#[test]
fn e2_8_root_of_trust_missing() {
    kd_case(|s| s.rot = None, AttestError::RootOfTrustMissing);
}

fn boot_of(rot: (Vec<u8>, bool, u64)) -> BootState {
    let s = KdSpec { rot: Some(rot), ..KdSpec::default() };
    run(&build(with_kd(s))).unwrap().boot
}

#[test]
fn e2_8_boot_state_labels() {
    assert_eq!(boot_of((AVB_KEY.to_vec(), true, 1)), BootState::SelfSigned { key: AVB_KEY.to_vec() });
    assert_eq!(boot_of((vec![0x77; 32], true, 1)), BootState::Unlocked);
    assert_eq!(boot_of((vec![0x44; 32], false, 0)), BootState::Unlocked);
    assert_eq!(boot_of((vec![0x44; 32], false, 2)), BootState::Unlocked);
}

#[test]
fn e2_8_self_signed_requires_device_locked() {
    // Listed AVB key and SelfSigned state, but deviceLocked = false: not the locked self-signed state.
    assert_eq!(boot_of((AVB_KEY.to_vec(), false, 1)), BootState::Unlocked);
}

#[test]
fn e2_9_app_id_missing() {
    kd_case(|s| s.app_id = None, AttestError::AppIdMissing);
}

#[test]
fn e2_9_package_not_allowed() {
    kd_case(|s| s.app_id = Some((vec![b"com.evil".to_vec()], vec![SIGNER.to_vec()])), AttestError::PackageNotAllowed);
    kd_case(
        |s| s.app_id = Some((vec![APP_PACKAGE.to_vec(), b"com.shared".to_vec()], vec![SIGNER.to_vec()])),
        AttestError::PackageNotAllowed,
    );
}

#[test]
fn e2_9_signer_not_allowed() {
    kd_case(|s| s.app_id = Some((vec![APP_PACKAGE.to_vec()], vec![vec![0x11; 32]])), AttestError::SignerNotAllowed);
}

#[test]
fn e2_9_signer_digest_list_empty() {
    kd_case(|s| s.app_id = Some((vec![APP_PACKAGE.to_vec()], vec![])), AttestError::SignerNotAllowed);
}

#[test]
fn e2_10_os_patch_too_low() {
    kd_case(|s| s.patch = Some(202312), AttestError::OsPatchTooLow);
}

#[test]
fn e2_10_os_patch_missing() {
    kd_case(|s| s.patch = None, AttestError::OsPatchMissing);
}

#[test]
fn brand_must_be_google() {
    kd_case(|s| s.brand = Some(b"Google".to_vec()), AttestError::BrandMismatch);
    kd_case(|s| s.brand = None, AttestError::BrandMissing);
}

// ------------------------------------------------------------ parsers and config


#[test]
fn key_description_parser_rejects_truncation_and_survives_mutation() {
    let kd = encode_kd(&KdSpec::default());
    assert!(parse_key_description(&kd).is_ok());
    for cut in 0..kd.len() {
        assert!(parse_key_description(&kd[..cut]).is_err());
    }
    for i in 0..kd.len() {
        for bit in 0..8 {
            let mut m = kd.clone();
            m[i] ^= 1 << bit;
            let _ = parse_key_description(&m);
        }
    }
    assert!(parse_key_description(&[kd.clone(), vec![0]].concat()).is_err());
}

fn rec(t: u8, v: &[u8]) -> Vec<u8> {
    let mut o = vec![t];
    o.extend_from_slice(&(v.len() as u16).to_be_bytes());
    o.extend_from_slice(v);
    o
}

#[test]
fn trust_config_from_tlv() {
    let b = build(Opts::default());
    let good = [vec![1], rec(1, &b.root), rec(2, &[0x05]), rec(3, &AVB_KEY), rec(4, &SIGNER), rec(5, &MIN_PATCH.to_be_bytes())].concat();
    let cfg = TrustConfig::from_tlv(&good).unwrap();
    assert!(verify_attestation(&b.chain, &cfg, &b.pub33).is_ok());
    let bad = TrustError::ConfigMalformed;
    assert_eq!(TrustConfig::from_tlv(&good[..good.len() - 1]).err(), Some(bad));
    assert_eq!(TrustConfig::from_tlv(&[good.clone(), rec(9, &[1])].concat()).err(), Some(bad));
    assert_eq!(TrustConfig::from_tlv(&[good.clone(), rec(5, &[0, 0, 0, 1])].concat()).err(), Some(bad));
    let no_root = [vec![1], rec(4, &SIGNER), rec(5, &MIN_PATCH.to_be_bytes())].concat();
    assert_eq!(TrustConfig::from_tlv(&no_root).err(), Some(bad));
    let no_signer = [vec![1], rec(1, &b.root), rec(5, &MIN_PATCH.to_be_bytes())].concat();
    assert_eq!(TrustConfig::from_tlv(&no_signer).err(), Some(bad));
    assert_eq!(TrustConfig::from_tlv(&[vec![2], good[1..].to_vec()].concat()).err(), Some(bad));
    assert_eq!(TrustConfig::from_tlv(&[vec![1], rec(1, &[0x30, 0x00]), rec(4, &SIGNER), rec(5, &[0, 3, 0x16, 0x01])].concat()).err(), Some(bad));
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
