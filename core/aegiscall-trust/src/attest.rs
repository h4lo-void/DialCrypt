//! Android hardware key attestation chain verification (design E2, amended by 6.1).

use crate::error::{AttestError, TrustError};
use crate::keydesc::{
    parse_key_description, ApplicationId, ALGORITHM_EC, BOOT_SELF_SIGNED, BOOT_VERIFIED,
    DIGEST_SHA256, EC_CURVE_P256, ORIGIN_GENERATED, PURPOSE_SIGN, SECURITY_LEVEL_STRONGBOX,
};
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::elliptic_curve::sec1::ToSec1Point;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::traits::PublicKeyParts;
use rsa::{Pkcs1v15Sign, PublicKey as RsaPublicKey};
use sha2::{Digest, Sha256, Sha384, Sha512};
use subtle::ConstantTimeEq;
use x509_cert::certificate::Version;
use x509_cert::der::oid::ObjectIdentifier;
use x509_cert::der::{Decode, Encode, Tag, Tagged};
use x509_cert::ext::pkix::BasicConstraints;
use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::Certificate;

/// The only DialCrypt package (design 6.1).
pub const APP_PACKAGE: &[u8] = b"io.github.h4lovoid.dialcrypt";
/// Fixed attestation challenge of the identity key (design A).
pub const ATTESTATION_CHALLENGE: &[u8] = b"AegisChat-ID-v2";
/// Required attestationIdBrand (design 6.1).
pub const REQUIRED_BRAND: &[u8] = b"google";
/// Minimum certificates in the chain passed to [`verify_attestation`] (root excluded).
pub const MIN_CHAIN_LEN: usize = 2;
/// Maximum certificates in the chain passed to [`verify_attestation`] (root excluded).
pub const MAX_CHAIN_LEN: usize = 5;

const MIN_ATTESTATION_VERSION: u64 = 4;
const MIN_RSA_BITS: u32 = 2048;
// rsa 0.9 refused moduli above 4096 bits while parsing; rsa 0.10 accepts up to 8192, so keep the old ceiling.
const MAX_RSA_BITS: u32 = 4096;
const MAX_CERT_LEN: usize = 16 * 1024;
const MAX_SERIAL_LEN: usize = 32;
const MAX_AVB_KEY_LEN: usize = 64;
const CONFIG_VERSION: u8 = 1;

const OID_KEY_DESCRIPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.11129.2.1.17");
const OID_BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const OID_SECP256R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const OID_SECP384R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const OID_RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const OID_ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const OID_ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
const OID_ECDSA_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4");
const OID_RSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const OID_RSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
const OID_RSA_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");

/// Hardware security level. Only StrongBox is accepted (design 6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecLevel {
    /// StrongBox KeyMint.
    StrongBox,
}

/// Boot state label derived from rootOfTrust (E2-8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootState {
    /// Verified boot with the OEM key and a locked bootloader.
    Verified,
    /// Locked with a user key listed in `avb_keys`.
    SelfSigned {
        /// verifiedBootKey.
        key: Vec<u8>,
    },
    /// Everything else; accepted but must be displayed as such.
    Unlocked,
}

/// Successful verification result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationVerdict {
    /// Security level (always StrongBox).
    pub level: SecLevel,
    /// Boot state label.
    pub boot: BootState,
    /// Hardware osPatchLevel (YYYYMM).
    pub os_patch: u32,
    /// SHA-384 over the concatenated DER certificates (root excluded), first 16 bytes.
    pub evidence_id: [u8; 16],
}

enum IssuerKey {
    P256(p256::ecdsa::VerifyingKey),
    P384(p384::ecdsa::VerifyingKey),
    Rsa(RsaPublicKey),
}

enum SigFail {
    Unsupported,
    Bad,
}

#[derive(Clone, Copy)]
enum HashAlg {
    S256,
    S384,
    S512,
}

fn params_absent_or_null(alg: &AlgorithmIdentifierOwned) -> bool {
    match &alg.parameters {
        None => true,
        Some(p) => p.tag() == Tag::Null && p.value().is_empty(),
    }
}

impl IssuerKey {
    fn from_spki(spki: &SubjectPublicKeyInfoOwned) -> Option<Self> {
        let bytes = spki.subject_public_key.as_bytes()?;
        if spki.algorithm.oid == OID_EC_PUBLIC_KEY {
            let curve: ObjectIdentifier = spki.algorithm.parameters.as_ref()?.decode_as().ok()?;
            if curve == OID_SECP256R1 {
                p256::ecdsa::VerifyingKey::from_sec1_bytes(bytes).ok().map(IssuerKey::P256)
            } else if curve == OID_SECP384R1 {
                p384::ecdsa::VerifyingKey::from_sec1_bytes(bytes).ok().map(IssuerKey::P384)
            } else {
                None
            }
        } else if spki.algorithm.oid == OID_RSA_ENCRYPTION {
            if !params_absent_or_null(&spki.algorithm) {
                return None;
            }
            let key = RsaPublicKey::from_pkcs1_der(bytes).ok()?;
            let bits = key.n().bit_width();
            if !(MIN_RSA_BITS..=MAX_RSA_BITS).contains(&bits) {
                return None;
            }
            Some(IssuerKey::Rsa(key))
        } else {
            None
        }
    }

    fn verify(&self, alg: &AlgorithmIdentifierOwned, msg: &[u8], sig: &[u8]) -> Result<(), SigFail> {
        let (ecdsa, hash) = match alg.oid {
            o if o == OID_ECDSA_SHA256 => (true, HashAlg::S256),
            o if o == OID_ECDSA_SHA384 => (true, HashAlg::S384),
            o if o == OID_ECDSA_SHA512 => (true, HashAlg::S512),
            o if o == OID_RSA_SHA256 => (false, HashAlg::S256),
            o if o == OID_RSA_SHA384 => (false, HashAlg::S384),
            o if o == OID_RSA_SHA512 => (false, HashAlg::S512),
            _ => return Err(SigFail::Unsupported),
        };
        let params_ok = if ecdsa { alg.parameters.is_none() } else { params_absent_or_null(alg) };
        if !params_ok {
            return Err(SigFail::Unsupported);
        }
        let digest: Vec<u8> = match hash {
            HashAlg::S256 => Sha256::digest(msg).to_vec(),
            HashAlg::S384 => Sha384::digest(msg).to_vec(),
            HashAlg::S512 => Sha512::digest(msg).to_vec(),
        };
        match (self, ecdsa) {
            (IssuerKey::P256(vk), true) => {
                let s = p256::ecdsa::Signature::from_der(sig).map_err(|_| SigFail::Bad)?;
                vk.verify_prehash(&digest, &s).map_err(|_| SigFail::Bad)
            }
            (IssuerKey::P384(vk), true) => {
                let s = p384::ecdsa::Signature::from_der(sig).map_err(|_| SigFail::Bad)?;
                vk.verify_prehash(&digest, &s).map_err(|_| SigFail::Bad)
            }
            (IssuerKey::Rsa(k), false) => {
                let scheme = match hash {
                    HashAlg::S256 => Pkcs1v15Sign::new::<Sha256>(),
                    HashAlg::S384 => Pkcs1v15Sign::new::<Sha384>(),
                    HashAlg::S512 => Pkcs1v15Sign::new::<Sha512>(),
                };
                k.verify(scheme, &digest, sig).map_err(|_| SigFail::Bad)
            }
            _ => Err(SigFail::Unsupported),
        }
    }
}

struct TrustedRoot {
    subject: Vec<u8>,
    key: IssuerKey,
    spki_hash: [u8; 32],
}

/// Verification inputs supplied by the app from its raw resources. No root is built in.
pub struct TrustConfig {
    roots: Vec<TrustedRoot>,
    revoked: Vec<Vec<u8>>,
    avb_keys: Vec<Vec<u8>>,
    app_signers: Vec<[u8; 32]>,
    min_os_patch: u32,
    require_locked_boot: bool,
}

fn strip_leading_zeros(b: &[u8]) -> &[u8] {
    let n = b.iter().take_while(|x| **x == 0).count();
    b.get(n..).unwrap_or(&[])
}

fn sha256_32(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

impl TrustConfig {
    /// Builds a configuration. `roots` are DER certificates; `revoked_serials` are
    /// big-endian serial numbers; `avb_keys` are verifiedBootKey values; `app_signers` are
    /// SHA-256 signing-certificate digests; `min_os_patch` is YYYYMM.
    pub fn new(
        roots: &[&[u8]],
        revoked_serials: &[&[u8]],
        avb_keys: &[&[u8]],
        app_signers: &[[u8; 32]],
        min_os_patch: u32,
    ) -> Result<Self, TrustError> {
        let bad = TrustError::ConfigMalformed;
        if roots.is_empty() || app_signers.is_empty() || min_os_patch == 0 {
            return Err(bad);
        }
        let mut parsed = Vec::with_capacity(roots.len());
        for der in roots {
            if der.len() > MAX_CERT_LEN {
                return Err(bad);
            }
            let cert = Certificate::from_der(der).map_err(|_| bad)?;
            if cert.to_der().map_err(|_| bad)?.as_slice() != *der {
                return Err(bad);
            }
            let spki = cert.tbs_certificate().subject_public_key_info();
            let key = IssuerKey::from_spki(spki).ok_or(bad)?;
            parsed.push(TrustedRoot {
                subject: cert.tbs_certificate().subject().to_der().map_err(|_| bad)?,
                key,
                spki_hash: sha256_32(&spki.to_der().map_err(|_| bad)?),
            });
        }
        let mut revoked = Vec::with_capacity(revoked_serials.len());
        for s in revoked_serials {
            let n = strip_leading_zeros(s);
            if s.is_empty() || s.len() > MAX_SERIAL_LEN {
                return Err(bad);
            }
            revoked.push(n.to_vec());
        }
        let mut avb = Vec::with_capacity(avb_keys.len());
        for k in avb_keys {
            if k.is_empty() || k.len() > MAX_AVB_KEY_LEN {
                return Err(bad);
            }
            avb.push(k.to_vec());
        }
        Ok(Self {
            roots: parsed,
            revoked,
            avb_keys: avb,
            app_signers: app_signers.to_vec(),
            min_os_patch,
            require_locked_boot: false,
        })
    }

    /// Requires verified or allowlisted self-signed locked boot (`BootState::Unlocked` is rejected).
    pub fn set_require_locked_boot(&mut self, require: bool) {
        self.require_locked_boot = require;
    }

    /// True when `BootState::Unlocked` is rejected during attestation verification.
    pub fn require_locked_boot(&self) -> bool {
        self.require_locked_boot
    }

    /// Parses `ver(1)=1` followed by records `type(1) · len(2, BE) · value`:
    /// 1 root DER (>=1), 2 revoked serial, 3 AVB key, 4 app signer SHA-256 (32 B, >=1),
    /// 5 min osPatchLevel u32 BE (exactly once), 6 optional require_locked_boot u8 (0 or 1).
    /// Unknown types are rejected.
    pub fn from_tlv(b: &[u8]) -> Result<Self, TrustError> {
        let bad = TrustError::ConfigMalformed;
        let (ver, mut rest) = b.split_first().ok_or(bad)?;
        if *ver != CONFIG_VERSION {
            return Err(bad);
        }
        let mut roots: Vec<&[u8]> = Vec::new();
        let mut revoked: Vec<&[u8]> = Vec::new();
        let mut avb: Vec<&[u8]> = Vec::new();
        let mut signers: Vec<[u8; 32]> = Vec::new();
        let mut patch: Option<u32> = None;
        let mut locked_boot: Option<bool> = None;
        while !rest.is_empty() {
            let hdr = rest.get(..3).ok_or(bad)?;
            let t = hdr.first().copied().ok_or(bad)?;
            let len = usize::from(u16::from_be_bytes([
                hdr.get(1).copied().ok_or(bad)?,
                hdr.get(2).copied().ok_or(bad)?,
            ]));
            let v = rest.get(3..3 + len).ok_or(bad)?;
            rest = rest.get(3 + len..).ok_or(bad)?;
            if v.is_empty() {
                return Err(bad);
            }
            match t {
                1 => roots.push(v),
                2 => revoked.push(v),
                3 => avb.push(v),
                4 => signers.push(<[u8; 32]>::try_from(v).map_err(|_| bad)?),
                5 => {
                    if patch.is_some() {
                        return Err(bad);
                    }
                    patch = Some(u32::from_be_bytes(<[u8; 4]>::try_from(v).map_err(|_| bad)?));
                }
                6 => {
                    if locked_boot.is_some() || v.len() != 1 || v[0] > 1 {
                        return Err(bad);
                    }
                    locked_boot = Some(v[0] == 1);
                }
                _ => return Err(bad),
            }
        }
        let mut cfg = Self::new(&roots, &revoked, &avb, &signers, patch.ok_or(bad)?)?;
        if let Some(req) = locked_boot {
            cfg.set_require_locked_boot(req);
        }
        Ok(cfg)
    }
}

/// `SHA-384(cert_0 ‖ cert_1 ‖ …)[..16]` over the DER certificates without the root.
pub fn evidence_id(chain_no_root: &[Vec<u8>]) -> [u8; 16] {
    let mut h = Sha384::new();
    for c in chain_no_root {
        h.update(c);
    }
    let d = h.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(d.get(..16).unwrap_or(&[0u8; 16]));
    out
}

/// Verifies an attestation chain (leaf first, root excluded) against `cfg` and binds the
/// leaf key to `expected_pub33`. Never panics on malformed input.
pub fn verify_attestation(
    chain_no_root: &[Vec<u8>],
    cfg: &TrustConfig,
    expected_pub33: &[u8; 33],
) -> Result<AttestationVerdict, TrustError> {
    verify_inner(chain_no_root, cfg, expected_pub33).map_err(TrustError::Attestation)
}

fn parse_cert(der: &[u8], index: usize) -> Result<Certificate, AttestError> {
    let bad = AttestError::CertMalformed { index };
    if der.len() > MAX_CERT_LEN {
        return Err(bad);
    }
    let c = Certificate::from_der(der).map_err(|_| bad)?;
    if c.to_der().map_err(|_| bad)?.as_slice() != der {
        return Err(bad);
    }
    if c.tbs_certificate().version() != Version::V3 || c.signature_algorithm() != c.tbs_certificate().signature() {
        return Err(bad);
    }
    Ok(c)
}

fn verify_cert_sig(cert: &Certificate, key: &IssuerKey, index: usize) -> Result<(), AttestError> {
    let tbs = cert.tbs_certificate().to_der().map_err(|_| AttestError::CertMalformed { index })?;
    let sig = cert.signature().as_bytes().ok_or(AttestError::CertMalformed { index })?;
    key.verify(cert.signature_algorithm(), &tbs, sig).map_err(|e| match e {
        SigFail::Unsupported => AttestError::UnsupportedAlgorithm { index },
        SigFail::Bad => AttestError::BadSignature { index },
    })
}

fn require_ca(cert: &Certificate, index: usize) -> Result<(), AttestError> {
    let not_ca = AttestError::IssuerNotCa { index };
    let exts = cert.tbs_certificate().extensions().map(Vec::as_slice).unwrap_or(&[]);
    let mut found = exts.iter().filter(|e| e.extn_id == OID_BASIC_CONSTRAINTS);
    let ext = found.next().ok_or(not_ca)?;
    if found.next().is_some() {
        return Err(not_ca);
    }
    let bc = BasicConstraints::from_der(ext.extn_value.as_bytes()).map_err(|_| not_ca)?;
    if bc.ca {
        Ok(())
    } else {
        Err(not_ca)
    }
}

fn leaf_pub33(cert: &Certificate) -> Result<[u8; 33], AttestError> {
    let spki = cert.tbs_certificate().subject_public_key_info();
    if spki.algorithm.oid != OID_EC_PUBLIC_KEY {
        return Err(AttestError::LeafKeyNotP256);
    }
    let curve: ObjectIdentifier = spki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|p| p.decode_as().ok())
        .ok_or(AttestError::LeafKeyNotP256)?;
    if curve != OID_SECP256R1 {
        return Err(AttestError::LeafKeyNotP256);
    }
    let bytes = spki.subject_public_key.as_bytes().ok_or(AttestError::LeafKeyNotP256)?;
    let pk = p256::PublicKey::from_sec1_bytes(bytes).map_err(|_| AttestError::LeafKeyNotP256)?;
    let enc = pk.to_sec1_point(true);
    <[u8; 33]>::try_from(enc.as_bytes()).map_err(|_| AttestError::LeafKeyNotP256)
}

fn check_app_id(app: &ApplicationId, cfg: &TrustConfig) -> Result<(), AttestError> {
    match app.packages.as_slice() {
        [(name, _)] if name.as_slice() == APP_PACKAGE => {}
        _ => return Err(AttestError::PackageNotAllowed),
    }
    if app.signature_digests.is_empty() {
        return Err(AttestError::SignerNotAllowed);
    }
    for d in &app.signature_digests {
        let listed = cfg.app_signers.iter().any(|s| bool::from(s.as_slice().ct_eq(d.as_slice())));
        if !listed {
            return Err(AttestError::SignerNotAllowed);
        }
    }
    Ok(())
}

fn verify_inner(
    chain: &[Vec<u8>],
    cfg: &TrustConfig,
    expected_pub33: &[u8; 33],
) -> Result<AttestationVerdict, AttestError> {
    let n = chain.len();
    if !(MIN_CHAIN_LEN..=MAX_CHAIN_LEN).contains(&n) {
        return Err(AttestError::ChainLength);
    }
    let mut certs = Vec::with_capacity(n);
    for (i, der) in chain.iter().enumerate() {
        certs.push(parse_cert(der, i)?);
    }
    // E2-1: the root must come from the config, never from the peer.
    for (i, c) in certs.iter().enumerate() {
        let spki = c.tbs_certificate().subject_public_key_info().to_der().map_err(|_| AttestError::CertMalformed { index: i })?;
        let h = sha256_32(&spki);
        if cfg.roots.iter().any(|r| bool::from(r.spki_hash.ct_eq(&h))) {
            return Err(AttestError::RootInChain { index: i });
        }
    }
    // E2-1: name chaining, CA flag and signature of every link.
    for i in 0..n - 1 {
        let (child, parent) = match (certs.get(i), certs.get(i + 1)) {
            (Some(c), Some(p)) => (c, p),
            _ => return Err(AttestError::ChainLength),
        };
        let issuer = child.tbs_certificate().issuer().to_der().map_err(|_| AttestError::CertMalformed { index: i })?;
        let subject = parent.tbs_certificate().subject().to_der().map_err(|_| AttestError::CertMalformed { index: i + 1 })?;
        if issuer != subject {
            return Err(AttestError::NameChainBroken { index: i });
        }
        require_ca(parent, i + 1)?;
        let key = IssuerKey::from_spki(&parent.tbs_certificate().subject_public_key_info())
            .ok_or(AttestError::UnsupportedAlgorithm { index: i })?;
        verify_cert_sig(child, &key, i)?;
    }
    // E2-1: the last certificate must be signed by a configured root.
    let last = certs.last().ok_or(AttestError::ChainLength)?;
    let last_issuer = last.tbs_certificate().issuer().to_der().map_err(|_| AttestError::CertMalformed { index: n - 1 })?;
    let anchored = cfg
        .roots
        .iter()
        .any(|r| r.subject == last_issuer && verify_cert_sig(last, &r.key, n - 1).is_ok());
    if !anchored {
        return Err(AttestError::UntrustedRoot);
    }
    // E2-2: revocation snapshot.
    for (i, c) in certs.iter().enumerate() {
        let serial = strip_leading_zeros(c.tbs_certificate().serial_number().as_bytes());
        if cfg.revoked.iter().any(|r| r.as_slice() == serial) {
            return Err(AttestError::Revoked { index: i });
        }
    }
    let leaf = certs.first().ok_or(AttestError::ChainLength)?;
    // E2-3: leaf key equals the handshake identity.
    let pub33 = leaf_pub33(leaf)?;
    if !bool::from(pub33.ct_eq(expected_pub33)) {
        return Err(AttestError::LeafKeyMismatch);
    }
    // E2-4: exactly one KeyDescription.
    let exts = leaf.tbs_certificate().extensions().map(Vec::as_slice).unwrap_or(&[]);
    let mut kds = exts.iter().filter(|e| e.extn_id == OID_KEY_DESCRIPTION);
    let kd_ext = kds.next().ok_or(AttestError::KeyDescriptionMissing)?;
    if kds.next().is_some() {
        return Err(AttestError::KeyDescriptionDuplicated);
    }
    let kd = parse_key_description(kd_ext.extn_value.as_bytes())
        .map_err(|_| AttestError::KeyDescriptionMalformed)?;
    if kd.attestation_version < MIN_ATTESTATION_VERSION {
        return Err(AttestError::AttestationVersionTooLow);
    }
    // E2-5 as amended by 6.1.
    if kd.attestation_security_level != SECURITY_LEVEL_STRONGBOX {
        return Err(AttestError::AttestationLevelNotStrongBox);
    }
    if kd.keymint_security_level != SECURITY_LEVEL_STRONGBOX {
        return Err(AttestError::KeyMintLevelNotStrongBox);
    }
    // E2-6.
    if !bool::from(kd.challenge.as_slice().ct_eq(ATTESTATION_CHALLENGE)) {
        return Err(AttestError::ChallengeMismatch);
    }
    // E2-7 (hardware-enforced list only).
    let hw = &kd.hardware_enforced;
    if hw.purpose.as_deref() != Some(&[PURPOSE_SIGN][..]) {
        return Err(AttestError::PurposeNotSignOnly);
    }
    if hw.algorithm != Some(ALGORITHM_EC) {
        return Err(AttestError::AlgorithmNotEc);
    }
    if hw.ec_curve != Some(EC_CURVE_P256) {
        return Err(AttestError::CurveNotP256);
    }
    if hw.digest.as_deref() != Some(&[DIGEST_SHA256][..]) {
        return Err(AttestError::DigestNotSha256);
    }
    if hw.origin != Some(ORIGIN_GENERATED) {
        return Err(AttestError::OriginNotGenerated);
    }
    // E2-8.
    let rot = hw.root_of_trust.as_ref().ok_or(AttestError::RootOfTrustMissing)?;
    let boot = match rot.verified_boot_state {
        BOOT_VERIFIED if rot.device_locked => BootState::Verified,
        BOOT_SELF_SIGNED
            if rot.device_locked
                && cfg.avb_keys.iter().any(|k| bool::from(k.as_slice().ct_eq(rot.verified_boot_key.as_slice()))) =>
        {
            BootState::SelfSigned { key: rot.verified_boot_key.clone() }
        }
        _ => BootState::Unlocked,
    };
    if cfg.require_locked_boot && matches!(boot, BootState::Unlocked) {
        return Err(AttestError::BootloaderUnlocked);
    }
    // E2-9: every attestationApplicationId present (either list) must pass.
    let apps: Vec<&ApplicationId> = [&kd.software_enforced, &kd.hardware_enforced]
        .iter()
        .filter_map(|l| l.application_id.as_ref())
        .collect();
    if apps.is_empty() {
        return Err(AttestError::AppIdMissing);
    }
    for app in apps {
        check_app_id(app, cfg)?;
    }
    // E2-10.
    let patch = hw.os_patch_level.ok_or(AttestError::OsPatchMissing)?;
    let os_patch = u32::try_from(patch).map_err(|_| AttestError::OsPatchTooLow)?;
    if os_patch < cfg.min_os_patch {
        return Err(AttestError::OsPatchTooLow);
    }
    // 6.1: device-properties attestation brand.
    let brand = hw.brand.as_ref().ok_or(AttestError::BrandMissing)?;
    if brand.as_slice() != REQUIRED_BRAND {
        return Err(AttestError::BrandMismatch);
    }
    Ok(AttestationVerdict { level: SecLevel::StrongBox, boot, os_patch, evidence_id: evidence_id(chain) })
}

#[cfg(test)]
#[path = "tests/attest.rs"]
mod tests;
