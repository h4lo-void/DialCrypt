//! Android KeyDescription (OID 1.3.6.1.4.1.11129.2.1.17) parser.
//!
//! Only the fields DialCrypt checks are extracted; other AuthorizationList tags are skipped
//! but must still be well-formed, context-specific, explicit and in strictly increasing order.

use crate::der_lite::{single, DerError, DerResult, Reader, Tlv, CONTEXT};
use crate::error::{AttestError, TrustError};

/// KeyDescription extension OID.
pub const KEY_DESCRIPTION_OID: &str = "1.3.6.1.4.1.11129.2.1.17";

/// SecurityLevel::StrongBox.
pub const SECURITY_LEVEL_STRONGBOX: u64 = 2;
/// KeyPurpose::SIGN.
pub const PURPOSE_SIGN: u64 = 2;
/// Algorithm::EC.
pub const ALGORITHM_EC: u64 = 3;
/// EcCurve::P_256.
pub const EC_CURVE_P256: u64 = 1;
/// Digest::SHA_2_256.
pub const DIGEST_SHA256: u64 = 4;
/// KeyOrigin::GENERATED.
pub const ORIGIN_GENERATED: u64 = 0;
/// VerifiedBootState::Verified.
pub const BOOT_VERIFIED: u64 = 0;
/// VerifiedBootState::SelfSigned.
pub const BOOT_SELF_SIGNED: u64 = 1;

const TAG_PURPOSE: u32 = 1;
const TAG_ALGORITHM: u32 = 2;
const TAG_DIGEST: u32 = 5;
const TAG_EC_CURVE: u32 = 10;
const TAG_ORIGIN: u32 = 702;
const TAG_ROOT_OF_TRUST: u32 = 704;
const TAG_OS_PATCH_LEVEL: u32 = 706;
const TAG_APPLICATION_ID: u32 = 709;
const TAG_ID_BRAND: u32 = 710;

/// Parsed KeyDescription.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyDescription {
    /// attestationVersion.
    pub attestation_version: u64,
    /// attestationSecurityLevel.
    pub attestation_security_level: u64,
    /// keyMintVersion.
    pub keymint_version: u64,
    /// keyMintSecurityLevel.
    pub keymint_security_level: u64,
    /// attestationChallenge.
    pub challenge: Vec<u8>,
    /// uniqueId.
    pub unique_id: Vec<u8>,
    /// softwareEnforced.
    pub software_enforced: AuthorizationList,
    /// hardwareEnforced (teeEnforced).
    pub hardware_enforced: AuthorizationList,
}

/// Subset of AuthorizationList used by the checks.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthorizationList {
    /// [1] purpose.
    pub purpose: Option<Vec<u64>>,
    /// [2] algorithm.
    pub algorithm: Option<u64>,
    /// [5] digest.
    pub digest: Option<Vec<u64>>,
    /// [10] ecCurve.
    pub ec_curve: Option<u64>,
    /// [702] origin.
    pub origin: Option<u64>,
    /// [704] rootOfTrust.
    pub root_of_trust: Option<RootOfTrust>,
    /// [706] osPatchLevel.
    pub os_patch_level: Option<u64>,
    /// [709] attestationApplicationId.
    pub application_id: Option<ApplicationId>,
    /// [710] attestationIdBrand.
    pub brand: Option<Vec<u8>>,
}

/// RootOfTrust.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootOfTrust {
    /// verifiedBootKey.
    pub verified_boot_key: Vec<u8>,
    /// deviceLocked.
    pub device_locked: bool,
    /// verifiedBootState.
    pub verified_boot_state: u64,
    /// verifiedBootHash.
    pub verified_boot_hash: Vec<u8>,
}

/// AttestationApplicationId.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationId {
    /// (package_name, version) pairs.
    pub packages: Vec<(Vec<u8>, u64)>,
    /// Signing certificate digests.
    pub signature_digests: Vec<Vec<u8>>,
}

/// Strictly parses a DER KeyDescription. Never panics; any deviation returns
/// `AttestError::KeyDescriptionMalformed`.
pub fn parse_key_description(der: &[u8]) -> Result<KeyDescription, TrustError> {
    parse_kd(der).map_err(|_| TrustError::Attestation(AttestError::KeyDescriptionMalformed))
}

fn parse_kd(der: &[u8]) -> DerResult<KeyDescription> {
    let top = single(der)?.as_sequence()?;
    let mut r = Reader::new(top);
    let attestation_version = r.read()?.as_uint()?;
    let attestation_security_level = r.read()?.as_enum()?;
    let keymint_version = r.read()?.as_uint()?;
    let keymint_security_level = r.read()?.as_enum()?;
    let challenge = r.read()?.as_octets()?.to_vec();
    let unique_id = r.read()?.as_octets()?.to_vec();
    let software_enforced = parse_auth_list(r.read()?.as_sequence()?)?;
    let hardware_enforced = parse_auth_list(r.read()?.as_sequence()?)?;
    r.finish()?;
    Ok(KeyDescription {
        attestation_version,
        attestation_security_level,
        keymint_version,
        keymint_security_level,
        challenge,
        unique_id,
        software_enforced,
        hardware_enforced,
    })
}

fn set_of_uint(t: &Tlv<'_>) -> DerResult<Vec<u64>> {
    let mut r = Reader::new(t.as_set()?);
    let mut out = Vec::new();
    while !r.is_empty() {
        out.push(r.read()?.as_uint()?);
    }
    Ok(out)
}

fn parse_auth_list(v: &[u8]) -> DerResult<AuthorizationList> {
    let mut r = Reader::new(v);
    let mut out = AuthorizationList::default();
    let mut last: Option<u32> = None;
    while !r.is_empty() {
        let t = r.read()?;
        if t.class != CONTEXT || !t.constructed {
            return Err(DerError);
        }
        if last.is_some_and(|l| t.number <= l) {
            return Err(DerError);
        }
        last = Some(t.number);
        let e = single(t.value)?;
        match t.number {
            TAG_PURPOSE => out.purpose = Some(set_of_uint(&e)?),
            TAG_ALGORITHM => out.algorithm = Some(e.as_uint()?),
            TAG_DIGEST => out.digest = Some(set_of_uint(&e)?),
            TAG_EC_CURVE => out.ec_curve = Some(e.as_uint()?),
            TAG_ORIGIN => out.origin = Some(e.as_uint()?),
            TAG_ROOT_OF_TRUST => out.root_of_trust = Some(parse_root_of_trust(&e)?),
            TAG_OS_PATCH_LEVEL => out.os_patch_level = Some(e.as_uint()?),
            TAG_APPLICATION_ID => out.application_id = Some(parse_app_id(e.as_octets()?)?),
            TAG_ID_BRAND => out.brand = Some(e.as_octets()?.to_vec()),
            _ => {}
        }
    }
    Ok(out)
}

fn parse_root_of_trust(t: &Tlv<'_>) -> DerResult<RootOfTrust> {
    let mut r = Reader::new(t.as_sequence()?);
    let verified_boot_key = r.read()?.as_octets()?.to_vec();
    let device_locked = r.read()?.as_bool()?;
    let verified_boot_state = r.read()?.as_enum()?;
    let verified_boot_hash = r.read()?.as_octets()?.to_vec();
    r.finish()?;
    Ok(RootOfTrust { verified_boot_key, device_locked, verified_boot_state, verified_boot_hash })
}

fn parse_app_id(der: &[u8]) -> DerResult<ApplicationId> {
    let mut r = Reader::new(single(der)?.as_sequence()?);
    let mut pkgs = Reader::new(r.read()?.as_set()?);
    let mut digs = Reader::new(r.read()?.as_set()?);
    r.finish()?;
    let mut packages = Vec::new();
    while !pkgs.is_empty() {
        let mut p = Reader::new(pkgs.read()?.as_sequence()?);
        let name = p.read()?.as_octets()?.to_vec();
        let version = p.read()?.as_uint()?;
        p.finish()?;
        packages.push((name, version));
    }
    let mut signature_digests = Vec::new();
    while !digs.is_empty() {
        signature_digests.push(digs.read()?.as_octets()?.to_vec());
    }
    Ok(ApplicationId { packages, signature_digests })
}
