//! Error values. Every attestation check has its own variant so callers and tests can tell
//! exactly which rule rejected a chain.

use core::fmt;

/// Attestation chain rejection reasons (design E2 items 1-10 plus the 6.1 brand rule).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestError {
    /// E2-1: chain (without root) is not MIN_CHAIN_LEN..=MAX_CHAIN_LEN certificates.
    ChainLength,
    /// E2-1: certificate at `index` is not canonical DER X.509 v3.
    CertMalformed { index: usize },
    /// E2-1: a configured trust root was included in the chain.
    RootInChain { index: usize },
    /// E2-1: issuer of cert `index` does not equal the subject of cert `index + 1`.
    NameChainBroken { index: usize },
    /// E2-1: cert `index` (an issuer) lacks BasicConstraints cA=TRUE.
    IssuerNotCa { index: usize },
    /// E2-1: signature algorithm or issuer key type for cert `index` is not supported.
    UnsupportedAlgorithm { index: usize },
    /// E2-1: signature on cert `index` does not verify.
    BadSignature { index: usize },
    /// E2-1: the last certificate is not signed by any configured root.
    UntrustedRoot,
    /// E2-2: serial number of cert `index` is in the revocation snapshot.
    Revoked { index: usize },
    /// E2-3: leaf key is not an EC P-256 key.
    LeafKeyNotP256,
    /// E2-3: leaf key differs from the handshake `pub33`.
    LeafKeyMismatch,
    /// E2-4: KeyDescription extension absent.
    KeyDescriptionMissing,
    /// E2-4: KeyDescription extension present more than once.
    KeyDescriptionDuplicated,
    /// E2-4: KeyDescription is not valid DER of the expected schema.
    KeyDescriptionMalformed,
    /// E2-4: attestationVersion < 4.
    AttestationVersionTooLow,
    /// E2-5 (6.1): attestationSecurityLevel is not StrongBox.
    AttestationLevelNotStrongBox,
    /// E2-5 (6.1): keyMintSecurityLevel is not StrongBox.
    KeyMintLevelNotStrongBox,
    /// E2-6: attestation challenge mismatch.
    ChallengeMismatch,
    /// E2-7: hardware purpose set is not exactly {SIGN}.
    PurposeNotSignOnly,
    /// E2-7: hardware algorithm is not EC.
    AlgorithmNotEc,
    /// E2-7: hardware curve is not P-256.
    CurveNotP256,
    /// E2-7 / design A: hardware digest set is not exactly {SHA-256}.
    DigestNotSha256,
    /// E2-7: origin is not GENERATED.
    OriginNotGenerated,
    /// E2-8: hardware rootOfTrust absent.
    RootOfTrustMissing,
    /// E2-9: attestationApplicationId absent.
    AppIdMissing,
    /// E2-9: package list is not exactly the DialCrypt package.
    PackageNotAllowed,
    /// E2-9: a signing certificate digest is not in `app_signers`.
    SignerNotAllowed,
    /// E2-10: hardware osPatchLevel absent.
    OsPatchMissing,
    /// E2-10: osPatchLevel below the configured minimum.
    OsPatchTooLow,
    /// 6.1: hardware attestationIdBrand absent.
    BrandMissing,
    /// 6.1: attestationIdBrand is not `google`.
    BrandMismatch,
}

/// Errors returned by this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustError {
    /// Attestation chain rejected.
    Attestation(AttestError),
    /// Trust configuration bytes are malformed or incomplete.
    ConfigMalformed,
    /// Vault file fails strict structural parsing.
    VaultMalformed,
    /// Vault file or content version is not supported.
    UnsupportedVersion,
    /// No unused ticket referenced by this vault file remains.
    VaultDead,
    /// PIN length outside MIN_PIN_LEN..=MAX_PIN_LEN.
    InvalidPin,
    /// Current PIN passed to `change_pins` does not match the unlocked vault's normal PIN.
    WrongCurrentPin,
    /// Like `WrongCurrentPin`, and the wrong-current-PIN limit of this unlock is reached: the
    /// vault was wiped (locked) and opens again only through a ticket-spending unlock.
    WrongCurrentPinLocked,
    /// `change_pins` on a vault opened with a kept stretch (fingerprint answer); only a PIN
    /// unlock may change the PINs.
    StretchUnlock,
    /// The current PIN given to `change_pins` is the duress PIN: the vault was wiped, as by a
    /// duress unlock, and the caller must run the duress path.
    DuressPin,
    /// Duress PIN equals the normal PIN.
    DuressEqualsPin,
    /// The vault must be rotated (unlock or identity change) before it can be persisted.
    RotationRequired,
    /// The vault was wiped (locked); it holds no PIN stretch to rotate with.
    VaultLocked,
    /// `commit_rotation` without a preceding `begin_rotation`.
    NoPendingRotation,
    /// Unknown contact id.
    UnknownContact,
    /// A contact with this `pub33` already exists.
    DuplicateContact,
    /// Another contact already uses this phone number.
    PhoneInUse,
    /// `pub33` is not a valid compressed P-256 point.
    InvalidPub33,
    /// Phone number is not E.164 (`+` and 2..=15 digits).
    InvalidPhone,
    /// Label longer than MAX_LABEL_LEN bytes.
    InvalidLabel,
    /// The contact holds a PSK; its key may only change through a new pairing.
    PskRequiredForKeyChange,
    /// Size, count or id space exhausted.
    CapacityExceeded,
    /// A lower-numbered resume update is still waiting for promotion.
    ResumeBusy,
    /// A higher-numbered resume update is already staged; an older one may not replace it.
    ResumeStale,
    /// Resume update number must be >= 1.
    InvalidResumeK,
    /// Invalid attestation summary for storage.
    InvalidAttestation,
    /// Internal cryptographic primitive failure.
    Crypto,
}

impl fmt::Display for AttestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "attestation rejected: {self:?}")
    }
}

impl fmt::Display for TrustError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TrustError::Attestation(e) => e.fmt(f),
            other => write!(f, "trust error: {other:?}"),
        }
    }
}

impl std::error::Error for AttestError {}
impl std::error::Error for TrustError {}

impl From<AttestError> for TrustError {
    fn from(e: AttestError) -> Self {
        TrustError::Attestation(e)
    }
}
