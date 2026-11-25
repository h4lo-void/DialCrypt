//! PIN-protected vault and hardware key attestation verification for DialCrypt.
//!
//! * [`Vault`]: contact, PSK and resume-secret storage whose root key is wrapped by five
//!   single-use StrongBox HMAC tickets (design 6.5 / 6.6). The crate never talks to Android;
//!   it produces the HMAC inputs and consumes the HMAC outputs (two-phase API).
//! * [`verify_attestation`]: Android key attestation chain verification (design E2 + 6.1).

#![forbid(unsafe_code)]

mod attest;
mod der_lite;
mod error;
pub mod keydesc;
mod vault;
pub mod wrap;

pub use aegiscall_memsec::SecretKey32;
pub use attest::{
    evidence_id, verify_attestation, AttestationVerdict, BootState, SecLevel, TrustConfig,
    APP_PACKAGE, ATTESTATION_CHALLENGE, MAX_CHAIN_LEN, MIN_CHAIN_LEN, REQUIRED_BRAND,
};
pub use error::{AttestError, TrustError};
pub use vault::{
    duress_overwrite, ContactProof, ContactSnapshot, ContactView, KdfParams, NewContact, PeerExpectation,
    PhoneChoice, ResumeCandidate, Rotation, TicketUse, UnlockOutcome, Vault, ARGON2ID_PARAMS,
    MAX_CONTACTS, MAX_LABEL_LEN, MAX_PIN_LEN, MAX_UNREFRESHED_RESUMES, MAX_VAULT_LEN, MIN_PIN_LEN,
    TICKETS_PER_VAULT, VAULT_PAD_BLOCK,
};
pub use wrap::{parse_wrapping_public_key, wrap_ticket_for_strongbox};
