//! DialCrypt cryptography: handshake v2 with resume, identity helpers, pairing code v2,
//! epoch cipher and DH ratchet (secure-session-v2).

pub mod aead;
pub mod dh_ratchet;
pub mod epoch_cipher;
pub mod handshake_v2;
pub mod identity;
pub mod pairing_v2;
mod primitives;

use thiserror::Error;

pub use aead::MUX_PAYLOAD_LEN;
pub use dh_ratchet::{
    pq_encapsulate, DhRatchet, PqKeyPair, PqSecret, RatchetAction, RatchetAssembler, RatchetError, RatchetMsg,
    RATCHET_DEADLINE_FRAMES, RATCHET_FLAG_PQ, RATCHET_INTERVAL_FRAMES,
};
pub use epoch_cipher::{EpochCipher, EpochError, OpenedFrame};
pub use handshake_v2::{
    resume_saved_tag, CallSide, Established, HandshakeV2, HsError, HsOut, LinkContext, Path, PeerExpectation,
    ResumeCandidate, Role, HS1_LEN, HS2_LEN, HS3_LEN, HS4_LEN, PATH_LEN, RS2_LEN, RS3_LEN,
};
#[cfg(any(test, feature = "test-signer"))]
pub use identity::SoftwareSigner;
pub use identity::{
    classify_peer, ecdsa_der_to_raw, spki_der_to_pub33, verify_identity_sig, IdentityStatus, LocalIdentity,
    PeerIdentity,
};
pub use pairing_v2::{PairingCodeV2, PairingSecret};

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("hardware secure element key destroyed or unavailable")]
    HardwareKeyDestroyed,
    #[error("invalid key material")]
    InvalidKeyMaterial,
    #[error("invalid peer public key")]
    InvalidPeerPublicKey,
    #[error("peer hardware attestation verification failed")]
    AttestationFailed,
    #[error("invalid handshake packet")]
    InvalidHandshakeMessage,
    #[error("superframe AEAD authentication failed")]
    AuthenticationFailed,
    #[error("superframe or message replay detected")]
    ReplayDetected,
    #[error("invalid or corrupted out-of-band pairing code")]
    InvalidPairingCode,
    #[error("peer hardware identity key mismatch (possible SIM-swap or MitM)")]
    PeerIdentityPinMismatch,
    #[error("peer edition downgrade rejected (expected Pixel Titan M2)")]
    EditionDowngradeAttack,
    #[error("message key-commitment tag verification failed")]
    KeyCommitmentMismatch,
    #[error("message ratchet window exceeded (> 32 skipped messages)")]
    RatchetWindowExceeded,
}
