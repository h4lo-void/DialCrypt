//! JNI bridge for `io.github.h4lovoid.dialcrypt.core.NativeBridge` (secure-session-v2 §2.D, §6.6).
//!
//! * Java never holds a pointer. App objects and call sessions live in two registry tables
//!   under random, never reused, non-zero 63-bit handles; each entry is
//!   `Arc<Mutex<Slot<T>>>` with `Slot::Live(T)` or `Slot::Closed`, and the slot lock is held
//!   for the whole operation. Closing takes the lock, wipes, marks the slot `Closed` and then
//!   removes it, so a call that already looked the handle up sees `Closed` and returns -1.
//!   [Bridge::panic_wipe] sets the global WIPING flag first: every later call returns -1.
//! * Rust never calls into Java. Signatures, vault writes and every state change are reported
//!   as events the app polls ([events]); the app answers with the matching function.
//! * Every function returns a code from [code] or a nullable value; nothing produces text for
//!   users. Data from the peer or from files never panics; secrets and the PIN, message and
//!   vault bytes copied from Java are zeroized after use.

mod audio;
mod bridge;
pub mod events;
mod exports;
mod registry;

pub use bridge::{harden, Bridge};

/// Return codes shared by every exported function (§2.D).
pub mod code {
    pub const OK: i32 = 0;
    /// Unknown, closed or wrong-type handle, or the global WIPING flag is set.
    pub const BAD_HANDLE: i32 = -1;
    pub const BAD_ARG: i32 = -2;
    pub const BAD_STATE: i32 = -3;
    pub const CRYPTO: i32 = -4;
    /// Vault locked, dead (no ticket left) or wiped by the duress PIN.
    pub const LOCKED: i32 = -5;
    /// The call session is aborted or ended.
    pub const ABORTED: i32 = -6;
    pub const BUSY: i32 = -7;
    pub const INTERNAL: i32 = -8;
}

#[cfg(test)]
mod tests;
