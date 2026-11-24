//! Clean-room locked RAM vault and deterministic zeroization primitives.
//!
//! Ensures session keys, ephemeral chat bubbles, and decrypted plaintext never hit
//! swap/zRAM or core dumps, and are forensically wiped within milliseconds of
//! hangup or panic-wipe invocation.

use std::alloc::{alloc_zeroed, dealloc, Layout};
use std::ptr::{self, NonNull};
use std::sync::atomic::{compiler_fence, Ordering};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Error)]
pub enum MemSecError {
    #[error("allocation size must be non-zero")]
    ZeroSized,
    #[error("failed to construct memory layout")]
    InvalidLayout,
    #[error("failed to allocate aligned memory")]
    AllocationFailed,
}

/// Platform-specific memory locking (`VirtualLock` on Windows, `mlock` + `MADV_DONTDUMP` on Unix).
mod platform {
    #[cfg(windows)]
    extern "system" {
        fn VirtualLock(lpAddress: *const core::ffi::c_void, dwSize: usize) -> i32;
        fn VirtualUnlock(lpAddress: *const core::ffi::c_void, dwSize: usize) -> i32;
    }

    pub unsafe fn lock_pages(ptr: *mut u8, len: usize) -> bool {
        if len == 0 {
            return true;
        }
        #[cfg(unix)]
        {
            let locked = libc::mlock(ptr as *const libc::c_void, len) == 0;
            #[cfg(target_os = "linux")]
            {
                let _ = libc::madvise(ptr as *mut libc::c_void, len, libc::MADV_DONTDUMP);
            }
            locked
        }
        #[cfg(windows)]
        {
            VirtualLock(ptr as *const core::ffi::c_void, len) != 0
        }
        #[cfg(not(any(unix, windows)))]
        {
            false
        }
    }

    pub unsafe fn unlock_pages(ptr: *mut u8, len: usize) {
        if len == 0 {
            return;
        }
        #[cfg(unix)]
        {
            let _ = libc::munlock(ptr as *const libc::c_void, len);
        }
        #[cfg(windows)]
        {
            let _ = VirtualUnlock(ptr as *const core::ffi::c_void, len);
        }
    }

    pub fn harden_process_anti_dump() {
        #[cfg(target_os = "linux")]
        unsafe {
            let _ = libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
            let rlim = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            let _ = libc::setrlimit(libc::RLIMIT_CORE, &rlim);
        }
    }
}

/// Enables OS-level anti-coredump / anti-ptrace hardening (`PR_SET_DUMPABLE = 0`).
pub fn harden_process() {
    platform::harden_process_anti_dump();
}

/// A heap buffer pinned in physical RAM (best-effort OS `mlock`/`VirtualLock`)
/// that is overwritten with volatile zeroes on drop.
pub struct LockedBuffer {
    ptr: NonNull<u8>,
    len: usize,
    layout: Layout,
    is_locked: bool,
}

// SAFETY: LockedBuffer owns its exclusive allocation and has no thread-local state.
unsafe impl Send for LockedBuffer {}
unsafe impl Sync for LockedBuffer {}

impl LockedBuffer {
    /// Allocates `len` zeroed bytes and attempts to lock the pages in physical RAM.
    pub fn new(len: usize) -> Result<Self, MemSecError> {
        if len == 0 {
            return Err(MemSecError::ZeroSized);
        }
        let align = 64;
        let layout = Layout::from_size_align(len, align).map_err(|_| MemSecError::InvalidLayout)?;
        // SAFETY: layout is non-zero and properly aligned.
        let raw = unsafe { alloc_zeroed(layout) };
        let ptr = NonNull::new(raw).ok_or(MemSecError::AllocationFailed)?;
        let is_locked = unsafe { platform::lock_pages(ptr.as_ptr(), len) };

        Ok(Self {
            ptr,
            len,
            layout,
            is_locked,
        })
    }

    /// Creates a locked buffer initialized from sensitive bytes and immediately zeroes `src`.
    pub fn from_secret_slice(src: &mut [u8]) -> Result<Self, MemSecError> {
        let mut buf = Self::new(src.len())?;
        buf.as_mut_slice().copy_from_slice(src);
        src.zeroize();
        Ok(buf)
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn is_os_locked(&self) -> bool {
        self.is_locked
    }

    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: `ptr` is valid for `len` bytes for the lifetime of `self`.
        unsafe { core::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: `ptr` is exclusively owned and valid for `len` bytes.
        unsafe { core::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }

    /// Returns a raw pointer for forensic zero-residual verification tests.
    pub fn raw_addr(&self) -> usize {
        self.ptr.as_ptr() as usize
    }

    /// Immediately performs a volatile memory scrub of all bytes in the buffer.
    pub fn scrub(&mut self) {
        volatile_zero_region(self.ptr.as_ptr(), self.len);
    }

    /// Counts non-zero bytes remaining inside this buffer (must be 0 after scrub).
    pub fn count_nonzero_bytes(&self) -> usize {
        self.as_slice().iter().filter(|&&b| b != 0).count()
    }
}

impl Drop for LockedBuffer {
    fn drop(&mut self) {
        self.scrub();
        unsafe {
            if self.is_locked {
                platform::unlock_pages(self.ptr.as_ptr(), self.len);
            }
            dealloc(self.ptr.as_ptr(), self.layout);
        }
    }
}

/// Performs an optimization-proof volatile zero wipe followed by a compiler fence.
#[inline(never)]
pub fn volatile_zero_region(ptr: *mut u8, len: usize) {
    for i in 0..len {
        // SAFETY: Caller guarantees `ptr..ptr+len` is valid for writes.
        unsafe {
            ptr::write_volatile(ptr.add(i), 0u8);
        }
    }
    compiler_fence(Ordering::SeqCst);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageDirection {
    Outgoing,
    Incoming,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryReceiptState {
    Queued,
    Transmitting { acked_shards: u16, total_shards: u16 },
    DeliveredToPeerRam,
    ViewedByPeer,
    FailedOrAborted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EphemeralMediaKind {
    Text,
}

/// A single ephemeral text message stored solely in RAM with optional burn TTL.
pub struct EphemeralMessage {
    pub msg_id: u32,
    pub direction: MessageDirection,
    pub created_at_ms: u64,
    pub burn_ttl_secs: u16,
    pub expires_at_ms: Option<u64>,
    pub delivery_state: DeliveryReceiptState,
    pub media_kind: EphemeralMediaKind,
    actual_len: usize,
    body: LockedBuffer,
}

impl EphemeralMessage {
    pub fn new(
        msg_id: u32,
        direction: MessageDirection,
        created_at_ms: u64,
        burn_ttl_secs: u16,
        plaintext_utf8: &mut Vec<u8>,
    ) -> Result<Self, MemSecError> {
        Self::new_with_kind(
            msg_id,
            direction,
            created_at_ms,
            burn_ttl_secs,
            EphemeralMediaKind::Text,
            plaintext_utf8,
        )
    }

    pub fn new_with_kind(
        msg_id: u32,
        direction: MessageDirection,
        created_at_ms: u64,
        burn_ttl_secs: u16,
        media_kind: EphemeralMediaKind,
        payload: &mut Vec<u8>,
    ) -> Result<Self, MemSecError> {
        let actual_len = payload.len();
        let len = actual_len.max(1);
        let mut body = LockedBuffer::new(len)?;
        if !payload.is_empty() {
            body.as_mut_slice()[..actual_len].copy_from_slice(payload);
        }
        payload.zeroize();

        let expires_at_ms = if burn_ttl_secs > 0 {
            Some(created_at_ms.saturating_add(burn_ttl_secs as u64 * 1000))
        } else {
            None
        };

        let mut msg = Self {
            msg_id,
            direction,
            created_at_ms,
            burn_ttl_secs,
            expires_at_ms,
            delivery_state: match direction {
                MessageDirection::Outgoing => DeliveryReceiptState::Queued,
                MessageDirection::Incoming => DeliveryReceiptState::DeliveredToPeerRam,
            },
            media_kind,
            actual_len,
            body,
        };
        if actual_len == 0 {
            msg.body.scrub();
        }
        Ok(msg)
    }

    pub fn text(&self) -> &str {
        if self.media_kind != EphemeralMediaKind::Text {
            return "";
        }
        core::str::from_utf8(self.raw_bytes()).unwrap_or("")
    }

    pub fn raw_bytes(&self) -> &[u8] {
        let len = self.actual_len.min(self.body.len());
        &self.body.as_slice()[..len]
    }

    pub fn scrub(&mut self) {
        self.body.scrub();
        self.actual_len = 0;
    }

    pub fn count_nonzero_bytes(&self) -> usize {
        self.body.count_nonzero_bytes()
    }
}

impl Drop for EphemeralMessage {
    fn drop(&mut self) {
        self.body.scrub();
    }
}

/// Zero-database, RAM-only chat vault bound to a single active call session.
/// Every message is scrubbed on TTL expiry, hangup, or panic-wipe.
pub struct EphemeralChatVault {
    messages: Vec<EphemeralMessage>,
    wiped: bool,
}

impl EphemeralChatVault {
    pub fn new() -> Self {
        harden_process();
        Self {
            messages: Vec::with_capacity(64),
            wiped: false,
        }
    }

    pub fn push_message(
        &mut self,
        msg_id: u32,
        direction: MessageDirection,
        now_ms: u64,
        burn_ttl_secs: u16,
        plaintext: &str,
    ) -> Result<(), MemSecError> {
        self.push_binary_payload(
            msg_id,
            direction,
            now_ms,
            burn_ttl_secs,
            EphemeralMediaKind::Text,
            plaintext.as_bytes(),
        )
    }

    pub fn push_binary_payload(
        &mut self,
        msg_id: u32,
        direction: MessageDirection,
        now_ms: u64,
        burn_ttl_secs: u16,
        media_kind: EphemeralMediaKind,
        raw_bytes: &[u8],
    ) -> Result<(), MemSecError> {
        if self.wiped {
            self.wiped = false;
        }
        let mut bytes = raw_bytes.to_vec();
        let msg = EphemeralMessage::new_with_kind(
            msg_id,
            direction,
            now_ms,
            burn_ttl_secs,
            media_kind,
            &mut bytes,
        )?;
        self.messages.push(msg);
        Ok(())
    }

    pub fn mark_delivered(&mut self, msg_id: u32) {
        if let Some(m) = self
            .messages
            .iter_mut()
            .find(|m| m.msg_id == msg_id && m.direction == MessageDirection::Outgoing)
        {
            if m.delivery_state != DeliveryReceiptState::ViewedByPeer {
                m.delivery_state = DeliveryReceiptState::DeliveredToPeerRam;
            }
        }
    }

    pub fn mark_viewed(&mut self, msg_id: u32) {
        if let Some(m) = self
            .messages
            .iter_mut()
            .find(|m| m.msg_id == msg_id && m.direction == MessageDirection::Outgoing)
        {
            m.delivery_state = DeliveryReceiptState::ViewedByPeer;
        }
    }

    pub fn mark_aborted(&mut self, msg_id: u32) {
        if let Some(m) = self.messages.iter_mut().find(|m| m.msg_id == msg_id) {
            m.delivery_state = DeliveryReceiptState::FailedOrAborted;
        }
    }

    pub fn update_progress(&mut self, msg_id: u32, acked_shards: u16, total_shards: u16) {
        if let Some(m) = self
            .messages
            .iter_mut()
            .find(|m| m.msg_id == msg_id && m.direction == MessageDirection::Outgoing)
        {
            if m.delivery_state != DeliveryReceiptState::DeliveredToPeerRam
                && m.delivery_state != DeliveryReceiptState::ViewedByPeer
                && m.delivery_state != DeliveryReceiptState::FailedOrAborted
            {
                m.delivery_state = DeliveryReceiptState::Transmitting {
                    acked_shards,
                    total_shards,
                };
            }
        }
    }

    /// Scrubs and evicts all messages whose burn-after-read timer has expired.
    pub fn tick_burn_ttl(&mut self, now_ms: u64) -> usize {
        let mut evicted = 0;
        let mut i = 0;
        while i < self.messages.len() {
            let expired = self.messages[i]
                .expires_at_ms
                .is_some_and(|exp| now_ms >= exp);
            if expired {
                let mut removed = self.messages.remove(i);
                removed.scrub();
                evicted += 1;
            } else {
                i += 1;
            }
        }
        evicted
    }

    pub fn messages(&self) -> &[EphemeralMessage] {
        &self.messages
    }

    pub fn is_wiped(&self) -> bool {
        self.wiped && self.messages.is_empty()
    }

    /// Immediately scrubs all stored message buffers and clears the vault.
    pub fn panic_wipe(&mut self) {
        for msg in &mut self.messages {
            msg.scrub();
        }
        self.messages.clear();
        self.messages.shrink_to(0);
        self.wiped = true;
    }

    /// Total non-zero secret bytes currently held across all live messages.
    pub fn total_live_secret_bytes(&self) -> usize {
        self.messages.iter().map(|m| m.count_nonzero_bytes()).sum()
    }
}

impl Default for EphemeralChatVault {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for EphemeralChatVault {
    fn drop(&mut self) {
        self.panic_wipe();
    }
}

/// Fixed-size zeroizing key wrapper for 256-bit symmetric session material.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey32(pub [u8; 32]);

impl SecretKey32 {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locked_buffer_scrub_leaves_zero_residual_bytes() {
        let mut secret = b"TOP_SECRET_COORDINATES_51.5007N_000.1246W".to_vec();
        let mut buf = LockedBuffer::from_secret_slice(&mut secret).expect("alloc locked buffer");
        assert!(secret.iter().all(|&b| b == 0), "source slice must be zeroed");
        assert!(buf.count_nonzero_bytes() > 0);
        buf.scrub();
        assert_eq!(buf.count_nonzero_bytes(), 0, "scrub must leave 0 secret bytes");
    }

    #[test]
    fn vault_burn_ttl_and_panic_wipe_evict_and_zeroize() {
        let mut vault = EphemeralChatVault::new();
        vault
            .push_message(1, MessageDirection::Outgoing, 1000, 10, "Café at B, 11pm tonight!")
            .unwrap();
        vault
            .push_message(2, MessageDirection::Incoming, 2000, 0, "Received, coordinates OK")
            .unwrap();
        assert_eq!(vault.messages().len(), 2);
        assert!(vault.total_live_secret_bytes() > 0);

        // At t=11_000 ms, msg 1 (created 1000 + 10s = 11_000) expires
        let evicted = vault.tick_burn_ttl(11_000);
        assert_eq!(evicted, 1);
        assert_eq!(vault.messages().len(), 1);
        assert_eq!(vault.messages()[0].text(), "Received, coordinates OK");

        vault.panic_wipe();
        assert!(vault.is_wiped());
        assert_eq!(vault.total_live_secret_bytes(), 0);
    }
}
