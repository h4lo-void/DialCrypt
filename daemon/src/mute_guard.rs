//! Fail-Closed Hardware Mute Guard & 20ms Watchdog.
//!
//! Prevents plaintext acoustic leakage if the crypto session stalls, crashes, or fails handshake
//! The firewall is always fail-closed; there is no fallback to a plain call.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Clone)]
pub struct MuteFirewall {
    mic_locked_muted: Arc<AtomicBool>,
    earpiece_silenced: Arc<AtomicBool>,
    fail_closed_tripped: Arc<AtomicBool>,
    last_heartbeat_ms: Arc<AtomicU64>,
    watchdog_timeout_ms: u64,
}

impl MuteFirewall {
    /// Hard-mutes physical mic and uplink TX forever if encryption drops.
    pub fn new(now_ms: u64) -> Self {
        Self {
            mic_locked_muted: Arc::new(AtomicBool::new(true)),
            earpiece_silenced: Arc::new(AtomicBool::new(true)),
            fail_closed_tripped: Arc::new(AtomicBool::new(false)),
            last_heartbeat_ms: Arc::new(AtomicU64::new(now_ms)),
            watchdog_timeout_ms: 100, // 5 missed 20ms frames triggers fail-closed clamp
        }
    }

    pub fn heartbeat(&self, now_ms: u64) {
        self.last_heartbeat_ms.store(now_ms, Ordering::Release);
    }

    pub fn poll_watchdog(&self, now_ms: u64) -> bool {
        let last = self.last_heartbeat_ms.load(Ordering::Acquire);
        if now_ms.saturating_sub(last) > self.watchdog_timeout_ms {
            self.trip_fail_closed();
            return false;
        }
        true
    }

    pub fn trip_fail_closed(&self) {
        self.mic_locked_muted.store(true, Ordering::SeqCst);
        self.earpiece_silenced.store(true, Ordering::SeqCst);
        self.fail_closed_tripped.store(true, Ordering::SeqCst);
    }

    pub fn is_mic_muted(&self) -> bool {
        self.mic_locked_muted.load(Ordering::Acquire)
    }

    pub fn is_fail_closed_tripped(&self) -> bool {
        self.fail_closed_tripped.load(Ordering::Acquire)
    }

    /// Sanitizes an outgoing cellular uplink frame: guarantees zero physical mic bleed.
    pub fn enforce_uplink_isolation(
        &self,
        physical_mic: &mut [i16],
        uplink_tx: &mut [i16],
        encrypted_modem_audio: &[i16],
    ) {
        if self.is_mic_muted() {
            physical_mic.fill(0);
        }
        if self.is_fail_closed_tripped() {
            uplink_tx.fill(0);
        } else {
            let n = uplink_tx.len().min(encrypted_modem_audio.len());
            uplink_tx[..n].copy_from_slice(&encrypted_modem_audio[..n]);
        }
    }
}
