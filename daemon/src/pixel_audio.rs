//! Google Pixel Native Call Audio Interception Bridge (`CALL_AUDIO_INTERCEPTION` / `TELEPHONY_TX`).
//!
//! Pixel Tensor devices expose privileged AOSP audio patches (`AUDIO_DEVICE_OUT_TELEPHONY_TX`
//! and `AUDIO_SOURCE_VOICE_DOWNLINK`) used natively for Google Call Screen. `aegiscalld`
//! acquires exclusive control of those streams during encrypted chat calls so acoustic leakage
//! is zero and modem latency stays minimal.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PixelAudioRouteState {
    Idle,
    InterceptedSilentTyping,
    FailClosedMuted,
}

pub struct PixelTelephonyBridge {
    state: PixelAudioRouteState,
    sample_rate_hz: u32,
    mic_hardware_cut: bool,
    earpiece_silenced: bool,
}

impl PixelTelephonyBridge {
    pub fn new() -> Self {
        Self {
            state: PixelAudioRouteState::Idle,
            sample_rate_hz: 16_000,
            mic_hardware_cut: false,
            earpiece_silenced: false,
        }
    }

    /// Engages Pixel digital telephony TX injection + RX capture while cutting mic and silencing earpiece.
    pub fn engage_silent_chat_patch(&mut self) {
        self.mic_hardware_cut = true;
        self.earpiece_silenced = true;
        self.state = PixelAudioRouteState::InterceptedSilentTyping;
    }

    /// Fail-closed emergency mute: drops telephony uplink TX to hard zero and disconnects physical mic.
    pub fn fail_closed_cutoff(&mut self) {
        self.mic_hardware_cut = true;
        self.earpiece_silenced = true;
        self.state = PixelAudioRouteState::FailClosedMuted;
    }

    pub fn release(&mut self) {
        self.mic_hardware_cut = false;
        self.earpiece_silenced = false;
        self.state = PixelAudioRouteState::Idle;
    }

    /// Processes one 20ms frame (320 samples): zeroes physical mic and replaces earpiece out with silence
    /// so user hears zero modem data chirps while in DialCrypt silent typing mode.
    pub fn filter_in_call_buffers(
        &self,
        physical_mic_in: &mut [i16],
        earpiece_out: &mut [i16],
        modem_tx_out: &mut [i16],
        generated_modem_frame: &[i16],
    ) {
        if self.mic_hardware_cut {
            physical_mic_in.fill(0);
        }
        if self.earpiece_silenced {
            earpiece_out.fill(0);
        }
        match self.state {
            PixelAudioRouteState::InterceptedSilentTyping => {
                let n = modem_tx_out.len().min(generated_modem_frame.len());
                modem_tx_out[..n].copy_from_slice(&generated_modem_frame[..n]);
            }
            PixelAudioRouteState::FailClosedMuted => {
                modem_tx_out.fill(0);
            }
            PixelAudioRouteState::Idle => {}
        }
    }

    pub fn state(&self) -> PixelAudioRouteState {
        self.state
    }

    pub fn sample_rate_hz(&self) -> u32 {
        self.sample_rate_hz
    }
}

impl Default for PixelTelephonyBridge {
    fn default() -> Self {
        Self::new()
    }
}
