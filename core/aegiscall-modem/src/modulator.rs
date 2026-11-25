//! FormantGuard Multi-Subband Pseudo-Speech Modulation Parameters & Modulator.
//!
//! Uses constant-weight multi-tone formant combinations per sub-band aligned to 20ms
//! telephony codec frames (320 samples @ 16 kHz) with smooth Hann tapering and a
//! continuous pilot tone for carrier/clock frequency offset (CFO) tracking.

use std::f32::consts::PI;

pub const SAMPLE_RATE: usize = 16_000;
pub const FRAME_SAMPLES: usize = 320; // 20 ms @ 16 kHz
pub const DFT_WINDOW_SAMPLES: usize = 256; // 16 ms active DFT core -> 62.5 Hz bin spacing
pub const GUARD_EDGE_SAMPLES: usize = (FRAME_SAMPLES - DFT_WINDOW_SAMPLES) / 2; // 32 samples each side
pub const BIN_HZ: f32 = SAMPLE_RATE as f32 / DFT_WINDOW_SAMPLES as f32; // 62.5 Hz

/// Continuous low-energy pilot bin at 375 Hz (`6 * 62.5 Hz`) for live CFO & frame-energy tracking.
pub const PILOT_BIN: usize = 6;
pub const PILOT_FREQ_HZ: f32 = PILOT_BIN as f32 * BIN_HZ; // 375.0 Hz

/// Modem speed & codec compatibility gear.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ModemGear {
    /// 1,200 raw bps / ~600 net bps: 6 subbands x 3-of-6 tones in 500..3062.5 Hz (GSM/AMR-NB safe).
    /// One 23-byte encrypted superframe = 16 frames (320 ms).
    Narrowband1200 = 1,
    /// 2,400 raw bps / ~1,200 net bps: 12 subbands x 2-of-7 tones in 500..6437.5 Hz (VoLTE AMR-WB/EVS).
    /// One 23-byte encrypted superframe = 8 frames (160 ms).
    Wideband2400 = 2,
    /// 300 raw bps / ~144 net bps: 3 subbands x 1-of-4 tones on the 125 Hz harmonic grid in
    /// 500..1875 Hz, built for codec-heavy paths (VoWiFi/VoLTE with CELP coding and noise
    /// suppression) that drop simultaneous tones and attenuate everything above ~2 kHz.
    /// One 23-byte encrypted superframe = 64 frames (1.28 s).
    Robust300 = 3,
    /// 300 raw bps / ~144 net bps: Glottal-Formant Pseudo-Speech Vocoder gear with 7-syllable
    /// prosodic pitch contour F0(t) (110..145 Hz), laryngeal voice bar (F0, 2F0, 3F0),
    /// co-modulated F1/F2/F3 vocal-tract formants, inter-frame coarticulation cross-fading,
    /// syllable-onset consonant aspiration, and vowel-glide utterance preamble.
    Speech300 = 4,
}

impl ModemGear {
    /// Gear for a preamble/wire gear number (1, 2, 3, 4).
    pub fn from_wire(v: u8) -> Option<Self> {
        match v {
            1 => Some(ModemGear::Narrowband1200),
            2 => Some(ModemGear::Wideband2400),
            3 => Some(ModemGear::Robust300),
            4 => Some(ModemGear::Speech300),
            _ => None,
        }
    }

    pub fn frames_per_superframe(self) -> usize {
        match self {
            ModemGear::Narrowband1200 => 16,
            ModemGear::Wideband2400 => 8,
            ModemGear::Robust300 | ModemGear::Speech300 => 64,
        }
    }

    pub fn bits_per_frame(self) -> usize {
        match self {
            ModemGear::Narrowband1200 => 24,
            ModemGear::Wideband2400 => 48,
            ModemGear::Robust300 | ModemGear::Speech300 => 6,
        }
    }

    pub fn subband_count(self) -> usize {
        match self {
            ModemGear::Narrowband1200 => 6,
            ModemGear::Wideband2400 => 12,
            ModemGear::Robust300 | ModemGear::Speech300 => 3,
        }
    }

    pub fn raw_bps(self) -> u32 {
        match self {
            ModemGear::Narrowband1200 => 1200,
            ModemGear::Wideband2400 => 2400,
            ModemGear::Robust300 | ModemGear::Speech300 => 300,
        }
    }

    pub fn net_bps(self) -> u32 {
        self.raw_bps() / 2
    }

    /// Width of one sub-band in DFT bins (tone offsets are below this).
    pub fn tones_per_band(self) -> usize {
        match self {
            ModemGear::Narrowband1200 => 6,
            ModemGear::Wideband2400 => 7,
            ModemGear::Robust300 | ModemGear::Speech300 => 7,
        }
    }

    /// Tone offsets inside a sub-band that any symbol can use.
    pub fn candidate_offsets(self) -> &'static [u8] {
        match self {
            ModemGear::Narrowband1200 => &[0, 1, 2, 3, 4, 5],
            ModemGear::Wideband2400 => &[0, 1, 2, 3, 4, 5, 6],
            ModemGear::Robust300 | ModemGear::Speech300 => &[0, 2, 4, 6],
        }
    }

    /// Bits carried by one sub-band symbol.
    pub fn bits_per_band(self) -> usize {
        match self {
            ModemGear::Robust300 | ModemGear::Speech300 => 2,
            _ => 4,
        }
    }

    pub fn symbols_per_band(self) -> usize {
        1 << self.bits_per_band()
    }

    /// Active tone offsets (relative to `subband_start_bin`) for sub-band symbol `sym`.
    pub fn codeword(self, sym: usize) -> &'static [u8] {
        match self {
            ModemGear::Narrowband1200 => &CODEBOOK_3_OF_6[sym],
            ModemGear::Wideband2400 => &CODEBOOK_2_OF_7[sym],
            ModemGear::Robust300 | ModemGear::Speech300 => &CODEBOOK_1_OF_4[sym],
        }
    }
}

/// 16 canonical 2-of-7 tone pairs (selected from C(7,2)=21, maximizing min pair spacing).
pub const CODEBOOK_2_OF_7: [[u8; 2]; 16] = [
    [0, 1], [0, 2], [0, 3], [0, 4], [0, 5], [0, 6],
    [1, 2], [1, 3], [1, 4], [1, 5], [1, 6],
    [2, 3], [2, 4], [2, 5], [2, 6],
    [3, 5],
];

/// 16 canonical 3-of-6 tone triples (selected from C(6,3)=20).
pub const CODEBOOK_3_OF_6: [[u8; 3]; 16] = [
    [0, 1, 2], [0, 1, 3], [0, 1, 4], [0, 1, 5],
    [0, 2, 3], [0, 2, 4], [0, 2, 5],
    [0, 3, 4], [0, 3, 5], [0, 4, 5],
    [1, 2, 3], [1, 2, 4], [1, 2, 5],
    [1, 3, 4], [1, 3, 5], [2, 4, 5],
];

/// 1-of-4 tones on every other bin (125 Hz apart), Gray-mapped so the nearest neighbouring
/// tones differ in one bit: symbol 00 -> offset 0, 01 -> 2, 11 -> 4, 10 -> 6.
pub const CODEBOOK_1_OF_4: [[u8; 1]; 4] = [[0], [2], [6], [4]];

#[inline]
pub fn subband_start_bin(gear: ModemGear, band: usize) -> usize {
    match gear {
        // Starts at bin 8 (500 Hz), 6 bins + 1 guard = stride 7 -> bins 8..49 (500..3062.5 Hz)
        ModemGear::Narrowband1200 => 8 + band * 7,
        // Starts at bin 8 (500 Hz), 7 bins + 1 guard = stride 8 -> bins 8..103 (500..6437.5 Hz)
        ModemGear::Wideband2400 => 8 + band * 8,
        // Starts at bin 8 (500 Hz), tones on even bins only, stride 8 -> bins 8..30 (500..1875 Hz):
        // every tone (and the 375 Hz pilot) is a harmonic of 125 Hz (or F0(t) in Speech300).
        ModemGear::Robust300 | ModemGear::Speech300 => 8 + band * 8,
    }
}

/// Deterministic golden-ratio phase offset per bin to minimize Peak-to-Average Power Ratio (PAPR),
/// keeping the synthesized multi-tone waveform speech-like and free of clipping spikes.
#[inline]
fn initial_phase(bin: usize, frame_idx: u32) -> f32 {
    let seed = (bin as f32) * 2.399_963_2 + (frame_idx as f32) * 0.618_033_9;
    seed % (2.0 * PI)
}

/// Phase of a tone on the 62.5 Hz grid at the start of frame `frame_idx`, continuous across
/// frames, plus a fixed per-bin offset to keep the crest factor low.
#[inline]
fn continuous_phase(bin: usize, frame_idx: u32) -> f32 {
    // Cycles elapsed before this frame: bin * 62.5 Hz * 20 ms * frame_idx = 1.25 * bin * frame_idx.
    let cycles = (1.25 * bin as f64 * frame_idx as f64).fract();
    let offset = (bin as f64 * 2.399_963_2) % (2.0 * std::f64::consts::PI);
    ((cycles * 2.0 * std::f64::consts::PI + offset) % (2.0 * std::f64::consts::PI)) as f32
}

pub struct FormantModulator {
    gear: ModemGear,
    frame_counter: u32,
    window: [f32; FRAME_SAMPLES],
    prev_speech_bins: [Option<usize>; 3],
    voice_timbre: crate::speech::VoiceTimbre,
}

impl FormantModulator {
    pub fn new(gear: ModemGear) -> Self {
        Self::new_with_timbre(gear, crate::speech::VoiceTimbre::MaleBaritone)
    }

    pub fn new_with_timbre(gear: ModemGear, voice_timbre: crate::speech::VoiceTimbre) -> Self {
        let mut window = [1.0f32; FRAME_SAMPLES];
        // Smooth 32-sample (2 ms) raised-cosine fade-in/fade-out avoids inter-frame codec clicks
        for i in 0..GUARD_EDGE_SAMPLES {
            let w = 0.5 * (1.0 - (PI * i as f32 / GUARD_EDGE_SAMPLES as f32).cos());
            window[i] = w;
            window[FRAME_SAMPLES - 1 - i] = w;
        }
        Self {
            gear,
            frame_counter: 0,
            window,
            prev_speech_bins: [None; 3],
            voice_timbre,
        }
    }

    pub fn set_voice_timbre(&mut self, voice_timbre: crate::speech::VoiceTimbre) {
        self.voice_timbre = voice_timbre;
    }

    pub fn gear(&self) -> ModemGear {
        self.gear
    }

    /// Modulates a 384-bit interleaved superframe into `8` (WB), `16` (NB) or `64` (Robust/Speech)
    /// 20ms PCM frames.
    pub fn modulate_superframe(&mut self, interleaved_bits: &[u8; 384]) -> Vec<i16> {
        let frames = self.gear.frames_per_superframe();
        let bpf = self.gear.bits_per_frame();
        let mut out = Vec::with_capacity(frames * FRAME_SAMPLES);

        if self.gear == ModemGear::Speech300 && self.frame_counter % 64 != 0 {
            // Advance to the next 64-frame phrase boundary without repeating an earlier phrase
            self.frame_counter = ((self.frame_counter / 64) + 1) * 64;
        }

        for f in 0..frames {
            let frame_bits = &interleaved_bits[f * bpf..(f + 1) * bpf];
            let pcm_frame = self.modulate_single_frame(frame_bits);
            out.extend_from_slice(&pcm_frame);
        }
        out
    }

    /// Modulates one 20ms frame (`24` bits NB, `48` bits WB, `6` bits Robust/Speech) into 320 PCM samples.
    pub fn modulate_single_frame(&mut self, bits: &[u8]) -> [i16; FRAME_SAMPLES] {
        if self.gear == ModemGear::Robust300 {
            return self.modulate_robust_frame(bits);
        }
        if self.gear == ModemGear::Speech300 {
            let fc = self.frame_counter;
            self.frame_counter = self.frame_counter.wrapping_add(1);
            return crate::speech::modulate_speech_frame_with_timbre(
                bits,
                fc,
                &mut self.prev_speech_bins,
                self.voice_timbre,
            );
        }
        let bands = self.gear.subband_count();
        debug_assert_eq!(bits.len(), bands * 4);

        let mut accum = [0.0f32; FRAME_SAMPLES];

        // Add steady pilot tone at 375 Hz for continuous CFO & frame-energy normalization
        let pilot_phase0 = (self.frame_counter as f32) * 0.5;
        let pilot_omega = 2.0 * PI * PILOT_FREQ_HZ / SAMPLE_RATE as f32;
        for (n, dst) in accum.iter_mut().enumerate() {
            *dst += 1.25 * (pilot_omega * n as f32 + pilot_phase0).sin();
        }

        // Synthesize active formant tones per subband
        for b in 0..bands {
            let sym = ((bits[b * 4] & 1) << 3)
                | ((bits[b * 4 + 1] & 1) << 2)
                | ((bits[b * 4 + 2] & 1) << 1)
                | (bits[b * 4 + 3] & 1);
            let base_bin = subband_start_bin(self.gear, b);

            match self.gear {
                ModemGear::Narrowband1200 => {
                    let tones = CODEBOOK_3_OF_6[sym as usize];
                    for &t in &tones {
                        let bin = base_bin + t as usize;
                        let freq = bin as f32 * BIN_HZ;
                        let omega = 2.0 * PI * freq / SAMPLE_RATE as f32;
                        let ph = initial_phase(bin, self.frame_counter);
                        for (n, dst) in accum.iter_mut().enumerate() {
                            *dst += (omega * n as f32 + ph).sin();
                        }
                    }
                }
                ModemGear::Wideband2400 => {
                    let tones = CODEBOOK_2_OF_7[sym as usize];
                    for &t in &tones {
                        let bin = base_bin + t as usize;
                        let freq = bin as f32 * BIN_HZ;
                        let omega = 2.0 * PI * freq / SAMPLE_RATE as f32;
                        let ph = initial_phase(bin, self.frame_counter);
                        for (n, dst) in accum.iter_mut().enumerate() {
                            *dst += (omega * n as f32 + ph).sin();
                        }
                    }
                }
                ModemGear::Robust300 | ModemGear::Speech300 => {
                    unreachable!("handled by early gear dispatch")
                }
            }
        }

        self.frame_counter = self.frame_counter.wrapping_add(1);

        // Normalize gently to ~-6 dBFS (safe headroom below AMR/EVS saturation clippers)
        let norm = match self.gear {
            ModemGear::Narrowband1200 => 1400.0,
            ModemGear::Wideband2400 => 1050.0,
            ModemGear::Robust300 | ModemGear::Speech300 => {
                unreachable!("handled by early gear dispatch")
            }
        };
        let mut pcm = [0i16; FRAME_SAMPLES];
        for i in 0..FRAME_SAMPLES {
            let s = (accum[i] * self.window[i] * norm).clamp(-30_000.0, 30_000.0);
            pcm[i] = s.round() as i16;
        }
        pcm
    }

    /// Robust300: three phase-continuous harmonic tones (one per sub-band) plus a lighter pilot.
    fn modulate_robust_frame(&mut self, bits: &[u8]) -> [i16; FRAME_SAMPLES] {
        let gear = self.gear;
        let bands = gear.subband_count();
        let bpb = gear.bits_per_band();
        debug_assert_eq!(bits.len(), bands * bpb);
        let mut accum = [0.0f32; FRAME_SAMPLES];

        let mut add_tone = |bin: usize, amp: f32, frame: u32| {
            let omega = 2.0 * PI * bin as f32 * BIN_HZ / SAMPLE_RATE as f32;
            let ph = continuous_phase(bin, frame);
            for (n, dst) in accum.iter_mut().enumerate() {
                *dst += amp * (omega * n as f32 + ph).sin();
            }
        };
        add_tone(PILOT_BIN, 0.7, self.frame_counter);
        for b in 0..bands {
            let mut sym = 0usize;
            for q in 0..bpb {
                sym = (sym << 1) | (bits[b * bpb + q] & 1) as usize;
            }
            for &t in gear.codeword(sym) {
                add_tone(subband_start_bin(gear, b) + t as usize, 1.0, self.frame_counter);
            }
        }
        self.frame_counter = self.frame_counter.wrapping_add(1);

        // Same RMS as the narrowband gear (~-17.5 dBFS); peak stays below ~-8 dBFS.
        let norm = 3300.0f32;
        let mut pcm = [0i16; FRAME_SAMPLES];
        for i in 0..FRAME_SAMPLES {
            let s = (accum[i] * self.window[i] * norm).clamp(-30_000.0, 30_000.0);
            pcm[i] = s.round() as i16;
        }
        pcm
    }
}
