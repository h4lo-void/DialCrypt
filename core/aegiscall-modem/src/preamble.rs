//! FormantChirp Auto-Discovery Preamble:
//! 1. V-Chirp (120 ms up-chirp + 120 ms down-chirp) immune to +/-50 Hz CFO that simultaneously
//!    pins exact frame synchronization to <= 2 samples and directly measures carrier offset.
//! 2. 160 ms Capability Trailer carrying capability flags, Protocol Version and preferred
//!    Gear protected by Rate-1/2 FEC + CRC-8. Protocol v2 (secure-session-v2 §2.B, §6.1):
//!    version 2, CAP_SUITE_V2 set, retired edition bits 0-1 kept at zero. The raw 5 bytes are
//!    reported with every detection because the handshake transcript binds them.
//! Total duration: 400 ms (6,400 samples @ 16 kHz).

use crate::demodulator::{dft_energy_at_freq, FormantDemodulator};
use crate::fec::{crc8_atm, encode_short_fec};
use crate::modulator::{
    subband_start_bin, ModemGear, BIN_HZ, CODEBOOK_3_OF_6, DFT_WINDOW_SAMPLES, FRAME_SAMPLES,
    GUARD_EDGE_SAMPLES, SAMPLE_RATE,
};
use std::f32::consts::PI;

pub const PREAMBLE_MAGIC: u8 = 0xAC;
pub const PROTOCOL_VERSION: u8 = 0x02;

/// Bits 0-1 carried the retired hardware-edition flags (§6.1); v2 senders keep them zero.
pub const CAP_RESERVED_EDITION_MASK: u16 = 0b11;
pub const CAP_CHAT_ARQ_V1: u16 = 1 << 2;
/// Retired v1 suite bit; v2 announces CAP_SUITE_V2 instead.
pub const CAP_MLKEM_768: u16 = 1 << 3;
pub const CAP_VOICE_V2_RESERVED: u16 = 1 << 4;
/// Handshake v2 suite 0x01 (X25519 + ML-KEM-1024, HKDF-SHA-384, XChaCha20-Poly1305, P-256).
pub const CAP_SUITE_V2: u16 = 1 << 5;

// V-Chirp parameters: 120 ms up-sweep + 120 ms down-sweep from 600 Hz to 1900 Hz
const CHIRP_SAMPLES: usize = 1920; // 120 ms
const CHIRP_F0: f32 = 600.0;
const CHIRP_F1: f32 = 1900.0;
const CHIRP_SLOPE: f32 = (CHIRP_F1 - CHIRP_F0) / (CHIRP_SAMPLES as f32 / SAMPLE_RATE as f32); // Hz/sec
const TRAILER_FRAMES: usize = 8; // 8 * 20ms = 160 ms (carries 48 bits @ NB 24 raw bps? wait: 4*24=96 raw bits -> 8 frames = 192 raw bits, enough for 40-bit header * 2 FEC = 92 bits repeated twice!)
pub const TOTAL_PREAMBLE_SAMPLES: usize = CHIRP_SAMPLES * 2 + TRAILER_FRAMES * FRAME_SAMPLES; // 6,400 samples = 400 ms

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreambleCapabilities {
    pub version: u8,
    /// Capability bits (the field name predates v2 and is kept for source compatibility).
    pub edition_flags: u16,
    pub preferred_gear: ModemGear,
}

impl PreambleCapabilities {
    /// What a v2 endpoint announces: version 2, CAP_SUITE_V2 | CAP_CHAT_ARQ_V1, edition bits zero.
    pub fn v2(preferred_gear: ModemGear) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            edition_flags: CAP_SUITE_V2 | CAP_CHAT_ARQ_V1,
            preferred_gear,
        }
    }

    /// True only for version 2 with CAP_SUITE_V2 and the retired edition bits clear.
    pub fn is_v2_compatible(&self) -> bool {
        self.version == PROTOCOL_VERSION
            && self.edition_flags & CAP_SUITE_V2 != 0
            && self.edition_flags & CAP_RESERVED_EDITION_MASK == 0
    }

    pub fn encode_bytes(&self) -> [u8; 5] {
        let flags_bytes = self.edition_flags.to_be_bytes();
        let mut buf = [
            PREAMBLE_MAGIC,
            (self.version & 0x0F) | (((self.preferred_gear as u8) & 0x0F) << 4),
            flags_bytes[0],
            flags_bytes[1],
            0,
        ];
        buf[4] = crc8_atm(&buf[..4]);
        buf
    }

    pub fn decode_bytes(raw: &[u8; 5]) -> Option<Self> {
        if raw[0] != PREAMBLE_MAGIC || crc8_atm(&raw[..4]) != raw[4] {
            return None;
        }
        let version = raw[1] & 0x0F;
        let gear = ModemGear::from_wire((raw[1] >> 4) & 0x0F)?;
        let edition_flags = u16::from_be_bytes([raw[2], raw[3]]);
        Some(Self {
            version,
            edition_flags,
            preferred_gear: gear,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PreambleDetection {
    /// Sample index inside the input buffer where the encrypted superframes begin.
    pub payload_start_sample: usize,
    /// Estimated carrier/clock frequency offset in Hz.
    pub estimated_cfo_hz: f32,
    pub peer_caps: PreambleCapabilities,
    pub confidence: f32,
    /// The decoded 5 preamble bytes exactly as sent (magic, version|gear, caps, CRC-8).
    pub raw: [u8; 5],
}

/// A preamble whose magic byte and CRC-8 check out, before the gear nibble is interpreted.
/// Test tools use this to sync on gears the session layer does not negotiate yet.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RawPreambleDetection {
    pub payload_start_sample: usize,
    pub estimated_cfo_hz: f32,
    pub confidence: f32,
    pub raw: [u8; 5],
}

impl RawPreambleDetection {
    /// Preferred gear carried in the capability bytes (including not-yet-negotiable gears).
    pub fn announced_gear(&self) -> Option<ModemGear> {
        ModemGear::from_wire((self.raw[1] >> 4) & 0x0F)
    }
}

fn generate_up_chirp() -> Vec<f32> {
    let mut buf = vec![0.0f32; CHIRP_SAMPLES];
    for (n, dst) in buf.iter_mut().enumerate() {
        let t = n as f32 / SAMPLE_RATE as f32;
        let phase = 2.0 * PI * (CHIRP_F0 * t + 0.5 * CHIRP_SLOPE * t * t);
        let env = if n < 80 {
            0.5 * (1.0 - (PI * n as f32 / 80.0).cos())
        } else if n >= CHIRP_SAMPLES - 80 {
            0.5 * (1.0 - (PI * (CHIRP_SAMPLES - 1 - n) as f32 / 80.0).cos())
        } else {
            1.0
        };
        *dst = phase.sin() * env;
    }
    buf
}

fn generate_down_chirp() -> Vec<f32> {
    let mut buf = vec![0.0f32; CHIRP_SAMPLES];
    for (n, dst) in buf.iter_mut().enumerate() {
        let t = n as f32 / SAMPLE_RATE as f32;
        let phase = 2.0 * PI * (CHIRP_F1 * t - 0.5 * CHIRP_SLOPE * t * t);
        let env = if n < 80 {
            0.5 * (1.0 - (PI * n as f32 / 80.0).cos())
        } else if n >= CHIRP_SAMPLES - 80 {
            0.5 * (1.0 - (PI * (CHIRP_SAMPLES - 1 - n) as f32 / 80.0).cos())
        } else {
            1.0
        };
        *dst = phase.sin() * env;
    }
    buf
}

/// Generates the 400 ms (6,400 samples @ 16 kHz) auto-discovery FormantChirp preamble
/// (or the Vowel-Glide Utterance preamble when `caps.preferred_gear == ModemGear::Speech300`).
pub fn synthesize_preamble(caps: PreambleCapabilities) -> Vec<i16> {
    if caps.preferred_gear == ModemGear::Speech300 {
        return crate::speech::synthesize_speech_preamble(caps);
    }
    let up = generate_up_chirp();
    let down = generate_down_chirp();
    let mut pcm = Vec::with_capacity(TOTAL_PREAMBLE_SAMPLES);

    for &s in &up {
        pcm.push((s * 9_000.0).round() as i16);
    }
    for &s in &down {
        pcm.push((s * 9_000.0).round() as i16);
    }

    // Encode 5-byte capability header with Rate-1/2 FEC: (40 + 6)*2 = 92 bits, padded to 96 bits (4 NB frames),
    // transmitted twice across 8 frames (160 ms) for extreme immunity to early call setup fades.
    let bytes = caps.encode_bytes();
    let mut coded = encode_short_fec(&bytes);
    coded.resize(96, 0);

    let mut demod_mod = crate::modulator::FormantModulator::new(ModemGear::Narrowband1200);
    for _repeat in 0..2 {
        for frame_idx in 0..4 {
            let chunk = &coded[frame_idx * 24..(frame_idx + 1) * 24];
            let frame_pcm = demod_mod.modulate_single_frame(chunk);
            pcm.extend_from_slice(&frame_pcm);
        }
    }
    debug_assert_eq!(pcm.len(), TOTAL_PREAMBLE_SAMPLES);
    pcm
}

/// Analytic complex envelope correlation of a linear chirp over `signal`:
/// Using complex correlation `|<s, exp(j*phase)>|` makes peak detection 100% phase-invariant!
fn find_chirp_peak(signal: &[f32], f0: f32, slope: f32, start_min: usize, start_max: usize) -> (usize, f32) {
    // Precompute complex reference chirp
    let mut ref_cos = vec![0.0f32; CHIRP_SAMPLES];
    let mut ref_sin = vec![0.0f32; CHIRP_SAMPLES];
    for n in 0..CHIRP_SAMPLES {
        let t = n as f32 / SAMPLE_RATE as f32;
        let ph = 2.0 * PI * (f0 * t + 0.5 * slope * t * t);
        let (s, c) = ph.sin_cos();
        ref_cos[n] = c;
        ref_sin[n] = s;
    }

    // Coarse step 8 samples, then fine +/-10 samples around best coarse hit -> fast even in debug mode!
    let mut best_idx = start_min;
    let mut best_norm_corr = 0.0f32;

    let eval_at = |idx: usize| -> f32 {
        if idx + CHIRP_SAMPLES > signal.len() {
            return 0.0;
        }
        let win = &signal[idx..idx + CHIRP_SAMPLES];
        let mut re = 0.0f32;
        let mut im = 0.0f32;
        let mut sig_e = 1e-9f32;
        // Decimate by 2 during coarse/fine? Wait: 16kHz / 2 = 8kHz Nyquist = 4kHz > 1900Hz, so stride-2 is exact!
        for n in (0..CHIRP_SAMPLES).step_by(2) {
            let x = win[n];
            sig_e += x * x;
            re += x * ref_cos[n];
            im += x * ref_sin[n];
        }
        let corr_sq = re * re + im * im;
        (corr_sq / (sig_e * (CHIRP_SAMPLES as f32 / 4.0))).sqrt()
    };

    let mut idx = start_min;
    while idx <= start_max {
        let score = eval_at(idx);
        if score > best_norm_corr {
            best_norm_corr = score;
            best_idx = idx;
        }
        idx += 8;
    }

    let fine_start = best_idx.saturating_sub(10).max(start_min);
    let fine_end = (best_idx + 10).min(start_max);
    for pos in fine_start..=fine_end {
        let score = eval_at(pos);
        if score > best_norm_corr {
            best_norm_corr = score;
            best_idx = pos;
        }
    }

    (best_idx, best_norm_corr)
}

/// Scans `pcm` for the FormantChirp preamble, returns exact payload alignment, CFO, and capabilities.
pub fn detect_preamble(pcm: &[i16]) -> Option<PreambleDetection> {
    let r = detect_preamble_raw(pcm)?;
    let peer_caps = PreambleCapabilities::decode_bytes(&r.raw)?;
    Some(PreambleDetection {
        payload_start_sample: r.payload_start_sample,
        estimated_cfo_hz: r.estimated_cfo_hz,
        peer_caps,
        confidence: r.confidence,
        raw: r.raw,
    })
}

/// Like `detect_preamble` but accepts any gear nibble once magic and CRC-8 are valid.
pub fn detect_preamble_raw(pcm: &[i16]) -> Option<RawPreambleDetection> {
    if let Some(det) = detect_vchirp_preamble_raw(pcm) {
        return Some(det);
    }
    crate::speech::detect_speech_preamble_raw(pcm)
}

fn detect_vchirp_preamble_raw(pcm: &[i16]) -> Option<RawPreambleDetection> {
    if pcm.len() < TOTAL_PREAMBLE_SAMPLES {
        return None;
    }
    let signal: Vec<f32> = pcm.iter().map(|&s| s as f32 / 32_768.0).collect();

    let max_up_start = signal.len().saturating_sub(TOTAL_PREAMBLE_SAMPLES);
    let (up_idx, up_score) = find_chirp_peak(&signal, CHIRP_F0, CHIRP_SLOPE, 0, max_up_start);
    if up_score < 0.30 {
        return None;
    }

    // Down-chirp nominally starts at `up_idx + CHIRP_SAMPLES`. With up to +/-60Hz CFO,
    // `|Δt| = 60 / (1300 / 0.12) * 16000 ≈ 90 samples`, so search +/-220 samples around expected offset.
    let nominal_down = up_idx + CHIRP_SAMPLES;
    let down_min = nominal_down.saturating_sub(220);
    let down_max = (nominal_down + 220).min(signal.len().saturating_sub(CHIRP_SAMPLES));
    if down_min > down_max {
        return None;
    }
    let (down_idx, down_score) = find_chirp_peak(&signal, CHIRP_F1, -CHIRP_SLOPE, down_min, down_max);
    if down_score < 0.30 {
        return None;
    }

    // True timing midpoint & direct CFO extraction from opposing chirp peak shifts!
    let true_down_nominal = (up_idx + down_idx + CHIRP_SAMPLES) / 2;
    let delta_samples = (down_idx as f32) - (up_idx as f32 + CHIRP_SAMPLES as f32);
    // Note: up-chirp shifted by -df/S, down-chirp shifted by +df/S => down_idx - (up_idx + L) = +2*df/S * Fs
    let estimated_cfo_hz = (delta_samples / (2.0 * SAMPLE_RATE as f32) * CHIRP_SLOPE).clamp(-60.0, 60.0);

    let trailer_start = true_down_nominal + CHIRP_SAMPLES;
    let trailer_end = trailer_start + TRAILER_FRAMES * FRAME_SAMPLES;
    if trailer_end > pcm.len() + 16 {
        return None;
    }
    let payload_start_sample = trailer_end.min(pcm.len());

    // Demodulate the two repeated 4-frame NB capability blocks & soft-combine their LLRs
    let mut demod = FormantDemodulator::new(ModemGear::Narrowband1200, estimated_cfo_hz);
    let mut combined_llr = [0.0f32; 96];
    for rep in 0..2 {
        for f in 0..4 {
            let s = trailer_start + (rep * 4 + f) * FRAME_SAMPLES;
            if s + FRAME_SAMPLES > pcm.len() {
                break;
            }
            let frame_llr = demod.demodulate_single_frame(&pcm[s..s + FRAME_SAMPLES]);
            for k in 0..24 {
                combined_llr[f * 24 + k] += frame_llr[k];
            }
        }
    }

    // Decode 46-bit (40 payload + 6 tail) short K=7 Viterbi
    let decoded_bytes = decode_short_viterbi_5(&combined_llr[..92]);
    if decoded_bytes[0] != PREAMBLE_MAGIC || crc8_atm(&decoded_bytes[..4]) != decoded_bytes[4] {
        return None;
    }

    // Suppress unused helper warnings when compiling all targets
    let _ = (subband_start_bin, BIN_HZ, CODEBOOK_3_OF_6, DFT_WINDOW_SAMPLES, GUARD_EDGE_SAMPLES, dft_energy_at_freq);

    Some(RawPreambleDetection {
        payload_start_sample,
        estimated_cfo_hz,
        confidence: 0.5 * (up_score + down_score),
        raw: decoded_bytes,
    })
}

fn decode_short_viterbi_5(llr: &[f32]) -> [u8; 5] {
    const POLY0: u8 = 0b1111001;
    const POLY1: u8 = 0b1011011;
    const STEPS: usize = 46; // 40 data + 6 tail
    let mut metrics = [f32::NEG_INFINITY; 64];
    metrics[0] = 0.0;
    let mut prev_state = [[0u8; 64]; STEPS];
    let mut prev_bit = [[0u8; 64]; STEPS];

    for step in 0..STEPS {
        let l0 = llr[2 * step];
        let l1 = llr[2 * step + 1];
        let mut next = [f32::NEG_INFINITY; 64];
        let max_in = if step >= 40 { 0 } else { 1 };
        for s in 0..64 {
            let m = metrics[s];
            if !m.is_finite() {
                continue;
            }
            for in_bit in 0..=max_in {
                let reg = ((in_bit as u8) << 6) | (s as u8);
                let o0 = ((reg & POLY0).count_ones() & 1) as u8;
                let o1 = ((reg & POLY1).count_ones() & 1) as u8;
                let ns = (reg >> 1) as usize;
                let cand = m + (if o0 == 1 { l0 } else { -l0 }) + (if o1 == 1 { l1 } else { -l1 });
                if cand > next[ns] {
                    next[ns] = cand;
                    prev_state[step][ns] = s as u8;
                    prev_bit[step][ns] = in_bit as u8;
                }
            }
        }
        metrics = next;
    }

    let mut cur = 0usize;
    let mut bits = [0u8; STEPS];
    for step in (0..STEPS).rev() {
        bits[step] = prev_bit[step][cur];
        cur = prev_state[step][cur] as usize;
    }

    let mut out = [0u8; 5];
    for byte_idx in 0..5 {
        let mut b = 0u8;
        for bit in 0..8 {
            b = (b << 1) | (bits[byte_idx * 8 + bit] & 1);
        }
        out[byte_idx] = b;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preamble_detects_under_leading_offset_and_cfo() {
        let caps = PreambleCapabilities::v2(ModemGear::Wideband2400);
        let preamble = synthesize_preamble(caps);

        // Prepend 743 silent samples + inject +27.5 Hz CFO using channel simulator
        let mut signal = vec![0i16; 743];
        signal.extend_from_slice(&preamble);
        signal.extend(vec![0i16; 640]);

        let impaired = crate::channel_sim::apply_channel_impairments(
            &signal,
            &crate::channel_sim::ChannelProfile {
                wideband: true,
                cfo_hz: 27.5,
                noise_std: 0.015,
                frame_drop_prob: 0.0,
                mu_law_quantization: true,
                seed: 42,
            },
        );

        let det = detect_preamble(&impaired).expect("must detect preamble");
        assert!((det.payload_start_sample as isize - (743 + TOTAL_PREAMBLE_SAMPLES) as isize).abs() <= 4);
        assert!((det.estimated_cfo_hz - 27.5).abs() < 4.5);
        assert_eq!(det.peer_caps, caps);
        assert_eq!(det.raw, caps.encode_bytes());
    }

    #[test]
    fn v2_capabilities_roundtrip_and_reject_old_or_edition_flagged_peers() {
        let caps = PreambleCapabilities::v2(ModemGear::Narrowband1200);
        assert_eq!(caps.version, 2);
        assert_eq!(caps.edition_flags & CAP_RESERVED_EDITION_MASK, 0);
        assert!(caps.is_v2_compatible());
        let raw = caps.encode_bytes();
        assert_eq!(PreambleCapabilities::decode_bytes(&raw), Some(caps));

        let mut pcm = vec![0i16; 300];
        pcm.extend_from_slice(&synthesize_preamble(caps));
        pcm.extend(vec![0i16; 320]);
        let det = detect_preamble(&pcm).expect("clean v2 preamble must be detected");
        assert_eq!(det.raw, raw);
        assert!(det.peer_caps.is_v2_compatible());

        let v1 = PreambleCapabilities { version: 1, ..caps };
        assert!(!v1.is_v2_compatible());
        let no_suite = PreambleCapabilities { edition_flags: CAP_CHAT_ARQ_V1, ..caps };
        assert!(!no_suite.is_v2_compatible());
        let edition = PreambleCapabilities { edition_flags: CAP_SUITE_V2 | (1 << 1), ..caps };
        assert!(!edition.is_v2_compatible());
    }
}
