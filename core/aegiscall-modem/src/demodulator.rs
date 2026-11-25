//! FormantGuard Soft-LLR Demodulator with Continuous Pilot AFC, Burst Erasure Detection and
//! decision-directed channel compensation.
//!
//! Compensation (on by default, see `set_compensation`):
//! - Per-bin equalization: the share of sub-band energy each tone carries when it is decided "on"
//!   is tracked per bin; once every tone of a band has been observed, energies are divided by that
//!   learned shape before the codeword decision (undoes frequency-response tilt inside a band).
//! - Per-band reliability: the share of (equalized) band energy captured by the decided codeword
//!   is tracked per band and scales that band's LLRs, so bands the channel mangles (high
//!   frequencies on codec paths) weigh less in the Viterbi decoder than clean bands.
//! - Gain swings (AGC, noise suppression): every decision and both trackers work on energies
//!   normalized within the sub-band of the current frame, so slow or sudden level changes do not
//!   move them; the learned shape only follows the spectral tilt.
//! Both trackers start neutral (flat shape, full reliability), so the first frames are demodulated
//! exactly as without compensation.

use crate::modulator::{
    subband_start_bin, ModemGear, BIN_HZ, DFT_WINDOW_SAMPLES, FRAME_SAMPLES, GUARD_EDGE_SAMPLES,
    PILOT_FREQ_HZ, SAMPLE_RATE,
};
use std::f32::consts::PI;

const MAX_BANDS: usize = 12;
const MAX_TONES: usize = 7;
/// Adaptation rate of the per-bin channel shape (decision-directed, ~0.6 s memory per tone).
const EQ_ALPHA: f32 = 1.0 / 32.0;
/// Observations every tone of a band needs before that band is equalized.
const EQ_MIN_OBS: u32 = 8;
/// Adaptation rate of the per-band reliability estimate.
const REL_ALPHA: f32 = 1.0 / 16.0;
/// Lowest LLR weight a band can get (it never drops out of the decoder completely).
const REL_FLOOR: f32 = 0.05;
/// Maximum tracked sample-clock skew magnitude in parts per million.
pub const MAX_CLOCK_SKEW_PPM: f32 = 1_000.0;

#[inline]
fn clamped_sample(samples: &[i16], idx: isize) -> f32 {
    if samples.is_empty() {
        return 0.0;
    }
    let clamped = idx.clamp(0, samples.len() as isize - 1) as usize;
    samples[clamped] as f32
}

/// Evaluates a 4-tap cubic Catmull-Rom Farrow fractional-delay interpolator at `pos` (in samples).
/// Exact at integer sample positions (`mu == 0.0`), preventing rounding drift on zero-skew streams.
#[inline]
pub fn farrow_cubic_sample(samples: &[i16], pos: f64) -> f32 {
    if samples.is_empty() || !pos.is_finite() {
        return 0.0;
    }
    let i = pos.floor() as isize;
    let mu = (pos - i as f64) as f32;
    if mu.abs() < 1e-7 {
        return clamped_sample(samples, i);
    }
    let ym1 = clamped_sample(samples, i - 1);
    let y0 = clamped_sample(samples, i);
    let y1 = clamped_sample(samples, i + 1);
    let y2 = clamped_sample(samples, i + 2);

    let c0 = y0;
    let c1 = 0.5 * (y1 - ym1);
    let c2 = ym1 - 2.5 * y0 + 2.0 * y1 - 0.5 * y2;
    let c3 = 0.5 * (y2 - ym1) + 1.5 * (y0 - y1);
    ((c3 * mu + c2) * mu + c1) * mu + c0
}

/// Resamples `out_len` PCM samples starting at fractional index `start_pos` with sample stride `step`
/// (`step = 1.0 - skew_rx`, i.e. received samples per nominal transmitter sample).
pub fn resample_farrow_i16(pcm: &[i16], start_pos: f64, step: f64, out_len: usize) -> Vec<i16> {
    let mut out = vec![0i16; out_len];
    if pcm.is_empty() || !start_pos.is_finite() || !step.is_finite() || step <= 0.0 {
        return out;
    }
    if (start_pos.fract()).abs() < 1e-7 && (step - 1.0).abs() < 1e-9 && start_pos >= 0.0 {
        let s = start_pos.round() as usize;
        if s < pcm.len() {
            let n = (pcm.len() - s).min(out_len);
            out[..n].copy_from_slice(&pcm[s..s + n]);
            return out;
        }
    }
    for (k, dst) in out.iter_mut().enumerate() {
        let pos = start_pos + (k as f64) * step;
        *dst = farrow_cubic_sample(pcm, pos).round().clamp(-32_768.0, 32_767.0) as i16;
    }
    out
}

/// Guard-edge early/late envelope Timing Error Detector (TED) for Hann-tapered 320-sample frames.
/// Returns a normalized timing error in `[-1.0, 1.0]`: positive when the sampling window is early
/// (behind the true frame center, so cursor should advance), negative when late.
fn guard_edge_timing_error(frame: &[i16]) -> Option<f32> {
    if frame.len() < FRAME_SAMPLES {
        return None;
    }
    let mut e_lead = 0.0f32;
    let mut e_trail = 0.0f32;
    let mut e_core = 0.0f32;
    for i in 4..(GUARD_EDGE_SAMPLES - 4) {
        let sl = frame[i] as f32 / 32_768.0;
        let st = frame[FRAME_SAMPLES - 1 - i] as f32 / 32_768.0;
        e_lead += sl * sl;
        e_trail += st * st;
    }
    for i in GUARD_EDGE_SAMPLES..(FRAME_SAMPLES - GUARD_EDGE_SAMPLES) {
        let sc = frame[i] as f32 / 32_768.0;
        e_core += sc * sc;
    }
    if e_core < 1e-4 {
        return None;
    }
    let norm_core = e_core * ((GUARD_EDGE_SAMPLES - 8) as f32 / DFT_WINDOW_SAMPLES as f32);
    let denom = e_trail + e_lead + 0.35 * norm_core;
    if denom <= 1e-9 {
        return None;
    }
    Some(((e_trail - e_lead) / denom).clamp(-1.0, 1.0))
}

/// Computes exact DFT magnitude-squared energy at an arbitrary floating-point frequency `freq_hz`
/// over the inner 256-sample Hann-tapered core of a 320-sample frame.
#[inline]
pub fn dft_energy_at_freq(core_samples: &[f32; DFT_WINDOW_SAMPLES], freq_hz: f32) -> f32 {
    let omega = 2.0 * PI * freq_hz / SAMPLE_RATE as f32;
    let mut re = 0.0f32;
    let mut im = 0.0f32;
    for (n, &x) in core_samples.iter().enumerate() {
        let angle = omega * n as f32;
        let (s, c) = angle.sin_cos();
        re += x * c;
        im -= x * s;
    }
    re * re + im * im
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DemodLinkMetrics {
    pub gear: ModemGear,
    pub estimated_cfo_hz: f32,
    pub estimated_clock_skew_ppm: f32,
    pub avg_llr_confidence: f32,
    pub erased_frames_count: u32,
    pub total_frames_count: u32,
}

impl DemodLinkMetrics {
    /// Returns a 0..=100 normalized link quality percentage based on soft LLR confidence and erasure rate.
    pub fn quality_score(&self) -> u8 {
        if self.total_frames_count == 0 {
            return 100;
        }
        let erasure_rate = self.erased_frames_count as f32 / self.total_frames_count as f32;
        let conf_part = (self.avg_llr_confidence / 4.5).clamp(0.0, 1.0);
        let survival_part = (1.0 - erasure_rate * 2.0).clamp(0.0, 1.0);
        ((conf_part * 0.65 + survival_part * 0.35) * 100.0)
            .round()
            .clamp(0.0, 100.0) as u8
    }

    /// Recommends automatically shifting down from Wideband2400 to Narrowband1200 when
    /// cellular codecs drop >20% of frames or link quality degrades below 35%.
    pub fn recommend_narrowband_fallback(&self) -> bool {
        if self.gear != ModemGear::Wideband2400 || self.total_frames_count < 8 {
            return false;
        }
        let erasure_rate = self.erased_frames_count as f32 / self.total_frames_count as f32;
        erasure_rate > 0.20 || self.quality_score() < 35
    }
}

pub struct FormantDemodulator {
    gear: ModemGear,
    cfo_hz: f32,
    clock_skew_ppm: f32,
    timing_offset_samples: f32,
    avg_pilot_energy: f32,
    avg_llr_confidence: f32,
    erased_frames_count: u32,
    total_frames_count: u32,
    speech_frame_idx: u32,
    speech_frame_offset: i32,
    speech_offset_ema: [f32; 9],
    compensate: bool,
    /// Mean within-band energy share of each tone when decided on (learned channel shape).
    on_level: [[f32; MAX_TONES]; MAX_BANDS],
    on_obs: [[u32; MAX_TONES]; MAX_BANDS],
    /// Mean share of equalized band energy captured by the decided codeword.
    capture: [f32; MAX_BANDS],
}

impl FormantDemodulator {
    pub fn new(gear: ModemGear, initial_cfo_hz: f32) -> Self {
        Self {
            gear,
            cfo_hz: initial_cfo_hz.clamp(-55.0, 55.0),
            clock_skew_ppm: 0.0,
            timing_offset_samples: 0.0,
            avg_pilot_energy: 0.0,
            avg_llr_confidence: 4.0,
            erased_frames_count: 0,
            total_frames_count: 0,
            speech_frame_idx: 0,
            speech_frame_offset: 0,
            speech_offset_ema: [0.0; 9],
            compensate: true,
            on_level: [[0.0; MAX_TONES]; MAX_BANDS],
            on_obs: [[0; MAX_TONES]; MAX_BANDS],
            capture: [1.0; MAX_BANDS],
        }
    }

    /// Sets the sample-clock skew estimate in ppm (positive = sender clock runs faster than receiver).
    pub fn set_clock_skew_ppm(&mut self, ppm: f32) {
        if ppm.is_finite() {
            self.clock_skew_ppm = ppm.clamp(-MAX_CLOCK_SKEW_PPM, MAX_CLOCK_SKEW_PPM);
        }
    }

    pub fn clock_skew_ppm(&self) -> f32 {
        self.clock_skew_ppm
    }

    pub fn timing_offset_samples(&self) -> f32 {
        self.timing_offset_samples
    }

    pub fn reset_timing(&mut self) {
        self.timing_offset_samples = 0.0;
    }

    /// Enables or disables channel compensation (enabled by default).
    pub fn set_compensation(&mut self, on: bool) {
        self.compensate = on;
    }

    /// Current LLR weight of every sub-band (1.0 = fully trusted).
    pub fn band_reliability(&self) -> Vec<f32> {
        (0..self.gear.subband_count()).map(|b| self.band_weight(b)).collect()
    }

    /// Learned per-tone gain inside sub-band `band` relative to the band mean (1.0 = flat), or
    /// None while some tone of the band has not been observed often enough.
    pub fn band_equalizer(&self, band: usize) -> Option<[f32; MAX_TONES]> {
        let offsets = self.gear.candidate_offsets();
        if band >= self.gear.subband_count()
            || offsets.iter().any(|&t| self.on_obs[band][t as usize] < EQ_MIN_OBS)
        {
            return None;
        }
        let mean = offsets.iter().map(|&t| self.on_level[band][t as usize]).sum::<f32>() / offsets.len() as f32;
        if mean <= 0.0 {
            return None;
        }
        let mut g = [1.0f32; MAX_TONES];
        for &t in offsets {
            g[t as usize] = (self.on_level[band][t as usize] / mean).clamp(0.25, 4.0);
        }
        Some(g)
    }

    fn band_weight(&self, band: usize) -> f32 {
        if !self.compensate {
            return 1.0;
        }
        let chance = self.gear.codeword(0).len() as f32 / self.gear.candidate_offsets().len() as f32;
        ((self.capture[band] - chance) / (1.0 - chance)).clamp(REL_FLOOR, 1.0).powi(2)
    }

    pub fn cfo_hz(&self) -> f32 {
        self.cfo_hz
    }

    pub fn metrics(&self) -> DemodLinkMetrics {
        DemodLinkMetrics {
            gear: self.gear,
            estimated_cfo_hz: self.cfo_hz,
            estimated_clock_skew_ppm: self.clock_skew_ppm,
            avg_llr_confidence: self.avg_llr_confidence,
            erased_frames_count: self.erased_frames_count,
            total_frames_count: self.total_frames_count,
        }
    }

    /// Estimates residual CFO on a frame using a parabolic peak search around `PILOT_FREQ_HZ * pitch_scale + self.cfo_hz`.
    fn track_pilot_cfo(&mut self, core: &[f32; DFT_WINDOW_SAMPLES], pitch_scale: f32) -> f32 {
        let base_f = PILOT_FREQ_HZ * pitch_scale + self.cfo_hz;
        let step = 12.0f32;
        let e_minus = dft_energy_at_freq(core, base_f - step);
        let e_zero = dft_energy_at_freq(core, base_f);
        let e_plus = dft_energy_at_freq(core, base_f + step);

        let total = e_minus + e_zero + e_plus;
        if self.avg_pilot_energy == 0.0 {
            self.avg_pilot_energy = total;
        } else if total > self.avg_pilot_energy * 0.25 {
            self.avg_pilot_energy = 0.85 * self.avg_pilot_energy + 0.15 * total;
        }

        // Parabolic peak interpolation if pilot is strong enough
        let denom = e_minus - 2.0 * e_zero + e_plus;
        if denom < -1e-6 && total > self.avg_pilot_energy * 0.2 {
            let delta_bins = 0.5 * (e_minus - e_plus) / denom;
            let delta_hz = (delta_bins * step).clamp(-10.0, 10.0);
            self.cfo_hz = (self.cfo_hz + 0.25 * delta_hz).clamp(-55.0, 55.0);
        }
        total
    }

    /// Demodulates one 20ms frame (`320` samples) into `24` (NB), `48` (WB) or `6` (Robust/Speech) soft LLRs.
    /// Convention: `llr > 0` favors bit `1`, `llr < 0` favors bit `0`, `0.0` signals erasure.
    pub fn demodulate_single_frame(&mut self, frame: &[i16]) -> Vec<f32> {
        let bands = self.gear.subband_count();
        let bpb = self.gear.bits_per_band();
        let mut llrs = vec![0.0f32; bands * bpb];
        if frame.len() < FRAME_SAMPLES {
            return llrs;
        }

        let speech_idx = self.speech_frame_idx as usize;
        self.speech_frame_idx = self.speech_frame_idx.wrapping_add(1);

        let mut core = [0.0f32; DFT_WINDOW_SAMPLES];
        let mut frame_energy = 0.0f32;
        for i in 0..DFT_WINDOW_SAMPLES {
            let s = frame[GUARD_EDGE_SAMPLES + i] as f32 / 32_768.0;
            core[i] = s;
            frame_energy += s * s;
        }

        self.total_frames_count = self.total_frames_count.saturating_add(1);

        // Burst erasure / DTX drop detector: blank frames produce zero LLRs so Viterbi ignores them
        if frame_energy < 1e-6 {
            self.erased_frames_count = self.erased_frames_count.saturating_add(1);
            return llrs;
        }

        let pitch_scale = if self.gear == ModemGear::Speech300 {
            crate::speech::track_speech_pitch_scale(
                &core,
                self.cfo_hz,
                speech_idx,
                &mut self.speech_frame_offset,
                &mut self.speech_offset_ema,
            )
        } else {
            1.0
        };

        let pilot_energy = self.track_pilot_cfo(&core, pitch_scale);
        if self.avg_pilot_energy > 1e-4 && pilot_energy < self.avg_pilot_energy * 0.06 && frame_energy < 0.0005 {
            self.erased_frames_count = self.erased_frames_count.saturating_add(1);
            return llrs;
        }

        let offsets = self.gear.candidate_offsets();
        let nsym = self.gear.symbols_per_band();
        let mut abs_sum = 0.0f32;
        for b in 0..bands {
            let base_bin = subband_start_bin(self.gear, b);

            let mut bin_e = [0.0f32; MAX_TONES];
            let mut band_sum = 1e-9f32;
            for &t in offsets {
                let t = t as usize;
                let freq = (base_bin + t) as f32 * BIN_HZ * pitch_scale + self.cfo_hz;
                let e = dft_energy_at_freq(&core, freq);
                bin_e[t] = e;
                band_sum += e;
            }

            // Normalize energy within each subband for total immunity to AGC gain swings
            for &t in offsets {
                bin_e[t as usize] /= band_sum;
            }

            // Undo the learned in-band channel shape, then renormalize.
            let mut eq_e = bin_e;
            if self.compensate {
                if let Some(g) = self.band_equalizer(b) {
                    let mut s = 1e-9f32;
                    for &t in offsets {
                        eq_e[t as usize] = bin_e[t as usize] / g[t as usize];
                        s += eq_e[t as usize];
                    }
                    for &t in offsets {
                        eq_e[t as usize] /= s;
                    }
                }
            }

            let mut sym_scores = [0.0f32; 16];
            for (sym, score) in sym_scores.iter_mut().enumerate().take(nsym) {
                *score = self.gear.codeword(sym).iter().map(|&t| eq_e[t as usize]).sum();
            }

            // Max-Log-MAP bit LLR extraction for all bits of this subband
            let weight = self.band_weight(b);
            for bit_pos in 0..bpb {
                let shift = bpb - 1 - bit_pos;
                let mut max_one = f32::NEG_INFINITY;
                let mut max_zero = f32::NEG_INFINITY;
                for (sym, &score) in sym_scores.iter().enumerate().take(nsym) {
                    if ((sym >> shift) & 1) == 1 {
                        if score > max_one {
                            max_one = score;
                        }
                    } else if score > max_zero {
                        max_zero = score;
                    }
                }
                // Scale to comfortable Viterbi dynamic range [-8.0, +8.0]
                let raw_llr = ((max_one - max_zero) * 10.0).clamp(-8.0, 8.0);
                abs_sum += raw_llr.abs();
                llrs[b * bpb + bit_pos] = if weight == 1.0 { raw_llr } else { raw_llr * weight };
            }

            if self.compensate {
                let mut dec = 0usize;
                for sym in 1..nsym {
                    if sym_scores[sym] > sym_scores[dec] {
                        dec = sym;
                    }
                }
                self.capture[b] += REL_ALPHA * (sym_scores[dec] - self.capture[b]);
                for &t in self.gear.codeword(dec) {
                    let t = t as usize;
                    let obs = self.on_obs[b][t].saturating_add(1);
                    self.on_obs[b][t] = obs;
                    let a = EQ_ALPHA.max(1.0 / obs as f32);
                    self.on_level[b][t] += a * (bin_e[t] - self.on_level[b][t]);
                }
            }
        }

        // Link-quality telemetry uses the unweighted LLRs so it keeps its meaning.
        let mean_abs = abs_sum / (llrs.len().max(1) as f32);
        self.avg_llr_confidence = 0.85 * self.avg_llr_confidence + 0.15 * mean_abs;

        llrs
    }

    /// Demodulates a full superframe (`8` WB, `16` NB or `64` Robust/Speech frames) into 384 raw channel LLRs.
    pub fn demodulate_superframe(&mut self, pcm: &[i16]) -> [f32; 384] {
        let frames = self.gear.frames_per_superframe();
        let bpf = self.gear.bits_per_frame();
        let sf_samples = frames * FRAME_SAMPLES;
        let resampled_buf;
        let src: &[i16] = if self.clock_skew_ppm.abs() > 1e-3 || self.timing_offset_samples.abs() > 1e-3 {
            let step = 1.0 / (1.0 + (self.clock_skew_ppm as f64) * 1e-6);
            resampled_buf = resample_farrow_i16(pcm, self.timing_offset_samples as f64, step, sf_samples);
            &resampled_buf
        } else {
            pcm
        };
        let mut out = [0.0f32; 384];
        self.speech_frame_idx = 0;
        for f in 0..frames {
            self.speech_frame_idx = f as u32;
            let start = f * FRAME_SAMPLES;
            if start + FRAME_SAMPLES > src.len() {
                break;
            }
            let frame_llrs = self.demodulate_single_frame(&src[start..start + FRAME_SAMPLES]);
            out[f * bpf..(f + 1) * bpf].copy_from_slice(&frame_llrs);
        }
        out
    }

    /// Demodulates one contiguous superframe from a streaming PCM buffer at fractional sample `cursor`,
    /// running a 2nd-order guard-edge Delay-Locked Loop (DLL) + cubic Farrow resampler to track
    /// continuous sample-clock drift (+/-300 ppm) across arbitrarily long calls without preamble resync.
    pub fn demodulate_stream(&mut self, pcm: &[i16], cursor: &mut f64) -> Option<[f32; 384]> {
        if !cursor.is_finite() || *cursor < 0.0 {
            return None;
        }
        let frames = self.gear.frames_per_superframe();
        let bpf = self.gear.bits_per_frame();
        let step = 1.0 / (1.0 + (self.clock_skew_ppm as f64) * 1e-6);
        let needed_end = *cursor + (frames * FRAME_SAMPLES) as f64 * step + 2.0;
        if needed_end.ceil() as usize > pcm.len() {
            return None;
        }

        let mut out = [0.0f32; 384];
        let mut ted_sum = 0.0f32;
        let mut ted_obs = 0u32;
        self.speech_frame_idx = 0;

        for f in 0..frames {
            self.speech_frame_idx = f as u32;
            let cur_step = 1.0 / (1.0 + (self.clock_skew_ppm as f64) * 1e-6);
            let frame_pcm = resample_farrow_i16(pcm, *cursor, cur_step, FRAME_SAMPLES);
            if self.gear != ModemGear::Speech300 {
                if let Some(err) = guard_edge_timing_error(&frame_pcm) {
                    ted_sum += err;
                    ted_obs += 1;
                }
            }
            let frame_llrs = self.demodulate_single_frame(&frame_pcm);
            out[f * bpf..(f + 1) * bpf].copy_from_slice(&frame_llrs);
            *cursor += (FRAME_SAMPLES as f64) * cur_step;
        }

        if ted_obs >= 4 {
            let mean_err = ted_sum / ted_obs as f32;
            // Positive mean_err => window was early => advance cursor (+), meaning RX had MORE samples
            // per TX frame than expected => sender clock is SLOWER (skew_ppm decreases).
            let phase_nudge = (mean_err * 6.5).clamp(-4.0, 4.0);
            *cursor = (*cursor + phase_nudge as f64).max(0.0);
            self.timing_offset_samples = phase_nudge;
            let freq_nudge_ppm = -mean_err * 38.0;
            self.clock_skew_ppm =
                (self.clock_skew_ppm + freq_nudge_ppm).clamp(-MAX_CLOCK_SKEW_PPM, MAX_CLOCK_SKEW_PPM);
        }
        Some(out)
    }
}
