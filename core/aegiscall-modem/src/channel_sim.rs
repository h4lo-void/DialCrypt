//! Realistic Cellular Voice Channel Impairment Simulator for Automated Verification.
//!
//! Models GSM / AMR-NB / VoLTE AMR-WB impairments:
//! - Telephone bandpass rolloff (300..3300 Hz NB or 150..6600 Hz WB)
//! - Non-linear G.711 mu-law quantization & soft-saturation (CELP envelope compression proxy)
//! - Carrier/crystal frequency offset (+/- Hz via quadrature analytic shift)
//! - Additive White Gaussian Noise (AWGN)
//! - Burst 20ms packet/frame drops (simulating VoLTE RTP packet loss)
//!
//! `apply_codec_channel` adds a codec-path model (VoWiFi/VoLTE CELP coding, noise suppression)
//! built from a measured call; see `CodecChannelProfile`.

use crate::modulator::{FRAME_SAMPLES, SAMPLE_RATE};
use std::f32::consts::PI;

#[derive(Debug, Clone, Copy)]
pub struct ChannelProfile {
    pub wideband: bool,
    pub cfo_hz: f32,
    pub noise_std: f32,
    pub frame_drop_prob: f32,
    pub mu_law_quantization: bool,
    pub seed: u64,
}

impl ChannelProfile {
    pub fn volte_harsh() -> Self {
        Self {
            wideband: true,
            cfo_hz: 28.0,
            noise_std: 0.020,
            frame_drop_prob: 0.08, // 8% burst packet loss!
            mu_law_quantization: true,
            seed: 0xAE61_5C47_2026_0001,
        }
    }

    pub fn gsm_legacy_harsh() -> Self {
        Self {
            wideband: false,
            cfo_hz: -22.0,
            noise_std: 0.025,
            frame_drop_prob: 0.06,
            mu_law_quantization: true,
            seed: 0xAE61_5C47_2026_0002,
        }
    }
}

struct XorShift64(u64);
impl XorShift64 {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn next_f32(&mut self) -> f32 {
        (self.next_u64() >> 40) as f32 / (1u64 << 24) as f32
    }
    fn next_normal(&mut self) -> f32 {
        let u1 = self.next_f32().clamp(1e-6, 1.0 - 1e-6);
        let u2 = self.next_f32();
        (-2.0 * u1.ln()).sqrt() * (2.0 * PI * u2).cos()
    }
}

/// First-order highpass + second-order Butterworth-like lowpass for telecom voice passband.
fn apply_bandpass(samples: &[f32], wideband: bool) -> Vec<f32> {
    let hp_fc = if wideband { 120.0f32 } else { 280.0f32 };
    let lp_fc = if wideband { 6550.0f32 } else { 3250.0f32 };

    // 1st-order HPF
    let rc_hp = 1.0 / (2.0 * PI * hp_fc);
    let dt = 1.0 / SAMPLE_RATE as f32;
    let alpha_hp = rc_hp / (rc_hp + dt);
    let mut hp_out = vec![0.0f32; samples.len()];
    let mut prev_x = 0.0f32;
    let mut prev_y = 0.0f32;
    for (i, &x) in samples.iter().enumerate() {
        let y = alpha_hp * (prev_y + x - prev_x);
        hp_out[i] = y;
        prev_x = x;
        prev_y = y;
    }

    // 2nd-order Biquad LPF
    let k = (PI * lp_fc / SAMPLE_RATE as f32).tan();
    let q = 0.7071f32;
    let norm = 1.0 / (1.0 + k / q + k * k);
    let b0 = k * k * norm;
    let b1 = 2.0 * b0;
    let b2 = b0;
    let a1 = 2.0 * (k * k - 1.0) * norm;
    let a2 = (1.0 - k / q + k * k) * norm;

    let mut out = vec![0.0f32; hp_out.len()];
    let (mut x1, mut x2, mut y1, mut y2) = (0.0, 0.0, 0.0, 0.0);
    for (i, &x0) in hp_out.iter().enumerate() {
        let y0 = b0 * x0 + b1 * x1 + b2 * x2 - a1 * y1 - a2 * y2;
        out[i] = y0;
        x2 = x1;
        x1 = x0;
        y2 = y1;
        y1 = y0;
    }
    out
}

/// Applies true single-sideband frequency shift `cfo_hz` via FIR Hilbert transform (taps = 63).
fn apply_frequency_shift(samples: &[f32], cfo_hz: f32) -> Vec<f32> {
    if cfo_hz.abs() < 0.01 {
        return samples.to_vec();
    }
    const HALF: usize = 31;
    let mut h = [0.0f32; 2 * HALF + 1];
    for k in -(HALF as isize)..=(HALF as isize) {
        if k != 0 && (k & 1) != 0 {
            let win = 0.54 + 0.46 * (PI * k as f32 / HALF as f32).cos();
            h[(k + HALF as isize) as usize] = (2.0 / (PI * k as f32)) * win;
        }
    }

    let mut out = vec![0.0f32; samples.len()];
    for n in 0..samples.len() {
        let re = samples[n];
        let mut im = 0.0f32;
        for (idx, &tap) in h.iter().enumerate() {
            if tap != 0.0 {
                let src = n as isize + (idx as isize - HALF as isize);
                if src >= 0 && (src as usize) < samples.len() {
                    im += samples[src as usize] * tap;
                }
            }
        }
        let ph = 2.0 * PI * cfo_hz * (n as f32 / SAMPLE_RATE as f32);
        let (s, c) = ph.sin_cos();
        // Real part of (re + j*im) * e^{j*ph}
        out[n] = re * c + im * s;
    }
    out
}

fn mu_law_roundtrip(x: f32) -> f32 {
    let mu = 255.0f32;
    let xc = x.clamp(-1.0, 1.0);
    let sign = xc.signum();
    let mag = (1.0 + mu * xc.abs()).ln() / (1.0 + mu).ln();
    // 8-bit quantization (127 magnitude levels) + soft tanh harmonic mimic
    let q = (mag * 127.0).round() / 127.0;
    let recon = sign * (((1.0 + mu).powf(q) - 1.0) / mu);
    (recon * 1.15).tanh() / 1.15
}

/// Runs `pcm` through the full telecom voice channel impairment simulator.
pub fn apply_channel_impairments(pcm: &[i16], profile: &ChannelProfile) -> Vec<i16> {
    let mut rng = XorShift64(profile.seed ^ 0x9E37_79B9_7F4A_7C15);
    let floats: Vec<f32> = pcm.iter().map(|&s| s as f32 / 32_768.0).collect();

    let filtered = apply_bandpass(&floats, profile.wideband);
    let shifted = apply_frequency_shift(&filtered, profile.cfo_hz);

    let mut impaired = Vec::with_capacity(shifted.len());
    let num_frames = (shifted.len() + FRAME_SAMPLES - 1) / FRAME_SAMPLES;

    for f in 0..num_frames {
        let start = f * FRAME_SAMPLES;
        let end = (start + FRAME_SAMPLES).min(shifted.len());
        let drop_frame = rng.next_f32() < profile.frame_drop_prob;

        for &sample in &shifted[start..end] {
            let base = if drop_frame { 0.0 } else { sample };
            let nonlin = if profile.mu_law_quantization && !drop_frame {
                mu_law_roundtrip(base)
            } else {
                base
            };
            let noisy = (nonlin + rng.next_normal() * profile.noise_std).clamp(-0.99, 0.99);
            impaired.push((noisy * 32_767.0).round() as i16);
        }
    }

    impaired
}

/// Codec-path voice channel (VoWiFi / VoLTE with CELP coding and noise suppression), parameterized
/// from a measured call (Google Voice web -> Pixel 9 over Wi-Fi calling). Effects, all in a 16 ms
/// STFT domain:
/// - frequency response: slope around a pivot plus low/high-pass corners;
/// - partial budget: the codec reproduces only the strongest spectral peaks of each analysis
///   frame, weaker peaks are attenuated (simultaneous tones drop out, high ones first);
/// - random loss of any peak for a whole 20 ms codec frame;
/// - coding noise that follows the local spectral envelope (fills the gaps between tones);
/// - slow gain wander (AGC / noise suppression) and a broadband noise floor.
#[derive(Debug, Clone, Copy)]
pub struct CodecChannelProfile {
    /// Response slope in dB per octave around `tilt_pivot_hz` (negative = treble loss).
    pub tilt_db_per_octave: f32,
    pub tilt_pivot_hz: f32,
    /// 4th-order low-pass corner.
    pub lowpass_hz: f32,
    /// 2nd-order high-pass corner.
    pub highpass_hz: f32,
    /// Spectral peaks kept per analysis frame; weaker ones are attenuated by `partial_drop_db`.
    pub max_partials: usize,
    pub partial_drop_db: f32,
    /// Probability that a peak is lost for one 20 ms codec frame regardless of the budget.
    pub partial_fade_prob: f32,
    /// Coding noise this many dB below the local spectral envelope (+/-3 bins average).
    pub fill_snr_db: f32,
    /// Slow gain wander: standard deviation (dB) and correlation time (s) of an AR(1) process.
    pub gain_sd_db: f32,
    pub gain_corr_s: f32,
    /// Broadband additive noise (RMS, dBFS).
    pub noise_floor_dbfs: f32,
    pub seed: u64,
}

impl CodecChannelProfile {
    /// Parameters estimated from the 2026-11-23 VoWiFi capture with `modem-wav diagnose`:
    /// about -3.5 dB/octave above 1 kHz with a ~3 kHz corner (2.5-3 kHz arrived 5-10 dB below the
    /// 0.5-1.5 kHz level, nothing usable above 4 kHz), in-band off bins only ~11 dB below the tones,
    /// tones of an 18-tone frame frequently missing, slow gain swings of ~5 dB (20 ms frame-to-frame
    /// correlation 0.92).
    pub fn vowifi_measured() -> Self {
        Self {
            tilt_db_per_octave: -3.5,
            tilt_pivot_hz: 1000.0,
            lowpass_hz: 3000.0,
            highpass_hz: 200.0,
            max_partials: 7,
            partial_drop_db: 18.0,
            partial_fade_prob: 0.06,
            fill_snr_db: 8.0,
            gain_sd_db: 5.0,
            gain_corr_s: 0.25,
            noise_floor_dbfs: -50.0,
            seed: 0xAE61_5C47_2026_1123,
        }
    }
}

/// In-place iterative radix-2 FFT (length must be a power of two); the inverse is scaled by 1/n.
fn fft_in_place(re: &mut [f32], im: &mut [f32], inverse: bool) {
    let n = re.len();
    let mut j = 0usize;
    for i in 1..n {
        let mut bit = n >> 1;
        while j & bit != 0 {
            j ^= bit;
            bit >>= 1;
        }
        j |= bit;
        if i < j {
            re.swap(i, j);
            im.swap(i, j);
        }
    }
    let mut len = 2;
    while len <= n {
        let ang = 2.0 * PI / len as f32 * if inverse { 1.0 } else { -1.0 };
        let (wi, wr) = ang.sin_cos();
        for start in (0..n).step_by(len) {
            let (mut cr, mut ci) = (1.0f32, 0.0f32);
            for k in 0..len / 2 {
                let a = start + k;
                let b = a + len / 2;
                let tr = re[b] * cr - im[b] * ci;
                let ti = re[b] * ci + im[b] * cr;
                re[b] = re[a] - tr;
                im[b] = im[a] - ti;
                re[a] += tr;
                im[a] += ti;
                let ncr = cr * wr - ci * wi;
                ci = cr * wi + ci * wr;
                cr = ncr;
            }
        }
        len <<= 1;
    }
    if inverse {
        let s = 1.0 / n as f32;
        for v in re.iter_mut().chain(im.iter_mut()) {
            *v *= s;
        }
    }
}

/// Deterministic uniform [0, 1) from three integers (SplitMix64 finalizer).
fn hash_unit(seed: u64, a: u64, b: u64) -> f32 {
    let mut z = seed ^ a.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ b.wrapping_mul(0xD6E8_FEB8_6659_FD93);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^= z >> 31;
    (z >> 40) as f32 / (1u64 << 24) as f32
}

/// Runs `pcm` (16 kHz) through the codec-path channel model.
pub fn apply_codec_channel(pcm: &[i16], p: &CodecChannelProfile) -> Vec<i16> {
    const N: usize = 256;
    const HOP: usize = N / 2;
    const HALF: usize = N / 2;
    let len = pcm.len();
    let x: Vec<f32> = pcm.iter().map(|&s| s as f32 / 32_768.0).collect();
    // sqrt-Hann analysis and synthesis windows: their product overlap-adds to 1 at 50% hop.
    let win: Vec<f32> = (0..N).map(|n| (PI * n as f32 / N as f32).sin()).collect();
    let bin_hz = SAMPLE_RATE as f32 / N as f32;
    let resp: Vec<f32> = (0..=HALF)
        .map(|k| {
            let f = (k as f32 * bin_hz).max(20.0);
            let tilt = p.tilt_db_per_octave * (f / p.tilt_pivot_hz).log2();
            let lp = 1.0 / (1.0 + (f / p.lowpass_hz).powi(8)).sqrt();
            let hp = 1.0 / (1.0 + (p.highpass_hz / f).powi(4)).sqrt();
            10f32.powf(tilt / 20.0) * lp * hp
        })
        .collect();
    let drop = 10f32.powf(-p.partial_drop_db / 20.0);
    let fill = 10f32.powf(-p.fill_snr_db / 10.0);
    let mut rng = XorShift64(p.seed ^ 0xC0DE_C0DE_5EED_0001);
    let rho = (-(HOP as f32 / SAMPLE_RATE as f32) / p.gain_corr_s.max(1e-3)).exp();
    let innov = (1.0 - rho * rho).sqrt() * p.gain_sd_db;
    let mut g_db = 0.0f32;
    // Codec frames are not aligned with the modem's frames on a real call.
    let codec_offset = (p.seed % FRAME_SAMPLES as u64) as usize;

    let mut out = vec![0.0f32; len];
    let mut re = vec![0.0f32; N];
    let mut im = vec![0.0f32; N];
    let mut pw = vec![0.0f32; HALF + 1];
    let frames = len / HOP + 2;
    for t in 0..frames {
        let start = t as isize * HOP as isize - HOP as isize;
        for n in 0..N {
            let i = start + n as isize;
            re[n] = if i >= 0 && (i as usize) < len { x[i as usize] * win[n] } else { 0.0 };
            im[n] = 0.0;
        }
        fft_in_place(&mut re, &mut im, false);

        g_db = rho * g_db + innov * rng.next_normal();
        let g = 10f32.powf(g_db / 20.0);
        for k in 0..=HALF {
            re[k] *= resp[k] * g;
            im[k] *= resp[k] * g;
            pw[k] = re[k] * re[k] + im[k] * im[k];
        }

        let center = (start + HOP as isize).max(0) as usize;
        let cframe = ((center + codec_offset) / FRAME_SAMPLES) as u64;
        let mut peaks: Vec<usize> =
            (1..HALF).filter(|&k| pw[k] > pw[k - 1] && pw[k] >= pw[k + 1] && pw[k] > 1e-12).collect();
        peaks.sort_by(|&a, &b| pw[b].total_cmp(&pw[a]));
        for (rank, &k) in peaks.iter().enumerate() {
            let faded = hash_unit(p.seed, cframe, k as u64) < p.partial_fade_prob;
            if rank >= p.max_partials || faded {
                for kk in k - 1..=k + 1 {
                    re[kk] *= drop;
                    im[kk] *= drop;
                }
            }
        }

        for k in 0..=HALF {
            pw[k] = re[k] * re[k] + im[k] * im[k];
        }
        for k in 1..HALF {
            let lo = k.saturating_sub(3).max(1);
            let hi = (k + 3).min(HALF - 1);
            let env = pw[lo..=hi].iter().sum::<f32>() / (hi - lo + 1) as f32;
            let sd = (env * fill * 0.5).sqrt();
            re[k] += sd * rng.next_normal();
            im[k] += sd * rng.next_normal();
        }
        im[0] = 0.0;
        im[HALF] = 0.0;
        for k in 1..HALF {
            re[N - k] = re[k];
            im[N - k] = -im[k];
        }
        fft_in_place(&mut re, &mut im, true);
        for n in 0..N {
            let i = start + n as isize;
            if i >= 0 && (i as usize) < len {
                out[i as usize] += re[n] * win[n];
            }
        }
    }

    let floor = 10f32.powf(p.noise_floor_dbfs / 20.0);
    out.iter()
        .map(|&v| ((v + floor * rng.next_normal()).clamp(-0.99, 0.99) * 32_767.0).round() as i16)
        .collect()
}

/// Resamples `pcm` to simulate sample-clock offset `skew_ppm` (positive = sender clock faster than
/// receiver clock, so `N` sender samples compress into `N / (1 + skew_ppm * 1e-6)` receiver samples).
pub fn apply_clock_skew(pcm: &[i16], skew_ppm: f32) -> Vec<i16> {
    if pcm.is_empty() || !skew_ppm.is_finite() {
        return pcm.to_vec();
    }
    let step = (1.0 + (skew_ppm as f64) * 1e-6).clamp(0.95, 1.05);
    let out_len = ((pcm.len() as f64) / step).round().max(1.0) as usize;
    crate::demodulator::resample_farrow_i16(pcm, 0.0, step, out_len)
}

/// Simulates VoLTE/VoWiFi NetEq jitter-buffer time-scale modifications (random 20 ms frame drops
/// or smooth cross-faded 20 ms frame duplications) with probability `edit_prob` per frame.
pub fn apply_jitter_time_scale(pcm: &[i16], edit_prob: f32, seed: u64) -> Vec<i16> {
    if pcm.is_empty() || edit_prob <= 0.0 {
        return pcm.to_vec();
    }
    let mut rng = XorShift64(seed ^ 0x4E65_7445_715F_2026);
    let mut out = Vec::with_capacity(pcm.len() + FRAME_SAMPLES * 4);
    for frame in pcm.chunks(FRAME_SAMPLES) {
        let u = rng.next_f32();
        if u < edit_prob * 0.5 && frame.len() == FRAME_SAMPLES {
            // NetEq time-compression: drop one 20 ms frame
            continue;
        } else if u < edit_prob && frame.len() == FRAME_SAMPLES {
            // NetEq PLC/WSOLA expansion: duplicate one 20 ms frame with 2 ms edge cross-fade
            out.extend_from_slice(frame);
            let mut dup = frame.to_vec();
            for k in 0..32 {
                let w = k as f32 / 32.0;
                dup[k] = ((1.0 - w) * frame[FRAME_SAMPLES - 32 + k] as f32 + w * frame[k] as f32)
                    .round()
                    .clamp(-32_768.0, 32_767.0) as i16;
            }
            out.extend_from_slice(&dup);
        } else {
            out.extend_from_slice(frame);
        }
    }
    out
}

/// Time-domain 3GPP AMR-WB / EVS ACELP (Algebraic Code-Excited Linear Prediction) vocoder simulator.
/// Models real cellular voice coding constraints:
/// 1. Pre-emphasis $H_{\text{pre}}(z) = 1 - 0.68 z^{-1}$ & telecom bandpass;
/// 2. 20 ms 16th-order Levinson-Durbin Linear Predictive Coding (LPC) all-pole vocal-tract envelope;
/// 3. Four 5 ms (80-sample) subframes with closed-loop fractional/integer pitch adaptive codebook;
/// 4. Sparse algebraic fixed-codebook signed-pulse search (`pulses_per_subframe` pulses per 5 ms);
/// 5. Voice Activity Detection (VAD) / Discontinuous Transmission (DTX) comfort-noise replacement;
/// 6. 16th-order all-pole synthesis filter $1 / A(z)$ + de-emphasis $1 / (1 - 0.68 z^{-1})$.
#[derive(Debug, Clone, Copy)]
pub struct AcelpChannelProfile {
    pub wideband: bool,
    /// Number of signed algebraic innovation pulses per 5 ms (80-sample) subframe:
    /// 2 = AMR-WB 6.60 kbps, 8 = AMR-WB 12.65 kbps, 16 = EVS 24.4 kbps.
    pub pulses_per_subframe: usize,
    /// Quantization step count for pitch and algebraic codebook gains.
    pub gain_quant_levels: u16,
    /// Enable VAD/DTX comfort-noise substitution on low-energy or stationary tonal frames.
    pub dtx_enabled: bool,
    /// Random 20 ms RTP frame erasure rate (concealed via damped pitch-lag PLC).
    pub frame_erasure_prob: f32,
    pub cfo_hz: f32,
    pub seed: u64,
}

impl AcelpChannelProfile {
    /// Harsh low-rate AMR-WB 6.60 kbps mode (only 2 pulses per 5 ms subframe).
    pub fn amr_wb_6k60() -> Self {
        Self {
            wideband: true,
            pulses_per_subframe: 2,
            gain_quant_levels: 32,
            dtx_enabled: true,
            frame_erasure_prob: 0.03,
            cfo_hz: 11.5,
            seed: 0x3650_505F_0660,
        }
    }

    /// Standard VoLTE AMR-WB 12.65 kbps mode (8 algebraic pulses per 5 ms subframe).
    pub fn amr_wb_12k65() -> Self {
        Self {
            wideband: true,
            pulses_per_subframe: 8,
            gain_quant_levels: 64,
            dtx_enabled: true,
            frame_erasure_prob: 0.02,
            cfo_hz: -14.0,
            seed: 0x3650_505F_1265,
        }
    }

    /// VoLTE/5G NR EVS 24.4 kbps ACELP mode (16 algebraic pulses per 5 ms subframe).
    pub fn evs_24k4() -> Self {
        Self {
            wideband: true,
            pulses_per_subframe: 16,
            gain_quant_levels: 128,
            dtx_enabled: false,
            frame_erasure_prob: 0.01,
            cfo_hz: 6.0,
            seed: 0x3650_505F_2440,
        }
    }
}

fn levinson_durbin_16(frame: &[f32]) -> [f32; 17] {
    const ORDER: usize = 16;
    let n = frame.len();
    let mut windowed = vec![0.0f32; n];
    for i in 0..n {
        let w = 0.54 - 0.46 * (2.0 * PI * i as f32 / n.max(1) as f32).cos();
        windowed[i] = frame[i] * w;
    }
    let mut r = [0.0f64; ORDER + 1];
    for k in 0..=ORDER {
        let mut s = 0.0f64;
        for i in k..n {
            s += (windowed[i] as f64) * (windowed[i - k] as f64);
        }
        // 3GPP lag windowing + white-noise floor for unconditional synthesis stability
        let bw = 0.994f64.powi(k as i32);
        r[k] = s * bw;
    }
    let mut a = [0.0f32; ORDER + 1];
    a[0] = 1.0;
    if r[0] <= 1e-10 {
        return a;
    }
    r[0] *= 1.0003;

    let mut a_cur = [0.0f64; ORDER + 1];
    let mut a_prev = [0.0f64; ORDER + 1];
    a_cur[0] = 1.0;
    let mut err = r[0];

    for m in 1..=ORDER {
        let mut sum = r[m];
        for i in 1..m {
            sum += a_cur[i] * r[m - i];
        }
        let k_ref = (-sum / err).clamp(-0.985, 0.985);
        a_prev[..m].copy_from_slice(&a_cur[..m]);
        a_cur[m] = k_ref;
        for i in 1..m {
            a_cur[i] = a_prev[i] + k_ref * a_prev[m - i];
        }
        err *= 1.0 - k_ref * k_ref;
        if err <= 1e-12 {
            break;
        }
    }
    // Slight bandwidth expansion (gamma = 0.992) prevents sharp pole ringing on multi-tone inputs
    let mut gamma = 1.0f64;
    for i in 1..=ORDER {
        gamma *= 0.992;
        a[i] = (a_cur[i] * gamma) as f32;
    }
    a
}

/// Runs 16 kHz `pcm` through the time-domain AMR-WB / EVS ACELP vocoder simulator.
pub fn apply_acelp_channel(pcm: &[i16], profile: &AcelpChannelProfile) -> Vec<i16> {
    if pcm.is_empty() {
        return Vec::new();
    }
    const ORDER: usize = 16;
    const SUBFRAME: usize = 80; // 5 ms @ 16 kHz
    const MAX_LAG: usize = 232; // ~69 Hz min pitch
    const MIN_LAG: usize = 34;  // ~470 Hz max pitch
    const PREEMPH: f32 = 0.68;

    let mut rng = XorShift64(profile.seed ^ 0xACE1_9000_2026_0007);
    let raw: Vec<f32> = pcm.iter().map(|&s| s as f32 / 32_768.0).collect();
    let bp = apply_bandpass(&raw, profile.wideband);
    let input = apply_frequency_shift(&bp, profile.cfo_hz);

    // Pre-emphasis H(z) = 1 - 0.68 z^-1
    let mut pre = vec![0.0f32; input.len()];
    let mut prev_in = 0.0f32;
    for (i, &x) in input.iter().enumerate() {
        pre[i] = x - PREEMPH * prev_in;
        prev_in = x;
    }

    let pulses = profile.pulses_per_subframe.clamp(1, 32);
    let q_levels = profile.gain_quant_levels.max(8) as f32;
    let mut exc_hist = vec![0.0f32; MAX_LAG + FRAME_SAMPLES];
    let mut syn_mem = [0.0f32; ORDER];
    let mut ana_mem = [0.0f32; ORDER];
    let mut deemph_state = 0.0f32;
    let mut last_lag = 128usize;
    let mut out = Vec::with_capacity(pcm.len());

    let num_frames = (pre.len() + FRAME_SAMPLES - 1) / FRAME_SAMPLES;
    for f in 0..num_frames {
        let start = f * FRAME_SAMPLES;
        let end = (start + FRAME_SAMPLES).min(pre.len());
        let len = end - start;
        let mut frame = [0.0f32; FRAME_SAMPLES];
        frame[..len].copy_from_slice(&pre[start..end]);

        let energy: f32 = frame.iter().map(|&v| v * v).sum::<f32>() / FRAME_SAMPLES as f32;
        if profile.dtx_enabled && energy < 2e-6 {
            // VAD/DTX inactive frame: comfort noise excitation only
            for _ in 0..len {
                let cn = rng.next_normal() * 0.0008;
                deemph_state = cn + PREEMPH * deemph_state;
                out.push((deemph_state.clamp(-0.99, 0.99) * 32_767.0).round() as i16);
            }
            syn_mem = [0.0; ORDER];
            ana_mem = [0.0; ORDER];
            exc_hist.fill(0.0);
            continue;
        }

        let a = levinson_durbin_16(&frame);

        // Compute LPC analysis residual r[n] = x[n] + sum_{k=1..16} a[k] * x[n - k]
        let mut residual = [0.0f32; FRAME_SAMPLES];
        for n in 0..FRAME_SAMPLES {
            let mut s = frame[n];
            for k in 1..=ORDER {
                let x_prev = if n >= k { frame[n - k] } else { ana_mem[k - 1 - n] };
                s += a[k] * x_prev;
            }
            residual[n] = s;
        }
        for k in 0..ORDER {
            ana_mem[k] = frame[FRAME_SAMPLES - 1 - k];
        }

        let erased = rng.next_f32() < profile.frame_erasure_prob;

        for sf in 0..4 {
            let sf_off = sf * SUBFRAME;
            let target = &residual[sf_off..sf_off + SUBFRAME];

            let mut sub_exc = [0.0f32; SUBFRAME];
            if erased {
                // 3GPP PLC: repeat adaptive codebook at last_lag with 0.75 attenuation
                for n in 0..SUBFRAME {
                    let src_idx = MAX_LAG + sf_off + n - last_lag;
                    sub_exc[n] = 0.75 * exc_hist[src_idx];
                }
            } else {
                // 1. Adaptive codebook pitch search over lags [MIN_LAG, MAX_LAG]
                let mut best_lag = last_lag;
                let mut best_score = f32::NEG_INFINITY;
                let mut best_gp = 0.0f32;
                for lag in MIN_LAG..=MAX_LAG {
                    let mut dot = 0.0f32;
                    let mut norm_sq = 1e-9f32;
                    for n in 0..SUBFRAME {
                        let cand = if n < lag {
                            exc_hist[MAX_LAG + sf_off + n - lag]
                        } else {
                            // Self-excited pitch extension for lags shorter than subframe (80)
                            exc_hist[MAX_LAG + sf_off + (n % lag) - lag]
                        };
                        dot += target[n] * cand;
                        norm_sq += cand * cand;
                    }
                    if dot > 0.0 {
                        let score = (dot * dot) / norm_sq;
                        if score > best_score {
                            best_score = score;
                            best_lag = lag;
                            best_gp = (dot / norm_sq).clamp(0.0, 1.2);
                        }
                    }
                }
                last_lag = best_lag;
                let gp_q = ((best_gp / 1.2) * q_levels).round() / q_levels * 1.2;

                let mut rem = [0.0f32; SUBFRAME];
                for n in 0..SUBFRAME {
                    let v = if n < best_lag {
                        exc_hist[MAX_LAG + sf_off + n - best_lag]
                    } else {
                        exc_hist[MAX_LAG + sf_off + (n % best_lag) - best_lag]
                    };
                    let pred = gp_q * v;
                    sub_exc[n] = pred;
                    rem[n] = target[n] - pred;
                }

                // 2. Interleaved Single-Pulse Permutation (ISPP) algebraic codebook search
                //    Places `pulses` signed unit impulses across 5 interleaved tracks.
                let mut fixed_cb = [0.0f32; SUBFRAME];
                let mut used = [false; SUBFRAME];
                for p_idx in 0..pulses {
                    let track = p_idx % 5;
                    let mut best_pos = track;
                    let mut best_abs = -1.0f32;
                    let mut pos = track;
                    while pos < SUBFRAME {
                        if !used[pos] && rem[pos].abs() > best_abs {
                            best_abs = rem[pos].abs();
                            best_pos = pos;
                        }
                        pos += 5;
                    }
                    used[best_pos] = true;
                    fixed_cb[best_pos] = if rem[best_pos] >= 0.0 { 1.0 } else { -1.0 };
                }

                let mut num = 0.0f32;
                let mut den = 1e-9f32;
                for n in 0..SUBFRAME {
                    num += rem[n] * fixed_cb[n];
                    den += fixed_cb[n] * fixed_cb[n];
                }
                let gc_raw = (num / den).max(0.0);
                // Logarithmic gain quantization modeling 3GPP 6..7-bit gain codebook
                let gc_q = if gc_raw > 1e-6 {
                    let db = (20.0 * gc_raw.log10()).clamp(-80.0, 6.0);
                    let db_q = ((db + 80.0) / 86.0 * q_levels).round() / q_levels * 86.0 - 80.0;
                    10.0f32.powf(db_q / 20.0)
                } else {
                    0.0
                };

                for n in 0..SUBFRAME {
                    sub_exc[n] += gc_q * fixed_cb[n];
                }
            }

            exc_hist[MAX_LAG + sf_off..MAX_LAG + sf_off + SUBFRAME].copy_from_slice(&sub_exc);

            // 3. All-pole LPC synthesis 1 / A(z) + De-emphasis 1 / (1 - 0.68 z^-1)
            for n in 0..SUBFRAME {
                let global_n = sf_off + n;
                if global_n >= len {
                    break;
                }
                let mut syn = sub_exc[n];
                for k in 1..=ORDER {
                    syn -= a[k] * syn_mem[k - 1];
                }
                syn = syn.clamp(-2.0, 2.0);
                for k in (1..ORDER).rev() {
                    syn_mem[k] = syn_mem[k - 1];
                }
                syn_mem[0] = syn;

                deemph_state = (syn + PREEMPH * deemph_state).clamp(-0.99, 0.99);
                let noisy = (deemph_state + rng.next_normal() * 0.0004).clamp(-0.99, 0.99);
                out.push((noisy * 32_767.0).round() as i16);
            }
        }

        // Shift adaptive-codebook history buffer back by 320 samples
        exc_hist.copy_within(FRAME_SAMPLES..MAX_LAG + FRAME_SAMPLES, 0);
    }

    out
}

