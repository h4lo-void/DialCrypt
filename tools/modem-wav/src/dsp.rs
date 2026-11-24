//! Small DSP helpers: PRNG, resampler, biquad filters, G.711 mu-law.

use std::f64::consts::PI;

/// SplitMix64 generator (deterministic, seedable).
pub struct Rng(pub u64);

impl Rng {
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    pub fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    pub fn normal(&mut self) -> f64 {
        let u1 = self.unit().max(1e-12);
        let u2 = self.unit();
        (-2.0 * u1.ln()).sqrt() * (2.0 * PI * u2).cos()
    }
}

pub fn to_f32(x: &[i16]) -> Vec<f32> {
    x.iter().map(|&s| s as f32 / 32_768.0).collect()
}

pub fn to_i16(x: &[f32]) -> Vec<i16> {
    x.iter()
        .map(|&v| (v * 32_768.0).round().clamp(-32_768.0, 32_767.0) as i16)
        .collect()
}

/// RMS level in dBFS (full scale = 32768); silence is floored at -120.
pub fn rms_dbfs(x: &[i16]) -> f64 {
    if x.is_empty() {
        return -120.0;
    }
    let sum: f64 = x.iter().map(|&s| (s as f64) * (s as f64)).sum();
    let rms = (sum / x.len() as f64).sqrt() / 32_768.0;
    if rms < 1e-6 {
        -120.0
    } else {
        20.0 * rms.log10()
    }
}

pub fn peak_dbfs(x: &[i16]) -> f64 {
    let peak = x.iter().map(|&s| (s as i32).abs()).max().unwrap_or(0) as f64 / 32_768.0;
    if peak < 1e-6 {
        -120.0
    } else {
        20.0 * peak.log10()
    }
}

/// Band-limited resampler (Blackman-windowed sinc, 24 zero crossings, table lookup).
/// `step` is the number of input samples per output sample; output sample n is taken at
/// input position n * step. When step > 1 the kernel low-passes to the new Nyquist.
pub fn resample_step(x: &[f32], step: f64, out_len: usize) -> Vec<f32> {
    const HW: f64 = 24.0;
    const RES: usize = 256;
    let scale = (1.0 / step).min(1.0) * 0.995;
    let hws = HW / scale;
    let tab_len = (hws * RES as f64).ceil() as usize + 2;
    let mut tab = vec![0.0f64; tab_len];
    for (j, v) in tab.iter_mut().enumerate() {
        let t = j as f64 / RES as f64;
        let a = scale * t;
        let sinc = if a == 0.0 { 1.0 } else { (PI * a).sin() / (PI * a) };
        let u = (t / hws).min(1.0);
        let win = 0.42 + 0.5 * (PI * u).cos() + 0.08 * (2.0 * PI * u).cos();
        *v = scale * sinc * win;
    }
    let mut out = Vec::with_capacity(out_len);
    for n in 0..out_len {
        let c = n as f64 * step;
        let lo = (c - hws).ceil() as isize;
        let hi = (c + hws).floor() as isize;
        let mut acc = 0.0f64;
        for k in lo..=hi {
            if k < 0 || k as usize >= x.len() {
                continue;
            }
            let pos = (k as f64 - c).abs() * RES as f64;
            let i = pos as usize;
            let f = pos - i as f64;
            let w = tab[i] * (1.0 - f) + tab[(i + 1).min(tab_len - 1)] * f;
            acc += x[k as usize] as f64 * w;
        }
        out.push(acc as f32);
    }
    out
}

/// Resamples `x` from `rin` Hz to `rout` Hz.
pub fn resample_rate(x: &[f32], rin: u32, rout: u32) -> Vec<f32> {
    if rin == rout {
        return x.to_vec();
    }
    let out_len = (x.len() as f64 * rout as f64 / rin as f64).round() as usize;
    resample_step(x, rin as f64 / rout as f64, out_len)
}

fn biquad(x: &[f32], highpass: bool, fc: f64, fs: f64) -> Vec<f32> {
    let q = std::f64::consts::FRAC_1_SQRT_2;
    let w0 = 2.0 * PI * fc / fs;
    let (sn, cs) = w0.sin_cos();
    let alpha = sn / (2.0 * q);
    let (b0, b1, b2) = if highpass {
        ((1.0 + cs) / 2.0, -(1.0 + cs), (1.0 + cs) / 2.0)
    } else {
        ((1.0 - cs) / 2.0, 1.0 - cs, (1.0 - cs) / 2.0)
    };
    let a0 = 1.0 + alpha;
    let (a1, a2) = (-2.0 * cs / a0, (1.0 - alpha) / a0);
    let (b0, b1, b2) = (b0 / a0, b1 / a0, b2 / a0);
    let (mut x1, mut x2, mut y1, mut y2) = (0.0f64, 0.0f64, 0.0f64, 0.0f64);
    x.iter()
        .map(|&v| {
            let x0 = v as f64;
            let y0 = b0 * x0 + b1 * x1 + b2 * x2 - a1 * y1 - a2 * y2;
            x2 = x1;
            x1 = x0;
            y2 = y1;
            y1 = y0;
            y0 as f32
        })
        .collect()
}

/// 4th-order Butterworth-style band-pass (two cascaded 2nd-order high-pass and low-pass).
pub fn bandpass(x: &[f32], lo_hz: f64, hi_hz: f64, fs: f64) -> Vec<f32> {
    let a = biquad(&biquad(x, true, lo_hz, fs), true, lo_hz, fs);
    biquad(&biquad(&a, false, hi_hz, fs), false, hi_hz, fs)
}

/// G.711 mu-law encode (standard algorithm).
pub fn mulaw_encode(sample: i16) -> u8 {
    const BIAS: i32 = 0x84;
    const CLIP: i32 = 32_635;
    let mut s = sample as i32;
    let sign = if s < 0 { 0x80 } else { 0 };
    if s < 0 {
        s = -s;
    }
    s = s.min(CLIP) + BIAS;
    let mut exp = 7;
    let mut mask = 0x4000;
    while exp > 0 && (s & mask) == 0 {
        exp -= 1;
        mask >>= 1;
    }
    let mant = (s >> (exp + 3)) & 0x0F;
    !((sign | (exp << 4) | mant) as u8)
}

pub fn mulaw_decode(code: u8) -> i16 {
    const BIAS: i32 = 0x84;
    let u = !code as i32;
    let sign = u & 0x80;
    let exp = (u >> 4) & 0x07;
    let mant = u & 0x0F;
    let mag = (((mant << 3) + BIAS) << exp) - BIAS;
    (if sign != 0 { -mag } else { mag }) as i16
}
