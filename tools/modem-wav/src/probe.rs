//! Channel probe: a known sweep and multi-tone combs between silences, used to measure a call path
//! per 62.5 Hz bin (gain, noise floor, SNR) and how its gain moves over time.

use crate::analyze::find_first_chirp;
use crate::diagnose::{db, Dft};
use crate::dsp::to_f32;
use aegiscall_modem::{synthesize_preamble, ModemGear, PreambleCapabilities, SAMPLE_RATE, TOTAL_PREAMBLE_SAMPLES};
use std::f64::consts::PI;

const SR: usize = SAMPLE_RATE;
const NBINS: usize = 128;
const BIN_HZ: f64 = 62.5;
const SWEEP_F0: f64 = 150.0;
const SWEEP_F1: f64 = 7800.0;
const SWEEP_S: f64 = 2.5;
const COMB_S: f64 = 0.5;
const COMBS: usize = 8;
const STEADY_S: f64 = 3.0;
const SILENCE_S: f64 = 0.5;
const FADE: usize = 160; // 10 ms edges
const MARGIN: usize = 800; // 50 ms skipped at each part edge during analysis
/// Energy of a full-scale sine centred in one bin of the 256-point DFT (|X| = 128).
const FULL_SCALE_BIN: f64 = 16_384.0;

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Silence,
    Sweep,
    /// Bins 2 + s + 8m (every 500 Hz, shifted by s bins).
    Comb(usize),
    /// Bins 8, 10, ..., 48 (500-3000 Hz) held constant, like a modem payload.
    Steady,
}

struct Part {
    kind: Kind,
    start: usize,
    len: usize,
}

/// Probe parts, positions relative to the end of the sync preamble.
fn layout() -> Vec<Part> {
    let mut plan = vec![(Kind::Silence, SILENCE_S), (Kind::Sweep, SWEEP_S), (Kind::Silence, SILENCE_S)];
    for s in 0..COMBS {
        plan.push((Kind::Comb(s), COMB_S));
    }
    plan.extend([(Kind::Silence, SILENCE_S), (Kind::Steady, STEADY_S), (Kind::Silence, SILENCE_S)]);
    let mut t = 0;
    plan.into_iter()
        .map(|(kind, secs)| {
            let len = (secs * SR as f64).round() as usize;
            let p = Part { kind, start: t, len };
            t += len;
            p
        })
        .collect()
}

fn comb_bins(kind: Kind) -> Vec<usize> {
    match kind {
        Kind::Comb(s) => (0..).map(|m| 2 + s + 8 * m).take_while(|&k| k <= 126).collect(),
        Kind::Steady => (8..=48).step_by(2).collect(),
        _ => Vec::new(),
    }
}

fn edge(n: usize, len: usize) -> f64 {
    let d = n.min(len - 1 - n);
    if d >= FADE {
        1.0
    } else {
        0.5 * (1.0 - (PI * d as f64 / FADE as f64).cos())
    }
}

fn synth(kind: Kind, len: usize) -> Vec<f64> {
    let mut v = vec![0.0f64; len];
    match kind {
        Kind::Silence => {}
        Kind::Sweep => {
            let t_total = len as f64 / SR as f64;
            let r = (SWEEP_F1 / SWEEP_F0).ln();
            for (n, x) in v.iter_mut().enumerate() {
                let t = n as f64 / SR as f64;
                let ph = 2.0 * PI * SWEEP_F0 * t_total / r * ((t * r / t_total).exp() - 1.0);
                *x = ph.sin() * edge(n, len);
            }
        }
        Kind::Comb(_) | Kind::Steady => {
            for k in comb_bins(kind) {
                let w = 2.0 * PI * k as f64 * BIN_HZ / SR as f64;
                let ph0 = (k as f64 * 2.399_963_2) % (2.0 * PI);
                for (n, x) in v.iter_mut().enumerate() {
                    *x += (w * n as f64 + ph0).sin();
                }
            }
            for (n, x) in v.iter_mut().enumerate() {
                *x *= edge(n, len);
            }
        }
    }
    v
}

fn scale_to(v: &[f64], level_dbfs: f64) -> Vec<i16> {
    let rms = (v.iter().map(|x| x * x).sum::<f64>() / v.len().max(1) as f64).sqrt();
    let g = if rms > 0.0 { 32_768.0 * 10f64.powf(level_dbfs / 20.0) / rms } else { 0.0 };
    v.iter().map(|x| (x * g).round().clamp(-32_768.0, 32_767.0) as i16).collect()
}

/// Probe body (without the sync preamble); every non-silent part has RMS \`level_dbfs\`.
fn body(level_dbfs: f64) -> Vec<i16> {
    let mut out = Vec::new();
    for p in layout() {
        let v = synth(p.kind, p.len);
        if p.kind == Kind::Silence {
            out.extend(std::iter::repeat(0i16).take(p.len));
        } else {
            out.extend(scale_to(&v, level_dbfs));
        }
    }
    out
}

/// Sync preamble (narrowband capability trailer) followed by the probe body.
pub fn gen_probe(level_dbfs: f64) -> Vec<i16> {
    let pre: Vec<f64> = synthesize_preamble(PreambleCapabilities::v2(ModemGear::Narrowband1200))
        .iter()
        .map(|&s| s as f64)
        .collect();
    let mut pcm = scale_to(&pre, level_dbfs);
    pcm.extend(body(level_dbfs));
    pcm
}

pub fn describe() -> String {
    format!(
        "lead-in 0.40 s | silence {s} | log sweep {f0:.0}–{f1:.0} Hz {sw} s | silence {s} | {c} comb groups of {cs} s each (one tone per 500 Hz, each group shifted by 62.5 Hz, together covering every bin from 125–7875 Hz) | silence {s} | fixed comb 500–3000 Hz, one tone per 125 Hz, {st} s | silence {s}",
        s = SILENCE_S, f0 = SWEEP_F0, f1 = SWEEP_F1, sw = SWEEP_S, c = COMBS, cs = COMB_S, st = STEADY_S
    )
}

fn windows(p: &Part, hop: usize) -> impl Iterator<Item = usize> {
    let lo = p.start + MARGIN;
    let hi = (p.start + p.len).saturating_sub(MARGIN + 256);
    (lo..=hi.max(lo)).step_by(hop).filter(move |&w| w <= hi)
}

pub fn analyze_probe(pcm: &[i16], offset_s: f64, level_dbfs: f64) -> Result<(), String> {
    let sig = to_f32(pcm);
    let (up, corr) = find_first_chirp(&sig).ok_or("lead-in (chirp) at the start of the probe signal not found")?;
    let origin = up + TOTAL_PREAMBLE_SAMPLES;
    let parts = layout();
    let total = parts.last().map(|p| p.start + p.len).unwrap_or(0);
    if origin + total > pcm.len() + SR / 2 {
        return Err(format!(
            "recording ended before the probe signal finished (need {:.2} s, only {:.2} s)",
            (origin + total) as f64 / SR as f64,
            pcm.len() as f64 / SR as f64
        ));
    }
    let tx = body(level_dbfs);
    let dft = Dft::new();
    let rx_at = |pos: usize| dft.core(pcm, (origin + pos) as i64);
    let tx_at = |pos: usize| dft.core(&tx, pos as i64);

    // Silence floor.
    let mut sil = [0f64; NBINS];
    let mut sil_n = 0usize;
    for p in parts.iter().filter(|p| p.kind == Kind::Silence) {
        for w in windows(p, 128) {
            let e = rx_at(w);
            for k in 0..NBINS {
                sil[k] += e[k] as f64;
            }
            sil_n += 1;
        }
    }
    for v in sil.iter_mut() {
        *v /= sil_n.max(1) as f64;
    }
    let sil_zero = sil.iter().all(|&v| v == 0.0);

    // Comb gains and in-signal floor (bins not in the current comb).
    let (mut on_rx, mut on_tx, mut on_n) = ([0f64; NBINS], [0f64; NBINS], [0usize; NBINS]);
    let (mut off_rx, mut off_n) = ([0f64; NBINS], [0usize; NBINS]);
    for p in parts.iter().filter(|p| matches!(p.kind, Kind::Comb(_))) {
        let bins = comb_bins(p.kind);
        for w in windows(p, 128) {
            let (er, et) = (rx_at(w), tx_at(w));
            for k in 1..NBINS {
                if bins.contains(&k) {
                    on_rx[k] += er[k] as f64;
                    on_tx[k] += et[k] as f64;
                    on_n[k] += 1;
                } else if !bins.contains(&(k - 1)) && !bins.contains(&(k + 1).min(NBINS - 1)) {
                    off_rx[k] += er[k] as f64;
                    off_n[k] += 1;
                }
            }
        }
    }

    // Single-tone (sweep) gain.
    let (mut sw_rx, mut sw_tx) = ([0f64; NBINS], [0f64; NBINS]);
    if let Some(p) = parts.iter().find(|p| p.kind == Kind::Sweep) {
        let r = (SWEEP_F1 / SWEEP_F0).ln();
        let t_total = p.len as f64 / SR as f64;
        for w in windows(p, 64) {
            let t = (w - p.start + 128) as f64 / SR as f64;
            let f = SWEEP_F0 * (t * r / t_total).exp();
            let c = (f / BIN_HZ).round() as usize;
            if c < 4 || c > NBINS - 4 {
                continue;
            }
            let (er, et) = (rx_at(w), tx_at(w));
            for k in c - 3..=c + 3 {
                sw_rx[c] += er[k] as f64;
                sw_tx[c] += et[k] as f64;
            }
        }
    }

    let avg = |s: f64, n: usize| if n == 0 { f64::NAN } else { s / n as f64 };
    let off: Vec<f64> = (0..NBINS).map(|k| avg(off_rx[k], off_n[k])).collect();
    let tone: Vec<f64> = (0..NBINS).map(|k| (avg(on_rx[k], on_n[k]) - off[k]).max(1e-20)).collect();
    let gain: Vec<f64> = (0..NBINS).map(|k| db(tone[k] / avg(on_tx[k], on_n[k]))).collect();
    let mut refs: Vec<f64> = (8..24).map(|k| gain[k]).filter(|g| g.is_finite()).collect();
    refs.sort_by(|a, b| a.total_cmp(b));
    let ref_db = refs.get(refs.len() / 2).copied().unwrap_or(f64::NAN);

    println!("== Channel probe ==");
    println!(
        "lead-in position {:.3} s (correlation {:.2}), probe body {:.3}–{:.3} s",
        offset_s + up as f64 / SR as f64,
        corr,
        offset_s + origin as f64 / SR as f64,
        offset_s + (origin + total) as f64 / SR as f64
    );
    if sil_zero {
        println!("Silence segment: digital zero (DTX/silence suppression), so the noise floor cannot be measured from silence; SNR instead uses the energy of unsounded bins during the comb tones");
    }
    println!("Gain = received/sent (call noise floor removed); relative = minus the 500–1500 Hz median {:.1} dB; level unit dBFS (full-scale sine per bin = 0)", ref_db);
    println!("  Bin Freq Hz    Comb dB Rel dB    Tone dB   RxLvl dBFS CallNoise dBFS     Sil dBFS   SNR dB");
    for k in 2..=126 {
        let sw = if sw_tx[k] > 0.0 { format!("{:10.1}", db(sw_rx[k] / sw_tx[k])) } else { "         -".to_string() };
        let sil_s = if sil_zero { "Digital zero".to_string() } else { format!("{:12.1}", db(sil[k] / FULL_SCALE_BIN)) };
        println!(
            "  {:3} {:7.1} {:10.1} {:6.1} {} {:12.1} {:14.1} {} {:8.1}",
            k,
            k as f64 * BIN_HZ,
            gain[k],
            gain[k] - ref_db,
            sw,
            db(tone[k] / FULL_SCALE_BIN),
            db(off[k] / FULL_SCALE_BIN),
            sil_s,
            db(tone[k] / off[k])
        );
    }
    let edge_hz = |limit: f64| -> (f64, f64) {
        let ok = |k: usize| gain[k] - ref_db >= limit;
        let mut lo = 16;
        while lo > 2 && ok(lo - 1) {
            lo -= 1;
        }
        let mut hi = 16;
        while hi < 126 && ok(hi + 1) {
            hi += 1;
        }
        (lo as f64 * BIN_HZ, hi as f64 * BIN_HZ)
    };
    let (l6, h6) = edge_hz(-6.0);
    let (l12, h12) = edge_hz(-12.0);
    println!("Contiguous bands with relative gain ≥ −6 dB: {:.1}–{:.1} Hz; ≥ −12 dB: {:.1}–{:.1} Hz", l6, h6, l12, h12);

    // Gain over time on a stationary comb (noise suppressors and AGC react to it).
    if let Some(p) = parts.iter().find(|p| p.kind == Kind::Steady) {
        let bins = comb_bins(p.kind);
        println!("Fixed comb tone gain over time (every 0.5 s; low <2 kHz / high ≥2 kHz, dB):");
        let chunk = SR / 2;
        let mut first: Option<f64> = None;
        let mut c = 0;
        while c * chunk + 256 <= p.len {
            let sub = Part { kind: p.kind, start: p.start + c * chunk, len: chunk };
            let lo_m = if c == 0 { MARGIN } else { 0 };
            let (mut lr, mut lt, mut hr, mut ht) = (0f64, 0f64, 0f64, 0f64);
            let mut w = sub.start + lo_m;
            while w + 256 <= sub.start + sub.len && w + 256 + MARGIN <= p.start + p.len {
                let (er, et) = (rx_at(w), tx_at(w));
                for &k in &bins {
                    if (k as f64) * BIN_HZ < 2000.0 {
                        lr += er[k] as f64;
                        lt += et[k] as f64;
                    } else {
                        hr += er[k] as f64;
                        ht += et[k] as f64;
                    }
                }
                w += 128;
            }
            if lt > 0.0 {
                let l = db(lr / lt);
                let f = *first.get_or_insert(l);
                println!(
                    "  {:.1}–{:.1} s: low {:6.1} (vs start {:+5.1})  high {:6.1}",
                    c as f64 * 0.5,
                    c as f64 * 0.5 + 0.5,
                    l,
                    l - f,
                    db(hr / ht.max(1e-20))
                );
            }
            c += 1;
        }
    }
    Ok(())
}

