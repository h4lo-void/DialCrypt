//! diagnose: aligns a recording with the regenerated transmit signal frame by frame and measures
//! per-bin channel gain, noise floor, leakage, smearing, gain fluctuation and per-subband symbol
//! errors with the impairment behind each error.

use crate::analyze::{locate, Params};
use crate::sig::{frame_data, gen_pcm, GenParams};
use aegiscall_modem::modulator::{subband_start_bin, PILOT_BIN};
use aegiscall_modem::{encode_superframe_fec, interleave_384, ModemGear, FRAME_SAMPLES, SAMPLE_RATE};

const NBINS: usize = 128;
const CORE: usize = 256;
const GUARD: usize = 32;
const BIN_HZ: f64 = 62.5;
const CHIRP: usize = 1920;
/// 0.5 s expressed in 20 ms subframes.
const HALF_SEC: usize = 25;

pub struct DiagParams {
    pub p: Params,
    /// Level the transmit WAV was generated with (gen --level-dbfs); only shifts absolute gains.
    pub level_dbfs: f64,
}

pub struct Dft {
    c: Vec<f32>,
    s: Vec<f32>,
}

impl Dft {
    pub fn new() -> Self {
        let mut c = Vec::with_capacity(CORE);
        let mut s = Vec::with_capacity(CORE);
        for m in 0..CORE {
            let a = 2.0 * std::f64::consts::PI * m as f64 / CORE as f64;
            c.push(a.cos() as f32);
            s.push(a.sin() as f32);
        }
        Dft { c, s }
    }

    /// Energy of bins 0..128 (62.5 Hz grid) of the 256 samples starting at `start` (zero outside).
    pub fn core(&self, pcm: &[i16], start: i64) -> [f32; NBINS] {
        let mut x = [0.0f32; CORE];
        for (n, v) in x.iter_mut().enumerate() {
            let i = start + n as i64;
            if i >= 0 && (i as usize) < pcm.len() {
                *v = pcm[i as usize] as f32 / 32_768.0;
            }
        }
        let mut out = [0.0f32; NBINS];
        for (k, o) in out.iter_mut().enumerate() {
            let (mut re, mut im) = (0.0f32, 0.0f32);
            for (n, &xv) in x.iter().enumerate() {
                let m = (k * n) & (CORE - 1);
                re += xv * self.c[m];
                im -= xv * self.s[m];
            }
            *o = re * re + im * im;
        }
        out
    }

    /// Same DFT over the demodulator's window of a 20 ms subframe starting at `start`.
    pub fn frame(&self, pcm: &[i16], start: i64) -> [f32; NBINS] {
        self.core(pcm, start + GUARD as i64)
    }
}

pub fn db(x: f64) -> f64 {
    10.0 * x.max(1e-20).log10()
}

fn median(mut v: Vec<f64>) -> f64 {
    if v.is_empty() {
        return f64::NAN;
    }
    v.sort_by(|a, b| a.total_cmp(b));
    v[v.len() / 2]
}

/// mean, standard deviation, 5th and 95th percentile.
fn spread(v: &[f64]) -> (f64, f64, f64, f64) {
    let v: Vec<f64> = v.iter().copied().filter(|x| x.is_finite()).collect();
    if v.is_empty() {
        return (f64::NAN, f64::NAN, f64::NAN, f64::NAN);
    }
    let n = v.len() as f64;
    let mean = v.iter().sum::<f64>() / n;
    let sd = (v.iter().map(|x| (x - mean) * (x - mean)).sum::<f64>() / n).sqrt();
    let mut s = v.clone();
    s.sort_by(|a, b| a.total_cmp(b));
    let pick = |q: f64| s[((s.len() - 1) as f64 * q).round() as usize];
    (mean, sd, pick(0.05), pick(0.95))
}

fn lag1(v: &[f64]) -> f64 {
    let (mean, sd, _, _) = spread(v);
    if !(sd > 0.0) || v.len() < 3 {
        return f64::NAN;
    }
    let mut acc = 0.0;
    let mut n = 0.0;
    for w in v.windows(2) {
        if w[0].is_finite() && w[1].is_finite() {
            acc += (w[0] - mean) * (w[1] - mean);
            n += 1.0;
        }
    }
    acc / n / (sd * sd)
}

fn pct(a: usize, b: usize) -> f64 {
    if b == 0 {
        f64::NAN
    } else {
        100.0 * a as f64 / b as f64
    }
}

struct Slot {
    rx_pos: i64,
    tx_pos: usize,
    seg: usize,
    seg_pos: usize,
    syms: Vec<usize>,
    bits: Vec<u8>,
    on: [bool; NBINS],
}

#[derive(Default, Clone)]
struct BinStat {
    t_on: f64,
    r_on: f64,
    n_on: usize,
    r_on_adj: f64,
    n_on_adj: usize,
    r_on_alone: f64,
    n_on_alone: usize,
    r_off: f64,
    n_off: usize,
    n_drop: usize,
    r_iso: f64,
    n_iso: usize,
    r_nb: f64,
    n_nb: usize,
    r_prev: f64,
    n_prev: usize,
}

fn decide<F: Fn(usize) -> f64>(gear: ModemGear, base: usize, e: F) -> usize {
    let mut best = (0usize, f64::NEG_INFINITY);
    for sym in 0..gear.symbols_per_band() {
        let s: f64 = gear.codeword(sym).iter().map(|&t| e(base + t as usize)).sum();
        if s > best.1 {
            best = (sym, s);
        }
    }
    best.0
}

fn sym_bits(gear: ModemGear, sym: usize) -> Vec<u8> {
    let n = gear.bits_per_band();
    (0..n).map(|q| ((sym >> (n - 1 - q)) & 1) as u8).collect()
}

pub fn run(pcm: &[i16], offset_s: f64, dp: &DiagParams) -> Result<(), String> {
    let p = &dp.p;
    let gear = p.gear;
    let loc = locate(pcm, p).ok_or("lead-in not found, cannot align the recording with the sent signal")?;
    let g = gen_pcm(&GenParams {
        gear,
        frames: p.frames,
        seed: p.seed,
        lead_ms: 0,
        tail_ms: 0,
        level_dbfs: dp.level_dbfs,
        repeat: p.repeat,
    });
    let fps = gear.frames_per_superframe();
    let bpf = gear.bits_per_frame();
    let bands = gear.subband_count();
    let bpb = gear.bits_per_band();
    let tpb = gear.tones_per_band();
    let dft = Dft::new();

    let mut slots: Vec<Slot> = Vec::new();
    for i in 0..p.frames {
        let Some((start, _)) = loc.sf_start[i] else { continue };
        let coded = encode_superframe_fec(&frame_data(p.seed, i));
        let il = interleave_384(&coded, fps);
        let seg = if p.repeat == 0 { 0 } else { i / p.repeat };
        let in_seg = if p.repeat == 0 { i } else { i % p.repeat };
        for f in 0..fps {
            let bits = il[f * bpf..(f + 1) * bpf].to_vec();
            let mut on = [false; NBINS];
            on[PILOT_BIN] = true;
            let mut syms = Vec::with_capacity(bands);
            for b in 0..bands {
                let mut sym = 0usize;
                for q in 0..bpb {
                    sym = (sym << 1) | (bits[b * bpb + q] & 1) as usize;
                }
                for &t in gear.codeword(sym) {
                    on[subband_start_bin(gear, b) + t as usize] = true;
                }
                syms.push(sym);
            }
            slots.push(Slot {
                rx_pos: start + (f * FRAME_SAMPLES) as i64,
                tx_pos: g.sf_start[i] + f * FRAME_SAMPLES,
                seg,
                seg_pos: in_seg * fps + f,
                syms,
                bits,
                on,
            });
        }
    }
    if slots.is_empty() {
        return Err("no data frames available for alignment".to_string());
    }

    // 1. Timing check: share of sub-band energy that lands on the transmitted tones.
    let on_frac = |off: i64, stride: usize| -> f64 {
        let (mut acc, mut n) = (0.0f64, 0usize);
        for s in slots.iter().step_by(stride) {
            let e = dft.frame(&loc.pcm, s.rx_pos + off);
            for b in 0..bands {
                let base = subband_start_bin(gear, b);
                let tot: f32 = (0..tpb).map(|t| e[base + t]).sum();
                let onv: f32 = (0..tpb).filter(|&t| s.on[base + t]).map(|t| e[base + t]).sum();
                if tot > 0.0 {
                    acc += (onv / tot) as f64;
                    n += 1;
                }
            }
        }
        if n == 0 {
            0.0
        } else {
            acc / n as f64
        }
    };
    let mut best = (0i64, on_frac(0, 4));
    let at_zero = best.1;
    let mut off = -160i64;
    while off <= 160 {
        let v = on_frac(off, 4);
        if v > best.1 {
            best = (off, v);
        }
        off += 8;
    }
    for off in best.0 - 7..=best.0 + 7 {
        let v = on_frac(off, 4);
        if v > best.1 {
            best = (off, v);
        }
    }
    let toff = best.0;
    let chance = gear.codeword(0).len() as f64 / tpb as f64;

    let rx: Vec<[f32; NBINS]> = slots.iter().map(|s| dft.frame(&loc.pcm, s.rx_pos + toff)).collect();
    let tx: Vec<[f32; NBINS]> = slots.iter().map(|s| dft.frame(&g.pcm, s.tx_pos as i64)).collect();
    let prev_of = |idx: usize| -> Option<&[bool; NBINS]> {
        if idx > 0 && slots[idx - 1].seg == slots[idx].seg && slots[idx - 1].seg_pos + 1 == slots[idx].seg_pos {
            Some(&slots[idx - 1].on)
        } else {
            None
        }
    };

    // 2. Silence floor: up to 5 s before the first preamble, else after the last data frame.
    let up0 = loc.preamble_up.iter().flatten().next().copied().unwrap_or(0);
    let mut sil_range = (up0.saturating_sub(5 * SAMPLE_RATE), up0.saturating_sub(SAMPLE_RATE / 4));
    if sil_range.1 < sil_range.0 + 10 * FRAME_SAMPLES {
        let last = slots.last().map(|s| (s.rx_pos + toff).max(0) as usize).unwrap_or(0) + FRAME_SAMPLES + SAMPLE_RATE / 4;
        sil_range = (last, loc.pcm.len().min(last + 5 * SAMPLE_RATE));
    }
    let mut sil = [0f64; NBINS];
    let mut sil_n = 0usize;
    let mut pos = sil_range.0;
    while pos + FRAME_SAMPLES <= sil_range.1 {
        let e = dft.frame(&loc.pcm, pos as i64);
        for k in 0..NBINS {
            sil[k] += e[k] as f64;
        }
        sil_n += 1;
        pos += FRAME_SAMPLES;
    }
    if sil_n > 0 {
        for v in sil.iter_mut() {
            *v /= sil_n as f64;
        }
    }

    // 3. Per-bin statistics.
    let mut st = vec![BinStat::default(); NBINS];
    for (idx, s) in slots.iter().enumerate() {
        let prev = prev_of(idx);
        for k in 1..NBINS - 1 {
            let r = rx[idx][k] as f64;
            if s.on[k] {
                let b = &mut st[k];
                b.t_on += tx[idx][k] as f64;
                b.r_on += r;
                b.n_on += 1;
                if s.on[k - 1] || s.on[k + 1] {
                    b.r_on_adj += r;
                    b.n_on_adj += 1;
                } else {
                    b.r_on_alone += r;
                    b.n_on_alone += 1;
                }
            } else {
                let nb = s.on[k - 1] || s.on[k + 1];
                let b = &mut st[k];
                b.r_off += r;
                b.n_off += 1;
                match (nb, prev.map(|pv| pv[k])) {
                    (false, Some(false)) => {
                        b.r_iso += r;
                        b.n_iso += 1;
                    }
                    (true, Some(false)) => {
                        b.r_nb += r;
                        b.n_nb += 1;
                    }
                    (false, Some(true)) => {
                        b.r_prev += r;
                        b.n_prev += 1;
                    }
                    _ => {}
                }
            }
        }
    }
    let avg = |s: f64, n: usize| if n == 0 { f64::NAN } else { s / n as f64 };
    let t_on: Vec<f64> = st.iter().map(|b| avg(b.t_on, b.n_on)).collect();
    let r_on: Vec<f64> = st.iter().map(|b| avg(b.r_on, b.n_on)).collect();
    let r_iso: Vec<f64> = st.iter().map(|b| avg(b.r_iso, b.n_iso)).collect();
    // Mean off-state energy over every off occurrence (some codebook positions are never isolated).
    let r_off: Vec<f64> = st.iter().map(|b| avg(b.r_off, b.n_off)).collect();
    let tone: Vec<f64> = (0..NBINS)
        .map(|k| if (r_on[k] - r_off[k]).is_finite() { (r_on[k] - r_off[k]).max(1e-12) } else { f64::NAN })
        .collect();
    for (idx, s) in slots.iter().enumerate() {
        for k in 1..NBINS - 1 {
            if s.on[k] && (rx[idx][k] as f64) < r_off[k] {
                st[k].n_drop += 1;
            }
        }
    }
    // Off-state energy of in-band bins (normalized by the bin's tone level) split by whether an
    // adjacent bin is on now and whether the bin itself was on in the previous subframe.
    let in_band = |k: usize| -> bool {
        (0..bands).any(|b| k >= subband_start_bin(gear, b) && k < subband_start_bin(gear, b) + tpb)
    };
    let mut cls = [(0f64, 0usize, 0usize); 4];
    for (idx, s) in slots.iter().enumerate() {
        let Some(pv) = prev_of(idx) else { continue };
        for k in 1..NBINS - 1 {
            if s.on[k] || !in_band(k) || !tone[k].is_finite() {
                continue;
            }
            let v = rx[idx][k] as f64 / tone[k];
            let c = (s.on[k - 1] || s.on[k + 1]) as usize + 2 * (pv[k] as usize);
            cls[c].0 += v;
            cls[c].1 += 1;
            if v > 0.5 {
                cls[c].2 += 1;
            }
        }
    }
    let cand: Vec<usize> = (0..bands)
        .flat_map(|b| (0..tpb).map(move |t| subband_start_bin(gear, b) + t))
        .collect();
    let last_bin = *cand.iter().max().unwrap();
    let med_tone = median(cand.iter().map(|&k| tone[k]).collect());
    let gain_db: Vec<f64> = (0..NBINS).map(|k| db(tone[k] / t_on[k])).collect();
    let ref_db = median(cand.iter().filter(|&&k| (k as f64) * BIN_HZ < 1500.0).map(|&k| gain_db[k]).collect());

    // 4. Single-tone (preamble chirp) gain on the same grid.
    let mut ch_rx = [0f64; NBINS];
    let mut ch_tx = [0f64; NBINS];
    for (j, up) in loc.preamble_up.iter().enumerate() {
        let (Some(u), Some(&tp)) = (up, g.preamble_start.get(j)) else { continue };
        let mut o = 0usize;
        while o + CORE <= 2 * CHIRP {
            if !(o < CHIRP && o + CORE > CHIRP) {
                let tc = (o + CORE / 2) as f64;
                let f = if o < CHIRP {
                    600.0 + 1300.0 * tc / CHIRP as f64
                } else {
                    1900.0 - 1300.0 * (tc - CHIRP as f64) / CHIRP as f64
                };
                let c = (f / BIN_HZ).round() as usize;
                let er = dft.core(&loc.pcm, (*u + o) as i64);
                let et = dft.core(&g.pcm, (tp + o) as i64);
                for k in c - 3..=c + 3 {
                    ch_rx[c] += er[k] as f64 - sil[k];
                    ch_tx[c] += et[k] as f64;
                }
            }
            o += 64;
        }
    }

    // 5. Decisions: current rule (raw energies), oracle per-bin equalization, oracle EQ + floor removal.
    let mut ser = [[0usize; 3]; 16];
    let mut ber = [[0usize; 3]; 16];
    let mut band_n = [0usize; 16];
    let mut errs_per_slot = vec![0usize; slots.len()];
    let (mut n_err, mut c_weak, mut c_strong, mut c_leak, mut c_smear, mut c_unexpl, mut c_fixed) = (0, 0, 0, 0, 0, 0, 0);
    let mut band_cause = vec![[0usize; 5]; bands];
    let (mut base_off, mut base_adj, mut base_prev) = (0usize, 0usize, 0usize);
    let (mut drop_n, mut drop_10db, mut on_groups) = (0usize, 0usize, 0usize);
    for (idx, s) in slots.iter().enumerate() {
        let prev = prev_of(idx);
        let e = &rx[idx];
        for b in 0..bands {
            let base = subband_start_bin(gear, b);
            let truth = s.syms[b];
            for k in base..base + tpb {
                if !s.on[k] {
                    base_off += 1;
                    base_adj += (s.on[k - 1] || s.on[k + 1]) as usize;
                    base_prev += prev.map(|pv| pv[k] as usize).unwrap_or(0);
                }
            }
            let d = [
                decide(gear, base, |k| e[k] as f64),
                decide(gear, base, |k| e[k] as f64 / tone[k]),
                decide(gear, base, |k| (e[k] as f64 - r_off[k]) / tone[k]),
            ];
            band_n[b] += 1;
            let tb = &s.bits[b * bpb..(b + 1) * bpb];
            for r in 0..3 {
                if d[r] != truth {
                    ser[b][r] += 1;
                }
                ber[b][r] += sym_bits(gear, d[r]).iter().zip(tb).filter(|(x, y)| x != y).count();
            }
            // On-tone dropout inside one sub-band symbol (gain-normalized).
            let ons: Vec<f64> = gear
                .codeword(truth)
                .iter()
                .map(|&t| {
                    let k = base + t as usize;
                    (e[k] as f64 - r_off[k]) / tone[k]
                })
                .collect();
            if ons.len() > 1 {
                on_groups += 1;
                let mx = ons.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
                let mn = ons.iter().cloned().fold(f64::INFINITY, f64::min);
                if mn < 0.1 * mx {
                    drop_10db += 1;
                }
                if mn < 0.0 {
                    drop_n += 1;
                }
            }
            if d[0] == truth {
                continue;
            }
            n_err += 1;
            errs_per_slot[idx] += 1;
            let tset: Vec<usize> = gear.codeword(truth).iter().map(|&t| base + t as usize).collect();
            let dset: Vec<usize> = gear.codeword(d[0]).iter().map(|&t| base + t as usize).collect();
            let missed: Vec<usize> = tset.iter().copied().filter(|k| !dset.contains(k)).collect();
            let falses: Vec<usize> = dset.iter().copied().filter(|k| !tset.contains(k)).collect();
            let weak = missed.iter().any(|&k| (e[k] as f64) < r_off[k]);
            let strong = falses.iter().any(|&k| (e[k] as f64) > 0.5 * r_on[k]);
            let leak = falses.iter().any(|&k| s.on[k - 1] || s.on[k + 1]);
            let smear = falses.iter().any(|&k| prev.map(|pv| pv[k]).unwrap_or(false));
            if weak {
                c_weak += 1;
                band_cause[b][0] += 1;
            }
            if strong {
                c_strong += 1;
                band_cause[b][1] += 1;
            }
            if leak {
                c_leak += 1;
                band_cause[b][2] += 1;
            }
            if smear {
                c_smear += 1;
                band_cause[b][3] += 1;
            }
            if strong && !leak && !smear {
                c_unexpl += 1;
            }
            if d[1] == truth {
                c_fixed += 1;
                band_cause[b][4] += 1;
            }
        }
    }

    // 6. Gain over time (on-tone rx/tx energy per subframe).
    let split = 2000.0;
    let mut gl = Vec::with_capacity(slots.len());
    let mut gh = Vec::with_capacity(slots.len());
    let mut gp = Vec::with_capacity(slots.len());
    let mut lin_l = Vec::with_capacity(slots.len());
    for (idx, s) in slots.iter().enumerate() {
        let (mut rl, mut tl, mut rh, mut th) = (0f64, 0f64, 0f64, 0f64);
        for &k in &cand {
            if s.on[k] {
                if (k as f64) * BIN_HZ < split {
                    rl += rx[idx][k] as f64;
                    tl += tx[idx][k] as f64;
                } else {
                    rh += rx[idx][k] as f64;
                    th += tx[idx][k] as f64;
                }
            }
        }
        lin_l.push((rl, tl));
        gl.push(if tl > 0.0 { db(rl / tl) } else { f64::NAN });
        gh.push(if th > 0.0 { db(rh / th) } else { f64::NAN });
        gp.push(db(rx[idx][PILOT_BIN] as f64 / tx[idx][PILOT_BIN].max(1e-12) as f64));
    }
    let win_db: Vec<f64> = lin_l
        .chunks(HALF_SEC)
        .filter(|c| c.len() == HALF_SEC)
        .map(|c| {
            let (r, t) = c.iter().fold((0.0f64, 0.0f64), |a, x| (a.0 + x.0, a.1 + x.1));
            db(r / t)
        })
        .collect();

    // ---------------------------------------------------------------- report
    println!("== Diagnosis: gear {}, {} frames, aligned {} 20 ms subframes ==", crate::gear_label(gear), p.frames, slots.len());
    println!(
        "clock offset {}; silence floor sampled {:.2}–{:.2} s ({} subframes)",
        loc.clock_ppm.map(|v| format!("{:+.0} ppm (corrected)", v)).unwrap_or_else(|| "unknown".to_string()),
        offset_s + sil_range.0 as f64 / SAMPLE_RATE as f64,
        offset_s + sil_range.1 as f64 / SAMPLE_RATE as f64,
        sil_n
    );
    println!(
        "[Time alignment] share of subband energy landing on the correct tone: at shift 0 samples {:.3}, at best shift {:+} samples {:.3} (sender 1.000, random guess {:.3})",
        at_zero, toff, best.1, chance
    );
    let sil_zero = sil_n > 0 && sil.iter().all(|&v| v == 0.0);
    if sil_zero {
        println!("[Silence] the recording before the lead-in is digital zero (DTX/silence suppression), so the noise floor cannot be measured from silence; all noise floors below use the energy of the in-call 'off' bins");
    }
    println!("[Per-bin gain] gain = (received on-tone energy - off-bin energy) / sent energy; relative = minus the 500–1500 Hz median {:.1} dB", ref_db);
    println!("  Bin Freq Hz Gain dB  Rel dB Tone dB   Off dB Sil dB Cont dB  OnDrop % Leak% Tail%   AdjOn dB");
    for k in PILOT_BIN..=(last_bin + 2).min(NBINS - 2) {
        let b = &st[k];
        let chirp = if ch_tx[k] > 0.0 {
            format!("{:7.1}", db(ch_rx[k].max(1e-20) / ch_tx[k]))
        } else {
            "      -".to_string()
        };
        let off_db = db(r_off[k] / med_tone);
        let sil_db = if sil_n > 0 { db(sil[k] / med_tone) } else { f64::NAN };
        if b.n_on == 0 || k == PILOT_BIN {
            println!(
                "  {:3} {:7.1}       -       - {} {:8.1} {:6.1}       -         -     -     -          -{}",
                k,
                k as f64 * BIN_HZ,
                chirp,
                off_db,
                sil_db,
                if k == PILOT_BIN { format!("  (pilot, gain {:.1} dB)", spread(&gp).0) } else { String::new() }
            );
            continue;
        }
        let fmt_pct = |v: f64| if v.is_finite() { format!("{:5.0}", v) } else { "    -".to_string() };
        let leak = fmt_pct(100.0 * (avg(b.r_nb, b.n_nb) - r_iso[k]) / tone[k]);
        let smear = fmt_pct(100.0 * (avg(b.r_prev, b.n_prev) - r_iso[k]) / tone[k]);
        let adj = db(avg(b.r_on_adj, b.n_on_adj) / avg(b.r_on_alone, b.n_on_alone));
        println!(
            "  {:3} {:7.1} {:7.1} {:7.1} {} {:8.1} {:6.1} {:7.1} {:9.1} {} {} {:10.1}",
            k,
            k as f64 * BIN_HZ,
            gain_db[k],
            gain_db[k] - ref_db,
            chirp,
            off_db,
            sil_db,
            db(r_on[k] / r_off[k]),
            pct(b.n_drop, b.n_on),
            leak,
            smear,
            adj
        );
    }
    println!("  (off bin and silence are relative to the median received level of all tone bins; on-tone drop = received energy for a bin sent on is below that bin's average when off; leak/tail = extra energy when a neighbour is on or the previous frame is on, as % of tone level)");
    let mut line = String::from("[Band noise floor] in-call off-bin energy per 500 Hz (dB relative to the median tone level): ");
    for c in 0..16 {
        let ks: Vec<usize> = (c * 8..c * 8 + 8).filter(|&k| k > 0 && k < NBINS - 1 && !r_off[k].is_nan()).collect();
        if ks.is_empty() {
            continue;
        }
        let v = ks.iter().map(|&k| r_off[k]).sum::<f64>() / ks.len() as f64;
        line += &format!("{:.1}k:{:.0} ", c as f64 * 0.5, db(v / med_tone));
    }
    println!("{}", line);
    let gap: Vec<f64> = (10..=30)
        .filter(|&k| ch_tx[k] > 0.0 && st[k].n_on > 0 && gain_db[k].is_finite())
        .map(|k| gain_db[k] - db(ch_rx[k].max(1e-20) / ch_tx[k]))
        .collect();
    println!(
        "[Multi-tone vs single tone] same bin at 600–1900 Hz: data multi-tone gain - lead-in single-tone gain averages {:+.1} dB ({} bins)",
        gap.iter().sum::<f64>() / gap.len().max(1) as f64,
        gap.len()
    );
    let cdb = |c: usize| db((cls[c].0 / cls[c].1.max(1) as f64) / (cls[0].0 / cls[0].1.max(1) as f64));
    println!(
        "[Leak/tail] mean in-band off-bin energy (relative to both neighbours off and previous frame off): a neighbour on {:+.1} dB, previous frame on {:+.1} dB, both {:+.1} dB;",
        cdb(1), cdb(2), cdb(3)
    );
    println!(
        "           probability that off-bin energy exceeds half the bin's tone level: both neighbours off and previous frame off {:.1}%, neighbour on {:.1}%, previous frame on {:.1}%, both {:.1}%",
        pct(cls[0].2, cls[0].1), pct(cls[1].2, cls[1].1), pct(cls[2].2, cls[2].1), pct(cls[3].2, cls[3].1)
    );
    let adj_all: Vec<f64> = cand
        .iter()
        .filter(|&&k| st[k].n_on_adj > 0 && st[k].n_on_alone > 0)
        .map(|&k| db(avg(st[k].r_on_adj, st[k].n_on_adj) / avg(st[k].r_on_alone, st[k].n_on_alone)))
        .collect();
    println!(
        "[Same-band multi-tone] tone energy change when an adjacent bin sounds at the same time averages {:+.1} dB; weakest on-tone in a subband is 10 dB or more below the strongest {:.1}%, weakest on-tone below the off bin {:.1}%",
        adj_all.iter().sum::<f64>() / adj_all.len().max(1) as f64,
        pct(drop_10db, on_groups),
        pct(drop_n, on_groups)
    );
    let (ml, sl, l5, l95) = spread(&gl);
    let (mh, sh, h5, h95) = spread(&gh);
    let (mw, sw, w5, w95) = spread(&win_db);
    println!(
        "[Gain fluctuation] every 20 ms low band (<2k) mean {:.1} dB std {:.1} dB (5%–95%: {:.1}…{:.1}), adjacent-frame correlation {:.2}",
        ml, sl, l5, l95, lag1(&gl)
    );
    println!(
        "           every 20 ms high band (≥2k) mean {:.1} dB std {:.1} dB (5%–95%: {:.1}…{:.1}); low-high difference {:.1} dB",
        mh, sh, h5, h95, mh - ml
    );
    println!("           every 0.5 s low band mean {:.1} dB std {:.1} dB (5%–95%: {:.1}…{:.1})", mw, sw, w5, w95);
    let max_pos = slots.iter().map(|s| s.seg_pos).max().unwrap_or(0);
    let mut line = String::from("           time since lead-in (every 0.5 s) low-band gain / symbol error rate: ");
    for bkt in 0..=(max_pos / HALF_SEC) {
        let ids: Vec<usize> = (0..slots.len()).filter(|&i| slots[i].seg_pos / HALF_SEC == bkt).collect();
        if ids.is_empty() {
            continue;
        }
        let (r, t) = ids.iter().fold((0.0f64, 0.0f64), |a, &i| (a.0 + lin_l[i].0, a.1 + lin_l[i].1));
        let e: usize = ids.iter().map(|&i| errs_per_slot[i]).sum();
        line += &format!("{:.1}s:{:.1}dB/{:.0}% ", bkt as f64 * 0.5, db(r / t), pct(e, ids.len() * bands));
    }
    println!("{}", line);
    let mut order: Vec<usize> = (0..slots.len()).filter(|&i| gl[i].is_finite()).collect();
    order.sort_by(|&a, &b| gl[a].total_cmp(&gl[b]));
    let q = order.len() / 4;
    if q > 0 {
        let lo: usize = order[..q].iter().map(|&i| errs_per_slot[i]).sum();
        let hi: usize = order[order.len() - q..].iter().map(|&i| errs_per_slot[i]).sum();
        println!(
            "           symbol error rate of the lowest-gain quarter of subframes {:.1}%, highest quarter {:.1}%",
            pct(lo, q * bands),
            pct(hi, q * bands)
        );
    }
    println!("[Per subband] symbol and bit error rates for current decision / ideal equalization / equalization + noise floor subtraction");
    let (mut tot_n, mut tot_s, mut tot_b) = (0usize, [0usize; 3], [0usize; 3]);
    for b in 0..bands {
        let lo = subband_start_bin(gear, b);
        let hi = lo + tpb - 1;
        let con: Vec<f64> = (lo..=hi).map(|k| db(r_on[k] / r_off[k])).collect();
        let drops: usize = (lo..=hi).map(|k| st[k].n_drop).sum();
        let ons: usize = (lo..=hi).map(|k| st[k].n_on).sum();
        println!(
            "  band{:2} {:6.1}–{:6.1} Hz: SER {:5.1}% / {:5.1}% / {:5.1}%  BER {:5.1}% / {:5.1}% / {:5.1}%  on/off contrast {:5.1} dB on-tone drop {:4.1}%",
            b,
            lo as f64 * BIN_HZ,
            hi as f64 * BIN_HZ,
            pct(ser[b][0], band_n[b]),
            pct(ser[b][1], band_n[b]),
            pct(ser[b][2], band_n[b]),
            pct(ber[b][0], band_n[b] * bpb),
            pct(ber[b][1], band_n[b] * bpb),
            pct(ber[b][2], band_n[b] * bpb),
            con.iter().sum::<f64>() / con.len() as f64,
            pct(drops, ons)
        );
        tot_n += band_n[b];
        for r in 0..3 {
            tot_s[r] += ser[b][r];
            tot_b[r] += ber[b][r];
        }
    }
    println!(
        "  total: SER {:.1}% / {:.1}% / {:.1}%  BER {:.1}% / {:.1}% / {:.1}%",
        pct(tot_s[0], tot_n),
        pct(tot_s[1], tot_n),
        pct(tot_s[2], tot_n),
        pct(tot_b[0], tot_n * bpb),
        pct(tot_b[1], tot_n * bpb),
        pct(tot_b[2], tot_n * bpb)
    );
    println!("[Error causes] the current decision has {} symbol errors (categories may overlap):", n_err);
    println!("  missed tone: received energy below the bin off average           {:5.1}%", pct(c_weak, n_err));
    println!("  wrongly chosen tone has on-level energy (> −3 dB)                {:5.1}%", pct(c_strong, n_err));
    println!(
        "  wrongly chosen tone is next to a true on-tone                    {:5.1}% (baseline: {:.1}% of in-band off bins are next to an on-tone)",
        pct(c_leak, n_err),
        pct(base_adj, base_off)
    );
    println!(
        "  wrongly chosen tone was on in the previous frame                 {:5.1}% (baseline: {:.1}% of in-band off bins were on in the previous frame)",
        pct(c_smear, n_err),
        pct(base_prev, base_off)
    );
    println!("  strong wrong tone, neither leak nor tail (distortion/intermod)   {:5.1}%", pct(c_unexpl, n_err));
    println!("  fixable by ideal equalization (frequency tilt)                   {:5.1}%", pct(c_fixed, n_err));
    for b in 0..bands {
        let e = ser[b][0];
        println!(
            "  band{:2}: missed tone gone {:4.0}% strong wrong tone {:4.0}% next to on-tone {:4.0}% prev frame on {:4.0}% equalization fix {:4.0}%",
            b,
            pct(band_cause[b][0], e),
            pct(band_cause[b][1], e),
            pct(band_cause[b][2], e),
            pct(band_cause[b][3], e),
            pct(band_cause[b][4], e)
        );
    }
    Ok(())
}

