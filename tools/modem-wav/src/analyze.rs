//! Recording analysis: preamble search, sync, demodulation, FEC decode, comparison with known data.

use crate::dsp::{peak_dbfs, resample_step, rms_dbfs, to_f32, to_i16};
use crate::sig::frame_data;
use aegiscall_modem::{
    decode_superframe_fec_soft, deinterleave_384_soft, detect_preamble_raw, encode_superframe_fec,
    interleave_384, FormantDemodulator, ModemGear, FRAME_SAMPLES, SAMPLE_RATE,
    TOTAL_PREAMBLE_SAMPLES,
};

const CH_L: usize = 1920; // up/down chirp length (120 ms), mirrors the preamble definition
const THRESH: f32 = 0.30; // detect_preamble accepts a chirp only above this normalized correlation

pub struct Params {
    pub gear: ModemGear,
    pub frames: usize,
    pub seed: u64,
    pub repeat: usize,
}

impl Params {
    fn sf_samples(&self) -> usize {
        self.gear.frames_per_superframe() * FRAME_SAMPLES
    }
    fn segments(&self) -> usize {
        if self.repeat == 0 {
            1
        } else {
            (self.frames + self.repeat - 1) / self.repeat
        }
    }
    fn spacing(&self) -> usize {
        TOTAL_PREAMBLE_SAMPLES + self.repeat * self.sf_samples()
    }
}

enum Chirp {
    Legacy { c: Vec<f32>, s: Vec<f32> },
    VowelGlide(aegiscall_modem::VowelGlideCorrelator),
}

impl Chirp {
    fn new() -> Self {
        let slope = (1900.0 - 600.0) / (CH_L as f64 / SAMPLE_RATE as f64);
        let mut c = Vec::with_capacity(CH_L);
        let mut s = Vec::with_capacity(CH_L);
        for n in 0..CH_L {
            let t = n as f64 / SAMPLE_RATE as f64;
            let ph = 2.0 * std::f64::consts::PI * (600.0 * t + 0.5 * slope * t * t);
            let (sn, cs) = ph.sin_cos();
            c.push(cs as f32);
            s.push(sn as f32);
        }
        Chirp::Legacy { c, s }
    }

    fn for_gear(gear: ModemGear) -> Self {
        if gear == ModemGear::Speech300 {
            Chirp::VowelGlide(aegiscall_modem::VowelGlideCorrelator::new(true))
        } else {
            Self::new()
        }
    }
}

fn score_at(sig: &[f32], ch: &Chirp, idx: usize) -> f32 {
    if idx + CH_L > sig.len() {
        return 0.0;
    }
    match ch {
        Chirp::Legacy { c, s } => {
            let win = &sig[idx..idx + CH_L];
            let (mut re, mut im, mut e) = (0.0f32, 0.0f32, 1e-9f32);
            for n in (0..CH_L).step_by(2) {
                let x = win[n];
                e += x * x;
                re += x * c[n];
                im += x * s[n];
            }
            ((re * re + im * im) / (e * (CH_L as f32 / 4.0))).sqrt()
        }
        Chirp::VowelGlide(vg) => vg.score_at(sig, idx),
    }
}

/// Coarse (step 8) then fine (+/-10) search for the best up-chirp start in [lo, hi].
fn scan_range(sig: &[f32], ch: &Chirp, lo: usize, hi: usize) -> (usize, f32) {
    let hi = hi.min(sig.len().saturating_sub(CH_L));
    if lo > hi {
        return (lo, 0.0);
    }
    let mut best = (lo, 0.0f32);
    let mut idx = lo;
    while idx <= hi {
        let s = score_at(sig, ch, idx);
        if s > best.1 {
            best = (idx, s);
        }
        idx += 8;
    }
    let fs = best.0.saturating_sub(10).max(lo);
    let fe = (best.0 + 10).min(hi);
    for p in fs..=fe {
        let s = score_at(sig, ch, p);
        if s > best.1 {
            best = (p, s);
        }
    }
    best
}

#[derive(Clone)]
struct SegSync {
    up: usize,
    score: f32,
    payload_start: usize,
    trailer_ok: bool,
    gear_match: bool,
    cfo: f32,
}

/// Earliest strong up-chirp (start of a preamble) in `sig`: sample position and correlation.
pub fn find_first_chirp(sig: &[f32]) -> Option<(usize, f32)> {
    if sig.len() < CH_L {
        return None;
    }
    let ch = Chirp::new();
    let scores: Vec<f32> = (0..=(sig.len() - CH_L) / 8).map(|i| score_at(sig, &ch, i * 8)).collect();
    let gmax = scores.iter().cloned().fold(0.0f32, f32::max);
    if gmax < THRESH {
        return None;
    }
    let thr = THRESH.max(0.4 * gmax);
    let first = scores.iter().position(|&s| s >= thr)?;
    let (up, s) = scan_range(sig, &ch, first * 8, first * 8 + 240);
    if s < THRESH {
        None
    } else {
        Some((up, s))
    }
}

#[derive(Clone)]
struct SyncResult {
    segs: Vec<Option<SegSync>>,
    max_corr: f32,
    max_pos: usize,
    /// Time-axis ratio (recorded / transmitted) estimated from repeated preambles; 1.0 if unknown.
    ratio: f64,
    ratio_known: bool,
}

impl SyncResult {
    fn found(&self) -> usize {
        self.segs.iter().flatten().count()
    }
}

fn lock_segment(pcm: &[i16], up: usize, score: f32, gear: ModemGear) -> SegSync {
    let w0 = up.saturating_sub(300);
    let w1 = (up + TOTAL_PREAMBLE_SAMPLES + 300).min(pcm.len());
    match detect_preamble_raw(&pcm[w0..w1]) {
        Some(det) => SegSync {
            up,
            score,
            payload_start: w0 + det.payload_start_sample,
            trailer_ok: true,
            gear_match: det.announced_gear() == Some(gear),
            cfo: det.estimated_cfo_hz,
        },
        None => SegSync {
            up,
            score,
            payload_start: up + TOTAL_PREAMBLE_SAMPLES,
            trailer_ok: false,
            gear_match: false,
            cfo: 0.0,
        },
    }
}

fn sync_pass(sig: &[f32], pcm: &[i16], p: &Params) -> SyncResult {
    let m = p.segments();
    let mut res = SyncResult { segs: vec![None; m], max_corr: 0.0, max_pos: 0, ratio: 1.0, ratio_known: false };
    if sig.len() < CH_L {
        return res;
    }
    let ch = Chirp::for_gear(p.gear);
    let scores: Vec<f32> = (0..=(sig.len() - CH_L) / 8).map(|i| score_at(sig, &ch, i * 8)).collect();
    let (gi, gmax) = scores
        .iter()
        .enumerate()
        .fold((0usize, 0.0f32), |a, (i, &s)| if s > a.1 { (i, s) } else { a });
    let (mp, ms) = scan_range(sig, &ch, (gi * 8).saturating_sub(8), gi * 8 + 8);
    res.max_corr = ms.max(gmax);
    res.max_pos = mp;
    if res.max_corr < THRESH {
        return res;
    }
    // The first preamble is the earliest strong peak (later ones may be stronger).
    let thr = THRESH.max(0.4 * gmax);
    let first = scores.iter().position(|&s| s >= thr).unwrap_or(gi);
    let (up0, s0) = scan_range(sig, &ch, first * 8, first * 8 + 240);
    if s0 < THRESH {
        return res;
    }
    let mut ups: Vec<Option<(usize, f32)>> = vec![None; m];
    ups[0] = Some((up0, s0));
    let spacing = p.spacing();
    let mut ratio_est = 1.0f64;
    let tol = ((spacing as f64) * 0.01).max(400.0) as usize;
    for j in 1..m {
        let expected = up0 as f64 + j as f64 * spacing as f64 * ratio_est;
        let lo = (expected - tol as f64).max(0.0) as usize;
        let hi = (expected + tol as f64) as usize;
        if lo + CH_L > sig.len() {
            continue;
        }
        let (idx, sc) = scan_range(sig, &ch, lo, hi);
        if sc >= THRESH {
            ups[j] = Some((idx, sc));
            ratio_est = (idx as f64 - up0 as f64) / (j as f64 * spacing as f64);
        }
    }
    for j in 0..m {
        if let Some((u, sc)) = ups[j] {
            res.segs[j] = Some(lock_segment(pcm, u, sc, p.gear));
        }
    }
    let found: Vec<(usize, usize)> = res
        .segs
        .iter()
        .enumerate()
        .filter_map(|(j, s)| s.as_ref().map(|s| (j, s.payload_start)))
        .collect();
    if found.len() >= 2 {
        let (ja, pa) = found[0];
        let (jb, pb) = found[found.len() - 1];
        let r = (pb as f64 - pa as f64) / ((jb - ja) as f64 * spacing as f64);
        res.ratio = r.clamp(0.98, 1.02);
        res.ratio_known = true;
    }
    res
}

pub struct Report {
    pub gear: ModemGear,
    pub frames_total: usize,
    pub input_rate: u32,
    pub channels: u16,
    pub length_s: f64,
    pub peak_dbfs: f64,
    pub rms_overall_dbfs: f64,
    pub rms_active_dbfs: Option<f64>,
    pub preamble_found: bool,
    pub preamble_pos_s: Option<f64>,
    pub preamble_score: f32,
    pub max_corr: f32,
    pub max_corr_pos_s: f64,
    pub trailer_ok: bool,
    pub gear_match: bool,
    pub cfo_hz: f32,
    pub preambles_found: usize,
    pub preambles_expected: usize,
    pub frames_ok: usize,
    pub frame_error_rate: f64,
    pub ber_prefec: Option<f64>,
    pub erased_bit_fraction: Option<f64>,
    pub goodput_bps: f64,
    pub nominal_net_bps: f64,
    pub longest_error_run: usize,
    pub errors_per_10: Vec<usize>,
    pub extrapolated_frames: usize,
    pub clock_ppm: Option<f64>,
    pub clock_corrected: bool,
    pub demod_erased_frames: u32,
    pub demod_total_frames: u32,
    /// Analyzed part of the input in seconds (None = whole file); positions are reported in file time.
    pub range: Option<(f64, f64)>,
}

struct Decoded {
    ok: Vec<bool>,
    bit_errors: usize,
    bits_counted: usize,
    bits_erased: usize,
    demod_erased: u32,
    demod_total: u32,
}

/// Start sample and preamble CFO of every superframe; the second value counts superframes whose
/// own preamble was missing (position extrapolated from the nearest found preamble).
fn frame_starts(sync: &SyncResult, p: &Params) -> (Vec<Option<(i64, f32)>>, usize) {
    let sf = p.sf_samples();
    let spacing = p.spacing() as f64;
    let m = p.segments();
    let nearest = |j: usize| -> Option<usize> {
        (0..m).filter(|&k| sync.segs[k].is_some()).min_by_key(|&k| (k as isize - j as isize).abs())
    };
    let mut out = Vec::with_capacity(p.frames);
    let mut extrapolated = 0;
    for i in 0..p.frames {
        let j = if p.repeat == 0 { 0 } else { i / p.repeat };
        let in_seg = (if p.repeat == 0 { i } else { i % p.repeat }) as f64;
        match nearest(j) {
            None => out.push(None),
            Some(k) => {
                let s = sync.segs[k].as_ref().unwrap();
                let start = if k == j {
                    s.payload_start as f64 + in_seg * sf as f64 * sync.ratio
                } else {
                    extrapolated += 1;
                    let off = (j as f64 - k as f64) * spacing + in_seg * sf as f64;
                    s.payload_start as f64 + off * sync.ratio
                };
                out.push(Some((start.round() as i64, s.cfo)));
            }
        }
    }
    (out, extrapolated)
}

/// Recording aligned to the known transmission (shared by analyze and diagnose).
pub struct Located {
    /// Recording after clock correction (unchanged when no correction was needed).
    pub pcm: Vec<i16>,
    /// First sample and preamble CFO of every superframe in `pcm`.
    pub sf_start: Vec<Option<(i64, f32)>>,
    /// Up-chirp start of every expected preamble in `pcm` (None when not found).
    pub preamble_up: Vec<Option<usize>>,
    pub clock_ppm: Option<f64>,
}

/// Undo the recording clock offset estimated from repeated preambles, then re-sync.
fn correct_clock(pcm: &[i16], sig: &[f32], s1: &SyncResult, p: &Params) -> (Vec<i16>, SyncResult, bool) {
    if s1.ratio_known && (s1.ratio - 1.0).abs() > 1e-4 {
        let out_len = (sig.len() as f64 / s1.ratio).round() as usize;
        let corr = to_i16(&resample_step(sig, s1.ratio, out_len));
        let s2 = sync_pass(&to_f32(&corr), &corr, p);
        if s2.segs[0].is_some() {
            return (corr, s2, true);
        }
    }
    (pcm.to_vec(), s1.clone(), false)
}

pub fn locate(pcm: &[i16], p: &Params) -> Option<Located> {
    let sig = to_f32(pcm);
    let s1 = sync_pass(&sig, pcm, p);
    s1.segs[0].as_ref()?;
    let (cpcm, s, _) = correct_clock(pcm, &sig, &s1, p);
    let (sf_start, _) = frame_starts(&s, p);
    let preamble_up = s.segs.iter().map(|g| g.as_ref().map(|g| g.up)).collect();
    Some(Located {
        pcm: cpcm,
        sf_start,
        preamble_up,
        clock_ppm: if s1.ratio_known { Some((s1.ratio - 1.0) * 1e6) } else { None },
    })
}

fn decode_all(pcm: &[i16], starts: &[Option<(i64, f32)>], p: &Params) -> Decoded {
    let gear = p.gear;
    let fps = gear.frames_per_superframe();
    let sf = p.sf_samples();
    let m = p.segments();
    let mut demods: Vec<Option<FormantDemodulator>> = (0..m).map(|_| None).collect();
    let mut d = Decoded { ok: Vec::new(), bit_errors: 0, bits_counted: 0, bits_erased: 0, demod_erased: 0, demod_total: 0 };
    for i in 0..p.frames {
        let expected = frame_data(p.seed, i);
        let coded = encode_superframe_fec(&expected);
        let tx_bits = interleave_384(&coded, fps);
        let j = if p.repeat == 0 { 0 } else { i / p.repeat };
        let (start, cfo) = match starts[i] {
            None => {
                d.ok.push(false);
                continue;
            }
            Some(v) => v,
        };
        let mut window = vec![0i16; sf];
        for (w, slot) in window.iter_mut().enumerate() {
            let idx = start + w as i64;
            if idx >= 0 && (idx as usize) < pcm.len() {
                *slot = pcm[idx as usize];
            }
        }
        let demod = demods[j].get_or_insert_with(|| FormantDemodulator::new(gear, cfo));
        let llrs = demod.demodulate_superframe(&window);
        for (k, &l) in llrs.iter().enumerate() {
            if l == 0.0 {
                d.bits_erased += 1;
            } else {
                d.bits_counted += 1;
                if (l > 0.0) as u8 != tx_bits[k] {
                    d.bit_errors += 1;
                }
            }
        }
        let decoded = decode_superframe_fec_soft(&deinterleave_384_soft(&llrs, fps));
        d.ok.push(decoded == expected);
    }
    for dm in demods.iter().flatten() {
        let mt = dm.metrics();
        d.demod_erased += mt.erased_frames_count;
        d.demod_total += mt.total_frames_count;
    }
    d
}

pub fn analyze_pcm(pcm: &[i16], in_rate: u32, channels: u16, p: &Params) -> Report {
    let sig = to_f32(pcm);
    let s1 = sync_pass(&sig, pcm, p);
    let found = s1.segs[0].is_some();
    let m = p.segments();
    let sf = p.sf_samples();
    let nominal_net = p.gear.net_bps() as f64;

    let mut rep = Report {
        gear: p.gear,
        frames_total: p.frames,
        input_rate: in_rate,
        channels,
        length_s: pcm.len() as f64 / SAMPLE_RATE as f64,
        peak_dbfs: peak_dbfs(pcm),
        rms_overall_dbfs: rms_dbfs(pcm),
        rms_active_dbfs: None,
        preamble_found: found,
        preamble_pos_s: None,
        preamble_score: 0.0,
        max_corr: s1.max_corr,
        max_corr_pos_s: s1.max_pos as f64 / SAMPLE_RATE as f64,
        trailer_ok: false,
        gear_match: false,
        cfo_hz: 0.0,
        preambles_found: s1.found(),
        preambles_expected: m,
        frames_ok: 0,
        frame_error_rate: 1.0,
        ber_prefec: None,
        erased_bit_fraction: None,
        goodput_bps: 0.0,
        nominal_net_bps: nominal_net,
        longest_error_run: p.frames,
        errors_per_10: Vec::new(),
        extrapolated_frames: 0,
        clock_ppm: if s1.ratio_known { Some((s1.ratio - 1.0) * 1e6) } else { None },
        clock_corrected: false,
        demod_erased_frames: 0,
        demod_total_frames: 0,
        range: None,
    };

    let ok_flags: Vec<bool>;
    if found {
        let first = s1.segs[0].as_ref().unwrap();
        rep.preamble_pos_s = Some(first.up as f64 / SAMPLE_RATE as f64);
        rep.preamble_score = first.score;
        rep.trailer_ok = first.trailer_ok;
        rep.gear_match = first.gear_match;
        rep.cfo_hz = first.cfo;
        let end = (first.up + TOTAL_PREAMBLE_SAMPLES * m + p.frames * sf).min(pcm.len());
        rep.rms_active_dbfs = Some(rms_dbfs(&pcm[first.up.min(end)..end]));

        // With repeated preambles the recording clock can be estimated; undo it and re-sync.
        let (used_pcm, used_sync, corrected) = correct_clock(pcm, &sig, &s1, p);
        rep.clock_corrected = corrected;
        let (starts, extrapolated) = frame_starts(&used_sync, p);
        let d = decode_all(&used_pcm, &starts, p);
        rep.extrapolated_frames = extrapolated;
        rep.demod_erased_frames = d.demod_erased;
        rep.demod_total_frames = d.demod_total;
        let total_bits = d.bits_counted + d.bits_erased;
        if d.bits_counted > 0 {
            rep.ber_prefec = Some(d.bit_errors as f64 / d.bits_counted as f64);
        }
        if total_bits > 0 {
            rep.erased_bit_fraction = Some(d.bits_erased as f64 / total_bits as f64);
        }
        ok_flags = d.ok;
    } else {
        ok_flags = vec![false; p.frames];
    }

    rep.frames_ok = ok_flags.iter().filter(|&&b| b).count();
    rep.frame_error_rate = 1.0 - rep.frames_ok as f64 / p.frames as f64;
    let airtime = (p.frames * sf) as f64 / SAMPLE_RATE as f64;
    rep.goodput_bps = rep.frames_ok as f64 * 184.0 / airtime;
    let (mut run, mut longest) = (0usize, 0usize);
    for &ok in &ok_flags {
        if ok {
            run = 0;
        } else {
            run += 1;
            longest = longest.max(run);
        }
    }
    rep.longest_error_run = longest;
    rep.errors_per_10 = ok_flags.chunks(10).map(|c| c.iter().filter(|&&b| !b).count()).collect();
    rep
}

fn gear_name(g: ModemGear) -> &'static str {
    crate::gear_label(g)
}

impl Report {
    fn offset_s(&self) -> f64 {
        self.range.map(|r| r.0).unwrap_or(0.0)
    }
}

pub fn print_text(r: &Report) {
    println!("Gear {} (nominal net rate {:.0} bps), frames {}", gear_name(r.gear), r.nominal_net_bps, r.frames_total);
    if let Some((s, e)) = r.range {
        println!("Analysis range: {:.2}–{:.2} s (all positions below are whole-file times)", s, e);
    }
    println!(
        "Input: {} Hz, {} channels (left used), length {:.2} s; peak {:.1} dBFS, whole-file RMS {:.1} dBFS",
        r.input_rate, r.channels, r.length_s, r.peak_dbfs, r.rms_overall_dbfs
    );
    if r.preamble_found {
        println!(
            "Lead-in: found, position {:.3} s (correlation {:.2}, threshold {:.2}); found {}/{} lead-ins",
            r.preamble_pos_s.unwrap_or(0.0) + r.offset_s(), r.preamble_score, THRESH, r.preambles_found, r.preambles_expected
        );
        println!(
            "Lead-in trailer: {}; gear {}; lead-in estimated frequency offset {:+.1} Hz",
            if r.trailer_ok { "CRC OK" } else { "undecodable (falling back to hard decisions at the phase-locked position)" },
            if r.gear_match { "matches the parameter" } else { "does not match the parameter, or unknown" },
            r.cfo_hz
        );
        if let Some(db) = r.rms_active_dbfs {
            println!("Signal level (lead-in start to data end): RMS {:.1} dBFS", db);
        }
    } else {
        println!(
            "Lead-in: not found. Max correlation {:.3} (position {:.3} s, threshold {:.2}); whole-file RMS {:.1} dBFS",
            r.max_corr, r.max_corr_pos_s + r.offset_s(), THRESH, r.rms_overall_dbfs
        );
    }
    println!(
        "Decoded frames: {}/{}, frame error rate {:.2}%",
        r.frames_ok, r.frames_total, r.frame_error_rate * 100.0
    );
    match (r.ber_prefec, r.erased_bit_fraction) {
        (Some(b), Some(e)) => println!("Pre-FEC bit error rate {:.2}% (another {:.1}% of bits judged erased and not counted)", b * 100.0, e * 100.0),
        _ => println!("Pre-FEC bit error rate: no data"),
    }
    println!("Effective net rate (during data-carrying time): {:.0} bps (nominal {:.0} bps)", r.goodput_bps, r.nominal_net_bps);
    println!("Longest error run {} frames; demodulator erased {}/{} 20 ms subframes", r.longest_error_run, r.demod_erased_frames, r.demod_total_frames);
    println!("Errors per 10 frames:");
    for (row, chunk) in r.errors_per_10.chunks(10).enumerate() {
        let cells: Vec<String> = chunk
            .iter()
            .enumerate()
            .map(|(k, e)| format!("{}-{}:{}", (row * 10 + k) * 10, (row * 10 + k) * 10 + 9, e))
            .collect();
        println!("  {}", cells.join("  "));
    }
    match r.clock_ppm {
        Some(ppm) => println!(
            "Sample clock offset: {:+.0} ppm (positive = recorded timeline is longer than the sender's){}",
            ppm,
            if r.clock_corrected { "; resampled and corrected before demodulation" } else { "" }
        ),
        None => println!("Sample clock offset: cannot be estimated (needs 2 or more lead-ins in the file; add --repeat-preamble-every K to both gen and analyze)"),
    }
    if r.extrapolated_frames > 0 {
        println!("Note: no lead-in found in the segment holding {} frames; positions extrapolated from other lead-ins", r.extrapolated_frames);
    }
}

fn jf(v: f64) -> String {
    if v.is_finite() {
        format!("{}", v)
    } else {
        "null".to_string()
    }
}

fn jo(v: Option<f64>) -> String {
    v.map(jf).unwrap_or_else(|| "null".to_string())
}

pub fn to_json(r: &Report) -> String {
    let errs: Vec<String> = r.errors_per_10.iter().map(|e| e.to_string()).collect();
    let fields: Vec<(&str, String)> = vec![
        ("gear", format!("\"{}\"", gear_name(r.gear))),
        ("frames_total", r.frames_total.to_string()),
        ("input_rate_hz", r.input_rate.to_string()),
        ("channels", r.channels.to_string()),
        ("length_s", jf(r.length_s)),
        ("range_start_s", jo(r.range.map(|x| x.0))),
        ("range_end_s", jo(r.range.map(|x| x.1))),
        ("peak_dbfs", jf(r.peak_dbfs)),
        ("rms_overall_dbfs", jf(r.rms_overall_dbfs)),
        ("rms_active_dbfs", jo(r.rms_active_dbfs)),
        ("preamble_found", r.preamble_found.to_string()),
        ("preamble_pos_s", jo(r.preamble_pos_s.map(|v| v + r.offset_s()))),
        ("preamble_corr", jf(r.preamble_score as f64)),
        ("max_corr", jf(r.max_corr as f64)),
        ("max_corr_pos_s", jf(r.max_corr_pos_s + r.offset_s())),
        ("trailer_ok", r.trailer_ok.to_string()),
        ("gear_match", r.gear_match.to_string()),
        ("cfo_hz", jf(r.cfo_hz as f64)),
        ("preambles_found", r.preambles_found.to_string()),
        ("preambles_expected", r.preambles_expected.to_string()),
        ("frames_ok", r.frames_ok.to_string()),
        ("frame_error_rate", jf(r.frame_error_rate)),
        ("ber_prefec", jo(r.ber_prefec)),
        ("erased_bit_fraction", jo(r.erased_bit_fraction)),
        ("goodput_bps", jf(r.goodput_bps)),
        ("nominal_net_bps", jf(r.nominal_net_bps)),
        ("longest_error_run", r.longest_error_run.to_string()),
        ("errors_per_10_frames", format!("[{}]", errs.join(","))),
        ("extrapolated_frames", r.extrapolated_frames.to_string()),
        ("clock_ppm", jo(r.clock_ppm)),
        ("clock_corrected", r.clock_corrected.to_string()),
        ("demod_erased_subframes", r.demod_erased_frames.to_string()),
        ("demod_total_subframes", r.demod_total_frames.to_string()),
    ];
    let body: Vec<String> = fields.iter().map(|(k, v)| format!("\"{}\":{}", k, v)).collect();
    format!("{{{}}}", body.join(","))
}

/// One-line summary used by selftest.
pub fn summary_line(r: &Report) -> String {
    let pre = if r.preamble_found {
        format!("lead-in {:.2}s", r.preamble_pos_s.unwrap_or(0.0) + r.offset_s())
    } else {
        format!("lead-in not found (max corr {:.2})", r.max_corr)
    };
    let ber = r.ber_prefec.map(|b| format!("{:.1}%", b * 100.0)).unwrap_or_else(|| "n/a".to_string());
    let clk = r.clock_ppm.map(|p| format!(", clock {:+.0}ppm", p)).unwrap_or_default();
    format!(
        "{}, frames {}/{}, FER {:.1}%, pre-FEC BER {}, net rate {:.0} bps, longest error run {} frames{}",
        pre, r.frames_ok, r.frames_total, r.frame_error_rate * 100.0, ber, r.goodput_bps, r.longest_error_run, clk
    )
}
