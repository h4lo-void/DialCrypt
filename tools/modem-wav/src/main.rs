//! modem-wav: DialCrypt modem test-signal generator and recorded-call analyzer.

mod analyze;
mod diagnose;
mod dsp;
mod probe;
mod selftest;
mod sig;
mod wav;

use aegiscall_modem::{ModemGear, VoiceTimbre, SAMPLE_RATE};
use std::collections::HashMap;
use std::process::exit;

const USAGE: &str = "Usage:
  modem-wav gen --gear wide|narrow|robust|speech --frames N --seed S [--lead-ms 1500] [--tail-ms 1000]
                [--level-dbfs -12] [--repeat-preamble-every K] [--voice male|female] -o out.wav
  modem-wav analyze in.wav --gear wide|narrow|robust|speech --frames N --seed S
                [--repeat-preamble-every K] [--start-s SEC] [--end-s SEC] [--json]
  modem-wav diagnose in.wav --gear wide|narrow|robust|speech --frames N --seed S
                [--repeat-preamble-every K] [--level-dbfs -12] [--start-s SEC] [--end-s SEC]
  modem-wav gen-probe [--level-dbfs -18] [--lead-ms 0] [--tail-ms 0] -o probe.wav
  modem-wav analyze-probe in.wav [--level-dbfs -18] [--start-s SEC] [--end-s SEC]
  modem-wav concat [--level-dbfs -18] -o out.wav SEG SEG ...
                SEG: silence:SEC | breath:SEC | probe | narrow|wide|robust|speech:FRAMES[:seed=S][:repeat=K][:voice=male|female]
  modem-wav selftest [--frames N] [--seed S]
  modem-wav stealth [in.wav ...]
(frame = one 23-byte FEC superframe; wide is 160 ms per frame, narrow 320 ms per frame, robust/speech 1280 ms per frame)";

struct Args {
    opts: HashMap<String, String>,
    positional: Vec<String>,
    json: bool,
}

fn parse_args(raw: &[String], allowed: &[&str]) -> Result<Args, String> {
    let mut a = Args { opts: HashMap::new(), positional: Vec::new(), json: false };
    let mut i = 0;
    while i < raw.len() {
        let s = raw[i].as_str();
        if s == "--json" {
            if !allowed.contains(&s) {
                return Err(format!("this subcommand does not accept {}", s));
            }
            a.json = true;
        } else if s.starts_with("--") || s == "-o" {
            if !allowed.contains(&s) {
                return Err(format!("unknown argument {}", s));
            }
            i += 1;
            let v = raw.get(i).ok_or(format!("{} is missing a value", s))?;
            a.opts.insert(s.to_string(), v.clone());
        } else {
            a.positional.push(raw[i].clone());
        }
        i += 1;
    }
    Ok(a)
}

impl Args {
    fn num<T: std::str::FromStr>(&self, key: &str, default: Option<T>) -> Result<T, String> {
        match self.opts.get(key) {
            Some(v) => v.parse::<T>().map_err(|_| format!("invalid value for {}: {}", key, v)),
            None => default.ok_or(format!("missing required argument {}", key)),
        }
    }
    fn gear(&self) -> Result<(ModemGear, &'static str), String> {
        match self.opts.get("--gear").map(|s| s.as_str()) {
            Some("wide") => Ok((ModemGear::Wideband2400, "wide")),
            Some("narrow") => Ok((ModemGear::Narrowband1200, "narrow")),
            Some("robust") => Ok((ModemGear::Robust300, "robust")),
            Some("speech") => Ok((ModemGear::Speech300, "speech")),
            Some(o) => Err(format!("--gear accepts only wide, narrow, robust or speech (got {})", o)),
            None => Err("missing required argument --gear".to_string()),
        }
    }
    fn voice_timbre(&self) -> Result<VoiceTimbre, String> {
        match self.opts.get("--voice").map(|s| s.as_str()) {
            None | Some("male") => Ok(VoiceTimbre::MaleBaritone),
            Some("female") => Ok(VoiceTimbre::FemaleContralto),
            Some(o) => Err(format!("--voice accepts only male or female (got {})", o)),
        }
    }
}

fn cmd_gen(raw: &[String]) -> Result<(), String> {
    let a = parse_args(
        raw,
        &[
            "--gear",
            "--frames",
            "--seed",
            "--lead-ms",
            "--tail-ms",
            "--level-dbfs",
            "--repeat-preamble-every",
            "--voice",
            "-o",
        ],
    )?;
    let (gear, _) = a.gear()?;
    let timbre = a.voice_timbre()?;
    let frames: usize = a.num("--frames", None)?;
    if frames == 0 {
        return Err("--frames must be greater than 0".to_string());
    }
    let out = a.opts.get("-o").ok_or("missing required argument -o")?;
    let g = sig::gen_pcm_with_timbre(
        &sig::GenParams {
            gear,
            frames,
            seed: a.num("--seed", None)?,
            lead_ms: a.num("--lead-ms", Some(1500))?,
            tail_ms: a.num("--tail-ms", Some(1000))?,
            level_dbfs: a.num("--level-dbfs", Some(-12.0))?,
            repeat: a.num("--repeat-preamble-every", Some(0))?,
        },
        timbre,
    );
    wav::write_wav(out, SAMPLE_RATE as u32, &g.pcm)?;
    println!(
        "Wrote {}: {:.2} s (16 kHz 16-bit mono), payload {} bytes ({} frames x 23), {} lead-ins",
        out,
        g.pcm.len() as f64 / SAMPLE_RATE as f64,
        frames * aegiscall_modem::SUPERFRAME_BYTES,
        frames,
        g.preambles
    );
    println!("Data segment RMS {:.1} dBFS, peak {:.1} dBFS, clipped samples {}", g.active_rms_dbfs, g.peak_dbfs, g.clipped);
    Ok(())
}

fn cmd_analyze(raw: &[String]) -> Result<(), String> {
    let a = parse_args(
        raw,
        &["--gear", "--frames", "--seed", "--repeat-preamble-every", "--json", "--start-s", "--end-s"],
    )?;
    if a.positional.len() != 1 {
        return Err("analyze needs exactly one input wav file".to_string());
    }
    let (gear, _) = a.gear()?;
    let frames: usize = a.num("--frames", None)?;
    if frames == 0 {
        return Err("--frames must be greater than 0".to_string());
    }
    let params = analyze::Params {
        gear,
        frames,
        seed: a.num("--seed", None)?,
        repeat: a.num("--repeat-preamble-every", Some(0))?,
    };
    let w = wav::read_wav(&a.positional[0])?;
    let pcm16 = dsp::to_i16(&dsp::resample_rate(&dsp::to_f32(&w.samples), w.rate, SAMPLE_RATE as u32));
    let (slice, range) = slice_range(&pcm16, &a)?;
    let mut rep = analyze::analyze_pcm(slice, w.rate, w.channels, &params);
    rep.range = range;
    if a.json {
        println!("{}", analyze::to_json(&rep));
    } else {
        analyze::print_text(&rep);
    }
    Ok(())
}

/// Applies --start-s / --end-s; returns the selected samples and the selected range in seconds.
fn slice_range<'a>(pcm: &'a [i16], a: &Args) -> Result<(&'a [i16], Option<(f64, f64)>), String> {
    if !a.opts.contains_key("--start-s") && !a.opts.contains_key("--end-s") {
        return Ok((pcm, None));
    }
    let total = pcm.len() as f64 / SAMPLE_RATE as f64;
    let start: f64 = a.num("--start-s", Some(0.0))?;
    let end: f64 = a.num("--end-s", Some(total))?;
    if !(start >= 0.0) || !(end > start) {
        return Err(format!("invalid --start-s/--end-s range: {}–{}", start, end));
    }
    let end = end.min(total);
    let s = ((start * SAMPLE_RATE as f64).round() as usize).min(pcm.len());
    let e = ((end * SAMPLE_RATE as f64).round() as usize).min(pcm.len());
    if e <= s {
        return Err(format!("--start-s {} exceeds the recording length {:.2} s", start, total));
    }
    Ok((&pcm[s..e], Some((s as f64 / SAMPLE_RATE as f64, e as f64 / SAMPLE_RATE as f64))))
}

fn cmd_diagnose(raw: &[String]) -> Result<(), String> {
    let a = parse_args(
        raw,
        &["--gear", "--frames", "--seed", "--repeat-preamble-every", "--level-dbfs", "--start-s", "--end-s"],
    )?;
    if a.positional.len() != 1 {
        return Err("diagnose needs exactly one input wav file".to_string());
    }
    let (gear, _) = a.gear()?;
    let frames: usize = a.num("--frames", None)?;
    if frames == 0 {
        return Err("--frames must be greater than 0".to_string());
    }
    let params = analyze::Params {
        gear,
        frames,
        seed: a.num("--seed", None)?,
        repeat: a.num("--repeat-preamble-every", Some(0))?,
    };
    let w = wav::read_wav(&a.positional[0])?;
    let pcm16 = dsp::to_i16(&dsp::resample_rate(&dsp::to_f32(&w.samples), w.rate, SAMPLE_RATE as u32));
    let (slice, range) = slice_range(&pcm16, &a)?;
    diagnose::run(
        slice,
        range.map(|r| r.0).unwrap_or(0.0),
        &diagnose::DiagParams { p: params, level_dbfs: a.num("--level-dbfs", Some(-12.0))? },
    )
}

/// Command-line name of a gear.
pub fn gear_label(g: ModemGear) -> &'static str {
    match g {
        ModemGear::Wideband2400 => "wide",
        ModemGear::Narrowband1200 => "narrow",
        ModemGear::Robust300 => "robust",
        ModemGear::Speech300 => "speech",
    }
}

fn cmd_gen_probe(raw: &[String]) -> Result<(), String> {
    let a = parse_args(raw, &["--level-dbfs", "--lead-ms", "--tail-ms", "-o"])?;
    let out = a.opts.get("-o").ok_or("missing required argument -o")?;
    let level: f64 = a.num("--level-dbfs", Some(-18.0))?;
    let lead = SAMPLE_RATE * a.num::<usize>("--lead-ms", Some(0))? / 1000;
    let tail = SAMPLE_RATE * a.num::<usize>("--tail-ms", Some(0))? / 1000;
    let mut pcm = vec![0i16; lead];
    pcm.extend(probe::gen_probe(level));
    pcm.extend(std::iter::repeat(0i16).take(tail));
    wav::write_wav(out, SAMPLE_RATE as u32, &pcm)?;
    println!("Wrote {}: {:.2} s, per-segment RMS {:.0} dBFS", out, pcm.len() as f64 / SAMPLE_RATE as f64, level);
    println!("{}", probe::describe());
    Ok(())
}

fn cmd_analyze_probe(raw: &[String]) -> Result<(), String> {
    let a = parse_args(raw, &["--level-dbfs", "--start-s", "--end-s"])?;
    if a.positional.len() != 1 {
        return Err("analyze-probe needs exactly one input wav file".to_string());
    }
    let w = wav::read_wav(&a.positional[0])?;
    let pcm16 = dsp::to_i16(&dsp::resample_rate(&dsp::to_f32(&w.samples), w.rate, SAMPLE_RATE as u32));
    let (slice, range) = slice_range(&pcm16, &a)?;
    probe::analyze_probe(slice, range.map(|r| r.0).unwrap_or(0.0), a.num("--level-dbfs", Some(-18.0))?)
}

/// Appends one concat segment; returns its description and the matching analysis command.
fn append_segment(pcm: &mut Vec<i16>, spec: &str, level: f64) -> Result<(String, Option<String>), String> {
    let mut it = spec.split(':');
    let kind = it.next().unwrap_or("");
    match kind {
        "silence" => {
            let secs: f64 = it
                .next()
                .and_then(|v| v.parse().ok())
                .filter(|v: &f64| *v >= 0.0)
                .ok_or(format!("segment {} must be in the form silence:SEC", spec))?;
            pcm.extend(std::iter::repeat(0i16).take((secs * SAMPLE_RATE as f64).round() as usize));
            Ok((format!("silence {} s", secs), None))
        }
        "breath" => {
            let secs: f64 = it
                .next()
                .and_then(|v| v.parse().ok())
                .filter(|v: &f64| *v >= 0.0)
                .ok_or(format!("segment {} must be in the form breath:SEC", spec))?;
            let samples = (secs * SAMPLE_RATE as f64).round() as usize;
            let noise = aegiscall_modem::synthesize_comfort_noise(samples, -48.0, pcm.len() as u64 ^ 0xA3615);
            pcm.extend_from_slice(&noise);
            Ok((format!("breath / ambient noise {} s (-48 dBFS pink comfort noise)", secs), None))
        }
        "probe" => {
            pcm.extend(probe::gen_probe(level));
            Ok(("channel probe".to_string(), Some("analyze-probe recording.wav".to_string())))
        }
        "narrow" | "wide" | "robust" | "speech" => {
            let gear = match kind {
                "narrow" => ModemGear::Narrowband1200,
                "wide" => ModemGear::Wideband2400,
                "robust" => ModemGear::Robust300,
                _ => ModemGear::Speech300,
            };
            let frames: usize = it
                .next()
                .and_then(|v| v.parse().ok())
                .filter(|v: &usize| *v > 0)
                .ok_or(format!("segment {} must be in the form {}:FRAMES[:seed=S][:repeat=K]", spec, kind))?;
            let (mut seed, mut repeat, mut timbre) = (7u64, 0usize, VoiceTimbre::MaleBaritone);
            for kv in it {
                match kv.split_once('=') {
                    Some(("seed", v)) => seed = v.parse().map_err(|_| format!("segment {} has an invalid seed", spec))?,
                    Some(("repeat", v)) => repeat = v.parse().map_err(|_| format!("segment {} has an invalid repeat", spec))?,
                    Some(("voice", "male")) => timbre = VoiceTimbre::MaleBaritone,
                    Some(("voice", "female")) => timbre = VoiceTimbre::FemaleContralto,
                    Some(("voice", v)) => return Err(format!("segment {} voice accepts only male or female (got {})", spec, v)),
                    _ => return Err(format!("segment {} has an unrecognized setting {}", spec, kv)),
                }
            }
            let g = sig::gen_pcm_with_timbre(
                &sig::GenParams { gear, frames, seed, lead_ms: 0, tail_ms: 0, level_dbfs: level, repeat },
                timbre,
            );
            pcm.extend_from_slice(&g.pcm);
            Ok((
                format!("{} {} frames ({} bytes), {} lead-ins", kind, frames, frames * aegiscall_modem::SUPERFRAME_BYTES, g.preambles),
                Some(format!(
                    "analyze recording.wav --gear {} --frames {} --seed {} --repeat-preamble-every {}",
                    kind, frames, seed, repeat
                )),
            ))
        }
        _ => Err(format!("unrecognized segment {} (silence:SEC, breath:SEC, probe, narrow|wide|robust|speech:FRAMES)", spec)),
    }
}

fn cmd_concat(raw: &[String]) -> Result<(), String> {
    let a = parse_args(raw, &["--level-dbfs", "-o"])?;
    let out = a.opts.get("-o").ok_or("missing required argument -o")?;
    let level: f64 = a.num("--level-dbfs", Some(-18.0))?;
    if a.positional.is_empty() {
        return Err("concat needs at least one segment".to_string());
    }
    let mut pcm: Vec<i16> = Vec::new();
    let mut rows = Vec::new();
    for spec in &a.positional {
        let start = pcm.len();
        let (label, cmd) = append_segment(&mut pcm, spec, level)?;
        rows.push((label, start, pcm.len(), cmd));
    }
    wav::write_wav(out, SAMPLE_RATE as u32, &pcm)?;
    let sec = |s: usize| s as f64 / SAMPLE_RATE as f64;
    println!("Wrote {}: {:.2} s (16 kHz 16-bit mono), signal segment RMS {:.0} dBFS", out, sec(pcm.len()), level);
    println!("No  Start s    End s    Len s   Content");
    for (i, (label, s, e, _)) in rows.iter().enumerate() {
        println!("{:2}  {:7.2}  {:7.2}  {:7.2}   {}", i + 1, sec(*s), sec(*e), sec(e - s), label);
    }
    println!("Analysis commands (times are file times; recording time = file time + offset, offset = lead-in position printed by analyze-probe - probe segment start):");
    for (i, (_, s, e, cmd)) in rows.iter().enumerate() {
        if let Some(c) = cmd {
            println!(
                "  segment {}: modem-wav {} --start-s {:.2} --end-s {:.2}",
                i + 1,
                c,
                (sec(*s) - 0.5).max(0.0),
                sec(*e) + 0.5
            );
        }
    }
    Ok(())
}

fn cmd_selftest(raw: &[String]) -> Result<(), String> {
    let a = parse_args(raw, &["--frames", "--seed"])?;
    let frames: usize = a.num("--frames", Some(100))?;
    let seed: u64 = a.num("--seed", Some(7))?;
    if frames == 0 {
        return Err("--frames must be greater than 0".to_string());
    }
    selftest::run(ModemGear::Wideband2400, "wide", frames, seed);
    selftest::run(ModemGear::Narrowband1200, "narrow", frames, seed);
    selftest::run(ModemGear::Robust300, "robust", frames, seed);
    selftest::run(ModemGear::Speech300, "speech", frames, seed);
    Ok(())
}

fn cmd_stealth(raw: &[String]) -> Result<(), String> {
    let a = parse_args(raw, &[])?;
    println!("== Telecom big-data voice anomaly screening metrics (Stealth & Speech-Likeness Scanner) ==");
    println!(
        "{:<28} | {:>10} | {:>10} | {:>11} | {:>11} | {:>10} | {:>10}",
        "Name / Gear",
        "Peak bin %",
        "V-Chirp",
        "50Hz buzz",
        "Syllabic dB",
        "Voice bar%",
        "Spec tilt"
    );
    println!("{}", "-".repeat(108));
    let print_row = |label: &str, pcm: &[i16]| {
        let m = aegiscall_modem::analyze_stealth_metrics(pcm);
        println!(
            "{:<28} | {:>9.2}% | {:>10.3} | {:>+9.1} dB | {:>8.2} dB | {:>9.1}% | {:>+8.2} dB",
            label,
            m.max_single_bin_concentration * 100.0,
            m.v_chirp_siren_score,
            m.frame_50hz_buzz_db,
            m.syllabic_envelope_range_db,
            m.voice_bar_energy_share * 100.0,
            m.spectral_tilt_db
        );
    };
    if a.positional.is_empty() {
        for (gear, name, frames) in [
            (ModemGear::Wideband2400, "wide (old wideband 2400)", 40usize),
            (ModemGear::Narrowband1200, "narrow (old narrowband 1200)", 20usize),
            (ModemGear::Robust300, "robust (old resilient 300)", 8usize),
            (ModemGear::Speech300, "speech (new speech-like 300)", 8usize),
        ] {
            let g = sig::gen_pcm(&sig::GenParams {
                gear,
                frames,
                seed: 7,
                lead_ms: 0,
                tail_ms: 0,
                level_dbfs: -16.0,
                repeat: 0,
            });
            print_row(name, &g.pcm);
        }
    } else {
        for path in &a.positional {
            let w = wav::read_wav(path)?;
            let pcm16 = dsp::to_i16(&dsp::resample_rate(&dsp::to_f32(&w.samples), w.rate, SAMPLE_RATE as u32));
            print_row(path, &pcm16);
        }
    }
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(|s| s.as_str()) {
        Some("gen") => cmd_gen(&args[1..]),
        Some("analyze") => cmd_analyze(&args[1..]),
        Some("diagnose") => cmd_diagnose(&args[1..]),
        Some("gen-probe") => cmd_gen_probe(&args[1..]),
        Some("analyze-probe") => cmd_analyze_probe(&args[1..]),
        Some("concat") => cmd_concat(&args[1..]),
        Some("selftest") => cmd_selftest(&args[1..]),
        Some("stealth") => cmd_stealth(&args[1..]),
        _ => {
            eprintln!("{}", USAGE);
            exit(2);
        }
    };
    if let Err(e) = result {
        eprintln!("Error: {}\n{}", e, USAGE);
        exit(1);
    }
}
