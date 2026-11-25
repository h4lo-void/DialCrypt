//! Independent acceptance tests for the Robust300 gear and the demodulator compensation (C4, C5 probe, C7).

use aegiscall_modem::{
    apply_channel_impairments, apply_codec_channel, decode_superframe_fec_soft, deinterleave_384_soft,
    detect_preamble, detect_preamble_raw, encode_superframe_fec, interleave_384, synthesize_preamble,
    ChannelProfile, CodecChannelProfile, FormantDemodulator, FormantModulator, ModemGear,
    PreambleCapabilities, FRAME_SAMPLES, SUPERFRAME_BYTES, TOTAL_PREAMBLE_SAMPLES,
};

const GEARS: [ModemGear; 3] = [ModemGear::Narrowband1200, ModemGear::Wideband2400, ModemGear::Robust300];

struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0 >> 33
    }
    fn block(&mut self) -> [u8; SUPERFRAME_BYTES] {
        let mut b = [0u8; SUPERFRAME_BYTES];
        for v in b.iter_mut() {
            *v = (self.next() & 0xFF) as u8;
        }
        b
    }
    fn pcm(&mut self, n: usize) -> Vec<i16> {
        (0..n).map(|_| if self.next() & 1 == 0 { i16::MAX } else { i16::MIN }).collect()
    }
}

fn tx_blocks(gear: ModemGear, blocks: &[[u8; SUPERFRAME_BYTES]]) -> Vec<i16> {
    let mut m = FormantModulator::new(gear);
    let mut pcm = Vec::new();
    for b in blocks {
        pcm.extend(m.modulate_superframe(&interleave_384(&encode_superframe_fec(b), gear.frames_per_superframe())));
    }
    pcm
}

fn rx_block(gear: ModemGear, demod: &mut FormantDemodulator, pcm: &[i16], idx: usize) -> [u8; SUPERFRAME_BYTES] {
    let fps = gear.frames_per_superframe();
    let sf = fps * FRAME_SAMPLES;
    let mut win = vec![0i16; sf];
    let start = (idx * sf).min(pcm.len());
    let n = (pcm.len() - start).min(sf);
    win[..n].copy_from_slice(&pcm[start..start + n]);
    let llrs = demod.demodulate_superframe(&win);
    decode_superframe_fec_soft(&deinterleave_384_soft(&llrs, fps))
}

#[test]
fn c4_random_bytes_roundtrip_every_gear() {
    for gear in GEARS {
        let mut rng = Lcg(0xC0FFEE ^ gear as u64);
        let blocks: Vec<_> = (0..40).map(|_| rng.block()).collect();
        let pcm = tx_blocks(gear, &blocks);
        let mut d = FormantDemodulator::new(gear, 0.0);
        for (i, b) in blocks.iter().enumerate() {
            assert_eq!(&rx_block(gear, &mut d, &pcm, i), b, "{:?} block {} mismatch", gear, i);
        }
    }
}

#[test]
fn c4_robust_roundtrip_through_preamble_100_of_100_lossless() {
    let gear = ModemGear::Robust300;
    let mut rng = Lcg(77);
    let blocks: Vec<_> = (0..100).map(|_| rng.block()).collect();
    let mut pcm = vec![0i16; 431];
    pcm.extend(synthesize_preamble(PreambleCapabilities::v2(gear)));
    pcm.extend(tx_blocks(gear, &blocks));
    pcm.extend(vec![0i16; 640]);
    let det = detect_preamble_raw(&pcm).expect("raw preamble");
    assert_eq!(det.announced_gear(), Some(gear));
    let mut d = FormantDemodulator::new(gear, det.estimated_cfo_hz);
    let body = &pcm[det.payload_start_sample..];
    let ok = (0..100).filter(|&i| rx_block(gear, &mut d, body, i) == blocks[i]).count();
    assert_eq!(ok, 100);
}

#[test]
fn c4_wrong_gear_never_yields_the_payload() {
    for tx in GEARS {
        let mut rng = Lcg(5 + tx as u64);
        let blocks: Vec<_> = (0..16).map(|_| rng.block()).collect();
        let pcm = tx_blocks(tx, &blocks);
        for rx in GEARS {
            if rx == tx {
                continue;
            }
            let mut d = FormantDemodulator::new(rx, 0.0);
            let n = pcm.len() / (rx.frames_per_superframe() * FRAME_SAMPLES);
            for i in 0..n {
                let got = rx_block(rx, &mut d, &pcm, i);
                assert!(!blocks.contains(&got), "tx {:?} decoded by rx {:?} block {}", tx, rx, i);
            }
        }
    }
}

#[test]
fn c4_negotiating_detector_rejects_robust_but_accepts_existing_gears() {
    let mk = |g: ModemGear| {
        let mut pcm = vec![0i16; 300];
        pcm.extend(synthesize_preamble(PreambleCapabilities::v2(g)));
        pcm.extend(vec![0i16; 320]);
        pcm
    };
    assert!(detect_preamble(&mk(ModemGear::Robust300)).is_none());
    assert!(detect_preamble_raw(&mk(ModemGear::Robust300)).is_some());
    for g in [ModemGear::Narrowband1200, ModemGear::Wideband2400] {
        let d = detect_preamble(&mk(g)).expect("existing gear still negotiable");
        assert_eq!(d.peer_caps.preferred_gear, g);
    }
}

fn finite_llrs(l: &[f32]) {
    assert!(l.iter().all(|v| v.is_finite() && v.abs() <= 8.0 + 1e-3), "non finite or out of range LLR");
}

fn check_state(d: &FormantDemodulator, gear: ModemGear) {
    assert!(d.cfo_hz().is_finite());
    assert!(d.metrics().avg_llr_confidence.is_finite());
    for w in d.band_reliability() {
        assert!(w.is_finite() && (0.0..=1.0).contains(&w), "reliability {}", w);
    }
    for b in 0..gear.subband_count() {
        if let Some(g) = d.band_equalizer(b) {
            assert!(g.iter().all(|v| v.is_finite() && *v > 0.0));
        }
    }
}

#[test]
fn c7_neutral_start() {
    for gear in GEARS {
        let mut rng = Lcg(9);
        let pcm = tx_blocks(gear, &[rng.block()]);
        let mut on = FormantDemodulator::new(gear, 0.0);
        let mut off = FormantDemodulator::new(gear, 0.0);
        off.set_compensation(false);
        assert!(on.band_reliability().iter().all(|&w| w == 1.0), "{:?} reliability not neutral", gear);
        assert!((0..gear.subband_count()).all(|b| on.band_equalizer(b).is_none()));
        let a = on.demodulate_single_frame(&pcm[..FRAME_SAMPLES]);
        let b = off.demodulate_single_frame(&pcm[..FRAME_SAMPLES]);
        assert_eq!(a, b, "{:?} first frame differs between compensation on/off", gear);
    }
}

#[test]
fn c7_degenerate_inputs_stay_finite_for_every_gear() {
    let mut rng = Lcg(1234);
    for gear in GEARS {
        let sf = gear.frames_per_superframe() * FRAME_SAMPLES;
        let inputs: Vec<(&str, Vec<i16>)> = vec![
            ("zeros", vec![0; sf * 3]),
            ("const+fs", vec![i16::MAX; sf * 3]),
            ("const-fs", vec![i16::MIN; sf * 3]),
            ("nyquist", (0..sf * 3).map(|i| if i % 2 == 0 { i16::MAX } else { i16::MIN }).collect()),
            ("square1k", (0..sf * 3).map(|i| if (i / 8) % 2 == 0 { i16::MAX } else { i16::MIN }).collect()),
            ("noise-fs", rng.pcm(sf * 3)),
            ("lsb", (0..sf * 3).map(|i| (i % 2) as i16).collect()),
        ];
        for (name, pcm) in inputs {
            let mut d = FormantDemodulator::new(gear, 0.0);
            for i in 0..3 {
                let llrs = d.demodulate_superframe(&pcm[i * sf..(i + 1) * sf]);
                finite_llrs(&llrs);
                let _ = decode_superframe_fec_soft(&deinterleave_384_soft(&llrs, gear.frames_per_superframe()));
            }
            check_state(&d, gear);
            let _ = name;
        }
    }
}

#[test]
fn c7_very_short_and_odd_lengths_do_not_panic() {
    for gear in GEARS {
        let mut d = FormantDemodulator::new(gear, 0.0);
        let src = Lcg(3).pcm(5000);
        for n in (0..=FRAME_SAMPLES + 2).chain([1000, 4999, 5000]) {
            finite_llrs(&d.demodulate_single_frame(&src[..n]));
            finite_llrs(&d.demodulate_superframe(&src[..n]));
        }
        check_state(&d, gear);
    }
}

#[test]
fn c7_long_fullscale_run_keeps_state_bounded() {
    for gear in GEARS {
        let mut rng = Lcg(55);
        let mut d = FormantDemodulator::new(gear, 0.0);
        for _ in 0..4000 {
            let f = rng.pcm(FRAME_SAMPLES);
            finite_llrs(&d.demodulate_single_frame(&f));
        }
        check_state(&d, gear);
        let mut r2 = Lcg(8);
        let pcm = tx_blocks(gear, &[r2.block()]);
        finite_llrs(&d.demodulate_superframe(&pcm));
    }
}

#[test]
fn c7_extreme_cfo_argument_is_clamped() {
    for cfo in [f32::MAX, f32::MIN, 1e30, -1e30, 0.0] {
        let mut d = FormantDemodulator::new(ModemGear::Robust300, cfo);
        assert!(d.cfo_hz().abs() <= 55.0 + 1e-3);
        finite_llrs(&d.demodulate_single_frame(&Lcg(1).pcm(FRAME_SAMPLES)));
    }
}

#[test]
fn c7_preamble_detectors_survive_hostile_input() {
    let mut rng = Lcg(21);
    let mut cases: Vec<Vec<i16>> = vec![
        vec![],
        vec![1],
        vec![0; TOTAL_PREAMBLE_SAMPLES - 1],
        vec![0; TOTAL_PREAMBLE_SAMPLES],
        vec![0; TOTAL_PREAMBLE_SAMPLES + 1],
        vec![0; 40_000],
        vec![i16::MAX; 40_000],
        vec![i16::MIN; 40_000],
    ];
    cases.push(rng.pcm(40_000));
    cases.push(rng.pcm(TOTAL_PREAMBLE_SAMPLES));
    for c in &cases {
        let _ = detect_preamble_raw(c);
        let _ = detect_preamble(c);
    }
}

#[test]
fn c7_channel_models_survive_degenerate_input() {
    let mut rng = Lcg(31);
    let p = CodecChannelProfile::vowifi_measured();
    for n in [0usize, 1, 2, 127, 128, 129, 255, 256, 257, 320, 1000, 20_000] {
        for pcm in [vec![0i16; n], vec![i16::MAX; n], vec![i16::MIN; n], rng.pcm(n)] {
            assert_eq!(apply_codec_channel(&pcm, &p).len(), n);
            assert_eq!(apply_channel_impairments(&pcm, &ChannelProfile::volte_harsh()).len(), n);
            assert_eq!(apply_channel_impairments(&pcm, &ChannelProfile::gsm_legacy_harsh()).len(), n);
        }
    }
    let mut bad = p;
    bad.gain_corr_s = 0.0;
    bad.max_partials = 0;
    bad.lowpass_hz = 1.0;
    let out = apply_codec_channel(&rng.pcm(2000), &bad);
    assert_eq!(out.len(), 2000);
}

fn goertzel_db(pcm: &[i16], hz: f32) -> f32 {
    let w = 2.0 * std::f64::consts::PI * hz as f64 / 16_000.0;
    let (mut re, mut im) = (0.0f64, 0.0f64);
    for (n, &s) in pcm.iter().enumerate() {
        re += s as f64 * (w * n as f64).cos();
        im += s as f64 * (w * n as f64).sin();
    }
    let p = (re * re + im * im) / (pcm.len() as f64).powi(2) + 1e-12;
    (10.0 * p.log10()) as f32
}

/// Informational (C5): per-tone level through the codec model, one tone alone vs 12 tones together.
#[test]
fn c5_probe_tone_level_alone_vs_in_dense_frame() {
    let p = CodecChannelProfile::vowifi_measured();
    let tones: Vec<f32> = (0..12).map(|i| (8 + 2 * i) as f32 * 62.5).collect();
    let len = 16_000 * 4;
    let synth = |set: &[f32]| -> Vec<i16> {
        (0..len)
            .map(|n| {
                let t = n as f32 / 16_000.0;
                (set.iter().map(|f| (2.0 * std::f32::consts::PI * f * t).sin()).sum::<f32>() * 2500.0) as i16
            })
            .collect()
    };
    let dense = apply_codec_channel(&synth(&tones), &p);
    let mut worst: f32 = 0.0;
    for &f in &tones {
        let alone = apply_codec_channel(&synth(&[f]), &p);
        let a = goertzel_db(&alone[16_000..], f);
        let d = goertzel_db(&dense[16_000..], f);
        println!("C5PROBE tone {:7.1} Hz alone {:6.1} dB dense {:6.1} dB delta {:6.1} dB", f, a, d, d - a);
        worst = worst.min(d - a);
    }
    println!("C5PROBE worst delta {:.1} dB", worst);
}
