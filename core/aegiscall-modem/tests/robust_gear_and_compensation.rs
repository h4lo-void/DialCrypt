//! Robust300 gear, channel compensation and wire compatibility of the existing gears.

use aegiscall_modem::{
    apply_channel_impairments, apply_codec_channel, decode_superframe_fec_soft, deinterleave_384_soft,
    detect_preamble, detect_preamble_raw, encode_superframe_fec, interleave_384, synthesize_preamble,
    ChannelProfile, CodecChannelProfile, FormantDemodulator, FormantModulator, ModemGear,
    PreambleCapabilities, FRAME_SAMPLES, SUPERFRAME_BYTES,
};
use std::f32::consts::PI;

fn payload(seed: u8, n: usize) -> Vec<[u8; SUPERFRAME_BYTES]> {
    (0..n)
        .map(|s| {
            let mut b = [0u8; SUPERFRAME_BYTES];
            for (i, v) in b.iter_mut().enumerate() {
                *v = (s as u8).wrapping_mul(37).wrapping_add(seed).wrapping_add((i as u8).wrapping_mul(101));
            }
            b
        })
        .collect()
}

/// Preamble + superframes, as a transmitter would send them.
fn transmit(gear: ModemGear, blocks: &[[u8; SUPERFRAME_BYTES]]) -> Vec<i16> {
    let mut pcm = vec![0i16; 517];
    pcm.extend(synthesize_preamble(PreambleCapabilities::v2(gear)));
    let mut m = FormantModulator::new(gear);
    for b in blocks {
        pcm.extend(m.modulate_superframe(&interleave_384(&encode_superframe_fec(b), gear.frames_per_superframe())));
    }
    pcm.extend(vec![0i16; 640]);
    pcm
}

struct RxResult {
    ok: usize,
    bit_errors: usize,
    bits: usize,
}

fn receive(gear: ModemGear, rx: &[i16], blocks: &[[u8; SUPERFRAME_BYTES]], compensate: bool) -> RxResult {
    let det = detect_preamble_raw(rx).expect("preamble must be found");
    assert_eq!(det.announced_gear(), Some(gear));
    let mut demod = FormantDemodulator::new(gear, det.estimated_cfo_hz);
    demod.set_compensation(compensate);
    let fps = gear.frames_per_superframe();
    let sf = fps * FRAME_SAMPLES;
    let mut res = RxResult { ok: 0, bit_errors: 0, bits: 0 };
    for (i, b) in blocks.iter().enumerate() {
        let start = det.payload_start_sample + i * sf;
        let mut win = vec![0i16; sf];
        let n = rx.len().saturating_sub(start).min(sf);
        win[..n].copy_from_slice(&rx[start..start + n]);
        let llrs = demod.demodulate_superframe(&win);
        let tx = interleave_384(&encode_superframe_fec(b), fps);
        for (l, t) in llrs.iter().zip(tx.iter()) {
            res.bits += 1;
            if (*l > 0.0) as u8 != *t {
                res.bit_errors += 1;
            }
        }
        if decode_superframe_fec_soft(&deinterleave_384_soft(&llrs, fps)) == *b {
            res.ok += 1;
        }
    }
    res
}

#[test]
fn robust_gear_layout_fits_the_superframe() {
    let g = ModemGear::Robust300;
    assert_eq!(g as u8, 3);
    assert_eq!(ModemGear::from_wire(3), Some(g));
    assert_eq!(g.frames_per_superframe() * g.bits_per_frame(), 384);
    assert_eq!(g.subband_count() * g.bits_per_band(), g.bits_per_frame());
    let mut used = Vec::new();
    for b in 0..g.subband_count() {
        for sym in 0..g.symbols_per_band() {
            for &t in g.codeword(sym) {
                let bin = aegiscall_modem::modulator::subband_start_bin(g, b) + t as usize;
                assert_eq!(bin % 2, 0, "every Robust300 tone sits on the 125 Hz grid");
                assert!((bin as f32) * 62.5 <= 2000.0, "Robust300 stays below 2 kHz");
                assert!(!used.contains(&bin));
                used.push(bin);
            }
        }
    }
    assert_eq!(used.len(), 12);
}

#[test]
fn robust_gear_roundtrip_clean_and_over_harsh_narrowband_channel() {
    let gear = ModemGear::Robust300;
    let blocks = payload(3, 6);
    let tx = transmit(gear, &blocks);
    let clean = receive(gear, &tx, &blocks, true);
    assert_eq!((clean.ok, clean.bit_errors), (6, 0));

    let rx = apply_channel_impairments(&tx, &ChannelProfile::gsm_legacy_harsh());
    let harsh = receive(gear, &rx, &blocks, true);
    assert!(harsh.ok >= 5, "Robust300 decoded only {}/6 over gsm_legacy_harsh", harsh.ok);
}

#[test]
fn robust_preamble_is_visible_to_tools_but_not_negotiable() {
    let caps = PreambleCapabilities::v2(ModemGear::Robust300);
    let mut pcm = vec![0i16; 300];
    pcm.extend(synthesize_preamble(caps));
    pcm.extend(vec![0i16; 320]);
    let raw = detect_preamble_raw(&pcm).expect("raw detection accepts any gear");
    assert_eq!(raw.raw, caps.encode_bytes());
    assert_eq!(raw.announced_gear(), Some(ModemGear::Robust300));
    assert!(detect_preamble(&pcm).is_none(), "the session-facing detector must keep rejecting gear 3");
    assert_eq!(PreambleCapabilities::decode_bytes(&caps.encode_bytes()), None);
}

#[test]
fn robust_gear_survives_measured_codec_channel() {
    let gear = ModemGear::Robust300;
    let blocks = payload(9, 20);
    let rx = apply_codec_channel(&transmit(gear, &blocks), &CodecChannelProfile::vowifi_measured());
    let r = receive(gear, &rx, &blocks, true);
    assert!(r.ok >= 19, "Robust300 FER above 5% on the measured codec channel: {}/20", r.ok);

    // Same channel, existing narrowband gear: the reason Robust300 exists.
    let nb_blocks = payload(9, 20);
    let nb_rx = apply_codec_channel(&transmit(ModemGear::Narrowband1200, &nb_blocks), &CodecChannelProfile::vowifi_measured());
    let nb = receive(ModemGear::Narrowband1200, &nb_rx, &nb_blocks, true);
    assert!(nb.ok < r.ok, "narrowband {} vs robust {}", nb.ok, r.ok);
}

#[test]
fn compensation_helps_narrowband_on_a_tilted_channel() {
    // Strong treble loss plus envelope-shaped coding noise, without tone dropping or gain wander.
    let tilt = CodecChannelProfile {
        tilt_db_per_octave: -12.0,
        tilt_pivot_hz: 1000.0,
        lowpass_hz: 3400.0,
        highpass_hz: 200.0,
        max_partials: 64,
        partial_drop_db: 0.0,
        partial_fade_prob: 0.0,
        fill_snr_db: 3.0,
        gain_sd_db: 0.0,
        gain_corr_s: 1.0,
        noise_floor_dbfs: -60.0,
        seed: 0x7117,
    };
    let gear = ModemGear::Narrowband1200;
    let blocks = payload(5, 40);
    let rx = apply_codec_channel(&transmit(gear, &blocks), &tilt);
    let off = receive(gear, &rx, &blocks, false);
    let on = receive(gear, &rx, &blocks, true);
    eprintln!(
        "tilted channel: without compensation {}/40 BER {:.2}%, with {}/40 BER {:.2}%",
        off.ok,
        100.0 * off.bit_errors as f64 / off.bits as f64,
        on.ok,
        100.0 * on.bit_errors as f64 / on.bits as f64
    );
    assert!(on.bit_errors < off.bit_errors, "equalization must lower the raw bit error count");
    assert!(on.ok > off.ok, "compensation must decode more superframes");
}

#[test]
fn compensation_is_neutral_on_a_clean_channel() {
    for gear in [ModemGear::Narrowband1200, ModemGear::Wideband2400, ModemGear::Robust300] {
        let blocks = payload(1, 4);
        let tx = transmit(gear, &blocks);
        let r = receive(gear, &tx, &blocks, true);
        assert_eq!((r.ok, r.bit_errors), (4, 0), "{:?}", gear);
    }
}

// ---- Reference copy of the pre-Robust300 modulator and interleaver (wire format of gears 1/2).

const REF_CODEBOOK_2_OF_7: [[u8; 2]; 16] = [
    [0, 1], [0, 2], [0, 3], [0, 4], [0, 5], [0, 6],
    [1, 2], [1, 3], [1, 4], [1, 5], [1, 6],
    [2, 3], [2, 4], [2, 5], [2, 6],
    [3, 5],
];
const REF_CODEBOOK_3_OF_6: [[u8; 3]; 16] = [
    [0, 1, 2], [0, 1, 3], [0, 1, 4], [0, 1, 5],
    [0, 2, 3], [0, 2, 4], [0, 2, 5],
    [0, 3, 4], [0, 3, 5], [0, 4, 5],
    [1, 2, 3], [1, 2, 4], [1, 2, 5],
    [1, 3, 4], [1, 3, 5], [2, 4, 5],
];

fn ref_initial_phase(bin: usize, frame_idx: u32) -> f32 {
    let seed = (bin as f32) * 2.399_963_2 + (frame_idx as f32) * 0.618_033_9;
    seed % (2.0 * PI)
}

fn ref_modulate_frame(narrow: bool, bits: &[u8], frame_counter: u32) -> [i16; 320] {
    let mut window = [1.0f32; 320];
    for i in 0..32 {
        let w = 0.5 * (1.0 - (PI * i as f32 / 32.0).cos());
        window[i] = w;
        window[319 - i] = w;
    }
    let bands = if narrow { 6 } else { 12 };
    let mut accum = [0.0f32; 320];
    let pilot_phase0 = (frame_counter as f32) * 0.5;
    let pilot_omega = 2.0 * PI * 375.0 / 16_000.0;
    for (n, dst) in accum.iter_mut().enumerate() {
        *dst += 1.25 * (pilot_omega * n as f32 + pilot_phase0).sin();
    }
    for b in 0..bands {
        let sym = ((bits[b * 4] & 1) << 3) | ((bits[b * 4 + 1] & 1) << 2) | ((bits[b * 4 + 2] & 1) << 1) | (bits[b * 4 + 3] & 1);
        let base_bin = if narrow { 8 + b * 7 } else { 8 + b * 8 };
        let tones: Vec<u8> = if narrow {
            REF_CODEBOOK_3_OF_6[sym as usize].to_vec()
        } else {
            REF_CODEBOOK_2_OF_7[sym as usize].to_vec()
        };
        for &t in &tones {
            let bin = base_bin + t as usize;
            let freq = bin as f32 * 62.5;
            let omega = 2.0 * PI * freq / 16_000.0;
            let ph = ref_initial_phase(bin, frame_counter);
            for (n, dst) in accum.iter_mut().enumerate() {
                *dst += (omega * n as f32 + ph).sin();
            }
        }
    }
    let norm = if narrow { 1400.0 } else { 1050.0 };
    let mut pcm = [0i16; 320];
    for i in 0..320 {
        pcm[i] = (accum[i] * window[i] * norm).clamp(-30_000.0, 30_000.0).round() as i16;
    }
    pcm
}

fn ref_interleave(coded: &[u8; 384], num_frames: usize) -> [u8; 384] {
    let cols = 384 / num_frames;
    let col_stride = match cols {
        48 => 17,
        24 => 7,
        _ => 1,
    };
    let mut out = [0u8; 384];
    for i in 0..384 {
        out[(i % num_frames) * cols + ((i / num_frames) * col_stride) % cols] = coded[i];
    }
    out
}

#[test]
fn existing_gears_keep_bit_identical_wire_output() {
    for (gear, narrow) in [(ModemGear::Narrowband1200, true), (ModemGear::Wideband2400, false)] {
        let fps = gear.frames_per_superframe();
        let bpf = gear.bits_per_frame();
        let mut m = FormantModulator::new(gear);
        let mut counter = 0u32;
        for block in payload(11, 12) {
            let il = interleave_384(&encode_superframe_fec(&block), fps);
            assert_eq!(il, ref_interleave(&encode_superframe_fec(&block), fps), "{:?} interleaver", gear);
            let got = m.modulate_superframe(&il);
            for f in 0..fps {
                let want = ref_modulate_frame(narrow, &il[f * bpf..(f + 1) * bpf], counter);
                counter += 1;
                assert_eq!(&got[f * 320..(f + 1) * 320], &want[..], "{:?} frame {}", gear, counter - 1);
            }
        }
    }
}

