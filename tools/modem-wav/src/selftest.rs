//! selftest: gen -> simulated channel -> analyze, one line per scenario.

use crate::analyze::{analyze_pcm, summary_line, Params};
use crate::dsp::{bandpass, mulaw_decode, mulaw_encode, resample_rate, resample_step, to_f32, to_i16, Rng};
use crate::sig::{gen_pcm, GenParams};
use aegiscall_modem::{
    apply_channel_impairments, apply_codec_channel, ChannelProfile, CodecChannelProfile, ModemGear, SAMPLE_RATE,
};

/// 16 kHz -> 8 kHz -> G.711 mu-law -> 16 kHz (traditional telephone network).
fn pstn(pcm: &[i16]) -> Vec<i16> {
    let down = to_i16(&resample_rate(&to_f32(pcm), 16_000, 8_000));
    let companded: Vec<i16> = down.iter().map(|&s| mulaw_decode(mulaw_encode(s))).collect();
    to_i16(&resample_rate(&to_f32(&companded), 8_000, 16_000))
}

fn noise_and_drift(pcm: &[i16]) -> Vec<i16> {
    let mut rng = Rng(0x5EED_0E);
    let amp = 32_768.0 * 10f64.powf(-30.0 / 20.0); // -30 dBFS RMS white noise, 3 s
    let mut v: Vec<f32> = (0..3 * SAMPLE_RATE)
        .map(|_| (rng.normal() * amp / 32_768.0) as f32)
        .collect();
    v.extend(to_f32(pcm));
    let ratio = 1.005f64; // recording clock 0.5% slow: time axis stretched
    let out_len = (v.len() as f64 * ratio).round() as usize;
    to_i16(&resample_step(&v, 1.0 / ratio, out_len))
}

pub fn run(gear: ModemGear, name: &str, frames: usize, seed: u64) {
    let profile = match gear {
        ModemGear::Wideband2400 => ChannelProfile::volte_harsh(),
        ModemGear::Narrowband1200 | ModemGear::Robust300 | ModemGear::Speech300 => {
            ChannelProfile::gsm_legacy_harsh()
        }
    };
    let cases: Vec<(&str, &str, usize)> = vec![
        ("a", "lossless", 0),
        ("b", "channel_sim default impaired channel", 0),
        ("c", "8 kHz + G.711 mu-law", 0),
        ("d", "300-3400 Hz band-pass + (c)", 0),
        ("e", "3 s leading noise + 0.5% clock offset (single lead-in)", 0),
        ("e2", "same as (e), lead-in repeated every 10 frames (extra scenario)", 10),
        ("f", "measured-style codec channel (VoWiFi measurement parameters, lead-in repeated every 10 frames)", 10),
    ];
    println!("== Gear {}, {} frames, seed {} ==", name, frames, seed);
    for (id, label, repeat) in cases {
        let g = gen_pcm(&GenParams { gear, frames, seed, lead_ms: 1500, tail_ms: 1000, level_dbfs: -12.0, repeat });
        let rx = match id {
            "a" => g.pcm.clone(),
            "b" => apply_channel_impairments(&g.pcm, &profile),
            "c" => pstn(&g.pcm),
            "d" => pstn(&to_i16(&bandpass(&to_f32(&g.pcm), 300.0, 3400.0, 16_000.0))),
            "f" => apply_codec_channel(&g.pcm, &CodecChannelProfile::vowifi_measured()),
            _ => noise_and_drift(&g.pcm),
        };
        let rep = analyze_pcm(&rx, 16_000, 1, &Params { gear, frames, seed, repeat });
        println!("[{}] ({}) {}：{}", name, id, label, summary_line(&rep));
    }
}
