//! Test-signal construction: known pseudo-random payload, FEC/framing path shared with the product.

use crate::dsp::{rms_dbfs, Rng};
use aegiscall_modem::{
    encode_superframe_fec, interleave_384, synthesize_preamble, FormantModulator, ModemGear,
    PreambleCapabilities, VoiceTimbre, SAMPLE_RATE, SUPERFRAME_BYTES,
};

/// Payload of superframe `index` for `seed` (deterministic).
pub fn frame_data(seed: u64, index: usize) -> [u8; SUPERFRAME_BYTES] {
    let mut rng = Rng(seed ^ (index as u64 + 1).wrapping_mul(0xD6E8_FEB8_6659_FD93));
    let mut out = [0u8; SUPERFRAME_BYTES];
    for chunk in out.chunks_mut(8) {
        let v = rng.next_u64().to_le_bytes();
        chunk.copy_from_slice(&v[..chunk.len()]);
    }
    out
}

pub struct GenParams {
    pub gear: ModemGear,
    pub frames: usize,
    pub seed: u64,
    pub lead_ms: u32,
    pub tail_ms: u32,
    pub level_dbfs: f64,
    /// Insert another preamble before every K-th superframe (0 = only one preamble).
    pub repeat: usize,
}

pub struct GenOut {
    pub pcm: Vec<i16>,
    pub clipped: usize,
    pub peak_dbfs: f64,
    pub active_rms_dbfs: f64,
    pub preambles: usize,
    /// First sample of every superframe in `pcm`.
    pub sf_start: Vec<usize>,
    /// First sample of every preamble in `pcm`.
    pub preamble_start: Vec<usize>,
}

/// Preamble(s) plus `frames` superframes at the modulator's native level, with the start of every
/// superframe and every preamble.
fn build_active(p: &GenParams, timbre: VoiceTimbre) -> (Vec<i16>, Vec<usize>, Vec<usize>) {
    let caps = PreambleCapabilities::v2(p.gear);
    let preamble = synthesize_preamble(caps);
    let fps = p.gear.frames_per_superframe();
    let mut modulator = FormantModulator::new_with_timbre(p.gear, timbre);
    let mut pcm = Vec::new();
    let mut sf_start = Vec::with_capacity(p.frames);
    let mut preamble_start = Vec::new();
    for i in 0..p.frames {
        if i == 0 || (p.repeat > 0 && i % p.repeat == 0) {
            preamble_start.push(pcm.len());
            pcm.extend_from_slice(&preamble);
        }
        let coded = encode_superframe_fec(&frame_data(p.seed, i));
        let interleaved = interleave_384(&coded, fps);
        sf_start.push(pcm.len());
        pcm.extend_from_slice(&modulator.modulate_superframe(&interleaved));
    }
    (pcm, sf_start, preamble_start)
}

pub fn gen_pcm(p: &GenParams) -> GenOut {
    gen_pcm_with_timbre(p, VoiceTimbre::MaleBaritone)
}

pub fn gen_pcm_with_timbre(p: &GenParams, timbre: VoiceTimbre) -> GenOut {
    let (active, sf_rel, pre_rel) = build_active(p, timbre);
    let cur = rms_dbfs(&active);
    let gain = 10f64.powf((p.level_dbfs - cur) / 20.0);
    let lead = SAMPLE_RATE * p.lead_ms as usize / 1000;
    let tail = SAMPLE_RATE * p.tail_ms as usize / 1000;
    let mut pcm = vec![0i16; lead];
    let mut clipped = 0;
    for &s in &active {
        let v = (s as f64 * gain).round();
        if v > 32_767.0 || v < -32_768.0 {
            clipped += 1;
        }
        pcm.push(v.clamp(-32_768.0, 32_767.0) as i16);
    }
    let active_rms = rms_dbfs(&pcm[lead..]);
    pcm.extend(std::iter::repeat(0i16).take(tail));
    let peak = crate::dsp::peak_dbfs(&pcm);
    GenOut {
        pcm,
        clipped,
        peak_dbfs: peak,
        active_rms_dbfs: active_rms,
        preambles: pre_rel.len(),
        sf_start: sf_rel.iter().map(|&s| s + lead).collect(),
        preamble_start: pre_rel.iter().map(|&s| s + lead).collect(),
    }
}
