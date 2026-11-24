//! Glottal-Formant Pseudo-Speech Vocoder (FOF Synthesis), Multi-Sentence Phonetic Articulator,
//! Vowel-Glide Utterance Preamble, Conversational Cadence Shaper, and Big-Data Stealth Scanner.
//!
//! Designed to defeat both automated mass-surveillance DSP screening (across 10^8+ call records)
//! and human perceptual inspection while maintaining high survival over cellular CELP codecs
//! (AMR-WB, EVS, VoWiFi noise suppression):
//!
//! 1. **No Stationary Pilot Tone**: Replaces the fixed 375 Hz crystal-locked pilot with a
//!    7-syllable human prosodic pitch contour $F_0(t) \in [105.0, 152.0]\text{ Hz}$ (4.5 semitones
//!    of natural intonation + a slow +/-1.6 Hz vibrato, 4 cycles per superframe). All vocal-tract harmonics co-modulate
//!    with $F_0(t)$, fusing into a single human voice via Bregman harmonic co-modulation and
//!    smearing long-term spectral energy so no stationary narrowband line exists.
//! 2. **FOF (Formant Wave Function) Glottal-Pulse Excitation & Laryngeal Voice Bar**:
//!    Synthesizes the laryngeal fundamental ($F_0$), chest/pharyngeal harmonics ($2F_0, 3F_0$),
//!    and clause-final vocal-fry subharmonics ($1.5 F_0$), while modulating each vocal-tract
//!    formant ($F_1, F_2, F_3$) with phase-locked glottal-pulse FOF sidebands and pitch-synchronous
//!    aspiration breathiness.
//! 3. **Inter-Frame Formant Coarticulation (Zero 50 Hz Buzz)**: Unchanged formants sustain across
//!    20 ms boundaries at full amplitude with exact phase continuity; changing formants smoothly
//!    cross-fade inside the 32-sample guard transition so the demodulator's 256-sample core sees
//!    zero inter-symbol leakage while the audio stream has zero 50 Hz frame-edge notches.
//! 4. **Multi-Sentence Phonetic Articulation & 7 Consonant Classes**: Across a 4-superframe
//!    (5.12 s) paragraph cycle, varies syllable stress patterns, vowel openness ($F_1/F_2/F_3$
//!    balance), $F_4$ speaker resonance, and 7 distinct consonant onset articulations
//!    (nasals `/m/, /n/`, sibilants `/s/, /ʃ/`, plosive bursts `/t/, /k/`, liquids `/l/, /w/`,
//!    and glottal aspiration `/h/`).
//! 5. **Vowel-Glide Utterance Preamble (`/wau/`)**: Replaces the 600–1900 Hz V-Chirp
//!    siren with a 3-formant + voice-bar human diphthong (`/o/ -> /a/ -> /o/`) detected via an
//!    incoherent multi-formant analytic complex correlator.

use crate::demodulator::dft_energy_at_freq;
use crate::fec::{crc8_atm, encode_short_fec};
use crate::modulator::{
    subband_start_bin, ModemGear, BIN_HZ, DFT_WINDOW_SAMPLES, FRAME_SAMPLES, GUARD_EDGE_SAMPLES,
    PILOT_BIN, SAMPLE_RATE,
};
use crate::preamble::{
    PreambleCapabilities, RawPreambleDetection, PREAMBLE_MAGIC, TOTAL_PREAMBLE_SAMPLES,
};
use std::f32::consts::PI;

/// Number of 20 ms frames in one Speech300 superframe (1.28 s).
pub const SPEECH_SUPERFRAME_FRAMES: usize = 64;

/// Non-uniform human syllable durations in 20 ms frames summing to 64 frames (1.28 s):
/// 180 ms, 160 ms, 200 ms, 180 ms, 160 ms, 200 ms, 200 ms (~5.47 syllables/sec).
pub const SYLLABLE_FRAME_LENGTHS: [usize; 7] = [9, 8, 10, 9, 8, 10, 10];

/// Target center pitch F0 (Hz) for each of the 7 syllables in a 1.28 s phrase, modeling natural
/// human sentence intonation (initial rise, emphatic peak on syllable 2, gradual declination).
const SYLLABLE_BASE_F0_HZ: [f32; 7] = [136.0, 124.0, 143.0, 118.5, 131.0, 113.0, 108.5];

/// Pitch inflection arch (Hz) within each syllable (positive = rising-falling arch, negative = dipping).
const SYLLABLE_ARCH_HZ: [f32; 7] = [10.5, -8.5, 12.0, -9.5, 9.5, -7.5, -8.0];

/// Directional pitch glide (Hz) across each syllable (models Mandarin/conversational tonal contours).
const SYLLABLE_GLIDE_HZ: [f32; 7] = [8.0, -10.0, 6.5, -11.0, -7.5, 5.5, -9.0];

/// Four distinct sentence stress patterns across a 4-superframe (5.12 s) paragraph cycle,
/// preventing repetitive 1.28 s looping while keeping the demodulator 100% frame-stateless.
const SENTENCE_STRESS_TABLE: [[f32; 7]; 4] = [
    // Sentence 0: Declarative statement (strong opening and mid peak, falling terminal coda)
    [1.08, 0.92, 1.16, 0.90, 1.04, 0.88, 0.78],
    // Sentence 1: Interrogative / expressive clause (rising prominence toward end of clause)
    [0.94, 1.10, 0.90, 1.06, 0.92, 1.12, 1.05],
    // Sentence 2: Rapid conversational cadence (alternating trochaic stress)
    [1.12, 0.86, 1.08, 0.88, 1.14, 0.86, 0.82],
    // Sentence 3: Calm concluding clause (warm mid-clause emphasis, soft breathy trail-off)
    [0.98, 1.04, 1.12, 0.96, 0.90, 0.84, 0.74],
];

/// Four distinct vowel-color formant tilt profiles (F1, F2, F3 weights) rotated across syllables
/// and sentences (open `/a/`, front `/e/-/i/`, rounded `/o/-/u/`, central `/ə/`).
const VOWEL_COLOR_TILT: [[f32; 3]; 4] = [
    [1.14, 1.02, 0.88], // Open vowel (/a/, /ɑ/): strong F1 jaw resonance
    [0.98, 1.10, 0.96], // Front vowel (/e/, /i/): bright F2/F3 tongue advancement
    [1.12, 0.94, 0.86], // Rounded back vowel (/o/, /u/): warm low F1/F2
    [1.06, 1.00, 0.92], // Neutral schwa/sonorant (/ə/, /l/): balanced vocal tract
];

/// Seven phonetic consonant onset classes rotated across syllables and sentences.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConsonantOnset {
    /// `/m/` or `/n/`: low 250 Hz nasal murmur + gentle high-formant damping in onset guard.
    NasalMurmur,
    /// `/s/`: crisp alveolar sibilant turbulence centered around 2950 Hz.
    AlveolarSibilant,
    /// `/l/` or `/w/`: warm sonorant liquid/glide with strong voice bar and smooth formant onset.
    LiquidGlide,
    /// `/t/` or `/k/`: brief pre-release closure dip in guard edge + 8 ms plosive burst at 2450 Hz.
    PlosiveBurst,
    /// `/ʃ/` or `/f/`: soft postalveolar fricative centered around 2400 Hz.
    PostalveolarFricative,
    /// `/r/` or `/j/`: palatal approximant with strong F3/F4 resonance.
    PalatalApproximant,
    /// `/h/`: pitch-synchronous glottal breath aspiration across syllable onset.
    GlottalAspiration,
}

impl ConsonantOnset {
    #[inline]
    fn for_syllable(sentence_idx: usize, syl_idx: usize) -> Self {
        use ConsonantOnset::*;
        const ORDER: [ConsonantOnset; 7] = [
            LiquidGlide,
            AlveolarSibilant,
            NasalMurmur,
            PlosiveBurst,
            PostalveolarFricative,
            PalatalApproximant,
            GlottalAspiration,
        ];
        ORDER[(syl_idx + sentence_idx * 3) % 7]
    }
}

/// Speaker voice timbre profile for conversational synthesis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VoiceTimbre {
    /// Adult male baritone/tenor vocal tract ($F_0 \in [105, 152]\text{ Hz}$, strong chest resonance).
    MaleBaritone,
    /// Adult female contralto/mezzo vocal tract (warmer upper harmonics $2F_0/3F_0$, higher $F_4$ resonance).
    FemaleContralto,
}

// Vowel-Glide Preamble parameters: 120 ms `/o/ -> /a/` up-glide + 120 ms `/a/ -> /o/` down-glide.
// All three vocal-tract formants shift in parallel by +400 Hz (and -400 Hz), giving an exact
// common chirp slope S = 3333.33 Hz/s for CFO-invariant multi-formant complex correlation.
const GLIDE_SAMPLES: usize = 1920; // 120 ms @ 16 kHz
const GLIDE_DELTA_HZ: f32 = 400.0;
const GLIDE_SLOPE: f32 = GLIDE_DELTA_HZ / (GLIDE_SAMPLES as f32 / SAMPLE_RATE as f32); // 3333.3333 Hz/s
const GLIDE_FORMANTS_F0: [f32; 3] = [420.0, 980.0, 1580.0]; // `/o/` vowel formants (F1, F2, F3)
const GLIDE_FORMANT_WEIGHTS: [f32; 3] = [1.00, 0.88, 0.70];
const TRAILER_FRAMES: usize = 8;
const TRAILER_BANDS: usize = 6;

/// Returns `(syllable_index, frame_in_syllable, syllable_len)` for `m in 0..64`.
#[inline]
pub fn syllable_position(frame_in_sf: usize) -> (usize, usize, usize) {
    let m = frame_in_sf % SPEECH_SUPERFRAME_FRAMES;
    let mut acc = 0usize;
    for (s, &len) in SYLLABLE_FRAME_LENGTHS.iter().enumerate() {
        if m < acc + len {
            return (s, m - acc, len);
        }
        acc += len;
    }
    (6, 0, SYLLABLE_FRAME_LENGTHS[6])
}

/// Deterministic human fundamental pitch $F_0(m)$ in Hz for frame `frame_idx`.
/// Smoothly varies across `[105.0, 152.0] Hz` with natural phrase declination, syllable arch,
/// tonal glide, and a +/-1.6 Hz vibrato of 4 cycles per 1.28 s superframe (about 3.1 Hz).
#[inline]
pub fn frame_f0_hz(frame_idx: usize) -> f32 {
    let m = frame_idx % SPEECH_SUPERFRAME_FRAMES;
    let (s, pos, len) = syllable_position(m);
    let u = (pos as f32 + 0.5) / len as f32; // 0..1 within syllable
    let arch = SYLLABLE_ARCH_HZ[s] * ((PI * u).sin() - 0.5);
    let glide = SYLLABLE_GLIDE_HZ[s] * (u - 0.5);
    let vibrato = 1.6 * (2.0 * PI * 4.0 * (m as f32) / (SPEECH_SUPERFRAME_FRAMES as f32)).sin();
    (SYLLABLE_BASE_F0_HZ[s] + arch + glide + vibrato).clamp(105.0, 152.0)
}

/// Ratio $\alpha(m) = F_0(m) / 125.0\text{ Hz}$ by which all vocal harmonics scale in frame `frame_idx`.
#[inline]
pub fn frame_pitch_scale(frame_idx: usize) -> f32 {
    frame_f0_hz(frame_idx) / 125.0
}

/// Prefix sum of `frame_pitch_scale(0..m)` so cumulative glottal phase at frame `k` is exact in O(1).
fn cumulative_pitch_scale(frame_counter: u32) -> f64 {
    let mut table = [0.0f64; SPEECH_SUPERFRAME_FRAMES + 1];
    for m in 0..SPEECH_SUPERFRAME_FRAMES {
        table[m + 1] = table[m] + frame_pitch_scale(m) as f64;
    }
    let q = (frame_counter as usize) / SPEECH_SUPERFRAME_FRAMES;
    let r = (frame_counter as usize) % SPEECH_SUPERFRAME_FRAMES;
    (q as f64) * table[SPEECH_SUPERFRAME_FRAMES] + table[r]
}

/// Exact starting phase of bin `bin` at sample 0 of `frame_counter`, maintaining 100% phase
/// continuity across frame boundaries under time-varying pitch scale $\alpha(m)$, with Rosenberg
/// glottal pulse phase dispersion across harmonics.
#[inline]
pub fn glottal_continuous_phase(bin: usize, frame_counter: u32) -> f32 {
    let cycles = (1.25 * (bin as f64) * cumulative_pitch_scale(frame_counter)).fract();
    let h = bin as f64 * 0.5;
    let glottal_disp = (-0.38 * h - 0.047 * h * h).rem_euclid(2.0 * std::f64::consts::PI);
    ((cycles * 2.0 * std::f64::consts::PI + glottal_disp) % (2.0 * std::f64::consts::PI)) as f32
}

/// Natural syllabic amplitude envelope for sample `n` (`0..320`) inside frame `frame_counter`.
/// Varies across a 4-sentence (5.12 s) prosodic paragraph so consecutive superframes have
/// distinct sentence rhythm and stress contours.
#[inline]
pub fn syllable_envelope(frame_counter: usize, sample_in_frame: usize) -> f32 {
    let sentence_idx = (frame_counter / SPEECH_SUPERFRAME_FRAMES) % 4;
    let m = frame_counter % SPEECH_SUPERFRAME_FRAMES;
    let (s, pos, len) = syllable_position(m);
    let u = (pos as f32 + (sample_in_frame as f32 / FRAME_SAMPLES as f32)) / (len as f32);

    // Consonant-dependent onset attack speed (plosives/liquids have crisper attack than fricatives)
    let onset_end = match ConsonantOnset::for_syllable(sentence_idx, s) {
        ConsonantOnset::PlosiveBurst => 0.16,
        ConsonantOnset::NasalMurmur | ConsonantOnset::LiquidGlide => 0.20,
        _ => 0.25,
    };

    let shape = if u < onset_end {
        let t = u / onset_end;
        0.50 + 0.50 * (0.5 * (1.0 - (PI * t).cos()))
    } else if u < 0.68 {
        // Gentle micro-shimmer inside vowel nucleus for natural vocal warmth
        let shimmer = 0.03 * (2.0 * PI * 3.0 * u).sin();
        1.0 + shimmer
    } else {
        let t = (u - 0.68) / 0.32;
        1.0 - 0.48 * (0.5 * (1.0 - (PI * t).cos()))
    };

    let stress = SENTENCE_STRESS_TABLE[sentence_idx][s];
    (shape * stress).clamp(0.45, 1.22)
}

/// Deterministic pseudo-random sample in `[-1.0, 1.0]` for consonant aspiration bursts.
#[inline]
fn aspiration_noise(frame_counter: u32, sample_idx: usize) -> f32 {
    let mut z = (frame_counter as u64)
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add((sample_idx as u64).wrapping_mul(0xBF58_476D_1CE4_E5B9));
    z = (z ^ (z >> 30)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^= z >> 31;
    let u = ((z >> 40) as f32 / (1u64 << 24) as f32) - 0.5;
    u * 2.0
}

/// Synthesizes one 20 ms (320-sample) `Speech300` frame from 6 coded bits (3 formant bands x 2 bits).
pub fn modulate_speech_frame(
    bits: &[u8],
    frame_counter: u32,
    prev_bins: &mut [Option<usize>; 3],
) -> [i16; FRAME_SAMPLES] {
    modulate_speech_frame_with_timbre(bits, frame_counter, prev_bins, VoiceTimbre::MaleBaritone)
}

/// Synthesizes one 20 ms (320-sample) `Speech300` frame with the selected speaker `VoiceTimbre`.
pub fn modulate_speech_frame_with_timbre(
    bits: &[u8],
    frame_counter: u32,
    prev_bins: &mut [Option<usize>; 3],
    timbre: VoiceTimbre,
) -> [i16; FRAME_SAMPLES] {
    let gear = ModemGear::Speech300;
    let bands = gear.subband_count();
    let bpb = gear.bits_per_band();
    debug_assert_eq!(bits.len(), bands * bpb);

    let sentence_idx = ((frame_counter as usize) / SPEECH_SUPERFRAME_FRAMES) % 4;
    let m = (frame_counter as usize) % SPEECH_SUPERFRAME_FRAMES;
    let (syl_idx, pos_in_syl, syl_len) = syllable_position(m);
    let onset_kind = ConsonantOnset::for_syllable(sentence_idx, syl_idx);

    let alpha = frame_pitch_scale(m);
    let prev_alpha = if frame_counter == 0 {
        alpha
    } else {
        frame_pitch_scale((frame_counter as usize - 1) % SPEECH_SUPERFRAME_FRAMES)
    };

    let mut accum = [0.0f32; FRAME_SAMPLES];

    // 1. Laryngeal Glottal Voice Bar (F0 at bin 2, 2*F0 at bin 4, 3*F0 at bin 6 = PILOT_BIN)
    // plus subtle clause-final vocal fry sub-harmonic (1.5*F0 at bin 3) on syllable 6.
    let (a_f0, a_2f0, a_3f0) = match timbre {
        VoiceTimbre::MaleBaritone => (0.46f32, 0.38f32, 0.42f32),
        VoiceTimbre::FemaleContralto => (0.28f32, 0.48f32, 0.46f32),
    };
    let nasal_boost = if pos_in_syl == 0 && onset_kind == ConsonantOnset::NasalMurmur {
        1.25f32
    } else {
        1.0f32
    };
    for &(bin, amp) in &[
        (2usize, a_f0),
        (4usize, a_2f0 * nasal_boost),
        (PILOT_BIN, a_3f0),
    ] {
        let omega = 2.0 * PI * (bin as f32 * BIN_HZ * alpha) / SAMPLE_RATE as f32;
        let ph = glottal_continuous_phase(bin, frame_counter);
        for (n, dst) in accum.iter_mut().enumerate() {
            *dst += amp * (omega * n as f32 + ph).sin();
        }
    }
    // Natural end-of-clause vocal fry / creaky voice resonance on the last syllable
    if syl_idx == 6 && pos_in_syl >= syl_len / 2 {
        let omega_fry = 2.0 * PI * (3.0 * BIN_HZ * alpha) / SAMPLE_RATE as f32;
        let ph_fry = glottal_continuous_phase(3, frame_counter);
        for (n, dst) in accum.iter_mut().enumerate() {
            *dst += 0.14 * (omega_fry * n as f32 + ph_fry).sin();
        }
    }

    // Precompute instantaneous glottal-pulse FOF envelope: `1.0 + fof_depth * cos(omega_half_f0 * n + ph_g)`.
    // In the frequency domain, multiplying an even-bin formant carrier `bin` by `cos(omega_half_f0 * n)`
    // places coherent glottal resonator skirts ONLY on the adjacent ODD bins `bin - 1` and `bin + 1`,
    // leaving the even demodulator candidate bins `[0, 2, 4, 6]` completely uncontaminated while
    // transforming pure sine tones into damped glottal-pulse vocal-tract oscillations (IRCAM FOF).
    let omega_half_f0 = 2.0 * PI * (BIN_HZ * alpha) / SAMPLE_RATE as f32;
    let ph_g = glottal_continuous_phase(1, frame_counter);
    let fof_depth = match timbre {
        VoiceTimbre::MaleBaritone => 0.24f32,
        VoiceTimbre::FemaleContralto => 0.18f32,
    };

    // 2. Three Vocal-Tract Formants (F1, F2, F3) with dynamic vowel-color tilt, FOF glottal
    //    pulse shaping, and 32-sample inter-frame coarticulation.
    let vowel_tilt = VOWEL_COLOR_TILT[(syl_idx + sentence_idx) % 4];
    for b in 0..bands {
        let mut sym = 0usize;
        for q in 0..bpb {
            sym = (sym << 1) | (bits[b * bpb + q] & 1) as usize;
        }
        let offset = gear.codeword(sym)[0] as usize;
        let bin = subband_start_bin(gear, b) + offset;
        let amp = vowel_tilt[b];
        let omega_curr = 2.0 * PI * (bin as f32 * BIN_HZ * alpha) / SAMPLE_RATE as f32;
        let ph_curr = glottal_continuous_phase(bin, frame_counter);

        // Plosive or nasal consonant onset briefly softens upper formants inside the 32-sample guard edge
        let guard_consonant_dip = if pos_in_syl == 0
            && b > 0
            && matches!(onset_kind, ConsonantOnset::PlosiveBurst | ConsonantOnset::NasalMurmur)
        {
            0.55f32
        } else {
            1.0f32
        };

        match prev_bins[b] {
            Some(pbin) if pbin == bin => {
                for (n, dst) in accum.iter_mut().enumerate() {
                    let fof = 1.0 + fof_depth * (omega_half_f0 * n as f32 + ph_g).cos();
                    let g = if n < GUARD_EDGE_SAMPLES { guard_consonant_dip } else { 1.0 };
                    *dst += amp * g * fof * (omega_curr * n as f32 + ph_curr).sin();
                }
            }
            Some(pbin) => {
                let omega_prev = 2.0 * PI * (pbin as f32 * BIN_HZ * prev_alpha) / SAMPLE_RATE as f32;
                let ph_prev = glottal_continuous_phase(pbin, frame_counter);
                for n in 0..GUARD_EDGE_SAMPLES {
                    let w = 0.5 * (1.0 - (PI * n as f32 / GUARD_EDGE_SAMPLES as f32).cos());
                    let fof = 1.0 + fof_depth * (omega_half_f0 * n as f32 + ph_g).cos();
                    let s_prev = (omega_prev * n as f32 + ph_prev).sin();
                    let s_curr = (omega_curr * n as f32 + ph_curr).sin();
                    accum[n] += amp * guard_consonant_dip * fof * ((1.0 - w) * s_prev + w * s_curr);
                }
                for n in GUARD_EDGE_SAMPLES..FRAME_SAMPLES {
                    let fof = 1.0 + fof_depth * (omega_half_f0 * n as f32 + ph_g).cos();
                    accum[n] += amp * fof * (omega_curr * n as f32 + ph_curr).sin();
                }
            }
            None => {
                for n in 0..FRAME_SAMPLES {
                    let w = if n < GUARD_EDGE_SAMPLES {
                        0.5 * (1.0 - (PI * n as f32 / GUARD_EDGE_SAMPLES as f32).cos())
                    } else {
                        1.0
                    };
                    let fof = 1.0 + fof_depth * (omega_half_f0 * n as f32 + ph_g).cos();
                    accum[n] += amp * w * fof * (omega_curr * n as f32 + ph_curr).sin();
                }
            }
        }
        prev_bins[b] = Some(bin);
    }

    // 3. F4 Speaker Identity Formant & Pitch-Synchronous Glottal Breathiness (>2250 Hz, completely
    //    above the 500..1875 Hz demodulation band).
    let f4_base = match timbre {
        VoiceTimbre::MaleBaritone => 38,     // ~2375..2625 Hz
        VoiceTimbre::FemaleContralto => 42,  // ~2625..2875 Hz
    };
    let f4_bin = f4_base + ((syl_idx + sentence_idx) % 3) * 2;
    let omega_f4 = 2.0 * PI * (f4_bin as f32 * BIN_HZ * alpha) / SAMPLE_RATE as f32;
    let ph_f4 = glottal_continuous_phase(f4_bin, frame_counter);
    let mut breath_lp = 0.0f32;
    for (n, dst) in accum.iter_mut().enumerate() {
        let raw = aspiration_noise(frame_counter ^ 0x55AA, n);
        breath_lp = 0.65 * breath_lp + 0.35 * raw;
        // Glottal open-phase synchronous aspiration whisper around F4
        let glottal_gate = 0.5 * (1.0 + (2.0 * omega_half_f0 * n as f32 + ph_g).sin());
        *dst += (0.15 + 0.04 * glottal_gate * breath_lp) * (omega_f4 * n as f32 + ph_f4).sin();
    }

    // 4. Syllable-Onset Consonant Articulation (7 phonetic consonant classes).
    if pos_in_syl == 0 {
        let (center_hz, amp_c, decay_samples) = match onset_kind {
            ConsonantOnset::AlveolarSibilant => (2950.0f32, 0.25f32, 170.0f32),
            ConsonantOnset::PostalveolarFricative => (2420.0f32, 0.22f32, 160.0f32),
            ConsonantOnset::PlosiveBurst => (2520.0f32, 0.28f32, 85.0f32),
            ConsonantOnset::GlottalAspiration => (2280.0f32, 0.20f32, 210.0f32),
            ConsonantOnset::PalatalApproximant => (2680.0f32, 0.14f32, 130.0f32),
            ConsonantOnset::NasalMurmur | ConsonantOnset::LiquidGlide => (2350.0f32, 0.10f32, 110.0f32),
        };
        let omega_c = 2.0 * PI * center_hz / SAMPLE_RATE as f32;
        let mut lp_noise = 0.0f32;
        for n in 0..FRAME_SAMPLES {
            let raw = aspiration_noise(frame_counter, n);
            lp_noise = 0.70 * lp_noise + 0.30 * raw;
            let env = if onset_kind == ConsonantOnset::PlosiveBurst && n < 12 {
                // Brief 0.75 ms pre-burst closure before plosive release
                (n as f32 / 12.0).powi(2)
            } else {
                (-(n as f32) / decay_samples).exp()
            };
            accum[n] += amp_c * env * lp_noise * (omega_c * n as f32).cos();
        }
    }

    // 5. Apply natural 5.5 Hz multi-sentence syllabic amplitude envelope & convert to 16-bit PCM.
    let norm = 2850.0f32;
    let mut pcm = [0i16; FRAME_SAMPLES];
    for (n, dst) in pcm.iter_mut().enumerate() {
        let env = syllable_envelope(frame_counter as usize, n);
        let s = (accum[n] * env * norm).clamp(-30_000.0, 30_000.0);
        *dst = s.round() as i16;
    }
    pcm
}

// ---------------------------------------------------------------------------
// Vowel-Glide Utterance Preamble (`/wau/`)
// ---------------------------------------------------------------------------

fn generate_vowel_up_glide() -> Vec<f32> {
    let mut buf = vec![0.0f32; GLIDE_SAMPLES];
    for (n, dst) in buf.iter_mut().enumerate() {
        let t = n as f32 / SAMPLE_RATE as f32;
        let env = if n < 96 {
            0.5 * (1.0 - (PI * n as f32 / 96.0).cos())
        } else if n >= GLIDE_SAMPLES - 64 {
            0.78 + 0.22 * 0.5 * (1.0 + (PI * (n - (GLIDE_SAMPLES - 64)) as f32 / 64.0).cos())
        } else {
            1.0
        };
        // Laryngeal voice bar gliding 125 -> 162 Hz + FOF glottal pulse modulation
        let ph_f0 = 2.0 * PI * (125.0 * t + 0.5 * (37.0 / 0.12) * t * t);
        let fof = 1.0 + 0.20 * ph_f0.cos();
        let mut sample = 0.28 * ph_f0.sin() + 0.20 * (2.0 * ph_f0 - 0.4).sin();
        for (k, (&f0, &w)) in GLIDE_FORMANTS_F0.iter().zip(GLIDE_FORMANT_WEIGHTS.iter()).enumerate() {
            let ph = 2.0 * PI * (f0 * t + 0.5 * GLIDE_SLOPE * t * t) - (k as f32) * 0.7;
            sample += w * fof * ph.sin();
        }
        *dst = sample * env * 0.52;
    }
    buf
}

fn generate_vowel_down_glide() -> Vec<f32> {
    let mut buf = vec![0.0f32; GLIDE_SAMPLES];
    for (n, dst) in buf.iter_mut().enumerate() {
        let t = n as f32 / SAMPLE_RATE as f32;
        let env = if n < 64 {
            0.78 + 0.22 * 0.5 * (1.0 - (PI * n as f32 / 64.0).cos())
        } else if n >= GLIDE_SAMPLES - 96 {
            0.5 * (1.0 - (PI * (GLIDE_SAMPLES - 1 - n) as f32 / 96.0).cos())
        } else {
            1.0
        };
        let ph_f0 = 2.0 * PI * (162.0 * t - 0.5 * (44.0 / 0.12) * t * t);
        let fof = 1.0 + 0.20 * ph_f0.cos();
        let mut sample = 0.28 * ph_f0.sin() + 0.20 * (2.0 * ph_f0 - 0.4).sin();
        for (k, (&f0, &w)) in GLIDE_FORMANTS_F0.iter().zip(GLIDE_FORMANT_WEIGHTS.iter()).enumerate() {
            let f1 = f0 + GLIDE_DELTA_HZ;
            let ph = 2.0 * PI * (f1 * t - 0.5 * GLIDE_SLOPE * t * t) - (k as f32) * 0.7;
            sample += w * fof * ph.sin();
        }
        *dst = sample * env * 0.52;
    }
    buf
}

#[inline]
fn trailer_band_start_bin(band: usize) -> usize {
    // 6 subbands in 500..2250 Hz: bins 8, 13, 18, 23, 28, 33 (4 offsets + 1 guard bin each)
    8 + band * 5
}

const TRAILER_GRAY_1_OF_4: [u8; 4] = [0, 1, 3, 2];

fn interleave_trailer_96(coded: &[u8]) -> [u8; 96] {
    let mut out = [0u8; 96];
    for i in 0..96 {
        let b = if i < coded.len() { coded[i] } else { 0 };
        let frame = i % TRAILER_FRAMES;
        let col = i / TRAILER_FRAMES;
        out[frame * 12 + col] = b;
    }
    out
}

fn deinterleave_trailer_96(llr: &[f32; 96]) -> [f32; 96] {
    let mut out = [0.0f32; 96];
    for i in 0..96 {
        let frame = i % TRAILER_FRAMES;
        let col = i / TRAILER_FRAMES;
        out[i] = llr[frame * 12 + col];
    }
    out
}

/// Synthesizes the 400 ms (6,400 samples) Human Vowel-Glide Utterance Preamble for `Speech300`.
pub fn synthesize_speech_preamble(caps: PreambleCapabilities) -> Vec<i16> {
    let up = generate_vowel_up_glide();
    let down = generate_vowel_down_glide();
    let mut pcm = Vec::with_capacity(TOTAL_PREAMBLE_SAMPLES);

    for &s in &up {
        pcm.push((s * 9_200.0).round().clamp(-30_000.0, 30_000.0) as i16);
    }
    for &s in &down {
        pcm.push((s * 9_200.0).round().clamp(-30_000.0, 30_000.0) as i16);
    }

    let bytes = caps.encode_bytes();
    let coded = encode_short_fec(&bytes);
    let il = interleave_trailer_96(&coded);
    const TILT: [f32; TRAILER_BANDS] = [1.05, 0.98, 0.92, 0.86, 0.80, 0.75];

    let mut prev_bins = [None; TRAILER_BANDS];
    for f in 0..TRAILER_FRAMES {
        let fbits = &il[f * 12..(f + 1) * 12];
        let mut accum = [0.0f32; FRAME_SAMPLES];
        for &(bin, amp) in &[(2usize, 0.42f32), (4usize, 0.30f32), (PILOT_BIN, 0.48f32)] {
            let omega = 2.0 * PI * (bin as f32 * BIN_HZ) / SAMPLE_RATE as f32;
            let ph = (1.25 * bin as f32 * f as f32 * 2.0 * PI) % (2.0 * PI);
            for (n, dst) in accum.iter_mut().enumerate() {
                *dst += amp * (omega * n as f32 + ph).sin();
            }
        }
        for b in 0..TRAILER_BANDS {
            let sym = (((fbits[b * 2] & 1) << 1) | (fbits[b * 2 + 1] & 1)) as usize;
            let bin = trailer_band_start_bin(b) + TRAILER_GRAY_1_OF_4[sym] as usize;
            let amp = TILT[b];
            let omega = 2.0 * PI * (bin as f32 * BIN_HZ) / SAMPLE_RATE as f32;
            let ph = (1.25 * bin as f32 * f as f32 * 2.0 * PI + (b as f32) * 1.1) % (2.0 * PI);
            match prev_bins[b] {
                Some(pbin) if pbin == bin => {
                    for (n, dst) in accum.iter_mut().enumerate() {
                        *dst += amp * (omega * n as f32 + ph).sin();
                    }
                }
                Some(pbin) => {
                    let omega_p = 2.0 * PI * (pbin as f32 * BIN_HZ) / SAMPLE_RATE as f32;
                    let ph_p = (1.25 * pbin as f32 * f as f32 * 2.0 * PI + (b as f32) * 1.1) % (2.0 * PI);
                    for n in 0..GUARD_EDGE_SAMPLES {
                        let w = 0.5 * (1.0 - (PI * n as f32 / GUARD_EDGE_SAMPLES as f32).cos());
                        accum[n] += amp * ((1.0 - w) * (omega_p * n as f32 + ph_p).sin() + w * (omega * n as f32 + ph).sin());
                    }
                    for n in GUARD_EDGE_SAMPLES..FRAME_SAMPLES {
                        accum[n] += amp * (omega * n as f32 + ph).sin();
                    }
                }
                None => {
                    for n in 0..FRAME_SAMPLES {
                        let w = if n < GUARD_EDGE_SAMPLES {
                            0.5 * (1.0 - (PI * n as f32 / GUARD_EDGE_SAMPLES as f32).cos())
                        } else {
                            1.0
                        };
                        accum[n] += amp * w * (omega * n as f32 + ph).sin();
                    }
                }
            }
            prev_bins[b] = Some(bin);
        }
        let frame_env = 0.96 - 0.14 * (f as f32 / TRAILER_FRAMES as f32);
        for (n, &a) in accum.iter().enumerate() {
            let tail_fade = if f == TRAILER_FRAMES - 1 && n >= FRAME_SAMPLES - GUARD_EDGE_SAMPLES {
                0.5 * (1.0 - (PI * (FRAME_SAMPLES - 1 - n) as f32 / GUARD_EDGE_SAMPLES as f32).cos())
            } else {
                1.0
            };
            let v = (a * frame_env * tail_fade * 2150.0).clamp(-30_000.0, 30_000.0);
            pcm.push(v.round() as i16);
        }
    }

    debug_assert_eq!(pcm.len(), TOTAL_PREAMBLE_SAMPLES);
    pcm
}

/// Precomputed multi-formant analytic complex templates for the Vowel-Glide Preamble.
pub struct VowelGlideCorrelator {
    cos_bank: [[f32; GLIDE_SAMPLES]; 3],
    sin_bank: [[f32; GLIDE_SAMPLES]; 3],
    up: bool,
}

impl VowelGlideCorrelator {
    pub fn new(up: bool) -> Self {
        let mut cos_bank = [[0.0f32; GLIDE_SAMPLES]; 3];
        let mut sin_bank = [[0.0f32; GLIDE_SAMPLES]; 3];
        let slope = if up { GLIDE_SLOPE } else { -GLIDE_SLOPE };
        for (k, &f_base) in GLIDE_FORMANTS_F0.iter().enumerate() {
            let f0 = if up { f_base } else { f_base + GLIDE_DELTA_HZ };
            for n in 0..GLIDE_SAMPLES {
                let t = n as f32 / SAMPLE_RATE as f32;
                let ph = 2.0 * PI * (f0 * t + 0.5 * slope * t * t);
                let (s, c) = ph.sin_cos();
                cos_bank[k][n] = c;
                sin_bank[k][n] = s;
            }
        }
        Self { cos_bank, sin_bank, up }
    }

    /// Evaluates the normalized incoherent 3-formant complex correlation at sample `idx`.
    #[inline]
    pub fn score_at(&self, signal: &[f32], idx: usize) -> f32 {
        if idx + GLIDE_SAMPLES > signal.len() {
            return 0.0;
        }
        let _ = self.up;
        let win = &signal[idx..idx + GLIDE_SAMPLES];
        let mut sig_e = 1e-9f32;
        let mut re = [0.0f32; 3];
        let mut im = [0.0f32; 3];
        for n in (0..GLIDE_SAMPLES).step_by(2) {
            let x = win[n];
            sig_e += x * x;
            re[0] += x * self.cos_bank[0][n];
            im[0] += x * self.sin_bank[0][n];
            re[1] += x * self.cos_bank[1][n];
            im[1] += x * self.sin_bank[1][n];
            re[2] += x * self.cos_bank[2][n];
            im[2] += x * self.sin_bank[2][n];
        }
        let corr_sq = (re[0] * re[0] + im[0] * im[0])
            + (re[1] * re[1] + im[1] * im[1])
            + (re[2] * re[2] + im[2] * im[2]);
        (corr_sq / (sig_e * (GLIDE_SAMPLES as f32 / 4.0))).sqrt().min(1.0)
    }

    pub fn scan_range(&self, signal: &[f32], start_min: usize, start_max: usize) -> (usize, f32) {
        let start_max = start_max.min(signal.len().saturating_sub(GLIDE_SAMPLES));
        if start_min > start_max {
            return (start_min, 0.0);
        }
        let mut best_idx = start_min;
        let mut best_score = 0.0f32;
        let mut idx = start_min;
        while idx <= start_max {
            let s = self.score_at(signal, idx);
            if s > best_score {
                best_score = s;
                best_idx = idx;
            }
            idx += 8;
        }
        let fine_lo = best_idx.saturating_sub(10).max(start_min);
        let fine_hi = (best_idx + 10).min(start_max);
        for pos in fine_lo..=fine_hi {
            let s = self.score_at(signal, pos);
            if s > best_score {
                best_score = s;
                best_idx = pos;
            }
        }
        (best_idx, best_score)
    }
}

fn decode_trailer_viterbi_5(llr: &[f32]) -> [u8; 5] {
    const POLY0: u8 = 0b1111001;
    const POLY1: u8 = 0b1011011;
    const STEPS: usize = 46; // 40 data + 6 tail
    let mut metrics = [f32::NEG_INFINITY; 64];
    metrics[0] = 0.0;
    let mut prev_state = [[0u8; 64]; STEPS];
    let mut prev_bit = [[0u8; 64]; STEPS];

    for step in 0..STEPS {
        let l0 = llr[2 * step];
        let l1 = llr[2 * step + 1];
        let mut next = [f32::NEG_INFINITY; 64];
        let max_in = if step >= 40 { 0 } else { 1 };
        for s in 0..64 {
            let m = metrics[s];
            if !m.is_finite() {
                continue;
            }
            for in_bit in 0..=max_in {
                let reg = ((in_bit as u8) << 6) | (s as u8);
                let o0 = ((reg & POLY0).count_ones() & 1) as u8;
                let o1 = ((reg & POLY1).count_ones() & 1) as u8;
                let ns = (reg >> 1) as usize;
                let cand = m + (if o0 == 1 { l0 } else { -l0 }) + (if o1 == 1 { l1 } else { -l1 });
                if cand > next[ns] {
                    next[ns] = cand;
                    prev_state[step][ns] = s as u8;
                    prev_bit[step][ns] = in_bit as u8;
                }
            }
        }
        metrics = next;
    }

    let mut cur = 0usize;
    let mut bits = [0u8; STEPS];
    for step in (0..STEPS).rev() {
        bits[step] = prev_bit[step][cur];
        cur = prev_state[step][cur] as usize;
    }

    let mut out = [0u8; 5];
    for byte_idx in 0..5 {
        let mut b = 0u8;
        for bit in 0..8 {
            b = (b << 1) | (bits[byte_idx * 8 + bit] & 1);
        }
        out[byte_idx] = b;
    }
    out
}

fn demodulate_speech_trailer(pcm: &[i16], trailer_start: usize, cfo_hz: f32) -> [u8; 5] {
    let mut raw_llr = [0.0f32; 96];
    for f in 0..TRAILER_FRAMES {
        let s = trailer_start + f * FRAME_SAMPLES;
        if s + FRAME_SAMPLES > pcm.len() {
            break;
        }
        let mut core = [0.0f32; DFT_WINDOW_SAMPLES];
        for i in 0..DFT_WINDOW_SAMPLES {
            core[i] = pcm[s + GUARD_EDGE_SAMPLES + i] as f32 / 32_768.0;
        }
        for b in 0..TRAILER_BANDS {
            let base = trailer_band_start_bin(b);
            let mut e = [0.0f32; 4];
            let mut sum = 1e-9f32;
            for sym in 0..4 {
                let bin = base + TRAILER_GRAY_1_OF_4[sym] as usize;
                let freq = bin as f32 * BIN_HZ + cfo_hz;
                let v = dft_energy_at_freq(&core, freq);
                e[sym] = v;
                sum += v;
            }
            for v in &mut e {
                *v /= sum;
            }
            for bit_pos in 0..2 {
                let shift = 1 - bit_pos;
                let mut max_one = f32::NEG_INFINITY;
                let mut max_zero = f32::NEG_INFINITY;
                for (sym, &score) in e.iter().enumerate() {
                    if ((sym >> shift) & 1) == 1 {
                        max_one = max_one.max(score);
                    } else {
                        max_zero = max_zero.max(score);
                    }
                }
                raw_llr[f * 12 + b * 2 + bit_pos] = ((max_one - max_zero) * 10.0).clamp(-8.0, 8.0);
            }
        }
    }
    let deint = deinterleave_trailer_96(&raw_llr);
    decode_trailer_viterbi_5(&deint[..92])
}

/// Scans `pcm` for the Human Vowel-Glide Utterance Preamble and decodes its capability trailer.
pub fn detect_speech_preamble_raw(pcm: &[i16]) -> Option<RawPreambleDetection> {
    if pcm.len() < TOTAL_PREAMBLE_SAMPLES {
        return None;
    }
    let signal: Vec<f32> = pcm.iter().map(|&s| s as f32 / 32_768.0).collect();
    let max_up_start = signal.len().saturating_sub(TOTAL_PREAMBLE_SAMPLES);
    let up_corr = VowelGlideCorrelator::new(true);
    let (up_idx, up_score) = up_corr.scan_range(&signal, 0, max_up_start);
    if up_score < 0.30 {
        return None;
    }

    let nominal_down = up_idx + GLIDE_SAMPLES;
    let down_min = nominal_down.saturating_sub(300);
    let down_max = (nominal_down + 300).min(signal.len().saturating_sub(GLIDE_SAMPLES));
    if down_min > down_max {
        return None;
    }
    let down_corr = VowelGlideCorrelator::new(false);
    let (down_idx, down_score) = down_corr.scan_range(&signal, down_min, down_max);
    if down_score < 0.30 {
        return None;
    }

    let true_down_nominal = (up_idx + down_idx + GLIDE_SAMPLES) / 2;
    let delta_samples = (down_idx as f32) - (up_idx as f32 + GLIDE_SAMPLES as f32);
    let estimated_cfo_hz =
        (delta_samples / (2.0 * SAMPLE_RATE as f32) * GLIDE_SLOPE).clamp(-60.0, 60.0);

    let trailer_start = true_down_nominal + GLIDE_SAMPLES;
    let trailer_end = trailer_start + TRAILER_FRAMES * FRAME_SAMPLES;
    if trailer_end > pcm.len() + 16 {
        return None;
    }
    let payload_start_sample = trailer_end.min(pcm.len());

    for cfo_try in [estimated_cfo_hz, 0.0, estimated_cfo_hz * 0.5] {
        let decoded = demodulate_speech_trailer(pcm, trailer_start, cfo_try);
        if decoded[0] == PREAMBLE_MAGIC && crc8_atm(&decoded[..4]) == decoded[4] {
            return Some(RawPreambleDetection {
                payload_start_sample,
                estimated_cfo_hz,
                confidence: 0.5 * (up_score + down_score),
                raw: decoded,
            });
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Conversational Turn-Taking & Comfort Noise Generator
// ---------------------------------------------------------------------------

/// Generates `num_samples` of warm pink-shaped room comfort noise at `level_dbfs` (typically -48 dBFS)
/// to fill natural breathing and turn-taking pauses between talkspurts.
pub fn synthesize_comfort_noise(num_samples: usize, level_dbfs: f32, seed: u64) -> Vec<i16> {
    let target_rms = 32_768.0 * 10.0f32.powf(level_dbfs / 20.0);
    let mut b0 = 0.0f32;
    let mut b1 = 0.0f32;
    let mut b2 = 0.0f32;
    let mut raw = Vec::with_capacity(num_samples);
    let mut sq_sum = 1e-9f32;
    for n in 0..num_samples {
        let w = aspiration_noise(seed as u32, n);
        b0 = 0.99765 * b0 + w * 0.0990460;
        b1 = 0.96300 * b1 + w * 0.2965164;
        b2 = 0.57000 * b2 + w * 1.0526913;
        let pink = b0 + b1 + b2 + w * 0.1848;
        sq_sum += pink * pink;
        raw.push(pink);
    }
    let rms = (sq_sum / num_samples.max(1) as f32).sqrt();
    let scale = if rms > 0.0 { target_rms / rms } else { 0.0 };
    raw.into_iter()
        .map(|x| (x * scale).round().clamp(-30_000.0, 30_000.0) as i16)
        .collect()
}

// ---------------------------------------------------------------------------
// Quantitative Big-Data Anomaly & Speech-Likeness Scanner
// ---------------------------------------------------------------------------

/// Quantitative acoustic and statistical metrics used by carrier mass-screening systems
/// to isolate modem/machine calls from human speech recordings.
#[derive(Debug, Clone, Copy)]
pub struct SpeechStealthMetrics {
    /// Highest share of total call energy concentrated in any single fixed 15.625 Hz narrowband line (0..1).
    pub max_single_bin_concentration: f32,
    /// Peak correlation against the legacy 600–1900 Hz linear V-Chirp radar sweep (0..1).
    pub v_chirp_siren_score: f32,
    /// 50 Hz frame-boundary amplitude-modulation artifact relative to 3–7 Hz syllabic modulation (dB).
    pub frame_50hz_buzz_db: f32,
    /// Dynamic range (95th minus 10th percentile in dB) of the 20 ms frame RMS envelope during active speech.
    pub syllabic_envelope_range_db: f32,
    /// Share of voice energy in the human laryngeal voice-bar band (100..450 Hz).
    pub voice_bar_energy_share: f32,
    /// Spectral tilt from F1 (500..1000 Hz) to F3/F4 (1500..3000 Hz) in dB (negative = natural human roll-off).
    pub spectral_tilt_db: f32,
}

/// Evaluates `pcm` (16 kHz mono) against the 6 mass-surveillance screening metrics.
pub fn analyze_stealth_metrics(pcm: &[i16]) -> SpeechStealthMetrics {
    if pcm.len() < FRAME_SAMPLES * 8 {
        return SpeechStealthMetrics {
            max_single_bin_concentration: 0.0,
            v_chirp_siren_score: 0.0,
            frame_50hz_buzz_db: -40.0,
            syllabic_envelope_range_db: 0.0,
            voice_bar_energy_share: 0.0,
            spectral_tilt_db: 0.0,
        };
    }

    let mut bin_energy = [0.0f64; 128];
    let mut frame_rms_db = Vec::new();
    let mut env_250hz = Vec::new();

    for frame in pcm.chunks_exact(FRAME_SAMPLES) {
        let sq: f64 = frame.iter().map(|&s| (s as f64 / 32_768.0).powi(2)).sum();
        let rms = (sq / FRAME_SAMPLES as f64).sqrt();
        if rms > 1e-3 {
            frame_rms_db.push(20.0 * rms.log10());
            let mut core = [0.0f32; DFT_WINDOW_SAMPLES];
            for i in 0..DFT_WINDOW_SAMPLES {
                core[i] = frame[GUARD_EDGE_SAMPLES + i] as f32 / 32_768.0;
            }
            for k in 1..64 {
                let e = dft_energy_at_freq(&core, k as f32 * BIN_HZ) as f64;
                bin_energy[k] += e;
            }
        }
        for sub in frame.chunks_exact(64) {
            let esq: f64 = sub.iter().map(|&s| (s as f64 / 32_768.0).powi(2)).sum();
            env_250hz.push((esq / 64.0).sqrt() as f32);
        }
    }

    let total_e: f64 = bin_energy[1..64].iter().sum::<f64>().max(1e-12);

    const NB_WIN: usize = 1024;
    const NB_BINS: usize = 200;
    let mut nb_energy = [0.0f64; NB_BINS];
    for chunk in pcm.chunks_exact(NB_WIN) {
        let csq: f64 = chunk.iter().map(|&s| (s as f64 / 32_768.0).powi(2)).sum();
        if (csq / NB_WIN as f64).sqrt() < 1e-3 {
            continue;
        }
        for k in 6..NB_BINS {
            let omega = 2.0 * std::f64::consts::PI * (k as f64) / (NB_WIN as f64);
            let (mut re, mut im) = (0.0f64, 0.0f64);
            for (n, &s) in chunk.iter().enumerate() {
                let x = s as f64 / 32_768.0;
                let (sn, cs) = (omega * n as f64).sin_cos();
                re += x * cs;
                im -= x * sn;
            }
            nb_energy[k] += re * re + im * im;
        }
    }
    let nb_total: f64 = nb_energy[6..NB_BINS].iter().sum::<f64>().max(1e-12);
    let nb_max = nb_energy[6..NB_BINS].iter().cloned().fold(0.0f64, f64::max);
    let max_single_bin_concentration = (nb_max / nb_total) as f32;

    let voice_bar_e: f64 = bin_energy[2..=7].iter().sum();
    let voice_bar_energy_share = (voice_bar_e / total_e) as f32;

    let low_formant_e = (bin_energy[8..=16].iter().sum::<f64>() / 9.0).max(1e-12);
    let high_formant_e = (bin_energy[24..=40].iter().sum::<f64>() / 17.0).max(1e-12);
    let spectral_tilt_db = (10.0 * (high_formant_e / low_formant_e).log10()) as f32;

    frame_rms_db.sort_by(|a, b| a.total_cmp(b));
    let syllabic_envelope_range_db = if frame_rms_db.len() >= 4 {
        let p10 = frame_rms_db[(frame_rms_db.len() - 1) * 10 / 100];
        let p95 = frame_rms_db[(frame_rms_db.len() - 1) * 95 / 100];
        (p95 - p10) as f32
    } else {
        0.0
    };

    let mean_env = env_250hz.iter().sum::<f32>() / env_250hz.len().max(1) as f32;
    let centered: Vec<f32> = env_250hz.iter().map(|&v| v - mean_env).collect();
    let goertzel_env = |freq_hz: f32| -> f32 {
        let omega = 2.0 * PI * freq_hz / 250.0;
        let (mut re, mut im) = (0.0f32, 0.0f32);
        for (n, &x) in centered.iter().enumerate() {
            let (s, c) = (omega * n as f32).sin_cos();
            re += x * c;
            im -= x * s;
        }
        (re * re + im * im) / (centered.len().max(1) as f32)
    };
    let p_50hz = goertzel_env(50.0).max(1e-12);
    let p_syllabic = (goertzel_env(4.5) + goertzel_env(5.5) + goertzel_env(6.5)).max(1e-12);
    let frame_50hz_buzz_db = 10.0 * (p_50hz / p_syllabic).log10();

    let sig: Vec<f32> = pcm.iter().map(|&s| s as f32 / 32_768.0).collect();
    let v_chirp_siren_score = scan_legacy_v_chirp_max(&sig);

    SpeechStealthMetrics {
        max_single_bin_concentration,
        v_chirp_siren_score,
        frame_50hz_buzz_db,
        syllabic_envelope_range_db,
        voice_bar_energy_share,
        spectral_tilt_db,
    }
}

fn scan_legacy_v_chirp_max(signal: &[f32]) -> f32 {
    if signal.len() < GLIDE_SAMPLES {
        return 0.0;
    }
    let slope = (1900.0 - 600.0) / (GLIDE_SAMPLES as f32 / SAMPLE_RATE as f32);
    let mut ref_cos = [0.0f32; GLIDE_SAMPLES];
    let mut ref_sin = [0.0f32; GLIDE_SAMPLES];
    for n in 0..GLIDE_SAMPLES {
        let t = n as f32 / SAMPLE_RATE as f32;
        let ph = 2.0 * PI * (600.0 * t + 0.5 * slope * t * t);
        let (s, c) = ph.sin_cos();
        ref_cos[n] = c;
        ref_sin[n] = s;
    }
    let mut best = 0.0f32;
    let mut idx = 0;
    while idx + GLIDE_SAMPLES <= signal.len() {
        let win = &signal[idx..idx + GLIDE_SAMPLES];
        let (mut re, mut im, mut e) = (0.0f32, 0.0f32, 1e-9f32);
        for n in (0..GLIDE_SAMPLES).step_by(2) {
            let x = win[n];
            e += x * x;
            re += x * ref_cos[n];
            im += x * ref_sin[n];
        }
        let sc = ((re * re + im * im) / (e * (GLIDE_SAMPLES as f32 / 4.0))).sqrt();
        if sc > best {
            best = sc;
        }
        idx += 4;
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        apply_channel_impairments, apply_codec_channel, decode_superframe_fec_soft,
        deinterleave_384_soft, detect_preamble_raw, encode_superframe_fec, interleave_384,
        synthesize_preamble, ChannelProfile, CodecChannelProfile, FormantDemodulator,
        FormantModulator, SUPERFRAME_BYTES,
    };

    fn make_payloads(seed: u8, count: usize) -> Vec<[u8; SUPERFRAME_BYTES]> {
        (0..count)
            .map(|s| {
                let mut b = [0u8; SUPERFRAME_BYTES];
                for (i, v) in b.iter_mut().enumerate() {
                    *v = (s as u8)
                        .wrapping_mul(41)
                        .wrapping_add(seed)
                        .wrapping_add((i as u8).wrapping_mul(97));
                }
                b
            })
            .collect()
    }

    fn transmit_gear(gear: ModemGear, blocks: &[[u8; SUPERFRAME_BYTES]]) -> Vec<i16> {
        let mut pcm = vec![0i16; 517];
        pcm.extend(synthesize_preamble(PreambleCapabilities::v2(gear)));
        let mut m = FormantModulator::new(gear);
        for b in blocks {
            let coded = encode_superframe_fec(b);
            let il = interleave_384(&coded, gear.frames_per_superframe());
            pcm.extend(m.modulate_superframe(&il));
        }
        pcm.extend(vec![0i16; 640]);
        pcm
    }

    fn receive_gear(gear: ModemGear, rx: &[i16], blocks: &[[u8; SUPERFRAME_BYTES]]) -> (usize, usize) {
        let det = detect_preamble_raw(rx).expect("preamble must be detected");
        assert_eq!(det.announced_gear(), Some(gear));
        let mut demod = FormantDemodulator::new(gear, det.estimated_cfo_hz);
        let fps = gear.frames_per_superframe();
        let sf = fps * FRAME_SAMPLES;
        let mut ok = 0;
        let mut bit_errs = 0;
        for (i, b) in blocks.iter().enumerate() {
            let start = det.payload_start_sample + i * sf;
            let mut win = vec![0i16; sf];
            let n = rx.len().saturating_sub(start).min(sf);
            win[..n].copy_from_slice(&rx[start..start + n]);
            let llrs = demod.demodulate_superframe(&win);
            let tx = interleave_384(&encode_superframe_fec(b), fps);
            for (l, t) in llrs.iter().zip(tx.iter()) {
                if (*l > 0.0) as u8 != *t {
                    bit_errs += 1;
                }
            }
            if decode_superframe_fec_soft(&deinterleave_384_soft(&llrs, fps)) == *b {
                ok += 1;
            }
        }
        (ok, bit_errs)
    }

    #[test]
    fn speech_gear_roundtrips_clean_and_harsh_channels() {
        let blocks = make_payloads(13, 8);
        let tx = transmit_gear(ModemGear::Speech300, &blocks);
        let (clean_ok, clean_ber) = receive_gear(ModemGear::Speech300, &tx, &blocks);
        assert_eq!((clean_ok, clean_ber), (8, 0));

        let rx_harsh = apply_channel_impairments(&tx, &ChannelProfile::gsm_legacy_harsh());
        let (harsh_ok, _) = receive_gear(ModemGear::Speech300, &rx_harsh, &blocks);
        assert!(harsh_ok >= 7, "Speech300 decoded {}/8 over gsm_legacy_harsh", harsh_ok);
    }

    #[test]
    fn speech_gear_survives_measured_vowifi_codec_channel() {
        let blocks = make_payloads(9, 20);
        let tx = transmit_gear(ModemGear::Speech300, &blocks);
        let rx = apply_codec_channel(&tx, &CodecChannelProfile::vowifi_measured());
        let (ok, bit_errs) = receive_gear(ModemGear::Speech300, &rx, &blocks);
        eprintln!("Speech300 on measured VoWiFi codec channel: {}/20 frames, raw bit errors {}", ok, bit_errs);
        assert!(ok >= 18, "Speech300 decoded {}/20 on measured VoWiFi codec channel", ok);
    }

    #[test]
    fn speech_gear_both_voice_timbres_roundtrip_losslessly() {
        for timbre in [VoiceTimbre::MaleBaritone, VoiceTimbre::FemaleContralto] {
            let blocks = make_payloads(33, 4);
            let mut pcm = vec![0i16; 320];
            pcm.extend(synthesize_preamble(PreambleCapabilities::v2(ModemGear::Speech300)));
            let mut m = FormantModulator::new_with_timbre(ModemGear::Speech300, timbre);
            for b in &blocks {
                let coded = encode_superframe_fec(b);
                let il = interleave_384(&coded, 64);
                pcm.extend(m.modulate_superframe(&il));
            }
            pcm.extend(vec![0i16; 320]);
            let (ok, errs) = receive_gear(ModemGear::Speech300, &pcm, &blocks);
            assert_eq!((ok, errs), (4, 0), "timbre {:?}", timbre);
        }
    }

    #[test]
    fn speech_gear_improves_all_big_data_stealth_metrics() {
        let blocks = make_payloads(21, 8);
        let tx_nb = transmit_gear(ModemGear::Narrowband1200, &blocks);
        let tx_rob = transmit_gear(ModemGear::Robust300, &blocks);
        let tx_sp = transmit_gear(ModemGear::Speech300, &blocks);

        let m_nb = analyze_stealth_metrics(&tx_nb);
        let m_rob = analyze_stealth_metrics(&tx_rob);
        let m_sp = analyze_stealth_metrics(&tx_sp);

        eprintln!("Stealth NB1200:   {:?}", m_nb);
        eprintln!("Stealth Robust:   {:?}", m_rob);
        eprintln!("Stealth Speech:   {:?}", m_sp);

        assert!(m_sp.v_chirp_siren_score < 0.30, "V-chirp score too high: {}", m_sp.v_chirp_siren_score);
        assert!(m_nb.v_chirp_siren_score > 0.80);

        assert!(
            m_sp.max_single_bin_concentration < m_rob.max_single_bin_concentration * 0.55,
            "single bin concentration not smeared: speech {} vs robust {}",
            m_sp.max_single_bin_concentration,
            m_rob.max_single_bin_concentration
        );

        assert!(
            m_sp.syllabic_envelope_range_db > 4.5 && m_rob.syllabic_envelope_range_db < 1.0,
            "syllable envelope range: speech {} dB vs robust {} dB",
            m_sp.syllabic_envelope_range_db,
            m_rob.syllabic_envelope_range_db
        );

        assert!(
            m_sp.frame_50hz_buzz_db < m_rob.frame_50hz_buzz_db - 10.0,
            "50 Hz buzz: speech {} dB vs robust {} dB",
            m_sp.frame_50hz_buzz_db,
            m_rob.frame_50hz_buzz_db
        );
    }
}
