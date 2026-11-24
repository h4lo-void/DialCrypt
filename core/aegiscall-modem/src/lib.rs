//! FormantGuard Cellular Pseudo-Speech Modem Crate.

pub mod channel_sim;
pub mod demodulator;
pub mod fec;
pub mod modulator;
pub mod preamble;
pub mod speech;

pub use channel_sim::{apply_channel_impairments, apply_codec_channel, ChannelProfile, CodecChannelProfile};
pub use demodulator::{DemodLinkMetrics, FormantDemodulator};
pub use fec::{
    crc16_ccitt, crc8_atm, decode_superframe_fec_soft, deinterleave_384_soft,
    encode_superframe_fec, interleave_384, CODED_BITS, SUPERFRAME_BYTES,
};
pub use modulator::{FormantModulator, ModemGear, FRAME_SAMPLES, SAMPLE_RATE};
pub use preamble::{
    detect_preamble, detect_preamble_raw, synthesize_preamble, PreambleCapabilities, PreambleDetection,
    RawPreambleDetection, CAP_CHAT_ARQ_V1, CAP_MLKEM_768, CAP_VOICE_V2_RESERVED, PROTOCOL_VERSION,
    TOTAL_PREAMBLE_SAMPLES,
};
pub use speech::{
    analyze_stealth_metrics, detect_speech_preamble_raw, frame_f0_hz, frame_pitch_scale,
    synthesize_comfort_noise, synthesize_speech_preamble, SpeechStealthMetrics, VoiceTimbre,
    VowelGlideCorrelator,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_superframe_roundtrip_over_harsh_volte_and_gsm_channels() {
        for (gear, profile) in [
            (ModemGear::Wideband2400, ChannelProfile::volte_harsh()),
            (ModemGear::Narrowband1200, ChannelProfile::gsm_legacy_harsh()),
        ] {
            let caps = PreambleCapabilities::v2(gear);

            let mut tx_pcm = vec![0i16; 321]; // arbitrary call connect offset
            tx_pcm.extend_from_slice(&synthesize_preamble(caps));

            let mut modulator = FormantModulator::new(gear);
            let mut expected_frames = Vec::new();
            for seq in 0u8..12 {
                let mut block = [0u8; SUPERFRAME_BYTES];
                for (i, b) in block.iter_mut().enumerate() {
                    *b = seq.wrapping_mul(31).wrapping_add(i as u8);
                }
                expected_frames.push(block);
                let coded = encode_superframe_fec(&block);
                let interleaved = interleave_384(&coded, gear.frames_per_superframe());
                tx_pcm.extend_from_slice(&modulator.modulate_superframe(&interleaved));
            }
            tx_pcm.extend(vec![0i16; 64]); // guard samples for filter/offset tolerance

            let rx_pcm = apply_channel_impairments(&tx_pcm, &profile);
            let det = detect_preamble(&rx_pcm).expect("preamble must sync over harsh channel");
            assert_eq!(det.peer_caps, caps);

            let mut demod = FormantDemodulator::new(gear, det.estimated_cfo_hz);
            let sf_samples = gear.frames_per_superframe() * FRAME_SAMPLES;
            let mut offset = det.payload_start_sample;
            let mut exact_matches = 0;

            for expected in &expected_frames {
                let end = (offset + sf_samples).min(rx_pcm.len());
                let mut window = vec![0i16; sf_samples];
                let copy_len = end.saturating_sub(offset);
                window[..copy_len].copy_from_slice(&rx_pcm[offset..offset + copy_len]);
                let llrs = demod.demodulate_superframe(&window);
                let deint = deinterleave_384_soft(&llrs, gear.frames_per_superframe());
                let decoded = decode_superframe_fec_soft(&deint);
                if &decoded == expected {
                    exact_matches += 1;
                }
                offset += sf_samples;
            }

            // Even under 8% random 20ms frame erasures + CFO + mu-law distortion, nearly all blocks
            // survive immediately; any remaining burst drop is handled by upper-layer ARQ.
            assert!(
                exact_matches >= 9,
                "gear {:?} only decoded {}/12 superframes cleanly",
                gear,
                exact_matches
            );

            let metrics = demod.metrics();
            assert!(metrics.total_frames_count > 0);
            assert!(metrics.quality_score() > 40);
        }
    }

    #[test]
    fn demod_telemetry_recommends_narrowband_fallback_on_severe_erasure() {
        let mut demod = FormantDemodulator::new(ModemGear::Wideband2400, 0.0);
        let blank_frame = [0i16; FRAME_SAMPLES];
        for _ in 0..16 {
            let _ = demod.demodulate_single_frame(&blank_frame);
        }
        let metrics = demod.metrics();
        assert_eq!(metrics.erased_frames_count, 16);
        assert!(metrics.recommend_narrowband_fallback());
    }
}
