//! End-to-end tests over handshake v2: acoustic channel (modulation, FEC, impairments) in
//! wideband and narrowband, chat features, PSK pinning, ratchet quick code, duress wipe and the
//! clean-room compliance audit.

mod common;

use aegiscall_chat::{AbortReason, PeerPresenceState, SecureCallSession, SessionEvent, TacticalQuickCode, TxUnit};
use aegiscall_crypto::{CallSide, PeerExpectation, SoftwareSigner};
use aegiscall_memsec::{EphemeralMediaKind, MessageDirection, SecretKey32};
use aegiscall_modem::{
    apply_channel_impairments, decode_superframe_fec_soft, deinterleave_384_soft, detect_preamble,
    encode_superframe_fec, interleave_384, synthesize_preamble, ChannelProfile, FormantDemodulator,
    FormantModulator, ModemGear, PreambleCapabilities, FRAME_SAMPLES,
};
use common::*;
use std::path::Path;

fn exchange_over_acoustic_channel(
    tx_wire: &[u8; 23],
    gear: ModemGear,
    modulator: &mut FormantModulator,
    demodulator: &mut FormantDemodulator,
    channel: ChannelProfile,
) -> [u8; 23] {
    let coded = encode_superframe_fec(tx_wire);
    let interleaved = interleave_384(&coded, gear.frames_per_superframe());
    let pcm = modulator.modulate_superframe(&interleaved);
    let impaired = apply_channel_impairments(&pcm, &channel);
    let llrs = demodulator.demodulate_superframe(&impaired);
    let deint = deinterleave_384_soft(&llrs, gear.frames_per_superframe());
    decode_superframe_fec_soft(&deint)
}

/// One direction of the acoustic link: modulator at the sender, demodulator (after preamble
/// sync) at the receiver.
struct Leg {
    gear: ModemGear,
    modulator: FormantModulator,
    demod: Option<FormantDemodulator>,
    profile: ChannelProfile,
}

impl Leg {
    fn new(gear: ModemGear, profile: ChannelProfile) -> Self {
        Self { gear, modulator: FormantModulator::new(gear), demod: None, profile }
    }

    fn carry(&mut self, u: TxUnit, to: &mut SecureCallSession, now: u64, seed: u64) {
        let profile = ChannelProfile { seed, ..self.profile };
        match u {
            TxUnit::Preamble(raw) => {
                let Some(caps) = PreambleCapabilities::decode_bytes(&raw) else { return };
                let mut pcm = vec![0i16; 240];
                pcm.extend_from_slice(&synthesize_preamble(caps));
                pcm.extend(vec![0i16; FRAME_SAMPLES]);
                let rx = apply_channel_impairments(&pcm, &ChannelProfile { frame_drop_prob: 0.0, ..profile });
                if let Some(det) = detect_preamble(&rx) {
                    if to.on_rx_preamble(det.raw, now) && self.demod.is_none() {
                        self.demod = Some(FormantDemodulator::new(self.gear, det.estimated_cfo_hz));
                    }
                }
            }
            TxUnit::Superframe(w) => {
                if let Some(d) = self.demod.as_mut() {
                    let rx = exchange_over_acoustic_channel(&w, self.gear, &mut self.modulator, d, profile);
                    to.on_rx_superframe(&rx, now);
                }
            }
            TxUnit::Voice | TxUnit::End => {}
        }
    }
}

fn acoustic_step(p: &mut Pair, ab: &mut Leg, ba: &mut Leg) {
    p.tick += 1;
    p.now += p.step_ms;
    let now = p.now;
    let ua = p.a.s.next_tx(now);
    let ub = p.b.s.next_tx(now);
    ab.carry(ua, &mut p.b.s, now, 0x1000 + p.tick * 17);
    ba.carry(ub, &mut p.a.s, now, 0x9000 + p.tick * 29);
    let tick = p.tick;
    p.a.react(tick);
    p.b.react(tick);
}

fn acoustic_run(p: &mut Pair, ab: &mut Leg, ba: &mut Leg, max: u64, cond: impl Fn(&Pair) -> bool) -> bool {
    for _ in 0..max {
        if cond(p) {
            return true;
        }
        acoustic_step(p, ab, ba);
    }
    cond(p)
}

fn delivered(p: &Party, id: u16) -> bool {
    p.has(|e| matches!(e, SessionEvent::MessageDelivered(m) if *m == id))
}

#[test]
fn e2e_v2_wideband_volte_handshake_chat_and_panic_wipe() {
    let gear = ModemGear::Wideband2400;
    let mut p = full_pair_gear(1, 0.0, gear);
    let mut ab = Leg::new(gear, ChannelProfile { frame_drop_prob: 0.02, ..ChannelProfile::volte_harsh() });
    let mut ba = Leg::new(gear, ChannelProfile { cfo_hz: -18.0, frame_drop_prob: 0.02, ..ChannelProfile::volte_harsh() });
    assert!(acoustic_run(&mut p, &mut ab, &mut ba, 1200, both_established), "acoustic WB handshake");
    assert_eq!(p.a.s.sas_bytes(), p.b.s.sas_bytes());

    let texts = [
        "Confirm: DialCrypt offline call encrypted channel on.",
        "Coordinates 51.500700, -0.124600 — passcode: K9#mP2!xQ8",
        "Even with just one signal bar and dropped packets, ARQ ensures zero typos",
    ];
    let now = p.now;
    let ids: Vec<u16> = texts
        .iter()
        .map(|t| p.a.s.chat().unwrap().send_text_message(now, 0, t).unwrap())
        .collect();
    let reply = p.b.s.chat().unwrap().send_text_message(now, 0, "Got it! Both ends verified, environment safe.").unwrap();
    assert!(acoustic_run(&mut p, &mut ab, &mut ba, 600, |p| ids.iter().all(|id| delivered(&p.a, *id)) && delivered(&p.b, reply)));
    let got = text_of(&p.b);
    for t in texts {
        assert!(got.iter().any(|g| g == t), "missing {t}");
    }
    assert!(text_of(&p.a).iter().any(|g| g == "Got it! Both ends verified, environment safe."));

    // Dual-end panic wipe over the acoustic channel.
    p.a.s.panic_wipe();
    assert_eq!(p.a.s.vault().map(|v| v.total_live_secret_bytes()), Some(0));
    assert!(acoustic_run(&mut p, &mut ab, &mut ba, 20, |p| p.a.s.is_closed() && p.b.s.is_closed()));
    assert!(p.b.has(|e| matches!(e, SessionEvent::RemoteWipe)));
}

#[test]
fn e2e_v2_narrowband_gsm_handshake_and_text() {
    let gear = ModemGear::Narrowband1200;
    let mut p = full_pair_gear(2, 0.0, gear);
    p.step_ms = 320;
    let mut ab = Leg::new(gear, ChannelProfile { frame_drop_prob: 0.02, ..ChannelProfile::gsm_legacy_harsh() });
    let mut ba = Leg::new(gear, ChannelProfile { cfo_hz: 15.0, frame_drop_prob: 0.02, ..ChannelProfile::gsm_legacy_harsh() });
    assert!(acoustic_run(&mut p, &mut ab, &mut ba, 1200, both_established), "acoustic NB handshake");
    let now = p.now;
    let id = p.a.s.chat().unwrap().send_text_message(now, 15, "GSM narrowband compat test: OK!").unwrap();
    let back = p.b.s.chat().unwrap().send_text_message(now, 0, "Narrow reply").unwrap();
    assert!(acoustic_run(&mut p, &mut ab, &mut ba, 400, |p| delivered(&p.a, id) && delivered(&p.b, back)));
    assert!(text_of(&p.b).iter().any(|t| t == "GSM narrowband compat test: OK!"));
    assert!(text_of(&p.a).iter().any(|t| t == "Narrow reply"));
}

#[test]
fn clean_room_license_and_zero_internet_permission_audit() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let root_dir = manifest_dir.parent().unwrap().parent().unwrap();

    // 1. Verify LICENSE exists and is the GNU GPL text
    assert!(root_dir.join("LICENSE").exists(), "LICENSE missing");
    assert!(
        std::fs::read_to_string(root_dir.join("LICENSE"))
            .unwrap()
            .contains("GNU GENERAL PUBLIC LICENSE"),
        "LICENSE is not the GNU GPL text"
    );
    assert!(root_dir.join("deny.toml").exists(), "deny.toml missing");

    // 2. Verify Cargo.toml [workspace.dependencies] contains zero copyleft crates
    let root_toml = std::fs::read_to_string(root_dir.join("Cargo.toml")).unwrap();
    let deps_section = root_toml
        .split("[workspace.dependencies]")
        .nth(1)
        .unwrap_or("");
    for forbidden in ["codec2", "gpl", "ffmpeg"] {
        assert!(
            !deps_section.to_lowercase().contains(forbidden),
            "forbidden dependency found in Cargo.toml: {}",
            forbidden
        );
    }

    // 3. Verify AndroidManifest.xml never declares INTERNET permission
    let android_manifest = root_dir.join("app/src/main/AndroidManifest.xml");
    assert!(android_manifest.exists(), "AndroidManifest.xml must exist");
    let content = std::fs::read_to_string(android_manifest).unwrap();
    assert!(
        !content.contains("android.permission.INTERNET"),
        "AndroidManifest MUST NEVER declare network permission"
    );
}

fn psk_party(signer: SoftwareSigner, contact: u32, peer_pub33: [u8; 33], psk: [u8; 32], side: CallSide) -> Party {
    let e = PeerExpectation { psk: vec![(contact, peer_pub33, SecretKey32::from_bytes(psk))], resume: Vec::new() };
    let mut p = Party::new(signer, e, side, Some(peer_pub33), ModemGear::Wideband2400);
    p.sas_choice = None;
    p
}

#[test]
fn e2e_v2_psk_pinning_ratchet_quick_codes_and_duress_wipe_under_8pct_loss() {
    let sa = SoftwareSigner::generate();
    let sb = SoftwareSigner::generate();
    let (pa, pb) = (sa.pub33(), sb.pub33());
    let psk = [0xC3u8; 32];

    // An attacker without the PSK answering instead of B is rejected before any user data.
    let attacker = Party::new(SoftwareSigner::generate(), empty(), CallSide::Answerer, None, ModemGear::Wideband2400);
    let mut bad = Pair::new(psk_party(sa.clone(), B_AT_A, pb, psk, dialing(B_AT_A)), attacker, 9, 0.0);
    assert!(bad.run_until(600, |p| p.a.s.is_closed()));
    assert!(matches!(
        bad.a.aborted(),
        Some(AbortReason::HsAeadFail | AbortReason::HsPskMismatch | AbortReason::HsPskRequired | AbortReason::PeerAbort)
    ));
    assert!(!bad.a.has(|e| matches!(e, SessionEvent::Established { .. })));

    // Genuine PSK contacts.
    let mut p = Pair::new(
        psk_party(sa, B_AT_A, pb, psk, dialing(B_AT_A)),
        psk_party(sb, A_AT_B, pa, psk, CallSide::Answerer),
        10,
        0.08,
    );
    assert!(p.run_until(800, both_established));
    assert!(p.a.has(|e| matches!(e, SessionEvent::Established { psk_contact: Some(B_AT_A), .. })));

    let now = p.now;
    let id1 = p.a.s.chat().unwrap().send_tactical_quick_code(now, TacticalQuickCode::SafeArrival).unwrap();
    let id2 = p
        .b
        .s
        .chat()
        .unwrap()
        .send_tactical_quick_code(now, TacticalQuickCode::RequestImmediateRekey)
        .unwrap();
    let id3 = p
        .a
        .s
        .chat()
        .unwrap()
        .send_tactical_quick_code(now, TacticalQuickCode::OfflineGpsPin { lat_e6: 51_500_700, lon_e6: -124_600 })
        .unwrap();
    let id4 = p.a.s.chat().unwrap().send_text_message(now, 20, "Key rotated mid-call via DH ratchet update!").unwrap();
    assert!(p.run_until(800, |p| {
        delivered(&p.a, id1)
            && delivered(&p.b, id2)
            && delivered(&p.a, id3)
            && delivered(&p.a, id4)
            && p.a.s.tx_epoch().unwrap_or(0) >= 1
            && p.b.s.tx_epoch().unwrap_or(0) >= 1
    }));
    assert!(text_of(&p.b).iter().any(|t| t.contains("51.500700")));
    assert!(text_of(&p.b).iter().any(|t| t.contains("DH ratchet")));
    // The PSK makes the full path eligible for the first resume secret without a SAS.
    assert!(p.run_until(200, |p| p.a.has(|e| matches!(e, SessionEvent::ResumePromote { k: 1, .. }))));
}

#[test]
fn e2e_v2_presence_viewed_receipt_and_abort_transfer_under_8pct_loss() {
    let mut p = full_pair(12, 0.08);
    assert!(p.run_until(800, both_established));
    let now = p.now;
    let chat = p.a.s.chat().unwrap();
    chat.send_presence_state(PeerPresenceState::TypingText);
    let long_text = "First msg: both sides confirm call encryption is up, awaiting next step.".repeat(3);
    let text_id = chat.send_text_message(now, 60, &long_text).unwrap();
    let abort_id = chat.send_text_message(now, 15, &"A".repeat(300)).unwrap();
    assert!(chat.abort_outgoing_transfer(abort_id));
    let urgent_id = chat.send_text_message(now, 0, "Urgent: cancel the long text above, send a short note!").unwrap();

    let mut viewed_sent = false;
    let mut done = false;
    for _ in 0..1500 {
        if !viewed_sent && text_of(&p.b).iter().any(|t| *t == long_text) {
            p.b.s.chat().unwrap().send_viewed_receipt(text_id);
            viewed_sent = true;
        }
        let a = p.a.s.chat().unwrap();
        if a.is_outgoing_viewed(text_id) && a.is_outgoing_delivered(urgent_id) {
            done = true;
            break;
        }
        p.step();
    }
    assert!(done, "text, viewed receipt and urgent text must all complete");
    assert_eq!(p.b.s.chat().unwrap().peer_presence(), PeerPresenceState::TypingText);
    let vault = p.b.s.vault().unwrap();
    let incoming: Vec<_> = vault.messages().iter().filter(|m| m.direction == MessageDirection::Incoming).collect();
    assert!(incoming.iter().any(|m| m.text() == long_text && m.media_kind == EphemeralMediaKind::Text));
    assert!(incoming.iter().any(|m| m.text() == "Urgent: cancel the long text above, send a short note!"));
    assert!(!incoming.iter().any(|m| m.msg_id == u32::from(abort_id)));
}
