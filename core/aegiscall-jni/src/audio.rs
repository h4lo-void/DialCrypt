//! Modem glue: one TxUnit becomes PCM, received PCM becomes preambles and superframes.
//!
//! The peer's stream is contiguous: preambles and 23-byte superframes back to back. The peer
//! repeats its preamble every few seconds for the whole call (call_session
//! RESYNC_PREAMBLE_SLOTS_*) and right after a voice window, because the two phones' sample
//! clocks differ (about -116 ppm measured between two Pixels) and the VoLTE jitter buffer
//! inserts or drops samples now and then.
//!
//! Once synchronised, every unit boundary is first checked for a preamble starting anywhere
//! from LOOKBACK samples before the boundary to LOOKBACK samples before the next one. These
//! ranges tile the stream, so a preamble is found before any of it is demodulated as data and
//! a superframe is never thrown away for a preamble that belongs to the next boundary. Every
//! preamble equal to the one we synchronised on re-anchors the timing. Between preambles the
//! timing follows the peer's clock: the offset of each preamble from where the tracked timing
//! expected it, divided by the distance from the previous one, estimates the clock offset,
//! and every superframe step is lengthened or shortened by whole samples to match. A jump
//! (offset too large to be clock drift) only re-anchors.

use aegiscall_chat::{SecureCallSession, TxUnit};
use aegiscall_modem::{
    decode_superframe_fec_soft, deinterleave_384_soft, detect_preamble, encode_superframe_fec, interleave_384,
    synthesize_preamble, FormantDemodulator, FormantModulator, ModemGear, PreambleCapabilities, PreambleDetection,
    FRAME_SAMPLES, TOTAL_PREAMBLE_SAMPLES,
};

/// Largest PCM chunk accepted per receive call (2 s at 16 kHz).
pub(crate) const MAX_RX_CHUNK: usize = 32_000;
const SCAN_SLACK: usize = 8 * FRAME_SAMPLES;
const MAX_RX_BUF: usize = 64_000;
/// How early (in samples) a preamble may start before the expected unit boundary and still be
/// taken at that boundary: half a frame, well beyond clock drift between two preambles and a
/// +-40 sample jitter-buffer jump. An earlier preamble was already found at the previous boundary.
/// To be confirmed on device: the size of a single VoLTE jitter-buffer insertion or drop (only +-40 simulated).
const LOOKBACK: usize = FRAME_SAMPLES / 2;
/// Largest offset (samples) of a preamble from the tracked timing that still counts as clock
/// drift: the 32-sample guard of a frame. Larger offsets are jumps and only re-anchor.
/// To be confirmed on device: detect_preamble locates the start within +-2 samples after the VoLTE codec (the
/// clock estimate relies on it; the simulated line gives 0/+-1).
const MAX_DRIFT_SAMPLES: u64 = 32;
/// Largest clock offset a single measurement may imply (twice the +-200 ppm design range).
const MAX_DRIFT_RATE: f64 = 400e-6;
/// Measurements over a longer distance (samples, 20 s) are not used: a jump spread over a long
/// distance would look like drift.
const MAX_DRIFT_SPAN: u64 = 20 * 16_000;
/// Bound of the clock offset estimate.
const MAX_SKEW: f64 = 1_000e-6;

fn superframe_samples(g: ModemGear) -> usize {
    g.frames_per_superframe() * FRAME_SAMPLES
}

/// PCM for one slot: Some(empty) during a voice window (send the microphone), None after End.
pub(crate) fn render_tx(unit: TxUnit, gear: ModemGear, m: &mut FormantModulator) -> Option<Vec<i16>> {
    match unit {
        TxUnit::Preamble(raw) => match PreambleCapabilities::decode_bytes(&raw) {
            Some(caps) => Some(synthesize_preamble(caps)),
            None => Some(vec![0i16; superframe_samples(gear)]),
        },
        TxUnit::Superframe(w) => {
            let coded = encode_superframe_fec(&w);
            let il = interleave_384(&coded, gear.frames_per_superframe());
            Some(m.modulate_superframe(&il))
        }
        TxUnit::Voice => Some(Vec::new()),
        TxUnit::End => None,
    }
}

/// The peer's sample clock relative to ours, learned from the spacing of its preambles.
struct ClockTrack {
    /// Received samples per sent sample, minus one.
    skew: f64,
    measured: bool,
    /// Part of a sample the timing still owes (carried from superframe to superframe).
    frac: f64,
    /// Stream position where the payload after the last preamble began.
    anchor: u64,
}

impl ClockTrack {
    fn new(anchor: u64) -> Self {
        Self { skew: 0.0, measured: false, frac: 0.0, anchor }
    }

    /// A preamble started err samples after the tracked timing expected it, at stream position
    /// start; its payload begins at payload.
    fn on_preamble(&mut self, err: i64, start: u64, payload: u64) {
        let span = start.saturating_sub(self.anchor);
        if span > 0 && span <= MAX_DRIFT_SPAN && err.unsigned_abs() <= MAX_DRIFT_SAMPLES {
            let d = err as f64 / span as f64;
            if d.abs() <= MAX_DRIFT_RATE {
                let gain = if self.measured { 0.5 } else { 1.0 };
                self.skew = (self.skew + gain * d).clamp(-MAX_SKEW, MAX_SKEW);
                self.measured = true;
            }
        }
        self.anchor = payload;
        self.frac = 0.0;
    }

    /// Samples to advance after a superframe of n samples.
    fn advance(&mut self, n: usize) -> usize {
        self.frac += self.skew * n as f64;
        let whole = self.frac.trunc();
        self.frac -= whole;
        (n as i64 + whole as i64).max(1) as usize
    }
}

struct Sync {
    gear: ModemGear,
    demod: FormantDemodulator,
    /// The preamble we synchronised on; only an identical one re-anchors the timing.
    raw: [u8; 5],
    clock: ClockTrack,
}

pub(crate) struct RxModem {
    buf: Vec<i16>,
    /// Stream position of buf[0] (samples received and dropped before it).
    base: u64,
    /// Index in buf where the next unit (preamble or superframe) should start.
    head: usize,
    sync: Option<Sync>,
}

impl RxModem {
    pub(crate) fn new() -> Self {
        Self { buf: Vec::new(), base: 0, head: 0, sync: None }
    }

    pub(crate) fn feed(&mut self, pcm: &[i16], call: &mut SecureCallSession, now: u64) {
        self.buf.extend_from_slice(pcm);
        while self.step(call, now) {}
        let keep = if self.sync.is_some() { LOOKBACK } else { 0 };
        self.drop_front(self.head.saturating_sub(keep));
        if self.buf.len() > MAX_RX_BUF {
            self.drop_front(self.buf.len() - MAX_RX_BUF);
        }
    }

    fn drop_front(&mut self, n: usize) {
        let n = n.min(self.buf.len());
        if n == 0 {
            return;
        }
        self.buf.drain(..n);
        self.base += n as u64;
        self.head = self.head.saturating_sub(n);
    }

    fn step(&mut self, call: &mut SecureCallSession, now: u64) -> bool {
        let Some((gear, raw)) = self.sync.as_ref().map(|s| (s.gear, s.raw)) else {
            return self.acquire(call, now);
        };
        let sf = superframe_samples(gear);
        let start = self.head.saturating_sub(LOOKBACK);
        // Room for a whole preamble starting anywhere in [start, start + sf].
        let Some(window) = self.buf.get(start..start + sf + TOTAL_PREAMBLE_SAMPLES) else { return false };
        if let Some(det) = detect_preamble(window) {
            let begins = det.payload_start_sample.saturating_sub(TOTAL_PREAMBLE_SAMPLES);
            if begins < sf && det.raw == raw {
                self.resync(start, begins, det, call, now);
                return true;
            }
        }
        let Some(sync) = self.sync.as_mut() else { return false };
        let Some(frame) = self.buf.get(self.head..self.head + sf) else { return false };
        let llr = sync.demod.demodulate_superframe(frame);
        let deint = deinterleave_384_soft(&llr, gear.frames_per_superframe());
        let wire = decode_superframe_fec_soft(&deint);
        self.head += sync.clock.advance(sf);
        call.on_rx_superframe(&wire, now);
        true
    }

    /// Not synchronised: look for the first preamble anywhere in the buffer.
    fn acquire(&mut self, call: &mut SecureCallSession, now: u64) -> bool {
        let Some(avail) = self.buf.get(self.head..) else { return false };
        if avail.len() < TOTAL_PREAMBLE_SAMPLES + SCAN_SLACK {
            return false;
        }
        let Some(det) = detect_preamble(avail) else {
            // Keep the tail: a preamble may have started in it.
            self.head = self.buf.len() - TOTAL_PREAMBLE_SAMPLES;
            return false;
        };
        let payload = self.head + det.payload_start_sample.min(avail.len());
        if call.on_rx_preamble(det.raw, now) {
            let g = det.peer_caps.preferred_gear;
            self.sync = Some(Sync {
                gear: g,
                demod: FormantDemodulator::new(g, det.estimated_cfo_hz),
                raw: det.raw,
                clock: ClockTrack::new(self.base + payload as u64),
            });
        }
        self.head = payload;
        true
    }

    /// The peer's preamble begins at buf[start + begins]: re-anchor the timing on its payload.
    fn resync(&mut self, start: usize, begins: usize, det: PreambleDetection, call: &mut SecureCallSession, now: u64) {
        let at = start + begins;
        let payload = (start + det.payload_start_sample).min(self.buf.len());
        // The session says whether the demodulator should start afresh (true while keyed only
        // right after a voice window, when it has been fed speech). During the handshake the
        // repeats only re-anchor, so the learned channel compensation is kept.
        let fresh = call.on_rx_preamble(det.raw, now) && call.is_keyed();
        let err = at as i64 - self.head as i64;
        let (base, head) = (self.base, payload);
        if let Some(sync) = self.sync.as_mut() {
            sync.clock.on_preamble(err, base + at as u64, base + payload as u64);
            if fresh {
                sync.demod = FormantDemodulator::new(sync.gear, det.estimated_cfo_hz);
            }
        }
        self.head = head;
    }
}
