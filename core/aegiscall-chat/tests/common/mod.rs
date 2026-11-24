//! Shared lockstep harness: two SecureCallSessions, software signers, optional loss.
#![allow(dead_code)]

use aegiscall_chat::{SecureCallSession, SessionEvent, TxUnit};
use aegiscall_crypto::{CallSide, PeerExpectation, ResumeCandidate, SoftwareSigner};
use aegiscall_memsec::SecretKey32;
use aegiscall_modem::ModemGear;

pub const B_AT_A: u32 = 7;
pub const A_AT_B: u32 = 9;

pub struct XorShift(pub u64);

impl XorShift {
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    pub fn chance(&mut self, p: f64) -> bool {
        ((self.next_u64() >> 11) as f64 / (1u64 << 53) as f64) < p
    }
}

pub struct Party {
    pub s: SecureCallSession,
    pub signer: SoftwareSigner,
    pub log: Vec<SessionEvent>,
    pub sas_choice: Option<bool>,
    pub auto_vault: bool,
    pub vault_delay_ticks: u64,
    pending_vault: Vec<(u64, u32)>,
    pub superframes: u64,
}

impl Party {
    pub fn new(
        signer: SoftwareSigner,
        expect: PeerExpectation,
        side: CallSide,
        stored: Option<[u8; 33]>,
        gear: ModemGear,
    ) -> Self {
        let s = SecureCallSession::new(signer.local_identity([0x11; 16]), expect, side, stored, gear, 0).unwrap();
        Self {
            s,
            signer,
            log: Vec::new(),
            sas_choice: Some(true),
            auto_vault: true,
            vault_delay_ticks: 0,
            pending_vault: Vec::new(),
            superframes: 0,
        }
    }

    /// Answers signature requests, SAS prompts and vault writes like the app would.
    pub fn react(&mut self, tick: u64) {
        loop {
            let due: Vec<u32> = self.pending_vault.iter().filter(|(t, _)| *t <= tick).map(|(_, s)| *s).collect();
            self.pending_vault.retain(|(t, _)| *t > tick);
            for seq in &due {
                self.s.vault_saved(*seq).unwrap();
            }
            let evs = self.s.poll_events();
            if evs.is_empty() && due.is_empty() {
                break;
            }
            for ev in evs {
                match &ev {
                    SessionEvent::NeedSignature { req_id, message } => {
                        let der = self.signer.sign_der(message);
                        self.s.on_signature(*req_id, &der);
                    }
                    SessionEvent::Sas(_) => {
                        if let Some(v) = self.sas_choice {
                            self.s.sas_decision(v).unwrap();
                        }
                    }
                    SessionEvent::VaultDirty { seq, .. } => {
                        if self.auto_vault {
                            self.pending_vault.push((tick + self.vault_delay_ticks, *seq));
                        }
                    }
                    _ => {}
                }
                self.log.push(ev);
            }
        }
    }

    pub fn has(&self, f: impl Fn(&SessionEvent) -> bool) -> bool {
        self.log.iter().any(f)
    }

    pub fn count(&self, f: impl Fn(&SessionEvent) -> bool) -> usize {
        self.log.iter().filter(|e| f(e)).count()
    }

    pub fn aborted(&self) -> Option<aegiscall_chat::AbortReason> {
        self.log.iter().find_map(|e| match e {
            SessionEvent::Aborted(r) => Some(*r),
            _ => None,
        })
    }
}

pub type DropFn = Box<dyn FnMut(u64, bool, &TxUnit) -> bool>;

pub struct Pair {
    pub a: Party,
    pub b: Party,
    pub tick: u64,
    pub now: u64,
    pub step_ms: u64,
    pub rng: XorShift,
    pub loss: f64,
    pub drop: Option<DropFn>,
    /// When false, random loss applies to superframes only (the preamble is a separate,
    /// heavily repeated waveform).
    pub lossy_preamble: bool,
    pub record: bool,
    pub tape: Vec<(u64, bool, TxUnit)>,
}

pub fn deliver(u: TxUnit, to: &mut SecureCallSession, now: u64) {
    match u {
        TxUnit::Preamble(raw) => {
            to.on_rx_preamble(raw, now);
        }
        TxUnit::Superframe(w) => to.on_rx_superframe(&w, now),
        TxUnit::Voice | TxUnit::End => {}
    }
}

impl Pair {
    pub fn new(a: Party, b: Party, seed: u64, loss: f64) -> Self {
        Self {
            a,
            b,
            tick: 0,
            now: 0,
            step_ms: 160,
            rng: XorShift(seed | 1),
            loss,
            drop: None,
            lossy_preamble: true,
            record: false,
            tape: Vec::new(),
        }
    }

    fn lost(&mut self, a_to_b: bool, u: &TxUnit) -> bool {
        let exempt = !self.lossy_preamble && matches!(u, TxUnit::Preamble(_));
        let random = self.loss > 0.0 && self.rng.chance(self.loss) && !exempt;
        let tick = self.tick;
        let custom = match self.drop.as_mut() {
            Some(f) => f(tick, a_to_b, u),
            None => false,
        };
        random || custom
    }

    pub fn step(&mut self) {
        self.tick += 1;
        self.now += self.step_ms;
        let now = self.now;
        let ua = self.a.s.next_tx(now);
        let ub = self.b.s.next_tx(now);
        if matches!(ua, TxUnit::Superframe(_)) {
            self.a.superframes += 1;
        }
        if matches!(ub, TxUnit::Superframe(_)) {
            self.b.superframes += 1;
        }
        if self.record {
            self.tape.push((self.tick, true, ua));
            self.tape.push((self.tick, false, ub));
        }
        let drop_a = self.lost(true, &ua);
        let drop_b = self.lost(false, &ub);
        if !drop_a {
            deliver(ua, &mut self.b.s, now);
        }
        if !drop_b {
            deliver(ub, &mut self.a.s, now);
        }
        let tick = self.tick;
        self.a.react(tick);
        self.b.react(tick);
    }

    pub fn run_until(&mut self, max_steps: u64, cond: impl Fn(&Pair) -> bool) -> bool {
        for _ in 0..max_steps {
            if cond(self) {
                return true;
            }
            self.step();
        }
        cond(self)
    }
}

pub fn empty() -> PeerExpectation {
    PeerExpectation { psk: Vec::new(), resume: Vec::new() }
}

/// The side that placed the call, naming the contact it dialed.
pub fn dialing(contact: u32) -> CallSide {
    CallSide::Dialer { contact: Some(contact) }
}

/// A dialer that typed a bare number.
pub const DIAL_NUMBER: CallSide = CallSide::Dialer { contact: None };

pub fn both_established(p: &Pair) -> bool {
    p.a.s.is_established() && p.b.s.is_established()
}

pub fn full_pair(seed: u64, loss: f64) -> Pair {
    full_pair_gear(seed, loss, ModemGear::Wideband2400)
}

pub fn full_pair_gear(seed: u64, loss: f64, gear: ModemGear) -> Pair {
    let a = Party::new(SoftwareSigner::generate(), empty(), DIAL_NUMBER, None, gear);
    let b = Party::new(SoftwareSigner::generate(), empty(), CallSide::Answerer, None, gear);
    Pair::new(a, b, seed, loss)
}

pub fn resume_expectation(contact: u32, peer_pub33: [u8; 33], rs: [u8; 32], is_new: bool) -> PeerExpectation {
    PeerExpectation {
        psk: Vec::new(),
        resume: vec![ResumeCandidate { contact, pub33: peer_pub33, secret: SecretKey32::from_bytes(rs), is_new }],
    }
}

pub fn resume_pair(seed: u64, loss: f64, rs: [u8; 32]) -> Pair {
    let sa = SoftwareSigner::generate();
    let sb = SoftwareSigner::generate();
    let (pa, pb) = (sa.pub33(), sb.pub33());
    // A dials its contact; B answers and is given the pinned key the caller ID points to.
    let a = Party::new(sa, resume_expectation(B_AT_A, pb, rs, false), dialing(B_AT_A), Some(pb), ModemGear::Wideband2400);
    let b = Party::new(sb, resume_expectation(A_AT_B, pa, rs, false), CallSide::Answerer, Some(pa), ModemGear::Wideband2400);
    Pair::new(a, b, seed, loss)
}

pub fn text_of(p: &Party) -> Vec<String> {
    p.s.vault().map(|v| v.messages().iter().map(|m| m.text().to_string()).collect()).unwrap_or_default()
}
