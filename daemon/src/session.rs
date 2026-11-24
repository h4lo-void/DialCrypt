//! Secure-session state machine (design E4): PREPARE → precheck →
//! journaled lockdown → READY(lease) → ATTACH → heartbeats under watch →
//! END / crash / violation → restore. Driven by [`Input`] events so the
//! whole lifecycle runs against the test double.

use std::collections::BTreeMap;

use crate::codes::{Code, Failure, Item};
use crate::commands;
use crate::firewall::{FwConfig, MediaLearner};
use crate::ipc::{self, ClientMsg, FrameReader, ServerMsg};
use crate::journal::{Kind, Writer};
use crate::monitor::{Finding, Monitor};
use crate::mute_guard::MuteFirewall;
use crate::nflog;
use crate::peer;
use crate::policy::Policy;
use crate::precheck::{self, Context};
use crate::procfs::{self, ProcId};
use crate::sysops::{read_text, Mutation, SysOps};
use crate::valid::ct_eq;

pub type ConnId = u64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Input {
    /// New connection; `uid`/`pid` come from SO_PEERCRED.
    Connected { conn: ConnId, uid: u32, pid: u32 },
    Data { conn: ConnId, bytes: Vec<u8> },
    Closed { conn: ConnId },
    /// Periodic timer (the server sends one every 100 ms).
    Tick,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    Send { conn: ConnId, frame: Vec<u8> },
    Close { conn: ConnId },
}

pub const ATTACH_WINDOW_MS: u64 = 10_000;
pub const LEASE_TIMEOUT_MS: u64 = 2_000;
pub const END_GRACE_MS: u64 = 3_000;
pub const FAST_CHECK_MS: u64 = 1_000;
pub const SLOW_CHECK_MS: u64 = 2_000;
pub const PROC_SCAN_MS: u64 = 250;
pub const BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RestoreReport {
    pub steps: Vec<String>,
    pub failed: Vec<String>,
    pub complete: bool,
    pub real: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Phase {
    Idle,
    Prepared { lease: [u8; 16], ready_ticks: u64, deadline_ms: u64, launcher: ProcId, conn: ConnId },
    Attached { lease: [u8; 16], conn: ConnId, secure: ProcId, last_hb_ms: u64 },
    Ending { conn: Option<ConnId>, secure: Option<ProcId>, deadline_ms: u64 },
}

struct Conn {
    uid: u32,
    pid: u32,
    reader: FrameReader,
}

pub struct Session<S: SysOps> {
    pub(crate) sys: S,
    pub(crate) policy: Policy,
    pub(crate) armed: bool,
    /// Dry-run record of every mutation that would have been applied.
    pub(crate) planned: Vec<Mutation>,
    pub(crate) writer: Writer,
    pub(crate) phase: Phase,
    conns: BTreeMap<ConnId, Conn>,
    pub(crate) ctx: Option<Context>,
    pub(crate) fw: Option<FwConfig>,
    pub(crate) monitor: Option<Monitor>,
    pub(crate) learner: MediaLearner,
    pub(crate) mute: MuteFirewall,
    pub(crate) claims: u8,
    pub(crate) tier: u8,
    pub(crate) app_uid: Option<u32>,
    pub(crate) restore_pending: bool,
    pub(crate) lock_held: bool,
    pub(crate) last_restore: Option<RestoreReport>,
    last_fast: u64,
    last_slow: u64,
    last_proc: u64,
}

pub(crate) fn send(out: &mut Vec<Output>, conn: ConnId, msg: ServerMsg) {
    out.push(Output::Send { conn, frame: ipc::encode_server(&msg) });
}

fn fail_msg(f: Failure) -> ServerMsg {
    ServerMsg::Fail { item: f.item.as_u16(), code: f.code.as_u16() }
}

impl<S: SysOps> Session<S> {
    pub fn new(mut sys: S) -> Self {
        let now = sys.now_ms();
        let mut s = Session {
            sys,
            policy: Policy::default(),
            armed: false,
            planned: Vec::new(),
            writer: Writer::new(false),
            phase: Phase::Idle,
            conns: BTreeMap::new(),
            ctx: None,
            fw: None,
            monitor: None,
            learner: MediaLearner::default(),
            mute: MuteFirewall::new(now),
            claims: 0,
            tier: 0,
            app_uid: None,
            restore_pending: false,
            lock_held: false,
            last_restore: None,
            last_fast: 0,
            last_slow: 0,
            last_proc: 0,
        };
        s.reload_policy();
        s
    }

    pub fn sys(&self) -> &S {
        &self.sys
    }

    pub fn sys_mut(&mut self) -> &mut S {
        &mut self.sys
    }

    /// Gives the backend back (tests use it to simulate a daemon restart).
    pub fn into_sys(self) -> S {
        self.sys
    }

    pub fn armed(&self) -> bool {
        self.armed
    }

    pub fn phase(&self) -> &Phase {
        &self.phase
    }

    pub fn planned(&self) -> &[Mutation] {
        &self.planned
    }

    pub fn last_restore(&self) -> Option<&RestoreReport> {
        self.last_restore.as_ref()
    }

    pub fn restore_pending(&self) -> bool {
        self.restore_pending
    }

    /// Re-reads policy.conf. Only armed when the file is valid and says armed=1.
    pub(crate) fn reload_policy(&mut self) {
        let (p, issue) = Policy::load(&mut self.sys);
        self.armed = p.armed && issue.is_none();
        self.policy = p;
    }

    pub(crate) fn mode_byte(&self) -> u8 {
        if self.armed {
            ipc::MODE_ARMED
        } else {
            ipc::MODE_DRY_RUN
        }
    }

    pub(crate) fn boot_id(&mut self) -> String {
        let b = read_text(&mut self.sys, BOOT_ID_PATH).map(|s| s.trim().to_string()).unwrap_or_default();
        if crate::valid::is_journal_token(&b) {
            b
        } else {
            "unknown".to_string()
        }
    }

    pub fn handle(&mut self, input: Input) -> Vec<Output> {
        let mut out = Vec::new();
        match input {
            Input::Connected { conn, uid, pid } => self.on_connected(conn, uid, pid, &mut out),
            Input::Data { conn, bytes } => self.on_data(conn, &bytes, &mut out),
            Input::Closed { conn } => {
                if self.conns.remove(&conn).is_some() {
                    self.after_conn_gone(conn);
                }
            }
            Input::Tick => self.on_tick(&mut out),
        }
        out
    }

    fn drop_conn(&mut self, conn: ConnId, out: &mut Vec<Output>) {
        if self.conns.remove(&conn).is_some() {
            out.push(Output::Close { conn });
            self.after_conn_gone(conn);
        }
    }

    fn fail_close(&mut self, conn: ConnId, f: Failure, out: &mut Vec<Output>) {
        send(out, conn, fail_msg(f));
        self.drop_conn(conn, out);
    }

    /// Losing the attached connection means the secure process is gone or
    /// broken: keep uplink muted and end the session.
    fn after_conn_gone(&mut self, conn: ConnId) {
        if let Phase::Attached { conn: c, secure, .. } = self.phase.clone() {
            if c == conn {
                self.mute.trip_fail_closed();
                let now = self.sys.now_ms();
                self.phase = Phase::Ending { conn: None, secure: Some(secure), deadline_ms: now };
            }
        }
    }

    fn on_connected(&mut self, conn: ConnId, uid: u32, pid: u32, out: &mut Vec<Output>) {
        if self.phase == Phase::Idle {
            self.reload_policy();
        }
        match peer::authenticate(&mut self.sys, uid, self.policy.app_cert_sha256.as_ref()) {
            Ok(()) => {
                self.conns.insert(conn, Conn { uid, pid, reader: FrameReader::default() });
            }
            Err(code) => {
                send(out, conn, fail_msg(Failure::new(Item::Auth, code)));
                out.push(Output::Close { conn });
            }
        }
    }

    fn on_data(&mut self, conn: ConnId, bytes: &[u8], out: &mut Vec<Output>) {
        let frames = match self.conns.get_mut(&conn) {
            Some(c) => c.reader.push(bytes),
            None => return,
        };
        let Ok(frames) = frames else {
            self.fail_close(conn, Failure::new(Item::Protocol, Code::BadFrame), out);
            return;
        };
        for f in frames {
            if !self.conns.contains_key(&conn) {
                break;
            }
            match ipc::decode_client(&f) {
                Ok(m) => self.on_msg(conn, m, out),
                Err(_) => {
                    self.fail_close(conn, Failure::new(Item::Protocol, Code::BadFrame), out);
                    break;
                }
            }
        }
    }

    fn on_msg(&mut self, conn: ConnId, m: ClientMsg, out: &mut Vec<Output>) {
        match m {
            ClientMsg::Hello { version } => {
                if version == ipc::PROTO_VERSION {
                    send(out, conn, ServerMsg::Hello { version, mode: self.mode_byte() });
                } else {
                    self.fail_close(conn, Failure::new(Item::Protocol, Code::UnexpectedMessage), out);
                }
            }
            ClientMsg::Prepare => self.on_prepare(conn, out),
            ClientMsg::Attach { lease } => self.on_attach(conn, lease, out),
            ClientMsg::Heartbeat { lease } => self.on_heartbeat(conn, lease, out),
            ClientMsg::End => self.on_end(conn, out),
        }
    }

    fn on_prepare(&mut self, conn: ConnId, out: &mut Vec<Output>) {
        if self.phase != Phase::Idle {
            return self.fail_close(conn, Failure::new(Item::Protocol, Code::Busy), out);
        }
        self.reload_policy();
        if self.restore_pending {
            self.recover_leftover();
        }
        if self.restore_pending {
            return self.fail_close(conn, Failure::new(Item::Restore, Code::RestorePending), out);
        }
        let Some((uid, pid)) = self.conns.get(&conn).map(|c| (c.uid, c.pid)) else { return };
        send(out, conn, ServerMsg::Progress { step: ipc::STEP_PRECHECK });
        let tier2 = self.armed && self.policy.dedicated_mode;
        let ctx = match precheck::run(&mut self.sys, &self.policy, tier2) {
            Ok(c) => c,
            Err(fails) => {
                for f in fails.iter().take(16) {
                    send(out, conn, fail_msg(*f));
                }
                self.drop_conn(conn, out);
                return;
            }
        };
        let Some(st) = procfs::read_starttime(&mut self.sys, pid) else {
            return self.fail_close(conn, Failure::new(Item::Attach, Code::AttachWrongProcess), out);
        };
        let launcher = ProcId { pid, starttime: st };
        // Draw the lease before taking the lock: a failure here must not leave the lock held.
        let Ok(lease) = self.sys.random16() else {
            return self.fail_close(conn, Failure::new(Item::Apply, Code::ApplyFailed), out);
        };
        // The restore lock (shared with aegis-restore.sh) is held for the whole
        // lifetime of this session's journal, so the boot/manual restore hook
        // can never process or delete a journal that belongs to a live session.
        if self.armed {
            match self.sys.restore_lock() {
                Ok(true) => self.lock_held = true,
                _ => return self.fail_close(conn, Failure::new(Item::Restore, Code::RestorePending), out),
            }
        }
        self.app_uid = Some(uid);
        self.tier = if tier2 { 2 } else { 1 };
        let result = self.lockdown(&ctx, &lease, launcher, conn, out);
        self.ctx = Some(ctx);
        let ready = result.and_then(|claims| {
            self.sys.uptime_ticks().map(|t| (claims, t)).map_err(|_| Failure::new(Item::Apply, Code::ApplyFailed))
        });
        match ready {
            Ok((claims, ready_ticks)) => {
                let now = self.sys.now_ms();
                self.claims = claims;
                self.last_fast = now;
                self.last_slow = now;
                self.last_proc = now;
                self.phase = Phase::Prepared { lease, ready_ticks, deadline_ms: now + ATTACH_WINDOW_MS, launcher, conn };
                send(out, conn, ServerMsg::Ready { lease, mode: self.mode_byte(), tier: self.tier, claims });
            }
            Err(f) => {
                self.restore_session();
                self.fail_close(conn, f, out);
            }
        }
    }

    fn check_attach(&mut self, uid: u32, pid: u32, lease: &[u8; 16], expected: &[u8; 16], ready_ticks: u64, launcher: ProcId) -> Result<ProcId, Code> {
        if Some(uid) != self.app_uid {
            return Err(Code::AttachUidMismatch);
        }
        if !ct_eq(lease, expected) {
            return Err(Code::LeaseMismatch);
        }
        let st = procfs::read_starttime(&mut self.sys, pid).ok_or(Code::AttachWrongProcess)?;
        if st <= ready_ticks {
            return Err(Code::AttachTooEarly);
        }
        let cmd = self.sys.read_file(&format!("/proc/{pid}/cmdline")).map(|b| procfs::cmdline_first(&b)).unwrap_or_default();
        if cmd != peer::SECURE_PROCESS {
            return Err(Code::AttachWrongProcess);
        }
        let status = read_text(&mut self.sys, &format!("/proc/{pid}/status")).map_err(|_| Code::AttachWrongProcess)?;
        if procfs::tracer_pid(&status) != Some(0) {
            return Err(Code::AttachTraced);
        }
        let maps = read_text(&mut self.sys, &format!("/proc/{pid}/maps")).map_err(|_| Code::AttachInjected)?;
        if procfs::maps_injected(&maps) {
            return Err(Code::AttachInjected);
        }
        let mut waited = 0;
        while procfs::alive(&mut self.sys, launcher) {
            if waited >= 1_000 {
                return Err(Code::LauncherStillAlive);
            }
            self.sys.sleep_ms(100);
            waited += 100;
        }
        if self.armed && self.tier == 2 {
            let ime = self.ctx.as_ref().and_then(|c| c.tier2.as_ref()).map(|t| t.system_ime.clone()).unwrap_or_default();
            let a11y = commands::read_item(&mut self.sys, Kind::A11y, "enabled_accessibility_services");
            let cur_ime = commands::read_item(&mut self.sys, Kind::Ime, "default_input_method");
            if a11y.as_deref() != Some("null") || cur_ime.as_deref() != Some(ime.as_str()) {
                return Err(Code::AttachInputNotCleared);
            }
        }
        Ok(ProcId { pid, starttime: st })
    }

    fn on_attach(&mut self, conn: ConnId, lease: [u8; 16], out: &mut Vec<Output>) {
        let Phase::Prepared { lease: expected, ready_ticks, launcher, .. } = self.phase.clone() else {
            return self.fail_close(conn, Failure::new(Item::Protocol, Code::UnexpectedMessage), out);
        };
        let Some((uid, pid)) = self.conns.get(&conn).map(|c| (c.uid, c.pid)) else { return };
        match self.check_attach(uid, pid, &lease, &expected, ready_ticks, launcher) {
            Ok(secure) => {
                let target = format!("{}:{}", secure.pid, secure.starttime);
                if let Err(c) = self.writer.intent(&mut self.sys, Kind::Proc, &target, "0") {
                    send(out, conn, fail_msg(Failure::new(Item::Apply, c)));
                    self.conns.remove(&conn);
                    out.push(Output::Close { conn });
                    self.finish(None, Some(secure), out);
                    return;
                }
                // The secure process locks its memory (nativeHarden: mlockall) and needs an
                // unlimited RLIMIT_MEMLOCK for it. `secure` is the peer of this connection as
                // check_attach just verified it (pid and start time). Done in dry-run mode as
                // well: the limit belongs to the App's own process and ends with it. A failure
                // is an ATTACH failure: no ATTACHED, uplink muted, process ended, restore.
                if self.sys.raise_memlock(secure.pid, secure.starttime).is_err() {
                    send(out, conn, fail_msg(Failure::new(Item::Attach, Code::ApplyFailed)));
                    self.conns.remove(&conn);
                    out.push(Output::Close { conn });
                    self.mute.trip_fail_closed();
                    self.finish(None, Some(secure), out);
                    return;
                }
                let now = self.sys.now_ms();
                self.phase = Phase::Attached { lease: expected, conn, secure, last_hb_ms: now };
                send(out, conn, ServerMsg::Attached { mode: self.mode_byte(), tier: self.tier, claims: self.claims });
            }
            Err(code) => {
                send(out, conn, fail_msg(Failure::new(Item::Attach, code)));
                self.conns.remove(&conn);
                out.push(Output::Close { conn });
                let victim = if Some(uid) == self.app_uid {
                    procfs::read_starttime(&mut self.sys, pid).map(|st| ProcId { pid, starttime: st })
                } else {
                    None
                };
                self.mute.trip_fail_closed();
                self.finish(None, victim, out);
            }
        }
    }

    fn on_heartbeat(&mut self, conn: ConnId, lease: [u8; 16], out: &mut Vec<Output>) {
        match self.phase.clone() {
            Phase::Attached { lease: expected, conn: c, .. } if c == conn => {
                if ct_eq(&lease, &expected) {
                    let now = self.sys.now_ms();
                    if let Phase::Attached { last_hb_ms, .. } = &mut self.phase {
                        *last_hb_ms = now;
                    }
                } else {
                    self.violation(Code::LeaseMismatch, Vec::new(), out);
                }
            }
            Phase::Ending { .. } => {}
            _ => self.fail_close(conn, Failure::new(Item::Protocol, Code::UnexpectedMessage), out),
        }
    }

    fn on_end(&mut self, conn: ConnId, out: &mut Vec<Output>) {
        let now = self.sys.now_ms();
        match self.phase.clone() {
            Phase::Attached { conn: c, secure, .. } if c == conn => {
                self.mute.trip_fail_closed();
                self.phase = Phase::Ending { conn: Some(conn), secure: Some(secure), deadline_ms: now + END_GRACE_MS };
            }
            Phase::Prepared { conn: c, .. } if c == conn => self.finish(Some(conn), None, out),
            _ => self.fail_close(conn, Failure::new(Item::Protocol, Code::UnexpectedMessage), out),
        }
    }

    /// Fail-closed (design E4): VIOLATION to the App, uplink muted, the
    /// offending item switched off again, then the normal end flow.
    pub(crate) fn violation(&mut self, code: Code, reapply: Vec<Mutation>, out: &mut Vec<Output>) {
        self.mute.trip_fail_closed();
        for m in reapply {
            let _ = self.mutate(m);
        }
        let now = self.sys.now_ms();
        match self.phase.clone() {
            Phase::Attached { conn, secure, .. } => {
                send(out, conn, ServerMsg::Violation { code: code.as_u16() });
                self.phase = Phase::Ending { conn: Some(conn), secure: Some(secure), deadline_ms: now + END_GRACE_MS };
            }
            Phase::Prepared { conn, .. } => {
                if self.conns.contains_key(&conn) {
                    send(out, conn, ServerMsg::Violation { code: code.as_u16() });
                }
                self.finish(Some(conn), None, out);
            }
            _ => {}
        }
    }

    /// Confirms the secure process is gone (SIGKILL if needed), restores,
    /// reports ENDED when the connection still exists.
    fn finish(&mut self, conn: Option<ConnId>, secure: Option<ProcId>, out: &mut Vec<Output>) {
        if let Some(p) = secure {
            if self.armed {
                self.kill_and_wait(p);
            } else {
                self.planned.push(Mutation::Kill { pid: p.pid, starttime: p.starttime });
            }
        }
        let rep = self.restore_session();
        if let Some(c) = conn {
            if self.conns.remove(&c).is_some() {
                send(out, c, ServerMsg::Ended { status: if rep.complete { 0 } else { 1 } });
                out.push(Output::Close { conn: c });
            }
        }
    }

    fn on_tick(&mut self, out: &mut Vec<Output>) {
        let now = self.sys.now_ms();
        match self.phase.clone() {
            Phase::Idle => return,
            Phase::Prepared { deadline_ms, conn, .. } => {
                if now > deadline_ms {
                    if self.conns.contains_key(&conn) {
                        send(out, conn, fail_msg(Failure::new(Item::Attach, Code::AttachTimeout)));
                    }
                    self.finish(Some(conn), None, out);
                    return;
                }
            }
            Phase::Attached { last_hb_ms, conn, secure, .. } => {
                if now.saturating_sub(last_hb_ms) > LEASE_TIMEOUT_MS {
                    self.mute.trip_fail_closed();
                    if self.conns.contains_key(&conn) {
                        send(out, conn, ServerMsg::Violation { code: Code::VioLeaseExpired.as_u16() });
                    }
                    self.phase = Phase::Ending { conn: Some(conn), secure: Some(secure), deadline_ms: now };
                }
            }
            Phase::Ending { .. } => {}
        }
        if let Phase::Ending { conn, secure, deadline_ms } = self.phase.clone() {
            let gone = secure.map_or(true, |p| !procfs::alive(&mut self.sys, p));
            if gone || now >= deadline_ms {
                self.finish(conn, secure, out);
            }
            return;
        }
        self.run_monitor(now, out);
        self.learn_media(out);
    }

    fn run_monitor(&mut self, now: u64, out: &mut Vec<Output>) {
        if !self.armed {
            return; // dry run: nothing was changed, so there is nothing to watch
        }
        let Some(mut mon) = self.monitor.take() else { return };
        let mut findings = Vec::new();
        if now.saturating_sub(self.last_fast) >= FAST_CHECK_MS {
            self.last_fast = now;
            findings.extend(mon.check_fast(&mut self.sys));
        }
        if now.saturating_sub(self.last_slow) >= SLOW_CHECK_MS {
            self.last_slow = now;
            findings.extend(mon.check_slow(&mut self.sys));
        }
        if mon.tier2.is_some() && now.saturating_sub(self.last_proc) >= PROC_SCAN_MS {
            self.last_proc = now;
            let protect: Vec<u32> = match &self.phase {
                Phase::Attached { secure, .. } => vec![secure.pid],
                _ => Vec::new(),
            };
            findings.extend(mon.check_procs(&mut self.sys, &protect));
        }
        self.monitor = Some(mon);
        for f in findings {
            match f {
                Finding::Violation { code, reapply } => self.violation(code, reapply, out),
                Finding::ImsChanged(link) => {
                    if let Some(cfg) = self.fw.as_mut() {
                        cfg.iface = link.iface;
                        cfg.pcscf = link.pcscf;
                    }
                    self.regen_rules(out);
                }
                Finding::Kill(p) => {
                    let _ = self.mutate(Mutation::Kill { pid: p.pid, starttime: p.starttime });
                }
            }
            if !matches!(self.phase, Phase::Prepared { .. } | Phase::Attached { .. }) {
                break;
            }
        }
    }

    /// Replaces the content of our chains atomically (P-CSCF change or a new
    /// learned media address) and re-records the chain hashes.
    pub(crate) fn regen_rules(&mut self, out: &mut Vec<Output>) {
        let Some(mut cfg) = self.fw.clone() else { return };
        cfg.media = self.learner.learned().to_vec();
        for fam in crate::firewall::Family::ALL {
            if self.mutate(crate::firewall::apply_mutation(&cfg, fam, false)).is_err() {
                self.fw = Some(cfg);
                self.violation(Code::VioFirewall, Vec::new(), out);
                return;
            }
        }
        self.fw = Some(cfg);
        if let Some(mut mon) = self.monitor.take() {
            mon.rebaseline(&mut self.sys);
            self.monitor = Some(mon);
        }
    }

    fn learn_media(&mut self, out: &mut Vec<Output>) {
        let packets = self.sys.poll_packets();
        if !self.armed || !matches!(self.phase, Phase::Prepared { .. } | Phase::Attached { .. }) {
            return;
        }
        let in_call = self.monitor.as_ref().and_then(|m| m.call_state) == Some(2);
        let known = self.fw.as_ref().map(|c| c.pcscf.clone()).unwrap_or_default();
        let mut changed = false;
        if !in_call && !self.learner.learned().is_empty() {
            self.learner.clear();
            changed = true;
        }
        for p in packets {
            if let Some((proto, dst)) = nflog::parse_ip(&p) {
                changed |= self.learner.observe(proto, dst, in_call, &known);
            }
        }
        if changed {
            self.regen_rules(out);
        }
    }
}
