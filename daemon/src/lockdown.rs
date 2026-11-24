//! Journaled two-tier lockdown and the restore engine.
//!
//! Order of a lockdown: read every prior value (nothing changed yet) →
//! journal header → firewall → radios/settings → network types → USB →
//! [tier 2] SCRUB marker → input method/accessibility → suspend and kill
//! other apps → memory scrub. Each change is INTENT (fsynced) → change →
//! read back → DONE. Restore replays the journal (see `journal.rs`), retries
//! each step three times, keeps going after failures and always tears the
//! firewall chains down last.

use sha2::{Digest, Sha256};

use crate::codes::{Code, Failure, Item};
use crate::commands;
use crate::firewall::{self, Family, FwConfig};
use crate::ipc::{self, ServerMsg};
use crate::journal::{self, Entry, Header, Kind, Parsed, State, Step, Writer};
use crate::memscrub;
use crate::monitor::{kill_candidates, MonState, Monitor, Tier2Watch, Watch};
use crate::mute_guard::MuteFirewall;
use crate::peer;
use crate::precheck::{Context, Tier2Plan};
use crate::procfs::{self, ProcId};
use crate::session::{send, ConnId, Output, Phase, RestoreReport, Session};
use crate::sysops::{Mutation, SysError, SysOps};
use crate::valid::{hex_encode, is_journal_token};

pub const RESTORE_ATTEMPTS: u32 = 3;
const READBACK_POLLS: u32 = 15;
const READBACK_INTERVAL_MS: u64 = 200;
const KILL_WAIT_POLLS: u32 = 30;

/// Tier 1 items with their target values (design 6.7 table).
/// `keep_usb` (policy `test_allow_usb_debug`) leaves the USB functions as they are.
pub fn tier1_items(ctx: &Context, keep_usb: bool) -> Vec<Watch> {
    let mut v = Vec::new();
    for r in ["wifi", "bluetooth", "nfc"] {
        v.push(Watch::new(Kind::Radio, r, "off"));
    }
    if ctx.uwb {
        v.push(Watch::new(Kind::Radio, "uwb", "off"));
    }
    v.push(Watch::new(Kind::Radio, "data", "off"));
    // To be confirmed on device: setting name for Bluetooth auto-on is not included.
    for s in ["global/wifi_scan_always_enabled", "global/wifi_wakeup_enabled", "global/ble_scan_always_enabled"] {
        v.push(Watch::new(Kind::Setting, s, "0"));
    }
    for slot in &ctx.slots {
        v.push(Watch::new(Kind::NetType, &slot.to_string(), commands::LTE_NR_MASK));
    }
    if !keep_usb {
        v.push(Watch::new(Kind::Usb, "functions", "none"));
    }
    v
}

/// Tier 2 settings: system-image input method, accessibility cleared.
pub fn tier2_items(t2: &Tier2Plan) -> Vec<Watch> {
    vec![
        Watch::new(Kind::Ime, "default_input_method", &t2.system_ime),
        Watch::new(Kind::A11y, "enabled_accessibility_services", "null"),
        Watch::new(Kind::A11y, "accessibility_enabled", "0"),
    ]
}

fn apply_fail(code: Code) -> Failure {
    Failure::new(Item::Apply, code)
}

impl<S: SysOps> Session<S> {
    pub(crate) fn do_mut(&mut self, real: bool, m: Mutation) -> Result<(), SysError> {
        if real {
            self.sys.apply(&m)
        } else {
            self.planned.push(m);
            Ok(())
        }
    }

    /// Applies a mutation in armed mode; records it in dry-run mode.
    pub(crate) fn mutate(&mut self, m: Mutation) -> Result<(), SysError> {
        let real = self.armed;
        self.do_mut(real, m)
    }

    fn read_prior(&mut self, w: &Watch) -> Result<String, Failure> {
        let prior = commands::read_item(&mut self.sys, w.kind, &w.target)
            .ok_or(Failure::new(Item::Commands, Code::CommandOutputUnparsed))?;
        if !is_journal_token(&prior) {
            return Err(Failure::new(Item::Commands, Code::PriorValueUnencodable));
        }
        Ok(prior)
    }

    fn readback(&mut self, kind: Kind, target: &str, want: &str) -> bool {
        for i in 0..READBACK_POLLS {
            if i > 0 {
                self.sys.sleep_ms(READBACK_INTERVAL_MS);
            }
            if commands::read_item(&mut self.sys, kind, target).is_some_and(|v| commands::same_value(kind, &v, want)) {
                return true;
            }
        }
        false
    }

    pub(crate) fn lockdown(&mut self, ctx: &Context, lease: &[u8; 16], launcher: ProcId, conn: ConnId, out: &mut Vec<Output>) -> Result<u8, Failure> {
        let real = self.armed;
        // 1. Read every prior value before the first change.
        let items = tier1_items(ctx, self.policy.test_allow_usb_debug);
        let t2_items = ctx.tier2.as_ref().map(tier2_items).unwrap_or_default();
        let mut priors = Vec::new();
        for w in items.iter().chain(t2_items.iter()) {
            priors.push(self.read_prior(w)?);
        }
        // 2. Journal header.
        let boot = self.boot_id();
        let digest = Sha256::digest(lease);
        let header = Header { boot_id: boot, lease_hash: hex_encode(&digest[..8]), owner_pid: launcher.pid, owner_start: launcher.starttime };
        self.writer = Writer::new(real);
        self.planned.clear();
        self.writer.begin(&mut self.sys, &header).map_err(apply_fail)?;
        // 3. Firewall (own chains only).
        send(out, conn, ServerMsg::Progress { step: ipc::STEP_FIREWALL });
        let cfg = FwConfig {
            iface: ctx.ims.iface.clone(),
            uids: ctx.ims_uids.clone(),
            pcscf: ctx.ims.pcscf.clone(),
            media: Vec::new(),
            nflog: self.policy.media_learning,
        };
        for fam in Family::ALL {
            let leftover = real && self.sys.read_cmd(&[fam.iptables(), "-w", "-S"]).map(|t| firewall::mentions_own_chain(&t)).unwrap_or(false);
            if leftover {
                self.fw_teardown(fam, true);
            }
            let seq = self.writer.intent(&mut self.sys, Kind::Fw, fam.tag(), "absent").map_err(apply_fail)?;
            self.mutate(firewall::apply_mutation(&cfg, fam, true)).map_err(|_| apply_fail(Code::ApplyFailed))?;
            if real && !firewall::verify_installed(&mut self.sys, fam) {
                return Err(apply_fail(Code::ReadbackMismatch));
            }
            self.writer.done(&mut self.sys, seq, Kind::Fw, fam.tag(), "absent").map_err(apply_fail)?;
        }
        self.fw = Some(cfg.clone());
        // 4. Radios, settings, network types, USB.
        send(out, conn, ServerMsg::Progress { step: ipc::STEP_RADIOS });
        for (w, prior) in items.iter().zip(priors.iter()) {
            self.apply_item(w, prior)?;
        }
        let mut claims = ipc::CLAIM_OFFLINE;
        // 5. Tier 2 (armed and dedicated_mode=1 only; precheck builds the plan).
        if let Some(t2) = &ctx.tier2 {
            send(out, conn, ServerMsg::Progress { step: ipc::STEP_APPS });
            self.writer.intent(&mut self.sys, Kind::Scrub, "memory", "0").map_err(apply_fail)?;
            for (w, prior) in t2_items.iter().zip(priors.iter().skip(items.len())) {
                self.apply_item(w, prior)?;
            }
            let apps_ok = self.stop_apps(ctx, t2);
            send(out, conn, ServerMsg::Progress { step: ipc::STEP_MEMORY });
            let mem_ok = self.scrub(real, false);
            if apps_ok {
                claims |= ipc::CLAIM_APPS_STOPPED;
            }
            if mem_ok {
                claims |= ipc::CLAIM_MEMORY_SCRUBBED;
            }
        }
        // 6. Monitor and media learning (armed only).
        if real {
            let mut watches = items;
            watches.extend(t2_items);
            let t2w = ctx.tier2.as_ref().map(|t| Tier2Watch {
                packages: ctx.packages.clone(),
                exempt: t.exempt.clone(),
                app_uid: self.app_uid.unwrap_or(u32::MAX),
            });
            let mut mon = Monitor::new(watches, ctx.ims.clone(), &self.policy.allowed_ifaces, t2w);
            mon.rebaseline(&mut self.sys);
            self.monitor = Some(mon);
            let _ = self.sys.packet_capture(cfg.nflog);
            Ok(claims)
        } else {
            Ok(0)
        }
    }

    fn apply_item(&mut self, w: &Watch, prior: &str) -> Result<(), Failure> {
        if commands::same_value(w.kind, prior, &w.desired) {
            return Ok(());
        }
        let argv = commands::set_argv(w.kind, &w.target, &w.desired).ok_or(apply_fail(Code::ApplyFailed))?;
        let seq = self.writer.intent(&mut self.sys, w.kind, &w.target, prior).map_err(apply_fail)?;
        self.mutate(Mutation::Exec(argv)).map_err(|_| apply_fail(Code::ApplyFailed))?;
        if self.armed && !self.readback(w.kind, &w.target, &w.desired) {
            return Err(apply_fail(Code::ReadbackMismatch));
        }
        self.writer.done(&mut self.sys, seq, w.kind, &w.target, prior).map_err(apply_fail)
    }

    /// Suspends every non-exempt package (journaled first) and kills its
    /// processes. Failures do not abort the session; they clear the claim.
    fn stop_apps(&mut self, ctx: &Context, t2: &Tier2Plan) -> bool {
        let mut ok = true;
        for p in &ctx.packages {
            if p.uid % 100_000 < 10_000 || t2.exempt.contains(&p.name) || t2.suspended_before.contains(&p.name) {
                continue;
            }
            let Ok(seq) = self.writer.intent(&mut self.sys, Kind::PkgSuspend, &p.name, "0") else {
                ok = false;
                continue;
            };
            if self.mutate(Mutation::Exec(commands::suspend_argv(&p.name))).is_ok() {
                let _ = self.writer.done(&mut self.sys, seq, Kind::PkgSuspend, &p.name, "0");
            } else {
                ok = false;
            }
        }
        let t2w = Tier2Watch { packages: ctx.packages.clone(), exempt: t2.exempt.clone(), app_uid: self.app_uid.unwrap_or(u32::MAX) };
        for v in kill_candidates(&mut self.sys, &t2w, &[]) {
            if self.mutate(Mutation::Kill { pid: v.pid, starttime: v.starttime }).is_err() {
                ok = false;
            }
        }
        ok
    }

    /// Tier 2 memory scrub. zram cycles are journaled so a crash in the
    /// middle still brings swap back.
    pub(crate) fn scrub(&mut self, real: bool, post: bool) -> bool {
        let mut ok = true;
        for m in [memscrub::drop_caches(), memscrub::compact_memory()] {
            ok &= self.do_mut(real, m).is_ok();
        }
        for z in memscrub::zram_devices(&mut self.sys) {
            let spec = memscrub::zram_spec(z.size, z.prio);
            let Ok(seq) = self.writer.intent(&mut self.sys, Kind::Zram, &z.dev, &spec) else {
                ok = false;
                continue;
            };
            let mut zok = true;
            for m in memscrub::zram_cycle(&z) {
                if self.do_mut(real, m).is_err() {
                    zok = false;
                    break;
                }
            }
            if real && !memscrub::swap_active(&mut self.sys, &z.dev) {
                let (reset, rest) = memscrub::zram_restore(&z);
                let _ = self.do_mut(real, reset);
                for m in rest {
                    let _ = self.do_mut(real, m);
                }
                zok = false;
            }
            if !real || memscrub::swap_active(&mut self.sys, &z.dev) {
                let _ = self.writer.done(&mut self.sys, seq, Kind::Zram, &z.dev, &spec);
            }
            ok &= zok;
        }
        ok &= self.do_mut(real, memscrub::fill_free()).is_ok();
        if post {
            for m in memscrub::clear_logs() {
                ok &= self.do_mut(real, m).is_ok();
            }
        }
        ok
    }

    pub(crate) fn kill_and_wait(&mut self, p: ProcId) -> bool {
        if !procfs::alive(&mut self.sys, p) {
            return true;
        }
        let _ = self.sys.apply(&Mutation::Kill { pid: p.pid, starttime: p.starttime });
        for _ in 0..KILL_WAIT_POLLS {
            if !procfs::alive(&mut self.sys, p) {
                return true;
            }
            self.sys.sleep_ms(100);
        }
        !procfs::alive(&mut self.sys, p)
    }

    pub(crate) fn fw_teardown(&mut self, fam: Family, real: bool) {
        let ipt = fam.iptables();
        for (b, c) in firewall::JUMPS {
            if real {
                for _ in 0..8 {
                    if self.sys.apply(&Mutation::exec(&[ipt, "-w", "-D", b, "-j", c])).is_err() {
                        break;
                    }
                }
            } else {
                self.planned.push(Mutation::exec(&[ipt, "-w", "-D", b, "-j", c]));
            }
            let _ = self.do_mut(real, Mutation::exec(&[ipt, "-w", "-F", c]));
            let _ = self.do_mut(real, Mutation::exec(&[ipt, "-w", "-X", c]));
        }
    }

    fn exec_step(&mut self, step: &Step, real: bool) -> bool {
        match step {
            Step::Exec(argv) => self.do_mut(real, Mutation::Exec(argv.clone())).is_ok(),
            Step::Kill { pid, starttime } => {
                let p = ProcId { pid: *pid, starttime: *starttime };
                if real {
                    self.kill_and_wait(p)
                } else {
                    self.planned.push(Mutation::Kill { pid: *pid, starttime: *starttime });
                    true
                }
            }
            Step::Zram { dev, spec } => {
                let Some((size, prio)) = memscrub::parse_zram_spec(spec) else { return false };
                if real && memscrub::swap_active(&mut self.sys, dev) {
                    return true;
                }
                let (reset, rest) = memscrub::zram_restore(&memscrub::ZramDev { dev: dev.clone(), size, prio });
                let _ = self.do_mut(real, reset);
                rest.into_iter().all(|m| self.do_mut(real, m).is_ok())
            }
            Step::FwDown(fam) => {
                self.fw_teardown(*fam, real);
                true
            }
        }
    }

    fn verify_step(&mut self, step: &Step, entry: Option<&Entry>) -> bool {
        match step {
            Step::FwDown(fam) => self.sys.read_cmd(&[fam.iptables(), "-w", "-S"]).map(|t| !firewall::mentions_own_chain(&t)).unwrap_or(false),
            Step::Kill { pid, starttime } => !procfs::alive(&mut self.sys, ProcId { pid: *pid, starttime: *starttime }),
            Step::Zram { dev, .. } => memscrub::swap_active(&mut self.sys, dev),
            Step::Exec(_) => match entry {
                Some(e) if matches!(e.kind, Kind::Setting | Kind::A11y | Kind::Ime | Kind::Radio | Kind::NetType | Kind::Usb) => {
                    let (kind, target, prior) = (e.kind, e.target.clone(), e.prior.clone());
                    self.readback(kind, &target, &prior)
                }
                _ => true,
            },
        }
    }

    /// Executes a restore plan. `real == false` only records the steps.
    pub(crate) fn run_restore(&mut self, parsed: &Parsed, boot: &str, real: bool) -> RestoreReport {
        if let Some(m) = self.monitor.as_mut() {
            m.state = MonState::Restoring;
        }
        let same_boot = parsed.header.as_ref().is_some_and(|h| h.boot_id == boot);
        let mut scrub_pending = same_boot && parsed.intents.iter().any(|e| e.kind == Kind::Scrub);
        let plan = journal::restore_plan(parsed, boot);
        let mut rep = RestoreReport { real, ..Default::default() };
        let mut failed: Vec<Entry> = Vec::new();
        let mut fw_failed = false;
        for (step, entry) in &plan {
            if scrub_pending && !matches!(step, Step::Kill { .. }) {
                scrub_pending = false;
                self.scrub(real, true);
            }
            rep.steps.push(step.render());
            let mut ok = false;
            for attempt in 0..RESTORE_ATTEMPTS {
                if attempt > 0 {
                    self.sys.sleep_ms(200);
                }
                if self.exec_step(step, real) && (!real || self.verify_step(step, entry.as_ref())) {
                    ok = true;
                    break;
                }
            }
            if !ok {
                rep.failed.push(step.render());
                match entry {
                    Some(e) => failed.push(e.clone()),
                    None => fw_failed = true,
                }
            }
        }
        rep.complete = failed.is_empty() && !fw_failed;
        if real {
            if rep.complete {
                let _ = self.sys.journal_remove();
            } else {
                // Keep only what still needs restoring; aegis-restore.sh and the
                // next daemon start retry it.
                let header = parsed.header.clone().unwrap_or(Header {
                    boot_id: "unknown".into(),
                    lease_hash: "0000000000000000".into(),
                    owner_pid: 0,
                    owner_start: 0,
                });
                let mut text = header.encode().unwrap_or_default();
                for e in &failed {
                    if let Ok(l) = journal::encode_line(e.seq, State::Intent, e.kind, &e.target, &e.prior) {
                        text.push_str(&l);
                    }
                }
                let _ = self.sys.journal_replace(text.as_bytes());
                let _ = self.sys.apply(&Mutation::Notify { code: Code::RestoreIncomplete.token() });
            }
        }
        rep
    }

    /// Restores the current session's journal and returns to Idle.
    pub(crate) fn restore_session(&mut self) -> RestoreReport {
        let real = self.armed;
        let parsed = journal::parse(self.writer.bytes());
        let boot = self.boot_id();
        let rep = self.run_restore(&parsed, &boot, real);
        self.restore_pending = real && !rep.complete;
        self.reset_session();
        self.last_restore = Some(rep.clone());
        rep
    }

    fn reset_session(&mut self) {
        let _ = self.sys.packet_capture(false);
        if self.lock_held {
            self.sys.restore_unlock();
            self.lock_held = false;
        }
        let now = self.sys.now_ms();
        self.phase = Phase::Idle;
        self.ctx = None;
        self.fw = None;
        self.monitor = None;
        self.learner.clear();
        self.writer = Writer::new(false);
        self.claims = 0;
        self.tier = 0;
        self.app_uid = None;
        self.mute = MuteFirewall::new(now);
    }

    /// Restores a journal left by a crashed daemon or a previous boot.
    /// Always really executes: undoing our own changes is the safe direction
    /// even when policy.conf has since been switched back to dry run.
    pub fn recover_leftover(&mut self) -> Option<RestoreReport> {
        let mut locked = false;
        for _ in 0..120 {
            match self.sys.restore_lock() {
                Ok(true) => {
                    locked = true;
                    break;
                }
                Ok(false) => self.sys.sleep_ms(1_000),
                Err(_) => break,
            }
        }
        if !locked {
            self.restore_pending = self.sys.journal_load().map(|j| j.is_some()).unwrap_or(true);
            return None;
        }
        let rep = self.recover_locked();
        self.sys.restore_unlock();
        rep
    }

    fn recover_locked(&mut self) -> Option<RestoreReport> {
        let data = match self.sys.journal_load() {
            Ok(Some(d)) => d,
            Ok(None) => {
                self.restore_pending = false;
                return None;
            }
            Err(_) => {
                self.restore_pending = true;
                return None;
            }
        };
        let clean = journal::complete_prefix(&data).to_vec();
        if clean.len() != data.len() {
            let _ = self.sys.journal_replace(&clean);
        }
        let parsed = journal::parse(&clean);
        let boot = self.boot_id();
        if parsed.header.as_ref().is_some_and(|h| h.boot_id == boot) {
            self.kill_stray_secure();
        }
        self.writer = Writer::adopt(&clean, &parsed, true);
        let rep = self.run_restore(&parsed, &boot, true);
        self.writer = Writer::new(false);
        self.restore_pending = !rep.complete;
        self.last_restore = Some(rep.clone());
        Some(rep)
    }

    /// Same boot after a daemon crash: no secure process may survive.
    fn kill_stray_secure(&mut self) {
        for pid in procfs::list_pids(&mut self.sys) {
            let cmd = self.sys.read_file(&format!("/proc/{pid}/cmdline")).map(|b| procfs::cmdline_first(&b)).unwrap_or_default();
            if cmd == peer::SECURE_PROCESS {
                if let Some(st) = procfs::read_starttime(&mut self.sys, pid) {
                    self.kill_and_wait(ProcId { pid, starttime: st });
                }
            }
        }
    }
}
