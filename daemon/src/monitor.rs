//! Session monitor (design E4 part 1 and 6.7): firewall jumps and chain
//! hashes, every applied setting, interfaces, IMS registration and bearer,
//! and in tier 2 newly started processes. In the RESTORING state the
//! monitor reports nothing.

use std::collections::{BTreeMap, BTreeSet};

use crate::codes::Code;
use crate::commands;
use crate::firewall::{self, Family, JUMPS};
use crate::journal::Kind;
use crate::precheck::PkgInfo;
use crate::procfs::{self, ProcId};
use crate::sysops::{read_text, Mutation, SysOps};
use crate::telephony::{self, ImsLink};
use crate::valid::is_iface_name;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Watch {
    pub kind: Kind,
    pub target: String,
    pub desired: String,
}

impl Watch {
    pub fn new(kind: Kind, target: &str, desired: &str) -> Self {
        Self { kind, target: target.to_string(), desired: desired.to_string() }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonState {
    Watching,
    Restoring,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finding {
    /// Fail-closed: notify the App, re-apply `reapply`, end the session.
    Violation { code: Code, reapply: Vec<Mutation> },
    /// IMS interface or P-CSCF changed: regenerate the rules atomically.
    ImsChanged(ImsLink),
    /// Tier 2: a non-exempt process appeared.
    Kill(ProcId),
}

pub fn vio_code(kind: Kind) -> Code {
    match kind {
        Kind::Radio => Code::VioRadio,
        Kind::NetType => Code::VioNetType,
        Kind::Usb => Code::VioUsb,
        Kind::A11y => Code::VioA11y,
        Kind::Ime => Code::VioIme,
        _ => Code::VioSetting,
    }
}

#[derive(Debug, Clone)]
pub struct Tier2Watch {
    pub packages: Vec<PkgInfo>,
    pub exempt: BTreeSet<String>,
    pub app_uid: u32,
}

#[derive(Debug, Clone)]
pub struct Monitor {
    pub state: MonState,
    pub watches: Vec<Watch>,
    pub fw_hash: BTreeMap<(Family, &'static str), [u8; 32]>,
    pub ims: ImsLink,
    pub allowed_ifaces: BTreeSet<String>,
    pub extra_ifaces: Vec<String>,
    pub allow_vowifi: bool,
    pub call_state: Option<u8>,
    pub tier2: Option<Tier2Watch>,
}

/// Processes of uid >= 10000 that do not belong to an exempt package.
pub fn kill_candidates<S: SysOps + ?Sized>(sys: &mut S, t2: &Tier2Watch, protect: &[u32]) -> Vec<ProcId> {
    let mut out = Vec::new();
    for pid in procfs::list_pids(sys) {
        if protect.contains(&pid) {
            continue;
        }
        let Ok(status) = read_text(sys, &format!("/proc/{pid}/status")) else { continue };
        let Some(uid) = procfs::status_uid(&status) else { continue };
        if uid % 100_000 < 10_000 || uid == t2.app_uid {
            continue;
        }
        let owners: Vec<&PkgInfo> = t2.packages.iter().filter(|p| p.uid == uid).collect();
        if owners.iter().any(|p| t2.exempt.contains(&p.name)) {
            continue;
        }
        if let Some(st) = procfs::read_starttime(sys, pid) {
            out.push(ProcId { pid, starttime: st });
        }
    }
    out
}

impl Monitor {
    pub fn new(watches: Vec<Watch>, ims: ImsLink, extra_ifaces: &[String], tier2: Option<Tier2Watch>) -> Self {
        let mut m = Monitor {
            state: MonState::Watching,
            watches,
            fw_hash: BTreeMap::new(),
            ims,
            allowed_ifaces: BTreeSet::new(),
            extra_ifaces: extra_ifaces.to_vec(),
            allow_vowifi: false,
            call_state: None,
            tier2,
        };
        m.reset_ifaces();
        m
    }

    pub fn set_allow_vowifi(&mut self, allow: bool) {
        self.allow_vowifi = allow;
        self.reset_ifaces();
    }

    fn reset_ifaces(&mut self) {
        self.allowed_ifaces = ["lo".to_string(), "dummy0".to_string(), self.ims.iface.clone()].into_iter().collect();
        if self.allow_vowifi && self.ims.rat == telephony::Rat::Iwlan {
            self.allowed_ifaces.insert("wlan0".to_string());
        }
        self.allowed_ifaces.extend(self.extra_ifaces.iter().cloned());
    }

    /// Records the chain hashes right after the session's own rule changes.
    pub fn rebaseline<S: SysOps + ?Sized>(&mut self, sys: &mut S) {
        self.fw_hash.clear();
        for fam in Family::ALL {
            for (_, c) in JUMPS {
                if let Ok(t) = sys.read_cmd(&[fam.iptables(), "-w", "-S", c]) {
                    self.fw_hash.insert((fam, c), firewall::content_hash(&t));
                }
            }
        }
    }

    /// Every second: firewall, settings and radios, interfaces.
    pub fn check_fast<S: SysOps + ?Sized>(&mut self, sys: &mut S) -> Vec<Finding> {
        if self.state == MonState::Restoring {
            return Vec::new();
        }
        let mut f = Vec::new();
        'fw: for fam in Family::ALL {
            for (b, c) in JUMPS {
                let first = sys.read_cmd(&[fam.iptables(), "-w", "-S", b]).map(|t| firewall::jump_is_first(&t, b, c)).unwrap_or(false);
                let hash = sys.read_cmd(&[fam.iptables(), "-w", "-S", c]).ok().map(|t| firewall::content_hash(&t));
                if !first || hash.is_none() || hash.as_ref() != self.fw_hash.get(&(fam, c)) {
                    f.push(Finding::Violation { code: Code::VioFirewall, reapply: Vec::new() });
                    break 'fw;
                }
            }
        }
        for w in &self.watches {
            if w.kind == Kind::NetType {
                continue;
            }
            let ok = commands::read_item(sys, w.kind, &w.target).is_some_and(|v| commands::same_value(w.kind, &v, &w.desired));
            if !ok {
                let reapply = commands::set_argv(w.kind, &w.target, &w.desired).map(|a| vec![Mutation::Exec(a)]).unwrap_or_default();
                f.push(Finding::Violation { code: vio_code(w.kind), reapply });
            }
        }
        match sys.list_dir("/sys/class/net") {
            Ok(names) => {
                for n in names {
                    if self.allowed_ifaces.contains(&n) {
                        continue;
                    }
                    let up = !is_iface_name(&n)
                        || read_text(sys, &format!("/sys/class/net/{n}/operstate")).map(|s| s.trim() == "up").unwrap_or(false);
                    if up {
                        f.push(Finding::Violation { code: Code::VioInterfaceUp, reapply: Vec::new() });
                        break;
                    }
                }
            }
            Err(_) => f.push(Finding::Violation { code: Code::VioInterfaceUp, reapply: Vec::new() }),
        }
        f
    }

    /// Every two seconds: IMS link and bearer cross-check (E3), network types.
    pub fn check_slow<S: SysOps + ?Sized>(&mut self, sys: &mut S) -> Vec<Finding> {
        if self.state == MonState::Restoring {
            return Vec::new();
        }
        let mut f = Vec::new();
        match sys.read_cmd(&["dumpsys", "telephony.registry"]) {
            Ok(text) => {
                let call = telephony::parse_call_bearer_opts(&text, self.allow_vowifi);
                self.call_state = Some(if call.in_call { 2 } else { 0 });
                if call.in_call && !call.ok {
                    f.push(Finding::Violation { code: Code::VioBearer, reapply: Vec::new() });
                }
                match telephony::parse_ims_link_opts(&text, self.allow_vowifi) {
                    Ok(link) => {
                        let mut a = link.pcscf.clone();
                        let mut b = self.ims.pcscf.clone();
                        a.sort();
                        b.sort();
                        if link.iface != self.ims.iface || a != b {
                            self.ims = link.clone();
                            self.reset_ifaces();
                            f.push(Finding::ImsChanged(link));
                        }
                    }
                    Err(Code::ImsNotOnLteNr) | Err(Code::ImsOnInternetApn) => {
                        f.push(Finding::Violation { code: Code::VioBearer, reapply: Vec::new() })
                    }
                    Err(_) => f.push(Finding::Violation { code: Code::VioImsLost, reapply: Vec::new() }),
                }
            }
            Err(_) => f.push(Finding::Violation { code: Code::VioImsLost, reapply: Vec::new() }),
        }
        for w in self.watches.iter().filter(|w| w.kind == Kind::NetType) {
            let ok = commands::read_item(sys, w.kind, &w.target).is_some_and(|v| commands::same_value(w.kind, &v, &w.desired));
            if !ok {
                let reapply = commands::set_argv(w.kind, &w.target, &w.desired).map(|a| vec![Mutation::Exec(a)]).unwrap_or_default();
                f.push(Finding::Violation { code: Code::VioNetType, reapply });
            }
        }
        f
    }

    /// Tier 2, every 250 ms: kill non-exempt processes.
    pub fn check_procs<S: SysOps + ?Sized>(&mut self, sys: &mut S, protect: &[u32]) -> Vec<Finding> {
        if self.state == MonState::Restoring {
            return Vec::new();
        }
        match &self.tier2 {
            Some(t2) => kill_candidates(sys, t2, protect).into_iter().map(Finding::Kill).collect(),
            None => Vec::new(),
        }
    }
}
