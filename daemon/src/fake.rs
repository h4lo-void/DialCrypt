//! Recording test double for [`SysOps`]. Models settings, radios, network
//! types, USB, packages, /proc, swaps and the iptables chains closely enough
//! for read-back verification, and can inject failures by mutation prefix.

use std::collections::{BTreeMap, BTreeSet};

use crate::sysops::{Mutation, SysError, SysOps};

#[derive(Debug, Default, Clone)]
pub struct FwFam {
    /// (built-in chain, target) jumps, in order (index 0 = first rule).
    pub jumps: Vec<(String, String)>,
    pub chains: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Default, Clone)]
pub struct FakeSys {
    pub reads: BTreeMap<String, String>,
    pub files: BTreeMap<String, Vec<u8>>,
    pub dirs: BTreeMap<String, Vec<String>>,
    /// (mutation key prefix, remaining failures); u32::MAX = always.
    pub fail: Vec<(String, u32)>,
    pub fail_reads: BTreeSet<String>,
    /// Every apply() call, including injected failures.
    pub log: Vec<Mutation>,
    pub journal: Option<Vec<u8>>,
    pub journal_writes: u32,
    pub fail_journal: bool,
    pub now: u64,
    pub ticks: u64,
    pub fw: [FwFam; 2],
    pub packets: Vec<Vec<u8>>,
    pub capture: bool,
    pub lock_held: bool,
    pub suspended: BTreeSet<String>,
    pub notifications: Vec<String>,
    /// Every raise_memlock() call as (pid, starttime), including refused ones. Kept apart from
    /// `log`: it is the one state change a dry run performs.
    pub memlock: Vec<(u32, u64)>,
    pub fail_memlock: bool,
}

fn fam_idx(prog: &str) -> Option<usize> {
    match prog {
        "iptables" | "iptables-restore" => Some(0),
        "ip6tables" | "ip6tables-restore" => Some(1),
        _ => None,
    }
}

impl FakeSys {
    pub fn set(&mut self, key: &str, value: &str) {
        self.reads.insert(key.to_string(), value.to_string());
    }

    pub fn setting(&mut self, ns: &str, key: &str, value: &str) {
        self.set(&format!("settings get {ns} {key}"), value);
    }

    pub fn get(&self, key: &str) -> String {
        self.reads.get(key).cloned().unwrap_or_default()
    }

    pub fn file(&mut self, path: &str, data: &str) {
        self.files.insert(path.to_string(), data.as_bytes().to_vec());
    }

    pub fn add_proc(&mut self, pid: u32, uid: u32, cmdline: &str, starttime: u64, tracer: u32, maps: &str) {
        self.file(&format!("/proc/{pid}/stat"), &format!("{pid} (x) S 1 1 0 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 {starttime} 0 0"));
        self.file(&format!("/proc/{pid}/status"), &format!("Name:\tx\nTracerPid:\t{tracer}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n"));
        self.files.insert(format!("/proc/{pid}/cmdline"), format!("{cmdline}\0").into_bytes());
        self.file(&format!("/proc/{pid}/maps"), maps);
        let procs = self.dirs.entry("/proc".into()).or_default();
        if !procs.contains(&pid.to_string()) {
            procs.push(pid.to_string());
        }
    }

    pub fn remove_proc(&mut self, pid: u32) {
        for f in ["stat", "status", "cmdline", "maps"] {
            self.files.remove(&format!("/proc/{pid}/{f}"));
        }
        if let Some(v) = self.dirs.get_mut("/proc") {
            v.retain(|p| *p != pid.to_string());
        }
    }

    /// State-changing operations that reached the backend (journal included).
    pub fn state_changes(&self) -> usize {
        self.log.len() + self.journal_writes as usize
    }

    pub fn keys(&self) -> Vec<String> {
        self.log.iter().map(Mutation::key).collect()
    }

    fn listing(&self, f: usize, chain: Option<&str>) -> String {
        let fw = &self.fw[f];
        let mut s = String::new();
        let builtins = ["INPUT", "OUTPUT", "FORWARD"];
        let show = |name: &str| chain.is_none_or(|c| c == name);
        for b in builtins {
            if show(b) {
                s.push_str(&format!("-P {b} ACCEPT\n"));
                for (jb, jc) in &fw.jumps {
                    if jb == b {
                        s.push_str(&format!("-A {b} -j {jc}\n"));
                    }
                }
                s.push_str(&format!("-A {b} -j fw_{b}\n"));
            }
        }
        for (name, rules) in &fw.chains {
            if show(name) {
                s.push_str(&format!("-N {name}\n"));
                for r in rules {
                    s.push_str(&format!("-A {name} {r}\n"));
                }
            }
        }
        s
    }

    fn ipt(&mut self, f: usize, a: &[String]) -> Result<(), SysError> {
        let fw = &mut self.fw[f];
        match (a.get(2).map(String::as_str), a.get(3), a.get(4).map(String::as_str), a.get(5)) {
            (Some("-D"), Some(b), Some("-j"), Some(c)) => {
                let pos = fw.jumps.iter().position(|(jb, jc)| jb == b && jc == c).ok_or(SysError::Exit(1))?;
                fw.jumps.remove(pos);
                Ok(())
            }
            (Some("-F"), Some(c), None, None) => fw.chains.get_mut(c.as_str()).map(Vec::clear).ok_or(SysError::Exit(1)),
            (Some("-X"), Some(c), None, None) => {
                if fw.jumps.iter().any(|(_, jc)| jc == c) {
                    return Err(SysError::Exit(1));
                }
                fw.chains.remove(c.as_str()).map(|_| ()).ok_or(SysError::Exit(1))
            }
            _ => Ok(()),
        }
    }

    fn ipt_restore(&mut self, f: usize, text: &str) -> Result<(), SysError> {
        let mut fw = self.fw[f].clone();
        for line in text.lines() {
            if let Some(c) = line.strip_prefix(':') {
                let name = c.split_whitespace().next().unwrap_or("").to_string();
                fw.chains.insert(name, Vec::new());
            } else if let Some(rest) = line.strip_prefix("-A ") {
                let (c, r) = rest.split_once(' ').ok_or(SysError::Exit(2))?;
                fw.chains.get_mut(c).ok_or(SysError::Exit(2))?.push(r.to_string());
            } else if let Some(rest) = line.strip_prefix("-I ") {
                let w: Vec<&str> = rest.split_whitespace().collect();
                if w.len() != 4 || !fw.chains.contains_key(w[3]) {
                    return Err(SysError::Exit(2));
                }
                fw.jumps.insert(0, (w[0].to_string(), w[3].to_string()));
            }
        }
        self.fw[f] = fw;
        Ok(())
    }

    fn exec_semantics(&mut self, a: &[String]) -> Result<(), SysError> {
        let s: Vec<&str> = a.iter().map(String::as_str).collect();
        if let Some(f) = s.first().and_then(|p| fam_idx(p)) {
            return self.ipt(f, a);
        }
        match s.as_slice() {
            ["settings", "put", ns, k, v] => self.setting(ns, k, v),
            ["settings", "delete", ns, k] => self.setting(ns, k, "null"),
            ["cmd", "wifi", "set-wifi-enabled", v] => self.setting("global", "wifi_on", if *v == "enabled" { "1" } else { "0" }),
            ["cmd", "bluetooth_manager", v] => self.setting("global", "bluetooth_on", if *v == "enable" { "1" } else { "0" }),
            ["svc", "nfc", v] => self.set("dumpsys nfc", if *v == "enable" { "mState=on" } else { "mState=off" }),
            ["cmd", "uwb", v] => self.set("cmd uwb get-uwb-state", if *v == "enable-uwb" { "Uwb state: enabled" } else { "Uwb state: disabled" }),
            ["svc", "data", v] => self.setting("global", "mobile_data", if *v == "enable" { "1" } else { "0" }),
            ["cmd", "phone", "set-allowed-network-types-for-users", "-s", slot, v] => {
                // Like the device: a slot without a subscription refuses (rc 255) and the
                // value reads back as a `|` joined name list.
                let key = format!("cmd phone get-allowed-network-types-for-users -s {slot}");
                if !self.reads.contains_key(&key) {
                    return Err(SysError::Exit(255));
                }
                let names = crate::commands::network_type_names(v).ok_or(SysError::Exit(1))?;
                self.set(&key, &format!("{names}\n"));
            }
            // No function at all reads back as an empty line.
            ["svc", "usb", "setFunctions"] => self.set("svc usb getFunctions", "\n"),
            ["svc", "usb", "setFunctions", v] => self.set("svc usb getFunctions", v),
            ["ime", "set", id] => self.setting("secure", "default_input_method", id),
            ["pm", "suspend", "--user", "0", p] => {
                self.suspended.insert(p.to_string());
            }
            ["pm", "unsuspend", "--user", "0", p] => {
                self.suspended.remove(*p);
            }
            ["swapoff", dev] => {
                let cur = String::from_utf8(self.files.get("/proc/swaps").cloned().unwrap_or_default()).unwrap_or_default();
                let kept: Vec<&str> = cur.lines().filter(|l| !l.starts_with(&format!("{dev} "))).collect();
                self.file("/proc/swaps", &(kept.join("\n") + "\n"));
            }
            ["swapon", .., dev] => {
                let mut cur = String::from_utf8(self.files.get("/proc/swaps").cloned().unwrap_or_default()).unwrap_or_default();
                if !cur.contains(&format!("{dev} ")) {
                    cur.push_str(&format!("{dev} partition 4194300 0 -2\n"));
                }
                self.file("/proc/swaps", &cur);
            }
            _ => {}
        }
        Ok(())
    }
}

impl SysOps for FakeSys {
    fn read_cmd(&mut self, argv: &[&str]) -> Result<String, SysError> {
        let key = argv.join(" ");
        if self.fail_reads.contains(&key) {
            return Err(SysError::Exit(1));
        }
        if let Some(f) = argv.first().and_then(|p| fam_idx(p)) {
            if argv.get(1) == Some(&"-w") && argv.get(2) == Some(&"-S") {
                return Ok(self.listing(f, argv.get(3).copied()));
            }
        }
        if argv.first() == Some(&"getprop") {
            return Ok(self.get(&key));
        }
        if argv.len() == 4 && argv[0] == "settings" && argv[1] == "get" {
            return Ok(self.reads.get(&key).cloned().unwrap_or_else(|| "null".to_string()));
        }
        self.reads.get(&key).cloned().ok_or(SysError::NotFound)
    }

    fn read_file(&mut self, path: &str) -> Result<Vec<u8>, SysError> {
        self.files.get(path).cloned().ok_or(SysError::NotFound)
    }

    fn read_file_range(&mut self, path: &str, offset: u64, len: usize) -> Result<Vec<u8>, SysError> {
        let f = self.files.get(path).ok_or(SysError::NotFound)?;
        let start = (offset as usize).min(f.len());
        let end = start.saturating_add(len).min(f.len());
        Ok(f[start..end].to_vec())
    }

    fn file_size(&mut self, path: &str) -> Result<u64, SysError> {
        self.files.get(path).map(|f| f.len() as u64).ok_or(SysError::NotFound)
    }

    fn list_dir(&mut self, path: &str) -> Result<Vec<String>, SysError> {
        self.dirs.get(path).cloned().ok_or(SysError::NotFound)
    }

    fn exists(&mut self, path: &str) -> bool {
        self.files.contains_key(path) || self.dirs.contains_key(path)
    }

    fn random16(&mut self) -> Result<[u8; 16], SysError> {
        Ok([0x5a; 16])
    }

    fn now_ms(&mut self) -> u64 {
        self.now
    }

    fn uptime_ticks(&mut self) -> Result<u64, SysError> {
        Ok(self.ticks)
    }

    fn sleep_ms(&mut self, ms: u64) {
        self.now += ms;
    }

    fn apply(&mut self, m: &Mutation) -> Result<(), SysError> {
        self.log.push(m.clone());
        let key = m.key();
        for (prefix, n) in self.fail.iter_mut() {
            if key.starts_with(prefix.as_str()) && *n > 0 {
                if *n != u32::MAX {
                    *n -= 1;
                }
                return Err(SysError::Exit(1));
            }
        }
        match m {
            Mutation::Exec(a) => self.exec_semantics(a),
            Mutation::ExecStdin { argv, stdin } => match argv.first().and_then(|p| fam_idx(p)) {
                Some(f) => self.ipt_restore(f, stdin),
                None => Ok(()),
            },
            Mutation::WriteFile { path, data } => {
                self.files.insert(path.clone(), data.as_bytes().to_vec());
                Ok(())
            }
            Mutation::Kill { pid, starttime } => {
                let stat = self.files.get(&format!("/proc/{pid}/stat")).map(|b| String::from_utf8_lossy(b).into_owned());
                if stat.as_deref().and_then(crate::procfs::stat_starttime) == Some(*starttime) {
                    self.remove_proc(*pid);
                }
                Ok(())
            }
            Mutation::FillFreeMemory { .. } => Ok(()),
            Mutation::Notify { code } => {
                self.notifications.push(code.clone());
                Ok(())
            }
        }
    }

    fn journal_load(&mut self) -> Result<Option<Vec<u8>>, SysError> {
        Ok(self.journal.clone())
    }

    fn journal_append(&mut self, line: &[u8]) -> Result<(), SysError> {
        if self.fail_journal {
            return Err(SysError::Io);
        }
        self.journal_writes += 1;
        self.journal.get_or_insert_with(Vec::new).extend_from_slice(line);
        Ok(())
    }

    fn journal_replace(&mut self, data: &[u8]) -> Result<(), SysError> {
        self.journal_writes += 1;
        self.journal = Some(data.to_vec());
        Ok(())
    }

    fn journal_remove(&mut self) -> Result<(), SysError> {
        if self.journal.is_some() {
            self.journal_writes += 1;
        }
        self.journal = None;
        Ok(())
    }

    fn restore_lock(&mut self) -> Result<bool, SysError> {
        if self.lock_held {
            return Ok(false);
        }
        self.lock_held = true;
        Ok(true)
    }

    fn restore_unlock(&mut self) {
        self.lock_held = false;
    }

    fn raise_memlock(&mut self, pid: u32, starttime: u64) -> Result<(), SysError> {
        self.memlock.push((pid, starttime));
        if self.fail_memlock {
            return Err(SysError::Io);
        }
        let stat = self.files.get(&format!("/proc/{pid}/stat")).map(|b| String::from_utf8_lossy(b).into_owned());
        if stat.as_deref().and_then(crate::procfs::stat_starttime) != Some(starttime) {
            return Err(SysError::NotFound);
        }
        Ok(())
    }

    fn packet_capture(&mut self, on: bool) -> Result<(), SysError> {
        self.capture = on;
        Ok(())
    }

    fn poll_packets(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.packets)
    }
}
