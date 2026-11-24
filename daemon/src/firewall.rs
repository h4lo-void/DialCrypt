//! Own-chain firewall (design 6.7). Rules are applied with
//! `iptables-restore -w -n`, declaring only `aegis_in`, `aegis_out` and
//! `aegis_fwd`; built-in chains only receive a jump inserted at position 1.
//! Built-in chains are never flushed, deleted or given a new policy.
//! Teardown removes the jumps and then flushes/deletes our own chains only.

use std::net::IpAddr;

use sha2::{Digest, Sha256};

use crate::sysops::{Mutation, SysOps};

pub const CHAIN_IN: &str = "aegis_in";
pub const CHAIN_OUT: &str = "aegis_out";
pub const CHAIN_FWD: &str = "aegis_fwd";
pub const NFLOG_GROUP: u16 = 7341;
pub const JUMPS: [(&str, &str); 3] = [("INPUT", CHAIN_IN), ("OUTPUT", CHAIN_OUT), ("FORWARD", CHAIN_FWD)];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Family {
    V4,
    V6,
}

impl Family {
    pub const ALL: [Family; 2] = [Family::V4, Family::V6];

    pub fn tag(self) -> &'static str {
        match self {
            Family::V4 => "v4",
            Family::V6 => "v6",
        }
    }

    pub fn iptables(self) -> &'static str {
        match self {
            Family::V4 => "iptables",
            Family::V6 => "ip6tables",
        }
    }

    pub fn restore_bin(self) -> &'static str {
        match self {
            Family::V4 => "iptables-restore",
            Family::V6 => "ip6tables-restore",
        }
    }

    pub fn matches(self, a: &IpAddr) -> bool {
        matches!((self, a), (Family::V4, IpAddr::V4(_)) | (Family::V6, IpAddr::V6(_)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FwConfig {
    /// IMS interface (validated interface name).
    pub iface: String,
    /// IMS service uids.
    pub uids: Vec<u32>,
    /// P-CSCF addresses.
    pub pcscf: Vec<IpAddr>,
    /// Media addresses learned during the current call.
    pub media: Vec<IpAddr>,
    /// Emit the NFLOG rule used for media address learning.
    pub nflog: bool,
}

fn host(a: &IpAddr) -> String {
    match a {
        IpAddr::V4(x) => format!("{x}/32"),
        IpAddr::V6(x) => format!("{x}/128"),
    }
}

/// Address usable as an allow-list destination.
pub fn usable_addr(a: &IpAddr) -> bool {
    let bcast = matches!(a, IpAddr::V4(v) if v.is_broadcast());
    !(a.is_unspecified() || a.is_loopback() || a.is_multicast() || bcast)
}

/// iptables-restore input for one family. Every ACCEPT in `aegis_out` other
/// than loopback and ICMPv6 neighbour discovery carries the IMS uid and a
/// destination address; every ACCEPT in `aegis_in` carries a source address.
pub fn restore_text(cfg: &FwConfig, fam: Family, insert_jumps: bool) -> String {
    let mut t = String::from("*filter\n");
    for c in [CHAIN_IN, CHAIN_OUT, CHAIN_FWD] {
        t.push_str(&format!(":{c} - [0:0]\n"));
    }
    let pcscf: Vec<&IpAddr> = cfg.pcscf.iter().filter(|a| fam.matches(a) && usable_addr(a)).collect();
    let media: Vec<&IpAddr> = cfg.media.iter().filter(|a| fam.matches(a) && usable_addr(a)).collect();
    let ifc = &cfg.iface;
    t.push_str(&format!("-A {CHAIN_OUT} -o lo -j ACCEPT\n"));
    for uid in &cfg.uids {
        for a in &pcscf {
            t.push_str(&format!("-A {CHAIN_OUT} -o {ifc} -m owner --uid-owner {uid} -d {} -j ACCEPT\n", host(a)));
        }
        for a in &media {
            t.push_str(&format!("-A {CHAIN_OUT} -o {ifc} -m owner --uid-owner {uid} -p udp -d {} -j ACCEPT\n", host(a)));
        }
    }
    if fam == Family::V6 {
        for ty in 133..=136 {
            t.push_str(&format!("-A {CHAIN_OUT} -o {ifc} -p ipv6-icmp -m icmp6 --icmpv6-type {ty} -j ACCEPT\n"));
        }
    }
    if cfg.nflog {
        for uid in &cfg.uids {
            t.push_str(&format!(
                "-A {CHAIN_OUT} -o {ifc} -m owner --uid-owner {uid} -p udp -j NFLOG --nflog-group {NFLOG_GROUP}\n"
            ));
        }
    }
    t.push_str(&format!("-A {CHAIN_OUT} -j DROP\n"));
    t.push_str(&format!("-A {CHAIN_IN} -i lo -j ACCEPT\n"));
    for a in &pcscf {
        t.push_str(&format!("-A {CHAIN_IN} -i {ifc} -s {} -j ACCEPT\n", host(a)));
    }
    for a in &media {
        t.push_str(&format!("-A {CHAIN_IN} -i {ifc} -p udp -s {} -j ACCEPT\n", host(a)));
    }
    if fam == Family::V6 {
        for ty in 133..=136 {
            t.push_str(&format!("-A {CHAIN_IN} -i {ifc} -p ipv6-icmp -m icmp6 --icmpv6-type {ty} -j ACCEPT\n"));
        }
    }
    t.push_str(&format!("-A {CHAIN_IN} -j DROP\n"));
    t.push_str(&format!("-A {CHAIN_FWD} -j DROP\n"));
    if insert_jumps {
        for (b, c) in JUMPS {
            t.push_str(&format!("-I {b} 1 -j {c}\n"));
        }
    }
    t.push_str("COMMIT\n");
    t
}

/// Atomic apply (first install inserts the jumps; later calls only replace
/// the content of our chains in one commit).
pub fn apply_mutation(cfg: &FwConfig, fam: Family, insert_jumps: bool) -> Mutation {
    Mutation::ExecStdin {
        argv: vec![fam.restore_bin().to_string(), "-w".to_string(), "-n".to_string()],
        stdin: restore_text(cfg, fam, insert_jumps),
    }
}

/// True when the first rule of `iptables -S <builtin>` is our jump.
pub fn jump_is_first(listing: &str, builtin: &str, chain: &str) -> bool {
    let want = format!("-A {builtin} -j {chain}");
    listing.lines().map(str::trim).find(|l| l.starts_with("-A ")) == Some(want.as_str())
}

pub fn mentions_own_chain(listing: &str) -> bool {
    listing.contains("aegis_")
}

pub fn content_hash(listing: &str) -> [u8; 32] {
    let d = Sha256::digest(listing.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

/// Read back after install: jumps first and each own chain ends in DROP.
pub fn verify_installed<S: SysOps + ?Sized>(sys: &mut S, fam: Family) -> bool {
    for (b, c) in JUMPS {
        let first = sys.read_cmd(&[fam.iptables(), "-w", "-S", b]).map(|t| jump_is_first(&t, b, c)).unwrap_or(false);
        let want_last = format!("-A {c} -j DROP");
        let ends_drop = sys
            .read_cmd(&[fam.iptables(), "-w", "-S", c])
            .map(|t| t.lines().map(str::trim).filter(|l| !l.is_empty()).last() == Some(want_last.as_str()))
            .unwrap_or(false);
        if !first || !ends_drop {
            return false;
        }
    }
    true
}

pub const MEDIA_MAX: usize = 4;
const IPPROTO_UDP: u8 = 17;

/// First-packet media address learning (design 6.7): only while a call is
/// dialing/active, only UDP, at most four addresses per call.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MediaLearner {
    learned: Vec<IpAddr>,
}

impl MediaLearner {
    pub fn learned(&self) -> &[IpAddr] {
        &self.learned
    }

    pub fn clear(&mut self) {
        self.learned.clear();
    }

    /// Returns true when `dst` was added (rules must be regenerated).
    pub fn observe(&mut self, proto: u8, dst: IpAddr, in_call: bool, known: &[IpAddr]) -> bool {
        if !in_call || proto != IPPROTO_UDP || self.learned.len() >= MEDIA_MAX || !usable_addr(&dst) {
            return false;
        }
        if known.contains(&dst) || self.learned.contains(&dst) {
            return false;
        }
        self.learned.push(dst);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> FwConfig {
        FwConfig {
            iface: "rmnet1".into(),
            uids: vec![1001],
            pcscf: vec!["10.0.0.10".parse().unwrap_or(IpAddr::from([0, 0, 0, 0])), "2607:fb90:1::10".parse().unwrap_or(IpAddr::from([0u16; 8]))],
            media: vec!["10.9.9.9".parse().unwrap_or(IpAddr::from([0, 0, 0, 0]))],
            nflog: true,
        }
    }

    #[test]
    fn fw_rules_declare_only_own_chains_and_every_accept_has_uid_and_dest() {
        for fam in Family::ALL {
            for insert in [true, false] {
                let t = restore_text(&cfg(), fam, insert);
                for line in t.lines() {
                    if let Some(chain) = line.strip_prefix(':') {
                        assert!(chain.starts_with("aegis_"), "declares foreign chain: {line}");
                    }
                    let words: Vec<&str> = line.split_whitespace().collect();
                    assert!(!words.contains(&"-F") && !words.contains(&"-P") && !words.contains(&"-X") && !words.contains(&"-D"), "{line}");
                    if words.first() == Some(&"-I") {
                        assert!(insert);
                        assert_eq!(words.len(), 5, "{line}");
                        assert_eq!(words[2], "1");
                        assert!(words[4].starts_with("aegis_"));
                    }
                    if words.first() == Some(&"-A") {
                        assert!(words[1].starts_with("aegis_"), "rule outside own chain: {line}");
                    }
                    if line.starts_with("-A aegis_out") && line.ends_with("-j ACCEPT") {
                        let is_lo = line == "-A aegis_out -o lo -j ACCEPT";
                        let is_nd = line.contains("--icmpv6-type 13");
                        if !is_lo && !is_nd {
                            assert!(line.contains("--uid-owner ") && line.contains(" -d "), "allow without uid+dest: {line}");
                        }
                    }
                    if line.starts_with("-A aegis_in") && line.ends_with("-j ACCEPT") && !line.contains(" -i lo ") {
                        assert!(line.contains(" -s ") || line.contains("--icmpv6-type 13"), "{line}");
                    }
                }
                assert!(t.contains("-A aegis_out -j DROP\n") && t.contains("-A aegis_in -j DROP\n") && t.contains("-A aegis_fwd -j DROP\n"));
                assert!(t.ends_with("COMMIT\n"));
                assert_eq!(t.contains("-I OUTPUT 1 -j aegis_out"), insert);
            }
        }
        let v4 = restore_text(&cfg(), Family::V4, true);
        assert!(v4.contains("--uid-owner 1001 -d 10.0.0.10/32 -j ACCEPT"));
        assert!(!v4.contains("2607:"), "v6 address leaked into v4 rules");
    }

    #[test]
    fn pcscf_change_produces_new_rules() {
        let a = restore_text(&cfg(), Family::V6, false);
        let mut c = cfg();
        c.pcscf = vec!["2607:fb90:2::20".parse().unwrap_or(IpAddr::from([0u16; 8]))];
        let b = restore_text(&c, Family::V6, false);
        assert_ne!(a, b);
        assert!(b.contains("-d 2607:fb90:2::20/128") && !b.contains("2607:fb90:1::10"));
    }

    #[test]
    fn media_learning_limits() {
        let mut m = MediaLearner::default();
        let pc: Vec<IpAddr> = vec![IpAddr::from([10, 0, 0, 10])];
        assert!(!m.observe(17, IpAddr::from([10, 1, 1, 1]), false, &pc), "not in call");
        assert!(!m.observe(6, IpAddr::from([10, 1, 1, 1]), true, &pc), "TCP");
        assert!(!m.observe(17, IpAddr::from([10, 0, 0, 10]), true, &pc), "already P-CSCF");
        assert!(!m.observe(17, IpAddr::from([224, 0, 0, 1]), true, &pc), "multicast");
        for i in 1..=6u8 {
            m.observe(17, IpAddr::from([10, 1, 1, i]), true, &pc);
        }
        assert_eq!(m.learned().len(), MEDIA_MAX);
        m.clear();
        assert!(m.learned().is_empty());
    }
}
