//! Write-ahead restore journal (`/data/adb/aegischat/journal.v1`).
//!
//! Header: `ACTIVE<TAB>boot_id<TAB>lease_hash<TAB>pid:starttime`.
//! Lines:  `seq<TAB>INTENT|DONE<TAB>kind<TAB>target<TAB>prior<TAB>crc32`,
//! every field in `[A-Za-z0-9._:/,=-]`, crc32 (IEEE, 8 lowercase hex) over
//! the bytes before the last TAB. An INTENT is fsynced before the change it
//! describes, so a torn (unterminated) last line never describes an applied
//! change and is ignored. Restore replays every INTENT (with or without DONE)
//! in the order of the design 6.7, newest first within a group, and always
//! ends by tearing down the firewall chains.
//!
//! `magisk-module/aegis-restore.sh` implements the same parser and plan; the
//! tests run both on the same input and compare the rendered steps.

use crate::codes::Code;
use crate::commands;
use crate::firewall::Family;
use crate::memscrub;
use crate::sysops::SysOps;
use crate::valid::{is_digits, is_journal_token, is_lower_hex, is_package_name};

pub const JOURNAL_PATH: &str = "/data/adb/aegischat/journal.v1";
pub const MAX_LINE: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Kind {
    Fw,
    Radio,
    Setting,
    NetType,
    Usb,
    PkgSuspend,
    Ime,
    A11y,
    Zram,
    Proc,
    Scrub,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Fw => "FW",
            Kind::Radio => "RADIO",
            Kind::Setting => "SETTING",
            Kind::NetType => "NETTYPE",
            Kind::Usb => "USB",
            Kind::PkgSuspend => "PKG_SUSPEND",
            Kind::Ime => "IME",
            Kind::A11y => "A11Y",
            Kind::Zram => "ZRAM",
            Kind::Proc => "PROC",
            Kind::Scrub => "SCRUB",
        }
    }

    pub fn parse(s: &str) -> Option<Kind> {
        Some(match s {
            "FW" => Kind::Fw,
            "RADIO" => Kind::Radio,
            "SETTING" => Kind::Setting,
            "NETTYPE" => Kind::NetType,
            "USB" => Kind::Usb,
            "PKG_SUSPEND" => Kind::PkgSuspend,
            "IME" => Kind::Ime,
            "A11Y" => Kind::A11y,
            "ZRAM" => Kind::Zram,
            "PROC" => Kind::Proc,
            "SCRUB" => Kind::Scrub,
            _ => return None,
        })
    }

    /// Restore group (design 6.7): secure process → [tier 2] swap → unsuspend →
    /// IME/accessibility → USB → network types → radios and settings.
    /// The firewall teardown always runs last; FW and SCRUB have no own step.
    pub fn restore_rank(self) -> Option<u8> {
        match self {
            Kind::Proc => Some(0),
            Kind::Zram => Some(1),
            Kind::PkgSuspend => Some(2),
            Kind::Ime | Kind::A11y => Some(3),
            Kind::Usb => Some(4),
            Kind::NetType => Some(5),
            Kind::Radio | Kind::Setting => Some(6),
            Kind::Fw | Kind::Scrub => None,
        }
    }
}

pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub boot_id: String,
    pub lease_hash: String,
    pub owner_pid: u32,
    pub owner_start: u64,
}

impl Header {
    pub fn encode(&self) -> Result<String, Code> {
        if !is_journal_token(&self.boot_id) || !is_lower_hex(&self.lease_hash, 16) {
            return Err(Code::PriorValueUnencodable);
        }
        Ok(format!(
            "ACTIVE\t{}\t{}\t{}:{}\n",
            self.boot_id, self.lease_hash, self.owner_pid, self.owner_start
        ))
    }

    pub fn parse(line: &str) -> Option<Header> {
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() != 4 || f[0] != "ACTIVE" || !is_journal_token(f[1]) || !is_lower_hex(f[2], 16) {
            return None;
        }
        let (pid, start) = f[3].split_once(':')?;
        if !is_digits(pid, 9) || !is_digits(start, 19) {
            return None;
        }
        Some(Header {
            boot_id: f[1].to_string(),
            lease_hash: f[2].to_string(),
            owner_pid: pid.parse().ok()?,
            owner_start: start.parse().ok()?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Intent,
    Done,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub seq: u32,
    pub kind: Kind,
    pub target: String,
    pub prior: String,
}

pub fn encode_line(seq: u32, state: State, kind: Kind, target: &str, prior: &str) -> Result<String, Code> {
    if !is_journal_token(target) || !is_journal_token(prior) || seq > 999_999_999 {
        return Err(Code::PriorValueUnencodable);
    }
    let st = match state {
        State::Intent => "INTENT",
        State::Done => "DONE",
    };
    let body = format!("{seq}\t{st}\t{}\t{target}\t{prior}", kind.as_str());
    let line = format!("{body}\t{:08x}\n", crc32(body.as_bytes()));
    if line.len() > MAX_LINE {
        return Err(Code::PriorValueUnencodable);
    }
    Ok(line)
}

/// Parses one complete line (without the newline).
pub fn parse_line(line: &str) -> Option<(State, Entry)> {
    if line.len() + 1 > MAX_LINE {
        return None;
    }
    let (body, crc_hex) = line.rsplit_once('\t')?;
    if !is_lower_hex(crc_hex, 8) || format!("{:08x}", crc32(body.as_bytes())) != crc_hex {
        return None;
    }
    let f: Vec<&str> = body.split('\t').collect();
    if f.len() != 5 || f.iter().any(|x| !is_journal_token(x)) || !is_digits(f[0], 9) {
        return None;
    }
    let state = match f[1] {
        "INTENT" => State::Intent,
        "DONE" => State::Done,
        _ => return None,
    };
    let kind = Kind::parse(f[2])?;
    Some((
        state,
        Entry { seq: f[0].parse().ok()?, kind, target: f[3].to_string(), prior: f[4].to_string() },
    ))
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Parsed {
    /// The first complete line, when it is a valid header.
    pub header: Option<Header>,
    /// Valid INTENT entries in file order.
    pub intents: Vec<Entry>,
    pub max_seq: u32,
}

/// Bytes up to and including the last newline (drops a torn tail).
pub fn complete_prefix(bytes: &[u8]) -> &[u8] {
    match bytes.iter().rposition(|&b| b == b'\n') {
        Some(i) => &bytes[..=i],
        None => &[],
    }
}

pub fn parse(bytes: &[u8]) -> Parsed {
    let mut out = Parsed::default();
    let mut first = true;
    for raw in complete_prefix(bytes).split(|&b| b == b'\n') {
        if first {
            first = false;
            out.header = std::str::from_utf8(raw).ok().and_then(Header::parse);
            continue;
        }
        let Some((state, e)) = std::str::from_utf8(raw).ok().and_then(parse_line) else {
            continue;
        };
        out.max_seq = out.max_seq.max(e.seq);
        if state == State::Intent {
            out.intents.push(e);
        }
    }
    out
}

/// One restore action. `render` is the text both implementations print in
/// plan mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    Exec(Vec<String>),
    Kill { pid: u32, starttime: u64 },
    Zram { dev: String, spec: String },
    FwDown(Family),
}

impl Step {
    pub fn render(&self) -> String {
        match self {
            Step::Exec(argv) => {
                let mut s = String::from("exec");
                for a in argv {
                    s.push('\t');
                    s.push_str(a);
                }
                s
            }
            Step::Kill { pid, starttime } => format!("kill\t{pid}\t{starttime}"),
            Step::Zram { dev, spec } => format!("zram\t{dev}\t{spec}"),
            Step::FwDown(f) => format!("fwdown\t{}", f.tag()),
        }
    }
}

/// Restore step for one INTENT; `None` for FW/SCRUB and for any entry whose
/// target or prior fails validation (identical rules in the shell script).
pub fn restore_step(e: &Entry, same_boot: bool) -> Option<Step> {
    match e.kind {
        Kind::Setting | Kind::A11y | Kind::Ime | Kind::Radio | Kind::NetType | Kind::Usb => {
            commands::set_argv(e.kind, &e.target, &e.prior).map(Step::Exec)
        }
        Kind::PkgSuspend => {
            if e.prior == "0" && is_package_name(&e.target) {
                Some(Step::Exec(commands::unsuspend_argv(&e.target)))
            } else {
                None
            }
        }
        Kind::Zram => {
            let n = e.target.strip_prefix("zram")?;
            if !is_digits(n, 2) || memscrub::parse_zram_spec(&e.prior).is_none() {
                return None;
            }
            Some(Step::Zram { dev: e.target.clone(), spec: e.prior.clone() })
        }
        Kind::Proc => {
            if !same_boot {
                return None;
            }
            let (pid, start) = e.target.split_once(':')?;
            if !is_digits(pid, 9) || !is_digits(start, 19) {
                return None;
            }
            Some(Step::Kill { pid: pid.parse().ok()?, starttime: start.parse().ok()? })
        }
        Kind::Fw | Kind::Scrub => None,
    }
}

/// Full restore plan: grouped by [`Kind::restore_rank`], newest entry first
/// within a group, then the IPv4 and IPv6 firewall teardown.
pub fn restore_plan(p: &Parsed, current_boot: &str) -> Vec<(Step, Option<Entry>)> {
    let same_boot = p.header.as_ref().is_some_and(|h| h.boot_id == current_boot);
    let mut out = Vec::new();
    for rank in 0..=6u8 {
        for e in p.intents.iter().rev() {
            if e.kind.restore_rank() == Some(rank) {
                if let Some(s) = restore_step(e, same_boot) {
                    out.push((s, Some(e.clone())));
                }
            }
        }
    }
    out.push((Step::FwDown(Family::V4), None));
    out.push((Step::FwDown(Family::V6), None));
    out
}

pub fn render_plan(plan: &[(Step, Option<Entry>)]) -> String {
    let mut s = String::new();
    for (step, _) in plan {
        s.push_str(&step.render());
        s.push('\n');
    }
    s
}

/// In-memory journal with optional persistence. In dry-run mode
/// (`persist == false`) nothing is written to disk.
#[derive(Debug, Clone, Default)]
pub struct Writer {
    persist: bool,
    text: Vec<u8>,
    next_seq: u32,
}

impl Writer {
    pub fn new(persist: bool) -> Self {
        Self { persist, text: Vec::new(), next_seq: 1 }
    }

    /// Continue an existing journal (already truncated to complete lines).
    pub fn adopt(clean: &[u8], parsed: &Parsed, persist: bool) -> Self {
        Self { persist, text: clean.to_vec(), next_seq: parsed.max_seq.saturating_add(1) }
    }

    pub fn bytes(&self) -> &[u8] {
        &self.text
    }

    fn write<S: SysOps + ?Sized>(&mut self, sys: &mut S, line: &str) -> Result<(), Code> {
        if self.persist {
            sys.journal_append(line.as_bytes()).map_err(|_| Code::JournalWriteFailed)?;
        }
        self.text.extend_from_slice(line.as_bytes());
        Ok(())
    }

    pub fn begin<S: SysOps + ?Sized>(&mut self, sys: &mut S, h: &Header) -> Result<(), Code> {
        let line = h.encode()?;
        self.text.clear();
        self.next_seq = 1;
        self.write(sys, &line)
    }

    pub fn intent<S: SysOps + ?Sized>(&mut self, sys: &mut S, kind: Kind, target: &str, prior: &str) -> Result<u32, Code> {
        let seq = self.next_seq;
        let line = encode_line(seq, State::Intent, kind, target, prior)?;
        self.write(sys, &line)?;
        self.next_seq += 1;
        Ok(seq)
    }

    pub fn done<S: SysOps + ?Sized>(&mut self, sys: &mut S, seq: u32, kind: Kind, target: &str, prior: &str) -> Result<(), Code> {
        let line = encode_line(seq, State::Done, kind, target, prior)?;
        self.write(sys, &line)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn sample_journal() -> Vec<u8> {
        let mut j = String::new();
        let h = Header { boot_id: "boot-1".into(), lease_hash: "0123456789abcdef".into(), owner_pid: 500, owner_start: 1000 };
        j.push_str(&h.encode().unwrap_or_default());
        let rows: [(Kind, &str, &str); 12] = [
            (Kind::Fw, "v4", "absent"),
            (Kind::Fw, "v6", "absent"),
            (Kind::Radio, "wifi", "on"),
            (Kind::Setting, "global/wifi_scan_always_enabled", "1"),
            (Kind::NetType, "0", "11111111111111111111"),
            (Kind::Usb, "functions", "mtp"),
            (Kind::Scrub, "memory", "0"),
            (Kind::Ime, "default_input_method", "com.x.kbd/.Ime"),
            (Kind::A11y, "enabled_accessibility_services", "com.x.a/.S:com.y.b/.T"),
            (Kind::PkgSuspend, "com.chat.app", "0"),
            (Kind::Zram, "zram0", "4294967296,-2"),
            (Kind::Proc, "700:5000", "0"),
        ];
        for (i, (k, t, p)) in rows.iter().enumerate() {
            let seq = i as u32 + 1;
            j.push_str(&encode_line(seq, State::Intent, *k, t, p).unwrap_or_default());
            j.push_str(&encode_line(seq, State::Done, *k, t, p).unwrap_or_default());
        }
        j.into_bytes()
    }

    #[test]
    fn crc32_matches_ieee_check_value() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn line_roundtrip_and_rejections() {
        let l = encode_line(7, State::Intent, Kind::Setting, "global/x", "null").unwrap_or_default();
        let (st, e) = parse_line(l.trim_end_matches('\n')).unwrap_or((State::Done, Entry { seq: 0, kind: Kind::Fw, target: String::new(), prior: String::new() }));
        assert_eq!(st, State::Intent);
        assert_eq!((e.seq, e.kind, e.target.as_str(), e.prior.as_str()), (7, Kind::Setting, "global/x", "null"));
        assert!(encode_line(1, State::Intent, Kind::Setting, "a b", "1").is_err());
        assert!(encode_line(1, State::Intent, Kind::Setting, "a", "$(reboot)").is_err());
        let mut bad = l.trim_end_matches('\n').to_string();
        bad.replace_range(0..1, "8");
        assert!(parse_line(&bad).is_none(), "crc must catch a changed field");
    }

    #[test]
    fn restore_order_follows_spec_6_7() {
        let p = parse(&sample_journal());
        let plan = restore_plan(&p, "boot-1");
        let kinds: Vec<String> = plan.iter().map(|(s, _)| s.render().split('\t').take(3).collect::<Vec<_>>().join(" ")).collect();
        assert_eq!(
            kinds,
            vec![
                "kill 700 5000",
                "zram zram0 4294967296,-2",
                "exec pm unsuspend",
                "exec settings put",
                "exec ime set",
                "exec svc usb",
                "exec cmd phone",
                "exec settings put",
                "exec cmd wifi",
                "fwdown v4",
                "fwdown v6",
            ]
        );
        // A different boot skips the PROC kill, everything else is identical.
        let other = restore_plan(&p, "boot-2");
        assert_eq!(other.len(), plan.len() - 1);
        assert!(!render_plan(&other).contains("kill"));
    }

    #[test]
    fn journal_truncated_at_every_byte_still_restores() {
        let full = sample_journal();
        for cut in 0..=full.len() {
            let part = &full[..cut];
            let p = parse(part);
            let plan = restore_plan(&p, "boot-1");
            // Expected: exactly the INTENT lines that are complete in the prefix.
            let complete = complete_prefix(part);
            let n_intents = complete
                .split(|&b| b == b'\n')
                .skip(1)
                .filter(|l| std::str::from_utf8(l).ok().and_then(parse_line).is_some_and(|(s, _)| s == State::Intent))
                .count();
            assert_eq!(p.intents.len(), n_intents, "cut at {cut}");
            let last_two: Vec<String> = plan.iter().rev().take(2).map(|(s, _)| s.render()).collect();
            assert_eq!(last_two, vec!["fwdown\tv6".to_string(), "fwdown\tv4".to_string()], "cut at {cut}");
            // Every step present in the prefix plan appears in the full plan in the same relative order.
            let full_plan = render_plan(&restore_plan(&parse(&full), "boot-1"));
            let mut pos = 0;
            for line in render_plan(&plan).lines() {
                let found = full_plan[pos..].find(line);
                assert!(found.is_some(), "cut at {cut}: step {line} not in full plan order");
                pos += found.unwrap_or(0) + line.len();
            }
        }
    }

    #[test]
    fn invalid_entries_and_torn_header_are_skipped() {
        let mut j = sample_journal();
        j.extend_from_slice(b"99\tINTENT\tSETTING\tglobal/x\t1\t00000000\n");
        j.extend_from_slice(b"100\tINTENT\tPKG_SUSPEND\tbad name\t0\tdeadbeef\n");
        let p = parse(&j);
        assert_eq!(p.intents.len(), 12);
        assert!(parse(b"ACTIVE\tboot-1\t0123").header.is_none());
        let torn = parse(b"ACTIVE\tboot-1\t0123");
        assert_eq!(render_plan(&restore_plan(&torn, "boot-1")), "fwdown\tv4\nfwdown\tv6\n");
    }
}
