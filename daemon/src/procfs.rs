//! /proc helpers. Process identity is always (pid, start time) so that a
//! reused pid is never mistaken for the original process.

use crate::sysops::{read_text, SysOps};
use crate::valid::parse_u32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcId {
    pub pid: u32,
    pub starttime: u64,
}

/// Field 22 of /proc/<pid>/stat (the comm field may contain spaces).
pub fn stat_starttime(stat: &str) -> Option<u64> {
    let r = stat.rfind(')')?;
    stat[r + 1..].split_whitespace().nth(19)?.parse().ok()
}

pub fn read_starttime<S: SysOps + ?Sized>(sys: &mut S, pid: u32) -> Option<u64> {
    read_text(sys, &format!("/proc/{pid}/stat")).ok().as_deref().and_then(stat_starttime)
}

pub fn alive<S: SysOps + ?Sized>(sys: &mut S, p: ProcId) -> bool {
    read_starttime(sys, p.pid) == Some(p.starttime)
}

fn status_value<'a>(status: &'a str, key: &str) -> Option<&'a str> {
    status.lines().find_map(|l| l.strip_prefix(key)).map(str::trim)
}

pub fn tracer_pid(status: &str) -> Option<u32> {
    parse_u32(status_value(status, "TracerPid:")?)
}

/// Real uid (first value of the `Uid:` line).
pub fn status_uid(status: &str) -> Option<u32> {
    parse_u32(status_value(status, "Uid:")?.split_whitespace().next()?)
}

pub fn cmdline_first(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

pub const INJECTION_MARKERS: [&str; 6] = ["frida", "xposed", "lsposed", "zygisk", "riru", "substrate"];

pub fn maps_injected(maps: &str) -> bool {
    let lower = maps.to_ascii_lowercase();
    INJECTION_MARKERS.iter().any(|m| lower.contains(m))
}

pub fn list_pids<S: SysOps + ?Sized>(sys: &mut S) -> Vec<u32> {
    sys.list_dir("/proc").map(|v| v.iter().filter_map(|n| parse_u32(n)).collect()).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_stat_status_maps() {
        let stat = "700 (com.x (y) z) S 1 1 0 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 5000 0 0";
        assert_eq!(stat_starttime(stat), Some(5000));
        assert_eq!(tracer_pid("Name:\tx\nTracerPid:\t0\n"), Some(0));
        assert_eq!(status_uid("Uid:\t10245\t10245\t10245\t10245\n"), Some(10245));
        assert_eq!(cmdline_first(b"io.github.h4lovoid.dialcrypt:secure\0\0"), "io.github.h4lovoid.dialcrypt:secure");
        assert!(maps_injected("7f00 r-xp /data/local/tmp/frida-agent-64.so"));
        assert!(!maps_injected("7f00 r-xp /system/lib64/libc.so"));
    }
}
