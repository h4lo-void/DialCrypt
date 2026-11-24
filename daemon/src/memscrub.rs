//! Tier 2 memory scrub steps (design E4 part 3): drop caches, compact,
//! zram swapoff/reset/swapon, fill free memory, clear logs. Logs are cleared
//! by running the tools directly, never through a shell.

use crate::sysops::{read_text, Mutation, SysOps};
use crate::valid::is_digits;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZramDev {
    pub dev: String,
    pub size: u64,
    pub prio: i32,
}

pub const FILL_RESERVE_MIB: u64 = 256;
pub const FILL_MAX_MS: u64 = 8_000;

/// `<disksize>,<priority>` as stored in ZRAM journal entries.
pub fn zram_spec(size: u64, prio: i32) -> String {
    format!("{size},{prio}")
}

/// Same rule as the restore script: digits(1..19) "," ["-"] digits(1..5).
pub fn parse_zram_spec(s: &str) -> Option<(u64, i32)> {
    let (size, prio) = s.split_once(',')?;
    let p = prio.strip_prefix('-').unwrap_or(prio);
    if !is_digits(size, 19) || !is_digits(p, 5) {
        return None;
    }
    Some((size.parse().ok()?, prio.parse().ok()?))
}

/// (device path, priority) for every swap area; `only_zram` is false when any
/// swap is not a zram device.
pub fn parse_swaps(text: &str) -> (Vec<(String, i32)>, bool) {
    let mut out = Vec::new();
    let mut only_zram = true;
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.is_empty() {
            continue;
        }
        if !f[0].starts_with("/dev/block/zram") {
            only_zram = false;
        }
        let prio = f.get(4).and_then(|p| p.parse().ok()).unwrap_or(-2);
        out.push((f[0].to_string(), prio));
    }
    (out, only_zram)
}

pub fn swap_active<S: SysOps + ?Sized>(sys: &mut S, dev: &str) -> bool {
    let path = format!("/dev/block/{dev}");
    read_text(sys, "/proc/swaps").map(|t| parse_swaps(&t).0.iter().any(|(p, _)| *p == path)).unwrap_or(false)
}

pub fn zram_devices<S: SysOps + ?Sized>(sys: &mut S) -> Vec<ZramDev> {
    let Ok(text) = read_text(sys, "/proc/swaps") else { return Vec::new() };
    let mut out = Vec::new();
    for (path, prio) in parse_swaps(&text).0 {
        let Some(dev) = path.strip_prefix("/dev/block/") else { continue };
        let ok_name = dev.strip_prefix("zram").is_some_and(|n| is_digits(n, 2));
        if !ok_name {
            continue;
        }
        let size = read_text(sys, &format!("/sys/block/{dev}/disksize")).ok().and_then(|s| s.trim().parse().ok());
        if let Some(size) = size {
            out.push(ZramDev { dev: dev.to_string(), size, prio });
        }
    }
    out
}

pub fn drop_caches() -> Mutation {
    Mutation::WriteFile { path: "/proc/sys/vm/drop_caches".into(), data: "3".into() }
}

pub fn compact_memory() -> Mutation {
    Mutation::WriteFile { path: "/proc/sys/vm/compact_memory".into(), data: "1".into() }
}

fn swapon(z: &ZramDev) -> Mutation {
    let dev = format!("/dev/block/{}", z.dev);
    if z.prio >= 0 {
        Mutation::exec(&["swapon", "-p", &z.prio.to_string(), &dev])
    } else {
        Mutation::exec(&["swapon", &dev])
    }
}

/// Steps that bring a zram device back as swap (reset may fail harmlessly).
pub fn zram_restore(z: &ZramDev) -> (Mutation, Vec<Mutation>) {
    let dev = format!("/dev/block/{}", z.dev);
    (
        Mutation::WriteFile { path: format!("/sys/block/{}/reset", z.dev), data: "1".into() },
        vec![
            Mutation::WriteFile { path: format!("/sys/block/{}/disksize", z.dev), data: z.size.to_string() },
            Mutation::exec(&["mkswap", &dev]),
            swapon(z),
        ],
    )
}

/// swapoff → reset → disksize → mkswap → swapon.
pub fn zram_cycle(z: &ZramDev) -> Vec<Mutation> {
    let (reset, rest) = zram_restore(z);
    let mut v = vec![Mutation::exec(&["swapoff", &format!("/dev/block/{}", z.dev)]), reset];
    v.extend(rest);
    v
}

pub fn fill_free() -> Mutation {
    Mutation::FillFreeMemory { reserve_mib: FILL_RESERVE_MIB, max_ms: FILL_MAX_MS }
}

pub fn clear_logs() -> Vec<Mutation> {
    vec![Mutation::exec(&["logcat", "-b", "all", "-c"]), Mutation::exec(&["dmesg", "-C"])]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zram_spec_and_swaps() {
        assert_eq!(parse_zram_spec("4294967296,-2"), Some((4294967296, -2)));
        assert_eq!(parse_zram_spec("1,2,3"), None);
        assert_eq!(parse_zram_spec("1,--2"), None);
        let (s, only) = parse_swaps("Filename Type Size Used Priority\n/dev/block/zram0 partition 4194300 0 -2\n");
        assert!(only && s == vec![("/dev/block/zram0".to_string(), -2)]);
        assert!(!parse_swaps("h\n/data/swapfile file 1 0 -3\n").1);
    }
}
