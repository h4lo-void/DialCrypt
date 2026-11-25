//! `aegiscalld` entry point.
//!
//! - no arguments: restore any leftover journal, then serve the App
//! - `--recover-boot`: restore a journal left by a crash or reboot and exit
//! - `--fill-memory <reserve_mib> <max_ms>`: tier 2 memory scrub helper
//! - `--selftest`: offline self-test of firewall, IPC, and journal invariants
//!
//! Exit codes follow sysexits: 0 ok, 64 usage, 70 self-test failed,
//! 71 socket unavailable, 75 restore incomplete, 77 not root,
//! 78 unsupported platform or device.

const EX_OK: i32 = 0;
const EX_USAGE: i32 = 64;
const EX_SOFTWARE: i32 = 70;
#[cfg(unix)]
const EX_TEMPFAIL: i32 = 75;
#[cfg(unix)]
const EX_NOPERM: i32 = 77;
const EX_CONFIG: i32 = 78;

fn main() {
    aegiscall_memsec::harden_process();
    let args: Vec<String> = std::env::args().collect();
    std::process::exit(run(&args));
}

fn run(args: &[String]) -> i32 {
    match args.get(1).map(String::as_str) {
        Some("--selftest") if args.len() == 2 => selftest(),
        Some("--fill-memory") if args.len() == 4 => fill_memory(&args[2], &args[3]),
        Some("--recover-boot") if args.len() == 2 => daemon(true),
        Some("--precheck") if args.len() == 2 => precheck_only(),
        None => daemon(false),
        _ => EX_USAGE,
    }
}

#[cfg(unix)]
fn daemon(recover_only: bool) -> i32 {
    use aegiscalld::real::RealSys;
    use aegiscalld::session::Session;

    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        return EX_NOPERM;
    }
    let mut session = Session::new(RealSys::new());
    let _ = session.recover_leftover();
    if recover_only {
        return if session.restore_pending() { EX_TEMPFAIL } else { EX_OK };
    }
    if aegiscalld::sysops::getprop(session.sys_mut(), "ro.product.manufacturer") != "Google" {
        return EX_CONFIG;
    }
    serve(&mut session)
}

#[cfg(not(unix))]
fn daemon(_recover_only: bool) -> i32 {
    EX_CONFIG
}

/// Runs the read-only precheck once with the installed policy and prints every
/// failing item and code. Changes nothing on the device.
#[cfg(unix)]
fn precheck_only() -> i32 {
    use aegiscalld::policy::Policy;
    use aegiscalld::real::RealSys;

    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        return EX_NOPERM;
    }
    let mut sys = RealSys::new();
    let (policy, issue) = Policy::load(&mut sys);
    if let Some(c) = issue {
        println!("policy invalid code={}", c.as_u16());
    }
    match aegiscalld::precheck::run(&mut sys, &policy, policy.dedicated_mode) {
        Ok(ctx) => {
            println!("precheck ok boot={:?} ims_uids={:?} slots={:?}", ctx.boot, ctx.ims_uids, ctx.slots);
            EX_OK
        }
        Err(fails) => {
            for f in fails {
                println!("precheck fail item={:?}({}) code={:?}({})", f.item, f.item.as_u16(), f.code, f.code.as_u16());
            }
            EX_CONFIG
        }
    }
}

#[cfg(not(unix))]
fn precheck_only() -> i32 {
    EX_CONFIG
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn serve(session: &mut aegiscalld::session::Session<aegiscalld::real::RealSys>) -> i32 {
    aegiscalld::server::serve(session)
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
fn serve(_session: &mut aegiscalld::session::Session<aegiscalld::real::RealSys>) -> i32 {
    EX_CONFIG
}

/// Allocates and touches anonymous memory until only `reserve_mib` remain
/// or `max_ms` passed, so the kernel hands out (and zeroes) free pages.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn fill_memory(reserve: &str, max_ms: &str) -> i32 {
    use std::time::{Duration, Instant};

    let (Some(reserve), Some(max_ms)) = (aegiscalld::valid::parse_u64(reserve), aegiscalld::valid::parse_u64(max_ms)) else {
        return EX_USAGE;
    };
    if !(64..=4096).contains(&reserve) || max_ms > 8_000 {
        return EX_USAGE;
    }
    let _ = std::fs::write("/proc/self/oom_score_adj", b"1000");
    let avail_mib = || -> Option<u64> {
        let t = std::fs::read_to_string("/proc/meminfo").ok()?;
        let l = t.lines().find(|l| l.starts_with("MemAvailable:"))?;
        l.split_whitespace().nth(1)?.parse::<u64>().ok().map(|kb| kb / 1024)
    };
    const CHUNK: usize = 64 << 20;
    let start = Instant::now();
    let mut maps: Vec<*mut libc::c_void> = Vec::new();
    while start.elapsed() < Duration::from_millis(max_ms) {
        match avail_mib() {
            Some(m) if m > reserve + 64 => {}
            _ => break,
        }
        // SAFETY: anonymous private mapping; checked against MAP_FAILED.
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                CHUNK,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_POPULATE,
                -1,
                0,
            )
        };
        if p == libc::MAP_FAILED {
            break;
        }
        maps.push(p);
    }
    for p in maps {
        // SAFETY: p was returned by mmap with length CHUNK.
        unsafe {
            libc::munmap(p, CHUNK);
        }
    }
    EX_OK
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn fill_memory(_reserve: &str, _max_ms: &str) -> i32 {
    EX_CONFIG
}

/// Offline check of the daemon's firewall, IPC framing, and restore journal invariants.
fn selftest() -> i32 {
    use std::net::IpAddr;

    use aegiscalld::firewall::{restore_text, Family, FwConfig, CHAIN_FWD, CHAIN_IN, CHAIN_OUT};
    use aegiscalld::ipc::{
        decode_client, decode_server, encode_client, encode_server, ClientMsg, FrameReader, ServerMsg, PROTO_VERSION,
    };
    use aegiscalld::journal::{encode_line, parse, restore_plan, Header, Kind, State, Step};

    let cfg = FwConfig {
        iface: "rmnet0".into(),
        uids: vec![10228],
        pcscf: vec![IpAddr::from([192, 0, 2, 10])],
        media: Vec::new(),
        nflog: true,
        wlan_iface: Some("wlan0".into()),
        epdg: vec![IpAddr::from([198, 51, 100, 20])],
    };
    let mut ok = true;
    for fam in Family::ALL {
        let rules = restore_text(&cfg, fam, true);
        for c in [CHAIN_IN, CHAIN_OUT, CHAIN_FWD] {
            let last = rules.lines().rfind(|l| l.starts_with(&format!("-A {c} "))).unwrap_or("");
            ok &= last == format!("-A {c} -j DROP");
        }
        ok &= rules.ends_with("COMMIT\n");
    }

    let mut reader = FrameReader::default();
    for msg in [
        ClientMsg::Hello { version: PROTO_VERSION },
        ClientMsg::Prepare,
        ClientMsg::TrimStorage,
        ClientMsg::End,
    ] {
        let wire = encode_client(&msg);
        match reader.push(&wire) {
            Ok(frames) if frames.len() == 1 => ok &= decode_client(&frames[0]) == Ok(msg),
            _ => ok = false,
        }
    }
    let srv = ServerMsg::Hello { version: PROTO_VERSION, mode: 1 };
    let srv_wire = encode_server(&srv);
    ok &= srv_wire.len() >= 3 && decode_server(&srv_wire[2..]) == Ok(srv);

    let hdr = Header {
        boot_id: "selftest-boot".into(),
        lease_hash: "0123456789abcdef".into(),
        owner_pid: 1,
        owner_start: 1,
    };
    if let (Ok(h), Ok(line)) = (hdr.encode(), encode_line(1, State::Intent, Kind::Radio, "wifi", "on")) {
        let text = format!("{h}{line}");
        let parsed = parse(text.as_bytes());
        let plan = restore_plan(&parsed, "selftest-boot");
        let n = plan.len();
        ok &= parsed.header == Some(hdr) && parsed.intents.len() == 1 && n == 3;
        if n == 3 {
            ok &= matches!(plan[n - 2].0, Step::FwDown(Family::V4))
                && matches!(plan[n - 1].0, Step::FwDown(Family::V6));
        }
    } else {
        ok = false;
    }

    if ok {
        EX_OK
    } else {
        EX_SOFTWARE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selftest_passes_and_usage_is_strict() {
        assert_eq!(selftest(), EX_OK);
        assert_eq!(run(&["aegiscalld".into(), "--bogus".into()]), EX_USAGE);
        assert_eq!(run(&["aegiscalld".into(), "--selftest".into(), "x".into()]), EX_USAGE);
    }
}
