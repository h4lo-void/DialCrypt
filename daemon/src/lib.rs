//! `aegiscalld` library: the secure-session logic of the DialCrypt root daemon.
//!
//! Every interaction with the system (commands, settings, firewall, packages,
//! /proc, properties, notifications, the restore journal) goes through
//! [`sysops::SysOps`]. The production implementation is [`real::RealSys`];
//! the tests drive the whole session with a recording fake.
//!
//! Nothing changes on the device unless `/data/adb/aegischat/policy.conf`
//! contains `armed=1`; otherwise the daemon runs in dry-run mode and only
//! records the steps it would take. The one exception is the RLIMIT_MEMLOCK
//! raise at ATTACH ([`sysops::SysOps::raise_memlock`]), which dry-run mode
//! performs as well: it applies only to the App's own secure process and is
//! gone when that process exits, so it is not a change to the device.

pub mod apk;
pub mod codes;
pub mod commands;
pub mod firewall;
pub mod ipc;
pub mod journal;
mod lockdown;
pub mod memscrub;
pub mod monitor;
pub mod mute_guard;
pub mod nflog;
pub mod peer;
pub mod pixel_audio;
pub mod pkgxml;
pub mod policy;
pub mod precheck;
pub mod procfs;
pub mod session;
pub mod sysops;
pub mod telephony;
pub mod valid;

#[cfg(unix)]
pub mod real;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub mod server;

#[cfg(test)]
mod fake;
#[cfg(test)]
mod scenario_tests;
