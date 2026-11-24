//! Prechecks (design E4 step 4 as amended by 6.1/6.7). Nothing on the device
//! is changed here; every failure is reported as (item, code).

use std::collections::BTreeSet;

use crate::codes::{Code, Failure, Item};
use crate::commands;
use crate::journal::Kind;
use crate::memscrub;
use crate::peer::APP_PACKAGE;
use crate::policy::Policy;
use crate::procfs;
use crate::sysops::{getprop, read_text, settings_get, SysOps};
use crate::telephony::{self, ImsLink};
use crate::valid::{is_iface_name, is_package_name, parse_u32};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PkgInfo {
    pub name: String,
    pub uid: u32,
    pub path: String,
}

impl PkgInfo {
    /// Installed from a read-only system image partition.
    pub fn on_system_image(&self) -> bool {
        ["/system/", "/system_ext/", "/product/", "/vendor/", "/odm/", "/apex/"].iter().any(|p| self.path.starts_with(p))
    }
}

/// `pm list packages -f -U --user 0`: `package:<path>=<name> uid:<uid>`.
pub fn parse_package_list(text: &str) -> Vec<PkgInfo> {
    let mut out = Vec::new();
    for line in text.lines() {
        let Some(rest) = line.trim().strip_prefix("package:") else { continue };
        let Some((left, uid)) = rest.rsplit_once(" uid:") else { continue };
        let Some((path, name)) = left.rsplit_once('=') else { continue };
        let Some(uid) = parse_u32(uid.split(',').next().unwrap_or("")) else { continue };
        if is_package_name(name) && path.starts_with('/') {
            out.push(PkgInfo { name: name.to_string(), uid, path: path.to_string() });
        }
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootMode {
    /// Locked with a custom AVB key on the allow list.
    Relocked,
    /// Unlocked bootloader with Magisk.
    Magisk,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tier2Plan {
    pub exempt: BTreeSet<String>,
    pub system_ime: String,
    pub suspended_before: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Context {
    pub boot: BootMode,
    pub ims: ImsLink,
    pub ims_uids: Vec<u32>,
    pub slots: Vec<u8>,
    pub uwb: bool,
    pub packages: Vec<PkgInfo>,
    pub tier2: Option<Tier2Plan>,
}

pub const REQUIRED_TOOLS: [&str; 12] =
    ["iptables", "ip6tables", "iptables-restore", "ip6tables-restore", "settings", "cmd", "svc", "dumpsys", "pm", "ime", "content", "getprop"];
pub const TIER2_TOOLS: [&str; 5] = ["logcat", "dmesg", "swapon", "swapoff", "mkswap"];

/// Exemptions allowed by the design 6.7, only when installed on the system image.
pub const SYSTEM_EXEMPT: [&str; 10] = [
    "com.android.systemui",
    "com.android.server.telecom",
    "com.android.phone",
    "com.android.carrierconfig",
    "com.google.android.carrier",
    "com.android.providers.telephony",
    "com.android.permissioncontroller",
    "com.google.android.permissioncontroller",
    "com.android.packageinstaller",
    "com.google.android.packageinstaller",
];
const TETHER_PREFIXES: [&str; 6] = ["ap", "swlan", "rndis", "ncm", "bt-pan", "softap"];
const INJECTION_PROCS: [&str; 4] = ["frida", "lsposed", "xposed", "riru"];

fn not_zero(v: Option<String>) -> bool {
    !matches!(v.as_deref(), Some("0") | Some("null") | Some(""))
}

/// Owners reported by `dumpsys device_policy` as (device owner, profile owner).
/// AOSP prints a `Device Owner:` block and a `Profile Owner (User N):` block, each
/// with an `admin=ComponentInfo{..}` line, only when an owner exists. The always
/// present `Device Owner Type: -1` and `Has PO:` lines say nothing about owners.
pub fn parse_owners(text: &str) -> (bool, bool) {
    let lines: Vec<&str> = text.lines().collect();
    let indent = |l: &str| l.len() - l.trim_start().len();
    let has_admin = |header: usize| {
        let base = indent(lines[header]);
        for (n, l) in lines[header + 1..].iter().enumerate() {
            if l.trim().is_empty() || (n > 0 && indent(l) <= base) {
                return false;
            }
            if l.trim_start().starts_with("admin=ComponentInfo{") {
                return true;
            }
        }
        false
    };
    let (mut device, mut profile) = (false, false);
    for (i, l) in lines.iter().enumerate() {
        let t = l.trim();
        if t == "Device Owner:" || (t.starts_with("Device Owner (") && t.ends_with(':')) {
            device |= has_admin(i);
        } else if t.starts_with("Profile Owner (") && t.ends_with(':') {
            profile |= has_admin(i);
        }
    }
    (device, profile)
}

fn role_holder<S: SysOps + ?Sized>(sys: &mut S, role: &str) -> Option<String> {
    let out = sys.read_cmd(&["cmd", "role", "get-role-holders", "--user", "0", role]).ok()?;
    out.split(|c: char| c.is_whitespace() || c == ',' || c == '[' || c == ']').find(|t| is_package_name(t)).map(str::to_string)
}

/// Phone app assumed when `cmd telecom get-system-dialer` prints nothing usable (Pixel),
/// names this app itself, or names a package that is not on the system image.
pub const SYSTEM_DIALER_FALLBACK: &str = "com.google.android.dialer";

/// The phone app built into the system image: the first package name printed by
/// `cmd telecom get-system-dialer` (To be confirmed on device: output format), else
/// [`SYSTEM_DIALER_FALLBACK`]. It keeps the emergency call screen working, so it is
/// always exempt from the Tier 2 lockdown.
fn system_dialer<S: SysOps + ?Sized>(sys: &mut S) -> String {
    sys.read_cmd(&["cmd", "telecom", "get-system-dialer"])
        .ok()
        .and_then(|out| out.split(|c: char| c.is_whitespace() || c == ',' || c == '[' || c == ']').find(|t| is_package_name(t)).map(str::to_string))
        .unwrap_or_else(|| SYSTEM_DIALER_FALLBACK.to_string())
}

/// Boot value as the bootloader passed it: `/proc/bootconfig` first (only root reads it and
/// `resetprop` cannot change it), then the `ro.boot.*` property.
fn boot_value<S: SysOps + ?Sized>(sys: &mut S, bootconfig: &str, name: &str) -> (String, bool) {
    let key = format!("androidboot.{name}");
    for l in bootconfig.lines() {
        if let Some((k, v)) = l.split_once('=') {
            if k.trim() == key {
                return (v.trim().trim_matches('"').to_string(), true);
            }
        }
    }
    (getprop(sys, &format!("ro.boot.{name}")), false)
}

pub fn run<S: SysOps + ?Sized>(sys: &mut S, policy: &Policy, tier2: bool) -> Result<Context, Vec<Failure>> {
    let mut f: Vec<Failure> = Vec::new();
    let mut fail = |item, code| f.push(Failure::new(item, code));

    // 6.1: Pixel only.
    if getprop(sys, "ro.product.manufacturer") != "Google" || !getprop(sys, "ro.product.brand").eq_ignore_ascii_case("google") {
        fail(Item::Device, Code::DeviceUnsupported);
    }

    // 1. Verified boot state.
    let bootconfig = read_text(sys, "/proc/bootconfig").unwrap_or_default();
    let (dev, dev_from_bootloader) = boot_value(sys, &bootconfig, "vbmeta.device_state");
    let (vbs, _) = boot_value(sys, &bootconfig, "verifiedbootstate");
    let locked = match boot_value(sys, &bootconfig, "flash.locked") {
        (v, true) => v,
        // Not every bootloader passes flash.locked; the property is then no better than
        // the device state the bootloader did pass.
        _ if dev_from_bootloader => if dev == "locked" { "1".to_string() } else { "0".to_string() },
        (v, false) => v,
    };
    let boot = match (dev.as_str(), vbs.as_str(), locked.as_str()) {
        ("locked", "yellow", "1") => {
            // To be confirmed on device: property that exposes the custom AVB key digest.
            let key = boot_value(sys, &bootconfig, "vbmeta.public_key_digest").0.to_ascii_lowercase();
            if !policy.avb_keys.iter().any(|k| *k == key) {
                fail(Item::Boot, Code::AvbKeyNotAllowed);
            }
            BootMode::Relocked
        }
        ("unlocked", "orange", "0") => BootMode::Magisk,
        _ => {
            fail(Item::Boot, Code::BootStateInvalid);
            BootMode::Magisk
        }
    };

    // 2. SELinux enforcing.
    if read_text(sys, "/sys/fs/selinux/enforce").map(|s| s.trim() != "1").unwrap_or(true) {
        fail(Item::Selinux, Code::SelinuxNotEnforcing);
    }

    // 3. ADB and developer options off, adbd not running. A test device with
    // `test_allow_usb_debug=1` may keep USB debugging; wireless ADB never passes.
    let usb_debug_ok = policy.test_allow_usb_debug;
    if !usb_debug_ok && not_zero(settings_get(sys, "global", "adb_enabled")) {
        fail(Item::Adb, Code::AdbEnabled);
    }
    if not_zero(settings_get(sys, "global", "adb_wifi_enabled")) {
        fail(Item::Adb, Code::AdbWifiEnabled);
    }
    if !usb_debug_ok && not_zero(settings_get(sys, "global", "development_settings_enabled")) {
        fail(Item::Adb, Code::DevSettingsEnabled);
    }
    if !usb_debug_ok && getprop(sys, "init.svc.adbd") == "running" {
        fail(Item::Adb, Code::AdbdRunning);
    }

    // 4. No device or profile owner (To be confirmed on device: the owner blocks, which a Pixel without
    //    owner never prints, follow the AOSP source and have not been captured).
    match sys.read_cmd(&["dumpsys", "device_policy"]) {
        Ok(t) => {
            let (device, profile) = parse_owners(&t);
            if device {
                fail(Item::Owner, Code::DeviceOwnerPresent);
            }
            // A test device may keep its work profile with `test_allow_profile_owner=1`.
            if profile && !policy.test_allow_profile_owner {
                fail(Item::Owner, Code::ProfileOwnerPresent);
            }
        }
        Err(_) => fail(Item::Commands, Code::CommandOutputUnparsed),
    }

    // 5. No hotspot / tethering interface up.
    let ifaces = sys.list_dir("/sys/class/net").unwrap_or_default();
    for n in &ifaces {
        if !is_iface_name(n) || !TETHER_PREFIXES.iter().any(|p| n.starts_with(p)) {
            continue;
        }
        if read_text(sys, &format!("/sys/class/net/{n}/operstate")).map(|s| s.trim() == "up").unwrap_or(false) {
            fail(Item::Tether, Code::TetheringActive);
        }
    }

    // 7. No screen recording or casting (To be confirmed on device: dumpsys media_projection layout;
    //    detection of other audio capture is not implemented).
    match sys.read_cmd(&["dumpsys", "media_projection"]) {
        Ok(t) if t.contains("MediaProjection{") => fail(Item::Capture, Code::ScreenCaptureActive),
        Ok(_) => {}
        Err(_) => fail(Item::Commands, Code::CommandOutputUnparsed),
    }

    // 8. Swap is zram only.
    match read_text(sys, "/proc/swaps") {
        Ok(t) if memscrub::parse_swaps(&t).1 => {}
        _ => fail(Item::Swap, Code::SwapNotZramOnly),
    }

    // 9. Magisk mode: DenyList enforced and containing the App; no injection frameworks.
    if boot == BootMode::Magisk {
        // KernelSU has no DenyList: root is granted per app and module mounts are hidden
        // from apps without root. To be confirmed on device: reading the App's KernelSU profile.
        let kernelsu = sys.exists("/data/adb/ksud");
        if !kernelsu {
            if sys.read_cmd(&["magisk", "--denylist", "status"]).is_err() {
                fail(Item::Magisk, Code::DenylistNotEnforced);
            }
            let listed = sys
                .read_cmd(&["magisk", "--denylist", "ls"])
                .map(|t| t.lines().any(|l| l.trim().starts_with(&format!("{APP_PACKAGE}|"))))
                .unwrap_or(false);
            if !listed {
                fail(Item::Magisk, Code::AppNotInDenylist);
            }
        }
        let modules = sys.list_dir("/data/adb/modules").unwrap_or_default();
        let mut injected = modules.iter().any(|m| {
            let l = m.to_ascii_lowercase();
            INJECTION_PROCS.iter().any(|x| l.contains(x))
        });
        for pid in procfs::list_pids(sys) {
            let cmd = sys.read_file(&format!("/proc/{pid}/cmdline")).map(|b| procfs::cmdline_first(&b)).unwrap_or_default();
            let l = cmd.to_ascii_lowercase();
            if INJECTION_PROCS.iter().any(|x| l.contains(x)) {
                injected = true;
            }
        }
        if injected {
            fail(Item::Magisk, Code::InjectionFramework);
        }
    }

    // 10. VoLTE on, IMS on WWAN LTE/NR, interface, P-CSCF and IMS uid resolved. The slots
    // to lock down are the ones that hold a SIM (siminfo rows with sim_id >= 0), whatever
    // persist.radio.multisim.config says.
    let mut slots: Vec<u8> = Vec::new();
    match sys.read_cmd(&["content", "query", "--uri", "content://telephony/siminfo", "--projection", "_id:volte_vt_enabled:sim_id"]) {
        Ok(t) => {
            let (s, verdict) = telephony::scan_siminfo(&t);
            slots = s;
            if let Err(c) = verdict {
                fail(Item::Ims, c);
            }
        }
        Err(_) => fail(Item::Ims, Code::VolteOff),
    }
    let ims = match sys.read_cmd(&["dumpsys", "telephony.registry"]) {
        Ok(t) => match telephony::parse_ims_link(&t) {
            Ok(l) => Some(l),
            Err(c) => {
                fail(Item::Ims, c);
                None
            }
        },
        Err(_) => {
            fail(Item::Ims, Code::ImsNotRegistered);
            None
        }
    };
    let packages = sys.read_cmd(&["pm", "list", "packages", "-f", "-U", "--user", "0"]).map(|t| parse_package_list(&t)).unwrap_or_default();
    if packages.is_empty() {
        fail(Item::Commands, Code::CommandOutputUnparsed);
    }
    // The command needs -c (carrier) or -d (device) and a slot; either may be the empty answer.
    let mut ims_pkgs: Vec<String> = Vec::new();
    for slot in &slots {
        for flag in ["-c", "-d"] {
            let out = sys.read_cmd(&["cmd", "phone", "ims", "get-ims-service", "-s", &slot.to_string(), flag]);
            if let Some(p) = out.ok().and_then(|t| telephony::parse_ims_service_package(&t)) {
                if !ims_pkgs.contains(&p) {
                    ims_pkgs.push(p);
                }
            }
        }
    }
    let mut ims_uids: Vec<u32> = policy.ims_uids.clone();
    for pkg in &ims_pkgs {
        if let Some(p) = packages.iter().find(|p| p.name == *pkg) {
            if !ims_uids.contains(&p.uid) {
                ims_uids.push(p.uid);
            }
        }
    }
    if ims_uids.is_empty() {
        fail(Item::Ims, Code::ImsUidUnresolved);
    }

    // 11. Required tools present and their outputs readable.
    for t in REQUIRED_TOOLS.iter().chain(if tier2 { TIER2_TOOLS.iter() } else { [].iter() }) {
        if !sys.exists(&format!("/system/bin/{t}")) {
            fail(Item::Commands, Code::CommandMissing);
            break;
        }
    }
    let uwb = commands::read_item(sys, Kind::Radio, "uwb").is_some();
    let mut readable = ["wifi", "bluetooth", "nfc", "data"].iter().all(|r| commands::read_item(sys, Kind::Radio, r).is_some());
    readable &= slots.iter().all(|s| commands::read_item(sys, Kind::NetType, &s.to_string()).is_some());
    // With test_allow_usb_debug the USB functions are not part of the session (tier1_items).
    readable &= policy.test_allow_usb_debug || commands::read_item(sys, Kind::Usb, "functions").is_some();
    if !readable {
        fail(Item::Commands, Code::CommandOutputUnparsed);
    }

    // Tier 2 extras (design 6.7): dialer and launcher from the system image,
    // a system-image input method to switch to, and the exemption list. When this
    // app holds the dialer role the system phone app must still be on the system
    // image: Telecom hands emergency calls to it.
    let mut t2 = None;
    if tier2 {
        let sys_pkg = |name: &str| packages.iter().find(|p| p.name == name).filter(|p| p.on_system_image()).cloned();
        let dialer = role_holder(sys, "android.app.role.DIALER").and_then(|d| sys_pkg(&d));
        // The command may name this app once it holds the dialer role, or a package outside the
        // system image; the phone app that takes emergency calls is then the constant one.
        let named = system_dialer(sys);
        let system_phone = Some(named)
            .filter(|n| n.as_str() != APP_PACKAGE)
            .and_then(|n| sys_pkg(&n))
            .or_else(|| sys_pkg(SYSTEM_DIALER_FALLBACK));
        let home = role_holder(sys, "android.app.role.HOME").and_then(|h| sys_pkg(&h));
        if dialer.is_none() {
            fail(Item::Tier2, Code::DialerNotSystem);
        } else if dialer.as_ref().is_some_and(|d| d.name == APP_PACKAGE) && system_phone.is_none() {
            fail(Item::Tier2, Code::SystemDialerMissing);
        }
        if home.is_none() {
            fail(Item::Tier2, Code::HomeNotSystem);
        }
        let imes = sys.read_cmd(&["ime", "list", "-s"]).unwrap_or_default();
        let system_ime = imes
            .lines()
            .map(str::trim)
            .filter(|id| crate::valid::is_ime_id(id))
            .find(|id| id.split('/').next().and_then(|p| sys_pkg(p)).is_some())
            .map(str::to_string);
        let Some(system_ime) = system_ime else {
            fail(Item::Tier2, Code::NoSystemIme);
            return Err(f);
        };
        let mut exempt: BTreeSet<String> = SYSTEM_EXEMPT.iter().filter(|n| sys_pkg(n).is_some()).map(|n| n.to_string()).collect();
        let others = [dialer.map(|d| d.name), system_phone.map(|d| d.name), home.map(|h| h.name), system_ime.split('/').next().map(str::to_string)];
        for p in ims_pkgs.iter().cloned().chain(others.into_iter().flatten()) {
            if sys_pkg(&p).is_some() {
                exempt.insert(p);
            }
        }
        exempt.insert(APP_PACKAGE.to_string());
        let magisk = policy.magisk_pkg.clone().unwrap_or_else(|| "com.topjohnwu.magisk".to_string());
        if packages.iter().any(|p| p.name == magisk) {
            exempt.insert(magisk);
        }
        let suspended_before = parse_suspended(&sys.read_cmd(&["dumpsys", "package", "packages"]).unwrap_or_default());
        t2 = Some(Tier2Plan { exempt, system_ime, suspended_before });
    }

    match ims {
        Some(ims) if f.is_empty() => Ok(Context { boot, ims, ims_uids, slots, uwb, packages, tier2: t2 }),
        _ => {
            if f.is_empty() {
                f.push(Failure::new(Item::Ims, Code::ImsNotRegistered));
            }
            Err(f)
        }
    }
}

/// Packages already suspended in user 0 according to `dumpsys package packages`
/// (To be confirmed on device: layout of the "User 0:" line).
pub fn parse_suspended(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut current: Option<String> = None;
    for line in text.lines().map(str::trim) {
        if let Some(rest) = line.strip_prefix("Package [") {
            current = rest.split(']').next().filter(|n| is_package_name(n)).map(str::to_string);
        } else if line.starts_with("User 0:") && line.contains("suspended=true") {
            if let Some(n) = &current {
                out.insert(n.clone());
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::parse_owners;

    /// Pixel 7 without owner: the lines of `dumpsys device_policy` that mention owners.
    const REAL: &str = "    mPasswordOwner=-1\n    mPasswordTokenHandle=0\n\n  Device provisioned: true\n  Device Owner Type: -1\n  Has PO:\n\nPersonalAppsSuspensionHelper\n";
    const ADMIN: &str = "admin=ComponentInfo{com.example.mdm/com.example.mdm.Admin}";

    #[test]
    fn lines_every_phone_prints_are_not_owners() {
        assert_eq!(parse_owners(REAL), (false, false));
        assert_eq!(parse_owners("  Device Owner Type: 0\n  Has PO: true\n"), (false, false));
        assert_eq!(parse_owners("  Device Owner: \n\n  Device provisioned: true\n"), (false, false), "block without admin");
    }

    #[test]
    fn owner_blocks_with_an_admin_count() {
        let dev = format!("{REAL}  Device Owner: \n    {ADMIN}\n    name=Example\n");
        assert_eq!(parse_owners(&dev), (true, false));
        let po = format!("{REAL}  Profile Owner (User 10):\n    {ADMIN}\n");
        assert_eq!(parse_owners(&po), (false, true));
        let both = format!("Device Owner:\n  {ADMIN}\nProfile Owner (User 0):\n  {ADMIN}\n");
        assert_eq!(parse_owners(&both), (true, true));
        // The admin of a profile owner does not make the empty device owner block before it a device owner.
        let only_po = format!("  Device Owner: \n\n  Profile Owner (User 0):\n    {ADMIN}\n");
        assert_eq!(parse_owners(&only_po), (false, true));
    }
}
