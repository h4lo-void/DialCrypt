//! End-to-end session scenarios against the recording fake, plus the
//! Rust ↔ shell parity check of the restore plan.

use std::process::Command;

use sha2::{Digest, Sha256};

use crate::apk::build_test_apk;
use crate::codes::{Code, Failure, Item};
use crate::fake::FakeSys;
use crate::ipc::{self, ClientMsg, ServerMsg};
use crate::journal::{self, encode_line, Header, Kind, State};
use crate::monitor::MonState;
use crate::policy::{Policy, POLICY_PATH};
use crate::precheck::{self, REQUIRED_TOOLS, TIER2_TOOLS};
use crate::session::{Input, Output, Phase, Session, BOOT_ID_PATH};
use crate::sysops::Mutation;
use crate::telephony::tests::{real_registry, real_siminfo};
use crate::valid::hex_encode;

const APP_UID: u32 = 10245;
const LAUNCHER: u32 = 500;
const SECURE: u32 = 700;
const CHAT_PID: u32 = 800;
const IME_PID: u32 = 810;
const BOOT: &str = "3f1c0b8e-1111-4000-8000-000000000001";
const CERT: &[u8] = b"aegis-release-cert/test stand-in for the DER of the pinned signer/0001";
const ATTACKER_CERT: &[u8] = b"attacker-cert/test stand-in for the DER of an unrelated signer/9999";
const SECOND_CERT: &[u8] = b"second-signer/test stand-in for the DER of an additional signer/0002";
const PLATFORM_CERT: &[u8] = b"platform-cert/test stand-in for the DER of the platform signer/0003";
const CHAT_CERT: &[u8] = b"chat-app-cert/test stand-in for the DER of a third party signer/0004";
const OLD_CERT: &[u8] = b"old-lineage-cert/test stand-in for the DER of a rotated-out key/0005";
const APK: &str = "/data/app/~~abc==/io.github.h4lovoid.dialcrypt-xyz==/base.apk";
const LTE_NR: &str = "11000001000000000000";
/// What the device prints once LTE_NR is set.
const LTE_NR_NAMES: &str = "LTE|LTE_CA|NR\n";
/// Pixel 7: allowed network types of slot 0 before the session (no NR).
const REAL_ALLOWED: &str = "GPRS|EDGE|UMTS|CDMA|CDMA - EvDo rev. 0|CDMA - EvDo rev. A|CDMA - 1xRTT|HSDPA|HSUPA|HSPA|CDMA - EvDo rev. B|LTE|CDMA - eHRPD|HSPA+|GSM|LTE_CA\n";
/// Pixel 7: the owner related lines of `dumpsys device_policy` (no owner is set).
const REAL_DEVICE_POLICY: &str = "    mPasswordOwner=-1\n    mPasswordTokenHandle=0\n    mAppsSuspended=false\n    mUserSetupComplete=true\n\n  Device provisioned: true\n  Device Owner Type: -1\n  Has PO:\n\nPersonalAppsSuspensionHelper\n";
/// Pixel 7: `dumpsys media_projection` with no projection.
const REAL_MEDIA_PROJECTION: &str = "MEDIA PROJECTION MANAGER (dumpsys media_projection)\nMedia Projection: \nnull\n";
const SIMINFO_CMD: &str = "content query --uri content://telephony/siminfo --projection _id:volte_vt_enabled:sim_id";
const IMS_PKG: &str = "com.shannon.imsservice";
const IMS_UID: u32 = 10228;

fn ims_service_cmd(slot: u8, flag: &str) -> String {
    format!("cmd phone ims get-ims-service -s {slot} {flag}")
}
const PACKAGES: &str = "package:/system/priv-app/SystemUI/SystemUI.apk=com.android.systemui uid:10050
package:/system/priv-app/Telecom/Telecom.apk=com.android.server.telecom uid:1000
package:/system_ext/priv-app/ShannonIms/ShannonIms.apk=com.shannon.imsservice uid:10228
package:/product/app/LatinIMEGooglePrebuilt/LatinIME.apk=com.google.android.inputmethod.latin uid:10120
package:/product/priv-app/GoogleDialer/GoogleDialer.apk=com.google.android.dialer uid:10130
package:/system_ext/priv-app/NexusLauncherRelease/NexusLauncher.apk=com.google.android.apps.nexuslauncher uid:10140
package:/product/priv-app/GmsCore/GmsCore.apk=com.google.android.gms uid:10150
package:/data/app/~~abc==/io.github.h4lovoid.dialcrypt-xyz==/base.apk=io.github.h4lovoid.dialcrypt uid:10245
package:/data/app/~~q==/com.chat.app-1==/base.apk=com.chat.app uid:10300
package:/data/app/~~r==/com.thirdparty.kbd-1==/base.apk=com.thirdparty.kbd uid:10310
package:/data/app/~~s==/com.already.suspended-1==/base.apk=com.already.suspended uid:10320
package:/data/app/~~t==/com.topjohnwu.magisk-1==/base.apk=com.topjohnwu.magisk uid:10330
";

fn policy(armed: bool, dedicated: bool) -> String {
    format!(
        "armed={}\ndedicated_mode={}\napp_cert_sha256={}\n",
        armed as u8,
        dedicated as u8,
        hex_encode(&Sha256::digest(CERT))
    )
}

fn pixel(policy_text: &str) -> FakeSys {
    let mut f = FakeSys::default();
    for (k, v) in [
        ("ro.product.manufacturer", "Google"),
        ("ro.product.brand", "google"),
        ("ro.boot.vbmeta.device_state", "unlocked"),
        ("ro.boot.verifiedbootstate", "orange"),
        ("ro.boot.flash.locked", "0"),
        ("init.svc.adbd", "stopped"),
        // dsds, but only slot 0 holds a SIM
        ("persist.radio.multisim.config", "dsds"),
    ] {
        f.set(&format!("getprop {k}"), v);
    }
    for (ns, k, v) in [
        ("global", "adb_enabled", "0"),
        ("global", "adb_wifi_enabled", "0"),
        ("global", "development_settings_enabled", "0"),
        ("global", "wifi_on", "1"),
        ("global", "bluetooth_on", "1"),
        ("global", "mobile_data", "1"),
        ("global", "wifi_scan_always_enabled", "1"),
        ("global", "wifi_wakeup_enabled", "1"),
        ("global", "ble_scan_always_enabled", "1"),
        ("secure", "default_input_method", "com.thirdparty.kbd/.Ime"),
        ("secure", "enabled_accessibility_services", "com.thirdparty.a11y/.Svc"),
        ("secure", "accessibility_enabled", "1"),
    ] {
        f.setting(ns, k, v);
    }
    f.set("dumpsys device_policy", REAL_DEVICE_POLICY);
    f.set("dumpsys media_projection", REAL_MEDIA_PROJECTION);
    f.set("magisk --denylist status", "Denylist is enforced\n");
    f.set("magisk --denylist ls", "io.github.h4lovoid.dialcrypt|io.github.h4lovoid.dialcrypt\nio.github.h4lovoid.dialcrypt|io.github.h4lovoid.dialcrypt:secure\n");
    f.set(SIMINFO_CMD, &real_siminfo());
    f.set("dumpsys telephony.registry", &real_registry());
    // The bare command is an error on the device (rc 255) and is not set; -c is empty, -d names the package.
    f.set(&ims_service_cmd(0, "-c"), "\n");
    f.set(&ims_service_cmd(0, "-d"), "com.shannon.imsservice\n");
    f.set("dumpsys nfc", "mState=on");
    // No uwb service on the Pixel 7 (rc 20) and no subscription in slot 1 (rc 255): both reads fail.
    f.set("cmd phone get-allowed-network-types-for-users -s 0", REAL_ALLOWED);
    f.set("svc usb getFunctions", "mtp");
    f.set("pm list packages -f -U --user 0", PACKAGES);
    f.set(PKG_XML_CMD, &packages_xml(&[CERT]));
    f.set("cmd role get-role-holders --user 0 android.app.role.DIALER", "com.google.android.dialer\n");
    f.set("cmd role get-role-holders --user 0 android.app.role.HOME", "com.google.android.apps.nexuslauncher\n");
    f.set("ime list -s", "com.google.android.inputmethod.latin/com.android.inputmethod.latin.LatinIME\ncom.thirdparty.kbd/.Ime\n");
    f.set(
        "dumpsys package packages",
        "Package [com.already.suspended] (a1):\n  User 0: ceDataInode=1 installed=true hidden=false suspended=true\nPackage [com.chat.app] (b2):\n  User 0: installed=true suspended=false\n",
    );
    f.file("/sys/fs/selinux/enforce", "1\n");
    f.file("/proc/swaps", "Filename Type Size Used Priority\n/dev/block/zram0 partition 4194300 0 -2\n");
    f.file("/sys/block/zram0/disksize", "4294967296\n");
    f.file(BOOT_ID_PATH, &format!("{BOOT}\n"));
    f.file(
        "/data/system/packages.list",
        "io.github.h4lovoid.dialcrypt 10245 0 /data/user/0/io.github.h4lovoid.dialcrypt default:privapp 3003\ncom.chat.app 10300 0 /data/user/0/com.chat.app default 3003\n",
    );
    if !policy_text.is_empty() {
        f.file(POLICY_PATH, policy_text);
    }
    // Interfaces of the Pixel 7; rmnet2 carries IMS, rmnet1 is the internet connection (down once data is off).
    let ifaces = [
        "aware_nmi0", "dummy0", "erspan0", "gre0", "gretap0", "ifb0", "ifb1", "ip6_vti0", "ip6gre0", "ip6tnl0", "ip_vti0", "lo", "radiotap0", "rmnet0",
        "rmnet1", "rmnet10", "rmnet2", "rmnet3", "sit0", "tunl0", "umts_dummy", "wlan0", "wlan1",
    ];
    f.dirs.insert("/sys/class/net".into(), ifaces.iter().map(|s| s.to_string()).collect());
    for n in ifaces {
        let st = match n {
            "lo" | "dummy0" | "umts_dummy" => "unknown",
            "rmnet2" => "up",
            _ => "down",
        };
        f.file(&format!("/sys/class/net/{n}/operstate"), st);
    }
    f.dirs.insert("/data/adb/modules".into(), vec!["aegischat_audio_firewall".into()]);
    for t in REQUIRED_TOOLS.iter().chain(TIER2_TOOLS.iter()) {
        f.file(&format!("/system/bin/{t}"), "");
    }
    f.add_proc(1, 0, "/system/bin/init", 1, 0, "");
    f.add_proc(LAUNCHER, APP_UID, "io.github.h4lovoid.dialcrypt", 1000, 0, "/system/lib64/libc.so");
    f.add_proc(CHAT_PID, 10300, "com.chat.app", 900, 0, "");
    f.add_proc(IME_PID, 10120, "com.google.android.inputmethod.latin", 900, 0, "");
    f.ticks = 2_000;
    f.now = 10_000;
    f
}

const PKG_XML_CMD: &str = "abx2xml /data/system/packages.xml -";
const SYSTEM_CODE_PATH: &str = "/system/priv-app/DialCrypt";

/// `<sigs>` block of a package: `count` as given, one `<cert>` per entry;
/// `(index, Some(der))` defines the key at that index, `(index, None)` only
/// refers to it.
fn sigs_xml(count: usize, certs: &[(u32, Option<&[u8]>)]) -> String {
    let mut s = format!("    <sigs count=\"{count}\" schemeVersion=\"2\">\n");
    for (index, der) in certs {
        match der {
            Some(d) => s.push_str(&format!("      <cert index=\"{index}\" key=\"{}\" />\n", hex_encode(d))),
            None => s.push_str(&format!("      <cert index=\"{index}\" />\n")),
        }
    }
    s.push_str("    </sigs>\n");
    s
}

/// The App's top-level `<package>` element (tag `tag`) with `sigs` as its signing record.
fn app_element(tag: &str, code_path: &str, sigs: &str) -> String {
    format!(
        "  <{tag} name=\"io.github.h4lovoid.dialcrypt\" codePath=\"{code_path}\" nativeLibraryPath=\"{code_path}/lib\" primaryCpuAbi=\"arm64-v8a\" publicFlags=\"541605445\" privateFlags=\"-1946157048\" ft=\"19a4c3f2b10\" ut=\"19a4c3f2b10\" version=\"1\" versionName=\"1.0\" userId=\"10245\" isOrphaned=\"true\" packageSource=\"0\" targetSdkVersion=\"35\">\n{sigs}    <perms>\n      <item name=\"android.permission.INTERNET\" granted=\"true\" flags=\"0\" />\n    </perms>\n    <proper-signing-keyset identifier=\"7\" />\n  </{tag}>\n"
    )
}

/// Another package whose signer is defined at `index` (`<cert index key>`).
fn other_package(name: &str, uid: u32, index: u32, der: &[u8]) -> String {
    format!(
        "  <package name=\"{name}\" codePath=\"/data/app/~~Zq3==/{name}-Pw1==\" primaryCpuAbi=\"arm64-v8a\" publicFlags=\"810073668\" privateFlags=\"0\" ft=\"19a4c3f2b10\" ut=\"19a4c3f2b10\" version=\"3\" userId=\"{uid}\" installer=\"com.android.vending\" packageSource=\"2\">\n{}    <perms />\n  </package>\n",
        sigs_xml(1, &[(index, Some(der))])
    )
}

/// `abx2xml /data/system/packages.xml -` on the Pixel 7, in the layout of the
/// field capture (declaration, one element per line, two-space indent):
/// `before`, then the App's element `app`, then `after`, between a platform
/// package that defines certificate index 3 and the system shared user that
/// refers to it by index.
fn packages_xml_with(before: &str, app: &str, after: &str) -> String {
    format!(
        "<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>\n<packages>\n  <version sdkVersion=\"36\" databaseVersion=\"3\" buildFingerprint=\"google/panther/panther:16/BP2A.250805.005/13691446:user/release-keys\" fingerprint=\"1a7f96d7c6a761ac7736437150de1c4e526db5a1\" />\n  <permission-trees />\n  <permissions>\n    <item name=\"io.github.h4lovoid.dialcrypt.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION\" package=\"io.github.h4lovoid.dialcrypt\" protection=\"2\" />\n  </permissions>\n  <package name=\"com.android.shell\" codePath=\"/system/priv-app/Shell\" publicFlags=\"810073669\" privateFlags=\"-1945631864\" ft=\"19a4c3f2b10\" ut=\"19a4c3f2b10\" version=\"36\" userId=\"2000\" isOrphaned=\"true\" packageSource=\"0\">\n{}    <perms />\n  </package>\n{before}{app}{}{after}  <shared-user name=\"android.uid.system\" userId=\"1000\">\n{}    <perms />\n  </shared-user>\n  <keyset-settings version=\"1\">\n    <keys>\n      <public-key identifier=\"7\" value=\"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\" />\n    </keys>\n  </keyset-settings>\n</packages>\n",
        sigs_xml(1, &[(3, Some(PLATFORM_CERT))]),
        other_package("com.chat.app", 10300, 200, CHAT_CERT),
        sigs_xml(1, &[(3, None)]),
    )
}

/// The App installed in the system image, signed by `certs` (indices 126..).
fn packages_xml(certs: &[&[u8]]) -> String {
    let refs: Vec<(u32, Option<&[u8]>)> = certs.iter().enumerate().map(|(i, c)| (126 + i as u32, Some(*c))).collect();
    packages_xml_with("", &app_element("package", SYSTEM_CODE_PATH, &sigs_xml(certs.len(), &refs)), "")
}

/// The App's element signed by `der`, defined at index 126.
fn app_signed_by(der: &[u8]) -> String {
    app_element("package", SYSTEM_CODE_PATH, &sigs_xml(1, &[(126, Some(der))]))
}

/// The daemon process died: its restore lock is stale (owner pid gone).
fn crash(s: Session<FakeSys>) -> FakeSys {
    let mut f = s.into_sys();
    f.lock_held = false;
    f
}

fn frames_to(out: &[Output], conn: u64) -> Vec<ServerMsg> {
    out.iter()
        .filter_map(|o| match o {
            Output::Send { conn: c, frame } if *c == conn => ipc::decode_server(&frame[2..]).ok(),
            _ => None,
        })
        .collect()
}

fn closed(out: &[Output], conn: u64) -> bool {
    out.iter().any(|o| *o == Output::Close { conn })
}

fn msg(s: &mut Session<FakeSys>, conn: u64, m: ClientMsg) -> Vec<Output> {
    s.handle(Input::Data { conn, bytes: ipc::encode_client(&m) })
}

fn tick(s: &mut Session<FakeSys>, ms: u64) -> Vec<Output> {
    s.sys_mut().now += ms;
    s.handle(Input::Tick)
}

fn prepare(s: &mut Session<FakeSys>) -> (Vec<ServerMsg>, [u8; 16]) {
    let out = s.handle(Input::Connected { conn: 1, uid: APP_UID, pid: LAUNCHER });
    assert!(frames_to(&out, 1).is_empty(), "auth failed: {:?}", frames_to(&out, 1));
    let out = msg(s, 1, ClientMsg::Prepare);
    let msgs = frames_to(&out, 1);
    let lease = msgs.iter().find_map(|m| match m {
        ServerMsg::Ready { lease, .. } => Some(*lease),
        _ => None,
    });
    (msgs, lease.unwrap_or([0; 16]))
}

/// Launcher exits, secure process starts after READY and attaches.
fn attach(s: &mut Session<FakeSys>, lease: [u8; 16]) -> Vec<ServerMsg> {
    s.sys_mut().remove_proc(LAUNCHER);
    s.sys_mut().add_proc(SECURE, APP_UID, "io.github.h4lovoid.dialcrypt:secure", 3_000, 0, "/system/lib64/libc.so");
    s.handle(Input::Connected { conn: 2, uid: APP_UID, pid: SECURE });
    frames_to(&msg(s, 2, ClientMsg::Attach { lease }), 2)
}

fn attached_session(policy_text: &str) -> (Session<FakeSys>, [u8; 16]) {
    let mut s = Session::new(pixel(policy_text));
    let (msgs, lease) = prepare(&mut s);
    assert!(msgs.iter().any(|m| matches!(m, ServerMsg::Ready { .. })), "{msgs:?}");
    let a = attach(&mut s, lease);
    assert!(matches!(a.as_slice(), [ServerMsg::Attached { .. }]), "{a:?}");
    (s, lease)
}

/// END from the App, the App exits, the daemon restores.
fn end_session(s: &mut Session<FakeSys>) -> Vec<ServerMsg> {
    let mut msgs = frames_to(&msg(s, 2, ClientMsg::End), 2);
    s.sys_mut().remove_proc(SECURE);
    msgs.extend(frames_to(&tick(s, 100), 2));
    msgs
}

fn fw_empty(f: &FakeSys) -> bool {
    f.fw.iter().all(|x| x.jumps.is_empty() && x.chains.is_empty())
}

fn assert_restored(f: &FakeSys) {
    assert_eq!(f.get("settings get global wifi_on"), "1");
    assert_eq!(f.get("settings get global bluetooth_on"), "1");
    assert_eq!(f.get("settings get global mobile_data"), "1");
    assert_eq!(f.get("settings get global wifi_scan_always_enabled"), "1");
    assert_eq!(f.get("dumpsys nfc"), "mState=on");
    assert_eq!(f.get("cmd phone get-allowed-network-types-for-users -s 0"), REAL_ALLOWED);
    assert_eq!(f.get("svc usb getFunctions"), "mtp");
    assert!(fw_empty(f), "firewall chains left behind");
    assert!(f.journal.is_none(), "journal not removed");
}

fn has_key(f: &FakeSys, prefix: &str) -> bool {
    f.keys().iter().any(|k| k.starts_with(prefix))
}

const TIER2_PREFIXES: [&str; 9] = [
    "pm suspend",
    "pm unsuspend",
    "ime set",
    "settings delete secure enabled_accessibility_services",
    "settings put secure accessibility_enabled",
    "write /proc/sys/vm/drop_caches",
    "swapoff",
    "fillmem",
    "logcat",
];

#[test]
fn dry_run_issues_no_state_changes() {
    let mut s = Session::new(pixel(&policy(false, true)));
    let (msgs, lease) = prepare(&mut s);
    assert!(msgs.contains(&ServerMsg::Ready { lease, mode: ipc::MODE_DRY_RUN, tier: 1, claims: 0 }), "{msgs:?}");
    let a = attach(&mut s, lease);
    assert_eq!(a, vec![ServerMsg::Attached { mode: ipc::MODE_DRY_RUN, tier: 1, claims: 0 }]);
    msg(&mut s, 2, ClientMsg::Heartbeat { lease });
    tick(&mut s, 1_500);
    let ended = end_session(&mut s);
    assert!(ended.contains(&ServerMsg::Ended { status: 0 }), "{ended:?}");
    let f = s.sys();
    assert_eq!(f.state_changes(), 0, "dry run reached the backend: {:?}", f.keys());
    assert!(f.journal.is_none());
    let planned: Vec<String> = s.planned().iter().map(Mutation::key).collect();
    assert!(planned.iter().any(|k| k.starts_with("iptables-restore -w -n")), "{planned:?}");
    assert!(planned.iter().any(|k| k == "cmd wifi set-wifi-enabled enabled"), "restore steps are planned too");
    assert!(!planned.iter().any(|k| TIER2_PREFIXES.iter().any(|p| k.starts_with(p))), "dedicated_mode needs armed=1");
}

#[test]
fn armed_without_dedicated_runs_tier1_only() {
    let (mut s, lease) = attached_session(&policy(true, false));
    {
        let f = s.sys();
        assert_eq!(f.get("settings get global wifi_on"), "0");
        assert_eq!(f.get("cmd phone get-allowed-network-types-for-users -s 0"), LTE_NR_NAMES);
        assert_eq!(f.get("svc usb getFunctions"), "\n");
        assert!(f.fw.iter().all(|x| x.jumps.len() == 3 && x.chains.len() == 3));
        assert!(f.journal.is_some());
    }
    msg(&mut s, 2, ClientMsg::Heartbeat { lease });
    end_session(&mut s);
    let f = s.sys();
    for p in TIER2_PREFIXES {
        assert!(!has_key(f, p), "tier 2 operation {p} with dedicated_mode=0");
    }
    assert!(!f.keys().iter().any(|k| k.starts_with("kill ") && !k.starts_with(&format!("kill {SECURE} "))));
    assert_restored(f);
}

#[test]
fn tier1_ready_reports_offline_claim_only() {
    let mut s = Session::new(pixel(&policy(true, false)));
    let (msgs, lease) = prepare(&mut s);
    assert!(msgs.contains(&ServerMsg::Ready { lease, mode: ipc::MODE_ARMED, tier: 1, claims: ipc::CLAIM_OFFLINE }), "{msgs:?}");
    let steps: Vec<u8> = msgs.iter().filter_map(|m| if let ServerMsg::Progress { step } = m { Some(*step) } else { None }).collect();
    assert_eq!(steps, vec![ipc::STEP_PRECHECK, ipc::STEP_FIREWALL, ipc::STEP_RADIOS]);
}

#[test]
fn tier2_suspends_switches_input_and_scrubs_then_restores() {
    let mut s = Session::new(pixel(&policy(true, true)));
    let (msgs, lease) = prepare(&mut s);
    assert!(msgs.contains(&ServerMsg::Ready { lease, mode: 1, tier: 2, claims: 7 }), "{msgs:?}");
    {
        let f = s.sys();
        for p in ["com.chat.app", "com.google.android.gms", "com.thirdparty.kbd"] {
            assert!(f.suspended.contains(p), "{p} not suspended");
        }
        for p in ["com.already.suspended", "com.android.systemui", "com.google.android.dialer", "com.google.android.inputmethod.latin", "com.topjohnwu.magisk", "io.github.h4lovoid.dialcrypt"] {
            assert!(!has_key(f, &format!("pm suspend --user 0 {p}")), "{p} must not be suspended");
        }
        assert_eq!(f.get("settings get secure default_input_method"), "com.google.android.inputmethod.latin/com.android.inputmethod.latin.LatinIME");
        assert_eq!(f.get("settings get secure enabled_accessibility_services"), "null");
        assert!(has_key(f, &format!("kill {CHAT_PID} ")) && !has_key(f, &format!("kill {IME_PID} ")) && !has_key(f, &format!("kill {LAUNCHER} ")));
        assert!(has_key(f, "write /proc/sys/vm/drop_caches 3") && has_key(f, "swapoff /dev/block/zram0") && has_key(f, "fillmem"));
    }
    let a = attach(&mut s, lease);
    assert_eq!(a, vec![ServerMsg::Attached { mode: 1, tier: 2, claims: 7 }]);
    msg(&mut s, 2, ClientMsg::Heartbeat { lease });
    let ended = end_session(&mut s);
    assert!(ended.contains(&ServerMsg::Ended { status: 0 }), "{ended:?}");
    let f = s.sys();
    assert!(f.suspended.is_empty() || f.suspended.iter().all(|p| p == "com.already.suspended"));
    assert_eq!(f.get("settings get secure default_input_method"), "com.thirdparty.kbd/.Ime");
    assert_eq!(f.get("settings get secure enabled_accessibility_services"), "com.thirdparty.a11y/.Svc");
    assert_eq!(f.get("settings get secure accessibility_enabled"), "1");
    assert!(has_key(f, "logcat -b all -c") && has_key(f, "dmesg -C"));
    assert_restored(f);
}

#[test]
fn restore_runs_in_spec_order_and_tears_firewall_down_last() {
    let (mut s, lease) = attached_session(&policy(true, true));
    msg(&mut s, 2, ClientMsg::Heartbeat { lease });
    let start = s.sys().log.len();
    end_session(&mut s);
    let keys: Vec<String> = s.sys().keys()[start..].to_vec();
    let pos = |p: &str| keys.iter().position(|k| k.starts_with(p)).unwrap_or(usize::MAX);
    let order = [
        "write /proc/sys/vm/drop_caches",
        "pm unsuspend",
        "settings put secure accessibility_enabled 1",
        "ime set com.thirdparty.kbd/.Ime",
        "svc usb setFunctions mtp",
        "cmd phone set-allowed-network-types-for-users -s 0 1001111101111111111",
        "settings put global wifi_scan_always_enabled 1",
        "cmd wifi set-wifi-enabled enabled",
        "iptables -w -D INPUT -j aegis_in",
        "ip6tables -w -X aegis_fwd",
    ];
    let positions: Vec<usize> = order.iter().map(|p| pos(p)).collect();
    assert!(positions.iter().all(|p| *p != usize::MAX), "missing step: {order:?} {positions:?}\n{keys:#?}");
    assert!(positions.windows(2).all(|w| w[0] < w[1]), "wrong order {positions:?}");
    assert_eq!(keys.iter().filter(|k| k.starts_with("ip")).last().map(String::as_str), Some("ip6tables -w -X aegis_fwd"));
}

#[test]
fn step_failure_does_not_stop_restore_and_firewall_is_torn_down() {
    let (mut s, lease) = attached_session(&policy(true, false));
    msg(&mut s, 2, ClientMsg::Heartbeat { lease });
    s.sys_mut().fail.push(("svc usb setFunctions mtp".into(), u32::MAX));
    let ended = end_session(&mut s);
    assert!(ended.contains(&ServerMsg::Ended { status: 1 }), "{ended:?}");
    let f = s.sys();
    assert!(fw_empty(f));
    assert_eq!(f.get("settings get global wifi_on"), "1", "later steps still ran");
    assert_eq!(f.notifications, vec![Code::RestoreIncomplete.token()]);
    let kept = journal::parse(f.journal.as_deref().unwrap_or_default());
    assert!(kept.header.is_some());
    assert_eq!(kept.intents.len(), 1);
    assert_eq!((kept.intents[0].kind, kept.intents[0].prior.as_str()), (Kind::Usb, "mtp"));
    assert!(s.restore_pending());
    // The next PREPARE retries the restore first and refuses while it still fails.
    s.handle(Input::Connected { conn: 9, uid: APP_UID, pid: LAUNCHER });
    let out = msg(&mut s, 9, ClientMsg::Prepare);
    assert!(frames_to(&out, 9).contains(&ServerMsg::Fail { item: Item::Restore.as_u16(), code: Code::RestorePending.as_u16() }));
}

#[test]
fn every_single_restore_failure_still_tears_down_firewall() {
    let (mut s, lease) = attached_session(&policy(true, true));
    msg(&mut s, 2, ClientMsg::Heartbeat { lease });
    end_session(&mut s);
    let steps: Vec<String> = s.last_restore().map(|r| r.steps.clone()).unwrap_or_default();
    let exec_steps: Vec<String> = steps.iter().filter_map(|st| st.strip_prefix("exec\t")).map(|r| r.replace('\t', " ")).collect();
    assert!(exec_steps.len() >= 10, "{steps:?}");
    for key in exec_steps {
        let (mut s, lease) = attached_session(&policy(true, true));
        msg(&mut s, 2, ClientMsg::Heartbeat { lease });
        s.sys_mut().fail.push((key.clone(), u32::MAX));
        end_session(&mut s);
        let rep = s.last_restore().cloned().unwrap_or_default();
        assert!(fw_empty(s.sys()), "firewall left after failing {key}");
        assert!(!rep.complete);
        assert_eq!(rep.failed.len(), 1, "{key}: {:?}", rep.failed);
        assert_eq!(rep.failed[0].replace('\t', " "), format!("exec {key}"));
    }
    // A transient failure of the teardown itself is retried.
    let (mut s, lease) = attached_session(&policy(true, false));
    msg(&mut s, 2, ClientMsg::Heartbeat { lease });
    s.sys_mut().fail.push(("iptables -w -D OUTPUT -j aegis_out".into(), 1));
    end_session(&mut s);
    assert!(fw_empty(s.sys()));
    assert!(s.last_restore().is_some_and(|r| r.complete));
}

#[test]
fn lockdown_failure_rolls_back_and_reports_code() {
    let mut f = pixel(&policy(true, false));
    f.fail.push((format!("cmd phone set-allowed-network-types-for-users -s 0 {LTE_NR}"), u32::MAX));
    let mut s = Session::new(f);
    let (msgs, _) = prepare(&mut s);
    assert!(msgs.contains(&ServerMsg::Fail { item: Item::Apply.as_u16(), code: Code::ApplyFailed.as_u16() }), "{msgs:?}");
    assert_eq!(*s.phase(), Phase::Idle);
    let f = s.sys();
    assert_eq!(f.get("settings get global wifi_on"), "1");
    assert!(fw_empty(f) && f.journal.is_none());
}

#[test]
fn journal_write_failure_aborts_before_any_change() {
    let mut f = pixel(&policy(true, false));
    f.fail_journal = true;
    let mut s = Session::new(f);
    let (msgs, _) = prepare(&mut s);
    assert!(msgs.contains(&ServerMsg::Fail { item: Item::Apply.as_u16(), code: Code::JournalWriteFailed.as_u16() }), "{msgs:?}");
    let f = s.sys();
    assert!(!f.log.iter().any(|m| matches!(m, Mutation::ExecStdin { .. })), "{:?}", f.keys());
    assert!(!has_key(f, "cmd wifi"));
}

#[test]
fn precheck_volte_off_reports_code_and_changes_nothing() {
    let mut f = pixel(&policy(true, false));
    f.set(SIMINFO_CMD, &real_siminfo().replace("Row: 9 _id=10, volte_vt_enabled=-1, sim_id=0", "Row: 9 _id=10, volte_vt_enabled=0, sim_id=0"));
    let mut s = Session::new(f);
    let out = s.handle(Input::Connected { conn: 1, uid: APP_UID, pid: LAUNCHER });
    assert!(out.is_empty());
    let out = msg(&mut s, 1, ClientMsg::Prepare);
    assert_eq!(
        frames_to(&out, 1),
        vec![ServerMsg::Progress { step: ipc::STEP_PRECHECK }, ServerMsg::Fail { item: Item::Ims.as_u16(), code: Code::VolteOff.as_u16() }]
    );
    assert!(closed(&out, 1));
    assert_eq!(s.sys().state_changes(), 0);
}

#[test]
fn precheck_reports_every_failing_item_with_codes() {
    let mut f = pixel(&policy(true, false));
    f.setting("global", "adb_enabled", "1");
    f.file("/sys/fs/selinux/enforce", "0");
    f.set("dumpsys telephony.registry", &real_registry().replace("transport: WWAN, id: 3", "transport: IWLAN, id: 3"));
    let mut s = Session::new(f);
    let (msgs, _) = prepare(&mut s);
    for (item, code) in [(Item::Adb, Code::AdbEnabled), (Item::Selinux, Code::SelinuxNotEnforcing), (Item::Ims, Code::ImsNotOnLteNr)] {
        assert!(msgs.contains(&ServerMsg::Fail { item: item.as_u16(), code: code.as_u16() }), "{msgs:?}");
    }
    assert_eq!(s.sys().state_changes(), 0);
}

#[test]
fn test_usb_debug_switch_keeps_adb_and_usb_functions() {
    // Spoofed boot properties do not hide the state the bootloader reported.
    let mut f = pixel(&policy(true, false));
    f.file("/proc/bootconfig", "androidboot.vbmeta.device_state = \"locked\"\nandroidboot.verifiedbootstate = \"green\"\n");
    let mut s = Session::new(f);
    let (msgs, _) = prepare(&mut s);
    assert!(msgs.contains(&ServerMsg::Fail { item: Item::Boot.as_u16(), code: Code::BootStateInvalid.as_u16() }), "{msgs:?}");

    // The reverse: properties rewritten to locked/green, bootloader says unlocked/orange.
    // KernelSU phones have no magisk binary and still pass.
    let mut f = pixel(&policy(true, false));
    for (k, v) in [("ro.boot.vbmeta.device_state", "locked"), ("ro.boot.verifiedbootstate", "green"), ("ro.boot.flash.locked", "1")] {
        f.set(&format!("getprop {k}"), v);
    }
    f.file("/proc/bootconfig", "androidboot.vbmeta.device_state = \"unlocked\"\nandroidboot.verifiedbootstate = \"orange\"\n");
    f.file("/data/adb/ksud", "x");
    f.fail.push(("magisk --denylist status".into(), u32::MAX));
    f.fail.push(("magisk --denylist ls".into(), u32::MAX));
    let mut s = Session::new(f);
    let (msgs, _) = prepare(&mut s);
    assert!(msgs.iter().any(|m| matches!(m, ServerMsg::Ready { .. })), "{msgs:?}");

    let text = format!("{}test_allow_usb_debug=1\n", policy(true, false));
    let mut f = pixel(&text);
    f.setting("global", "adb_enabled", "1");
    f.setting("global", "development_settings_enabled", "1");
    let mut s = Session::new(f);
    let (msgs, _) = prepare(&mut s);
    assert!(msgs.iter().any(|m| matches!(m, ServerMsg::Ready { .. })), "{msgs:?}");
    assert_eq!(s.sys().get("svc usb getFunctions"), "mtp");

    // Wireless ADB stays refused, and the default policy still refuses USB debugging.
    let mut f = pixel(&text);
    f.setting("global", "adb_wifi_enabled", "1");
    let mut s = Session::new(f);
    let (msgs, _) = prepare(&mut s);
    assert!(msgs.contains(&ServerMsg::Fail { item: Item::Adb.as_u16(), code: Code::AdbWifiEnabled.as_u16() }), "{msgs:?}");
    assert_eq!(s.sys().state_changes(), 0);
}

#[test]
fn app_connection_loss_triggers_restore() {
    let (mut s, _) = attached_session(&policy(true, false));
    s.handle(Input::Closed { conn: 2 });
    tick(&mut s, 100);
    assert_eq!(*s.phase(), Phase::Idle);
    assert!(!s.sys().files.contains_key(&format!("/proc/{SECURE}/stat")), "secure process must be killed");
    assert_restored(s.sys());
}

#[test]
fn heartbeats_keep_session_and_missing_heartbeat_ends_it() {
    let (mut s, lease) = attached_session(&policy(true, false));
    for _ in 0..20 {
        msg(&mut s, 2, ClientMsg::Heartbeat { lease });
        let out = tick(&mut s, 500);
        assert!(frames_to(&out, 2).is_empty(), "healthy session reported {:?}", frames_to(&out, 2));
    }
    assert!(matches!(s.phase(), Phase::Attached { .. }));
    let out = tick(&mut s, 2_100);
    assert!(frames_to(&out, 2).contains(&ServerMsg::Violation { code: Code::VioLeaseExpired.as_u16() }));
    tick(&mut s, 100);
    assert_eq!(*s.phase(), Phase::Idle);
    assert!(has_key(s.sys(), &format!("kill {SECURE} 3000")));
    assert_restored(s.sys());
}

#[test]
fn daemon_restart_with_active_journal_same_boot_restores() {
    let (s, _) = attached_session(&policy(true, true));
    let f = crash(s);
    assert!(f.journal.is_some());
    let mut s2 = Session::new(f);
    let rep = s2.recover_leftover().unwrap_or_default();
    assert!(rep.complete && rep.real, "{rep:?}");
    assert_eq!(rep.steps.first().map(String::as_str), Some("kill\t700\t3000"));
    let f = s2.sys();
    assert!(!f.files.contains_key(&format!("/proc/{SECURE}/stat")));
    assert!(has_key(f, "write /proc/sys/vm/drop_caches"), "same boot after a crash scrubs memory");
    assert_eq!(f.get("settings get secure default_input_method"), "com.thirdparty.kbd/.Ime");
    assert_restored(f);
}

#[test]
fn daemon_restart_restores_even_when_policy_switched_to_dry_run() {
    let (s, _) = attached_session(&policy(true, false));
    let mut f = crash(s);
    f.file(POLICY_PATH, &policy(false, false));
    let mut s2 = Session::new(f);
    assert!(!s2.armed());
    assert!(s2.recover_leftover().is_some_and(|r| r.complete));
    assert_restored(s2.sys());
}

#[test]
fn reboot_recovery_restores_with_different_boot_id() {
    let (s, _) = attached_session(&policy(true, true));
    let mut f = crash(s);
    // Reboot: new boot id, kernel firewall state gone, old processes gone.
    f.file(BOOT_ID_PATH, "9a9a9a9a-2222-4000-8000-000000000002\n");
    f.fw = Default::default();
    f.remove_proc(SECURE);
    let mut s2 = Session::new(f);
    let rep = s2.recover_leftover().unwrap_or_default();
    assert!(rep.complete, "{rep:?}");
    assert!(!rep.steps.iter().any(|x| x.starts_with("kill")));
    let f = s2.sys();
    assert!(f.suspended.iter().all(|p| p == "com.already.suspended"));
    assert_restored(f);
}

#[test]
fn crash_journal_cut_at_every_byte_is_restored() {
    let (s, _) = attached_session(&policy(true, false));
    let locked = crash(s);
    let full = locked.journal.clone().unwrap_or_default();
    assert!(full.len() > 200);
    for cut in 0..=full.len() {
        let mut f = locked.clone();
        f.journal = Some(full[..cut].to_vec());
        let parsed = journal::parse(&full[..cut]);
        let wifi_logged = parsed.intents.iter().any(|e| e.kind == Kind::Radio && e.target == "wifi");
        let mut s2 = Session::new(f);
        let rep = s2.recover_leftover().unwrap_or_default();
        let f = s2.sys();
        assert!(rep.complete, "cut {cut}: {rep:?}");
        assert!(fw_empty(f), "cut {cut}: firewall left");
        assert!(f.journal.is_none(), "cut {cut}: journal left");
        assert_eq!(f.get("settings get global wifi_on") == "1", wifi_logged, "cut {cut}");
    }
}

#[test]
fn violation_notifies_app_reapplies_and_restores() {
    let (mut s, lease) = attached_session(&policy(true, false));
    msg(&mut s, 2, ClientMsg::Heartbeat { lease });
    s.sys_mut().setting("global", "wifi_on", "1"); // someone switched Wi-Fi back on
    let out = tick(&mut s, 1_000);
    assert!(frames_to(&out, 2).contains(&ServerMsg::Violation { code: Code::VioRadio.as_u16() }), "{:?}", frames_to(&out, 2));
    assert!(s.is_fail_closed_tripped());
    assert_eq!(s.sys().keys().last().map(String::as_str), Some("cmd wifi set-wifi-enabled disabled"));
    assert!(matches!(s.phase(), Phase::Ending { .. }));
    s.sys_mut().remove_proc(SECURE); // App wipes and exits
    let out = tick(&mut s, 100);
    assert!(frames_to(&out, 2).contains(&ServerMsg::Ended { status: 0 }));
    assert_restored(s.sys());
}

#[test]
fn monitor_reports_nothing_while_restoring() {
    let (mut s, _) = attached_session(&policy(true, false));
    let mut mon = s.monitor.take().unwrap_or_else(|| panic!("monitor missing"));
    s.sys_mut().setting("global", "wifi_on", "1");
    s.sys_mut().fw = Default::default();
    s.sys_mut().set("dumpsys telephony.registry", "");
    assert!(!mon.check_fast(s.sys_mut()).is_empty(), "sanity: violations visible while watching");
    mon.state = MonState::Restoring;
    assert!(mon.check_fast(s.sys_mut()).is_empty());
    assert!(mon.check_slow(s.sys_mut()).is_empty());
    assert!(mon.check_procs(s.sys_mut(), &[]).is_empty());
}

#[test]
fn pcscf_change_regenerates_rules_atomically() {
    let (mut s, lease) = attached_session(&policy(true, false));
    let new_reg = real_registry().replace("/2001:db8::1,/2001:db8::1,/192.0.2.1,/192.0.2.1", "/2001:db8::20");
    s.sys_mut().set("dumpsys telephony.registry", &new_reg);
    let before = s.sys().log.len();
    msg(&mut s, 2, ClientMsg::Heartbeat { lease });
    let out = tick(&mut s, 2_000);
    assert!(frames_to(&out, 2).is_empty(), "{:?}", frames_to(&out, 2));
    let regen: Vec<&Mutation> = s.sys().log[before..].iter().filter(|m| matches!(m, Mutation::ExecStdin { .. })).collect();
    assert_eq!(regen.len(), 2);
    for m in regen {
        if let Mutation::ExecStdin { stdin, .. } = m {
            assert!(!stdin.contains("-I "), "regeneration must not insert jumps again");
            assert!(!stdin.contains("192.0.2.1") && !stdin.contains("2001:db8::1/128"));
        }
    }
    assert!(s.sys().fw[1].chains.get("aegis_out").is_some_and(|r| r.iter().any(|l| l.contains("-d 2001:db8::20/128"))));
    msg(&mut s, 2, ClientMsg::Heartbeat { lease });
    let out = tick(&mut s, 1_000);
    assert!(frames_to(&out, 2).is_empty(), "new baseline must not look like tampering");
}

fn udp4(dst: [u8; 4], proto: u8) -> Vec<u8> {
    let mut p = vec![0x45, 0, 0, 28, 0, 0, 0, 0, 64, proto, 0, 0, 10, 0, 0, 2];
    p.extend_from_slice(&dst);
    p.extend_from_slice(&[0u8; 8]);
    p
}

#[test]
fn media_learning_only_in_call_udp_and_capped_at_four() {
    let (mut s, lease) = attached_session(&policy(true, false));
    s.sys_mut().packets = vec![udp4([10, 1, 1, 1], 17)];
    msg(&mut s, 2, ClientMsg::Heartbeat { lease });
    tick(&mut s, 2_000);
    assert!(s.learner.learned().is_empty(), "no learning outside a call");
    s.sys_mut().set("dumpsys telephony.registry", &real_registry().replace("mCallState=0", "mCallState=2"));
    msg(&mut s, 2, ClientMsg::Heartbeat { lease });
    tick(&mut s, 2_000);
    let mut pk: Vec<Vec<u8>> = (1..=6).map(|i| udp4([10, 1, 1, i], 17)).collect();
    pk.push(udp4([10, 2, 2, 2], 6));
    s.sys_mut().packets = pk;
    msg(&mut s, 2, ClientMsg::Heartbeat { lease });
    let out = tick(&mut s, 100);
    assert!(frames_to(&out, 2).is_empty(), "{:?}", frames_to(&out, 2));
    assert_eq!(s.learner.learned().len(), 4);
    let rules = s.sys().fw[0].chains.get("aegis_out").cloned().unwrap_or_default();
    assert_eq!(rules.iter().filter(|r| r.contains("-p udp -d 10.1.1.")).count(), 4);
    assert!(!rules.iter().any(|r| r.contains("10.2.2.2")), "TCP must not be learned");
    assert!(rules.iter().filter(|r| r.contains(" -d ") && r.ends_with("ACCEPT")).all(|r| r.contains("--uid-owner 10228")));
    s.sys_mut().set("dumpsys telephony.registry", &real_registry());
    msg(&mut s, 2, ClientMsg::Heartbeat { lease });
    tick(&mut s, 2_000);
    msg(&mut s, 2, ClientMsg::Heartbeat { lease });
    tick(&mut s, 100);
    assert!(s.learner.learned().is_empty(), "call ended: learned addresses cleared");
    let rules = s.sys().fw[0].chains.get("aegis_out").cloned().unwrap_or_default();
    assert!(!rules.iter().any(|r| r.contains("10.1.1.")));
}

#[test]
fn attach_checks_reject_and_end_the_session() {
    let cases: [(&str, Code); 5] = [
        ("early", Code::AttachTooEarly),
        ("cmdline", Code::AttachWrongProcess),
        ("traced", Code::AttachTraced),
        ("frida", Code::AttachInjected),
        ("launcher", Code::LauncherStillAlive),
    ];
    for (case, code) in cases {
        let mut s = Session::new(pixel(&policy(true, false)));
        let (_, lease) = prepare(&mut s);
        let (start, cmd, tracer, maps) = match case {
            "early" => (1_500, "io.github.h4lovoid.dialcrypt:secure", 0, ""),
            "cmdline" => (3_000, "io.github.h4lovoid.dialcrypt", 0, ""),
            "traced" => (3_000, "io.github.h4lovoid.dialcrypt:secure", 4412, ""),
            "frida" => (3_000, "io.github.h4lovoid.dialcrypt:secure", 0, "7f00 r-xp /data/local/tmp/frida-agent-64.so"),
            _ => (3_000, "io.github.h4lovoid.dialcrypt:secure", 0, ""),
        };
        if case != "launcher" {
            s.sys_mut().remove_proc(LAUNCHER);
        }
        s.sys_mut().add_proc(SECURE, APP_UID, cmd, start, tracer, maps);
        s.handle(Input::Connected { conn: 2, uid: APP_UID, pid: SECURE });
        let out = msg(&mut s, 2, ClientMsg::Attach { lease });
        assert_eq!(frames_to(&out, 2), vec![ServerMsg::Fail { item: Item::Attach.as_u16(), code: code.as_u16() }], "{case}");
        assert_eq!(*s.phase(), Phase::Idle, "{case}");
        assert_restored(s.sys());
        assert!(s.sys().memlock.is_empty(), "{case}: a rejected process must not get the memlock limit");
    }
    // Wrong lease from the right App also ends the session.
    let mut s = Session::new(pixel(&policy(true, false)));
    let (_, lease) = prepare(&mut s);
    let mut bad = lease;
    bad[0] ^= 1;
    let a = attach(&mut s, bad);
    assert_eq!(a, vec![ServerMsg::Fail { item: Item::Attach.as_u16(), code: Code::LeaseMismatch.as_u16() }]);
    assert_restored(s.sys());
    assert!(s.sys().memlock.is_empty(), "wrong lease must not get the memlock limit");
}

#[test]
fn attach_raises_memlock_of_the_verified_secure_process_once_before_attached() {
    let mut s = Session::new(pixel(&policy(true, false)));
    let (_, lease) = prepare(&mut s);
    s.sys_mut().remove_proc(LAUNCHER);
    s.sys_mut().add_proc(SECURE, APP_UID, "io.github.h4lovoid.dialcrypt:secure", 3_000, 0, "/system/lib64/libc.so");
    s.handle(Input::Connected { conn: 2, uid: APP_UID, pid: SECURE });
    assert!(s.sys().memlock.is_empty(), "nothing is raised for the launcher or before ATTACH is verified");
    // ATTACHED leaves the daemon only when this call returns, and by then the limit is raised.
    let out = msg(&mut s, 2, ClientMsg::Attach { lease });
    assert!(matches!(frames_to(&out, 2).as_slice(), [ServerMsg::Attached { mode: ipc::MODE_ARMED, .. }]), "{out:?}");
    assert_eq!(s.sys().memlock, vec![(SECURE, 3_000)]);
    msg(&mut s, 2, ClientMsg::Heartbeat { lease });
    tick(&mut s, 400);
    assert_eq!(s.sys().memlock.len(), 1, "heartbeats and ticks do not repeat it");
}

#[test]
fn memlock_failure_refuses_attach_and_restores() {
    let mut f = pixel(&policy(true, false));
    f.fail_memlock = true;
    let mut s = Session::new(f);
    let (_, lease) = prepare(&mut s);
    s.sys_mut().remove_proc(LAUNCHER);
    s.sys_mut().add_proc(SECURE, APP_UID, "io.github.h4lovoid.dialcrypt:secure", 3_000, 0, "/system/lib64/libc.so");
    s.handle(Input::Connected { conn: 2, uid: APP_UID, pid: SECURE });
    let out = msg(&mut s, 2, ClientMsg::Attach { lease });
    assert_eq!(frames_to(&out, 2), vec![ServerMsg::Fail { item: Item::Attach.as_u16(), code: Code::ApplyFailed.as_u16() }]);
    assert!(closed(&out, 2));
    assert_eq!(s.sys().memlock, vec![(SECURE, 3_000)]);
    assert_eq!(*s.phase(), Phase::Idle);
    assert!(has_key(s.sys(), &format!("kill {SECURE} 3000")), "{:?}", s.sys().keys());
    assert_restored(s.sys());
}

#[test]
fn dry_run_raises_memlock_and_changes_nothing_else() {
    let mut s = Session::new(pixel(&policy(false, true)));
    let (_, lease) = prepare(&mut s);
    let a = attach(&mut s, lease);
    assert_eq!(a, vec![ServerMsg::Attached { mode: ipc::MODE_DRY_RUN, tier: 1, claims: 0 }]);
    assert_eq!(s.sys().memlock, vec![(SECURE, 3_000)]);
    assert_eq!(s.sys().state_changes(), 0, "dry run reached the backend: {:?}", s.sys().keys());

    // A failed raise refuses ATTACH in a dry run as well.
    let mut f = pixel(&policy(false, true));
    f.fail_memlock = true;
    let mut s = Session::new(f);
    let (_, lease) = prepare(&mut s);
    let a = attach(&mut s, lease);
    assert_eq!(a, vec![ServerMsg::Fail { item: Item::Attach.as_u16(), code: Code::ApplyFailed.as_u16() }]);
    assert_eq!(*s.phase(), Phase::Idle);
    assert_eq!(s.sys().state_changes(), 0, "dry run reached the backend: {:?}", s.sys().keys());
    assert!(s.planned().iter().any(|m| m.key() == format!("kill {SECURE} 3000")), "the kill is planned, not issued");
}

#[test]
fn memlock_is_never_raised_for_unverified_connections() {
    // A peer that fails authentication is closed and its ATTACH (even with the right lease) is ignored.
    let mut s = Session::new(pixel(&policy(true, false)));
    let (_, lease) = prepare(&mut s);
    s.sys_mut().add_proc(900, 10300, "com.evil.app", 3_000, 0, "");
    let out = s.handle(Input::Connected { conn: 3, uid: 10300, pid: 900 });
    assert!(closed(&out, 3));
    let out = msg(&mut s, 3, ClientMsg::Attach { lease });
    assert!(!frames_to(&out, 3).iter().any(|m| matches!(m, ServerMsg::Attached { .. })), "{out:?}");
    assert!(matches!(s.phase(), Phase::Prepared { .. }));
    assert!(s.sys().memlock.is_empty());

    // ATTACH from the App without a prepared session.
    let mut s = Session::new(pixel(&policy(true, false)));
    s.handle(Input::Connected { conn: 1, uid: APP_UID, pid: LAUNCHER });
    let out = msg(&mut s, 1, ClientMsg::Attach { lease: [7; 16] });
    assert_eq!(frames_to(&out, 1), vec![ServerMsg::Fail { item: Item::Protocol.as_u16(), code: Code::UnexpectedMessage.as_u16() }]);
    assert!(s.sys().memlock.is_empty());
}

#[test]
fn attach_window_expiry_restores() {
    let mut s = Session::new(pixel(&policy(true, false)));
    prepare(&mut s);
    let out = tick(&mut s, 10_001);
    assert!(frames_to(&out, 1).contains(&ServerMsg::Fail { item: Item::Attach.as_u16(), code: Code::AttachTimeout.as_u16() }));
    assert_restored(s.sys());
}

#[test]
fn peer_identity_is_verified_by_the_daemon() {
    let deny = |f: FakeSys, uid: u32, code: Code| {
        let mut s = Session::new(f);
        let out = s.handle(Input::Connected { conn: 1, uid, pid: LAUNCHER });
        assert_eq!(frames_to(&out, 1), vec![ServerMsg::Fail { item: Item::Auth.as_u16(), code: code.as_u16() }], "uid {uid}");
        assert!(closed(&out, 1));
    };
    deny(pixel(&policy(true, false)), 10300, Code::PeerPackageMismatch);
    deny(pixel(&policy(true, false)), 2000, Code::PeerUidRejected);
    deny(pixel("armed=1\n"), APP_UID, Code::PinnedCertMissing);
    let mut f = pixel(&policy(true, false));
    f.file("/data/system/packages.list", "io.github.h4lovoid.dialcrypt 10245 1 /data/user/0/x default 3003\n");
    deny(f, APP_UID, Code::PeerDebuggable);
    let mut f = pixel(&policy(true, false));
    f.file("/data/system/packages.list", "io.github.h4lovoid.dialcrypt 10245 0 /d default 3003\ncom.evil.shared 10245 0 /d default 3003\n");
    deny(f, APP_UID, Code::PeerSharedUid);
}

fn deny_auth(f: FakeSys, code: Code, why: &str) {
    let mut s = Session::new(f);
    let out = s.handle(Input::Connected { conn: 1, uid: APP_UID, pid: LAUNCHER });
    assert_eq!(frames_to(&out, 1), vec![ServerMsg::Fail { item: Item::Auth.as_u16(), code: code.as_u16() }], "{why}");
    assert!(closed(&out, 1), "{why}");
    assert_eq!(s.sys().state_changes(), 0, "{why}");
}

#[test]
fn apk_carrying_pinned_cert_is_rejected_when_system_record_differs() {
    // The installed APK file embeds the pinned certificate in its signing
    // block (unverified bytes), but the package manager verified and recorded
    // a different signer. Only the system record counts.
    let mut f = pixel(&policy(true, false));
    f.set("pm path io.github.h4lovoid.dialcrypt", &format!("package:{APK}\n"));
    f.files.insert(APK.into(), build_test_apk(&[CERT], true));
    f.set(PKG_XML_CMD, &packages_xml(&[ATTACKER_CERT]));
    deny_auth(f, Code::PeerSignatureMismatch, "smuggled certificate");
    // Two recorded signers, one of them pinned: still rejected.
    let mut f = pixel(&policy(true, false));
    f.set(PKG_XML_CMD, &packages_xml(&[CERT, SECOND_CERT]));
    deny_auth(f, Code::PeerSignatureMismatch, "multiple signers");
    // Sanity: the genuine record is accepted.
    accept_auth(pixel(&policy(true, false)), "genuine record");
}

fn accept_auth(f: FakeSys, why: &str) {
    let mut s = Session::new(f);
    assert!(s.handle(Input::Connected { conn: 1, uid: APP_UID, pid: LAUNCHER }).is_empty(), "{why}");
}

fn with_xml(xml: &str) -> FakeSys {
    let mut f = pixel(&policy(true, false));
    f.set(PKG_XML_CMD, xml);
    f
}

#[test]
fn updated_system_app_is_judged_by_its_package_record() {
    // pm install -r over the system App: the running version is the
    // <package> in /data/app, the replaced system copy is <updated-package>.
    let data_path = "/data/app/~~Kx9==/io.github.h4lovoid.dialcrypt-Hq2==";
    let current = app_element("package", data_path, &sigs_xml(1, &[(126, Some(CERT))]));
    let replaced = app_element("updated-package", SYSTEM_CODE_PATH, &sigs_xml(1, &[(126, None)]));
    accept_auth(with_xml(&packages_xml_with("", &current, &replaced)), "update signed by the pinned key");
    // The replaced system copy carries the pinned key, the running version does not.
    let current = app_element("package", data_path, &sigs_xml(1, &[(126, Some(ATTACKER_CERT))]));
    let replaced = app_element("updated-package", SYSTEM_CODE_PATH, &sigs_xml(1, &[(127, Some(CERT))]));
    deny_auth(with_xml(&packages_xml_with(&replaced, &current, "")), Code::PeerSignatureMismatch, "pinned key only on updated-package before");
    deny_auth(with_xml(&packages_xml_with("", &current, &replaced)), Code::PeerSignatureMismatch, "pinned key only on updated-package after");
    // Only the replaced copy is recorded: no running package record at all.
    let replaced = app_element("updated-package", SYSTEM_CODE_PATH, &sigs_xml(1, &[(127, Some(CERT))]));
    deny_auth(with_xml(&packages_xml_with("", "", &replaced)), Code::PeerSignatureSourceMissing, "updated-package without package");
}

#[test]
fn signing_record_decoys_and_rotation_are_refused() {
    // A certificate referred to by index resolves to the key defined earlier
    // under another package; the pinned key there is accepted ...
    let earlier = other_package("com.vendor.tool", 10310, 57, CERT);
    let app = app_element("package", SYSTEM_CODE_PATH, &sigs_xml(1, &[(57, None)]));
    accept_auth(with_xml(&packages_xml_with(&earlier, &app, "")), "index defined by another package");
    // ... and any other key is not (index 3 is the platform certificate).
    let app = app_element("package", SYSTEM_CODE_PATH, &sigs_xml(1, &[(3, None)]));
    deny_auth(with_xml(&packages_xml_with("", &app, "")), Code::PeerSignatureMismatch, "index of the platform certificate");
    // Key rotation history (pastSigs inside sigs) is refused even with the pinned current signer.
    let sigs = format!(
        "    <sigs count=\"1\" schemeVersion=\"3\">\n      <cert index=\"126\" key=\"{}\" />\n      <pastSigs count=\"2\" schemeVersion=\"3\">\n        <cert index=\"127\" key=\"{}\" flags=\"23\" />\n        <cert index=\"126\" flags=\"23\" />\n      </pastSigs>\n    </sigs>\n",
        hex_encode(CERT),
        hex_encode(OLD_CERT)
    );
    let app = app_element("package", SYSTEM_CODE_PATH, &sigs);
    deny_auth(with_xml(&packages_xml_with("", &app, "")), Code::PeerSignatureMismatch, "rotation lineage");
    // Markup for a fake App record inside attribute values (escaped, as abx2xml
    // writes it) is data, not an element.
    let fake = format!(
        "&lt;package name=&quot;io.github.h4lovoid.dialcrypt&quot;&gt;&lt;sigs count=&quot;1&quot;&gt;&lt;cert index=&quot;126&quot; key=&quot;{}&quot; /&gt;&lt;/sigs&gt;&lt;/package&gt;",
        hex_encode(CERT)
    );
    let decoy = format!("  <package name=\"com.evil.app\" codePath=\"/data/app/x\" userId=\"10301\" installer=\"{fake}\" />\n");
    deny_auth(with_xml(&packages_xml_with(&decoy, &app_signed_by(ATTACKER_CERT), "")), Code::PeerSignatureMismatch, "escaped record in an attribute");
    // The same record nested inside another element is not the top-level package.
    let nested = format!("  <shared-user name=\"com.evil.shared\" userId=\"10302\">\n  {}  </shared-user>\n", app_signed_by(CERT).replace("126", "128"));
    deny_auth(with_xml(&packages_xml_with(&nested, &app_signed_by(ATTACKER_CERT), "")), Code::PeerSignatureMismatch, "nested package of the same name");
}

#[test]
fn missing_or_malformed_signature_source_refuses_connection() {
    let good = packages_xml(&[CERT]);
    let app = app_signed_by(CERT);
    let mut f = pixel(&policy(true, false));
    f.reads.remove(PKG_XML_CMD);
    deny_auth(f, Code::PeerSignatureSourceMissing, "abx2xml unavailable");
    let mut f = pixel(&policy(true, false));
    f.fail_reads.insert(PKG_XML_CMD.to_string());
    deny_auth(f, Code::PeerSignatureSourceMissing, "abx2xml fails");
    let sigs_count = |count: &str| app.replacen("sigs count=\"1\"", &format!("sigs count=\"{count}\""), 1);
    let with_key = |key: String| app_element("package", SYSTEM_CODE_PATH, &format!("    <sigs count=\"1\" schemeVersion=\"2\">\n      <cert index=\"126\" key=\"{key}\" />\n    </sigs>\n"));
    let cert_hex = hex_encode(CERT);
    let pad = " ".repeat(crate::pkgxml::MAX_XML + 1 - good.len());
    let cases: Vec<(String, &str)> = vec![
        (String::new(), "empty output"),
        ("\n \n".into(), "blank output"),
        (good[..good.len() / 2].to_string(), "truncated output"),
        (good.replace("</packages>", &format!("{pad}</packages>")), "output over the size limit"),
        (packages_xml_with("", "", ""), "package missing"),
        (good.replace("name=\"io.github.h4lovoid.dialcrypt\" codePath", "name=\"io.github.h4lovoid.dialcrypt2\" codePath"), "only a similar name"),
        (packages_xml_with(&app, &app, ""), "two package elements"),
        (packages_xml_with(&app.replace("h4lovoid.dialcrypt\" codePath", "h4lovoid&#46;dialcrypt\" codePath"), &app, ""), "second package written with a character reference"),
        (packages_xml_with("", &app_element("package", SYSTEM_CODE_PATH, ""), ""), "sigs missing"),
        (packages_xml_with("", &app_element("package", SYSTEM_CODE_PATH, &format!("{0}{0}", sigs_xml(1, &[(126, Some(CERT))]))), ""), "two sigs"),
        (packages_xml_with("", &sigs_count("2"), ""), "count above the certificates"),
        (packages_xml_with("", &sigs_count("0"), ""), "count below the certificates"),
        (packages_xml_with("", &sigs_count("one"), ""), "count not a number"),
        (packages_xml_with("", &app.replacen(" count=\"1\"", "", 1), ""), "count missing"),
        (packages_xml_with("", &app_element("package", SYSTEM_CODE_PATH, &sigs_xml(0, &[])), ""), "no certificate"),
        (packages_xml_with("", &app_element("package", SYSTEM_CODE_PATH, &sigs_xml(1, &[(999, None)])), ""), "index never defined"),
        (
            packages_xml_with("", &app_element("package", SYSTEM_CODE_PATH, &sigs_xml(1, &[(300, None)])), &other_package("com.vendor.late", 10311, 300, CERT)),
            "index defined only after the reference",
        ),
        (packages_xml_with("", &app, &other_package("com.vendor.tool", 10310, 126, ATTACKER_CERT)), "index redefined later with another key"),
        (packages_xml_with(&other_package("com.vendor.tool", 10310, 126, ATTACKER_CERT), &app, ""), "index defined earlier with another key"),
        (packages_xml_with("", &with_key(format!("zz{}", &cert_hex[2..])), ""), "key not hex"),
        (packages_xml_with("", &with_key(format!("{cert_hex}0")), ""), "key of odd length"),
        (packages_xml_with("", &with_key(String::new()), ""), "key empty"),
        (packages_xml_with("", &with_key(hex_encode(&[0x30; crate::pkgxml::MIN_CERT - 1])), ""), "key too short"),
        (packages_xml_with("", &with_key(hex_encode(&vec![0x30; crate::pkgxml::MAX_CERT + 1])), ""), "key too long"),
        (
            packages_xml_with("", &app, "  <package name=\"com.evil.app\" userId=\"10301\" installer=\"<package name=\"io.github.h4lovoid.dialcrypt\">\" />\n"),
            "raw markup in an attribute value",
        ),
        (good.replace("</perms>\n    <proper", "</perm>\n    <proper"), "mismatched end tag"),
        (good.replace("<packages>", "<!DOCTYPE packages [<!ENTITY x \"y\">]>\n<packages>"), "doctype"),
    ];
    for (text, why) in cases {
        assert_ne!(text, good, "{why}: case did not change the file");
        deny_auth(with_xml(&text), Code::PeerSignatureSourceMissing, why);
    }
    // The certificate key is decoded case-insensitively; the digest is over the bytes.
    accept_auth(with_xml(&packages_xml_with("", &with_key(cert_hex.to_uppercase()), "")), "upper-case key");
}

#[test]
fn session_holds_restore_lock_for_the_whole_journal_lifetime() {
    let mut s = Session::new(pixel(&policy(true, false)));
    assert!(!s.sys().lock_held);
    let (msgs, lease) = prepare(&mut s);
    assert!(msgs.iter().any(|m| matches!(m, ServerMsg::Ready { .. })));
    assert!(s.sys().lock_held && s.sys().journal.is_some(), "journal exists only under the lock");
    attach(&mut s, lease);
    msg(&mut s, 2, ClientMsg::Heartbeat { lease });
    tick(&mut s, 500);
    assert!(s.sys().lock_held);
    end_session(&mut s);
    assert!(!s.sys().lock_held && s.sys().journal.is_none(), "lock released only after the journal is gone");
    // A failed lockdown releases it as well.
    let mut f = pixel(&policy(true, false));
    f.fail.push(("cmd wifi set-wifi-enabled disabled".into(), u32::MAX));
    let mut s = Session::new(f);
    prepare(&mut s);
    assert!(!s.sys().lock_held && s.sys().journal.is_none());
}

#[test]
fn new_session_is_refused_while_restore_script_holds_the_lock() {
    let mut f = pixel(&policy(true, false));
    f.lock_held = true; // aegis-restore.sh is working on a journal
    f.journal = Some(b"ACTIVE\tsomeone-elses\n".to_vec());
    let mut s = Session::new(f);
    let (msgs, _) = prepare(&mut s);
    assert!(msgs.contains(&ServerMsg::Fail { item: Item::Restore.as_u16(), code: Code::RestorePending.as_u16() }), "{msgs:?}");
    assert_eq!(*s.phase(), Phase::Idle);
    let f = s.sys();
    assert_eq!(f.state_changes(), 0, "nothing written, changed or deleted: {:?}", f.keys());
    assert_eq!(f.journal.as_deref(), Some(b"ACTIVE\tsomeone-elses\n".as_slice()), "the script's journal is untouched");
    assert!(f.lock_held, "the script's lock is untouched");
}

#[test]
fn call_on_non_lte_nr_voice_bearer_is_a_violation() {
    let (mut s, lease) = attached_session(&policy(true, false));
    let in_call = real_registry().replace("mCallState=0", "mCallState=2\n  mServiceState={mVoiceRegState=0(IN_SERVICE), getRilVoiceRadioTechnology=14(LTE), x}\n  mSrvccState=-1");
    s.sys_mut().set("dumpsys telephony.registry", &in_call);
    msg(&mut s, 2, ClientMsg::Heartbeat { lease });
    let out = tick(&mut s, 2_000);
    assert!(frames_to(&out, 2).is_empty(), "VoLTE call must not be a violation: {:?}", frames_to(&out, 2));
    s.sys_mut().set("dumpsys telephony.registry", &in_call.replace("14(LTE)", "3(UMTS)"));
    msg(&mut s, 2, ClientMsg::Heartbeat { lease });
    let out = tick(&mut s, 2_000);
    assert!(frames_to(&out, 2).contains(&ServerMsg::Violation { code: Code::VioBearer.as_u16() }), "{:?}", frames_to(&out, 2));
    assert!(s.is_fail_closed_tripped());
    assert!(has_key(s.sys(), "cmd telecom end-call"), "active call must be severed on fail-closed violation");
}

fn run_test_restore(sh: &str, journal: &std::path::Path) -> (Option<i32>, String) {
    match Command::new(sh).arg(script_path()).arg("--test-restore").arg(journal).arg("boot-1").output() {
        Ok(o) => (o.status.code(), String::from_utf8_lossy(&o.stdout).into_owned()),
        Err(e) => (None, format!("spawn failed: {e}")),
    }
}

#[test]
fn restore_script_respects_live_lock_and_breaks_stale_ones() {
    let j = journal::tests::sample_journal();
    let want = journal::render_plan(&journal::restore_plan(&journal::parse(&j), "boot-1"));
    for (i, sh) in shells().into_iter().enumerate() {
        let path = temp_file(&format!("lock{i}"), &j);
        let lock = std::path::PathBuf::from(format!("{}.lock", path.display()));
        let owner = lock.join("owner");
        let hold = |text: &str| {
            let _ = std::fs::create_dir_all(&lock);
            let _ = std::fs::write(&owner, text);
        };
        // Held by a live process of this boot (a daemon session): the script
        // gives up, restores nothing and deletes nothing.
        hold(&format!("{} boot-1\n", std::process::id()));
        let (rc, out) = run_test_restore(sh, &path);
        assert_eq!((rc, out.as_str()), (Some(75), ""), "{sh}: live lock");
        assert_eq!(std::fs::read(&path).ok().as_deref(), Some(j.as_slice()), "{sh}: journal must survive");
        assert!(owner.exists(), "{sh}: live lock must survive");
        // Same pid recorded for a previous boot: stale, restore proceeds.
        hold(&format!("{} boot-0\n", std::process::id()));
        let (rc, out) = run_test_restore(sh, &path);
        assert_eq!((rc, out.as_str()), (Some(0), want.as_str()), "{sh}: lock from another boot");
        assert!(!path.exists() && !lock.exists(), "{sh}: journal and lock removed after success");
        // Owner process gone: stale.
        let _ = std::fs::write(&path, &j);
        hold("99999999 boot-1 5\n");
        let (rc, out) = run_test_restore(sh, &path);
        assert_eq!((rc, out.as_str()), (Some(0), want.as_str()), "{sh}: dead owner");
        assert!(!path.exists() && !lock.exists(), "{sh}");
        // No lock at all, and no journal: nothing to do.
        assert_eq!(run_test_restore(sh, &path), (Some(0), String::new()), "{sh}: no journal");
        let _ = std::fs::write(&path, &j);
        let (rc, out) = run_test_restore(sh, &path);
        assert_eq!((rc, out.as_str()), (Some(0), want.as_str()), "{sh}: free lock");
        assert!(!path.exists() && !lock.exists(), "{sh}");
    }
}

#[test]
fn malformed_and_unexpected_messages_close_the_connection() {
    let mut s = Session::new(pixel(&policy(true, false)));
    s.handle(Input::Connected { conn: 1, uid: APP_UID, pid: LAUNCHER });
    let out = s.handle(Input::Data { conn: 1, bytes: vec![0, 0] });
    assert_eq!(frames_to(&out, 1), vec![ServerMsg::Fail { item: Item::Protocol.as_u16(), code: Code::BadFrame.as_u16() }]);
    assert!(closed(&out, 1));
    s.handle(Input::Connected { conn: 3, uid: APP_UID, pid: LAUNCHER });
    let out = s.handle(Input::Data { conn: 3, bytes: vec![0, 2, 99, 0] });
    assert!(closed(&out, 3));
    s.handle(Input::Connected { conn: 4, uid: APP_UID, pid: LAUNCHER });
    let out = msg(&mut s, 4, ClientMsg::Heartbeat { lease: [0; 16] });
    assert_eq!(frames_to(&out, 4), vec![ServerMsg::Fail { item: Item::Protocol.as_u16(), code: Code::UnexpectedMessage.as_u16() }]);
    s.handle(Input::Connected { conn: 5, uid: APP_UID, pid: LAUNCHER });
    let out = msg(&mut s, 5, ClientMsg::Hello { version: 1 });
    assert_eq!(frames_to(&out, 5), vec![ServerMsg::Hello { version: 1, mode: ipc::MODE_ARMED }]);
    let (msgs, _) = prepare(&mut s);
    assert!(msgs.iter().any(|m| matches!(m, ServerMsg::Ready { .. })));
    s.handle(Input::Connected { conn: 6, uid: APP_UID, pid: LAUNCHER });
    let out = msg(&mut s, 6, ClientMsg::Prepare);
    assert_eq!(frames_to(&out, 6), vec![ServerMsg::Fail { item: Item::Protocol.as_u16(), code: Code::Busy.as_u16() }]);
    assert!(matches!(s.phase(), Phase::Prepared { .. }), "a refused second PREPARE leaves the first session intact");
}

// ---------------------------------------------------------------- shell parity

fn script_path() -> String {
    format!("{}/../magisk-module/aegis-restore.sh", env!("CARGO_MANIFEST_DIR"))
}

fn shells() -> Vec<&'static str> {
    ["/bin/dash", "/bin/sh"].into_iter().filter(|p| std::path::Path::new(p).exists()).collect()
}

fn parity_journal() -> Vec<u8> {
    let mut j = journal::tests::sample_journal();
    let mut add = |k: &str, t: &str, p: &str, seq: u32| {
        let body = format!("{seq}\tINTENT\t{k}\t{t}\t{p}");
        j.extend_from_slice(format!("{body}\t{:08x}\n", journal::crc32(body.as_bytes())).as_bytes());
    };
    // Valid CRC, invalid content: both implementations must skip these.
    add("SETTING", "bogus/x", "1", 20);
    add("SETTING", "global/a/b", "1", 21);
    add("SETTING", "noslash", "1", 22);
    add("RADIO", "wifi", "maybe", 23);
    add("RADIO", "modem", "on", 24);
    add("NETTYPE", "7", "1", 25);
    add("NETTYPE", "0", "12", 26);
    add("USB", "functions", "MTP", 27);
    add("PKG_SUSPEND", "com.x.y", "1", 28);
    add("PKG_SUSPEND", "1bad.name", "0", 29);
    add("ZRAM", "zram123", "1,2", 30);
    add("ZRAM", "zram1", "1,2,3", 31);
    add("PROC", "1:2:3", "0", 32);
    add("IME", "default_input_method", "noslash", 33);
    add("A11Y", "other", "1", 34);
    add("FOO", "x", "y", 35);
    add("SETTING", "secure/x", "null", 36);
    add("USB", "functions", "none", 37);
    add("IME", "default_input_method", "null", 38);
    add("ZRAM", "zram1", "100,5", 39);
    j.extend_from_slice(b"40\tINTENT\tSETTING\tglobal/y\t1\t00000000\n");
    j.extend_from_slice(b"41\tINTENT\t\tSETTING\tglobal/y\t1\tdeadbeef\n");
    j.extend_from_slice("42\tINTENT\tSETTING\tglobal/\u{e9}\t1\tdeadbeef\n".as_bytes());
    j.extend_from_slice(encode_line(43, State::Done, Kind::Setting, "global/z", "1").unwrap_or_default().as_bytes());
    j.extend_from_slice(b"44\tINTENT\tSETTING\tglobal/torn");
    j
}

fn shell_plan(shell: &str, path: &std::path::Path, boot: &str) -> String {
    let out = Command::new(shell).arg(script_path()).arg("--print-plan").arg(path).arg(boot).output();
    match out {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).into_owned(),
        Ok(o) => format!("exit {:?}: {}", o.status.code(), String::from_utf8_lossy(&o.stderr)),
        Err(e) => format!("spawn failed: {e}"),
    }
}

fn temp_file(tag: &str, data: &[u8]) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("aegis-parity-{}-{tag}", std::process::id()));
    let _ = std::fs::write(&p, data);
    p
}

#[test]
fn shell_restore_script_matches_rust_plan() {
    let shells = shells();
    #[cfg(unix)]
    assert!(!shells.is_empty(), "no POSIX shell found");
    if shells.is_empty() {
        return;
    }
    let j = parity_journal();
    let path = temp_file("full", &j);
    let parsed = journal::parse(&j);
    for boot in ["boot-1", "another-boot"] {
        let want = journal::render_plan(&journal::restore_plan(&parsed, boot));
        assert!(want.lines().count() > 12, "{want}");
        for sh in &shells {
            assert_eq!(shell_plan(sh, &path, boot), want, "{sh} boot={boot}");
        }
    }
    let mut bad_header = b"NOT A HEADER\n".to_vec();
    bad_header.extend_from_slice(&j[j.iter().position(|&b| b == b'\n').map_or(0, |i| i + 1)..]);
    let path2 = temp_file("hdr", &bad_header);
    let want = journal::render_plan(&journal::restore_plan(&journal::parse(&bad_header), "boot-1"));
    assert!(!want.contains("kill"), "invalid header never counts as the same boot");
    for sh in &shells {
        assert_eq!(shell_plan(sh, &path2, "boot-1"), want, "{sh} bad header");
    }
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&path2);
}

#[test]
fn shell_and_rust_agree_on_every_truncation() {
    let sh_list = shells();
    #[cfg(unix)]
    assert!(!sh_list.is_empty(), "no POSIX shell found");
    let Some(&sh) = sh_list.first() else {
        return;
    };
    let j = journal::tests::sample_journal();
    let path = temp_file("cut", b"");
    for cut in 0..=j.len() {
        let _ = std::fs::write(&path, &j[..cut]);
        let want = journal::render_plan(&journal::restore_plan(&journal::parse(&j[..cut]), "boot-1"));
        assert_eq!(shell_plan(sh, &path, "boot-1"), want, "cut at {cut}");
    }
    let _ = std::fs::remove_file(&path);
}

#[test]
fn magisk_scripts_are_posix_and_lf() {
    let dir = format!("{}/../magisk-module", env!("CARGO_MANIFEST_DIR"));
    let scripts = [
        "aegis-restore.sh",
        "service.sh",
        "post-fs-data.sh",
        "action.sh",
        "customize.sh",
        "META-INF/com/google/android/update-binary",
    ];
    for name in scripts {
        let path = format!("{dir}/{name}");
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        assert!(!text.is_empty(), "{name} missing");
        assert!(!text.contains('\r'), "{name} has CRLF");
        for bashism in ["[[", "<<<", "$'", "function ", "source ", "local ", "${!", "=(", "pushd", "declare "] {
            assert!(!text.contains(bashism), "{name} uses {bashism}");
        }
        for sh in shells() {
            let st = Command::new(sh).arg("-n").arg(&path).status();
            assert!(st.is_ok_and(|s| s.success()), "{sh} -n {name}");
        }
    }
    let restore = std::fs::read_to_string(format!("{dir}/aegis-restore.sh")).unwrap_or_default();
    for forbidden in ["eval ", ". \"$", "$($", "sh -c"] {
        assert!(!restore.contains(forbidden), "restore script must never evaluate journal data ({forbidden})");
    }
}

#[test]
fn header_encodes_and_rejects_bad_values() {
    let h = Header { boot_id: BOOT.into(), lease_hash: "0123456789abcdef".into(), owner_pid: 1, owner_start: 2 };
    let line = h.encode().unwrap_or_default();
    assert_eq!(Header::parse(line.trim_end()), Some(h));
    let bad = Header { boot_id: "a b".into(), lease_hash: "0123456789abcdef".into(), owner_pid: 1, owner_start: 2 };
    assert!(bad.encode().is_err());
}

fn run_precheck(f: &mut FakeSys, policy_text: &str) -> Result<precheck::Context, Vec<Failure>> {
    precheck::run(f, &Policy::parse(policy_text).expect("policy"), false)
}

/// Failures only, for comparing a refused precheck.
fn refused(r: Result<precheck::Context, Vec<Failure>>) -> Result<(), Vec<Failure>> {
    r.map(|_| ())
}

#[test]
fn precheck_passes_on_the_pixel7_formats() {
    // Real formats: dsds with a SIM in slot 0 only, VoLTE at the carrier default,
    // an unused profile with VoLTE off, no owner, IMS on rmnet2 next to the internet connection.
    let text = policy(true, false);
    let mut f = pixel(&text);
    let ctx = run_precheck(&mut f, &text).expect("precheck on the real formats");
    assert_eq!(ctx.slots, vec![0]);
    assert_eq!(ctx.ims_uids, vec![IMS_UID]);
    assert_eq!(ctx.ims.iface, "rmnet2");
    assert_eq!(ctx.ims.pcscf, vec!["2001:db8::1".parse::<std::net::IpAddr>().unwrap(), "192.0.2.1".parse().unwrap()]);
    assert!(!ctx.uwb);
}

#[test]
fn ims_service_is_read_per_slot_with_carrier_and_device_flag() {
    let text = policy(true, false);
    let uids = |f: &mut FakeSys| run_precheck(f, &text).map(|c| c.ims_uids);
    // -c alone is enough.
    let mut f = pixel(&text);
    f.set(&ims_service_cmd(0, "-c"), &format!("{IMS_PKG}\n"));
    f.set(&ims_service_cmd(0, "-d"), "\n");
    assert_eq!(uids(&mut f), Ok(vec![IMS_UID]));
    // Different packages behind -c and -d: both uids are collected.
    let mut f = pixel(&text);
    let pm = format!("{PACKAGES}package:/system_ext/priv-app/ShannonRcs/ShannonRcs.apk=com.shannon.rcsservice uid:10246\n");
    f.set("pm list packages -f -U --user 0", &pm);
    f.set(&ims_service_cmd(0, "-c"), "com.shannon.rcsservice\n");
    assert_eq!(uids(&mut f), Ok(vec![10246, IMS_UID]));
    // Only the bare command (an error on the device) names a package: nothing resolves.
    let mut f = pixel(&text);
    f.set(&ims_service_cmd(0, "-d"), "\n");
    f.set("cmd phone ims get-ims-service", &format!("{IMS_PKG}\n"));
    assert_eq!(uids(&mut f), Err(vec![Failure::new(Item::Ims, Code::ImsUidUnresolved)]));
    // The error text is not a package.
    let mut f = pixel(&text);
    f.set(&ims_service_cmd(0, "-d"), "ims get-ims-service requires either \"-c\" or \"-d\" to be set.\n");
    assert_eq!(uids(&mut f), Err(vec![Failure::new(Item::Ims, Code::ImsUidUnresolved)]));
}

#[test]
fn slot_without_a_sim_is_neither_read_nor_set() {
    let text = policy(true, false);
    let (mut s, lease) = attached_session(&text);
    msg(&mut s, 2, ClientMsg::Heartbeat { lease });
    end_session(&mut s);
    let keys = s.sys().keys();
    assert!(keys.iter().any(|k| k.starts_with("cmd phone set-allowed-network-types-for-users -s 0 ")), "{keys:?}");
    assert!(!keys.iter().any(|k| k.contains("network-types-for-users -s 1")), "slot 1 has no SIM: {keys:?}");
    assert_restored(s.sys());

    // A SIM in slot 1 puts the slot in scope, and its network types must then be readable.
    let mut f = pixel(&text);
    f.set(SIMINFO_CMD, &format!("{}Row: 26 _id=27, volte_vt_enabled=-1, sim_id=1\n", real_siminfo()));
    assert_eq!(refused(run_precheck(&mut f, &text)), Err(vec![Failure::new(Item::Commands, Code::CommandOutputUnparsed)]));
    f.set("cmd phone get-allowed-network-types-for-users -s 1", "LTE|LTE_CA|NR\n");
    assert_eq!(run_precheck(&mut f, &text).map(|c| c.slots), Ok(vec![0, 1]));
}

#[test]
fn owner_blocks_fail_the_precheck_but_the_always_printed_lines_do_not() {
    let text = policy(true, false);
    let with = |extra: &str| {
        let mut f = pixel(&text);
        f.set("dumpsys device_policy", &format!("{REAL_DEVICE_POLICY}{extra}"));
        refused(run_precheck(&mut f, &text))
    };
    assert_eq!(with(""), Ok(()), "Device Owner Type: -1 and Has PO: are printed on every phone");
    let dev = "  Device Owner: \n    admin=ComponentInfo{com.example.mdm/com.example.mdm.Admin}\n    name=Example\n";
    assert_eq!(with(dev), Err(vec![Failure::new(Item::Owner, Code::DeviceOwnerPresent)]));
    let po = "  Profile Owner (User 10):\n    admin=ComponentInfo{com.example.work/com.example.work.Admin}\n";
    assert_eq!(with(po), Err(vec![Failure::new(Item::Owner, Code::ProfileOwnerPresent)]));
}

#[test]
fn blank_usb_functions_line_is_none_and_not_a_failed_read() {
    let text = policy(true, false);
    let mut f = pixel(&text);
    f.set("svc usb getFunctions", "\n");
    assert!(run_precheck(&mut f, &text).is_ok());
    let mut s = Session::new(f);
    let (msgs, _) = prepare(&mut s);
    assert!(msgs.iter().any(|m| matches!(m, ServerMsg::Ready { .. })), "{msgs:?}");
    assert!(!has_key(s.sys(), "svc usb"), "USB already has no function: nothing to set");
}

#[test]
fn unreadable_usb_functions_fail_unless_test_allow_usb_debug() {
    let text = policy(true, false);
    let mut f = pixel(&text);
    f.fail_reads.insert("svc usb getFunctions".into());
    assert_eq!(refused(run_precheck(&mut f, &text)), Err(vec![Failure::new(Item::Commands, Code::CommandOutputUnparsed)]));

    let text = format!("{text}test_allow_usb_debug=1\n");
    let mut f = pixel(&text);
    f.fail_reads.insert("svc usb getFunctions".into());
    assert!(run_precheck(&mut f, &text).is_ok(), "USB functions are not an item of this session");
    let mut s = Session::new(f);
    let (msgs, _) = prepare(&mut s);
    assert!(msgs.iter().any(|m| matches!(m, ServerMsg::Ready { .. })), "{msgs:?}");
    assert!(!has_key(s.sys(), "svc usb"));
}

#[test]
fn missing_uwb_service_means_no_uwb() {
    // The Pixel 7 has no uwb service: the state read fails (rc 20) and uwb is left alone.
    let text = policy(true, false);
    let mut s = Session::new(pixel(&text));
    let (msgs, _) = prepare(&mut s);
    assert!(msgs.iter().any(|m| matches!(m, ServerMsg::Ready { .. })), "{msgs:?}");
    assert!(!s.sys().keys().iter().any(|k| k.contains("uwb")));
    // A phone that has the service gets it switched off and back.
    let mut f = pixel(&text);
    f.set("cmd uwb get-uwb-state", "Uwb state: enabled");
    assert!(run_precheck(&mut f, &text).is_ok_and(|c| c.uwb));
}

const PACKAGE_LIST_CMD: &str = "pm list packages -f -U --user 0";
const DIALER_ROLE_CMD: &str = "cmd role get-role-holders --user 0 android.app.role.DIALER";
const SYSTEM_DIALER_CMD: &str = "cmd telecom get-system-dialer";
const APP_PKG: &str = "io.github.h4lovoid.dialcrypt";
const GOOGLE_DIALER: &str = "com.google.android.dialer";

fn run_tier2_precheck(f: &mut FakeSys, policy_text: &str) -> Result<precheck::Context, Vec<Failure>> {
    precheck::run(f, &Policy::parse(policy_text).expect("policy"), true)
}

/// A phone where DialCrypt is built into the system image and holds the dialer role.
fn dialcrypt_is_dialer(policy_text: &str) -> FakeSys {
    let mut f = pixel(policy_text);
    f.set(PACKAGE_LIST_CMD, &PACKAGES.replace(APK, &format!("{SYSTEM_CODE_PATH}/base.apk")));
    f.set(DIALER_ROLE_CMD, &format!("{APP_PKG}\n"));
    f
}

#[test]
fn dialcrypt_as_dialer_passes_tier2_and_exempts_itself_and_the_system_phone() {
    let text = policy(true, true);
    let mut f = dialcrypt_is_dialer(&text);
    f.set(SYSTEM_DIALER_CMD, &format!("{GOOGLE_DIALER}\n"));
    let ctx = run_tier2_precheck(&mut f, &text).expect("precheck with DialCrypt as the dialer");
    let exempt = ctx.tier2.expect("tier 2 plan").exempt;
    assert!(exempt.contains(APP_PKG) && exempt.contains(GOOGLE_DIALER), "{exempt:?}");
}

#[test]
fn missing_system_phone_is_refused_while_dialcrypt_holds_the_dialer_role() {
    let text = policy(true, true);
    let mut f = dialcrypt_is_dialer(&text);
    let without_phone: Vec<String> = f.get(PACKAGE_LIST_CMD).lines().filter(|l| !l.contains(GOOGLE_DIALER)).map(str::to_string).collect();
    f.set(PACKAGE_LIST_CMD, &without_phone.join("\n"));
    let missing = Err(vec![Failure::new(Item::Tier2, Code::SystemDialerMissing)]);
    // The command names a package that is not installed ...
    f.set(SYSTEM_DIALER_CMD, "com.example.phone\n");
    assert_eq!(refused(run_tier2_precheck(&mut f, &text)), missing);
    // ... or cannot be read and the fallback package is not installed either.
    f.fail_reads.insert(SYSTEM_DIALER_CMD.into());
    assert_eq!(refused(run_tier2_precheck(&mut f, &text)), missing);
}

#[test]
fn dialer_role_holder_outside_the_system_image_is_refused() {
    let text = policy(true, true);
    let mut f = pixel(&text);
    f.set(DIALER_ROLE_CMD, &format!("{APP_PKG}\n"));
    f.set(SYSTEM_DIALER_CMD, &format!("{GOOGLE_DIALER}\n"));
    assert_eq!(refused(run_tier2_precheck(&mut f, &text)), Err(vec![Failure::new(Item::Tier2, Code::DialerNotSystem)]));
}

#[test]
fn unreadable_system_dialer_falls_back_to_the_constant_package() {
    let text = policy(true, true);
    let mut f = dialcrypt_is_dialer(&text);
    f.fail_reads.insert(SYSTEM_DIALER_CMD.into());
    let ctx = run_tier2_precheck(&mut f, &text).expect("the fallback package is on the system image");
    let exempt = ctx.tier2.expect("tier 2 plan").exempt;
    assert!(exempt.contains(APP_PKG) && exempt.contains(GOOGLE_DIALER), "{exempt:?}");
    // An error message without a package name behaves the same.
    let mut f = dialcrypt_is_dialer(&text);
    f.set(SYSTEM_DIALER_CMD, "Error: unknown command\n");
    assert!(run_tier2_precheck(&mut f, &text).is_ok_and(|c| c.tier2.is_some_and(|t| t.exempt.contains(GOOGLE_DIALER))));
}

#[test]
fn system_dialer_naming_dialcrypt_or_a_non_system_package_falls_back_to_the_constant_package() {
    let text = policy(true, true);
    for named in [APP_PKG, "com.example.phone"] {
        let mut f = dialcrypt_is_dialer(&text);
        f.set(SYSTEM_DIALER_CMD, &format!("{named}\n"));
        let ctx = run_tier2_precheck(&mut f, &text).expect("the fallback package is on the system image");
        let exempt = ctx.tier2.expect("tier 2 plan").exempt;
        assert!(exempt.contains(APP_PKG) && exempt.contains(GOOGLE_DIALER), "{named}: {exempt:?}");
    }
    // DialCrypt naming itself is no system phone app: without the constant package Tier 2 is refused.
    let mut f = dialcrypt_is_dialer(&text);
    let without_phone: Vec<String> = f.get(PACKAGE_LIST_CMD).lines().filter(|l| !l.contains(GOOGLE_DIALER)).map(str::to_string).collect();
    f.set(PACKAGE_LIST_CMD, &without_phone.join("\n"));
    f.set(SYSTEM_DIALER_CMD, &format!("{APP_PKG}\n"));
    assert_eq!(refused(run_tier2_precheck(&mut f, &text)), Err(vec![Failure::new(Item::Tier2, Code::SystemDialerMissing)]));
}

#[test]
fn trim_storage_and_controlled_vowifi_lockdown() {
    // 1. TrimStorage runs `sm fstrim` when armed and is a no-op in dry-run mode.
    let mut dry = Session::new(pixel(&policy(false, false)));
    dry.handle(Input::Connected { conn: 1, uid: APP_UID, pid: LAUNCHER });
    msg(&mut dry, 1, ClientMsg::TrimStorage);
    assert!(!has_key(dry.sys(), "sm fstrim"));

    let mut armed = Session::new(pixel(&policy(true, false)));
    armed.handle(Input::Connected { conn: 1, uid: APP_UID, pid: LAUNCHER });
    msg(&mut armed, 1, ClientMsg::TrimStorage);
    assert!(has_key(armed.sys(), "sm fstrim"));

    // 2. Controlled VoWiFi keeps Wi-Fi up while pinning wlan0 rules strictly to ePDG IPSec.
    let vowifi_pol = format!("{}allow_vowifi=1\nepdg_addrs=198.51.100.10\n", policy(true, false));
    let mut f = pixel(&vowifi_pol);
    let iwlan_reg = real_registry()
        .replace("transport: WWAN, id: 3", "transport: IWLAN, id: 3")
        .replace("netId: 101, network type: LTE", "netId: 101, network type: IWLAN")
        .replace("InterfaceName: rmnet2", "InterfaceName: ipsec0");
    f.set("dumpsys telephony.registry", &iwlan_reg);
    f.dirs.get_mut("/sys/class/net").unwrap().push("ipsec0".into());
    f.file("/sys/class/net/ipsec0/operstate", "up");
    f.file("/sys/class/net/wlan0/operstate", "up");
    f.file("/sys/class/net/rmnet2/operstate", "down");
    let mut s = Session::new(f);
    let (msgs, lease) = prepare(&mut s);
    assert!(msgs.iter().any(|m| matches!(m, ServerMsg::Ready { .. })), "{msgs:?}");
    assert_eq!(s.sys().get("settings get global wifi_on"), "1", "Wi-Fi stays enabled for VoWiFi");
    let a = attach(&mut s, lease);
    assert!(matches!(a.as_slice(), [ServerMsg::Attached { .. }]), "{a:?}");
    msg(&mut s, 2, ClientMsg::Heartbeat { lease });
    let out = tick(&mut s, 2_000);
    assert!(frames_to(&out, 2).is_empty(), "wlan0+ipsec0 must pass monitor under VoWiFi: {:?}", frames_to(&out, 2));
}
