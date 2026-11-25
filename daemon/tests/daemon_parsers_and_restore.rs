//! Independent acceptance tests for WP6 (aegiscalld). Black box over the public API:
//! APK signature parsing, IPC framing, telephony/package/policy parsing, firewall
//! text and the restore plan are fed hostile input. Nothing here touches the device.

use std::net::IpAddr;

use aegiscalld::apk::{signer_cert_digests, ApkError};
use aegiscalld::firewall::{restore_text, Family, FwConfig};
use aegiscalld::ipc::{decode_client, FrameReader};
use aegiscalld::journal::{self, Step};
use aegiscalld::sysops::{Mutation, SysError, SysOps};
use sha2::{Digest, Sha256};

struct OneFile {
    data: Vec<u8>,
}

impl SysOps for OneFile {
    fn read_cmd(&mut self, _argv: &[&str]) -> Result<String, SysError> {
        Err(SysError::Unsupported)
    }
    fn read_file(&mut self, _path: &str) -> Result<Vec<u8>, SysError> {
        Ok(self.data.clone())
    }
    fn read_file_range(&mut self, _path: &str, offset: u64, len: usize) -> Result<Vec<u8>, SysError> {
        let start = (offset as usize).min(self.data.len());
        let end = start.saturating_add(len).min(self.data.len());
        Ok(self.data[start..end].to_vec())
    }
    fn file_size(&mut self, _path: &str) -> Result<u64, SysError> {
        Ok(self.data.len() as u64)
    }
    fn list_dir(&mut self, _path: &str) -> Result<Vec<String>, SysError> {
        Err(SysError::Unsupported)
    }
    fn exists(&mut self, _path: &str) -> bool {
        false
    }
    fn random16(&mut self) -> Result<[u8; 16], SysError> {
        Err(SysError::Unsupported)
    }
    fn now_ms(&mut self) -> u64 {
        0
    }
    fn uptime_ticks(&mut self) -> Result<u64, SysError> {
        Err(SysError::Unsupported)
    }
    fn sleep_ms(&mut self, _ms: u64) {}
    fn apply(&mut self, _m: &Mutation) -> Result<(), SysError> {
        panic!("a pure parser must never change the system");
    }
    fn journal_load(&mut self) -> Result<Option<Vec<u8>>, SysError> {
        Ok(None)
    }
    fn journal_append(&mut self, _line: &[u8]) -> Result<(), SysError> {
        Err(SysError::Unsupported)
    }
    fn journal_replace(&mut self, _data: &[u8]) -> Result<(), SysError> {
        Err(SysError::Unsupported)
    }
    fn journal_remove(&mut self) -> Result<(), SysError> {
        Err(SysError::Unsupported)
    }
    fn restore_lock(&mut self) -> Result<bool, SysError> {
        Ok(true)
    }
    fn restore_unlock(&mut self) {}
    fn packet_capture(&mut self, _on: bool) -> Result<(), SysError> {
        Ok(())
    }
    fn poll_packets(&mut self) -> Vec<Vec<u8>> {
        Vec::new()
    }
}

struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0 >> 33
    }
    fn byte(&mut self) -> u8 {
        self.next() as u8
    }
}

const MAGIC: &[u8; 16] = b"APK Sig Block 42";
const LOCAL: &[u8] = b"PK\x03\x04local-file-entries";

fn p(b: &[u8]) -> Vec<u8> {
    let mut v = (b.len() as u32).to_le_bytes().to_vec();
    v.extend_from_slice(b);
    v
}

/// Minimal signed APK: local entries, v2/v3 signing block, central directory, EOCD.
fn build_apk(cert: &[u8], v3: bool) -> Vec<u8> {
    let mut signed = p(&[]);
    signed.extend(p(&p(cert)));
    if v3 {
        signed.extend(28u32.to_le_bytes());
        signed.extend(0x7fff_ffffu32.to_le_bytes());
    }
    signed.extend(p(&[]));
    let mut signer = p(&signed);
    signer.extend(p(&[]));
    signer.extend(p(b"public-key"));
    let value = p(&p(&signer));
    let id: u32 = if v3 { 0xf053_68c0 } else { 0x7109_871a };
    let mut pairs = ((value.len() + 4) as u64).to_le_bytes().to_vec();
    pairs.extend(id.to_le_bytes());
    pairs.extend(value);
    let block_size = (pairs.len() + 8 + 16) as u64;
    let mut apk = LOCAL.to_vec();
    apk.extend(block_size.to_le_bytes());
    apk.extend(pairs);
    apk.extend(block_size.to_le_bytes());
    apk.extend_from_slice(MAGIC);
    let cd_offset = apk.len() as u32;
    let cd = b"PK\x01\x02central-directory";
    apk.extend_from_slice(cd);
    apk.extend(0x0605_4b50u32.to_le_bytes());
    apk.extend([0u8; 4]);
    apk.extend(1u16.to_le_bytes());
    apk.extend(1u16.to_le_bytes());
    apk.extend((cd.len() as u32).to_le_bytes());
    apk.extend(cd_offset.to_le_bytes());
    apk.extend(0u16.to_le_bytes());
    apk
}

fn parse_apk(b: &[u8]) -> Result<Vec<[u8; 32]>, ApkError> {
    let mut f = OneFile { data: b.to_vec() };
    signer_cert_digests(&mut f, "/data/app/x/base.apk")
}

#[test]
fn apk_parser_survives_truncation_and_every_byte_mutation_without_a_false_match() {
    let cert = b"cert-one".as_slice();
    for v3 in [false, true] {
        let apk = build_apk(cert, v3);
        let want: [u8; 32] = Sha256::digest(cert).into();
        assert_eq!(parse_apk(&apk), Ok(vec![want]), "sanity v3={v3}");
        let pos = apk.windows(cert.len()).position(|w| w == cert).unwrap_or(0);
        for cut in 0..apk.len() {
            assert!(parse_apk(&apk[..cut]).is_err(), "truncated at {cut} was accepted (v3={v3})");
        }
        for i in 0..apk.len() {
            for m in [0x00u8, 0xff, 0x01, 0x80] {
                let mut b = apk.clone();
                b[i] = if m == 0x01 || m == 0x80 { b[i] ^ m } else { m };
                if b == apk {
                    continue;
                }
                let r = parse_apk(&b);
                if (pos..pos + cert.len()).contains(&i) {
                    assert!(r != Ok(vec![want]), "a changed certificate byte at {i} still yields the pinned digest");
                }
            }
        }
        // Absurd length fields in the footer and header copies of the block size.
        let magic_at = apk.windows(16).position(|w| w == MAGIC.as_slice()).unwrap_or(0);
        for huge in [u64::MAX, u64::MAX / 2, 1u64 << 40, 23, 0] {
            let mut b = apk.clone();
            b[magic_at - 8..magic_at].copy_from_slice(&huge.to_le_bytes());
            assert!(parse_apk(&b).is_err(), "footer size {huge}");
            let mut b = apk.clone();
            b[LOCAL.len()..LOCAL.len() + 8].copy_from_slice(&huge.to_le_bytes());
            assert!(parse_apk(&b).is_err(), "header size {huge}");
        }
    }
    // Random garbage of many sizes never panics and is never accepted.
    let mut rng = Lcg(7);
    for _ in 0..300 {
        let n = (rng.next() % 3000) as usize;
        let b: Vec<u8> = (0..n).map(|_| rng.byte()).collect();
        assert!(parse_apk(&b).is_err());
    }
}

#[test]
fn ipc_decoder_accepts_only_exact_client_messages_and_bounds_frames() {
    for ty in 0..=255u8 {
        for len in 0..=40usize {
            let mut body = vec![ty];
            body.extend(std::iter::repeat(0xabu8).take(len));
            let ok = decode_client(&body).is_ok();
            let expect = matches!((ty, len), (1, 1) | (2, 0) | (6, 16) | (8, 16) | (10, 0));
            assert_eq!(ok, expect, "type {ty} payload {len}");
        }
    }
    let mut rng = Lcg(1);
    for _ in 0..3000 {
        let mut r = FrameReader::default();
        for _ in 0..20 {
            let n = (rng.next() % 40) as usize;
            let mut chunk: Vec<u8> = (0..n).map(|_| rng.byte()).collect();
            if rng.next() % 2 == 0 && chunk.len() >= 2 {
                chunk[0] = 0;
                chunk[1] = (rng.next() % 70) as u8;
            }
            match r.push(&chunk) {
                Ok(frames) => {
                    for f in frames {
                        assert!(!f.is_empty() && f.len() <= 64, "frame outside 1..=64 bytes");
                        let _ = decode_client(&f);
                    }
                }
                Err(_) => break,
            }
        }
    }
    // A huge stream of zero bytes is rejected at the first length prefix instead of buffering.
    let mut r = FrameReader::default();
    assert!(r.push(&vec![0u8; 1 << 20]).is_err());
}

const REGISTRY: &str = "  mCallState=0\n    { state: CONNECTED, transport: WWAN, id: 2, network type: LTE, APN Setting: [ApnSetting] IMS, 2731, 310260, ims, , null, null, null, , null, -1, ims, IPV6, IPV4V6, link properties: {InterfaceName: rmnet1 LinkAddresses: [ 2607:fb90:8::5/64 ] DnsAddresses: [ ] PcscfServers: [ /10.0.0.10,/2607:fb90:1::10 ] MTU: 1430}, default network fail: NONE }\n";

fn journal_alphabet(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '/' | ',' | '=' | '-')
}

#[test]
fn hostile_dumpsys_values_never_reach_firewall_rules() {
    let hostile_ifaces = [
        "rmnet1;reboot", "rmnet1\u{0}x", "..", "rmnet1$(id)", "rmnet1\u{60}id\u{60}", "rmnet_data_very_long_name_x", "rm net", "rmnet1|x", "r\u{e9}net", "rmnet1&&x", "rmnet1>x", "rmnet1\"x",
    ];
    for h in hostile_ifaces {
        let text = REGISTRY.replace("InterfaceName: rmnet1", &format!("InterfaceName: {h}"));
        if let Ok(link) = aegiscalld::telephony::parse_ims_link(&text) {
            assert!(link.iface.len() <= 15 && link.iface.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')), "iface {:?} accepted", link.iface);
        }
    }
    let text = REGISTRY.replace(
        "/10.0.0.10,/2607:fb90:1::10",
        "/0.0.0.0, /127.0.0.1, /224.0.0.1, /255.255.255.255, /::, /::1, /ff02::1, /1.2.3.4;reboot, /999.1.1.1, /10.0.0.10",
    );
    let link = aegiscalld::telephony::parse_ims_link(&text);
    let Ok(link) = link else { panic!("{link:?}") };
    assert_eq!(link.pcscf, vec!["10.0.0.10".parse::<IpAddr>().unwrap_or(IpAddr::from([0, 0, 0, 0]))]);
    // Package list lines: only syntactically valid package names survive.
    let pm = "package:/data/app/a/base.apk=com.ok.app uid:10001\npackage:/x=com.evil;rm -rf uid:10002\npackage:/x=com.a b uid:10003\npackage:/x=1bad.name uid:10004\npackage:/x=com.a..b uid:10005\npackage:/x=com.ok.two uid:10006abc\npackage:/x=com.ok.three uid:10007,10008\n";
    let names: Vec<String> = aegiscalld::precheck::parse_package_list(pm).into_iter().map(|x| x.name).collect();
    assert_eq!(names, vec!["com.ok.app".to_string(), "com.ok.three".to_string()]);
}

fn fw_cfg() -> FwConfig {
    let a = |s: &str| s.parse::<IpAddr>().unwrap_or(IpAddr::from([0, 0, 0, 0]));
    FwConfig {
        iface: "rmnet1".into(),
        uids: vec![1001, 1002],
        pcscf: ["10.0.0.10", "0.0.0.0", "127.0.0.1", "224.0.0.1", "255.255.255.255", "2607:fb90:1::10", "::", "::1", "ff02::1"].iter().map(|s| a(*s)).collect(),
        media: ["10.9.9.1", "10.9.9.2", "10.9.9.3", "10.9.9.4", "2607:fb90:9::9", "239.1.1.1"].iter().map(|s| a(*s)).collect(),
        nflog: true,
    }
}

#[test]
fn firewall_text_is_closed_to_unusable_addresses_and_ends_every_chain_in_drop() {
    for fam in Family::ALL {
        for jumps in [true, false] {
            let t = restore_text(&fw_cfg(), fam, jumps);
            for bad in ["0.0.0.0", "127.0.0.1", "224.0.0.1", "255.255.255.255", "239.1.1.1", "::/128", "::1/128", "ff02::1"] {
                assert!(!t.contains(bad), "{bad} reached the {fam:?} rules");
            }
            let first = t.lines().next().unwrap_or("");
            assert_eq!(first, "*filter");
            assert!(t.lines().filter(|l| l.starts_with(':')).all(|l| l.starts_with(":aegis_") && l.ends_with(" - [0:0]")));
            for l in t.lines() {
                let w: Vec<&str> = l.split_whitespace().collect();
                assert!(!w.iter().any(|x| matches!(*x, "-F" | "-X" | "-P" | "-D" | "-Z" | "-R")), "{l}");
                if l.starts_with("-A aegis_out") && l.ends_with("-j ACCEPT") {
                    let nd = l.contains("-p ipv6-icmp") && l.contains("--icmpv6-type 13");
                    assert!(l == "-A aegis_out -o lo -j ACCEPT" || nd || (l.contains("--uid-owner ") && l.contains(" -d ") && l.contains("-o rmnet1")), "{l}");
                }
                if l.starts_with("-A aegis_in") && l.ends_with("-j ACCEPT") {
                    assert!(l == "-A aegis_in -i lo -j ACCEPT" || l.contains(" -s ") || l.contains("--icmpv6-type 13"), "{l}");
                }
            }
            for c in ["aegis_in", "aegis_out", "aegis_fwd"] {
                let last = t.lines().filter(|l| l.starts_with(&format!("-A {c} "))).last().unwrap_or("");
                assert_eq!(last, format!("-A {c} -j DROP"), "{c} must end in DROP");
            }
            let media_rules = t.lines().filter(|l| l.starts_with("-A aegis_out") && l.contains("-p udp -d ") && l.ends_with("ACCEPT")).count();
            let expect = if fam == Family::V4 { 4 * 2 } else { 2 };
            assert_eq!(media_rules, expect, "{fam:?} media rules (uids x learned addresses of this family)");
        }
    }
}

fn jline(seq: u32, state: &str, kind: &str, t: &str, pr: &str) -> String {
    let body = format!("{seq}\t{state}\t{kind}\t{t}\t{pr}");
    format!("{body}\t{:08x}\n", journal::crc32(body.as_bytes()))
}

#[test]
fn restore_plan_from_hostile_but_well_formed_journal_only_runs_fixed_commands() {
    let kinds = ["FW", "RADIO", "SETTING", "NETTYPE", "USB", "PKG_SUSPEND", "IME", "A11Y", "ZRAM", "PROC", "SCRUB"];
    let values = [
        "-rf", "--user", "-s", "global/-x", "global/../x", "secure/a=b", "..", "a..b", "-1", "/system/bin/sh", "com.a.b/-x", "com.x.y", "null", "none", "wifi", "on", "0", "zram0", "1,2", "700:5000", "global/x", "x:y", "a,b", "mtp,adb",
        "default_input_method", "accessibility_enabled", "enabled_accessibility_services", "functions", "com.x.kbd/.Ime", "11000001000000000000", "uwb", "bluetooth", "off", "nfc", "data", "global/wifi_on",
    ];
    let mut text = String::from("ACTIVE\tboot-1\t0123456789abcdef\t500:1000\n");
    let mut seq = 1;
    for k in kinds {
        for t in values {
            for pr in values {
                text.push_str(&jline(seq, "INTENT", k, t, pr));
                seq += 1;
            }
        }
    }
    let parsed = journal::parse(text.as_bytes());
    assert!(parsed.intents.len() > 5000);
    let mut exec_steps = 0;
    for boot in ["boot-1", "other"] {
        let plan = journal::restore_plan(&parsed, boot);
        let n = plan.len();
        assert!(matches!(plan[n - 2].0, Step::FwDown(Family::V4)) && matches!(plan[n - 1].0, Step::FwDown(Family::V6)));
        for (step, _) in &plan {
            match step {
                Step::Exec(argv) => {
                    exec_steps += 1;
                    assert!(argv.iter().all(|a| !a.is_empty() && a.chars().all(journal_alphabet)), "{argv:?}");
                    let a: Vec<&str> = argv.iter().map(String::as_str).collect();
                    let ok = match a.as_slice() {
                        ["settings", "put", ns, key, _val] => matches!(*ns, "global" | "secure" | "system") && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
                        ["settings", "delete", ns, key] => matches!(*ns, "global" | "secure" | "system") && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
                        ["ime", "set", id] => id.contains('/') && !id.starts_with('-') && id.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/')),
                        ["pm", "unsuspend", "--user", "0", pkg] => pkg.contains('.') && pkg.chars().next().is_some_and(|c| c.is_ascii_alphabetic()),
                        ["svc", "usb", "setFunctions"] => true,
                        ["svc", "usb", "setFunctions", f] => f.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | ',')),
                        ["svc", "nfc" | "data", "enable" | "disable"] => true,
                        ["cmd", "wifi", "set-wifi-enabled", "enabled" | "disabled"] => true,
                        ["cmd", "bluetooth_manager", "enable" | "disable"] => true,
                        ["cmd", "uwb", "enable-uwb" | "disable-uwb"] => true,
                        ["cmd", "phone", "set-allowed-network-types-for-users", "-s", slot, mask] => matches!(*slot, "0" | "1" | "2" | "3") && !mask.is_empty() && mask.chars().all(|c| c == '0' || c == '1'),
                        _ => false,
                    };
                    assert!(ok, "restore step outside the fixed command table: {argv:?}");
                }
                Step::Kill { pid, .. } => assert!(boot == "boot-1" && *pid > 0, "kill step on another boot or with pid 0"),
                Step::Zram { dev, spec } => {
                    assert!(dev.starts_with("zram") && dev[4..].len() <= 2 && dev[4..].chars().all(|c| c.is_ascii_digit()));
                    assert!(aegiscalld::memscrub::parse_zram_spec(spec).is_some());
                }
                Step::FwDown(_) => {}
            }
        }
    }
    assert!(exec_steps > 100, "the hostile journal produced almost no steps ({exec_steps}), the test proves nothing");
}

fn sample_journal() -> Vec<u8> {
    let mut t = String::from("ACTIVE\tboot-1\t0123456789abcdef\t500:1000\n");
    let rows = [
        ("FW", "v4", "absent"), ("RADIO", "wifi", "on"), ("SETTING", "global/wifi_scan_always_enabled", "1"),
        ("NETTYPE", "0", "11111111111111111111"), ("USB", "functions", "mtp"), ("PKG_SUSPEND", "com.chat.app", "0"),
        ("ZRAM", "zram0", "4294967296,-2"), ("PROC", "700:5000", "0"), ("IME", "default_input_method", "com.x.kbd/.Ime"),
    ];
    for (i, (k, a, b)) in rows.iter().enumerate() {
        t.push_str(&jline(i as u32 + 1, "INTENT", k, a, b));
        t.push_str(&jline(i as u32 + 1, "DONE", k, a, b));
    }
    t.into_bytes()
}

#[test]
fn journal_policy_and_netlink_parsers_never_panic_on_random_bytes() {
    let mut rng = Lcg(99);
    let good = sample_journal();
    for _ in 0..2000 {
        let mut b = good.clone();
        for _ in 0..(1 + rng.next() % 6) {
            let i = (rng.next() as usize) % b.len();
            b[i] = rng.byte();
        }
        let cut = (rng.next() as usize) % (b.len() + 1);
        let parsed = journal::parse(&b[..cut]);
        let plan = journal::restore_plan(&parsed, "boot-1");
        assert!(plan.len() >= 2);
        let s = String::from_utf8_lossy(&b[..cut]).into_owned();
        if let Ok(pol) = aegiscalld::policy::Policy::parse(&s) {
            assert!(pol.allowed_ifaces.iter().all(|i| aegiscalld::valid::is_iface_name(i)));
        }
        let _ = aegiscalld::telephony::parse_ims_link(&s);
        let _ = aegiscalld::nflog::parse_messages(&b[..cut]);
        let _ = aegiscalld::nflog::parse_ip(&b[..cut]);
    }
}
