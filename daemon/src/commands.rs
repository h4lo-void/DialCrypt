//! Command table for every tier 1 / tier 2 item: how to set a value, how to
//! read it back, and how to normalize the output. Restore uses the same
//! `set_argv` with the journaled prior value, and aegis-restore.sh mirrors
//! these argument vectors exactly (checked by the parity test).
//!
//! The read commands and their output formats follow captures from a Pixel 7
//! (Android 16, KernelSU). To be confirmed on device: the set commands have not been run on a
//! device; in particular `cmd phone set-allowed-network-types-for-users` is
//! assumed to take the bitmask in binary as its help text says. Adjust this
//! table and the shell script together once they are confirmed.

use crate::journal::Kind;
use crate::sysops::{last_line, SysOps};
use crate::valid::{is_ime_id, is_journal_token, is_setting_key};

/// Allowed network types bitmask: LTE (bit 12) | LTE_CA (bit 18) | NR (bit 19),
/// written in binary as the help text of the set command describes
/// (To be confirmed on device: not yet run on a device). The same text is the internal form of
/// a read-back value, see [`normalize`].
pub const LTE_NR_MASK: &str = "11000001000000000000";

/// Names printed by `cmd phone get-allowed-network-types-for-users` (joined by
/// `|`) with their TelephonyManager network type number; the bit of a type in
/// NETWORK_TYPE_BITMASK is the number minus one.
const NETWORK_TYPES: [(&str, u32); 20] = [
    ("GPRS", 1),
    ("EDGE", 2),
    ("UMTS", 3),
    ("CDMA", 4),
    ("CDMA - EvDo rev. 0", 5),
    ("CDMA - EvDo rev. A", 6),
    ("CDMA - 1xRTT", 7),
    ("HSDPA", 8),
    ("HSUPA", 9),
    ("HSPA", 10),
    ("iDEN", 11),
    ("CDMA - EvDo rev. B", 12),
    ("LTE", 13),
    ("CDMA - eHRPD", 14),
    ("HSPA+", 15),
    ("GSM", 16),
    ("TD_SCDMA", 17),
    ("IWLAN", 18),
    ("LTE_CA", 19),
    ("NR", 20),
];

/// Name list as printed by the device for a binary bitmask (test double).
#[cfg(test)]
pub fn network_type_names(bitmask: &str) -> Option<String> {
    let mask = u32::from_str_radix(bitmask, 2).ok()?;
    let names: Vec<&str> = NETWORK_TYPES.iter().filter(|(_, n)| mask & (1 << (n - 1)) != 0).map(|(name, _)| *name).collect();
    Some(names.join("|"))
}

fn v(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| s.to_string()).collect()
}

pub const RADIOS: [&str; 5] = ["wifi", "bluetooth", "nfc", "uwb", "data"];

fn is_usb_functions(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b',')
}

fn is_bitmask(s: &str) -> bool {
    (1..=32).contains(&s.len()) && s.bytes().all(|c| c == b'0' || c == b'1')
}

fn is_slot(s: &str) -> bool {
    matches!(s, "0" | "1" | "2" | "3")
}

fn settings_set(ns: &str, key: &str, value: &str) -> Vec<String> {
    if value == "null" {
        v(&["settings", "delete", ns, key])
    } else {
        v(&["settings", "put", ns, key, value])
    }
}

/// Command that sets `target` to `value`. `None` when target or value is
/// not one this table knows (such journal entries are skipped on restore).
pub fn set_argv(kind: Kind, target: &str, value: &str) -> Option<Vec<String>> {
    match kind {
        Kind::Setting => {
            let (ns, key) = target.split_once('/')?;
            if !matches!(ns, "global" | "secure" | "system") || !is_setting_key(key) || !is_journal_token(value) {
                return None;
            }
            Some(settings_set(ns, key, value))
        }
        Kind::A11y => {
            if !matches!(target, "enabled_accessibility_services" | "accessibility_enabled") || !is_journal_token(value) {
                return None;
            }
            Some(settings_set("secure", target, value))
        }
        Kind::Ime => {
            if target != "default_input_method" {
                return None;
            }
            if value == "null" {
                Some(settings_set("secure", target, value))
            } else if is_ime_id(value) {
                Some(v(&["ime", "set", value]))
            } else {
                None
            }
        }
        Kind::Radio => {
            let on = match value {
                "on" => true,
                "off" => false,
                _ => return None,
            };
            Some(match target {
                "wifi" => v(&["cmd", "wifi", "set-wifi-enabled", if on { "enabled" } else { "disabled" }]),
                "bluetooth" => v(&["cmd", "bluetooth_manager", if on { "enable" } else { "disable" }]),
                "nfc" => v(&["svc", "nfc", if on { "enable" } else { "disable" }]),
                "uwb" => v(&["cmd", "uwb", if on { "enable-uwb" } else { "disable-uwb" }]),
                "data" => v(&["svc", "data", if on { "enable" } else { "disable" }]),
                _ => return None,
            })
        }
        Kind::NetType => {
            if !is_slot(target) || !is_bitmask(value) {
                return None;
            }
            Some(v(&["cmd", "phone", "set-allowed-network-types-for-users", "-s", target, value]))
        }
        Kind::Usb => {
            if target != "functions" || !is_usb_functions(value) {
                return None;
            }
            if value == "none" {
                Some(v(&["svc", "usb", "setFunctions"]))
            } else {
                Some(v(&["svc", "usb", "setFunctions", value]))
            }
        }
        Kind::Fw | Kind::PkgSuspend | Kind::Zram | Kind::Proc | Kind::Scrub => None,
    }
}

pub fn suspend_argv(pkg: &str) -> Vec<String> {
    v(&["pm", "suspend", "--user", "0", pkg])
}

pub fn unsuspend_argv(pkg: &str) -> Vec<String> {
    v(&["pm", "unsuspend", "--user", "0", pkg])
}

/// Read-only command whose output [`normalize`] turns into a comparable value.
pub fn read_argv(kind: Kind, target: &str) -> Option<Vec<String>> {
    match kind {
        Kind::Setting => {
            let (ns, key) = target.split_once('/')?;
            if !matches!(ns, "global" | "secure" | "system") || !is_setting_key(key) {
                return None;
            }
            Some(v(&["settings", "get", ns, key]))
        }
        Kind::A11y => Some(v(&["settings", "get", "secure", target])),
        Kind::Ime => Some(v(&["settings", "get", "secure", "default_input_method"])),
        Kind::Radio => Some(match target {
            "wifi" => v(&["settings", "get", "global", "wifi_on"]),
            "bluetooth" => v(&["settings", "get", "global", "bluetooth_on"]),
            "nfc" => v(&["dumpsys", "nfc"]),
            "uwb" => v(&["cmd", "uwb", "get-uwb-state"]),
            "data" => v(&["settings", "get", "global", "mobile_data"]),
            _ => return None,
        }),
        Kind::NetType => {
            if !is_slot(target) {
                return None;
            }
            Some(v(&["cmd", "phone", "get-allowed-network-types-for-users", "-s", target]))
        }
        Kind::Usb => Some(v(&["svc", "usb", "getFunctions"])),
        _ => None,
    }
}

/// Turns raw command output into the journal form of the value.
pub fn normalize(kind: Kind, target: &str, raw: &str) -> Option<String> {
    match kind {
        Kind::Setting | Kind::A11y | Kind::Ime => {
            let l = last_line(raw);
            Some(if l.is_empty() { "null".to_string() } else { l.to_string() })
        }
        Kind::Radio => {
            let on = match target {
                // wifi_on: 1 enabled, 2 enabled while in airplane mode, 0/3 disabled (to be confirmed on device)
                "wifi" => match last_line(raw) {
                    "1" | "2" => true,
                    "0" | "3" => false,
                    _ => return None,
                },
                "bluetooth" => match last_line(raw) {
                    "1" | "2" => true,
                    "0" => false,
                    _ => return None,
                },
                "data" => match last_line(raw) {
                    "1" => true,
                    "0" => false,
                    _ => return None,
                },
                "nfc" => {
                    let pos = raw.find("mState=")?;
                    let rest = &raw[pos + 7..];
                    let tok: String = rest.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
                    match tok.as_str() {
                        "on" | "ON" | "STATE_ON" => true,
                        "off" | "OFF" | "STATE_OFF" => false,
                        _ => return None,
                    }
                }
                "uwb" => {
                    let l = raw.to_ascii_lowercase();
                    if l.contains("disabled") {
                        false
                    } else if l.contains("enabled") {
                        true
                    } else {
                        return None;
                    }
                }
                _ => return None,
            };
            Some(if on { "on" } else { "off" }.to_string())
        }
        Kind::NetType => {
            // Names joined by '|' -> bitmask in binary without leading zeros.
            // A name that is not in the table makes the value unreadable.
            let mut mask: u32 = 0;
            for name in last_line(raw).split('|') {
                let (_, n) = NETWORK_TYPES.iter().find(|(known, _)| known.eq_ignore_ascii_case(name.trim()))?;
                mask |= 1 << (n - 1);
            }
            Some(format!("{mask:b}"))
        }
        Kind::Usb => {
            // Only USB debugging and no other function prints an empty line (rc 0).
            let Some(tok) = last_line(raw).split_whitespace().last() else { return Some("none".to_string()) };
            if is_usb_functions(tok) {
                Some(tok.to_string())
            } else {
                None
            }
        }
        _ => None,
    }
}

pub fn read_item<S: SysOps + ?Sized>(sys: &mut S, kind: Kind, target: &str) -> Option<String> {
    let argv = read_argv(kind, target)?;
    let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
    let raw = sys.read_cmd(&refs).ok()?;
    normalize(kind, target, &raw)
}

pub fn same_value(kind: Kind, a: &str, b: &str) -> bool {
    match kind {
        Kind::NetType => a.trim_start_matches('0') == b.trim_start_matches('0'),
        _ => a == b,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizers_and_table() {
        assert_eq!(normalize(Kind::Radio, "wifi", "1\n").as_deref(), Some("on"));
        assert_eq!(normalize(Kind::Radio, "nfc", "x\nmState=off\n").as_deref(), Some("off"));
        assert_eq!(normalize(Kind::Radio, "uwb", "Uwb state: disabled").as_deref(), Some("off"));
        assert_eq!(normalize(Kind::Usb, "functions", "mtp\n").as_deref(), Some("mtp"));
        assert_eq!(normalize(Kind::A11y, "enabled_accessibility_services", "\n").as_deref(), Some("null"));
        assert_eq!(set_argv(Kind::Usb, "functions", "none"), Some(v(&["svc", "usb", "setFunctions"])));
        assert!(set_argv(Kind::Setting, "global/x;y", "1").is_none());
        assert!(set_argv(Kind::NetType, "9", "1").is_none());
        assert!(set_argv(Kind::Ime, "default_input_method", "notanid").is_none());
    }

    /// Pixel 7 output of the get command for slot 0 (no NR, no iDEN).
    const REAL_ALLOWED: &str = "GPRS|EDGE|UMTS|CDMA|CDMA - EvDo rev. 0|CDMA - EvDo rev. A|CDMA - 1xRTT|HSDPA|HSUPA|HSPA|CDMA - EvDo rev. B|LTE|CDMA - eHRPD|HSPA+|GSM|LTE_CA";

    #[test]
    fn allowed_network_type_names_become_the_internal_bitmask() {
        // bits 0-9, 11-15 and 18
        let prior = normalize(Kind::NetType, "0", &format!("{REAL_ALLOWED}\n")).unwrap();
        assert_eq!(prior, "1001111101111111111");
        // The target as the device would print it compares equal to LTE_NR_MASK.
        let target = normalize(Kind::NetType, "0", "LTE|LTE_CA|NR\n").unwrap();
        assert_eq!(target, LTE_NR_MASK);
        assert!(same_value(Kind::NetType, &target, LTE_NR_MASK));
        assert!(!same_value(Kind::NetType, &prior, LTE_NR_MASK));
        // Restore sets the recorded prior value back, and the device's own listing is reproduced from it.
        assert_eq!(
            set_argv(Kind::NetType, "0", &prior),
            Some(v(&["cmd", "phone", "set-allowed-network-types-for-users", "-s", "0", "1001111101111111111"]))
        );
        assert_eq!(network_type_names(&prior).as_deref(), Some(REAL_ALLOWED));
        assert_eq!(network_type_names(LTE_NR_MASK).as_deref(), Some("LTE|LTE_CA|NR"));
        assert_eq!(read_argv(Kind::NetType, "0"), Some(v(&["cmd", "phone", "get-allowed-network-types-for-users", "-s", "0"])));
    }

    #[test]
    fn network_type_bits_follow_telephony_manager() {
        let bit = |name: &str| normalize(Kind::NetType, "0", name).unwrap();
        let one_at = |b: usize| format!("1{}", "0".repeat(b));
        for (name, b) in [
            ("GPRS", 0),
            ("EDGE", 1),
            ("UMTS", 2),
            ("CDMA", 3),
            ("CDMA - EvDo rev. 0", 4),
            ("CDMA - EvDo rev. A", 5),
            ("CDMA - 1xRTT", 6),
            ("HSDPA", 7),
            ("HSUPA", 8),
            ("HSPA", 9),
            ("iDEN", 10),
            ("CDMA - EvDo rev. B", 11),
            ("LTE", 12),
            ("CDMA - eHRPD", 13),
            ("HSPA+", 14),
            ("GSM", 15),
            ("TD_SCDMA", 16),
            ("IWLAN", 17),
            ("LTE_CA", 18),
            ("NR", 19),
        ] {
            assert_eq!(bit(name), one_at(b), "{name}");
        }
    }

    #[test]
    fn unknown_or_empty_network_type_names_fail_the_read() {
        for raw in ["", "\n", "LTE|FOO", "LTE|", "|LTE", "NR_SA", "11000001000000000000", "No valid subscription found."] {
            assert_eq!(normalize(Kind::NetType, "0", raw), None, "{raw:?}");
        }
    }

    #[test]
    fn empty_usb_functions_line_means_none() {
        assert_eq!(normalize(Kind::Usb, "functions", "\n").as_deref(), Some("none"));
        assert_eq!(normalize(Kind::Usb, "functions", "").as_deref(), Some("none"));
        assert_eq!(normalize(Kind::Usb, "functions", "none\n").as_deref(), Some("none"));
        assert_eq!(normalize(Kind::Usb, "functions", "mtp,adb\n").as_deref(), Some("mtp,adb"));
        assert_eq!(normalize(Kind::Usb, "functions", "bad;word\n"), None);
    }
}
