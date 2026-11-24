//! `/data/adb/aegischat/policy.conf` (root-only). Missing or invalid file
//! means dry-run mode with tier 1 only.
//!
//! Keys: `armed` (0/1), `dedicated_mode` (0/1), `app_cert_sha256` (64 hex,
//! pinned signing certificate of the App), `ims_uids` (comma list),
//! `magisk_pkg`, `avb_keys` (comma list of 64-hex AVB key digests),
//! `allowed_ifaces` (comma list of interfaces that may be up besides lo and
//! the IMS interface), `media_learning` (0/1, default 1),
//! `test_allow_usb_debug` (0/1, default 0; test devices only: the precheck
//! accepts USB debugging and the lockdown leaves the USB functions alone),
//! `test_allow_profile_owner` (0/1, default 0; test devices only: the precheck
//! accepts a work profile. A device owner is refused in every case).

use crate::codes::Code;
use crate::sysops::{read_text, SysError, SysOps};
use crate::valid::{hex_decode32, is_iface_name, is_lower_hex, is_package_name, parse_u32};

pub const POLICY_PATH: &str = "/data/adb/aegischat/policy.conf";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub armed: bool,
    pub dedicated_mode: bool,
    pub app_cert_sha256: Option<[u8; 32]>,
    pub ims_uids: Vec<u32>,
    pub magisk_pkg: Option<String>,
    pub avb_keys: Vec<String>,
    pub allowed_ifaces: Vec<String>,
    pub media_learning: bool,
    pub test_allow_usb_debug: bool,
    pub test_allow_profile_owner: bool,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            armed: false,
            dedicated_mode: false,
            app_cert_sha256: None,
            ims_uids: Vec::new(),
            magisk_pkg: None,
            avb_keys: Vec::new(),
            allowed_ifaces: Vec::new(),
            media_learning: true,
            test_allow_usb_debug: false,
            test_allow_profile_owner: false,
        }
    }
}

fn flag(v: &str) -> Result<bool, Code> {
    match v {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err(Code::PolicyInvalid),
    }
}

fn list<'a>(v: &'a str) -> impl Iterator<Item = &'a str> {
    v.split(',').map(str::trim).filter(|s| !s.is_empty())
}

impl Policy {
    pub fn parse(text: &str) -> Result<Policy, Code> {
        let mut p = Policy::default();
        let mut seen: Vec<String> = Vec::new();
        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (k, v) = line.split_once('=').ok_or(Code::PolicyInvalid)?;
            let (k, v) = (k.trim(), v.trim());
            if seen.iter().any(|s| s == k) {
                return Err(Code::PolicyInvalid);
            }
            seen.push(k.to_string());
            match k {
                "armed" => p.armed = flag(v)?,
                "dedicated_mode" => p.dedicated_mode = flag(v)?,
                "media_learning" => p.media_learning = flag(v)?,
                "test_allow_usb_debug" => p.test_allow_usb_debug = flag(v)?,
                "test_allow_profile_owner" => p.test_allow_profile_owner = flag(v)?,
                "app_cert_sha256" => p.app_cert_sha256 = Some(hex_decode32(v).ok_or(Code::PolicyInvalid)?),
                "ims_uids" => {
                    for u in list(v) {
                        p.ims_uids.push(parse_u32(u).ok_or(Code::PolicyInvalid)?);
                    }
                }
                "magisk_pkg" => {
                    if !is_package_name(v) {
                        return Err(Code::PolicyInvalid);
                    }
                    p.magisk_pkg = Some(v.to_string());
                }
                "avb_keys" => {
                    for key in list(v) {
                        let key = key.to_ascii_lowercase();
                        if !is_lower_hex(&key, 64) {
                            return Err(Code::PolicyInvalid);
                        }
                        p.avb_keys.push(key);
                    }
                }
                "allowed_ifaces" => {
                    for i in list(v) {
                        if !is_iface_name(i) {
                            return Err(Code::PolicyInvalid);
                        }
                        p.allowed_ifaces.push(i.to_string());
                    }
                }
                _ => return Err(Code::PolicyInvalid),
            }
        }
        Ok(p)
    }

    /// Returns the policy and an issue code. Missing file: defaults, no issue.
    /// Unreadable or invalid file: defaults (dry run), `PolicyInvalid`.
    pub fn load<S: SysOps + ?Sized>(sys: &mut S) -> (Policy, Option<Code>) {
        match read_text(sys, POLICY_PATH) {
            Ok(t) => match Policy::parse(&t) {
                Ok(p) => (p, None),
                Err(c) => (Policy::default(), Some(c)),
            },
            Err(SysError::NotFound) => (Policy::default(), None),
            Err(_) => (Policy::default(), Some(Code::PolicyInvalid)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_parsing_is_strict() {
        let p = Policy::parse("# c\narmed=1\ndedicated_mode=0\nims_uids=1001, 1002\nallowed_ifaces=dummy0\n");
        assert!(matches!(&p, Ok(x) if x.armed && !x.dedicated_mode && x.ims_uids == vec![1001, 1002]));
        assert_eq!(Policy::parse("armed=yes"), Err(Code::PolicyInvalid));
        assert_eq!(Policy::parse("armed=1\narmed=1"), Err(Code::PolicyInvalid));
        assert_eq!(Policy::parse("unknown=1"), Err(Code::PolicyInvalid));
        assert_eq!(Policy::parse("allowed_ifaces=wlan0 x"), Err(Code::PolicyInvalid));
        assert_eq!(Policy::parse(""), Ok(Policy::default()));
        assert!(!Policy::default().test_allow_usb_debug);
        assert!(matches!(Policy::parse("test_allow_usb_debug=1"), Ok(x) if x.test_allow_usb_debug && !x.armed));
        assert_eq!(Policy::parse("test_allow_usb_debug=yes"), Err(Code::PolicyInvalid));
        assert!(!Policy::default().test_allow_profile_owner);
        assert!(matches!(Policy::parse("test_allow_profile_owner=1"), Ok(x) if x.test_allow_profile_owner && !x.test_allow_usb_debug));
    }
}
