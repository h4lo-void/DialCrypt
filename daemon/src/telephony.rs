//! Parsers for telephony state. Inputs are untrusted text; every value is
//! validated before it is used in a rule or command.
//!
//! The IMS connection line, the siminfo rows and the IMS service output follow
//! captures from a Pixel 7 (Android 16, KernelSU); the fixtures in the tests
//! below are those captures with addresses replaced by documentation ones.
//! To be confirmed on device: only `mPreciseDataConnectionStates` was captured from
//! `dumpsys telephony.registry`; the layout of `mCallState`,
//! `getRilVoiceRadioTechnology`, `mSrvccState` and `Phone Id=` is still the
//! documented one.

use std::collections::BTreeSet;
use std::net::IpAddr;

use crate::codes::Code;
use crate::firewall::usable_addr;
use crate::valid::{is_iface_name, is_package_name};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rat {
    Lte,
    Nr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImsLink {
    pub iface: String,
    pub pcscf: Vec<IpAddr>,
    pub rat: Rat,
}

/// Value after `key` followed by `:` or `=`, up to a separator.
pub fn field<'a>(line: &'a str, keys: &[&str]) -> Option<&'a str> {
    for key in keys {
        let mut from = 0;
        while let Some(i) = line[from..].find(key) {
            let start = from + i + key.len();
            let rest = line[start..].trim_start();
            if let Some(r) = rest.strip_prefix(':').or_else(|| rest.strip_prefix('=')) {
                let r = r.trim_start();
                let end = r.find(|c: char| c == ',' || c == '}' || c == ']' || c.is_whitespace()).unwrap_or(r.len());
                return Some(&r[..end]);
            }
            from = start;
        }
    }
    None
}

fn segment<'a>(line: &'a str, starts: &[&str], ends: &[&str]) -> Option<&'a str> {
    let s = starts.iter().filter_map(|k| line.find(k)).min()?;
    let rest = &line[s..];
    let e = ends.iter().filter_map(|k| rest.find(k)).min().unwrap_or(rest.len());
    Some(&rest[..e])
}

fn tokens_lower(s: &str) -> Vec<String> {
    s.split(|c: char| !c.is_ascii_alphanumeric()).filter(|t| !t.is_empty()).map(|t| t.to_ascii_lowercase()).collect()
}

/// P-CSCF addresses of one connection: the list after `PcscfAddresses`
/// (Android 16) or `PcscfServers` (older builds). Entries carry a leading
/// slash and may repeat; the result has each address once.
fn parse_pcscf(conn: &str) -> Vec<IpAddr> {
    let Some(pos) = ["PcscfAddresses", "PcscfServers"].iter().filter_map(|k| conn.find(k)).min() else { return Vec::new() };
    let rest = &conn[pos..];
    let (Some(open), Some(close)) = (rest.find('['), rest.find(']')) else { return Vec::new() };
    if close < open {
        return Vec::new();
    }
    let mut out: Vec<IpAddr> = Vec::new();
    for a in rest[open + 1..close]
        .split(|c: char| c == ',' || c.is_whitespace())
        .map(|t| t.trim().trim_start_matches('/'))
        .filter_map(|t| t.parse::<IpAddr>().ok())
        .filter(usable_addr)
    {
        if !out.contains(&a) {
            out.push(a);
        }
    }
    out
}

/// One `mPreciseDataConnectionStates` line holds every connection of a phone
/// as `Pair{<apn>}= state: ..., Pair{...}= ...`; each piece starting at a
/// `Pair{` is one connection. A line without it is a single connection.
fn connections(line: &str) -> Vec<&str> {
    let starts: Vec<usize> = line.match_indices("Pair{").map(|(i, _)| i).collect();
    if starts.is_empty() {
        return vec![line];
    }
    starts.iter().enumerate().map(|(n, s)| &line[*s..starts.get(n + 1).copied().unwrap_or(line.len())]).collect()
}

/// Finds the connected IMS data connection (design 6.7 "address sources").
pub fn parse_ims_link(text: &str) -> Result<ImsLink, Code> {
    let mut seen = Code::ImsNotRegistered;
    for line in text.lines().flat_map(connections) {
        if !line.contains("InterfaceName") {
            continue;
        }
        let Some(apn) = segment(line, &["APN Setting", "apnSetting", "ApnSetting"], &["link properties", "linkProperties", "InterfaceName"]) else {
            continue;
        };
        let types = tokens_lower(apn);
        if !types.iter().any(|t| t == "ims") {
            continue;
        }
        let state = field(line, &["{ state", " state", "{state"]).unwrap_or("");
        if !state.eq_ignore_ascii_case("CONNECTED") {
            continue;
        }
        // The IMS connection must not also be the internet connection.
        if types.iter().any(|t| t == "default" || t == "internet") || line.contains("INTERNET") {
            return Err(Code::ImsOnInternetApn);
        }
        if field(line, &["transportType", "transport"]) != Some("WWAN") {
            seen = Code::ImsNotOnLteNr;
            continue;
        }
        let rat = match field(line, &["network type", "networkType"]) {
            Some("LTE") | Some("LTE_CA") => Rat::Lte,
            Some("NR") => Rat::Nr,
            _ => {
                seen = Code::ImsNotOnLteNr;
                continue;
            }
        };
        let iface = match field(line, &["InterfaceName"]) {
            Some(i) if is_iface_name(i) => i.to_string(),
            _ => return Err(Code::ImsLinkUnresolved),
        };
        let pcscf = parse_pcscf(line);
        if pcscf.is_empty() {
            return Err(Code::PcscfUnresolved);
        }
        return Ok(ImsLink { iface, pcscf, rat });
    }
    Err(seen)
}

/// `mCallState`: 0 idle, 1 ringing, 2 off-hook (dialing or in a call).
pub fn parse_call_state(text: &str) -> Option<u8> {
    field(text, &["mCallState"])?.parse().ok()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallBearer {
    /// Some phone is off-hook (dialing or in a call).
    pub in_call: bool,
    /// False when the phone in a call reports a voice bearer other than
    /// LTE/NR or an SRVCC handover that started or completed.
    pub ok: bool,
}

fn voice_rat_ok(v: &str) -> bool {
    let name = v.split_once('(').and_then(|(_, r)| r.strip_suffix(')')).unwrap_or(v);
    matches!(name, "LTE" | "LTE_CA" | "NR" | "14" | "19" | "20")
}

fn judge_phone(out: &mut CallBearer, state: Option<&str>, rat: Option<&str>, srvcc: Option<&str>) {
    if state == Some("2") {
        out.in_call = true;
        if rat.is_some_and(|r| !voice_rat_ok(r)) || matches!(srvcc, Some("0") | Some("1")) {
            out.ok = false;
        }
    }
}

/// E3 cross-check of the call itself. The registry dump is split per phone
/// (`Phone Id=`); for a phone with `mCallState=2` the voice radio technology
/// of its service state must be LTE/NR and `mSrvccState` must not be 0
/// (started) or 1 (completed).
///
/// To be confirmed on device: whether the target Pixel prints `getRilVoiceRadioTechnology`
/// and `mSrvccState`. A field that is absent cannot be judged and is not a
/// violation; in that case 2G/3G voice is still excluded by the allowed
/// network types (LTE/NR only, read back every 2 s) and by the IMS data
/// connection check.
pub fn parse_call_bearer(text: &str) -> CallBearer {
    let mut out = CallBearer { in_call: false, ok: true };
    let (mut state, mut rat, mut srvcc): (Option<&str>, Option<&str>, Option<&str>) = (None, None, None);
    for line in text.lines() {
        if line.contains("Phone Id=") {
            judge_phone(&mut out, state, rat, srvcc);
            (state, rat, srvcc) = (None, None, None);
        }
        state = state.or_else(|| field(line, &["mCallState"]));
        rat = rat.or_else(|| field(line, &["getRilVoiceRadioTechnology"]));
        srvcc = srvcc.or_else(|| field(line, &["mSrvccState"]));
    }
    judge_phone(&mut out, state, rat, srvcc);
    out
}

/// Package name reported by `cmd phone ims get-ims-service`.
pub fn parse_ims_service_package(text: &str) -> Option<String> {
    text.split(|c: char| c.is_whitespace() || c == ',' || c == ':' || c == '[' || c == ']')
        .filter(|t| is_package_name(t))
        .last()
        .map(str::to_string)
}

/// `content query --uri content://telephony/siminfo --projection
/// _id:volte_vt_enabled:sim_id`. Rows with sim_id < 0 are profiles that are not
/// in a slot and are ignored. Every other row is an active SIM whose slot is
/// returned; its VoLTE switch must not be off: 0 is off, -1 is "never changed,
/// carrier default" (on) and 1 is on. Any other value cannot be judged and
/// counts as off.
///
/// Returns the slots of all active SIMs together with the verdict, so that a
/// failed VoLTE check does not hide which slots exist.
pub fn scan_siminfo(text: &str) -> (Vec<u8>, Result<(), Code>) {
    let mut slots = BTreeSet::new();
    let mut active = 0;
    let mut off = false;
    for line in text.lines().filter(|l| l.trim_start().starts_with("Row:")) {
        let sim: i64 = field(line, &["sim_id"]).and_then(|s| s.parse().ok()).unwrap_or(-1);
        if sim < 0 {
            continue;
        }
        active += 1;
        if !matches!(field(line, &["volte_vt_enabled"]), Some("1") | Some("-1")) {
            off = true;
        }
        if sim <= 3 {
            slots.insert(sim as u8);
        }
    }
    let verdict = if active == 0 {
        Err(Code::ImsNotRegistered)
    } else if off {
        Err(Code::VolteOff)
    } else {
        Ok(())
    };
    (slots.into_iter().collect(), verdict)
}

/// [`scan_siminfo`] as one result: the slots when every active SIM passes.
pub fn parse_siminfo(text: &str) -> Result<Vec<u8>, Code> {
    let (slots, verdict) = scan_siminfo(text);
    verdict.map(|()| slots)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) const REGISTRY: &str = "  mCallState=0\n  mPreciseDataConnectionStates:\n    { state: CONNECTED, transport: WWAN, id: 1, network type: LTE, APN Setting: [ApnSetting] Internet, 2730, 310260, fast.example, , null, null, null, , null, -1, default | mms | supl, IPV6, IPV4V6, link properties: {InterfaceName: rmnet0 LinkAddresses: [ 2607:fb90::5/64 ] PcscfServers: [ ] }, default network fail: NONE }\n    { state: CONNECTED, transport: WWAN, id: 2, network type: LTE, APN Setting: [ApnSetting] IMS, 2731, 310260, ims, , null, null, null, , null, -1, ims, IPV6, IPV4V6, link properties: {InterfaceName: rmnet1 LinkAddresses: [ 2607:fb90:8::5/64 ] DnsAddresses: [ ] PcscfServers: [ /10.0.0.10,/2607:fb90:1::10 ] MTU: 1430}, default network fail: NONE }\n";

    #[test]
    fn parses_ims_link_from_fixture() {
        let l = parse_ims_link(REGISTRY);
        assert!(matches!(&l, Ok(x) if x.iface == "rmnet1" && x.pcscf.len() == 2 && x.rat == Rat::Lte), "{l:?}");
        assert_eq!(parse_call_state(REGISTRY), Some(0));
        let iwlan = REGISTRY.replace("transport: WWAN, id: 2", "transport: IWLAN, id: 2");
        assert_eq!(parse_ims_link(&iwlan), Err(Code::ImsNotOnLteNr));
        let g3 = REGISTRY.replace("id: 2, network type: LTE", "id: 2, network type: UMTS");
        assert_eq!(parse_ims_link(&g3), Err(Code::ImsNotOnLteNr));
        let shared = REGISTRY.replace("-1, ims, IPV6", "-1, default | ims, IPV6");
        assert_eq!(parse_ims_link(&shared), Err(Code::ImsOnInternetApn));
        let nopc = REGISTRY.replace("/10.0.0.10,/2607:fb90:1::10", "");
        assert_eq!(parse_ims_link(&nopc), Err(Code::PcscfUnresolved));
        let evil = REGISTRY.replace("InterfaceName: rmnet1", "InterfaceName: rmnet1;reboot");
        assert_eq!(parse_ims_link(&evil), Err(Code::ImsLinkUnresolved));
        assert_eq!(parse_ims_link("nothing"), Err(Code::ImsNotRegistered));
    }

    /// Pixel 7, Android 16: the `mPreciseDataConnectionStates` line of phone 0
    /// as captured (IP addresses replaced). It holds the IMS and the internet
    /// connection; phone 1 has no connection.
    pub(crate) const REAL_IMS_STATES: &str = r#"    mPreciseDataConnectionStates={Pair{1 [ApnSetting] IMS, 62, 00101, ims, , null, , null, null, 0, ims, IPV4V6, IP, true, 0, false, 0, 0, 0, 0, 0, null, , false, LTE|IWLAN|LTE_CA|NR, UNKNOWN, 0, -1, -1, false, 3, 961, false, UNEDITED}= state: CONNECTED, transport: WWAN, id: 3, netId: 101, network type: LTE, APN Setting: [ApnSetting] IMS, 62, 00101, ims, , null, , null, null, 0, ims, IPV4V6, IP, true, 0, false, 0, 0, 0, 0, 0, null, , false, LTE|IWLAN|LTE_CA|NR, UNKNOWN, 0, -1, -1, false, 3, 961, false, UNEDITED, link properties: {InterfaceName: rmnet2 LinkAddresses: [ 2001:db8::1/64,192.0.2.1/32 ] DnsAddresses: [ ] PcscfAddresses: [ /2001:db8::1,/2001:db8::1,/192.0.2.1,/192.0.2.1 ] Domains: null MTU: 1310 TcpBufferSizes: 2097152,6291456,16777216,512000,2097152,8388608 Routes: [ ::/0 -> :: rmnet2 mtu 1310,192.0.2.1/0 -> 192.0.2.1 rmnet2 mtu 1310 ]}, default QoS: EpsQos { qosClassId=5 downlink=Bandwidth { maxBitrateKbps=-1 guaranteedBitrateKbps=-1} uplink=Bandwidth { maxBitrateKbps=-1 guaranteedBitrateKbps=-1}}, fail cause: NONE(0x0), network validation status: unsupported, Pair{1 [ApnSetting] Example Carrier (Internet), 60, 00101, internet, , null, , null, null, 0, supl | hipri | default, IPV4V6, IP, true, 0, false, 0, 0, 0, 0, 0, null, , false, UNKNOWN, UNKNOWN, 0, -1, -1, false, 3, 961, false, UNEDITED}= state: CONNECTED, transport: WWAN, id: 2, netId: 100, network type: LTE, APN Setting: [ApnSetting] Example Carrier (Internet), 60, 00101, internet, , null, , null, null, 0, supl | hipri | default, IPV4V6, IP, true, 0, false, 0, 0, 0, 0, 0, null, , false, UNKNOWN, UNKNOWN, 0, -1, -1, false, 3, 961, false, UNEDITED, link properties: {InterfaceName: rmnet1 LinkAddresses: [ 192.0.2.1/32 ] DnsAddresses: [ /2001:db8::1,/2001:db8::1,/192.0.2.1,/192.0.2.1 ] Domains: null MTU: 1500 TcpBufferSizes: 2097152,6291456,16777216,512000,2097152,8388608 Routes: [ 192.0.2.1/0 -> 192.0.2.1 rmnet1 mtu 1500 ]}, default QoS: EpsQos { qosClassId=8 downlink=Bandwidth { maxBitrateKbps=-1 guaranteedBitrateKbps=-1} uplink=Bandwidth { maxBitrateKbps=-1 guaranteedBitrateKbps=-1}}, fail cause: NONE(0x0), network validation status: unsupported}"#;

    /// Registry text around the captured line. To be confirmed on device: the `mCallState` line.
    pub(crate) fn real_registry() -> String {
        format!("  mCallState=0\n{REAL_IMS_STATES}\n    mPreciseDataConnectionStates={{}}\n")
    }

    /// Pixel 7 siminfo query: slot 0 holds the only SIM; row 14 is an unused
    /// profile with VoLTE explicitly off.
    pub(crate) fn real_siminfo() -> String {
        (0..26)
            .map(|i| {
                let volte = if i == 13 { 0 } else { -1 };
                let sim = if i == 9 { 0 } else { -1 };
                format!("Row: {i} _id={}, volte_vt_enabled={volte}, sim_id={sim}\n", i + 1)
            })
            .collect()
    }

    #[test]
    fn real_pixel7_ims_line_yields_interface_and_pcscf() {
        let want = Ok(ImsLink {
            iface: "rmnet2".to_string(),
            pcscf: vec!["2001:db8::1".parse().unwrap(), "192.0.2.1".parse().unwrap()],
            rat: Rat::Lte,
        });
        let reg = real_registry();
        assert_eq!(parse_ims_link(&reg), want, "rmnet1 is the internet connection of the same line");
        assert_eq!(parse_call_state(&reg), Some(0));

        // The result does not depend on the order of the connections in the line.
        let at: Vec<usize> = REAL_IMS_STATES.match_indices("Pair{").map(|(i, _)| i).collect();
        assert_eq!(at.len(), 2);
        let swapped = format!(
            "{}{}, {}}}",
            &REAL_IMS_STATES[..at[0]],
            REAL_IMS_STATES[at[1]..].trim_end_matches('}'),
            REAL_IMS_STATES[at[0]..at[1]].trim_end_matches(", ")
        );
        assert!(swapped.find("Pair{1 [ApnSetting] IMS").unwrap() > swapped.find("(Internet)").unwrap());
        assert_eq!(parse_ims_link(&swapped), want);

        // Rejections stay in force on the real layout.
        let bad = |from: &str, to: &str| {
            assert!(REAL_IMS_STATES.contains(from), "fixture lacks {from}");
            parse_ims_link(&REAL_IMS_STATES.replace(from, to))
        };
        assert_eq!(bad("transport: WWAN, id: 3", "transport: IWLAN, id: 3"), Err(Code::ImsNotOnLteNr));
        assert_eq!(bad("netId: 101, network type: LTE", "netId: 101, network type: UMTS"), Err(Code::ImsNotOnLteNr));
        assert_eq!(bad("state: CONNECTED, transport: WWAN, id: 3", "state: CONNECTING, transport: WWAN, id: 3"), Err(Code::ImsNotRegistered));
        assert_eq!(bad(", 0, ims, IPV4V6", ", 0, default | ims, IPV4V6"), Err(Code::ImsOnInternetApn));
        assert_eq!(bad("unsupported, Pair{", "unsupported INTERNET, Pair{"), Err(Code::ImsOnInternetApn));
        assert_eq!(bad("InterfaceName: rmnet2", "InterfaceName: rmnet2;reboot"), Err(Code::ImsLinkUnresolved));
        assert_eq!(bad("PcscfAddresses: [ /2001:db8::1,/2001:db8::1,/192.0.2.1,/192.0.2.1 ]", "PcscfAddresses: [ ]"), Err(Code::PcscfUnresolved));
        assert_eq!(parse_ims_link("    mPreciseDataConnectionStates={}\n"), Err(Code::ImsNotRegistered));
    }

    #[test]
    fn call_bearer_cross_check() {
        let b = |t: &str| parse_call_bearer(t);
        assert_eq!(b(REGISTRY), CallBearer { in_call: false, ok: true });
        assert_eq!(b("mCallState=2\n"), CallBearer { in_call: true, ok: true }, "absent fields are not judged");
        assert!(b("mCallState=2\n mServiceState={getRilVoiceRadioTechnology=14(LTE), x}\n mSrvccState=-1\n").ok);
        assert!(b("mCallState=2\n mServiceState={getRilVoiceRadioTechnology=20(NR), x}\n").ok);
        assert!(!b("mCallState=2\n mServiceState={getRilVoiceRadioTechnology=3(UMTS), x}\n").ok);
        assert!(!b("mCallState=2\n mServiceState={getRilVoiceRadioTechnology=16(GSM)}\n").ok);
        assert!(!b("mCallState=2\n mSrvccState=1\n").ok);
        assert!(b("mCallState=0\n mServiceState={getRilVoiceRadioTechnology=3(UMTS)}\n").ok, "idle phone is not judged");
        let dsds = "Phone Id=0\n mCallState=0\n getRilVoiceRadioTechnology=0(Unknown)\nPhone Id=1\n mCallState=2\n getRilVoiceRadioTechnology=14(LTE)\n";
        assert_eq!(b(dsds), CallBearer { in_call: true, ok: true });
        assert!(!b(&dsds.replace("14(LTE)", "3(UMTS)")).ok);
    }

    #[test]
    fn siminfo_volte_default_and_inactive_profiles() {
        let real = real_siminfo();
        assert!(real.contains("volte_vt_enabled=0, sim_id=-1"), "fixture keeps the off-but-unused profile");
        assert_eq!(parse_siminfo(&real), Ok(vec![0]), "-1 is the carrier default (on); the sim_id=-1 profile with 0 is ignored");
        assert_eq!(parse_siminfo(&real.replace("Row: 9 _id=10, volte_vt_enabled=-1, sim_id=0", "Row: 9 _id=10, volte_vt_enabled=0, sim_id=0")), Err(Code::VolteOff));
        assert_eq!(parse_siminfo(&real.replace("Row: 9 _id=10, volte_vt_enabled=-1, sim_id=0", "Row: 9 _id=10, volte_vt_enabled=1, sim_id=0")), Ok(vec![0]));
        assert_eq!(parse_siminfo(&real.replace("Row: 9 _id=10, volte_vt_enabled=-1, sim_id=0", "Row: 9 _id=10, volte_vt_enabled=-1, sim_id=-1")), Err(Code::ImsNotRegistered));
        assert_eq!(parse_siminfo("Row: 0 _id=1, volte_vt_enabled=0, sim_id=-1\n"), Err(Code::ImsNotRegistered));
        assert_eq!(parse_siminfo("Row: 0 _id=1, volte_vt_enabled=1, sim_id=0\n"), Ok(vec![0]));
        let dual = format!("{real}Row: 26 _id=27, volte_vt_enabled=-1, sim_id=1\n");
        assert_eq!(parse_siminfo(&dual), Ok(vec![0, 1]));
        assert_eq!(parse_siminfo(&dual.replace("volte_vt_enabled=-1, sim_id=1", "volte_vt_enabled=0, sim_id=1")), Err(Code::VolteOff));
    }

    #[test]
    fn ims_service_package_from_real_outputs() {
        // -s 0 -c prints an empty line, -s 0 -d the package.
        assert_eq!(parse_ims_service_package("\n"), None);
        assert_eq!(parse_ims_service_package(""), None);
        assert_eq!(parse_ims_service_package("com.shannon.imsservice\n").as_deref(), Some("com.shannon.imsservice"));
        assert_eq!(parse_ims_service_package("ims get-ims-service requires either \"-c\" or \"-d\" to be set.\n"), None);
        assert_eq!(parse_ims_service_package("Returned package: com.shannon.imsservice\n").as_deref(), Some("com.shannon.imsservice"));
    }
}
