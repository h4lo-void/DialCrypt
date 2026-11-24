//! Independent acceptance tests for the caller signature check of aegiscalld
//! (`pkgxml::package_signers` and `peer::authenticate`). Black box over the public
//! API with hostile and damaged abx2xml output. Nothing here touches a device.
//! Tests named finding_* pin down behaviour reported as a finding.

use std::collections::HashMap;
use std::time::Instant;

use aegiscalld::codes::Code;
use aegiscalld::peer::{authenticate, APP_PACKAGE, PACKAGES_LIST, PACKAGES_XML_CMD};
use aegiscalld::pkgxml::{package_signers, Signers, MAX_CERT, MAX_XML, MIN_CERT};
use aegiscalld::sysops::{Mutation, SysError, SysOps};
use sha2::{Digest, Sha256};

const PKG: &str = "io.github.h4lovoid.dialcrypt";
const UID: u32 = 10297;

// ---------------------------------------------------------------- test double

struct Dev {
    list: String,
    xml: Result<String, SysError>,
    xml_reads: u32,
}

impl SysOps for Dev {
    fn read_cmd(&mut self, argv: &[&str]) -> Result<String, SysError> {
        if argv == &PACKAGES_XML_CMD[..] {
            self.xml_reads += 1;
            self.xml.clone()
        } else {
            Err(SysError::Unsupported)
        }
    }
    fn read_file(&mut self, path: &str) -> Result<Vec<u8>, SysError> {
        if path == PACKAGES_LIST {
            Ok(self.list.clone().into_bytes())
        } else {
            Err(SysError::NotFound)
        }
    }
    fn read_file_range(&mut self, _path: &str, _offset: u64, _len: usize) -> Result<Vec<u8>, SysError> {
        Err(SysError::Unsupported)
    }
    fn file_size(&mut self, _path: &str) -> Result<u64, SysError> {
        Err(SysError::Unsupported)
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
        panic!("authentication must never change the system");
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
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

// ------------------------------------------------------------------- fixtures

/// Deterministic stand-in for a DER certificate: SEQUENCE header carrying the
/// real length, then noise.
fn cert(seed: u32, len: usize) -> Vec<u8> {
    let body = len - 4;
    let mut v = vec![0x30, 0x82, (body >> 8) as u8, body as u8];
    let mut x = seed.wrapping_mul(2_654_435_761).wrapping_add(0x9e37_79b9);
    while v.len() < len {
        x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        v.push((x >> 24) as u8);
    }
    v
}

/// The pinned certificate. 1310 bytes, so its hex starts with 3082051a like the field capture.
fn good() -> Vec<u8> {
    cert(1, 1310)
}

fn evil() -> Vec<u8> {
    cert(2, 1187)
}

fn plat() -> Vec<u8> {
    cert(3, 933)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn digest(c: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(c));
    out
}

const HEAD: &str = "<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>\n<packages>\n  <version sdkVersion=\"36\" databaseVersion=\"3\" buildFingerprint=\"google/cheetah/cheetah:16/BP2A.250805.005/13691446:user/release-keys\" volumeUuid=\"\" />\n  <permission-trees />\n  <permissions>\n    <item name=\"android.permission.REAL_GET_TASKS\" package=\"android\" protection=\"18\" />\n  </permissions>\n";
const TAIL: &str = "  <shared-user name=\"android.uid.system\" userId=\"1000\">\n    <sigs count=\"1\" schemeVersion=\"3\">\n      <cert index=\"3\" />\n    </sigs>\n  </shared-user>\n  <keyset-settings version=\"1\">\n    <keys>\n      <public-key identifier=\"1\" value=\"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\" />\n    </keys>\n    <keysets>\n      <keyset identifier=\"1\">\n        <key-id identifier=\"1\" />\n      </keyset>\n    </keysets>\n    <lastIssuedKeyId value=\"1\" />\n    <lastIssuedKeySetId value=\"1\" />\n  </keyset-settings>\n</packages>\n";

fn sigs(count: &str, certs: &[(u32, Option<&[u8]>)]) -> String {
    let mut s = format!("    <sigs count=\"{count}\" schemeVersion=\"2\">\n");
    for (i, k) in certs {
        match k {
            Some(k) => s.push_str(&format!("      <cert index=\"{i}\" key=\"{}\" />\n", hex(k))),
            None => s.push_str(&format!("      <cert index=\"{i}\" />\n")),
        }
    }
    s.push_str("    </sigs>\n");
    s
}

fn element(tag: &str, name: &str, uid: u32, inner: &str) -> String {
    format!("  <{tag} name=\"{name}\" codePath=\"/system/priv-app/DialCrypt\" nativeLibraryPath=\"/system/priv-app/DialCrypt/lib\" publicFlags=\"810073605\" privateFlags=\"-1946152952\" ft=\"11e8f7d4c00\" ut=\"11e8f7d4c00\" version=\"12\" userId=\"{uid}\" isOrphaned=\"true\" loadingProgress=\"1.0\">\n{inner}    <perms>\n      <item name=\"android.permission.INTERNET\" granted=\"true\" flags=\"0\" />\n    </perms>\n    <proper-signing-keyset identifier=\"1\" />\n  </{tag}>\n")
}

fn app(inner: &str) -> String {
    element("package", PKG, UID, inner)
}

fn app_signed(c: &[u8]) -> String {
    app(&sigs("1", &[(126, Some(c))]))
}

fn other(name: &str, uid: u32, index: u32, key: Option<&[u8]>) -> String {
    element("package", name, uid, &sigs("1", &[(index, key)]))
}

fn doc(body: &str) -> String {
    let p = plat();
    format!("{HEAD}{}{body}{TAIL}", other("android", 1000, 3, Some(&p[..])))
}

fn list() -> String {
    format!("com.vendor.tool 10310 0 /data/user/0/com.vendor.tool default:targetSdkVersion=34 none 0 0 1 @null\n{PKG} {UID} 0 /data/user/0/{PKG} platform:privapp:targetSdkVersion=35 3003 0 12 1 @system\ncom.evil.app 10301 0 /data/user/0/com.evil.app default:targetSdkVersion=35 none 0 0 1 @null\n")
}

fn auth_with(xml: Result<String, SysError>, uid: u32, list: String, pinned: &[u8; 32]) -> Result<(), Code> {
    let mut dev = Dev { list, xml, xml_reads: 0 };
    authenticate(&mut dev, uid, Some(pinned))
}

fn auth(xml: &str) -> Result<(), Code> {
    auth_with(Ok(xml.to_string()), UID, list(), &digest(&good()))
}

fn is_good(r: &Option<Signers>) -> bool {
    matches!(r, Some(s) if !s.rotated && s.current.len() == 1 && s.current[0] == good())
}

/// The record is read as exactly this one certificate, and only the pinned one authenticates.
#[track_caller]
fn exactly(xml: &str, c: &[u8], what: &str) {
    assert_eq!(package_signers(xml, PKG), Some(Signers { current: vec![c.to_vec()], rotated: false }), "{what}: signers");
    let want = if c == &good()[..] { Ok(()) } else { Err(Code::PeerSignatureMismatch) };
    assert_eq!(auth(xml), want, "{what}: authenticate");
}

#[track_caller]
fn accepted(xml: &str, what: &str) {
    exactly(xml, &good(), what);
}

#[track_caller]
fn unreadable(xml: &str, what: &str) {
    assert_eq!(package_signers(xml, PKG), None, "{what}: signers");
    assert_eq!(auth(xml), Err(Code::PeerSignatureSourceMissing), "{what}: authenticate");
}

/// A record was read, but it does not authenticate.
#[track_caller]
fn mismatch(xml: &str, what: &str) {
    assert!(package_signers(xml, PKG).is_some(), "{what}: signers");
    assert_eq!(auth(xml), Err(Code::PeerSignatureMismatch), "{what}: authenticate");
}

/// Refused one way or the other, and the pinned certificate is not what was read.
#[track_caller]
fn never_good(xml: &str, what: &str) {
    let r = package_signers(xml, PKG);
    assert!(!matches!(&r, Some(s) if s.current.iter().any(|c| *c == good())), "{what}: the pinned certificate was taken");
    assert!(matches!(auth(xml), Err(Code::PeerSignatureSourceMissing) | Err(Code::PeerSignatureMismatch)), "{what}: authenticate");
}

// ------------------------------------------------------- criterion 2: accepts

#[test]
fn c2_accepts_field_layout_crlf_and_index_only_reference() {
    assert_eq!(APP_PACKAGE, PKG);
    let (gv, ev, pv) = (good(), evil(), plat());
    let (g, e, p): (&[u8], &[u8], &[u8]) = (&gv, &ev, &pv);
    let d = doc(&app_signed(g));
    assert!(d.contains(&format!("  <package name=\"{PKG}\" codePath=\"/system/priv-app/DialCrypt\" ")));
    assert!(d.contains("    <sigs count=\"1\" schemeVersion=\"2\">\n      <cert index=\"126\" key=\"3082051a"));
    accepted(&d, "field layout");
    let read = package_signers(&d, PKG).expect("field layout");
    assert_eq!(digest(&read.current[0]), digest(g));
    assert_eq!(auth_with(Ok(d.clone()), UID, list(), &digest(e)), Err(Code::PeerSignatureMismatch), "another pin");

    let crlf = d.replace('\n', "\r\n");
    assert!(crlf.contains("\r\n") && crlf.len() > d.len());
    accepted(&crlf, "CRLF");
    accepted(&format!("\u{feff}{d}"), "byte order mark");
    accepted(&d.replace('\n', ""), "no line breaks");

    let by_ref = app(&sigs("1", &[(126, None)]));
    assert!(by_ref.contains("<cert index=\"126\" />") && !by_ref.contains("key="));
    accepted(&doc(&format!("{}{by_ref}", other("com.vendor.tool", 10310, 126, Some(g)))), "index defined by the package before");
    accepted(
        &doc(&format!("{}{}{}{by_ref}", other("com.vendor.tool", 10310, 126, Some(g)), other("com.vendor.b", 10311, 126, None), other("com.vendor.c", 10312, 41, Some(e)))),
        "index defined three packages earlier",
    );
    accepted(&doc(&format!("{}{by_ref}", other("com.vendor.tool", 10310, 126, Some(g))).replace('\n', "\r\n")), "index reference with CRLF");
    accepted(&doc(&format!("{}{by_ref}", element("updated-package", "com.vendor.tool", 10310, &sigs("1", &[(126, Some(g))])))), "index defined under updated-package before");
    let lineage = format!(
        "  <package name=\"com.vendor.rotated\" userId=\"10312\">\n    <sigs count=\"1\" schemeVersion=\"3\">\n      <cert index=\"40\" key=\"{}\" />\n      <pastSigs count=\"2\" schemeVersion=\"3\">\n        <cert index=\"126\" key=\"{}\" flags=\"17\" />\n        <cert index=\"40\" flags=\"2\" />\n      </pastSigs>\n    </sigs>\n  </package>\n",
        hex(p).replace("3082", "3083"),
        hex(g)
    );
    accepted(&doc(&format!("{lineage}{by_ref}")), "index defined in the pastSigs of a package before");
}

// ------------------------------------------------------- criterion 3: rejects

#[test]
fn c3_rejects_missing_duplicate_and_malformed_records() {
    let (gv, ev) = (good(), evil());
    let (g, e): (&[u8], &[u8]) = (&gv, &ev);
    let gh = hex(g);
    let app_g = app_signed(g);
    let app_e = app_signed(e);
    let with_key = |k: &str| app(&format!("    <sigs count=\"1\" schemeVersion=\"2\">\n      <cert index=\"126\" key=\"{k}\" />\n    </sigs>\n"));

    // package not found
    unreadable(&doc(""), "no package");
    unreadable(&doc(&other("com.vendor.tool", 10310, 126, Some(g))), "only another package signed by the pinned key");

    // the name twice
    unreadable(&doc(&format!("{app_g}{app_g}")), "same record twice");
    unreadable(&doc(&format!("{app_e}{app_g}")), "attacker record then pinned record");
    unreadable(&doc(&format!("{app_g}{app_e}")), "pinned record then attacker record");
    unreadable(&doc(&format!("{app_g}{}{app_g}", other("com.vendor.tool", 10310, 41, Some(e)))), "twice with a package between");
    unreadable(&doc(&format!("{app_g}  <package name=\"{PKG}\" />\n")), "second one empty");
    unreadable(&doc(&format!("  <package name=\"{PKG}\" />\n{app_g}")), "first one empty");

    // updated-package only
    unreadable(&doc(&element("updated-package", PKG, UID, &sigs("1", &[(126, Some(g))]))), "only updated-package");
    exactly(&doc(&format!("{}{}", element("updated-package", PKG, UID, &sigs("1", &[(57, Some(g))])), app_e)), e, "pinned key only on updated-package before");
    exactly(&doc(&format!("{}{}", app_e, element("updated-package", PKG, UID, &sigs("1", &[(57, Some(g))])))), e, "pinned key only on updated-package after");

    // sigs missing
    unreadable(&doc(&app("")), "no sigs");
    unreadable(&doc(&app("    <sigs count=\"1\" schemeVersion=\"2\" />\n")), "empty sigs claiming one");
    unreadable(&doc(&app("    <sigs count=\"0\" schemeVersion=\"2\" />\n")), "empty sigs");
    unreadable(&doc(&app(&format!("    <x>\n{}    </x>\n", sigs("1", &[(126, Some(g))])))), "sigs only inside another child");
    unreadable(&doc(&app(&format!("{0}{0}", sigs("1", &[(126, Some(g))])))), "two sigs");

    // count and number of certificates disagree
    for c in ["0", "2", "", "one", "-1", "+1", " 1", "1 ", "1.0", "0x1", "4294967297", "99999999999", "\u{ff11}"] {
        unreadable(&doc(&app(&sigs(c, &[(126, Some(g))]))), &format!("count {c:?} with one certificate"));
    }
    unreadable(&doc(&app_g.replacen(" count=\"1\"", "", 1)), "count missing");
    unreadable(&doc(&app(&sigs("1", &[(126, Some(g)), (127, Some(e))]))), "count 1 with two certificates");
    unreadable(&doc(&app(&sigs("3", &[(126, Some(g)), (127, Some(e))]))), "count 3 with two certificates");

    // two certificates
    mismatch(&doc(&app(&sigs("2", &[(126, Some(g)), (127, Some(e))]))), "pinned then attacker");
    mismatch(&doc(&app(&sigs("2", &[(127, Some(e)), (126, Some(g))]))), "attacker then pinned");
    mismatch(&doc(&app(&sigs("2", &[(126, Some(g)), (126, None)]))), "pinned twice");

    // index not defined
    unreadable(&doc(&app(&sigs("1", &[(999, None)]))), "index never defined");
    unreadable(&doc(&format!("{}{}", app(&sigs("1", &[(300, None)])), other("com.vendor.late", 10311, 300, Some(g)))), "index defined only later");
    unreadable(&doc(&format!("{}{}", app(&sigs("1", &[(300, None)])), element("updated-package", PKG, UID, &sigs("1", &[(300, Some(g))])))), "index defined only by a later updated-package");
    unreadable(&doc(&app_g.replace(" index=\"126\"", "")), "index attribute missing");
    for i in ["", "-1", "abc", "126 ", "1e2", "4294967296"] {
        unreadable(&doc(&app_g.replace("index=\"126\"", &format!("index=\"{i}\""))), &format!("index {i:?}"));
    }

    // one index, two keys
    unreadable(&doc(&format!("{}{app_g}", other("com.vendor.tool", 10310, 126, Some(e)))), "index defined before with another key");
    unreadable(&doc(&format!("{app_g}{}", other("com.vendor.tool", 10310, 126, Some(e)))), "index defined again later with another key");
    unreadable(&doc(&format!("{app_g}{}", element("updated-package", PKG, UID, &sigs("1", &[(126, Some(e))])))), "conflict under updated-package");
    unreadable(&doc(&format!("{app_g}{}", element("shared-user", "android.uid.evil", 10400, &sigs("1", &[(126, Some(e))])))), "conflict under shared-user");
    unreadable(&doc(&app(&sigs("2", &[(126, Some(g)), (126, Some(e))]))), "conflict inside the record");
    unreadable(
        &doc(&format!("{app_g}  <package name=\"com.vendor.rotated\" userId=\"10312\">\n    <sigs count=\"1\" schemeVersion=\"3\">\n      <cert index=\"40\" key=\"{0}\" />\n      <pastSigs count=\"1\" schemeVersion=\"3\">\n        <cert index=\"126\" key=\"{0}\" flags=\"17\" />\n      </pastSigs>\n    </sigs>\n  </package>\n", hex(e))),
        "conflict in the pastSigs of another package",
    );

    // key not hex, odd length, empty
    unreadable(&doc(&with_key(&format!("zz{}", &gh[2..]))), "key not hex at the start");
    unreadable(&doc(&with_key(&format!("{}g", &gh[..gh.len() - 1]))), "key not hex at the end");
    unreadable(&doc(&with_key(&format!("{} {}", &gh[..10], &gh[11..]))), "key with a space");
    unreadable(&doc(&with_key(&format!("0x{}", &gh[2..]))), "key with 0x");
    unreadable(&doc(&with_key(&format!("{gh}0"))), "key one digit too long");
    unreadable(&doc(&with_key(&gh[..gh.len() - 1])), "key one digit short");
    unreadable(&doc(&with_key("")), "key empty");
    unreadable(&doc(&with_key(" ")), "key blank");
    unreadable(&doc(&with_key(&hex(&cert(7, MIN_CERT - 1)))), "key below the minimum");
    unreadable(&doc(&with_key(&hex(&cert(7, MAX_CERT + 1)))), "key above the maximum");
    for len in [MIN_CERT, MAX_CERT] {
        let c = cert(7, len);
        assert_eq!(package_signers(&doc(&app_signed(&c)), PKG), Some(Signers { current: vec![c.clone()], rotated: false }), "certificate of {len} bytes");
    }
}

#[test]
fn c3_rejects_a_record_with_past_sigs() {
    let (gv, ev) = (good(), evil());
    let (g, e): (&[u8], &[u8]) = (&gv, &ev);
    let rotated = Some(Signers { current: vec![gv.clone()], rotated: true });
    let field = app(&format!(
        "    <sigs count=\"1\" schemeVersion=\"3\">\n      <cert index=\"126\" key=\"{}\" />\n      <pastSigs count=\"2\" schemeVersion=\"3\">\n        <cert index=\"125\" key=\"{}\" flags=\"17\" />\n        <cert index=\"126\" flags=\"2\" />\n      </pastSigs>\n    </sigs>\n",
        hex(g),
        hex(e)
    ));
    assert_eq!(package_signers(&doc(&field), PKG), rotated, "platform layout");
    assert_eq!(auth(&doc(&field)), Err(Code::PeerSignatureMismatch), "platform layout");
    let variants = [
        app(&format!("    <sigs count=\"1\" schemeVersion=\"3\">\n      <cert index=\"126\" key=\"{}\" />\n      <pastSigs count=\"0\" />\n    </sigs>\n", hex(g))),
        app(&format!("    <sigs count=\"1\" schemeVersion=\"3\">\n      <pastSigs count=\"0\"></pastSigs>\n      <cert index=\"126\" key=\"{}\" />\n    </sigs>\n", hex(g))),
        app(&format!("{}    <pastSigs count=\"0\" />\n", sigs("1", &[(126, Some(g))]))),
        app(&format!("    <pastSigs count=\"0\" />\n{}", sigs("1", &[(126, Some(g))]))),
        app(&format!("{}    <x>\n      <y>\n        <pastSigs />\n      </y>\n    </x>\n", sigs("1", &[(126, Some(g))]))),
    ];
    for (i, v) in variants.iter().enumerate() {
        assert_eq!(package_signers(&doc(v), PKG), rotated, "variant {i}");
        assert_eq!(auth(&doc(v)), Err(Code::PeerSignatureMismatch), "variant {i}");
    }
}

#[test]
fn c3_rejects_empty_failed_and_oversized_output() {
    for e in [SysError::NotFound, SysError::Io, SysError::Spawn, SysError::Exit(1), SysError::Timeout, SysError::Invalid, SysError::Unsupported] {
        assert_eq!(auth_with(Err(e), UID, list(), &digest(&good())), Err(Code::PeerSignatureSourceMissing), "{e:?}");
    }
    for s in ["", " ", "\n", "\r\n", "\u{feff}", "\0", "<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>\n", "<packages />", "<packages></packages>", "<packages>"] {
        unreadable(s, &format!("output {s:?}"));
    }
    let d = doc(&app_signed(&good()));
    let pad_to = |n: usize| d.replace("</packages>", &format!("{}</packages>", " ".repeat(n - d.len())));
    let fits = pad_to(MAX_XML);
    assert_eq!(fits.len(), MAX_XML);
    accepted(&fits, "exactly the size limit");
    let big = pad_to(MAX_XML + 1);
    assert_eq!(big.len(), MAX_XML + 1);
    unreadable(&big, "one byte above the size limit");
    unreadable(&format!("{d}{}", " ".repeat(MAX_XML + 1 - d.len())), "above the limit by trailing blanks");
    unreadable(&pad_to(8 << 20), "8 MiB");
}

#[test]
fn c3_rejects_every_truncation() {
    let g = good();
    let by_ref = doc(&format!("{}{}", other("com.vendor.tool", 10310, 126, Some(&g[..])), app(&sigs("1", &[(126, None)]))));
    for d in [doc(&app_signed(&g)), by_ref.replace('\n', "\r\n")] {
        assert!(d.is_ascii());
        let complete = d.rfind("</packages>").expect("end tag") + "</packages>".len();
        for cut in 0..complete {
            assert_eq!(package_signers(&d[..cut], PKG), None, "cut at {cut} of {complete}");
            if cut % 131 == 0 || cut + 40 > complete {
                assert_eq!(auth(&d[..cut]), Err(Code::PeerSignatureSourceMissing), "cut at {cut}");
            }
        }
        accepted(&d[..complete], "complete without the final line break");
    }
}

// ------------------------------------------------- criterion 4: impersonation

fn fake(index: u32, key: Option<&[u8]>) -> String {
    let k = key.map(|k| format!(" key=\"{}\"", hex(k))).unwrap_or_default();
    format!("<package name=\"{PKG}\" codePath=\"/system/priv-app/DialCrypt\" userId=\"{UID}\"><sigs count=\"1\" schemeVersion=\"2\"><cert index=\"{index}\"{k} /></sigs></package>")
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

fn numeric(s: &str, hexa: bool) -> String {
    s.chars().map(|c| if hexa { format!("&#x{:x};", c as u32) } else { format!("&#{};", c as u32) }).collect()
}

/// The fake record placed where another App can put text, written the way a
/// serializer writes it, or placed as real markup below another element.
fn inert_decoys(f: &str) -> Vec<(String, String)> {
    let evil_pkg = |attr: &str| format!("  <package name=\"com.evil.app\" codePath=\"/data/app/~~x==/com.evil.app-1\" userId=\"10301\" {attr} />\n");
    vec![
        ("escaped in an attribute".to_string(), evil_pkg(&format!("installer=\"{}\"", esc(f)))),
        ("escaped, closing the tag first".to_string(), evil_pkg(&format!("installer=\"x&quot; /&gt;{}&lt;package name=&quot;com.evil.rest\"", esc(f)))),
        ("permission name".to_string(), format!("  <permissions>\n    <item name=\"{}\" package=\"com.evil.app\" protection=\"2\" />\n  </permissions>\n", esc(f))),
        ("decimal references in an attribute".to_string(), evil_pkg(&format!("installer=\"{}\"", numeric(f, false)))),
        ("hex references in an attribute".to_string(), evil_pkg(&format!("installer=\"{}\"", numeric(f, true)))),
        ("single-quoted attribute with &lt;".to_string(), evil_pkg(&format!("installer='{}'", f.replace('<', "&lt;")))),
        ("escaped text node".to_string(), format!("  <package name=\"com.evil.app\" userId=\"10301\">{}</package>\n", esc(f))),
        ("text node with &#60; and &#62;".to_string(), format!("  <package name=\"com.evil.app\" userId=\"10301\">{}</package>\n", f.replace('<', "&#60;").replace('>', "&#62;"))),
        ("text node with &lt; only".to_string(), format!("  <package name=\"com.evil.app\" userId=\"10301\">{}</package>\n", f.replace('<', "&lt;"))),
        ("comment".to_string(), format!("  <!-- {f} -->\n")),
        ("processing instruction".to_string(), format!("  <?evil {f} ?>\n")),
        ("nested in shared-user".to_string(), format!("  <shared-user name=\"android.uid.evil\" userId=\"10400\">\n    {f}\n    <sigs count=\"1\" schemeVersion=\"3\">\n      <cert index=\"3\" />\n    </sigs>\n  </shared-user>\n")),
        ("nested in another package".to_string(), format!("  <package name=\"com.evil.app\" userId=\"10301\">\n    {f}\n  </package>\n")),
        ("nested in the perms of another package".to_string(), format!("  <package name=\"com.evil.app\" userId=\"10301\">\n    <perms>\n      {f}\n    </perms>\n  </package>\n")),
        ("nested in an updated-package of the name".to_string(), format!("  <updated-package name=\"{PKG}\" userId=\"{UID}\">{f}</updated-package>\n")),
        ("nested in a second packages element".to_string(), format!("  <packages>{f}</packages>\n")),
        ("nested in an unknown element".to_string(), format!("  <x>{f}</x>\n")),
    ]
}

/// Top-level elements that differ from the real record in the element name,
/// the attribute name or the package name.
fn variant_decoys(f: &str) -> Vec<(String, String)> {
    let mut v = Vec::new();
    for tag in ["Package", "PACKAGE", "package2", "a:package", "package.x", "package-", "_package", "updated-package", "packages", "pkg"] {
        v.push((format!("element {tag}"), format!("  {}\n", f.replace("<package ", &format!("<{tag} ")).replace("</package>", &format!("</{tag}>")))));
    }
    for an in ["Name", "NAME", "a:name", "name2", "name.", "_name", "nam", "pkg"] {
        v.push((format!("attribute {an}"), format!("  {}\n", f.replace("<package name=", &format!("<package {an}=")))));
    }
    let names = [
        "IO.GITHUB.H4LOVOID.DIALCRYPT",
        "Io.github.h4lovoid.dialcrypt",
        "io.github.h4lovoid.dialCrypt",
        " io.github.h4lovoid.dialcrypt",
        "io.github.h4lovoid.dialcrypt ",
        "io.github.h4lovoid.dialcrypt\t",
        "io.github.h4lovoid.dialcrypt\n",
        "io.github.h4lovoid.dialcrypt\0",
        "io.github.h4lovoid.dialcrypt&#9;",
        "io.github.h4lovoid.dialcrypt&#10;",
        "io.github.h4lovoid.dialcrypt&#0;",
        "io.github.h4lovoid.dialcrypt&#32;",
        "&#32;io.github.h4lovoid.dialcrypt",
        "io.github.h4lovoid.dialcrypt.",
        "io.github.h4lovoid.dialcryptx",
        "io.github.h4lovoid.dialcrypt2",
        "io.github.h4lovoid.dialcrypt:secure",
        "io.github.h4lovoid.dialcrypt/",
        "xio.github.h4lovoid.dialcrypt",
        "io.github.h4lovoid.dialcryp",
        "io github h4lovoid dialcrypt",
        "io.github.h4lovoid&amp;#46;dialcrypt",
        "io.github.h4lovoid&amp;dialcrypt",
        "io.github.h4lovoid.di\u{430}lcrypt",
        "io.github.h4lovoid\u{ff0e}dialcrypt",
        "io.github.h4lovoid.dialcrypt\u{200b}",
        "",
    ];
    for n in names {
        v.push((format!("name {n:?}"), format!("  {}\n", f.replace(&format!("name=\"{PKG}\""), &format!("name=\"{n}\"")))));
    }
    v
}

#[test]
fn c4_decoys_never_stand_in_for_the_package() {
    let (gv, ev) = (good(), evil());
    let (g, e): (&[u8], &[u8]) = (&gv, &ev);
    // Another App of the vendor carries the pinned certificate at index 57, so
    // an index-only decoy resolves to it.
    let helper = other("io.github.h4lovoid.dialcrypt.helper", 10298, 57, Some(g));
    let real_evil = app_signed(e);
    let real_good = app_signed(g);
    let mut cases = 0;
    for pinned_fake in [fake(57, Some(g)), fake(57, None)] {
        let mut decoys = inert_decoys(&pinned_fake);
        decoys.extend(variant_decoys(&pinned_fake));
        for (what, decoy) in &decoys {
            exactly(&doc(&format!("{helper}{decoy}{real_evil}")), e, &format!("{what}, before the record"));
            exactly(&doc(&format!("{helper}{real_evil}{decoy}")), e, &format!("{what}, after the record"));
            unreadable(&doc(&format!("{helper}{decoy}")), &format!("{what}, no record"));
            cases += 3;
        }
    }
    // The other direction: decoys with the attacker's certificate do not
    // displace or spoil the genuine record.
    let attacker_fake = fake(58, Some(e));
    let mut decoys = inert_decoys(&attacker_fake);
    decoys.extend(variant_decoys(&attacker_fake));
    for (what, decoy) in &decoys {
        accepted(&doc(&format!("{decoy}{real_good}")), &format!("{what}, attacker decoy before"));
        accepted(&doc(&format!("{real_good}{decoy}")), &format!("{what}, attacker decoy after"));
        cases += 2;
    }
    println!("C4 decoys: {cases} files checked");
}

#[test]
fn c4_raw_markup_tricks_fail_closed() {
    let (gv, ev) = (good(), evil());
    let (g, e): (&[u8], &[u8]) = (&gv, &ev);
    let helper = other("io.github.h4lovoid.dialcrypt.helper", 10298, 57, Some(g));
    let real_evil = app_signed(e);
    let real_good = app_signed(g);
    let raw = |f: &str| -> Vec<(String, String)> {
        vec![
            ("raw markup in a single-quoted attribute".to_string(), format!("  <package name=\"com.evil.app\" userId=\"10301\" installer='{f}' />\n")),
            ("CDATA below the root".to_string(), format!("  <![CDATA[{f}]]>\n")),
            ("CDATA inside a package".to_string(), format!("  <package name=\"com.evil.app\" userId=\"10301\"><![CDATA[{f}]]></package>\n")),
            ("CDATA closed early".to_string(), format!("  <package name=\"com.evil.app\" userId=\"10301\"><![CDATA[]]>{f}</package>\n")),
            ("entity declared in a DOCTYPE".to_string(), format!("  <!DOCTYPE packages [<!ENTITY e '{}'>]>\n  <x>&e;</x>\n", esc(f))),
            ("comment left open".to_string(), format!("  <!-- {f}\n")),
            ("attribute left open".to_string(), format!("  <package name=\"com.evil.app\" installer=\"x>\n  {f}\n")),
            ("unknown entity in an attribute".to_string(), format!("  <package name=\"com.evil.app\" installer=\"&fake;\" />\n  {f}\n")),
        ]
    };
    for (what, decoy) in raw(&fake(57, Some(g))) {
        never_good(&doc(&format!("{helper}{decoy}{real_evil}")), &format!("{what}, before the record"));
        never_good(&doc(&format!("{helper}{real_evil}{decoy}")), &format!("{what}, after the record"));
        never_good(&doc(&format!("{helper}{decoy}")), &format!("{what}, no record"));
    }
    for (what, decoy) in raw(&fake(58, Some(e))) {
        for d in [doc(&format!("{decoy}{real_good}")), doc(&format!("{real_good}{decoy}"))] {
            let r = package_signers(&d, PKG);
            assert!(r.is_none() || is_good(&r), "{what}: attacker certificate read");
            assert_eq!(auth(&d) == Ok(()), is_good(&r), "{what}");
        }
    }
    // The fake record inside the real one.
    let inside_after = app(&format!("{}    {}\n", sigs("1", &[(126, Some(e))]), fake(57, Some(g))));
    let inside_before = app(&format!("    {}\n{}", fake(57, Some(g)), sigs("1", &[(126, Some(e))])));
    let inside_perms = app(&format!("{}    <x>\n      {}\n    </x>\n", sigs("1", &[(126, Some(e))]), fake(57, Some(g))));
    for (i, v) in [inside_after, inside_before, inside_perms].iter().enumerate() {
        never_good(&doc(&format!("{helper}{v}")), &format!("fake record inside the real one, variant {i}"));
    }
}

#[test]
fn c4_name_spelled_with_references_is_the_same_name_and_never_a_second_record() {
    let (gv, ev) = (good(), evil());
    let (g, e): (&[u8], &[u8]) = (&gv, &ev);
    let helper = other("io.github.h4lovoid.dialcrypt.helper", 10298, 57, Some(g));
    let spell = |f: String| f.replace(&format!("name=\"{PKG}\""), "name=\"io&#46;github&#x2e;h4lovoid&#46;di&#97;lcrypt\"");
    let spelled_good = spell(fake(57, Some(g)));
    assert!(!spelled_good.contains(PKG));
    // Next to the real record it is a second record of the name: refused.
    unreadable(&doc(&format!("{helper}  {spelled_good}\n{}", app_signed(e))), "spelled record before the real one");
    unreadable(&doc(&format!("{helper}{}  {spelled_good}\n", app_signed(e))), "spelled record after the real one");
    unreadable(&doc(&format!("  {}\n{}", spell(fake(58, Some(e))), app_signed(g))), "spelled attacker record before the genuine one");
    // Alone it is the record of that name; its certificate decides.
    exactly(&doc(&format!("  {}\n", spell(fake(126, Some(e))))), e, "spelled record alone, attacker key");
    accepted(&doc(&format!("  {}\n", spell(fake(126, Some(g))))), "spelled record alone, pinned key");
    // A serializer writes a literal ampersand as &amp;, which is another name.
    let literal = fake(57, Some(g)).replace(&format!("name=\"{PKG}\""), "name=\"io&amp;#46;github.h4lovoid.dialcrypt\"");
    exactly(&doc(&format!("{helper}  {literal}\n{}", app_signed(e))), e, "literal &#46; in a package name");
}

// ------------------------------------------------- authenticate around the XML

#[test]
fn authenticate_checks_uid_package_and_pin_before_trusting_the_record() {
    let (gv, ev) = (good(), evil());
    let d = doc(&app_signed(&gv));
    let pin = digest(&gv);
    let mut dev = Dev { list: list(), xml: Ok(d.clone()), xml_reads: 0 };
    assert_eq!(authenticate(&mut dev, UID, Some(&pin)), Ok(()));
    assert_eq!(dev.xml_reads, 1);
    assert_eq!(authenticate(&mut dev, UID, None), Err(Code::PinnedCertMissing));
    assert_eq!(auth_with(Ok(d.clone()), UID, list(), &digest(&ev)), Err(Code::PeerSignatureMismatch));
    let mut near = pin;
    near[31] ^= 1;
    assert_eq!(auth_with(Ok(d.clone()), UID, list(), &near), Err(Code::PeerSignatureMismatch));
    assert_eq!(auth_with(Ok(d.clone()), UID, list(), &[0u8; 32]), Err(Code::PeerSignatureMismatch));
    for uid in [0, 1000, 2000, 9999, 20000, 1_010_297, u32::MAX] {
        assert_eq!(auth_with(Ok(d.clone()), uid, list(), &pin), Err(Code::PeerUidRejected), "uid {uid}");
    }
    assert_eq!(auth_with(Ok(d.clone()), 10301, list(), &pin), Err(Code::PeerPackageMismatch), "uid of another package");
    assert_eq!(auth_with(Ok(d.clone()), 10555, list(), &pin), Err(Code::PeerPackageMismatch), "uid of no package");
    assert_eq!(auth_with(Ok(d.clone()), UID, String::new(), &pin), Err(Code::PeerPackageMismatch), "empty packages.list");
    let shared = format!("{}com.evil.shared {UID} 0 /data/user/0/com.evil.shared default none\n", list());
    assert_eq!(auth_with(Ok(d.clone()), UID, shared, &pin), Err(Code::PeerSharedUid));
    let debuggable = list().replace(&format!("{PKG} {UID} 0 "), &format!("{PKG} {UID} 1 "));
    assert_eq!(auth_with(Ok(d.clone()), UID, debuggable, &pin), Err(Code::PeerDebuggable));
    // The attacker's own uid never reaches the record of our package.
    let evil_named = doc(&format!("{}{}", app_signed(&gv), other("com.evil.app", 10301, 126, None)));
    assert_eq!(auth_with(Ok(evil_named), 10301, list(), &pin), Err(Code::PeerPackageMismatch));
}

// ------------------------------------------------ criterion 5: the five doubts

#[test]
fn d1_state_transitions_around_self_closing_elements() {
    let (gv, ev) = (good(), evil());
    let (g, e): (&[u8], &[u8]) = (&gv, &ev);
    let good_sigs = sigs("1", &[(126, Some(g))]);
    let evil_sigs = sigs("1", &[(126, Some(e))]);
    let stray_good = format!("  <package name=\"com.evil.app\" userId=\"10301\">\n{}  </package>\n", sigs("1", &[(57, Some(g))]));

    // An empty record followed by another package with the pinned key.
    unreadable(&doc(&format!("  <package name=\"{PKG}\" userId=\"{UID}\" />\n{stray_good}")), "self-closing record");
    unreadable(&doc(&format!("  <package name=\"{PKG}\" userId=\"{UID}\"></package>\n{stray_good}")), "empty record");
    // Empty sigs followed by certificates outside it.
    unreadable(&doc(&app(&format!("    <sigs count=\"1\" schemeVersion=\"2\" />\n      <cert index=\"126\" key=\"{}\" />\n", hex(g)))), "self-closing sigs then cert");
    unreadable(&doc(&app(&format!("    <sigs count=\"1\" schemeVersion=\"2\"></sigs>\n      <cert index=\"126\" key=\"{}\" />\n", hex(g)))), "empty sigs then cert");
    // Siblings of sigs, self-closing or not, before and after.
    accepted(&doc(&app(&format!("    <a />\n    <b></b>\n{good_sigs}    <c />\n    <d></d>\n"))), "siblings around sigs");
    accepted(&doc(&app(&format!("    <perms>\n      <item name=\"x\" />\n      <item name=\"y\"></item>\n    </perms>\n{good_sigs}"))), "sigs after a closed sibling with children");
    // Certificates after the record's sigs closed are not counted.
    let late = format!("{evil_sigs}    <cert index=\"57\" key=\"{0}\" />\n    <x>\n      <cert index=\"57\" key=\"{0}\" />\n    </x>\n", hex(g));
    exactly(&doc(&app(&late)), e, "cert elements after sigs inside the record");
    // Certificates of the package after the record are not counted.
    exactly(&doc(&format!("{}{stray_good}", app(&evil_sigs))), e, "package after the record");
    exactly(&doc(&format!("{stray_good}{}{stray_good}", app(&evil_sigs))), e, "packages around the record");
    // A sigs directly below the root does not belong to any package.
    let root_sigs = sigs("1", &[(57, Some(g))]);
    exactly(&doc(&format!("{root_sigs}{}{root_sigs}", app(&evil_sigs))), e, "sigs below the root");
    accepted(&doc(&format!("{}{}", sigs("7", &[(57, Some(e))]), app(&good_sigs))), "foreign sigs below the root with another count");
    unreadable(&doc(&format!("{root_sigs}  <package name=\"{PKG}\" userId=\"{UID}\" />\n{root_sigs}")), "empty record between root-level sigs");
    // Children of sigs.
    unreadable(&doc(&app(&format!("    <sigs count=\"1\" schemeVersion=\"2\">\n      <cert index=\"126\" key=\"{}\" />\n      <junk />\n    </sigs>\n", hex(g)))), "unknown child in sigs");
    unreadable(&doc(&app(&format!("    <sigs count=\"1\" schemeVersion=\"2\">\n      <cert index=\"126\" key=\"{}\" />\n{good_sigs}    </sigs>\n", hex(g)))), "sigs inside sigs");
    accepted(&doc(&app(&format!("    <sigs count=\"1\" schemeVersion=\"2\">\n      <cert index=\"126\" key=\"{}\"></cert>\n    </sigs>\n", hex(g)))), "cert written with an end tag");
    let nested_cert = app(&format!("    <sigs count=\"1\" schemeVersion=\"2\">\n      <cert index=\"126\" key=\"{}\"><cert index=\"57\" key=\"{}\" /></cert>\n    </sigs>\n", hex(e), hex(g)));
    never_good(&doc(&nested_cert), "pinned cert nested inside the attacker cert");
    // A second sigs anywhere in the record.
    unreadable(&doc(&app(&format!("{good_sigs}    <sigs count=\"0\" />\n"))), "second sigs, self-closing, after");
    unreadable(&doc(&app(&format!("    <sigs count=\"0\" />\n{good_sigs}"))), "second sigs, self-closing, before");
    unreadable(&doc(&app(&format!("{good_sigs}    <x>\n      <y>\n        <sigs count=\"0\" />\n      </y>\n    </x>\n"))), "second sigs deep in the record");
    // Depth limit.
    let deep = format!("{}{}", "<a>".repeat(40), "</a>".repeat(40));
    unreadable(&doc(&format!("{}  {deep}\n", app(&good_sigs))), "40 levels");
    let shallow = format!("{}{}", "<a>".repeat(20), "</a>".repeat(20));
    accepted(&doc(&format!("{}  {shallow}\n", app(&good_sigs))), "20 levels");
}

#[test]
fn d2_past_sigs_with_an_undefined_index() {
    let (gv, pv) = (good(), plat());
    let (g, p): (&[u8], &[u8]) = (&gv, &pv);
    let rotated = app(&format!(
        "    <sigs count=\"1\" schemeVersion=\"3\">\n      <cert index=\"126\" key=\"{}\" />\n      <pastSigs count=\"2\" schemeVersion=\"3\">\n        <cert index=\"999\" flags=\"17\" />\n        <cert index=\"126\" flags=\"2\" />\n      </pastSigs>\n    </sigs>\n",
        hex(g)
    ));
    // In the record of the App: read as rotated, and a rotated record never authenticates.
    assert_eq!(package_signers(&doc(&rotated), PKG), Some(Signers { current: vec![gv.clone()], rotated: true }));
    assert_eq!(auth(&doc(&rotated)), Err(Code::PeerSignatureMismatch));
    // In another package: the genuine record is still read, and the undefined
    // index stays undefined for a later reference.
    let other_rotated = format!(
        "  <package name=\"com.vendor.rotated\" userId=\"10312\">\n    <sigs count=\"1\" schemeVersion=\"3\">\n      <cert index=\"40\" key=\"{}\" />\n      <pastSigs count=\"1\" schemeVersion=\"3\">\n        <cert index=\"999\" flags=\"17\" />\n      </pastSigs>\n    </sigs>\n  </package>\n",
        hex(p).replace("3082", "3083")
    );
    accepted(&doc(&format!("{other_rotated}{}", app_signed(g))), "undefined pastSigs index in another package");
    unreadable(&doc(&format!("{other_rotated}{}", app(&sigs("1", &[(999, None)])))), "reference to the index a pastSigs left undefined");
}

#[test]
fn d3_character_references_and_duplicate_attributes() {
    let (gv, ev) = (good(), evil());
    let (g, e): (&[u8], &[u8]) = (&gv, &ev);
    let app_g = app_signed(g);
    let tool = |attr: &str| format!("  <package name=\"com.vendor.tool\" userId=\"10310\" {attr} />\n");
    // Valid references in unrelated attributes, including the control
    // characters a serializer writes as references.
    accepted(&doc(&format!("{}{app_g}", tool("label=\"a&#10;b&#0;c&#x1F600;d&#x2e;&#46;&amp;&lt;&gt;&quot;&apos;&#0000000046;\""))), "valid references");
    // References inside the values that are read spell the same value.
    let spelled = app_g.replace("index=\"126\"", "index=\"&#49;26\"").replace("count=\"1\"", "count=\"&#x31;\"").replace("key=\"3082", "key=\"&#51;082");
    assert_ne!(spelled, app_g);
    accepted(&doc(&spelled), "references in count, index and key");
    // Malformed references anywhere make the file unusable.
    for bad in ["&", "&#;", "&#x;", "&bogus;", "&#xD800;", "&#xDFFF;", "&#1114112;", "&#x110000;", "&#99999999999;", "&#X41;", "&#-1;", "&#+1;", "&# 46;", "&lt", "&#46", "&#0x2e;", "&#00000000046;"] {
        unreadable(&doc(&format!("{}{app_g}", tool(&format!("label=\"a{bad}b\"")))), &format!("reference {bad:?}"));
    }
    // A reference can not smuggle a quote or a bracket into the markup.
    exactly(
        &doc(&format!("{}{}", tool(&format!("label=\"x&#34; /&#62;&#60;package name=&#34;{PKG}&#34;&#62;&#60;sigs count=&#34;1&#34;&#62;&#60;cert index=&#34;57&#34; key=&#34;{}&#34; /&#62;\"", hex(g))), app_signed(e))),
        e,
        "markup spelled with references",
    );
    // Duplicate attributes, on the record and elsewhere.
    let dup = [
        app_g.replacen(&format!("name=\"{PKG}\""), &format!("name=\"com.evil.app\" name=\"{PKG}\""), 1),
        app_g.replacen(&format!("name=\"{PKG}\""), &format!("name=\"{PKG}\" name=\"com.evil.app\""), 1),
        app_g.replacen(&format!("name=\"{PKG}\""), &format!("name=\"{PKG}\" name=\"{PKG}\""), 1),
        app_g.replacen("count=\"1\"", "count=\"1\" count=\"2\"", 1),
        app_g.replacen("count=\"1\"", "count=\"2\" count=\"1\"", 1),
        app_g.replacen("index=\"126\"", "index=\"126\" index=\"57\"", 1),
        app_g.replacen("key=\"", &format!("key=\"{}\" key=\"", hex(e)), 1),
        format!("{}{app_g}", tool("a=\"1\" a=\"1\"")),
        format!("{app_g}{}", tool("a=\"1\" b=\"2\" a=\"3\"")),
    ];
    for (i, d) in dup.iter().enumerate() {
        unreadable(&doc(d), &format!("duplicate attribute, case {i}"));
    }
    // Attribute names differing in case are different attributes.
    let cased = format!("  <package Name=\"{PKG}\" name=\"com.evil.app\" userId=\"10301\">\n{}  </package>\n", sigs("1", &[(57, Some(g))]));
    exactly(&doc(&format!("{cased}{}", app_signed(e))), e, "Name next to name");
}

#[test]
fn d4_size_limit_is_below_the_capture_cap() {
    assert!(MAX_XML < 8 << 20);
    assert_eq!(MAX_XML, 6 << 20);
}

/// Runs the production command runner on this host (a shell that prints a
/// padded genuine file) and feeds what it captured to the parser.
#[cfg(unix)]
#[test]
fn d4_capture_of_the_real_backend_is_refused_when_truncated() {
    use aegiscalld::real::RealSys;
    const CAP: usize = 8 << 20;
    let d = doc(&app_signed(&good()));
    let cut = d.rfind("</packages>").expect("end tag");
    let (head, tail) = d.split_at(cut);
    let script = "printf %s \"$1\"; /usr/bin/head -c \"$3\" /dev/zero | /usr/bin/tr '\\000' ' '; printf %s \"$2\"";
    let mut sys = RealSys::new();
    for total in [200_000usize, MAX_XML, MAX_XML + 1, CAP, CAP + 1, CAP + 4096, 16 << 20] {
        let pad = (total - d.len()).to_string();
        let out = sys.read_cmd(&["/bin/sh", "-c", script, "sh", head, tail, pad.as_str()]);
        match out {
            Ok(s) => {
                let r = package_signers(&s, PKG);
                println!("D4 output {total} bytes: captured {} bytes, record {}", s.len(), if is_good(&r) { "read" } else { "refused" });
                assert_eq!(s.len(), total.min(CAP), "captured length for {total}");
                assert_eq!(is_good(&r), total <= MAX_XML, "{total}");
                if total > MAX_XML {
                    assert_eq!(r, None, "{total}");
                    assert_eq!(auth(&s), Err(Code::PeerSignatureSourceMissing), "{total}");
                }
            }
            Err(e) => {
                println!("D4 output {total} bytes: command error {e:?}");
                assert!(total > CAP, "a capture within the cap failed: {total} {e:?}");
            }
        }
    }
}

#[test]
fn d5_upper_case_hex_is_the_same_certificate() {
    let (gv, ev) = (good(), evil());
    let (g, e): (&[u8], &[u8]) = (&gv, &ev);
    let (lower, upper) = (hex(g), hex(g).to_uppercase());
    assert_ne!(lower, upper);
    let mixed: String = lower.chars().enumerate().map(|(i, c)| if i % 2 == 0 { c.to_ascii_uppercase() } else { c }).collect();
    accepted(&doc(&app_signed(g).replace(&lower, &upper)), "upper-case key");
    accepted(&doc(&app_signed(g).replace(&lower, &mixed)), "mixed-case key");
    // The same index written in another case is the same key, not a conflict.
    accepted(&doc(&format!("{}{}", other("com.vendor.tool", 10310, 126, Some(g)).replace(&lower, &upper), app_signed(g))), "upper case before, lower case after");
    accepted(&doc(&format!("{}{}", other("com.vendor.tool", 10310, 126, Some(g)).replace(&lower, &upper), app(&sigs("1", &[(126, None)])))), "upper-case definition, index-only reference");
    // Case does not turn another key into the pinned one.
    exactly(&doc(&app_signed(e).replace(&hex(e), &hex(e).to_uppercase())), e, "upper-case attacker key");
    unreadable(&doc(&app_signed(g).replace(&lower, &format!("G{}", &upper[1..]))), "letter after F");
}

// ----------------------------------- doubt 1: scanner against a tree model

#[derive(Clone)]
struct Node {
    name: String,
    attrs: Vec<(String, String)>,
    kids: Vec<Node>,
}

fn node(name: &str, attrs: &[(&str, &str)], kids: Vec<Node>) -> Node {
    Node { name: name.to_string(), attrs: attrs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(), kids }
}

fn attr<'a>(n: &'a Node, name: &str) -> Option<&'a str> {
    n.attrs.iter().find(|(k, _)| k.as_str() == name).map(|(_, v)| v.as_str())
}

fn dec(s: &str) -> Option<u32> {
    if s.is_empty() || s.len() > 10 || !s.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if b.len() % 2 != 0 || b.len() < 2 * MIN_CERT || b.len() > 2 * MAX_CERT {
        return None;
    }
    let mut out = Vec::with_capacity(b.len() / 2);
    for p in b.chunks(2) {
        let hi = (p[0] as char).to_digit(16)?;
        let lo = (p[1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some(out)
}

/// Descendants of `n` with this element name.
fn count_named(n: &Node, name: &str) -> usize {
    n.kids.iter().map(|k| usize::from(k.name == name) + count_named(k, name)).sum()
}

fn has_duplicate_attr(n: &Node) -> bool {
    let dup = n.attrs.iter().enumerate().any(|(i, (k, _))| n.attrs[..i].iter().any(|(o, _)| o == k));
    dup || n.kids.iter().any(has_duplicate_attr)
}

/// Document-order pass over every cert below a sigs or pastSigs.
fn walk<'a>(n: &'a Node, parent: Option<&'a Node>, the_sigs: &'a Node, keys: &mut HashMap<u32, Vec<u8>>, current: &mut Vec<Vec<u8>>) -> bool {
    if let Some(p) = parent {
        if n.name == "cert" && (p.name == "sigs" || p.name == "pastSigs") {
            let Some(i) = attr(n, "index").and_then(dec) else { return false };
            if let Some(k) = attr(n, "key") {
                let Some(der) = unhex(k) else { return false };
                if keys.get(&i).map_or(false, |old| *old != der) {
                    return false;
                }
                keys.entry(i).or_insert(der);
            }
            if std::ptr::eq(p, the_sigs) {
                match keys.get(&i) {
                    Some(k) => current.push(k.clone()),
                    None => return false,
                }
            }
        }
    }
    for k in &n.kids {
        if !walk(k, Some(n), the_sigs, keys, current) {
            return false;
        }
    }
    true
}

/// What the documented rules give for a parsed tree.
fn expected(root: &Node) -> Option<Signers> {
    if root.name != "packages" || has_duplicate_attr(root) {
        return None;
    }
    let targets: Vec<&Node> = root.kids.iter().filter(|k| k.name == "package" && attr(k, "name") == Some(PKG)).collect();
    if targets.len() != 1 {
        return None;
    }
    let t = targets[0];
    let direct: Vec<&Node> = t.kids.iter().filter(|k| k.name == "sigs").collect();
    if direct.len() != 1 || count_named(t, "sigs") != 1 {
        return None;
    }
    let s = direct[0];
    if s.kids.iter().any(|k| k.name != "cert" && k.name != "pastSigs") {
        return None;
    }
    let n = s.kids.iter().filter(|k| k.name == "cert").count();
    if n == 0 || attr(s, "count").and_then(dec) != Some(n as u32) {
        return None;
    }
    let mut keys = HashMap::new();
    let mut current = Vec::new();
    if !walk(root, None, s, &mut keys, &mut current) {
        return None;
    }
    Some(Signers { current, rotated: count_named(t, "pastSigs") > 0 })
}

fn fuzz_key(i: u32) -> Vec<u8> {
    cert(5000 + i, MIN_CERT + (i % 5) as usize)
}

struct Maker {
    r: Lcg,
    defined: Vec<u32>,
}

impl Maker {
    fn below(&mut self, n: u64) -> u64 {
        self.r.below(n)
    }

    fn hit(&mut self, pct: u64) -> bool {
        self.r.below(100) < pct
    }

    fn cert(&mut self) -> Node {
        let i = [3u32, 57, 126, 127][self.below(4) as usize];
        let mut attrs: Vec<(String, String)> = Vec::new();
        match self.below(100) {
            0 => {}
            1 => attrs.push(("index".to_string(), "x7".to_string())),
            2 => attrs.push(("index".to_string(), format!("0{i}"))),
            _ => attrs.push(("index".to_string(), i.to_string())),
        }
        let known = self.defined.contains(&i);
        let roll = self.below(100);
        if roll == 98 {
            attrs.push(("key".to_string(), hex(&fuzz_key(i + 1000))));
        } else if roll == 99 {
            attrs.push(("key".to_string(), ["", "zz", "abc"][self.below(3) as usize].to_string()));
        } else if (!known && roll < 88) || (known && roll < 8) {
            let h = hex(&fuzz_key(i));
            attrs.push(("key".to_string(), if self.hit(10) { h.to_uppercase() } else { h }));
            if !known {
                self.defined.push(i);
            }
        }
        if self.hit(10) {
            attrs.push(("flags".to_string(), "2".to_string()));
        }
        let kids = if self.hit(3) { vec![node("cert", &[("index", "126")], vec![])] } else { vec![] };
        Node { name: "cert".to_string(), attrs, kids }
    }

    fn past(&mut self) -> Node {
        let n = self.below(3);
        let mut kids = Vec::new();
        for _ in 0..n {
            kids.push(self.cert());
        }
        node("pastSigs", &[("count", "1")], kids)
    }

    fn sigs(&mut self, depth: usize) -> Node {
        let n = match self.below(100) {
            0..=74 => 1,
            75..=82 => 0,
            83..=92 => 2,
            _ => 3,
        };
        let mut kids = Vec::new();
        for _ in 0..n {
            kids.push(self.cert());
        }
        if self.hit(10) {
            kids.push(self.past());
        }
        if self.hit(3) {
            kids.push(node("junk", &[], vec![]));
        }
        if self.hit(3) && depth < 6 {
            kids.push(self.sigs(depth + 1));
        }
        if self.hit(4) {
            kids.push(self.cert());
        }
        let certs = kids.iter().filter(|k| k.name == "cert").count();
        let mut attrs: Vec<(String, String)> = Vec::new();
        match self.below(100) {
            0..=87 => attrs.push(("count".to_string(), certs.to_string())),
            88..=90 => attrs.push(("count".to_string(), (certs + 1).to_string())),
            91..=92 => attrs.push(("count".to_string(), "x".to_string())),
            93 => attrs.push(("count".to_string(), String::new())),
            _ => {}
        }
        attrs.push(("schemeVersion".to_string(), "2".to_string()));
        Node { name: "sigs".to_string(), attrs, kids }
    }

    fn perms(&mut self, depth: usize) -> Node {
        let mut kids = Vec::new();
        for _ in 0..self.below(3) {
            kids.push(node("item", &[("name", "android.permission.INTERNET"), ("granted", "true")], vec![]));
        }
        if self.hit(6) {
            kids.push(self.sigs(depth + 1));
        }
        if self.hit(4) && depth < 4 {
            kids.push(self.pkg("package", depth + 1));
        }
        if self.hit(3) {
            kids.push(self.cert());
        }
        node("perms", &[], kids)
    }

    fn pkg(&mut self, tag: &str, depth: usize) -> Node {
        let name = match self.below(100) {
            0..=44 => PKG.to_string(),
            45..=49 => format!("{PKG} "),
            50..=54 => PKG.to_uppercase(),
            55..=59 => format!("{PKG}.x"),
            _ => format!("com.vendor.app{}", self.below(4)),
        };
        let mut attrs: Vec<(String, String)> = Vec::new();
        if !self.hit(3) {
            attrs.push(("name".to_string(), name));
        }
        attrs.push(("userId".to_string(), (10_000 + self.below(500)).to_string()));
        if self.hit(20) {
            attrs.push(("installer".to_string(), format!("<package name=\"{PKG}\"> & 'co' ]]> <!--")));
        }
        let mut kids = Vec::new();
        if self.hit(8) {
            kids.push(node("junk", &[], vec![]));
        }
        match self.below(100) {
            0..=79 => kids.push(self.sigs(depth + 1)),
            80..=86 => {}
            87..=92 => {
                kids.push(self.sigs(depth + 1));
                kids.push(self.sigs(depth + 1));
            }
            _ => {
                let s = self.sigs(depth + 2);
                kids.push(node("wrap", &[], vec![s]));
            }
        }
        if self.hit(40) {
            kids.push(self.perms(depth + 1));
        }
        if self.hit(4) {
            kids.push(self.past());
        }
        if self.hit(5) && depth < 4 {
            let tag = ["package", "updated-package"][self.below(2) as usize];
            kids.push(self.pkg(tag, depth + 1));
        }
        if self.hit(3) {
            kids.push(self.cert());
        }
        Node { name: tag.to_string(), attrs, kids }
    }

    fn root(&mut self) -> Node {
        let mut kids = vec![node("version", &[("sdkVersion", "36")], vec![])];
        for _ in 0..1 + self.below(5) {
            match self.below(100) {
                0..=64 => kids.push(self.pkg("package", 1)),
                65..=76 => kids.push(self.pkg("updated-package", 1)),
                77..=86 => {
                    let mut inner = Vec::new();
                    if self.hit(40) {
                        inner.push(self.pkg("package", 2));
                    }
                    inner.push(self.sigs(2));
                    kids.push(node("shared-user", &[("name", "android.uid.system")], inner));
                }
                87..=90 => kids.push(self.sigs(1)),
                91..=94 => {
                    let p = self.pkg("package", 2);
                    kids.push(node("packages", &[], vec![p]));
                }
                95..=97 => kids.push(self.cert()),
                _ => kids.push(node("junk", &[], vec![])),
            }
        }
        node("packages", &[], kids)
    }
}

const DECOY_TEXT: &str = "&lt;package name=\"io.github.h4lovoid.dialcrypt\"&gt; x &amp; y > z";

fn write_attr(r: &mut Lcg, v: &str, q: char, out: &mut String) {
    for c in v.chars() {
        let roll = r.below(100);
        if c == '&' {
            out.push_str("&amp;");
        } else if c == '<' {
            out.push_str("&lt;");
        } else if c == q {
            out.push_str(if q == '"' { "&quot;" } else { "&apos;" });
        } else if roll < 3 {
            out.push_str(&format!("&#{};", c as u32));
        } else if roll < 6 {
            out.push_str(&format!("&#x{:X};", c as u32));
        } else if c == '>' && roll < 50 {
            out.push_str("&gt;");
        } else {
            out.push(c);
        }
    }
}

fn write_node(r: &mut Lcg, n: &Node, depth: usize, out: &mut String) {
    let nl = ["\n", "\r\n", "", " "][r.below(4) as usize];
    out.push_str(nl);
    if nl.len() > 1 || nl == "\n" {
        out.push_str(&"  ".repeat(depth));
    }
    out.push('<');
    out.push_str(&n.name);
    for (k, v) in &n.attrs {
        out.push_str([" ", "  ", "\n      ", "\t"][r.below(4) as usize]);
        out.push_str(k);
        out.push_str(["=", "=", " = ", "= "][r.below(4) as usize]);
        let q = if r.below(5) == 0 { '\'' } else { '"' };
        out.push(q);
        write_attr(r, v, q, out);
        out.push(q);
    }
    if n.kids.is_empty() {
        match r.below(6) {
            0 => out.push_str("/>"),
            1..=3 => out.push_str(" />"),
            4 => {
                out.push_str("></");
                out.push_str(&n.name);
                out.push('>');
            }
            _ => {
                out.push('>');
                out.push_str(DECOY_TEXT);
                out.push_str("</");
                out.push_str(&n.name);
                out.push_str(" >");
            }
        }
        return;
    }
    out.push('>');
    for k in &n.kids {
        if r.below(12) == 0 {
            out.push_str("<!-- <package name=\"io.github.h4lovoid.dialcrypt\"><sigs count=\"1\"> -->");
        }
        if r.below(15) == 0 {
            out.push_str(DECOY_TEXT);
        }
        write_node(r, k, depth + 1, out);
    }
    out.push('\n');
    out.push_str("</");
    out.push_str(&n.name);
    out.push('>');
}

#[test]
fn d1_scanner_agrees_with_a_tree_model_on_generated_files() {
    let mut m = Maker { r: Lcg(0x00c0_ffee_1234_5678), defined: Vec::new() };
    let (mut some, mut none, mut rotated, mut multi) = (0u32, 0u32, 0u32, 0u32);
    for round in 0..20_000 {
        m.defined.clear();
        let mut root = m.root();
        if m.hit(1) {
            let a = root.kids[0].attrs[0].clone();
            root.kids[0].attrs.push(a);
        }
        let mut xml = String::new();
        if m.hit(80) {
            xml.push_str("<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>");
        }
        write_node(&mut m.r, &root, 0, &mut xml);
        xml.push('\n');
        let want = expected(&root);
        let got = package_signers(&xml, PKG);
        assert_eq!(got, want, "round {round}:\n{xml}");
        match &want {
            Some(s) => {
                some += 1;
                rotated += u32::from(s.rotated);
                multi += u32::from(s.current.len() > 1);
            }
            None => none += 1,
        }
    }
    println!("FUZZ model: 20000 generated files, {some} with a record ({rotated} rotated, {multi} with several certificates), {none} refused, 0 disagreements");
    assert!(some >= 300 && none >= 300 && rotated >= 5 && multi >= 5, "generator lost coverage: {some} {none} {rotated} {multi}");
}

// --------------------------------------------------- criterion 6: robustness

/// A small file in the field layout. The App is signed by `target`; `helper` is
/// defined at index 57 and referenced by an updated-package of the App's name,
/// by a nested package of that name, by an escaped attribute and optionally by
/// a comment.
fn compact_doc(target: &[u8], helper: &[u8], comment: bool) -> String {
    let f = format!("<package name=\"{PKG}\"><sigs count=\"1\"><cert index=\"57\" /></sigs></package>");
    let c = if comment { format!("  <!-- {f} -->\n") } else { String::new() };
    format!(
        "<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>\n<packages>\n  <package name=\"android\" userId=\"1000\">\n    <sigs count=\"1\" schemeVersion=\"3\">\n      <cert index=\"3\" key=\"{}\" />\n    </sigs>\n  </package>\n  <package name=\"io.github.h4lovoid.dialcrypt.helper\" userId=\"10298\" installer=\"{}\">\n    <sigs count=\"1\" schemeVersion=\"2\">\n      <cert index=\"57\" key=\"{}\" />\n    </sigs>\n  </package>\n{c}  <updated-package name=\"{PKG}\" userId=\"{UID}\">\n    <sigs count=\"1\" schemeVersion=\"2\">\n      <cert index=\"57\" />\n    </sigs>\n  </updated-package>\n  <package name=\"{PKG}\" codePath=\"/data/app/~~b==/{PKG}-2\" userId=\"{UID}\">\n    <sigs count=\"1\" schemeVersion=\"2\">\n      <cert index=\"126\" key=\"{}\" />\n    </sigs>\n    <perms>\n      <item name=\"android.permission.INTERNET\" granted=\"true\" flags=\"0\" />\n    </perms>\n  </package>\n  <shared-user name=\"android.uid.system\" userId=\"1000\">\n    {f}\n    <sigs count=\"1\" schemeVersion=\"3\">\n      <cert index=\"3\" />\n    </sigs>\n  </shared-user>\n</packages>\n",
        hex(&cert(13, MIN_CERT)),
        esc(&f),
        hex(helper),
        hex(target)
    )
}

fn mutation_bytes(orig: u8) -> Vec<u8> {
    let mut v: Vec<u8> = b"<>/=\"'&;#!?-[] \t\r\n.:_0159afgkpsxzAFNP\x00\x7f\x80\xc3\xff".to_vec();
    v.extend([orig ^ 0x20, orig.wrapping_add(1), orig.wrapping_sub(1), orig ^ 0x01]);
    v.sort_unstable();
    v.dedup();
    v.retain(|&b| b != orig);
    v
}

fn for_each_single_mutation(doc: &[u8], mut f: impl FnMut(&str, usize, &str)) {
    const INSERT: &[u8] = b"<>/\"'&;= !-?";
    for i in 0..doc.len() {
        for m in mutation_bytes(doc[i]) {
            let mut v = doc.to_vec();
            v[i] = m;
            f(&String::from_utf8_lossy(&v), i, "replace");
        }
        let mut v = doc.to_vec();
        v.remove(i);
        f(&String::from_utf8_lossy(&v), i, "delete");
        for &m in INSERT {
            let mut v = doc.to_vec();
            v.insert(i, m);
            f(&String::from_utf8_lossy(&v), i, "insert");
        }
        let mut v = doc.to_vec();
        v.insert(i, doc[i]);
        f(&String::from_utf8_lossy(&v), i, "duplicate");
    }
}

#[test]
fn c6_single_byte_mutations_of_a_decoy_file_never_yield_the_pinned_certificate() {
    let (g, e) = (cert(11, MIN_CERT), cert(12, MIN_CERT));
    let d = compact_doc(&e, &g, true);
    assert_eq!(package_signers(&d, PKG), Some(Signers { current: vec![e.clone()], rotated: false }));
    let (mut n, mut parsed) = (0u32, 0u32);
    for_each_single_mutation(d.as_bytes(), |s, i, kind| {
        n += 1;
        let r = package_signers(s, PKG);
        parsed += u32::from(r.is_some());
        assert!(!matches!(&r, Some(x) if x.current.iter().any(|c| *c == g)), "{kind} at {i} yields the pinned certificate");
    });
    let complete = d.rfind("</packages>").expect("end tag") + "</packages>".len();
    for cut in 0..complete {
        assert_eq!(package_signers(&d[..cut], PKG), None, "cut at {cut}");
    }
    println!("MUT decoy file ({} bytes): {n} single-byte mutations, {parsed} still give a record, 0 give the pinned certificate", d.len());
}

#[test]
fn c6_single_byte_mutations_of_a_genuine_file_authenticate_only_the_original_certificate() {
    let (g, e, p) = (cert(11, MIN_CERT), cert(12, MIN_CERT), cert(13, MIN_CERT));
    let d = compact_doc(&g, &e, true);
    let pin = digest(&g);
    assert_eq!(auth_with(Ok(d.clone()), UID, list(), &pin), Ok(()));
    let (mut n, mut same, mut changed, mut refused) = (0u32, 0u32, 0u32, 0u32);
    for_each_single_mutation(d.as_bytes(), |s, i, kind| {
        n += 1;
        let r = package_signers(s, PKG);
        let original = matches!(&r, Some(x) if !x.rotated && x.current.len() == 1 && x.current[0] == g);
        let ok = auth_with(Ok(s.to_string()), UID, list(), &pin) == Ok(());
        assert_eq!(ok, original, "{kind} at {i}: authenticated without the original certificate, or refused with it");
        match &r {
            Some(x) => {
                assert!(x.current.iter().all(|c| *c != e && *c != p), "{kind} at {i}: another certificate of the file was read");
                if original {
                    same += 1;
                } else {
                    changed += 1;
                }
            }
            None => refused += 1,
        }
    });
    println!("MUT genuine file ({} bytes): {n} single-byte mutations, {same} keep the certificate and authenticate, {changed} read another record and are refused, {refused} unreadable", d.len());
}

#[test]
fn c6_random_input_and_random_multi_byte_mutations() {
    let mut rng = Lcg(0x0bad_5eed_cafe_f00d);
    let alphabet: &[u8] = b"<>/=\"'&;#x ?!-[]packgesitnmyoudr0123456789abcdef.\n";
    for round in 0..8000 {
        let len = rng.below(900) as usize;
        let mut raw = Vec::with_capacity(len);
        for _ in 0..len {
            raw.push(if round % 2 == 0 { rng.next() as u8 } else { alphabet[rng.below(alphabet.len() as u64) as usize] });
        }
        assert_eq!(package_signers(&String::from_utf8_lossy(&raw), PKG), None, "random input {round}");
    }
    let (g, e) = (cert(11, MIN_CERT), cert(12, MIN_CERT));
    let pin = digest(&g);
    let (mut records, mut authenticated) = (0u32, 0u32);
    for genuine in [false, true] {
        let base = if genuine { compact_doc(&g, &e, false) } else { compact_doc(&e, &g, false) }.into_bytes();
        for round in 0..12_000 {
            let mut v = base.clone();
            for _ in 0..1 + rng.below(4) {
                let at = rng.below(v.len() as u64) as usize;
                match rng.below(4) {
                    0 => v[at] = rng.next() as u8,
                    1 => v[at] = alphabet[rng.below(alphabet.len() as u64) as usize],
                    2 => {
                        v.remove(at);
                    }
                    _ => {
                        let from = rng.below(base.len() as u64) as usize;
                        let n = (rng.below(60) as usize).min(base.len() - from);
                        v.splice(at..at, base[from..from + n].iter().copied());
                    }
                }
            }
            let s = String::from_utf8_lossy(&v).into_owned();
            let r = package_signers(&s, PKG);
            records += u32::from(r.is_some());
            let original = matches!(&r, Some(x) if !x.rotated && x.current.len() == 1 && x.current[0] == g);
            if genuine {
                let ok = auth_with(Ok(s), UID, list(), &pin) == Ok(());
                authenticated += u32::from(ok);
                assert_eq!(ok, original, "genuine file, round {round}");
            } else {
                assert!(!matches!(&r, Some(x) if x.current.iter().any(|c| *c == g)), "decoy file, round {round}: pinned certificate read");
            }
        }
    }
    println!("MUT random: 8000 random inputs refused; 24000 multi-byte mutations, {records} still give a record, {authenticated} of the genuine ones authenticate, 0 wrong");
}

fn realistic_doc() -> String {
    let g = good();
    let mut body = String::new();
    let items = "      <item name=\"android.permission.SOMETHING_RATHER_LONG\" granted=\"true\" flags=\"0\" />\n".repeat(20);
    for n in 0..560u32 {
        let own = cert(10_000 + n, 1100);
        let s = if n % 10 == 0 { sigs("1", &[(200 + n, Some(&own[..]))]) } else { sigs("1", &[(3, None)]) };
        body.push_str(&format!(
            "  <package name=\"com.vendor.app{n}\" codePath=\"/data/app/~~{n:08x}==/com.vendor.app{n}-1\" nativeLibraryPath=\"/data/app/~~{n:08x}==/com.vendor.app{n}-1/lib\" publicFlags=\"810073605\" privateFlags=\"0\" ft=\"11e8f7d4c00\" ut=\"11e8f7d4c00\" version=\"{n}\" userId=\"{}\" installer=\"com.android.vending\">\n{s}    <perms>\n{items}    </perms>\n    <proper-signing-keyset identifier=\"{n}\" />\n  </package>\n",
            10_400 + n
        ));
    }
    doc(&format!("{body}{}", app_signed(&g)))
}

#[test]
fn c6_parse_time_of_a_realistic_file() {
    let d = realistic_doc();
    assert!(d.len() > 1_100_000 && d.len() < 1_500_000, "{} bytes", d.len());
    let mut times = Vec::new();
    for _ in 0..5 {
        let t = Instant::now();
        let r = package_signers(&d, PKG);
        times.push(t.elapsed());
        assert!(is_good(&r));
    }
    times.sort();
    println!("PERF realistic file {} bytes: fastest {:?}, slowest {:?} of 5 runs", d.len(), times[0], times[4]);
    assert!(times[4].as_secs() < 5, "slowest run {:?}", times[4]);
    let t = Instant::now();
    assert_eq!(auth(&d), Ok(()));
    println!("PERF authenticate on the same file: {:?}", t.elapsed());
}

#[test]
fn c6_parse_time_of_worst_case_shapes_at_the_size_limit() {
    let fill = |prefix: &str, unit: &str, suffix: &str| -> String {
        let n = (MAX_XML - prefix.len() - suffix.len()) / unit.len();
        format!("{prefix}{}{suffix}", unit.repeat(n))
    };
    let many_attrs = {
        let mut t = String::from("<a");
        for i in 0..250 {
            t.push_str(&format!(" x{i}=\"\""));
        }
        t.push_str("/>");
        t
    };
    let mut certs = String::from("<packages><package name=\"p\"><sigs count=\"1\">");
    let mut i = 0u32;
    while certs.len() + 200 < MAX_XML {
        certs.push_str(&format!("<cert index=\"{i}\" key=\"{}\"/>", hex(&cert(i, MIN_CERT))));
        i += 1;
    }
    certs.push_str("</sigs></package></packages>");
    let shapes: Vec<(&str, String)> = vec![
        ("empty elements", fill("<packages>", "<a/>", "</packages>")),
        ("element pairs", fill("<packages>", "<a></a>", "</packages>")),
        ("one attribute of references", fill("<packages><a b=\"", "&#46;", "\"/></packages>")),
        ("many small attributes of references", fill("<packages>", "<a b=\"&lt;&#x2e;&amp;\"/>", "</packages>")),
        ("elements with 250 attributes", fill("<packages>", &many_attrs, "</packages>")),
        ("index-only certificates", fill("<packages><package name=\"p\"><sigs count=\"1\">", "<cert index=\"1\"/>", "</sigs></package></packages>")),
        ("empty comments", fill("<packages>", "<!---->", "</packages>")),
        ("processing instructions", fill("<packages>", "<?a?>", "</packages>")),
        ("one text node", fill("<packages><a>", "> ", "</a></packages>")),
        ("one attribute value", fill("<packages><a b=\"", "> ", "\"/></packages>")),
        ("unclosed brackets", fill("<packages>", "<", "")),
        ("unclosed quotes", fill("<packages><a b=\"", "x", "")),
        ("distinct certificates", certs),
    ];
    for (what, s) in &shapes {
        assert!(s.len() <= MAX_XML && s.len() + 4096 > MAX_XML, "{what}: {} bytes", s.len());
        let t = Instant::now();
        let r = package_signers(s, PKG);
        let took = t.elapsed();
        println!("PERF {what}: {} bytes in {took:?}", s.len());
        assert_eq!(r, None, "{what}");
        assert!(took.as_secs() < 20, "{what}: {took:?}");
    }
    println!("PERF distinct certificates in the last shape: {i}");
}

// -------------------------------------------------------------------- findings

/// Finding F1. A certificate of any other package that is longer than
/// MAX_CERT makes the whole file unusable, so the genuine App is refused
/// (fail-closed) for as long as such a package is installed.
#[test]
fn finding_f1_oversized_certificate_of_another_package_refuses_the_genuine_app() {
    let g = good();
    let at_limit = cert(9, MAX_CERT);
    let above = cert(9, MAX_CERT + 1);
    accepted(&doc(&format!("{}{}", other("com.evil.app", 10301, 200, Some(&at_limit[..])), app_signed(&g))), "other package at the limit");
    unreadable(&doc(&format!("{}{}", other("com.evil.app", 10301, 200, Some(&above[..])), app_signed(&g))), "other package one byte above the limit, before");
    unreadable(&doc(&format!("{}{}", app_signed(&g), other("com.evil.app", 10301, 200, Some(&above[..])))), "other package one byte above the limit, after");
}

/// Finding F2. A key first written below an install-initiator-sigs element is
/// not recorded, so a later index-only reference from the App's sigs does not
/// resolve and the genuine App is refused (fail-closed).
#[test]
fn finding_f2_index_defined_under_install_initiator_sigs_is_not_recorded() {
    let (gv, pv) = (good(), plat());
    let (g, p): (&[u8], &[u8]) = (&gv, &pv);
    let sideloaded = format!(
        "  <package name=\"com.vendor.sideloaded\" userId=\"10320\">\n    <sigs count=\"1\" schemeVersion=\"2\">\n      <cert index=\"40\" key=\"{}\" />\n    </sigs>\n    <install-initiator-sigs count=\"1\" schemeVersion=\"2\">\n      <cert index=\"126\" key=\"{}\" />\n    </install-initiator-sigs>\n  </package>\n",
        hex(p).replace("3082", "3083"),
        hex(g)
    );
    unreadable(&doc(&format!("{sideloaded}{}", app(&sigs("1", &[(126, None)])))), "index defined under install-initiator-sigs before the record");
    // With the key repeated in the record itself the file is read.
    accepted(&doc(&format!("{sideloaded}{}", app_signed(g))), "key repeated in the record");
}

