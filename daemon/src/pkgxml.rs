//! Signing record of one package in the package manager's settings file,
//! read from the text form printed by `abx2xml /data/system/packages.xml -`.
//!
//! The text is parsed element by element with a strict, single-pass XML
//! scanner: quoted attribute values (unescaped per XML), matched end tags,
//! one `<packages>` root, no DOCTYPE or CDATA. A string that merely looks like
//! markup inside an attribute value can never open an element, and any
//! malformed or truncated input yields `None`. The cost is linear in the input
//! size: every byte is visited a bounded number of times and certificate keys
//! live in a hash map.
//!
//! Certificate references follow the platform writer (`PackageSignatures`):
//! the first `<cert>` with a given `index` under any `<sigs>` or `<pastSigs>`
//! carries the certificate as hex in `key`; later ones carry only `index`. A
//! reference must therefore resolve to a key defined at or before it, and an
//! index defined twice with different keys makes the whole file unusable.

use std::borrow::Cow;
use std::collections::hash_map::Entry;
use std::collections::HashMap;

use crate::valid::parse_u32;

/// Largest accepted `abx2xml` output. The field capture is 1.2 MB; the bound
/// stays below the 8 MiB stdout cap of the real backend, so a truncated
/// capture is rejected by size even before the missing end tags are noticed.
pub const MAX_XML: usize = 6 << 20;
const MAX_DEPTH: usize = 32;
const MAX_ATTRS: usize = 256;
/// Bounds of a DER certificate in bytes. Real X.509 signing certificates are
/// several hundred bytes to a few KiB.
pub const MIN_CERT: usize = 64;
pub const MAX_CERT: usize = 16 << 10;
const MAX_SIGNERS: usize = 64;

/// What the package manager recorded for one package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signers {
    /// DER of each current signing certificate, in file order.
    pub current: Vec<Vec<u8>>,
    /// The package has a `<pastSigs>` (key rotation lineage) record.
    pub rotated: bool,
}

/// Signing record of the top-level `<package name="pkg">`. `None` when the
/// text is not a complete, well-formed settings file within [`MAX_XML`], when
/// there is not exactly one such `<package>`, when it does not have exactly
/// one direct `<sigs>` whose `count` equals its number of `<cert>` children
/// (at least one), when a certificate reference does not resolve, or when any
/// recorded certificate key in the file is malformed or conflicting.
pub fn package_signers(xml: &str, pkg: &str) -> Option<Signers> {
    if xml.len() > MAX_XML {
        return None;
    }
    let xml = xml.strip_prefix('\u{feff}').unwrap_or(xml);
    let mut lx = Lexer { s: xml, pos: 0 };
    let mut st = Scan { pkg, ..Scan::default() };
    let mut stack: Vec<&str> = Vec::new();
    while let Some(ev) = lx.next().ok()? {
        match ev {
            Ev::Skip => {}
            Ev::Text(t) => {
                if stack.is_empty() && !t.bytes().all(is_ws) {
                    return None;
                }
            }
            Ev::Start(tag) => {
                st.open(stack.len(), stack.last().copied(), &tag)?;
                if tag.empty {
                    st.close(stack.len());
                } else {
                    stack.push(tag.name);
                }
            }
            Ev::End(name) => {
                if stack.pop()? != name {
                    return None;
                }
                st.close(stack.len());
            }
        }
    }
    st.finish(stack.is_empty())
}

#[derive(Default)]
struct Scan<'p> {
    pkg: &'p str,
    root_done: bool,
    keys: HashMap<u32, Vec<u8>>,
    targets: u32,
    in_target: bool,
    sigs_seen: u32,
    in_sigs: bool,
    declared: Option<u32>,
    indices: Vec<u32>,
    rotated: bool,
}

impl Scan<'_> {
    /// `depth` is the number of open ancestors, `parent` the innermost one.
    fn open(&mut self, depth: usize, parent: Option<&str>, tag: &Tag) -> Option<()> {
        let name = tag.name;
        if depth == 0 && (self.root_done || name != "packages") {
            return None;
        }
        if depth >= MAX_DEPTH {
            return None;
        }
        if depth == 1 && name == "package" && tag.attr("name") == Some(self.pkg) {
            self.targets += 1;
            if self.targets > 1 {
                return None;
            }
            self.in_target = true;
        }
        if self.in_target && depth >= 2 {
            match name {
                "pastSigs" => self.rotated = true,
                "sigs" => {
                    self.sigs_seen += 1;
                    if depth != 2 || self.sigs_seen > 1 {
                        return None;
                    }
                    self.declared = Some(parse_u32(tag.attr("count")?)?);
                    self.in_sigs = true;
                }
                _ => {}
            }
            if depth == 3 && self.in_sigs && name != "cert" && name != "pastSigs" {
                return None;
            }
        }
        if name == "cert" && matches!(parent, Some("sigs") | Some("pastSigs")) {
            let index = parse_u32(tag.attr("index")?)?;
            if let Some(hex) = tag.attr("key") {
                let der = decode_cert(hex)?;
                match self.keys.entry(index) {
                    Entry::Occupied(e) if *e.get() != der => return None,
                    Entry::Occupied(_) => {}
                    Entry::Vacant(e) => {
                        e.insert(der);
                    }
                }
            }
            if self.in_sigs && depth == 3 && parent == Some("sigs") {
                if !self.keys.contains_key(&index) || self.indices.len() >= MAX_SIGNERS {
                    return None;
                }
                self.indices.push(index);
            }
        }
        Some(())
    }

    /// `depth` is the number of ancestors still open after the element closed.
    fn close(&mut self, depth: usize) {
        match depth {
            0 => self.root_done = true,
            1 => self.in_target = false,
            2 => self.in_sigs = false,
            _ => {}
        }
    }

    fn finish(self, balanced: bool) -> Option<Signers> {
        if !balanced || !self.root_done || self.targets != 1 || self.sigs_seen != 1 {
            return None;
        }
        if self.indices.is_empty() || self.declared != Some(self.indices.len() as u32) {
            return None;
        }
        let current = self.indices.iter().map(|i| self.keys.get(i).cloned()).collect::<Option<Vec<_>>>()?;
        Some(Signers { current, rotated: self.rotated })
    }
}

fn decode_cert(hex: &str) -> Option<Vec<u8>> {
    let b = hex.as_bytes();
    if b.len() % 2 != 0 || b.len() < 2 * MIN_CERT || b.len() > 2 * MAX_CERT {
        return None;
    }
    let nib = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    b.chunks(2).map(|p| Some(nib(p[0])? << 4 | nib(p[1])?)).collect()
}

fn is_ws(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\r' | b'\n')
}

struct Tag<'a> {
    name: &'a str,
    attrs: Vec<(&'a str, Cow<'a, str>)>,
    empty: bool,
}

impl Tag<'_> {
    fn attr(&self, name: &str) -> Option<&str> {
        self.attrs.iter().find(|(n, _)| *n == name).map(|(_, v)| v.as_ref())
    }
}

enum Ev<'a> {
    Start(Tag<'a>),
    End(&'a str),
    Text(&'a str),
    /// XML declaration, processing instruction or comment.
    Skip,
}

struct Lexer<'a> {
    s: &'a str,
    pos: usize,
}

impl<'a> Lexer<'a> {
    fn next(&mut self) -> Result<Option<Ev<'a>>, ()> {
        let b = self.s.as_bytes();
        if self.pos >= b.len() {
            return Ok(None);
        }
        if b[self.pos] != b'<' {
            let end = b[self.pos..].iter().position(|&c| c == b'<').map_or(b.len(), |i| self.pos + i);
            let t = &self.s[self.pos..end];
            self.pos = end;
            return Ok(Some(Ev::Text(t)));
        }
        let rest = &self.s[self.pos..];
        if rest.starts_with("<?") {
            self.pos += rest.find("?>").ok_or(())? + 2;
            return Ok(Some(Ev::Skip));
        }
        if let Some(body) = rest.strip_prefix("<!--") {
            self.pos += 4 + body.find("-->").ok_or(())? + 3;
            return Ok(Some(Ev::Skip));
        }
        if rest.starts_with("<!") {
            return Err(());
        }
        if rest.starts_with("</") {
            self.pos += 2;
            let name = self.name()?;
            self.ws();
            self.expect(b'>')?;
            return Ok(Some(Ev::End(name)));
        }
        self.pos += 1;
        let name = self.name()?;
        let mut attrs: Vec<(&'a str, Cow<'a, str>)> = Vec::new();
        loop {
            let spaced = self.ws();
            match b.get(self.pos) {
                Some(b'>') | Some(b'/') => {
                    let empty = b[self.pos] == b'/';
                    self.pos += 1;
                    if empty {
                        self.expect(b'>')?;
                    }
                    let mut names: Vec<&str> = attrs.iter().map(|(n, _)| *n).collect();
                    names.sort_unstable();
                    if names.windows(2).any(|w| w[0] == w[1]) {
                        return Err(());
                    }
                    return Ok(Some(Ev::Start(Tag { name, attrs, empty })));
                }
                Some(_) if spaced && attrs.len() < MAX_ATTRS => {
                    let an = self.name()?;
                    self.ws();
                    self.expect(b'=')?;
                    self.ws();
                    let q = *b.get(self.pos).ok_or(())?;
                    if q != b'"' && q != b'\'' {
                        return Err(());
                    }
                    let start = self.pos + 1;
                    let len = b[start..].iter().position(|&c| c == q).ok_or(())?;
                    let raw = &self.s[start..start + len];
                    self.pos = start + len + 1;
                    if raw.contains('<') {
                        return Err(());
                    }
                    attrs.push((an, unescape(raw)?));
                }
                _ => return Err(()),
            }
        }
    }

    fn name(&mut self) -> Result<&'a str, ()> {
        let b = self.s.as_bytes();
        let start = self.pos;
        match b.get(start) {
            Some(c) if c.is_ascii_alphabetic() || *c == b'_' || *c == b':' => {}
            _ => return Err(()),
        }
        let len = b[start..]
            .iter()
            .position(|c| !(c.is_ascii_alphanumeric() || matches!(c, b'_' | b':' | b'.' | b'-')))
            .unwrap_or(b.len() - start);
        self.pos = start + len;
        Ok(&self.s[start..start + len])
    }

    /// Skips whitespace; true if there was any.
    fn ws(&mut self) -> bool {
        let start = self.pos;
        let b = self.s.as_bytes();
        while self.pos < b.len() && is_ws(b[self.pos]) {
            self.pos += 1;
        }
        self.pos > start
    }

    fn expect(&mut self, c: u8) -> Result<(), ()> {
        if self.s.as_bytes().get(self.pos) == Some(&c) {
            self.pos += 1;
            Ok(())
        } else {
            Err(())
        }
    }
}

/// Resolves the five predefined entities and numeric character references.
fn unescape(raw: &str) -> Result<Cow<'_, str>, ()> {
    if !raw.contains('&') {
        return Ok(Cow::Borrowed(raw));
    }
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        let after = &rest[i + 1..];
        let semi = after.bytes().take(12).position(|c| c == b';').ok_or(())?;
        let ent = &after[..semi];
        let c = match ent {
            "lt" => '<',
            "gt" => '>',
            "amp" => '&',
            "quot" => '"',
            "apos" => '\'',
            _ => {
                let (digits, radix) = match ent.strip_prefix("#x") {
                    Some(h) => (h, 16),
                    None => (ent.strip_prefix('#').ok_or(())?, 10),
                };
                if digits.is_empty() || !digits.chars().all(|c| c.is_digit(radix)) {
                    return Err(());
                }
                char::from_u32(u32::from_str_radix(digits, radix).map_err(|_| ())?).ok_or(())?
            }
        };
        out.push(c);
        rest = &after[semi + 1..];
    }
    out.push_str(rest);
    Ok(Cow::Owned(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::valid::hex_encode;

    const PKG: &str = "io.github.h4lovoid.dialcrypt";
    const PINNED: &[u8] = b"pinned-release-certificate/0123456789abcdef0123456789abcdef/0001";
    const OTHER: &[u8] = b"attacker-certificate/fedcba9876543210fedcba9876543210/9999999999";
    const PLATFORM: &[u8] = b"platform-certificate/00112233445566778899aabbccddeeff/5555555555";

    /// Our package is signed by OTHER (index 126). PINNED appears only as
    /// decoys: defined at index 57 under another package, carried by an
    /// `<updated-package>` of our name, by a `<package>` of our name nested
    /// inside a `<shared-user>`, and as escaped markup in attribute values.
    fn decoy_doc() -> String {
        let (p, o, k) = (hex_encode(PINNED), hex_encode(OTHER), hex_encode(PLATFORM));
        format!(
            "<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>\n<packages>\n  <version sdkVersion=\"36\" databaseVersion=\"3\" />\n  <permissions>\n    <item name=\"x&quot; /&gt;&lt;package name=&quot;{PKG}&quot;&gt;&lt;sigs count=&quot;1&quot;&gt;&lt;cert index=&quot;57&quot; /&gt;\" package=\"com.evil.app\" protection=\"2\" />\n  </permissions>\n  <package name=\"com.android.shell\" codePath=\"/system/priv-app/Shell\" userId=\"2000\">\n    <sigs count=\"1\" schemeVersion=\"3\">\n      <cert index=\"3\" key=\"{k}\" />\n    </sigs>\n  </package>\n  <package name=\"com.evil.app\" codePath=\"/data/app/~~a/com.evil.app-1\" userId=\"10300\" installer=\"&lt;package name=&apos;{PKG}&apos;&gt;\">\n    <sigs count=\"1\" schemeVersion=\"2\">\n      <cert index=\"57\" key=\"{p}\" />\n    </sigs>\n  </package>\n  <updated-package name=\"{PKG}\" codePath=\"/system/priv-app/DialCrypt\" userId=\"10297\">\n    <sigs count=\"1\" schemeVersion=\"2\">\n      <cert index=\"57\" />\n    </sigs>\n  </updated-package>\n  <package name=\"{PKG}\" codePath=\"/data/app/~~b/{PKG}-2\" userId=\"10297\">\n    <sigs count=\"1\" schemeVersion=\"2\">\n      <cert index=\"126\" key=\"{o}\" />\n    </sigs>\n    <perms>\n      <item name=\"android.permission.INTERNET\" granted=\"true\" flags=\"0\" />\n    </perms>\n  </package>\n  <shared-user name=\"android.uid.system\" userId=\"1000\">\n    <package name=\"{PKG}\">\n      <sigs count=\"1\" schemeVersion=\"2\">\n        <cert index=\"57\" />\n      </sigs>\n    </package>\n    <sigs count=\"1\" schemeVersion=\"3\">\n      <cert index=\"3\" />\n    </sigs>\n  </shared-user>\n</packages>\n"
        )
    }

    /// The same file with our package signed by PINNED.
    fn signed_by_pinned() -> String {
        decoy_doc().replace(&hex_encode(OTHER), &hex_encode(PINNED))
    }

    fn is_pinned(r: &Option<Signers>) -> bool {
        matches!(r, Some(s) if !s.rotated && s.current.len() == 1 && s.current[0] == PINNED)
    }

    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            self.0 >> 33
        }
    }

    #[test]
    fn decoys_do_not_replace_the_top_level_record() {
        assert_eq!(package_signers(&decoy_doc(), PKG), Some(Signers { current: vec![OTHER.to_vec()], rotated: false }));
        assert!(is_pinned(&package_signers(&signed_by_pinned(), PKG)));
    }

    #[test]
    fn decoy_survives_truncation_and_every_byte_mutation_without_a_false_match() {
        let doc = decoy_doc();
        let b = doc.as_bytes();
        // Cutting only the final newline still leaves a complete document.
        let complete = doc.rfind("</packages>").map_or(0, |i| i + "</packages>".len());
        assert_eq!(complete, b.len() - 1);
        for cut in 0..complete {
            if let Ok(s) = std::str::from_utf8(&b[..cut]) {
                assert_eq!(package_signers(s, PKG), None, "truncated at {cut} was accepted");
            }
        }
        for i in 0..b.len() {
            for m in [b'<', b'>', b'"', b'\'', b'&', b'/', b' ', b'0', b'a', b'=', b';', 0x00, 0x7f] {
                for delete in [false, true] {
                    let mut v = b.to_vec();
                    if delete {
                        v.remove(i);
                    } else if v[i] == m {
                        continue;
                    } else {
                        v[i] = m;
                    }
                    let s = String::from_utf8_lossy(&v);
                    assert!(!is_pinned(&package_signers(&s, PKG)), "mutation {m:#x} delete={delete} at {i} yields the pinned certificate");
                }
            }
        }
    }

    #[test]
    fn genuine_record_survives_every_byte_mutation_without_panic() {
        let doc = signed_by_pinned();
        let b = doc.as_bytes();
        for i in 0..b.len() {
            for m in [b'<', b'"', b'&', 0xff] {
                let mut v = b.to_vec();
                v[i] = m;
                let _ = package_signers(&String::from_utf8_lossy(&v), PKG);
            }
        }
    }

    #[test]
    fn parser_never_panics_on_random_input_and_never_finds_the_pinned_cert() {
        let mut rng = Lcg(0x5eed_a5c1_1d00_0001);
        let alphabet: &[u8] = b"<>/=\"'&;#x ?!-[]packgesitnmyoud0123456789abcdef\n";
        let doc = decoy_doc().into_bytes();
        for round in 0..6000 {
            let len = (rng.next() % 600) as usize;
            let raw: Vec<u8> = (0..len)
                .map(|_| if round % 2 == 0 { rng.next() as u8 } else { alphabet[(rng.next() as usize) % alphabet.len()] })
                .collect();
            assert!(!is_pinned(&package_signers(&String::from_utf8_lossy(&raw), PKG)));
            // Several random byte changes, deletions and splices of the decoy file.
            let mut v = doc.clone();
            for _ in 0..1 + rng.next() % 6 {
                let at = (rng.next() as usize) % v.len();
                match rng.next() % 3 {
                    0 => v[at] = alphabet[(rng.next() as usize) % alphabet.len()],
                    1 => {
                        v.remove(at);
                    }
                    _ => {
                        let from = (rng.next() as usize) % doc.len();
                        let n = ((rng.next() % 40) as usize).min(doc.len() - from);
                        v.splice(at..at, doc[from..from + n].iter().copied());
                    }
                }
            }
            let _ = package_signers(&String::from_utf8_lossy(&v), PKG);
        }
    }

    #[test]
    fn entities_and_markup_rules() {
        assert_eq!(unescape("a&lt;&gt;&amp;&quot;&apos;&#46;&#x2E;z").ok().as_deref(), Some("a<>&\"'..z"));
        for bad in ["&", "&lt", "&bogus;", "&#;", "&#x;", "&#xD800;", "&#99999999999;", "&#-1;", "&#x+1;"] {
            assert!(unescape(bad).is_err(), "{bad}");
        }
        let good = signed_by_pinned();
        let broken = [
            good.replace("<packages>", "<!DOCTYPE packages><packages>"),
            good.replace("</perms>", "</perm>"),
            good.replace("codePath=\"/data/app/~~b", "codePath=\"/data/app/<b"),
            good.replace("userId=\"10297\">\n    <sigs", "userId=\"10297\" name=\"x\">\n    <sigs"),
            good.replace("granted=\"true\"", "granted=true"),
            good.replace("granted=\"true\" flags", "granted=\"true\"flags"),
            good.replace("</packages>\n", "</packages>\n<packages></packages>\n"),
            good.replace("</packages>\n", "</packages>\ntrailing\n"),
            good.replace("<?xml", "junk<?xml"),
            good.replace("protection=\"2\"", "protection=\"&nbsp;\""),
            good.replace("<perms>", "<![CDATA[x]]><perms>"),
            good.replace("<perms>", "<!-- open comment <perms>"),
        ];
        for (i, doc) in broken.iter().enumerate() {
            assert_ne!(doc, &good, "case {i} did not change the document");
            assert_eq!(package_signers(doc, PKG), None, "case {i}");
        }
        // Comments, single quotes, a byte order mark and CRLF are valid XML.
        let fine = format!("\u{feff}{}", good.replace("<perms>", "<!-- c --><perms>").replace("granted=\"true\"", "granted='true'").replace('\n', "\r\n"));
        assert!(is_pinned(&package_signers(&fine, PKG)));
    }

    #[test]
    fn deep_nesting_and_size_are_bounded() {
        let good = signed_by_pinned();
        let deep = good.replace("<perms>", &format!("<perms>{}{}", "<a>".repeat(40), "</a>".repeat(40)));
        assert_eq!(package_signers(&deep, PKG), None);
        let pad = " ".repeat(MAX_XML + 1 - good.len());
        let big = good.replace("</packages>", &format!("{pad}</packages>"));
        assert_eq!(big.len(), MAX_XML + 1);
        assert_eq!(package_signers(&big, PKG), None);
        let fits = good.replace("</packages>", &format!("{}</packages>", &pad[1..]));
        assert!(is_pinned(&package_signers(&fits, PKG)));
    }

    #[test]
    fn large_realistic_file_parses() {
        // About 1.3 MB like the field capture, with many index-only references.
        let mut body = String::new();
        for n in 0..600 {
            body.push_str(&format!(
                "  <package name=\"com.vendor.app{n}\" codePath=\"/system/app/App{n}\" userId=\"{}\">\n    <sigs count=\"1\" schemeVersion=\"3\">\n      <cert index=\"3\" />\n    </sigs>\n    <perms>\n{}    </perms>\n  </package>\n",
                10_000 + n,
                "      <item name=\"android.permission.SOMETHING\" granted=\"true\" flags=\"0\" />\n".repeat(25)
            ));
        }
        let doc = signed_by_pinned().replace("  <shared-user", &format!("{body}  <shared-user"));
        assert!(doc.len() > 1_200_000);
        assert!(is_pinned(&package_signers(&doc, PKG)));
    }
}
