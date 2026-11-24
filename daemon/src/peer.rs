//! Client authentication. The daemon learns the peer uid from SO_PEERCRED,
//! maps it to packages through /data/system/packages.list, and compares the
//! signing certificate digest that the package manager recorded when it
//! verified the APK at install time with the pinned digest. Nothing the App
//! sends about itself is used, and the APK file is never parsed here: only
//! the platform's own verification (signature, content digests, v3 SDK
//! range, signer selection) decides which certificate a package has.
//!
//! The record is the `<sigs>` of the top-level `<package>` element in
//! /data/system/packages.xml, a binary XML file that the daemon (root)
//! converts with `abx2xml <file> -` and reads with [`crate::pkgxml`]. When an
//! update is installed over the system App, the file also holds an
//! `<updated-package>` for the replaced system copy; only `<package>`, the
//! version that runs, is used. The pinned value is the SHA-256 of the
//! certificate DER, the digest `apksigner` prints.
//!
//! To be confirmed on device: `abx2xml` (an `app_process` wrapper) runs from the daemon's
//! SELinux domain and finishes well inside the 20 s command timeout on every
//! connection, and `/system/bin/abx2xml` stays present after OTA updates; if
//! not, every connection is refused with PeerSignatureSourceMissing.

use crate::codes::Code;
use crate::pkgxml;
use crate::sysops::{read_text, SysOps};
use crate::valid::{ct_eq, parse_u32};
use sha2::{Digest, Sha256};

pub const APP_PACKAGE: &str = "io.github.h4lovoid.dialcrypt";
pub const SECURE_PROCESS: &str = "io.github.h4lovoid.dialcrypt:secure";
pub const PACKAGES_LIST: &str = "/data/system/packages.list";
pub const PACKAGES_XML: &str = "/data/system/packages.xml";
/// Prints PACKAGES_XML as text XML on stdout.
pub const PACKAGES_XML_CMD: [&str; 3] = ["abx2xml", PACKAGES_XML, "-"];

/// Accepts only the uid of the single package `APP_PACKAGE`, not
/// debuggable, whose platform-verified signing record is exactly one signer
/// equal to the pinned certificate, without a key rotation history. Any
/// missing, unreadable or ambiguous source refuses the connection.
pub fn authenticate<S: SysOps + ?Sized>(sys: &mut S, uid: u32, pinned: Option<&[u8; 32]>) -> Result<(), Code> {
    let pinned = pinned.ok_or(Code::PinnedCertMissing)?;
    if !(10_000..20_000).contains(&uid) {
        return Err(Code::PeerUidRejected);
    }
    let list = read_text(sys, PACKAGES_LIST).map_err(|_| Code::PeerPackageMismatch)?;
    let mut owners: Vec<&str> = Vec::new();
    let mut debuggable = true;
    for line in list.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 3 || parse_u32(f[1]) != Some(uid) {
            continue;
        }
        owners.push(f[0]);
        if f[0] == APP_PACKAGE {
            debuggable = f[2] != "0";
        }
    }
    match owners.as_slice() {
        [p] if *p == APP_PACKAGE => {}
        [] | [_] => return Err(Code::PeerPackageMismatch),
        _ => return Err(Code::PeerSharedUid),
    }
    if debuggable {
        return Err(Code::PeerDebuggable);
    }
    let xml = sys.read_cmd(&PACKAGES_XML_CMD).map_err(|_| Code::PeerSignatureSourceMissing)?;
    let signers = pkgxml::package_signers(&xml, APP_PACKAGE).ok_or(Code::PeerSignatureSourceMissing)?;
    // A rotation lineage (`<pastSigs>`) is refused: the pin names one key, and
    // accepting a lineage would also have to decide which capabilities the
    // older keys keep.
    if signers.rotated {
        return Err(Code::PeerSignatureMismatch);
    }
    match signers.current.as_slice() {
        [only] if ct_eq(&Sha256::digest(only), pinned) => Ok(()),
        _ => Err(Code::PeerSignatureMismatch),
    }
}
