//! Tests without a JVM: the inner Bridge functions are called directly. A software P-256 key
//! stands in for the StrongBox identity, a map of HMAC keys for the single-use PIN tickets, and
//! a test CA issues Android-style attestation chains.

use crate::bridge::{Bridge, PAIRING_PSK_CHANGED};
use crate::code::*;
use crate::events::*;
use aegiscall_trust::{APP_PACKAGE, ATTESTATION_CHALLENGE};
use hmac::{Hmac, Mac};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::OnceLock;
use std::time::Duration;
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::der::oid::{AssociatedOid, ObjectIdentifier};
use x509_cert::der::{Decode, Encode, Length, Writer};
use x509_cert::ext::pkix::BasicConstraints;
use x509_cert::ext::{AsExtension, Extension};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{EncodePublicKey, SubjectPublicKeyInfoOwned};
use x509_cert::time::Validity;

mod call;
mod pin;
mod registry;
mod review_psk;

pub(crate) const PIN: &[u8] = b"2580";
pub(crate) const DURESS: &[u8] = b"9110";
const SIGNER: [u8; 32] = [0x5a; 32];
const MIN_PATCH: u32 = 202401;
const ROOT_CN: &str = "CN=Test Attestation Root";
const INTER_CN: &str = "CN=Test Intermediate";

// ------------------------------------------------------------ KeyDescription (DER)

fn tlv(tag: &[u8], content: &[u8]) -> Vec<u8> {
    let mut o = tag.to_vec();
    let n = content.len();
    if n < 0x80 {
        o.push(n as u8);
    } else if n < 0x100 {
        o.extend_from_slice(&[0x81, n as u8]);
    } else {
        o.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]);
    }
    o.extend_from_slice(content);
    o
}

fn uint(v: u64) -> Vec<u8> {
    let mut b: Vec<u8> = v.to_be_bytes().iter().copied().skip_while(|x| *x == 0).collect();
    if b.first().map_or(true, |x| x & 0x80 != 0) {
        b.insert(0, 0);
    }
    b
}

fn int(v: u64) -> Vec<u8> {
    tlv(&[0x02], &uint(v))
}

fn enm(v: u64) -> Vec<u8> {
    tlv(&[0x0a], &uint(v))
}

fn oct(b: &[u8]) -> Vec<u8> {
    tlv(&[0x04], b)
}

fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(&[0x30], &parts.concat())
}

fn set(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(&[0x31], &parts.concat())
}

fn ctx(n: u32, inner: &[u8]) -> Vec<u8> {
    if n < 31 {
        tlv(&[0xa0 | n as u8], inner)
    } else {
        let mut groups = vec![(n & 0x7f) as u8];
        let mut m = n >> 7;
        while m > 0 {
            groups.push(0x80 | (m & 0x7f) as u8);
            m >>= 7;
        }
        groups.push(0xbf);
        groups.reverse();
        tlv(&groups, inner)
    }
}

/// StrongBox, verified boot, EC P-256 signing key of the DialCrypt package.
fn key_description() -> Vec<u8> {
    let mut hw = Vec::new();
    hw.extend(ctx(1, &set(&[int(2)])));
    hw.extend(ctx(2, &int(3)));
    hw.extend(ctx(3, &int(256)));
    hw.extend(ctx(5, &set(&[int(4)])));
    hw.extend(ctx(10, &int(1)));
    hw.extend(ctx(503, &[0x05, 0x00]));
    hw.extend(ctx(702, &int(0)));
    hw.extend(ctx(704, &seq(&[oct(&[0x44; 32]), vec![0x01, 0x01, 0xff], enm(0), oct(&[0x55; 32])])));
    hw.extend(ctx(705, &int(150000)));
    hw.extend(ctx(706, &int(202409)));
    hw.extend(ctx(710, &oct(b"google")));
    hw.extend(ctx(718, &int(20240905)));
    let mut sw = Vec::new();
    sw.extend(ctx(701, &int(1_700_000_000_000)));
    let app_id = seq(&[set(&[seq(&[oct(APP_PACKAGE), int(1)])]), set(&[oct(&SIGNER)])]);
    sw.extend(ctx(709, &oct(&app_id)));
    seq(&[
        int(300),
        enm(2),
        int(300),
        enm(2),
        oct(ATTESTATION_CHALLENGE),
        oct(&[]),
        tlv(&[0x30], &sw),
        tlv(&[0x30], &hw),
    ])
}

struct KdExt(Vec<u8>);

impl AssociatedOid for KdExt {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.11129.2.1.17");
}

impl Encode for KdExt {
    fn encoded_len(&self) -> x509_cert::der::Result<Length> {
        Length::try_from(self.0.len())
    }
    fn encode(&self, w: &mut impl Writer) -> x509_cert::der::Result<()> {
        w.write(&self.0)
    }
}

impl AsExtension for KdExt {
    fn critical(&self, _: &Name, _: &[Extension]) -> bool {
        false
    }
}

fn spki_of(k: &SigningKey) -> SubjectPublicKeyInfoOwned {
    SubjectPublicKeyInfoOwned::from_der(k.verifying_key().to_public_key_der().unwrap().as_bytes()).unwrap()
}

fn issue(signer: &SigningKey, profile: Profile, serial: u8, subject: &str, spki: SubjectPublicKeyInfoOwned, kd: Option<&KdExt>) -> Vec<u8> {
    let manual = matches!(profile, Profile::Manual { .. });
    let mut b = CertificateBuilder::new(
        profile,
        SerialNumber::new(&[0x01, serial]).unwrap(),
        Validity::from_now(Duration::from_secs(3600)).unwrap(),
        Name::from_str(subject).unwrap(),
        spki,
        signer,
    )
    .unwrap();
    if manual {
        b.add_extension(&BasicConstraints { ca: false, path_len_constraint: None }).unwrap();
    }
    if let Some(e) = kd {
        b.add_extension(e).unwrap();
    }
    b.build::<p256::ecdsa::DerSignature>().unwrap().to_der().unwrap()
}

struct Pki {
    inter_key: SigningKey,
    inter_der: Vec<u8>,
    trust_tlv: Vec<u8>,
}

fn push_rec(out: &mut Vec<u8>, t: u8, v: &[u8]) {
    out.push(t);
    out.extend_from_slice(&(v.len() as u16).to_be_bytes());
    out.extend_from_slice(v);
}

fn pki() -> &'static Pki {
    static P: OnceLock<Pki> = OnceLock::new();
    P.get_or_init(|| {
        let root_key = SigningKey::random(&mut OsRng);
        let root = issue(&root_key, Profile::Root, 1, ROOT_CN, spki_of(&root_key), None);
        let inter_key = SigningKey::random(&mut OsRng);
        let profile = Profile::SubCA { issuer: Name::from_str(ROOT_CN).unwrap(), path_len_constraint: None };
        let inter_der = issue(&root_key, profile, 10, INTER_CN, spki_of(&inter_key), None);
        let mut trust_tlv = vec![1u8];
        push_rec(&mut trust_tlv, 1, &root);
        push_rec(&mut trust_tlv, 4, &SIGNER);
        push_rec(&mut trust_tlv, 5, &MIN_PATCH.to_be_bytes());
        Pki { inter_key, inter_der, trust_tlv }
    })
}

pub(crate) fn trust_tlv() -> &'static [u8] {
    &pki().trust_tlv
}

pub(crate) fn hmac(key: &[u8; 32], msg: &[u8]) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).unwrap();
    m.update(msg);
    let mut out = [0u8; 32];
    out.copy_from_slice(&m.finalize().into_bytes());
    out
}

pub(crate) fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

// ------------------------------------------------------------ simulated phone

/// One phone: identity key with its attestation chain, StrongBox tickets and the vault file.
pub(crate) struct Device {
    pub sk: SigningKey,
    pub spki: Vec<u8>,
    pub chain_tlv: Vec<u8>,
    pub tickets: BTreeMap<u32, [u8; 32]>,
    pub blob: Vec<u8>,
}

impl Device {
    pub fn new() -> Self {
        let sk = SigningKey::random(&mut OsRng);
        let chain_tlv = chain_for(&sk, 99);
        let spki = sk.verifying_key().to_public_key_der().unwrap().as_bytes().to_vec();
        Self { sk, spki, chain_tlv, tickets: BTreeMap::new(), blob: Vec::new() }
    }

    pub fn pub33(&self) -> [u8; 33] {
        let mut out = [0u8; 33];
        out.copy_from_slice(self.sk.verifying_key().to_encoded_point(true).as_bytes());
        out
    }

    pub fn live(&self) -> Vec<i32> {
        self.tickets.keys().map(|k| *k as i32).collect()
    }

    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        let sig: Signature = self.sk.sign(msg);
        sig.to_der().as_bytes().to_vec()
    }

    /// Imports a rotation payload; returns the ticket ids to retire.
    pub fn import(&mut self, rot: &[u8]) -> Vec<u32> {
        let n = usize::from(rot[0]);
        let mut off = 1;
        for _ in 0..n {
            let mut k = [0u8; 32];
            k.copy_from_slice(&rot[off + 4..off + 36]);
            self.tickets.insert(be32(&rot[off..]), k);
            off += 36;
        }
        let m = usize::from(rot[off]);
        assert_eq!(rot.len(), off + 1 + 4 * m);
        (0..m).map(|i| be32(&rot[off + 1 + 4 * i..])).collect()
    }

    /// Rotation as the app runs it: import, commit, write the file, retire the old tickets.
    pub fn rotate(&mut self, b: &Bridge, app: i64) {
        let rot = b.vault_rotate_begin(app).unwrap();
        let retire = self.import(&rot);
        self.blob = b.vault_rotate_commit(app, true).unwrap().to_vec();
        for id in retire {
            self.tickets.remove(&id);
        }
    }

    /// App object with identity and an unlocked vault.
    pub fn open(&self, b: &Bridge) -> i64 {
        let app = b.app_open(trust_tlv()).unwrap();
        assert_eq!(b.set_identity(app, &self.spki, &self.chain_tlv), OK);
        app
    }

    pub fn setup(&mut self, b: &Bridge) -> i64 {
        let app = self.open(b);
        let rot = b.pin_setup(app, PIN, DURESS).unwrap();
        assert!(self.import(&rot).is_empty());
        assert_eq!(self.tickets.len(), 5);
        self.blob = b.vault_rotate_commit(app, true).unwrap().to_vec();
        app
    }

    /// One unlock attempt: begin, StrongBox HMAC (consumes the ticket), finish.
    pub fn unlock(&mut self, b: &Bridge, app: i64, pin: &[u8]) -> i32 {
        let begin = match b.pin_begin(app, &self.blob, pin, &self.live()) {
            Ok(v) => v,
            Err(c) => return c,
        };
        self.finish(b, app, &begin)
    }

    /// Phase 2 for a phase-1 result of pin_begin or pin_begin_stretch.
    pub fn finish(&mut self, b: &Bridge, app: i64, begin: &[u8]) -> i32 {
        assert_eq!(begin.len(), 36);
        let id = be32(begin);
        let key = self.tickets.remove(&id).expect("live ticket");
        let out = hmac(&key, &begin[4..]);
        b.pin_finish(app, &self.blob, id as i32, Some(&out), &self.live())
    }
}

/// Chain TLV (leaf, intermediate) attesting sk; another serial gives another valid chain.
pub(crate) fn chain_for(sk: &SigningKey, serial: u8) -> Vec<u8> {
    let p = pki();
    let profile = Profile::Manual { issuer: Some(Name::from_str(INTER_CN).unwrap()) };
    let leaf = issue(&p.inter_key, profile, serial, "CN=Android Keystore Key", spki_of(sk), Some(&KdExt(key_description())));
    let mut chain_tlv = Vec::new();
    for c in [&leaf, &p.inter_der] {
        chain_tlv.extend_from_slice(&(c.len() as u16).to_be_bytes());
        chain_tlv.extend_from_slice(c);
    }
    chain_tlv
}

/// A pairing code of somebody who is not in the test: (code, pub33).
pub(crate) fn synthetic_code() -> (String, [u8; 33]) {
    let sk = SigningKey::random(&mut OsRng);
    let mut pub33 = [0u8; 33];
    pub33.copy_from_slice(sk.verifying_key().to_encoded_point(true).as_bytes());
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let xpub = aegiscall_crypto::PairingSecret::from_seed(&seed).public();
    let code = aegiscall_crypto::PairingCodeV2::new(pub33, xpub).unwrap().to_code();
    (code.as_str().to_owned(), pub33)
}

/// Splits an import_pairing result into (contact id, PSK changed).
pub(crate) fn imported(rc: i32) -> (i32, bool) {
    assert!(rc > 0, "import failed: {rc}");
    (rc & !PAIRING_PSK_CHANGED, rc & PAIRING_PSK_CHANGED != 0)
}

pub(crate) fn events(b: &Bridge, s: i64) -> Vec<(u8, Vec<u8>)> {
    match b.session_poll(s) {
        Ok(buf) => decode_tlv(&buf).expect("well-formed TLV").into_iter().map(|(t, v)| (t, v.to_vec())).collect(),
        Err(_) => Vec::new(),
    }
}

/// Decoded contact list entry: (id, flags, pub33, label).
pub(crate) fn contacts(b: &Bridge, app: i64) -> Vec<(u32, u8, [u8; 33], String)> {
    let buf = b.contact_list(app).unwrap();
    let n = usize::from(u16::from_be_bytes([buf[0], buf[1]]));
    let mut off = 2;
    let mut out = Vec::new();
    for _ in 0..n {
        let id = be32(&buf[off..]);
        let flags = buf[off + 4];
        let mut pub33 = [0u8; 33];
        pub33.copy_from_slice(&buf[off + 5..off + 38]);
        let ll = usize::from(buf[off + 38]);
        let label = String::from_utf8(buf[off + 39..off + 39 + ll].to_vec()).unwrap();
        off += 39 + ll;
        if flags & 0x10 != 0 {
            off += 5;
        }
        if flags & 0x20 != 0 {
            off += 16;
        }
        out.push((id, flags, pub33, label));
    }
    assert_eq!(off, buf.len());
    out
}

/// A phone in a call: answers signature requests, SAS prompts and vault writes like the app.
pub(crate) struct Party {
    pub b: Bridge,
    pub d: Device,
    pub app: i64,
    pub s: i64,
    pub log: Vec<(u8, Vec<u8>)>,
    pub auto_sas: bool,
}

impl Party {
    pub fn new() -> Self {
        let b = Bridge::new();
        let mut d = Device::new();
        let app = d.setup(&b);
        // The app hands the persisted pairing seed over after every unlock.
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        assert_eq!(b.set_pairing_seed(app, &seed), OK);
        Self { b, d, app, s: 0, log: Vec::new(), auto_sas: true }
    }

    pub fn call(&mut self, dial: bool, contact: i32, e164: Option<&str>, now: i64) {
        self.s = self.b.session_create(self.app, dial, contact, e164.map(str::as_bytes), true, now).unwrap();
        self.log.clear();
    }

    pub fn save(&self, contact: i32, label: &str, phone: Option<&str>) -> i32 {
        self.b.session_save_contact(self.s, contact, label.as_bytes(), phone.map(str::as_bytes))
    }

    pub fn import(&self, contact: i32, code: &str, label: Option<&str>) -> i32 {
        self.b.import_pairing(self.app, contact, code.as_bytes(), label.map(str::as_bytes))
    }

    pub fn persist(&mut self) {
        match self.b.vault_export(self.app) {
            Ok(blob) => self.d.blob = blob.to_vec(),
            Err(c) => {
                assert_eq!(c, BAD_STATE);
                self.d.rotate(&self.b, self.app);
            }
        }
    }

    pub fn react(&mut self) {
        loop {
            let evs = events(&self.b, self.s);
            if evs.is_empty() {
                break;
            }
            for (t, v) in evs {
                match t {
                    EV_NEED_SIGNATURE => {
                        let der = self.d.sign(&v[4..]);
                        assert_eq!(self.b.session_sign_result(self.s, be32(&v) as i32, true, Some(&der)), OK);
                    }
                    EV_SAS => {
                        if self.auto_sas {
                            assert_eq!(self.b.session_sas(self.s, true), OK);
                        }
                    }
                    EV_VAULT_DIRTY => {
                        self.persist();
                        assert_eq!(self.b.vault_saved(self.app, be32(&v) as i32), OK);
                    }
                    _ => {}
                }
                self.log.push((t, v));
            }
        }
    }

    pub fn find(&self, t: u8) -> Option<&Vec<u8>> {
        self.log.iter().find(|(x, _)| *x == t).map(|(_, v)| v)
    }

    pub fn has(&self, t: u8) -> bool {
        self.find(t).is_some()
    }

    /// Current resume secret (rs_cur) held for contact.
    pub fn rs_cur(&self, contact: u32) -> Option<[u8; 32]> {
        self.b.resume_secrets(self.app).unwrap().into_iter().find(|(c, _, new)| *c == contact && !new).map(|(_, s, _)| s)
    }

    pub fn flags(&self, contact: u32) -> u8 {
        contacts(&self.b, self.app).into_iter().find(|c| c.0 == contact).map(|c| c.1).unwrap_or(0)
    }
}

/// Lockstep over the wire units (the PCM path has its own test).
pub(crate) fn run_until(a: &mut Party, b: &mut Party, now: &mut i64, max: usize, cond: impl Fn(&Party, &Party) -> bool) -> bool {
    for _ in 0..max {
        if cond(a, b) {
            return true;
        }
        *now += 160;
        let ua = a.b.session_next_unit(a.s, *now).unwrap();
        let ub = b.b.session_next_unit(b.s, *now).unwrap();
        b.b.session_deliver(b.s, ua, *now).unwrap();
        a.b.session_deliver(a.s, ub, *now).unwrap();
        a.react();
        b.react();
    }
    cond(a, b)
}
