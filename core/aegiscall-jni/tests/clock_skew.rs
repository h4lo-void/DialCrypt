//! Two phones joined through the real modem path: Bridge PCM out, a simulated line, Bridge PCM
//! in. The line resamples the audio to model the two phones' different sample clocks, can
//! insert or drop samples once mid-call (VoLTE jitter buffer), adds a little noise and can go
//! completely silent. Time is the audio itself: every 20 ms each phone plays and hears 320
//! samples, so the reported seconds are call seconds.

use aegiscall_chat::call_session::{HANDSHAKE_LIMIT_MS, STALL_LIMIT_MS};
use aegiscall_jni::code::OK;
use aegiscall_jni::events::{
    decode_tlv, EV_ABORTED, EV_HS_PROGRESS, EV_MESSAGE_RECEIVED, EV_NEED_SIGNATURE, EV_SAS, EV_SAS_CONFIRMED,
};
use aegiscall_jni::Bridge;
use aegiscall_trust::{APP_PACKAGE, ATTESTATION_CHALLENGE};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use std::f64::consts::PI;
use std::str::FromStr;
use std::sync::OnceLock;
use std::time::Duration;
use x509_cert::builder::{Builder, CertificateBuilder};
use x509_cert::der::oid::{AssociatedOid, ObjectIdentifier};
use x509_cert::der::{Decode, Encode, Length, Writer};
use x509_cert::ext::pkix::BasicConstraints;
use x509_cert::ext::{Criticality, Extension};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{EncodePublicKey, SubjectPublicKeyInfoOwned};
use x509_cert::time::Validity;

const PIN: &[u8] = b"2580";
const DURESS: &[u8] = b"9110";
const SIGNER: [u8; 32] = [0x5a; 32];
const MIN_PATCH: u32 = 202401;
const ROOT_CN: &str = "CN=Test Attestation Root";
const INTER_CN: &str = "CN=Test Intermediate";

const RATE: u64 = 16_000;
const CHUNK: usize = 320;
/// A call that has not finished by then counts as failed.
const CALL_LIMIT_MS: u64 = 200_000;
/// Both SAS confirmations must arrive within this much call time (wideband; doubled on
/// narrowband, like the session's own limits).
const ESTABLISH_BOUND_MS: u64 = 60_000;
const STALL_TIMEOUT_CODE: u8 = 4;
const TEXT_AB: &[u8] = b"A to B over a skewed line";
const TEXT_BA: &[u8] = b"B to A over a skewed line";

// ------------------------------------------------------------ attestation chain (test CA)

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

impl Criticality for KdExt {
    fn criticality(&self, _: &Name, _: &[Extension]) -> bool {
        false
    }
}

fn spki_of(k: &SigningKey) -> SubjectPublicKeyInfoOwned {
    SubjectPublicKeyInfoOwned::from_der(k.verifying_key().to_public_key_der().unwrap().as_bytes()).unwrap()
}

fn issue(signer: &SigningKey, profile: Profile, serial: u8, subject: &str, spki: SubjectPublicKeyInfoOwned, kd: Option<&KdExt>) -> Vec<u8> {
    let manual = matches!(profile, Profile::Manual { .. });
    let mut b = CertificateBuilder::new(
        FixtureProfile { kind: profile, subject: Name::from_str(subject).unwrap() },
        SerialNumber::new(&[0x01, serial]).unwrap(),
        Validity::from_now(Duration::from_secs(3600)).unwrap(),
        spki,
    )
    .unwrap();
    if manual {
        b.add_extension(&BasicConstraints { ca: false, path_len_constraint: None }).unwrap();
    }
    if let Some(e) = kd {
        b.add_extension(e).unwrap();
    }
    b.build::<_, p256::ecdsa::DerSignature>(signer).unwrap().to_der().unwrap()
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
        let root_key = <SigningKey as p256::elliptic_curve::Generate>::generate();
        let root = issue(&root_key, Profile::Root, 1, ROOT_CN, spki_of(&root_key), None);
        let inter_key = <SigningKey as p256::elliptic_curve::Generate>::generate();
        let profile = Profile::SubCA { issuer: Name::from_str(ROOT_CN).unwrap(), path_len_constraint: None };
        let inter_der = issue(&root_key, profile, 10, INTER_CN, spki_of(&inter_key), None);
        let mut trust_tlv = vec![1u8];
        push_rec(&mut trust_tlv, 1, &root);
        push_rec(&mut trust_tlv, 4, &SIGNER);
        push_rec(&mut trust_tlv, 5, &MIN_PATCH.to_be_bytes());
        Pki { inter_key, inter_der, trust_tlv }
    })
}

fn chain_for(sk: &SigningKey) -> Vec<u8> {
    let p = pki();
    let profile = Profile::Manual { issuer: Some(Name::from_str(INTER_CN).unwrap()) };
    let leaf = issue(&p.inter_key, profile, 99, "CN=Android Keystore Key", spki_of(sk), Some(&KdExt(key_description())));
    let mut chain_tlv = Vec::new();
    for c in [&leaf, &p.inter_der] {
        chain_tlv.extend_from_slice(&(c.len() as u16).to_be_bytes());
        chain_tlv.extend_from_slice(c);
    }
    chain_tlv
}

// ------------------------------------------------------------ phone

/// One phone in a call: answers signature requests and the SAS prompt like the app.
struct Phone {
    b: Bridge,
    sk: SigningKey,
    s: i64,
    /// (call ms, event type, value)
    log: Vec<(u64, u8, Vec<u8>)>,
}

impl Phone {
    fn new(dial: bool, wideband: bool) -> Self {
        let b = Bridge::new();
        let sk = <SigningKey as p256::elliptic_curve::Generate>::generate();
        let spki = sk.verifying_key().to_public_key_der().unwrap().as_bytes().to_vec();
        let app = b.app_open(&pki().trust_tlv).unwrap();
        assert_eq!(b.set_identity(app, &spki, &chain_for(&sk)), OK);
        b.pin_setup(app, PIN, DURESS).unwrap();
        b.vault_rotate_commit(app, true).unwrap();
        let s = b.session_create(app, dial, 0, None, wideband, 0).unwrap();
        Self { b, sk, s, log: Vec::new() }
    }

    fn react(&mut self, now: u64) {
        loop {
            let Ok(buf) = self.b.session_poll(self.s) else { return };
            let evs: Vec<(u8, Vec<u8>)> =
                decode_tlv(&buf).expect("well-formed TLV").into_iter().map(|(t, v)| (t, v.to_vec())).collect();
            if evs.is_empty() {
                return;
            }
            for (t, v) in evs {
                match t {
                    EV_NEED_SIGNATURE => {
                        let sig: Signature = self.sk.sign(&v[4..]);
                        let req = i32::from_be_bytes([v[0], v[1], v[2], v[3]]);
                        self.b.session_sign_result(self.s, req, true, Some(sig.to_der().as_bytes()));
                    }
                    EV_SAS => {
                        self.b.session_sas(self.s, true);
                    }
                    _ => {}
                }
                self.log.push((now, t, v));
            }
        }
    }

    fn first(&self, t: u8) -> Option<u64> {
        self.log.iter().find(|e| e.1 == t).map(|e| e.0)
    }

    fn progress(&self) -> u8 {
        self.log.iter().filter(|e| e.1 == EV_HS_PROGRESS).map(|e| e.2[0]).max().unwrap_or(0)
    }

    fn received(&self, text: &[u8]) -> bool {
        self.log.iter().any(|e| e.1 == EV_MESSAGE_RECEIVED && &e.2[2..] == text)
    }

    fn aborted(&self) -> Option<(u64, u8)> {
        self.log.iter().find(|e| e.1 == EV_ABORTED).map(|e| (e.0, e.2[0]))
    }
}

// ------------------------------------------------------------ line

const SINC_HALF: usize = 16;
const SINC_RES: usize = 256;

/// Blackman-windowed sinc, sampled every 1/SINC_RES of a sample from 0 to SINC_HALF.
fn sinc_table() -> &'static [f64] {
    static T: OnceLock<Vec<f64>> = OnceLock::new();
    T.get_or_init(|| {
        (0..=SINC_HALF * SINC_RES + 1)
            .map(|j| {
                let t = j as f64 / SINC_RES as f64;
                let sinc = if t == 0.0 { 1.0 } else { (PI * t).sin() / (PI * t) };
                let u = (t / SINC_HALF as f64).min(1.0);
                sinc * (0.42 + 0.5 * (PI * u).cos() + 0.08 * (2.0 * PI * u).cos())
            })
            .collect()
    })
}

/// Band-limited value of x at fractional position pos (zero outside x).
fn interp(x: &[f32], pos: f64) -> f64 {
    let i0 = pos.floor() as i64;
    let at = |k: i64| if k >= 0 && (k as usize) < x.len() { f64::from(x[k as usize]) } else { 0.0 };
    if pos == i0 as f64 {
        return at(i0);
    }
    let tab = sinc_table();
    let mut acc = 0.0;
    for k in i0 - SINC_HALF as i64 + 1..=i0 + SINC_HALF as i64 {
        let d = (k as f64 - pos).abs() * SINC_RES as f64;
        let j = d as usize;
        let f = d - j as f64;
        acc += at(k) * (tab[j] * (1.0 - f) + tab[j + 1] * f);
    }
    acc
}

/// One direction of the call: the sender's audio as the receiver's phone records it.
struct Line {
    sent: Vec<f32>,
    /// The sender's sample clock runs this many ppm faster than the receiver's.
    ppm: f64,
    /// From this received sample on, n extra samples were inserted (n < 0: dropped).
    jump: Option<(u64, i64)>,
    /// From this received sample on, nothing of the sender arrives (not even noise).
    mute_from: Option<u64>,
    heard: u64,
    rng: u64,
}

impl Line {
    fn new(ppm: f64, jump: Option<(u64, i64)>, seed: u64) -> Self {
        Self { sent: Vec::new(), ppm, jump, mute_from: None, heard: 0, rng: seed | 1 }
    }

    fn position(&self, k: u64) -> f64 {
        let mut x = k as f64 * (1.0 + self.ppm * 1e-6);
        if let Some((at, n)) = self.jump {
            if k >= at {
                x -= n as f64;
            }
        }
        x
    }

    fn noise(&mut self) -> f64 {
        let mut x = self.rng;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.rng = x;
        ((x >> 11) as f64 / (1u64 << 53) as f64 - 0.5) * 96.0
    }

    /// The next 20 ms the receiver hears; asks the sender for more audio when needed.
    fn hear(&mut self, from: &Phone, now: u64) -> Vec<i16> {
        let mut out = Vec::with_capacity(CHUNK);
        for _ in 0..CHUNK {
            let k = self.heard;
            self.heard += 1;
            let pos = self.position(k);
            let need = pos.floor() as i64 + SINC_HALF as i64 + 2;
            while (self.sent.len() as i64) < need {
                match from.b.session_tx_pcm(from.s, now as i64) {
                    Ok(Some(p)) if !p.is_empty() => self.sent.extend(p.iter().map(|&s| f32::from(s))),
                    _ => self.sent.extend(std::iter::repeat(0.0f32).take(CHUNK)),
                }
            }
            let v = if self.mute_from.is_some_and(|m| k >= m) { 0.0 } else { interp(&self.sent, pos) + self.noise() };
            out.push(v.round().clamp(-32768.0, 32767.0) as i16);
        }
        out
    }
}

// ------------------------------------------------------------ call

struct Call {
    a: Phone,
    b: Phone,
    ab: Line,
    ba: Line,
    t: u64,
}

#[derive(Debug, Default)]
struct Report {
    established_ms: Option<u64>,
    messages_ms: Option<u64>,
    mute_ms: Option<u64>,
    a_abort: Option<(u64, u8)>,
    b_abort: Option<(u64, u8)>,
}

impl Call {
    /// A dials B. The A to B line sees +ppm, the B to A line -ppm (one pair of clocks); the
    /// jump, at jump_ms of call time, hits both directions.
    fn new(ppm: f64, jump: Option<(u64, i64)>, wideband: bool) -> Self {
        let at = jump.map(|(ms, n)| (ms * RATE / 1000, n));
        Self {
            a: Phone::new(true, wideband),
            b: Phone::new(false, wideband),
            ab: Line::new(ppm, at, 0x9e37_79b9_7f4a_7c15),
            ba: Line::new(-ppm, at, 0xd1b5_4a32_d192_ed03),
            t: 0,
        }
    }

    fn now(&self) -> u64 {
        self.t * 1000 / RATE
    }

    fn tick(&mut self) {
        let now = self.now();
        let to_b = self.ab.hear(&self.a, now);
        let to_a = self.ba.hear(&self.b, now);
        self.b.b.session_rx_pcm(self.b.s, &to_b, now as i64);
        self.a.b.session_rx_pcm(self.a.s, &to_a, now as i64);
        self.t += CHUNK as u64;
        let now = self.now();
        self.a.react(now);
        self.b.react(now);
    }

    /// Runs until both texts arrived, a side aborted or the call limit. mute_b_at: B's audio
    /// stops reaching A once A's handshake progress reaches this percentage.
    fn run(mut self, mute_b_at: Option<u8>) -> Report {
        let mut r = Report::default();
        while self.now() < CALL_LIMIT_MS {
            self.tick();
            let now = self.now();
            if let Some(p) = mute_b_at {
                if r.mute_ms.is_none() && self.a.progress() >= p {
                    self.ba.mute_from = Some(self.ba.heard);
                    r.mute_ms = Some(now);
                }
            }
            r.a_abort = self.a.aborted();
            r.b_abort = self.b.aborted();
            if r.a_abort.is_some() || r.b_abort.is_some() {
                break;
            }
            if r.established_ms.is_none() && self.a.first(EV_SAS_CONFIRMED).is_some() && self.b.first(EV_SAS_CONFIRMED).is_some() {
                r.established_ms = Some(now);
                assert!(self.a.b.session_send_text(self.a.s, TEXT_AB, 0, now as i64) >= 0);
                assert!(self.b.b.session_send_text(self.b.s, TEXT_BA, 0, now as i64) >= 0);
            }
            if r.established_ms.is_some() && self.b.received(TEXT_AB) && self.a.received(TEXT_BA) {
                r.messages_ms = Some(now);
                break;
            }
        }
        r
    }
}

fn secs(ms: Option<u64>) -> String {
    ms.map_or("-".to_owned(), |v| format!("{:.1} s", v as f64 / 1000.0))
}

fn connects(name: &str, ppm: f64, jump: Option<(u64, i64)>, wideband: bool) {
    let r = Call::new(ppm, jump, wideband).run(None);
    let slow = if wideband { 1 } else { 2 };
    println!(
        "{name}: established {} (call time), texts both ways {}, aborts A {:?} B {:?}",
        secs(r.established_ms),
        secs(r.messages_ms),
        r.a_abort,
        r.b_abort
    );
    assert_eq!((r.a_abort, r.b_abort), (None, None), "{name}: {r:?}");
    let est = r.established_ms.unwrap_or_else(|| panic!("{name}: not established: {r:?}"));
    assert!(est <= ESTABLISH_BOUND_MS * slow && est < HANDSHAKE_LIMIT_MS * slow, "{name}: established only after {est} ms");
    assert!(r.messages_ms.is_some(), "{name}: texts not delivered both ways: {r:?}");
}

#[test]
fn line_0ppm_establishes_and_texts_cross() {
    connects("0ppm", 0.0, None, true);
}

#[test]
fn line_plus_200ppm_establishes_and_texts_cross() {
    connects("+200ppm", 200.0, None, true);
}

#[test]
fn line_minus_200ppm_establishes_and_texts_cross() {
    connects("-200ppm", -200.0, None, true);
}

#[test]
fn line_minus_116ppm_with_40_sample_jump_at_20s_establishes_and_texts_cross() {
    connects("-116ppm+jump40@20s", -116.0, Some((20_000, 40)), true);
}

#[test]
fn narrowband_line_minus_200ppm_with_40_sample_drop_establishes_and_texts_cross() {
    connects("narrowband-200ppm-drop40@20s", -200.0, Some((20_000, -40)), false);
}

#[test]
fn peer_silent_mid_handshake_aborts_with_stall_timeout() {
    let r = Call::new(-116.0, None, true).run(Some(30));
    let mute = r.mute_ms.expect("handshake reached 30 %");
    let (at, code) = r.a_abort.unwrap_or_else(|| panic!("A did not abort: {r:?}"));
    println!(
        "silent peer: B muted at {}, A aborted with code {code} at {} ({:.1} s of silence)",
        secs(Some(mute)),
        secs(Some(at)),
        (at - mute) as f64 / 1000.0
    );
    assert_eq!(code, STALL_TIMEOUT_CODE);
    assert!(r.established_ms.is_none());
    assert!(at - mute <= STALL_LIMIT_MS + 1_000, "abort {} ms after the peer went silent", at - mute);
}

// x509-cert 0.3 replaced the builder's `Profile` enum with the `BuilderProfile` trait. This keeps
// the 0.2 Root / SubCA / Manual variants these fixtures use and emits the same extensions, in the
// same order, as x509-cert 0.2 did.
mod fixture_profile {
    use x509_cert::builder::profile::BuilderProfile;
    use x509_cert::certificate::TbsCertificate;
    use x509_cert::ext::pkix::{AuthorityKeyIdentifier, BasicConstraints, KeyUsage, KeyUsages, SubjectKeyIdentifier};
    use x509_cert::ext::{Extension, ToExtension};
    use x509_cert::name::Name;
    use x509_cert::spki::SubjectPublicKeyInfoRef;

    pub(super) enum Profile {
        Root,
        SubCA { issuer: Name, path_len_constraint: Option<u8> },
        Manual { issuer: Option<Name> },
    }

    pub(super) struct FixtureProfile {
        pub(super) kind: Profile,
        pub(super) subject: Name,
    }

    impl BuilderProfile for FixtureProfile {
        fn get_issuer(&self, subject: &Name) -> Name {
            match &self.kind {
                Profile::Root => subject.clone(),
                Profile::SubCA { issuer, .. } => issuer.clone(),
                Profile::Manual { issuer } => issuer.as_ref().unwrap_or(subject).clone(),
            }
        }

        fn get_subject(&self) -> Name {
            self.subject.clone()
        }

        fn build_extensions(
            &self,
            spk: SubjectPublicKeyInfoRef<'_>,
            issuer_spk: SubjectPublicKeyInfoRef<'_>,
            tbs: &TbsCertificate,
        ) -> x509_cert::builder::Result<Vec<Extension>> {
            let path_len_constraint = match &self.kind {
                Profile::Manual { .. } => return Ok(Vec::new()),
                Profile::Root => None,
                Profile::SubCA { path_len_constraint, .. } => *path_len_constraint,
            };
            let subject = tbs.subject();
            let mut exts = Vec::new();
            exts.push(SubjectKeyIdentifier::try_from(spk)?.to_extension(subject, &exts)?);
            if !matches!(self.kind, Profile::Root) {
                exts.push(AuthorityKeyIdentifier::try_from(issuer_spk)?.to_extension(subject, &exts)?);
            }
            exts.push(BasicConstraints { ca: true, path_len_constraint }.to_extension(subject, &exts)?);
            exts.push(KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign).to_extension(subject, &exts)?);
            Ok(exts)
        }
    }
}
use fixture_profile::{FixtureProfile, Profile};
