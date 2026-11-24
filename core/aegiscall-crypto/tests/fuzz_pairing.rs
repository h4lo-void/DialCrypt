//! Fuzzing of the pairing code parser (AEGIS2- base32 code, raw = ver || pub33 || X25519 key || CRC-16).
//!
//! Why the parser can be asserted this strictly: the CRC-16/CCITT checksum (generator degree 16, odd
//! constant term, Hamming distance 4 for messages of this size) detects every burst error of up to
//! 16 bits and every pattern of up to 3 flipped bits. Substituting one base32 character changes at
//! most 5 adjacent bits of the 544-bit stream, so a single wrong character is rejected with
//! certainty (an error in the 4 data bits plus the 1 padding bit of the last character is rejected
//! by the CRC or by the zero-padding rule). Inserting or deleting a character shifts the stream by
//! 5 bits and is rejected by the length rules. Two or more wrong characters are only caught with
//! probability 1 - 2^-16 by the CRC (and the version byte, the point check on the identity key and
//! the top-bit rule on the X25519 key shave the remaining chance further), so for those the test
//! asserts consistency and counts how often a different payload slips through; the count must stay
//! near the CRC's 2^-16 expectation.
//!
//! Knobs: AEGIS_FUZZ_ITERS (scales the random-mutation counts), AEGIS_FUZZ_SEED.

use aegiscall_crypto::{PairingCodeV2, SoftwareSigner};
use rand_core::{CryptoRng, RngCore};
use std::time::Instant;

const DEFAULT_SEED: u64 = 0x0AE6_15C4_9A12_2611;
const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const PREFIX: &str = "AEGIS2-";
const RAW_LEN: usize = 68;

struct Rng(u64);

impl Rng {
    fn step(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.step() % n as u64) as usize
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        let mut v = vec![0u8; n];
        self.fill_bytes(&mut v);
        v
    }
    fn bytes_below(&mut self, n: usize) -> Vec<u8> {
        let l = self.below(n);
        self.bytes(l)
    }
}

impl RngCore for Rng {
    fn next_u32(&mut self) -> u32 {
        (self.step() >> 32) as u32
    }
    fn next_u64(&mut self) -> u64 {
        self.step()
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for c in dest.chunks_mut(8) {
            let b = self.step().to_le_bytes();
            c.copy_from_slice(&b[..c.len()]);
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for Rng {}

fn env_u64(name: &str) -> Option<u64> {
    let v = std::env::var(name).ok()?;
    let v = v.trim();
    match v.strip_prefix("0x") {
        Some(h) => u64::from_str_radix(h, 16).ok(),
        None => v.parse().ok(),
    }
}

fn scale() -> u64 {
    env_u64("AEGIS_FUZZ_ITERS").unwrap_or(if cfg!(debug_assertions) { 20 } else { 10_000 })
}

fn seed() -> u64 {
    env_u64("AEGIS_FUZZ_SEED").unwrap_or(DEFAULT_SEED)
}

fn sample_code(rng: &mut Rng, i: u8) -> (PairingCodeV2, String) {
    let s = SoftwareSigner::from_seed([i.wrapping_add(1); 32]);
    let mut xpub = [0u8; 32];
    rng.fill_bytes(&mut xpub);
    xpub[31] &= 0x7F;
    let p = PairingCodeV2::new(s.pub33(), xpub).expect("valid sample identity");
    let code = p.to_code().to_string();
    (p, code)
}

fn normalized(s: &str) -> String {
    s.chars().filter(|c| *c != '-' && *c != ' ').map(|c| c.to_ascii_uppercase()).collect()
}

fn same_payload(a: &PairingCodeV2, b: &PairingCodeV2) -> bool {
    a.pub33 == b.pub33 && a.xpub == b.xpub
}

/// An accepted code must be canonical: its payload re-encodes and parses back to itself.
fn assert_canonical(p: &PairingCodeV2, what: &str) {
    let re = p.to_code().to_string();
    let back = PairingCodeV2::from_code(&re).unwrap_or_else(|_| panic!("{what}: accepted payload does not re-parse"));
    assert!(same_payload(p, &back), "{what}: re-encoded payload differs");
    assert_eq!(&back.to_raw()[..], &p.to_raw()[..], "{what}: raw form differs");
}

/// Indices (in chars) of the base32 payload characters of a canonical code.
fn body_positions(code: &str) -> Vec<usize> {
    code.chars().enumerate().filter(|(i, c)| *i >= PREFIX.len() && *c != '-').map(|(i, _)| i).collect()
}

fn replace_char(code: &str, idx: usize, with: &str) -> String {
    let mut out = String::new();
    for (i, c) in code.chars().enumerate() {
        if i == idx {
            out.push_str(with);
        } else {
            out.push(c);
        }
    }
    out
}

#[test]
fn every_single_character_error_is_rejected() {
    let mut rng = Rng(seed());
    for i in 0..4u8 {
        let (orig, code) = sample_code(&mut rng, i);
        assert!(PairingCodeV2::from_code(&code).is_ok(), "sample code must parse");
        let pos = body_positions(&code);
        assert_eq!(pos.len(), 109, "unexpected code shape");
        let chars: Vec<char> = code.chars().collect();
        for &p in &pos {
            // Substitution by every other base32 symbol.
            for &a in ALPHABET.iter() {
                if a as char == chars[p] {
                    continue;
                }
                let m = replace_char(&code, p, &(a as char).to_string());
                assert!(PairingCodeV2::from_code(&m).is_err(), "substitution at {p} with {} accepted: {m}", a as char);
            }
            // Substitution by characters outside the alphabet, and deletion (also via separators).
            for junk in ["0", "1", "8", "9", "!", "=", "_", "é", "\u{0}", "-", " ", ""] {
                let m = replace_char(&code, p, junk);
                assert!(PairingCodeV2::from_code(&m).is_err(), "replacement of {p} by {junk:?} accepted: {m}");
            }
            // Insertion of one extra base32 symbol before the character.
            for &a in [b'A', b'Z', b'2', b'7'].iter() {
                let m = replace_char(&code, p, &format!("{}{}", a as char, chars[p]));
                assert!(PairingCodeV2::from_code(&m).is_err(), "insertion at {p} accepted: {m}");
            }
        }
        // Every proper prefix, and every append of 1..=40 symbols.
        for cut in 0..code.len() {
            assert!(PairingCodeV2::from_code(&code[..cut]).is_err(), "prefix of {cut} bytes accepted");
        }
        for extra in 1..=40usize {
            let m = format!("{code}{}", "A".repeat(extra));
            assert!(PairingCodeV2::from_code(&m).is_err(), "{extra} appended symbols accepted");
        }
        // The unmodified code still parses to the original payload.
        let back = PairingCodeV2::from_code(&code).unwrap_or_else(|_| panic!("sample code stopped parsing"));
        assert!(same_payload(&orig, &back));
    }
}

#[test]
fn raw_form_rejects_every_burst_up_to_16_bits_and_up_to_3_flips() {
    let mut rng = Rng(seed() ^ 1);
    let (orig, _) = sample_code(&mut rng, 9);
    let raw = *orig.to_raw();
    assert!(PairingCodeV2::from_raw(&raw).is_ok());
    let nbits = RAW_LEN * 8;
    let flip = |r: &mut [u8; RAW_LEN], b: usize| r[b / 8] ^= 0x80 >> (b % 8);
    // Every burst of up to 16 bits (first and last bit of the burst flipped, arbitrary inside).
    for start in 0..nbits {
        for len in 1..=16usize {
            if start + len > nbits {
                break;
            }
            for _ in 0..3 {
                let mut r = raw;
                flip(&mut r, start);
                if len > 1 {
                    flip(&mut r, start + len - 1);
                    for k in 1..len - 1 {
                        if rng.below(2) == 1 {
                            flip(&mut r, start + k);
                        }
                    }
                }
                assert!(PairingCodeV2::from_raw(&r).is_err(), "burst of {len} bits at {start} accepted");
            }
        }
    }
    // Every pair of flipped bits.
    for x in 0..nbits {
        for y in x + 1..nbits {
            let mut r = raw;
            flip(&mut r, x);
            flip(&mut r, y);
            assert!(PairingCodeV2::from_raw(&r).is_err(), "bits {x},{y} accepted");
        }
    }
    // Random triples.
    for _ in 0..(scale() * 100) {
        let (x, y, z) = (rng.below(nbits), rng.below(nbits), rng.below(nbits));
        if x == y || y == z || x == z {
            continue;
        }
        let mut r = raw;
        flip(&mut r, x);
        flip(&mut r, y);
        flip(&mut r, z);
        assert!(PairingCodeV2::from_raw(&r).is_err(), "bits {x},{y},{z} accepted");
    }
    // Every length except 68 is rejected.
    for l in 0..=(RAW_LEN + 16) {
        if l == RAW_LEN {
            continue;
        }
        let mut v = raw.to_vec();
        v.resize(l, 0);
        assert!(PairingCodeV2::from_raw(&v).is_err(), "raw length {l} accepted");
    }
}

#[test]
fn random_and_hostile_strings_never_panic() {
    let mut rng = Rng(seed() ^ 2);
    let n = scale() * 50;
    let mut accepted = 0u64;
    for k in 0..n {
        let s: String = match k % 8 {
            0 => (0..rng.below(300)).map(|_| char::from(rng.below(128) as u8)).collect(),
            1 => {
                let mut s = PREFIX.to_string();
                s.extend((0..rng.below(200)).map(|_| ALPHABET[rng.below(32)] as char));
                s
            }
            2 => {
                // Random scalar values (multi-byte UTF-8, surrogate gaps skipped).
                (0..rng.below(120)).filter_map(|_| char::from_u32((rng.step() % 0x11_0000) as u32)).collect()
            }
            3 => {
                let mut s = PREFIX.to_string();
                s.extend((0..109).map(|_| ALPHABET[rng.below(32)] as char));
                s
            }
            4 => format!("{}{}", PREFIX.to_lowercase(), "-".repeat(rng.below(50))),
            5 => {
                // Prefix lookalikes with multi-byte characters straddling the prefix boundary.
                let mut s = String::from("AEGIS2é");
                s.extend((0..rng.below(120)).map(|_| ALPHABET[rng.below(32)] as char));
                s
            }
            6 => {
                let mut s = String::from("  \t\n");
                s.push_str(PREFIX);
                s.extend((0..rng.below(130)).map(|_| if rng.below(5) == 0 { ' ' } else { ALPHABET[rng.below(32)] as char }));
                s.push_str("\r\n ");
                s
            }
            _ => String::from_utf8_lossy(&rng.bytes_below(200)).into_owned(),
        };
        if let Ok(p) = PairingCodeV2::from_code(&s) {
            accepted += 1;
            assert_canonical(&p, "random input");
        }
    }
    // A random 68-byte raw blob is only accepted when version, CRC and point all line up.
    for _ in 0..n {
        let raw = rng.bytes(RAW_LEN);
        if let Ok(p) = PairingCodeV2::from_raw(&raw) {
            accepted += 1;
            assert_canonical(&p, "random raw");
        }
    }
    assert!(accepted <= 2 + n / 4096, "{accepted} random inputs accepted; the CRC and version byte should make this about 0");
}

#[test]
fn very_long_inputs_are_handled_without_panic_or_acceptance() {
    let mut rng = Rng(seed() ^ 3);
    let (orig, code) = sample_code(&mut rng, 5);
    let big = 1 << 20;
    let cases: Vec<String> = vec![
        format!("{PREFIX}{}", "A".repeat(big)),
        format!("{PREFIX}{}", "2".repeat(big)),
        format!("{}{}", PREFIX, "é".repeat(big / 2)),
        format!("{code}{}", "A".repeat(big)),
        "A".repeat(big),
        "-".repeat(big),
        PREFIX.repeat(big / 8),
        format!("{code}{}", "-".repeat(big)).replace("AEGIS2-", "AEGIS2-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
    ];
    for (i, c) in cases.iter().enumerate() {
        assert!(PairingCodeV2::from_code(c).is_err(), "hostile long case {i} accepted");
    }
    // Separators are ignored by design, so a valid code padded with a lot of them is still that code.
    let padded = format!("{}{}{}", "  ", code.replace('-', &"-".repeat(10_000)), " ".repeat(1 << 16));
    let back = PairingCodeV2::from_code(&padded).unwrap_or_else(|_| panic!("separator padding must be ignored"));
    assert!(same_payload(&orig, &back));
}

#[test]
fn multi_character_mutations_are_consistent_and_collisions_stay_rare() {
    let mut rng = Rng(seed() ^ 4);
    let n = scale() * 50;
    let samples: Vec<(PairingCodeV2, String)> = (0..4u8).map(|i| sample_code(&mut rng, 20 + i)).collect();
    let t0 = Instant::now();
    let (mut accepted_same, mut collisions, mut tried) = (0u64, 0u64, 0u64);
    for _ in 0..n {
        let (orig, code) = &samples[rng.below(samples.len())];
        let mut chars: Vec<char> = code.chars().collect();
        let mut changed_payload_chars = false;
        match rng.below(6) {
            // Two to eight substituted symbols.
            0 | 1 | 2 => {
                let k = 2 + rng.below(7);
                for _ in 0..k {
                    let p = 7 + rng.below(chars.len() - 7);
                    if chars[p] != '-' {
                        chars[p] = ALPHABET[rng.below(32)] as char;
                    }
                }
                changed_payload_chars = true;
            }
            // Case changes and extra separators: same payload, must still be accepted as such.
            3 => {
                for c in chars.iter_mut() {
                    if rng.below(3) == 0 {
                        *c = c.to_ascii_lowercase();
                    }
                }
                let p = rng.below(chars.len());
                chars.insert(p, if rng.below(2) == 0 { ' ' } else { '-' });
            }
            // Swap two payload symbols.
            4 => {
                let (x, y) = (7 + rng.below(chars.len() - 7), 7 + rng.below(chars.len() - 7));
                chars.swap(x, y);
                changed_payload_chars = true;
            }
            // Insert and delete symbols.
            _ => {
                for _ in 0..(1 + rng.below(3)) {
                    let p = 7 + rng.below(chars.len() - 7);
                    if rng.below(2) == 0 {
                        chars.insert(p, ALPHABET[rng.below(32)] as char);
                    } else {
                        chars.remove(p);
                    }
                }
                changed_payload_chars = true;
            }
        }
        let m: String = chars.iter().collect();
        tried += 1;
        if let Ok(p) = PairingCodeV2::from_code(&m) {
            assert_canonical(&p, "mutated code");
            if same_payload(&p, orig) {
                accepted_same += 1;
                assert_eq!(normalized(&m), normalized(code), "same payload accepted from different symbols: {m}");
            } else {
                assert!(changed_payload_chars, "payload changed although only case or separators were touched: {m}");
                collisions += 1;
            }
        }
    }
    eprintln!(
        "fuzz_pairing: {tried} multi-character mutations, {accepted_same} accepted with the same payload, {collisions} accepted with a different payload (CRC collisions), {:.1}s",
        t0.elapsed().as_secs_f64()
    );
    assert!(collisions <= 2 + n / 8192, "{collisions} different payloads accepted out of {n}; the 16-bit CRC predicts about {}", n / 65536);
}
