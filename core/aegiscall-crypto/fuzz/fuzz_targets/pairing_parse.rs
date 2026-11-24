#![no_main]
//! Pairing code parser: arbitrary text and bytes must never panic, and an accepted code must be
//! canonical (its payload re-encodes to a code that parses back to the same payload).

use aegiscall_crypto::PairingCodeV2;
use libfuzzer_sys::fuzz_target;

const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fn canonical(p: &PairingCodeV2) {
    let re = p.to_code().to_string();
    let back = PairingCodeV2::from_code(&re).expect("a re-encoded code must parse");
    assert_eq!(back.pub33, p.pub33);
    assert_eq!(back.xpub, p.xpub);
    assert_eq!(&back.to_raw()[..], &p.to_raw()[..]);
}

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(p) = PairingCodeV2::from_code(s) {
            canonical(&p);
        }
    }
    // Reach the base32 decoder: prefix plus the bytes read as text, and as alphabet symbols.
    let lossy = format!("AEGIS2-{}", String::from_utf8_lossy(data));
    if let Ok(p) = PairingCodeV2::from_code(&lossy) {
        canonical(&p);
    }
    let symbols: String = data.iter().map(|b| ALPHABET[usize::from(*b & 31)] as char).collect();
    if let Ok(p) = PairingCodeV2::from_code(&format!("AEGIS2-{symbols}")) {
        canonical(&p);
    }
    if let Ok(p) = PairingCodeV2::from_raw(data) {
        assert_eq!(&p.to_raw()[..], data);
        canonical(&p);
    }
});
