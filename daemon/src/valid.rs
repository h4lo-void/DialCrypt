//! Format validation for every value that comes from system output, the App
//! or the journal. Nothing is used before passing one of these checks.

pub const MAX_TOKEN: usize = 255;

/// Journal field alphabet: `[A-Za-z0-9._:/,=-]`.
pub fn is_journal_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b':' | b'/' | b',' | b'=' | b'-')
}

pub fn is_journal_token(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_TOKEN && s.bytes().all(is_journal_char)
}

/// Android package name. Must stay identical to `is_pkg` in aegis-restore.sh.
pub fn is_package_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_TOKEN
        && s.contains('.')
        && !s.contains("..")
        && !s.ends_with('.')
        && s.as_bytes()[0].is_ascii_alphabetic()
        && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'.' || c == b'_')
}

/// Network interface name (IFNAMSIZ - 1).
pub fn is_iface_name(s: &str) -> bool {
    (1..=15).contains(&s.len())
        && s.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.'))
}

/// `settings` key. Must stay identical to `is_key` in aegis-restore.sh.
pub fn is_setting_key(s: &str) -> bool {
    (1..=128).contains(&s.len()) && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
}

/// Input method id such as `pkg/.Service`. Same rule as the restore script.
pub fn is_ime_id(s: &str) -> bool {
    is_journal_token(s)
        && s.contains('/')
        && s.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'/'))
}

pub fn is_digits(s: &str, max_len: usize) -> bool {
    !s.is_empty() && s.len() <= max_len && s.bytes().all(|c| c.is_ascii_digit())
}

pub fn parse_u32(s: &str) -> Option<u32> {
    if is_digits(s, 10) {
        s.parse().ok()
    } else {
        None
    }
}

pub fn parse_u64(s: &str) -> Option<u64> {
    if is_digits(s, 20) {
        s.parse().ok()
    } else {
        None
    }
}

pub fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 15) as usize] as char);
    }
    s
}

pub fn hex_decode32(s: &str) -> Option<[u8; 32]> {
    let s = s.trim().to_ascii_lowercase();
    if !is_lower_hex(&s, 64) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        out[i] = (hi * 16 + lo) as u8;
    }
    Some(out)
}

/// Constant-time equality for secrets of equal length.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validators_accept_expected_and_reject_injection() {
        assert!(is_journal_token("global/wifi_on"));
        assert!(!is_journal_token("a b"));
        assert!(!is_journal_token("x;rm"));
        assert!(!is_journal_token("$(id)"));
        assert!(!is_journal_token(""));
        assert!(is_package_name("io.github.h4lovoid.dialcrypt"));
        assert!(!is_package_name("io..x"));
        assert!(!is_package_name("1a.b"));
        assert!(!is_package_name("nodot"));
        assert!(is_iface_name("rmnet1"));
        assert!(!is_iface_name("rmnet1 -j ACCEPT"));
        assert!(is_ime_id("com.a.b/.Ime"));
        assert!(!is_ime_id("com.a.b"));
        assert_eq!(hex_decode32(&"ab".repeat(32)), Some([0xab; 32]));
        assert!(ct_eq(b"abc", b"abc") && !ct_eq(b"abc", b"abd"));
    }
}
