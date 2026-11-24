//! Structural APK Signature Scheme v2/v3 reader: returns the SHA-256 of the
//! first certificate each signer block carries.
//!
//! NOT an identity source. It does not verify signatures, content digests or
//! the v3 SDK range, so a crafted APK can carry any certificate bytes. Peer
//! authentication (`peer.rs`) uses the package manager's verified signing
//! record instead; this parser is kept only as a diagnostic helper.

use sha2::{Digest, Sha256};

use crate::sysops::SysOps;

const EOCD_SIG: u32 = 0x0605_4b50;
const MAGIC: &[u8; 16] = b"APK Sig Block 42";
const V2_ID: u32 = 0x7109_871a;
const V3_ID: u32 = 0xf053_68c0;
const MAX_BLOCK: u64 = 16 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApkError {
    Io,
    Format,
    NoSignature,
}

struct Cur<'a> {
    b: &'a [u8],
}

impl<'a> Cur<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if n > self.b.len() {
            return None;
        }
        let (h, t) = self.b.split_at(n);
        self.b = t;
        Some(h)
    }
    fn u32(&mut self) -> Option<u32> {
        let s = self.take(4)?;
        Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn u64(&mut self) -> Option<u64> {
        let s = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(s);
        Some(u64::from_le_bytes(a))
    }
    fn prefixed(&mut self) -> Option<&'a [u8]> {
        let n = self.u32()? as usize;
        self.take(n)
    }
}

fn le32(b: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_le_bytes([*b.get(i)?, *b.get(i + 1)?, *b.get(i + 2)?, *b.get(i + 3)?]))
}

fn le16(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_le_bytes([*b.get(i)?, *b.get(i + 1)?]))
}

fn find_eocd(tail: &[u8]) -> Option<usize> {
    if tail.len() < 22 {
        return None;
    }
    (0..=tail.len() - 22).rev().find(|&i| {
        le32(tail, i) == Some(EOCD_SIG) && le16(tail, i + 20).map(|c| i + 22 + c as usize) == Some(tail.len())
    })
}

fn first_certs(value: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut c = Cur { b: value };
    let mut signers = Cur { b: c.prefixed()? };
    let mut out = Vec::new();
    while !signers.b.is_empty() {
        let mut s = Cur { b: signers.prefixed()? };
        let mut signed = Cur { b: s.prefixed()? };
        let _digests = signed.prefixed()?;
        let mut certs = Cur { b: signed.prefixed()? };
        let first = certs.prefixed()?;
        if first.is_empty() {
            return None;
        }
        out.push(first.to_vec());
    }
    Some(out)
}

pub fn signer_cert_digests<S: SysOps + ?Sized>(sys: &mut S, path: &str) -> Result<Vec<[u8; 32]>, ApkError> {
    let size = sys.file_size(path).map_err(|_| ApkError::Io)?;
    if size < 22 {
        return Err(ApkError::Format);
    }
    let tail_len = size.min(65_535 + 22);
    let tail = sys.read_file_range(path, size - tail_len, tail_len as usize).map_err(|_| ApkError::Io)?;
    let eocd = find_eocd(&tail).ok_or(ApkError::Format)?;
    let cd_offset = le32(&tail, eocd + 16).ok_or(ApkError::Format)? as u64;
    if cd_offset < 32 || cd_offset > size {
        return Err(ApkError::Format);
    }
    let footer = sys.read_file_range(path, cd_offset - 24, 24).map_err(|_| ApkError::Io)?;
    if footer.len() != 24 || &footer[8..24] != MAGIC {
        return Err(ApkError::NoSignature);
    }
    let block_size = Cur { b: &footer[..8] }.u64().ok_or(ApkError::Format)?;
    if !(24..=MAX_BLOCK).contains(&block_size) || block_size + 8 > cd_offset {
        return Err(ApkError::Format);
    }
    let start = cd_offset - block_size - 8;
    let block = sys.read_file_range(path, start, (block_size + 8) as usize).map_err(|_| ApkError::Io)?;
    let mut c = Cur { b: &block };
    if c.u64() != Some(block_size) {
        return Err(ApkError::Format);
    }
    let pairs_len = block.len().checked_sub(8 + 24).ok_or(ApkError::Format)?;
    let mut pairs = Cur { b: c.take(pairs_len).ok_or(ApkError::Format)? };
    let (mut v2, mut v3) = (None, None);
    while !pairs.b.is_empty() {
        let len = pairs.u64().ok_or(ApkError::Format)?;
        if len < 4 || len > pairs.b.len() as u64 {
            return Err(ApkError::Format);
        }
        let id = pairs.u32().ok_or(ApkError::Format)?;
        let value = pairs.take(len as usize - 4).ok_or(ApkError::Format)?;
        match id {
            V2_ID => v2 = Some(value),
            V3_ID => v3 = Some(value),
            _ => {}
        }
    }
    let value = v3.or(v2).ok_or(ApkError::NoSignature)?;
    let certs = first_certs(value).ok_or(ApkError::Format)?;
    if certs.is_empty() {
        return Err(ApkError::NoSignature);
    }
    Ok(certs
        .iter()
        .map(|c| {
            let mut d = [0u8; 32];
            d.copy_from_slice(&Sha256::digest(c));
            d
        })
        .collect())
}

/// Builds a minimal signed-APK layout for tests.
#[cfg(test)]
pub(crate) fn build_test_apk(certs: &[&[u8]], scheme_v3: bool) -> Vec<u8> {
    fn p(b: &[u8]) -> Vec<u8> {
        let mut v = (b.len() as u32).to_le_bytes().to_vec();
        v.extend_from_slice(b);
        v
    }
    let mut certs_seq = Vec::new();
    for c in certs {
        certs_seq.extend(p(c));
    }
    let mut signed = p(&[]);
    signed.extend(p(&certs_seq));
    if scheme_v3 {
        signed.extend(28u32.to_le_bytes());
        signed.extend(0x7fff_ffffu32.to_le_bytes());
    }
    signed.extend(p(&[]));
    let mut signer = p(&signed);
    signer.extend(p(&[]));
    signer.extend(p(b"public-key"));
    let value = p(&p(&signer));
    let id = if scheme_v3 { V3_ID } else { V2_ID };
    let mut pairs = ((value.len() + 4) as u64).to_le_bytes().to_vec();
    pairs.extend(id.to_le_bytes());
    pairs.extend(value);
    let block_size = (pairs.len() + 8 + 16) as u64;
    let mut apk = b"PK\x03\x04local-file-entries".to_vec();
    apk.extend(block_size.to_le_bytes());
    apk.extend(pairs);
    apk.extend(block_size.to_le_bytes());
    apk.extend_from_slice(MAGIC);
    let cd_offset = apk.len() as u32;
    let cd = b"PK\x01\x02central-directory";
    apk.extend_from_slice(cd);
    apk.extend(EOCD_SIG.to_le_bytes());
    apk.extend([0u8; 4]);
    apk.extend(1u16.to_le_bytes());
    apk.extend(1u16.to_le_bytes());
    apk.extend((cd.len() as u32).to_le_bytes());
    apk.extend(cd_offset.to_le_bytes());
    apk.extend(0u16.to_le_bytes());
    apk
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::FakeSys;

    #[test]
    fn reads_v2_and_v3_signer_digests() {
        for v3 in [false, true] {
            let mut f = FakeSys::default();
            f.files.insert("/a.apk".into(), build_test_apk(&[b"cert-one", b"intermediate"], v3));
            let d = signer_cert_digests(&mut f, "/a.apk");
            let mut want = [0u8; 32];
            want.copy_from_slice(&Sha256::digest(b"cert-one"));
            assert_eq!(d, Ok(vec![want]));
        }
        let mut f = FakeSys::default();
        f.files.insert("/b.apk".into(), b"PK not a signed apk at all, just bytes".to_vec());
        assert!(signer_cert_digests(&mut f, "/b.apk").is_err());
        let mut good = build_test_apk(&[b"c"], false);
        let n = good.len();
        good[n - 6] ^= 0xff; // corrupt the central directory offset
        f.files.insert("/c.apk".into(), good);
        assert!(signer_cert_digests(&mut f, "/c.apk").is_err());
    }
}
