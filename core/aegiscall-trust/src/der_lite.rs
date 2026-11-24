//! Minimal strict DER reader for the Android KeyDescription extension.
//!
//! `der` 0.7 cannot represent tag numbers above 30 (KeyMint uses up to [719]), so the
//! extension is parsed here. Definite minimal lengths only, no indefinite form, no trailing
//! bytes, every access bounds-checked.

pub(crate) const UNIVERSAL: u8 = 0;
pub(crate) const CONTEXT: u8 = 2;
pub(crate) const T_BOOLEAN: u32 = 1;
pub(crate) const T_INTEGER: u32 = 2;
pub(crate) const T_OCTET_STRING: u32 = 4;
pub(crate) const T_ENUMERATED: u32 = 10;
pub(crate) const T_SEQUENCE: u32 = 16;
pub(crate) const T_SET: u32 = 17;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DerError;

pub(crate) type DerResult<T> = Result<T, DerError>;

#[derive(Clone, Copy)]
pub(crate) struct Tlv<'a> {
    pub(crate) class: u8,
    pub(crate) constructed: bool,
    pub(crate) number: u32,
    pub(crate) value: &'a [u8],
}

impl<'a> Tlv<'a> {
    pub(crate) fn is(&self, class: u8, constructed: bool, number: u32) -> bool {
        self.class == class && self.constructed == constructed && self.number == number
    }

    fn universal(&self, constructed: bool, number: u32) -> DerResult<&'a [u8]> {
        if self.is(UNIVERSAL, constructed, number) {
            Ok(self.value)
        } else {
            Err(DerError)
        }
    }

    pub(crate) fn as_uint(&self) -> DerResult<u64> {
        uint(self.universal(false, T_INTEGER)?)
    }

    pub(crate) fn as_enum(&self) -> DerResult<u64> {
        uint(self.universal(false, T_ENUMERATED)?)
    }

    pub(crate) fn as_octets(&self) -> DerResult<&'a [u8]> {
        self.universal(false, T_OCTET_STRING)
    }

    pub(crate) fn as_bool(&self) -> DerResult<bool> {
        match self.universal(false, T_BOOLEAN)? {
            [0x00] => Ok(false),
            [0xff] => Ok(true),
            _ => Err(DerError),
        }
    }

    pub(crate) fn as_sequence(&self) -> DerResult<&'a [u8]> {
        self.universal(true, T_SEQUENCE)
    }

    pub(crate) fn as_set(&self) -> DerResult<&'a [u8]> {
        self.universal(true, T_SET)
    }
}

pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn byte(&mut self) -> DerResult<u8> {
        let b = *self.buf.get(self.pos).ok_or(DerError)?;
        self.pos += 1;
        Ok(b)
    }

    pub(crate) fn read(&mut self) -> DerResult<Tlv<'a>> {
        let b0 = self.byte()?;
        let class = b0 >> 6;
        let constructed = b0 & 0x20 != 0;
        let mut number = u32::from(b0 & 0x1f);
        if number == 0x1f {
            number = 0;
            let mut count = 0u32;
            loop {
                let b = self.byte()?;
                if count == 0 && b == 0x80 {
                    return Err(DerError);
                }
                count += 1;
                if count > 4 {
                    return Err(DerError);
                }
                number = (number << 7) | u32::from(b & 0x7f);
                if b & 0x80 == 0 {
                    break;
                }
            }
            if number < 0x1f {
                return Err(DerError);
            }
        }
        let l0 = self.byte()?;
        let len = if l0 < 0x80 {
            usize::from(l0)
        } else {
            let n = usize::from(l0 & 0x7f);
            if n == 0 || n > 4 {
                return Err(DerError);
            }
            let mut v = 0usize;
            for i in 0..n {
                let b = self.byte()?;
                if i == 0 && b == 0 {
                    return Err(DerError);
                }
                v = (v << 8) | usize::from(b);
            }
            if v < 0x80 {
                return Err(DerError);
            }
            v
        };
        let end = self.pos.checked_add(len).ok_or(DerError)?;
        let value = self.buf.get(self.pos..end).ok_or(DerError)?;
        self.pos = end;
        Ok(Tlv { class, constructed, number, value })
    }

    pub(crate) fn finish(&self) -> DerResult<()> {
        if self.pos == self.buf.len() {
            Ok(())
        } else {
            Err(DerError)
        }
    }
}

/// Exactly one TLV spanning the whole buffer.
pub(crate) fn single(buf: &[u8]) -> DerResult<Tlv<'_>> {
    let mut r = Reader::new(buf);
    let t = r.read()?;
    r.finish()?;
    Ok(t)
}

/// Non-negative, minimally encoded INTEGER/ENUMERATED content that fits in u64.
pub(crate) fn uint(v: &[u8]) -> DerResult<u64> {
    let (&first, rest) = v.split_first().ok_or(DerError)?;
    if first & 0x80 != 0 {
        return Err(DerError);
    }
    let mag = if first == 0 {
        match rest.first() {
            None => return Ok(0),
            Some(b) if b & 0x80 == 0 => return Err(DerError),
            Some(_) => rest,
        }
    } else {
        v
    };
    if mag.len() > 8 {
        return Err(DerError);
    }
    Ok(mag.iter().fold(0u64, |acc, b| (acc << 8) | u64::from(*b)))
}
