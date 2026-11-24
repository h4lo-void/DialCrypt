//! Minimal WAV reader/writer (16-bit PCM).

use std::fs;

pub struct WavData {
    pub rate: u32,
    pub channels: u16,
    /// Left (first) channel only.
    pub samples: Vec<i16>,
}

fn u16le(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}

fn u32le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

pub fn parse_wav(b: &[u8]) -> Result<WavData, String> {
    if b.len() < 12 || &b[0..4] != b"RIFF" || &b[8..12] != b"WAVE" {
        return Err("not a RIFF/WAVE file".to_string());
    }
    let mut pos = 12;
    let mut fmt: Option<(u16, u16, u32, u16)> = None;
    while pos + 8 <= b.len() {
        let id = &b[pos..pos + 4];
        let size = u32le(b, pos + 4) as usize;
        let body = pos + 8;
        if id == b"fmt " {
            if body + 16 > b.len() {
                return Err("fmt chunk truncated".to_string());
            }
            let mut tag = u16le(b, body);
            if tag == 0xFFFE && size >= 26 && body + 26 <= b.len() {
                tag = u16le(b, body + 24);
            }
            fmt = Some((tag, u16le(b, body + 2), u32le(b, body + 4), u16le(b, body + 14)));
        } else if id == b"data" {
            let (tag, channels, rate, bits) = fmt.ok_or("data chunk appears before fmt")?;
            if tag != 1 || bits != 16 {
                return Err(format!("only 16-bit PCM is supported (this file: format code={} bits={})", tag, bits));
            }
            if channels == 0 || rate == 0 {
                return Err("invalid fmt chunk content".to_string());
            }
            let avail = b.len() - body;
            let len = if size == 0 || size > avail { avail } else { size };
            let stride = 2 * channels as usize;
            let frames = len / stride;
            let mut samples = Vec::with_capacity(frames);
            for i in 0..frames {
                let o = body + i * stride;
                samples.push(i16::from_le_bytes([b[o], b[o + 1]]));
            }
            return Ok(WavData { rate, channels, samples });
        }
        pos = body + size + (size & 1);
    }
    Err("data chunk not found".to_string())
}

pub fn read_wav(path: &str) -> Result<WavData, String> {
    let bytes = fs::read(path).map_err(|e| format!("failed to read {}: {}", path, e))?;
    parse_wav(&bytes)
}

pub fn write_wav(path: &str, rate: u32, samples: &[i16]) -> Result<(), String> {
    let data_len = (samples.len() * 2) as u32;
    let mut out = Vec::with_capacity(44 + samples.len() * 2);
    out.extend_from_slice(b"RIFF");
    out.extend_from_slice(&(36 + data_len).to_le_bytes());
    out.extend_from_slice(b"WAVEfmt ");
    out.extend_from_slice(&16u32.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&rate.to_le_bytes());
    out.extend_from_slice(&(rate * 2).to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&16u16.to_le_bytes());
    out.extend_from_slice(b"data");
    out.extend_from_slice(&data_len.to_le_bytes());
    for s in samples {
        out.extend_from_slice(&s.to_le_bytes());
    }
    fs::write(path, out).map_err(|e| format!("failed to write {}: {}", path, e))
}
