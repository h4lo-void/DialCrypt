//! Rate-1/2 K=7 Convolutional FEC + Soft-Decision Viterbi + Deep Block Interleaver + CRC-16.

use crc::{Crc, CRC_16_IBM_SDLC};

pub const SUPERFRAME_BYTES: usize = 23;
pub const SUPERFRAME_DATA_BITS: usize = SUPERFRAME_BYTES * 8; // 184 bits
pub const CONVOL_TAIL_BITS: usize = 6;
pub const PRE_FEC_BITS: usize = SUPERFRAME_DATA_BITS + CONVOL_TAIL_BITS + 2; // 192 bits (184 data + 2 pad + 6 tail)
pub const CODED_BITS: usize = PRE_FEC_BITS * 2; // 384 bits

const CRC16: Crc<u16> = Crc::<u16>::new(&CRC_16_IBM_SDLC);

// Standard NASA/CCSDS K=7 rate-1/2 polynomials (octal 0171, 0133)
const POLY0: u8 = 0b1111001; // 0o171
const POLY1: u8 = 0b1011011; // 0o133
const NUM_STATES: usize = 64;

#[inline]
pub fn crc16_ccitt(data: &[u8]) -> u16 {
    CRC16.checksum(data)
}

#[inline]
pub fn crc8_atm(data: &[u8]) -> u8 {
    let mut crc = 0u8;
    for &byte in data {
        crc ^= byte;
        for _ in 0..8 {
            if (crc & 0x80) != 0 {
                crc = (crc << 1) ^ 0x07;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

#[inline]
fn parity_bit(x: u8) -> u8 {
    (x.count_ones() & 1) as u8
}

/// Encodes `SUPERFRAME_BYTES` (23 bytes = 184 bits) into 384 coded bits (MSB-first per byte).
pub fn encode_superframe_fec(payload: &[u8; SUPERFRAME_BYTES]) -> [u8; CODED_BITS] {
    let mut input_bits = [0u8; PRE_FEC_BITS];
    for byte_idx in 0..SUPERFRAME_BYTES {
        let b = payload[byte_idx];
        for bit in 0..8 {
            input_bits[byte_idx * 8 + bit] = (b >> (7 - bit)) & 1;
        }
    }
    // bits 184..186 are 2 pad bits (0), bits 186..192 are 6 zero tail bits

    let mut coded = [0u8; CODED_BITS];
    let mut state: u8 = 0;
    for (i, &in_bit) in input_bits.iter().enumerate() {
        let reg = ((in_bit & 1) << 6) | (state & 0x3F);
        coded[2 * i] = parity_bit(reg & POLY0);
        coded[2 * i + 1] = parity_bit(reg & POLY1);
        state = reg >> 1;
    }
    coded
}

/// Decodes 384 soft LLRs (`llr > 0` favors bit `1`, `llr < 0` favors bit `0`, `0` = erasure)
/// into `SUPERFRAME_BYTES` (23 bytes) using a K=7 Soft-Decision Viterbi decoder.
pub fn decode_superframe_fec_soft(llr: &[f32; CODED_BITS]) -> [u8; SUPERFRAME_BYTES] {
    let mut metrics = [f32::NEG_INFINITY; NUM_STATES];
    metrics[0] = 0.0;

    // 192 steps * 64 states fits trivially on stack (12 KiB)
    let mut prev_state = [[0u8; NUM_STATES]; PRE_FEC_BITS];
    let mut prev_bit = [[0u8; NUM_STATES]; PRE_FEC_BITS];

    for step in 0..PRE_FEC_BITS {
        let llr0 = llr[2 * step];
        let llr1 = llr[2 * step + 1];
        let mut next_metrics = [f32::NEG_INFINITY; NUM_STATES];

        // During the last 6 tail steps, only input bit 0 is valid
        let max_in_bit = if step >= PRE_FEC_BITS - CONVOL_TAIL_BITS {
            0
        } else {
            1
        };

        for s in 0..NUM_STATES {
            let m = metrics[s];
            if !m.is_finite() {
                continue;
            }
            for in_bit in 0..=max_in_bit {
                let reg = ((in_bit as u8) << 6) | (s as u8);
                let out0 = parity_bit(reg & POLY0);
                let out1 = parity_bit(reg & POLY1);
                let ns = (reg >> 1) as usize;

                let s0 = if out0 == 1 { llr0 } else { -llr0 };
                let s1 = if out1 == 1 { llr1 } else { -llr1 };
                let cand = m + s0 + s1;

                if cand > next_metrics[ns] {
                    next_metrics[ns] = cand;
                    prev_state[step][ns] = s as u8;
                    prev_bit[step][ns] = in_bit as u8;
                }
            }
        }
        metrics = next_metrics;
    }

    // Tail bits force end state = 0 (fallback to best metric if tail severely corrupted)
    let mut cur_state = if metrics[0].is_finite() {
        0usize
    } else {
        metrics
            .iter()
            .enumerate()
            .max_by(|a, b| a.1.total_cmp(b.1))
            .map_or(0, |(idx, _)| idx)
    };

    let mut decoded_bits = [0u8; PRE_FEC_BITS];
    for step in (0..PRE_FEC_BITS).rev() {
        decoded_bits[step] = prev_bit[step][cur_state];
        cur_state = prev_state[step][cur_state] as usize;
    }

    let mut out = [0u8; SUPERFRAME_BYTES];
    for byte_idx in 0..SUPERFRAME_BYTES {
        let mut b = 0u8;
        for bit in 0..8 {
            b = (b << 1) | (decoded_bits[byte_idx * 8 + bit] & 1);
        }
        out[byte_idx] = b;
    }
    out
}

/// Frame permutation stride: with many short frames (Robust300, 64 x 20 ms) consecutive coded bits
/// are spread 19 frames (380 ms) apart so slow fades do not hit a run of adjacent coded bits.
/// The 8- and 16-frame layouts keep stride 1 (unchanged wire format).
fn frame_stride(num_frames: usize) -> usize {
    match num_frames {
        64 => 19, // coprime to 64
        _ => 1,
    }
}

/// Block interleaves 384 coded bits across `num_frames` 20ms frames (`bits_per_frame` per frame).
/// Ensures adjacent coded bits are mapped to maximally separated frames AND distinct subbands.
pub fn interleave_384(coded: &[u8; CODED_BITS], num_frames: usize) -> [u8; CODED_BITS] {
    debug_assert_eq!(CODED_BITS % num_frames, 0);
    let cols = CODED_BITS / num_frames;
    let col_stride = match cols {
        48 => 17, // coprime to 48
        24 => 7,  // coprime to 24
        _ => 1,
    };
    let fstride = frame_stride(num_frames);
    let mut out = [0u8; CODED_BITS];
    for i in 0..CODED_BITS {
        let frame = ((i % num_frames) * fstride) % num_frames;
        let col = ((i / num_frames) * col_stride) % cols;
        out[frame * cols + col] = coded[i];
    }
    out
}

/// Inverse of `interleave_384` for soft LLRs.
pub fn deinterleave_384_soft(channel_llr: &[f32; CODED_BITS], num_frames: usize) -> [f32; CODED_BITS] {
    debug_assert_eq!(CODED_BITS % num_frames, 0);
    let cols = CODED_BITS / num_frames;
    let col_stride = match cols {
        48 => 17,
        24 => 7,
        _ => 1,
    };
    let fstride = frame_stride(num_frames);
    let mut out = [0.0f32; CODED_BITS];
    for i in 0..CODED_BITS {
        let frame = ((i % num_frames) * fstride) % num_frames;
        let col = ((i / num_frames) * col_stride) % cols;
        out[i] = channel_llr[frame * cols + col];
    }
    out
}

/// General rate-1/2 encoder for short handshake capability frames (up to 64 coded bits).
pub fn encode_short_fec(data: &[u8]) -> Vec<u8> {
    let total_in = data.len() * 8 + CONVOL_TAIL_BITS;
    let mut coded = Vec::with_capacity(total_in * 2);
    let mut state: u8 = 0;

    for i in 0..total_in {
        let in_bit = if i < data.len() * 8 {
            (data[i / 8] >> (7 - (i % 8))) & 1
        } else {
            0
        };
        let reg = ((in_bit & 1) << 6) | (state & 0x3F);
        coded.push(parity_bit(reg & POLY0));
        coded.push(parity_bit(reg & POLY1));
        state = reg >> 1;
    }
    coded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fec_recovers_from_two_full_erased_frames_and_bit_flips() {
        let payload: [u8; SUPERFRAME_BYTES] = *b"AegisChat_FEC_Test_2026";
        let coded = encode_superframe_fec(&payload);
        let tx = interleave_384(&coded, 8);

        let mut rx_llr = [0.0f32; CODED_BITS];
        for i in 0..CODED_BITS {
            rx_llr[i] = if tx[i] == 1 { 4.0 } else { -4.0 };
        }

        // Completely erase 2 entire 20ms frames out of 8 (frames 2 and 5 = 96 bits wiped = 25% loss!)
        for i in (2 * 48)..(3 * 48) {
            rx_llr[i] = 0.0;
        }
        for i in (5 * 48)..(6 * 48) {
            rx_llr[i] = 0.0;
        }
        // Plus flip 5 random surviving bits
        for &idx in &[3, 19, 100, 211, 355] {
            rx_llr[idx] = -rx_llr[idx];
        }

        let deinterleaved = deinterleave_384_soft(&rx_llr, 8);
        let decoded = decode_superframe_fec_soft(&deinterleaved);
        assert_eq!(decoded, payload);
    }
}
