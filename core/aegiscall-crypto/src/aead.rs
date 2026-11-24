//! Superframe payload size shared by the multiplexer and the epoch cipher.

/// Plaintext bytes carried by one 23-byte superframe (1 B mux header + 13 B body).
pub const MUX_PAYLOAD_LEN: usize = 14;
