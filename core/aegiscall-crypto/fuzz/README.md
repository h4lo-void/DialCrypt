# aegiscall-crypto fuzz targets

Coverage-guided targets for the handshake v2 state machine and the pairing code parser. The
mutation tests in `tests/fuzz_handshake.rs` and `tests/fuzz_pairing.rs` run in plain `cargo test`;
these targets are for long libFuzzer runs. They need a nightly toolchain and cargo-fuzz.

    rustup toolchain install nightly --profile minimal
    cargo install cargo-fuzz

Run from `core/aegiscall-crypto` (add `-max_total_time=300` for a five minute run):

    cargo +nightly fuzz run hs_on_message
    cargo +nightly fuzz run pairing_parse

`hs_on_message`: byte 0 picks the path (full, PSK, resume); the rest is a script of operations
(deliver, bit-flip, truncate, retype, raw message, signature, timeout) driving two handshake objects.
A panic, a key mismatch, a tampered message that still yields two established sides, or an aborted
object that revives is a crash. `pairing_parse`: any accepted code must re-encode to itself.

Crashes land in `fuzz/artifacts/<target>/`; replay one with `cargo +nightly fuzz run <target> <file>`.
