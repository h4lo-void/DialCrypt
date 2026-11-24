# Contributing to DialCrypt

DialCrypt carries encrypted text over a real phone call, and it depends on
real phones, real carriers, and a rooted system layer. Every phone model and
network behaves a little differently. That makes the most useful contribution a
short, precise report or a small fix with a test.

DialCrypt is a pre-alpha research prototype. Please read the Threat model
section of [`README.md`](README.md) and
[`docs/design/secure-session-v2.md`](docs/design/secure-session-v2.md) before
you change security-relevant code.

## Ways to help

| You have | What helps most |
|---|---|
| Two Pixel phones with a Magisk-rooted setup and a carrier with VoLTE / VoNR | A report: did the call connect, did the modem link come up, how did it behave? |
| Rust experience | A bug fix with a unit test, or a new test case for the modem, the link layer, or the handshake |
| Kotlin or Android experience | A fix or test for the app, the JNI bridge, or the Magisk module |
| A security background | A review of the handshake, the vault and duress flow, or the daemon, reported through [`SECURITY.md`](SECURITY.md) |
| A good eye for text | Documentation fixes |

## Reporting what works and what does not

Open an issue with:

- the commit you tested;
- phone model, Android build, root method, and carrier network (VoLTE / VoNR);
- what you did, what you expected, what happened;
- the relevant log lines, with phone numbers, device serial numbers, and keys
  removed.

Never attach real phone numbers, real call recordings, device serial numbers,
or signing keys. Security problems do not go in a public issue; follow
[`SECURITY.md`](SECURITY.md).

## Building and testing

The Rust workspace (the `aegiscall-*` crates in `core/` and the daemon in
`daemon/`):

```text
cargo test --workspace
cargo deny check licenses bans sources
```

Android unit tests use the `pixelTitan` flavor and the `debug` build type, so
the Gradle task is:

```text
./gradlew :app:testPixelTitanDebugUnitTest
```

Run the tests for the area you touched while you work, and the whole suite
before a pull request. The Magisk module is packaged as described in
[`magisk-module/BUILD.md`](magisk-module/BUILD.md).

## Project rules

- **Permissive third-party dependencies.** Third-party dependencies stay under
  permissive licenses, and `cargo deny check licenses bans sources`
  (configured in [`deny.toml`](deny.toml)) must pass. Do not copy code with an
  incompatible license or an unknown origin into the repository. Code from
  other projects must have a license that allows it and be marked with its
  source and license.
- **Tests for cryptography and parsers.** A change to cryptography (handshake,
  key exchange, ratchet, AEAD, vault, key attestation verification) or to any
  parser (modem, link layer, framing, daemon IPC) must come with tests that
  cover the new behaviour, including malformed input.
- **No personal or secret data in commits.** Do not commit real phone numbers,
  recordings of real people, device serial numbers, or signing keys. Use made-up
  values in tests and documentation.
- **Security problems go through [`SECURITY.md`](SECURITY.md).** Do not open a
  public issue or pull request that describes an unfixed vulnerability.
- **Identifiers stay as they are.** The working names in the code (`aegiscall-*`
  crates, `aegiscalld`, `io.github.h4lovoid.dialcrypt`) are not renamed in
  unrelated changes.

## Changing security-sensitive code

The handshake, the vault, the duress flow, and the daemon's lockdown and
restore logic protect people and their devices, and much of their behaviour
looks odd until you know the failure it prevents. Please:

- keep changes small and say what behaviour they are meant to change;
- add or adapt a unit test, as described above;
- say in the pull request whether you tried the change on a real device and
  real call, on which phone and network. "Not tried on a real call" is a fine
  and useful answer.

The daemon changes network and radio settings and writes a restore journal, so
a change to it must keep the fail-closed restore behaviour described in its
design document.

## Documentation

Documentation changes are welcome. Keep facts consistent between
[`README.md`](README.md) and the design documents in `docs/design/`, and use
made-up names and placeholder numbers in examples.

## Pull requests

Changes reach `main` only through a pull request, merged on GitHub. Keep one
topic per pull request, and describe the problem and the resulting behaviour
first.

## Style

- Rust: `cargo fmt`; no new dependencies without a reason.
- Comments say why, not what.

## Licensing of contributions

DialCrypt is licensed under `GPL-3.0-only` (see [`LICENSE`](LICENSE)). By
submitting a contribution you agree to license it under `GPL-3.0-only` as well
(inbound = outbound), and that it is provided "AS IS", subject to
[`LEGAL.md`](LEGAL.md). Sign off every commit with `git commit -s` to add a
`Signed-off-by` line; this certifies the Developer Certificate of Origin 1.1
(<https://developercertificate.org/>).

<!-- SPDX-FileCopyrightText: h4lo-void <https://github.com/h4lo-void/DialCrypt> -->
