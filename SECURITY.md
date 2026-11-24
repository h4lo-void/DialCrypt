# Security

DialCrypt carries end-to-end encrypted text over an ordinary VoLTE / VoNR call
between two Google Pixel phones. It keeps its keys in StrongBox (Titan M2), has
no server and no accounts, and uses a root daemon to cut network access during
a session. A flaw in any of those parts matters, so this page covers how to
report a problem, what is in scope, and what to expect.

## Reporting a vulnerability

Please do not open a public issue, and do not post vulnerability details in
public. Use GitHub's private vulnerability reporting for this repository:
<https://github.com/h4lo-void/DialCrypt/security/advisories/new>. There is no
email address for security reports.

Include:

- what an attacker can do, and what they need first (physical access, a rooted
  device, a position on the call path, a paired peer, and so on);
- the steps to reproduce it, or a test or proof of concept;
- the commit you tested and the device, Android build, and carrier network if
  it depends on them;
- logs with phone numbers, device serial numbers, and keys removed.

## Status and supported versions

DialCrypt is a pre-alpha research prototype. It has not been audited by any
third party, and it has completed only initial VoLTE tests between test phones
with the lockdown daemon in dry-run mode (`armed=0`). Only the latest version
on the `main` branch is supported; security fixes go there, and older commits
are not patched.

It is maintained by one person on a best-effort basis. There is no bug bounty,
and no response or fix time is guaranteed.

## What is in scope

- the handshake and key exchange, and the short authentication string (SAS);
- verification of the key attestation chain;
- the vault and the duress flow (PIN handling, the wrong-PIN limit, the duress
  PIN that destroys keys and vault);
- the JNI boundary between the app and the Rust core;
- the modem and link-layer parsers (anything that reads bytes from the call
  audio);
- the daemon (`aegiscalld`): its IPC, its firewall rules, and its restore
  journal;
- the Magisk module and its sepolicy rules.

Known limitations are described in the Threat model section of
[`README.md`](README.md) and in
[`docs/design/secure-session-v2.md`](docs/design/secure-session-v2.md). Please
read them first; a report about a limitation that is already documented is
still welcome if you can show it is worse than described.

## Testing rules

Test only on devices and phone numbers you own or are authorized to test. Do
not test against other people's calls, carriers, or networks, and do not
attach real call recordings or other people's data to a report. See
[Legal disclaimer & usage notice](LEGAL.md) for the risks of unlocking and
rooting a device.

See also [Legal disclaimer & usage notice](LEGAL.md).

<!-- SPDX-FileCopyrightText: h4lo-void <https://github.com/h4lo-void/DialCrypt> -->
