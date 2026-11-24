# Notices

Copyright (C) 2026 **h4lo-void** (<https://github.com/h4lo-void>).

DialCrypt is released under the **GNU General Public License v3.0 only**
(`GPL-3.0-only`, verbatim text in [`LICENSE`](LICENSE)). General disclaimers
and usage notices are in [`LEGAL.md`](LEGAL.md).

## Third-party software

All core code in this repository was written for this project. Third-party
dependencies are limited to permissive licenses. For the Rust crates, the
exact set is pinned in [`Cargo.lock`](Cargo.lock), and the policy is
enforced by [`deny.toml`](deny.toml) with `cargo-deny`: it allows only
`MIT`, `Apache-2.0` (also with the LLVM exception), `BSD-2-Clause`,
`BSD-3-Clause`, `ISC`, `Zlib`, `CC0-1.0`, `Unicode-3.0`, and
`Unicode-DFS-2016`, and it rejects unknown registries and git sources. Each
dependency remains under its own license and its own copyright notice.

The Android app is built with Gradle and uses the Android Gradle plugin,
Kotlin, AndroidX, Jetpack Compose, CameraX, and ZXing Core (`com.google.zxing:core`),
which are distributed under the **Apache License, Version 2.0** and their
respective open-source notices.

The Gradle Wrapper files (`gradlew`, `gradlew.bat`, and
`gradle/wrapper/gradle-wrapper.jar`) come from the Gradle project and are
licensed under the **Apache License, Version 2.0**.

## Trademarks & third-party services

The name **DialCrypt** is a reserved identifier of this project; the license
grants no trademark rights in it.

"Google", "Pixel", "Titan M2", "Android", "Google Voice", and other product
names, and "Magisk", are trademarks or names of their respective owners and are
used here only to identify compatible hardware, software, and services. This
project is not affiliated with, and is not endorsed by, Google LLC, the Magisk
project, or any other trademark owner.

<!-- SPDX-FileCopyrightText: h4lo-void <https://github.com/h4lo-void/DialCrypt> -->
