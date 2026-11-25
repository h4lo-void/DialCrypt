# Packaging the DialCrypt Magisk module

The repository does not contain the daemon binary. Build it, place it in the
module tree, then zip the module.

1. Cross-compile for the Pixel (needs the Android NDK and the Rust target
   `aarch64-linux-android`):

   ```sh
   export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/<host>/bin/aarch64-linux-android34-clang"
   cargo build -p aegiscalld --release --target aarch64-linux-android
   ```

2. Copy the result into the module:

   ```sh
   mkdir -p magisk-module/system/bin
   cp target/aarch64-linux-android/release/aegiscalld magisk-module/system/bin/aegiscalld
   ```

   `customize.sh` sets it to root:root 0755 at install time. Without this
   file `service.sh` logs `E_DAEMON_MISSING` (logcat tag `aegischat`) and no
   secure session can start; the boot restore hook is still installed.

3. Zip the contents of `magisk-module/` (with `module.prop` at the zip root)
   and install it either from the Magisk / KernelSU / APatch manager GUI
   (via `META-INF/com/google/android/update-binary` and `updater-script`) or
   from a root shell with `magisk --install-module <zip>`.

## policy.conf (required)

`/data/adb/aegischat/policy.conf` is created at install time with `armed=0`
and `dedicated_mode=0` (dry run). The installer also pins the signing
certificate of the bundled app:

```
app_cert_sha256=<64 hex digits, SHA-256 of the App's signing certificate>
```

It reads the value from the file `app_cert_sha256` at the module root, which
`tools/android-build/build.sh` writes, and replaces any earlier value, so a
module signed with another key needs no edit by hand. A module packed without
that file leaves the key as it is; then set it to the "Signer #1 certificate
SHA-256 digest" printed by `apksigner verify --print-certs <app.apk>`. The daemon compares this value
with the signing record the package manager keeps for
`io.github.h4lovoid.dialcrypt`. While the key is missing or does not match,
the daemon refuses every connection (FAIL code 206, 205 or 207). That is the
intended behavior, not a fault.

Other keys: `armed=1` makes the daemon really change the system,
`dedicated_mode=1` enables tier 2 (only after device verification),
`ims_uids`, `magisk_pkg`, `avb_keys`, `allowed_ifaces`, `media_learning`,
`allow_vowifi=1` with `epdg_addrs=<comma-separated carrier ePDG IPs>` (keeps
Wi-Fi enabled solely for IPSec/IKEv2 VoWiFi tunnel traffic on UDP 500/4500 and
ESP to the pinned carrier ePDG addresses).
The file must stay root-only (0600); an invalid file means dry run.

Test devices only: `test_allow_usb_debug=1` lets the precheck pass with USB
debugging, developer options and adbd on, and makes the lockdown leave the
USB functions unchanged, so the phone stays reachable over the cable during
a session. Wireless ADB is still refused. Never set it on a phone in real use.

Test devices only: `test_allow_profile_owner=1` lets the precheck pass on a
phone that has a work profile (for example one made by Shelter). A device
owner is still refused. Never set it on a phone in real use.

## Runtime permissions

The app never asks for its call permissions itself. At every boot `service.sh`
grants `CALL_PHONE`, `READ_PHONE_STATE`, `ANSWER_PHONE_CALLS`,
`READ_CALL_LOG`, `WRITE_CALL_LOG` and `RECORD_AUDIO` with `pm grant`
(`CallPermissions.RUNTIME` in the app), except a permission the owner turned
off in Settings. `READ_CALL_LOG` with `WRITE_CALL_LOG` lets the app delete
the system call log entry of a call it placed or took over; without them calls
work the same and the entry stays. The privileged permissions come from
`system/etc/permissions/privapp-permissions-aegiscall.xml`.

`service.sh` also grants `POST_NOTIFICATIONS` (same rule: left alone when the owner
turned it off), so the call notifications of the optional default phone app mode
(`docs/design/default-dialer-v1.md`) can be shown. `service.sh` never assigns
a role; the user picks DialCrypt as the phone app in the App's settings.

## Action button

The Action button of the root manager runs `action.sh`. It runs the restore hook
once (`--now`) and prints `rc=<exit code>` (0 restored, 75 something still
pending). Then it checks `cmd role get-role-holders` for
`android.app.role.DIALER` and `android.app.role.CALL_SCREENING`. For each role
that DialCrypt holds, it gives the role back with
`cmd role add-role-holder --user 0 <role> <system phone app>`, where the system
phone app is the first package name printed by `cmd telecom get-system-dialer`
(`com.google.android.dialer` when that cannot be read). It prints one extra line,
`dialer=<package>` on success or `dialer=failed`, and nothing when DialCrypt
holds neither role. Disabling or removing the module has the same effect on the
next boot, because the package disappears and Android falls back to the phone app
of the system image. Not verified on a device.

## One-shot build (tools/android-build/build.sh)

`tools/android-build/build.sh` produces the signed test APK and the finished
module zip in one go. Run it on a build host that has the Android toolchain,
from a copy of this repository:

```sh
source ~/aegis-build/env.sh
bash tools/android-build/build.sh
```

It builds `libaegiscall_jni.so` (into `app/src/main/jniLibs/arm64-v8a/`, git
ignored) and `aegiscalld` with `cargo ndk`, creates the test signing key
`~/aegis-build/keys/test-release.jks` (RSA 4096, alias `aegis-test`, password in
`~/aegis-build/keys/pass.txt`, mode 600) on the first run, runs
`./gradlew :app:assemblePixelTitanRelease` with the key passed through
`AEGIS_KEYSTORE`, `AEGIS_KEYSTORE_PASS` and `AEGIS_KEY_ALIAS`, and assembles the
module. The key and password stay outside the repository and are never printed.
Without those three variables Gradle still configures and builds an unsigned
release APK.

Artifacts, relative to the repository root:

- `app/build/outputs/apk/pixelTitan/release/app-pixelTitan-release.apk`: signed APK
- `out/module/`: unpacked module (this directory plus `system/bin/aegiscalld`,
  `system/priv-app/DialCrypt/DialCrypt.apk` and `app_cert_sha256`; this file is left out)
- `out/aegischat-module.zip`: the module, `module.prop` at the zip root; install it
  from the KernelSU manager or a root shell
- `out/app_cert_sha256.txt`: 64 lowercase hex digits, the SHA-256 of the APK
  signing certificate

`app_cert_sha256` in `policy.conf` (see above) is the content of
`out/app_cert_sha256.txt`; the script also prints it at the end and puts it in
the module, whose installer pins it. The value changes only if
`~/aegis-build/keys/test-release.jks` is replaced.

## Field-test builds

The test switches `AEGIS_TEST_NO_PIN=1` (built-in test PIN, no PIN screen) and
`AEGIS_FIELD_TEST=1` (line probe files read from `filesDir`)
only take effect in the `fieldTest` build
type. It compiles the release sources with the release signing settings and
gets the version name suffix `-fieldtest`. The release build type always has
all three switches off, and Gradle stops with an error if
`assemblePixelTitanRelease` or `bundlePixelTitanRelease` is run while either
variable is set.

With either variable set to `1`, `build.sh` runs
`./gradlew :app:assemblePixelTitanFieldTest` instead of the release task, takes
the APK from `app/build/outputs/apk/pixelTitan/fieldTest/app-pixelTitan-fieldTest.apk`,
writes the module as `out/aegischat-module-FIELDTEST.zip` and ends with
`DONE: FIELD TEST BUILD`. Never install a field-test build on a phone in real use.
