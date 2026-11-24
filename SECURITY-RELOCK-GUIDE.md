# Bootloader Relock and Self-Signed System (Pixel) Guide

This document describes the two boot states DialCrypt supports on a Pixel, and how far the bootloader relock route has been taken. **Steps and commands in this document marked "to be confirmed on device" have no supporting code or script in the repo. Verify them on the target Pixel before use.**

## Current status

- The install method that works today is `magisk-module/`: bootloader unlocked, Magisk in use. On such a device the verified boot chain is broken, so security is lower than on a self-signed system with a relocked bootloader.
- The highest assurance requires relocking the bootloader, having the system image signed only by your own AVB key, and a third-party audit. **This project has not had a third-party audit**, and has not received any security certification.
- The repo contains no build flow for a custom system image, and no configuration that builds the daemon and the app into the system partition. For the relock route, the repo has only the daemon-side precheck (see the table below); everything else has to be done separately and verified on a device.
- Only Google Pixel is supported at present.

## The two boot states the daemon accepts

`daemon/src/precheck.rs` reads the following system properties before startup. Every other combination fails the precheck (`BootStateInvalid`):

| State | `ro.boot.vbmeta.device_state` | `ro.boot.verifiedbootstate` | `ro.boot.flash.locked` | Extra condition |
| :--- | :--- | :--- | :--- | :--- |
| Magisk (`BootMode::Magisk`) | `unlocked` | `orange` | `0` | None |
| Self-signed relock (`BootMode::Relocked`) | `locked` | `yellow` | `1` | The AVB public key digest must be in the `avb_keys` list in `policy.conf` |

`avb_keys` is a comma-separated list of 64-digit hexadecimal digests. The property the code reads the digest from is `ro.boot.vbmeta.public_key_digest`; the source marks this as "to be confirmed on device".

## Relock precautions

- Do not run `fastboot flashing lock` on a device whose `boot` or `init_boot` has been patched with Magisk. On stock Android, the factory AVB key fails to verify the patched image, and the device may not boot. (General behavior, not backed by anything in the repo; to be confirmed on device.)
- After relocking, the system should contain neither Magisk nor `su`. Today the daemon can only be installed through `magisk-module/`, and the boot restore script is also placed in `/data/adb/service.d/`. The repo has no way to deploy the daemon on a system without Magisk.
- Before relocking, prepare a re-flashable image and a backup of the keys; locking and writing a custom key affect the whole device's data and its ability to boot.

## Relock flow outline (all to be confirmed on device; the repo has no matching script)

1. Build a Pixel system image that contains only content you signed yourself (building the image itself is outside this project).
2. Generate an AVB signing key, and export the public key file the Pixel needs to write a custom root of trust:

   ```sh
   openssl genrsa -out aegis_avb_key.pem 4096
   avbtool extract_public_key --key aegis_avb_key.pem --output avb_pkmd.bin
   ```

   Keep the private key offline. Whether the key length and file name meet the target model's requirements is to be confirmed on device.
3. Sign every partition that needs verification, plus `vbmeta`, with that key, and flash the whole image set.
4. Write the custom root of trust and relock, confirming after each step that the device still boots normally:

   ```sh
   fastboot flash avb_custom_key avb_pkmd.bin
   fastboot flashing lock
   ```

   After relocking, the boot screen is expected to show a yellow notice (system signed with a custom key). The behavior of these two commands on each Pixel model and firmware version is to be confirmed on device.
5. Compute the SHA-256 digest of that AVB public key and write it to `avb_keys` in `/data/adb/aegischat/policy.conf`. How to obtain the digest, and whether it matches the value `ro.boot.vbmeta.public_key_digest` outputs, is to be confirmed on device.
6. Turn off "OEM unlocking" in system settings and enable the daemon. The repo does not yet provide a way to deploy the daemon on a system without Magisk.

## Limits that remain after relocking

- Relocking only solves the verified boot chain. The other limits (bearer limited to VoLTE/VoNR, armed daemon lockdown and tier 2 system hardening not yet verified during a live call on a device, low-rate modem gears not yet negotiated in sessions, telecom metadata visible to the carrier) are the same as those listed in [README.md](README.md).
- Until there is a third-party audit, the project should not be described as meeting any specific security level.
