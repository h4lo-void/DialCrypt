# Fingerprint answer

Optional and off by default. A strong fingerprint can open DialCrypt for one ringing secure call, so the call is not missed while the PIN is typed. It never replaces the PIN anywhere else.

## Summary

Answering a secure call means unlocking the PIN vault before the caller's network gives up, which is often 20 to 30 seconds of ringing. With fingerprint answer on, the vault unlocks with a fingerprint during that ringing call only.

The fingerprint does not open the vault by itself. Turning the feature on stores the PIN stretch P = Argon2id(PIN, salt) of the normal PIN, wrapped by a StrongBox key that needs a fingerprint for every use. When a secure call rings, the fingerprint releases P, and the unlock then runs like a PIN unlock: it spends one single-use StrongBox ticket and rotates the vault. The rotation after a fingerprint unlock gives back only the ticket that unlock spent, so attempts used up by wrong PINs stay used up; only a PIN unlock refills all five. The rollback protection is unchanged, and a failed or cancelled fingerprint spends no ticket.

The unlock is call-scoped. Contacts, pairing and settings cannot be changed, and the vault locks again as soon as that call ends or stops ringing before it is picked up.

## Why P and not the vault root key

The vault root key changes at every rotation, and unwrapping it directly would bypass the single-use tickets. P is the value a PIN unlock already hands to the app (it is the input of the ticket HMAC), so keeping it under a fingerprint-bound key adds no new place where it appears, and every unlock still goes through a ticket.

## Key parameters

Alias `aegis_bio_v1`, AES-256-GCM, encrypt and decrypt:

- StrongBox only (`setIsStrongBoxBacked(true)`). If StrongBox refuses the parameters the feature is unavailable; there is no fallback to another key store.
- `setUserAuthenticationRequired(true)` with `setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG)`: every use needs its own strong biometric bound to the cipher (CryptoObject); the device PIN is not accepted instead.
- `setInvalidatedByBiometricEnrollment(true)`: adding a fingerprint, removing all fingerprints or removing the screen lock destroys the key.
- `setUnlockedDeviceRequired(true)` and `setRandomizedEncryptionRequired(true)`.

The fingerprint dialog is the platform `BiometricPrompt` with `BIOMETRIC_STRONG` only. It is started by the secure process, so the released P never leaves that process.

## Files

Both files live in the app's no-backup directory and are written atomically.

`bio_answer.bin`, 97 bytes:

| Offset | Length | Field |
|---|---|---|
| 0 | 4 | magic `ABIO` |
| 4 | 1 | version = 1 |
| 5 | 32 | binding |
| 37 | 12 | GCM IV |
| 49 | 48 | ciphertext of P (32) and tag (16) |

The AAD is `"AegisBio-v1" ‖ version ‖ binding`. The binding is SHA-256(`"AegisVault-v2 stretch id"` ‖ vault bytes 0..34), which covers the vault magic, format, KDF parameters and salt. Rotation keeps the salt, so the binding stays equal for every file of one vault until a PIN change, which draws a new salt. A wrapped P that belongs to another vault or to an earlier PIN is detected before a ticket is spent and the files are removed.

`bio_fresh.bin`, 13 bytes: `version = 1 · boot count u32 · elapsedRealtime ms u64`. It is written only by a successful PIN unlock, and deleted by a wrong PIN, the emergency PIN, a dead vault, a wipe and turning the feature off. A fingerprint may stand in for the PIN only when the boot count matches and less than 12 hours have passed. Twelve hours lets one PIN entry in the morning cover the day, while every night or new day needs the PIN, when the emergency PIN works again.

A wrong PIN deletes the stamp until the next correct PIN. The stamp is plain data: root software can copy it back or rewrite it, which defeats both the 12-hour window and "a wrong PIN turns fingerprint answer off" (the user's finger is still needed). The attempt limit does not depend on it. The vault caps every rotation after a fingerprint unlock at the tickets that were still in StrongBox plus the one that unlock spent; the file keeps five ticket records, and the records above the cap get wraps whose single-use key is never handed out, so they can never be used. The cap comes from the single-use StrongBox keys, which nothing outside the vault can recreate, so guessing four PINs and refilling the tickets with a fingerprint does not work for someone who can only restore or rewrite files. Root software that can create Keystore entries as the app could recreate entries for the unused records and raise the cap; software with that much access can also read P during a fingerprint unlock, so the cap is not a defence against it. Example: two wrong PINs leave three tickets; a fingerprint answer spends one and its rotation brings the count back to three, not five.

## Lifecycle

- **Turn on**: only from Settings, with no call, ringing call or call-scoped unlock. The user reads a warning and confirms; the vault locks and the PIN is entered once more. That entry is a real attempt and spends a ticket like any unlock, so there is no extra way to try PINs. On success P is kept in memory for at most 60 seconds and dropped on lock. A new key is created, a fingerprint confirms it (encryption), and both files are written. Cancelling or any failure drops P and deletes the key.
- **Turn off**: deletes both files and the key; no PIN needed.
- **Emergency PIN**: the key is destroyed with every other key and both files are deleted. This includes the emergency PIN entered as the current PIN of a PIN change.
- **Dead vault, wipe**: the key and both files are deleted.
- **PIN change**: turns the feature off: once the new PINs are written, both files and the key are deleted and the state is off, because the wrapped P belongs to the old PIN (the new salt also changes the binding, so an old wrap left behind would be refused before a ticket is spent). Turning it on again needs the new PIN. A change that is not written leaves the feature as it was. A PIN change is refused after a fingerprint unlock and while the feature is being turned on, when the app holds P of the current PIN.
- **Fingerprints or screen lock change**: the key store reports the key as permanently invalidated; the files and key are deleted and Settings says the feature was turned off.
- **Restart**: the boot count changes, so the PIN is needed.

## Scope of a fingerprint unlock

The fingerprint is offered only on the unlock screen of a secure call that is ringing and was handed over from the incoming-call prompt. After it:

- the call is answered and the secure session runs as usual;
- saving a contact, editing or deleting one, importing a pairing code, making a new code, showing one's own card and changing settings are refused, and the save screen asks for the PIN instead;
- when the call ends (normally or with an error), or stops ringing before it is picked up, the vault locks at once.

Pressing a finger on the sensor under force therefore yields at most that one call.

### Vault writes during a call-scoped unlock

Every path that can change the vault or the contact metadata, and what it does while the unlock is call-scoped:

| Entry point | Changes | Call-scoped |
|---|---|---|
| Rotation right after the fingerprint unlock | Tickets and vault file | Allowed; refills only the spent ticket |
| Resume secret staging and promotion (VAULT_DIRTY during the call) | The answered contact's resume secrets | Allowed: they belong to this call and are written as usual |
| Attestation verdict stored after the call checks the peer's chain | The answered contact's attestation | Allowed: it is checked against the identity key already stored and signed in this handshake; it changes no identity |
| Mutual mark after a call established with the pairing | contact_meta, not the vault | Allowed: this call proves it |
| Pruning of contact_meta at unlock to the contacts the vault still holds | contact_meta, not the vault | Allowed: it only drops entries of contacts that no longer exist |
| Rebuild of the contact number index at unlock | number_index.bin | Allowed: derived from the stored numbers, no identity data |
| Loading the pairing seed at unlock, or creating it when none is stored | contact_meta and the native core | Allowed: needed to recognise paired callers; showing or changing the code stays refused |
| Save the caller as a new contact (saveContact) | Adds a contact | Refused; the save screen asks for the PIN |
| "Compare again and update" after a key change (SAS confirmed) | Replaces a contact's identity key | Refused; the same screen asks for the PIN |
| Edit, rename, delete a contact; set a number | Contact data | Refused, and the screens are not reachable |
| Import a pairing code (add contact, contact page), preview | PSK, label, number | Refused |
| Show own card or code, make a new code | Pairing seed | Refused |
| Settings, turn fingerprint answer on | Preferences, fingerprint key | Refused (settings are not reachable; turning it on refuses a call-scoped unlock) |
| Change PIN (changePins, nativePinChange) | PIN stretches, salt, tickets and vault file | Refused by the app and by the native core (the vault was opened with a kept stretch); also refused while turning fingerprint answer on holds P (nativeStretchHeld). Both refuse only after the current-PIN check, so the emergency PIN still takes the duress path. Settings are not reachable either |
| Turn fingerprint answer off, wipe | Deletes keys and files | Not reachable from the call screens; both only remove access |
| Lock, emergency PIN, dead vault | Locks or destroys | Allowed |

## Failure handling

The fingerprint dialog sits over the PIN pad and opens once by itself. "Use PIN" closes it at once. Lockout, permanent lockout, unavailable hardware, cancellation and timeout close it and give the focus back to the PIN; "Use fingerprint" is offered again only when the sensor is not locked out. A fingerprint that does not match lets the system ask again. When the call stops ringing the dialog is cancelled. None of this spends a ticket or counts as a wrong PIN, and every key-store or dialog error falls back to the PIN, so the feature never makes a call easier to miss than it is without it.

## Related lock-back behaviour

- When the secure screen is not visible, it keeps watching the call: a call that ends while the screen is off or another app is in front locks the vault (and ends the hardened session after a short grace period), also after a plain call the app was waiting for.
- An incoming secure call that the secure process cannot show (the screen is not in front, the lock screen is up, or the app is ending) is handed back to the full-screen incoming-call prompt. An error screen left from an earlier call is cleared so the new call shows.
- Five minutes without a touch lock the app, except while a call is ringing, starting or up.
  The end screen of a finished call counts as idle and is cleared before locking.
- When the call of a call-scoped unlock ends, or stops ringing before it is picked up, the end screen is cleared with the lock, so the unlock screen that follows can show the next incoming secure call; when the secure screen cannot show it, the call goes back to the full-screen prompt.
- The incoming-call prompt has a Decline button, also over the lock screen.

## Residual risks

- Someone who forces the user's finger onto the sensor while a secure call rings gets that call; the emergency PIN cannot protect it.
- The freshness stamp is plain data. Root software can restore or rewrite it, so with root the 12-hour window and the "wrong PIN turns it off" rule no longer hold; it still needs the user's finger. The attempt limit does not depend on the stamp and holds against restored files, but not against root software that can create Keystore entries as the app.
- Two fingerprint touches are still needed on a locked phone: one for the lock screen and one in the app.

## To be confirmed on a device

1. StrongBox accepts AES-256-GCM together with per-use authentication, unlocked-device-required and invalidation by biometric enrollment.
2. BiometricPrompt shows normally over the secure screen, which sets FLAG_SECURE.
3. Time from "Answer securely" to a connected call with the PIN and with a fingerprint, and the no-answer timeout of the target carriers.
4. After unlocking the lock screen with a fingerprint, whether the in-app dialog asks for a second touch (expected: yes).
5. Adding a fingerprint really invalidates the key.
6. The PIN still works while the sensor is locked out or permanently locked out.
7. `Settings.Global.BOOT_COUNT` is readable without a permission.
8. Compose pauses while the activity is stopped (the reason a non-Compose watcher is needed), and with the watcher, hanging up with the screen off locks or ends the session within two seconds.
9. An incoming call during the error screen, or during the grace period after leaving the app, shows the prompt.
10. Handing an offer back to the prompt while the app is ending after a finished call does not race with the exit.

