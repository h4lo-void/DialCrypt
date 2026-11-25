use super::*;
use rand_core::OsRng;
use std::collections::BTreeMap;

const PIN: &[u8] = b"246810";
const DURESS: &[u8] = b"135790";
const WRONG: &[u8] = b"000000";

/// Software stand-in for StrongBox single-use HMAC keys (setMaxUsageCount(1)).
#[derive(Clone, Default)]
struct SimKeystore {
    keys: BTreeMap<u32, [u8; 32]>,
}

impl SimKeystore {
    fn import(&mut self, rot: &Rotation) {
        for (id, m) in &rot.new {
            self.keys.insert(*id, *m.as_bytes());
        }
    }
    /// Consumes the key: a second use of the same id returns None.
    fn use_ticket(&mut self, id: u32, input: &[u8; 32]) -> Option<[u8; 32]> {
        let k = self.keys.remove(&id)?;
        Some(*hmac32(&k, &[input]).unwrap().as_bytes())
    }
    fn retire(&mut self, ids: &[u32]) {
        for id in ids {
            let _ = self.use_ticket(*id, &[0u8; 32]);
        }
    }
    fn live(&self) -> Vec<u32> {
        self.keys.keys().copied().collect()
    }
}

fn attempt(ks: &mut SimKeystore, blob: &[u8], pin: &[u8]) -> UnlockOutcome {
    let tu = match Vault::begin_unlock(blob, pin, &ks.live()) {
        Ok(t) => t,
        Err(TrustError::VaultDead) => return UnlockOutcome::Dead,
        Err(_) => return UnlockOutcome::Malformed,
    };
    let out = ks.use_ticket(tu.ticket_id, tu.hmac_input.as_bytes());
    Vault::finish_unlock(blob, tu, out.as_ref(), &ks.live())
}

fn pub33() -> [u8; 33] {
    let sk = <p256::SecretKey as p256::elliptic_curve::Generate>::generate();
    let enc = p256::elliptic_curve::sec1::ToSec1Point::to_sec1_point(&sk.public_key(), true);
    <[u8; 33]>::try_from(enc.as_bytes()).unwrap()
}

fn new_vault() -> (Vault, Vec<u8>, SimKeystore) {
    let (mut v, rot) = Vault::create(PIN, DURESS, &mut OsRng).unwrap();
    let mut ks = SimKeystore::default();
    ks.import(&rot);
    let blob = v.commit_rotation().unwrap();
    (v, blob, ks)
}

fn sas_contact(label: &str, phone: Option<&[u8]>) -> NewContact {
    NewContact {
        pub33: pub33(),
        label: label.to_owned(),
        phone: phone.map_or(PhoneChoice::NoNumber, |p| PhoneChoice::UserConfirmed(p.to_vec())),
        proof: ContactProof::SasMatchedThisCall,
    }
}

/// Rotates (unlock or identity change) and returns the new file after retiring old tickets.
fn rotate(v: &mut Vault, ks: &mut SimKeystore) -> Vec<u8> {
    let rot = v.begin_rotation(&mut OsRng).unwrap();
    ks.import(&rot);
    let blob = v.commit_rotation().unwrap();
    ks.retire(&rot.retire);
    blob
}

fn unlock_normal(ks: &mut SimKeystore, blob: &[u8]) -> Vault {
    match attempt(ks, blob, PIN) {
        UnlockOutcome::Normal(v) => *v,
        other => panic!("expected Normal, got {other:?}"),
    }
}

#[test]
fn file_format_shape() {
    let (_v, blob, _ks) = new_vault();
    assert_eq!(blob.len(), VAULT_PAD_BLOCK);
    assert_eq!(&blob[..4], b"AGVT");
    assert_eq!(Vault::ticket_ids(&blob).unwrap(), vec![1, 2, 3, 4, 5]);
}

#[test]
fn normal_pin_unlocks() {
    let (mut v, _, mut ks) = new_vault();
    let id = v.add_contact(sas_contact("alice", Some(b"+447700900123"))).unwrap();
    let blob = rotate(&mut v, &mut ks);
    let u = unlock_normal(&mut ks, &blob);
    let c = u.contacts();
    assert_eq!(c.len(), 1);
    assert_eq!(c[0].id, id);
    assert_eq!(c[0].label, "alice");
    assert!(c[0].sas_verified);
    assert!(u.rotation_required());
}

#[test]
fn duress_pin_reports_duress() {
    let (_, blob, mut ks) = new_vault();
    assert!(matches!(attempt(&mut ks, &blob, DURESS), UnlockOutcome::Duress));
}

#[test]
fn wrong_pin_is_invalid() {
    let (_, blob, mut ks) = new_vault();
    assert!(matches!(attempt(&mut ks, &blob, WRONG), UnlockOutcome::Invalid { left: 4 }));
}

#[test]
fn simulated_ticket_is_single_use() {
    let (_, blob, mut ks) = new_vault();
    let tu = Vault::begin_unlock(&blob, PIN, &ks.live()).unwrap();
    let first_id = tu.ticket_id;
    assert!(ks.use_ticket(first_id, tu.hmac_input.as_bytes()).is_some());
    assert!(ks.use_ticket(first_id, tu.hmac_input.as_bytes()).is_none());
    // A consumed ticket yields no HMAC; the attempt counts as failed.
    assert!(matches!(Vault::finish_unlock(&blob, tu, None, &ks.live()), UnlockOutcome::Invalid { left: 4 }));
    // The next attempt automatically moves to the next live ticket.
    let tu2 = Vault::begin_unlock(&blob, PIN, &ks.live()).unwrap();
    assert_ne!(tu2.ticket_id, first_id);
}

/// Unlock attempt with a kept stretch instead of the PIN.
fn attempt_stretch(ks: &mut SimKeystore, blob: &[u8], p: &SecretKey32) -> UnlockOutcome {
    let tu = match Vault::begin_unlock_stretch(blob, p, &ks.live()) {
        Ok(t) => t,
        Err(TrustError::VaultDead) => return UnlockOutcome::Dead,
        Err(_) => return UnlockOutcome::Malformed,
    };
    let out = ks.use_ticket(tu.ticket_id, tu.hmac_input.as_bytes());
    Vault::finish_unlock(blob, tu, out.as_ref(), &ks.live())
}

#[test]
fn kept_stretch_unlocks_through_the_same_ticket() {
    let (_, blob, mut ks) = new_vault();
    let by_pin = Vault::begin_unlock(&blob, PIN, &ks.live()).unwrap();
    let p = by_pin.hmac_input.clone();
    let by_stretch = Vault::begin_unlock_stretch(&blob, &p, &ks.live()).unwrap();
    assert_eq!(by_stretch.ticket_id, by_pin.ticket_id);
    assert_eq!(by_stretch.hmac_input.as_bytes(), p.as_bytes());
    let v = match attempt_stretch(&mut ks, &blob, &p) {
        UnlockOutcome::Normal(v) => v,
        other => panic!("expected Normal, got {other:?}"),
    };
    assert!(v.rotation_required());
    assert_eq!(ks.live().len(), 4);
}

#[test]
fn kept_stretch_needs_a_live_ticket() {
    let (_, blob, mut ks) = new_vault();
    let p = Vault::begin_unlock(&blob, PIN, &ks.live()).unwrap().hmac_input;
    assert_eq!(Vault::begin_unlock_stretch(&blob, &p, &[]).err(), Some(TrustError::VaultDead));
    ks.retire(&ks.live());
    assert!(matches!(attempt_stretch(&mut ks, &blob, &p), UnlockOutcome::Dead));
    assert_eq!(Vault::begin_unlock_stretch(&blob[..100], &p, &[1]).err(), Some(TrustError::VaultMalformed));
}

#[test]
fn duress_stretch_still_reports_duress_and_a_wrong_one_spends_a_ticket() {
    let (_, blob, mut ks) = new_vault();
    let p_duress = Vault::begin_unlock(&blob, DURESS, &ks.live()).unwrap().hmac_input;
    assert!(matches!(attempt_stretch(&mut ks, &blob, &p_duress), UnlockOutcome::Duress));
    let (_, blob, mut ks) = new_vault();
    let wrong = SecretKey32::from_bytes([7; 32]);
    assert!(matches!(attempt_stretch(&mut ks, &blob, &wrong), UnlockOutcome::Invalid { left: 4 }));
}

#[test]
fn a_stretch_unlock_refills_only_the_ticket_it_spent() {
    let (_, blob, mut ks) = new_vault();
    let p = Vault::begin_unlock(&blob, PIN, &ks.live()).unwrap().hmac_input;
    assert!(matches!(attempt(&mut ks, &blob, WRONG), UnlockOutcome::Invalid { left: 4 }));
    assert!(matches!(attempt(&mut ks, &blob, WRONG), UnlockOutcome::Invalid { left: 3 }));
    let mut v = match attempt_stretch(&mut ks, &blob, &p) {
        UnlockOutcome::Normal(v) => *v,
        other => panic!("expected Normal, got {other:?}"),
    };
    assert_eq!(ks.live().len(), 2);
    v.cap_refill(&ks.live());
    let rot = v.begin_rotation(&mut OsRng).unwrap();
    assert_eq!(rot.new.len(), 3, "only the spent ticket comes back");
    ks.import(&rot);
    let next = v.commit_rotation().unwrap();
    ks.retire(&rot.retire);
    assert_eq!(Vault::ticket_ids(&next).unwrap().len(), TICKETS_PER_VAULT);
    assert_eq!(ks.live().len(), 3);
    // Every later rotation of this unlocked vault keeps the cap.
    let next = rotate(&mut v, &mut ks);
    assert_eq!(ks.live().len(), 3);
    // The records without a key cannot be used, and the file still opens with the PIN.
    let mut v = unlock_normal(&mut ks, &next);
    assert_eq!(ks.live().len(), 2);
    // A PIN unlock refills all five.
    rotate(&mut v, &mut ks);
    assert_eq!(ks.live().len(), TICKETS_PER_VAULT);
}

#[test]
fn stretch_binding_survives_rotation_and_differs_between_vaults() {
    let (_, blob, mut ks) = new_vault();
    let binding = Vault::stretch_binding(&blob).unwrap();
    let mut v = unlock_normal(&mut ks, &blob);
    let next = rotate(&mut v, &mut ks);
    assert_ne!(next, blob);
    assert_eq!(Vault::stretch_binding(&next).unwrap(), binding);
    let (_, other, _) = new_vault();
    assert_ne!(Vault::stretch_binding(&other).unwrap(), binding);
    assert_eq!(Vault::stretch_binding(&blob[..4095]).err(), Some(TrustError::VaultMalformed));
}

#[test]
fn five_wrong_pins_is_dead() {
    let (_, blob, mut ks) = new_vault();
    for left in (1..=4).rev() {
        match attempt(&mut ks, &blob, WRONG) {
            UnlockOutcome::Invalid { left: l } => assert_eq!(l, left),
            other => panic!("{other:?}"),
        }
    }
    assert!(matches!(attempt(&mut ks, &blob, WRONG), UnlockOutcome::Dead));
    assert_eq!(Vault::begin_unlock(&blob, PIN, &ks.live()).err(), Some(TrustError::VaultDead));
    assert!(matches!(attempt(&mut ks, &blob, PIN), UnlockOutcome::Dead));
}

#[test]
fn old_file_is_dead_after_rotation() {
    let (_, old, mut ks) = new_vault();
    let mut v = unlock_normal(&mut ks, &old);
    let new = rotate(&mut v, &mut ks);
    assert!(matches!(attempt(&mut ks.clone(), &old, PIN), UnlockOutcome::Dead));
    assert_eq!(Vault::begin_unlock(&old, PIN, &ks.live()).err(), Some(TrustError::VaultDead));
    let _ = unlock_normal(&mut ks, &new);
}

#[test]
fn wraps_equal_length_and_order_does_not_leak() {
    let mut normal_first = 0;
    let mut normal_second = 0;
    for _ in 0..20 {
        let (mut v, rot) = Vault::create(PIN, DURESS, &mut OsRng).unwrap();
        let blob = v.commit_rotation().unwrap();
        let parsed = parse(&blob).unwrap();
        for (t, (id, mat)) in parsed.tickets.iter().zip(rot.new.iter()) {
            assert_eq!(t.id, *id);
            assert_eq!(t.wraps[0].len(), WRAP_LEN);
            assert_eq!(t.wraps[1].len(), WRAP_LEN);
            assert!(t.wraps[0] < t.wraps[1]);
            let p = v.p_normal.as_ref().unwrap();
            let hn = hmac32(mat.as_bytes(), &[p.as_bytes()]).unwrap();
            let key = wrap_key(hn.as_bytes(), p, &parsed.file_id, t.id).unwrap();
            let aad = parsed.wrap_aad(t.id);
            let a = aead_open(&key, &ZERO_NONCE, &aad, t.wraps[0]).is_some();
            let b = aead_open(&key, &ZERO_NONCE, &aad, t.wraps[1]).is_some();
            assert!(a ^ b);
            if a {
                normal_first += 1;
            } else {
                normal_second += 1;
            }
        }
    }
    assert!(normal_first > 0 && normal_second > 0, "{normal_first}/{normal_second}");
}

#[test]
fn rotation_interrupted_before_write_recovers() {
    let (_, blob, mut ks) = new_vault();
    let mut v = unlock_normal(&mut ks, &blob);
    let rot = v.begin_rotation(&mut OsRng).unwrap();
    ks.import(&rot);
    drop(v); // crash before the new file is written
    let referenced = Vault::ticket_ids(&blob).unwrap();
    let orphans: Vec<u32> = ks.live().into_iter().filter(|id| !referenced.contains(id)).collect();
    assert_eq!(orphans.len(), TICKETS_PER_VAULT);
    ks.retire(&orphans);
    let mut v = unlock_normal(&mut ks, &blob);
    let new = rotate(&mut v, &mut ks);
    let _ = unlock_normal(&mut ks, &new);
}

#[test]
fn rotation_interrupted_after_write_recovers() {
    let (_, old, mut ks) = new_vault();
    let mut v = unlock_normal(&mut ks, &old);
    let rot = v.begin_rotation(&mut OsRng).unwrap();
    ks.import(&rot);
    let new = v.commit_rotation().unwrap();
    drop(v); // crash after the atomic write, before retiring old tickets
    let referenced = Vault::ticket_ids(&new).unwrap();
    let stale: Vec<u32> = ks.live().into_iter().filter(|id| !referenced.contains(id)).collect();
    assert_eq!(stale, rot.retire.iter().copied().filter(|id| ks.live().contains(id)).collect::<Vec<_>>());
    ks.retire(&stale);
    assert!(matches!(attempt(&mut ks.clone(), &old, PIN), UnlockOutcome::Dead));
    let _ = unlock_normal(&mut ks, &new);
}

#[test]
fn commit_without_begin_fails() {
    let (mut v, _, _) = new_vault();
    assert_eq!(v.commit_rotation().err(), Some(TrustError::NoPendingRotation));
}

#[test]
fn any_byte_tamper_never_unlocks() {
    let (mut v, _, mut ks) = new_vault();
    v.add_contact(sas_contact("bob", Some(b"+14155550100"))).unwrap();
    let blob = rotate(&mut v, &mut ks);
    for i in 0..blob.len() {
        for bit in [0x01u8, 0x80] {
            let mut t = blob.clone();
            t[i] ^= bit;
            let out = attempt(&mut ks.clone(), &t, PIN);
            assert!(!matches!(out, UnlockOutcome::Normal(_)), "byte {i} bit {bit:#x} unlocked");
        }
    }
    for t in [blob[..blob.len() - 1].to_vec(), [blob.clone(), vec![0]].concat(), blob[..VAULT_PAD_BLOCK / 2].to_vec(), Vec::new()] {
        assert!(matches!(attempt(&mut ks.clone(), &t, PIN), UnlockOutcome::Malformed));
    }
    let _ = unlock_normal(&mut ks, &blob);
}

#[test]
fn duress_returns_no_content_and_overwrite_matches_file_length() {
    let (mut v, _, mut ks) = new_vault();
    for i in 0..60 {
        let phone = format!("+4477{:08}", i);
        v.add_contact(NewContact {
            pub33: pub33(),
            label: "x".repeat(MAX_LABEL_LEN),
            phone: PhoneChoice::UserConfirmed(phone.into_bytes()),
            proof: ContactProof::Paired(random_key(&mut OsRng)),
        })
        .unwrap();
    }
    let blob = rotate(&mut v, &mut ks);
    assert!(blob.len() > VAULT_PAD_BLOCK);
    // The duress outcome is a bare marker: no vault, no keys, nothing with a length.
    assert!(matches!(attempt(&mut ks.clone(), &blob, DURESS), UnlockOutcome::Duress));
    let junk = duress_overwrite(blob.len(), &mut OsRng);
    assert_eq!(junk.len(), blob.len());
    assert_ne!(junk, blob);
    assert!(Vault::ticket_ids(&junk).is_err());
}

#[test]
fn create_rejects_bad_pins() {
    assert_eq!(Vault::create(PIN, PIN, &mut OsRng).err(), Some(TrustError::DuressEqualsPin));
    assert_eq!(Vault::create(b"12", DURESS, &mut OsRng).err(), Some(TrustError::InvalidPin));
    assert_eq!(Vault::create(PIN, &[b'1'; MAX_PIN_LEN + 1], &mut OsRng).err(), Some(TrustError::InvalidPin));
}

#[test]
fn identity_change_requires_rotation_before_export() {
    let (mut v, _, mut ks) = new_vault();
    assert!(v.export().is_ok());
    let id = v.add_contact(sas_contact("carol", None)).unwrap();
    assert_eq!(v.export().err(), Some(TrustError::RotationRequired));
    let _ = rotate(&mut v, &mut ks);
    v.set_label(id, "carol2".into()).unwrap();
    assert!(v.export().is_ok());
    v.remove_contact(id).unwrap();
    assert_eq!(v.export().err(), Some(TrustError::RotationRequired));
}

#[test]
fn contacts_identified_by_pub33_with_confirmed_phone() {
    let (mut v, _, _) = new_vault();
    let c = sas_contact("dave", Some(b"+447700900111"));
    let key = c.pub33;
    let id = v.add_contact(c).unwrap();
    let dup = NewContact { pub33: key, ..sas_contact("again", None) };
    assert_eq!(v.add_contact(dup).err(), Some(TrustError::DuplicateContact));
    assert_eq!(v.add_contact(sas_contact("same number", Some(b"+447700900111"))).err(), Some(TrustError::PhoneInUse));
    assert_eq!(v.add_contact(sas_contact("bad", Some(b"07700900111"))).err(), Some(TrustError::InvalidPhone));
    let mut bad_key = sas_contact("bad key", None);
    bad_key.pub33[0] = 0x04;
    assert_eq!(v.add_contact(bad_key).err(), Some(TrustError::InvalidPub33));
    assert!(v.add_contact(sas_contact("hidden caller", None)).is_ok());
    assert_eq!(v.contact_by_pub33(&key).map(|c| c.id), Some(id));
    // Phone number is only a hint that the number used another key before.
    let (_, hint) = v.expectation_for(Some(b"+447700900111"));
    assert_eq!(hint, Some(key));
    assert_eq!(v.expectation_for(Some(b"+447700900222")).1, None);
}

#[test]
fn psk_contact_key_change_needs_pairing() {
    let (mut v, _, _) = new_vault();
    let psk = random_key(&mut OsRng);
    let id = v
        .add_contact(NewContact { proof: ContactProof::Paired(psk.clone()), ..sas_contact("erin", None) })
        .unwrap();
    let (exp, _) = v.expectation_for(None);
    assert_eq!(exp.psk.len(), 1);
    assert_eq!(exp.psk[0].2.as_bytes(), psk.as_bytes());
    assert!(v.holds_pairing_psk(id, &psk));
    assert!(!v.holds_pairing_psk(id, &random_key(&mut OsRng)));
    assert!(!v.holds_pairing_psk(id + 1, &psk));
    let sas = v.add_contact(sas_contact("frank", None)).unwrap();
    assert!(!v.holds_pairing_psk(sas, &psk));
    assert_eq!(
        v.replace_contact_key(id, pub33(), ContactProof::SasMatchedThisCall).err(),
        Some(TrustError::PskRequiredForKeyChange)
    );
    v.resume_stage(id, random_key(&mut OsRng), 1).unwrap();
    let new_key = pub33();
    v.replace_contact_key(id, new_key, ContactProof::Paired(random_key(&mut OsRng))).unwrap();
    let c = v.contact_by_pub33(&new_key).unwrap();
    assert_eq!(c.resume, (false, false));
    assert!(v.rotation_required());
}

#[test]
fn a_new_pairing_psk_keeps_everything_bound_to_the_identity_key() {
    let (mut v, _, mut ks) = new_vault();
    let key = pub33();
    let id = v
        .add_contact(NewContact { pub33: key, proof: ContactProof::SasMatchedThisCall, ..sas_contact("gina", Some(b"+447700900333")) })
        .unwrap();
    v.resume_stage(id, random_key(&mut OsRng), 1).unwrap();
    let blob = rotate(&mut v, &mut ks);
    let mut v = unlock_normal(&mut ks, &blob);
    rotate(&mut v, &mut ks);
    let before = v.contact_by_pub33(&key).unwrap();
    assert!(!v.rotation_required());

    let psk = random_key(&mut OsRng);
    v.set_pairing_psk(id, psk.clone()).unwrap();
    assert!(v.rotation_required());
    let after = v.contact_by_pub33(&key).unwrap();
    assert!(after.has_psk && v.holds_pairing_psk(id, &psk));
    assert_eq!(
        (after.label.as_str(), after.sas_verified, after.resume, after.phone_tag),
        (before.label.as_str(), true, before.resume, before.phone_tag)
    );
    assert_eq!(v.set_pairing_psk(id + 100, psk).err(), Some(TrustError::UnknownContact));
}

#[test]
fn a_contact_snapshot_undoes_a_pairing_and_a_rename() {
    let (mut v, _, _) = new_vault();
    let old = random_key(&mut OsRng);
    let id = v.add_contact(NewContact { proof: ContactProof::Paired(old.clone()), ..sas_contact("hal", None) }).unwrap();
    v.resume_stage(id, random_key(&mut OsRng), 1).unwrap();
    let snap = v.contact_snapshot(id).unwrap();
    assert!(v.contact_snapshot(id + 1).is_none());
    let before = v.contacts();
    v.set_pairing_psk(id, random_key(&mut OsRng)).unwrap();
    v.set_label(id, "mallory".to_owned()).unwrap();
    assert!(!v.holds_pairing_psk(id, &old));
    v.restore_contact(snap).unwrap();
    assert!(v.holds_pairing_psk(id, &old));
    let after = v.contacts();
    assert_eq!(after.len(), 1);
    assert_eq!((after[0].label.as_str(), after[0].resume, after[0].pub33), (before[0].label.as_str(), before[0].resume, before[0].pub33));
    assert!(v.rotation_required());
    let gone = v.contact_snapshot(id).unwrap();
    v.remove_contact(id).unwrap();
    assert_eq!(v.restore_contact(gone).err(), Some(TrustError::UnknownContact));
}

#[test]
fn resume_stage_and_promote() {
    let (mut v, _, mut ks) = new_vault();
    let id = v.add_contact(sas_contact("frank", None)).unwrap();
    let _ = rotate(&mut v, &mut ks);
    let r1 = random_key(&mut OsRng);
    v.resume_stage(id, r1.clone(), 1).unwrap();
    // Only rs updates: export allowed without rotation.
    let blob = v.export().unwrap();
    let (exp, _) = v.expectation_for(None);
    assert_eq!(exp.resume.len(), 1);
    assert!(exp.resume[0].is_new);
    assert!(v.resume_promote(id, 1).unwrap());
    assert!(!v.resume_promote(id, 1).unwrap()); // duplicate RESUME_SAVED is harmless
    let r2 = random_key(&mut OsRng);
    v.resume_stage(id, r2.clone(), 2).unwrap();
    let (exp, _) = v.expectation_for(None);
    assert_eq!(exp.resume.len(), 2);
    assert!(exp.resume.iter().any(|c| !c.is_new && c.secret.as_bytes() == r1.as_bytes()));
    assert!(exp.resume.iter().any(|c| c.is_new && c.secret.as_bytes() == r2.as_bytes()));
    assert!(v.resume_promote(id, 2).unwrap());
    let (exp, _) = v.expectation_for(None);
    assert_eq!(exp.resume.len(), 1);
    assert_eq!(exp.resume[0].secret.as_bytes(), r2.as_bytes());
    // The staged state survived persistence.
    let u = unlock_normal(&mut ks, &blob);
    assert_eq!(u.contacts()[0].resume, (false, true));
}

#[test]
fn resume_receiving_k_confirms_smaller_updates() {
    let (mut v, _, _) = new_vault();
    let id = v.add_contact(sas_contact("gina", None)).unwrap();
    v.resume_stage(id, random_key(&mut OsRng), 1).unwrap();
    // A later update may not overwrite an unpromoted lower one.
    assert_eq!(v.resume_stage(id, random_key(&mut OsRng), 2).err(), Some(TrustError::ResumeBusy));
    // RESUME_SAVED(2) also confirms update 1.
    assert!(v.resume_promote(id, 2).unwrap());
    assert_eq!(v.contacts()[0].resume, (true, false));
    // RESUME_SAVED(1) does not confirm a staged update 2.
    v.resume_stage(id, random_key(&mut OsRng), 2).unwrap();
    assert!(!v.resume_promote(id, 1).unwrap());
    assert_eq!(v.contacts()[0].resume, (true, true));
    // Step 5: a resume that used rs_new promotes it.
    v.resume_mark_used(id, true).unwrap();
    assert_eq!(v.contacts()[0].resume, (true, false));
    assert_eq!(v.resume_stage(id, random_key(&mut OsRng), 0).err(), Some(TrustError::InvalidResumeK));
    assert_eq!(v.resume_promote(999, 1).err(), Some(TrustError::UnknownContact));
}

#[test]
fn attestation_verdict_roundtrip() {
    let (mut v, _, mut ks) = new_vault();
    let id = v.add_contact(sas_contact("hank", None)).unwrap();
    let verdict = AttestationVerdict {
        level: SecLevel::StrongBox,
        boot: BootState::SelfSigned { key: vec![7; 32] },
        os_patch: 202409,
        evidence_id: [9; 16],
    };
    v.set_attestation(id, verdict.clone()).unwrap();
    let blob = rotate(&mut v, &mut ks);
    let u = unlock_normal(&mut ks, &blob);
    assert_eq!(u.contacts()[0].attestation, Some(verdict));
}

#[test]
fn production_kdf_params_work() {
    let salt = [3u8; 16];
    let a = stretch(ARGON2ID_PARAMS, PIN, &salt).unwrap();
    assert_ne!(a.as_bytes(), &[0u8; 32]);
    assert_ne!(a.as_bytes(), stretch(TEST_KDF_PARAMS, PIN, &salt).unwrap().as_bytes());
}

// ---------------------------------------------------------------- review round

#[test]
fn exported_content_has_no_normal_pin_stretch() {
    let (_, blob, mut ks) = new_vault();
    let salt = parse(&blob).unwrap().salt;
    let p_normal = stretch(TEST_KDF_PARAMS, PIN, &salt).unwrap();
    let p_duress = stretch(TEST_KDF_PARAMS, DURESS, &salt).unwrap();
    let mut v = unlock_normal(&mut ks, &blob);
    let rotated = rotate(&mut v, &mut ks);
    let exported = v.export().unwrap();
    for file in [&rotated, &exported] {
        let parsed = parse(file).unwrap();
        let key = body_key(&v.k_root, &parsed.file_id).unwrap();
        let pt = aead_open(&key, &body_nonce(parsed.seq), &file[..BODY_HDR_END], &file[BODY_HDR_END..]).unwrap();
        // Raw plaintext: the normal stretch appears nowhere, the duress stretch does.
        assert!(!pt.windows(32).any(|w| w == p_normal.as_bytes()));
        assert!(pt.windows(32).any(|w| w == p_duress.as_bytes()));
        // Parsed content: version, one stretch, phone key, meta key, two counters, contact count.
        let content_len = u32::from_be_bytes(pt[..4].try_into().unwrap()) as usize;
        assert_eq!(content_len, 1 + 32 + 32 + 32 + 4 + 4 + 2);
        assert_eq!(content_len, CONTENT_FIXED_LEN);
        let content = Content::decode_padded(&pt).unwrap();
        assert_eq!(content.p_duress.as_bytes(), p_duress.as_bytes());
        assert_ne!(content.phone_key.as_bytes(), p_normal.as_bytes());
        assert!(content.contacts.is_empty());
        assert!(!file.windows(32).any(|w| w == p_normal.as_bytes()));
    }
    // The stretch exists in memory while unlocked and is gone after locking.
    assert_eq!(v.p_normal.as_ref().map(|p| *p.as_bytes()), Some(*p_normal.as_bytes()));
    v.wipe();
    assert!(v.p_normal.is_none());
    assert_eq!(v.begin_rotation(&mut OsRng).err(), Some(TrustError::VaultLocked));
}

#[test]
fn finish_unlock_rejects_unconsumed_ticket() {
    let (_, blob, mut ks) = new_vault();
    let tu = Vault::begin_unlock(&blob, PIN, &ks.live()).unwrap();
    let id = tu.ticket_id;
    // The right HMAC, computed without consuming the StrongBox key.
    let material = ks.keys[&id];
    let out = *hmac32(&material, &[tu.hmac_input.as_bytes()]).unwrap().as_bytes();
    assert!(ks.live().contains(&id));
    assert!(matches!(Vault::finish_unlock(&blob, tu, Some(&out), &ks.live()), UnlockOutcome::TicketNotConsumed));
    // Same when the keystore reported a failure and the key is still there.
    let tu = Vault::begin_unlock(&blob, PIN, &ks.live()).unwrap();
    assert!(matches!(Vault::finish_unlock(&blob, tu, None, &ks.live()), UnlockOutcome::TicketNotConsumed));
    // Once the ticket is really consumed the same file unlocks.
    let _ = unlock_normal(&mut ks, &blob);
}

#[test]
fn mismatched_pin_stretch_cannot_unlock() {
    let (_, blob, mut ks) = new_vault();
    let tu = Vault::begin_unlock(&blob, PIN, &ks.live()).unwrap();
    let out = ks.use_ticket(tu.ticket_id, tu.hmac_input.as_bytes()).unwrap();
    let other = stretch(TEST_KDF_PARAMS, WRONG, &parse(&blob).unwrap().salt).unwrap();
    let forged = TicketUse { ticket_id: tu.ticket_id, hmac_input: other };
    // A valid HMAC paired with a different stretch must not yield a vault that would later
    // re-wrap under that stretch.
    assert!(matches!(Vault::finish_unlock(&blob, forged, Some(&out), &ks.live()), UnlockOutcome::Invalid { left: 4 }));
}

#[test]
fn vault_keeps_no_ticket_material_after_begin_rotation() {
    let (_, blob, mut ks) = new_vault();
    let mut v = unlock_normal(&mut ks, &blob);
    let rot = v.begin_rotation(&mut OsRng).unwrap();
    ks.import(&rot);
    let materials: Vec<[u8; 32]> = rot.new.iter().map(|(_, m)| *m.as_bytes()).collect();
    let retire = rot.retire.clone();
    drop(rot); // wipes the material; the vault holds only the finished wraps
    let pending = v.pending.as_ref().unwrap();
    assert_eq!(pending.hdr.len(), TICKETS_END);
    assert_eq!(pending.ids.len(), TICKETS_PER_VAULT);
    assert!(materials.iter().all(|m| !pending.hdr.windows(32).any(|w| w == m)));
    let new = v.commit_rotation().unwrap();
    ks.retire(&retire);
    let _ = unlock_normal(&mut ks, &new);
}

#[test]
fn content_ticket_counter_must_exceed_file_tickets() {
    let (mut v, _, ks) = new_vault();
    assert_eq!(v.content.next_ticket_id, 6);
    v.content.next_ticket_id = 5; // not above the highest ticket id of this file
    let bad = v.export().unwrap();
    assert!(matches!(attempt(&mut ks.clone(), &bad, PIN), UnlockOutcome::Invalid { left: 4 }));
    v.content.next_ticket_id = 6;
    let good = v.export().unwrap();
    assert!(matches!(attempt(&mut ks.clone(), &good, PIN), UnlockOutcome::Normal(_)));
}

#[test]
fn resume_stage_rejects_older_update_over_newer() {
    let (mut v, _, _) = new_vault();
    let id = v.add_contact(sas_contact("ivy", None)).unwrap();
    let newer = random_key(&mut OsRng);
    v.resume_stage(id, newer.clone(), 2).unwrap();
    assert_eq!(v.resume_stage(id, random_key(&mut OsRng), 1).err(), Some(TrustError::ResumeStale));
    let (exp, _) = v.expectation_for(None);
    assert_eq!(exp.resume.len(), 1);
    assert_eq!(exp.resume[0].secret.as_bytes(), newer.as_bytes());
    // The same update number may be staged again (retry after a failed write).
    v.resume_stage(id, newer.clone(), 2).unwrap();
    // A new session that did not use the leftover drops it, then stages its own update 1.
    v.resume_discard_staged(id).unwrap();
    v.resume_stage(id, random_key(&mut OsRng), 1).unwrap();
    assert_eq!(v.contacts()[0].resume, (false, true));
}

#[test]
fn hkdf32_matches_reference_implementation() {
    let salt = [0x11u8; 16];
    let ikm = [0x22u8; 64];
    let id = 7u32.to_be_bytes();
    let mut expected = [0u8; 32];
    hkdf::Hkdf::<Sha256>::new(Some(&salt), &ikm).expand_multi_info(&[b"AegisVault-v2 wrap", &id], &mut expected).unwrap();
    assert_eq!(hkdf32(&salt, &ikm, &[b"AegisVault-v2 wrap", &id]).unwrap().as_bytes(), &expected);
}

#[test]
fn set_phone_updates_clears_and_rejects_duplicates() {
    let (mut v, _, mut ks) = new_vault();
    let a = v.add_contact(sas_contact("alice", None)).unwrap();
    let b = v.add_contact(sas_contact("bob", Some(b"+447700900202"))).unwrap();
    let _ = rotate(&mut v, &mut ks);

    // Duplicate phone belonging to another contact is rejected.
    assert_eq!(v.set_phone(a, PhoneChoice::UserConfirmed(b"+447700900202".to_vec())), Err(TrustError::PhoneInUse));
    assert_eq!(v.set_phone(a, PhoneChoice::UserConfirmed(b"bad".to_vec())), Err(TrustError::InvalidPhone));

    // Setting own number and replacing it with another works; clearing removes the tag.
    v.set_phone(a, PhoneChoice::UserConfirmed(b"+447700900101".to_vec())).unwrap();
    v.set_phone(b, PhoneChoice::UserConfirmed(b"+447700900202".to_vec())).unwrap();
    assert!(v.contacts().iter().find(|c| c.id == a).unwrap().phone_tag.is_some());
    let blob = v.export().unwrap();
    let mut u = unlock_normal(&mut ks, &blob);
    assert_eq!(u.contacts().iter().find(|c| c.id == a).unwrap().phone_tag, v.contacts().iter().find(|c| c.id == a).unwrap().phone_tag);

    u.set_phone(a, PhoneChoice::NoNumber).unwrap();
    assert!(u.contacts().iter().find(|c| c.id == a).unwrap().phone_tag.is_none());
}

// ---------------------------------------------------------------- contact metadata key

/// Rewrites `blob` (sealed under `k_root`) with version 1 content, which has no meta key.
fn downgrade_to_v1(blob: &[u8], k_root: &SecretKey32) -> Vec<u8> {
    let parsed = parse(blob).unwrap();
    let key = body_key(k_root, &parsed.file_id).unwrap();
    let nonce = body_nonce(parsed.seq);
    let aad = &blob[..BODY_HDR_END];
    let pt = aead_open(&key, &nonce, aad, &blob[BODY_HDR_END..]).unwrap();
    let len = u32::from_be_bytes(pt[..4].try_into().unwrap()) as usize;
    let body = &pt[4..4 + len];
    assert_eq!(body[0], CONTENT_VERSION);
    // version · p_duress · phone_key, then everything after the meta key.
    let mut v1 = vec![CONTENT_VERSION_NO_META];
    v1.extend_from_slice(&body[1..65]);
    v1.extend_from_slice(&body[97..]);
    let mut padded = vec![0u8; pt.len()];
    padded[..4].copy_from_slice(&(v1.len() as u32).to_be_bytes());
    padded[4..4 + v1.len()].copy_from_slice(&v1);
    let mut out = aad.to_vec();
    out.extend_from_slice(&aead_seal(&key, &nonce, aad, &padded).unwrap());
    out
}

#[test]
fn meta_seal_and_open_need_an_unlocked_vault() {
    let (mut v, _, _) = new_vault();
    let a = v.meta_seal(b"x", &mut OsRng).unwrap();
    let b = v.meta_seal(b"x", &mut OsRng).unwrap();
    assert_eq!(a.len(), 1 + 24 + 1 + 16);
    assert_eq!(a[0], META_FORMAT);
    assert_ne!(a, b, "every seal draws a fresh nonce");
    assert_eq!(&v.meta_open(&a).unwrap()[..], b"x");
    assert_eq!(&v.meta_open(&b).unwrap()[..], b"x");
    let empty = v.meta_seal(&[], &mut OsRng).unwrap();
    assert!(v.meta_open(&empty).unwrap().is_empty());
    v.wipe();
    assert_eq!(v.meta_seal(b"x", &mut OsRng).err(), Some(TrustError::VaultLocked));
    assert_eq!(v.meta_open(&a).err(), Some(TrustError::VaultLocked));
}

#[test]
fn meta_open_rejects_tampering_and_other_vaults() {
    let (v, _, _) = new_vault();
    let sealed = v.meta_seal(b"07700900123", &mut OsRng).unwrap();
    for i in 0..sealed.len() {
        let mut bad = sealed.clone();
        bad[i] ^= 0x01;
        assert_eq!(v.meta_open(&bad).err(), Some(TrustError::Crypto), "byte {i}");
    }
    for len in 0..sealed.len() {
        assert_eq!(v.meta_open(&sealed[..len]).err(), Some(TrustError::Crypto), "length {len}");
    }
    let (other, _, _) = new_vault();
    assert_ne!(other.content.meta_key.as_bytes(), v.content.meta_key.as_bytes());
    assert_eq!(other.meta_open(&sealed).err(), Some(TrustError::Crypto));
}

#[test]
fn meta_key_survives_rotations_and_unlocks() {
    let (v, blob, mut ks) = new_vault();
    let sealed = v.meta_seal(b"seed and numbers", &mut OsRng).unwrap();
    drop(v);
    // Every unlock re-wraps the root key under the PIN stretches; the meta key stays.
    let mut u = unlock_normal(&mut ks, &blob);
    assert_eq!(&u.meta_open(&sealed).unwrap()[..], b"seed and numbers");
    let rotated = rotate(&mut u, &mut ks);
    let resealed = u.meta_seal(b"after rotation", &mut OsRng).unwrap();
    drop(u);
    let mut u2 = unlock_normal(&mut ks, &rotated);
    assert_eq!(&u2.meta_open(&sealed).unwrap()[..], b"seed and numbers");
    assert_eq!(&u2.meta_open(&resealed).unwrap()[..], b"after rotation");
    let rotated2 = rotate(&mut u2, &mut ks);
    drop(u2);
    let u3 = unlock_normal(&mut ks, &rotated2);
    assert_eq!(&u3.meta_open(&sealed).unwrap()[..], b"seed and numbers");
}

#[test]
fn version_one_content_gets_a_stable_meta_key() {
    let (v, blob, mut ks) = new_vault();
    let old = downgrade_to_v1(&blob, &v.k_root);
    drop(v);
    let mut u = unlock_normal(&mut ks, &old);
    let derived = hkdf32(b"AegisVault-v2 meta upgrade", u.content.phone_key.as_bytes(), &[b"AegisMeta-v1 key"]).unwrap();
    assert_eq!(u.content.meta_key.as_bytes(), derived.as_bytes());
    let sealed = u.meta_seal(b"numbers", &mut OsRng).unwrap();
    assert_eq!(&u.meta_open(&sealed).unwrap()[..], b"numbers");
    // The next file stores the key in version 2 content, so the same blob still opens.
    let rotated = rotate(&mut u, &mut ks);
    drop(u);
    let u2 = unlock_normal(&mut ks, &rotated);
    assert_eq!(u2.content.meta_key.as_bytes(), derived.as_bytes());
    assert_eq!(&u2.meta_open(&sealed).unwrap()[..], b"numbers");
    let parsed = parse(&rotated).unwrap();
    let key = body_key(&u2.k_root, &parsed.file_id).unwrap();
    let pt = aead_open(&key, &body_nonce(parsed.seq), &rotated[..BODY_HDR_END], &rotated[BODY_HDR_END..]).unwrap();
    assert_eq!(pt[4], CONTENT_VERSION);
    // An unknown content version is refused.
    let mut bad = pt.to_vec();
    bad[4] = 3;
    assert_eq!(Content::decode_padded(&bad).err().map(|e| e == TrustError::UnsupportedVersion), Some(true));
}

#[test]
fn change_pins_rotates_stretches_preserves_contacts_and_rolls_back_on_abort() {
    let (mut v, _, mut ks) = new_vault();
    let id = v.add_contact(sas_contact("bob", Some(b"+14155550101"))).unwrap();
    let sealed = v.meta_seal(b"meta-secret", &mut OsRng).unwrap();
    let blob0 = rotate(&mut v, &mut ks);

    let mut u = unlock_normal(&mut ks, &blob0);
    // Rotate after unlock so rotation_required becomes false before testing abort rollback.
    let blob1 = rotate(&mut u, &mut ks);
    assert!(!u.rotation_required());

    const NEW_PIN: &[u8] = b"99887766";
    const NEW_DURESS: &[u8] = b"11223344";

    // Wrong current PIN, invalid lengths, and equal PINs are rejected without disturbing state.
    assert_eq!(u.change_pins(WRONG, NEW_PIN, NEW_DURESS, &mut OsRng), Err(TrustError::WrongCurrentPin));
    assert_eq!(u.change_pins(PIN, b"123", NEW_DURESS, &mut OsRng), Err(TrustError::InvalidPin));
    assert_eq!(u.change_pins(PIN, NEW_PIN, NEW_PIN, &mut OsRng), Err(TrustError::DuressEqualsPin));
    assert!(!u.rotation_required());
    assert!(u.export().is_ok());

    // Staging + aborted rotation rolls back cleanly to the old PINs and rotation_required state.
    u.change_pins(PIN, NEW_PIN, NEW_DURESS, &mut OsRng).unwrap();
    assert!(u.rotation_required());
    assert_eq!(u.export().err(), Some(TrustError::RotationRequired));
    let _aborted_rot = u.begin_rotation(&mut OsRng).unwrap();
    u.abort_rotation();
    assert!(!u.rotation_required());
    let still_old = u.export().unwrap();

    // Commit a real PIN change: old PIN fails, new normal and new duress PINs both work.
    u.change_pins(PIN, NEW_PIN, NEW_DURESS, &mut OsRng).unwrap();
    let blob2 = rotate(&mut u, &mut ks);
    drop(u);

    // Old file's tickets were retired.
    assert!(matches!(attempt(&mut ks, &blob1, PIN), UnlockOutcome::Dead));
    assert!(matches!(attempt(&mut ks, &still_old, PIN), UnlockOutcome::Dead));

    // Old PIN is rejected on the new file (spends 1 ticket, 4 left).
    assert!(matches!(attempt(&mut ks, &blob2, PIN), UnlockOutcome::Invalid { left: 4 }));

    // New normal PIN unlocks, preserves contacts and meta_key.
    let mut ks_duress = ks.clone();
    let u2 = match attempt(&mut ks, &blob2, NEW_PIN) {
        UnlockOutcome::Normal(v) => *v,
        other => panic!("expected Normal with NEW_PIN, got {other:?}"),
    };
    assert_eq!(u2.contacts().len(), 1);
    assert_eq!(u2.contacts()[0].id, id);
    assert_eq!(&u2.meta_open(&sealed).unwrap()[..], b"meta-secret");

    // New duress PIN triggers Duress; old duress PIN does not.
    assert!(matches!(attempt(&mut ks_duress, &blob2, DURESS), UnlockOutcome::Invalid { left: 3 }));
    assert!(matches!(attempt(&mut ks_duress, &blob2, NEW_DURESS), UnlockOutcome::Duress));
}

const NEXT_PIN: &[u8] = b"99887766";
const NEXT_DURESS: &[u8] = b"11223344";

fn unlock_stretch(ks: &mut SimKeystore, blob: &[u8], p: &SecretKey32) -> Vault {
    match attempt_stretch(ks, blob, p) {
        UnlockOutcome::Normal(v) => *v,
        other => panic!("expected Normal, got {other:?}"),
    }
}

#[test]
fn a_kept_stretch_unlock_cannot_change_pins_and_a_pin_change_refills_every_ticket() {
    let (_, blob, mut ks) = new_vault();
    let p = Vault::begin_unlock(&blob, PIN, &ks.live()).unwrap().hmac_input;
    assert!(matches!(attempt(&mut ks, &blob, WRONG), UnlockOutcome::Invalid { left: 4 }));

    // Fingerprint answer: the vault is capped and refuses a PIN change, even with the right PIN.
    let mut v = unlock_stretch(&mut ks, &blob, &p);
    v.cap_refill(&ks.live());
    assert_eq!(v.change_pins(PIN, NEXT_PIN, NEXT_DURESS, &mut OsRng), Err(TrustError::StretchUnlock));
    let blob = rotate(&mut v, &mut ks);
    assert_eq!(v.change_pins(PIN, NEXT_PIN, NEXT_DURESS, &mut OsRng), Err(TrustError::StretchUnlock));
    assert_eq!(ks.live().len(), 4, "the cap still holds after the refused change");
    drop(v);

    // A PIN unlock may change the PINs, and that rotation hands out all five tickets.
    let mut v = unlock_normal(&mut ks, &blob);
    assert_eq!(ks.live().len(), 3);
    v.change_pins(PIN, NEXT_PIN, NEXT_DURESS, &mut OsRng).unwrap();
    let rot = v.begin_rotation(&mut OsRng).unwrap();
    assert_eq!(rot.new.len(), TICKETS_PER_VAULT);
    ks.import(&rot);
    let next = v.commit_rotation().unwrap();
    ks.retire(&rot.retire);
    assert_eq!(ks.live().len(), TICKETS_PER_VAULT);
    drop(v);
    let _ = match attempt(&mut ks, &next, NEXT_PIN) {
        UnlockOutcome::Normal(v) => v,
        other => panic!("expected Normal with the new PIN, got {other:?}"),
    };
}

#[test]
fn the_third_wrong_current_pin_locks_the_vault_until_a_real_unlock() {
    let (mut v, _, mut ks) = new_vault();
    v.add_contact(sas_contact("jo", None)).unwrap();
    let blob = rotate(&mut v, &mut ks);
    let mut v = unlock_normal(&mut ks, &blob);
    let blob = rotate(&mut v, &mut ks);
    assert_eq!(ks.live().len(), TICKETS_PER_VAULT);

    assert_eq!(v.change_pins(WRONG, NEXT_PIN, NEXT_DURESS, &mut OsRng), Err(TrustError::WrongCurrentPin));
    // The current PIN is checked before the new ones: with invalid new PINs it still counts.
    assert_eq!(v.change_pins(b"111111", b"12", NEXT_DURESS, &mut OsRng), Err(TrustError::WrongCurrentPin));
    // A current PIN of invalid length is no guess.
    assert_eq!(v.change_pins(b"12", NEXT_PIN, NEXT_DURESS, &mut OsRng), Err(TrustError::InvalidPin));
    assert_eq!(v.change_pins(WRONG, NEXT_PIN, NEXT_DURESS, &mut OsRng), Err(TrustError::WrongCurrentPinLocked));

    // Locked: the right PIN no longer helps, nothing can be rotated, exported or read.
    assert_eq!(v.change_pins(PIN, NEXT_PIN, NEXT_DURESS, &mut OsRng), Err(TrustError::VaultLocked));
    assert_eq!(v.begin_rotation(&mut OsRng).err(), Some(TrustError::VaultLocked));
    assert_eq!(v.export().err(), Some(TrustError::RotationRequired));
    assert!(v.contacts().is_empty());
    assert_eq!(ks.live().len(), TICKETS_PER_VAULT, "guesses of the current PIN spend no ticket");
    drop(v);

    // Trying again needs an unlock, which spends a ticket and starts a new count.
    let mut v = unlock_normal(&mut ks, &blob);
    assert_eq!(ks.live().len(), TICKETS_PER_VAULT - 1);
    assert_eq!(v.contacts().len(), 1);
    for _ in 0..2 {
        assert_eq!(v.change_pins(WRONG, NEXT_PIN, NEXT_DURESS, &mut OsRng), Err(TrustError::WrongCurrentPin));
    }
    v.change_pins(PIN, NEXT_PIN, NEXT_DURESS, &mut OsRng).unwrap();
    let next = rotate(&mut v, &mut ks);
    drop(v);
    assert!(matches!(attempt(&mut ks, &next, NEXT_PIN), UnlockOutcome::Normal(_)));
}

#[test]
fn a_pin_change_gives_a_new_binding_so_a_kept_old_stretch_is_caught_before_a_ticket() {
    let (_, blob, mut ks) = new_vault();
    let binding = Vault::stretch_binding(&blob).unwrap();
    let p_old = Vault::begin_unlock(&blob, PIN, &ks.live()).unwrap().hmac_input;
    let mut v = unlock_normal(&mut ks, &blob);
    let blob = rotate(&mut v, &mut ks);
    assert_eq!(Vault::stretch_binding(&blob).unwrap(), binding);

    // An aborted change keeps the salt: the binding and the kept stretch stay valid.
    v.change_pins(PIN, NEXT_PIN, NEXT_DURESS, &mut OsRng).unwrap();
    let _ = v.begin_rotation(&mut OsRng).unwrap();
    v.abort_rotation();
    let same = v.export().unwrap();
    assert_eq!(Vault::stretch_binding(&same).unwrap(), binding);

    v.change_pins(PIN, NEXT_PIN, NEXT_DURESS, &mut OsRng).unwrap();
    let next = rotate(&mut v, &mut ks);
    drop(v);
    let new_binding = Vault::stretch_binding(&next).unwrap();
    assert_ne!(new_binding, binding, "a wrap of the old PIN must not match the new file");
    let p_new = Vault::begin_unlock(&next, NEXT_PIN, &ks.live()).unwrap().hmac_input;
    assert_ne!(p_new.as_bytes(), p_old.as_bytes());
    // A further rotation keeps the new binding.
    let mut v = unlock_stretch(&mut ks, &next, &p_new);
    v.cap_refill(&ks.live());
    let after = rotate(&mut v, &mut ks);
    drop(v);
    assert_eq!(Vault::stretch_binding(&after).unwrap(), new_binding);

    // Why the app compares bindings before phase 1: past that check the old stretch would spend a
    // ticket like a wrong PIN.
    let live = ks.live().len();
    assert!(matches!(attempt_stretch(&mut ks, &after, &p_old), UnlockOutcome::Invalid { .. }));
    assert_eq!(ks.live().len(), live - 1);
}

#[test]
fn contact_changes_made_while_pins_are_staged_survive_an_aborted_rotation() {
    let (mut v, _, mut ks) = new_vault();
    let id = v.add_contact(NewContact { proof: ContactProof::Paired(random_key(&mut OsRng)), ..sas_contact("ivy", None) }).unwrap();
    let blob = rotate(&mut v, &mut ks);
    let mut v = unlock_normal(&mut ks, &blob);
    rotate(&mut v, &mut ks);
    assert!(!v.rotation_required());

    // A new pairing PSK while new PINs are staged: the abort must not hide the unsaved PSK.
    let snap = v.contact_snapshot(id).unwrap();
    v.change_pins(PIN, NEXT_PIN, NEXT_DURESS, &mut OsRng).unwrap();
    let psk = random_key(&mut OsRng);
    v.set_pairing_psk(id, psk.clone()).unwrap();
    v.abort_rotation();
    assert!(v.rotation_required());
    assert_eq!(v.export().err(), Some(TrustError::RotationRequired));
    rotate(&mut v, &mut ks);

    // The same for the undo of an import (restore_contact).
    v.change_pins(PIN, NEXT_PIN, NEXT_DURESS, &mut OsRng).unwrap();
    v.restore_contact(snap).unwrap();
    v.abort_rotation();
    assert!(v.rotation_required());
    assert!(!v.holds_pairing_psk(id, &psk));
    let blob = rotate(&mut v, &mut ks);
    drop(v);

    // Both changes were aborted: the old PIN still opens the vault, the new one does not.
    assert!(matches!(attempt(&mut ks, &blob, NEXT_PIN), UnlockOutcome::Invalid { .. }));
    let v = unlock_normal(&mut ks, &blob);
    assert!(!v.holds_pairing_psk(id, &psk));
}

#[test]
fn the_duress_pin_as_the_current_pin_wipes_the_vault_like_a_duress_unlock() {
    let (mut v, _, mut ks) = new_vault();
    v.add_contact(sas_contact("kim", Some(b"+447700900444"))).unwrap();
    let blob = rotate(&mut v, &mut ks);
    let mut v = unlock_normal(&mut ks, &blob);
    let blob = rotate(&mut v, &mut ks);
    assert_eq!(v.file_len().unwrap(), blob.len());

    // Two wrong guesses first: the duress PIN still takes the duress path, not the lockout.
    for _ in 0..2 {
        assert_eq!(v.change_pins(WRONG, NEXT_PIN, NEXT_DURESS, &mut OsRng), Err(TrustError::WrongCurrentPin));
    }
    assert_eq!(v.change_pins(DURESS, NEXT_PIN, NEXT_DURESS, &mut OsRng), Err(TrustError::DuressPin));
    assert_eq!(v.change_pins(PIN, NEXT_PIN, NEXT_DURESS, &mut OsRng), Err(TrustError::VaultLocked));
    assert_eq!(v.begin_rotation(&mut OsRng).err(), Some(TrustError::VaultLocked));
    assert!(v.contacts().is_empty());
    drop(v);

    // Checked before the new PINs: invalid or equal new PINs do not keep it from firing.
    let mut v = unlock_normal(&mut ks, &blob);
    assert_eq!(v.change_pins(DURESS, b"12", b"12", &mut OsRng), Err(TrustError::DuressPin));
    let mut v = unlock_normal(&mut ks, &blob);
    assert_eq!(v.change_pins(DURESS, NEXT_PIN, NEXT_PIN, &mut OsRng), Err(TrustError::DuressPin));
    // A staged change does not hide the stored duress PIN either.
    let mut v = unlock_normal(&mut ks, &blob);
    v.change_pins(PIN, NEXT_PIN, NEXT_DURESS, &mut OsRng).unwrap();
    assert_eq!(v.change_pins(DURESS, NEXT_PIN, NEXT_DURESS, &mut OsRng), Err(TrustError::DuressPin));
    assert_eq!(v.begin_rotation(&mut OsRng).err(), Some(TrustError::VaultLocked));
}

#[test]
fn the_current_pin_is_compared_before_over_long_new_pins_and_a_right_one_is_not_counted() {
    let (_, blob, mut ks) = new_vault();
    let long = vec![b'a'; MAX_PIN_LEN + 1];
    let mut v = unlock_normal(&mut ks, &blob);
    let blob = rotate(&mut v, &mut ks);
    // Right current PIN, invalid new PINs: refused without counting, any number of times.
    for _ in 0..3 {
        assert_eq!(v.change_pins(PIN, &long, NEXT_DURESS, &mut OsRng), Err(TrustError::InvalidPin));
        assert_eq!(v.change_pins(PIN, NEXT_PIN, &long, &mut OsRng), Err(TrustError::InvalidPin));
    }
    // Wrong current PIN with invalid new PINs: a wrong PIN like any other.
    assert_eq!(v.change_pins(WRONG, &long, &long, &mut OsRng), Err(TrustError::WrongCurrentPin));
    assert_eq!(v.change_pins(WRONG, NEXT_PIN, NEXT_DURESS, &mut OsRng), Err(TrustError::WrongCurrentPin));
    assert!(v.export().is_ok(), "nothing was staged");
    // The duress PIN with over-long new PINs.
    assert_eq!(v.change_pins(DURESS, &long, &long, &mut OsRng), Err(TrustError::DuressPin));
    assert!(v.contacts().is_empty());
    drop(v);
    let _ = unlock_normal(&mut ks, &blob);
}

#[test]
fn a_refused_pin_change_still_takes_the_duress_pin_and_counts_nothing_else() {
    let (_, blob, mut ks) = new_vault();
    let p = Vault::begin_unlock(&blob, PIN, &ks.live()).unwrap().hmac_input;

    // Fingerprint (stretch) unlock: StretchUnlock for the right and wrong PIN alike, never locked.
    let mut v = unlock_stretch(&mut ks, &blob, &p);
    v.cap_refill(&ks.live());
    for _ in 0..4 {
        assert_eq!(v.change_pins(WRONG, NEXT_PIN, NEXT_DURESS, &mut OsRng), Err(TrustError::StretchUnlock));
    }
    assert_eq!(v.change_pins(PIN, NEXT_PIN, NEXT_DURESS, &mut OsRng), Err(TrustError::StretchUnlock));
    assert_eq!(v.change_pins(DURESS, NEXT_PIN, NEXT_DURESS, &mut OsRng), Err(TrustError::DuressPin));
    assert!(v.contacts().is_empty() && v.begin_rotation(&mut OsRng).is_err());
    drop(v);

    // Refusal while fingerprint answer is being turned on: same check, nothing counted.
    let mut v = unlock_normal(&mut ks, &blob);
    for _ in 0..4 {
        assert_eq!(v.refuse_pin_change(WRONG), Ok(()));
    }
    assert_eq!(v.refuse_pin_change(PIN), Ok(()));
    assert!(v.change_pins(PIN, NEXT_PIN, NEXT_DURESS, &mut OsRng).is_ok(), "the refusals were not counted");
    v.abort_rotation();
    assert_eq!(v.refuse_pin_change(DURESS), Err(TrustError::DuressPin));
    assert_eq!(v.refuse_pin_change(PIN), Err(TrustError::VaultLocked));
}

#[test]
fn ticket_ids_come_from_the_header_and_a_broken_file_is_refused() {
    let (mut v, blob, mut ks) = new_vault();
    assert_eq!(Vault::ticket_ids(&blob).unwrap(), vec![1, 2, 3, 4, 5]);
    let next = rotate(&mut v, &mut ks);
    assert_eq!(Vault::ticket_ids(&next).unwrap(), vec![6, 7, 8, 9, 10]);
    assert_eq!(Vault::ticket_ids(&next).unwrap(), ks.live());
    assert!(Vault::ticket_ids(&next[..next.len() - 1]).is_err());
    assert!(Vault::ticket_ids(&next[..100]).is_err());
    assert!(Vault::ticket_ids(&duress_overwrite(next.len(), &mut OsRng)).is_err());
    let mut bad = next.clone();
    bad[0] ^= 1;
    assert!(Vault::ticket_ids(&bad).is_err());
    assert!(Vault::ticket_ids(&[]).is_err());
}
