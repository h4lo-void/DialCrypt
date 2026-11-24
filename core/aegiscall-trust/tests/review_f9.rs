//! Review tests for the ticket cap: after an unlock with a kept stretch
//! (fingerprint answer) no rotation gives back attempts spent on wrong PINs. Public API only.
use aegiscall_memsec::SecretKey32;
use aegiscall_trust::*;
use hmac::{Hmac, Mac};
use rand_core::OsRng;
use sha2::Sha256;
use std::collections::BTreeMap;

const PIN: &[u8] = b"246810";
const DURESS: &[u8] = b"135790";

/// Stand-in for the single-use StrongBox tickets: alias id to HMAC key, gone after one use.
#[derive(Default)]
struct Ks(BTreeMap<u32, [u8; 32]>);

impl Ks {
    fn import(&mut self, r: &Rotation) {
        for (id, m) in &r.new {
            self.0.insert(*id, *m.as_bytes());
        }
    }
    fn use_t(&mut self, id: u32, input: &[u8; 32]) -> Option<[u8; 32]> {
        let k = self.0.remove(&id)?;
        let mut m = <Hmac<Sha256> as Mac>::new_from_slice(&k).unwrap();
        m.update(input);
        let mut out = [0u8; 32];
        out.copy_from_slice(&m.finalize().into_bytes());
        Some(out)
    }
    fn live(&self) -> Vec<u32> {
        self.0.keys().copied().collect()
    }
}

fn fresh() -> (Vec<u8>, Ks) {
    let (mut v, rot) = Vault::create(PIN, DURESS, &mut OsRng).unwrap();
    let mut ks = Ks::default();
    ks.import(&rot);
    (v.commit_rotation().unwrap(), ks)
}

fn finish(ks: &mut Ks, blob: &[u8], tu: TicketUse) -> UnlockOutcome {
    let out = ks.use_t(tu.ticket_id, tu.hmac_input.as_bytes());
    Vault::finish_unlock(blob, tu, out.as_ref(), &ks.live())
}

/// A wrong guess: spends one ticket like a wrong PIN, without the cost of the KDF.
fn wrong_guess(ks: &mut Ks, blob: &[u8]) {
    let tu = Vault::begin_unlock_stretch(blob, &SecretKey32::from_bytes([7; 32]), &ks.live()).unwrap();
    assert!(matches!(finish(ks, blob, tu), UnlockOutcome::Invalid { .. } | UnlockOutcome::Dead));
}

/// What the bridge does for a fingerprint unlock: phase 1 with the kept stretch, then the cap.
fn fingerprint_unlock(ks: &mut Ks, blob: &[u8], p: &SecretKey32) -> Vault {
    let tu = Vault::begin_unlock_stretch(blob, p, &ks.live()).unwrap();
    match finish(ks, blob, tu) {
        UnlockOutcome::Normal(v) => {
            let mut v = *v;
            v.cap_refill(&ks.live());
            v
        }
        o => panic!("expected Normal, got {o:?}"),
    }
}

/// What the app does with a rotation: import, commit, write, retire the old tickets.
fn rotate(v: &mut Vault, ks: &mut Ks) -> Vec<u8> {
    let rot = v.begin_rotation(&mut OsRng).unwrap();
    ks.import(&rot);
    let blob = v.commit_rotation().unwrap();
    for id in &rot.retire {
        ks.0.remove(id);
    }
    blob
}

#[test]
fn no_fingerprint_unlock_rotation_or_restart_gives_back_spent_attempts() {
    let (mut blob, mut ks) = fresh();
    let p = Vault::begin_unlock(&blob, PIN, &ks.live()).unwrap().hmac_input;
    wrong_guess(&mut ks, &blob);
    wrong_guess(&mut ks, &blob);
    assert_eq!(ks.live().len(), 3);

    // Three fingerprint-answered calls, each in a new process, each with several rotations
    // (the one after the unlock, then resume secrets written during the call).
    for _ in 0..3 {
        let mut v = fingerprint_unlock(&mut ks, &blob, &p);
        assert_eq!(ks.live().len(), 2);
        for _ in 0..3 {
            blob = rotate(&mut v, &mut ks);
            assert_eq!(ks.live().len(), 3, "a rotation after a fingerprint unlock gave attempts back");
            assert_eq!(Vault::ticket_ids(&blob).unwrap().len(), TICKETS_PER_VAULT);
        }
        // A write without rotation changes nothing either.
        assert!(v.export().is_ok());
        assert_eq!(ks.live().len(), 3);
    }

    // One more wrong guess, then a fingerprint: still only what was left comes back.
    wrong_guess(&mut ks, &blob);
    assert_eq!(ks.live().len(), 2);
    let mut v = fingerprint_unlock(&mut ks, &blob, &p);
    blob = rotate(&mut v, &mut ks);
    assert_eq!(ks.live().len(), 2);
    drop(v);

    // The wrong-PIN count of the PIN path follows the real tickets.
    let tu = Vault::begin_unlock_stretch(&blob, &SecretKey32::from_bytes([9; 32]), &ks.live()).unwrap();
    assert!(matches!(finish(&mut ks, &blob, tu), UnlockOutcome::Invalid { left: 1 }));

    // Only the PIN fills all five again; the emergency PIN still reports duress on a capped file.
    let tu = Vault::begin_unlock(&blob, PIN, &ks.live()).unwrap();
    let mut v = match finish(&mut ks, &blob, tu) {
        UnlockOutcome::Normal(v) => *v,
        o => panic!("expected Normal, got {o:?}"),
    };
    blob = rotate(&mut v, &mut ks);
    assert_eq!(ks.live().len(), TICKETS_PER_VAULT);
    drop(v);
    wrong_guess(&mut ks, &blob);
    let mut v = fingerprint_unlock(&mut ks, &blob, &p);
    blob = rotate(&mut v, &mut ks);
    assert_eq!(ks.live().len(), 4);
    let tu = Vault::begin_unlock(&blob, DURESS, &ks.live()).unwrap();
    assert!(matches!(finish(&mut ks, &blob, tu), UnlockOutcome::Duress));
}

#[test]
fn a_capped_vault_dies_after_its_real_tickets_like_any_other() {
    let (blob, mut ks) = fresh();
    let p = Vault::begin_unlock(&blob, PIN, &ks.live()).unwrap().hmac_input;
    for _ in 0..3 {
        wrong_guess(&mut ks, &blob);
    }
    let mut v = fingerprint_unlock(&mut ks, &blob, &p);
    let blob = rotate(&mut v, &mut ks);
    drop(v);
    assert_eq!(ks.live().len(), 2);
    wrong_guess(&mut ks, &blob);
    wrong_guess(&mut ks, &blob);
    assert!(ks.live().is_empty());
    // The three records without a key are no attempts: the vault is dead, also for the right PIN.
    assert_eq!(Vault::begin_unlock(&blob, PIN, &ks.live()).err(), Some(TrustError::VaultDead));
    assert_eq!(Vault::begin_unlock_stretch(&blob, &p, &ks.live()).err(), Some(TrustError::VaultDead));
}
