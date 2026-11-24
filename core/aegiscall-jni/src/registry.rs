//! Handle registry (§2.D, §6.6): random 63-bit handles mapped to `Arc<Mutex<Slot<T>>>`.

use crate::code::{BAD_HANDLE, INTERNAL, OK};
use rand_core::{OsRng, RngCore};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard};

pub(crate) enum Slot<T> {
    Live(T),
    Closed,
}

pub(crate) type Entry<T> = Arc<Mutex<Slot<T>>>;

pub(crate) fn lock<T>(m: &Mutex<T>) -> Result<MutexGuard<'_, T>, i32> {
    m.lock().map_err(|_| INTERNAL)
}

/// Runs f on a live entry while holding its lock; a closed entry yields BAD_HANDLE.
pub(crate) fn with_live<T, R>(e: &Entry<T>, f: impl FnOnce(&mut T) -> Result<R, i32>) -> Result<R, i32> {
    let mut g = lock(e)?;
    match &mut *g {
        Slot::Live(v) => f(v),
        Slot::Closed => Err(BAD_HANDLE),
    }
}

/// Takes the lock (even if poisoned), runs `before` on the live value, drops it and marks the
/// slot closed. Returns BAD_HANDLE when the slot was already closed.
pub(crate) fn close_entry<T>(e: &Entry<T>, before: impl FnOnce(&mut T)) -> i32 {
    let mut g = match e.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    match std::mem::replace(&mut *g, Slot::Closed) {
        Slot::Live(mut v) => {
            before(&mut v);
            drop(v);
            OK
        }
        Slot::Closed => BAD_HANDLE,
    }
}

/// Issues handles: non-zero, 63-bit, never reused across both tables.
pub(crate) struct Handles {
    issued: Mutex<HashSet<u64>>,
}

impl Handles {
    pub(crate) fn new() -> Self {
        Self { issued: Mutex::new(HashSet::new()) }
    }

    pub(crate) fn fresh(&self) -> Result<u64, i32> {
        let mut issued = lock(&self.issued)?;
        loop {
            let h = OsRng.next_u64() >> 1;
            if h != 0 && issued.insert(h) {
                return Ok(h);
            }
        }
    }
}

/// One handle table. Each entry remembers its owner (the app handle of a session, 0 for apps).
pub(crate) struct Table<T> {
    map: Mutex<HashMap<u64, (u64, Entry<T>)>>,
}

impl<T> Table<T> {
    pub(crate) fn new() -> Self {
        Self { map: Mutex::new(HashMap::new()) }
    }

    /// Copies the Arc and releases the table lock at once.
    pub(crate) fn get(&self, h: u64) -> Result<Entry<T>, i32> {
        lock(&self.map)?.get(&h).map(|(_, e)| e.clone()).ok_or(BAD_HANDLE)
    }

    pub(crate) fn insert(&self, h: u64, owner: u64, value: T) -> Result<(), i32> {
        lock(&self.map)?.insert(h, (owner, Arc::new(Mutex::new(Slot::Live(value)))));
        Ok(())
    }

    pub(crate) fn remove(&self, h: u64) {
        if let Ok(mut m) = lock(&self.map) {
            m.remove(&h);
        }
    }

    pub(crate) fn handles(&self) -> Vec<u64> {
        lock(&self.map).map(|m| m.keys().copied().collect()).unwrap_or_default()
    }

    pub(crate) fn owned_by(&self, owner: u64) -> Vec<u64> {
        lock(&self.map)
            .map(|m| m.iter().filter(|(_, (o, _))| *o == owner).map(|(h, _)| *h).collect())
            .unwrap_or_default()
    }
}
