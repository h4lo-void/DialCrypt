//! The single boundary between the daemon logic and the operating system.
//!
//! Reads never change system state. Every state change is a [`Mutation`]
//! passed to [`SysOps::apply`]; the session only calls it in armed mode, so a
//! dry run can be verified by checking that no mutation reached the backend.
//! Commands are argument vectors executed directly, never shell strings.
//!
//! The one exception is [`SysOps::raise_memlock`]. It changes a resource limit
//! of the App's own secure process only, the limit disappears when that
//! process exits, and nothing on the device has to be restored afterwards, so
//! it is not a [`Mutation`] and the session also calls it in a dry run.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SysError {
    NotFound,
    Io,
    Spawn,
    Exit(i32),
    Timeout,
    Invalid,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mutation {
    /// Run a program with arguments (no shell).
    Exec(Vec<String>),
    /// Run a program and feed `stdin` (used for `iptables-restore`).
    ExecStdin { argv: Vec<String>, stdin: String },
    /// Write a kernel tunable (`/proc/sys/...`, `/sys/block/zram*`).
    WriteFile { path: String, data: String },
    /// SIGKILL `pid` only if its start time still equals `starttime`.
    Kill { pid: u32, starttime: u64 },
    /// Run the daemon's own `--fill-memory` child (tier 2 memory scrub).
    FillFreeMemory { reserve_mib: u64, max_ms: u64 },
    /// Post a system notification carrying only a code token.
    Notify { code: String },
}

impl Mutation {
    pub fn exec(parts: &[&str]) -> Mutation {
        Mutation::Exec(parts.iter().map(|s| s.to_string()).collect())
    }

    /// Text form for logs and the test double. Never executed by a shell.
    pub fn key(&self) -> String {
        match self {
            Mutation::Exec(a) => a.join(" "),
            Mutation::ExecStdin { argv, .. } => format!("{} <stdin>", argv.join(" ")),
            Mutation::WriteFile { path, data } => format!("write {path} {data}"),
            Mutation::Kill { pid, starttime } => format!("kill {pid} {starttime}"),
            Mutation::FillFreeMemory { reserve_mib, max_ms } => format!("fillmem {reserve_mib} {max_ms}"),
            Mutation::Notify { code } => format!("notify {code}"),
        }
    }
}

pub trait SysOps {
    /// Run a read-only command and return its stdout.
    fn read_cmd(&mut self, argv: &[&str]) -> Result<String, SysError>;
    fn read_file(&mut self, path: &str) -> Result<Vec<u8>, SysError>;
    fn read_file_range(&mut self, path: &str, offset: u64, len: usize) -> Result<Vec<u8>, SysError>;
    fn file_size(&mut self, path: &str) -> Result<u64, SysError>;
    fn list_dir(&mut self, path: &str) -> Result<Vec<String>, SysError>;
    fn exists(&mut self, path: &str) -> bool;
    fn random16(&mut self) -> Result<[u8; 16], SysError>;
    /// Monotonic milliseconds.
    fn now_ms(&mut self) -> u64;
    /// Clock ticks since boot, same unit as `/proc/<pid>/stat` field 22.
    fn uptime_ticks(&mut self) -> Result<u64, SysError>;
    fn sleep_ms(&mut self, ms: u64);
    /// The only entry point that changes system state.
    fn apply(&mut self, m: &Mutation) -> Result<(), SysError>;
    /// Raise the soft and hard RLIMIT_MEMLOCK of process `pid` to unlimited so
    /// it can `mlockall` (design §3). The backend must act only while
    /// the start time of `pid` equals `starttime`, i.e. on the very process
    /// the session verified. Called in dry-run mode too (see the module text).
    /// The default refuses, so a backend without this operation fails ATTACH
    /// closed.
    fn raise_memlock(&mut self, _pid: u32, _starttime: u64) -> Result<(), SysError> {
        Err(SysError::Unsupported)
    }
    fn journal_load(&mut self) -> Result<Option<Vec<u8>>, SysError>;
    /// Append one line, then fsync the file and its directory.
    fn journal_append(&mut self, line: &[u8]) -> Result<(), SysError>;
    /// Atomically replace the journal (temp file, fsync, rename, fsync dir).
    fn journal_replace(&mut self, data: &[u8]) -> Result<(), SysError>;
    fn journal_remove(&mut self) -> Result<(), SysError>;
    /// Restore lock shared with aegis-restore.sh. `Ok(false)` = held by someone else.
    fn restore_lock(&mut self) -> Result<bool, SysError>;
    fn restore_unlock(&mut self);
    /// Start or stop receiving NFLOG packets for media address learning.
    fn packet_capture(&mut self, on: bool) -> Result<(), SysError>;
    /// Raw IP packets received from NFLOG since the last call.
    fn poll_packets(&mut self) -> Vec<Vec<u8>>;
}

pub fn read_text<S: SysOps + ?Sized>(sys: &mut S, path: &str) -> Result<String, SysError> {
    let b = sys.read_file(path)?;
    String::from_utf8(b).map_err(|_| SysError::Invalid)
}

pub fn getprop<S: SysOps + ?Sized>(sys: &mut S, key: &str) -> String {
    sys.read_cmd(&["getprop", key]).map(|s| s.trim().to_string()).unwrap_or_default()
}

/// Last non-empty line of `settings get`, trimmed; `None` if the command failed.
pub fn settings_get<S: SysOps + ?Sized>(sys: &mut S, ns: &str, key: &str) -> Option<String> {
    let out = sys.read_cmd(&["settings", "get", ns, key]).ok()?;
    Some(last_line(&out).to_string())
}

pub fn last_line(s: &str) -> &str {
    s.lines().map(str::trim).filter(|l| !l.is_empty()).last().unwrap_or("")
}
