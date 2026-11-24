//! Production [`SysOps`]: programs are executed directly from /system/bin
//! with an argument vector (no shell), with a timeout and an output cap.

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::journal::JOURNAL_PATH;
use crate::procfs;
use crate::session::BOOT_ID_PATH;
use crate::sysops::{Mutation, SysError, SysOps};
use crate::valid::parse_u32;

pub const STATE_DIR: &str = "/data/adb/aegischat";
const LOCK_DIR: &str = "/data/adb/aegischat/restore.lock";
const LOCK_OWNER: &str = "/data/adb/aegischat/restore.lock/owner";
const JOURNAL_TMP: &str = "/data/adb/aegischat/journal.v1.tmp";
const CMD_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_OUTPUT: u64 = 8 << 20;

pub struct RealSys {
    start: Instant,
    clk_tck: u64,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    nflog: Option<crate::nflog::Listener>,
}

impl Default for RealSys {
    fn default() -> Self {
        Self::new()
    }
}

impl RealSys {
    pub fn new() -> Self {
        // SAFETY: sysconf has no preconditions.
        let t = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        RealSys {
            start: Instant::now(),
            clk_tck: if t > 0 { t as u64 } else { 100 },
            #[cfg(any(target_os = "linux", target_os = "android"))]
            nflog: None,
        }
    }
}

fn program_path(name: &str) -> Result<PathBuf, SysError> {
    if name.starts_with('/') {
        Ok(PathBuf::from(name))
    } else if !name.is_empty() && name.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.')) {
        Ok(Path::new("/system/bin").join(name))
    } else {
        Err(SysError::Invalid)
    }
}

fn run<A: AsRef<str>>(argv: &[A], stdin: Option<&[u8]>) -> Result<Vec<u8>, SysError> {
    let (first, rest) = argv.split_first().ok_or(SysError::Invalid)?;
    let mut cmd = Command::new(program_path(first.as_ref())?);
    for a in rest {
        if a.as_ref().contains('\0') {
            return Err(SysError::Invalid);
        }
        cmd.arg(a.as_ref());
    }
    cmd.env("PATH", "/system/bin:/system/xbin").env("LC_ALL", "C");
    cmd.stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() }).stdout(Stdio::piped()).stderr(Stdio::null());
    let mut child = cmd.spawn().map_err(|_| SysError::Spawn)?;
    if let (Some(data), Some(mut si)) = (stdin, child.stdin.take()) {
        if si.write_all(data).is_err() {
            let _ = child.kill();
            let _ = child.wait();
            return Err(SysError::Io);
        }
    }
    let Some(out) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(SysError::Io);
    };
    let reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = out.take(MAX_OUTPUT).read_to_end(&mut buf);
        buf
    });
    let deadline = Instant::now() + CMD_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break Some(s),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    let buf = reader.join().map_err(|_| SysError::Io)?;
    match status {
        Some(s) if s.success() => Ok(buf),
        Some(s) => Err(SysError::Exit(s.code().unwrap_or(-1))),
        None => Err(SysError::Timeout),
    }
}

fn io(e: std::io::Error) -> SysError {
    if e.kind() == ErrorKind::NotFound {
        SysError::NotFound
    } else {
        SysError::Io
    }
}

fn ensure_state_dir() -> Result<(), SysError> {
    match fs::DirBuilder::new().mode(0o700).create(STATE_DIR) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {}
        Err(e) => return Err(io(e)),
    }
    fs::set_permissions(STATE_DIR, fs::Permissions::from_mode(0o700)).map_err(io)
}

fn sync_state_dir() -> Result<(), SysError> {
    File::open(STATE_DIR).and_then(|d| d.sync_all()).map_err(io)
}

impl SysOps for RealSys {
    fn read_cmd(&mut self, argv: &[&str]) -> Result<String, SysError> {
        let out = run(argv, None)?;
        String::from_utf8(out).map_err(|_| SysError::Invalid)
    }

    fn read_file(&mut self, path: &str) -> Result<Vec<u8>, SysError> {
        let f = File::open(path).map_err(io)?;
        let mut buf = Vec::new();
        f.take(MAX_OUTPUT).read_to_end(&mut buf).map_err(io)?;
        Ok(buf)
    }

    fn read_file_range(&mut self, path: &str, offset: u64, len: usize) -> Result<Vec<u8>, SysError> {
        let mut f = File::open(path).map_err(io)?;
        f.seek(SeekFrom::Start(offset)).map_err(io)?;
        let mut buf = Vec::with_capacity(len.min(1 << 20));
        f.take(len as u64).read_to_end(&mut buf).map_err(io)?;
        Ok(buf)
    }

    fn file_size(&mut self, path: &str) -> Result<u64, SysError> {
        fs::metadata(path).map(|m| m.len()).map_err(io)
    }

    fn list_dir(&mut self, path: &str) -> Result<Vec<String>, SysError> {
        let mut out = Vec::new();
        for e in fs::read_dir(path).map_err(io)? {
            let e = e.map_err(io)?;
            if let Some(n) = e.file_name().to_str() {
                out.push(n.to_string());
            }
        }
        Ok(out)
    }

    fn exists(&mut self, path: &str) -> bool {
        Path::new(path).exists()
    }

    fn random16(&mut self) -> Result<[u8; 16], SysError> {
        let mut b = [0u8; 16];
        File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut b)).map_err(io)?;
        Ok(b)
    }

    fn now_ms(&mut self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    fn uptime_ticks(&mut self) -> Result<u64, SysError> {
        let t = fs::read_to_string("/proc/uptime").map_err(io)?;
        let first = t.split_whitespace().next().ok_or(SysError::Invalid)?;
        let (secs, frac) = first.split_once('.').unwrap_or((first, "0"));
        let secs: u64 = secs.parse().map_err(|_| SysError::Invalid)?;
        let centis: u64 = format!("{frac:0<2}")[..2].parse().map_err(|_| SysError::Invalid)?;
        Ok(secs * self.clk_tck + centis * self.clk_tck / 100)
    }

    fn sleep_ms(&mut self, ms: u64) {
        std::thread::sleep(Duration::from_millis(ms));
    }

    fn apply(&mut self, m: &Mutation) -> Result<(), SysError> {
        match m {
            Mutation::Exec(argv) => run(argv, None).map(|_| ()),
            Mutation::ExecStdin { argv, stdin } => run(argv, Some(stdin.as_bytes())).map(|_| ()),
            Mutation::WriteFile { path, data } => {
                if !(path.starts_with("/proc/sys/vm/") || path.starts_with("/sys/block/zram")) || path.contains("..") {
                    return Err(SysError::Invalid);
                }
                OpenOptions::new().write(true).open(path).and_then(|mut f| f.write_all(data.as_bytes())).map_err(io)
            }
            Mutation::Kill { pid, starttime } => {
                if *pid <= 1 || *pid > 0x3fff_ffff {
                    return Err(SysError::Invalid);
                }
                match fs::read_to_string(format!("/proc/{pid}/stat")) {
                    Err(_) => Ok(()),
                    Ok(s) if procfs::stat_starttime(&s) != Some(*starttime) => Ok(()),
                    Ok(_) => {
                        // SAFETY: plain kill(2) on a validated positive pid.
                        let rc = unsafe { libc::kill(*pid as libc::pid_t, libc::SIGKILL) };
                        if rc == 0 {
                            Ok(())
                        } else {
                            Err(SysError::Io)
                        }
                    }
                }
            }
            Mutation::FillFreeMemory { reserve_mib, max_ms } => {
                let exe = std::env::current_exe().map_err(io)?;
                let exe = exe.to_str().ok_or(SysError::Invalid)?.to_string();
                run(&[exe, "--fill-memory".to_string(), reserve_mib.to_string(), max_ms.to_string()], None).map(|_| ())
            }
            Mutation::Notify { code } => {
                run(&["cmd", "notification", "post", "-t", "DialCrypt", "aegischat", code.as_str()], None).map(|_| ())
            }
        }
    }

    fn journal_load(&mut self) -> Result<Option<Vec<u8>>, SysError> {
        match fs::read(JOURNAL_PATH) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io(e)),
        }
    }

    fn journal_append(&mut self, line: &[u8]) -> Result<(), SysError> {
        ensure_state_dir()?;
        let mut f = OpenOptions::new().create(true).append(true).mode(0o600).open(JOURNAL_PATH).map_err(io)?;
        f.write_all(line).map_err(io)?;
        f.sync_all().map_err(io)?;
        sync_state_dir()
    }

    fn journal_replace(&mut self, data: &[u8]) -> Result<(), SysError> {
        ensure_state_dir()?;
        let mut f = OpenOptions::new().create(true).write(true).truncate(true).mode(0o600).open(JOURNAL_TMP).map_err(io)?;
        f.write_all(data).map_err(io)?;
        f.sync_all().map_err(io)?;
        fs::rename(JOURNAL_TMP, JOURNAL_PATH).map_err(io)?;
        sync_state_dir()
    }

    fn journal_remove(&mut self) -> Result<(), SysError> {
        match fs::remove_file(JOURNAL_PATH) {
            Ok(()) => sync_state_dir(),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
            Err(e) => Err(io(e)),
        }
    }

    /// mkdir-based lock shared with aegis-restore.sh. The owner file holds
    /// `<pid> <boot_id> <starttime>`. The lock is stale when it is from
    /// another boot, when the pid is gone or has a different start time, or
    /// when it has no valid owner after 60 s.
    fn restore_lock(&mut self) -> Result<bool, SysError> {
        ensure_state_dir()?;
        let boot = fs::read_to_string(BOOT_ID_PATH).map(|s| s.trim().to_string()).unwrap_or_default();
        let start_of = |pid: u32| fs::read_to_string(format!("/proc/{pid}/stat")).ok().as_deref().and_then(procfs::stat_starttime);
        for _ in 0..2 {
            match fs::DirBuilder::new().mode(0o700).create(LOCK_DIR) {
                Ok(()) => {
                    let me = std::process::id();
                    let start = start_of(me).map(|s| s.to_string()).unwrap_or_default();
                    fs::write(LOCK_OWNER, format!("{me} {boot} {start}\n")).map_err(io)?;
                    return Ok(true);
                }
                Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                    let owner = fs::read_to_string(LOCK_OWNER).unwrap_or_default();
                    let f: Vec<&str> = owner.split_whitespace().collect();
                    let stale = match f.first().and_then(|p| parse_u32(p)) {
                        Some(pid) => {
                            let live = start_of(pid);
                            let recorded = f.get(2).and_then(|s| s.parse::<u64>().ok());
                            f.get(1).copied().unwrap_or("") != boot || live.is_none() || (recorded.is_some() && recorded != live)
                        }
                        None => fs::metadata(LOCK_DIR)
                            .and_then(|m| m.modified())
                            .ok()
                            .and_then(|t| t.elapsed().ok())
                            .is_some_and(|age| age > Duration::from_secs(60)),
                    };
                    if !stale {
                        return Ok(false);
                    }
                    let _ = fs::remove_file(LOCK_OWNER);
                    let _ = fs::remove_dir(LOCK_DIR);
                }
                Err(e) => return Err(io(e)),
            }
        }
        Ok(false)
    }

    fn restore_unlock(&mut self) {
        let _ = fs::remove_file(LOCK_OWNER);
        let _ = fs::remove_dir(LOCK_DIR);
    }

    fn raise_memlock(&mut self, pid: u32, starttime: u64) -> Result<(), SysError> {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            if pid <= 1 || pid > 0x3fff_ffff {
                return Err(SysError::Invalid);
            }
            let same_process =
                || fs::read_to_string(format!("/proc/{pid}/stat")).ok().as_deref().and_then(procfs::stat_starttime) == Some(starttime);
            if !same_process() {
                return Err(SysError::NotFound);
            }
            let unlimited = libc::rlimit64 { rlim_cur: libc::RLIM64_INFINITY, rlim_max: libc::RLIM64_INFINITY };
            // To be confirmed on device: on the Pixel 7 (Android 16) the daemon's domain (magisk or ksu) may set
            // the limit of a priv_app process: CAP_SYS_RESOURCE plus SELinux `process setrlimit`.
            // SAFETY: prlimit64(2) on a validated positive pid with a valid new limit and no old-limit buffer.
            let rc = unsafe { libc::prlimit64(pid as libc::pid_t, libc::RLIMIT_MEMLOCK, &unlimited, std::ptr::null_mut()) };
            if rc != 0 {
                return Err(SysError::Io);
            }
            // The pid may have been recycled between the first check and the call. A stranger that
            // received the limit keeps it, which grants it nothing else; the caller must still fail.
            if !same_process() {
                return Err(SysError::NotFound);
            }
            Ok(())
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            let _ = (pid, starttime);
            Err(SysError::Unsupported)
        }
    }

    fn packet_capture(&mut self, on: bool) -> Result<(), SysError> {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            if !on {
                self.nflog = None;
                return Ok(());
            }
            if self.nflog.is_none() {
                self.nflog = Some(crate::nflog::Listener::open(crate::firewall::NFLOG_GROUP)?);
            }
            Ok(())
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            if on {
                Err(SysError::Unsupported)
            } else {
                Ok(())
            }
        }
    }

    fn poll_packets(&mut self) -> Vec<Vec<u8>> {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            match self.nflog.as_mut() {
                Some(l) => l.drain(),
                None => Vec::new(),
            }
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            Vec::new()
        }
    }
}
