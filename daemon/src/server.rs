//! Socket loop (Linux/Android): abstract socket `@io.github.h4lovoid.dialcrypt.d`, peer
//! identity from SO_PEERCRED, a tick every 100 ms. All decisions are made by
//! [`Session`]; this file only moves bytes.

use std::collections::BTreeMap;
use std::io::{ErrorKind, Read, Write};
use std::os::fd::AsRawFd;
#[cfg(target_os = "android")]
use std::os::android::net::SocketAddrExt;
#[cfg(target_os = "linux")]
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr, UnixListener, UnixStream};
use std::time::{Duration, Instant};

use crate::ipc::SOCKET_NAME;
use crate::session::{ConnId, Input, Output, Session};
use crate::sysops::SysOps;

pub const EX_OSERR: i32 = 71;
const MAX_CONNS: usize = 8;

/// Field diagnostics in the system log (tag `aegiscalld`): connection events, message types
/// and numeric codes only. Never a lease, an address or anything a peer sent.
#[cfg(target_os = "android")]
fn diag(text: &str) {
    use std::ffi::CString;
    use std::os::raw::{c_char, c_int};
    #[link(name = "log")]
    extern "C" {
        fn __android_log_write(prio: c_int, tag: *const c_char, text: *const c_char) -> c_int;
    }
    if let (Ok(tag), Ok(msg)) = (CString::new("aegiscalld"), CString::new(text)) {
        // SAFETY: both pointers are valid NUL-terminated strings for the duration of the call.
        unsafe {
            __android_log_write(4, tag.as_ptr(), msg.as_ptr());
        }
    }
}

#[cfg(not(target_os = "android"))]
fn diag(_text: &str) {}

/// Type and codes of a server frame (`[u16 len][u8 type][payload]`) worth a log line.
fn describe(frame: &[u8]) -> Option<String> {
    let ty = *frame.get(2)?;
    let p = frame.get(3..)?;
    let be = |i: usize| p.get(i..i + 2).map(|b| u16::from_be_bytes([b[0], b[1]])).unwrap_or(u16::MAX);
    let b = |i: usize| p.get(i).copied().unwrap_or(u8::MAX);
    match ty {
        4 => Some("READY".to_string()),
        5 => Some(format!("FAIL item={} code={}", be(0), be(2))),
        7 => Some(format!("ATTACHED mode={} tier={} claims={}", b(0), b(1), b(2))),
        9 => Some(format!("VIOLATION code={}", be(0))),
        11 => Some(format!("ENDED status={}", b(0))),
        _ => None,
    }
}

fn peer_cred(s: &UnixStream) -> Option<(u32, u32)> {
    // SAFETY: zeroed ucred is a valid out-buffer for getsockopt.
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: cred/len point to valid memory of the advertised size.
    let rc = unsafe {
        libc::getsockopt(
            s.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut libc::ucred as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 || cred.pid <= 0 {
        return None;
    }
    Some((cred.uid, cred.pid as u32))
}

pub fn serve<S: SysOps>(session: &mut Session<S>) -> i32 {
    let Ok(addr) = SocketAddr::from_abstract_name(SOCKET_NAME) else { return EX_OSERR };
    let Ok(listener) = UnixListener::bind_addr(&addr) else { return EX_OSERR };
    if listener.set_nonblocking(true).is_err() {
        return EX_OSERR;
    }
    let mut conns: BTreeMap<ConnId, UnixStream> = BTreeMap::new();
    let mut next: ConnId = 1;
    let mut last_tick = Instant::now();
    let mut pending: Vec<Output> = Vec::new();
    let mut buf = [0u8; 256];
    loop {
        let mut outputs = std::mem::take(&mut pending);
        while let Ok((s, _)) = listener.accept() {
            let id = next;
            next += 1;
            if conns.len() >= MAX_CONNS || s.set_nonblocking(true).is_err() {
                continue;
            }
            if let Some((uid, pid)) = peer_cred(&s) {
                conns.insert(id, s);
                diag(&format!("conn {id} connected uid={uid} pid={pid}"));
                outputs.extend(session.handle(Input::Connected { conn: id, uid, pid }));
            }
        }
        let ids: Vec<ConnId> = conns.keys().copied().collect();
        for id in ids {
            loop {
                let r = match conns.get_mut(&id) {
                    Some(s) => s.read(&mut buf),
                    None => break,
                };
                match r {
                    Ok(n) if n > 0 => outputs.extend(session.handle(Input::Data { conn: id, bytes: buf[..n].to_vec() })),
                    Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                    _ => {
                        conns.remove(&id);
                        diag(&format!("conn {id} closed by peer"));
                        outputs.extend(session.handle(Input::Closed { conn: id }));
                        break;
                    }
                }
            }
        }
        if last_tick.elapsed() >= Duration::from_millis(100) {
            last_tick = Instant::now();
            outputs.extend(session.handle(Input::Tick));
        }
        for o in outputs {
            match o {
                Output::Send { conn, frame } => {
                    if let Some(d) = describe(&frame) {
                        diag(&format!("conn {conn} send {d}"));
                    }
                    let failed = conns.get_mut(&conn).map(|s| s.write_all(&frame).is_err()).unwrap_or(false);
                    if failed {
                        conns.remove(&conn);
                        pending.extend(session.handle(Input::Closed { conn }));
                    }
                }
                Output::Close { conn } => {
                    diag(&format!("conn {conn} closed by daemon"));
                    conns.remove(&conn);
                }
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}
