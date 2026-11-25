//! Local protocol on the abstract Unix socket `@io.github.h4lovoid.dialcrypt.d`.
//!
//! Frame: `[u16 BE len][u8 type][payload]`, `len = 1 + payload length`,
//! at most [`MAX_FRAME`]. Every message type has one exact payload length;
//! anything else is a protocol error and closes the connection.
//!
//! | type | name      | direction | payload |
//! |------|-----------|-----------|---------|
//! | 1    | HELLO     | App→d     | version(1) |
//! | 1    | HELLO     | d→App     | version(1) mode(1) |
//! | 2    | PREPARE   | App→d     | – |
//! | 3    | PROGRESS  | d→App     | step(1) |
//! | 4    | READY     | d→App     | lease(16) mode(1) tier(1) claims(1) |
//! | 5    | FAIL      | d→App     | item(u16 BE) code(u16 BE) |
//! | 6    | ATTACH    | App→d     | lease(16) |
//! | 7    | ATTACHED  | d→App     | mode(1) tier(1) claims(1) |
//! | 8    | HEARTBEAT | App→d     | lease(16), every 500 ms; 2 s silence = App dead |
//! | 9    | VIOLATION | d→App     | code(u16 BE) |
//! | 10   | END       | App→d     | – |
//! | 11   | ENDED     | d→App     | status(1): 0 restored, 1 restore incomplete |
//! | 12   | TRIM      | App→d     | – (best-effort `sm fstrim` after duress/wipe) |
//!
//! mode: 0 dry run (nothing on the device was changed), 1 armed.
//! In both modes the daemon raises RLIMIT_MEMLOCK of the attaching secure
//! process before it sends ATTACHED; that limit belongs to the App's own
//! process and ends with it, so it does not count as a device change.
//! claims: bit0 offline/radios off/LTE-NR only, bit1 other apps stopped,
//! bit2 memory scrubbed (bits 1–2 only in tier 2 and only when they succeeded).

pub const SOCKET_NAME: &[u8] = b"io.github.h4lovoid.dialcrypt.d";
pub const PROTO_VERSION: u8 = 1;
pub const MAX_FRAME: usize = 64;

pub const MODE_DRY_RUN: u8 = 0;
pub const MODE_ARMED: u8 = 1;
pub const CLAIM_OFFLINE: u8 = 1;
pub const CLAIM_APPS_STOPPED: u8 = 2;
pub const CLAIM_MEMORY_SCRUBBED: u8 = 4;

pub const STEP_PRECHECK: u8 = 1;
pub const STEP_FIREWALL: u8 = 2;
pub const STEP_RADIOS: u8 = 3;
pub const STEP_APPS: u8 = 4;
pub const STEP_MEMORY: u8 = 5;

const T_HELLO: u8 = 1;
const T_PREPARE: u8 = 2;
const T_PROGRESS: u8 = 3;
const T_READY: u8 = 4;
const T_FAIL: u8 = 5;
const T_ATTACH: u8 = 6;
const T_ATTACHED: u8 = 7;
const T_HEARTBEAT: u8 = 8;
const T_VIOLATION: u8 = 9;
const T_END: u8 = 10;
const T_ENDED: u8 = 11;
const T_TRIM: u8 = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    Length,
    UnknownType,
    BadPayload,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientMsg {
    Hello { version: u8 },
    Prepare,
    Attach { lease: [u8; 16] },
    Heartbeat { lease: [u8; 16] },
    End,
    TrimStorage,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerMsg {
    Hello { version: u8, mode: u8 },
    Progress { step: u8 },
    Ready { lease: [u8; 16], mode: u8, tier: u8, claims: u8 },
    Fail { item: u16, code: u16 },
    Attached { mode: u8, tier: u8, claims: u8 },
    Violation { code: u16 },
    Ended { status: u8 },
}

fn frame(ty: u8, payload: &[u8]) -> Vec<u8> {
    let len = (1 + payload.len()) as u16;
    let mut f = len.to_be_bytes().to_vec();
    f.push(ty);
    f.extend_from_slice(payload);
    f
}

fn lease_of(p: &[u8]) -> Result<[u8; 16], FrameError> {
    let mut l = [0u8; 16];
    if p.len() != 16 {
        return Err(FrameError::BadPayload);
    }
    l.copy_from_slice(p);
    Ok(l)
}

fn be16(p: &[u8], i: usize) -> u16 {
    u16::from_be_bytes([p[i], p[i + 1]])
}

pub fn encode_client(m: &ClientMsg) -> Vec<u8> {
    match m {
        ClientMsg::Hello { version } => frame(T_HELLO, &[*version]),
        ClientMsg::Prepare => frame(T_PREPARE, &[]),
        ClientMsg::Attach { lease } => frame(T_ATTACH, lease),
        ClientMsg::Heartbeat { lease } => frame(T_HEARTBEAT, lease),
        ClientMsg::End => frame(T_END, &[]),
        ClientMsg::TrimStorage => frame(T_TRIM, &[]),
    }
}

/// Decodes `type ‖ payload` (a frame without its length prefix).
pub fn decode_client(body: &[u8]) -> Result<ClientMsg, FrameError> {
    let (&ty, p) = body.split_first().ok_or(FrameError::Length)?;
    let need = |n: usize| if p.len() == n { Ok(()) } else { Err(FrameError::BadPayload) };
    match ty {
        T_HELLO => need(1).map(|_| ClientMsg::Hello { version: p[0] }),
        T_PREPARE => need(0).map(|_| ClientMsg::Prepare),
        T_ATTACH => Ok(ClientMsg::Attach { lease: lease_of(p)? }),
        T_HEARTBEAT => Ok(ClientMsg::Heartbeat { lease: lease_of(p)? }),
        T_END => need(0).map(|_| ClientMsg::End),
        T_TRIM => need(0).map(|_| ClientMsg::TrimStorage),
        _ => Err(FrameError::UnknownType),
    }
}

pub fn encode_server(m: &ServerMsg) -> Vec<u8> {
    match m {
        ServerMsg::Hello { version, mode } => frame(T_HELLO, &[*version, *mode]),
        ServerMsg::Progress { step } => frame(T_PROGRESS, &[*step]),
        ServerMsg::Ready { lease, mode, tier, claims } => {
            let mut p = lease.to_vec();
            p.extend_from_slice(&[*mode, *tier, *claims]);
            frame(T_READY, &p)
        }
        ServerMsg::Fail { item, code } => {
            let mut p = item.to_be_bytes().to_vec();
            p.extend_from_slice(&code.to_be_bytes());
            frame(T_FAIL, &p)
        }
        ServerMsg::Attached { mode, tier, claims } => frame(T_ATTACHED, &[*mode, *tier, *claims]),
        ServerMsg::Violation { code } => frame(T_VIOLATION, &code.to_be_bytes()),
        ServerMsg::Ended { status } => frame(T_ENDED, &[*status]),
    }
}

/// Reference decoder for the App side (and tests).
pub fn decode_server(body: &[u8]) -> Result<ServerMsg, FrameError> {
    let (&ty, p) = body.split_first().ok_or(FrameError::Length)?;
    let need = |n: usize| if p.len() == n { Ok(()) } else { Err(FrameError::BadPayload) };
    match ty {
        T_HELLO => need(2).map(|_| ServerMsg::Hello { version: p[0], mode: p[1] }),
        T_PROGRESS => need(1).map(|_| ServerMsg::Progress { step: p[0] }),
        T_READY => {
            need(19)?;
            Ok(ServerMsg::Ready { lease: lease_of(&p[..16])?, mode: p[16], tier: p[17], claims: p[18] })
        }
        T_FAIL => need(4).map(|_| ServerMsg::Fail { item: be16(p, 0), code: be16(p, 2) }),
        T_ATTACHED => need(3).map(|_| ServerMsg::Attached { mode: p[0], tier: p[1], claims: p[2] }),
        T_VIOLATION => need(2).map(|_| ServerMsg::Violation { code: be16(p, 0) }),
        T_ENDED => need(1).map(|_| ServerMsg::Ended { status: p[0] }),
        _ => Err(FrameError::UnknownType),
    }
}

/// Reassembles frames from a byte stream.
#[derive(Debug, Default)]
pub struct FrameReader {
    buf: Vec<u8>,
}

impl FrameReader {
    /// Returns every complete frame body (`type ‖ payload`). A zero or
    /// oversized length is fatal for the connection.
    pub fn push(&mut self, data: &[u8]) -> Result<Vec<Vec<u8>>, FrameError> {
        self.buf.extend_from_slice(data);
        let mut out = Vec::new();
        loop {
            if self.buf.len() < 2 {
                break;
            }
            let len = u16::from_be_bytes([self.buf[0], self.buf[1]]) as usize;
            if len == 0 || len > MAX_FRAME {
                self.buf.clear();
                return Err(FrameError::Length);
            }
            if self.buf.len() < 2 + len {
                break;
            }
            out.push(self.buf[2..2 + len].to_vec());
            self.buf.drain(..2 + len);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipc_roundtrip_all_messages() {
        let lease = [9u8; 16];
        for m in [
            ClientMsg::Hello { version: 1 },
            ClientMsg::Prepare,
            ClientMsg::Attach { lease },
            ClientMsg::Heartbeat { lease },
            ClientMsg::End,
            ClientMsg::TrimStorage,
        ] {
            let f = encode_client(&m);
            let mut r = FrameReader::default();
            let got = r.push(&f);
            assert_eq!(got.as_ref().map(|v| v.len()), Ok(1));
            assert_eq!(decode_client(&f[2..]), Ok(m));
        }
        for m in [
            ServerMsg::Hello { version: 1, mode: 0 },
            ServerMsg::Progress { step: 3 },
            ServerMsg::Ready { lease, mode: 1, tier: 2, claims: 7 },
            ServerMsg::Fail { item: 10, code: 100 },
            ServerMsg::Attached { mode: 1, tier: 1, claims: 1 },
            ServerMsg::Violation { code: 401 },
            ServerMsg::Ended { status: 0 },
        ] {
            let f = encode_server(&m);
            assert_eq!(u16::from_be_bytes([f[0], f[1]]) as usize, f.len() - 2);
            assert_eq!(decode_server(&f[2..]), Ok(m));
        }
    }

    #[test]
    fn ipc_rejects_malformed_frames() {
        let mut r = FrameReader::default();
        assert_eq!(r.push(&[0, 0]), Err(FrameError::Length));
        let mut r = FrameReader::default();
        assert_eq!(r.push(&[0xff, 0xff, 1]), Err(FrameError::Length));
        let mut r = FrameReader::default();
        assert_eq!(r.push(&[0, 65]), Err(FrameError::Length));
        // Split delivery: one byte at a time still yields exactly one frame.
        let f = encode_client(&ClientMsg::Attach { lease: [1; 16] });
        let mut r = FrameReader::default();
        let mut frames = Vec::new();
        for b in &f {
            frames.extend(r.push(&[*b]).unwrap_or_default());
        }
        assert_eq!(frames.len(), 1);
        assert_eq!(decode_client(&[]), Err(FrameError::Length));
        assert_eq!(decode_client(&[99]), Err(FrameError::UnknownType));
        assert_eq!(decode_client(&[2, 0]), Err(FrameError::BadPayload), "PREPARE with payload");
        assert_eq!(decode_client(&[6, 1, 2, 3]), Err(FrameError::BadPayload), "short lease");
        assert_eq!(decode_client(&[1]), Err(FrameError::BadPayload), "HELLO without version");
        assert_eq!(decode_client(&[4; 20]), Err(FrameError::UnknownType), "server-only type from client");
        assert_eq!(decode_server(&[5, 0, 1]), Err(FrameError::BadPayload));
    }
}
