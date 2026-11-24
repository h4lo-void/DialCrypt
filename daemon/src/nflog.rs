//! NFLOG packet source for media address learning (design 6.7).
//! Parsing is platform independent and tested; the netlink socket exists
//! only on Linux/Android. To be confirmed on device: kernel NFLOG support and SELinux
//! permission for netlink_netfilter_socket in the magisk domain.

use std::net::IpAddr;

pub const NFNL_SUBSYS_ULOG: u16 = 4;
pub const NFULNL_MSG_PACKET: u16 = 0;
pub const NFULNL_MSG_CONFIG: u16 = 1;
pub const NFULA_PAYLOAD: u16 = 9;

fn u16_at(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_ne_bytes([*b.get(i)?, *b.get(i + 1)?]))
}

fn u32_at(b: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_ne_bytes([*b.get(i)?, *b.get(i + 1)?, *b.get(i + 2)?, *b.get(i + 3)?]))
}

/// Extracts NFULA_PAYLOAD (raw IP packets) from a netlink datagram.
pub fn parse_messages(buf: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + 16 <= buf.len() {
        let (Some(len), Some(ty)) = (u32_at(buf, off), u16_at(buf, off + 4)) else { break };
        let len = len as usize;
        if len < 16 || off + len > buf.len() {
            break;
        }
        if ty == (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_PACKET && len >= 20 {
            let end = off + len;
            let mut a = off + 20;
            while a + 4 <= end {
                let (Some(alen), Some(aty)) = (u16_at(buf, a), u16_at(buf, a + 2)) else { break };
                let alen = alen as usize;
                if alen < 4 || a + alen > end {
                    break;
                }
                if aty & 0x3fff == NFULA_PAYLOAD {
                    out.push(buf[a + 4..a + alen].to_vec());
                }
                a += (alen + 3) & !3;
            }
        }
        off += (len + 3) & !3;
    }
    out
}

/// (protocol, destination) of an IPv4/IPv6 packet.
pub fn parse_ip(p: &[u8]) -> Option<(u8, IpAddr)> {
    match p.first()? >> 4 {
        4 => {
            if p.len() < 20 || (p[0] & 0x0f) < 5 {
                return None;
            }
            Some((p[9], IpAddr::from([p[16], p[17], p[18], p[19]])))
        }
        6 => {
            if p.len() < 40 {
                return None;
            }
            let mut a = [0u8; 16];
            a.copy_from_slice(&p[24..40]);
            Some((p[6], IpAddr::from(a)))
        }
        _ => None,
    }
}

/// nfnetlink config message for `group` with one attribute.
pub fn config_msg(group: u16, attr_type: u16, attr: &[u8], seq: u32) -> Vec<u8> {
    let attr_len = 4 + attr.len();
    let padded = (attr_len + 3) & !3;
    let total = 16 + 4 + padded;
    let mut m = Vec::with_capacity(total);
    m.extend_from_slice(&(total as u32).to_ne_bytes());
    m.extend_from_slice(&((NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_CONFIG).to_ne_bytes());
    m.extend_from_slice(&(1u16 | 4u16).to_ne_bytes()); // NLM_F_REQUEST | NLM_F_ACK
    m.extend_from_slice(&seq.to_ne_bytes());
    m.extend_from_slice(&0u32.to_ne_bytes());
    m.extend_from_slice(&[0u8, 0u8]); // AF_UNSPEC, NFNETLINK_V0
    m.extend_from_slice(&group.to_be_bytes());
    m.extend_from_slice(&(attr_len as u16).to_ne_bytes());
    m.extend_from_slice(&attr_type.to_ne_bytes());
    m.extend_from_slice(attr);
    m.resize(total, 0);
    m
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub use linux::Listener;

#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    use super::{config_msg, parse_messages};
    use crate::sysops::SysError;

    const NETLINK_NETFILTER: libc::c_int = 12;
    const NFULA_CFG_CMD: u16 = 1;
    const NFULA_CFG_MODE: u16 = 2;
    const NFULNL_CFG_CMD_BIND: u8 = 1;
    const NFULNL_COPY_PACKET: u8 = 2;

    pub struct Listener {
        fd: OwnedFd,
    }

    impl Listener {
        pub fn open(group: u16) -> Result<Self, SysError> {
            // SAFETY: plain socket(2) call; the result is checked before use.
            let raw = unsafe {
                libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK, NETLINK_NETFILTER)
            };
            if raw < 0 {
                return Err(SysError::Unsupported);
            }
            // SAFETY: `raw` is a fresh, owned descriptor.
            let fd = unsafe { OwnedFd::from_raw_fd(raw) };
            // SAFETY: zeroed sockaddr_nl is a valid "kernel assigns pid" address.
            let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
            addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
            // SAFETY: addr is a valid sockaddr_nl for the duration of the call.
            let rc = unsafe {
                libc::bind(
                    fd.as_raw_fd(),
                    &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
                )
            };
            if rc != 0 {
                return Err(SysError::Io);
            }
            let l = Listener { fd };
            l.send(&config_msg(group, NFULA_CFG_CMD, &[NFULNL_CFG_CMD_BIND], 1))?;
            let mut mode = 128u32.to_be_bytes().to_vec();
            mode.extend_from_slice(&[NFULNL_COPY_PACKET, 0]);
            l.send(&config_msg(group, NFULA_CFG_MODE, &mode, 2))?;
            Ok(l)
        }

        fn send(&self, msg: &[u8]) -> Result<(), SysError> {
            // SAFETY: zeroed sockaddr_nl addresses the kernel (pid 0).
            let mut dst: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
            dst.nl_family = libc::AF_NETLINK as libc::sa_family_t;
            // SAFETY: msg and dst are valid for the duration of the call.
            let n = unsafe {
                libc::sendto(
                    self.fd.as_raw_fd(),
                    msg.as_ptr() as *const libc::c_void,
                    msg.len(),
                    0,
                    &dst as *const libc::sockaddr_nl as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
                )
            };
            if n < 0 || n as usize != msg.len() {
                Err(SysError::Io)
            } else {
                Ok(())
            }
        }

        pub fn drain(&mut self) -> Vec<Vec<u8>> {
            let mut out = Vec::new();
            let mut buf = vec![0u8; 65536];
            for _ in 0..64 {
                // SAFETY: buf is writable for buf.len() bytes.
                let n = unsafe {
                    libc::recv(self.fd.as_raw_fd(), buf.as_mut_ptr() as *mut libc::c_void, buf.len(), libc::MSG_DONTWAIT)
                };
                if n <= 0 {
                    break;
                }
                out.extend(parse_messages(&buf[..n as usize]));
            }
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet_msg(payload: &[u8]) -> Vec<u8> {
        let alen = 4 + payload.len();
        let total = 20 + ((alen + 3) & !3);
        let mut m = Vec::new();
        m.extend_from_slice(&(total as u32).to_ne_bytes());
        m.extend_from_slice(&((NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_PACKET).to_ne_bytes());
        m.extend_from_slice(&[0u8; 10]);
        m.extend_from_slice(&[2u8, 0, 0x1c, 0xad]);
        m.extend_from_slice(&(alen as u16).to_ne_bytes());
        m.extend_from_slice(&NFULA_PAYLOAD.to_ne_bytes());
        m.extend_from_slice(payload);
        m.resize(total, 0);
        m
    }

    #[test]
    fn extracts_udp_destination_from_nflog() {
        let mut ip = vec![0x45u8, 0, 0, 28, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 2, 10, 9, 9, 9];
        ip.extend_from_slice(&[0u8; 8]);
        let mut buf = packet_msg(&ip);
        buf.extend(packet_msg(&ip));
        let pk = parse_messages(&buf);
        assert_eq!(pk.len(), 2);
        assert_eq!(parse_ip(&pk[0]), Some((17, IpAddr::from([10, 9, 9, 9]))));
        assert!(parse_messages(&buf[..buf.len() - 3]).len() == 1, "truncated message ignored");
        assert_eq!(parse_ip(&[0x45, 0]), None);
        assert_eq!(config_msg(7341, 1, &[1], 1).len(), 28);
    }
}
