use crate::convert::TryFrom;
use crate::fmt;
use crate::io::{self, IoSlice, IoSliceMut, BorrowedCursor};
use crate::net::{Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, SocketAddrV4};
use crate::sys::unsupported;
use crate::sys_common::IntoInner;
use crate::time::Duration;
use crate::ffi::CString;

use core::ffi::c_void;

const SOCK_STREAM: i32 = 1;
const SOCK_DGRAM: i32 = 2;
const AF_INET: u8 = 2;

#[derive(Clone)]
pub struct Socket(i32);

impl Drop for Socket {
    fn drop(&mut self) {
        unsafe { psp::sys::sceNetInetClose(self.0); }
    }
}

#[derive(Clone)]
pub struct TcpStream(Socket);

fn socketaddr_to_sockaddr(addr: &SocketAddr) -> io::Result<psp::sys::sockaddr> {
    match addr {
        SocketAddr::V4(v4) =>
            Ok(psp::sys::sockaddr_in::new(u32::from_be_bytes(v4.ip().octets()), v4.port()).into()),
        _ => unsupported(),
    }
}

impl TcpStream {
    pub fn connect(addr: io::Result<&SocketAddr>) -> io::Result<TcpStream> {
        let sock = unsafe { psp::sys::sceNetInetSocket(AF_INET as i32, SOCK_STREAM, 0) };
        if sock < 0 {
            todo!()
        } else {
            let sockaddr = socketaddr_to_sockaddr(addr?)?;
            if unsafe { psp::sys::sceNetInetConnect(sock, &sockaddr, sockaddr.sa_len as u32) } < 0  {
                todo!("Error Handling")
            } else {
                Ok(TcpStream(Socket(sock)))
            }
        }
    }

    // these timeout functions definitely aren't supported, despite the psp having
    // sceNetInetSetsockopt, I checked thoroughly.

    pub fn connect_timeout(_: &SocketAddr, _: Duration) -> io::Result<TcpStream> {
        unsupported()
    }

    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        unsupported()
    }

    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        unsupported()
    }

    pub fn read_timeout(&self) -> io::Result<Option<Duration>> {
        unsupported()
    }

    pub fn write_timeout(&self) -> io::Result<Option<Duration>> {
        unsupported()
    }

    pub fn peek(&self, _: &mut [u8]) -> io::Result<usize> {
        //TODO might be sceNetInetRecv with MSG_PEEK flag set
        unsupported()
    }

    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let result = unsafe { psp::sys::sceNetInetRecv(self.0.0, buf.as_mut_ptr() as *mut c_void, buf.len(), 0) };
        if result < 0 {
            let err = unsafe { psp::sys::sceNetInetGetErrno() };
            Err(io::Error::new(io::ErrorKind::Other, err.to_string()))
        } else {
            Ok(result as usize)
        }
    }

    pub fn read_buf(&self, buf: BorrowedCursor<'_>) -> io::Result<()> {
        crate::io::default_read_buf(|b| self.read(b), buf)
    }

    pub fn read_vectored(&self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        crate::io::default_read_vectored(|buf| self.read(buf), bufs)
    }

    pub fn is_read_vectored(&self) -> bool {
        false
    }

    pub fn write(&self, buf: &[u8]) -> io::Result<usize> {
        let result = unsafe { psp::sys::sceNetInetSend(self.0.0, buf.as_ptr() as *const c_void, buf.len(), 0) };
        if result < 0 {
            todo!("Error Handling")
        } else {
            Ok(result as usize)
        }
    }

    pub fn write_vectored(&self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        crate::io::default_write_vectored(|buf| self.write(buf), bufs)
    }

    pub fn is_write_vectored(&self) -> bool {
        false
    }

    fn flush(&mut self) -> io::Result<()> { Ok(()) }

    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        let mut addr: psp::sys::sockaddr = unsafe { core::mem::zeroed() };
        let mut addr_len: psp::sys::socklen_t = core::mem::size_of::<psp::sys::sockaddr_in>() as psp::sys::socklen_t;
        let ret = unsafe { psp::sys::sceNetInetGetpeername(self.0.0, &mut addr, &mut addr_len) };
        if ret < 0 {
            todo!("Error Handling")
        } else {
            let addr = unsafe { core::mem::transmute::<psp::sys::sockaddr, psp::sys::sockaddr_in>(addr) };
            let port = addr.sin_port;
            let octets = u32::to_le_bytes(addr.sin_addr.s_addr);
            let sockaddr = SocketAddrV4::new(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]), port);
            Ok(SocketAddr::V4(sockaddr))
        }
    }

    pub fn socket_addr(&self) -> io::Result<SocketAddr> {
        let mut addr: psp::sys::sockaddr = unsafe { core::mem::zeroed() };
        let mut addr_len: psp::sys::socklen_t = core::mem::size_of::<psp::sys::sockaddr_in>() as psp::sys::socklen_t;
        let ret = unsafe { psp::sys::sceNetInetGetsockname(self.0.0, &mut addr, &mut addr_len) };
        if ret < 0 {
            todo!("Error Handling")
        } else {
            let addr = unsafe { core::mem::transmute::<psp::sys::sockaddr, psp::sys::sockaddr_in>(addr) };
            let port = addr.sin_port;
            let octets = u32::to_le_bytes(addr.sin_addr.s_addr);
            let sockaddr = SocketAddrV4::new(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]), port);
            Ok(SocketAddr::V4(sockaddr))
        }
    }

    pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        let result = unsafe { psp::sys::sceNetInetShutdown(self.0.0, how as i32) };
        if result < 0 {
            todo!("Error Handling")
        } else {
            Ok(())
        }
    }

    pub fn duplicate(&self) -> io::Result<TcpStream> {
        Ok(self.clone())
    }

    pub fn set_linger(&self, _: Option<Duration>) -> io::Result<()> {
        unsupported()
    }

    pub fn linger(&self) -> io::Result<Option<Duration>> {
        unsupported()
    }

    pub fn set_nodelay(&self, _: bool) -> io::Result<()> {
        //TODO might be possible with sceNetInetSetsockopt
        unsupported()
    }

    pub fn nodelay(&self) -> io::Result<bool> {
        //TODO might be possible with sceNetInetGetsockopt
        unsupported()
    }

    pub fn set_ttl(&self, _: u32) -> io::Result<()> {
        //TODO might be possible with sceNetInetSetsockopt
        unsupported()
    }

    pub fn ttl(&self) -> io::Result<u32> {
        //TODO might be possible with sceNetInetGetsockopt
        unsupported()
    }

    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        //TODO is this the same as sceNetInetGetErrno?
        unsupported()
    }

    pub fn set_nonblocking(&self, _: bool) -> io::Result<()> {
        // sceNetInetSetsockopt SO_NONBLOCK ?
        unsupported()
    }
}

impl fmt::Debug for TcpStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unsupported")
    }
}

#[derive(Clone)]
pub struct TcpListener(Socket);

impl TcpListener {
    pub fn bind(addr: io::Result<&SocketAddr>) -> io::Result<TcpListener> {
        let sock = unsafe { psp::sys::sceNetInetSocket(AF_INET as i32, SOCK_STREAM, 0) };
        if sock < 0 {
            todo!()
        } else {
            let sockaddr = socketaddr_to_sockaddr(addr?)?;
            if unsafe { psp::sys::sceNetInetBind(sock, &sockaddr, sockaddr.sa_len as u32) } < 0  {
                todo!("Error Handling")
            } else {
                if unsafe { psp::sys::sceNetInetListen(sock, 128) } < 0 {
                    todo!("Error Handling")
                } else {
                    Ok(TcpListener(Socket(sock)))
                }
            }
        }
    }

    pub fn socket_addr(&self) -> io::Result<SocketAddr> {
        let mut addr: psp::sys::sockaddr = unsafe { core::mem::zeroed() };
        let mut addr_len: psp::sys::socklen_t = core::mem::size_of::<psp::sys::sockaddr_in>() as psp::sys::socklen_t;
        let ret = unsafe { psp::sys::sceNetInetGetsockname(self.0.0, &mut addr, &mut addr_len) };
        if ret < 0 {
            todo!("Error Handling")
        } else {
            let addr = unsafe { core::mem::transmute::<psp::sys::sockaddr, psp::sys::sockaddr_in>(addr) };
            let port = addr.sin_port;
            let octets = u32::to_le_bytes(addr.sin_addr.s_addr);
            let sockaddr = SocketAddrV4::new(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]), port);
            Ok(SocketAddr::V4(sockaddr))
        }
    }

    pub fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
        let mut addr: psp::sys::sockaddr = unsafe { core::mem::zeroed() };
        let mut addr_len: psp::sys::socklen_t = 0;
        let sock = unsafe { psp::sys::sceNetInetAccept(self.0.0, &mut addr, &mut addr_len) };
        if sock < 0 {
            todo!("Error Handling")
        } else {
            let addr = unsafe { core::mem::transmute::<psp::sys::sockaddr, psp::sys::sockaddr_in>(addr) };
            let port = addr.sin_port;
            let octets = u32::to_le_bytes(addr.sin_addr.s_addr);
            let sockaddr = SocketAddrV4::new(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]), port);
            let stream = TcpStream(Socket(sock));
            return Ok((stream, SocketAddr::V4(sockaddr)))
        }
    }

    pub fn duplicate(&self) -> io::Result<TcpListener> {
        Ok(self.clone())
    }

    pub fn set_ttl(&self, _: u32) -> io::Result<()> {
        //TODO might be possible with sceNetInetSetsockopt
        unsupported()
    }

    pub fn ttl(&self) -> io::Result<u32> {
        //TODO might be possible with sceNetInetGetsockopt
        unsupported()
    }

    pub fn set_only_v6(&self, _: bool) -> io::Result<()> {
        unsupported()
    }

    pub fn only_v6(&self) -> io::Result<bool> {
        unsupported()
    }

    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        //TODO is this the same as sceNetInetGetErrno?
        unsupported()
    }

    pub fn set_nonblocking(&self, _: bool) -> io::Result<()> {
        // sceNetInetSetsockopt SO_NONBLOCK ?
        unsupported()
    }
}

impl fmt::Debug for TcpListener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unsupported")
    }
}

#[derive(Clone)]
pub struct UdpSocket(Socket);

impl UdpSocket {
    pub fn bind(addr: io::Result<&SocketAddr>) -> io::Result<UdpSocket> {
        let sock = unsafe { psp::sys::sceNetInetSocket(AF_INET as i32, SOCK_DGRAM, 0) };
        if sock < 0 {
            todo!()
        } else {
            let sockaddr = socketaddr_to_sockaddr(addr?)?;
            if unsafe { psp::sys::sceNetInetBind(sock, &sockaddr, sockaddr.sa_len as u32) } < 0 {
                todo!("Error Handling")
            } else {
                Ok(UdpSocket(Socket(sock)))
            }
        }
    }

    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        unsupported()
    }

    pub fn socket_addr(&self) -> io::Result<SocketAddr> {
        unsupported()
    }

    pub fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut addr: psp::sys::sockaddr = unsafe { core::mem::zeroed() };
        let mut addr_len: psp::sys::socklen_t = core::mem::size_of::<psp::sys::sockaddr_in>() as psp::sys::socklen_t;
        let ret = unsafe { psp::sys::sceNetInetRecvfrom(self.0.0, buf.as_mut_ptr() as *mut _, buf.len(), 0, &mut addr, &mut addr_len) as i32 }; //TODO change to i32 upstream, returns -1 on error
        if ret < 0  {
            todo!("Error Handling")
        } else {
 let addr = unsafe { core::mem::transmute::<psp::sys::sockaddr, psp::sys::sockaddr_in>(addr) };
            let port = addr.sin_port;
            let octets = u32::to_le_bytes(addr.sin_addr.s_addr);
            let sockaddr = SocketAddrV4::new(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]), port);
            Ok((ret as usize, SocketAddr::V4(sockaddr)))
        }
    }

    pub fn peek_from(&self, _: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        unsupported()
    }

    pub fn send_to(&self, buf: &[u8], addr: &SocketAddr) -> io::Result<usize> {
        let sockaddr = socketaddr_to_sockaddr(addr)?;
        let ret = unsafe { psp::sys::sceNetInetSendto(self.0.0, buf.as_ptr() as *const _, buf.len(), 0, &sockaddr, sockaddr.sa_len as psp::sys::socklen_t) as i32 }; //TODO change to i32 upstream, returns -1 on error
        if ret < 0  {
            todo!("Error Handling")
        } else {
            return Ok(ret as usize);
        }
    }

    pub fn duplicate(&self) -> io::Result<UdpSocket> {
        Ok(self.clone())
    }

    pub fn set_read_timeout(&self, _: Option<Duration>) -> io::Result<()> {
        unsupported()
    }

    pub fn set_write_timeout(&self, _: Option<Duration>) -> io::Result<()> {
        unsupported()
    }

    pub fn read_timeout(&self) -> io::Result<Option<Duration>> {
        unsupported()
    }

    pub fn write_timeout(&self) -> io::Result<Option<Duration>> {
        unsupported()
    }

    pub fn set_broadcast(&self, _: bool) -> io::Result<()> {
        unsupported()
    }

    pub fn broadcast(&self) -> io::Result<bool> {
        unsupported()
    }

    pub fn set_multicast_loop_v4(&self, _: bool) -> io::Result<()> {
        unsupported()
    }

    pub fn multicast_loop_v4(&self) -> io::Result<bool> {
        unsupported()
    }

    pub fn set_multicast_ttl_v4(&self, _: u32) -> io::Result<()> {
        unsupported()
    }

    pub fn multicast_ttl_v4(&self) -> io::Result<u32> {
        unsupported()
    }

    pub fn set_multicast_loop_v6(&self, _: bool) -> io::Result<()> {
        unsupported()
    }

    pub fn multicast_loop_v6(&self) -> io::Result<bool> {
        unsupported()
    }

    pub fn join_multicast_v4(&self, _: &Ipv4Addr, _: &Ipv4Addr) -> io::Result<()> {
        unsupported()
    }

    pub fn join_multicast_v6(&self, _: &Ipv6Addr, _: u32) -> io::Result<()> {
        unsupported()
    }

    pub fn leave_multicast_v4(&self, _: &Ipv4Addr, _: &Ipv4Addr) -> io::Result<()> {
        unsupported()
    }

    pub fn leave_multicast_v6(&self, _: &Ipv6Addr, _: u32) -> io::Result<()> {
        unsupported()
    }

    pub fn set_ttl(&self, _: u32) -> io::Result<()> {
        unsupported()
    }

    pub fn ttl(&self) -> io::Result<u32> {
        unsupported()
    }

    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        unsupported()
    }

    pub fn set_nonblocking(&self, _: bool) -> io::Result<()> {
        unsupported()
    }

    pub fn recv(&self, _: &mut [u8]) -> io::Result<usize> {
        unsupported()
    }

    pub fn peek(&self, _: &mut [u8]) -> io::Result<usize> {
        unsupported()
    }

    pub fn send(&self, _: &[u8]) -> io::Result<usize> {
        unsupported()
    }

    pub fn connect(&self, _: io::Result<&SocketAddr>) -> io::Result<()> {
        unsupported()
    }
}

impl fmt::Debug for UdpSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unsupported")
    }
}

pub struct LookupHost {
    hostname: CString,
    port: u16,
    resolver_id: i32,
    resolver_buf: [u8; 1024],
    timeout: u32,
    retries: i32,
    // TODO is this necessary? Just don't want to get caught in an infinite loop
    // returning the same address with no errors returned from sceNetResolverStartNtoA
    prev_result: u32,
}

impl LookupHost {
    pub fn port(&self) -> u16 {
        self.port
    }
}

impl Iterator for LookupHost {
    type Item = SocketAddr;
    fn next(&mut self) -> Option<SocketAddr> {
        let mut in_addr: psp::sys::in_addr = unsafe { core::mem::zeroed() };
        let result =  unsafe { psp::sys::sceNetResolverStartNtoA(self.resolver_id, self.hostname.as_ptr() as *const u8, &mut in_addr, self.timeout, self.retries) };
        if result < 0 || in_addr.s_addr == self.prev_result {
            None
        } else {
            self.prev_result = in_addr.s_addr;
            let octets = u32::to_le_bytes(in_addr.s_addr);
            Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]), self.port)))
        }
    }
}

//TODO less unwrapping
impl TryFrom<&str> for LookupHost {
    type Error = io::Error;

    fn try_from(v: &str) -> io::Result<LookupHost> {
        let mut split = v.split(":");
        let host = split.next().unwrap();
        let mut port: u16 = 80;
        let next = split.next();
        if next.is_some() {
            port = next.unwrap().parse::<u16>().unwrap();
        }
        let cstring = crate::ffi::CString::new(host).unwrap();

        let mut rid: i32 = 0;
        let mut dns_buf: [u8; 1024] = [0u8; 1024];
        if unsafe { psp::sys::sceNetResolverCreate(&mut rid, &mut dns_buf[0] as *mut _ as *mut _, dns_buf.len() as u32) } < 0 {
            todo!("Error Handling");
        } else {
            Ok(LookupHost {
                hostname: cstring,
                port,
                resolver_id: rid,
                resolver_buf: dns_buf,
                retries: 5,
                timeout: 5,
                prev_result: 0,
            })
        }
    }
}

impl TryFrom<(&str, u16)> for LookupHost {
    type Error = io::Error;

    fn try_from(v: (&str, u16)) -> io::Result<LookupHost> {
        let cstring = crate::ffi::CString::new(v.0).unwrap();
        let mut rid: i32 = 0;
        let mut dns_buf: [u8; 1024] = [0u8; 1024];
        if unsafe { psp::sys::sceNetResolverCreate(&mut rid, &mut dns_buf[0] as *mut _ as *mut _, dns_buf.len() as u32) } < 0 {
            todo!("Error Handling");
        } else {
            Ok(LookupHost {
                hostname: cstring,
                port: v.1,
                resolver_id: rid,
                resolver_buf: dns_buf,
                retries: 5,
                timeout: 5,
                prev_result: 0,
            })
        }
    }
}

impl Drop for LookupHost {
    fn drop(&mut self) {
        unsafe { psp::sys::sceNetResolverDelete(self.resolver_id) };
    }
}

pub mod netc {
    pub const AF_INET: u8 = 2;
    pub const AF_INET6: u8 = 24;

    pub use psp::sys::in_addr;
    pub use psp::sys::sockaddr_in;
    pub type sa_family_t = u8;

    // Dummy types to satisfy the rest of std, the PSP doesn't support IPv6
    #[derive(Copy, Clone)]
    pub struct in6_addr {
        pub s6_addr: [u8; 16],
    }

    #[derive(Copy, Clone)]
    pub struct sockaddr_in6 {
        pub sin6_family: sa_family_t,
        pub sin6_port: u16,
        pub sin6_addr: in6_addr,
        pub sin6_flowinfo: u32,
        pub sin6_scope_id: u32,
    }

}
