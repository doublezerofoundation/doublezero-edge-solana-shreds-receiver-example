//! DoubleZero edge-solana shred receiver.
//!
//! Joins the DoubleZero multicast feed and delivers raw shred bytes to a callback.
//! Edit `main()` to plug in your strategy, then `cargo run --release`.
//!
//! Verify the socket is bound:
//! ```
//! sudo ss -ulnp | grep 7733
//! # expect: UNCONN ... 233.84.178.1:7733 ... users:(("doublezero-recei", ...))
//! ```
//!
//! # Socket notes
//!
//! - IF you set `SO_REUSEADDR`: multiple processes can bind the same address:port
//!   simultaneously — the kernel delivers every packet to all of them.
//!
//! - IF you set `SO_REUSEPORT`: all DoubleZero shreds arrive from the same source
//!   IP:port, so the kernel hashes everything to one socket and any other receives
//!   nothing, silently.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::time::{Duration, Instant};

const MULTICAST_GROUP: Ipv4Addr = Ipv4Addr::new(233, 84, 178, 1);
const PORT: u16 = 7733;
const INTERFACE: &str = "doublezero1";

// ─── Boilerplate ─────────────────────────────────────────────────────────────

/// Deduplicates at the packet level. If your application deduplicates downstream,
/// Delete this entire section until the next comment.
fn run<F: FnMut(&[u8])>(mut on_shred: F) {
    let socket = bind().expect("failed to bind multicast socket");

    let mut seen: HashMap<[u8; 20], Instant> = HashMap::new();
    let mut last_evict = Instant::now();

    let mut buf = vec![0u8; 1500];
    loop {
        let n = match socket.recv(&mut buf) {
            Ok(n) if n > 0 => n,
            _ => continue,
        };

        if last_evict.elapsed() > Duration::from_secs(10) {
            seen.retain(|_, t| t.elapsed() < Duration::from_secs(30)); // max shred age
            last_evict = Instant::now();
        }

        if n < 20 { continue; }
        let key: [u8; 20] = buf[..20].try_into().unwrap();
        if seen.insert(key, Instant::now()).is_some() { continue; }

        on_shred(&buf[..n]);
    }
}

/// Bind to the DoubleZero multicast group on the `doublezero1` interface.
fn bind() -> std::io::Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};

    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.bind(&SocketAddrV4::new(MULTICAST_GROUP, PORT).into())?;
    socket.join_multicast_v4(&MULTICAST_GROUP, &interface_ipv4(INTERFACE)?)?;
    socket.set_recv_buffer_size(8 * 1024 * 1024).ok(); // increase for high-throughput feeds
    Ok(socket.into())
}

/// Resolve a network interface name to its IPv4 address.
fn interface_ipv4(name: &str) -> std::io::Result<Ipv4Addr> {
    unsafe {
        let mut addrs: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut addrs) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut cur = addrs;
        while !cur.is_null() {
            let ifa = &*cur;
            if !ifa.ifa_name.is_null() && !ifa.ifa_addr.is_null() {
                let ifa_name = std::ffi::CStr::from_ptr(ifa.ifa_name).to_str().unwrap_or("");
                if ifa_name == name && (*ifa.ifa_addr).sa_family == libc::AF_INET as libc::sa_family_t {
                    let sin = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                    let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                    libc::freeifaddrs(addrs);
                    return Ok(ip);
                }
            }
            cur = ifa.ifa_next;
        }
        libc::freeifaddrs(addrs);
    }
    Err(std::io::Error::new(std::io::ErrorKind::NotFound, format!("interface '{}' not found", name)))
}

// ─── Your strategy goes here ─────────────────────────────────────────────────

fn main() {
    let mut count: u64 = 0;
    let start = Instant::now();
    let mut last_print = Instant::now();

    run(|_shred| {
        count += 1;
        if last_print.elapsed() >= Duration::from_secs(5) {
            let secs = start.elapsed().as_secs_f64();
            println!("{:.0}s — {} shreds ({:.0}/s)", secs, count, count as f64 / secs);
            last_print = Instant::now();
        }
    });
}
