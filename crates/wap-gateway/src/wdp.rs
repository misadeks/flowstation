//! WDP (Wireless Datagram Protocol) — thin async wrapper around a UDP socket.
//!
//! For our purposes WDP is just "UDP with a peer address". This module owns the
//! `tokio::net::UdpSocket` and exposes `recv` / `send` helpers that upper
//! layers (WTP) treat as opaque datagram I/O.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::UdpSocket;

/// Maximum datagram size we will read from the socket in a single `recv_from`
/// call. WAP UDP MTU is 1500 by convention; we allow a little extra headroom.
pub const MAX_DATAGRAM_SIZE: usize = 2048;

/// A shareable UDP endpoint used as the WDP layer.
#[derive(Debug, Clone)]
pub struct Wdp {
    socket: Arc<UdpSocket>,
    local_addr: SocketAddr,
}

impl Wdp {
    /// Bind a UDP socket to `addr`.
    pub async fn bind(addr: SocketAddr) -> io::Result<Self> {
        let socket = UdpSocket::bind(addr).await?;
        let local_addr = socket.local_addr()?;
        Ok(Self {
            socket: Arc::new(socket),
            local_addr,
        })
    }

    /// Local address the socket is bound to (useful after binding to port 0
    /// in tests).
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Await the next datagram. Returns `(peer, bytes)`.
    pub async fn recv(&self) -> io::Result<(SocketAddr, Vec<u8>)> {
        let mut buf = vec![0u8; MAX_DATAGRAM_SIZE];
        let (n, peer) = self.socket.recv_from(&mut buf).await?;
        buf.truncate(n);
        Ok((peer, buf))
    }

    /// Send a datagram to `peer`. Returns the number of bytes sent.
    pub async fn send(&self, peer: SocketAddr, bytes: &[u8]) -> io::Result<usize> {
        self.socket.send_to(bytes, peer).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn wdp_roundtrip_localhost() {
        let server = Wdp::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).await.unwrap();
        let client = Wdp::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).await.unwrap();

        let payload = b"\x01\x02\x03hello".to_vec();
        client.send(server.local_addr(), &payload).await.unwrap();

        let (peer, got) = tokio::time::timeout(std::time::Duration::from_secs(2), server.recv())
            .await
            .expect("recv timed out")
            .unwrap();

        assert_eq!(peer, client.local_addr());
        assert_eq!(got, payload);
    }
}
