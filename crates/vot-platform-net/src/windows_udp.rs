//! Per-message UDP segmentation, without changing a shared socket's options.

#![allow(unsafe_code)]

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::os::windows::io::AsRawSocket as _;
use windows_sys::Win32::Networking::WinSock as w;

#[repr(C)]
struct Segmentation {
    header: w::CMSGHDR,
    size: u32,
    padding: [u8; size_of::<usize>() - size_of::<u32>()],
}

/// Sends a UDP burst as equal-sized datagrams, with an optional short last one.
/// The segment size applies only to this send, including on a shared socket.
///
/// # Errors
/// Rejects empty/oversized bursts and invalid segment sizes. Reports Winsock
/// refusal, including systems without segmentation support; callers may fall back.
pub fn send_segmented(
    socket: &UdpSocket,
    burst: &[u8],
    segment: usize,
    destination: SocketAddr,
) -> io::Result<()> {
    if burst.is_empty() || burst.len() > 65_507 || segment == 0 || segment > burst.len() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut control = Segmentation {
        header: w::CMSGHDR {
            cmsg_len: size_of::<w::CMSGHDR>() + size_of::<u32>(),
            cmsg_level: w::IPPROTO_UDP,
            cmsg_type: w::UDP_SEND_MSG_SIZE,
        },
        size: u32::try_from(segment).map_err(io::Error::other)?,
        padding: [0; size_of::<usize>() - size_of::<u32>()],
    };
    let mut address = w::SOCKADDR_INET::default();
    let address_len = match destination {
        SocketAddr::V4(to) => {
            address.Ipv4 = w::SOCKADDR_IN {
                sin_family: w::AF_INET,
                sin_port: to.port().to_be(),
                sin_addr: w::IN_ADDR {
                    S_un: w::IN_ADDR_0 {
                        S_addr: u32::from_ne_bytes(to.ip().octets()),
                    },
                },
                sin_zero: [0; 8],
            };
            size_of::<w::SOCKADDR_IN>()
        }
        SocketAddr::V6(to) => {
            address.Ipv6 = w::SOCKADDR_IN6 {
                sin6_family: w::AF_INET6,
                sin6_port: to.port().to_be(),
                sin6_flowinfo: to.flowinfo().to_be(),
                sin6_addr: w::IN6_ADDR {
                    u: w::IN6_ADDR_0 {
                        Byte: to.ip().octets(),
                    },
                },
                Anonymous: w::SOCKADDR_IN6_0 {
                    sin6_scope_id: to.scope_id(),
                },
            };
            size_of::<w::SOCKADDR_IN6>()
        }
    };
    let mut payload = w::WSABUF {
        len: u32::try_from(burst.len()).map_err(io::Error::other)?,
        buf: burst.as_ptr().cast_mut(),
    };
    let message = w::WSAMSG {
        name: (&raw mut address).cast(),
        namelen: i32::try_from(address_len).map_err(io::Error::other)?,
        lpBuffers: &raw mut payload,
        dwBufferCount: 1,
        Control: w::WSABUF {
            len: u32::try_from(size_of::<Segmentation>()).map_err(io::Error::other)?,
            buf: (&raw mut control).cast(),
        },
        dwFlags: 0,
    };
    let mut sent = 0;
    // SAFETY: synchronous send borrows the socket and initialized, aligned
    // address/control buffers; Winsock only reads the immutable payload.
    let result = unsafe {
        w::WSASendMsg(
            usize::try_from(socket.as_raw_socket()).map_err(io::Error::other)?,
            &raw const message,
            0,
            &raw mut sent,
            std::ptr::null_mut(),
            None,
        )
    };
    if result != 0 {
        // SAFETY: this reads only the calling thread's Winsock error.
        return Err(io::Error::from_raw_os_error(unsafe {
            w::WSAGetLastError()
        }));
    }
    if sent != payload.len {
        return Err(io::ErrorKind::WriteZero.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn segmentation_preserves_boundaries_and_does_not_change_the_socket() {
        for bind in ["127.0.0.1:0", "[::1]:0"] {
            let sender = UdpSocket::bind(bind).unwrap();
            std::thread::scope(|scope| {
                for segment in [1200, 1350, 1472] {
                    let sender = &sender;
                    scope.spawn(move || {
                        let receiver = UdpSocket::bind(bind).unwrap();
                        receiver
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        let to = receiver.local_addr().unwrap();
                        let data: Vec<u8> = (0..segment * 3 + 17)
                            .map(|i| u8::try_from(i % 251).unwrap())
                            .collect();
                        send_segmented(sender, &data, segment, to).unwrap();
                        let mut packet = [0; 8192];
                        for expected in data.chunks(segment) {
                            let (n, from) = receiver.recv_from(&mut packet).unwrap();
                            assert_eq!(from, sender.local_addr().unwrap());
                            assert_eq!(&packet[..n], expected);
                        }
                        sender.send_to(&data, to).unwrap();
                        let (n, _) = receiver.recv_from(&mut packet).unwrap();
                        assert_eq!(&packet[..n], data);
                    });
                }
            });
            let to = sender.local_addr().unwrap();
            for (data, segment) in [(&[][..], 1), (&[1][..], 0), (&[1][..], 2)] {
                assert_eq!(
                    send_segmented(&sender, data, segment, to)
                        .unwrap_err()
                        .kind(),
                    io::ErrorKind::InvalidInput
                );
            }
            assert_eq!(
                send_segmented(&sender, &vec![0; 65_508], 1200, to)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }
}
