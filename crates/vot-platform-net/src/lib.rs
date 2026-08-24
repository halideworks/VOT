//! Small, isolated platform socket operations that require native FFI.

#![deny(unsafe_code)]

use std::io;
use std::net::UdpSocket;

/// Sets the don't-fragment flag for PMTU discovery. Required for sound path
/// probing above UDP.
///
/// # Errors
/// Returns the OS error when the option cannot be set.
pub fn refuse_fragmentation(socket: &UdpSocket) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        refuse_fragmentation_linux(socket)
    }
    #[cfg(target_os = "macos")]
    {
        refuse_fragmentation_macos(socket)
    }
    #[cfg(windows)]
    {
        refuse_fragmentation_windows(socket)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = socket;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn refuse_fragmentation_linux(socket: &UdpSocket) -> io::Result<()> {
    use std::os::fd::AsRawFd as _;

    fn set(fd: i32, level: i32, option: i32, value: libc::c_int) -> io::Result<()> {
        let length = libc::socklen_t::try_from(size_of::<libc::c_int>())
            .expect("an int's length fits its own kind");
        // SAFETY: the descriptor is owned by the borrowed socket for the whole
        // call, and the pointer and length describe the one int this option
        // takes.
        let result =
            unsafe { libc::setsockopt(fd, level, option, (&raw const value).cast(), length) };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    let fd = socket.as_raw_fd();
    if socket.local_addr()?.is_ipv4() {
        set(
            fd,
            libc::IPPROTO_IP,
            libc::IP_MTU_DISCOVER,
            libc::IP_PMTUDISC_PROBE,
        )
    } else {
        set(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_MTU_DISCOVER,
            libc::IPV6_PMTUDISC_PROBE,
        )?;
        set(
            fd,
            libc::IPPROTO_IP,
            libc::IP_MTU_DISCOVER,
            libc::IP_PMTUDISC_PROBE,
        )
    }
}

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
fn refuse_fragmentation_macos(socket: &UdpSocket) -> io::Result<()> {
    use std::os::fd::AsRawFd as _;

    fn set(fd: i32, level: i32, option: i32) -> io::Result<()> {
        let value: libc::c_int = 1;
        let length = libc::socklen_t::try_from(size_of::<libc::c_int>())
            .expect("an int's length fits its own kind");
        // SAFETY: the descriptor is owned by the borrowed socket for the whole
        // call, and the pointer and length describe the one int this option
        // takes.
        let result =
            unsafe { libc::setsockopt(fd, level, option, (&raw const value).cast(), length) };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    let fd = socket.as_raw_fd();
    if socket.local_addr()?.is_ipv4() {
        set(fd, libc::IPPROTO_IP, libc::IP_DONTFRAG)
    } else {
        set(fd, libc::IPPROTO_IPV6, libc::IPV6_DONTFRAG)
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn refuse_fragmentation_windows(socket: &UdpSocket) -> io::Result<()> {
    use std::os::windows::io::AsRawSocket as _;
    use windows_sys::Win32::Networking::WinSock;

    fn set(handle: usize, level: i32, option: i32) -> io::Result<()> {
        let value: u32 = 1;
        let length = i32::try_from(size_of::<u32>()).expect("an int's length fits its own kind");
        // SAFETY: the handle is owned by the borrowed socket for the whole
        // call, and the pointer and length describe the one DWORD this option
        // takes.
        let result = unsafe {
            WinSock::setsockopt(handle, level, option, (&raw const value).cast(), length)
        };
        if result == 0 {
            Ok(())
        } else {
            // SAFETY: reading the calling thread's last WinSock error takes no
            // arguments and touches no memory of ours.
            Err(io::Error::from_raw_os_error(unsafe {
                WinSock::WSAGetLastError()
            }))
        }
    }

    let handle = usize::try_from(socket.as_raw_socket()).expect("a socket handle is one word");
    if socket.local_addr()?.is_ipv4() {
        set(handle, WinSock::IPPROTO_IP, WinSock::IP_DONTFRAGMENT)
    } else {
        set(handle, WinSock::IPPROTO_IPV6, WinSock::IPV6_DONTFRAG)
    }
}

/// Socket buffer sizes the kernel granted, in the same terms as the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Granted {
    /// Receive buffer bytes the kernel granted.
    pub receive_bytes: u32,
    /// Send buffer bytes the kernel granted.
    pub send_bytes: u32,
}

/// Reports the granted size when it falls short of the request, `None` when
/// the kernel met or exceeded it.
#[must_use]
pub fn buffer_shortfall(requested: u32, granted: u32) -> Option<u32> {
    (granted < requested).then_some(granted)
}

/// Requests socket buffer sizes of at least `send` and `receive` bytes and
/// reports what the kernel granted, which its own caps may hold below the
/// request or refuse outright.
///
/// # Errors
/// Returns the OS error when a granted size cannot be read back. A refused
/// request is not an error: the size the socket kept is what it reports.
pub fn size_buffers(
    socket: &UdpSocket,
    receive_bytes: u32,
    send_bytes: u32,
) -> io::Result<Granted> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        size_buffers_unix(socket, receive_bytes, send_bytes)
    }
    #[cfg(windows)]
    {
        size_buffers_windows(socket, receive_bytes, send_bytes)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = (socket, receive_bytes, send_bytes);
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[allow(unsafe_code)]
fn size_buffers_unix(
    socket: &UdpSocket,
    receive_bytes: u32,
    send_bytes: u32,
) -> io::Result<Granted> {
    use std::os::fd::AsRawFd as _;

    fn set(fd: i32, option: i32, bytes: u32) -> io::Result<()> {
        let value = libc::c_int::try_from(bytes)
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        let length = libc::socklen_t::try_from(size_of::<libc::c_int>())
            .expect("an int's length fits its own kind");
        // SAFETY: the descriptor is owned by the borrowed socket for the whole
        // call, and the pointer and length describe the one int this option
        // takes.
        let result = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                option,
                (&raw const value).cast(),
                length,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn get(fd: i32, option: i32) -> io::Result<u32> {
        let mut value: libc::c_int = 0;
        let mut length = libc::socklen_t::try_from(size_of::<libc::c_int>())
            .expect("an int's length fits its own kind");
        // SAFETY: the descriptor is owned by the borrowed socket for the whole
        // call, and the pointers describe the one int this option yields and
        // its length.
        let result = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                option,
                (&raw mut value).cast(),
                &raw mut length,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        u32::try_from(value).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))
    }

    // Every set is best effort: a kernel that clamps keeps its own size, and
    // macOS refuses a request past kern.ipc.maxsockbuf outright rather than
    // clamping it. The forced variants, which CAP_NET_ADMIN allows past
    // Linux's rmem_max and wmem_max, are refused without that privilege. The
    // read-back below is what says which of those happened.
    let fd = socket.as_raw_fd();
    let _ = set(fd, libc::SO_RCVBUF, receive_bytes);
    let _ = set(fd, libc::SO_SNDBUF, send_bytes);
    #[cfg(target_os = "linux")]
    {
        let _ = set(fd, libc::SO_RCVBUFFORCE, receive_bytes);
        let _ = set(fd, libc::SO_SNDBUFFORCE, send_bytes);
    }
    let receive = get(fd, libc::SO_RCVBUF)?;
    let send = get(fd, libc::SO_SNDBUF)?;
    // Linux reports twice what it granted, the second half being its own
    // bookkeeping allowance, so halve it to compare against the request.
    #[cfg(target_os = "linux")]
    let (receive, send) = (receive / 2, send / 2);
    Ok(Granted {
        receive_bytes: receive,
        send_bytes: send,
    })
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn size_buffers_windows(
    socket: &UdpSocket,
    receive_bytes: u32,
    send_bytes: u32,
) -> io::Result<Granted> {
    use std::os::windows::io::AsRawSocket as _;
    use windows_sys::Win32::Networking::WinSock;

    fn last_error() -> io::Error {
        // SAFETY: reading the calling thread's last WinSock error takes no
        // arguments and touches no memory of ours.
        io::Error::from_raw_os_error(unsafe { WinSock::WSAGetLastError() })
    }

    fn set(handle: usize, option: i32, bytes: u32) -> io::Result<()> {
        let value =
            i32::try_from(bytes).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        let length = i32::try_from(size_of::<i32>()).expect("an int's length fits its own kind");
        // SAFETY: the handle is owned by the borrowed socket for the whole
        // call, and the pointer and length describe the one int this option
        // takes.
        let result = unsafe {
            WinSock::setsockopt(
                handle,
                WinSock::SOL_SOCKET,
                option,
                (&raw const value).cast(),
                length,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(last_error())
        }
    }

    fn get(handle: usize, option: i32) -> io::Result<u32> {
        let mut value: i32 = 0;
        let mut length =
            i32::try_from(size_of::<i32>()).expect("an int's length fits its own kind");
        // SAFETY: the handle is owned by the borrowed socket for the whole
        // call, and the pointers describe the one int this option yields and
        // its length.
        let result = unsafe {
            WinSock::getsockopt(
                handle,
                WinSock::SOL_SOCKET,
                option,
                (&raw mut value).cast(),
                &raw mut length,
            )
        };
        if result != 0 {
            return Err(last_error());
        }
        u32::try_from(value).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))
    }

    // Best effort, as on unix: the read-back reports what the socket kept.
    let handle = usize::try_from(socket.as_raw_socket()).expect("a socket handle is one word");
    let _ = set(handle, WinSock::SO_RCVBUF, receive_bytes);
    let _ = set(handle, WinSock::SO_SNDBUF, send_bytes);
    Ok(Granted {
        receive_bytes: get(handle, WinSock::SO_RCVBUF)?,
        send_bytes: get(handle, WinSock::SO_SNDBUF)?,
    })
}

#[cfg(test)]
mod tests {
    use super::refuse_fragmentation;
    use std::net::UdpSocket;

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[allow(unsafe_code)]
    fn read_option(socket: &UdpSocket, level: i32, option: i32) -> libc::c_int {
        use std::os::fd::AsRawFd as _;
        let mut value: libc::c_int = -1;
        let mut length = libc::socklen_t::try_from(size_of::<libc::c_int>())
            .expect("an int's length fits its own kind");
        // SAFETY: the descriptor is owned by the borrowed socket for the whole
        // call, and the pointers describe the one int this option yields and
        // its length.
        let result = unsafe {
            libc::getsockopt(
                socket.as_raw_fd(),
                level,
                option,
                (&raw mut value).cast(),
                &raw mut length,
            )
        };
        assert_eq!(result, 0, "{}", std::io::Error::last_os_error());
        value
    }

    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    #[test]
    fn sized_buffers_grow_toward_what_was_asked() {
        // Kernels clamp silently; assert strict growth or adequacy.
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        let read = |socket: &UdpSocket, option: i32| read_option(socket, libc::SOL_SOCKET, option);
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        let (receive_option, send_option) = (libc::SO_RCVBUF, libc::SO_SNDBUF);
        #[cfg(windows)]
        let read = |socket: &UdpSocket, option: i32| {
            use windows_sys::Win32::Networking::WinSock;
            read_option(socket, WinSock::SOL_SOCKET, option)
        };
        #[cfg(windows)]
        let (receive_option, send_option) = {
            use windows_sys::Win32::Networking::WinSock;
            (WinSock::SO_RCVBUF, WinSock::SO_SNDBUF)
        };
        let (receive_request, send_request) = (4u32 * 1024 * 1024, 2u32 * 1024 * 1024);
        let socket = UdpSocket::bind("127.0.0.1:0").expect("a socket");
        let receive_before = read(&socket, receive_option);
        let send_before = read(&socket, send_option);
        let granted =
            super::size_buffers(&socket, receive_request, send_request).expect("the sizes");
        let receive = read(&socket, receive_option);
        let send = read(&socket, send_option);
        assert!(
            (receive > receive_before || i64::from(receive) >= i64::from(receive_request))
                && receive >= 200 * 1024,
            "receive buffer {receive} from {receive_before}"
        );
        assert!(
            (send > send_before || i64::from(send) >= i64::from(send_request))
                && send >= 200 * 1024,
            "send buffer {send} from {send_before}"
        );
        // Linux reports twice what it granted; the report is in request terms.
        #[cfg(target_os = "linux")]
        let halve = 2;
        #[cfg(not(target_os = "linux"))]
        let halve = 1;
        assert_eq!(
            granted.receive_bytes,
            u32::try_from(receive).expect("a size") / halve
        );
        assert_eq!(
            granted.send_bytes,
            u32::try_from(send).expect("a size") / halve
        );
    }

    #[test]
    fn a_shortfall_is_only_reported_below_the_request() {
        for (requested, granted, expected) in [
            (1024u32, 1024u32, None),
            (1024, 2048, None),
            (1024, 512, Some(512)),
            (1024, 0, Some(0)),
            (0, 0, None),
        ] {
            assert_eq!(
                super::buffer_shortfall(requested, granted),
                expected,
                "requested {requested}, granted {granted}"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn an_ipv4_socket_probes_and_never_fragments() {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("a socket");
        refuse_fragmentation(&socket).expect("the option");
        assert_eq!(
            read_option(&socket, libc::IPPROTO_IP, libc::IP_MTU_DISCOVER),
            libc::IP_PMTUDISC_PROBE
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn an_ipv6_socket_probes_on_both_stacks() {
        let socket = UdpSocket::bind("[::1]:0").expect("a socket");
        refuse_fragmentation(&socket).expect("the option");
        assert_eq!(
            read_option(&socket, libc::IPPROTO_IPV6, libc::IPV6_MTU_DISCOVER),
            libc::IPV6_PMTUDISC_PROBE
        );
        assert_eq!(
            read_option(&socket, libc::IPPROTO_IP, libc::IP_MTU_DISCOVER),
            libc::IP_PMTUDISC_PROBE
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn an_ipv4_socket_sets_dont_fragment() {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("a socket");
        refuse_fragmentation(&socket).expect("the option");
        assert_eq!(read_option(&socket, libc::IPPROTO_IP, libc::IP_DONTFRAG), 1);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn an_ipv6_socket_sets_dont_fragment() {
        let socket = UdpSocket::bind("[::1]:0").expect("a socket");
        refuse_fragmentation(&socket).expect("the option");
        assert_eq!(
            read_option(&socket, libc::IPPROTO_IPV6, libc::IPV6_DONTFRAG),
            1
        );
    }

    #[cfg(windows)]
    #[allow(unsafe_code)]
    fn read_option(socket: &UdpSocket, level: i32, option: i32) -> u32 {
        use std::os::windows::io::AsRawSocket as _;
        use windows_sys::Win32::Networking::WinSock;
        let mut value: u32 = u32::MAX;
        let mut length =
            i32::try_from(size_of::<u32>()).expect("an int's length fits its own kind");
        let handle = usize::try_from(socket.as_raw_socket()).expect("a socket handle is one word");
        // SAFETY: the handle is owned by the borrowed socket for the whole
        // call, and the pointers describe the one DWORD this option yields and
        // its length.
        let result = unsafe {
            WinSock::getsockopt(
                handle,
                level,
                option,
                (&raw mut value).cast(),
                &raw mut length,
            )
        };
        assert_eq!(result, 0);
        value
    }

    #[cfg(windows)]
    #[test]
    fn an_ipv4_socket_sets_dont_fragment() {
        use windows_sys::Win32::Networking::WinSock;
        let socket = UdpSocket::bind("127.0.0.1:0").expect("a socket");
        refuse_fragmentation(&socket).expect("the option");
        assert_eq!(
            read_option(&socket, WinSock::IPPROTO_IP, WinSock::IP_DONTFRAGMENT),
            1
        );
    }

    #[cfg(windows)]
    #[test]
    fn an_ipv6_socket_sets_dont_fragment() {
        use windows_sys::Win32::Networking::WinSock;
        let socket = UdpSocket::bind("[::1]:0").expect("a socket");
        refuse_fragmentation(&socket).expect("the option");
        assert_eq!(
            read_option(&socket, WinSock::IPPROTO_IPV6, WinSock::IPV6_DONTFRAG),
            1
        );
    }
}
