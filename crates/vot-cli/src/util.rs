//! Argument grammar and the small filesystem helpers.

use crate::{Error, File, OpenOptions, Path, PathBuf, Read, Write, fs, hex, io};

/// A package root as the hex a `send` printed.
///
/// # Errors
/// Rejects anything that is not exactly 32 bytes of hexadecimal.
pub fn parse_package_root(value: &str) -> Result<[u8; 32], Error> {
    if value.len() != 64 {
        return Err(Error::InvalidArguments);
    }
    let mut root = [0_u8; 32];
    for (slot, pair) in root.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        let high = hex(pair[0]).ok_or(Error::InvalidArguments)?;
        let low = hex(pair[1]).ok_or(Error::InvalidArguments)?;
        *slot = high * 16 + low;
    }
    Ok(root)
}

/// Lowercase hexadecimal, which is how every key and root is written here.
///
/// One writer, because a root the binary prints and a key this mints have to
/// read the same to a caller pasting one into the other.
#[must_use]
pub fn hex_of(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut text, byte| {
        let _ = write!(text, "{byte:02x}");
        text
    })
}

/// Set to fetch from an address without naming the package to accept.
pub const UNPINNED: &str = "VOT_FETCH_UNPINNED";

/// The package root a fetch at an address will accept.
///
/// Required. An address says where to fetch from, not what to fetch, and the
/// channel is not authenticated, so the root is the only thing that decides
/// which package this is. A root-addressed fetch does not come through here:
/// it already named one to resolve.
///
/// [`UNPINNED`] is the way out, for a server whose package the caller cannot
/// know in advance.
///
/// Here rather than in the binary because the binary is excluded from
/// mutation testing, and this is a decision rather than a dispatch.
///
/// # Errors
/// Reports [`Error::UnpinnedFetch`] for no root without the override, and
/// [`Error::InvalidArguments`] for a root that is not one.
pub fn address_pin(root: Option<&str>) -> Result<Option<[u8; 32]>, Error> {
    pin_for_address(
        root,
        unpinned_allowed(std::env::var_os(UNPINNED).as_deref()),
    )
}

/// Whether [`UNPINNED`] says to fetch without a root.
///
/// Set and empty is not permission. A variable that carries nothing is what
/// an unset one expands to in a shell, so reading it as yes would turn
/// `VOT_FETCH_UNPINNED=$MAYBE` into a silent waiver.
pub(crate) fn unpinned_allowed(value: Option<&std::ffi::OsStr>) -> bool {
    value.is_some_and(|value| !value.is_empty())
}

/// [`address_pin`] with the override as an argument, so a test can hold both
/// answers without setting a variable every parallel test would see.
pub(crate) fn pin_for_address(
    root: Option<&str>,
    unpinned_allowed: bool,
) -> Result<Option<[u8; 32]>, Error> {
    match root {
        Some(root) => parse_package_root(root).map(Some),
        None if unpinned_allowed => Ok(None),
        None => Err(Error::UnpinnedFetch),
    }
}

/// Every address a rendezvous service answers at, given `ADDR:PORT` or
/// `NAME:PORT`, or a comma-separated list of either, IPv6 first.
///
/// IPv6 leads because a global IPv6 address has no translation in front of
/// it: nothing to punch, and no mapping to keep alive. A serve registers
/// at all of them and a fetch tries them in this order.
///
/// The list is for a service whose families are not behind one name, which
/// is every service two people point at each other without running DNS.
///
/// # Errors
/// Rejects a value with any part that is neither an address nor a name
/// that resolves.
pub fn parse_rendezvous(value: &str) -> Result<Vec<std::net::SocketAddr>, Error> {
    // `to_socket_addrs` parses a literal itself and only reaches the resolver
    // for what is not one, so a literal costs no lookup.
    use std::net::ToSocketAddrs as _;
    let mut answered: Vec<std::net::SocketAddr> = Vec::new();
    for part in value.split(',') {
        let part = part.trim();
        if part.is_empty() {
            return Err(Error::InvalidArguments);
        }
        answered.extend(
            part.to_socket_addrs()
                .map_err(|_| Error::InvalidArguments)?,
        );
    }
    let mut ordered: Vec<std::net::SocketAddr> = Vec::new();
    for address in answered
        .iter()
        .filter(|address| address.is_ipv6())
        .chain(answered.iter().filter(|address| address.is_ipv4()))
    {
        // A name and a literal can answer with the same address, and trying
        // it twice would spend the punch bound twice on one route.
        if !ordered.contains(address) {
            ordered.push(*address);
        }
    }
    if ordered.is_empty() {
        return Err(Error::InvalidArguments);
    }
    Ok(ordered)
}

pub(crate) fn read_bounded_file(path: &Path, maximum: usize) -> Result<Vec<u8>, Error> {
    let limit = u64::try_from(maximum)
        .map_err(|_| Error::InvalidBundle)?
        .saturating_add(1);
    let mut input = File::open(path)?.take(limit);
    let mut output = Vec::with_capacity(maximum.min(4096));
    input.read_to_end(&mut output)?;
    if output.len() > maximum {
        return Err(Error::InvalidBundle);
    }
    Ok(output)
}

pub(crate) fn write_new_synced(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    write_new_synced_with_mode(path, bytes, None)
}

/// Writes a new file and syncs it, optionally restricting who may read it.
///
/// One writer rather than two: a credential file wants mode 0600 and nothing
/// else does, which is one argument rather than a second copy of the same
/// create, write, and sync that a later durability change would miss.
/// `mode` is ignored where the platform has no mode bits.
pub(crate) fn write_new_synced_with_mode(
    path: &Path,
    bytes: &[u8],
    #[allow(unused_variables)] mode: Option<u32>,
) -> Result<(), Error> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    if let Some(mode) = mode {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

pub(crate) fn file_matches_bytes(path: &Path, expected: &[u8]) -> Result<bool, Error> {
    match read_bounded_file(path, expected.len()) {
        Ok(actual) => Ok(actual == expected),
        Err(Error::InvalidBundle) => Ok(false),
        Err(error) => Err(error),
    }
}

pub(crate) fn create_parent(path: &Path) -> Result<(), Error> {
    let parent = path.parent().ok_or(Error::InvalidPath)?;
    fs::create_dir_all(parent)?;
    Ok(())
}

pub(crate) fn sync_directories(root: &Path) -> Result<usize, Error> {
    let mut pending = vec![root.to_owned()];
    let mut directories = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)? {
            let path = entry?.path();
            if path.is_dir() {
                pending.push(path);
            }
        }
        directories.push(directory);
    }
    let count = directories.len();
    for directory in directories.into_iter().rev() {
        sync_directory(&directory)?;
    }
    Ok(count)
}

pub(crate) fn u32_len(length: usize) -> Result<u32, Error> {
    u32::try_from(length).map_err(|_| Error::InvalidBundle)
}

pub(crate) fn link_or_match(
    prepared: &Path,
    destination: &Path,
    maximum: usize,
) -> Result<(), Error> {
    match fs::hard_link(prepared, destination) {
        Ok(()) => Ok(()),
        Err(error) => resolve_link_error(error, prepared, destination, maximum),
    }
}

pub(crate) fn bounded_files_equal(
    left: &Path,
    right: &Path,
    maximum: usize,
) -> Result<bool, Error> {
    let left = match read_bounded_file(left, maximum) {
        Ok(bytes) => bytes,
        Err(Error::InvalidBundle) => return Ok(false),
        Err(error) => return Err(error),
    };
    let right = match read_bounded_file(right, maximum) {
        Ok(bytes) => bytes,
        Err(Error::InvalidBundle) => return Ok(false),
        Err(error) => return Err(error),
    };
    Ok(left == right)
}

pub(crate) fn resolve_link_error(
    error: io::Error,
    prepared: &Path,
    destination: &Path,
    maximum: usize,
) -> Result<(), Error> {
    if error.kind() != io::ErrorKind::AlreadyExists {
        return Err(Error::Io(error));
    }
    if bounded_files_equal(prepared, destination, maximum)? {
        Ok(())
    } else {
        Err(Error::DestinationExists)
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn atomic_rename_noreplace(source: &Path, destination: &Path) -> Result<(), Error> {
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        source,
        rustix::fs::CWD,
        destination,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(|error| Error::Io(error.into()))
}

#[cfg(target_os = "windows")]
pub(crate) fn windows_rename_noreplace(source: &Path, destination: &Path) -> Result<(), Error> {
    fs::rename(source, destination)?;
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub(crate) fn unsupported_rename_noreplace(
    _source: &Path,
    _destination: &Path,
) -> Result<(), Error> {
    Err(Error::InvalidArguments)
}

#[cfg(target_os = "windows")]
use windows_rename_noreplace as atomic_rename_noreplace;

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
use unsupported_rename_noreplace as atomic_rename_noreplace;

/// Makes a directory's own entries durable, once the files in it are.
#[cfg(not(windows))]
pub(crate) fn sync_directory(directory: &Path) -> Result<(), Error> {
    File::open(directory)?.sync_all()?;
    Ok(())
}

/// Windows has no directory fsync, and asking for one is not a no-op that
/// fails quietly: a directory cannot be opened as a file there without
/// `FILE_FLAG_BACKUP_SEMANTICS`, so `File::open` returns `PermissionDenied`
/// and every write path that ends in one of these failed outright. NTFS logs
/// a directory entry with the data it names, so what the unix call makes
/// durable is already durable here.
#[cfg(windows)]
pub(crate) fn windows_sync_directory(_directory: &Path) -> Result<(), Error> {
    Ok(())
}

#[cfg(windows)]
use windows_sync_directory as sync_directory;

pub(crate) fn staging_path(destination: &Path) -> Result<PathBuf, Error> {
    let name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(Error::InvalidPath)?;
    Ok(destination.with_file_name(format!(".{name}.vot-staging-{}", std::process::id())))
}

pub(crate) fn parent_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}
