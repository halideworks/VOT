//! Explicit caller assertion of a NAS server's stable-storage contract.

#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::io;

/// A successful probe cannot establish the remote server's power-loss behavior.
/// Persist this choice with the receiver's configuration and resume record.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum NasContract {
    #[default]
    Unqualified,
    /// The administrator has qualified stable SMB FLUSH/NFS COMMIT and
    /// synchronous namespace operations. Server ACLs establish service ownership
    /// and exclude every other principal from temporary data and metadata.
    /// For CIFS, those ACLs also prevent renaming/replacing the temporary namespace
    /// and every ancestor path. Same-principal mutations remain serialized.
    /// Mode bits and successful probes do not establish these server properties.
    ServerAcknowledged,
}

/// Validates the kernel client's part of an explicitly qualified NAS contract.
/// The caller remains responsible for the server's configuration and behavior.
///
/// # Errors
/// Refuses an absent mount, synthetic permissions, unsafe caching or disabled flushes.
#[cfg(target_os = "linux")]
pub fn validate_nas_mount(file: &File) -> io::Result<()> {
    use rustix::fs::{AtFlags, StatxFlags};
    let stat = rustix::fs::statx(file, "", AtFlags::EMPTY_PATH, StatxFlags::MNT_ID)?;
    if stat.stx_mask & StatxFlags::MNT_ID.bits() == 0 {
        return Err(io::Error::other("filesystem mount identity is unavailable"));
    }
    let mounts = std::fs::read_to_string("/proc/self/mountinfo")?;
    validate_mount_info(&mounts, stat.stx_mnt_id)
}

#[cfg(target_os = "linux")]
fn validate_mount_info(mounts: &str, mount_id: u64) -> io::Result<()> {
    let fields = mounts
        .lines()
        .find_map(|line| {
            let fields: Vec<_> = line.split_ascii_whitespace().collect();
            (fields.first()?.parse::<u64>().ok()? == mount_id).then_some(fields)
        })
        .ok_or_else(|| io::Error::other("admitted NAS mount is no longer attached"))?;
    let separator = fields
        .iter()
        .position(|field| *field == "-")
        .filter(|separator| *separator >= 6 && fields.len() == *separator + 4)
        .ok_or_else(|| io::Error::other("malformed mount information"))?;
    let filesystem = fields[separator + 1];
    let options: Vec<_> = fields[5]
        .split(',')
        .chain(fields[separator + 3].split(','))
        .collect();
    validate_options(filesystem, &options)
}

#[cfg(target_os = "linux")]
fn validate_options(filesystem: &str, options: &[&str]) -> io::Result<()> {
    let has = |option| options.contains(&option);
    if has("ro")
        || has("nostrictsync")
        || has("cache=loose")
        || has("dynperm")
        || has("noperm")
        || has("modefromsid")
    {
        return Err(io::Error::other(
            "NAS mount disables required flush, cache or permission guarantees",
        ));
    }
    let qualified = match filesystem {
        "cifs" | "smb3" => {
            let smb3 = options
                .iter()
                .any(|option| matches!(*option, "vers=3.0" | "vers=3.02" | "vers=3.1.1"));
            smb3 && has("serverino") && (has("cifsacl") || has("posix"))
        }
        "nfs" | "nfs4" => {
            has("hard")
                && options.iter().any(|option| {
                    matches!(*option, "vers=4" | "vers=4.0" | "vers=4.1" | "vers=4.2")
                })
        }
        _ => false,
    };
    if !qualified {
        return Err(io::Error::other(
            "NAS requires SMB3 with server identities and ACLs, or hard-mounted NFS4",
        ));
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn qualification_requires_every_client_guarantee() {
        for (filesystem, required) in [
            ("cifs", vec!["vers=3.1.1", "serverino", "cifsacl"]),
            ("smb3", vec!["vers=3.02", "serverino", "posix"]),
            ("nfs", vec!["vers=4.1", "hard"]),
            ("nfs4", vec!["vers=4.2", "hard"]),
        ] {
            assert!(validate_options(filesystem, &required).is_ok());
            for index in 0..required.len() {
                let mut missing = required.clone();
                missing.remove(index);
                assert!(validate_options(filesystem, &missing).is_err());
            }
            for unsafe_option in [
                "ro",
                "nostrictsync",
                "cache=loose",
                "dynperm",
                "noperm",
                "modefromsid",
            ] {
                let mut unsafe_options = required.clone();
                unsafe_options.push(unsafe_option);
                assert!(validate_options(filesystem, &unsafe_options).is_err());
            }
            assert!(validate_options("ext4", &required).is_err());
        }
        for version in ["vers=3.0", "vers=3.02", "vers=3.1.1"] {
            assert!(validate_options("cifs", &[version, "serverino", "cifsacl"]).is_ok());
        }
        for version in ["vers=4", "vers=4.0", "vers=4.1", "vers=4.2"] {
            assert!(validate_options("nfs4", &[version, "hard"]).is_ok());
        }
        assert!(validate_options("cifs", &["vers=2.1", "serverino", "cifsacl"]).is_err());
        assert!(validate_options("nfs4", &["vers=3", "hard"]).is_err());
        assert!(validate_options("nfs4", &["vers=4.1", "soft"]).is_err());
    }

    #[test]
    fn mount_lookup_binds_options_to_the_held_mount() {
        let valid = "15 1 0:4 / /mnt rw,relatime shared:1 - cifs //nas/media rw,vers=3.1.1,serverino,cifsacl\n16 1 0:5 / /mnt/nested rw - nfs4 nas:/media rw,vers=4.1,hard";
        assert!(validate_mount_info(valid, 15).is_ok());
        assert!(validate_mount_info(valid, 16).is_ok());
        for (text, id) in [
            (valid, 17),
            ("15", 15),
            ("15 - cifs a rw", 15),
            ("", 15),
            ("15 1 0:4 / /mnt rw - cifs a", 15),
        ] {
            assert!(validate_mount_info(text, id).is_err());
        }
        assert!(validate_mount_info(&valid.replace("rw,relatime", "ro,relatime"), 15).is_err());
        assert!(validate_nas_mount(&File::open("/").unwrap()).is_err());
    }
}
