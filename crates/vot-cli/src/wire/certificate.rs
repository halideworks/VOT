//! Ephemeral credentials and private file handling.

use super::{Error, Path, PathBuf};

/// Temp files for an ephemeral certificate and key. quiche requires file paths.
pub(crate) struct Ephemeral {
    pub(crate) directory: PathBuf,
    pub(crate) certificate: PathBuf,
    pub(crate) key: PathBuf,
}

impl Drop for Ephemeral {
    fn drop(&mut self) {
        // Best-effort cleanup; the key is ephemeral.
        let _ = std::fs::remove_file(&self.certificate);
        let _ = std::fs::remove_file(&self.key);
        let _ = std::fs::remove_dir(&self.directory);
    }
}

impl Ephemeral {
    /// Generates a self-signed ECDSA P-256 certificate. `BoringSSL` rejects
    /// Ed25519 leaves; RSA generation is too slow for an unchecked cert.
    pub(crate) fn generate() -> Result<Self, Error> {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .map_err(|_| Error::Randomness)?;
        let mut parameters = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
            .map_err(|_| Error::InvalidArguments)?;
        parameters
            .distinguished_name
            .push(rcgen::DnType::CommonName, "localhost");
        let certificate = parameters
            .self_signed(&key)
            .map_err(|_| Error::InvalidArguments)?;

        // The name is unguessable rather than merely unique. A private key
        // at a path another local user can work out is one they can wait
        // for, and a process ID is neither secret nor unique: inside a PID
        // namespace it repeats every run, and the second serve cannot start.
        let mut suffix = [0_u8; 16];
        getrandom::fill(&mut suffix).map_err(|_| Error::Randomness)?;
        let mut name = String::from("vot-serve-");
        for byte in suffix {
            use std::fmt::Write;
            let _ = write!(name, "{byte:02x}");
        }
        let directory = std::env::temp_dir().join(name);
        create_private_directory(&directory)?;
        let written = Self {
            certificate: directory.join("cert.pem"),
            key: directory.join("key.pem"),
            directory,
        };
        write_private_synced(&written.certificate, certificate.pem().as_bytes())?;
        write_private_synced(&written.key, key.serialize_pem().as_bytes())?;
        Ok(written)
    }
}

/// Creates a directory only this user can enter. A directory that takes the
/// umask leaves the key inside it readable by anyone on the host. Windows has
/// no mode bits here, so there the per-user temp directory and the
/// unguessable name are the protection.
///
/// Any missing parents are created first, without the mode: they are the
/// temp root, shared by everything, and only the leaf holds a key. Creating
/// just the leaf was a regression, because a `TMPDIR` whose tree does not
/// exist yet then aborts a serve before it binds.
pub(crate) fn create_private_directory(path: &Path) -> Result<(), Error> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)?;
    Ok(())
}

/// Writes a new file only this user can read, and syncs it.
fn write_private_synced(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    crate::write_new_synced_with_mode(path, bytes, Some(0o600))
}
