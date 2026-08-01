//! Conservative Windows and macOS publication capabilities and native commit path.

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]

use std::fs::{self, File};
use std::io;
use std::path::Path;

use vot_receipt::{AssuranceLevel, CommitProfile};

pub const WINDOWS_PROVIDER: u16 = 3;
pub const MACOS_PROVIDER: u16 = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Platform {
    Windows,
    MacOs,
    Unsupported,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NamespaceOperation {
    AtomicNoOverwriteLink,
    AtomicNoOverwriteLinkAndDirectorySync,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Capabilities {
    pub provider: u16,
    pub fast: bool,
    pub balanced: bool,
    pub strict: bool,
    pub highest_predecessor: AssuranceLevel,
    pub namespace: NamespaceOperation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicationClaim {
    pub provider: u16,
    pub profile: CommitProfile,
    pub assurance: AssuranceLevel,
    pub actual_predecessor: AssuranceLevel,
    pub provider_version: [u16; 3],
}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    UnsupportedPlatform,
    UnsupportedProfile,
    InvalidLayout,
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[must_use]
pub const fn capabilities(platform: Platform) -> Option<Capabilities> {
    match platform {
        Platform::Windows => Some(Capabilities {
            provider: WINDOWS_PROVIDER,
            fast: true,
            balanced: false,
            strict: false,
            highest_predecessor: AssuranceLevel::TransitVerified,
            namespace: NamespaceOperation::AtomicNoOverwriteLink,
        }),
        Platform::MacOs => Some(Capabilities {
            provider: MACOS_PROVIDER,
            fast: true,
            balanced: true,
            strict: false,
            highest_predecessor: AssuranceLevel::Durable,
            namespace: NamespaceOperation::AtomicNoOverwriteLinkAndDirectorySync,
        }),
        Platform::Unsupported => None,
    }
}

#[must_use]
pub const fn native_platform() -> Platform {
    if cfg!(target_os = "windows") {
        Platform::Windows
    } else if cfg!(target_os = "macos") {
        Platform::MacOs
    } else {
        Platform::Unsupported
    }
}

pub fn claim(platform: Platform, profile: CommitProfile) -> Result<PublicationClaim, Error> {
    let capabilities = capabilities(platform).ok_or(Error::UnsupportedPlatform)?;
    let actual_predecessor = match profile {
        CommitProfile::Fast => AssuranceLevel::TransitVerified,
        CommitProfile::Balanced => {
            if !capabilities.balanced {
                return Err(Error::UnsupportedProfile);
            }
            AssuranceLevel::Durable
        }
        CommitProfile::Strict => return Err(Error::UnsupportedProfile),
    };
    Ok(PublicationClaim {
        provider: capabilities.provider,
        profile,
        assurance: AssuranceLevel::Published,
        actual_predecessor,
        provider_version: [0, 3, 0],
    })
}

/// Publishes a same-directory staged file with atomic no-overwrite semantics.
///
/// Windows reports Fast only. macOS reports Balanced only after data and
/// directory synchronization succeeds. Strict is explicitly unsupported.
pub fn publish_native(
    staging: &Path,
    destination: &Path,
    profile: CommitProfile,
) -> Result<PublicationClaim, Error> {
    publish_for(native_platform(), staging, destination, profile)
}

fn publish_for(
    platform: Platform,
    staging: &Path,
    destination: &Path,
    profile: CommitProfile,
) -> Result<PublicationClaim, Error> {
    publish_with(
        platform,
        staging,
        destination,
        profile,
        &mut NativeOperations,
    )
}

trait Operations {
    fn sync_file(&mut self, path: &Path) -> Result<(), Error>;
    fn link(&mut self, source: &Path, destination: &Path) -> Result<(), Error>;
    fn remove(&mut self, path: &Path) -> Result<(), Error>;
    fn sync_parent(&mut self, path: &Path) -> Result<(), Error>;
}

struct NativeOperations;

impl Operations for NativeOperations {
    fn sync_file(&mut self, path: &Path) -> Result<(), Error> {
        File::open(path)?.sync_all()?;
        Ok(())
    }

    fn link(&mut self, source: &Path, destination: &Path) -> Result<(), Error> {
        fs::hard_link(source, destination)?;
        Ok(())
    }

    fn remove(&mut self, path: &Path) -> Result<(), Error> {
        fs::remove_file(path)?;
        Ok(())
    }

    fn sync_parent(&mut self, path: &Path) -> Result<(), Error> {
        #[cfg(unix)]
        {
            let parent = path.parent().ok_or(Error::InvalidLayout)?;
            File::open(parent)?.sync_all()?;
            Ok(())
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            Err(Error::UnsupportedPlatform)
        }
    }
}

fn publish_with(
    platform: Platform,
    staging: &Path,
    destination: &Path,
    profile: CommitProfile,
    operations: &mut impl Operations,
) -> Result<PublicationClaim, Error> {
    let claim = claim(platform, profile)?;
    if staging.parent() != destination.parent() || staging == destination {
        return Err(Error::InvalidLayout);
    }
    if profile == CommitProfile::Balanced {
        operations.sync_file(staging)?;
    }
    operations.link(staging, destination)?;
    if platform == Platform::MacOs {
        operations.sync_parent(destination)?;
    }
    operations.remove(staging)?;
    Ok(claim)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn directory(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("vot-platform-{}-{name}", std::process::id()))
    }

    #[derive(Default)]
    struct RecordingOperations {
        trace: Vec<&'static str>,
    }

    impl Operations for RecordingOperations {
        fn sync_file(&mut self, _path: &Path) -> Result<(), Error> {
            self.trace.push("sync-file");
            Ok(())
        }

        fn link(&mut self, _source: &Path, _destination: &Path) -> Result<(), Error> {
            self.trace.push("link");
            Ok(())
        }

        fn remove(&mut self, _path: &Path) -> Result<(), Error> {
            self.trace.push("remove");
            Ok(())
        }

        fn sync_parent(&mut self, _path: &Path) -> Result<(), Error> {
            self.trace.push("sync-parent");
            Ok(())
        }
    }

    #[test]
    fn platform_receipts_state_only_actual_capabilities() {
        let windows = capabilities(Platform::Windows).unwrap();
        assert!(windows.fast);
        assert!(!windows.balanced);
        assert!(!windows.strict);
        assert_eq!(windows.provider, WINDOWS_PROVIDER);
        assert_eq!(
            claim(Platform::Windows, CommitProfile::Fast)
                .unwrap()
                .actual_predecessor,
            AssuranceLevel::TransitVerified
        );
        assert!(matches!(
            claim(Platform::Windows, CommitProfile::Balanced),
            Err(Error::UnsupportedProfile)
        ));

        let macos = capabilities(Platform::MacOs).unwrap();
        assert!(macos.fast);
        assert!(macos.balanced);
        assert!(!macos.strict);
        assert_eq!(macos.provider, MACOS_PROVIDER);
        assert_eq!(
            claim(Platform::MacOs, CommitProfile::Balanced)
                .unwrap()
                .actual_predecessor,
            AssuranceLevel::Durable
        );
        assert!(matches!(
            claim(Platform::MacOs, CommitProfile::Strict),
            Err(Error::UnsupportedProfile)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn macos_balanced_claim_follows_native_commit_operations() {
        let root = directory("macos");
        fs::create_dir(&root).unwrap();
        let staging = root.join("staging");
        let destination = root.join("published");
        fs::write(&staging, b"verified bytes").unwrap();
        let result = publish_for(
            Platform::MacOs,
            &staging,
            &destination,
            CommitProfile::Balanced,
        )
        .unwrap();
        assert_eq!(result.actual_predecessor, AssuranceLevel::Durable);
        assert!(!staging.exists());
        assert_eq!(fs::read(destination).unwrap(), b"verified bytes");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn publication_is_no_overwrite_and_profile_checked_first() {
        let root = directory("no-overwrite");
        fs::create_dir(&root).unwrap();
        let staging = root.join("staging");
        let destination = root.join("published");
        fs::write(&staging, b"new").unwrap();
        fs::write(&destination, b"existing").unwrap();
        assert!(matches!(
            publish_for(
                Platform::Windows,
                &staging,
                &destination,
                CommitProfile::Balanced
            ),
            Err(Error::UnsupportedProfile)
        ));
        assert!(matches!(
            publish_for(
                Platform::Windows,
                &staging,
                &destination,
                CommitProfile::Fast
            ),
            Err(Error::Io(_))
        ));
        assert_eq!(fs::read(&destination).unwrap(), b"existing");
        assert_eq!(fs::read(&staging).unwrap(), b"new");
        assert!(matches!(
            publish_for(Platform::Windows, &staging, &staging, CommitProfile::Fast),
            Err(Error::InvalidLayout)
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn provider_operations_match_the_claimed_profile_exactly() {
        let staging = Path::new("root/staging");
        let destination = Path::new("root/destination");
        let mut windows = RecordingOperations::default();
        publish_with(
            Platform::Windows,
            staging,
            destination,
            CommitProfile::Fast,
            &mut windows,
        )
        .unwrap();
        assert_eq!(windows.trace, ["link", "remove"]);

        let mut macos = RecordingOperations::default();
        publish_with(
            Platform::MacOs,
            staging,
            destination,
            CommitProfile::Balanced,
            &mut macos,
        )
        .unwrap();
        assert_eq!(macos.trace, ["sync-file", "link", "sync-parent", "remove"]);
    }

    #[test]
    fn macos_namespace_failure_retains_staging() {
        struct FailedNamespace {
            trace: Vec<&'static str>,
        }

        impl Operations for FailedNamespace {
            fn sync_file(&mut self, _path: &Path) -> Result<(), Error> {
                self.trace.push("sync-file");
                Ok(())
            }

            fn link(&mut self, _source: &Path, _destination: &Path) -> Result<(), Error> {
                self.trace.push("link");
                Ok(())
            }

            fn remove(&mut self, _path: &Path) -> Result<(), Error> {
                self.trace.push("remove");
                Ok(())
            }

            fn sync_parent(&mut self, _path: &Path) -> Result<(), Error> {
                self.trace.push("sync-parent");
                Err(Error::Io(io::Error::other("injected namespace failure")))
            }
        }

        let mut operations = FailedNamespace { trace: Vec::new() };
        assert!(matches!(
            publish_with(
                Platform::MacOs,
                Path::new("root/staging"),
                Path::new("root/destination"),
                CommitProfile::Balanced,
                &mut operations,
            ),
            Err(Error::Io(_))
        ));
        assert_eq!(operations.trace, ["sync-file", "link", "sync-parent"]);
    }

    #[test]
    fn native_platform_reports_only_target_capabilities() {
        let platform = native_platform();
        if cfg!(target_os = "windows") {
            assert_eq!(platform, Platform::Windows);
            assert_eq!(
                capabilities(platform).unwrap().highest_predecessor,
                AssuranceLevel::TransitVerified
            );
        } else if cfg!(target_os = "macos") {
            assert_eq!(platform, Platform::MacOs);
            assert_eq!(
                capabilities(platform).unwrap().highest_predecessor,
                AssuranceLevel::Durable
            );
        } else {
            assert_eq!(platform, Platform::Unsupported);
            assert_eq!(capabilities(platform), None);
        }
    }

    #[cfg(any(target_os = "windows", target_os = "macos"))]
    #[test]
    fn native_provider_publishes_at_its_claimed_level() {
        let root = directory("native");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        let staging = root.join("staging");
        let destination = root.join("published");
        fs::write(&staging, b"verified bytes").unwrap();
        let profile = if cfg!(target_os = "windows") {
            CommitProfile::Fast
        } else {
            CommitProfile::Balanced
        };
        let result = publish_native(&staging, &destination, profile).unwrap();
        assert_eq!(
            result.provider,
            capabilities(native_platform()).unwrap().provider
        );
        assert_eq!(result.profile, profile);
        assert_eq!(fs::read(&destination).unwrap(), b"verified bytes");
        assert!(!staging.exists());
        fs::remove_dir_all(root).unwrap();
    }
}
