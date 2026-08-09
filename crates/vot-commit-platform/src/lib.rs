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
    match profile {
        CommitProfile::Fast => {}
        CommitProfile::Balanced if capabilities.balanced => {}
        CommitProfile::Balanced | CommitProfile::Strict => {
            return Err(Error::UnsupportedProfile);
        }
    }
    // Read from the one table rather than repeated here. A receipt this
    // emits with a weaker predecessor than the profile requires is one
    // `vot_receipt::verify_chain` refuses, and nothing would have said so.
    let actual_predecessor = vot_receipt::required_predecessor(profile);
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
    fn same_file(&mut self, source: &Path, destination: &Path) -> Result<bool, Error>;
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

    fn same_file(&mut self, source: &Path, destination: &Path) -> Result<bool, Error> {
        vot_platform_fs::same_file_regular(source, destination).map_err(Error::Io)
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
    let already_linked = matches!(platform, Platform::Windows | Platform::MacOs)
        && operations.same_file(staging, destination)?;
    if !already_linked {
        operations.link(staging, destination)?;
    }
    if platform == Platform::MacOs {
        operations.sync_parent(destination)?;
        if !operations.same_file(staging, destination)? {
            return Err(Error::InvalidLayout);
        }
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
        linked: bool,
    }

    impl Operations for RecordingOperations {
        fn sync_file(&mut self, _path: &Path) -> Result<(), Error> {
            self.trace.push("sync-file");
            Ok(())
        }

        fn same_file(&mut self, _source: &Path, _destination: &Path) -> Result<bool, Error> {
            self.trace.push("same-file");
            Ok(self.linked)
        }

        fn link(&mut self, _source: &Path, _destination: &Path) -> Result<(), Error> {
            self.trace.push("link");
            self.linked = true;
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

    #[derive(Clone, Copy)]
    enum SyncBehavior {
        Fail,
        Succeed,
        ReplaceDestination,
    }

    #[derive(Clone, Copy)]
    enum RemoveBehavior {
        Fail,
        Succeed,
    }

    struct FaultOperations {
        trace: Vec<&'static str>,
        linked: bool,
        sync_behavior: SyncBehavior,
        remove_behavior: RemoveBehavior,
        removed: bool,
    }

    impl Operations for FaultOperations {
        fn sync_file(&mut self, _path: &Path) -> Result<(), Error> {
            self.trace.push("sync-file");
            Ok(())
        }

        fn same_file(&mut self, _source: &Path, _destination: &Path) -> Result<bool, Error> {
            self.trace.push("same-file");
            Ok(self.linked)
        }

        fn link(&mut self, _source: &Path, _destination: &Path) -> Result<(), Error> {
            self.trace.push("link");
            if self.linked {
                return Err(Error::Io(io::Error::from(io::ErrorKind::AlreadyExists)));
            }
            self.linked = true;
            Ok(())
        }

        fn remove(&mut self, _path: &Path) -> Result<(), Error> {
            self.trace.push("remove");
            if matches!(self.remove_behavior, RemoveBehavior::Fail) {
                return Err(Error::Io(io::Error::other("injected removal failure")));
            }
            self.removed = true;
            Ok(())
        }

        fn sync_parent(&mut self, _path: &Path) -> Result<(), Error> {
            self.trace.push("sync-parent");
            match self.sync_behavior {
                SyncBehavior::Fail => {
                    Err(Error::Io(io::Error::other("injected namespace failure")))
                }
                SyncBehavior::Succeed => Ok(()),
                SyncBehavior::ReplaceDestination => {
                    self.linked = false;
                    Ok(())
                }
            }
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

    #[cfg(any(unix, windows))]
    #[test]
    fn native_same_file_identity_is_exact() {
        let root = directory("same-file");
        fs::create_dir(&root).unwrap();
        let source = root.join("source");
        let linked = root.join("linked");
        let other = root.join("other");
        fs::write(&source, b"source").unwrap();
        fs::hard_link(&source, &linked).unwrap();
        fs::write(&other, b"other").unwrap();
        let mut operations = NativeOperations;
        assert!(operations.same_file(&source, &linked).unwrap());
        assert!(!operations.same_file(&source, &other).unwrap());
        #[cfg(unix)]
        {
            let symlink = root.join("symlink");
            std::os::unix::fs::symlink(&source, &symlink).unwrap();
            assert!(!operations.same_file(&source, &symlink).unwrap());
        }
        assert!(
            !operations
                .same_file(&source, &root.join("missing"))
                .unwrap()
        );
        #[cfg(unix)]
        assert!(matches!(
            operations.same_file(&source, &source.join("child")),
            Err(Error::Io(_))
        ));
        #[cfg(windows)]
        assert!(
            !operations
                .same_file(&source, &source.join("child"))
                .unwrap()
        );
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
        assert_eq!(windows.trace, ["same-file", "link", "remove"]);

        let mut macos = RecordingOperations::default();
        publish_with(
            Platform::MacOs,
            staging,
            destination,
            CommitProfile::Balanced,
            &mut macos,
        )
        .unwrap();
        assert_eq!(
            macos.trace,
            [
                "sync-file",
                "same-file",
                "link",
                "sync-parent",
                "same-file",
                "remove",
            ]
        );
    }

    #[test]
    fn macos_namespace_failure_retains_staging() {
        let mut operations = FaultOperations {
            trace: Vec::new(),
            linked: false,
            sync_behavior: SyncBehavior::Fail,
            remove_behavior: RemoveBehavior::Succeed,
            removed: false,
        };
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
        assert!(operations.linked);
        assert!(!operations.removed);
        operations.sync_behavior = SyncBehavior::Succeed;
        publish_with(
            Platform::MacOs,
            Path::new("root/staging"),
            Path::new("root/destination"),
            CommitProfile::Balanced,
            &mut operations,
        )
        .unwrap();
        assert!(operations.removed);
        assert_eq!(
            operations.trace,
            [
                "sync-file",
                "same-file",
                "link",
                "sync-parent",
                "sync-file",
                "same-file",
                "sync-parent",
                "same-file",
                "remove",
            ]
        );
    }

    #[test]
    fn macos_destination_replacement_after_sync_retains_staging() {
        let mut replaced = FaultOperations {
            trace: Vec::new(),
            linked: false,
            sync_behavior: SyncBehavior::ReplaceDestination,
            remove_behavior: RemoveBehavior::Succeed,
            removed: false,
        };
        assert!(matches!(
            publish_with(
                Platform::MacOs,
                Path::new("root/staging"),
                Path::new("root/destination"),
                CommitProfile::Balanced,
                &mut replaced,
            ),
            Err(Error::InvalidLayout)
        ));
        assert!(!replaced.removed);
    }

    #[test]
    fn windows_cleanup_failure_recovers_the_existing_link() {
        let mut operations = FaultOperations {
            trace: Vec::new(),
            linked: false,
            sync_behavior: SyncBehavior::Succeed,
            remove_behavior: RemoveBehavior::Fail,
            removed: false,
        };
        assert!(matches!(
            publish_with(
                Platform::Windows,
                Path::new("root/staging"),
                Path::new("root/destination"),
                CommitProfile::Fast,
                &mut operations,
            ),
            Err(Error::Io(_))
        ));
        assert!(operations.linked);
        assert!(!operations.removed);
        operations.remove_behavior = RemoveBehavior::Succeed;
        publish_with(
            Platform::Windows,
            Path::new("root/staging"),
            Path::new("root/destination"),
            CommitProfile::Fast,
            &mut operations,
        )
        .unwrap();
        assert!(operations.removed);
        assert_eq!(
            operations.trace,
            ["same-file", "link", "remove", "same-file", "remove"]
        );
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
