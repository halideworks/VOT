//! Conservative Windows and macOS publication capabilities and native commit path.

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]

use std::fs::File;
use std::io;
use std::path::Path;

#[cfg(test)]
use std::fs;

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
    let staging_file = vot_platform_fs::guard_staging_file(staging)?;
    publish_native_file(&staging_file, staging, destination, profile)
}

/// Publishes a same-directory staged file bound to an already trusted handle.
///
/// The staging name and destination are checked against `staging_file` before
/// publication and again before the staging name is removed. On Windows,
/// callers must retain the no-share-delete handle returned by
/// `vot_platform_fs::create_staging_file` or `guard_staging_file`.
pub fn publish_native_file(
    staging_file: &File,
    staging: &Path,
    destination: &Path,
    profile: CommitProfile,
) -> Result<PublicationClaim, Error> {
    vot_platform_fs::validate_removal_parent(staging)?;
    publish_file_for(
        native_platform(),
        staging_file,
        staging,
        destination,
        profile,
    )
}

#[cfg(test)]
fn publish_for(
    platform: Platform,
    staging: &Path,
    destination: &Path,
    profile: CommitProfile,
) -> Result<PublicationClaim, Error> {
    let staging_file = vot_platform_fs::guard_staging_file(staging)?;
    publish_file_for(platform, &staging_file, staging, destination, profile)
}

fn publish_file_for(
    platform: Platform,
    staging_file: &File,
    staging: &Path,
    destination: &Path,
    profile: CommitProfile,
) -> Result<PublicationClaim, Error> {
    publish_with(
        platform,
        staging,
        destination,
        profile,
        &mut NativeOperations { staging_file },
    )
}

trait Operations {
    fn sync_file(&mut self, path: &Path) -> Result<(), Error>;
    fn same_file(&mut self, source: &Path, destination: &Path) -> Result<bool, Error>;
    fn link(&mut self, source: &Path, destination: &Path) -> Result<(), Error>;
    fn remove(&mut self, path: &Path) -> Result<(), Error>;
    fn sync_parent(&mut self, path: &Path) -> Result<(), Error>;
}

struct NativeOperations<'a> {
    staging_file: &'a File,
}

impl Operations for NativeOperations<'_> {
    fn sync_file(&mut self, _path: &Path) -> Result<(), Error> {
        self.staging_file.sync_all()?;
        Ok(())
    }

    fn same_file(&mut self, _source: &Path, destination: &Path) -> Result<bool, Error> {
        vot_platform_fs::same_file_handle(self.staging_file, destination).map_err(Error::Io)
    }

    fn link(&mut self, source: &Path, destination: &Path) -> Result<(), Error> {
        vot_platform_fs::link_file_handle(self.staging_file, source, destination)?;
        Ok(())
    }

    fn remove(&mut self, path: &Path) -> Result<(), Error> {
        vot_platform_fs::remove_file_handle(self.staging_file, path)?;
        Ok(())
    }

    fn sync_parent(&mut self, path: &Path) -> Result<(), Error> {
        let parent = containing_directory(path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    }
}

fn containing_directory(path: &Path) -> Result<&Path, Error> {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .or_else(|| path.file_name().map(|_| Path::new(".")))
        .ok_or(Error::InvalidLayout)
}

fn validate_layout(staging: &Path, destination: &Path) -> Result<(), Error> {
    if containing_directory(staging)? != containing_directory(destination)?
        || staging.file_name() == destination.file_name()
    {
        return Err(Error::InvalidLayout);
    }
    Ok(())
}

fn publish_with(
    platform: Platform,
    staging: &Path,
    destination: &Path,
    profile: CommitProfile,
    operations: &mut impl Operations,
) -> Result<PublicationClaim, Error> {
    let claim = claim(platform, profile)?;
    validate_layout(staging, destination)?;
    if !operations.same_file(staging, staging)? {
        return Err(Error::InvalidLayout);
    }
    if profile == CommitProfile::Balanced {
        operations.sync_file(staging)?;
    }
    if !operations.same_file(staging, destination)? {
        operations.link(staging, destination)?;
    }
    if !operations.same_file(staging, destination)? {
        return Err(Error::InvalidLayout);
    }
    if platform == Platform::MacOs {
        operations.sync_parent(destination)?;
        if !operations.same_file(staging, destination)? {
            return Err(Error::InvalidLayout);
        }
    }
    if !operations.same_file(staging, staging)? {
        return Err(Error::InvalidLayout);
    }
    operations.remove(staging)?;
    Ok(claim)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn directory(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "vot-platform-{}-{}-{name}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;

            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700).create(&path).unwrap();
        }
        #[cfg(not(unix))]
        fs::create_dir(&path).unwrap();
        path
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

        fn same_file(&mut self, source: &Path, destination: &Path) -> Result<bool, Error> {
            if source == destination {
                self.trace.push("same-staging");
                Ok(true)
            } else {
                self.trace.push("same-destination");
                Ok(self.linked)
            }
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
        same_file_results: Vec<bool>,
        same_file_index: usize,
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
            let result = self.same_file_results[self.same_file_index];
            self.same_file_index += 1;
            Ok(result)
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

    #[cfg(unix)]
    #[test]
    fn handle_bound_publication_rejects_a_swapped_staging_name() {
        let root = directory("handle-bound-swap");
        let staging = root.join("staging");
        let trusted_alias = root.join("trusted-alias");
        let destination = root.join("published");
        fs::write(&staging, b"verified bytes").unwrap();
        let held = File::open(&staging).unwrap();
        fs::hard_link(&staging, &trusted_alias).unwrap();
        fs::remove_file(&staging).unwrap();
        fs::write(&staging, b"replacement bytes").unwrap();

        assert!(matches!(
            publish_file_for(
                Platform::MacOs,
                &held,
                &staging,
                &destination,
                CommitProfile::Balanced,
            ),
            Err(Error::InvalidLayout)
        ));
        assert!(!destination.exists());
        assert_eq!(fs::read(trusted_alias).unwrap(), b"verified bytes");
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn native_same_file_identity_is_exact() {
        let root = directory("same-file");
        let source = root.join("source");
        let linked = root.join("linked");
        let other = root.join("other");
        fs::write(&source, b"source").unwrap();
        fs::hard_link(&source, &linked).unwrap();
        fs::write(&other, b"other").unwrap();
        let source_file = File::open(&source).unwrap();
        let mut operations = NativeOperations {
            staging_file: &source_file,
        };
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

    #[cfg(unix)]
    #[test]
    fn public_file_publisher_rejects_unsafe_parent_before_linking() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = directory("unsafe-parent");
        let staging = root.join("staging");
        let destination = root.join("published");
        fs::write(&staging, b"verified bytes").unwrap();
        let file = File::open(&staging).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(matches!(
            publish_native_file(
                &file,
                &staging,
                &destination,
                CommitProfile::Fast
            ),
            Err(Error::Io(ref error)) if error.kind() == io::ErrorKind::PermissionDenied
        ));
        assert!(!destination.exists());
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn publication_is_no_overwrite_and_profile_checked_first() {
        let root = directory("no-overwrite");
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
        assert!(matches!(
            publish_for(
                Platform::Windows,
                &staging,
                &root.join("other").join("published"),
                CommitProfile::Fast
            ),
            Err(Error::InvalidLayout)
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn bare_relative_paths_use_the_current_directory_layout() {
        assert_eq!(
            containing_directory(Path::new("object")).unwrap(),
            Path::new(".")
        );
        assert!(validate_layout(Path::new("./stage"), Path::new("object")).is_ok());
        assert!(matches!(
            validate_layout(Path::new("./object"), Path::new("object")),
            Err(Error::InvalidLayout)
        ));
        assert!(matches!(
            validate_layout(Path::new("other/stage"), Path::new("object")),
            Err(Error::InvalidLayout)
        ));
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
        assert_eq!(
            windows.trace,
            [
                "same-staging",
                "same-destination",
                "link",
                "same-destination",
                "same-staging",
                "remove",
            ]
        );

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
                "same-staging",
                "sync-file",
                "same-destination",
                "link",
                "same-destination",
                "sync-parent",
                "same-destination",
                "same-staging",
                "remove",
            ]
        );
    }

    #[test]
    fn macos_namespace_failure_retains_staging() {
        let mut operations = FaultOperations {
            trace: Vec::new(),
            linked: false,
            same_file_results: vec![true, false, true, true, true, true, true, true],
            same_file_index: 0,
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
                "same-file",
                "sync-file",
                "same-file",
                "link",
                "same-file",
                "sync-parent",
                "same-file",
                "sync-file",
                "same-file",
                "same-file",
                "sync-parent",
                "same-file",
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
            same_file_results: vec![true, false, true, false],
            same_file_index: 0,
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
    fn publication_rejects_destination_identity_loss_after_link() {
        let mut operations = FaultOperations {
            trace: Vec::new(),
            linked: false,
            same_file_results: vec![true, false, false],
            same_file_index: 0,
            sync_behavior: SyncBehavior::Succeed,
            remove_behavior: RemoveBehavior::Succeed,
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
            Err(Error::InvalidLayout)
        ));
        assert!(!operations.removed);
    }

    #[test]
    fn publication_rejects_staging_identity_loss_before_cleanup() {
        let mut operations = FaultOperations {
            trace: Vec::new(),
            linked: false,
            same_file_results: vec![true, false, true, false],
            same_file_index: 0,
            sync_behavior: SyncBehavior::Succeed,
            remove_behavior: RemoveBehavior::Succeed,
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
            Err(Error::InvalidLayout)
        ));
        assert!(!operations.removed);
    }

    #[test]
    fn windows_cleanup_failure_recovers_the_existing_link() {
        let mut operations = FaultOperations {
            trace: Vec::new(),
            linked: false,
            same_file_results: vec![true, false, true, true, true, true, true, true],
            same_file_index: 0,
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
            [
                "same-file",
                "same-file",
                "link",
                "same-file",
                "same-file",
                "remove",
                "same-file",
                "same-file",
                "same-file",
                "same-file",
                "remove",
            ]
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
