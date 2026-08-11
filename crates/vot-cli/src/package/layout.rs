//! Package layout names, suite identifiers, and path encoding.

use crate::{Component, Error, PackagePath, Path, PathBuf, PathProfile, Suite, canonical_path_key};

pub(crate) const MANIFEST_DIRECTORY: &str = "manifest";
pub(crate) const MANIFEST_SEAL: &str = "seal.cbor";
pub(crate) const DEFAULT_LOGICAL_SUITE: Suite = Suite::Sha256Bep52;

pub(crate) const fn suite_id(suite: Suite) -> u16 {
    suite.identifier()
}

pub fn parse_suite(value: &str) -> Result<Suite, Error> {
    match value {
        "blake3" | "blake3-bao64" | "1" => Ok(Suite::Blake3Bao64),
        "sha256" | "sha256-bep52" | "2" => Ok(Suite::Sha256Bep52),
        _ => Err(Error::InvalidArguments),
    }
}

pub(crate) fn manifest_page_path(directory: &Path, index: u64) -> PathBuf {
    directory.join(format!("{index:016}.cbor"))
}

pub(crate) fn manifest_spool_path(directory: &Path, index: u64) -> PathBuf {
    directory.join(format!(".spool-{index:016}.cbor"))
}

pub(crate) fn output_path(root: &Path, path: &PackagePath) -> Result<PathBuf, Error> {
    canonical_path_key(path, PathProfile::Portable).map_err(|_| Error::InvalidPath)?;
    let mut output = root.to_owned();
    for component in path {
        let Component::Text(component) = component else {
            return Err(Error::InvalidPath);
        };
        output.push(component);
    }
    Ok(output)
}

pub(crate) fn object_name(root: &[u8; 32]) -> String {
    let mut output = String::with_capacity(68);
    for byte in root {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to a string cannot fail");
    }
    output.push_str(".obj");
    output
}
