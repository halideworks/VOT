//! Path profiles, canonical keys, and component validation.

use super::{Error, MAX_PATH_COMPONENTS, UnicodeNormalization};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathProfile {
    Portable,
    RawPosix,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Component {
    Text(String),
    Bytes(Vec<u8>),
}

pub type PackagePath = Vec<Component>;

pub fn canonical_path_key(path: &PackagePath, profile: PathProfile) -> Result<Vec<u8>, Error> {
    // The decoder refuses a path past this bound, so an encoder that emitted
    // one would produce a page nothing could read back.
    if path.is_empty() || path.len() > MAX_PATH_COMPONENTS {
        return Err(Error::InvalidPath);
    }
    let mut key = Vec::new();
    for component in path {
        if !key.is_empty() {
            key.push(0);
        }
        match (profile, component) {
            (PathProfile::Portable, Component::Text(text)) => {
                validate_portable_component(text)?;
                let folded = portable_fold(text);
                key.extend_from_slice(folded.trim_end_matches(['.', ' ']).as_bytes());
            }
            (PathProfile::RawPosix, Component::Bytes(bytes)) if valid_raw_component(bytes) => {
                key.extend_from_slice(bytes);
            }
            _ => return Err(Error::InvalidPath),
        }
    }
    Ok(key)
}

pub(super) fn validate_portable_component(component: &str) -> Result<(), Error> {
    // Neither "." nor ".." is named here. Both end in a dot, which the rule
    // below refuses, and their compatibility spellings are settled after the
    // NFKC form is taken rather than before it.
    if component.is_empty()
        || component.len() > 255
        || component.contains(['\0', '/', '\\', '<', '>', ':', '"', '|', '?', '*'])
        || component.ends_with(['.', ' '])
        || component.chars().any(|character| {
            character <= '\u{1f}'
                || matches!(
                    character,
                    '\u{200c}'
                        | '\u{200d}'
                        | '\u{202a}'..='\u{202e}'
                        | '\u{2066}'..='\u{2069}'
                        | '\u{feff}'
                )
        })
    {
        return Err(Error::InvalidPath);
    }
    let compatibility: String = component.nfkc().collect();
    if matches!(compatibility.as_str(), "." | "..") {
        return Err(Error::InvalidPath);
    }
    let folded = portable_fold(component);
    if matches!(folded.as_str(), "" | "." | "..") {
        return Err(Error::InvalidPath);
    }
    let stem = folded.split('.').next().unwrap_or_default();
    let reserved = matches!(stem, "con" | "prn" | "aux" | "nul")
        || stem.strip_prefix("com").is_some_and(is_device_digit)
        || stem.strip_prefix("lpt").is_some_and(is_device_digit);
    if reserved {
        Err(Error::InvalidPath)
    } else {
        Ok(())
    }
}

pub(super) fn portable_fold(component: &str) -> String {
    let mut folded = String::with_capacity(component.len());
    for character in component.nfc() {
        match character {
            'I' | 'i' | '\u{130}' | '\u{131}' => folded.push('i'),
            _ => folded.extend(character.to_lowercase()),
        }
    }
    folded.nfc().collect()
}

pub(super) fn is_device_digit(value: &str) -> bool {
    matches!(
        value,
        "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "\u{b9}" | "\u{b2}" | "\u{b3}"
    )
}

pub(super) fn valid_raw_component(component: &[u8]) -> bool {
    // "." and ".." are not names, they are directions. A raw path that can
    // say either is a path that can leave the destination it was extracted
    // into, and the portable profile has refused them all along.
    //
    // The backslash goes with the slash for the same reason. A component is
    // a component on every host that extracts the package, and one holding
    // a separator stops being one the moment it lands on Windows. This
    // refuses a legal POSIX filename, which is the trade: the portable
    // profile is where such a name belongs.
    !component.is_empty()
        && component.len() <= 255
        && component != b"."
        && component != b".."
        && !component.contains(&0)
        && !component.contains(&b'/')
        && !component.contains(&b'\\')
}
