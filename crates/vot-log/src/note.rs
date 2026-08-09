//! Signed-note encoding and parsing.

use super::{BASE64, Checkpoint, Digest, Error, Hash, Sha256};
use base64::Engine as _;
use std::fmt::Write as _;

/// One signature line on a checkpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NoteSignature {
    pub name: String,
    pub key_hash: [u8; 4],
    pub signature: Vec<u8>,
}

/// A checkpoint with witness signatures. The log's own signature carries no
/// weight; what matters is how many independent witnesses signed the same head.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedCheckpoint {
    pub checkpoint: Checkpoint,
    pub signatures: Vec<NoteSignature>,
}

pub(super) const ED25519_NOTE_ALGORITHM: u8 = 0x01;
pub(super) const MAX_NOTE_BYTES: usize = 65_536;
pub(super) const MAX_NAME_BYTES: usize = 256;

/// Whether a name may appear in a signed note. Follows Go's signed-note rules:
/// non-empty, no plus sign, no Unicode whitespace.
pub(super) fn valid_note_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_BYTES
        && !name.contains('+')
        && !name.chars().any(char::is_whitespace)
}

/// Identifier a note signature carries so a verifier can select a key.
#[must_use]
pub fn note_key_hash(name: &str, public_key: &[u8; 32]) -> [u8; 4] {
    let mut hasher = Sha256::new();
    hasher.update(name.as_bytes());
    hasher.update(b"\n");
    hasher.update([ED25519_NOTE_ALGORITHM]);
    hasher.update(public_key);
    let digest: [u8; 32] = hasher.finalize().into();
    [digest[0], digest[1], digest[2], digest[3]]
}

pub(super) fn base64(bytes: &[u8]) -> String {
    BASE64.encode(bytes)
}

pub(super) fn unbase64(text: &str) -> Result<Vec<u8>, Error> {
    BASE64.decode(text).map_err(|_| Error::Malformed)
}

impl SignedCheckpoint {
    /// Renders the note: body, a blank line, then one line per signature.
    ///
    /// # Errors
    /// Rejects a malformed origin or signer name.
    pub fn to_note(&self) -> Result<String, Error> {
        let mut note = self.checkpoint.body()?;
        note.push('\n');
        for signature in &self.signatures {
            if !valid_note_name(&signature.name) {
                return Err(Error::Malformed);
            }
            let mut blob = signature.key_hash.to_vec();
            blob.extend_from_slice(&signature.signature);
            writeln!(note, "\u{2014} {} {}", signature.name, base64(&blob))
                .map_err(|_| Error::Malformed)?;
        }
        Ok(note)
    }

    /// Parses a note back into a checkpoint and its signatures.
    ///
    /// # Errors
    /// Rejects an oversized, misshapen, or non-numeric note.
    pub fn parse_note(note: &str) -> Result<Self, Error> {
        if note.len() > MAX_NOTE_BYTES {
            return Err(Error::Malformed);
        }
        let (body, signatures) = note.split_once("\n\n").ok_or(Error::Malformed)?;
        let mut lines = body.split('\n');
        let origin = lines.next().ok_or(Error::Malformed)?.to_owned();
        let size: usize = lines
            .next()
            .ok_or(Error::Malformed)?
            .parse()
            .map_err(|_| Error::Malformed)?;
        let root: Hash = unbase64(lines.next().ok_or(Error::Malformed)?)?
            .try_into()
            .map_err(|_| Error::Malformed)?;
        if lines.next().is_some() {
            return Err(Error::Malformed);
        }

        let mut parsed = Vec::new();
        for line in signatures.lines() {
            let rest = line.strip_prefix("\u{2014} ").ok_or(Error::Malformed)?;
            let (name, blob) = rest.split_once(' ').ok_or(Error::Malformed)?;
            let blob = unbase64(blob)?;
            if blob.len() < 4 {
                return Err(Error::Malformed);
            }
            let (key_hash, signature) = blob.split_at(4);
            parsed.push(NoteSignature {
                name: name.to_owned(),
                key_hash: key_hash.try_into().map_err(|_| Error::Malformed)?,
                signature: signature.to_vec(),
            });
        }
        let checkpoint = Checkpoint { origin, size, root };
        let rebuilt = Self {
            checkpoint,
            signatures: parsed,
        };
        if rebuilt.to_note()? != note {
            return Err(Error::Malformed);
        }
        Ok(rebuilt)
    }
}
