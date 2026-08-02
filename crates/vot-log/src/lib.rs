//! Append-only transparency log for receipt chain heads.
//!
//! A witnessed chain stops an issuer rewriting its own history. It does not
//! stop the issuer telling two counterparties two different histories for the
//! same object, because neither counterparty sees the other's copy. A log both
//! can read closes that gap: entries are append-only, and a consistency proof
//! between any two published tree heads shows nothing earlier was changed or
//! removed.
//!
//! The tree is RFC 6962. That specification is chosen because it is precise,
//! independently implemented many times, and its proofs are checkable by a
//! reader who has only a published head. Nothing here depends on who runs the
//! log: a customer, an auditor, a counterparty, or a third-party service can
//! all operate one, and a checkpoint carries however many witness signatures a
//! relying party demands.

#![forbid(unsafe_code)]

use std::fmt::Write as _;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

/// RFC 6962 prefixes keep a leaf hash from ever colliding with an interior one.
const LEAF_PREFIX: u8 = 0x00;
const NODE_PREFIX: u8 = 0x01;

/// Largest log this implementation will build, so a caller cannot ask for an
/// allocation it has not sized.
pub const MAX_ENTRIES: usize = 1 << 32;

pub type Hash = [u8; 32];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// An index or size falls outside the tree.
    OutOfRange,
    /// A proof did not reconstruct the head it claims.
    ProofInvalid,
    /// A checkpoint could not be parsed.
    Malformed,
    /// A signature did not verify, or there were too few witnesses.
    Unwitnessed,
    /// The log is at its size limit.
    Full,
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::OutOfRange => "index or size outside the tree",
            Self::ProofInvalid => "proof does not reconstruct the head",
            Self::Malformed => "checkpoint is malformed",
            Self::Unwitnessed => "signature failed or too few witnesses",
            Self::Full => "log is at its size limit",
        })
    }
}

#[must_use]
pub fn leaf_hash(entry: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([LEAF_PREFIX]);
    hasher.update(entry);
    hasher.finalize().into()
}

#[must_use]
fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([NODE_PREFIX]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Largest power of two strictly less than `n`, for `n > 1`.
fn split(n: usize) -> usize {
    debug_assert!(n > 1);
    1 << (usize::BITS - 1 - (n - 1).leading_zeros())
}

/// An append-only log holding one leaf hash per entry.
///
/// Proofs are recomputed from the leaves rather than cached. That is linear per
/// proof, which is the right trade while a log is small and is the reason
/// `MAX_ENTRIES` exists; a production operator would keep interior nodes.
#[derive(Clone, Debug, Default)]
pub struct MerkleLog {
    leaves: Vec<Hash>,
}

impl MerkleLog {
    #[must_use]
    pub const fn new() -> Self {
        Self { leaves: Vec::new() }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Appends one entry and returns its index.
    ///
    /// # Errors
    /// Rejects an append past the size limit.
    pub fn append(&mut self, entry: &[u8]) -> Result<usize, Error> {
        if self.leaves.len() >= MAX_ENTRIES {
            return Err(Error::Full);
        }
        self.leaves.push(leaf_hash(entry));
        Ok(self.leaves.len() - 1)
    }

    /// Head of the tree over the first `size` entries.
    ///
    /// # Errors
    /// Rejects a size beyond the log.
    pub fn root_at(&self, size: usize) -> Result<Hash, Error> {
        if size > self.leaves.len() {
            return Err(Error::OutOfRange);
        }
        Ok(root_of(&self.leaves[..size]))
    }

    /// Head of the whole log.
    ///
    /// # Errors
    /// Never fails; the signature matches `root_at`.
    pub fn root(&self) -> Result<Hash, Error> {
        self.root_at(self.leaves.len())
    }

    /// Proof that entry `index` is in the tree of `size` entries.
    ///
    /// # Errors
    /// Rejects an index at or beyond `size`, or a size beyond the log.
    pub fn inclusion_proof(&self, index: usize, size: usize) -> Result<Vec<Hash>, Error> {
        if size > self.leaves.len() || index >= size {
            return Err(Error::OutOfRange);
        }
        Ok(path(index, &self.leaves[..size]))
    }

    /// Proof that the tree of `old_size` entries is a prefix of `new_size`.
    ///
    /// # Errors
    /// Rejects a zero or shrinking range, or a size beyond the log.
    pub fn consistency_proof(&self, old_size: usize, new_size: usize) -> Result<Vec<Hash>, Error> {
        if old_size == 0 || old_size > new_size || new_size > self.leaves.len() {
            return Err(Error::OutOfRange);
        }
        Ok(subproof(old_size, &self.leaves[..new_size], true))
    }
}

fn root_of(leaves: &[Hash]) -> Hash {
    match leaves.len() {
        0 => Sha256::digest([]).into(),
        1 => leaves[0],
        n => {
            let k = split(n);
            node_hash(&root_of(&leaves[..k]), &root_of(&leaves[k..]))
        }
    }
}

fn path(index: usize, leaves: &[Hash]) -> Vec<Hash> {
    if leaves.len() <= 1 {
        return Vec::new();
    }
    let k = split(leaves.len());
    if index < k {
        let mut proof = path(index, &leaves[..k]);
        proof.push(root_of(&leaves[k..]));
        proof
    } else {
        let mut proof = path(index - k, &leaves[k..]);
        proof.push(root_of(&leaves[..k]));
        proof
    }
}

fn subproof(old_size: usize, leaves: &[Hash], is_prefix: bool) -> Vec<Hash> {
    if old_size == leaves.len() {
        // The old tree is the whole of this subtree. Its head is only needed
        // when this is not the caller's original left edge.
        return if is_prefix {
            Vec::new()
        } else {
            vec![root_of(leaves)]
        };
    }
    let k = split(leaves.len());
    if old_size <= k {
        let mut proof = subproof(old_size, &leaves[..k], is_prefix);
        proof.push(root_of(&leaves[k..]));
        proof
    } else {
        let mut proof = subproof(old_size - k, &leaves[k..], false);
        proof.push(root_of(&leaves[..k]));
        proof
    }
}

/// Splits an inclusion proof into the part inside the leaf's subtree and the
/// part along the tree's right border.
///
/// Deriving both lengths lets the verifier reject a proof of the wrong length
/// outright, rather than consuming what it is given.
fn decompose(index: usize, size: usize) -> (u32, u32) {
    let inner = usize::BITS - (index ^ (size - 1)).leading_zeros();
    let border = (index >> inner).count_ones();
    (inner, border)
}

/// Recomputes a head from a leaf hash and its inclusion proof.
///
/// # Errors
/// Rejects an out-of-range index, a proof of the wrong length, or one that does
/// not reconstruct `root`.
pub fn verify_inclusion(
    leaf: &Hash,
    index: usize,
    size: usize,
    proof: &[Hash],
    root: &Hash,
) -> Result<(), Error> {
    // A size is attacker supplied by way of a checkpoint, and a full-width
    // shift in the decomposition would panic rather than fail.
    if size == 0 || size > MAX_ENTRIES || index >= size {
        return Err(Error::OutOfRange);
    }
    let (inner, border) = decompose(index, size);
    if proof.len() != (inner + border) as usize {
        return Err(Error::ProofInvalid);
    }
    let inner = inner as usize;
    let mut computed = *leaf;
    for (level, sibling) in proof[..inner].iter().enumerate() {
        computed = if (index >> level) & 1 == 0 {
            node_hash(&computed, sibling)
        } else {
            node_hash(sibling, &computed)
        };
    }
    for sibling in &proof[inner..] {
        computed = node_hash(sibling, &computed);
    }
    if computed == *root {
        Ok(())
    } else {
        Err(Error::ProofInvalid)
    }
}

/// Checks that the tree of `old_size` entries is a prefix of the tree of
/// `new_size` entries.
///
/// This is the property that makes a log append-only to a reader: it shows
/// nothing before `old_size` was changed or removed.
///
/// # Errors
/// Rejects a malformed range, a proof of the wrong length, or one that does not
/// reconcile both heads.
pub fn verify_consistency(
    old_size: usize,
    old_root: &Hash,
    new_size: usize,
    new_root: &Hash,
    proof: &[Hash],
) -> Result<(), Error> {
    if old_size == 0 || old_size > new_size || new_size > MAX_ENTRIES {
        return Err(Error::OutOfRange);
    }
    if old_size == new_size {
        // Nothing appended: the heads must agree and the proof must be empty.
        // Accepting nodes here would let a prover pad a proof.
        return if proof.is_empty() && old_root == new_root {
            Ok(())
        } else {
            Err(Error::ProofInvalid)
        };
    }

    // Walk up from the old tree's right edge to the root of each tree at once.
    // Each step shifts right, so the bit width bounds every loop below. A
    // mutated condition then fails rather than hanging, and a hung mutant is
    // indistinguishable from an untested one.
    let mut node = old_size - 1;
    let mut last = new_size - 1;
    for _ in 0..usize::BITS {
        if node & 1 == 0 {
            break;
        }
        node >>= 1;
        last >>= 1;
    }

    let mut rest = proof;
    let (mut from_old, mut from_new) = if node > 0 {
        let (first, tail) = rest.split_first().ok_or(Error::ProofInvalid)?;
        rest = tail;
        (*first, *first)
    } else {
        // node == 0 means the old tree is a complete subtree, so its own head
        // is the starting node and the prover omits it.
        (*old_root, *old_root)
    };

    for _ in 0..usize::BITS {
        if node == 0 {
            break;
        }
        if node & 1 == 1 {
            let (sibling, tail) = rest.split_first().ok_or(Error::ProofInvalid)?;
            rest = tail;
            from_old = node_hash(sibling, &from_old);
            from_new = node_hash(sibling, &from_new);
        } else if node < last {
            let (sibling, tail) = rest.split_first().ok_or(Error::ProofInvalid)?;
            rest = tail;
            from_new = node_hash(&from_new, sibling);
        }
        node >>= 1;
        last >>= 1;
    }

    for _ in 0..usize::BITS {
        if last == 0 {
            break;
        }
        let (sibling, tail) = rest.split_first().ok_or(Error::ProofInvalid)?;
        rest = tail;
        from_new = node_hash(&from_new, sibling);
        last >>= 1;
    }

    if from_old == *old_root && from_new == *new_root && rest.is_empty() {
        Ok(())
    } else {
        Err(Error::ProofInvalid)
    }
}

/// A published tree head.
///
/// The serialisation is the signed-note format used by Go's checkpoint tooling
/// and by Sigstore, so an existing witness can co-sign a VOT checkpoint without
/// knowing anything about VOT.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Checkpoint {
    /// Names the log, so a signature over one log's head is not valid for
    /// another's.
    pub origin: String,
    pub size: usize,
    pub root: Hash,
}

/// One signature line on a checkpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NoteSignature {
    pub name: String,
    pub key_hash: [u8; 4],
    pub signature: Vec<u8>,
}

/// A checkpoint with the signatures gathered over it.
///
/// The log's own signature carries no weight on its own. What a relying party
/// checks is how many independent witnesses signed the same head.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedCheckpoint {
    pub checkpoint: Checkpoint,
    pub signatures: Vec<NoteSignature>,
}

const ED25519_NOTE_ALGORITHM: u8 = 0x01;
const MAX_NOTE_BYTES: usize = 65_536;
const MAX_NAME_BYTES: usize = 256;

/// Whether a name may appear in a signed note.
///
/// These are the rules Go's signed-note tooling applies: non-empty, no plus
/// sign, and no Unicode whitespace. Interoperating with that tooling is the
/// whole reason for this format, so a name it would reject must not be emitted
/// here either.
fn valid_note_name(name: &str) -> bool {
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

impl Checkpoint {
    /// The signed body: origin, size, base64 root, each on its own line.
    ///
    /// # Errors
    /// Rejects an origin that is empty, oversized, or contains a newline, since
    /// either would let one checkpoint be read as another.
    pub fn body(&self) -> Result<String, Error> {
        if self.origin.is_empty() || self.origin.len() > MAX_NAME_BYTES {
            return Err(Error::Malformed);
        }
        if self.origin.contains('\n') {
            return Err(Error::Malformed);
        }
        Ok(format!(
            "{}\n{}\n{}\n",
            self.origin,
            self.size,
            base64(&self.root)
        ))
    }
}

fn base64(bytes: &[u8]) -> String {
    BASE64.encode(bytes)
}

fn unbase64(text: &str) -> Result<Vec<u8>, Error> {
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
        // Round-trip so a note with a shape the encoder would never produce is
        // refused rather than silently normalised.
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

/// Adds a signature over a checkpoint body.
///
/// The same call serves the log operator and a witness. Nothing distinguishes
/// them in the format, which is deliberate: a witness is a key pair and a
/// clock, so any party can be one without the log granting it a role.
///
/// # Errors
/// Rejects a malformed origin or signer name.
pub fn sign_checkpoint(
    signed: &mut SignedCheckpoint,
    name: &str,
    key: &SigningKey,
) -> Result<(), Error> {
    if !valid_note_name(name) {
        return Err(Error::Malformed);
    }
    let body = signed.checkpoint.body()?;
    let public = key.verifying_key().to_bytes();
    signed.signatures.push(NoteSignature {
        name: name.to_owned(),
        key_hash: note_key_hash(name, &public),
        signature: key.sign(body.as_bytes()).to_bytes().to_vec(),
    });
    Ok(())
}

/// A key a relying party is willing to accept as a witness.
#[derive(Clone, Debug)]
pub struct WitnessKey {
    pub name: String,
    pub key: VerifyingKey,
}

/// Checks a checkpoint against a witness policy.
///
/// Returns the names that verified. A signature from a key the caller did not
/// list is ignored rather than rejected, so an extra witness is never a reason
/// to refuse an otherwise well-witnessed head.
///
/// # Errors
/// Rejects a malformed checkpoint, or one carrying fewer distinct accepted
/// witnesses than `required`.
pub fn verify_checkpoint(
    signed: &SignedCheckpoint,
    witnesses: &[WitnessKey],
    required: usize,
) -> Result<Vec<String>, Error> {
    let body = signed.checkpoint.body()?;
    // Keyed by public key, not by name. A policy that lists one key under two
    // names would otherwise let a single key pair satisfy a threshold of two,
    // which is not two independent witnesses.
    let mut accepted: Vec<(String, [u8; 32])> = Vec::new();
    for signature in &signed.signatures {
        let bytes: [u8; 64] = match signature.signature.as_slice().try_into() {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };
        for witness in witnesses {
            if witness.name != signature.name {
                continue;
            }
            // The key hash binds the name to the key, so a signature cannot be
            // moved to a signer whose name a verifier happens to accept.
            if note_key_hash(&witness.name, &witness.key.to_bytes()) != signature.key_hash {
                continue;
            }
            let public = witness.key.to_bytes();
            if witness
                .key
                .verify_strict(body.as_bytes(), &Signature::from_bytes(&bytes))
                .is_ok()
                && !accepted.iter().any(|(_, seen)| *seen == public)
            {
                accepted.push((witness.name.clone(), public));
            }
        }
    }
    if accepted.len() < required {
        return Err(Error::Unwitnessed);
    }
    Ok(accepted.into_iter().map(|(name, _)| name).collect())
}

#[cfg(test)]
mod tests {
    use super::{
        Checkpoint, Error, Hash, MAX_ENTRIES, MerkleLog, NoteSignature, SignedCheckpoint,
        WitnessKey, base64, decompose, leaf_hash, node_hash, note_key_hash, sign_checkpoint, split,
        unbase64, verify_checkpoint, verify_consistency, verify_inclusion,
    };
    use ed25519_dalek::SigningKey;

    fn log_of(entries: usize) -> MerkleLog {
        let mut log = MerkleLog::new();
        for index in 0..entries {
            log.append(&index.to_be_bytes()).unwrap();
        }
        log
    }

    fn hex(bytes: &Hash) -> String {
        use std::fmt::Write as _;
        bytes.iter().fold(String::new(), |mut text, byte| {
            let _ = write!(text, "{byte:02x}");
            text
        })
    }

    #[test]
    fn hashing_matches_rfc_6962() {
        // The empty tree is the hash of nothing, and prefixes separate a leaf
        // from an interior node so one can never be presented as the other.
        assert_eq!(
            hex(&MerkleLog::new().root().unwrap()),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&leaf_hash(b"")),
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
        );
        let one = log_of(1);
        assert_eq!(one.root().unwrap(), leaf_hash(&0_usize.to_be_bytes()));
        let two = log_of(2);
        assert_eq!(
            two.root().unwrap(),
            node_hash(
                &leaf_hash(&0_usize.to_be_bytes()),
                &leaf_hash(&1_usize.to_be_bytes())
            )
        );
    }

    #[test]
    fn every_inclusion_proof_verifies_for_every_size() {
        for size in 1..=64_usize {
            let log = log_of(size);
            let root = log.root().unwrap();
            for index in 0..size {
                let proof = log.inclusion_proof(index, size).unwrap();
                let leaf = leaf_hash(&index.to_be_bytes());
                verify_inclusion(&leaf, index, size, &proof, &root)
                    .unwrap_or_else(|error| panic!("size {size} index {index}: {error}"));
            }
        }
    }

    #[test]
    fn an_inclusion_proof_fails_for_anything_it_does_not_prove() {
        let size = 13;
        let log = log_of(size);
        let root = log.root().unwrap();
        let proof = log.inclusion_proof(6, size).unwrap();
        let leaf = leaf_hash(&6_usize.to_be_bytes());
        verify_inclusion(&leaf, 6, size, &proof, &root).unwrap();

        // A different leaf, index, root, or a tampered node.
        let other = leaf_hash(&7_usize.to_be_bytes());
        assert_eq!(
            verify_inclusion(&other, 6, size, &proof, &root),
            Err(Error::ProofInvalid)
        );
        assert!(verify_inclusion(&leaf, 5, size, &proof, &root).is_err());
        assert_eq!(
            verify_inclusion(&leaf, 6, size, &proof, &[9; 32]),
            Err(Error::ProofInvalid)
        );
        let mut tampered = proof.clone();
        tampered[0][0] ^= 1;
        assert_eq!(
            verify_inclusion(&leaf, 6, size, &tampered, &root),
            Err(Error::ProofInvalid)
        );

        // A padded or truncated proof is rejected on length, not consumed.
        let mut padded = proof.clone();
        padded.push([0; 32]);
        assert_eq!(
            verify_inclusion(&leaf, 6, size, &padded, &root),
            Err(Error::ProofInvalid)
        );
        let mut short = proof;
        short.pop();
        assert_eq!(
            verify_inclusion(&leaf, 6, size, &short, &root),
            Err(Error::ProofInvalid)
        );

        assert_eq!(
            verify_inclusion(&leaf, 0, 0, &[], &root),
            Err(Error::OutOfRange)
        );
        assert_eq!(
            verify_inclusion(&leaf, 13, size, &[], &root),
            Err(Error::OutOfRange)
        );
    }

    #[test]
    fn every_consistency_proof_verifies_for_every_pair_of_sizes() {
        for new_size in 1..=48_usize {
            let log = log_of(new_size);
            let new_root = log.root().unwrap();
            for old_size in 1..=new_size {
                let old_root = log.root_at(old_size).unwrap();
                let proof = log.consistency_proof(old_size, new_size).unwrap();
                verify_consistency(old_size, &old_root, new_size, &new_root, &proof)
                    .unwrap_or_else(|error| panic!("{old_size} -> {new_size}: {error}"));
            }
        }
    }

    #[test]
    fn a_log_that_rewrote_history_cannot_produce_a_consistency_proof() {
        // The property the whole design rests on. Two logs agree for ten
        // entries, then one of them changes an early entry.
        let honest = log_of(20);
        let mut forged = MerkleLog::new();
        for index in 0..20_usize {
            let entry = if index == 3 {
                b"rewritten".to_vec()
            } else {
                index.to_be_bytes().to_vec()
            };
            forged.append(&entry).unwrap();
        }
        let published = honest.root_at(10).unwrap();
        let forged_head = forged.root().unwrap();
        assert_ne!(forged.root_at(10).unwrap(), published);

        // No proof the forger can produce reconciles the head it already
        // published with the history it now claims.
        let proof = forged.consistency_proof(10, 20).unwrap();
        assert_eq!(
            verify_consistency(10, &published, 20, &forged_head, &proof),
            Err(Error::ProofInvalid)
        );
    }

    #[test]
    fn a_consistency_proof_fails_when_padded_truncated_or_tampered() {
        let log = log_of(21);
        let old_root = log.root_at(9).unwrap();
        let new_root = log.root().unwrap();
        let proof = log.consistency_proof(9, 21).unwrap();
        verify_consistency(9, &old_root, 21, &new_root, &proof).unwrap();

        let mut padded = proof.clone();
        padded.push([0; 32]);
        assert_eq!(
            verify_consistency(9, &old_root, 21, &new_root, &padded),
            Err(Error::ProofInvalid)
        );
        let mut short = proof.clone();
        short.pop();
        assert!(verify_consistency(9, &old_root, 21, &new_root, &short).is_err());
        let mut tampered = proof;
        tampered[0][0] ^= 1;
        assert_eq!(
            verify_consistency(9, &old_root, 21, &new_root, &tampered),
            Err(Error::ProofInvalid)
        );
    }

    #[test]
    fn an_unchanged_log_needs_an_empty_proof_and_matching_heads() {
        let log = log_of(7);
        let root = log.root().unwrap();
        verify_consistency(7, &root, 7, &root, &[]).unwrap();
        // A prover cannot pad an equal-size proof.
        assert_eq!(
            verify_consistency(7, &root, 7, &root, &[[0; 32]]),
            Err(Error::ProofInvalid)
        );
        assert_eq!(
            verify_consistency(7, &root, 7, &[1; 32], &[]),
            Err(Error::ProofInvalid)
        );
    }

    #[test]
    fn ranges_outside_the_log_are_refused() {
        let log = log_of(5);
        assert_eq!(log.root_at(6), Err(Error::OutOfRange));
        assert_eq!(log.inclusion_proof(5, 5), Err(Error::OutOfRange));
        assert_eq!(log.inclusion_proof(0, 6), Err(Error::OutOfRange));
        assert_eq!(log.consistency_proof(0, 5), Err(Error::OutOfRange));
        assert_eq!(log.consistency_proof(4, 3), Err(Error::OutOfRange));
        assert_eq!(log.consistency_proof(1, 6), Err(Error::OutOfRange));
        assert_eq!(
            verify_consistency(0, &[0; 32], 1, &[0; 32], &[]),
            Err(Error::OutOfRange)
        );
        assert_eq!(
            verify_consistency(2, &[0; 32], 1, &[0; 32], &[]),
            Err(Error::OutOfRange)
        );
    }

    #[test]
    fn appending_grows_the_log_and_reports_the_index() {
        let mut log = MerkleLog::new();
        assert!(log.is_empty());
        assert_eq!(log.append(b"a").unwrap(), 0);
        assert_eq!(log.append(b"b").unwrap(), 1);
        assert_eq!(log.len(), 2);
        assert!(!log.is_empty());
        // A head over a prefix is the head that prefix had at the time.
        assert_eq!(log.root_at(1).unwrap(), leaf_hash(b"a"));
        assert_eq!(MAX_ENTRIES, 1 << 32);
    }

    #[test]
    fn the_split_point_is_the_largest_power_of_two_below_the_size() {
        for (size, expected) in [(2, 1), (3, 2), (4, 2), (5, 4), (8, 4), (9, 8), (16, 8)] {
            assert_eq!(split(size), expected, "size {size}");
        }
    }

    #[test]
    fn proof_lengths_are_derived_not_assumed() {
        // Both halves of the decomposition matter: the inner path within the
        // leaf's subtree, and the border nodes above it.
        assert_eq!(decompose(0, 1), (0, 0));
        assert_eq!(decompose(0, 2), (1, 0));
        assert_eq!(decompose(2, 3), (0, 1));
        for size in 1..=32_usize {
            let log = log_of(size);
            for index in 0..size {
                let (inner, border) = decompose(index, size);
                assert_eq!(
                    log.inclusion_proof(index, size).unwrap().len(),
                    (inner + border) as usize,
                    "size {size} index {index}"
                );
            }
        }
    }

    fn checkpoint_of(log: &MerkleLog) -> SignedCheckpoint {
        SignedCheckpoint {
            checkpoint: Checkpoint {
                origin: "vot.example/log".to_owned(),
                size: log.len(),
                root: log.root().unwrap(),
            },
            signatures: Vec::new(),
        }
    }

    #[test]
    fn base64_round_trips_and_rejects_malformed_input() {
        for bytes in [&b""[..], b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar"] {
            if bytes.is_empty() {
                continue;
            }
            assert_eq!(unbase64(&base64(bytes)).unwrap(), bytes);
        }
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        for bad in ["A", "AAAAA", "A===", "Zg=A", "!!!!"] {
            assert_eq!(unbase64(bad), Err(Error::Malformed), "accepted {bad}");
        }
        // Empty decodes to nothing, which the note parser rejects downstream
        // because a root is 32 bytes and a signature blob is at least four.
        assert_eq!(unbase64("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn a_checkpoint_note_round_trips() {
        let log = log_of(11);
        let mut signed = checkpoint_of(&log);
        let operator = SigningKey::from_bytes(&[21; 32]);
        let witness = SigningKey::from_bytes(&[22; 32]);
        sign_checkpoint(&mut signed, "vot.example", &operator).unwrap();
        sign_checkpoint(&mut signed, "witness.example", &witness).unwrap();

        let note = signed.to_note().unwrap();
        assert!(note.starts_with("vot.example/log\n11\n"));
        assert_eq!(SignedCheckpoint::parse_note(&note).unwrap(), signed);
    }

    #[test]
    fn a_note_that_the_encoder_would_not_produce_is_refused() {
        let log = log_of(4);
        let mut signed = checkpoint_of(&log);
        sign_checkpoint(
            &mut signed,
            "vot.example",
            &SigningKey::from_bytes(&[21; 32]),
        )
        .unwrap();
        let note = signed.to_note().unwrap();

        for broken in [
            note.replace("\n\n", "\n"),
            note.replace("vot.example/log", ""),
            note.replace("4\n", "four\n"),
            format!("{note}trailing"),
            note.replacen('\u{2014}', "-", 1),
        ] {
            assert_eq!(
                SignedCheckpoint::parse_note(&broken),
                Err(Error::Malformed),
                "accepted {broken:?}"
            );
        }

        // An origin with a newline could be read as a different checkpoint.
        let mut sneaky = checkpoint_of(&log);
        sneaky.checkpoint.origin = "a\nb".to_owned();
        assert_eq!(sneaky.to_note(), Err(Error::Malformed));
        sneaky.checkpoint.origin = String::new();
        assert_eq!(sneaky.to_note(), Err(Error::Malformed));
    }

    #[test]
    fn a_head_counts_only_with_enough_distinct_witnesses() {
        let log = log_of(9);
        let mut signed = checkpoint_of(&log);
        let alpha = SigningKey::from_bytes(&[31; 32]);
        let beta = SigningKey::from_bytes(&[32; 32]);
        let witnesses = vec![
            WitnessKey {
                name: "alpha".to_owned(),
                key: alpha.verifying_key(),
            },
            WitnessKey {
                name: "beta".to_owned(),
                key: beta.verifying_key(),
            },
        ];

        assert_eq!(
            verify_checkpoint(&signed, &witnesses, 1),
            Err(Error::Unwitnessed)
        );
        sign_checkpoint(&mut signed, "alpha", &alpha).unwrap();
        assert_eq!(
            verify_checkpoint(&signed, &witnesses, 1).unwrap(),
            ["alpha"]
        );
        assert_eq!(
            verify_checkpoint(&signed, &witnesses, 2),
            Err(Error::Unwitnessed)
        );
        sign_checkpoint(&mut signed, "beta", &beta).unwrap();
        assert_eq!(
            verify_checkpoint(&signed, &witnesses, 2).unwrap(),
            ["alpha", "beta"]
        );

        // The same witness twice is still one witness.
        sign_checkpoint(&mut signed, "alpha", &alpha).unwrap();
        assert_eq!(
            verify_checkpoint(&signed, &witnesses, 3),
            Err(Error::Unwitnessed)
        );

        // And one key listed under two names is still one witness, or a policy
        // that aliases a key would silently halve the threshold it asked for.
        let aliased = vec![
            WitnessKey {
                name: "alpha".to_owned(),
                key: alpha.verifying_key(),
            },
            WitnessKey {
                name: "alpha-backup".to_owned(),
                key: alpha.verifying_key(),
            },
        ];
        let mut doubled = checkpoint_of(&log_of(9));
        sign_checkpoint(&mut doubled, "alpha", &alpha).unwrap();
        sign_checkpoint(&mut doubled, "alpha-backup", &alpha).unwrap();
        assert_eq!(verify_checkpoint(&doubled, &aliased, 1).unwrap().len(), 1);
        assert_eq!(
            verify_checkpoint(&doubled, &aliased, 2),
            Err(Error::Unwitnessed)
        );
    }

    #[test]
    fn a_signature_does_not_carry_to_another_head_name_or_key() {
        let alpha = SigningKey::from_bytes(&[31; 32]);
        let witnesses = vec![WitnessKey {
            name: "alpha".to_owned(),
            key: alpha.verifying_key(),
        }];
        let mut signed = checkpoint_of(&log_of(9));
        sign_checkpoint(&mut signed, "alpha", &alpha).unwrap();
        verify_checkpoint(&signed, &witnesses, 1).unwrap();

        // A different size, root, or origin is a different body.
        for mutated in [
            Checkpoint {
                size: 10,
                ..signed.checkpoint.clone()
            },
            Checkpoint {
                root: [7; 32],
                ..signed.checkpoint.clone()
            },
            Checkpoint {
                origin: "other.example/log".to_owned(),
                ..signed.checkpoint.clone()
            },
        ] {
            let moved = SignedCheckpoint {
                checkpoint: mutated,
                signatures: signed.signatures.clone(),
            };
            assert_eq!(
                verify_checkpoint(&moved, &witnesses, 1),
                Err(Error::Unwitnessed)
            );
        }

        // Relabelling a signature does not make it another witness's, because
        // the key hash binds the name to the key.
        let mut relabelled = signed.clone();
        relabelled.signatures[0].name = "beta".to_owned();
        let beta_listed = vec![WitnessKey {
            name: "beta".to_owned(),
            key: alpha.verifying_key(),
        }];
        assert_eq!(
            verify_checkpoint(&relabelled, &beta_listed, 1),
            Err(Error::Unwitnessed)
        );

        // An unknown signer is ignored, not fatal.
        let mut extra = signed;
        extra.signatures.push(NoteSignature {
            name: "stranger".to_owned(),
            key_hash: [0; 4],
            signature: vec![0; 64],
        });
        assert_eq!(verify_checkpoint(&extra, &witnesses, 1).unwrap(), ["alpha"]);
    }

    /// Builds a valid note of exactly `target` bytes by padding signer names.
    ///
    /// Each signature line costs the name length plus fourteen: the marker, two
    /// spaces, eight base64 characters for a four byte blob, and a newline.
    fn note_of_length(target: usize) -> String {
        const LINE_OVERHEAD: usize = 14;
        let mut signed = checkpoint_of(&log_of(3));
        let base = signed.to_note().unwrap().len();
        let mut remaining = target - base;
        let line = |name_len: usize, signed: &mut SignedCheckpoint| {
            signed.signatures.push(NoteSignature {
                name: "n".repeat(name_len),
                key_hash: [1, 2, 3, 4],
                signature: Vec::new(),
            });
        };
        while remaining > 256 + LINE_OVERHEAD {
            line(100, &mut signed);
            remaining -= 100 + LINE_OVERHEAD;
        }
        line(remaining - LINE_OVERHEAD, &mut signed);
        signed.to_note().unwrap()
    }

    #[test]
    fn an_absurd_tree_size_is_refused_rather_than_crashing() {
        // A size arrives inside a checkpoint, so it is attacker supplied. A
        // full width shift in the proof decomposition would panic.
        let root = [0; 32];
        assert_eq!(
            verify_inclusion(&root, 0, usize::MAX, &[], &root),
            Err(Error::OutOfRange)
        );
        assert_eq!(
            verify_inclusion(&root, 0, MAX_ENTRIES + 1, &[], &root),
            Err(Error::OutOfRange)
        );
        assert_eq!(
            verify_consistency(1, &root, usize::MAX, &root, &[]),
            Err(Error::OutOfRange)
        );

        // The limit itself is allowed through, and then fails on proof length
        // rather than range. Testing only past the limit would not observe
        // where the limit is.
        assert_eq!(
            verify_inclusion(&root, 0, MAX_ENTRIES, &[], &root),
            Err(Error::ProofInvalid)
        );
        assert_eq!(
            verify_consistency(1, &root, MAX_ENTRIES, &root, &[]),
            Err(Error::ProofInvalid)
        );
        // And a note can carry such a size, so the two must agree.
        let mut signed = checkpoint_of(&log_of(2));
        signed.checkpoint.size = usize::MAX;
        let note = signed.to_note().unwrap();
        let parsed = SignedCheckpoint::parse_note(&note).unwrap();
        assert_eq!(
            verify_inclusion(&root, 0, parsed.checkpoint.size, &[], &root),
            Err(Error::OutOfRange)
        );
    }

    #[test]
    fn signer_names_follow_the_signed_note_rules() {
        // Go's tooling rejects a plus sign and any Unicode whitespace. Emitting
        // a name it would reject defeats the reason for using this format.
        let mut signed = checkpoint_of(&log_of(3));
        let key = SigningKey::from_bytes(&[81; 32]);
        for bad in [
            "",
            "has space",
            "has\nnewline",
            "has\ttab",
            "has\rreturn",
            "has+plus",
            "has\u{00a0}nbsp",
            "has\u{2003}emspace",
        ] {
            assert_eq!(
                sign_checkpoint(&mut signed, bad, &key),
                Err(Error::Malformed),
                "accepted {bad:?}"
            );
        }
        for good in ["vot.example", "witness-1", "a.b/c", "\u{00e9}quipe"] {
            assert!(sign_checkpoint(&mut signed, good, &key).is_ok(), "{good}");
        }
        // to_note applies the same rules, not a weaker set.
        signed.signatures[0].name = "bad+name".to_owned();
        assert_eq!(signed.to_note(), Err(Error::Malformed));
    }

    #[test]
    fn every_error_says_what_went_wrong() {
        for (error, expected) in [
            (Error::OutOfRange, "index or size outside the tree"),
            (Error::ProofInvalid, "proof does not reconstruct the head"),
            (Error::Malformed, "checkpoint is malformed"),
            (Error::Unwitnessed, "signature failed or too few witnesses"),
            (Error::Full, "log is at its size limit"),
        ] {
            assert_eq!(error.to_string(), expected);
        }
    }

    #[test]
    fn note_and_name_limits_are_checked_at_their_exact_edges() {
        let log = log_of(2);
        let mut signed = checkpoint_of(&log);

        // Origin: 256 bytes is allowed, 257 is not.
        signed.checkpoint.origin = "o".repeat(256);
        assert!(signed.checkpoint.body().is_ok());
        signed.checkpoint.origin = "o".repeat(257);
        assert_eq!(signed.checkpoint.body(), Err(Error::Malformed));
        signed.checkpoint.origin = "vot.example/log".to_owned();

        // Signer name: the same edge, checked when the note is rendered.
        let key = SigningKey::from_bytes(&[61; 32]);
        sign_checkpoint(&mut signed, "ok", &key).unwrap();
        signed.signatures[0].name = "n".repeat(256);
        assert!(signed.to_note().is_ok());
        signed.signatures[0].name = "n".repeat(257);
        assert_eq!(signed.to_note(), Err(Error::Malformed));
        signed.signatures[0].name = String::new();
        assert_eq!(signed.to_note(), Err(Error::Malformed));

        // A well formed note at the exact ceiling parses, and the same note one
        // byte longer is refused. Testing the limit with a note that is
        // malformed anyway would not observe the limit at all.
        assert_eq!(
            note_of_length(super::MAX_NOTE_BYTES).len(),
            super::MAX_NOTE_BYTES
        );
        SignedCheckpoint::parse_note(&note_of_length(super::MAX_NOTE_BYTES)).unwrap();
        assert_eq!(
            SignedCheckpoint::parse_note(&note_of_length(super::MAX_NOTE_BYTES + 1)),
            Err(Error::Malformed)
        );
    }

    #[test]
    fn a_signature_blob_shorter_than_its_key_hash_is_refused() {
        let log = log_of(2);
        let mut signed = checkpoint_of(&log);
        sign_checkpoint(&mut signed, "alpha", &SigningKey::from_bytes(&[71; 32])).unwrap();
        let note = signed.to_note().unwrap();
        let line = note.lines().last().unwrap();
        let blob = line.rsplit(' ').next().unwrap();

        // Four bytes is exactly the key hash and nothing else, which parses.
        let four = note.replace(blob, &base64(&[1, 2, 3, 4]));
        let parsed = SignedCheckpoint::parse_note(&four).unwrap();
        assert!(parsed.signatures[0].signature.is_empty());

        // Three bytes cannot even carry the key hash.
        let three = note.replace(blob, &base64(&[1, 2, 3]));
        assert_eq!(SignedCheckpoint::parse_note(&three), Err(Error::Malformed));
    }

    #[test]
    fn a_key_hash_binds_the_name_to_the_key() {
        let key = SigningKey::from_bytes(&[41; 32]).verifying_key().to_bytes();
        let other = SigningKey::from_bytes(&[42; 32]).verifying_key().to_bytes();
        assert_ne!(note_key_hash("a", &key), note_key_hash("b", &key));
        assert_ne!(note_key_hash("a", &key), note_key_hash("a", &other));
        assert_eq!(note_key_hash("a", &key), note_key_hash("a", &key));
    }

    #[test]
    fn a_signer_name_cannot_break_the_note_shape() {
        let mut signed = checkpoint_of(&log_of(3));
        let key = SigningKey::from_bytes(&[51; 32]);
        for bad in ["", "has space", "has\nnewline"] {
            assert_eq!(
                sign_checkpoint(&mut signed, bad, &key),
                Err(Error::Malformed)
            );
        }
        assert!(sign_checkpoint(&mut signed, &"n".repeat(256), &key).is_ok());
        assert_eq!(
            sign_checkpoint(&mut signed, &"n".repeat(257), &key),
            Err(Error::Malformed)
        );
    }
}
