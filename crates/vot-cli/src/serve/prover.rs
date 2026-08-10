//! The prover layer over precomputed hashes.

use super::{Error, GROUP_SIZE, Suite};

/// The chaining-value layer a range is proved from without the object.
pub(crate) enum ProverLayer {
    Blake3(vot_proof_blake3::GroupCvs),
    Sha256(vot_proof_sha256::PieceHashes),
}

impl ProverLayer {
    pub(crate) fn empty(suite: Suite) -> Self {
        match suite {
            Suite::Blake3Bao64 => Self::Blake3(vot_proof_blake3::GroupCvs::new()),
            Suite::Sha256Bep52 => Self::Sha256(vot_proof_sha256::PieceHashes::new()),
        }
    }

    pub(crate) fn push(&mut self, group: &[u8]) -> Result<(), Error> {
        match self {
            Self::Blake3(cvs) => cvs.push(group).map_err(|_| Error::Proof),
            Self::Sha256(pieces) => pieces.push(group).map_err(|_| Error::Proof),
        }
    }

    /// Whether the bytes read back match what the layer was built from.
    ///
    /// The cover starts on a group boundary; the first group is at
    /// `covered_offset / GROUP_SIZE`.
    pub(crate) fn holds(&self, covered_offset: u64, plaintext: &[u8]) -> bool {
        if covered_offset % GROUP_SIZE as u64 != 0 {
            return false;
        }
        let Ok(first) = usize::try_from(covered_offset / GROUP_SIZE as u64) else {
            return false;
        };
        plaintext
            .chunks(GROUP_SIZE)
            .enumerate()
            .all(|(offset, group)| match first.checked_add(offset) {
                Some(index) => match self {
                    Self::Blake3(cvs) => cvs.holds(index, group),
                    Self::Sha256(pieces) => pieces.holds(index, group),
                },
                None => false,
            })
    }

    /// Proves a range, returning the group-aligned cover it is proved under.
    pub(crate) fn prove(&self, offset: u64, length: u64) -> Result<(u64, u64, Vec<u8>), Error> {
        match self {
            Self::Blake3(cvs) => vot_proof_blake3::prove_with(cvs, offset, length)
                .map(|cover| (cover.covered_offset, cover.covered_length, cover.proof))
                .map_err(|_| Error::Proof),
            Self::Sha256(pieces) => vot_proof_sha256::prove_with(pieces, offset, length)
                .map(|cover| (cover.covered_offset, cover.covered_length, cover.proof))
                .map_err(|_| Error::Proof),
        }
    }
}
