use std::collections::BTreeMap;

use super::{Error, ErrorKind, GROUP, MAX_CAPTURE_GROUPS, ObjectId, Suite, invalid};

pub(super) const SNAPSHOT: u8 = 1;
pub(super) const SELECT: u8 = 2;
pub(super) const INVALIDATE: u8 = 3;
pub(super) const COMMIT: u8 = 4;
pub(super) const REUSE: u8 = 5;
const MAGIC: &[u8; 8] = b"VOTCAP01";
const GROUP_BYTES: usize = 88;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Group {
    pub offset: u64,
    pub length: u64,
    pub hash: [u8; 32],
    pub small_root: [u8; 32],
    pub generation: u64,
}

impl Group {
    pub fn from_bytes(
        suite: Suite,
        offset: u64,
        bytes: &[u8],
        generation: u64,
    ) -> Result<Self, Error> {
        let length = bytes.len() as u64;
        let end = offset.checked_add(length).ok_or_else(invalid)?;
        if length == 0 || length > GROUP || !offset.is_multiple_of(GROUP) {
            return Err(invalid());
        }
        let hashes =
            vot_sdk::object::proof_leaves_at(suite, offset, bytes, end).map_err(|_| invalid())?;
        let small_root = if offset == 0 {
            vot_verifier::root(suite, bytes).map_err(|_| invalid())?
        } else {
            [0; 32]
        };
        Ok(Self {
            offset,
            length,
            hash: hashes[0],
            small_root,
            generation,
        })
    }

    pub fn verify(&self, object: &ObjectId, proof: &[u8]) -> Result<(), Error> {
        if group_length(object.length, self.offset)? != self.length {
            return Err(invalid());
        }
        let valid = if object.length <= GROUP {
            proof.is_empty() && self.small_root == object.root
        } else if object.suite == 1 {
            vot_proof_blake3::verify_group_cvs(
                &object.root,
                object.length,
                self.offset,
                self.length,
                &[self.hash],
                proof,
            )
            .is_ok()
        } else {
            vot_proof_sha256::verify_piece_hashes(
                &object.root,
                object.length,
                self.offset,
                self.length,
                &[self.hash],
                proof,
            )
            .is_ok()
        };
        if valid {
            Ok(())
        } else {
            Err(Error::plain(ErrorKind::IdentityMismatch))
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(GROUP_BYTES);
        bytes.extend_from_slice(&self.offset.to_le_bytes());
        bytes.extend_from_slice(&self.length.to_le_bytes());
        bytes.extend_from_slice(&self.hash);
        bytes.extend_from_slice(&self.small_root);
        bytes.extend_from_slice(&self.generation.to_le_bytes());
        bytes
    }

    fn decode(bytes: &mut &[u8]) -> Result<Self, Error> {
        Ok(Self {
            offset: u64::from_le_bytes(take(bytes)?),
            length: u64::from_le_bytes(take(bytes)?),
            hash: take(bytes)?,
            small_root: take(bytes)?,
            generation: u64::from_le_bytes(take(bytes)?),
        })
    }

    fn validate(&self, state: &State) -> Result<(), Error> {
        let maximum = group_length(state.object.length, self.offset)?;
        if self.length == 0
            || self.length > maximum
            || self.generation > state.generation
            || (self.generation == state.generation && self.length != maximum)
            || (self.offset != 0 && self.small_root != [0; 32])
        {
            return Err(invalid());
        }
        Ok(())
    }
}

pub(super) struct State {
    pub binding: [u64; 4],
    pub limit: usize,
    pub object: ObjectId,
    pub generation: u64,
    pub sequence: u64,
    pub groups: BTreeMap<u64, Group>,
    pending: Option<u64>,
}

impl State {
    pub fn new(binding: [u64; 4], limit: usize, object: ObjectId) -> Result<Self, Error> {
        validate_object(&object)?;
        if limit == 0 || limit > MAX_CAPTURE_GROUPS {
            return Err(invalid());
        }
        Ok(Self {
            binding,
            limit,
            object,
            generation: 0,
            sequence: 0,
            groups: BTreeMap::new(),
            pending: None,
        })
    }

    pub fn snapshot(&self) -> Vec<u8> {
        let mut bytes = MAGIC.to_vec();
        for value in self.binding {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        bytes.extend_from_slice(&(self.limit as u64).to_le_bytes());
        bytes.extend_from_slice(&encode_object(&self.object));
        bytes.extend_from_slice(&self.generation.to_le_bytes());
        bytes.extend_from_slice(&self.pending.unwrap_or(u64::MAX).to_le_bytes());
        bytes.extend_from_slice(&(self.groups.len() as u64).to_le_bytes());
        for group in self.groups.values() {
            bytes.extend_from_slice(&group.encode());
        }
        bytes
    }

    pub fn restore(record: &vot_journal::Record) -> Result<Self, Error> {
        if record.state != SNAPSHOT || (!record.checkpoint && record.sequence != 0) {
            return Err(invalid());
        }
        let mut bytes = record.payload.as_slice();
        if take::<8>(&mut bytes)? != *MAGIC {
            return Err(invalid());
        }
        let mut binding = [0; 4];
        for value in &mut binding {
            *value = u64::from_le_bytes(take(&mut bytes)?);
        }
        let limit =
            usize::try_from(u64::from_le_bytes(take(&mut bytes)?)).map_err(|_| invalid())?;
        let object = decode_object(&mut bytes)?;
        let mut state = Self::new(binding, limit, object)?;
        state.sequence = record.sequence;
        state.generation = u64::from_le_bytes(take(&mut bytes)?);
        if state.generation > state.sequence {
            return Err(invalid());
        }
        let pending = u64::from_le_bytes(take(&mut bytes)?);
        if pending != u64::MAX {
            group_length(state.object.length, pending)?;
            state.pending = Some(pending);
        }
        let count =
            usize::try_from(u64::from_le_bytes(take(&mut bytes)?)).map_err(|_| invalid())?;
        if count > state.limit || bytes.len() != count * GROUP_BYTES {
            return Err(invalid());
        }
        for _ in 0..count {
            let group = Group::decode(&mut bytes)?;
            group.validate(&state)?;
            if state.pending == Some(group.offset)
                || state.groups.insert(group.offset, group).is_some()
            {
                return Err(invalid());
            }
        }
        Ok(state)
    }

    pub fn apply(&mut self, sequence: u64, kind: u8, mut payload: &[u8]) -> Result<(), Error> {
        if self.sequence.checked_add(1) != Some(sequence) {
            return Err(invalid());
        }
        match kind {
            SELECT => {
                let object = decode_object(&mut payload)?;
                exhausted(payload)?;
                if object.suite != self.object.suite {
                    return Err(invalid());
                }
                drop(self.groups.split_off(&object.length));
                if let Some((&offset, group)) = self.groups.last_key_value()
                    && group.length > object.length - offset
                {
                    self.groups.remove(&offset);
                }
                self.object = object;
                self.generation = sequence;
                self.pending = None;
            }
            INVALIDATE | REUSE => {
                let offset = u64::from_le_bytes(take(&mut payload)?);
                exhausted(payload)?;
                let length = group_length(self.object.length, offset)?;
                if kind == INVALIDATE {
                    self.groups.remove(&offset);
                    self.pending = Some(offset);
                } else {
                    let group = self.groups.get_mut(&offset).ok_or_else(invalid)?;
                    if group.length != length {
                        return Err(invalid());
                    }
                    group.generation = self.generation;
                    self.pending = None;
                }
            }
            COMMIT => {
                let group = Group::decode(&mut payload)?;
                exhausted(payload)?;
                group.validate(self)?;
                if self.pending != Some(group.offset)
                    || group.generation != self.generation
                    || self.groups.len() >= self.limit
                {
                    return Err(invalid());
                }
                self.groups.insert(group.offset, group);
                self.pending = None;
            }
            _ => return Err(invalid()),
        }
        self.sequence = sequence;
        Ok(())
    }

    pub fn covered_bytes(&self) -> u64 {
        // ponytail: progress scans at most 8,192 entries; keep a counter if polling dominates.
        self.groups
            .values()
            .filter(|group| group.generation == self.generation)
            .map(|group| group.length)
            .sum()
    }
}

pub(super) fn validate_object(object: &ObjectId) -> Result<Suite, Error> {
    let suite = Suite::try_from(object.suite).map_err(|_| invalid())?;
    if object.length > vot_sdk::object::MAX_OBJECT_LENGTH
        || (object.length == 0
            && object.root != vot_verifier::root(suite, &[]).map_err(|_| invalid())?)
    {
        return Err(invalid());
    }
    Ok(suite)
}

pub(super) fn group_length(length: u64, offset: u64) -> Result<u64, Error> {
    if offset >= length || !offset.is_multiple_of(GROUP) {
        return Err(invalid());
    }
    Ok((length - offset).min(GROUP))
}

pub(super) fn encode_object(object: &ObjectId) -> Vec<u8> {
    let mut bytes = object.suite.to_le_bytes().to_vec();
    bytes.extend_from_slice(&object.root);
    bytes.extend_from_slice(&object.length.to_le_bytes());
    bytes
}

fn decode_object(bytes: &mut &[u8]) -> Result<ObjectId, Error> {
    let object = ObjectId {
        suite: u16::from_le_bytes(take(bytes)?),
        root: take(bytes)?,
        length: u64::from_le_bytes(take(bytes)?),
    };
    validate_object(&object)?;
    Ok(object)
}

fn take<const N: usize>(bytes: &mut &[u8]) -> Result<[u8; N], Error> {
    let (field, rest) = bytes.split_at_checked(N).ok_or_else(invalid)?;
    *bytes = rest;
    Ok(field.try_into().expect("the field has its fixed width"))
}

fn exhausted(bytes: &[u8]) -> Result<(), Error> {
    if bytes.is_empty() {
        Ok(())
    } else {
        Err(invalid())
    }
}
