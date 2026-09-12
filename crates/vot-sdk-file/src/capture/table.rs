use super::{Error, File, FileLocation, GROUP, Group, MAX_CAPTURE_GROUPS, invalid};
use super::{read_exact_at, write_all_at};
use vot_journal::{CRC32C_EMPTY, crc32c_update};

const SLOT: usize = 96;
const PAGE: usize = 512 * SLOT;
const DOMAIN: &[u8] = b"VOT capture group metadata v1";

pub(super) struct Table {
    pub file: File,
    pub location: FileLocation,
    page: Vec<u8>,
    page_at: Option<u64>,
}

impl Table {
    pub fn new(file: File, location: FileLocation) -> Self {
        Self {
            file,
            location,
            page: vec![0; PAGE],
            page_at: None,
        }
    }

    pub fn get(&mut self, offset: u64) -> Result<Option<Group>, Error> {
        let at = slot_offset(offset)?;
        let length = self.file.metadata().map_err(Error::io)?.len();
        if at >= length {
            return Ok(None);
        }
        if length - at < SLOT as u64 {
            return Err(invalid());
        }
        let page_at = page_offset(at);
        self.load(page_at, length)?;
        let start = usize::try_from(at - page_at).map_err(|_| invalid())?;
        decode(offset, &self.page[start..start + SLOT])
    }

    pub fn put(&mut self, offset: u64, group: Option<&Group>) -> Result<(), Error> {
        let at = slot_offset(offset)?;
        self.page_at = None;
        if group.is_none() && at >= self.file.metadata().map_err(Error::io)?.len() {
            return Ok(());
        }
        let bytes = encode(offset, group)?;
        write_all_at(&self.file, &bytes, at).map_err(Error::io)
    }

    pub fn select(&mut self, length: u64) -> Result<(), Error> {
        let end = length.div_ceil(GROUP) * SLOT as u64;
        let current = self.file.metadata().map_err(Error::io)?.len();
        self.page_at = None;
        self.file.set_len(current.min(end)).map_err(Error::io)?;
        if !length.is_multiple_of(GROUP) && current >= end {
            let offset = length / GROUP * GROUP;
            let mut bytes = [0; SLOT];
            read_exact_at(&self.file, &mut bytes, slot_offset(offset)?).map_err(Error::io)?;
            // A torn tail clear must be redone. SELECT retires its coverage;
            // later full afterimages restore any newer slot it removes.
            let stored_length =
                u64::from_le_bytes(bytes[8..16].try_into().expect("fixed length field"));
            if decode(offset, &bytes).is_err() || stored_length > length % GROUP {
                self.put(offset, None)?;
            }
        }
        Ok(())
    }

    pub fn extent(&self, maximum: u64) -> Result<u64, Error> {
        let length = self.file.metadata().map_err(Error::io)?.len();
        if !length.is_multiple_of(SLOT as u64) || length / SLOT as u64 > maximum {
            return Err(invalid());
        }
        Ok(length)
    }

    pub fn next(&mut self, cursor: &mut u64) -> Result<Option<Group>, Error> {
        let length = self.extent(MAX_CAPTURE_GROUPS)?;
        let mut remaining = length;
        while let Some(mut at) = scan_offset(*cursor, length) {
            remaining = remaining.checked_sub(SLOT as u64).ok_or_else(invalid)?;
            let page_at = page_offset(at);
            if self.page_at != Some(page_at) {
                let data =
                    vot_platform_fs::next_file_data_offset(&self.file, at).map_err(Error::io)?;
                let Some(slot) = next_slot(at, data, length)? else {
                    return Ok(None);
                };
                *cursor = slot;
                at = *cursor * SLOT as u64;
                self.load(page_offset(at), length)?;
            }
            let offset = *cursor * GROUP;
            *cursor = cursor.checked_add(1).ok_or_else(invalid)?;
            let start = usize::try_from(at % PAGE as u64).map_err(|_| invalid())?;
            if let Some(group) = decode(offset, &self.page[start..start + SLOT])? {
                return Ok(Some(group));
            }
        }
        Ok(None)
    }

    fn load(&mut self, at: u64, length: u64) -> Result<(), Error> {
        if self.page_at != Some(at) {
            self.page.fill(0);
            let count = usize::try_from((length - at).min(PAGE as u64)).map_err(|_| invalid())?;
            read_exact_at(&self.file, &mut self.page[..count], at).map_err(Error::io)?;
            self.page_at = Some(at);
        }
        Ok(())
    }
}

fn page_offset(at: u64) -> u64 {
    at / PAGE as u64 * PAGE as u64
}

fn scan_offset(cursor: u64, length: u64) -> Option<u64> {
    let at = cursor.checked_mul(SLOT as u64)?;
    (at < length).then_some(at)
}

fn next_slot(at: u64, data: Option<u64>, length: u64) -> Result<Option<u64>, Error> {
    let Some(data) = data else {
        return Ok(None);
    };
    if data < at || data >= length {
        return Err(invalid());
    }
    Ok(Some(data / SLOT as u64))
}

fn slot_offset(offset: u64) -> Result<u64, Error> {
    if !offset.is_multiple_of(GROUP) || offset / GROUP >= MAX_CAPTURE_GROUPS {
        return Err(invalid());
    }
    Ok(offset / GROUP * SLOT as u64)
}

fn checksum(offset: u64, bytes: &[u8]) -> u32 {
    let crc = crc32c_update(CRC32C_EMPTY, DOMAIN);
    let crc = crc32c_update(crc, &offset.to_le_bytes());
    crc32c_update(crc, bytes)
}

fn encode(offset: u64, group: Option<&Group>) -> Result<[u8; SLOT], Error> {
    let mut bytes = [0; SLOT];
    if let Some(group) = group {
        if group.offset != offset {
            return Err(invalid());
        }
        bytes[..88].copy_from_slice(&group.encode());
        let crc = checksum(offset, &bytes[..88]);
        bytes[88..92].copy_from_slice(&crc.to_le_bytes());
    }
    Ok(bytes)
}

fn decode(offset: u64, bytes: &[u8]) -> Result<Option<Group>, Error> {
    if bytes.iter().all(|byte| *byte == 0) {
        return Ok(None);
    }
    if bytes[92..] != [0; 4] || bytes[88..92] != checksum(offset, &bytes[..88]).to_le_bytes() {
        return Err(invalid());
    }
    let group = Group::decode(&mut &bytes[..88])?;
    if group.offset != offset || group.length == 0 || group.length > GROUP {
        return Err(invalid());
    }
    Ok(Some(group))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::{Suite, tests::Temp};
    use std::ffi::OsStr;
    use vot_platform_fs::Directory;

    fn table(dir: &Temp) -> Table {
        let directory = Directory::open(&dir.0).unwrap();
        let location = directory.entry(OsStr::new("groups")).unwrap();
        Table::new(location.create().unwrap(), location)
    }

    #[test]
    fn pages_bound_memory_across_large_and_sparse_group_sets() {
        let dir = Temp::new();
        let mut table = table(&dir);
        let mut group = Group::from_bytes(Suite::Blake3Bao64, 0, &[7; 17], 0).unwrap();
        assert!(table.get(0).unwrap().is_none());
        table.put(GROUP, None).unwrap();
        assert_eq!(table.file.metadata().unwrap().len(), 0);
        let mut page = vec![0; PAGE];
        for first in (0..16_385_u64).step_by(512) {
            let count = usize::try_from((16_385 - first).min(512)).unwrap();
            for index in 0..count {
                group.offset = (first + u64::try_from(index).unwrap()) * GROUP;
                page[index * SLOT..(index + 1) * SLOT]
                    .copy_from_slice(&encode(group.offset, Some(&group)).unwrap());
            }
            write_all_at(&table.file, &page[..count * SLOT], first * SLOT as u64).unwrap();
        }
        let mut cursor = 0;
        for index in 0..16_385 {
            let stored = table.next(&mut cursor).unwrap().unwrap();
            assert_eq!(stored.offset, index * GROUP);
            assert_eq!(stored.length, 17);
        }
        assert!(table.next(&mut cursor).unwrap().is_none());
        assert_eq!(table.page.len(), 49_152);
        assert_eq!(table.page.capacity(), 49_152);
        let last = 100_003 * GROUP;
        group.offset = last;
        table.put(last, Some(&group)).unwrap();
        assert_eq!(table.get(last).unwrap(), Some(group.clone()));
        group.generation = 9;
        table.put(last, Some(&group)).unwrap();
        assert_eq!(table.get(last).unwrap(), Some(group));
        assert_eq!(table.next(&mut cursor).unwrap().unwrap().offset, last);
        assert!(table.next(&mut cursor).unwrap().is_none());
        table.put(last, None).unwrap();
        assert!(table.get(last).unwrap().is_none());
        table.select(42 * GROUP + 9).unwrap();
        assert_eq!(table.file.metadata().unwrap().len(), 43 * SLOT as u64);
        assert!(table.get(42 * GROUP).unwrap().is_none());
        assert!(table.get(41 * GROUP).unwrap().is_some());
        table.select(44 * GROUP).unwrap();
        assert_eq!(table.file.metadata().unwrap().len(), 43 * SLOT as u64);
        table.select(0).unwrap();
        assert!(table.next(&mut 0).unwrap().is_none());
    }

    #[test]
    fn empty_allocated_pages_finish_scanning() {
        let dir = Temp::new();
        let mut table = table(&dir);
        write_all_at(&table.file, &[0; SLOT], 0).unwrap();
        assert!(table.get(0).unwrap().is_none());
        let mut cursor = 0;
        assert!(table.next(&mut cursor).unwrap().is_none());
        assert_eq!(cursor, 1);
        assert!(table.next(&mut cursor).unwrap().is_none());
        assert_eq!(cursor, 1);
    }

    #[test]
    fn every_torn_tail_clear_finishes_on_replay() {
        let dir = Temp::new();
        let mut table = table(&dir);
        let group = Group::from_bytes(
            Suite::Blake3Bao64,
            0,
            &vec![7; usize::try_from(GROUP).unwrap()],
            0,
        )
        .unwrap();
        let original = encode(0, Some(&group)).unwrap();
        for prefix in 0..=SLOT {
            write_all_at(&table.file, &original, 0).unwrap();
            write_all_at(&table.file, &vec![0; prefix], 0).unwrap();
            table.select(17).unwrap();
            assert!(table.get(0).unwrap().is_none(), "prefix={prefix}");
        }
    }

    #[test]
    fn sparse_hints_include_split_slots_and_refuse_invalid_offsets() {
        for (at, expected) in [
            (0, 0),
            (1, 0),
            (49_151, 0),
            (49_152, 49_152),
            (98_303, 49_152),
        ] {
            assert_eq!(page_offset(at), expected);
        }
        for (cursor, length, expected) in [
            (0, 0, None),
            (0, 96, Some(0)),
            (1, 96, None),
            (1, 192, Some(96)),
            (2, 192, None),
            (3, 192, None),
            (u64::MAX, u64::MAX, None),
        ] {
            assert_eq!(scan_offset(cursor, length), expected);
        }
        assert_eq!(next_slot(4032, Some(4096), 4224).unwrap(), Some(42));
        assert_eq!(next_slot(4032, Some(4032), 4224).unwrap(), Some(42));
        assert_eq!(next_slot(4032, Some(4223), 4224).unwrap(), Some(43));
        assert_eq!(next_slot(4032, None, 4224).unwrap(), None);
        assert!(next_slot(4032, Some(4031), 4224).is_err());
        assert!(next_slot(4032, Some(4224), 4224).is_err());
        assert!(next_slot(4032, Some(u64::MAX), 4224).is_err());
    }

    #[test]
    fn slots_refuse_relocation_corruption_and_partial_records() {
        let group = Group::from_bytes(Suite::Blake3Bao64, 0, &[7; 17], 0).unwrap();
        let bytes = encode(0, Some(&group)).unwrap();
        assert_eq!(decode(0, &bytes).unwrap(), Some(group.clone()));
        assert!(decode(GROUP, &bytes).is_err());
        assert!(encode(GROUP, Some(&group)).is_err());
        assert!(decode(0, &[0; SLOT]).unwrap().is_none());
        for index in 0..SLOT {
            let mut corrupt = bytes;
            corrupt[index] ^= 1;
            assert!(decode(0, &corrupt).is_err());
        }
        for (offset, length) in [(GROUP, 17), (0, 0), (0, GROUP + 1)] {
            let mut bad = group.clone();
            bad.offset = offset;
            bad.length = length;
            let mut raw = [0; SLOT];
            raw[..88].copy_from_slice(&bad.encode());
            let crc = checksum(0, &raw[..88]);
            raw[88..92].copy_from_slice(&crc.to_le_bytes());
            assert!(decode(0, &raw).is_err());
        }
        assert!(slot_offset(1).is_err());
        assert!(slot_offset(MAX_CAPTURE_GROUPS * GROUP).is_err());
        assert_eq!(
            slot_offset((MAX_CAPTURE_GROUPS - 1) * GROUP).unwrap(),
            (MAX_CAPTURE_GROUPS - 1) * SLOT as u64
        );
        let dir = Temp::new();
        let mut table = table(&dir);
        table.put(0, Some(&group)).unwrap();
        table.file.set_len(95).unwrap();
        assert!(table.get(0).is_err());
        assert!(table.next(&mut 0).is_err());
        table.put(0, Some(&group)).unwrap();
        assert!(table.extent(0).is_err());
        assert_eq!(table.extent(1).unwrap(), SLOT as u64);
        assert!(table.get(0).unwrap().is_some());
        let mut second = group;
        second.offset = GROUP;
        table.put(GROUP, Some(&second)).unwrap();
        table.file.set_len(191).unwrap();
        assert!(table.get(GROUP).is_err());
    }
}
