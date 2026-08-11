use vot_sdk::proof as sdk_proof;
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{ObjectId, VerifiedRange, VotError};

/// Validated static proof catalog header bound to an expected object.
#[wasm_bindgen]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogHeader {
    inner: sdk_proof::CatalogHeader,
}

#[wasm_bindgen]
impl CatalogHeader {
    #[wasm_bindgen(getter, js_name = objectId)]
    #[must_use]
    pub fn object_id(&self) -> ObjectId {
        ObjectId::from_sdk(self.inner.object_id().clone())
    }

    #[wasm_bindgen(getter, js_name = recordCount)]
    #[must_use]
    pub fn record_count(&self) -> u64 {
        self.inner.record_count()
    }

    #[wasm_bindgen(getter, js_name = catalogLength)]
    #[must_use]
    pub fn catalog_length(&self) -> u64 {
        self.inner.catalog_length()
    }

    #[wasm_bindgen(js_name = indexEntryOffset)]
    pub fn index_entry_offset(&self, ordinal: u64) -> Result<u64, VotError> {
        self.inner.index_entry_offset(ordinal).map_err(Into::into)
    }

    pub fn entry(&self, ordinal: u64, encoded: &[u8]) -> Result<CatalogEntry, VotError> {
        let entry = self.inner.decode_entry(ordinal, encoded)?;
        Ok(CatalogEntry {
            header: self.inner.clone(),
            ordinal,
            encoded: encoded.to_vec(),
            data_offset: entry.data_offset(),
            data_length: entry.data_length(),
            proof_offset: entry.proof_offset(),
            proof_length: entry.proof_length(),
        })
    }
}

/// One catalog entry whose offsets were checked against its header.
#[wasm_bindgen]
pub struct CatalogEntry {
    header: sdk_proof::CatalogHeader,
    ordinal: u64,
    encoded: Vec<u8>,
    data_offset: u64,
    data_length: u64,
    proof_offset: u64,
    proof_length: u64,
}

#[wasm_bindgen]
impl CatalogEntry {
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn ordinal(&self) -> u64 {
        self.ordinal
    }

    #[wasm_bindgen(getter, js_name = dataOffset)]
    #[must_use]
    pub fn data_offset(&self) -> u64 {
        self.data_offset
    }

    #[wasm_bindgen(getter, js_name = dataLength)]
    #[must_use]
    pub fn data_length(&self) -> u64 {
        self.data_length
    }

    #[wasm_bindgen(getter, js_name = proofOffset)]
    #[must_use]
    pub fn proof_offset(&self) -> u64 {
        self.proof_offset
    }

    #[wasm_bindgen(getter, js_name = proofLength)]
    #[must_use]
    pub fn proof_length(&self) -> u64 {
        self.proof_length
    }

    pub fn verify(&self, data: &[u8], proof: &[u8]) -> Result<VerifiedRange, VotError> {
        let entry = self.header.decode_entry(self.ordinal, &self.encoded)?;
        let verified = entry.verify(data, proof)?;
        Ok(VerifiedRange::from_verified(&verified))
    }
}

/// Decodes only the fixed-width header needed for random catalog access.
#[wasm_bindgen(js_name = decodeCatalogHeader)]
pub fn decode_catalog_header(
    encoded_header: &[u8],
    expected: &ObjectId,
) -> Result<CatalogHeader, VotError> {
    Ok(CatalogHeader {
        inner: sdk_proof::decode_header(encoded_header, &expected.inner)?,
    })
}

/// Validates one complete in-memory catalog before random access.
#[wasm_bindgen(js_name = validateCatalog)]
pub fn validate_catalog(
    encoded_catalog: &[u8],
    expected: &ObjectId,
) -> Result<CatalogHeader, VotError> {
    Ok(CatalogHeader {
        inner: sdk_proof::validate_catalog(encoded_catalog, &expected.inner)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ObjectBuilder, Suite};

    #[test]
    fn third_catalog_entry_reports_nontrivial_random_access_geometry() {
        let length = usize::try_from(sdk_proof::RANGE_LENGTH * 2 + 3).unwrap();
        let data = vec![7; length];
        let mut builder =
            ObjectBuilder::new(Suite::Blake3Bao64, Some(length as u64), length as u64).unwrap();
        builder.update(&data).unwrap();
        let prepared = builder.finish().unwrap();
        let catalog = prepared.encode_catalog(u64::MAX).unwrap();
        let header = validate_catalog(&catalog, &prepared.object_id()).unwrap();
        assert_eq!(header.record_count(), 3);
        let index = usize::try_from(header.index_entry_offset(2).unwrap()).unwrap();
        let entry = header
            .entry(2, &catalog[index..index + sdk_proof::INDEX_ENTRY_LENGTH])
            .unwrap();
        assert_eq!(entry.ordinal(), 2);
        assert_eq!(entry.data_offset(), sdk_proof::RANGE_LENGTH * 2);
        assert_eq!(entry.data_length(), 3);
        assert!(entry.proof_offset() > 1);
        assert!(entry.proof_length() > 1);
        let proof_start = usize::try_from(entry.proof_offset()).unwrap();
        let proof_end = proof_start + usize::try_from(entry.proof_length()).unwrap();
        assert_eq!(
            entry
                .verify(&data[length - 3..], &catalog[proof_start..proof_end],)
                .unwrap()
                .bytes(),
            data[length - 3..]
        );
    }
}
