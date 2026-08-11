use std::panic::{RefUnwindSafe, UnwindSafe};

use super::*;

fn node(value: u8) -> ProofNode {
    [value; 32]
}

fn assert_auto_traits<T: Send + Sync + UnwindSafe + RefUnwindSafe>() {}

#[test]
fn new_and_default_are_empty() {
    for store in [MemoryNodeStorage::new(), MemoryNodeStorage::default()] {
        assert_eq!(store.len(), Ok(0));
        assert_eq!(store.is_empty(), Ok(true));
        assert_eq!(store.read(0), Err(StoreError::Corrupt));
        assert_eq!(store.read(u64::MAX), Err(StoreError::Corrupt));
    }
}

#[test]
fn successful_appends_add_one_ordered_ordinal() {
    let mut store = MemoryNodeStorage::new();
    for (ordinal, value) in [0x11, 0x22, 0x33].into_iter().enumerate() {
        let before = store.len().unwrap();
        assert_eq!(before, ordinal as u64);
        store.append(node(value)).unwrap();
        assert_eq!(store.is_empty(), Ok(false));
        assert_eq!(store.len(), Ok(before + 1));
        assert_eq!(store.read(before), Ok(node(value)));
    }

    assert_eq!(store.read(0), Ok(node(0x11)));
    assert_eq!(store.read(1), Ok(node(0x22)));
    assert_eq!(store.read(2), Ok(node(0x33)));
}

#[test]
fn reads_never_substitute_for_missing_ordinals() {
    let mut store = MemoryNodeStorage::new();
    store.append(node(0x41)).unwrap();
    store.append(node(0x42)).unwrap();

    assert_eq!(store.read(2), Err(StoreError::Corrupt));
    assert_eq!(store.read(3), Err(StoreError::Corrupt));
    assert_eq!(store.read(u64::MAX), Err(StoreError::Corrupt));
    assert_eq!(store.len(), Ok(2));
    assert_eq!(store.read(0), Ok(node(0x41)));
    assert_eq!(store.read(1), Ok(node(0x42)));
}

#[test]
fn trait_objects_preserve_order_and_exact_length() {
    let mut store: Box<dyn ProofNodeStorage> = Box::new(MemoryNodeStorage::new());
    assert_eq!(store.len(), Ok(0));
    store.append(node(7)).unwrap();
    store.append(node(9)).unwrap();
    assert_eq!(store.len(), Ok(2));
    assert_eq!(store.read(0), Ok(node(7)));
    assert_eq!(store.read(1), Ok(node(9)));
}

#[test]
fn memory_storage_and_trait_objects_keep_required_auto_traits() {
    assert_auto_traits::<MemoryNodeStorage>();
    assert_auto_traits::<Box<dyn ProofNodeStorage>>();
}

#[test]
fn store_errors_are_copyable_values() {
    for error in [
        StoreError::Capacity,
        StoreError::Corrupt,
        StoreError::Unavailable,
    ] {
        let copied = error;
        assert_eq!(copied, error);
    }
}
