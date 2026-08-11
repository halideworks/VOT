//! Coverage-guided static proof catalog target.

#![no_main]

use cap::Cap;
use std::alloc::System;

use vot_proof_catalog_fuzz_driver::{ALLOCATION_LIMIT, MAX_INPUT, exercise};

#[global_allocator]
static ALLOCATOR: Cap<System> = Cap::new(System, ALLOCATION_LIMIT);

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT {
        return;
    }
    exercise(data);
});
