//! Coverage-guided retained proof-store target.

#![no_main]

use std::alloc::System;

use cap::Cap;
use vot_retained_proof_store_fuzz_driver::{ALLOCATION_LIMIT, MAX_INPUT, exercise};

#[global_allocator]
static ALLOCATOR: Cap<System> = Cap::new(System, ALLOCATION_LIMIT);

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT {
        return;
    }
    exercise(data);
});
