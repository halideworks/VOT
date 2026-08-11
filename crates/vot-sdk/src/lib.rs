//! Stable, pure facade for constructing and consuming VOT evidence.

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc, clippy::module_name_repetitions)]

mod error;

pub mod coverage;
pub mod object;
pub mod package;
pub mod proof;
pub mod receipt;
pub mod resume;
pub mod verify;

pub use error::{Error, ErrorCode};
