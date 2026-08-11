use vot_sdk::{Error as SdkError, ErrorCode as SdkErrorCode};
use wasm_bindgen::prelude::wasm_bindgen;

/// Stable failure category exposed to JavaScript without internal details.
#[wasm_bindgen]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorCode {
    InvalidInput,
    LimitExceeded,
    Unsupported,
    Malformed,
    IdentityMismatch,
    VerificationFailed,
    Incomplete,
    StateConflict,
    AuthenticationFailed,
    ResourceExhausted,
    Internal,
}

/// Structured JavaScript failure containing only a stable category.
#[wasm_bindgen]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VotError {
    code: ErrorCode,
}

#[wasm_bindgen]
impl VotError {
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        self.code
    }
}

impl From<SdkError> for VotError {
    fn from(error: SdkError) -> Self {
        Self::new(map_code(error.code()))
    }
}

impl From<ErrorCode> for VotError {
    fn from(code: ErrorCode) -> Self {
        Self::new(code)
    }
}

impl VotError {
    pub(crate) const fn new(code: ErrorCode) -> Self {
        Self { code }
    }
}

const fn map_code(code: SdkErrorCode) -> ErrorCode {
    match code {
        SdkErrorCode::InvalidInput => ErrorCode::InvalidInput,
        SdkErrorCode::LimitExceeded => ErrorCode::LimitExceeded,
        SdkErrorCode::Unsupported => ErrorCode::Unsupported,
        SdkErrorCode::Malformed => ErrorCode::Malformed,
        SdkErrorCode::IdentityMismatch => ErrorCode::IdentityMismatch,
        SdkErrorCode::VerificationFailed => ErrorCode::VerificationFailed,
        SdkErrorCode::Incomplete => ErrorCode::Incomplete,
        SdkErrorCode::StateConflict => ErrorCode::StateConflict,
        SdkErrorCode::AuthenticationFailed => ErrorCode::AuthenticationFailed,
        SdkErrorCode::ResourceExhausted => ErrorCode::ResourceExhausted,
        _ => ErrorCode::Internal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_sdk_error_has_one_stable_wasm_category() {
        let cases = [
            (SdkErrorCode::InvalidInput, ErrorCode::InvalidInput),
            (SdkErrorCode::LimitExceeded, ErrorCode::LimitExceeded),
            (SdkErrorCode::Unsupported, ErrorCode::Unsupported),
            (SdkErrorCode::Malformed, ErrorCode::Malformed),
            (SdkErrorCode::IdentityMismatch, ErrorCode::IdentityMismatch),
            (
                SdkErrorCode::VerificationFailed,
                ErrorCode::VerificationFailed,
            ),
            (SdkErrorCode::Incomplete, ErrorCode::Incomplete),
            (SdkErrorCode::StateConflict, ErrorCode::StateConflict),
            (
                SdkErrorCode::AuthenticationFailed,
                ErrorCode::AuthenticationFailed,
            ),
            (
                SdkErrorCode::ResourceExhausted,
                ErrorCode::ResourceExhausted,
            ),
            (SdkErrorCode::Internal, ErrorCode::Internal),
        ];
        for (sdk, expected) in cases {
            assert_eq!(map_code(sdk), expected);
            assert_eq!(VotError::new(expected).code(), expected);
        }
    }
}
