use std::fmt;

/// Stable classification for SDK failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ErrorCode {
    InvalidInput,
    LimitExceeded,
    Unsupported,
    Malformed,
    IdentityMismatch,
    VerificationFailed,
    Incomplete,
    StateConflict,
    /// The operation collides with work still in flight; retry once that
    /// work settles.
    RangeInFlight,
    AuthenticationFailed,
    ResourceExhausted,
    Internal,
}

/// Opaque SDK failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Error {
    code: ErrorCode,
}

impl Error {
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        self.code
    }

    pub(crate) const fn new(code: ErrorCode) -> Self {
        Self { code }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "VOT SDK error: {:?}", self.code)
    }
}

impl std::error::Error for Error {}

pub(crate) const fn coverage(error: vot_coverage::Error) -> Error {
    let code = match error {
        vot_coverage::Error::EmptyRange => ErrorCode::InvalidInput,
        vot_coverage::Error::LengthExceeded => ErrorCode::LimitExceeded,
        vot_coverage::Error::PartialOverlap => ErrorCode::StateConflict,
        vot_coverage::Error::ReservedOverlap => ErrorCode::RangeInFlight,
        vot_coverage::Error::FragmentsExhausted => ErrorCode::ResourceExhausted,
    };
    Error::new(code)
}

pub(crate) fn object(error: vot_object::Error) -> Error {
    let code = match error {
        vot_object::Error::ExpectedLengthOutOfRange | vot_object::Error::InvalidRange => {
            ErrorCode::InvalidInput
        }
        vot_object::Error::LengthOverflow | vot_object::Error::LengthExceeded => {
            ErrorCode::LimitExceeded
        }
        vot_object::Error::LengthMismatch => ErrorCode::Incomplete,
        vot_object::Error::Verifier(_) => ErrorCode::VerificationFailed,
        vot_object::Error::Storage(_) | vot_object::Error::Proof => ErrorCode::Internal,
    };
    Error::new(code)
}

pub(crate) fn package(error: vot_package::Error) -> Error {
    let code = match error {
        vot_package::Error::InvalidPath => ErrorCode::InvalidInput,
        vot_package::Error::InvalidBundle => ErrorCode::Malformed,
        vot_package::Error::RootMismatch => ErrorCode::IdentityMismatch,
        vot_package::Error::Verifier(_) => ErrorCode::VerificationFailed,
    };
    Error::new(code)
}

pub(crate) fn proof(error: vot_proof_catalog::Error) -> Error {
    let code = match error {
        vot_proof_catalog::Error::CatalogUnavailable => ErrorCode::Incomplete,
        vot_proof_catalog::Error::IdentityMismatch => ErrorCode::IdentityMismatch,
        vot_proof_catalog::Error::MalformedCatalog | vot_proof_catalog::Error::RecordOutOfRange => {
            ErrorCode::Malformed
        }
        vot_proof_catalog::Error::UnsupportedCatalog => ErrorCode::Unsupported,
        vot_proof_catalog::Error::ProofInvalid => ErrorCode::VerificationFailed,
        vot_proof_catalog::Error::AllocationFailed => ErrorCode::ResourceExhausted,
        vot_proof_catalog::Error::ProofGeneration => ErrorCode::Internal,
    };
    Error::new(code)
}

pub(crate) fn verify(error: vot_verified_range::Error) -> Error {
    let code = match error {
        vot_verified_range::Error::UnknownSuite
        | vot_verified_range::Error::UnsupportedCompression => ErrorCode::Unsupported,
        vot_verified_range::Error::RecordTooLarge | vot_verified_range::Error::LengthExceeded => {
            ErrorCode::LimitExceeded
        }
        vot_verified_range::Error::LengthMismatch => ErrorCode::Malformed,
        vot_verified_range::Error::ProofInvalid => ErrorCode::VerificationFailed,
    };
    Error::new(code)
}

pub(crate) fn resume_run(error: vot_resume_core::units::RunError) -> Error {
    let code = match error {
        vot_resume_core::units::RunError::EmptyRun
        | vot_resume_core::units::RunError::EndOverflow => ErrorCode::InvalidInput,
        vot_resume_core::units::RunError::TooManyRuns => ErrorCode::LimitExceeded,
    };
    Error::new(code)
}

pub(crate) fn resume(error: vot_resume_core::Error) -> Error {
    let code = match error {
        vot_resume_core::Error::InvalidConfiguration | vot_resume_core::Error::InvalidUnit => {
            ErrorCode::InvalidInput
        }
        vot_resume_core::Error::InvalidCheckpoint => ErrorCode::Malformed,
        vot_resume_core::Error::CheckpointGenerationExhausted => ErrorCode::LimitExceeded,
        vot_resume_core::Error::UnitAlreadyActive
        | vot_resume_core::Error::UnitNotActive
        | vot_resume_core::Error::CheckpointRequired
        | vot_resume_core::Error::StaleCheckpointPlan => ErrorCode::StateConflict,
    };
    Error::new(code)
}

pub(crate) fn receipt(error: vot_receipt::Error) -> Error {
    let code = match error {
        vot_receipt::Error::InvalidKey
        | vot_receipt::Error::Authentication
        | vot_receipt::Error::UnexpectedScheme => ErrorCode::AuthenticationFailed,
        vot_receipt::Error::TooLarge => ErrorCode::LimitExceeded,
        vot_receipt::Error::InvalidSuite => ErrorCode::Unsupported,
        vot_receipt::Error::InvalidKeyId
        | vot_receipt::Error::InvalidTimestamp
        | vot_receipt::Error::InvalidFlags
        | vot_receipt::Error::InvalidClockSource
        | vot_receipt::Error::InvalidProvider
        | vot_receipt::Error::InvalidSubjectLength
        | vot_receipt::Error::InvalidSequence
        | vot_receipt::Error::InvalidEncoding
        | vot_receipt::Error::NonCanonical => ErrorCode::Malformed,
        vot_receipt::Error::EmptyChain => ErrorCode::InvalidInput,
        vot_receipt::Error::WitnessHeadMismatch
        | vot_receipt::Error::ChainBroken
        | vot_receipt::Error::ChainSubjectMismatch
        | vot_receipt::Error::ChainIssuerMismatch
        | vot_receipt::Error::ChainScopeMismatch
        | vot_receipt::Error::AssuranceDidNotAdvance
        | vot_receipt::Error::PredecessorTooWeak
        | vot_receipt::Error::PredecessorNotObserved => ErrorCode::VerificationFailed,
    };
    Error::new(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opaque_errors_keep_stable_public_classifications() {
        assert_eq!(
            coverage(vot_coverage::Error::EmptyRange).code(),
            ErrorCode::InvalidInput
        );
        assert_eq!(
            coverage(vot_coverage::Error::LengthExceeded).code(),
            ErrorCode::LimitExceeded
        );
        assert_eq!(
            coverage(vot_coverage::Error::PartialOverlap).code(),
            ErrorCode::StateConflict
        );
        assert_eq!(
            coverage(vot_coverage::Error::ReservedOverlap).code(),
            ErrorCode::RangeInFlight
        );
        assert_eq!(
            coverage(vot_coverage::Error::FragmentsExhausted).code(),
            ErrorCode::ResourceExhausted
        );
        assert_eq!(
            object(vot_object::Error::InvalidRange).code(),
            ErrorCode::InvalidInput
        );
        assert_eq!(
            package(vot_package::Error::RootMismatch).code(),
            ErrorCode::IdentityMismatch
        );
        assert_eq!(
            proof(vot_proof_catalog::Error::AllocationFailed).code(),
            ErrorCode::ResourceExhausted
        );
        assert_eq!(
            verify(vot_verified_range::Error::ProofInvalid).code(),
            ErrorCode::VerificationFailed
        );
        assert_eq!(
            resume_run(vot_resume_core::units::RunError::TooManyRuns).code(),
            ErrorCode::LimitExceeded
        );
        assert_eq!(
            resume(vot_resume_core::Error::StaleCheckpointPlan).code(),
            ErrorCode::StateConflict
        );
        assert_eq!(
            receipt(vot_receipt::Error::Authentication).code(),
            ErrorCode::AuthenticationFailed
        );
        assert_eq!(
            Error::new(ErrorCode::Incomplete).to_string(),
            "VOT SDK error: Incomplete"
        );
    }
}
