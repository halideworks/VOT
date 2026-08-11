//! Predecessor-chain verification.

use super::{
    AssuranceLevel, AuthenticatedReceipt, Error, Receipt, SubjectKind, model_assurance,
    required_predecessor,
};

/// The tuple that identifies what a receipt is about.
pub(super) fn subject_identity(receipt: &Receipt) -> (SubjectKind, u16, [u8; 32], u64) {
    (
        receipt.subject_kind,
        receipt.suite_id,
        receipt.subject_digest,
        receipt.subject_length,
    )
}

/// A receipt whose authenticator this process checked.
///
/// The only way to hold one is to have verified it, which is what makes a
/// chain of them evidence. `AuthenticatedReceipt` names a decoded envelope
/// carrying an authenticator; it says nothing about whether the authenticator
/// is good. There is no constructor and no deserialization: a persisted
/// receipt is decoded and verified again.
#[derive(Clone, Debug)]
pub struct VerifiedReceipt {
    pub(super) authenticated: AuthenticatedReceipt,
    pub(super) by: VerifiedBy,
}

/// What actually checked a receipt, as opposed to the `key_id` label the
/// receipt carries about itself.
///
/// A chain is scoped to one of these. The label cannot do that job: two keys
/// may share one, and a chain mixing schemes would let an entry the reader
/// could have minted sit inside a record presented as third-party evidence.
/// That is the rule [`crate::verify_witness`] already applies to a witness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VerifiedBy {
    /// The public key the signature verified under, so two keys sharing a
    /// label are two issuers.
    Ed25519(Box<[u8; 32]>),
    /// A shared secret. Whoever can check it can mint it, so a chain of these
    /// is one domain's own record rather than evidence for anybody else.
    HmacSha256,
}

impl VerifiedReceipt {
    #[must_use]
    pub const fn receipt(&self) -> &Receipt {
        &self.authenticated.receipt
    }

    #[must_use]
    pub const fn authenticated(&self) -> &AuthenticatedReceipt {
        &self.authenticated
    }

    /// What actually checked this receipt. A chain is scoped to one of these.
    #[must_use]
    pub const fn verified_by(&self) -> &VerifiedBy {
        &self.by
    }
}

/// What one issuer's observations of one object must agree about.
pub(super) fn chain_scope(receipt: &Receipt) -> (u16, [u16; 3], [u8; 16], [u8; 16]) {
    (
        receipt.provider,
        receipt.provider_version,
        receipt.session_id,
        receipt.incarnation_id,
    )
}

/// Checks that a sequence of verified observations forms one unbroken chain.
///
/// Every entry must link to its predecessor's envelope digest, carry the same
/// subject, advance the issuer sequence, and come from the same issuer key,
/// provider, session, and incarnation. The first entry must not link.
///
/// Assurance advances at every step, and a `Published` observation must name
/// exactly the predecessor its profile requires, from the table
/// `vot_commit_model` holds the machine to, and an earlier entry must have
/// observed it. The field alone would only say the receipt agrees with
/// itself.
///
/// The elements are `VerifiedReceipt` rather than `AuthenticatedReceipt`
/// because an unbroken chain of forgeries is not evidence of anything, and a
/// caller that has to remember to check each one separately will one day
/// forget.
///
/// # Errors
/// Reports the first break.
pub fn verify_chain(chain: &[VerifiedReceipt]) -> Result<(), Error> {
    let Some(first) = chain.first() else {
        return Err(Error::EmptyChain);
    };
    if first.receipt().previous.is_some() {
        return Err(Error::ChainBroken);
    }
    // Object identity is the suite, the root, and the length. Identical digest
    // bytes under different suites are different objects, so leaving the suite
    // out would let a chain mix two of them.
    let subject = subject_identity(first.receipt());
    let scope = chain_scope(first.receipt());
    let by = first.verified_by().clone();
    let mut previous_digest = first.authenticated().digest()?;
    let mut previous_sequence = first.receipt().sequence;
    let mut previous_assurance = first.receipt().assurance;
    let mut observed = vec![first.receipt().assurance];
    check_predecessor(first.receipt(), &[])?;
    for entry in chain.iter().skip(1) {
        let receipt = entry.receipt();
        if receipt.previous != Some(previous_digest) {
            return Err(Error::ChainBroken);
        }
        if subject_identity(receipt) != subject {
            return Err(Error::ChainSubjectMismatch);
        }
        if entry.verified_by() != &by {
            return Err(Error::ChainIssuerMismatch);
        }
        if chain_scope(receipt) != scope {
            return Err(Error::ChainScopeMismatch);
        }
        if receipt.sequence <= previous_sequence {
            return Err(Error::InvalidSequence);
        }
        if model_assurance(receipt.assurance) <= model_assurance(previous_assurance) {
            return Err(Error::AssuranceDidNotAdvance);
        }
        check_predecessor(receipt, &observed)?;
        observed.push(receipt.assurance);
        previous_digest = entry.authenticated().digest()?;
        previous_sequence = receipt.sequence;
        previous_assurance = receipt.assurance;
    }
    Ok(())
}

/// A publication must name exactly the assurance its profile requires, and
/// the chain must contain an observation of it.
///
/// Exactly, not at least: the machine gates publication on `performed` of
/// that level, which is membership rather than an ordering, so `>=` would
/// accept a publication naming itself as its own predecessor. And `observed`
/// rather than the receipt's own word for it, because `actual_predecessor` is
/// a field the issuer fills in: without the chain to check it against, a
/// passing chain would say only that a receipt agrees with itself.
pub(super) fn check_predecessor(
    receipt: &Receipt,
    observed: &[AssuranceLevel],
) -> Result<(), Error> {
    if receipt.assurance != AssuranceLevel::Published {
        return Ok(());
    }
    let required = model_assurance(required_predecessor(receipt.profile));
    if model_assurance(receipt.actual_predecessor) != required {
        return Err(Error::PredecessorTooWeak);
    }
    if !observed
        .iter()
        .any(|level| model_assurance(*level) == required)
    {
        return Err(Error::PredecessorNotObserved);
    }
    Ok(())
}
