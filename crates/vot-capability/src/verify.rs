//! Capability verification: whether to believe a presented capability.
//!
//! Checks key anchoring, issuer, audience, time window, denial list, proof of
//! possession, and request scope. Refusals are precise locally but coarse on the
//! wire to avoid leaking an oracle.

use ed25519_dalek::{Signature, VerifyingKey};
use vot_transport_api::ChannelBinding;

use crate::{Capability, Error, FORMAT_ID, Range, SignedCapability, bounds};

/// What a proof of possession covers. Distinct from the capability signature
/// domain.
const PROOF_DOMAIN: &[u8] = b"VOT capability pop v1\0";

/// One trusted key bound to one issuer and its audiences.
#[derive(Clone, Debug)]
pub struct IssuerEntry {
    /// The identifier the issuer puts in the envelope. Issuer-chosen and not
    /// globally unique, so it selects candidates and the issuer claim decides.
    pub key_id: Vec<u8>,
    /// The issuer identity a capability must claim to use this key.
    pub issuer: String,
    /// The audiences this key may issue for.
    pub audiences: Vec<String>,
    pub key: VerifyingKey,
}

/// Trusted issuer keys. Empty set accepts nothing (fail closed).
#[derive(Clone, Debug, Default)]
pub struct Anchors {
    entries: Vec<IssuerEntry>,
}

impl Anchors {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Adds one entry.
    #[must_use]
    pub fn with(mut self, entry: IssuerEntry) -> Self {
        self.entries.push(entry);
        self
    }

    /// Whether this verifier will accept anything at all.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Entries whose key ID matches. May be multiple; the issuer claim decides.
    fn candidates<'a>(&'a self, key_id: &'a [u8]) -> impl Iterator<Item = &'a IssuerEntry> {
        self.entries
            .iter()
            .filter(move |entry| entry.key_id == key_id)
    }
}

/// What this deployment is, and what it knows about the moment and about tokens.
#[derive(Clone, Copy, Debug)]
pub struct Policy<'a> {
    /// The audience a capability must name. A verifier that accepted any would
    /// accept a capability issued for another deployment.
    pub audience: &'a str,
    /// Seconds since the epoch, from the verifier's clock.
    pub now: u64,
    /// Clock skew tolerance in seconds. Declared, not assumed.
    pub skew: u64,
    /// Token identifiers this deployment has revoked before their expiry.
    pub denied: &'a [[u8; 16]],
    /// Enforceable resource limits. Unknown restrictions fail closed.
    pub known_limits: &'a [u16],
}

/// What the holder presented alongside the capability.
#[derive(Clone, Copy, Debug)]
pub struct Presentation<'a> {
    /// The nonce this endpoint put in `AUTH_CONTEXT`. Freshness comes from here.
    pub nonce: &'a [u8],
    /// The identifier of the attempt, fresh per attempt by section 1.1, so a
    /// proof cannot be replayed into a later attempt on the same session.
    pub session_id: [u8; 16],
    /// Carrier-derived material for the connection carrying this attempt.
    pub channel_binding: ChannelBinding,
    /// The signature over those, under the key the capability names.
    pub proof: &'a [u8],
}

/// Why a capability was not believed. Precise for audit, coarse on the wire.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Denial {
    /// The bytes are not a capability of this format.
    Malformed(Error),
    /// No anchored entry names this key identifier.
    UnknownKey,
    /// An entry names the key, but not for the issuer the capability claims.
    IssuerNotAnchored,
    /// The entry does not permit the audience the capability names.
    AudienceNotPermitted,
    /// This deployment is not the audience the capability names.
    AudienceIsAnother,
    /// The signature does not verify under the anchored key.
    Signature,
    /// The window has not opened yet, allowing for declared skew.
    NotYetValid,
    /// The window has closed, allowing for declared skew.
    Expired,
    /// The token identifier is on this deployment's deny list.
    Revoked,
    /// The holder did not prove possession of the key the capability names.
    ProofOfPossession,
    /// The capability names a resource limit this verifier cannot enforce.
    LimitNotEnforceable(u16),
    /// The capability does not allow the operation requested.
    OperationNotAllowed(u64),
    /// The capability's scope does not cover the range requested.
    RangeNotAllowed,
    /// The request is about another object.
    SubjectIsAnother,
}

impl Denial {
    /// Wire-facing reason. Almost always `AUTHENTICATION_FAILED` to avoid
    /// leaking an oracle. Revoked tokens return `REPLAY_REJECTED`.
    #[must_use]
    pub const fn wire_reason(self) -> u16 {
        match self {
            Self::Revoked => vot_codec::error_code::REPLAY_REJECTED,
            _ => vot_codec::error_code::AUTHENTICATION_FAILED,
        }
    }

    /// Wire-facing detail. Always empty to avoid leaking an oracle.
    #[must_use]
    pub const fn wire_detail() -> &'static str {
        ""
    }
}

/// What a request asks a capability to authorize.
///
/// The variant is the operation. A raw identifier cannot be one, and a
/// ranges request cannot omit the range:
///
/// ```compile_fail,E0559
/// use vot_capability::verify::AuthorizedRequest;
///
/// let _ = AuthorizedRequest::Publish {
///     suite: 1,
///     root: [0; 32],
///     operation: 0x0004,
/// };
/// ```
///
/// ```compile_fail,E0063
/// use vot_capability::verify::AuthorizedRequest;
///
/// let _ = AuthorizedRequest::ReadRanges {
///     suite: 1,
///     root: [0; 32],
/// };
/// ```
#[derive(Clone, Copy, Debug)]
pub enum AuthorizedRequest {
    Publish {
        suite: u16,
        root: [u8; 32],
    },
    ReadManifest {
        suite: u16,
        root: [u8; 32],
    },
    ReadRanges {
        suite: u16,
        root: [u8; 32],
        range: Range,
    },
}

impl AuthorizedRequest {
    #[must_use]
    pub const fn operation(self) -> vot_codec::Operation {
        match self {
            Self::Publish { .. } => vot_codec::Operation::Publish,
            Self::ReadManifest { .. } => vot_codec::Operation::ReadManifest,
            Self::ReadRanges { .. } => vot_codec::Operation::ReadRanges,
        }
    }

    const fn suite(self) -> u16 {
        match self {
            Self::Publish { suite, .. }
            | Self::ReadManifest { suite, .. }
            | Self::ReadRanges { suite, .. } => suite,
        }
    }

    const fn root(self) -> [u8; 32] {
        match self {
            Self::Publish { root, .. }
            | Self::ReadManifest { root, .. }
            | Self::ReadRanges { root, .. } => root,
        }
    }
}

/// A verified capability with the audience and clock it was accepted under.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Authorized {
    capability: Capability,
}

impl Authorized {
    /// The claims, for a deployment that needs them.
    #[must_use]
    pub const fn capability(&self) -> &Capability {
        &self.capability
    }

    /// Whether this capability authorizes `request`. Rechecked per request.
    ///
    /// # Errors
    /// Reports an operation the capability does not allow, another object, and a
    /// range outside its scope.
    pub fn allows(&self, request: AuthorizedRequest) -> Result<(), Denial> {
        if !self.capability.allows(request.operation()) {
            return Err(Denial::OperationNotAllowed(
                request.operation().identifier(),
            ));
        }
        if request.suite() != self.capability.scope.suite
            || request.root() != self.capability.scope.root
        {
            return Err(Denial::SubjectIsAnother);
        }
        if let AuthorizedRequest::ReadRanges { range, .. } = request
            && !self.capability.scope.allows(range)
        {
            return Err(Denial::RangeNotAllowed);
        }
        Ok(())
    }

    /// The ceiling this capability puts on a limit, when it states one.
    #[must_use]
    pub fn limit(&self, id: u16) -> Option<u64> {
        self.capability.limit(id)
    }
}

/// Decides whether to believe a presented capability. Checks anchor first,
/// then signature, then claims (cheapest to most expensive).
///
/// # Errors
/// Reports the first rule the presentation broke.
pub fn authorize(
    signed: &SignedCapability,
    presented: Presentation<'_>,
    anchors: &Anchors,
    policy: Policy<'_>,
) -> Result<Authorized, Denial> {
    let mut key_known = false;
    let mut issuer_known = false;
    for entry in anchors.candidates(&signed.key_id) {
        key_known = true;
        if crate::verify_signature(signed, &entry.key).is_err() {
            continue;
        }
        let capability =
            Capability::from_canonical_bytes(&signed.capability).map_err(Denial::Malformed)?;
        if capability.issuer != entry.issuer {
            issuer_known = true;
            continue;
        }
        return finish(capability, entry, presented, policy);
    }
    Err(if !key_known {
        Denial::UnknownKey
    } else if issuer_known {
        Denial::IssuerNotAnchored
    } else {
        Denial::Signature
    })
}

/// The checks that need the capability, the entry, and this deployment.
fn finish(
    capability: Capability,
    entry: &IssuerEntry,
    presented: Presentation<'_>,
    policy: Policy<'_>,
) -> Result<Authorized, Denial> {
    if !entry.audiences.contains(&capability.audience) {
        return Err(Denial::AudienceNotPermitted);
    }
    if capability.audience != policy.audience {
        return Err(Denial::AudienceIsAnother);
    }

    if policy.now.saturating_add(policy.skew) < capability.not_before {
        return Err(Denial::NotYetValid);
    }
    if policy.now.saturating_sub(policy.skew) >= capability.expiry {
        return Err(Denial::Expired);
    }

    if policy.denied.contains(&capability.token_id) {
        return Err(Denial::Revoked);
    }

    for limit in &capability.limits {
        if !policy.known_limits.contains(&limit.id) {
            return Err(Denial::LimitNotEnforceable(limit.id));
        }
    }

    verify_proof_of_possession(&capability, presented)?;
    Ok(Authorized { capability })
}

/// What the holder signs to prove it holds the key the capability names.
///
/// The nonce is the challenge, so the proof is fresh for this session. The token
/// identifier is bound in so a proof made for one capability cannot be presented
/// with another, the attempt identifier prevents replay within a session, and
/// the channel binding prevents replay onto another carrier session.
///
/// # Errors
/// Rejects a nonce outside the bounds `spec/session.cddl` gives the challenge.
pub fn proof_input(
    token_id: &[u8; 16],
    session_id: &[u8; 16],
    nonce: &[u8],
    channel_binding: ChannelBinding,
) -> Result<Vec<u8>, Error> {
    if !(16..=64).contains(&nonce.len()) {
        return Err(Error::InvalidLength);
    }
    let nonce_len = u16::try_from(nonce.len()).map_err(|_| Error::InvalidLength)?;
    let mut input = Vec::with_capacity(
        PROOF_DOMAIN.len()
            + std::mem::size_of::<u16>()
            + token_id.len()
            + session_id.len()
            + std::mem::size_of::<u16>()
            + nonce.len()
            + channel_binding.as_bytes().len(),
    );
    input.extend_from_slice(PROOF_DOMAIN);
    input.extend_from_slice(&FORMAT_ID.to_be_bytes());
    input.extend_from_slice(token_id);
    input.extend_from_slice(session_id);
    input.extend_from_slice(&nonce_len.to_be_bytes());
    input.extend_from_slice(nonce);
    input.extend_from_slice(channel_binding.as_bytes());
    Ok(input)
}

fn verify_proof_of_possession(
    capability: &Capability,
    presented: Presentation<'_>,
) -> Result<(), Denial> {
    if !(16..=64).contains(&presented.nonce.len()) {
        return Err(Denial::ProofOfPossession);
    }
    let signature: [u8; 64] = presented
        .proof
        .try_into()
        .map_err(|_| Denial::ProofOfPossession)?;
    let key =
        VerifyingKey::from_bytes(&capability.holder_key).map_err(|_| Denial::ProofOfPossession)?;
    let input = proof_input(
        &capability.token_id,
        &presented.session_id,
        presented.nonce,
        presented.channel_binding,
    )
    .map_err(|_| Denial::ProofOfPossession)?;
    key.verify_strict(&input, &Signature::from_bytes(&signature))
        .map_err(|_| Denial::ProofOfPossession)
}

/// Signs the proof a holder presents, which is the client half of the same rule.
///
/// # Errors
/// Rejects a nonce outside the bounds `spec/session.cddl` gives the challenge.
pub fn prove_possession(
    capability: &Capability,
    session_id: &[u8; 16],
    nonce: &[u8],
    channel_binding: ChannelBinding,
    key: &ed25519_dalek::SigningKey,
) -> Result<Vec<u8>, Error> {
    let input = proof_input(&capability.token_id, session_id, nonce, channel_binding)?;
    Ok(ed25519_dalek::Signer::sign(key, &input).to_bytes().to_vec())
}

/// The limits this revision can enforce, for a deployment with no reason to
/// narrow the set.
#[must_use]
pub fn enforceable_limits() -> Vec<u16> {
    vot_codec::REGISTERED_LIMITS
        .iter()
        .filter_map(|identifier| u16::try_from(*identifier).ok())
        .collect()
}

/// The bound on a proof, which is one Ed25519 signature.
pub const PROOF_BYTES: usize = 64;

const _: () = assert!(
    PROOF_BYTES <= bounds::SCOPE,
    "a proof must fit the binding proof field spec/session.cddl gives it"
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Limit, Scope};
    use ed25519_dalek::SigningKey;

    const NONCE: &[u8] = &[0x5a; 32];
    const SESSION: [u8; 16] = [0xc0; 16];
    const TOKEN: [u8; 16] = [0xc1; 16];
    const CHANNEL: ChannelBinding = ChannelBinding::from_bytes([0x27; 32]);

    fn issuer_key() -> SigningKey {
        SigningKey::from_bytes(&[3; 32])
    }

    fn holder_key() -> SigningKey {
        SigningKey::from_bytes(&[5; 32])
    }

    fn capability() -> Capability {
        Capability {
            issuer: "issuer.example".to_owned(),
            audience: "receiver.example".to_owned(),
            holder_key: holder_key().verifying_key().to_bytes(),
            operations: vec![
                vot_codec::operation::PUBLISH,
                vot_codec::operation::READ_RANGES,
            ],
            scope: Scope {
                suite: 1,
                root: [7; 32],
                length: Some(1 << 20),
                ranges: vec![Range::new(0, 65_536).unwrap()],
            },
            limits: vec![Limit { id: 1, value: 4 }],
            not_before: 1_700_000_000,
            expiry: 1_700_003_600,
            token_id: TOKEN,
            delegation: crate::NO_FURTHER_DELEGATION,
        }
    }

    fn anchors() -> Anchors {
        Anchors::new().with(IssuerEntry {
            key_id: b"issuer-1".to_vec(),
            issuer: "issuer.example".to_owned(),
            audiences: vec!["receiver.example".to_owned()],
            key: issuer_key().verifying_key(),
        })
    }

    fn limits() -> Vec<u16> {
        enforceable_limits()
    }

    fn policy<'a>(known: &'a [u16], denied: &'a [[u8; 16]]) -> Policy<'a> {
        Policy {
            audience: "receiver.example",
            now: 1_700_001_000,
            skew: 0,
            denied,
            known_limits: known,
        }
    }

    fn presented(proof: &[u8]) -> Presentation<'_> {
        Presentation {
            nonce: NONCE,
            session_id: SESSION,
            channel_binding: CHANNEL,
            proof,
        }
    }

    fn proof_for(capability: &Capability) -> Vec<u8> {
        prove_possession(capability, &SESSION, NONCE, CHANNEL, &holder_key()).unwrap()
    }

    #[test]
    fn possession_transcript_has_one_canonical_layout() {
        let input = proof_input(&TOKEN, &SESSION, NONCE, CHANNEL).unwrap();
        let mut expected = Vec::new();
        expected.extend_from_slice(b"VOT capability pop v1\0");
        expected.extend_from_slice(&FORMAT_ID.to_be_bytes());
        expected.extend_from_slice(&TOKEN);
        expected.extend_from_slice(&SESSION);
        expected.extend_from_slice(&32_u16.to_be_bytes());
        expected.extend_from_slice(NONCE);
        expected.extend_from_slice(CHANNEL.as_bytes());
        assert_eq!(input, expected);
    }

    /// The whole decision, on a capability everything about which is right.
    #[test]
    fn an_anchored_capability_with_a_proof_is_believed() {
        let value = capability();
        let signed = crate::sign(&value, b"issuer-1", &issuer_key()).unwrap();
        let proof = proof_for(&value);
        let authorized = authorize(
            &signed,
            presented(&proof),
            &anchors(),
            policy(&limits(), &[]),
        )
        .unwrap();
        assert_eq!(authorized.capability(), &value);
        assert_eq!(authorized.limit(1), Some(4));
        assert_eq!(
            authorized.allows(AuthorizedRequest::Publish {
                suite: 1,
                root: [7; 32],
            }),
            Ok(())
        );
    }

    #[test]
    fn token_signature_rejected() {
        let value = capability();
        let mut signed = crate::sign(&value, b"issuer-1", &issuer_key()).unwrap();
        signed.signature[0] ^= 1;
        let proof = proof_for(&value);
        assert_eq!(
            authorize(
                &signed,
                presented(&proof),
                &anchors(),
                policy(&limits(), &[])
            ),
            Err(Denial::Signature)
        );

        let other = SigningKey::from_bytes(&[9; 32]);
        let elsewhere = crate::sign(&value, b"issuer-1", &other).unwrap();
        assert_eq!(
            authorize(
                &elsewhere,
                presented(&proof),
                &anchors(),
                policy(&limits(), &[])
            ),
            Err(Denial::Signature)
        );

        let unknown = crate::sign(&value, b"issuer-9", &issuer_key()).unwrap();
        assert_eq!(
            authorize(
                &unknown,
                presented(&proof),
                &anchors(),
                policy(&limits(), &[])
            ),
            Err(Denial::UnknownKey)
        );
    }

    #[test]
    fn token_issuer_rejected() {
        let mut value = capability();
        value.issuer = "issuer.elsewhere".to_owned();
        let signed = crate::sign(&value, b"issuer-1", &issuer_key()).unwrap();
        let proof = proof_for(&value);
        assert_eq!(
            authorize(
                &signed,
                presented(&proof),
                &anchors(),
                policy(&limits(), &[])
            ),
            Err(Denial::IssuerNotAnchored)
        );
    }

    #[test]
    fn token_audience_rejected() {
        let mut value = capability();
        value.audience = "receiver.elsewhere".to_owned();
        let signed = crate::sign(&value, b"issuer-1", &issuer_key()).unwrap();
        let proof = proof_for(&value);
        assert_eq!(
            authorize(
                &signed,
                presented(&proof),
                &anchors(),
                policy(&limits(), &[])
            ),
            Err(Denial::AudienceNotPermitted)
        );

        let wider = Anchors::new().with(IssuerEntry {
            key_id: b"issuer-1".to_vec(),
            issuer: "issuer.example".to_owned(),
            audiences: vec![
                "receiver.example".to_owned(),
                "receiver.elsewhere".to_owned(),
            ],
            key: issuer_key().verifying_key(),
        });
        assert_eq!(
            authorize(&signed, presented(&proof), &wider, policy(&limits(), &[])),
            Err(Denial::AudienceIsAnother)
        );
    }

    #[test]
    fn token_expiry_rejected() {
        let value = capability();
        let signed = crate::sign(&value, b"issuer-1", &issuer_key()).unwrap();
        let proof = proof_for(&value);
        let known = limits();
        let at = |now, skew| Policy {
            now,
            skew,
            ..policy(&known, &[])
        };

        assert!(
            authorize(
                &signed,
                presented(&proof),
                &anchors(),
                at(value.not_before, 0)
            )
            .is_ok()
        );
        assert_eq!(
            authorize(
                &signed,
                presented(&proof),
                &anchors(),
                at(value.not_before - 1, 0)
            ),
            Err(Denial::NotYetValid)
        );
        assert!(
            authorize(
                &signed,
                presented(&proof),
                &anchors(),
                at(value.expiry - 1, 0)
            )
            .is_ok()
        );
        assert_eq!(
            authorize(&signed, presented(&proof), &anchors(), at(value.expiry, 0)),
            Err(Denial::Expired)
        );

        assert!(
            authorize(
                &signed,
                presented(&proof),
                &anchors(),
                at(value.not_before - 30, 30)
            )
            .is_ok()
        );
        assert_eq!(
            authorize(
                &signed,
                presented(&proof),
                &anchors(),
                at(value.not_before - 31, 30)
            ),
            Err(Denial::NotYetValid)
        );
        assert!(
            authorize(
                &signed,
                presented(&proof),
                &anchors(),
                at(value.expiry + 29, 30)
            )
            .is_ok()
        );
        assert_eq!(
            authorize(
                &signed,
                presented(&proof),
                &anchors(),
                at(value.expiry + 30, 30)
            ),
            Err(Denial::Expired)
        );
    }

    #[test]
    fn token_revoked_rejected() {
        let value = capability();
        let signed = crate::sign(&value, b"issuer-1", &issuer_key()).unwrap();
        let proof = proof_for(&value);
        assert_eq!(
            authorize(
                &signed,
                presented(&proof),
                &anchors(),
                policy(&limits(), &[TOKEN])
            ),
            Err(Denial::Revoked)
        );
        assert!(
            authorize(
                &signed,
                presented(&proof),
                &anchors(),
                policy(&limits(), &[[0xff; 16]])
            )
            .is_ok()
        );
    }

    #[test]
    fn token_channel_binding_rejected() {
        let value = capability();
        let signed = crate::sign(&value, b"issuer-1", &issuer_key()).unwrap();
        let honest = proof_for(&value);

        let thief = SigningKey::from_bytes(&[11; 32]);
        let stolen = prove_possession(&value, &SESSION, NONCE, CHANNEL, &thief).unwrap();
        assert_eq!(
            authorize(
                &signed,
                presented(&stolen),
                &anchors(),
                policy(&limits(), &[])
            ),
            Err(Denial::ProofOfPossession)
        );

        let elsewhere =
            prove_possession(&value, &SESSION, &[0x11; 32], CHANNEL, &holder_key()).unwrap();
        assert_eq!(
            authorize(
                &signed,
                presented(&elsewhere),
                &anchors(),
                policy(&limits(), &[])
            ),
            Err(Denial::ProofOfPossession)
        );

        let earlier = prove_possession(&value, &[0xc9; 16], NONCE, CHANNEL, &holder_key()).unwrap();
        assert_eq!(
            authorize(
                &signed,
                presented(&earlier),
                &anchors(),
                policy(&limits(), &[])
            ),
            Err(Denial::ProofOfPossession)
        );

        let mut other = capability();
        other.token_id = [0xc2; 16];
        let other_signed = crate::sign(&other, b"issuer-1", &issuer_key()).unwrap();
        assert_eq!(
            authorize(
                &other_signed,
                presented(&honest),
                &anchors(),
                policy(&limits(), &[])
            ),
            Err(Denial::ProofOfPossession)
        );

        assert_eq!(
            authorize(&signed, presented(&[]), &anchors(), policy(&limits(), &[])),
            Err(Denial::ProofOfPossession)
        );

        let mut omitted_input = proof_input(&TOKEN, &SESSION, NONCE, CHANNEL).unwrap();
        omitted_input.truncate(omitted_input.len() - CHANNEL.as_bytes().len());
        let omitted = ed25519_dalek::Signer::sign(&holder_key(), &omitted_input)
            .to_bytes()
            .to_vec();
        assert_eq!(
            authorize(
                &signed,
                presented(&omitted),
                &anchors(),
                policy(&limits(), &[])
            ),
            Err(Denial::ProofOfPossession)
        );

        let other_channel = ChannelBinding::from_bytes([0x28; 32]);
        let proof =
            prove_possession(&value, &SESSION, NONCE, other_channel, &holder_key()).unwrap();
        assert_eq!(
            authorize(
                &signed,
                presented(&proof),
                &anchors(),
                policy(&limits(), &[])
            ),
            Err(Denial::ProofOfPossession)
        );
        assert_eq!(
            authorize(
                &signed,
                Presentation {
                    nonce: &[0x5a; 15],
                    session_id: SESSION,
                    channel_binding: CHANNEL,
                    proof: &honest,
                },
                &anchors(),
                policy(&limits(), &[])
            ),
            Err(Denial::ProofOfPossession)
        );
        assert_eq!(
            prove_possession(&value, &SESSION, &[0x5a; 65], CHANNEL, &holder_key()),
            Err(Error::InvalidLength)
        );
    }

    #[test]
    fn an_unknown_operation_in_a_valid_capability_grants_nothing() {
        // A capability issued by a later revision, holding one value this one
        // cannot name alongside one it can. The registry says such a token
        // stays valid and the unknown value grants nothing.
        let mut value = capability();
        value.operations = vec![vot_codec::operation::PUBLISH, 0x0004];
        let signed = crate::sign(&value, b"issuer-1", &issuer_key()).unwrap();
        let proof = proof_for(&value);
        let authorized = authorize(
            &signed,
            presented(&proof),
            &anchors(),
            policy(&limits(), &[]),
        )
        .expect("an unknown operation does not invalidate the token");

        assert!(
            authorized.capability().carries(0x0004),
            "the value survived the round trip, so the refusal below is the type's doing"
        );
        assert_eq!(
            crate::Operation::try_from(0x0004_u64),
            Err(vot_codec::UnknownOperation(0x0004)),
            "and neither a request nor a grant can name it"
        );

        assert_eq!(
            authorized.allows(AuthorizedRequest::Publish {
                suite: 1,
                root: [7; 32],
            }),
            Ok(())
        );
    }

    #[test]
    fn token_scope_rejected() {
        let value = capability();
        let signed = crate::sign(&value, b"issuer-1", &issuer_key()).unwrap();
        let proof = proof_for(&value);
        let authorized = authorize(
            &signed,
            presented(&proof),
            &anchors(),
            policy(&limits(), &[]),
        )
        .unwrap();

        assert_eq!(
            authorized.allows(AuthorizedRequest::ReadManifest {
                suite: 1,
                root: [7; 32],
            }),
            Err(Denial::OperationNotAllowed(
                vot_codec::operation::READ_MANIFEST
            ))
        );

        assert_eq!(
            authorized.allows(AuthorizedRequest::Publish {
                suite: 1,
                root: [8; 32],
            }),
            Err(Denial::SubjectIsAnother)
        );
        assert_eq!(
            authorized.allows(AuthorizedRequest::Publish {
                suite: 2,
                root: [7; 32],
            }),
            Err(Denial::SubjectIsAnother)
        );

        assert_eq!(
            authorized.allows(AuthorizedRequest::ReadRanges {
                suite: 1,
                root: [7; 32],
                range: Range::new(0, 65_537).unwrap(),
            }),
            Err(Denial::RangeNotAllowed)
        );
        assert_eq!(
            authorized.allows(AuthorizedRequest::ReadRanges {
                suite: 1,
                root: [7; 32],
                range: Range::new(65_535, 1).unwrap(),
            }),
            Ok(())
        );
        assert_eq!(
            AuthorizedRequest::ReadRanges {
                suite: 1,
                root: [7; 32],
                range: Range::new(65_535, 1).unwrap(),
            }
            .operation(),
            vot_codec::Operation::ReadRanges
        );
    }

    #[test]
    fn token_delegation_rejected() {
        let mut value = capability();
        value.delegation = 1;
        let bytes = {
            let mut honest = capability().canonical_bytes().unwrap();
            let last = honest.len() - 1;
            honest[last] = 1;
            honest
        };
        let input = crate::signing_input(b"issuer-1", &bytes).unwrap();
        let signed = SignedCapability {
            key_id: b"issuer-1".to_vec(),
            capability: bytes,
            signature: ed25519_dalek::Signer::sign(&issuer_key(), &input).to_bytes(),
        };
        let proof = proof_for(&value);
        assert_eq!(
            authorize(
                &signed,
                presented(&proof),
                &anchors(),
                policy(&limits(), &[])
            ),
            Err(Denial::Malformed(Error::UnsupportedDelegation(1)))
        );
    }

    #[test]
    fn a_limit_this_verifier_cannot_enforce_refuses_the_capability() {
        let mut value = capability();
        value.limits = vec![Limit {
            id: 0x4000,
            value: 1,
        }];
        let signed = crate::sign(&value, b"issuer-1", &issuer_key()).unwrap();
        let proof = proof_for(&value);
        assert_eq!(
            authorize(
                &signed,
                presented(&proof),
                &anchors(),
                policy(&limits(), &[])
            ),
            Err(Denial::LimitNotEnforceable(0x4000))
        );
        assert!(
            authorize(
                &signed,
                presented(&proof),
                &anchors(),
                policy(&[0x4000], &[])
            )
            .is_ok()
        );
    }

    #[test]
    fn an_empty_anchor_set_accepts_nothing() {
        let value = capability();
        let signed = crate::sign(&value, b"issuer-1", &issuer_key()).unwrap();
        let proof = proof_for(&value);
        let empty = Anchors::new();
        assert!(empty.is_empty());
        assert!(
            !anchors().is_empty(),
            "and a configured set does not report itself empty"
        );
        assert_eq!(
            authorize(&signed, presented(&proof), &empty, policy(&limits(), &[])),
            Err(Denial::UnknownKey)
        );
    }

    #[test]
    fn two_issuers_may_choose_the_same_key_identifier() {
        let second = SigningKey::from_bytes(&[13; 32]);
        let shared = Anchors::new()
            .with(IssuerEntry {
                key_id: b"key-1".to_vec(),
                issuer: "issuer.example".to_owned(),
                audiences: vec!["receiver.example".to_owned()],
                key: issuer_key().verifying_key(),
            })
            .with(IssuerEntry {
                key_id: b"key-1".to_vec(),
                issuer: "issuer.second".to_owned(),
                audiences: vec!["receiver.example".to_owned()],
                key: second.verifying_key(),
            });

        for (issuer, key) in [
            ("issuer.example", issuer_key()),
            ("issuer.second", second.clone()),
        ] {
            let mut value = capability();
            value.issuer = issuer.to_owned();
            let signed = crate::sign(&value, b"key-1", &key).unwrap();
            let proof = proof_for(&value);
            assert!(
                authorize(&signed, presented(&proof), &shared, policy(&limits(), &[])).is_ok(),
                "{issuer}"
            );
        }

        let mut crossed = capability();
        crossed.issuer = "issuer.example".to_owned();
        let signed = crate::sign(&crossed, b"key-1", &second).unwrap();
        let proof = proof_for(&crossed);
        let denial = authorize(&signed, presented(&proof), &shared, policy(&limits(), &[]))
            .expect_err("an anchored key signing for another name is refused");
        assert_eq!(denial, Denial::IssuerNotAnchored);
        assert_eq!(
            denial.wire_reason(),
            Denial::Signature.wire_reason(),
            "and the peer cannot tell the two apart"
        );
    }

    #[test]
    fn a_peer_learns_the_same_thing_from_almost_every_refusal() {
        for denial in [
            Denial::Malformed(Error::InvalidValidity),
            Denial::UnknownKey,
            Denial::IssuerNotAnchored,
            Denial::AudienceNotPermitted,
            Denial::AudienceIsAnother,
            Denial::Signature,
            Denial::NotYetValid,
            Denial::Expired,
            Denial::ProofOfPossession,
            Denial::LimitNotEnforceable(1),
            Denial::OperationNotAllowed(1),
            Denial::RangeNotAllowed,
            Denial::SubjectIsAnother,
        ] {
            assert_eq!(
                denial.wire_reason(),
                vot_codec::error_code::AUTHENTICATION_FAILED,
                "{denial:?}"
            );
        }
        assert_eq!(
            Denial::Revoked.wire_reason(),
            vot_codec::error_code::REPLAY_REJECTED
        );
        assert_eq!(Denial::wire_detail(), "");
    }

    #[test]
    fn the_limits_this_revision_enforces_are_the_ones_it_registered() {
        let enforceable = enforceable_limits();
        assert_eq!(enforceable.len(), vot_codec::REGISTERED_LIMITS.len());
        for identifier in &enforceable {
            assert!(vot_codec::is_registered_limit(u64::from(*identifier)));
        }
    }
}
