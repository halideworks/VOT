//! What a verifier decides about a capability, from ADR-0023.
//!
//! The format says whether bytes are a capability and whether the signature over
//! them holds. This says whether to believe it: that the key is one this
//! deployment anchored, for the issuer that claims it and the audience it names;
//! that the window is open on this verifier's clock; that the token is not
//! denied; that the holder proved possession of the key the capability names; and
//! that the operation and scope a request asks for are inside it.
//!
//! Every refusal is reported precisely here and coarsely on the wire.
//! `spec/wire.md` section 1.1 forbids a rejection that distinguishes a valid
//! capability with insufficient scope from an invalid one, because that
//! difference is an oracle a holder can probe. [`Denial`] is for the audit record
//! the deployment keeps; [`Denial::wire_reason`] is what a peer learns, and it is
//! deliberately the same answer for almost all of them.

use ed25519_dalek::{Signature, VerifyingKey};

use crate::{Capability, Error, FORMAT_ID, Range, SignedCapability, bounds};

/// What a proof of possession covers, before the capability and the challenge.
///
/// Distinct from the domain the capability itself is signed under, so a signature
/// over one is not valid input for the other.
const PROOF_DOMAIN: &[u8] = b"VOT capability pop v0\0";

/// One key this deployment trusts, for one issuer, for named audiences.
///
/// The three travel together because each alone admits something nobody
/// authorized: a key with no issuer signs for any name, and an issuer with no
/// audience list signs for any deployment that trusts it.
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

/// The issuer keys a verifier will accept, and nothing else.
///
/// An empty set accepts nothing. `spec/wire.md` section 1.1 already covers the
/// deployment that requires no authentication: it advertises no capability
/// format. An empty set with a format advertised is a misconfiguration, and
/// failing closed is what `spec/security.md` section 5 asks of one.
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

    /// The entries whose key identifier matches, in configured order.
    ///
    /// More than one is expected rather than exceptional: two issuers can choose
    /// the same identifier, so the issuer claim is what decides between them.
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
    /// Seconds since the epoch, from the verifier's clock. ADR-0023 puts the
    /// clock here because no VOT frame carries one.
    pub now: u64,
    /// How far the clock may be out, in seconds, declared rather than assumed. A
    /// tolerance wide enough for one deployment's clocks is a replay window in
    /// another.
    pub skew: u64,
    /// Token identifiers this deployment has revoked before their expiry.
    pub denied: &'a [[u8; 16]],
    /// Resource limits this verifier can enforce. A capability naming one that is
    /// absent here is refused: `spec/registries.md` section 13 makes an unknown
    /// restriction fail closed, because ignoring one lifts it.
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
    /// The signature over those, under the key the capability names.
    pub proof: &'a [u8],
}

/// Why a capability was not believed.
///
/// Precise for the audit record and coarse on the wire: see
/// [`wire_reason`](Self::wire_reason).
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
    /// What a peer is told, from the three codes section 1.1 assigns.
    ///
    /// Almost every denial answers `AUTHENTICATION_FAILED`, including the ones a
    /// deployment can tell apart locally. Section 1.1 forbids a rejection that
    /// distinguishes a valid capability with insufficient scope from an invalid
    /// one, so a holder probing with a narrow capability learns the same thing
    /// either way. A revoked token is the one exception, because a holder
    /// presenting a token this deployment revoked is being told to stop rather
    /// than to try again, and `REPLAY_REJECTED` is the code the registry assigns
    /// a token that has been seen and refused.
    #[must_use]
    pub const fn wire_reason(self) -> u16 {
        match self {
            Self::Revoked => vot_codec::error_code::REPLAY_REJECTED,
            _ => vot_codec::error_code::AUTHENTICATION_FAILED,
        }
    }

    /// The detail a rejection may carry, which is nothing.
    ///
    /// Section 1.1 allows an optional detail and forbids one that distinguishes
    /// these cases. Every string that would be useful to an operator is a string
    /// that would be useful to a holder probing, so the audit record gets the
    /// [`Denial`] and the peer gets an empty detail.
    #[must_use]
    pub const fn wire_detail() -> &'static str {
        ""
    }
}

/// What a request asks a capability to authorize.
#[derive(Clone, Copy, Debug)]
pub struct Request {
    /// An operation identifier from `spec/registries.md` section 12.
    pub operation: u64,
    /// The suite and root the request is about.
    pub suite: u16,
    pub root: [u8; 32],
    /// The bytes it asks for, when it asks for bytes.
    pub range: Option<Range>,
}

/// A capability this verifier believes, and what it believed about it.
///
/// Held rather than returned as bare claims so a caller cannot forget which
/// audience and clock it was accepted under.
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

    /// Whether this capability authorizes `request`.
    ///
    /// Checked again per request rather than once at authentication, which is
    /// what `spec/security.md` section 5 requires: authorization is rechecked
    /// when a request expands scope, switches source or carrier, publishes, or
    /// renews.
    ///
    /// # Errors
    /// Reports an operation the capability does not allow, another object, and a
    /// range outside its scope.
    pub fn allows(&self, request: Request) -> Result<(), Denial> {
        if !self.capability.allows(request.operation) {
            return Err(Denial::OperationNotAllowed(request.operation));
        }
        if request.suite != self.capability.scope.suite
            || request.root != self.capability.scope.root
        {
            return Err(Denial::SubjectIsAnother);
        }
        if let Some(range) = request.range
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

/// Decides whether to believe a presented capability.
///
/// The order is deliberate: nothing expensive happens before the anchor is
/// found, and the signature is checked before any claim is read, because a claim
/// from an unsigned capability is a claim from whoever sent it.
///
/// # Errors
/// Reports the first rule the presentation broke. Every one of them is refused;
/// which one a peer is told is [`Denial::wire_reason`]'s answer, not this one's.
pub fn authorize(
    signed: &SignedCapability,
    presented: Presentation<'_>,
    anchors: &Anchors,
    policy: Policy<'_>,
) -> Result<Authorized, Denial> {
    // An entry has to name the key before anything is read from the capability.
    // The claims decide which entry, so the candidates come first and the issuer
    // narrows them.
    let mut key_known = false;
    let mut issuer_known = false;
    for entry in anchors.candidates(&signed.key_id) {
        key_known = true;
        // The signature is checked per candidate, because two entries can share
        // an identifier and only one holds the key that signed this.
        if crate::verify_signature(signed, &entry.key).is_err() {
            continue;
        }
        let capability = Capability::from_canonical_bytes(&signed.capability).map_err(|error| {
            // The signature held, so the issuer minted something this revision
            // cannot read. That is the issuer's fault and not the holder's, and
            // it is still refused.
            Denial::Malformed(error)
        })?;
        if capability.issuer != entry.issuer {
            issuer_known = true;
            continue;
        }
        return finish(capability, entry, presented, policy);
    }
    // Reported as precisely as the anchor set allows, and no more: a holder is
    // told the same thing either way.
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
    // The audience is two checks, not one. The entry decides whether this key may
    // issue for that audience at all, and the policy decides whether that
    // audience is this deployment. Without the first, a key anchored for one
    // tenant signs for another; without the second, a capability issued for
    // another deployment verifies here.
    if !entry.audiences.contains(&capability.audience) {
        return Err(Denial::AudienceNotPermitted);
    }
    if capability.audience != policy.audience {
        return Err(Denial::AudienceIsAnother);
    }

    // The window, against this verifier's clock and its declared tolerance.
    if policy.now.saturating_add(policy.skew) < capability.not_before {
        return Err(Denial::NotYetValid);
    }
    if policy.now.saturating_sub(policy.skew) >= capability.expiry {
        return Err(Denial::Expired);
    }

    if policy.denied.contains(&capability.token_id) {
        return Err(Denial::Revoked);
    }

    // Every limit the capability states has to be one this verifier can hold the
    // holder to. Ignoring one would lift it.
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
/// with another, and the attempt identifier so a proof cannot be replayed into a
/// later attempt on the same session, which shares the nonce.
#[must_use]
pub fn proof_input(token_id: &[u8; 16], session_id: &[u8; 16], nonce: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(PROOF_DOMAIN.len() + 2 + 32 + nonce.len());
    input.extend_from_slice(PROOF_DOMAIN);
    input.extend_from_slice(&FORMAT_ID.to_be_bytes());
    input.extend_from_slice(token_id);
    input.extend_from_slice(session_id);
    input.extend_from_slice(nonce);
    input
}

fn verify_proof_of_possession(
    capability: &Capability,
    presented: Presentation<'_>,
) -> Result<(), Denial> {
    // The nonce bounds are the challenge's, from spec/session.cddl. A proof over
    // a nonce this endpoint could not have sent is not a proof of anything.
    if !(16..=64).contains(&presented.nonce.len()) {
        return Err(Denial::ProofOfPossession);
    }
    let signature: [u8; 64] = presented
        .proof
        .try_into()
        .map_err(|_| Denial::ProofOfPossession)?;
    let key =
        VerifyingKey::from_bytes(&capability.holder_key).map_err(|_| Denial::ProofOfPossession)?;
    let input = proof_input(&capability.token_id, &presented.session_id, presented.nonce);
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
    key: &ed25519_dalek::SigningKey,
) -> Result<Vec<u8>, Error> {
    if !(16..=64).contains(&nonce.len()) {
        return Err(Error::InvalidLength);
    }
    let input = proof_input(&capability.token_id, session_id, nonce);
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
                ranges: vec![Range {
                    offset: 0,
                    length: 65_536,
                }],
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
            proof,
        }
    }

    fn proof_for(capability: &Capability) -> Vec<u8> {
        prove_possession(capability, &SESSION, NONCE, &holder_key()).unwrap()
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
            authorized.allows(Request {
                operation: vot_codec::operation::PUBLISH,
                suite: 1,
                root: [7; 32],
                range: Some(Range {
                    offset: 0,
                    length: 65_536
                }),
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

        // A capability another key signed, whose identifier this deployment does
        // anchor. The identifier is a label, and the key is what decides.
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

        // And an identifier nothing anchors at all.
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
        // The key verifies and the issuer is not the one it was anchored for, so a
        // key cannot sign for a name nobody authorized it for.
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
        // Two separate checks. The entry decides whether this key may issue for an
        // audience at all, and the policy decides whether that audience is this
        // deployment.
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

        // Anchored for that audience, and this deployment is another one: the case
        // that makes a capability issued for one deployment fail at every other.
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
        // The limit list has to outlive the closure, since a Policy borrows it.
        let known = limits();
        let at = |now, skew| Policy {
            now,
            skew,
            ..policy(&known, &[])
        };

        // The window is inclusive of not-before and exclusive of expiry, and each
        // edge is asserted with the value one second outside it.
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

        // Declared skew moves both edges and nothing else.
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
        // Another token on the list is not this one.
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
        // The binding is proof of possession, so this is where a stolen capability
        // stops: the holder key is in the signed claims and the thief cannot sign
        // the challenge under it.
        let value = capability();
        let signed = crate::sign(&value, b"issuer-1", &issuer_key()).unwrap();
        let honest = proof_for(&value);

        let thief = SigningKey::from_bytes(&[11; 32]);
        let stolen = prove_possession(&value, &SESSION, NONCE, &thief).unwrap();
        assert_eq!(
            authorize(
                &signed,
                presented(&stolen),
                &anchors(),
                policy(&limits(), &[])
            ),
            Err(Denial::ProofOfPossession)
        );

        // A proof over another challenge, which is what makes it fresh.
        let elsewhere = prove_possession(&value, &SESSION, &[0x11; 32], &holder_key()).unwrap();
        assert_eq!(
            authorize(
                &signed,
                presented(&elsewhere),
                &anchors(),
                policy(&limits(), &[])
            ),
            Err(Denial::ProofOfPossession)
        );

        // A proof from another attempt on the same session, which shares the
        // nonce. Without the attempt identifier in the input this would pass.
        let earlier = prove_possession(&value, &[0xc9; 16], NONCE, &holder_key()).unwrap();
        assert_eq!(
            authorize(
                &signed,
                presented(&earlier),
                &anchors(),
                policy(&limits(), &[])
            ),
            Err(Denial::ProofOfPossession)
        );

        // A proof made for another capability, which the token identifier binds.
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

        // A proof of the wrong size, and a challenge outside the bounds
        // spec/session.cddl gives one.
        assert_eq!(
            authorize(&signed, presented(&[]), &anchors(), policy(&limits(), &[])),
            Err(Denial::ProofOfPossession)
        );
        assert_eq!(
            authorize(
                &signed,
                Presentation {
                    nonce: &[0x5a; 15],
                    session_id: SESSION,
                    proof: &honest,
                },
                &anchors(),
                policy(&limits(), &[])
            ),
            Err(Denial::ProofOfPossession)
        );
        assert_eq!(
            prove_possession(&value, &SESSION, &[0x5a; 65], &holder_key()),
            Err(Error::InvalidLength)
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

        // An operation the capability does not name.
        assert_eq!(
            authorized.allows(Request {
                operation: vot_codec::operation::READ_MANIFEST,
                suite: 1,
                root: [7; 32],
                range: None,
            }),
            Err(Denial::OperationNotAllowed(
                vot_codec::operation::READ_MANIFEST
            ))
        );

        // Another object, by root and by suite.
        assert_eq!(
            authorized.allows(Request {
                operation: vot_codec::operation::PUBLISH,
                suite: 1,
                root: [8; 32],
                range: None,
            }),
            Err(Denial::SubjectIsAnother)
        );
        assert_eq!(
            authorized.allows(Request {
                operation: vot_codec::operation::PUBLISH,
                suite: 2,
                root: [7; 32],
                range: None,
            }),
            Err(Denial::SubjectIsAnother)
        );

        // One byte past the range it allows, and the last byte inside it.
        assert_eq!(
            authorized.allows(Request {
                operation: vot_codec::operation::READ_RANGES,
                suite: 1,
                root: [7; 32],
                range: Some(Range {
                    offset: 0,
                    length: 65_537
                }),
            }),
            Err(Denial::RangeNotAllowed)
        );
        assert_eq!(
            authorized.allows(Request {
                operation: vot_codec::operation::READ_RANGES,
                suite: 1,
                root: [7; 32],
                range: Some(Range {
                    offset: 65_535,
                    length: 1
                }),
            }),
            Ok(())
        );
    }

    #[test]
    fn token_delegation_rejected() {
        // The format refuses a delegation claim it does not define, so a verifier
        // never reads past one. Signed by an anchored key, so this is the
        // verifier's answer to an issuer that minted a capability for a later
        // format rather than a decoder's answer to a stranger.
        let mut value = capability();
        value.delegation = 1;
        let bytes = {
            let mut honest = capability().canonical_bytes().unwrap();
            // Key 10 is the delegation constraint and its value is the last byte.
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
        // spec/registries.md section 13: an unknown restriction fails closed,
        // which is the opposite of what an unknown operation does. Ignoring this
        // would lift the ceiling the issuer set.
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
        // And a verifier that can enforce it accepts the same capability.
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
        // A key identifier is issuer-chosen, so it selects candidates and the
        // issuer claim decides. A verifier keyed on the identifier alone works
        // until the second issuer arrives.
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

        // The second issuer's key does not sign for the first issuer's name. Both
        // entries are tried: the first's key does not verify these bytes, the
        // second's does and is anchored for another name, so the refusal names the
        // issuer rather than the signature. A peer is told the same thing either
        // way, which is what keeps the distinction out of the oracle.
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
        // spec/wire.md section 1.1: a rejection must not distinguish a valid
        // capability with insufficient scope from an invalid one, because that
        // difference is an oracle. The audit record keeps the difference; the
        // peer does not.
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
        // A revoked token is the one a holder is told to stop over rather than to
        // try again with another capability.
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
