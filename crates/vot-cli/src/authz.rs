//! Who may fetch a package: what a serve requires and what a fetch answers.
//!
//! ADR-0036. The exchange itself is `spec/wire.md` section 1.1 and lives in
//! `vot-session`; the token is `vot-capability`. This module is the policy
//! between them, which is the part the spec leaves to a deployment.

use ed25519_dalek::{SigningKey, VerifyingKey};
use vot_capability::verify::{Anchors, AuthorizedRequest, IssuerEntry, Policy, Presentation};
use vot_capability::{Capability, Operation, Scope};
use vot_codec::frames::{AuthContext, Binding, SessionOpen};
use vot_transport_api::ChannelBinding;

use crate::Error;

/// The suite a package root is under, from `spec/object.md` section 5.1.
const PACKAGE_SUITE: u16 = 1;

/// What a refusal says, whatever the reason.
///
/// `spec/wire.md` 1.1: a server "MUST NOT put anything in the detail that
/// distinguishes a valid capability with insufficient scope from an invalid
/// one, since that difference is an oracle." The reason code is held constant
/// for the same reason, which the registry's three codes would otherwise
/// leak. The precise [`vot_capability::verify::Denial`] is the serve
/// operator's to read locally, not the caller's to be told.
pub const REFUSAL_DETAIL: &str = "not authorized for this package";

/// The code every refusal carries. See [`REFUSAL_DETAIL`].
pub const REFUSAL_REASON: u16 = vot_codec::error_code::AUTHENTICATION_FAILED;

/// Clock skew a serve tolerates in a capability's validity window.
///
/// Declared rather than assumed, which is what [`Policy`] asks for. Two
/// machines that have both talked to a time server are inside this.
const SKEW_SECONDS: u64 = 300;

/// What a serve requires of a fetch before it answers.
///
/// Absent means the serve requires nothing, which is what it did before
/// ADR-0036 and still does unless an issuer is configured.
#[derive(Clone)]
pub struct Requirement {
    anchors: Anchors,
    audience: String,
    root: [u8; 32],
}

impl Requirement {
    /// A requirement naming one anchored issuer.
    #[must_use]
    pub fn new(
        issuer: &str,
        key_id: Vec<u8>,
        key: VerifyingKey,
        audience: &str,
        root: [u8; 32],
    ) -> Self {
        Self {
            anchors: Anchors::new().with(IssuerEntry {
                issuer: issuer.to_owned(),
                audiences: vec![audience.to_owned()],
                key_id,
                key,
            }),
            audience: audience.to_owned(),
            root,
        }
    }

    /// The challenge this serve advertises.
    ///
    /// Names the VOT capability format and asks for proof of possession, so
    /// a token seen on the wire is not a token anyone else can spend.
    #[must_use]
    pub fn challenge(&self, nonce: [u8; 32]) -> AuthContext {
        AuthContext {
            nonce: nonce.to_vec(),
            binding: Binding::ProofOfPossession,
            formats: vec![u64::from(vot_capability::FORMAT_ID)],
        }
    }

    /// The scope to grant for `open`, or nothing to refuse it.
    ///
    /// Refuses without saying which rule broke: every path out is the same
    /// two values, and the reason is [`REFUSAL_DETAIL`]'s to explain.
    #[must_use]
    pub fn decide(
        &self,
        challenge: &AuthContext,
        open: &SessionOpen,
        channel_binding: ChannelBinding,
        now: u64,
    ) -> Option<Vec<u8>> {
        if open.capability_format != u64::from(vot_capability::FORMAT_ID) {
            return None;
        }
        let signed = vot_capability::decode(&open.capability).ok()?;
        let authorized = vot_capability::verify::authorize(
            &signed,
            Presentation {
                nonce: &challenge.nonce,
                session_id: open.session_id,
                channel_binding,
                proof: &open.binding_proof,
            },
            &self.anchors,
            Policy {
                audience: &self.audience,
                now,
                skew: SKEW_SECONDS,
                denied: &[],
                // Nothing here installs a capability limit, and an
                // unenforceable one fails closed, so a token carrying any is
                // refused rather than half honoured.
                known_limits: &[],
            },
        )
        .ok()?;
        // Both, because a fetch reads the manifest and then its ranges, and a
        // token that allows one without the other authorizes half a transfer.
        authorized
            .allows(AuthorizedRequest::ReadManifest {
                suite: PACKAGE_SUITE,
                root: self.root,
            })
            .ok()?;
        if !authorized.capability().allows(Operation::ReadRanges) {
            return None;
        }
        // The scope names the package root, and its range list has no object
        // to apply to (ADR-0036); nothing on the serve path consults it, so a
        // token that carries one is refused rather than half honoured.
        if !authorized.capability().scope.ranges.is_empty() {
            return None;
        }
        // The whole scope the token carries. A client asking for a subset is
        // allowed by section 1.1 and this one never does, so granting the
        // token's own scope grants no more than it allows.
        vot_capability::encode_scope(&authorized.capability().scope).ok()
    }
}

/// What a fetch presents: the token it holds and the key that proves it.
pub struct Holder {
    signed: Vec<u8>,
    capability: Capability,
    key: SigningKey,
}

impl Holder {
    /// Reads a holder from an encoded capability and the key it names.
    ///
    /// # Errors
    /// Rejects bytes that are not a capability of this format, and a key that
    /// is not the holder key the capability names, which is a mistake worth
    /// catching here rather than as a refusal from the far end.
    pub fn new(signed: Vec<u8>, key: SigningKey) -> Result<Self, Error> {
        let decoded = vot_capability::decode(&signed).map_err(|_| Error::InvalidArguments)?;
        let capability = Capability::from_canonical_bytes(&decoded.capability)
            .map_err(|_| Error::InvalidArguments)?;
        if key.verifying_key().to_bytes() != capability.holder_key {
            return Err(Error::InvalidArguments);
        }
        Ok(Self {
            signed,
            capability,
            key,
        })
    }

    /// The request answering `challenge`.
    ///
    /// The session identifier is fresh per attempt, which section 1.1
    /// requires and which the proof binds, so a proof cannot be replayed into
    /// a later attempt on the same session.
    ///
    /// # Errors
    /// Reports [`Error::Randomness`] for a system that will not give 16
    /// bytes, and [`Error::InvalidArguments`] for a challenge whose nonce is
    /// outside what the format signs over.
    pub fn answer(
        &self,
        challenge: &AuthContext,
        channel_binding: ChannelBinding,
    ) -> Result<SessionOpen, Error> {
        let mut session_id = [0_u8; 16];
        getrandom::fill(&mut session_id).map_err(|_| Error::Randomness)?;
        let proof = vot_capability::verify::prove_possession(
            &self.capability,
            &session_id,
            &challenge.nonce,
            channel_binding,
            &self.key,
        )
        .map_err(|_| Error::InvalidArguments)?;
        Ok(SessionOpen {
            session_id,
            capability_format: u64::from(vot_capability::FORMAT_ID),
            capability: self.signed.clone(),
            // Empty asks for the token's whole scope, which is what a fetch
            // of the package the token names wants.
            requested_scope: Vec::new(),
            binding_proof: proof,
        })
    }
}

/// The scope a capability for one package carries: the whole package, no
/// range restriction.
///
/// One home for the shape, so what `vot capability issue` writes and what
/// [`Requirement::decide`] checks cannot drift.
#[must_use]
pub fn package_scope(root: [u8; 32]) -> Scope {
    Scope {
        suite: PACKAGE_SUITE,
        root,
        // The issuer does not know it, and nothing checks a length here.
        length: None,
        ranges: Vec::new(),
    }
}

/// The operations a capability for one package carries, ascending.
#[must_use]
pub fn package_operations() -> Vec<u64> {
    let mut operations = vec![
        Operation::ReadManifest.identifier(),
        Operation::ReadRanges.identifier(),
    ];
    operations.sort_unstable();
    operations
}

/// Seconds since the epoch, for a validity window and for checking one.
///
/// # Errors
/// Reports [`Error::InvalidArguments`] for a clock before the epoch, which
/// nothing this uses can act on.
pub fn now_seconds() -> Result<u64, Error> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_secs())
        .map_err(|_| Error::InvalidArguments)
}

/// What a serve asks of one session: the stance it advertises, and the policy
/// that answers what the stance invites.
///
/// One value because the two have to agree. A challenge naming a capability
/// format with nothing behind it to check one leaves every session waiting on
/// a decision that never comes, and a requirement behind a challenge that
/// asks for nothing is never consulted.
pub struct Stance<'a> {
    pub(crate) authentication: vot_session::Authentication,
    pub(crate) requirement: Option<&'a Requirement>,
}

impl Stance<'_> {
    /// A serve that requires nothing, which is the default.
    #[must_use]
    pub const fn open(nonce: [u8; 32]) -> Self {
        Self {
            authentication: vot_session::Authentication::NotRequired { nonce },
            requirement: None,
        }
    }
}

impl<'a> Stance<'a> {
    /// A serve that requires a capability from `requirement`.
    #[must_use]
    pub fn required(requirement: &'a Requirement, nonce: [u8; 32]) -> Self {
        Self {
            authentication: vot_session::Authentication::Capability {
                challenge: requirement.challenge(nonce),
            },
            requirement: Some(requirement),
        }
    }
}

/// A stance that requires nothing, for a caller that already has the
/// authentication value. The requirement is absent because a bare
/// `NotRequired` invites no answer.
impl From<vot_session::Authentication> for Stance<'_> {
    fn from(authentication: vot_session::Authentication) -> Self {
        Self {
            authentication,
            requirement: None,
        }
    }
}

/// The identifier a serve knows an issuer key by.
///
/// Derived from the key rather than chosen, so the two ends agree on it
/// without a third value to pass around: a serve given the public key can
/// compute what the token will claim.
#[must_use]
pub fn key_id_of(key: &VerifyingKey) -> Vec<u8> {
    blake3::hash(&key.to_bytes()).as_bytes()[..16].to_vec()
}

/// Mints a capability for one package and signs it.
///
/// The window is `[now, now + seconds)`, which the token carries and the
/// verifier enforces, and which is the only thing that ends a grant short of
/// stopping the serve.
///
/// # Errors
/// Rejects a window of no length, a validity that runs past what the clock
/// can hold, and a capability the format will not carry.
pub fn issue(
    issuer: &str,
    audience: &str,
    issuer_key: &SigningKey,
    holder_key: [u8; 32],
    root: [u8; 32],
    now: u64,
    seconds: u64,
) -> Result<Vec<u8>, Error> {
    if seconds == 0 {
        return Err(Error::InvalidArguments);
    }
    let expiry = now.checked_add(seconds).ok_or(Error::InvalidArguments)?;
    let mut token_id = [0_u8; 16];
    getrandom::fill(&mut token_id).map_err(|_| Error::Randomness)?;
    let capability = Capability {
        issuer: issuer.to_owned(),
        audience: audience.to_owned(),
        holder_key,
        operations: package_operations(),
        scope: package_scope(root),
        // None, because nothing here enforces one and an unenforceable limit
        // is refused rather than half honoured.
        limits: Vec::new(),
        not_before: now,
        expiry,
        token_id,
        delegation: vot_capability::NO_FURTHER_DELEGATION,
    };
    let signed = vot_capability::sign(
        &capability,
        &key_id_of(&issuer_key.verifying_key()),
        issuer_key,
    )
    .map_err(|_| Error::InvalidArguments)?;
    vot_capability::encode(&signed).map_err(|_| Error::InvalidArguments)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    const ISSUER: &str = "issuer.example";
    const AUDIENCE: &str = "receiver.example";
    const ROOT: [u8; 32] = [7; 32];
    const NOW: u64 = 1_700_000_000;

    fn channel(seed: u8) -> ChannelBinding {
        ChannelBinding::from_bytes([seed; vot_transport_api::CHANNEL_BINDING_LEN])
    }

    fn requirement(issuer_key: &SigningKey) -> Requirement {
        Requirement::new(
            ISSUER,
            key_id_of(&issuer_key.verifying_key()),
            issuer_key.verifying_key(),
            AUDIENCE,
            ROOT,
        )
    }

    fn holder(issuer_key: &SigningKey, holder_key: &SigningKey, root: [u8; 32]) -> Holder {
        let token = issue(
            ISSUER,
            AUDIENCE,
            issuer_key,
            holder_key.verifying_key().to_bytes(),
            root,
            NOW,
            3_600,
        )
        .expect("a token");
        Holder::new(token, holder_key.clone()).expect("a holder")
    }

    #[test]
    fn a_token_for_this_package_from_the_anchored_issuer_is_granted() {
        let issuer_key = keypair(1);
        let requirement = requirement(&issuer_key);
        let holder = holder(&issuer_key, &keypair(2), ROOT);
        let challenge = requirement.challenge([9; 32]);
        let binding = channel(5);
        let open = holder.answer(&challenge, binding).expect("a request");
        let granted = requirement
            .decide(&challenge, &open, binding, NOW)
            .expect("the token names this package");
        assert_eq!(
            granted,
            vot_capability::encode_scope(&package_scope(ROOT)).expect("the scope"),
            "the grant is the scope the token carries"
        );
    }

    #[test]
    fn a_token_that_narrows_to_ranges_is_refused() {
        let issuer_key = keypair(1);
        let requirement = requirement(&issuer_key);
        let challenge = requirement.challenge([9; 32]);
        let holder_key = keypair(2);
        let capability = Capability {
            issuer: ISSUER.to_owned(),
            audience: AUDIENCE.to_owned(),
            holder_key: holder_key.verifying_key().to_bytes(),
            operations: package_operations(),
            scope: Scope {
                ranges: vec![vot_capability::Range::new(0, 65_536).expect("a range")],
                ..package_scope(ROOT)
            },
            limits: Vec::new(),
            not_before: NOW,
            expiry: NOW + 3_600,
            token_id: [7; 16],
            delegation: vot_capability::NO_FURTHER_DELEGATION,
        };
        let signed = vot_capability::sign(
            &capability,
            &key_id_of(&issuer_key.verifying_key()),
            &issuer_key,
        )
        .expect("a signed token");
        let token = vot_capability::encode(&signed).expect("an encoded token");
        let narrowed = Holder::new(token, holder_key.clone()).expect("a holder");
        let request = narrowed.answer(&challenge, channel(5)).expect("a request");
        assert!(
            requirement
                .decide(&challenge, &request, channel(5), NOW)
                .is_none(),
            "a range list this serve cannot enforce must fail closed"
        );
    }

    #[test]
    fn a_proof_from_one_channel_cannot_be_replayed_on_another() {
        let issuer_key = keypair(1);
        let requirement = requirement(&issuer_key);
        let holder = holder(&issuer_key, &keypair(2), ROOT);
        let challenge = requirement.challenge([9; 32]);
        let first = channel(5);
        let second = channel(6);
        let open = holder.answer(&challenge, first).expect("a request");

        assert!(
            requirement.decide(&challenge, &open, first, NOW).is_some(),
            "the channel that made the proof was refused"
        );
        assert_eq!(
            requirement.decide(&challenge, &open, second, NOW),
            None,
            "a proof moved between carriers"
        );
    }

    #[test]
    fn every_refusal_is_the_same_refusal() {
        // The reason a token failed is an oracle, so the wire carries one
        // answer whatever it was. This holds the rule where it can be
        // checked: the decision itself, which has no room for a detail.
        let issuer_key = keypair(1);
        let requirement = requirement(&issuer_key);
        let challenge = requirement.challenge([9; 32]);
        let holder_key = keypair(2);
        let binding = channel(5);

        let another_issuer = holder(&keypair(3), &holder_key, ROOT);
        let another_package = holder(&issuer_key, &holder_key, [8; 32]);
        let good = holder(&issuer_key, &holder_key, ROOT);

        let mut expired = good.answer(&challenge, binding).expect("a request");
        let mut wrong_nonce = good.answer(&challenge, binding).expect("a request");
        wrong_nonce.binding_proof = holder(&issuer_key, &holder_key, ROOT)
            .answer(&requirement.challenge([1; 32]), binding)
            .expect("a request made for another challenge")
            .binding_proof;
        let mut no_proof = good.answer(&challenge, binding).expect("a request");
        no_proof.binding_proof.clear();
        let mut wrong_format = good.answer(&challenge, binding).expect("a request");
        wrong_format.capability_format += 1;
        let mut not_a_token = good.answer(&challenge, binding).expect("a request");
        not_a_token.capability = vec![0xff; 8];

        for (name, request, now) in [
            (
                "another issuer",
                another_issuer
                    .answer(&challenge, binding)
                    .expect("a request"),
                NOW,
            ),
            (
                "another package",
                another_package
                    .answer(&challenge, binding)
                    .expect("a request"),
                NOW,
            ),
            ("a proof for another challenge", wrong_nonce, NOW),
            ("no proof at all", no_proof, NOW),
            ("a format nothing here reads", wrong_format, NOW),
            ("bytes that are not a token", not_a_token, NOW),
            // Past the window, and before it.
            ("expired", expired.clone(), NOW + 3_600 + 3_600),
            (
                "not yet valid",
                {
                    expired.session_id = [1; 16];
                    expired
                },
                NOW - 3_600 - 3_600,
            ),
        ] {
            assert_eq!(
                requirement.decide(&challenge, &request, binding, now),
                None,
                "{name} was granted"
            );
        }
        // And the one that should pass still does, so the loop above is not
        // measuring a decision that refuses everything.
        assert!(
            requirement
                .decide(
                    &challenge,
                    &good.answer(&challenge, binding).expect("a request"),
                    binding,
                    NOW
                )
                .is_some()
        );
    }

    #[test]
    fn a_holder_key_that_is_not_the_tokens_is_refused_before_the_wire() {
        let issuer_key = keypair(1);
        let token = issue(
            ISSUER,
            AUDIENCE,
            &issuer_key,
            keypair(2).verifying_key().to_bytes(),
            ROOT,
            NOW,
            3_600,
        )
        .expect("a token");
        assert!(
            matches!(Holder::new(token, keypair(4)), Err(Error::InvalidArguments)),
            "a key that cannot prove the token was accepted"
        );
    }

    #[test]
    fn a_window_of_no_length_is_not_a_capability() {
        let issuer_key = keypair(1);
        assert!(matches!(
            issue(
                ISSUER,
                AUDIENCE,
                &issuer_key,
                keypair(2).verifying_key().to_bytes(),
                ROOT,
                NOW,
                0
            ),
            Err(Error::InvalidArguments)
        ));
        assert!(
            matches!(
                issue(
                    ISSUER,
                    AUDIENCE,
                    &issuer_key,
                    keypair(2).verifying_key().to_bytes(),
                    ROOT,
                    u64::MAX,
                    1
                ),
                Err(Error::InvalidArguments)
            ),
            "a window that runs past the clock"
        );
    }

    #[test]
    fn the_challenge_asks_for_what_this_end_can_check() {
        let requirement = requirement(&keypair(1));
        let challenge = requirement.challenge([3; 32]);
        assert_eq!(challenge.nonce, vec![3; 32]);
        assert_eq!(challenge.binding, Binding::ProofOfPossession);
        assert_eq!(
            challenge.formats,
            vec![u64::from(vot_capability::FORMAT_ID)],
            "a format this end cannot read would refuse every token"
        );
        assert!(
            !challenge.formats.is_empty(),
            "an empty list is what says no authentication is required"
        );
    }

    #[test]
    fn a_package_token_carries_both_read_operations_ascending() {
        let operations = package_operations();
        assert_eq!(
            operations,
            vec![
                Operation::ReadManifest.identifier(),
                Operation::ReadRanges.identifier()
            ]
        );
        assert!(
            operations.windows(2).all(|pair| pair[0] < pair[1]),
            "the format wants them ascending with no repeats"
        );
    }

    #[test]
    fn the_clock_is_the_clock() {
        // A constant here would make every validity window meaningless: a
        // token minted at zero never expires against a verifier that also
        // reads zero.
        let now = now_seconds().expect("a clock");
        assert!(
            now > 1_767_225_600,
            "{now} is before 2026, so this is not reading the clock"
        );
        assert!(
            now < 4_102_444_800,
            "{now} is past 2100, so this is not reading the clock either"
        );
    }

    #[test]
    fn one_issuer_key_has_one_identifier() {
        let first = key_id_of(&keypair(1).verifying_key());
        assert_eq!(first, key_id_of(&keypair(1).verifying_key()), "derived");
        assert_ne!(first, key_id_of(&keypair(2).verifying_key()));
        assert!(
            (1..=64).contains(&first.len()),
            "outside what the format carries: {}",
            first.len()
        );
    }
}
