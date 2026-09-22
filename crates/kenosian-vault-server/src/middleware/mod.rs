pub mod constant_time;
pub mod ed25519_sig;
pub mod mtls;
pub mod tttps_seal;

/// Uniform failure response envelope.
///
/// Every rejection from every middleware returns the same 401 body,
/// regardless of the actual reason (bad signature, bad cert, missing header,
/// unknown FQN, quota exceeded). The real reason is logged internally only.
///
/// Reason: buyers with reverse-engineering intent probe with malformed inputs
/// and infer routing/policy from response deltas. Constant body + constant
/// timing (see `constant_time`) removes that channel.
pub const UNIFORM_UNAUTHORIZED_BODY: &str = r#"{"error":"unauthorized"}"#;
