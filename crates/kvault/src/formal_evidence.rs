//! Identifiers for the TTTPS formal-evidence binding.
//!
//! These constants identify an external receipt and manifest. They do not
//! claim that this Rust bridge is a mechanically verified refinement.

pub const FORMAL_PROOF_RECEIPT_ID: &str = "33108706ed730e5296ae1b06";
pub const FORMAL_BINDING_MANIFEST_SHA256: &str =
    "0bfadc1791f60c34183238ba934b8304015d403a1dbeefb6a7687436fda3627a";
pub const FORMAL_LEAN_SOURCE_SHA256: &str =
    "6116b82318d540a1e4e5b694e31978739851f658356330349b9d4289aeb5bae8";
pub const FORMAL_VERIFY_URL: &str =
    "https://kpp.kenosian.com/v1/verify?receipt_id=33108706ed730e5296ae1b06";
