//! Small Rust bridge for the already-checked TTTPS v2 ingress model.
//!
//! This is not a replacement for the existing OpenTTT/GRG runtime. It gives
//! KVault/OmniVault a fixed-record adapter with the same admission boundary as
//! `KLean.TTTPS.Core`: reject malformed input before state mutation and commit
//! only after the caller's verifier succeeds.

use core::convert::TryFrom;

pub const POT_V2_LEN: usize = 180;

/// Wire-shaped storage. Integer fields remain byte arrays so no unaligned
/// integer load is possible. Decode them explicitly as big-endian values.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PoTRecordV2 {
    pub version: u8,
    pub holder_auth_type: u8,
    pub alg_id: [u8; 2],
    pub ts: [u8; 8],
    pub dispersion: [u8; 4],
    pub ctx_id: [u8; 16],
    pub nonce: [u8; 16],
    pub holder_auth_data: [u8; 32],
    pub integrity_tag: [u8; 32],
    pub issuer_key_id: [u8; 4],
    pub issuer_sig: [u8; 64],
}

const _: () = assert!(core::mem::size_of::<PoTRecordV2>() == POT_V2_LEN);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseError {
    InvalidFrameSize { expected: usize, actual: usize },
}

impl PoTRecordV2 {
    pub fn alg_id_u16(&self) -> u16 {
        u16::from_be_bytes(self.alg_id)
    }
    pub fn ts_u64(&self) -> u64 {
        u64::from_be_bytes(self.ts)
    }
    pub fn issuer_key_id_u32(&self) -> u32 {
        u32::from_be_bytes(self.issuer_key_id)
    }
}

impl TryFrom<&[u8]> for PoTRecordV2 {
    type Error = ParseError;

    fn try_from(raw: &[u8]) -> Result<Self, Self::Error> {
        if raw.len() != POT_V2_LEN {
            return Err(ParseError::InvalidFrameSize {
                expected: POT_V2_LEN,
                actual: raw.len(),
            });
        }
        let mut out = Self {
            version: raw[0],
            holder_auth_type: raw[1],
            alg_id: [0; 2],
            ts: [0; 8],
            dispersion: [0; 4],
            ctx_id: [0; 16],
            nonce: [0; 16],
            holder_auth_data: [0; 32],
            integrity_tag: [0; 32],
            issuer_key_id: [0; 4],
            issuer_sig: [0; 64],
        };
        out.alg_id.copy_from_slice(&raw[2..4]);
        out.ts.copy_from_slice(&raw[4..12]);
        out.dispersion.copy_from_slice(&raw[12..16]);
        out.ctx_id.copy_from_slice(&raw[16..32]);
        out.nonce.copy_from_slice(&raw[32..48]);
        out.holder_auth_data.copy_from_slice(&raw[48..80]);
        out.integrity_tag.copy_from_slice(&raw[80..112]);
        out.issuer_key_id.copy_from_slice(&raw[112..116]);
        out.issuer_sig.copy_from_slice(&raw[116..180]);
        Ok(out)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SystemState {
    pub app_state: u64,
    pub commit_marker: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IngressError {
    Parse(ParseError),
    VerificationFailed,
}

/// No state is changed on parse or verification failure.
pub fn admit_with<F>(state: &mut SystemState, raw: &[u8], verify: F) -> Result<(), IngressError>
where
    F: FnOnce(&PoTRecordV2) -> bool,
{
    let record = PoTRecordV2::try_from(raw).map_err(IngressError::Parse)?;
    if !verify(&record) {
        return Err(IngressError::VerificationFailed);
    }
    state.app_state += 1;
    state.commit_marker += 1;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_layout_is_180_octets() {
        assert_eq!(core::mem::size_of::<PoTRecordV2>(), 180);
    }

    #[test]
    fn malformed_input_does_not_mutate_state() {
        let mut state = SystemState::default();
        let before = state;
        assert!(matches!(
            admit_with(&mut state, &[0xff; POT_V2_LEN - 1], |_| true),
            Err(IngressError::Parse(ParseError::InvalidFrameSize { .. }))
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn verifier_failure_does_not_mutate_state() {
        let mut state = SystemState::default();
        let before = state;
        assert_eq!(
            admit_with(&mut state, &[0xff; POT_V2_LEN], |r| r.version == 0x02),
            Err(IngressError::VerificationFailed)
        );
        assert_eq!(state, before);
    }

    #[test]
    fn verified_record_commits_once() {
        let mut state = SystemState::default();
        assert_eq!(admit_with(&mut state, &[0; POT_V2_LEN], |_| true), Ok(()));
        assert_eq!(
            state,
            SystemState {
                app_state: 1,
                commit_marker: 1
            }
        );
    }
}
