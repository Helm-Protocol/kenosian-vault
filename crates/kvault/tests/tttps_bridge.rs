use kvault::tttps_bridge::{admit_with, IngressError, ParseError, SystemState, POT_V2_LEN};

#[test]
fn invalid_ingress_has_zero_state_delta() {
    let mut state = SystemState::default();
    let before = state;
    let result = admit_with(&mut state, &[0xff; POT_V2_LEN], |record| {
        record.version == 0x02
    });
    assert_eq!(result, Err(IngressError::VerificationFailed));
    assert_eq!(state, before);
}

#[test]
fn short_frame_is_rejected_before_verifier() {
    let mut state = SystemState::default();
    let result = admit_with(&mut state, &[0; 179], |_| panic!("verifier called"));
    assert!(matches!(
        result,
        Err(IngressError::Parse(ParseError::InvalidFrameSize {
            expected: 180,
            actual: 179
        }))
    ));
    assert_eq!(state, SystemState::default());
}
