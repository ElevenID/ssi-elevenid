#![cfg(feature = "bbs")]

use ssi_jwk::{Error, Params, JWK};

#[test]
fn bbs_jwk_exposes_only_public_key_conversion() {
    let jwk: JWK = serde_json::from_str(include_str!(
        "../../../tests/fixtures/v2-bbs-public.jwk.json"
    ))
    .unwrap();
    let public: ssi_bbs::BBSplusPublicKey = (&jwk).try_into().unwrap();
    assert_eq!(JWK::from(public), jwk);

    let mut with_private_parameter = jwk;
    if let Params::EC(params) = &mut with_private_parameter.params {
        params.ecc_private_key = Some(());
    } else {
        unreachable!();
    }
    assert!(matches!(
        ssi_bbs::BBSplusPublicKey::try_from(&with_private_parameter),
        Err(Error::LocalKeyOperationsDisabled)
    ));
}
