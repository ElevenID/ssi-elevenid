use ssi_claims_core::VerificationParameters;
use ssi_jwk::JWK;
use ssi_jws::JwsVec;
use ssi_sd_jwt::SdJwtBuf;
use ssi_vc::enveloped::{EnvelopedVerifiableCredential, EnvelopedVerifiablePresentation};
use ssi_vc_jose_cose::{JoseVc, JoseVp, SdJwtVc, SdJwtVp};

fn public_key(input: &str) -> JWK {
    serde_json::from_str(input).unwrap()
}

#[async_std::test]
async fn jose_credential_envelope_verifies() {
    let key = public_key(include_str!("fixtures/jose-vc-public.jwk.json"));
    let enveloped: EnvelopedVerifiableCredential =
        serde_json::from_str(include_str!("fixtures/jose-vc-enveloped.json")).unwrap();
    let jws = JwsVec::new(enveloped.id.decoded_data().unwrap().into_owned()).unwrap();
    let credential = JoseVc::decode_any(&jws).unwrap();
    assert_eq!(
        credential
            .verify(VerificationParameters::from_resolver(&key))
            .await
            .unwrap(),
        Ok(())
    );
}

#[async_std::test]
async fn jose_presentation_envelope_verifies() {
    let key = public_key(include_str!("fixtures/jose-vp-public.jwk.json"));
    let enveloped: EnvelopedVerifiablePresentation =
        serde_json::from_str(include_str!("fixtures/jose-vp-enveloped.json")).unwrap();
    let jws = JwsVec::new(enveloped.id.decoded_data().unwrap().into_owned()).unwrap();
    let presentation = JoseVp::decode_any(&jws).unwrap();
    assert_eq!(
        presentation
            .verify(VerificationParameters::from_resolver(&key))
            .await
            .unwrap(),
        Ok(())
    );
}

#[async_std::test]
async fn sd_jwt_credential_envelope_verifies() {
    let key = public_key(include_str!("fixtures/sdjwt-vc-public.jwk.json"));
    let enveloped: EnvelopedVerifiableCredential =
        serde_json::from_str(include_str!("fixtures/sdjwt-vc-enveloped.json")).unwrap();
    let sd_jwt = SdJwtBuf::new(enveloped.id.decoded_data().unwrap().into_owned()).unwrap();
    let credential = SdJwtVc::decode_reveal_any(&sd_jwt).unwrap();
    assert_eq!(
        credential
            .verify(VerificationParameters::from_resolver(&key))
            .await
            .unwrap(),
        Ok(())
    );
}

#[async_std::test]
async fn sd_jwt_presentation_envelope_verifies() {
    let key = public_key(include_str!("fixtures/sdjwt-vp-public.jwk.json"));
    let enveloped: EnvelopedVerifiablePresentation =
        serde_json::from_str(include_str!("fixtures/sdjwt-vp-enveloped.json")).unwrap();
    let sd_jwt = SdJwtBuf::new(enveloped.id.decoded_data().unwrap().into_owned()).unwrap();
    let presentation = SdJwtVp::decode_reveal_any(&sd_jwt).unwrap();
    assert_eq!(
        presentation
            .verify(VerificationParameters::from_resolver(&key))
            .await
            .unwrap(),
        Ok(())
    );
}
