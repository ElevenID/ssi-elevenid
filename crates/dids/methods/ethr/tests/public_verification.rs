use did_ethr::DIDEthr;
use ssi_claims::{
    data_integrity::{signing::AlterSignature, AnySuite},
    vc::v1::{JsonCredential, JsonPresentation},
    VerificationParameters,
};
use ssi_data_integrity::DataIntegrity;
use ssi_dids_core::DIDResolver;
use ssi_jwk::JWK;
use static_iref::uri;

async fn signed_vectors_verify(
    credential_json: &str,
    wrong_key_credential_json: &str,
    presentation_json: &str,
    expected_signature: &str,
) {
    let public_key: JWK = serde_json::from_str(include_str!("fixtures/public.jwk.json")).unwrap();
    let did = DIDEthr::generate(&public_key).unwrap();
    let resolver = DIDEthr.into_vm_resolver();
    let verifier = VerificationParameters::from_resolver(&resolver);

    let mut vc: DataIntegrity<JsonCredential, AnySuite> =
        serde_json::from_str(credential_json).unwrap();
    assert_eq!(vc.issuer, did.clone().into_uri().into());
    assert_eq!(
        vc.proofs.first().unwrap().signature.as_ref(),
        expected_signature
    );
    assert!(vc.verify(&verifier).await.unwrap().is_ok());

    vc.issuer = uri!("did:pkh:example:bad").to_owned().into();
    assert!(vc.verify(&verifier).await.unwrap().is_err());

    let wrong_key_vc: DataIntegrity<JsonCredential, AnySuite> =
        serde_json::from_str(wrong_key_credential_json).unwrap();
    assert!(wrong_key_vc.verify(&verifier).await.unwrap().is_err());

    let mut vp: DataIntegrity<JsonPresentation, AnySuite> =
        serde_json::from_str(presentation_json).unwrap();
    assert!(vp.verify(&verifier).await.unwrap().is_ok());

    vp.proofs.first_mut().unwrap().signature.alter();
    let tampered_result = vp.verify(&verifier).await;
    assert!(tampered_result.is_err() || tampered_result.is_ok_and(|result| result.is_err()));

    let mut vp: DataIntegrity<JsonPresentation, AnySuite> =
        serde_json::from_str(presentation_json).unwrap();
    vp.holder = Some(uri!("did:pkh:example:bad").to_owned());
    assert!(vp.verify(&verifier).await.unwrap().is_err());
}

#[tokio::test]
async fn recovery_suite_verifies_public_vectors() {
    signed_vectors_verify(
        include_str!("fixtures/recovery-vc.json"),
        include_str!("fixtures/recovery-wrong-vc.json"),
        include_str!("fixtures/recovery-vp.json"),
        "eyJhbGciOiJFUzI1NkstUiIsImNyaXQiOlsiYjY0Il0sImI2NCI6ZmFsc2V9..nwNfIHhCQlI-j58zgqwJgX2irGJNP8hqLis-xS16hMwzs3OuvjqzZIHlwvdzDMPopUA_Oq7M7Iql2LNe0B22oQE",
    )
    .await;
}

#[tokio::test]
async fn eip712_suite_verifies_public_vectors() {
    signed_vectors_verify(
        include_str!("fixtures/eip712-vc.json"),
        include_str!("fixtures/eip712-wrong-vc.json"),
        include_str!("fixtures/eip712-vp.json"),
        "0xd3f4a049551fd25c7fb0789c7303be63265e8ade2630747de3807710382bbb7a25b0407e9f858a771782c35b4f487f4337341e9a4375a073730bda643895964e1b",
    )
    .await;
}
