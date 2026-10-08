#![cfg(all(feature = "eip", feature = "tezos"))]

use did_pkh::DIDPKH;
use serde::Deserialize;
use ssi_claims::{
    data_integrity::{signing::AlterSignature, AnySuite, DataIntegrity},
    vc::v1::{JsonCredential, JsonPresentation},
    VerificationParameters,
};
use ssi_dids_core::VerificationMethodDIDResolver;
use ssi_jwk::JWK;
use static_iref::uri;

#[derive(Deserialize)]
struct SignedCase {
    name: String,
    chain_type: String,
    public: JWK,
    vc: DataIntegrity<JsonCredential, AnySuite>,
    wrong_vc: DataIntegrity<JsonCredential, AnySuite>,
    vp: DataIntegrity<JsonPresentation, AnySuite>,
}

#[tokio::test]
async fn supported_pkh_suites_verify_public_vectors() {
    let cases: Vec<SignedCase> =
        serde_json::from_str(include_str!("fixtures/signed-pkh-cases.json")).unwrap();
    let expected_cases = [
        ("eth-recovery", "eip155"),
        ("eth-eip712", "eip155"),
        ("eth-personal-from-typed-key", "eip155"),
        ("eth-eip712-domain", "eip155"),
        ("eth-eip712-from-personal-key", "eip155"),
        ("tz-ed-blake2b", "tz"),
        ("tz-p256-blake2b", "tz"),
        ("sol-ed25519", "sol"),
        ("btc-recovery", "btc"),
        ("doge-recovery", "doge"),
        ("tz-ed-tezos-signature", "tz"),
        ("tz-p256-tezos-signature", "tz"),
    ];
    assert_eq!(cases.len(), expected_cases.len());
    let resolver = VerificationMethodDIDResolver::new(DIDPKH);
    let verifier = VerificationParameters::from_resolver(&resolver);

    for (case, (name, chain_type)) in cases.into_iter().zip(expected_cases) {
        assert_eq!(case.name, name);
        assert_eq!(case.chain_type, chain_type);
        let did = DIDPKH::generate(&case.public, &case.chain_type).unwrap();
        assert_eq!(
            case.vc.issuer,
            did.clone().into_uri().into(),
            "{}",
            case.name
        );
        assert!(
            case.vc.verify(&verifier).await.unwrap().is_ok(),
            "{}",
            case.name
        );

        let mut wrong_issuer = case.vc.clone();
        wrong_issuer.issuer = uri!("did:pkh:example:bad").to_owned().into();
        assert!(
            wrong_issuer.verify(&verifier).await.unwrap().is_err(),
            "{}",
            case.name
        );
        assert!(
            case.wrong_vc.verify(&verifier).await.unwrap().is_err(),
            "{}",
            case.name
        );

        let mut tampered_vc = case.vc.clone();
        tampered_vc.proofs.first_mut().unwrap().signature.alter();
        let result = tampered_vc.verify(&verifier).await;
        assert!(
            result.is_err() || result.is_ok_and(|value| value.is_err()),
            "{}",
            case.name
        );

        assert_eq!(
            case.vp.holder.as_ref().unwrap().as_str(),
            did.as_str(),
            "{}",
            case.name
        );
        assert!(
            case.vp.verify(&verifier).await.unwrap().is_ok(),
            "{}",
            case.name
        );

        let mut tampered_vp = case.vp.clone();
        tampered_vp.proofs.first_mut().unwrap().signature.alter();
        let result = tampered_vp.verify(&verifier).await;
        assert!(
            result.is_err() || result.is_ok_and(|value| value.is_err()),
            "{}",
            case.name
        );

        let mut wrong_holder = case.vp;
        wrong_holder.holder = Some(uri!("did:pkh:example:bad").to_owned());
        assert!(
            wrong_holder.verify(&verifier).await.unwrap().is_err(),
            "{}",
            case.name
        );
    }
}
