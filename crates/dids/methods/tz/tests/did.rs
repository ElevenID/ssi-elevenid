use did_tz::DIDTz;
use iref::UriBuf;
use serde_json::json;
use ssi_claims::{
    data_integrity::{signing::AlterSignature, AnySuite, DataIntegrity},
    vc::{
        syntax::NonEmptyVec,
        v1::{JsonCredential, JsonPresentation},
    },
    VerificationParameters,
};
use ssi_dids_core::{did, resolution::Options, DIDResolver, VerificationMethodDIDResolver};
use ssi_jwk::JWK;
use ssi_verification_methods_core::ProofPurpose;
use static_iref::{iri, uri};

const TZ1: &str = "did:tz:tz1YwA1FwpgLtc1G8DKbbZ6e6PTb1dQMRn5x";
const TZ1_JSON: &str = "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"GvidwVqGgicuL68BRM89OOtDzK1gjs8IqUXFkjKkm8Iwg18slw==\"}";

const DIDTZ: DIDTz = DIDTz::new(None);

#[test]
fn jwk_to_did_tezos() {
    // TODO: add tz2 and tz3 test cases
    let jwk: JWK = serde_json::from_str(TZ1_JSON).unwrap();
    let tz1 = DIDTZ.generate(&jwk).unwrap();
    assert_eq!(tz1, TZ1);
}

#[test]
fn jwk_to_tz3() {
    let jwk: JWK = serde_json::from_value(serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": "UmzXjEZzlGmpaM_CmFEJtOO5JBntW8yl_fM1LEQlWQ4",
        "y": "OmoZmcbUadg7dEC8bg5kXryN968CJqv2UFMUKRERZ6s"
    }))
    .unwrap();
    let did = DIDTZ.generate(&jwk).unwrap();
    // https://github.com/murbard/pytezos/blob/a228a67fbc94b11dd7dbc7ff0df9e996d0ff5f01tests/test_crypto.py#L34
    assert_eq!(did, "did:tz:tz3agP9LGe2cXmKQyYn6T68BHKjjktDbbSWX");
}

#[tokio::test]
async fn test_too_short_did() {
    // Subslicing this method-specific id by byte range 0..3 would overflow.
    let bad_did = did!("did:tz:tz");
    assert!(DIDTZ
        .resolve_with(bad_did, Options::default())
        .await
        .is_err())
}

#[tokio::test]
async fn test_derivation_tz1() {
    let output = DIDTZ
        .resolve_with(
            did!("did:tz:mainnet:tz1TzrmTBSuiVHV2VfMnGRMYvTEPCP42oSM8"),
            Options::default(),
        )
        .await
        .unwrap();
    let doc = output.document;
    eprintln!("{}", serde_json::to_string_pretty(&doc).unwrap());
    assert_eq!(
        serde_json::to_value(doc).unwrap(),
        json!({
            "@context": [
                "https://www.w3.org/ns/did/v1",
                {
                    "blockchainAccountId": "https://w3id.org/security#blockchainAccountId",
                    "Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021": "https://w3id.org/security#Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021"
                }
            ],
            "id": "did:tz:mainnet:tz1TzrmTBSuiVHV2VfMnGRMYvTEPCP42oSM8",
            "verificationMethod": [{
                "id": "did:tz:mainnet:tz1TzrmTBSuiVHV2VfMnGRMYvTEPCP42oSM8#blockchainAccountId",
                "type": "Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021",
                "controller": "did:tz:mainnet:tz1TzrmTBSuiVHV2VfMnGRMYvTEPCP42oSM8",
                "blockchainAccountId": "tezos:NetXdQprcVkpaWU:tz1TzrmTBSuiVHV2VfMnGRMYvTEPCP42oSM8"
            }],
            "authentication": [
                "did:tz:mainnet:tz1TzrmTBSuiVHV2VfMnGRMYvTEPCP42oSM8#blockchainAccountId"
            ],
            "assertionMethod": [
                "did:tz:mainnet:tz1TzrmTBSuiVHV2VfMnGRMYvTEPCP42oSM8#blockchainAccountId"
            ]
        })
    );
}

#[tokio::test]
async fn test_derivation_tz2() {
    let output = DIDTZ
        .resolve_with(
            did!("did:tz:mainnet:tz2BFTyPeYRzxd5aiBchbXN3WCZhx7BqbMBq"),
            Options::default(),
        )
        .await
        .unwrap();
    let doc = output.document;
    eprintln!("{}", serde_json::to_string_pretty(&doc).unwrap());
    assert_eq!(
        serde_json::to_value(doc).unwrap(),
        json!({
            "@context": [
            "https://www.w3.org/ns/did/v1",
            {
                "blockchainAccountId": "https://w3id.org/security#blockchainAccountId",
                "EcdsaSecp256k1RecoveryMethod2020": "https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#EcdsaSecp256k1RecoveryMethod2020"
            }
            ],
            "id": "did:tz:mainnet:tz2BFTyPeYRzxd5aiBchbXN3WCZhx7BqbMBq",
            "verificationMethod": [{
            "id": "did:tz:mainnet:tz2BFTyPeYRzxd5aiBchbXN3WCZhx7BqbMBq#blockchainAccountId",
            "type": "EcdsaSecp256k1RecoveryMethod2020",
            "controller": "did:tz:mainnet:tz2BFTyPeYRzxd5aiBchbXN3WCZhx7BqbMBq",
            "blockchainAccountId": "tezos:NetXdQprcVkpaWU:tz2BFTyPeYRzxd5aiBchbXN3WCZhx7BqbMBq"
            }],
            "authentication": [
            "did:tz:mainnet:tz2BFTyPeYRzxd5aiBchbXN3WCZhx7BqbMBq#blockchainAccountId"
            ],
            "assertionMethod": [
            "did:tz:mainnet:tz2BFTyPeYRzxd5aiBchbXN3WCZhx7BqbMBq#blockchainAccountId"
            ]
        })
    );
}

#[tokio::test]
async fn test_derivation_tz3() {
    let resolved = DIDTZ
        .resolve_with(
            did!("did:tz:mainnet:tz3agP9LGe2cXmKQyYn6T68BHKjjktDbbSWX"),
            Options::default(),
        )
        .await
        .unwrap();
    let doc = resolved.document;
    eprintln!("{}", serde_json::to_string_pretty(&doc).unwrap());
    assert_eq!(
        serde_json::to_value(doc).unwrap(),
        json!({
            "@context": [
                "https://www.w3.org/ns/did/v1",
                {
                "P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021": "https://w3id.org/security#P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021",
                "blockchainAccountId": "https://w3id.org/security#blockchainAccountId"
                }
            ],
            "id": "did:tz:mainnet:tz3agP9LGe2cXmKQyYn6T68BHKjjktDbbSWX",
            "verificationMethod": [{
                "id": "did:tz:mainnet:tz3agP9LGe2cXmKQyYn6T68BHKjjktDbbSWX#blockchainAccountId",
                "type": "P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021",
                "controller": "did:tz:mainnet:tz3agP9LGe2cXmKQyYn6T68BHKjjktDbbSWX",
                "blockchainAccountId": "tezos:NetXdQprcVkpaWU:tz3agP9LGe2cXmKQyYn6T68BHKjjktDbbSWX"
            }],
            "authentication": [
                "did:tz:mainnet:tz3agP9LGe2cXmKQyYn6T68BHKjjktDbbSWX#blockchainAccountId"
            ],
            "assertionMethod": [
                "did:tz:mainnet:tz3agP9LGe2cXmKQyYn6T68BHKjjktDbbSWX#blockchainAccountId"
            ]
        })
    )
}

#[tokio::test]
async fn credential_prove_verify_did_tz1() {
    // use ssi_claims::{Credential, Issuer, LinkedDataProofOptions, URI};
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("v1/contracts"))
        .and(query_param(
            "creator",
            "tz1WvvbEGpBXGeTVbLiR6DYBe1izmgiYuZbq",
        ))
        .and(query_param("codeHash", "1222545108"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!(["KT1ACXxefCq3zVG9cth4whZqS1XYK9Qsn8Gi"])),
        )
        .mount(&mock_server)
        .await;
    Mock::given(method("GET"))
		.and(path(format!("v1/contracts/{}/storage", "KT1ACXxefCq3zVG9cth4whZqS1XYK9Qsn8Gi")))
		.respond_with(
		ResponseTemplate::new(200)
		.set_body_json(json!({"verification_method": "did:tz:delphinet:tz1WvvbEGpBXGeTVbLiR6DYBe1izmgiYuZbq#blockchainAccountId",
			"service": {"type_": "TezosDiscoveryService", "endpoint": "http://example.com"}})),
		)
		.mount(&mock_server)
		.await;

    let didtz = VerificationMethodDIDResolver::new(DIDTz::new(Some(
        UriBuf::new(mock_server.uri().into_bytes()).unwrap(),
    )));
    let params = VerificationParameters::from_resolver(&didtz);

    let did = did!("did:tz:delphinet:tz1WvvbEGpBXGeTVbLiR6DYBe1izmgiYuZbq").to_owned();
    let vc = DataIntegrity::new(
        JsonCredential::new(
            None,
            did.clone().into_uri().into(),
            "2021-01-27T16:39:07Z".parse().unwrap(),
            NonEmptyVec::new(json_syntax::json!({
                "id": "did:example:foo"
            }))
        ),
        vec![ssi_claims::data_integrity::Proof::new(
            ssi_claims::data_integrity::suites::Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021,
            "2021-03-02T18:59:44.462Z".parse().unwrap(),
            iri!("did:tz:delphinet:tz1WvvbEGpBXGeTVbLiR6DYBe1izmgiYuZbq#blockchainAccountId").to_owned().into(),
            ProofPurpose::Assertion,
            ssi_claims::data_integrity::suites::tezos::Options::new(
                r#"{"crv": "Ed25519","kty": "OKP","x": "CFdO_rVP08v1wQQVNybqBxHmTPOBPIt4Kn6LLhR1fMA"}"#.parse().unwrap()
            ),
            ssi_claims::data_integrity::signing::DetachedJwsSignature::new(
                // FIXME: this is wrong! The VM expects an EdBlake2b signature,
                // instead this is EdDsa.
                "eyJhbGciOiJFZERTQSIsImNyaXQiOlsiYjY0Il0sImI2NCI6ZmFsc2V9..thpumbPTltH6b6P9QUydy8DcoK2Jj63-FIntxiq09XBk7guF_inA0iQWw7_B_GBwmmsmhYdGL4TdtiNieAdeAg".parse().unwrap()
            )
        ).with_context(ssi_claims::data_integrity::suites::tezos::TZ_CONTEXT.clone().into())].into()
    );

    // FIXME: this cannot work because the VC is wrong!
    // `Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021` expects an
    // EdBlake2b signature, but the provided signature is EdDsa.
    // assert_eq!(vc.verify(&didtz).await.unwrap(), Ok(()));

    // test that issuer property is used for verification
    let mut _vc_bad_issuer = vc.clone();
    _vc_bad_issuer.issuer = uri!("did:example:bad").to_owned().into();

    // FIXME: this cannot work because the VC is wrong! See above.
    // assert!(vc_bad_issuer.verify(&didtz).await.unwrap().is_err());

    // Check that proof JWK must match proof verificationMethod
    let vc_wrong_key: DataIntegrity<JsonCredential, AnySuite> =
        serde_json::from_str(include_str!("fixtures/tz1-wrong-vc.json")).unwrap();
    assert!(vc_wrong_key.verify(&params).await.unwrap().is_err());

    let vp = DataIntegrity::new(
        JsonPresentation::new(
            Some(uri!("http://example.org/presentations/3731").to_owned()),
            Some(did.into()),
            vec![vc]
        ),
        vec![ssi_claims::data_integrity::Proof::new(
            ssi_claims::data_integrity::suites::Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021,
            "2021-03-02T19:05:08.271Z".parse().unwrap(),
            iri!("did:tz:delphinet:tz1WvvbEGpBXGeTVbLiR6DYBe1izmgiYuZbq#blockchainAccountId").to_owned().into(),
            ProofPurpose::Authentication,
            ssi_claims::data_integrity::suites::tezos::Options::new(
                r#"{"crv": "Ed25519","kty": "OKP","x": "CFdO_rVP08v1wQQVNybqBxHmTPOBPIt4Kn6LLhR1fMA"}"#.parse().unwrap()
            ),
            ssi_claims::data_integrity::signing::DetachedJwsSignature::new(
                // FIXME: this is wrong! The VM expects an EdBlake2b signature,
                // instead this is EdDsa.
                "eyJhbGciOiJFZERTQSIsImNyaXQiOlsiYjY0Il0sImI2NCI6ZmFsc2V9..7GLIUeNKvO3WsA3DmBZpbuPinhOcv7Mhgx9QP0svO55T_Zoy7wmJJtLXSoghtkI7DWOnVbiJO5X246Qr0CqGDw".parse().unwrap()
            )
        ).with_context(ssi_claims::data_integrity::suites::tezos::TZ_CONTEXT.clone().into())].into()
    );

    println!("VP: {}", serde_json::to_string_pretty(&vp).unwrap());

    // FIXME: this cannot work because the VP is wrong! See above.
    // assert!(vp.verify(&didtz).await.unwrap().is_ok());

    // mess with the VP proof to make verify fail
    let mut vp1: DataIntegrity<JsonPresentation, AnySuite> =
        serde_json::from_value(serde_json::to_value(&vp).unwrap()).unwrap();
    vp1.proofs.first_mut().unwrap().signature.alter();
    let tampered_result = vp1.verify(&params).await;
    assert!(tampered_result.is_err() || tampered_result.is_ok_and(|result| result.is_err()));

    // test that holder is verified
    let mut _vp2 = vp.clone();
    _vp2.holder = Some(did!("did:example:bad").to_owned().into());

    // FIXME: this cannot work because the VP is wrong! See above.
    // assert!(vp2.verify(&didtz).await.unwrap().is_err());
}

async fn signed_tezos_vectors_verify(
    public_json: &str,
    vc_json: &str,
    wrong_vc_json: &str,
    vp_json: &str,
) {
    let public_key: JWK = serde_json::from_str(public_json).unwrap();
    let did = DIDTZ.generate(&public_key).unwrap();
    let resolver = VerificationMethodDIDResolver::new(DIDTZ);
    let params = VerificationParameters::from_resolver(&resolver);

    let mut vc: DataIntegrity<JsonCredential, AnySuite> = serde_json::from_str(vc_json).unwrap();
    assert_eq!(vc.issuer, did.clone().into_uri().into());
    assert!(vc.verify(&params).await.unwrap().is_ok());

    vc.issuer = uri!("did:example:bad").to_owned().into();
    assert!(vc.verify(&params).await.unwrap().is_err());

    let wrong_key_vc: DataIntegrity<JsonCredential, AnySuite> =
        serde_json::from_str(wrong_vc_json).unwrap();
    assert!(wrong_key_vc.verify(&params).await.unwrap().is_err());

    let mut vp: DataIntegrity<JsonPresentation, AnySuite> = serde_json::from_str(vp_json).unwrap();
    assert_eq!(vp.holder.as_ref().unwrap().as_str(), did.as_str());
    assert!(vp.verify(&params).await.unwrap().is_ok());

    vp.proofs.first_mut().unwrap().signature.alter();
    let tampered_result = vp.verify(&params).await;
    assert!(tampered_result.is_err() || tampered_result.is_ok_and(|result| result.is_err()));

    let mut vp: DataIntegrity<JsonPresentation, AnySuite> = serde_json::from_str(vp_json).unwrap();
    vp.holder = Some(did!("did:example:bad").to_owned().into());
    assert!(vp.verify(&params).await.unwrap().is_err());
}

#[tokio::test]
async fn credential_prove_verify_did_tz2() {
    signed_tezos_vectors_verify(
        include_str!("fixtures/tz2-public.json"),
        include_str!("fixtures/tz2-vc.json"),
        include_str!("fixtures/tz2-wrong-vc.json"),
        include_str!("fixtures/tz2-vp.json"),
    )
    .await;
}

#[tokio::test]
async fn credential_prove_verify_did_tz3() {
    signed_tezos_vectors_verify(
        include_str!("fixtures/tz3-public.json"),
        include_str!("fixtures/tz3-vc.json"),
        include_str!("fixtures/tz3-wrong-vc.json"),
        include_str!("fixtures/tz3-vp.json"),
    )
    .await;
}
