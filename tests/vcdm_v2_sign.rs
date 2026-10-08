use serde_json::json;
use ssi_claims::{
    data_integrity::{AnySuite, DataIntegrity},
    vc::v2::JsonCredential,
    VerificationParameters,
};
use ssi_dids::{AnyDidMethod, VerificationMethodDIDResolver};
use ssi_verification_methods::AnyMethod;
use static_iref::uri;

#[cfg(all(feature = "w3c", feature = "bbs"))]
use ssi::JWK;

async fn signed_ecdsa_vc_verifies(fixture: &str, expected_issuer: &str) {
    let resolver = VerificationMethodDIDResolver::<_, AnyMethod>::new(AnyDidMethod::default());
    let mut signed_vc: DataIntegrity<JsonCredential, AnySuite> =
        serde_json::from_str(fixture).unwrap();
    assert_eq!(
        serde_json::to_value(&signed_vc.issuer).unwrap(),
        json!(expected_issuer)
    );
    signed_vc
        .verify(VerificationParameters::from_resolver(&resolver))
        .await
        .unwrap()
        .unwrap();

    signed_vc.issuer = uri!("did:example:bad").to_owned().into();
    assert!(signed_vc
        .verify(VerificationParameters::from_resolver(&resolver))
        .await
        .unwrap()
        .is_err());
}

#[cfg(feature = "secp256r1")]
#[async_std::test]
async fn ecdsa_rdfc_2019_p256() {
    signed_ecdsa_vc_verifies(
        include_str!("fixtures/v2-p256-signed-vc.json"),
        "did:key:zDnaeqRNmCGRy8f4RgNSoj9YiwG697iWB7htXNX89G8Nu3Hxo",
    )
    .await;
}

#[cfg(feature = "secp384r1")]
#[async_std::test]
async fn ecdsa_rdfc_2019_p384() {
    signed_ecdsa_vc_verifies(
        include_str!("fixtures/v2-p384-signed-vc.json"),
        "did:key:z82LkvutaARmY8poLhUnMCAhFbts88q4yDBmkqwRFYbxpFvmE1nbGUGLKf9fD66LGUbXDce",
    )
    .await;
}
#[cfg(all(feature = "w3c", feature = "bbs"))]
#[async_std::test]
async fn bbs_2023() {
    use json_syntax::Value;

    let public_key: JWK =
        serde_json::from_str(include_str!("fixtures/v2-bbs-public.jwk.json")).unwrap();
    let did_url = ssi::dids::DIDKey::generate_url(&public_key).unwrap();
    let resolver = VerificationMethodDIDResolver::<_, AnyMethod>::new(AnyDidMethod::default());
    let base_vc: DataIntegrity<JsonCredential, AnySuite> =
        serde_json::from_str(include_str!("fixtures/v2-bbs-signed-vc.json")).unwrap();
    assert_eq!(
        serde_json::to_value(&base_vc.issuer).unwrap(),
        json!(did_url.to_string())
    );

    let params = VerificationParameters::from_resolver(&resolver);
    let mut selection = ssi::claims::data_integrity::AnySelectionOptions::default();
    selection.selective_pointers = vec![
        "/id".parse().unwrap(),
        "/type".parse().unwrap(),
        "/credentialSubject/foo".parse().unwrap(),
        "/issuer".parse().unwrap(),
    ];
    let derived = base_vc
        .select(&params, selection)
        .await
        .unwrap()
        .map(|object| {
            ssi::json_ld::syntax::from_value::<JsonCredential>(Value::Object(object)).unwrap()
        });

    let derived_json = serde_json::to_value(&derived).unwrap();
    assert_eq!(derived_json["credentialSubject"]["foo"], "value1");
    assert!(derived_json["credentialSubject"].get("bar").is_none());
    derived.verify(params).await.unwrap().unwrap();
}
