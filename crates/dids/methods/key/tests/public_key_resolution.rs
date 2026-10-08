use did_method_key::DIDKey;
use ssi_claims::{data_integrity::AnySuite, vc::v1::JsonCredential, VerificationParameters};
use ssi_data_integrity::DataIntegrity;
use ssi_dids_core::{DIDResolver, VerificationMethodDIDResolver};
use ssi_jwk::{JWKResolver, JWK};
use ssi_verification_methods::AnyMethod;
use static_iref::uri;

async fn fetch_public_jwk(jwk_json: &str) {
    let jwk: JWK = serde_json::from_str(jwk_json).unwrap();
    let did = DIDKey::generate(&jwk).unwrap();
    let resolver: VerificationMethodDIDResolver<_, AnyMethod> =
        VerificationMethodDIDResolver::new(DIDKey);
    let method = DIDKey
        .resolve_into_any_verification_method(&did)
        .await
        .unwrap()
        .unwrap();
    let resolved = resolver.fetch_public_jwk(Some(&method.id)).await.unwrap();
    assert_eq!(*resolved, jwk);
}

#[async_std::test]
async fn ed25519_public_key_resolves() {
    fetch_public_jwk(include_str!(
        "../../../../../tests/public_keys/ed25519.json"
    ))
    .await;
}

#[cfg(feature = "secp256k1")]
#[async_std::test]
async fn secp256k1_public_key_resolves() {
    fetch_public_jwk(include_str!(
        "../../../../../tests/public_keys/secp256k1.json"
    ))
    .await;
}

#[cfg(feature = "secp256r1")]
#[async_std::test]
async fn p256_public_key_resolves() {
    fetch_public_jwk(include_str!("../../../../../tests/public_keys/p256.json")).await;
}

#[cfg(feature = "secp384r1")]
#[async_std::test]
async fn p384_public_key_resolves() {
    fetch_public_jwk(include_str!("../../../../../tests/public_keys/p384.json")).await;
}

async fn signed_credential_verifies(jwk_json: &str, credential_json: &str, expected_jws: &str) {
    let public_key: JWK = serde_json::from_str(jwk_json).unwrap();
    let mut credential: DataIntegrity<JsonCredential, AnySuite> =
        serde_json::from_str(credential_json).unwrap();
    let did = DIDKey::generate(&public_key).unwrap();
    assert_eq!(credential.issuer, did.clone().into_uri().into());
    assert_eq!(
        credential.proofs.first().unwrap().signature.as_ref(),
        expected_jws
    );

    let resolver = VerificationMethodDIDResolver::new(DIDKey);
    let params = VerificationParameters::from_resolver(&resolver);
    assert!(credential.verify(&params).await.unwrap().is_ok());

    credential.issuer = uri!("did:pkh:example:bad").to_owned().into();
    assert!(credential.verify(&params).await.unwrap().is_err());
}

#[async_std::test]
async fn signed_ed25519_credential_verifies_with_public_did_key() {
    signed_credential_verifies(
        include_str!("fixtures/ed25519-public.jwk.json"),
        include_str!("fixtures/ed25519-signed-vc.json"),
        "eyJhbGciOiJFZERTQSIsImNyaXQiOlsiYjY0Il0sImI2NCI6ZmFsc2V9..o4SzDo1RBQqdK49OPdmfVRVh68xCTNEmb7hq39IVqISkelld6t6Aatg4PCXKpopIXmX8RCCF4BwrO8ERg1YFBg",
    )
    .await;
}

#[cfg(feature = "secp256k1")]
#[async_std::test]
async fn signed_secp256k1_credential_verifies_with_public_did_key() {
    signed_credential_verifies(
        include_str!("fixtures/secp256k1-public.jwk.json"),
        include_str!("fixtures/secp256k1-signed-vc.json"),
        "eyJhbGciOiJFUzI1NksiLCJjcml0IjpbImI2NCJdLCJiNjQiOmZhbHNlfQ..jTUkFd_eYI72Y8j2OS5LRLhlc3gZn-gVsb76soi3FuJ5gWrbOb0W2CW6D-sjEsCuLkvSOfYd8Y8hB9pyeeZ2TQ",
    )
    .await;
}

#[cfg(feature = "secp256r1")]
#[async_std::test]
async fn signed_p256_credential_verifies_with_public_did_key() {
    signed_credential_verifies(
        include_str!("fixtures/p256-public.jwk.json"),
        include_str!("fixtures/p256-signed-vc.json"),
        "eyJhbGciOiJFUzI1NiIsImNyaXQiOlsiYjY0Il0sImI2NCI6ZmFsc2V9..y8dqMGW7w-bLGT_iDvBrdwNOt-PBrNAVSrST0cWLVy8hv-WfyYAz6v1y3ZgHqgzgq2qeAO9jDSGdI5cLTxIApw",
    )
    .await;
}
