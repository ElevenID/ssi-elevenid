use ssi_claims::{
    data_integrity::{AnySuite, DataIntegrity},
    vc::v1::JsonCredential,
    VerificationParameters,
};
use ssi_dids::{AnyDidMethod, VerificationMethodDIDResolver};
use ssi_verification_methods::AnyMethod;
use static_iref::uri;

#[async_std::test]
async fn ed25519_signature_2020() {
    let resolver = VerificationMethodDIDResolver::<_, AnyMethod>::new(AnyDidMethod::default());
    let mut signed_vc: DataIntegrity<JsonCredential, AnySuite> =
        serde_json::from_str(include_str!("fixtures/v1-ed25519-signed-vc.json")).unwrap();
    assert_eq!(
        signed_vc.issuer,
        uri!("did:key:z6MkgYAGxLBSXa6Ygk1PnUbK2F7zya8juE9nfsZhrvY7c9GD")
            .to_owned()
            .into()
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
