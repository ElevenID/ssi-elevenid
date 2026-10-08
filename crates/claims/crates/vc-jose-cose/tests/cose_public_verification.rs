use serde::Deserialize;
use ssi_claims_core::VerificationParameters;
use ssi_cose::{coset::CborSerializable, CoseKey, CoseSign1BytesBuf};
use ssi_vc_jose_cose::{CoseVc, CoseVp};

#[derive(Deserialize)]
struct SignedCase {
    name: String,
    public_hex: String,
    signed_hex: String,
}

#[async_std::test]
async fn signed_credential_and_presentation_verify_with_public_keys() {
    let cases: Vec<SignedCase> =
        serde_json::from_str(include_str!("fixtures/cose-signed-cases.json")).unwrap();
    assert_eq!(cases.len(), 2);

    for case in cases {
        let key = CoseKey::from_slice(&hex::decode(case.public_hex).unwrap()).unwrap();
        let signed = CoseSign1BytesBuf::new(hex::decode(case.signed_hex).unwrap());
        let result = match case.name.as_str() {
            "vc" => CoseVc::decode_any(&signed, true)
                .unwrap()
                .verify(VerificationParameters::from_resolver(&key))
                .await
                .unwrap(),
            "vp" => CoseVp::decode_any(&signed, true)
                .unwrap()
                .verify(VerificationParameters::from_resolver(&key))
                .await
                .unwrap(),
            other => panic!("unknown COSE case: {other}"),
        };
        assert_eq!(result, Ok(()), "{}", case.name);
    }
}
