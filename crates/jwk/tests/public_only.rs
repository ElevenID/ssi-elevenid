#![cfg(feature = "secp256r1")]

use ssi_jwk::{FromMulticodecError, JWK};
use ssi_multicodec::{MultiEncodedBuf, P256_PRIV};

#[test]
fn public_p256_decoding_survives_without_private_key_operations() {
    let generator = hex::decode(concat!(
        "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
    ))
    .unwrap();
    let jwk = ssi_jwk::p256_parse(&generator).unwrap();
    assert!(jwk.is_public());
    assert_eq!(jwk.get_algorithm().unwrap().to_string(), "ES256");
}

#[test]
fn private_multicodec_is_unsupported_without_private_key_operations() {
    let encoded = MultiEncodedBuf::encode_bytes(P256_PRIV, &[]);
    assert!(matches!(
        JWK::from_multicodec(&encoded),
        Err(FromMulticodecError::UnsupportedCodec(P256_PRIV))
    ));
}

#[test]
fn private_der_encoding_is_disabled_without_key_material() {
    // Empty sentinels exercise the private branch without storing a key fixture.
    let mut rsa = ssi_jwk::RSAParams::new_public(&[1], &[1]);
    rsa.private_exponent = Some(());
    assert!(matches!(
        simple_asn1::der_encode(&rsa),
        Err(ssi_jwk::Error::LocalKeyOperationsDisabled)
    ));

    let octet = ssi_jwk::OctetParams {
        curve: "Ed25519".to_owned(),
        public_key: ssi_jwk::Base64urlUInt(Vec::new()),
        private_key: Some(()),
    };
    assert!(matches!(
        simple_asn1::der_encode(&octet),
        Err(ssi_jwk::Error::LocalKeyOperationsDisabled)
    ));
}

#[test]
fn private_jwk_parameters_are_rejected_without_key_material() {
    for json in [
        r#"{"kty":"EC","crv":"P-256","x":"","y":"","d":""}"#,
        r#"{"kty":"RSA","n":"AQ","e":"AQAB","d":""}"#,
        r#"{"kty":"RSA","n":"AQ","e":"AQAB","p":""}"#,
        r#"{"kty":"RSA","n":"AQ","e":"AQAB","q":""}"#,
        r#"{"kty":"RSA","n":"AQ","e":"AQAB","dp":""}"#,
        r#"{"kty":"RSA","n":"AQ","e":"AQAB","dq":""}"#,
        r#"{"kty":"RSA","n":"AQ","e":"AQAB","qi":""}"#,
        r#"{"kty":"RSA","n":"AQ","e":"AQAB","oth":[]}"#,
        r#"{"kty":"OKP","crv":"Ed25519","x":"","d":""}"#,
        r#"{"kty":"oct","k":""}"#,
    ] {
        assert!(serde_json::from_str::<JWK>(json).is_err(), "{json}");
    }
}

#[test]
fn directly_constructed_private_jwk_fields_cannot_be_serialized() {
    let mut ec: JWK = serde_json::from_str(r#"{"kty":"EC","crv":"P-256","x":"","y":""}"#).unwrap();
    if let ssi_jwk::Params::EC(params) = &mut ec.params {
        params.ecc_private_key = Some(());
    } else {
        unreachable!();
    }
    assert!(serde_json::to_string(&ec).is_err());
    assert_eq!(ec.to_string(), "[private JWK prohibited]");

    let mut rsa = ssi_jwk::RSAParams::new_public(&[1], &[1]);
    rsa.private_exponent = Some(());
    assert!(serde_json::to_string(&rsa).is_err());

    let octet = ssi_jwk::OctetParams {
        curve: "Ed25519".to_owned(),
        public_key: ssi_jwk::Base64urlUInt(Vec::new()),
        private_key: Some(()),
    };
    assert!(serde_json::to_string(&octet).is_err());

    let symmetric = ssi_jwk::SymmetricParams {
        key_value: Some(()),
    };
    assert!(serde_json::to_string(&symmetric).is_err());
    assert!(
        !ssi_jwk::JWK::from(ssi_jwk::Params::Symmetric(ssi_jwk::SymmetricParams {
            key_value: None
        }))
        .is_public()
    );
}

#[test]
fn public_curve_serializers_validate_curve_point_and_coordinate_widths() {
    type Serialize = fn(&ssi_jwk::ECParams) -> Result<Vec<u8>, ssi_jwk::Error>;
    let mut cases: Vec<(&str, Serialize)> = vec![("P-256", ssi_jwk::serialize_p256)];
    #[cfg(feature = "secp384r1")]
    cases.push(("P-384", ssi_jwk::serialize_p384));
    #[cfg(feature = "secp256k1")]
    cases.push(("secp256k1", ssi_jwk::serialize_secp256k1));
    for (curve, serialize) in cases {
        let json = match curve {
            "P-256" => include_str!("../../../tests/public_keys/p256.json"),
            "P-384" => include_str!("../../../tests/public_keys/p384.json"),
            _ => include_str!("../../../tests/public_keys/secp256k1.json"),
        };
        let jwk: JWK = serde_json::from_str(json).unwrap();
        let ssi_jwk::Params::EC(public) = jwk.params else {
            panic!("EC fixture")
        };
        assert!(serialize(&public).is_ok(), "{curve}");
        let mut wrong_curve = public.clone();
        wrong_curve.curve = Some("wrong-curve".to_owned());
        assert!(serialize(&wrong_curve).is_err());
        let mut shifted = public.clone();
        let last_x = shifted.x_coordinate.as_mut().unwrap().0.pop().unwrap();
        shifted.y_coordinate.as_mut().unwrap().0.insert(0, last_x);
        // The concatenated SEC1 bytes are unchanged. Independent JWK widths must still reject it.
        assert!(serialize(&shifted).is_err());
        let mut short = public.clone();
        short.x_coordinate.as_mut().unwrap().0.clear();
        assert!(serialize(&short).is_err());
        let mut off_curve = public.clone();
        off_curve.x_coordinate.as_mut().unwrap().0.fill(0);
        off_curve.y_coordinate.as_mut().unwrap().0.fill(0);
        assert!(serialize(&off_curve).is_err());
    }
}
