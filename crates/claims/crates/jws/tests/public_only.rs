use ssi_jwk::JWK;
use ssi_jws::decode_verify;

#[cfg(feature = "secp256r1")]
const PUBLIC_JWK: &str = r#"{"kty":"EC","crv":"P-256","x":"OnI8cxizlWZUBw5icIHEUn5EVMpcz4bNr__HnrmYGrE","y":"IB3NJQlX9rCu0yyAYSm0k-Vk1NlNkkEcRUZLwZHnuGc"}"#;
#[cfg(feature = "secp256r1")]
const SIGNED_JWS: &str = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJkaWQ6ZXhhbXBsZTpmb28iLCJ2cCI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJ0eXBlIjoiVmVyaWZpYWJsZVByZXNlbnRhdGlvbiJ9fQ.rJzO6MmTNS8Tn-L3baIf9_2Jr9OoK8E06MxJtofz8xMUGSom6eRUmWGZ7oQVjgP3HogOD80miTvuvKTWa54Nvw";

#[test]
#[cfg(feature = "secp256r1")]
fn es256_verification_survives_without_local_signing() {
    let public: JWK = serde_json::from_str(PUBLIC_JWK).unwrap();
    assert!(public.is_public());
    let (_, payload) = decode_verify(SIGNED_JWS, &public).unwrap();
    assert!(std::str::from_utf8(&payload)
        .unwrap()
        .contains("did:example:foo"));
}

#[test]
#[cfg(feature = "secp384r1")]
fn es384_verification_survives_without_local_signing() {
    let public: JWK = serde_json::from_str(r#"{"kty":"EC","crv":"P-384","x":"G09OCsHnoen7IWnA9ETEKl7NmPwakpHo9KOH5bUB2nJzyn5Zco-qqBchqUi1-uaz","y":"_CtCA3SUZS4IEOJN999aLTEIQOOWOX9biXqbFs4OCa1OMvjoVzzC2BimVnHrrcQ7"}"#).unwrap();
    let signed = "eyJhbGciOiJFUzM4NCJ9.eyJpc3MiOiJkaWQ6ZXhhbXBsZTpmb28iLCJ2cCI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJ0eXBlIjoiVmVyaWZpYWJsZVByZXNlbnRhdGlvbiJ9fQ.2vpBSFN7DxuS57epgq_e7-NyNiJ5eOOrExmi65C_wtZOC2-9i6fVvMnfUig7QmgiirznAg1wr_b7_kH-bbMCI5Pdf8pAnxQg3LL9I9OhzttyG06qAl9L7BE6aNS-aqnf";
    assert!(public.is_public());
    assert!(decode_verify(signed, &public).is_ok());
    let tampered = signed.replace("eyJpc3Mi", "eyJpc3Mj");
    assert!(decode_verify(&tampered, &public).is_err());
}

#[test]
#[cfg(feature = "rsa")]
fn rs256_verification_survives_without_local_signing() {
    // RFC 7515 Appendix A.2, with only its public modulus and exponent.
    let public: JWK = serde_json::from_str(r#"{"kty":"RSA","n":"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ","e":"AQAB"}"#).unwrap();
    let signed = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw";
    assert!(public.is_public());
    assert!(decode_verify(signed, &public).is_ok());
}
