use serde::{Deserialize, Serialize};
use ssi_jws::JwsBuf;
use ssi_jwt::{JWTClaims, NumericDate};
use ssi_sd_jwt::{disclosure, Disclosure, PartsRef};

#[derive(Debug, Default, Deserialize, Serialize, PartialEq)]
struct ExampleClaims {
    #[serde(skip_serializing_if = "Option::is_none")]
    given_name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    family_name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    phone_number: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    phone_number_verified: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<AddressClaim>,

    #[serde(skip_serializing_if = "Option::is_none")]
    birthdate: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    updated_at: Option<NumericDate>,

    #[serde(skip_serializing_if = "Option::is_none")]
    nationalities: Option<Vec<String>>,
}

#[derive(Debug, Default, Deserialize, Serialize, PartialEq)]
struct AddressClaim {
    #[serde(skip_serializing_if = "Option::is_none")]
    street_address: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    locality: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    region: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    country: Option<String>,
}

fn test_standard_sd_jwt() -> JwsBuf {
    // The shared fixture carries a real signature and contains no private key.
    let issuer_jws = include_str!("fixtures/sd_jwt_kb.txt")
        .split('~')
        .next()
        .unwrap();
    JwsBuf::new(issuer_jws.as_bytes().to_vec()).unwrap()
}

// *Claim email*:
// *  SHA-256 Hash: JzYjH4svliH0R3PyEMfeZu6Jt69u5qehZo7F7EPYlSE
// *  Disclosure:
//     WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgImVtYWlsIiwgImpvaG5kb2VA
//     ZXhhbXBsZS5jb20iXQ
// *  Contents: ["6Ij7tM-a5iVPGboS5tmvVA", "email",
//     "johndoe@example.com"]
const EMAIL_DISCLOSURE: &Disclosure =
    disclosure!("WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgImVtYWlsIiwgImpvaG5kb2VAZXhhbXBsZS5jb20iXQ");

// *Array Entry*:
// *  SHA-256 Hash: 7Cf6JkPudry3lcbwHgeZ8khAv1U1OSlerP0VkBJrWZ0
// *  Disclosure:
//    WyJuUHVvUW5rUkZxM0JJZUFtN0FuWEZBIiwgIkRFIl0
// *  Contents: ["nPuoQnkRFq3BIeAm7AnXFA", "DE"]
const NATIONALITY_DE_DISCLOSURE: &Disclosure =
    disclosure!("WyJuUHVvUW5rUkZxM0JJZUFtN0FuWEZBIiwgIkRFIl0");

#[async_std::test]
async fn disclose_single() {
    let jwt = test_standard_sd_jwt();

    let sd_jwt = PartsRef::new(&jwt, vec![EMAIL_DISCLOSURE], None);

    let disclosed = sd_jwt.decode().unwrap().reveal::<ExampleClaims>().unwrap();

    let expected = JWTClaims::builder()
        .iss("https://issuer.example.com")
        .iat(1683000000)
        .exp(1883000000)
        .sub("user_42")
        .with_private_claims(ExampleClaims {
            email: Some("johndoe@example.com".to_owned()),
            nationalities: Some(vec![]),
            ..Default::default()
        })
        .unwrap();

    eprintln!(
        "found    = {}",
        serde_json::to_string_pretty(disclosed.claims()).unwrap()
    );
    eprintln!(
        "expected = {}",
        serde_json::to_string_pretty(&expected).unwrap()
    );

    assert_eq!(disclosed.into_claims(), expected);
}

#[async_std::test]
async fn decode_single_array_item() {
    let jwt = test_standard_sd_jwt();

    let sd_jwt = PartsRef::new(&jwt, vec![NATIONALITY_DE_DISCLOSURE], None);

    let disclosed = sd_jwt.decode().unwrap().reveal::<ExampleClaims>().unwrap();

    assert_eq!(
        disclosed.into_claims(),
        JWTClaims::builder()
            .iss("https://issuer.example.com")
            .iat(1683000000)
            .exp(1883000000)
            .sub("user_42")
            .with_private_claims(ExampleClaims {
                nationalities: Some(vec!["DE".to_owned()]),
                ..Default::default()
            })
            .unwrap()
    )
}
