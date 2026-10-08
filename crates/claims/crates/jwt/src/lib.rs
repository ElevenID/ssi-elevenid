//! JSON Web Token (JWT) implementation following [RFC7519].
//!
//! [RFC7519]: <https://datatracker.ietf.org/doc/html/rfc7519>
//!
//! # Usage
//!
//! ## Decoding & Verification
//!
//! ```
//! # async_std::task::block_on(async {
//! use serde_json::json;
//! use ssi_jwk::JWK;
//! use ssi_jws::Jws;
//! use ssi_jwt::ToDecodedJwt;
//!
//! let jws = Jws::new(b"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBTbWl0aCIsImlhdCI6MTcxNTM0Mjc5MCwiaXNzIjoiaHR0cDovL2V4YW1wbGUub3JnLyNpc3N1ZXIifQ.S51Gmlkwy4UxOhhc4nVl4_sHHVPSrNmjZDwJCDXDbKp2MT8-UyhZLw03gVKe-JRUzcsteWoeRCUoA5rwnuTSoA").unwrap();
//!
//! let jwk: JWK = json!({
//!     "kty": "EC",
//!     "use": "sig",
//!     "crv": "P-256",
//!     "x": "dxdB360AJqJFYhdctoKZD_a_P6vLGAxtEVaCLnyraXQ",
//!     "y": "iH6o0l5AECsfRuEw2Eghbrp-6Fob3j98-1Cbe1YOmwM",
//!     "alg": "ES256"
//! }).try_into().unwrap();
//!
//! assert!(jws.verify_jwt(&jwk).await.unwrap().is_ok());
//! # })
//! ```
//!
//! Internally [`ToDecodedJwt::verify_jwt`] uses
//! [`ToDecodedJwt::to_decoded_jwt`] to decode the JWT,
//! then [`DecodedJws::verify`] to validate the signature and
//! registered claims.
//!
//! [`DecodedJws::verify`]: ssi_jws::DecodedJws::verify
//!
use serde::de::DeserializeOwned;
use serde::Serialize;

use ssi_jwk::JWK;
use ssi_jws::Error;

mod claims;
mod datatype;
mod decoding;

pub use claims::*;
pub use datatype::*;
pub use decoding::*;

pub fn encode_unsigned<Claims: Serialize>(claims: &Claims) -> Result<String, Error> {
    let payload = serde_json::to_string(claims)?;
    ssi_jws::encode_unsigned(&payload)
}

pub fn decode_verify<Claims: DeserializeOwned>(jwt: &str, key: &JWK) -> Result<Claims, Error> {
    let (_header, payload) = ssi_jws::decode_verify(jwt, key)?;
    let claims = serde_json::from_slice(&payload)?;
    Ok(claims)
}

// for vc-test-suite
pub fn decode_unverified<Claims: DeserializeOwned>(jwt: &str) -> Result<Claims, Error> {
    let (_header, payload) = ssi_jws::decode_unverified(jwt)?;
    let claims = serde_json::from_slice(&payload)?;
    Ok(claims)
}
