//! CBOR Object Signing and Encryption ([COSE]) implementation based on
//! [`coset`].
//!
//! [COSE]: <https://datatracker.ietf.org/doc/html/rfc8152>
//! [`coset`]: <https://crates.io/crates/coset>
//!
//! # Verifying a COSE signature
//!
//! This example uses a signed COSE object and its public key.
//!
//! ```
//! # #[async_std::main]
//! # async fn main() {
//! use ssi_claims_core::VerificationParameters;
//! use ssi_cose::{CoseKey, CoseSign1BytesBuf, DecodedCoseSign1};
//! use ssi_cose::coset::CborSerializable;
//!
//! let key = CoseKey::from_slice(&hex::decode("a4010220012158208ba05652fc7578854ee90d0035a99b140c2b6421637f844713608f1c6d52bd862258208a51164a9a95a53ae827079f7cefe8d54e11c83dd0daf9cc5f51076bcd9ac4fd").unwrap()).unwrap();
//! let signed = CoseSign1BytesBuf::new(hex::decode("d28443a10126a0475041594c4f41445840a3d5781892b9db81658ed3d223ac06e264e31129dcaf46592e9fe5b55e5f2acc3c734dec47129069698ed97492b7502267e6ef4430b9189c189fddf7b13867a8").unwrap());
//! let decoded: DecodedCoseSign1 = signed.decode(true).unwrap();
//! assert_eq!(decoded.signing_bytes.payload.as_bytes(), b"PAYLOAD");
//! assert_eq!(decoded.verify(VerificationParameters::from_resolver(&key)).await.unwrap(), Ok(()));
//! # }
//! ```
use ssi_claims_core::SignatureError;
use std::borrow::Cow;

pub use coset;
pub use coset::{ContentType, CoseError, CoseKey, CoseSign1, Header, Label, ProtectedHeader};

pub use ciborium;
pub use ciborium::Value as CborValue;

pub mod key;

mod signature;
pub use signature::*;

mod verification;
pub use verification::*;

pub mod algorithm;

mod sign1;
pub use sign1::*;

/// COSE payload.
///
/// This trait defines how a custom type can be encoded and signed using COSE.
///
/// # Example
///
/// ```
/// use std::borrow::Cow;
/// use serde::{Serialize, Deserialize};
/// use ssi_cose::{CosePayload, CosePayloadType, ContentType};
///
/// // Our custom payload type.
/// #[derive(Serialize, Deserialize)]
/// struct CustomPayload {
///   data: String
/// }
///
/// // Define how the payload is encoded in COSE.
/// impl CosePayload for CustomPayload {
///   fn typ(&self) -> Option<CosePayloadType> {
///     Some(CosePayloadType::Text(
///       "application/json+cose".to_owned(),
///     ))
///   }
///
///   fn content_type(&self) -> Option<ContentType> {
///     Some(ContentType::Text("application/json".to_owned()))
///   }
///
///   // Serialize the payload as JSON.
///   fn payload_bytes(&self) -> Cow<[u8]> {
///     Cow::Owned(serde_json::to_vec(self).unwrap())
///   }
/// }
/// ```
pub trait CosePayload {
    /// `typ` header parameter.
    ///
    /// See: <https://www.rfc-editor.org/rfc/rfc9596#section-2>
    fn typ(&self) -> Option<CosePayloadType> {
        None
    }

    /// Content type header parameter.
    fn content_type(&self) -> Option<ContentType> {
        None
    }

    /// Payload bytes.
    ///
    /// Returns the payload bytes representing this value.
    fn payload_bytes(&'_ self) -> Cow<'_, [u8]>;

    /// Sign the payload to produce a serialized `COSE_Sign1` object.
    ///
    /// The `tagged` flag specifies if the COSE object should be tagged or
    /// not.
    #[allow(async_fn_in_trait)]
    async fn sign(
        &self,
        signer: impl CoseSigner,
        tagged: bool,
    ) -> Result<CoseSign1BytesBuf, SignatureError> {
        signer.sign(self, None, tagged).await
    }
}

impl CosePayload for [u8] {
    fn payload_bytes(&'_ self) -> Cow<'_, [u8]> {
        Cow::Borrowed(self)
    }
}

pub const TYP_LABEL: Label = Label::Int(16);

/// COSE payload type.
///
/// Value of the `typ` header parameter.
///
/// See: <https://www.rfc-editor.org/rfc/rfc9596#section-2>
pub enum CosePayloadType {
    UInt(u64),
    Text(String),
}

impl From<CosePayloadType> for CborValue {
    fn from(ty: CosePayloadType) -> Self {
        match ty {
            CosePayloadType::UInt(i) => Self::Integer(i.into()),
            CosePayloadType::Text(t) => Self::Text(t),
        }
    }
}

/// COSE signature bytes.
pub struct CoseSignatureBytes(pub Vec<u8>);

impl CoseSignatureBytes {
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}
