use coset::{
    iana::{self, EnumI64},
    CoseKey, KeyType, Label,
};
use ssi_claims_core::ProofValidationError;
use ssi_crypto::PublicKey;
use std::borrow::Cow;

/// COSE key resolver.
pub trait CoseKeyResolver {
    /// Fetches the COSE key associated to the give identifier.
    #[allow(async_fn_in_trait)]
    async fn fetch_public_cose_key(
        &'_ self,
        id: Option<&[u8]>,
    ) -> Result<Cow<'_, CoseKey>, ProofValidationError>;
}

impl<T: CoseKeyResolver> CoseKeyResolver for &T {
    async fn fetch_public_cose_key(
        &'_ self,
        id: Option<&[u8]>,
    ) -> Result<Cow<'_, CoseKey>, ProofValidationError> {
        T::fetch_public_cose_key(*self, id).await
    }
}

impl CoseKeyResolver for CoseKey {
    async fn fetch_public_cose_key(
        &'_ self,
        _id: Option<&[u8]>,
    ) -> Result<Cow<'_, CoseKey>, ProofValidationError> {
        Ok(Cow::Borrowed(self))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum KeyDecodingError {
    #[error("unsupported key type")]
    UnsupportedKeyType(KeyType),

    #[error("missing parameter")]
    MissingParam(Label),

    #[error("invalid parameter")]
    InvalidParam(Label),

    #[error("unsupported parameter value")]
    UnsupportedParam(Label, ciborium::Value),

    #[error("invalid key")]
    InvalidKey,

    #[error("private key material is not permitted")]
    PrivateKeyMaterial,
}

impl From<ssi_crypto::key::InvalidPublicKey> for KeyDecodingError {
    fn from(_value: ssi_crypto::key::InvalidPublicKey) -> Self {
        Self::InvalidKey
    }
}

/// Decode COSE keys.
pub trait CoseKeyDecode {
    /// Reads a key parameter, if it exists.
    fn fetch_param(&self, label: &Label) -> Option<&ciborium::Value>;

    /// Requires the given key parameter.
    ///
    /// Returns an error if the key parameter is not present in the key.
    fn require_param(&self, label: &Label) -> Result<&ciborium::Value, KeyDecodingError> {
        self.fetch_param(label)
            .ok_or_else(|| KeyDecodingError::MissingParam(label.clone()))
    }

    /// Requires and parses the given key parameter.
    ///
    /// Returns an error if the key parameter is not present in the key, or
    /// if the parsing function `f` returns `None`.
    fn parse_required_param<'a, T>(
        &'a self,
        label: &Label,
        f: impl FnOnce(&'a ciborium::Value) -> Option<T>,
    ) -> Result<T, KeyDecodingError> {
        f(self.require_param(label)?).ok_or_else(|| KeyDecodingError::InvalidParam(label.clone()))
    }

    /// Decodes the COSE key as a public key.
    fn decode_public(&self) -> Result<ssi_crypto::PublicKey, KeyDecodingError>;
}

impl CoseKeyDecode for CoseKey {
    /// Fetch a key parameter.
    fn fetch_param(&self, label: &Label) -> Option<&ciborium::Value> {
        self.params
            .iter()
            .find_map(|(l, value)| if l == label { Some(value) } else { None })
    }

    fn decode_public(&self) -> Result<ssi_crypto::PublicKey, KeyDecodingError> {
        if self.fetch_param(&OKP_D).is_some() {
            return Err(KeyDecodingError::PrivateKeyMaterial);
        }
        match &self.kty {
            t @ KeyType::Assigned(kty) => {
                match kty {
                    // Octet Key Pair.
                    iana::KeyType::OKP => {
                        let crv = self.parse_required_param(&OKP_CRV, |v| {
                            v.as_integer().and_then(|i| i64::try_from(i).ok())
                        })?;

                        #[allow(unused_variables)]
                        let x = self.parse_required_param(&OKP_X, ciborium::Value::as_bytes)?;

                        match iana::EllipticCurve::from_i64(crv) {
                            #[cfg(feature = "ed25519")]
                            Some(iana::EllipticCurve::Ed25519) => {
                                ssi_crypto::PublicKey::new_ed25519(x).map_err(Into::into)
                            }
                            _ => Err(KeyDecodingError::UnsupportedParam(EC2_CRV, crv.into())),
                        }
                    }
                    // Double Coordinate Curves.
                    // See: <https://datatracker.ietf.org/doc/html/rfc8152#section-13.1.1>
                    iana::KeyType::EC2 => {
                        let crv = self.parse_required_param(&EC2_CRV, |v| {
                            v.as_integer().and_then(|i| i64::try_from(i).ok())
                        })?;

                        #[allow(unused_variables)]
                        let x = self.parse_required_param(&EC2_X, ciborium::Value::as_bytes)?;

                        #[allow(unused_variables)]
                        let y = self.parse_required_param(
                            &EC2_Y,
                            ciborium::Value::as_bytes, // TODO: this can be a `bool`
                        )?;

                        match iana::EllipticCurve::from_i64(crv) {
                            #[cfg(feature = "secp256k1")]
                            Some(iana::EllipticCurve::Secp256k1) => {
                                ssi_crypto::PublicKey::new_secp256k1(x, y).map_err(Into::into)
                            }
                            #[cfg(feature = "secp256r1")]
                            Some(iana::EllipticCurve::P_256) => {
                                ssi_crypto::PublicKey::new_p256(x, y).map_err(Into::into)
                            }
                            #[cfg(feature = "secp384r1")]
                            Some(iana::EllipticCurve::P_384) => {
                                ssi_crypto::PublicKey::new_p384(x, y).map_err(Into::into)
                            }
                            _ => Err(KeyDecodingError::UnsupportedParam(EC2_CRV, crv.into())),
                        }
                    }
                    _ => Err(KeyDecodingError::UnsupportedKeyType(t.clone())),
                }
            }
            other => Err(KeyDecodingError::UnsupportedKeyType(other.clone())),
        }
    }
}

pub const OKP_CRV: Label = Label::Int(iana::OkpKeyParameter::Crv as i64);
pub const OKP_X: Label = Label::Int(iana::OkpKeyParameter::X as i64);
pub const OKP_D: Label = Label::Int(iana::OkpKeyParameter::D as i64);

pub const EC2_CRV: Label = Label::Int(iana::Ec2KeyParameter::Crv as i64);
pub const EC2_X: Label = Label::Int(iana::Ec2KeyParameter::X as i64);
pub const EC2_Y: Label = Label::Int(iana::Ec2KeyParameter::Y as i64);
pub const EC2_D: Label = Label::Int(iana::Ec2KeyParameter::D as i64);

#[derive(Debug, thiserror::Error)]
pub enum KeyEncodingError {
    #[error("unsupported key type")]
    UnsupportedKeyType,
}

/// COSE key encoding
pub trait CoseKeyEncode: Sized {
    fn encode_public(key: &PublicKey) -> Result<CoseKey, KeyEncodingError>;

    fn encode_public_with_id(key: &PublicKey, id: Vec<u8>) -> Result<CoseKey, KeyEncodingError> {
        let mut cose_key = Self::encode_public(key)?;
        cose_key.key_id = id;
        Ok(cose_key)
    }
}

impl CoseKeyEncode for CoseKey {
    fn encode_public(key: &PublicKey) -> Result<Self, KeyEncodingError> {
        match key {
            #[cfg(feature = "ed25519")]
            PublicKey::Ed25519(key) => Ok(Self {
                kty: KeyType::Assigned(iana::KeyType::OKP),
                params: vec![
                    (OKP_CRV, iana::EllipticCurve::Ed25519.to_i64().into()),
                    (OKP_X, key.as_bytes().to_vec().into()),
                ],
                ..Default::default()
            }),
            #[cfg(feature = "secp256k1")]
            PublicKey::Secp256k1(key) => {
                use ssi_crypto::k256::elliptic_curve::sec1::ToEncodedPoint;
                let encoded_point = key.to_encoded_point(false);
                Ok(Self {
                    kty: KeyType::Assigned(iana::KeyType::EC2),
                    params: vec![
                        (EC2_CRV, iana::EllipticCurve::Secp256k1.to_i64().into()),
                        (EC2_X, encoded_point.x().unwrap().to_vec().into()),
                        (EC2_Y, encoded_point.y().unwrap().to_vec().into()),
                    ],
                    ..Default::default()
                })
            }
            #[cfg(feature = "secp256r1")]
            PublicKey::P256(key) => {
                use ssi_crypto::p256::elliptic_curve::sec1::ToEncodedPoint;
                let encoded_point = key.to_encoded_point(false);
                Ok(Self {
                    kty: KeyType::Assigned(iana::KeyType::EC2),
                    params: vec![
                        (EC2_CRV, iana::EllipticCurve::P_256.to_i64().into()),
                        (EC2_X, encoded_point.x().unwrap().to_vec().into()),
                        (EC2_Y, encoded_point.y().unwrap().to_vec().into()),
                    ],
                    ..Default::default()
                })
            }
            #[cfg(feature = "secp384r1")]
            PublicKey::P384(key) => {
                use ssi_crypto::p384::elliptic_curve::sec1::ToEncodedPoint;
                let encoded_point = key.to_encoded_point(false);
                Ok(Self {
                    kty: KeyType::Assigned(iana::KeyType::EC2),
                    params: vec![
                        (EC2_CRV, iana::EllipticCurve::P_384.to_i64().into()),
                        (EC2_X, encoded_point.x().unwrap().to_vec().into()),
                        (EC2_Y, encoded_point.y().unwrap().to_vec().into()),
                    ],
                    ..Default::default()
                })
            }
            _ => Err(KeyEncodingError::UnsupportedKeyType),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CoseKeyDecode, CoseKeyEncode, KeyDecodingError, EC2_D, OKP_D};
    use coset::{CborSerializable, CoseKey, KeyType};
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct SignedCase {
        name: String,
        public_hex: String,
    }

    #[test]
    fn public_keys_roundtrip_without_private_material() {
        let cases: Vec<SignedCase> =
            serde_json::from_str(include_str!("../tests/fixtures/signed-cases.json")).unwrap();
        for case in cases {
            let key = CoseKey::from_slice(&hex::decode(case.public_hex).unwrap()).unwrap();
            let public = key.decode_public().unwrap();
            let encoded = CoseKey::encode_public_with_id(&public, key.key_id.clone()).unwrap();
            assert_eq!(encoded, key, "{}", case.name);

            let mut with_private_parameter = key.clone();
            let d = match key.kty {
                KeyType::Assigned(coset::iana::KeyType::OKP) => OKP_D,
                KeyType::Assigned(coset::iana::KeyType::EC2) => EC2_D,
                _ => unreachable!(),
            };
            with_private_parameter
                .params
                .push((d, vec![0u8; 32].into()));
            assert!(
                matches!(
                    with_private_parameter.decode_public(),
                    Err(KeyDecodingError::PrivateKeyMaterial)
                ),
                "{}",
                case.name
            );
        }
    }
}
