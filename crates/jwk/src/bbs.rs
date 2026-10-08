use ssi_bbs::BBSplusPublicKey;

use crate::{Base64urlUInt, ECParams, Error, Params, JWK};

pub fn bls12381g2_parse(bytes: &[u8]) -> Result<JWK, ssi_bbs::Error> {
    Ok(BBSplusPublicKey::from_bytes(bytes)?.into())
}

impl<'a> TryFrom<&'a JWK> for BBSplusPublicKey {
    type Error = Error;

    fn try_from(value: &'a JWK) -> Result<Self, Self::Error> {
        (&value.params).try_into()
    }
}

impl TryFrom<JWK> for BBSplusPublicKey {
    type Error = Error;

    fn try_from(value: JWK) -> Result<Self, Self::Error> {
        value.params.try_into()
    }
}

impl<'a> From<&'a BBSplusPublicKey> for ECParams {
    fn from(value: &'a BBSplusPublicKey) -> Self {
        let (x, y) = value.to_coordinates();
        Self {
            curve: Some("BLS12381G2".to_owned()),
            x_coordinate: Some(Base64urlUInt(x.to_vec())),
            y_coordinate: Some(Base64urlUInt(y.to_vec())),
            ecc_private_key: None,
        }
    }
}

impl From<BBSplusPublicKey> for ECParams {
    fn from(value: BBSplusPublicKey) -> Self {
        (&value).into()
    }
}

impl<'a> From<&'a BBSplusPublicKey> for Params {
    fn from(value: &'a BBSplusPublicKey) -> Self {
        Self::EC(value.into())
    }
}

impl From<BBSplusPublicKey> for Params {
    fn from(value: BBSplusPublicKey) -> Self {
        Self::EC(value.into())
    }
}

impl<'a> From<&'a BBSplusPublicKey> for JWK {
    fn from(value: &'a BBSplusPublicKey) -> Self {
        Params::from(value).into()
    }
}

impl From<BBSplusPublicKey> for JWK {
    fn from(value: BBSplusPublicKey) -> Self {
        Params::from(value).into()
    }
}

impl<'a> TryFrom<&'a Params> for BBSplusPublicKey {
    type Error = Error;

    fn try_from(value: &'a Params) -> Result<Self, Self::Error> {
        match value {
            Params::EC(params) => match params.curve.as_deref() {
                Some("BLS12381G2") => {
                    if params.ecc_private_key.is_some() {
                        return Err(Error::LocalKeyOperationsDisabled);
                    }
                    let x: &[u8; 96] = params
                        .x_coordinate
                        .as_ref()
                        .ok_or(Error::MissingPoint)?
                        .0
                        .as_slice()
                        .try_into()
                        .map_err(|_| Error::InvalidCoordinates)?;
                    let y: &[u8; 96] = params
                        .y_coordinate
                        .as_ref()
                        .ok_or(Error::MissingPoint)?
                        .0
                        .as_slice()
                        .try_into()
                        .map_err(|_| Error::InvalidCoordinates)?;

                    BBSplusPublicKey::from_coordinates(x, y).map_err(|_| Error::InvalidCoordinates)
                }
                Some(other) => Err(Error::CurveNotImplemented(other.to_owned())),
                None => Err(Error::MissingCurve),
            },
            _ => Err(Error::UnsupportedKeyType),
        }
    }
}

impl TryFrom<Params> for BBSplusPublicKey {
    type Error = Error;

    fn try_from(value: Params) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}
