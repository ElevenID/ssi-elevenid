//! Functionality related to [Aleo] blockchain network.
//!
//! Required crate feature: `aleo`
//!
//! [Aleo]: https://developer.aleo.org/testnet/getting_started/overview#the-network
//!
//! This module verifies Aleo signatures using the static [struct@ENC_PARAMS]
//! and public Aleo account addresses.

use crate::{Params, JWK};
use thiserror::Error;

use blake2::Blake2s;
use snarkvm_algorithms::{
    encryption::{GroupEncryption, GroupEncryptionParameters},
    signature::SchnorrSignature,
};
use snarkvm_curves::edwards_bls12::{EdwardsAffine, EdwardsProjective};
use snarkvm_dpc::{account::Address, testnet1::instantiated::Components};
use snarkvm_parameters::{global::AccountEncryptionParameters, Parameter};
use snarkvm_utilities::FromBytes;
use std::str::FromStr;

/// An error resulting from attempting to [verify a signature from an Aleo account](verify).
#[derive(Error, Debug)]
pub enum AleoVerifyError {
    #[error("Invalid signature over message")]
    InvalidSignature,
    #[error("Unable to verify signature: {0}")]
    VerifySignature(#[source] snarkvm_dpc::AccountError),
    #[error("Unable to deserialize account address: {0}")]
    AddressFromStr(#[source] snarkvm_dpc::AccountError),
    #[error("Unable to read signature bytes: {0}")]
    ReadSignature(#[source] std::io::Error),
}

/// An error resulting from attempting to convert a [JWK] to an Aleo account address.
///
/// The expected JWK format is described in [OKP_CURVE].
#[derive(Error, Debug)]
pub enum ParseAddressError {
    #[error("private key material is not permitted")]
    PrivateKeyMaterial,
    #[error("Unexpected JWK OKP curve: {0}")]
    UnexpectedCurve(String),
    #[error("Unexpected JWK key type. Expected \"OKP\"")]
    ExpectedOKP,
    #[error("Unable to read address from bytes: {0}")]
    ReadAddress(#[source] std::io::Error),
}

lazy_static::lazy_static! {
    /// Aleo account encryption parameters
    pub static ref ENC_PARAMS: GroupEncryption<EdwardsProjective, EdwardsAffine, Blake2s> = {
        let enc_params_bytes = AccountEncryptionParameters::load_bytes()
                .unwrap();
        GroupEncryptionParameters::read_le(
            enc_params_bytes
                .as_slice(),
        )
        .unwrap()
        .into()
    };
}

/// Unregistered JWK OKP curve for public Aleo Testnet 1 account addresses.
///
/// The public `x` parameter contains a base64url-encoded account address.
pub const OKP_CURVE: &str = "AleoTestnet1Key";

/// Decode the account address represented by a public Aleo JWK.
pub fn address_from_jwk(jwk: &JWK) -> Result<Address<Components>, ParseAddressError> {
    if !jwk.is_public() {
        return Err(ParseAddressError::PrivateKeyMaterial);
    }
    let params = match &jwk.params {
        Params::OKP(ref okp_params) => {
            if okp_params.curve != OKP_CURVE {
                return Err(ParseAddressError::UnexpectedCurve(
                    okp_params.curve.to_string(),
                ));
            }
            okp_params
        }
        _ => return Err(ParseAddressError::ExpectedOKP),
    };
    let public_key_bytes = &params.public_key.0;
    let address = Address::<Components>::read_le(&**public_key_bytes)
        .map_err(ParseAddressError::ReadAddress)?;
    Ok(address)
}

/// Verify an Aleo signature by an Aleo address as a string.
///
/// Verification uses [struct@ENC_PARAMS].
pub fn verify(msg: &[u8], address: &str, sig: &[u8]) -> Result<(), AleoVerifyError> {
    let address =
        Address::<Components>::from_str(address).map_err(AleoVerifyError::AddressFromStr)?;
    let sig =
        SchnorrSignature::<EdwardsAffine>::read_le(sig).map_err(AleoVerifyError::ReadSignature)?;
    let enc_params = ENC_PARAMS.clone();
    let valid = address
        .verify_signature(&enc_params, msg, &sig)
        .map_err(AleoVerifyError::VerifySignature)?;
    if !valid {
        return Err(AleoVerifyError::InvalidSignature);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct SignedCase {
        public_jwk: JWK,
        signature_hex: String,
    }

    #[test]
    fn public_aleo_address_verifies_signed_vector() {
        let case: SignedCase =
            serde_json::from_str(include_str!("../tests/fixtures/aleo-public-only.json")).unwrap();
        assert!(case.public_jwk.is_public());
        let address = address_from_jwk(&case.public_jwk).unwrap();
        assert_eq!(
            address.to_string(),
            "aleo1al8unplh8vtsuwna0h6u2t6g0hvr7t0tnfkem2we5gj7t70aeuxsd94hsy"
        );

        let mut with_private_parameter = case.public_jwk.clone();
        if let Params::OKP(params) = &mut with_private_parameter.params {
            params.private_key = Some(());
        }
        assert!(matches!(
            address_from_jwk(&with_private_parameter),
            Err(ParseAddressError::PrivateKeyMaterial)
        ));

        let signature = hex::decode(case.signature_hex).unwrap();
        verify(b"asdf", &address.to_string(), &signature).unwrap();
        assert!(matches!(
            verify(b"asdfg", &address.to_string(), &signature),
            Err(AleoVerifyError::InvalidSignature)
        ));
    }
}
