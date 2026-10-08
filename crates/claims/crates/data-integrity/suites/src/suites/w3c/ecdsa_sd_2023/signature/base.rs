use multibase::Base;
use ssi_claims_core::SignatureError;
use ssi_core::JsonPointerBuf;
use ssi_crypto::algorithm::ES256OrES384;
use ssi_di_sd_primitives::{HmacShaAnyKey, ShaAny, ShaAnyBytes};
use ssi_multicodec::{MultiEncoded, MultiEncodedBuf};
use ssi_rdf::IntoNQuads;
use ssi_security::MultibaseBuf;
use ssi_verification_methods::MessageSigner;

use crate::ecdsa_sd_2023::BaseHashData;

use super::Signature;

#[derive(Debug, thiserror::Error)]
#[error("invalid base signature")]
pub struct InvalidBaseSignature;

pub async fn generate_proof<T>(
    signer: T,
    hash_data: BaseHashData,
) -> Result<Signature, SignatureError>
where
    T: MessageSigner<ES256OrES384>,
{
    let messages: Vec<Vec<u8>> = hash_data
        .transformed_document
        .non_mandatory
        .into_nquads_lines()
        .into_iter()
        .map(|line| line.into_bytes())
        .collect();

    let proof_scoped = signer.sign_proof_scoped_p256(&messages).await?;
    let public_key = p256::PublicKey::from_sec1_bytes(&proof_scoped.public_key_sec1)
        .map_err(SignatureError::other)?;
    if proof_scoped.signatures.len() != messages.len() {
        return Err(SignatureError::other(
            "proof-scoped signature count mismatch",
        ));
    }
    let verifying_key = p256::ecdsa::VerifyingKey::from(&public_key);
    let signatures: Vec<[u8; 64]> = proof_scoped
        .signatures
        .iter()
        .zip(&messages)
        .map(|(signature, message)| {
            use p256::ecdsa::signature::Verifier;
            let signature =
                p256::ecdsa::Signature::from_slice(signature).map_err(SignatureError::other)?;
            verifying_key
                .verify(message, &signature)
                .map_err(SignatureError::other)?;
            Ok(signature.to_bytes().into())
        })
        .collect::<Result<_, SignatureError>>()?;

    let encoded_public_key: MultiEncodedBuf = MultiEncodedBuf::encode(&public_key);

    let to_sign = serialize_sign_data(
        &hash_data.proof_hash,
        &hash_data.mandatory_hash,
        &encoded_public_key,
    );

    let algorithm = match hash_data.transformed_document.hmac_key.algorithm() {
        ShaAny::Sha256 => ES256OrES384::ES256,
        ShaAny::Sha384 => ES256OrES384::ES384,
    };

    let base_signature = signer.sign(algorithm, &to_sign).await?;

    Ok(Signature::encode_base(
        &base_signature,
        &encoded_public_key,
        hash_data.transformed_document.hmac_key,
        &signatures,
        &hash_data.transformed_document.options.mandatory_pointers,
    ))
}

/// Serialize sign data.
///
/// See: <https://www.w3.org/TR/vc-di-ecdsa/#serializesigndata>
pub(crate) fn serialize_sign_data(
    proof_hash: &ShaAnyBytes,
    mandatory_hash: &ShaAnyBytes,
    public_key: &MultiEncoded,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(proof_hash.len() + mandatory_hash.len() + public_key.len());
    bytes.extend(proof_hash.as_slice());
    bytes.extend(public_key.as_bytes());
    bytes.extend(mandatory_hash.as_slice());
    bytes
}

impl Signature {
    pub fn encode_base(
        base_signature: &[u8],
        public_key: &MultiEncoded,
        hmac_key: HmacShaAnyKey,
        signatures: &[[u8; 64]],
        mandatory_pointers: &[JsonPointerBuf],
    ) -> Self {
        let components = vec![
            serde_cbor::Value::Bytes(base_signature.to_vec()),
            serde_cbor::Value::Bytes(public_key.as_bytes().to_vec()),
            serde_cbor::Value::Bytes(hmac_key.to_vec()),
            serde_cbor::Value::Array(signatures.iter().map(|p| p.to_vec().into()).collect()),
            serde_cbor::Value::Array(
                mandatory_pointers
                    .iter()
                    .map(|p| p.as_str().to_owned().into())
                    .collect(),
            ),
        ];

        let mut proof_value = vec![0xd9, 0x5d, 0x00];
        serde_cbor::to_writer(&mut proof_value, &components).unwrap();

        Self {
            proof_value: MultibaseBuf::encode(multibase::Base::Base64Url, proof_value),
        }
    }

    pub fn decode_base(&self) -> Result<DecodedBaseProof, InvalidBaseSignature> {
        let (base, decoded_proof_value) = self
            .proof_value
            .decode()
            .map_err(|_| InvalidBaseSignature)?;

        if base != Base::Base64Url || decoded_proof_value.len() < 3 {
            return Err(InvalidBaseSignature);
        }

        let header = [
            decoded_proof_value[0],
            decoded_proof_value[1],
            decoded_proof_value[2],
        ];

        if header != [0xd9, 0x5d, 0x00] {
            return Err(InvalidBaseSignature);
        }

        let mut components =
            serde_cbor::from_slice::<Vec<serde_cbor::Value>>(&decoded_proof_value[3..])
                .map_err(|_| InvalidBaseSignature)?
                .into_iter();

        let Some(serde_cbor::Value::Bytes(base_signature)) = components.next() else {
            return Err(InvalidBaseSignature);
        };

        let Some(serde_cbor::Value::Bytes(public_key_bytes)) = components.next() else {
            return Err(InvalidBaseSignature);
        };

        let public_key =
            MultiEncodedBuf::new(public_key_bytes).map_err(|_| InvalidBaseSignature)?;

        let Some(serde_cbor::Value::Bytes(hmac_key_bytes)) = components.next() else {
            return Err(InvalidBaseSignature);
        };

        let hmac_key =
            HmacShaAnyKey::from_bytes(&hmac_key_bytes).map_err(|_| InvalidBaseSignature)?;

        let Some(serde_cbor::Value::Array(signatures_values)) = components.next() else {
            return Err(InvalidBaseSignature);
        };

        let mut signatures = Vec::with_capacity(signatures_values.len());
        for value in signatures_values {
            let serde_cbor::Value::Bytes(bytes) = value else {
                return Err(InvalidBaseSignature);
            };

            signatures.push(bytes)
        }

        let Some(serde_cbor::Value::Array(mandatory_pointers_values)) = components.next() else {
            return Err(InvalidBaseSignature);
        };

        let mut mandatory_pointers = Vec::with_capacity(mandatory_pointers_values.len());
        for value in mandatory_pointers_values {
            let serde_cbor::Value::Text(text) = value else {
                return Err(InvalidBaseSignature);
            };

            mandatory_pointers.push(JsonPointerBuf::new(text).map_err(|_| InvalidBaseSignature)?)
        }

        Ok(DecodedBaseProof {
            base_signature,
            public_key,
            hmac_key,
            signatures,
            mandatory_pointers,
        })
    }
}

#[derive(Clone)]
pub struct DecodedBaseProof {
    pub base_signature: Vec<u8>,
    pub public_key: MultiEncodedBuf,
    pub hmac_key: HmacShaAnyKey,
    pub signatures: Vec<Vec<u8>>,
    pub mandatory_pointers: Vec<JsonPointerBuf>,
}
