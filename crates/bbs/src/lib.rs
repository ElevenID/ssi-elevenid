use ssi_claims_core::{InvalidProof, ProofValidationError, ProofValidity};
use zkryptium::{bbsplus::ciphersuites::Bls12381Sha256, schemes::algorithms::BBSplus};
pub use zkryptium::{bbsplus::keys::BBSplusPublicKey, errors::Error};

pub use ssi_crypto::algorithm::Bbs;

#[derive(Debug)]
pub struct ProofGenFailed;

pub fn proof_gen(
    pk: &BBSplusPublicKey,
    signature: &[u8],
    header: &[u8],
    ph: Option<&[u8]>,
    messages: &[Vec<u8>],
    disclosed_indexes: &[usize],
) -> Result<Vec<u8>, ProofGenFailed> {
    Ok(
        zkryptium::schemes::generics::PoKSignature::<BBSplus<Bls12381Sha256>>::proof_gen(
            pk,
            signature,
            Some(header),
            ph,
            Some(messages),
            Some(disclosed_indexes),
        )
        .map_err(|_| ProofGenFailed)?
        .to_bytes(),
    )
}

pub fn proof_verify(
    pk: &BBSplusPublicKey,
    signature: &[u8],
    header: &[u8],
    ph: Option<&[u8]>,
    disclosed_messages: &[Vec<u8>],
    disclosed_indexes: &[usize],
) -> Result<ProofValidity, ProofValidationError> {
    let signature =
        zkryptium::schemes::generics::PoKSignature::<BBSplus<Bls12381Sha256>>::from_bytes(
            signature,
        )
        .map_err(|_| ProofValidationError::InvalidSignature)?;

    Ok(signature
        .proof_verify(
            pk,
            Some(disclosed_messages),
            Some(disclosed_indexes),
            Some(header),
            ph,
        )
        .map_err(|_| InvalidProof::Signature))
}
