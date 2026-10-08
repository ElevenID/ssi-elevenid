use crate::{AlgorithmInstance, VerificationError};

#[derive(Debug, thiserror::Error)]
#[error("invalid public key")]
pub struct InvalidPublicKey;

/// Public key.
#[non_exhaustive]
pub enum PublicKey {
    #[cfg(feature = "ed25519")]
    Ed25519(ed25519_dalek::VerifyingKey),

    #[cfg(feature = "secp256k1")]
    Secp256k1(k256::PublicKey),

    #[cfg(feature = "secp256r1")]
    P256(p256::PublicKey),

    #[cfg(feature = "secp384r1")]
    P384(p384::PublicKey),
}

impl PublicKey {
    #[cfg(feature = "ed25519")]
    pub fn new_ed25519(bytes: &[u8]) -> Result<Self, InvalidPublicKey> {
        bytes
            .try_into()
            .map(Self::Ed25519)
            .map_err(|_| InvalidPublicKey)
    }

    #[cfg(feature = "secp256k1")]
    pub fn new_secp256k1(x: &[u8], y: &[u8]) -> Result<Self, InvalidPublicKey> {
        let mut bytes = Vec::new();
        bytes.push(0x04);
        bytes.extend(x);
        bytes.extend(y);

        k256::PublicKey::from_sec1_bytes(&bytes)
            .map(Self::Secp256k1)
            .map_err(|_| InvalidPublicKey)
    }

    #[cfg(feature = "secp256r1")]
    pub fn new_p256(x: &[u8], y: &[u8]) -> Result<Self, InvalidPublicKey> {
        let mut bytes = Vec::new();
        bytes.push(0x04);
        bytes.extend(x);
        bytes.extend(y);

        p256::PublicKey::from_sec1_bytes(&bytes)
            .map(Self::P256)
            .map_err(|_| InvalidPublicKey)
    }

    #[cfg(feature = "secp384r1")]
    pub fn new_p384(x: &[u8], y: &[u8]) -> Result<Self, InvalidPublicKey> {
        let mut bytes = Vec::new();
        bytes.push(0x04);
        bytes.extend(x);
        bytes.extend(y);

        p384::PublicKey::from_sec1_bytes(&bytes)
            .map(Self::P384)
            .map_err(|_| InvalidPublicKey)
    }

    pub fn verify(
        &self,
        algorithm: AlgorithmInstance,
        signing_bytes: &[u8],
        signature_bytes: &[u8],
    ) -> Result<bool, VerificationError> {
        algorithm.verify(self, signing_bytes, signature_bytes)
    }
}
