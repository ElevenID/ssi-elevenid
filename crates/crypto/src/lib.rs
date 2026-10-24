#![cfg_attr(docsrs, feature(doc_auto_cfg))]

#[cfg(any(feature = "secp256k1", feature = "secp256r1", feature = "secp384r1"))]
/// Public ECDSA verification, without local signing capability.
///
/// ```compile_fail
/// use ssi_crypto::ecdsa::SigningKey;
/// ```
/// ```compile_fail
/// use ssi_crypto::ecdsa::hazmat::sign_prehashed;
/// ```
/// ```compile_fail
/// use ssi_crypto::ecdsa::hazmat::sign_prehashed_rfc6979;
/// ```
pub use ecdsa_core as ecdsa;

#[cfg(feature = "ed25519")]
pub use ed25519_dalek as ed25519;
#[cfg(feature = "secp256k1")]
pub use k256;
#[cfg(feature = "secp256r1")]
pub use p256;
#[cfg(feature = "secp384r1")]
pub use p384;

pub mod algorithm;
pub mod hashes;
pub mod key;
mod verification;

pub use algorithm::{Algorithm, AlgorithmError, AlgorithmInstance, UnsupportedAlgorithm};
pub use key::PublicKey;
pub use verification::*;
