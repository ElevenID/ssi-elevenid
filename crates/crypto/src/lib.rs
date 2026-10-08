#![cfg_attr(docsrs, feature(doc_auto_cfg))]

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
