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

/// Public Ed25519 verification types. Credential signing stays in KMS.
/// ```compile_fail
/// use ssi_crypto::ed25519::SigningKey;
/// ```
#[cfg(feature = "ed25519")]
pub mod ed25519 {
    pub use ed25519_dalek::{Signature, SignatureError, Verifier, VerifyingKey};
}

/// Public curve and verification types, without a credential secret-key API.
/// ```compile_fail
/// use ssi_crypto::k256::SecretKey;
/// ```
#[cfg(feature = "secp256k1")]
pub mod k256 {
    pub use ::k256::elliptic_curve::sec1::ToSec1Point;
    pub use ::k256::{PublicKey, Sec1Point, Secp256k1};

    pub mod ecdsa {
        pub use ::k256::ecdsa::Signature;
        pub type VerifyingKey = ecdsa_core::VerifyingKey<::k256::Secp256k1>;
    }
}

/// Public curve and verification types, without a credential secret-key API.
/// ```compile_fail
/// use ssi_crypto::p256::SecretKey;
/// ```
#[cfg(feature = "secp256r1")]
pub mod p256 {
    pub use ::p256::elliptic_curve::sec1::ToSec1Point;
    pub use ::p256::{NistP256, PublicKey, Sec1Point};

    pub mod ecdsa {
        pub use ::p256::ecdsa::Signature;
        pub type VerifyingKey = ecdsa_core::VerifyingKey<::p256::NistP256>;
    }
}

/// Public curve and verification types, without a credential secret-key API.
/// ```compile_fail
/// use ssi_crypto::p384::SecretKey;
/// ```
#[cfg(feature = "secp384r1")]
pub mod p384 {
    pub use ::p384::elliptic_curve::sec1::ToSec1Point;
    pub use ::p384::{NistP384, PublicKey, Sec1Point};

    pub mod ecdsa {
        pub use ::p384::ecdsa::Signature;
        pub type VerifyingKey = ecdsa_core::VerifyingKey<::p384::NistP384>;
    }
}

pub mod algorithm;
pub mod hashes;
pub mod key;
mod verification;

pub use algorithm::{Algorithm, AlgorithmError, AlgorithmInstance, UnsupportedAlgorithm};
pub use key::PublicKey;
pub use verification::*;
