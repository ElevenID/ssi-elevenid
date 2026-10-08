use core::fmt;

use base64::Engine;
use json_patch::Patch;
use serde::{Deserialize, Serialize};
use ssi_dids_core::{
    document::service::Endpoint as ServiceEndpoint, registration::DIDTransactionCreationError,
};
use ssi_jwk::{Base64urlUInt, JWK};
use ssi_verification_methods::ProofPurpose;

mod client;
mod did;
mod operation;
mod resolver;

pub use client::*;
pub use did::*;
pub use operation::*;
pub use resolver::*;

const MULTIHASH_SHA2_256_PREFIX: &[u8] = &[0x12];
const MULTIHASH_SHA2_256_SIZE: &[u8] = &[0x20];

/// Verification method type for Create operation
///
/// This is used when converting JWK to [verification method map][vmm] for the Create operation.
///
/// Reference: [Sidetree Ã‚Â§12.1.1 `add-public-keys`][apk] Step 3.2
///
/// [apk]: https://identity.foundation/sidetree/spec/v1.0.0/#add-public-keys
/// [vmm]: https://www.w3.org/TR/did-core/#verification-methods
pub const VERIFICATION_METHOD_TYPE: &str = "JsonWebSignature2020";

#[derive(Debug, thiserror::Error)]
#[error("key generation failed")]
pub struct KeyGenerationFailed;

#[derive(Debug, thiserror::Error)]
pub enum CreateError {
    #[error("same update and recovery keys")]
    SameUpdateAndRecoveryKeys,

    #[error(transparent)]
    KeyGenerationFailed(#[from] KeyGenerationFailed),

    #[error("invalid update key")]
    InvalidUpdateKey,

    #[error("invalid recovery key")]
    InvalidRecoveryKey,
}

impl From<CreateError> for DIDTransactionCreationError {
    fn from(value: CreateError) -> Self {
        match value {
            CreateError::SameUpdateAndRecoveryKeys => {
                DIDTransactionCreationError::SameUpdateAndRecoveryKeys
            }
            CreateError::KeyGenerationFailed(_) => DIDTransactionCreationError::KeyGenerationFailed,
            CreateError::InvalidUpdateKey => DIDTransactionCreationError::InvalidUpdateKey,
            CreateError::InvalidRecoveryKey => DIDTransactionCreationError::InvalidRecoveryKey,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum UpdateError {
    #[error("invalid update key")]
    InvalidUpdateKey,

    #[error("update key unchanged")]
    UpdateKeyUnchanged,

    #[error("signature failed")]
    SignatureFailed,
}

impl From<UpdateError> for DIDTransactionCreationError {
    fn from(value: UpdateError) -> Self {
        match value {
            UpdateError::InvalidUpdateKey => Self::InvalidUpdateKey,
            UpdateError::UpdateKeyUnchanged => Self::UpdateKeyUnchanged,
            UpdateError::SignatureFailed => Self::SignatureFailed,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DeactivateError {
    #[error("invalid recovery key")]
    InvalidRecoveryKey,

    #[error("signature failed")]
    SignatureFailed,
}

impl From<DeactivateError> for DIDTransactionCreationError {
    fn from(value: DeactivateError) -> Self {
        match value {
            DeactivateError::InvalidRecoveryKey => Self::InvalidRecoveryKey,
            DeactivateError::SignatureFailed => Self::SignatureFailed,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RecoverError {
    #[error("invalid recovery key")]
    InvalidRecoveryKey,

    #[error("recovery key unchanged")]
    RecoveryKeyUnchanged,

    #[error("signature failed")]
    SignatureFailed,

    #[error(transparent)]
    KeyGenerationFailed(#[from] KeyGenerationFailed),
}

impl From<RecoverError> for DIDTransactionCreationError {
    fn from(value: RecoverError) -> Self {
        match value {
            RecoverError::InvalidRecoveryKey => Self::InvalidRecoveryKey,
            RecoverError::RecoveryKeyUnchanged => Self::RecoveryKeyUnchanged,
            RecoverError::SignatureFailed => Self::SignatureFailed,
            RecoverError::KeyGenerationFailed(_) => Self::KeyGenerationFailed,
        }
    }
}

/// Parameters for a Sidetree client implementation
///
/// This trait consistest of the subset of parameters defined in [Sidetree Ã‚Â§5. Default Parameters][default-params] that are needed to implemented a Sidetree client, that is a client to the [Sidetree REST API][sidetree-rest].
///
/// [default-params]: https://identity.foundation/sidetree/spec/v1.0.0/#default-parameters
/// [sidetree-rest]: https://identity.foundation/sidetree/api/
pub trait Sidetree {
    /// [`HASH_PROTOCOL`](https://identity.foundation/sidetree/spec/v1.0.0/#hash-protocol)
    ///
    /// This should be implemented using [hash_algorithm].
    ///
    /// Default implementation calls [hash_protocol_algorithm] and returns the concatenation of the
    /// prefix and hash.
    ///
    /// This function must correspond with [hash_algorithm]. To ensure that correspondence,
    /// implementers may want to override [hash_protocol_algorithm] instead of this function.
    ///
    /// [hash_algorithm]: Self::hash_algorithm
    /// [hash_protocol_algorithm]: Self::hash_protocol_algorithm
    fn hash_protocol(data: &[u8]) -> Vec<u8> {
        let (prefix, hash) = Self::hash_protocol_algorithm(data);
        [prefix, hash].concat()
    }

    /// [`HASH_ALGORITHM`](https://identity.foundation/sidetree/spec/v1.0.0/#hash-algorithm)
    ///
    /// Default implementation calls [hash_protocol_algorithm] and returns the hash, discarding the
    /// prefix.
    ///
    /// This function must correspond with [hash_protocol]. To ensure that correspondence,
    /// implementers may want to override [hash_protocol_algorithm] instead of this function.
    ///
    /// [hash_protocol]: Self::hash_protocol
    /// [hash_protocol_algorithm]: Self::hash_protocol_algorithm
    fn hash_algorithm(data: &[u8]) -> Vec<u8> {
        let (_prefix, hash) = Self::hash_protocol_algorithm(data);
        hash
    }

    /// Combination of [hash_protocol] and [hash_algorithm]
    ///
    /// Returns multihash prefix and hash.
    ///
    /// Default implementation: SHA-256 (`sha2-256`)
    ///
    /// [hash_protocol] and [hash_algorithm] must correspond, and their default implementations
    /// call this function ([hash_protocol_algorithm]). Implementers are therefore encouraged to
    /// overwrite this function ([hash_protocol_algorithm]) rather than those ([hash_protocol] and
    /// [hash_algorithm]).
    ///
    /// [hash_protocol]: Self::hash_protocol
    /// [hash_algorithm]: Self::hash_algorithm
    /// [hash_protocol_algorithm]: Self::hash_protocol_algorithm
    fn hash_protocol_algorithm(data: &[u8]) -> (Vec<u8>, Vec<u8>) {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hasher.finalize().to_vec();
        (
            [MULTIHASH_SHA2_256_PREFIX, MULTIHASH_SHA2_256_SIZE].concat(),
            hash,
        )
    }

    /// [`DATA_ENCODING_SCHEME`](https://identity.foundation/sidetree/spec/v1.0.0/#data-encoding-scheme)
    fn data_encoding_scheme(data: &[u8]) -> String {
        base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(data)
    }

    /// Ensure that a keypair is valid for this Sidetree DID Method
    ///
    /// Check that the key uses this Sidetree DID method's [KEY_ALGORITHM][ka].
    ///
    /// [ka]: https://identity.foundation/sidetree/spec/v1.0.0/#key-algorithm
    fn validate_key(key: &JWK) -> bool;

    /// [`SIGNATURE_ALGORITHM`](https://identity.foundation/sidetree/spec/v1.0.0/#sig-algorithm) (JWS alg)
    const SIGNATURE_ALGORITHM: ssi_jwk::Algorithm;

    /// [`REVEAL_VALUE`](https://identity.foundation/sidetree/spec/v1.0.0/#reveal-value)
    fn reveal_value(commitment_value: &[u8]) -> String {
        // The spec implies that REVEAL_VALUE uses HASH_PROTOCOL, in Ã‚Â§6.2.1:
        //   "Use the implementationÃ¢â‚¬â„¢s HASH_PROTOCOL to hash the canonicalized public key to generate the REVEAL_VALUE"
        //   https://identity.foundation/sidetree/spec/v1.0.0/#public-key-commitment-scheme
        let hash = Self::hash_protocol(commitment_value);
        Self::data_encoding_scheme(&hash)
    }

    /// [`MAX_OPERATION_HASH_LENGTH`](https://identity.foundation/sidetree/spec/v1.0.0/#max-operation-hash-length)
    const MAX_OPERATION_HASH_LENGTH: usize = 100;

    /// [`NONCE_SIZE`](https://identity.foundation/sidetree/spec/v1.0.0/#nonce-size)
    const NONCE_SIZE: usize = 16;

    /// Method name for Sidetree-based DID
    ///
    /// Mentioned in [Sidetree Ã‚Â§9. DID URI Composition](https://identity.foundation/sidetree/spec/v1.0.0/#did-uri-composition)
    const METHOD: &'static str;

    /// Network instance
    ///
    /// Additional segment after the method-id (METHOD), as a prefix for the method-specific-id
    /// (DID Suffix), identifiying a network instance. e.g. "testnet"
    ///
    /// Mentioned in [Note 1](https://identity.foundation/sidetree/spec/v1.0.0/#note-1)
    const NETWORK: Option<&'static str> = None;

    /// Maximum length of `controller` property
    ///
    /// Reference: [Sidetree Ã‚Â§12.1.1 `add-public-keys`](https://identity.foundation/sidetree/spec/v1.0.0/#add-public-keys)
    const MAX_CONTROLLER_LENGTH: Option<usize> = None;

    /// Maximum length of `publicKeyMultibase` property
    ///
    /// Reference: [Sidetree Ã‚Â§12.1.1 `add-public-keys`](https://identity.foundation/sidetree/spec/v1.0.0/#add-public-keys)
    const MAX_PKMB_LENGTH: Option<usize> = None;

    /// Hash and encode data
    ///
    /// [Sidetree Ã‚Â§6.1 Hashing Process](https://identity.foundation/sidetree/spec/#hashing-process)
    fn hash(data: &[u8]) -> String {
        let hash = Self::hash_protocol(data);
        /*
        ensure!(
            hash.len() <= Self::MAX_OPERATION_HASH_LENGTH,
            "Hash is too long"
        );
        */
        Self::data_encoding_scheme(&hash)
    }

    /// [Public Key Commitment Scheme (Sidetree Ã‚Â§6.2.1)][pkcs]
    ///
    /// [pkcs]: https://identity.foundation/sidetree/spec/v1.0.0/#public-key-commitment-scheme
    fn commitment_scheme(pkjwk: &PublicKeyJwk) -> String {
        let canonicalized_public_key = json_canonicalization_scheme(&pkjwk).unwrap();
        // Note: hash_algorithm called here instead of reveal_value, since the underlying hash is
        // used, not the encoded/prefixed one.
        let reveal_value = Self::hash_algorithm(canonicalized_public_key.as_bytes());
        Self::hash(&reveal_value)
    }

    /// Create a Sidetree-based DID using existing keys
    ///
    /// This function creates a Sidetree-based DID using existing public keys for
    /// the update key and recovery key and respective
    /// [commitments][].
    ///
    /// Sidetree specifies in ([Ã‚Â§11.1 Create][create]) that creating a Sidetree DID involves
    /// generating an Update keypair and Recovery keypair. This method accepts
    /// their public keys from an external key manager.
    ///
    /// **Note**: The Sidetree specification ([Ã‚Â§6.2.1 Public Key Commitment
    /// Scheme][pkcs]) recommends not reusing public keys across different commitment invocations, and
    /// requires not using public key JWK payloads across commitment invocations.
    ///
    /// [commitments]: https://identity.foundation/sidetree/spec/v1.0.0/#commitment
    /// [create]: https://identity.foundation/sidetree/spec/v1.0.0/#create
    /// [pkcs]: https://identity.foundation/sidetree/spec/v1.0.0/#public-key-commitment-scheme
    fn create_existing(
        update_pk: &PublicKeyJwk,
        recovery_pk: &PublicKeyJwk,
        patches: Vec<DIDStatePatch>,
    ) -> Result<Operation, CreateError> {
        if update_pk == recovery_pk {
            return Err(CreateError::SameUpdateAndRecoveryKeys);
        }

        let update_commitment = Self::commitment_scheme(update_pk);

        let create_operation_delta_object = Delta {
            patches,
            update_commitment,
        };
        let delta_string = json_canonicalization_scheme(&create_operation_delta_object).unwrap();
        let delta_hash = Self::hash(delta_string.as_bytes());

        let recovery_commitment = Self::commitment_scheme(recovery_pk);

        let create_operation_suffix_data_object = SuffixData {
            r#type: None,
            delta_hash,
            recovery_commitment,
            anchor_origin: None,
        };

        let create_operation = CreateOperation {
            suffix_data: create_operation_suffix_data_object,
            delta: create_operation_delta_object,
        };

        Ok(Operation::Create(create_operation))
    }

    /// Serialize and hash [Suffix Data][SuffixData], to generate a [Short-Form Sidetree
    /// DID][SidetreeDID::Short] ([`DIDSuffix`]).
    ///
    /// Reference: <https://identity.foundation/sidetree/spec/v1.0.0/#did-uri-composition>
    fn serialize_suffix_data(suffix_data: &SuffixData) -> DIDSuffix {
        let string = json_canonicalization_scheme(suffix_data).unwrap();
        let hash = Self::hash(string.as_bytes());
        DIDSuffix(hash)
    }

    /// Check that a DID Suffix looks valid
    fn validate_did_suffix(suffix: &DIDSuffix) -> Result<(), InvalidSidetreeDIDSuffix> {
        let bytes = base64::prelude::BASE64_URL_SAFE_NO_PAD
            .decode(&suffix.0)
            .map_err(|_| InvalidSidetreeDIDSuffix::Base64)?;

        if bytes.len() != 34 {
            return Err(InvalidSidetreeDIDSuffix::Length(bytes.len()));
        }

        if &bytes[0..1] != MULTIHASH_SHA2_256_PREFIX || &bytes[1..2] != MULTIHASH_SHA2_256_SIZE {
            return Err(InvalidSidetreeDIDSuffix::Prefix);
        }

        Ok(())
    }
}

/// [`JSON_CANONICALIZATION_SCHEME`](https://identity.foundation/sidetree/spec/v1.0.0/#json-canonicalization-scheme)
fn json_canonicalization_scheme<T: Serialize + ?Sized>(
    value: &T,
) -> Result<String, serde_json::Error> {
    serde_jcs::to_string(value)
}

#[derive(Debug, thiserror::Error)]
pub enum InvalidSidetreeDIDSuffix {
    #[error("invalid base64")]
    Base64,

    #[error("unexpected DID suffix length ({0})")]
    Length(usize),

    #[error("unexpected DID suffix prefix")]
    Prefix,
}

/// Public key as JWK or Multibase
///
/// Property of a public key / verification method containing public key data,
/// as part of a [PublicKeyEntry][].
///
/// per [Sidetree Ã‚Â§12.1.1 `add-public-keys`: Step 4][apk].
///
/// [apk]: https://identity.foundation/sidetree/spec/v1.0.0/#add-public-keys
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub enum PublicKey {
    /// [`publicKeyJwk`](https://www.w3.org/TR/did-core/#dfn-publickeyjwk) as defined in DID Core.
    ///
    /// JSON Web Key (JWK) is specified in [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517).
    PublicKeyJwk(PublicKeyJwk),

    /// [`publicKeyMultibase`](https://www.w3.org/TR/did-core/#dfn-publickeymultibase) as defined in DID Core.
    ///
    /// Maximum length may be set in [Sidetree::MAX_PKMB_LENGTH].
    PublicKeyMultibase(String),
}

/// Public Key Entry
///
/// Used by the [`add-public-keys`](DIDStatePatch::AddPublicKeys) and
/// [`replace`](DIDStatePatch::Replace) DID state patch actions.
///
/// Specified in [Sidetree Ã‚Â§12.1.1 `add-public-keys`][apk].
///
/// [apk]: https://identity.foundation/sidetree/spec/v1.0.0/#add-public-keys
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyEntry {
    /// `id` property
    ///
    /// Maximum length: 50 in Base64url
    pub id: String,

    /// Verification method type
    pub r#type: String,

    /// Verification method controller (DID)
    ///
    /// Maximum length may be set in [Sidetree::MAX_CONTROLLER_LENGTH].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub controller: Option<String>,

    /// `publicKeyJwk` or `publicKeyMultibase` property
    #[serde(flatten)]
    pub public_key: PublicKey,

    /// Verification relationships
    ///
    /// Defined in [DID Core](https://www.w3.org/TR/did-core/#verification-relationships).
    ///
    /// Corresponds to [`proofPurpose`](https://www.w3.org/TR/did-core/#verification-relationships) in VC Data Model.
    pub purposes: Vec<ProofPurpose>,
}

#[derive(Debug, thiserror::Error)]
#[error("invalid public key entry")]
pub struct InvalidPublicKeyEntry(pub JWK);

impl TryFrom<JWK> for PublicKeyEntry {
    type Error = InvalidPublicKeyEntry;

    fn try_from(jwk: JWK) -> Result<Self, Self::Error> {
        let Ok(id) = jwk.thumbprint() else {
            return Err(InvalidPublicKeyEntry(jwk));
        };

        let Ok(pkjwk) = PublicKeyJwk::try_from(jwk.to_public()) else {
            return Err(InvalidPublicKeyEntry(jwk));
        };

        let public_key = PublicKey::PublicKeyJwk(pkjwk);
        Ok(PublicKeyEntry {
            id,
            r#type: VERIFICATION_METHOD_TYPE.to_owned(),
            controller: None,
            public_key,
            purposes: vec![
                ProofPurpose::Assertion,
                ProofPurpose::Authentication,
                ProofPurpose::KeyAgreement,
                ProofPurpose::CapabilityInvocation,
                ProofPurpose::CapabilityDelegation,
            ],
        })
    }
}

/// Service Endpoint Entry
///
/// Used by the [`add-services`](DIDStatePatch::AddServices) and
/// [`replace`](DIDStatePatch::Replace) DID state patch actions.
///
/// Specified in [Sidetree Ã‚Â§12.1.3 `add-services`][as].
///
/// [as]: https://identity.foundation/sidetree/spec/v1.0.0/#add-services
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ServiceEndpointEntry {
    /// `id` property
    ///
    /// Maximum length: 50 in Base64Url
    pub id: String,

    /// Service type
    ///
    /// Maximum length: 30 in Base64Url
    pub r#type: String,

    /// Service endpoint URL or object
    pub service_endpoint: ServiceEndpoint,
}

/// DID PKI metadata state
///
/// Used by the [`replace`](DIDStatePatch::Replace) DID state patch.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct DocumentState {
    /// Public key entries
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_keys: Option<Vec<PublicKeyEntry>>,

    /// Services
    #[serde(skip_serializing_if = "Option::is_none")]
    pub services: Option<Vec<ServiceEndpointEntry>>,
}

/// [DID State Patch][dsp] using a [Sidetree Standard Patch action][spa]
///
/// [dsp]: https://identity.foundation/sidetree/spec/v1.0.0/#did-state-patches
/// [spa]: https://identity.foundation/sidetree/spec/v1.0.0/#standard-patch-actions
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "action")]
#[serde(rename_all = "kebab-case")]
pub enum DIDStatePatch {
    /// [`add-public-keys`][apk] Patch Action
    ///
    /// [apk]: https://identity.foundation/sidetree/spec/v1.0.0/#add-public-keys
    AddPublicKeys {
        /// Keys to add or over overwrite
        #[serde(rename = "publicKeys")]
        public_keys: Vec<PublicKeyEntry>,
    },

    /// [`remove-public-keys`][rpk] Patch Action
    ///
    /// [rpk]: https://identity.foundation/sidetree/spec/v1.0.0/#remove-public-keys
    RemovePublicKeys {
        /// IDs of keys to remove
        ids: Vec<String>,
    },

    /// [`add-services`][as] Patch Action
    ///
    /// [as]: https://identity.foundation/sidetree/spec/v1.0.0/#add-services
    AddServices {
        /// Service entries to add
        services: Vec<ServiceEndpointEntry>,
    },

    /// [`remove-services`][rs] Patch Action
    ///
    /// [rs]: https://identity.foundation/sidetree/spec/v1.0.0/#remove-services
    RemoveServices {
        /// IDs of service endpoints to remove
        ids: Vec<String>,
    },

    /// [`replace`][r] Patch Action
    ///
    /// [r]: https://identity.foundation/sidetree/spec/v1.0.0/#replace
    Replace {
        /// Reset DID state
        document: DocumentState,
    },

    /// [`ietf-json-patch`][ijp] Patch Action
    ///
    /// [ijp]: https://identity.foundation/sidetree/spec/v1.0.0/#ietf-json-patch
    ///
    IetfJsonPatch {
        /// JSON Patches according to [RFC 6902](https://datatracker.ietf.org/doc/html/rfc6902).
        patches: Patch,
    },
}

/// Create/Update/Recover Delta Object
///
/// ### References
/// - [Sidetree Ã‚Â§11.1 Create - Create Operation Delta Object][codo]
/// - [Sidetree Ã‚Â§11.2 Update - Update Operation Delta Object][uodo]
/// - [Sidetree Ã‚Â§11.3 Recover - Recover Operation Delta Object][rodo]
///
/// [codo]: https://identity.foundation/sidetree/spec/v1.0.0/#create-delta-object
/// [uodo]: https://identity.foundation/sidetree/spec/v1.0.0/#update-delta-object
/// [rodo]: https://identity.foundation/sidetree/spec/v1.0.0/#recover-delta-object
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Delta {
    /// DID state patches to apply.
    pub patches: Vec<DIDStatePatch>,

    /// Update commitment generated as part of a Sidetree Create or Update operation.
    pub update_commitment: String,
}

/// Public Key JWK (JSON Web Key)
///
/// Wraps [ssi_jwk::JWK], while allowing a `nonce` property, and disallowing private key
/// properties ("d").
///
/// Sidetree may allow a `nonce` property in public key JWKs ([Ã‚Â§6.2.2 JWK Nonce][jwkn]).
///
/// [jwkn]: https://identity.foundation/sidetree/spec/#jwk-nonce
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyJwk {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<Base64urlUInt>,
    #[serde(flatten)]
    jwk: serde_json::Value,
}

/// Error resulting from [converting JWK to PublicKeyJwk][PublicKeyJwk::try_from]
#[derive(thiserror::Error, Debug)]
pub enum PublicKeyJwkFromJWKError {
    /// Public Key JWK must not contain private key parameters (e.g. "d")
    #[error("Public Key JWK must not contain private key parameters")]
    PrivateKeyParameters,
}

/// Error resulting from attempting to convert [PublicKeyJwk] to JWK
#[derive(thiserror::Error, Debug)]
pub enum JWKFromPublicKeyJwkError {
    /// Unable to convert [`serde_json::Value`] to JWK
    #[error("Unable to convert Value to JWK")]
    FromValue(#[from] serde_json::Error),
}

impl TryFrom<JWK> for PublicKeyJwk {
    type Error = PublicKeyJwkFromJWKError;
    fn try_from(jwk: JWK) -> Result<Self, Self::Error> {
        let jwk_value = serde_json::to_value(jwk).unwrap();
        if jwk_value.get("d").is_some() {
            return Err(PublicKeyJwkFromJWKError::PrivateKeyParameters);
        };
        Ok(Self {
            jwk: jwk_value,
            nonce: None,
        })
    }
}

/// Convert [PublicKeyJwk] to [JWK].
///
/// Note: `nonce` property is dropped.
impl TryFrom<PublicKeyJwk> for JWK {
    type Error = JWKFromPublicKeyJwkError;
    fn try_from(pkjwk: PublicKeyJwk) -> Result<Self, Self::Error> {
        let jwk = serde_json::from_value(pkjwk.jwk).map_err(JWKFromPublicKeyJwkError::FromValue)?;
        Ok(jwk)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SidetreeAPIError {
    // List of error codes: https://github.com/decentralized-identity/sidetree/blob/v1.0.0/lib/core/versions/1.0/ErrorCode.ts
    pub code: String,
    pub message: Option<String>,
}

impl fmt::Display for SidetreeAPIError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Sidetree error {}", self.code)?;
        if let Some(ref message) = self.message {
            write!(f, ": {}", message)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::ion::is_secp256k1;

    use super::*;
    use serde_json::json;
    use ssi_jwk::Algorithm;

    struct Example;

    impl Sidetree for Example {
        fn validate_key(key: &JWK) -> bool {
            is_secp256k1(key)
        }
        const SIGNATURE_ALGORITHM: Algorithm = Algorithm::ES256K;
        const METHOD: &'static str = "sidetree";
    }

    /// <https://identity.foundation/sidetree/spec/v1.0.0/#did>
    static LONGFORM_DID: &str = "did:sidetree:EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJwdWJsaWNLZXlNb2RlbDFJZCIsInB1YmxpY0tleUp3ayI6eyJjcnYiOiJzZWNwMjU2azEiLCJrdHkiOiJFQyIsIngiOiJ0WFNLQl9ydWJYUzdzQ2pYcXVwVkpFelRjVzNNc2ptRXZxMVlwWG45NlpnIiwieSI6ImRPaWNYcWJqRnhvR0otSzAtR0oxa0hZSnFpY19EX09NdVV3a1E3T2w2bmsifSwicHVycG9zZXMiOlsiYXV0aGVudGljYXRpb24iLCJrZXlBZ3JlZW1lbnQiXSwidHlwZSI6IkVjZHNhU2VjcDI1NmsxVmVyaWZpY2F0aW9uS2V5MjAxOSJ9XSwic2VydmljZXMiOlt7ImlkIjoic2VydmljZTFJZCIsInNlcnZpY2VFbmRwb2ludCI6Imh0dHA6Ly93d3cuc2VydmljZTEuY29tIiwidHlwZSI6InNlcnZpY2UxVHlwZSJ9XX19XSwidXBkYXRlQ29tbWl0bWVudCI6IkVpREtJa3dxTzY5SVBHM3BPbEhrZGI4Nm5ZdDBhTnhTSFp1MnItYmhFem5qZEEifSwic3VmZml4RGF0YSI6eyJkZWx0YUhhc2giOiJFaUNmRFdSbllsY0Q5RUdBM2RfNVoxQUh1LWlZcU1iSjluZmlxZHo1UzhWRGJnIiwicmVjb3ZlcnlDb21taXRtZW50IjoiRWlCZk9aZE10VTZPQnc4UGs4NzlRdFotMkotOUZiYmpTWnlvYUFfYnFENHpoQSJ9fQ";
    static SHORTFORM_DID: &str = "did:sidetree:EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg";

    lazy_static::lazy_static! {

        /// <https://identity.foundation/sidetree/spec/v1.0.0/#create-2>
        static ref CREATE_OPERATION: Operation = serde_json::from_value(json!({
          "type": "create",
          "suffixData": {
            "deltaHash": "EiCfDWRnYlcD9EGA3d_5Z1AHu-iYqMbJ9nfiqdz5S8VDbg",
            "recoveryCommitment": "EiBfOZdMtU6OBw8Pk879QtZ-2J-9FbbjSZyoaA_bqD4zhA"
          },
          "delta": {
            "updateCommitment": "EiDKIkwqO69IPG3pOlHkdb86nYt0aNxSHZu2r-bhEznjdA",
            "patches": [
              {
                "action": "replace",
                "document": {
                  "publicKeys": [
                    {
                      "id": "publicKeyModel1Id",
                      "type": "EcdsaSecp256k1VerificationKey2019",
                      "publicKeyJwk": {
                        "kty": "EC",
                        "crv": "secp256k1",
                        "x": "tXSKB_rubXS7sCjXqupVJEzTcW3MsjmEvq1YpXn96Zg",
                        "y": "dOicXqbjFxoGJ-K0-GJ1kHYJqic_D_OMuUwkQ7Ol6nk"
                      },
                      "purposes": [
                        "authentication",
                        "keyAgreement"
                      ]
                    }
                  ],
                  "services": [
                    {
                      "id": "service1Id",
                      "type": "service1Type",
                      "serviceEndpoint": "http://www.service1.com"
                    }
                  ]
                }
              }
            ]
          }
        })).unwrap();

        /// <https://identity.foundation/sidetree/spec/v1.0.0/#update-2>
        static ref UPDATE_OPERATION: Operation = serde_json::from_value(json!({
          "type": "update",
          "didSuffix": "EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg",
          "revealValue": "EiBkRSeixqX-PhOij6PIpuGfPld5Nif5MxcrgtGCw-t6LA",
          "delta": {
            "patches": [
              {
                "action": "add-public-keys",
                "publicKeys": [
                  {
                    "id": "additional-key",
                    "type": "EcdsaSecp256k1VerificationKey2019",
                    "publicKeyJwk": {
                      "kty": "EC",
                      "crv": "secp256k1",
                      "x": "aN75CTjy3VCgGAJDNJHbcb55hO8CobEKzgCNrUeOwAY",
                      "y": "K9FhCEpa_jG09pB6qriXrgSvKzXm6xtxBvZzIoXXWm4"
                    },
                    "purposes": [
                      "authentication",
                      "assertionMethod",
                      "capabilityInvocation",
                      "capabilityDelegation",
                      "keyAgreement"
                    ]
                  }
                ]
              }
            ],
            "updateCommitment": "EiDOrcmPtfMHuwIWN6YoihdeIPxOKDHy3D6sdMXu_7CN0w"
          },
          "signedData": "eyJhbGciOiJFUzI1NksifQ.eyJ1cGRhdGVLZXkiOnsia3R5IjoiRUMiLCJjcnYiOiJzZWNwMjU2azEiLCJ4Ijoid2Z3UUNKM09ScVZkbkhYa1Q4UC1MZ19HdHhCRWhYM3R5OU5VbnduSHJtdyIsInkiOiJ1aWU4cUxfVnVBblJEZHVwaFp1eExPNnFUOWtQcDNLUkdFSVJsVHBXcmZVIn0sImRlbHRhSGFzaCI6IkVpQ3BqTjQ3ZjBNcTZ4RE5VS240aFNlZ01FcW9EU19ycFEyOVd5MVY3M1ZEYncifQ.RwZK1DG5zcr4EsrRImzStb0VX5j2ZqApXZnuoAkA3IoRdErUscNG8RuxNZ0FjlJtjMJ0a-kn-_MdtR0wwvWVgg"
        })).unwrap();

        /// <https://identity.foundation/sidetree/spec/v1.0.0/#recover-2>
        static ref RECOVER_OPERATION: Operation = serde_json::from_value(json!({
          "type": "recover",
          "didSuffix": "EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg",
          "revealValue": "EiAJ-97Is59is6FKAProwDo870nmwCeP8n5nRRFwPpUZVQ",
          "signedData": "eyJhbGciOiJFUzI1NksifQ.eyJkZWx0YUhhc2giOiJFaUNTem1ZSk0yWGpaWE00a1Q0bGpKcEVGTjVmVkM1QVNWZ3hSekVtMEF2OWp3IiwicmVjb3ZlcnlLZXkiOnsia3R5IjoiRUMiLCJjcnYiOiJzZWNwMjU2azEiLCJ4IjoibklxbFJDeDBleUJTWGNRbnFEcFJlU3Y0enVXaHdDUldzc29jOUxfbmo2QSIsInkiOiJpRzI5Vks2bDJVNXNLQlpVU0plUHZ5RnVzWGdTbEsyZERGbFdhQ004RjdrIn0sInJlY292ZXJ5Q29tbWl0bWVudCI6IkVpQ3NBN1NHTE5lZGE1SW5sb3Fub2tVY0pGejZ2S1Q0SFM1ZGNLcm1ubEpocEEifQ.lxWnrg5jaeCAhYuz1fPhidKw6Z2cScNlEc6SWcs15DtJbrHZFxl5IezGJ3cWdOSS2DlzDl4M1ZF8dDE9kRwFeQ",
          "delta": {
            "patches": [
              {
                "action": "replace",
                "document": {
                  "publicKeys": [
                    {
                      "id": "newKey",
                      "type": "EcdsaSecp256k1VerificationKey2019",
                      "publicKeyJwk": {
                        "kty": "EC",
                        "crv": "secp256k1",
                        "x": "JUWp0pAMGevNLhqq_Qmd48izuLYfO5XWpjSmy5btkjc",
                        "y": "QYaSu1NHYnxR4qfk-RkXb4NQnQf1X3XQCpDYuibvlNc"
                      },
                      "purposes": [
                        "authentication",
                        "assertionMethod",
                        "capabilityInvocation",
                        "capabilityDelegation",
                        "keyAgreement"
                      ]
                    }
                  ],
                  "services": [
                    {
                      "id": "serviceId123",
                      "type": "someType",
                      "serviceEndpoint": "https://www.url.com"
                    }
                  ]
                }
              }
            ],
            "updateCommitment": "EiD6_csybTfxELBoMgkE9O2BTCmhScG_RW_qaZQkIkJ_aQ"
          }
        })).unwrap();

        /// <https://identity.foundation/sidetree/spec/v1.0.0/#deactivate-2>
        static ref DEACTIVATE_OPERATION: Operation = serde_json::from_value(json!({
          "type": "deactivate",
          "didSuffix": "EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg",
          "revealValue": "EiB-dib5oumdaDGH47TB17Qg1nHza036bTIGibQOKFUY2A",
          "signedData": "eyJhbGciOiJFUzI1NksifQ.eyJkaWRTdWZmaXgiOiJFaUR5T1FiYlpBYTNhaVJ6ZUNrVjdMT3gzU0VSampIOTNFWG9JTTNVb040b1dnIiwicmVjb3ZlcnlLZXkiOnsia3R5IjoiRUMiLCJjcnYiOiJzZWNwMjU2azEiLCJ4IjoiSk1ucF9KOW5BSGFkTGpJNmJfNVU3M1VwSEZqSEZTVHdtc1ZUUG9FTTVsMCIsInkiOiJ3c1QxLXN0UWJvSldPeEJyUnVINHQwVV9zX1lSQy14WXQyRkFEVUNHR2M4In19.ARTZrvupKdShOFNAJ4EWnsuaONKBgXUiwY5Ct10a9IXIp1uFsg0UyDnZGZtJT2v2bgtmYsQBmT6L9kKaaDcvUQ"
        })).unwrap();
    }

    #[test]
    fn test_did_parse_format() {
        let longform_did = SidetreeDID::<Example>::from_str(LONGFORM_DID).unwrap();
        let shortform_did = SidetreeDID::<Example>::from_str(SHORTFORM_DID).unwrap();
        assert_eq!(longform_did.to_string(), LONGFORM_DID);
        assert_eq!(shortform_did.to_string(), SHORTFORM_DID);
        assert!(LONGFORM_DID.starts_with(SHORTFORM_DID));
    }

    #[test]
    fn test_longform_did_construction() {
        let create_operation = match &*CREATE_OPERATION {
            Operation::Create(op) => op,
            _ => panic!("Expected Create Operation"),
        };
        let did: SidetreeDID<Example> = create_operation.to_sidetree_did();
        assert_eq!(did.to_string(), LONGFORM_DID);
    }

    #[test]
    fn test_update_verify_reveal() {
        let create_pvo = CREATE_OPERATION
            .clone()
            .partial_verify::<Example>()
            .unwrap();
        let update_pvo = UPDATE_OPERATION
            .clone()
            .partial_verify::<Example>()
            .unwrap();
        update_pvo.follows::<Example>(&create_pvo).unwrap();
    }

    #[test]
    fn test_recover_verify_reveal() {
        let create_pvo = CREATE_OPERATION
            .clone()
            .partial_verify::<Example>()
            .unwrap();
        let recover_pvo = RECOVER_OPERATION
            .clone()
            .partial_verify::<Example>()
            .unwrap();
        recover_pvo.follows::<Example>(&create_pvo).unwrap();
    }

    #[test]
    fn test_deactivate_verify_reveal() {
        let recover_pvo = RECOVER_OPERATION
            .clone()
            .partial_verify::<Example>()
            .unwrap();
        let deactivate_pvo = DEACTIVATE_OPERATION
            .clone()
            .partial_verify::<Example>()
            .unwrap();
        deactivate_pvo.follows::<Example>(&recover_pvo).unwrap();
    }
}
