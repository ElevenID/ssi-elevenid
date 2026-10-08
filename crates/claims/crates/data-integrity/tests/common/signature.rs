#![allow(unused)]
use std::{borrow::Cow, collections::HashMap};

use iref::IriBuf;
use json_syntax::Print;
use serde::Deserialize;
use ssi_claims_core::{MessageSignatureError, SignatureEnvironment, SignatureError};
use ssi_crypto::algorithm::SignatureAlgorithmInstance;
use ssi_data_integrity::{
    AnyDataIntegrity, AnySignatureAlgorithm, AnySignatureAlgorithmInstance, AnySignatureOptions,
    AnySuite, CryptographicSuite, DataIntegrityDocument, ProofConfiguration,
};
use ssi_verification_methods::{
    AnyMethod, MessageSigner, ProofScopedP256Signatures, Signer, VerificationMethod,
};

// A fixed response models an external signer without loading private key material.
// The algorithm and prepared-message digest pin the request as well as the proof.
#[derive(Clone)]
struct VectorSigner {
    signature: Vec<u8>,
    algorithm: String,
    message_sha256: String,
    method_id: IriBuf,
    proof_scoped: Option<ProofScopedVector>,
}

#[derive(Clone)]
struct ProofScopedVector {
    signatures: ProofScopedP256Signatures,
    message_sha256: Vec<String>,
}

impl Signer<AnyMethod> for VectorSigner {
    type MessageSigner = Self;

    async fn for_method(
        &self,
        method: Cow<'_, AnyMethod>,
    ) -> Result<Option<Self::MessageSigner>, SignatureError> {
        assert_eq!(method.id(), self.method_id.as_iri());
        Ok(Some(self.clone()))
    }
}

impl MessageSigner<AnySignatureAlgorithm> for VectorSigner {
    async fn sign(
        self,
        algorithm: AnySignatureAlgorithmInstance,
        message: &[u8],
    ) -> Result<Vec<u8>, MessageSignatureError> {
        assert_eq!(algorithm.0.algorithm().to_string(), self.algorithm);
        assert_eq!(
            hex::encode(ssi_crypto::hashes::sha256::sha256(message)),
            self.message_sha256
        );
        Ok(self.signature)
    }

    async fn sign_proof_scoped_p256(
        &self,
        messages: &[Vec<u8>],
    ) -> Result<ProofScopedP256Signatures, MessageSignatureError> {
        let vector = self
            .proof_scoped
            .as_ref()
            .expect("proof-scoped test vector");
        let hashes: Vec<String> = messages
            .iter()
            .map(|message| hex::encode(ssi_crypto::hashes::sha256::sha256(message)))
            .collect();
        assert_eq!(hashes, vector.message_sha256);
        Ok(vector.signatures.clone())
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureTest {
    pub id: Option<IriBuf>,
    pub expected_algorithm: String,
    pub expected_message_sha256: String,
    #[serde(default)]
    pub proof_scoped_message_sha256: Option<Vec<String>>,
    pub verification_methods: HashMap<IriBuf, AnyMethod>,
    pub configuration: ProofConfiguration<AnySuite>,
    #[serde(default)]
    pub options: AnySignatureOptions,
    pub input: DataIntegrityDocument,
    pub expected_output: json_syntax::Value,
}

impl SignatureTest {
    pub async fn run(self) {
        self.run_with_tampered_proof_scoped_signature(false).await
    }

    pub async fn run_with_tampered_proof_scoped_signature(mut self, tamper: bool) {
        let (suite, options) = self.configuration.into_suite_and_options();

        let expected = serde_json::to_value(&self.expected_output).unwrap();
        let proof_value = expected["proof"]["proofValue"].as_str().unwrap();
        let (signature, mut proof_scoped): (Vec<u8>, Option<ProofScopedVector>) =
            match self.proof_scoped_message_sha256 {
                #[cfg(all(feature = "w3c", feature = "secp256r1"))]
                Some(message_sha256) => {
                    let proof: ssi_data_integrity::suites::ecdsa_sd_2023::Signature =
                        serde_json::from_value(expected["proof"].clone()).unwrap();
                    let decoded = proof.decode_base().unwrap();
                    (
                        decoded.base_signature,
                        Some(ProofScopedVector {
                            signatures: ProofScopedP256Signatures {
                                public_key_sec1: decoded.public_key.data().to_vec(),
                                signatures: decoded.signatures,
                            },
                            message_sha256,
                        }),
                    )
                }
                #[cfg(not(all(feature = "w3c", feature = "secp256r1")))]
                Some(_) => panic!("proof-scoped P-256 fixture requires the ecdsa-sd-2023 suite"),
                None => (multibase::decode(proof_value).unwrap().1, None),
            };
        if tamper {
            let signature = &mut proof_scoped
                .as_mut()
                .expect("proof-scoped test vector")
                .signatures
                .signatures[0];
            signature[0] ^= 1;
        }
        let mut methods = self.verification_methods.keys();
        let method_id = methods.next().expect("one verification method").clone();
        assert!(methods.next().is_none(), "exactly one verification method");
        let signed = suite
            .sign_with(
                SignatureEnvironment::default(),
                self.input,
                &self.verification_methods,
                VectorSigner {
                    signature,
                    algorithm: self.expected_algorithm,
                    message_sha256: self.expected_message_sha256,
                    method_id,
                    proof_scoped,
                },
                options.cast(),
                self.options,
            )
            .await;
        if tamper {
            assert!(
                signed.is_err(),
                "invalid proof-scoped signature was accepted"
            );
            return;
        }
        let vc: AnyDataIntegrity = signed.unwrap();

        let mut json = json_syntax::to_value(vc).unwrap();
        json.canonicalize();

        self.expected_output.canonicalize();

        if json != self.expected_output {
            eprintln!("expected: {}", self.expected_output.pretty_print());
            eprintln!("found: {}", json.pretty_print());
            match self.id {
                Some(id) => panic!("test <{}> failed", id),
                None => panic!("test failed"),
            }
        }
    }
}
