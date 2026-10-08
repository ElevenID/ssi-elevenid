use ssi_claims_core::{MessageSignatureError, SignatureError};
use ssi_crypto::algorithm::SignatureAlgorithmType;
use std::{borrow::Cow, marker::PhantomData};

use crate::VerificationMethod;

/// Verification method signer.
pub trait Signer<M: VerificationMethod> {
    type MessageSigner;

    #[allow(async_fn_in_trait)]
    async fn for_method(
        &self,
        method: Cow<'_, M>,
    ) -> Result<Option<Self::MessageSigner>, SignatureError>;
}

impl<M: VerificationMethod, S: Signer<M>> Signer<M> for &S {
    type MessageSigner = S::MessageSigner;

    async fn for_method(
        &self,
        method: Cow<'_, M>,
    ) -> Result<Option<Self::MessageSigner>, SignatureError> {
        S::for_method(*self, method).await
    }
}

pub trait MessageSigner<A: SignatureAlgorithmType>: Sized {
    #[allow(async_fn_in_trait)]
    async fn sign(
        self,
        algorithm: A::Instance,
        message: &[u8],
    ) -> Result<Vec<u8>, MessageSignatureError>;

    #[allow(async_fn_in_trait)]
    async fn sign_multi(
        self,
        algorithm: A::Instance,
        messages: &[Vec<u8>],
    ) -> Result<Vec<u8>, MessageSignatureError> {
        match messages.split_first() {
            Some((message, [])) => self.sign(algorithm, message).await,
            Some(_) => Err(MessageSignatureError::TooManyMessages),
            None => Err(MessageSignatureError::MissingMessage),
        }
    }

    /// Create a proof-scoped P-256 key in the signer and sign each message.
    /// The private key must remain with the signer; only its SEC1 public key
    /// and raw ECDSA signatures are returned to the cryptographic suite.
    #[allow(async_fn_in_trait)]
    async fn sign_proof_scoped_p256(
        &self,
        _messages: &[Vec<u8>],
    ) -> Result<ProofScopedP256Signatures, MessageSignatureError> {
        Err(MessageSignatureError::UnsupportedAlgorithm(
            "proof-scoped P-256 signing".to_owned(),
        ))
    }
}

#[derive(Clone)]
pub struct ProofScopedP256Signatures {
    pub public_key_sec1: Vec<u8>,
    pub signatures: Vec<Vec<u8>>,
}

pub struct MessageSignerAdapter<S, A> {
    // Underlying signer.
    signer: S,

    algorithm: PhantomData<A>,
}

impl<S, A> MessageSignerAdapter<S, A> {
    pub fn new(signer: S) -> Self {
        Self {
            signer,
            algorithm: PhantomData,
        }
    }
}

impl<S: MessageSigner<A>, A: SignatureAlgorithmType, B: SignatureAlgorithmType> MessageSigner<B>
    for MessageSignerAdapter<S, A>
where
    A::Instance: TryFrom<B::Instance>,
{
    async fn sign(
        self,
        algorithm: B::Instance,
        message: &[u8],
    ) -> Result<Vec<u8>, MessageSignatureError> {
        let algorithm = algorithm
            .try_into()
            .map_err(|_| MessageSignatureError::InvalidQuery)?;

        self.signer.sign(algorithm, message).await
    }

    async fn sign_multi(
        self,
        algorithm: <B as SignatureAlgorithmType>::Instance,
        messages: &[Vec<u8>],
    ) -> Result<Vec<u8>, MessageSignatureError> {
        let algorithm = algorithm
            .try_into()
            .map_err(|_| MessageSignatureError::InvalidQuery)?;

        self.signer.sign_multi(algorithm, messages).await
    }

    async fn sign_proof_scoped_p256(
        &self,
        messages: &[Vec<u8>],
    ) -> Result<ProofScopedP256Signatures, MessageSignatureError> {
        self.signer.sign_proof_scoped_p256(messages).await
    }
}
