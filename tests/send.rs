//! When too many lifetime requirements are added to async fns in traits, the
//! compiler may get confused, triggering this issue:
//! <https://github.com/rust-lang/rust/issues/100013>
//! This test ensures that the Rust compiler is able to prove that the
//! `CryptographicSuite::sign` returns a future that is `Send` without
//! triggering the issue.
mod vcdm_v1_sign;
mod vcdm_v2_sign;

use serde::{Deserialize, Serialize};
use ssi::{
    claims::{
        data_integrity::{AnySuite, CryptographicSuite, ProofOptions},
        vc::v1::JsonCredential,
    },
    dids::{DIDResolver, DIDJWK},
    verification_methods::{AnyMethod, MessageSigner, Signer},
    JWK,
};
use ssi_claims::{
    data_integrity::{AnySignatureAlgorithm, AnySignatureAlgorithmInstance},
    vc::syntax::NonEmptyVec,
};
use ssi_claims_core::{MessageSignatureError, SignatureError};
use static_iref::uri;
use std::{borrow::Cow, future::Future};

struct RemoteSigner;
struct RemoteMessageSigner;

impl Signer<AnyMethod> for RemoteSigner {
    type MessageSigner = RemoteMessageSigner;

    async fn for_method(
        &self,
        _: Cow<'_, AnyMethod>,
    ) -> Result<Option<Self::MessageSigner>, SignatureError> {
        Ok(Some(RemoteMessageSigner))
    }
}

impl MessageSigner<AnySignatureAlgorithm> for RemoteMessageSigner {
    async fn sign(
        self,
        _: AnySignatureAlgorithmInstance,
        _: &[u8],
    ) -> Result<Vec<u8>, MessageSignatureError> {
        panic!("the Send-future test must not execute a signature")
    }
}

fn assert_send(f: impl Send + Future) {
    drop(f)
}

#[test]
fn data_integrity_sign_is_send() {
    let credential = JsonCredential::<Claims>::new(
        Some(uri!("https://example.org/#CredentialId").to_owned()),
        uri!("https://example.org/#Issuer").to_owned().into(),
        xsd_types::DateTime::now().into(),
        NonEmptyVec::new(Claims {
            name: "name".into(),
            email: "email@example.com".into(),
        }),
    );

    let key: JWK = serde_json::from_str(include_str!("public_keys/p256.json")).unwrap();
    let did = DIDJWK::generate_url(&key);
    let vm_resolver = DIDJWK.into_vm_resolver();
    let signer = RemoteSigner;
    let verification_method = did.into_iri().into();

    let cryptosuite = AnySuite::pick(&key, Some(&verification_method))
        .expect("could not find appropriate cryptosuite");

    assert_send(cryptosuite.sign(
        credential,
        &vm_resolver,
        &signer,
        ProofOptions::from_method(verification_method),
    ))
}

#[derive(Serialize, Deserialize)]
pub struct Claims {
    #[serde(rename = "https://example.org/#name")]
    name: String,

    #[serde(rename = "https://example.org/#email")]
    email: String,
}
