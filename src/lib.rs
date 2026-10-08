//! The SSI library provides a simple and modular API to sign and verify claims
//! exchanged between applications using
//! [Decentralized Identifiers (DIDs)][dids]. SSI is embedded in the
//! cross-platform [`didkit`][didkit] library as a core dependency.
//!
//! This library supports the two main families of verifiable claims:
//! - [JSON Web Tokens (JWT)][jwt] where claims are encoded into JSON and
//!   secured using [JSON Web Signatures][jws]; and
//! - [W3C's Verifiable Credentials (VCs)][vc-data-model], a
//!   [Linked-Data][linked-data]-based model where claims (VCs) can be
//!   interpreted as RDF datasets. VC supports multiple signature formats
//!   provided by SSI:
//!   - VC over JWT ([JWT-VC][jwt-vc]), a restricted form of JWT following the
//!     VC data model; or
//!   - [Data Integrity][data-integrity], encoding the claims and their proof
//!     in the same JSON-LD document using a wide variety of
//!     [*cryptographic suites*][cryptosuite].
//!
//! [dids]: <https://www.w3.org/TR/did-core/>
//! [didkit]: <https://github.com/spruceid/didkit>
//! [vc-data-model]: <https://www.w3.org/TR/vc-data-model/>
//! [linked-data]: <https://www.w3.org/DesignIssues/LinkedData.html>
//! [jwt]: <https://www.rfc-editor.org/rfc/rfc7519>
//! [jws]: <https://www.rfc-editor.org/rfc/rfc7515>
//! [jwt-vc]: <https://www.w3.org/TR/vc-data-model/#json-web-token>
//! [data-integrity]: <https://www.w3.org/TR/vc-data-integrity/>
//! [cryptosuite]: <https://www.w3.org/TR/vc-data-integrity/#dfn-cryptosuite>
//!
//! # Basic Usage
//!
//! SSI provides various functions to parse, verify, create and sign various
//! kind of claims. This section shows how to use these functions in combination
//! with JSON Web Signatures (or Tokens) and Verifiable Credentials.
//!
//! ## Verification
//!
//! The simplest type of claim to load and verify is probably JSON Web
//! Signatures (JWSs), often use to encode JSON Web Tokens (JWTs). To represent
//! such claims SSI provides the `JwsBuf` type representing a JWS
//! in compact textual form. One can load a JWS using [`new`] and verify
//! it using [`verify`].
//!
//! [`new`]: ssi_jws::JwsBuf::new
//! [`verify`]: ssi_jws::JwsSlice::verify
//!
//! ```
//! # use ssi_dids::example::ExampleDIDResolver;
//! # #[async_std::main]
//! # async fn main() {
//! use ssi::prelude::*;
//!
//! // Load a JWT from the file system.
//! let jwt = JwsBuf::new(
//!   std::fs::read_to_string("examples/files/claims.jwt")
//!   .expect("unable to load JWT")
//! ).expect("invalid JWS");
//!
//! // Setup a verification method resolver, in charge of retrieving the
//! // public key used to sign the JWT.
//! // Here we use the example `ExampleDIDResolver` resolver, enabled with the
//! // `example` feature.
//! let vm_resolver = ExampleDIDResolver::default().into_vm_resolver::<AnyJwkMethod>();
//!
//! // Setup the verification parameters.
//! let params = VerificationParameters::from_resolver(vm_resolver);
//!
//! // Verify the JWT.
//! assert!(jwt.verify(&params).await.expect("verification failed").is_ok())
//! # }
//! ```
//!
//! ### Verifiable Credentials
//!
//! Verifiable Credential are much more complex as they require interpreting
//! the input claims and proofs, such as Data-Integrity proofs as Linked-Data
//! using JSON-LD. This operation is highly configurable. SSI provide
//! functions exposing various levels of implementation details that you can
//! tweak as needed. The simplest of them is [`any_credential_from_json_str`]
//! that will simply load a VC from a string, assuming it is signed using
//! any Data-Integrity proof supported by SSI.
//!
//! [`any_credential_from_json_str`]: ssi_vc::v1::data_integrity::any_credential_from_json_str
//!
//! ```
//! # use ssi_dids::example::ExampleDIDResolver;
//! # fn main() {
//! # std::thread::Builder::new().stack_size(16 * 1024 * 1024).spawn(|| async_std::task::block_on(async {
//! use ssi::prelude::*;
//!
//! let vc = ssi::claims::vc::v1::data_integrity::any_credential_from_json_str(
//!   &std::fs::read_to_string("examples/files/vc.jsonld")
//!   .expect("unable to load VC")
//! ).expect("invalid VC");
//!
//! // Setup a verification method resolver, in charge of retrieving the
//! // public key used to sign the JWT.
//! let vm_resolver = ExampleDIDResolver::default().into_vm_resolver();
//!
//! // Setup the verification parameters.
//! let params = VerificationParameters::from_resolver(vm_resolver);
//!
//! assert!(vc.verify(&params).await.expect("verification failed").is_ok());
//! # })).unwrap().join().unwrap();
//! # }
//! ```
//!
//! ## Signing with a remote key
//!
//! Issuance uses a provider implementing [`Signer`] and [`MessageSigner`].
//! The provider resolves a public verification method to a remote key reference
//! and asks the KMS to sign the prepared bytes. Private key material stays in
//! the KMS. Applications must supply this provider; this crate does not create
//! or load a local signing key. Public signed VC and JWT fixtures remain in
//! `examples/files` for verification examples.
//!
//! [`Signer`]: ssi_verification_methods::Signer
//! [`MessageSigner`]: ssi_verification_methods::MessageSigner
//!//! # Data-Models
//!
//! The examples above are using the VC data-model 1.1, but you ssi also has support for:
//! - [`VC data-model 2.0`]
//! - [`A wrapper type to accept both`]
//!
//! [`VC data-model 2.0`]: ssi_vc::v2
//! [`A wrapper type to accept both`]: ssi_vc::syntax::AnySpecializedJsonCredential
//!
//! # Features
#![doc = document_features::document_features!()]
#![cfg_attr(docsrs, feature(doc_auto_cfg), feature(doc_cfg))]

/// XSD types.
#[doc(inline)]
pub use xsd_types as xsd;

/// Collection of common names defined by SSI.
pub mod prelude;

// Re-export core functions and types.
#[doc(hidden)]
pub use ssi_core::*;

/// Cryptography.
#[doc(inline)]
pub use ssi_crypto as crypto;

/// JSON Web Key (JWK).
///
/// See: <https://www.rfc-editor.org/rfc/rfc7517>
#[doc(inline)]
pub use ssi_jwk as jwk;

/// JSON Web Key (JWK).
#[doc(inline)]
pub use jwk::JWK;

/// RDF utilities.
#[doc(inline)]
pub use ssi_rdf as rdf;

/// JSON-LD utilities.
#[doc(inline)]
pub use ssi_json_ld as json_ld;

/// W3C's Security Vocabulary.
#[doc(inline)]
pub use ssi_security as security;

/// Verifiable Claims.
///
/// Includes Verifiable Credentials and Data-Integrity Proofs.
#[doc(inline)]
pub use ssi_claims as claims;

/// Claims status.
#[doc(inline)]
pub use ssi_status as status;

/// Default verification parameters type.
///
/// This type can be used as parameters of the
/// [`claims::VerifiableClaims::verify`] function for most claims and signature
/// types. It provides sensible defaults for common parameters:
///   - A DID resolver with support for various DID methods,
///   - A JSON-LD document loader recognizing popular JSON-LD contexts,
///   - the current date and time.
pub type DefaultVerificationParameters = claims::VerificationParameters<
    dids::VerificationMethodDIDResolver<dids::AnyDidMethod, verification_methods::AnyMethod>,
>;

/// Verification Methods.
#[doc(inline)]
pub use ssi_verification_methods as verification_methods;

/// Chain Agnostic Improvement Proposals (CAIPs).
///
/// See: <https://chainagnostic.org/>
#[doc(inline)]
pub use ssi_caips as caips;

/// Decentralized Identifiers (DIDs).
///
/// See: <https://www.w3.org/TR/did-core/>
#[doc(inline)]
pub use ssi_dids as dids;

/// Ethereum Typed Structured Data Hashing and Signing (EIP-712).
///
/// See: <https://eips.ethereum.org/EIPS/eip-712>
#[doc(inline)]
pub use ssi_eip712 as eip712;

/// User Controlled Authorization Network (UCAN).
///
/// See: <https://github.com/ucan-wg/spec>
#[doc(inline)]
pub use ssi_ucan as ucan;

/// Authorization Capabilities for Linked Data (ZCAP-LD).
///
/// See: <https://w3c-ccg.github.io/zcap-spec/>
#[doc(inline)]
pub use ssi_zcap_ld as zcap_ld;

/// Multicodec.
///
/// See: <https://github.com/multiformats/multicodec>
#[doc(inline)]
pub use ssi_multicodec as multicodec;

/// Secure Shell utilities.
#[doc(inline)]
pub use ssi_ssh as ssh;

/// BBS cryptoscheme.
#[cfg(feature = "bbs")]
#[doc(inline)]
pub use ssi_bbs as bbs;
