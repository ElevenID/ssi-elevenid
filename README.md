[![](https://img.shields.io/github/actions/workflow/status/spruceid/ssi/build.yml?branch=main)](https://github.com/spruceid/ssi/actions?query=workflow%3Aci+branch%3Amain)
[![](https://img.shields.io/badge/Rust-v1.66.0-orange)](https://www.rust-lang.org/)
[![](https://img.shields.io/badge/License-Apache--2.0-green)](https://github.com/spruceid/didkit/blob/main/LICENSE)
[![](https://img.shields.io/twitter/follow/spruceid?label=Follow&style=social)](https://twitter.com/spruceid)

# SSI

<!-- cargo-rdme start -->

The SSI library provides a simple and modular API to sign and verify claims
exchanged between applications using
[Decentralized Identifiers (DIDs)][dids]. SSI is embedded in the
cross-platform [`didkit`][didkit] library as a core dependency.

This library supports the two main families of verifiable claims:
- [JSON Web Tokens (JWT)][jwt] where claims are encoded into JSON and
  secured using [JSON Web Signatures][jws]; and
- [W3C's Verifiable Credentials (VCs)][vc-data-model], a
  [Linked-Data][linked-data]-based model where claims (VCs) can be
  interpreted as RDF datasets. VC supports multiple signature formats
  provided by SSI:
  - VC over JWT ([JWT-VC][jwt-vc]), a restricted form of JWT following the
    VC data model; or
  - [Data Integrity][data-integrity], encoding the claims and their proof
    in the same JSON-LD document using a wide variety of
    [*cryptographic suites*][cryptosuite].

[dids]: <https://www.w3.org/TR/did-core/>
[didkit]: <https://github.com/spruceid/didkit>
[vc-data-model]: <https://www.w3.org/TR/vc-data-model/>
[linked-data]: <https://www.w3.org/DesignIssues/LinkedData.html>
[jwt]: <https://www.rfc-editor.org/rfc/rfc7519>
[jws]: <https://www.rfc-editor.org/rfc/rfc7515>
[jwt-vc]: <https://www.w3.org/TR/vc-data-model/#json-web-token>
[data-integrity]: <https://www.w3.org/TR/vc-data-integrity/>
[cryptosuite]: <https://www.w3.org/TR/vc-data-integrity/#dfn-cryptosuite>

## Basic Usage

SSI provides various functions to parse, verify, create and sign various
kind of claims. This section shows how to use these functions in combination
with JSON Web Signatures (or Tokens) and Verifiable Credentials.

### Verification

The simplest type of claim to load and verify is probably JSON Web
Signatures (JWSs), often use to encode JSON Web Tokens (JWTs). To represent
such claims SSI provides the `JwsBuf` type representing a JWS
in compact textual form. One can load a JWS using [`new`] and verify
it using [`verify`].

[`new`]: ssi_jws::JwsBuf::new
[`verify`]: ssi_jws::JwsSlice::verify

```rust
use ssi::prelude::*;

// Load a JWT from the file system.
let jwt = JwsBuf::new(
  std::fs::read_to_string("examples/files/claims.jwt")
  .expect("unable to load JWT")
).expect("invalid JWS");

// Setup a verification method resolver, in charge of retrieving the
// public key used to sign the JWT.
// Here we use the example `ExampleDIDResolver` resolver, enabled with the
// `example` feature.
let vm_resolver = ExampleDIDResolver::default().into_vm_resolver::<AnyJwkMethod>();

// Setup the verification parameters.
let params = VerificationParameters::from_resolver(vm_resolver);

// Verify the JWT.
assert!(jwt.verify(&params).await.expect("verification failed").is_ok())
```

#### Verifiable Credentials

Verifiable Credential are much more complex as they require interpreting
the input claims and proofs, such as Data-Integrity proofs as Linked-Data
using JSON-LD. This operation is highly configurable. SSI provide
functions exposing various levels of implementation details that you can
tweak as needed. The simplest of them is [`any_credential_from_json_str`]
that will simply load a VC from a string, assuming it is signed using
any Data-Integrity proof supported by SSI.

[`any_credential_from_json_str`]: ssi_vc::v1::data_integrity::any_credential_from_json_str

```rust
use ssi::prelude::*;

let vc = ssi::claims::vc::v1::data_integrity::any_credential_from_json_str(
  &std::fs::read_to_string("examples/files/vc.jsonld")
  .expect("unable to load VC")
).expect("invalid VC");

// Setup a verification method resolver, in charge of retrieving the
// public key used to sign the JWT.
let vm_resolver = ExampleDIDResolver::default().into_vm_resolver();

// Setup the verification parameters.
let params = VerificationParameters::from_resolver(vm_resolver);

assert!(vc.verify(&params).await.expect("verification failed").is_ok());
```

### Signing with a remote key

Issuance uses a provider implementing `Signer` and `MessageSigner`. The
provider maps a public verification method to a remote key reference and asks
the KMS to sign the prepared bytes. Private key material stays in the KMS.
Applications must supply this provider; this fork does not generate or load
local signing keys. Public signed VC and JWT fixtures remain in
`examples/files` for the verification examples.
## Data-Models

The examples above are using the VC data-model 1.1, but you ssi also has support for:
- [`VC data-model 2.0`]
- [`A wrapper type to accept both`]

[`VC data-model 2.0`]: ssi_vc::v2
[`A wrapper type to accept both`]: ssi_vc::syntax::AnySpecializedJsonCredential

## Features

<!-- cargo-rdme end -->

## Security Audits

ssi has undergone the following security reviews:
- [March 14th, 2022 - Trail of Bits](https://github.com/trailofbits/publications/blob/master/reviews/SpruceID.pdf) | [Summary of Findings](https://blog.spruceid.com/spruce-completes-first-security-audit-from-trail-of-bits/)

## Testing

Testing SSI requires the RDF canonicalization test suite, which is embedded as
a git submodule.

```sh
$ git submodule update --init
$ cargo test --workspace
```
