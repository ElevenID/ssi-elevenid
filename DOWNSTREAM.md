# ElevenID downstream status

This repository is a temporary security fork of
[`spruceid/ssi`](https://github.com/spruceid/ssi). ElevenID keeps its patch
small, submits the same change upstream, and retires the fork when a safe
upstream release is available.

Current delta: remove the unused `serde_with 2.3` dependency from `ssi-jwt`
and remove local issuer signing-key generation, private-key import/export,
and JWK-backed signing across the fork, including optional Aleo and BBS
signing helpers.
JWK private parameter structs retain only unit presence markers for rejection;
they cannot hold key bytes. did:ion retains resolution and signed-operation
verification while its local transaction-signing API is removed. Public
verification, cryptographic preparation, and provider-based signer interfaces
remain. Tests for affected verification and DID resolution use signed or
public-only vectors. Product-level KMS custody still requires a coherent Core
pin, remote provider integration, and exact release qualification.

The verification-only test conversion also fixes SD-JWT VP envelope typing:
the VP signing API now returns `EnvelopedVerifiablePresentation`, matching its
documented VP media type.
