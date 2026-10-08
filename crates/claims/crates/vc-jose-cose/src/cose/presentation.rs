use super::CoseDecodeError;
use base64::Engine;
use serde::{de::DeserializeOwned, Serialize};
use ssi_claims_core::{ClaimsValidity, SignatureError, ValidateClaims};
use ssi_cose::{CosePayload, CoseSign1Bytes, CoseSigner, DecodedCoseSign1, ValidateCoseHeader};
use ssi_json_ld::{iref::Uri, syntax::Context};
use ssi_vc::{
    enveloped::{EnvelopedVerifiableCredential, EnvelopedVerifiablePresentation},
    v2::{syntax::JsonPresentation, Presentation, PresentationTypes},
    MaybeIdentified,
};
use std::borrow::Cow;

/// Payload of a COSE-secured Verifiable Presentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CoseVp<T = JsonPresentation<EnvelopedVerifiableCredential>>(pub T);

impl<T: Serialize> CosePayload for CoseVp<T> {
    fn typ(&self) -> Option<ssi_cose::CosePayloadType> {
        Some(ssi_cose::CosePayloadType::Text(
            "application/vp-ld+cose".to_owned(),
        ))
    }

    fn content_type(&self) -> Option<ssi_cose::ContentType> {
        Some(ssi_cose::ContentType::Text("application/vp".to_owned()))
    }

    fn payload_bytes(&'_ self) -> Cow<'_, [u8]> {
        Cow::Owned(serde_json::to_vec(&self.0).unwrap())
    }
}

impl<E, T> ValidateCoseHeader<E> for CoseVp<T> {
    fn validate_cose_headers(
        &self,
        _params: &E,
        _protected: &ssi_cose::ProtectedHeader,
        _unprotected: &ssi_cose::Header,
    ) -> ClaimsValidity {
        Ok(())
    }
}

impl<T: Serialize> CoseVp<T> {
    /// Sign a COSE VP into an enveloped verifiable presentation.
    pub async fn sign_into_enveloped(
        &self,
        signer: &impl CoseSigner,
    ) -> Result<EnvelopedVerifiablePresentation, SignatureError> {
        let cose = CosePayload::sign(self, signer, true).await?;
        let base64_cose = base64::prelude::BASE64_STANDARD.encode(&cose);
        Ok(EnvelopedVerifiablePresentation {
            context: Context::iri_ref(ssi_vc::v2::CREDENTIALS_V2_CONTEXT_IRI.to_owned().into()),
            id: format!("data:application/vp-ld+cose;base64,{base64_cose}")
                .parse()
                .unwrap(),
        })
    }
}

impl<T: DeserializeOwned> CoseVp<T> {
    /// Decode a JOSE VP.
    pub fn decode(
        cose: &CoseSign1Bytes,
        tagged: bool,
    ) -> Result<DecodedCoseSign1<Self>, CoseDecodeError> {
        cose.decode(tagged)?
            .try_map(|_, payload| serde_json::from_slice(payload).map(Self))
            .map_err(Into::into)
    }
}

impl CoseVp {
    /// Decode a JOSE VP with an arbitrary presentation type.
    pub fn decode_any(
        jws: &CoseSign1Bytes,
        tagged: bool,
    ) -> Result<DecodedCoseSign1<Self>, CoseDecodeError> {
        Self::decode(jws, tagged)
    }
}

impl<T: MaybeIdentified> MaybeIdentified for CoseVp<T> {
    fn id(&self) -> Option<&ssi_json_ld::iref::Uri> {
        self.0.id()
    }
}

impl<T: Presentation> Presentation for CoseVp<T> {
    type Credential = T::Credential;
    type Holder = T::Holder;

    fn id(&self) -> Option<&Uri> {
        Presentation::id(&self.0)
    }

    fn additional_types(&self) -> &[String] {
        self.0.additional_types()
    }

    fn types(&'_ self) -> PresentationTypes<'_> {
        self.0.types()
    }

    fn verifiable_credentials(&self) -> &[Self::Credential] {
        self.0.verifiable_credentials()
    }

    fn holders(&self) -> &[Self::Holder] {
        self.0.holders()
    }
}

impl<E, P, T: ValidateClaims<E, P>> ValidateClaims<E, P> for CoseVp<T> {
    fn validate_claims(&self, environment: &E, proof: &P) -> ClaimsValidity {
        self.0.validate_claims(environment, proof)
    }
}
