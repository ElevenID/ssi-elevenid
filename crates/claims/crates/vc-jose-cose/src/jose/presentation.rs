use super::JoseDecodeError;
use serde::{de::DeserializeOwned, Serialize};
use ssi_claims_core::{ClaimsValidity, SignatureError, ValidateClaims};
use ssi_json_ld::{iref::Uri, syntax::Context};
use ssi_jws::{DecodedJws, JwsPayload, JwsSigner, JwsSlice, ValidateJwsHeader};
use ssi_vc::{
    enveloped::{EnvelopedVerifiableCredential, EnvelopedVerifiablePresentation},
    v2::{syntax::JsonPresentation, Presentation, PresentationTypes},
    MaybeIdentified,
};
use std::borrow::Cow;

/// Payload of a JWS-secured Verifiable Presentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct JoseVp<T = JsonPresentation<EnvelopedVerifiableCredential>>(pub T);

impl<T: Serialize> JwsPayload for JoseVp<T> {
    fn typ(&self) -> Option<&str> {
        Some("vp-ld+jwt")
    }

    fn cty(&self) -> Option<&str> {
        Some("vp")
    }

    fn payload_bytes(&'_ self) -> Cow<'_, [u8]> {
        Cow::Owned(serde_json::to_vec(&self.0).unwrap())
    }
}

impl<E, T> ValidateJwsHeader<E> for JoseVp<T> {
    fn validate_jws_header(&self, _env: &E, _header: &ssi_jws::Header) -> ClaimsValidity {
        // There are no formal obligations about `typ` and `cty`.
        // It SHOULD be `vp-ld+jwt` and `vp`, but it does not MUST.
        Ok(())
    }
}

impl<T: Serialize> JoseVp<T> {
    /// Sign a JOSE VC into an enveloped verifiable presentation.
    pub async fn sign_into_enveloped(
        &self,
        signer: &impl JwsSigner,
    ) -> Result<EnvelopedVerifiablePresentation, SignatureError> {
        let jws = JwsPayload::sign(self, signer).await?;
        Ok(EnvelopedVerifiablePresentation {
            context: Context::iri_ref(ssi_vc::v2::CREDENTIALS_V2_CONTEXT_IRI.to_owned().into()),
            id: format!("data:application/vp-ld+jwt,{jws}").parse().unwrap(),
        })
    }
}

impl<T: DeserializeOwned> JoseVp<T> {
    /// Decode a JOSE VP.
    pub fn decode(jws: &'_ JwsSlice) -> Result<DecodedJws<'_, Self>, JoseDecodeError> {
        jws.decode()?
            .try_map(|payload| serde_json::from_slice(&payload).map(Self))
            .map_err(Into::into)
    }
}

impl JoseVp {
    /// Decode a JOSE VP with an arbitrary presentation type.
    pub fn decode_any(jws: &'_ JwsSlice) -> Result<DecodedJws<'_, Self>, JoseDecodeError> {
        Self::decode(jws)
    }
}

impl<T: MaybeIdentified> MaybeIdentified for JoseVp<T> {
    fn id(&self) -> Option<&ssi_json_ld::iref::Uri> {
        self.0.id()
    }
}

impl<T: Presentation> Presentation for JoseVp<T> {
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

impl<E, P, T: ValidateClaims<E, P>> ValidateClaims<E, P> for JoseVp<T> {
    fn validate_claims(&self, environment: &E, proof: &P) -> ClaimsValidity {
        self.0.validate_claims(environment, proof)
    }
}
