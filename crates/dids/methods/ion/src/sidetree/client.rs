use iref::UriBuf;
use ssi_dids_core::{
    resolution::{self, DIDMethodResolver},
    DIDMethod,
};

use super::{HTTPSidetreeDIDResolver, Sidetree};

#[derive(Debug, thiserror::Error)]
#[error("missing Sidetree REST API endpoint")]
pub struct MissingSidetreeApiEndpoint;

/// Sidetree DID Method client implementation
#[derive(Default, Clone)]
pub struct SidetreeClient<S: Sidetree> {
    pub resolver: Option<HTTPSidetreeDIDResolver<S>>,
    pub endpoint: Option<UriBuf>,
}

impl<S: Sidetree> SidetreeClient<S> {
    pub fn new(api_url_opt: Option<UriBuf>) -> Self {
        let resolver_opt = api_url_opt
            .as_deref()
            .map(|url| HTTPSidetreeDIDResolver::new(url));
        Self {
            endpoint: api_url_opt,
            resolver: resolver_opt,
        }
    }
}

impl<S: Sidetree> DIDMethod for SidetreeClient<S> {
    const DID_METHOD_NAME: &'static str = S::METHOD;
}

impl<S: Sidetree> DIDMethodResolver for SidetreeClient<S> {
    async fn resolve_method_representation<'a>(
        &'a self,
        method_specific_id: &'a str,
        options: resolution::Options,
    ) -> Result<resolution::Output<Vec<u8>>, resolution::Error> {
        match &self.resolver {
            Some(res) => {
                res.resolve_method_representation(method_specific_id, options)
                    .await
            }
            None => Err(resolution::Error::internal(MissingSidetreeApiEndpoint)),
        }
    }
}
