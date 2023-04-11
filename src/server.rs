use crate::name::NameVerifier;
use rustls::server::AllowAnyAuthenticatedClient;
use rustls::DistinguishedName;

/// Verifier used by the server to check the client's certificate chain
///
/// This verifier is similar to the default verifier in rustls as it
/// uses webpki for the heavy lifting to verify the chain.
///
/// It can also verify the name in the server cert from the Common Name as well.
pub struct ClientCertVerifier {
    inner: AllowAnyAuthenticatedClient,
    verifier: NameVerifier,
}

impl ClientCertVerifier {
    /// Create the verifier from the root store and a ['crate::NameVerifier`]
    pub fn new(roots: rustls::RootCertStore, verifier: NameVerifier) -> Self {
        let inner = AllowAnyAuthenticatedClient::new(roots);
        Self { inner, verifier }
    }
}

impl rustls::server::ClientCertVerifier for ClientCertVerifier {
    fn client_auth_root_subjects(&self) -> &[DistinguishedName] {
        self.inner.client_auth_root_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &rustls::Certificate,
        intermediates: &[rustls::Certificate],
        now: std::time::SystemTime,
    ) -> Result<rustls::server::ClientCertVerified, rustls::Error> {
        self.inner
            .verify_client_cert(end_entity, intermediates, now)?;

        self.verifier.verify(end_entity)?;

        Ok(rustls::server::ClientCertVerified::assertion())
    }
}
