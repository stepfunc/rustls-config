use std::path::Path;
use std::sync::Arc;

use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};
use rustls::client::danger::HandshakeSignatureValid;
use rustls::server::WebPkiClientVerifier;
use rustls::pki_types::{CertificateDer, UnixTime};

use crate::name::NameVerifier;
use crate::{Error, MinProtocolVersion};

/// Create a client configuration based on a verifier that allows self-signed certificates
pub fn self_signed(
    min_version: MinProtocolVersion,
    peer_cert_path: &Path,
    local_cert_path: &Path,
    private_key_path: &Path,
    private_key_password: Option<&str>,
) -> Result<rustls::ServerConfig, Error> {
    let peer_cert = crate::read_one_cert(peer_cert_path)?;
    let local_cert = crate::read_one_cert(local_cert_path)?;
    let private_key = crate::read_private_key(private_key_path, private_key_password)?;
    let verifier = crate::self_signed::SelfSignedVerifier::create(peer_cert)?;

    let config = build_config(
        min_version,
        vec![local_cert],
        private_key,
        Arc::new(verifier),
    )?;

    Ok(config)
}

/// Create a client configuration based on a chain verifier with custom name verification
pub fn authority(
    min_version: MinProtocolVersion,
    name_verifier: NameVerifier,
    peer_cert_path: &Path,
    local_cert_path: &Path,
    private_key_path: &Path,
    private_key_password: Option<&str>,
) -> Result<rustls::ServerConfig, Error> {
    let peer_certs = crate::read_certificates(peer_cert_path)?;
    let local_certs = crate::read_certificates(local_cert_path)?;
    let private_key = crate::read_private_key(private_key_path, private_key_password)?;

    let mut roots = rustls::RootCertStore::empty();
    for cert in peer_certs.into_iter() {
        roots.add(cert)?;
    }

    let verifier = ClientCertVerifier::new(roots, name_verifier);

    let config = build_config(min_version, local_certs, private_key, Arc::new(verifier))?;

    Ok(config)
}

fn build_config(
    min_tls_version: MinProtocolVersion,
    local_certs: Vec<CertificateDer<'static>>,
    private_key: rustls::pki_types::PrivateKeyDer<'static>,
    verifier: Arc<dyn rustls::server::danger::ClientCertVerifier>,
) -> Result<rustls::ServerConfig, rustls::Error> {
    let config = rustls::ServerConfig::builder()
        //.with_protocol_versions(min_tls_version.versions())? TODO - set protocol versions
        .with_client_cert_verifier(verifier)
        .with_single_cert(local_certs, private_key)?;

    Ok(config)
}

/// Verifier used by the server to check the client's certificate chain
///
/// This verifier is similar to the default verifier in rustls as it
/// uses webpki for the heavy lifting to verify the chain.
///
/// It can also verify the name in the server cert from the Common Name as well.
#[derive(Debug)]
struct ClientCertVerifier {
    inner: Arc<dyn rustls::server::danger::ClientCertVerifier>,
    verifier: NameVerifier,
}

impl ClientCertVerifier {
    /// Create the verifier from the root store and a ['crate::NameVerifier`]
    fn new(roots: rustls::RootCertStore, verifier: NameVerifier) -> Self {
        // TODO - remove the unwrap and bubble up error?
        let inner = WebPkiClientVerifier::builder(Arc::new(roots)).build().unwrap();
        Self { inner, verifier }
    }
}

impl rustls::server::danger::ClientCertVerifier for ClientCertVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.inner.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        self.inner
            .verify_client_cert(end_entity, intermediates, now)?;

        self.verifier.verify(end_entity)?;

        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        todo!()
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        todo!()
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        todo!()
    }
}
