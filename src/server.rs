use rustls::client::danger::HandshakeSignatureValid;
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::WebPkiClientVerifier;
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};
use std::path::Path;
use std::sync::Arc;
use webpki::types::ServerName;

use crate::{ClientNameVerification, Error, MinProtocolVersion};

/// Create a client configuration based on a verifier that allows self-signed certificates
pub fn self_signed(
    min_version: MinProtocolVersion,
    peer_cert_path: &Path,
    local_cert_path: &Path,
    private_key_path: &Path,
    private_key_password: Option<&str>,
) -> Result<rustls::ServerConfig, Error> {
    let peer_cert = crate::pem::read_one_cert(peer_cert_path)?;
    let local_cert = crate::pem::read_one_cert(local_cert_path)?;
    let private_key = crate::pem::read_private_key(private_key_path, private_key_password)?;
    let verifier = crate::self_signed::SelfSignedVerifier::create(peer_cert)?;

    let config = rustls::ServerConfig::builder_with_protocol_versions(min_version.versions())
        .with_client_cert_verifier(Arc::new(verifier))
        .with_single_cert(vec![local_cert], private_key)?;

    Ok(config)
}

/// Create a client configuration based on a chain verifier with custom name verification
pub fn authority(
    min_version: MinProtocolVersion,
    name_verification: ClientNameVerification,
    peer_cert_path: &Path,
    local_cert_path: &Path,
    private_key_path: &Path,
    private_key_password: Option<&str>,
) -> Result<rustls::ServerConfig, Error> {
    let peer_certs = crate::pem::read_certificates(peer_cert_path)?;
    let local_cert_chain = crate::pem::read_certificates(local_cert_path)?;
    let private_key = crate::pem::read_private_key(private_key_path, private_key_password)?;

    let mut roots = rustls::RootCertStore::empty();
    for cert in peer_certs.into_iter() {
        roots.add(cert)?;
    }

    let verifier = WebPkiClientVerifier::builder(roots.into()).build()?;

    let verifier = match name_verification {
        // the normal WebPKI client verifier doesn't do any name checking so we can just use it
        ClientNameVerification::None => verifier,

        ClientNameVerification::Verify(name) => {
            let verifier = ClientNameVerifier {
                inner: verifier,
                name,
            };

            Arc::new(verifier)
        }
    };

    let config = rustls::ServerConfig::builder_with_protocol_versions(min_version.versions())
        .with_client_cert_verifier(verifier)
        .with_single_cert(local_cert_chain, private_key)?;

    Ok(config)
}

#[derive(Debug)]
struct ClientNameVerifier {
    inner: Arc<dyn ClientCertVerifier>,
    name: ServerName<'static>,
}

impl ClientCertVerifier for ClientNameVerifier {
    fn offer_client_auth(&self) -> bool {
        self.inner.offer_client_auth()
    }

    fn client_auth_mandatory(&self) -> bool {
        self.inner.client_auth_mandatory()
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.inner.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let res = self
            .inner
            .verify_client_cert(end_entity, intermediates, now)?;

        // now do the additional name checking
        let end_entity_cert = webpki::EndEntityCert::try_from(end_entity)
            .map_err(|err| rustls::Error::General(err.to_string()))?;

        end_entity_cert
            .verify_is_valid_for_subject_name(&self.name)
            .map_err(|err| rustls::Error::General(err.to_string()))?;

        Ok(res)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}
