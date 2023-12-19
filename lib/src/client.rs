use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, RootCertStore, SignatureScheme};
use std::path::Path;
use std::sync::Arc;

use crate::name::ServerNameVerification;
use crate::{Error, MinProtocolVersion};

/// Create a client configuration based on a verifier that allows self-signed certificates
pub fn self_signed(
    min_version: MinProtocolVersion,
    peer_cert_path: &Path,
    local_cert_path: &Path,
    private_key_path: &Path,
    private_key_password: Option<&str>,
) -> Result<rustls::ClientConfig, Error> {
    let peer_cert = crate::pem::read_one_cert(peer_cert_path)?;
    let client_cert = crate::pem::read_one_cert(local_cert_path)?;
    let private_key = crate::pem::read_private_key(private_key_path, private_key_password)?;
    let verifier = crate::self_signed::SelfSignedVerifier::create(peer_cert)?;

    let config = rustls::ClientConfig::builder_with_protocol_versions(min_version.versions())
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_client_auth_cert(vec![client_cert], private_key)?;

    Ok(config)
}

/// Create a client configuration based on a chain verifier with custom name verification
pub fn authority(
    min_version: MinProtocolVersion,
    name_verification: ServerNameVerification,
    ca_cert_path: &Path,
    local_cert_path: &Path,
    private_key_path: &Path,
    private_key_password: Option<&str>,
) -> Result<rustls::ClientConfig, Error> {
    let ca_certs = crate::pem::read_certificates(ca_cert_path)?;
    let cert_chain = crate::pem::read_certificates(local_cert_path)?;
    let private_key = crate::pem::read_private_key(private_key_path, private_key_password)?;

    let mut root_cert_store = RootCertStore::empty();
    for cert in ca_certs {
        root_cert_store.add(cert)?;
    }

    match name_verification {
        ServerNameVerification::DisableNameVerification => {
            // wrap the default verifier in one that will trap the name verification errors
            let verifier = DisableNameVerification(
                WebPkiServerVerifier::builder(Arc::new(root_cert_store)).build()?,
            );
            let config =
                rustls::ClientConfig::builder_with_protocol_versions(min_version.versions())
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(verifier))
                    .with_client_auth_cert(cert_chain, private_key)?;

            Ok(config)
        }
        ServerNameVerification::Verify => {
            // we just use the standard verifier!
            let config =
                rustls::ClientConfig::builder_with_protocol_versions(min_version.versions())
                    .with_root_certificates(root_cert_store)
                    .with_client_auth_cert(cert_chain, private_key)?;
            Ok(config)
        }
    }
}

#[derive(Debug)]
struct DisableNameVerification(Arc<dyn ServerCertVerifier>);

impl ServerCertVerifier for DisableNameVerification {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let res =
            self.0
                .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now);

        if let Err(rustls::Error::InvalidCertificate(rustls::CertificateError::NotValidForName)) =
            res
        {
            // Name verification is the LAST step inside WebPkiServerVerifier so we can safely trap it and then
            // just ignore this error
            return Ok(ServerCertVerified::assertion());
        }

        res
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_verify_schemes()
    }
}
