use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, Error, RootCertStore, SignatureScheme};
use std::path::Path;
use std::sync::Arc;

use crate::name::ServerNameVerification;
use crate::ProtocolVersions;

/// Create a client configuration based on a verifier that allows self-signed certificates
pub fn self_signed(
    versions: ProtocolVersions,
    peer_cert_path: &Path,
    local_cert_path: &Path,
    private_key_path: &Path,
    private_key_password: Option<&str>,
) -> Result<rustls::ClientConfig, crate::Error> {
    let peer_cert = crate::pem::read_one_cert(peer_cert_path)?;
    let client_cert = crate::pem::read_one_cert(local_cert_path)?;
    let private_key = crate::pem::read_private_key(private_key_path, private_key_password)?;
    let verifier = crate::self_signed::SelfSignedVerifier::create(peer_cert)?;

    let config = rustls::ClientConfig::builder_with_protocol_versions(versions.versions())
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_client_auth_cert(vec![client_cert], private_key)?;

    Ok(config)
}

/// Create a client configuration based on a chain verifier with custom name verification
pub fn authority(
    versions: ProtocolVersions,
    name_verification: ServerNameVerification,
    ca_cert_path: &Path,
    local_cert_path: &Path,
    private_key_path: &Path,
    private_key_password: Option<&str>,
) -> Result<rustls::ClientConfig, crate::Error> {
    let ca_certs = crate::pem::read_certificates(ca_cert_path)?;
    let cert_chain = crate::pem::read_certificates(local_cert_path)?;
    let private_key = crate::pem::read_private_key(private_key_path, private_key_password)?;

    let verifier = {
        let mut root_cert_store = RootCertStore::empty();
        for cert in ca_certs {
            root_cert_store.add(cert)?;
        }
        WebPkiServerVerifier::builder(Arc::new(root_cert_store)).build()?
    };

    let verifier = ModifiedNameVerifier {
        base_verifier: verifier,
        mode: name_verification,
    };

    let config = rustls::ClientConfig::builder_with_protocol_versions(versions.versions())
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_client_auth_cert(cert_chain, private_key)?;

    Ok(config)
}

#[derive(Debug)]
struct ModifiedNameVerifier {
    base_verifier: Arc<dyn ServerCertVerifier>,
    mode: ServerNameVerification,
}

impl ServerCertVerifier for ModifiedNameVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let res = self.base_verifier.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        );

        // Name verification is the LAST step inside WebPkiServerVerifier so we can safely trap it if it fails
        if let Err(Error::InvalidCertificate(CertificateError::NotValidForName)) = res {
            match self.mode {
                ServerNameVerification::SanExtOnly => {}
                ServerNameVerification::SanOrCommonName => {
                    // we have to re-parse w/ rx509 to get the common name
                    crate::common_name::verify_name_from_subject(end_entity, server_name)?;
                    return Ok(ServerCertVerified::assertion());
                }
                ServerNameVerification::DisableNameVerification => {
                    return Ok(ServerCertVerified::assertion())
                }
            }
        }

        res
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.base_verifier
            .verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.base_verifier
            .verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.base_verifier.supported_verify_schemes()
    }
}
