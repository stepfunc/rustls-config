use rustls::client::danger::HandshakeSignatureValid;
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::WebPkiClientVerifier;
use rustls::Error::General;
use rustls::{CertificateError, DigitallySignedStruct, DistinguishedName, SignatureScheme};
use std::path::Path;
use std::sync::Arc;
use webpki::types::ServerName;

use crate::{ClientNameVerification, Error, ProtocolVersions};

/// Create a client configuration based on a verifier that allows self-signed certificates
pub fn self_signed(
    versions: ProtocolVersions,
    peer_cert_path: &Path,
    local_cert_path: &Path,
    private_key_path: &Path,
    private_key_password: Option<&str>,
) -> Result<rustls::ServerConfig, Error> {
    let peer_cert = crate::pem::read_one_cert(peer_cert_path)?;
    let local_cert = crate::pem::read_one_cert(local_cert_path)?;
    let private_key = crate::pem::read_private_key(private_key_path, private_key_password)?;
    let verifier = crate::self_signed::SelfSignedVerifier::create(peer_cert)?;

    let config = rustls::ServerConfig::builder_with_protocol_versions(versions.versions())
        .with_client_cert_verifier(Arc::new(verifier))
        .with_single_cert(vec![local_cert], private_key)?;

    Ok(config)
}

/// Create a client configuration based on a chain verifier with custom name verification
pub fn authority(
    versions: ProtocolVersions,
    name_verification: ClientNameVerification,
    ca_cert_path: &Path,
    local_cert_chain_path: &Path,
    private_key_path: &Path,
    private_key_password: Option<&str>,
) -> Result<rustls::ServerConfig, Error> {
    let peer_certs = crate::pem::read_certificates(ca_cert_path)?;
    let local_cert_chain = crate::pem::read_certificates(local_cert_chain_path)?;
    let private_key = crate::pem::read_private_key(private_key_path, private_key_password)?;

    // create the base verifier
    let verifier = {
        let mut roots = rustls::RootCertStore::empty();
        for cert in peer_certs.into_iter() {
            roots.add(cert)?;
        }
        WebPkiClientVerifier::builder(roots.into()).build()?
    };

    let verifier = ClientNameVerifier {
        base_verifier: verifier,
        verification: name_verification,
    };

    let config = rustls::ServerConfig::builder_with_protocol_versions(versions.versions())
        .with_client_cert_verifier(Arc::new(verifier))
        .with_single_cert(local_cert_chain, private_key)?;

    Ok(config)
}

#[derive(Debug)]
struct ClientNameVerifier {
    base_verifier: Arc<dyn ClientCertVerifier>,
    verification: ClientNameVerification,
}

impl ClientNameVerifier {
    fn verify_client_name(
        &self,
        cert: &CertificateDer<'_>,
        name: &ServerName<'_>,
        use_common_name: bool,
    ) -> Result<ClientCertVerified, rustls::Error> {
        // first we try web-PKI to see if its in the SAN
        let end_entity_cert =
            webpki::EndEntityCert::try_from(cert).map_err(|err| General(err.to_string()))?;

        match end_entity_cert.verify_is_valid_for_subject_name(name) {
            Ok(()) => Ok(ClientCertVerified::assertion()),
            Err(webpki::Error::CertNotValidForName) => {
                if use_common_name {
                    crate::common_name::verify_name_from_subject(cert, name)?;
                    Ok(ClientCertVerified::assertion())
                } else {
                    Err(rustls::Error::InvalidCertificate(
                        CertificateError::NotValidForName,
                    ))
                }
            }
            Err(err) => Err(General(err.to_string())),
        }
    }
}

impl ClientCertVerifier for ClientNameVerifier {
    fn offer_client_auth(&self) -> bool {
        self.base_verifier.offer_client_auth()
    }

    fn client_auth_mandatory(&self) -> bool {
        self.base_verifier.client_auth_mandatory()
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.base_verifier.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer,
        intermediates: &[CertificateDer],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let verified = self
            .base_verifier
            .verify_client_cert(end_entity, intermediates, now)?;

        let res = match &self.verification {
            ClientNameVerification::None => {
                // we're done
                Ok(verified)
            }
            ClientNameVerification::SanExtOnly(x) => self.verify_client_name(end_entity, x, false),
            ClientNameVerification::SanOrCommonName(x) => {
                self.verify_client_name(end_entity, x, true)
            }
        };

        println!("client result: {res:?}");

        res
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.base_verifier
            .verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.base_verifier
            .verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.base_verifier.supported_verify_schemes()
    }
}
