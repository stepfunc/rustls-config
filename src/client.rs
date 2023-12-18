use std::path::Path;
use std::sync::Arc;
use rustls::client::danger::HandshakeSignatureValid;
use rustls::{DigitallySignedStruct, SignatureScheme};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime, TrustAnchor};


use crate::name::NameVerifier;
use crate::{Error, MinProtocolVersion};

/// Create a client configuration based on a verifier that allows self-signed certificates
pub fn self_signed(
    min_version: MinProtocolVersion,
    peer_cert_path: &Path,
    local_cert_path: &Path,
    private_key_path: &Path,
    private_key_password: Option<&str>,
) -> Result<rustls::ClientConfig, Error> {
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
) -> Result<rustls::ClientConfig, Error> {
    let peer_certs = crate::read_certificates(peer_cert_path)?;
    let local_certs = crate::read_certificates(local_cert_path)?;
    let private_key = crate::read_private_key(private_key_path, private_key_password)?;

    let verifier = ServerCertVerifier::new(peer_certs, name_verifier)?;

    let config = build_config(min_version, local_certs, private_key, Arc::new(verifier))?;

    Ok(config)
}

fn build_config(
    _min_version: MinProtocolVersion,
    local_certs: Vec<CertificateDer<'static>>,
    private_key: rustls::pki_types::PrivateKeyDer<'static>,
    verifier: Arc<dyn rustls::client::danger::ServerCertVerifier>,
) -> Result<rustls::ClientConfig, rustls::Error> {
    let config = rustls::ClientConfig::builder()
        //.with_protocol_versions(4) // TODO configure protocol versions?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(local_certs, private_key)?;

    Ok(config)
}

/// Verifier used by the client to check the server's certificate chain
///
/// This verifier is similar to the default verifier in rustls as it
/// uses webpki for the heavy lifting to verify the chain.
///
/// It can also verify the name in the server cert from the Common Name as well.
#[derive(Debug)]
struct ServerCertVerifier {
    roots: Vec<TrustAnchor<'static>>,
    name: NameVerifier,
}

impl ServerCertVerifier {
    /// Create the verifier from some root anchors and a name verifier
    fn new(roots: Vec<CertificateDer<'static>>, name: NameVerifier) -> Result<Self, rustls::Error> {
        let mut anchors = Vec::new();

        for root in roots {
            let anchor = webpki::anchor_from_trusted_cert(&root).map_err(crate::pki_error)?;
            anchors.push(anchor.to_owned());
        }

        //let roots = Self::trust_anchors(anchors).map_err(crate::pki_error)?;
        Ok(Self { roots: anchors, name })
    }
}

impl rustls::client::danger::ServerCertVerifier for ServerCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {

        // Note: this code is taken from `WebPkiVerifier` in the `verifier` module of `rustls`

        /*
        // Verify trust chain using webpki
        let (cert, chain, trustroots) = prepare(end_entity, intermediates, &self.roots)?;
        let webpki_now =
            webpki::Time::try_from(now).map_err(|_| rustls::Error::FailedToGetCurrentTime)?;

        cert.verify_for_usage(
            SUPPORTED_SIG_ALGS,
            &trustroots,
            &chain,
            webpki_now,
            KeyUsage::server_auth(),
            &[]
        ).map_err(super::pki_error)?;

        // Check DNS name (including in the Common Name)
        self.name.verify(end_entity)?;
        */

        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &rustls::crypto::ring::default_provider().signature_verification_algorithms)
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &rustls::crypto::ring::default_provider().signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes()
    }
}

/*
type SignatureAlgorithms = &'static [&'static webpki::SignatureAlgorithm];

static SUPPORTED_SIG_ALGS: SignatureAlgorithms = &[
    &webpki::ECDSA_P256_SHA256,
    &webpki::ECDSA_P256_SHA384,
    &webpki::ECDSA_P384_SHA256,
    &webpki::ECDSA_P384_SHA384,
    &webpki::ED25519,
    &webpki::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
    &webpki::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
    &webpki::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
    &webpki::RSA_PKCS1_2048_8192_SHA256,
    &webpki::RSA_PKCS1_2048_8192_SHA384,
    &webpki::RSA_PKCS1_2048_8192_SHA512,
    &webpki::RSA_PKCS1_3072_8192_SHA384,
];

 */

/*
// TODO: if `rustls::OwnedTrustAnchor::to_trust_anchor` was public,
// we wouldn't need to duplicate this.
#[derive(Debug, Clone)]
struct OwnedTrustAnchor {
    subject: Vec<u8>,
    spki: Vec<u8>,
    name_constraints: Option<Vec<u8>>,
}

impl OwnedTrustAnchor {
    /// Get a `webpki::TrustAnchor` by borrowing the owned elements.
    fn to_trust_anchor(&self) -> rustls::pki_types::TrustAnchor {

        rustls::pki_types::TrustAnchor {
            subject: &self.subject,
            name_constraints: self.name_constraints.as_deref(),
            subject_public_key_info: &self.spki,
        }
    }

    fn try_from_cert_der(cert_der: &[u8]) -> Result<Self, webpki::Error> {
        let trust_anchor = webpki::TrustAnchor::try_from_cert_der(cert_der)?;

        Ok(Self {
            subject: trust_anchor.subject.to_owned(),
            spki: trust_anchor.spki.to_owned(),
            name_constraints: trust_anchor.name_constraints.map(|x| x.to_owned()),
        })
    }
}


type CertChainAndRoots<'a, 'b> = (
    webpki::EndEntityCert<'a>,
    Vec<&'a [u8]>,
    Vec<rustls::pki_types::TrustAnchor<'b>>,
);

fn prepare<'a, 'b>(
    end_entity: &'a rustls::Certificate,
    intermediates: &'a [rustls::Certificate],
    roots: &'b [OwnedTrustAnchor],
) -> Result<CertChainAndRoots<'a, 'b>, rustls::Error> {
    // EE cert must appear first.
    let cert = webpki::EndEntityCert::try_from(end_entity.0.as_ref()).map_err(super::pki_error)?;

    let intermediates: Vec<&'a [u8]> = intermediates.iter().map(|cert| cert.0.as_ref()).collect();

    let roots: Vec<webpki::TrustAnchor> = roots
        .iter()
        .map(OwnedTrustAnchor::to_trust_anchor)
        .collect();

    Ok((cert, intermediates, roots))
}
*/