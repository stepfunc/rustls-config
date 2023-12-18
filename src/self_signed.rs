use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified};
use rustls::server::danger::ClientCertVerified;
use rustls::{CertificateError, DigitallySignedStruct, DistinguishedName, Error, SignatureScheme};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use webpki::types::TrustAnchor;
use crate::pki_error;


/// Verifier that can used as a client or server verifier based on a pre-shared peer certificate
#[derive(Debug)]
pub(crate) struct SelfSignedVerifier {
    /// expected certificate
    expected_peer_cert: CertificateDer<'static>,
    /// pre-parsed validity
    validity: rx509::x509::Validity,

    anchor: TrustAnchor<'static>,

    //subjects: Vec<DistinguishedName>,
}

impl SelfSignedVerifier {

    /*
    fn subjects(expected: &CertificateDer) -> Result<Vec<DistinguishedName>, Error> {
        let mut store = RootCertStore::empty();
        store.add(expected.to_owned())?;
        Ok(store
            .roots
            .into_iter()
            .map(|x| x.subject.clone())
            .collect())
    }

     */

    /// Create a verifier specifying the expected peer certificate.
    ///
    /// This method performs a light parsing of the certificate using [rx509](https://crates.io/crates/rx509)
    /// to extract the Validity (not before, not after) time interval for the certificate so that
    /// can be later used during validation. An error is returned if the certificate cannot be parsed.
    pub(crate) fn create(expected: CertificateDer<'static>) -> Result<Self, crate::Error> {
        let parsed = rx509::x509::Certificate::parse(expected.as_ref())?;

        let validity = parsed.tbs_certificate.value.validity;

        let anchor = webpki::anchor_from_trusted_cert(&expected).map_err(pki_error)?.to_owned();

        Ok(Self {
            expected_peer_cert: expected,
            validity,
            anchor
        })
    }

    fn verify_peer(
        &self,
        end_entity: &CertificateDer,
        intermediates: &[CertificateDer],
        now: UnixTime,
    ) -> Result<(), Error> {
        // Check that no intermediate certificates are present
        if !intermediates.is_empty() {
            let msg = format!(
                "client sent {} intermediate certificates, expected none",
                intermediates.len()
            );
            return Err(Error::General(msg));
        }

        // Check that presented certificate matches byte-for-byte the expected certificate
        if end_entity != &self.expected_peer_cert {
            return Err(Error::InvalidCertificate(
                CertificateError::UnknownIssuer,
            ));
        }

        let now = rx509::der::UtcTime::from_seconds_since_epoch(now.as_secs());

        if !self.validity.is_valid(now) {
            return Err(Error::InvalidCertificate(CertificateError::Expired));
        }

        // We do not validate DNS name. Providing the exact same certificate is sufficient.

        Ok(())
    }
}

impl rustls::server::danger::ClientCertVerifier for SelfSignedVerifier {

    fn root_hint_subjects(&self) -> &[DistinguishedName] {

        //self.subjects.as_slice()
        &[] // TODO - this might not be necessary
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer,
        intermediates: &[CertificateDer],
        now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        self.verify_peer(end_entity, intermediates, now)?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &rustls::crypto::ring::default_provider().signature_verification_algorithms)
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &rustls::crypto::ring::default_provider().signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes()
    }
}

impl rustls::client::danger::ServerCertVerifier for SelfSignedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer,
        intermediates: &[CertificateDer],
        _server_name: &ServerName,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        self.verify_peer(end_entity, intermediates, now)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &rustls::crypto::ring::default_provider().signature_verification_algorithms)
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &rustls::crypto::ring::default_provider().signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes()
    }
}
