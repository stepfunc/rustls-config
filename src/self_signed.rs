use rustls::CertificateError;

/// Core verify that can be converted to a client or server cert verifier
pub struct SelfSignedVerifier {
    // expected certificate
    expected_peer_cert: rustls::Certificate,
    // pre-parsed validity
    validity: rx509::x509::Validity,
}

impl SelfSignedVerifier {
    pub fn create(expected: rustls::Certificate) -> Result<Self, rx509::der::ASNError> {
        let parsed = rx509::x509::Certificate::parse(&expected.0)?;

        let validity = parsed.tbs_certificate.value.validity;

        Ok(Self {
            expected_peer_cert: expected,
            validity
        })
    }

    pub(crate) fn verify(
        &self,
        end_entity: &rustls::Certificate,
        intermediates: &[rustls::Certificate],
        now: std::time::SystemTime,
    ) -> Result<(), rustls::Error> {
        // Check that no intermediate certificates are present
        if !intermediates.is_empty() {
            return Err(rustls::Error::General(format!(
                "client sent {} intermediate certificates, expected none",
                intermediates.len()
            )));
        }

        // Check that presented certificate matches byte-for-byte the expected certificate
        if end_entity != &self.expected_peer_cert {
            return Err(
                rustls::Error::InvalidCertificate(CertificateError::UnknownIssuer)
            );
        }

        let now = now
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| rustls::Error::FailedToGetCurrentTime)?;
        let now = rx509::der::UtcTime::from_seconds_since_epoch(now.as_secs());

        if !self.validity.is_valid(now) {
            return Err(rustls::Error::InvalidCertificate(CertificateError::Expired));
        }

        // We do not validate DNS name. Providing the exact same certificate is sufficient.

        Ok(())
    }
}

impl rustls::server::ClientCertVerifier for SelfSignedVerifier {

}