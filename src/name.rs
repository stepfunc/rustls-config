#[derive(Clone)]
enum VerifierType {
    Any,
    Strict(String),
}

/// Type that can be used to perform name verification on end-entity x.509 certificates
#[derive(Clone)]
pub struct NameVerifier {
    inner: VerifierType,
}

impl NameVerifier {
    /// Name verifier that doesn't perform an verification at all
    pub fn any() -> Self {
        Self {
            inner: VerifierType::Any,
        }
    }

    /// Name verifier that requires the specified name (DNS or IP) to be exactly as specified
    ///
    /// The DNS name may be matched against a Common Name
    pub fn equal_to(name: String) -> Self {
        Self {
            inner: VerifierType::Strict(name),
        }
    }

    /// Verify that the certificate matches the name in this verifier
    pub(crate) fn verify(&self, end_entity: &rustls::Certificate) -> Result<(), rustls::Error> {
        match &self.inner {
            VerifierType::Any => Ok(()),
            VerifierType::Strict(x) => verify_dns_name(end_entity, x.as_str()),
        }
    }
}

fn verify_dns_name(cert: &rustls::Certificate, server_name: &str) -> Result<(), rustls::Error> {
    // Extract the DNS name
    let subject_name = webpki::SubjectNameRef::try_from_ascii_str(server_name)
        .map_err(|_| rustls::Error::General("invalid DNS name".to_string()))?;

    // Let webpki parse the cert
    let end_entity_cert =
        webpki::EndEntityCert::try_from(cert.0.as_ref()).map_err(crate::pki_error)?;

    // Try validating the name using webpki. This only checks SAN extensions
    match end_entity_cert.verify_is_valid_for_subject_name(subject_name) {
        Ok(()) => Ok(()), // Good, we found a SAN extension that fits for the DNS name
        Err(webpki::Error::CertNotValidForName) => {
            // Let's extend our search to the CN
            // Parse the certificate using rasn
            let parsed_cert = rx509::x509::Certificate::parse(&cert.0).map_err(|err| {
                rustls::Error::General(format!("unable to parse cert with rasn: {err:?}"))
            })?;

            // Parse the extensions (if present) and check that no SAN are present
            if let Some(extensions) = &parsed_cert.tbs_certificate.value.extensions {
                // Parse the extensions
                let extensions = extensions.parse().map_err(|err| {
                    rustls::Error::General(format!(
                        "unable to parse certificate extensions with rasn: {err:?}"
                    ))
                })?;

                // Check that no SAN extension are present
                if extensions.iter().any(|x| {
                    matches!(
                        x.content,
                        rx509::x509::ext::SpecificExtension::SubjectAlternativeName(_)
                    )
                }) {
                    return Err(rustls::Error::General(
                        "certificate not valid for name, SAN extensions do not match".to_string(),
                    ));
                }
            }

            // Parse the cert subject
            let subject = parsed_cert
                .tbs_certificate
                .value
                .subject
                .parse()
                .map_err(|err| {
                    rustls::Error::General(format!("unable to parse certificate subject: {err:?}"))
                })?;

            let common_name = subject.common_name.ok_or_else(|| {
                rustls::Error::General(
                    "certificate not valid for name, no SAN and no CN present".to_string(),
                )
            })?;

            match common_name == server_name {
                true => Ok(()),
                false => Err(rustls::Error::General(
                    "certificate not valid for name, no SAN and CN doesn't match".to_string(),
                )),
            }
        }
        Err(err) => Err(crate::pki_error(err)), // Any other error means there was an error parsing the cert, we should throw
    }
}
