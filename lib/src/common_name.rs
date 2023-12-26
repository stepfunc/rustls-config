use rustls::{CertificateError, Error};
use webpki::types::{CertificateDer, ServerName};

pub(crate) fn verify_name_from_subject(
    end_entity: &CertificateDer,
    name: &ServerName,
) -> Result<(), Error> {
    let dns_name = match name {
        ServerName::DnsName(name) => name,
        _ => return Err(Error::InvalidCertificate(CertificateError::NotValidForName)),
    };

    let parsed_cert = rx509::x509::Certificate::parse(end_entity)
        .map_err(|err| Error::General(format!("unable to parse certificate w/ rx509: {err}")))?;

    // Parse the extensions (if present) and check that no SAN extensions present
    if let Some(extensions) = &parsed_cert.tbs_certificate.value.extensions {
        // Parse the extensions
        let extensions = extensions.parse().map_err(|err| {
            Error::General(format!(
                "unable to parse certificate extensions w/ rx509: {err:?}"
            ))
        })?;

        // Check that no SAN extension are present
        if extensions.iter().any(|x| {
            matches!(
                x.content,
                rx509::x509::ext::SpecificExtension::SubjectAlternativeName(_)
            )
        }) {
            return Err(Error::InvalidCertificate(CertificateError::NotValidForName));
        }
    }

    // Parse the cert subject
    let subject = parsed_cert
        .tbs_certificate
        .value
        .subject
        .parse()
        .map_err(|err| {
            Error::General(format!(
                "unable to parse certificate subject w/ rx509: {err:?}"
            ))
        })?;

    let common_name = subject
        .common_name
        .ok_or_else(|| Error::General("No common name (CN) found w/ rx509".to_string()))?;

    if common_name != dns_name.as_ref() {
        return Err(Error::InvalidCertificate(CertificateError::NotValidForName));
    }

    Ok(())
}
