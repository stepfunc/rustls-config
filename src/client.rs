use crate::name::NameVerifier;

/// Verifier used by the client to check the server's certificate chain
///
/// This verifier is similar to the default verifier in rustls as it
/// uses webpki for the heavy lifting to verify the chain.
///
/// It can also verify the name in the server cert from the Common Name as well.
pub struct ServerCertVerifier {
    roots: Vec<OwnedTrustAnchor>,
    name: NameVerifier,
}

impl ServerCertVerifier {
    /// Create the verifier from some root anchors and a name verifier
    pub fn new(
        anchors: Vec<rustls::Certificate>,
        name: NameVerifier,
    ) -> Result<Self, rustls::Error> {
        let roots = Self::trust_anchors(anchors).map_err(crate::pki_error)?;
        Ok(Self { roots, name })
    }

    fn trust_anchors(
        certs: Vec<rustls::Certificate>,
    ) -> Result<Vec<OwnedTrustAnchor>, webpki::Error> {
        certs
            .iter()
            .map(|x| OwnedTrustAnchor::try_from_cert_der(x.0.as_slice()))
            .collect()
    }
}

impl rustls::client::ServerCertVerifier for ServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::Certificate,
        intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        // Note: this code is taken from `WebPkiVerifier` in the `verifier` module of `rustls`

        // Verify trust chain using webpki
        let (cert, chain, trustroots) = prepare(end_entity, intermediates, &self.roots)?;
        let webpki_now =
            webpki::Time::try_from(now).map_err(|_| rustls::Error::FailedToGetCurrentTime)?;

        cert.verify_is_valid_tls_server_cert(
            SUPPORTED_SIG_ALGS,
            &webpki::TlsServerTrustAnchors(&trustroots),
            &chain,
            webpki_now,
        )
        .map_err(super::pki_error)?;

        // Check DNS name (including in the Common Name)
        self.name.verify(end_entity)?;

        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

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
    fn to_trust_anchor(&self) -> webpki::TrustAnchor {
        webpki::TrustAnchor {
            subject: &self.subject,
            spki: &self.spki,
            name_constraints: self.name_constraints.as_deref(),
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
    Vec<webpki::TrustAnchor<'b>>,
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
