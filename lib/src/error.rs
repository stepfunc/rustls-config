use rustls::client::VerifierBuilderError;

/// Opaque error type used by the library that implements [`std::error::Error`].
#[derive(Debug)]
pub struct Error {
    details: Details,
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Self {
            details: Details::Io(err),
        }
    }
}

impl From<crate::pem::Error> for Error {
    fn from(err: crate::pem::Error) -> Self {
        Self {
            details: Details::Pem(err),
        }
    }
}

impl From<rx509::der::ASNError> for Error {
    fn from(err: rx509::der::ASNError) -> Self {
        Self {
            details: Details::X509(err),
        }
    }
}

impl From<rustls::Error> for Error {
    fn from(err: rustls::Error) -> Self {
        Self {
            details: Details::Tls(err),
        }
    }
}

impl From<VerifierBuilderError> for Error {
    fn from(err: VerifierBuilderError) -> Self {
        Self {
            details: Details::BuilderError(err),
        }
    }
}

#[derive(Debug)]
enum Details {
    /// Error reading PEM data from file
    Io(std::io::Error),
    /// Bad PEM file
    Pem(crate::pem::Error),
    /// RX509 error decoding certificate
    X509(rx509::der::ASNError),
    /// Error returned by Rustls
    Tls(rustls::Error),
    /// Error building a certificate verifier
    BuilderError(VerifierBuilderError),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self.details {
            Details::Io(err) => write!(f, "I/O error: {err}"),
            Details::Pem(err) => write!(f, "PEM error: {err}"),
            Details::X509(err) => write!(f, "RX509 error: {err}"),
            Details::Tls(err) => write!(f, "Rustls error: {err}"),
            Details::BuilderError(err) => write!(f, "Error building certificate verifier: {err}"),
        }
    }
}
