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

impl From<sfio_pem_util::Error> for Error {
    fn from(err: sfio_pem_util::Error) -> Self {
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

#[derive(Debug)]
enum Details {
    /// Error reading PEM data from file
    Io(std::io::Error),
    /// Bad PEM file
    Pem(sfio_pem_util::Error),
    /// RX509 error decoding certificate
    X509(rx509::der::ASNError),
    /// Error returned by Rustls
    Tls(rustls::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self.details {
            Details::Io(err) => write!(f, "I/O error: {err}"),
            Details::Pem(err) => write!(f, "PEM error: {err}"),
            Details::X509(err) => write!(f, "RX509 error: {err}"),
            Details::Tls(err) => write!(f, "Rustls error: {err}"),
        }
    }
}
