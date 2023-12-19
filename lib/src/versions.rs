/// Minimum protocol version allowed
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MinProtocolVersion {
    /// Allow TLS 1.2 and 1.3
    V1_2,
    /// Allow TLS 1.3 only
    V1_3,
}

impl MinProtocolVersion {
    pub(crate) fn versions(self) -> &'static [&'static rustls::SupportedProtocolVersion] {
        static MIN_TLS12_VERSIONS: &[&rustls::SupportedProtocolVersion] =
            &[&rustls::version::TLS13, &rustls::version::TLS12];
        static MIN_TLS13_VERSIONS: &[&rustls::SupportedProtocolVersion] =
            &[&rustls::version::TLS13];

        match self {
            Self::V1_2 => MIN_TLS12_VERSIONS,
            Self::V1_3 => MIN_TLS13_VERSIONS,
        }
    }
}
