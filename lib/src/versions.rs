/// Specifies which protocol version should be allowed
#[derive(Default, Copy, Clone, Debug, PartialEq, Eq)]
pub struct ProtocolVersions {
    /// Allow TLS 1.2
    v1_2: bool,
    /// Allow TLS 1.3
    v1_3: bool,
}

impl ProtocolVersions {
    /// Construct ProtocolVersions with nothing enabled
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct ProtocolVersions with only TLS 1.2 enabled
    pub fn v12_only() -> Self {
        Self::new().enable_v12()
    }

    /// Construct ProtocolVersions with only TLS 1.3 enabled
    pub fn v13_only() -> Self {
        Self::new().enable_v13()
    }

    /// Enable support for TLS 1.2
    pub fn enable_v12(self) -> Self {
        Self { v1_2: true, ..self }
    }

    /// Enable support for TLS 1.3
    pub fn enable_v13(self) -> Self {
        Self { v1_3: true, ..self }
    }
}

impl ProtocolVersions {
    pub(crate) fn versions(self) -> &'static [&'static rustls::SupportedProtocolVersion] {
        static V12_ONLY: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS12];
        static V13_ONLY: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];
        static V12_AND_V13: &[&rustls::SupportedProtocolVersion] =
            &[&rustls::version::TLS12, &rustls::version::TLS13];

        match (self.v1_2, self.v1_3) {
            (false, false) => &[],
            (false, true) => V13_ONLY,
            (true, false) => V12_ONLY,
            (true, true) => V12_AND_V13,
        }
    }
}
