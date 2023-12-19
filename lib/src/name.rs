/// Specifies how name verification should or should not be performed on the server's name
///
/// Server names get passed in when connecting, so no name is present in this enum
#[derive(Copy, Clone, Debug)]
pub enum ServerNameVerification {
    /// Perform name verification using standard WebPKI verifier
    Verify,
    /// Don't perform any name verification
    DisableNameVerification,
}

/// Specifies how name verification should or should not be performed on the client's name
#[derive(Clone, Debug)]
pub enum ClientNameVerification {
    /// Don't perform any client name verification (which is the default for mTLS)
    None,
    /// Check that client's name matches one of these server names
    Verify(rustls::pki_types::ServerName<'static>),
}
