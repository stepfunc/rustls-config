#![doc = include_str!("../README.md")]
#![deny(
dead_code,
arithmetic_overflow,
invalid_type_param_default,
missing_fragment_specifier,
mutable_transmutes,
no_mangle_const_items,
overflowing_literals,
patterns_in_fns_without_body,
pub_use_of_private_extern_crate,
unknown_crate_types,
order_dependent_trait_objects,
illegal_floating_point_literal_pattern,
improper_ctypes,
late_bound_lifetime_arguments,
non_camel_case_types,
non_shorthand_field_patterns,
non_snake_case,
non_upper_case_globals,
no_mangle_generic_items,
private_in_public,
stable_features,
type_alias_bounds,
tyvar_behind_raw_pointer,
unconditional_recursion,
unused_comparisons,
unreachable_pub,
anonymous_parameters,
missing_copy_implementations,
//missing_debug_implementations,
missing_docs,
trivial_casts,
trivial_numeric_casts,
unused_import_braces,
unused_qualifications,
clippy::all
)]
#![forbid(
    unsafe_code,
    rustdoc::broken_intra_doc_links,
    while_true,
    bare_trait_objects
)]

pub(crate) mod pem;
pub(crate) mod self_signed;

/// Client configurations
pub mod client;
/// Server configurations
pub mod server;

mod error;
mod name;

use rustls::OtherError;
pub use error::*;
pub use name::*;

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

pub(crate) fn pki_error(error: webpki::Error) -> rustls::Error {
    use webpki::Error::*;
    match error {
        BadDer | BadDerTime => rustls::CertificateError::BadEncoding.into(),
        CertNotValidYet => rustls::CertificateError::NotValidYet.into(),
        CertExpired | InvalidCertValidity => rustls::CertificateError::Expired.into(),
        UnknownIssuer => rustls::CertificateError::UnknownIssuer.into(),
        CertNotValidForName => rustls::CertificateError::NotValidForName.into(),

        InvalidSignatureForPublicKey
        | UnsupportedSignatureAlgorithm
        | UnsupportedSignatureAlgorithmForPublicKey => {
            rustls::CertificateError::BadSignature.into()
        }
        _ => rustls::CertificateError::Other(OtherError(std::sync::Arc::new(error))).into(),
    }
}

pub(crate) fn read_certificates(path: &std::path::Path) -> Result<Vec<rustls::pki_types::CertificateDer>, Error> {
    let bytes = std::fs::read(path)?;
    let certs = pem::read_certificates(bytes)?;
    Ok(certs.into_iter().map(|x| x.into()).collect())
}

pub(crate) fn read_one_cert(path: &std::path::Path) -> Result<rustls::pki_types::CertificateDer, Error> {
    let bytes = std::fs::read(path)?;
    let cert = pem::read_one_certificate(bytes)?;
    Ok(cert.into())
}

pub(crate) fn read_private_key(
    path: &std::path::Path,
    password: Option<&str>,
) -> Result<rustls::PrivateKey, Error> {
    let bytes = std::fs::read(path)?;
    let key = match password {
        Some(x) => pem::PrivateKey::decrypt_from_pem(bytes, x)?,
        None => pem::PrivateKey::read_from_pem(bytes)?,
    };
    Ok(rustls::PrivateKey(key.into_inner()))
}
