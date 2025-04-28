#![doc = include_str!("../README.md")]

#[cfg(all(feature = "crypto-ring", feature = "crypto-aws-lc-rs"))]
compile_error!("Features 'crypto-ring' and 'crypto-aws-lc-rs' are mutually exclusive and cannot be enabled together");

#[cfg(not(any(feature = "crypto-ring", feature = "crypto-aws-lc-rs")))]
compile_error!("'crypto-ring' OR 'crypto-aws-lc-rs' must be enabled");

#[cfg(feature = "crypto-ring")]
pub(crate) use rustls::crypto::ring::default_provider as default_crypto_provider;

#[cfg(feature = "crypto-aws-lc-rs")]
pub(crate) use rustls::crypto::aws_lc_rs::default_provider as default_crypto_provider;

/// Client configurations
pub mod client;
/// Server configurations
pub mod server;

mod error;
mod name;
mod versions;

pub use error::*;
pub use name::*;
pub use versions::*;

pub(crate) mod common_name;
pub(crate) mod pem;
pub(crate) mod self_signed;
