#![doc = include_str!("../README.md")]

#[cfg(all(feature = "crypto-ring", feature = "crypto-aws-lc-rs"))]
compile_error!("Features 'cryto-ring' and 'cryto-aws-lc-rs' are mutually exclusive and cannot be enabled together");

#[cfg(not(any(feature = "crypto-ring", feature = "crypto-aws-lc-rs")))]
compile_error!("'cryto-ring' OR 'cryto-aws-lc-rs' must be enabled");

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
