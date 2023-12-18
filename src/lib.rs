#![doc = include_str!("../README.md")]

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

pub(crate) mod pem;
pub(crate) mod self_signed;
