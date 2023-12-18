#![doc = include_str!("../README.md")]
#![deny(
//dead_code,
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
