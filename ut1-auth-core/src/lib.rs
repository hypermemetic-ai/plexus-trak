//! UT-W3 shim: re-export the UNMERGED UT-1 branch of `plexus-auth-core`
//! (feature/UT-1-tenancy-oidc, d5688c7) under the extern name
//! `plexus_auth_core_ut1`.
//!
//! See the manifest comment for why this exists. TODO: delete this crate
//! once feature/UT-1-tenancy-oidc merges into ../plexus-auth-core.

pub use plexus_auth_core::*;
