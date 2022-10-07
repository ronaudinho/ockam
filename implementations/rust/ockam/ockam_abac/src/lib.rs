//! Attribute Based Access Control
#![warn(
    trivial_casts,
    trivial_numeric_casts,
    unused_import_braces,
    unused_qualifications
)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
#[macro_use]
extern crate core;

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod mem;

mod policy;
mod traits;
mod types;

pub use policy::*;
pub use traits::*;
pub use types::*;
