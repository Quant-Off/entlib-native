#![no_std]
pub mod constant_time;

#[cfg(feature = "ct-tests")]
#[doc(hidden)]
pub mod constant_time_asm;

#[cfg(not(feature = "ct-tests"))]
pub(crate) mod constant_time_asm;
