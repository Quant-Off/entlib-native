#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]

pub(crate) const TYPE_ID: i8 = 0;

mod buffer;
mod memory;
mod zeroize;

extern crate alloc;

pub use buffer::SecureBuffer;
