#![no_std]

extern crate alloc;

mod aes;
mod cbc;
mod error;
mod gcm;
mod ghash;

pub use aes::aes256_encrypt_ecb;
pub use cbc::{cbc_output_len, cbc_plaintext_max_len, AES256CBCHmac, CBC_HMAC_LEN, CBC_IV_LEN};
pub use error::AESError;
pub use gcm::{AES256GCM, GCM_NONCE_LEN, GCM_TAG_LEN};
