//! AES-256 암호 모듈입니다.
//! FIPS 140-3 요구사항을 충족하는 GCM(AEAD) 및 CBC+PKCS7+HMAC-SHA256 모드를 제공합니다.
//!
//! # Examples
//! ```rust
//! use entlib_native_aes::{AES256GCM, AES256CBCHmac, GCM_NONCE_LEN, GCM_TAG_LEN, CBC_IV_LEN, cbc_output_len};
//! use entlib_native_secure_buffer::SecureBuffer;
//!
//! let mut key = SecureBuffer::new_owned(32).unwrap();
//! key.as_mut_slice().copy_from_slice(&[0u8; 32]);
//! let nonce = [0u8; GCM_NONCE_LEN];
//! let plaintext = b"hello world";
//! let mut ct = vec![0u8; plaintext.len()];
//! let mut tag = [0u8; GCM_TAG_LEN];
//! AES256GCM::encrypt(&key, &nonce, &[], plaintext, &mut ct, &mut tag).unwrap();
//!
//! let mut enc_key = SecureBuffer::new_owned(32).unwrap();
//! enc_key.as_mut_slice().copy_from_slice(&[0u8; 32]);
//! let mut mac_key = SecureBuffer::new_owned(32).unwrap();
//! mac_key.as_mut_slice().copy_from_slice(&[1u8; 32]);
//! let iv = [0u8; CBC_IV_LEN];
//! let mut out = vec![0u8; cbc_output_len(plaintext.len())];
//! AES256CBCHmac::encrypt(&enc_key, &mac_key, &iv, plaintext, &mut out).unwrap();
//! ```
//!
//! # Authors
//! Q. T. Felix

#![no_std]
#![doc = include_str!("../README.md")]

extern crate alloc;

mod aes;
mod cbc;
mod error;
mod gcm;
mod ghash;

pub use aes::aes256_encrypt_ecb;
pub use cbc::{AES256CBCHmac, CBC_HMAC_LEN, CBC_IV_LEN, cbc_output_len, cbc_plaintext_max_len};
pub use error::AESError;
pub use gcm::{AES256GCM, GCM_NONCE_LEN, GCM_TAG_LEN};
