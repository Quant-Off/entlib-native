#![no_std]

extern crate alloc;

mod hmac;

pub use hmac::{
    HMACSHA3_224, HMACSHA3_256, HMACSHA3_384, HMACSHA3_512, HMACSHA224, HMACSHA256, HMACSHA384,
    HMACSHA512, MacResult,
};

use entlib_native_base::error::hash::HashError;
use entlib_native_base::error::secure_buffer::SecureBufferError;

/// HMAC 연산 중 발생할 수 있는 보안 오류
#[derive(Debug)]
pub enum HmacError {
    /// NIST SP 800-107r1에 따른 최소 키 길이(112 bits / 14 bytes) 미달
    WeakKeyLength,
    /// 내부 해시 연산 중 발생한 오류
    HashComputationError(HashError),
    /// MAC 결과를 저장하기 위한 SecureBuffer 할당 실패
    AllocationError(SecureBufferError),
}
