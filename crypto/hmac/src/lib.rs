#![no_std]

mod hmac;

pub use hmac::{HMACSHA224, HMACSHA256, HMACSHA384, HMACSHA512, MacResult};

/// HMAC 연산 중 발생할 수 있는 보안 오류
#[derive(Debug)]
pub enum HmacError {
    /// NIST SP 800-107r1에 따른 최소 키 길이(112 bits / 14 bytes) 미달
    WeakKeyLength,
    /// 내부 해시 연산 중 발생한 오류
    HashComputationError(&'static str),
}
