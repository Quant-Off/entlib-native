//! 고보안 DER/PEM 파일 I/O 모듈입니다.
//!
//! RFC 7468 표준을 준수하는 PEM 파일 출력 및 DER/PEM 파일 읽기를 제공합니다.
//!
//! # Security Note
//! - 파일 읽기: 최대 1 MiB 크기 제한으로 메모리 고갈 공격 방어
//! - 파일 쓰기: Unix에서 `0o600` 권한 강제, 원자적 임시 파일 교체
//! - 경로 검증: 빈 경로, null 바이트 삽입 즉시 거부
//! - 모든 데이터 버퍼는 SecureBuffer(mlock)에 보관
//!
//! # Examples
//! ```rust,ignore
//! use entlib_native_armor::io::{read_pem, write_pem};
//! use entlib_native_armor::pem::PemLabel;
//! use std::path::Path;
//!
//! // PEM 파일 쓰기 (0o600 권한, 원자적)
//! write_pem(Path::new("key.pem"), &der_bytes, PemLabel::EncryptedPrivateKey).unwrap();
//!
//! // PEM 파일 읽기 (DER 구조 검증 포함)
//! let (label, der) = read_pem(Path::new("key.pem")).unwrap();
//! ```

mod error;
mod reader;
mod writer;

pub use error::IoError;
pub use reader::{read_der, read_pem};
pub use writer::{write_der, write_pem};
