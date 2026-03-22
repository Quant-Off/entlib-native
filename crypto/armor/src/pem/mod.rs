//! PEM (Privacy Enhanced Mail) 인코더/디코더 모듈입니다.
//!
//! RFC 7468 기반의 PEM 포맷으로 DER 바이트열을 인코딩/디코딩합니다.
//! DER 입력만 허용하며, 허용된 레이블 목록으로 구조체 타입을 제한합니다.
//!
//! # Examples
//! ```rust,ignore
//! use entlib_native_armor::pem::{encode, decode, PemLabel};
//!
//! // DER 인코딩 (DER은 이미 암호화된 상태여야 함)
//! let pem_buf = encode(&der_bytes, PemLabel::EncryptedPrivateKey).unwrap();
//!
//! // PEM 디코딩
//! let (label, der_buf) = decode(pem_buf.as_slice()).unwrap();
//! assert_eq!(label, PemLabel::EncryptedPrivateKey);
//! ```

mod decoder;
mod encoder;
mod error;
mod filter;
mod label;

pub use decoder::decode;
pub use encoder::encode;
pub use error::PemError;
pub use label::PemLabel;
