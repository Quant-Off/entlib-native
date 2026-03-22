//! NIST FIPS 140-3 준수 암호 아머(Armor) 크레이트 모듈입니다.
//! 이 모듈은 데이터 직렬화 및 인코딩 파이프라인 구성 기능을 제공하기
//! 위해 만들어졌습니다.
//!
//! ASN.1/DER 파싱·인코딩, RFC 7468 PEM 포맷 변환, 고보안 파일 I/O를
//! 단일 크레이트에서 제공합니다. 모든 민감 데이터는 `SecureBuffer`로
//! 격리하며, 부채널 공격 방어를 위해 상수-시간 연산을 적용합니다.
//!
//! # Security Note
//! - **DER 파서**: 버퍼 오버리드·재귀 폭탄·비최소 인코딩·부정길이(BER)를
//!   거부하는 반복(iterative) 커서 기반 구현입니다.
//! - **PEM 디코더**: 허용 레이블 목록(`EncryptedPrivateKey`, `Certificate`,
//!   `PublicKey`, `CertificateRequest`)으로 비승인 구조체 타입을 차단합니다.
//!   비암호화 개인 키(`PRIVATE KEY`)는 의도적으로 허용 목록에서 제외됩니다.
//! - **파일 I/O**: Unix `0o600` 권한 강제, 원자적 임시 파일 교체,
//!   1 MiB 읽기 크기 제한, 경로 null 바이트 주입 거부.
//! - **OID 비교**: 타이밍 정보 누출을 막기 위해 전체 슬롯을 항상 순회하는
//!   상수-시간 `ct_eq()` 비교를 사용합니다.
//!
//! # Examples
//! ```rust,ignore
//! use entlib_native_armor::der::{DerReader, DerWriter, MAX_DEPTH};
//! use entlib_native_armor::pem::{encode, decode, PemLabel};
//! use entlib_native_armor::asn1::Oid;
//!
//! // DER 인코딩
//! let mut w = DerWriter::new();
//! w.write_octet_string(&[0xDE, 0xAD, 0xBE, 0xEF]).unwrap();
//! let der = w.finish();
//!
//! // PEM 래핑 (이미 암호화된 DER 페이로드 가정)
//! let pem = encode(&der, PemLabel::EncryptedPrivateKey).unwrap();
//!
//! // PEM 언래핑 및 DER 복원
//! let (label, restored) = decode(pem.as_slice()).unwrap();
//! assert_eq!(label, PemLabel::EncryptedPrivateKey);
//! assert_eq!(restored.as_slice(), &der);
//! ```
//! 
//! # Authors
//! Q. T. Felix

#![no_std]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

pub mod asn1;
pub mod der;
pub mod pem;
mod error;
#[cfg(feature = "std")]
pub mod io;

pub use error::ArmorError;
pub use pem::{PemError, PemLabel};
#[cfg(feature = "std")]
pub use io::IoError;
