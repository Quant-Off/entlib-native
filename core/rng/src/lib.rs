#![no_std]

extern crate alloc;

mod hash_drbg;
mod os_entropy;

/// DRBG 연산 중 발생할 수 있는 오류에 대한 열거형입니다.
///
/// 모든 DRBG 구현에서 공유됩니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrbgError {
    /// 엔트로피 입력이 최소 보안 강도 요구사항(security_strength bytes) 미달
    EntropyTooShort,
    /// 엔트로피 입력 또는 Nonce가 최대 허용 길이(2^35 bits = 2^32 bytes) 초과
    EntropyTooLong,
    /// additional_input 또는 personalization_string이 최대 허용 길이(2^35 bits = 2^32 bytes) 초과
    InputTooLong,
    /// Nonce가 최소 길이(security_strength / 2 bytes) 미달
    NonceTooShort,
    /// 잘못된 인수 (예: no_of_bits 오버플로우)
    InvalidArgument,
    /// 재시드 간격(2^48) 초과 — 즉시 reseed() 호출 필요
    ReseedRequired,
    /// SecureBuffer 메모리 할당 실패 또는 OS mlock 실패
    AllocationFailed,
    /// 내부 해시 연산 실패
    InternalHashError,
    /// 요청한 출력 크기가 최대 허용치(65536 bytes = 2^19 bits) 초과
    RequestTooLarge,
    /// OS 엔트로피 소스 접근 실패
    ///
    /// 발생 원인:
    /// - 지원되지 않는 플랫폼: `os_entropy::extract_os_entropy` cfg 조건 미충족
    /// - VM 환경: 엔트로피 풀 초기화 미완료 (부팅 직후)
    OsEntropyFailed,
}

pub use hash_drbg::{HashDRBGSHA224, HashDRBGSHA256, HashDRBGSHA384, HashDRBGSHA512};
