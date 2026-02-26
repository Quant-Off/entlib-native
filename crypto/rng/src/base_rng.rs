//! 아키텍처 레벨 진난수 생성기 및 보안 버퍼 통합 모듈
//!
//! # Author
//! Q. T. Felix
//!
//! # Security Warning
//! 본 구현체는 외부 크레이트 없이 프로세서의 하드웨어 난수 생성기에 의존합니다.
//! `Intel` 및 `ARM` 등 제조사의 하드웨어 백도어(hardware backdoor) 가능성을
//! 배제할 수 없는 경우, 이 출력값을 시드(seed)로 삼아 스트림 암호(stream cipher) 또는
//! 해시 기반 결정론적 난수 생성기(hash-drbg)와 결합하는 혼합 과정이 추가로 요구됩니다.

use core::arch::asm;
use core::ptr::{copy_nonoverlapping, write_unaligned, write_volatile};
use core::sync::atomic::compiler_fence;
use entlib_native_core_secure::secure_buffer::SecureBuffer;
use std::sync::atomic::Ordering;
use std::vec::Vec;

/// 난수 생성 중 발생할 수 있는 시스템 및 보안 에러를 정의한 열거형입니다.
#[derive(Debug)]
pub enum RngError {
    /// 프로세서가 필요한 하드웨어 난수 명령어를 지원하지 않습니다.
    UnsupportedHardware,
    /// 엔트로피 풀 고갈 또는 하드웨어 응답에 실패했습니다.
    EntropyDepletion,
    /// 양자 난수 네트워크 요청(curl)이 실패했습니다.
    NetworkFailure(String),
    /// 양자 난수 API 응답 데이터 파싱에 실패했습니다.
    ParseError,
    /// 잘못된 포인터를 참조합니다.
    InvalidPointer,
    /// 잘못된 파라미터를 전달했거나 받았습니다.
    InvalidParameter,
}

/// 요청한 길이만큼의 진난수를 포함하는 보안 버퍼를 반환합니다.
///
/// 하드웨어 명령어를 통해 추출된 엔트로피를 직접 할당하며,
/// 지원되지 않는 아키텍처의 경우 컴파일 타임 에러를 발생시킵니다.
pub fn generate_hardware_random_bytes(len: usize) -> Result<SecureBuffer, RngError> {
    let mut buffer: Vec<u8> = Vec::with_capacity(len);

    unsafe {
        let ptr: *mut _ = buffer.as_mut_ptr();
        let mut offset = 0;

        // 8바이트(u64) 단위로 난수를 채움
        while offset + 8 <= len {
            let rand_val = get_hw_random_u64()?;
            write_unaligned((ptr.add(offset)) as *mut u64, rand_val);
            offset += 8;
        }

        // 나머지 바이트 처리
        if offset < len {
            let rand_val = get_hw_random_u64()?;
            let bytes = rand_val.to_ne_bytes();
            copy_nonoverlapping(bytes.as_ptr(), ptr.add(offset), len - offset);
        }

        // 모든 쓰기가 성공적으로 완료된 후 길이 설정
        buffer.set_len(len);
    }

    Ok(SecureBuffer { inner: buffer })
}

/// `x86_64` 아키텍처에서 진난수(`u64`)를 추출합니다.
///
/// NIST SP 800-90b 규격을 만족하는 `rdseed` 명령어를 우선적으로 시도하며,
/// 실패 시 `rdrand` 명령어로 폴백합니다.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn get_hw_random_u64() -> Result<u64, RngError> {
    // 런타임 기능 탐지
    if !std::arch::is_x86_feature_detected!("rdseed") {
        return Err(RngError::UnsupportedHardware);
    }

    let mut val: u64 = 0;
    let mut success: u8;
    let max_retries = 1000; // 무한 루프 방지

    unsafe {
        for _ in 0..max_retries {
            asm!(
            "rdseed {0}",
            "setc {1}",
            out(reg) val,
            out(reg_byte) success,
            options(nomem, nostack)
            );
            if success != 0 {
                return Ok(val);
            }
            core::hint::spin_loop();
        }
    }

    // rdseed 실패 시 강등(rdrand)하지 않고 명시적 에러 반환
    Err(RngError::EntropyDepletion)
}

/// 기존에 할당된 보안 버퍼(`secure_buffer`)에 하드웨어 진난수를 안전하게 주입합니다.
///
/// ffi 계층을 통해 자바(java) 측에서 전달된 메모리 세그먼트(memory segment)를
/// 재사용할 때 발생할 수 있는 힙 메모리 파편화를 방지하며, 난수 생성 중
/// 스택에 복사된 임시 레지스터 값들을 함수 종료 전 강제로 소거(zeroize)합니다.
pub fn next_generate(buffer: &mut SecureBuffer) -> Result<(), RngError> {
    let len = buffer.inner.len();
    if len == 0 {
        return Ok(());
    }

    let ptr = buffer.inner.as_mut_ptr();
    let mut offset = 0;

    unsafe {
        // 8바이트(u64) 단위 난수 주입
        while offset + 8 <= len {
            let mut rand_val = get_hw_random_u64()?;
            write_unaligned((ptr.add(offset)) as *mut u64, rand_val);
            offset += 8;

            // 스택에 남은 rand_val 값을 즉각 소거하여 잔여 데이터 유출 방지
            write_volatile(&mut rand_val, 0);
        }

        // 8바이트로 나누어떨어지지 않는 잔여 바이트 처리
        if offset < len {
            let mut rand_val = get_hw_random_u64()?;
            let mut bytes = rand_val.to_ne_bytes();
            let remain = len - offset;

            copy_nonoverlapping(bytes.as_ptr(), ptr.add(offset), remain);

            // 잔여 바이트 배열 및 원본 난수 변수 스택 소거
            for byte in bytes.iter_mut() {
                write_volatile(byte, 0);
            }
            write_volatile(&mut rand_val, 0);
        }

        // 컴파일러의 dce(dead code elimination) 및 명령어 재배치 최적화 방지
        compiler_fence(Ordering::SeqCst);
    }

    Ok(())
}

/// `aarch64` 아키텍처에서 진난수(`u64`)를 추출합니다.
///
/// `armv8.5-a` 이상에서 지원되는 `rndr` 레지스터를 통해 난수를 추출합니다.
#[cfg(target_arch = "aarch64")]
#[inline(always)]
fn get_hw_random_u64() -> Result<u64, RngError> {
    // aarch64의 rndr 기능 탐지 (libc::getauxval 등을 통한 HWCAP 확인 권장)
    // 현재 예시에서는 논리적 흐름을 보여줍니다.
    /* if !has_rndr_feature() {
        return Err(RngError::UnsupportedHardware);
    }
    */

    let mut val: u64;
    let mut success: u64;
    let max_retries = 1000; // 무한 루프 방지

    unsafe {
        for _ in 0..max_retries {
            asm!(
            "mrs {0}, s3_3_c2_c4_0",
            "cset {1}, ne",
            out(reg) val,
            out(reg) success,
            options(nomem, nostack)
            );
            if success != 0 {
                return Ok(val);
            }
            core::hint::spin_loop();
        }
    }

    Err(RngError::EntropyDepletion)
}

/// 지원되지 않는 아키텍처에 대한 컴파일을 차단합니다.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[inline(always)]
fn get_hw_random_u64() -> Result<u64, RngError> {
    Err(RngError::UnsupportedHardware);
}
