//! 외부 함수 인터페이스(foreign function interface) 환경에서 민감 데이터의 안전한 교환 및
//! 메모리 소거(zeroize)를 완벽하게 보장하기 위한 통제 모듈입니다.
//!
//! 얽힘 라이브러리의 Java 런타임과 네이티브 환경 간의 브리지 역할을 수행하며,
//! 가비지 컬렉터(garbage collector)에 의한 메모리 누수 및 잔류 데이터 노출을 원천 차단합니다.
//! 본 모듈은 대규모 엔터프라이즈 및 군사급 보안 요구사항을 충족하기 위해, 다음과 같이
//! 두 가지 독립적이고 엄격한 메모리 소유권(memory ownership) 모델을 지원합니다.
//!
//! # 피호출자 할당 패턴 (callee-allocated, rust-owned memory)
//! 네이티브 환경에서 연산 결과의 크기를 Java 측이 사전에 알 수 없는 경우(가변 길이의 암호문 생성 등)
//! 사용되는 패턴입니다. Rust가 동적으로 할당한 [SecureBuffer]의 불투명 포인터(opaque pointer)가
//! Java로 반환됩니다.
//!
//! Java 측은 획득한 포인터를 통해 다음 함수들을 순차적으로 호출해야 합니다.
//! - [entlib_secure_buffer_data]: 실제 데이터의 메모리 주소 매핑
//! - [entlib_secure_buffer_len]: 데이터의 바이트 길이 확인
//! - [entlib_secure_buffer_free]: 사용 완료 후 즉각적인 데이터 소거 및 메모리 할당 해제(deallocation) 지시
//!
//! # 호출자 할당 패턴 (caller-allocated, java-owned memory)
//! Java 측의 보안 데이터 컨테이너(`SensitiveDataContainer`)가 `off-heap` 영역에 메모리를
//! 선제적으로 확보하여 제공하는 경우 사용되는 패턴입니다.
//!
//! Java 스코프 컨텍스트(`SDCScopeContext`)가 종료될 때 호출되며, 네이티브는 데이터의 덮어쓰기만 수행합니다.
//! - [entanglement_secure_wipe]: Java가 소유한 메모리 영역을 임시로 `FFIExternalSecureBuffer`에
//!   매핑하여 소거 로직을 실행하되, 할당 해제는 수행하지 않음 (해제 권한은 Java에 위임됨)
//!
//! # Authors
//! Q. T. Felix

use core::ptr;
use entlib_native_core_secure::secure_buffer::{FFIExternalSecureBuffer, SecureBuffer};

/// 보안 버퍼 내 실제 데이터의 메모리 주소 반환 (get immutable data pointer)
///
/// # Safety
/// - 반환된 원시 포인터(raw pointer)는 `SecureBuffer`가 `entlib_secure_buffer_free`를 통해
///   해제되기 전까지만 유효합니다. 해제 후 역참조 시 미정의 동작(undefined behavior)이 발생합니다.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn entlib_secure_buffer_data(buf: *const SecureBuffer) -> *const u8 {
    if buf.is_null() {
        return ptr::null();
    }
    let buffer = unsafe { &*buf };
    buffer.inner.as_ptr()
}

/// 보안 버퍼 내 데이터의 바이트 길이 반환 (get length of data)
///
/// # Safety
/// - `buf`가 null이 아닌 경우, 유효한 `SecureBuffer` 인스턴스를 가리켜야 합니다.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn entlib_secure_buffer_len(buf: *const SecureBuffer) -> usize {
    if buf.is_null() {
        return 0;
    }
    let buffer = unsafe { &*buf };
    buffer.inner.len()
}

/// 보안 버퍼 메모리 해제 및 데이터 소거 (free and zeroize)
///
/// # Safety
/// - 호출 즉시 `SecureBuffer`의 `Drop` 트레이트가 실행되어 `write_volatile` 및
///   `compiler_fence`를 통해 메모리가 안전하게 소거됩니다.
/// - Java 링커(java linker api)를 통해 반드시 한 번만 호출되어야 합니다 (double-free 방지).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn entlib_secure_buffer_free(buf: *mut SecureBuffer) {
    if !buf.is_null() {
        unsafe {
            // Box::from_raw를 통해 소유권을 가져오며, 즉시 스코프를 벗어나 Drop 실행
            drop(Box::from_raw(buf));
        }
    }
}

/// Java 측 `SensitiveDataContainer`가 소유한 네이티브 메모리 세그먼트(memory segment)를
/// 안전하게 소거(zeroize)하는 ffi 엔드포인트입니다.
///
/// # Arguments
/// * `ptr` - 소거할 메모리 영역의 시작 포인터 (*mut u8)
/// * `len` - 소거할 메모리의 바이트 크기 (usize)
///
/// # Safety
/// - `ptr`은 `len` 바이트만큼 할당된 유효한 메모리 영역을 가리켜야 합니다.
/// - Java의 제한된 아레나(confined arena) 수명 주기에 의해 유효성이 검증된 상태에서만 호출되어야 합니다.
/// - 이 함수는 호출자 할당 패턴으로, Java 측에서 할당 해제를 수행해야 합니다.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn entanglement_secure_wipe(ptr: *mut u8, len: usize) {
    // null 포인터 및 길이 검증
    if ptr.is_null() || len == 0 {
        return;
    }

    // 명시적 drop 호출로 RAII 소멸자를 즉시 실행
    // Q. T. Felix NOTE: FFIExternalSecureBuffer의 Drop 구현은 오직 write_volatile을 통한 소거만 수행해야 하며,
    //                   메모리 할당 해제(deallocate)는 Java 측에서 수행되어야 합니당
    drop(FFIExternalSecureBuffer { inner: ptr, len });
}
