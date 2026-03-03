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

/// JNI/FFM 환경에서 여러 번의 컨텍스트 스위칭 오버헤드를 줄이기 위해,
/// 데이터 포인터와 길이를 한 번에 반환하는 구조체입니다.
#[repr(C)]
pub struct FfiSecureBufferView {
    pub data: *const u8,
    pub len: usize,
}

/// 보안 버퍼 내 데이터의 메모리 주소와 길이를 동시에 반환합니다.
/// 기존의 `len` 및 `data` 개별 호출로 인한 병목(FFI 경계 횡단)을 1회로 줄입니다.
/// Java 측에서는 데이터를 안전하게 복사한 뒤 반드시 `entlib_secure_buffer_free`를 호출해야 합니다.
///
/// # Safety
/// - 반환된 원시 포인터는 `SecureBuffer`가 해제되기 전까지만 유효합니다.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn entlib_secure_buffer_view(
    buf: *const SecureBuffer,
) -> FfiSecureBufferView {
    if buf.is_null() {
        return FfiSecureBufferView {
            data: ptr::null(),
            len: 0,
        };
    }
    // 레퍼런스 차용을 통해 원본 소유권을 유지
    let buffer = unsafe { &*buf };
    FfiSecureBufferView {
        data: buffer.inner.as_ptr(),
        len: buffer.inner.len(),
    }
}

/// Java가 제공한 메모리로 데이터를 복사하고, Rust 버퍼를 즉각 소거합니다.
/// 기존 (Len 확인 -> Data 매핑 -> Free)의 3회 호출을 **단 1회의 FFI 호출**로 극단적으로 압축합니다.
///
/// # Arguments
/// * `buf` - 해제할 `SecureBuffer`의 가변 포인터
/// * `dest` - 복사될 Java 측 오프힙 메모리(또는 Secure Array)의 시작 포인터
/// * `dest_capacity` - 버퍼 오버플로우 방지를 위한 `dest`의 최대 용량
///
/// # Returns
/// 실제 복사된 바이트 길이(usize). 만약 용량 부족 등 에러가 발생하면 0을 반환합니다.
///
/// # Safety
/// - 호출 즉시 `buf`의 `Drop` 트레이트가 실행되어 메모리가 소거됩니다.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn entlib_secure_buffer_copy_and_free(
    buf: *mut SecureBuffer,
    dest: *mut u8,
    dest_capacity: usize,
) -> usize {
    if buf.is_null() || dest.is_null() {
        return 0;
    }

    // Box::from_raw로 소유권 획득 (스코프 종료 시 자동 소거)
    let buffer = unsafe { Box::from_raw(buf) };
    let len = buffer.inner.len();

    // Zero Trust 검증: Java 측 버퍼 용량이 실제 반환할 데이터보다 크거나 같은지 확인
    if dest_capacity >= len {
        unsafe {
            // 메모리 복사 수행
            ptr::copy_nonoverlapping(buffer.inner.as_ptr(), dest, len);
        }
        len
    } else {
        // 공간 부족 시 복사를 수행하지 않음 (단, 원본 buffer는 그대로 소멸하여 보안 유지)
        0
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
