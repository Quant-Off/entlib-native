use entlib_native_helper::secure_buffer::SecureBuffer;
use core::ptr::{self, write_volatile};
use core::slice;
use core::sync::atomic::{Ordering, compiler_fence};

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
/// - 자바 링커(java linker api)를 통해 반드시 한 번만 호출되어야 합니다 (double-free 방지).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn entlib_secure_buffer_free(buf: *mut SecureBuffer) {
    if !buf.is_null() {
        unsafe {
            // Box::from_raw를 통해 소유권을 가져오며, 즉시 스코프를 벗어나 Drop 실행
            drop(Box::from_raw(buf));
        }
    }
}

/// 자바 측 `SensitiveDataContainer`가 소유한 네이티브 메모리 세그먼트(memory segment)를
/// 안전하게 소거(zeroize)하는 ffi 엔드포인트입니다.
///
/// # Arguments
/// * `ptr` - 소거할 메모리 영역의 시작 포인터 (*mut u8)
/// * `len` - 소거할 메모리의 바이트 크기 (usize)
///
/// # Safety
/// * `ptr`은 `len` 바이트만큼 할당된 유효한 메모리 영역을 가리켜야 합니다.
/// * 자바의 제한된 아레나(confined arena) 수명 주기에 의해 유효성이 검증된 상태에서만 호출되어야 합니다.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn entanglement_secure_wipe(ptr: *mut u8, len: usize) {
    // null pointer 및 0바이트 길이 방어 코드
    if ptr.is_null() || len == 0 {
        return;
    }

    // 원시 포인터로부터 가변 슬라이스 생성
    let buffer = unsafe { slice::from_raw_parts_mut(ptr, len) };

    // secure_buffer 구조체와 동일한 수준의 컴파일러 최적화 방어 소거
    for byte in buffer.iter_mut() {
        unsafe {
            // 휘발성 쓰기(volatile write)를 통해 dce 최적화 강제 회피
            write_volatile(byte, 0);
        }
    }

    // 메모리 배리어를 통해 소거 작업이 후속 메모리 해제(arena#close) 연산보다
    // 반드시 먼저 완료되도록 순서(sequential consistency) 보장
    compiler_fence(Ordering::SeqCst);
}