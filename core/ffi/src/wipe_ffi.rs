use core::ptr::write_volatile;
use core::slice;
use core::sync::atomic::{Ordering, compiler_fence};

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
