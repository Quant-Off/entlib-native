use std::panic;
use std::slice;
use zeroize::Zeroize;

/// `Java MemorySegment`의 주소와 길이를 받아 안전하게 소거합니다.
///
/// # Safety
/// 이 함수는 FFI 경계에서 호출되기 떄문에 패닉이 발생해도 JVM을 중단시키지 않도록
/// `catch_unwind`로 감싸져 있습니다. 다만, 여전히 `ptr`은 유효한 메모리 주소여야 합니다.
#[unsafe(no_mangle)]
pub extern "C" fn entanglement_secure_wipe(ptr: *mut u8, len: usize) {
    // Rust 내부 패닉이 JVM으로 전파되지 않도록 차단
    let result = panic::catch_unwind(|| {
        unsafe {
            // 입력값 검증 강화
            if ptr.is_null() || len == 0 {
                return;
            }

            // Rust 슬라이스 길이 제한 검사
            if len > isize::MAX as usize {
                // 너무 큰 길이는 처리하지 않음 todo: (로그 또는 에러 코드 반환 고려 가능)
                return;
            }

            // 안전한 슬라이스 생성 및 소거
            let data = slice::from_raw_parts_mut(ptr, len);
            data.zeroize();
        }
    });

    // 패닉 발생 시 로깅
    if result.is_err() {
        // 표준 에러
        eprintln!("[EntLib-Native] 치명적 에러: 보안 삭제 중 패닉이 발생했습니다!");
    }
}
