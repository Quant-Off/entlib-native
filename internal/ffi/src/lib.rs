use entlib_native_base::error::secure_buffer::SecureBufferError;
use entlib_native_result::EntLibResult;
use entlib_native_secure_buffer::SecureBuffer;
use std::mem::ManuallyDrop;

pub(crate) const TYPE_ID: i8 = 1;

mod base64_ffi;
mod hex_ffi;
mod sha_ffi;

/// 얽힘 라이브러리 FFI 경계 통신 표준 구조체입니다.
///
/// FFI 경계를 넘어온 브릿지 객체를 핸들링합니다.
#[repr(C)]
pub struct FFIStandard {
    pub ptr: *mut u8,
    pub len: usize,
    /// # Returns
    /// `true` = Rust-Owned 패턴 (Rust가 할당 해제)
    /// `false` = Java-Owned 패턴 (Java가 할당 해제)
    pub is_rust_owned: bool,
}

impl FFIStandard {
    /// FFI 경계를 넘어온 브릿지 객체를 Rust 도메인 객체인 [SecureBuffer]로 변환합니다.
    ///
    /// # Safety
    /// 이 함수는 `ptr`이 유효하고 `len`만큼 접근 가능하며,
    /// OS 페이지 크기(PAGE_SIZE)에 맞게 정렬되어 있음을 가정합니다.
    pub unsafe fn into_domain_buffer(
        &self,
    ) -> Result<ManuallyDrop<SecureBuffer>, SecureBufferError> {
        // from_raw_parts를 통해 메모리 검증 및 래핑
        // 이 과정에서 정렬 검사 및 OS 메모리 잠금(lock_memory) 수행
        let buffer = unsafe { SecureBuffer::from_raw_parts(self.ptr, self.len)? };

        // 자동 소거(Drop) 우회 및 소유권 제어
        if !self.is_rust_owned {
            // JO 패턴
            // 함수 스코프가 끝나도 SecureBuffer의 Drop 트레이트가 실행되지 않도록 감쌈
            Ok(ManuallyDrop::new(buffer))
        } else {
            // RO 패턴(is_rust_owned = true)이 이 구조체로 들어오는 경우는 거의 없는데
            // 만약 들어오더라도 브릿지를 통한 임시 뷰 역할이라서 자동 소거를 막음
            Ok(ManuallyDrop::new(buffer))
        }
    }
}

/// Java-Owned End Process order
///
/// # Safety
/// - `target`은 유효한 `FFIStandard` 포인터여야 합니다.
/// - `target`이 가리키는 메모리는 Java FFM API에서 할당된 페이지-정렬 메모리여야 합니다.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn joep(target: *const FFIStandard) -> EntLibResult {
    if target.is_null() {
        return EntLibResult::new(TYPE_ID, -1);
    }

    // ManuallyDrop으로 감싸지 않고 곧바로 SecureBuffer 생성
    // 내부적으로 PAGE_SIZE 검증 및 lock 통과 후 생성됨
    let result = unsafe { SecureBuffer::from_raw_parts((*target).ptr, (*target).len) };

    if result.is_ok() {
        // 블록이 종료되면서 변수가 스코프를 벗어남
        // -> SecureBuffer의 Drop 강제 발동
        // -> Zeroizer::zeroize_raw 실행 (완벽 소거)
        // -> os_lock::unlock_memory 연쇄 실행 (잠금 해제)
        EntLibResult::new(TYPE_ID, 0)
    } else {
        EntLibResult::new(TYPE_ID, -1)
    }
}
