use crate::memory::SecureMemoryBlock;
use crate::zeroize::{SecureZeroize, Zeroizer};
use entlib_native_base::error::secure_buffer::SecureBufferError;

/// 군사급 보안 요구사항을 충족하는 고수준 보안 버퍼입니다.
///
/// 이 구조체는 `SecureMemoryBlock`을 래핑하여, 메모리 할당부터 소멸까지의 전체 생명주기를
/// 안전하게 관리합니다. Rust 내부 할당뿐만 아니라 외부(FFI)에서 주입된 메모리도 지원합니다.
///
/// # Features
/// - **자동 소거 (Zeroization)**: `Drop` 시점에 할당된 전체 메모리(`capacity`)를 강제로 0으로 덮어씁니다.
/// - **메모리 잠금 (Memory Locking)**: 스왑(Swap) 영역으로의 데이터 유출을 방지하기 위해 OS 레벨 잠금을 수행합니다.
/// - **페이지 정렬 검증 (Page Alignment Check)**: 외부 메모리 주입 시, 보안 강화를 위해 페이지 정렬 여부를 엄격히 검사합니다.
pub struct SecureBuffer {
    /// 데이터가 저장된 메모리의 시작 포인터
    ptr: *mut u8,
    /// 데이터의 유효 길이 (바이트 단위)
    len: usize,
    /// 할당된 전체 메모리 용량 (바이트 단위, 소거 대상)
    capacity: usize,
    /// Rust가 할당한 메모리 블록 정보 (소유권이 있는 경우에만 존재)
    owned_block: Option<SecureMemoryBlock>,
}

impl SecureBuffer {
    /// Rust 내부에서 페이지 정렬된 안전한 메모리를 새로 할당합니다.
    ///
    /// `SecureMemoryBlock`을 사용하여 OS 레벨에서 잠긴(Locked) 메모리를 할당받습니다.
    ///
    /// # Arguments
    /// - `size` - 필요한 메모리 크기 (바이트). 내부적으로 페이지 크기 배수로 올림 처리됩니다.
    ///
    /// # Returns
    /// - `Ok(SecureBuffer)` - 할당 및 잠금 성공 시
    /// - `Err(SecureBufferError)` - 메모리 할당 실패 또는 OS 리소스 제한 도달 시
    pub fn new_owned(size: usize) -> Result<Self, SecureBufferError> {
        let block = SecureMemoryBlock::allocate_locked(size)?;

        Ok(Self {
            ptr: block.ptr,
            len: size,
            capacity: block.capacity,
            owned_block: Some(block),
        })
    }

    /// Java 등 외부 시스템에서 FFM API를 통해 전달한 메모리를 래핑합니다.
    ///
    /// 외부에서 할당된 메모리를 `SecureBuffer`로 감싸서, Rust 쪽에서 안전하게 사용하고
    /// 소거할 수 있게 합니다. 단, 메모리 해제는 수행하지 않습니다.
    ///
    /// # Security Note
    /// 외부에서 주입된 메모리가 페이지 경계에 맞게 정렬되었는지(`PAGE_SIZE` 배수) 엄격하게 검증합니다.
    /// 정렬되지 않은 메모리는 보안 취약점(Side-channel attack 등)의 원인이 될 수 있으므로 거부합니다.
    ///
    /// # Safety
    /// - `ptr`은 유효한 메모리 주소를 가리켜야 합니다.
    /// - `len`은 해당 메모리 영역의 올바른 크기여야 합니다.
    /// - 호출자는 `ptr`이 가리키는 메모리가 `len`만큼 유효함을 보장해야 합니다.
    pub unsafe fn from_raw_parts(ptr: *mut u8, len: usize) -> Result<Self, SecureBufferError> {
        let ps = crate::memory::page_size();
        if !(ptr as usize).is_multiple_of(ps) {
            return Err(SecureBufferError::PageAlignmentViolation);
        }
        if !len.is_multiple_of(ps) {
            return Err(SecureBufferError::PageAlignmentViolation);
        }

        #[cfg(feature = "std")]
        unsafe {
            // Q. T. Felix TODO: 베어메탈 std 환경에서 lock_memory는 사용할 수 없습니다.
            if !crate::memory::os_lock::lock_memory(ptr, len) {
                return Err(SecureBufferError::MemoryLockFailed);
            }
        }

        Ok(Self {
            ptr,
            len,
            capacity: len,
            owned_block: None, // 외부 소유 메모리이므로 None
        })
    }

    /// 버퍼의 유효 데이터 길이(바이트)를 반환합니다.
    #[inline(always)]
    pub fn len(&self) -> usize {
        self.len
    }

    /// 버퍼의 유효 데이터가 없으면 `true`를 반환합니다.
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline(always)]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// 버퍼의 내용을 읽기 전용 슬라이스로 반환합니다.
    ///
    /// # Security Note
    /// 반환된 슬라이스는 `SecureBuffer`의 수명에 묶여 있습니다.
    /// 슬라이스를 통해 얻은 데이터는 별도로 복사하지 말고 제자리에서 사용하세요.
    #[inline(always)]
    pub fn as_slice(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.ptr, self.len) }
    }

    /// 버퍼의 내용을 변경 가능한 슬라이스로 반환합니다.
    ///
    /// # Safety
    /// 반환된 슬라이스를 통해 데이터를 읽거나 쓸 수 있습니다.
    /// 동시성 문제가 발생하지 않도록 주의해야 합니다.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.ptr, self.len) }
    }
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        if self.ptr.is_null() {
            return;
        }

        // 강제 물리적 소거
        // 할당된 '전체 capacity'에 대해 수행하여, 패딩 영역까지 꼼꼼하게 지움
        unsafe {
            Zeroizer::zeroize_raw(self.ptr, self.capacity);
        }

        // 소유권에 따른 메모리 해제 및 잠금 해제 분기
        if let Some(block) = &self.owned_block {
            // Rust가 소유한 메모리: SecureMemoryBlock에게 해제 위임
            // (내부적으로 잠금 해제 및 dealloc 수행)
            unsafe {
                block.deallocate_unlocked();
            }
        } else {
            // 외부가 소유한 메모리: 잠금만 해제하고, 메모리 반환은 Java Arena 등에 위임
            #[cfg(feature = "std")]
            unsafe {
                // Q. T. Felix TODO: 베어메탈 std 환경에서 unlock_memory는 사용할 수 없습니다.
                crate::memory::os_lock::unlock_memory(self.ptr, self.capacity);
            }
        }
    }
}
