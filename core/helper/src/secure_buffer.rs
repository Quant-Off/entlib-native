use alloc::vec::Vec;
use core::ptr::write_volatile;
use core::sync::atomic::{Ordering, compiler_fence};

/// 메모리 소거를 보장하는 보안 버퍼 구조체입니다.
pub struct SecureBuffer {
    pub inner: Vec<u8>,
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        for byte in self.inner.iter_mut() {
            // volatile write -> 컴파일러 dce 최적화 방지함
            unsafe {
                write_volatile(byte, 0);
            }
        }
        // 메모리 배리어로 소거 순서 보장
        compiler_fence(Ordering::SeqCst);
    }
}
