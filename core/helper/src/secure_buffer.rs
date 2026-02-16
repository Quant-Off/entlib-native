use alloc::vec::Vec;
use core::ptr::write_volatile;
use core::sync::atomic::{Ordering, compiler_fence};

/// 메모리 소거를 보장하는 보안 버퍼 구조체입니다.
///
/// 민감한 데이터를 사용한 연산 후 그 결과를 Java Heap으로 전달하는 경우,
/// 가비지 컬렉터의 생명주기에 종속되어 위험에 다시 노출되는 딜레마를 가지게
/// 됩니다. 이 문제를 해결하기 위해 단순히 `byte[]`와 같은 Java 데이터로
/// 직렬화(serialize)하지 않고, 이 구조체에 저장합니다.
///
/// Java 측으로는 오직 해당 메모리의 원시 포인만이 전달되기 떄문에 안전한
/// 데이터 관리가 가능합니다.
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
